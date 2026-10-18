/**
 * The one list of censored countries (`censorship.countries` in `appSettings`).
 *
 * It replaces five lists that had drifted apart: the server-name curated set
 * (`edge.sni.curatedCountries`), the probe countries (`edge.probe.countries`),
 * the opt-in for name checks from inside a country (`edge.sni.vantage.countries`),
 * the "suggest the censorship mode" list (`delivery.privacyCountries`) and the
 * rows of the status page's availability matrix (`status.censorship`).
 *
 * One entry per country, in the operator's order:
 *  - being on the list makes it a country where server names are judged, a
 *    choice under "Where are you connecting from?", a row the status matrix can
 *    show, and a country the mode suggestion treats as censored;
 *  - `checkEdges`: edges are probed from vantages there;
 *  - `checkNamesInside`: server names are checked from inside it (opt-in, with
 *    the residual risk docs/edges.md "Checks from inside a country" describes).
 *
 * While the key has never been written, the list is computed LIVE from the old
 * keys (their union, in the order curated, probe, vantage, privacy, matrix
 * rows, never truncated), so behaviour does not move between `convex deploy`
 * and the seed that copies it (`seed.seedCensoredCountries`). The old keys are
 * left in place until a later cleanup, so a rollback still finds them. A union
 * longer than the cap is not copied: it stays live until an admin trims it.
 *
 * Pure apart from the reads; no import from edgeConfig or sniConfig (they read
 * this module).
 */
import type { DatabaseReader } from '../_generated/server';

export const CENSORED_COUNTRIES_KEY = 'censorship.countries';
export const MAX_CENSORED_COUNTRIES = 40;

/** Codes that never name a country: unknown (`XX`) and "Somewhere else" (`ZZ`). */
const RESERVED_CODES: ReadonlySet<string> = new Set(['XX', 'ZZ']);

export interface CensoredCountry {
  /** ISO 3166-1 alpha-2, uppercase. */
  code: string;
  /** Edges are probed from vantages in this country. */
  checkEdges: boolean;
  /** Server names are checked from inside this country (opt-in). */
  checkNamesInside: boolean;
}

export interface CensoredCountries {
  list: CensoredCountry[];
  /** Every listed code, in list order. */
  codes: string[];
  /** Codes with `checkEdges`, in list order. */
  edgeChecks: string[];
  /** Codes with `checkNamesInside`, in list order. */
  namesInside: string[];
  /** `stored`: the key exists; `legacy`: computed from the old keys. */
  source: 'stored' | 'legacy';
}

/** The keys the list replaced, read only while `censorship.countries` is absent. */
export const LEGACY_COUNTRY_KEYS = {
  curated: 'edge.sni.curatedCountries',
  probe: 'edge.probe.countries',
  vantage: 'edge.sni.vantage.countries',
  privacy: 'delivery.privacyCountries',
  matrix: 'status.censorship',
} as const;

/** The old keys' compiled defaults (what an install that never set them used). */
export const LEGACY_DEFAULTS = {
  curated: ['CN', 'RU', 'IR', 'MM'],
  probe: ['IR', 'RU', 'CN', 'TR', 'AE', 'KZ', 'BY'],
  vantage: [] as string[],
  privacy: [] as string[],
} as const;

export function normalizeCode(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  const c = v.trim().toUpperCase();
  return /^[A-Z]{2}$/.test(c) && !RESERVED_CODES.has(c) ? c : null;
}

function codeList(v: unknown, dflt: readonly string[]): string[] {
  if (!Array.isArray(v)) return [...dflt];
  const out: string[] = [];
  for (const c of v) {
    const n = normalizeCode(c);
    if (n && !out.includes(n)) out.push(n);
  }
  return out;
}

function matrixCodes(v: unknown): string[] {
  if (!v || typeof v !== 'object') return [];
  const rows = (v as Record<string, unknown>).rows;
  if (!Array.isArray(rows)) return [];
  return codeList(
    rows.map((r) =>
      r && typeof r === 'object' ? (r as Record<string, unknown>).countryCode : null,
    ),
    [],
  );
}

/**
 * Coerce a stored or submitted list: entries with a bad or reserved code are
 * dropped, a repeated code keeps its first entry, missing flags are false, and
 * the list is capped. Null when the value is not an array at all.
 */
export function sanitizeCensoredCountries(v: unknown): CensoredCountry[] | null {
  if (!Array.isArray(v)) return null;
  const out: CensoredCountry[] = [];
  for (const e of v) {
    if (!e || typeof e !== 'object') continue;
    const o = e as Record<string, unknown>;
    const code = normalizeCode(o.code);
    if (!code || out.some((x) => x.code === code)) continue;
    out.push({
      code,
      checkEdges: o.checkEdges === true,
      checkNamesInside: o.checkNamesInside === true,
    });
    if (out.length >= MAX_CENSORED_COUNTRIES) break;
  }
  return out;
}

/** The raw (JSON-parsed) old values; `undefined` = the key was never written. */
export interface LegacyCountryValues {
  curated?: unknown;
  probe?: unknown;
  vantage?: unknown;
  privacy?: unknown;
  matrix?: unknown;
}

/**
 * The union of the old lists, as one list. A probe country gets `checkEdges`;
 * a vantage country gets `checkNamesInside` only when it was also curated
 * (that is the only way it was ever checked before). NOT truncated: the old
 * lists could together exceed the cap, and dropping the tail would silently
 * stop checks, suggestions and matrix rows. The seed refuses such a union.
 */
export function legacyUnion(raw: LegacyCountryValues): CensoredCountry[] {
  const curated = codeList(raw.curated, LEGACY_DEFAULTS.curated);
  const probe = codeList(raw.probe, LEGACY_DEFAULTS.probe);
  const vantage = codeList(raw.vantage, LEGACY_DEFAULTS.vantage);
  const privacy = codeList(raw.privacy, LEGACY_DEFAULTS.privacy);
  const matrix = matrixCodes(raw.matrix);
  const order: string[] = [];
  for (const c of [...curated, ...probe, ...vantage, ...privacy, ...matrix])
    if (!order.includes(c)) order.push(c);
  return order.map((code) => ({
    code,
    checkEdges: probe.includes(code),
    checkNamesInside: vantage.includes(code) && curated.includes(code),
  }));
}

export function describeCensoredCountries(
  list: CensoredCountry[],
  source: CensoredCountries['source'],
): CensoredCountries {
  return {
    list,
    codes: list.map((c) => c.code),
    edgeChecks: list.filter((c) => c.checkEdges).map((c) => c.code),
    namesInside: list.filter((c) => c.checkNamesInside).map((c) => c.code),
    source,
  };
}

/** The list an install that never set any of the old keys gets. */
export const DEFAULT_CENSORED_COUNTRIES: CensoredCountries = describeCensoredCountries(
  legacyUnion({}),
  'legacy',
);

async function readSetting(db: DatabaseReader, key: string): Promise<unknown> {
  const row = await db
    .query('appSettings')
    .withIndex('by_key', (q) => q.eq('key', key))
    .unique();
  if (!row) return undefined;
  try {
    return JSON.parse(row.value);
  } catch {
    return undefined;
  }
}

/** The list, from its own key when written, else live from the old keys. */
export async function resolveCensoredCountries(db: DatabaseReader): Promise<CensoredCountries> {
  const stored = sanitizeCensoredCountries(await readSetting(db, CENSORED_COUNTRIES_KEY));
  if (stored) return describeCensoredCountries(stored, 'stored');
  const [curated, probe, vantage, privacy, matrix] = await Promise.all([
    readSetting(db, LEGACY_COUNTRY_KEYS.curated),
    readSetting(db, LEGACY_COUNTRY_KEYS.probe),
    readSetting(db, LEGACY_COUNTRY_KEYS.vantage),
    readSetting(db, LEGACY_COUNTRY_KEYS.privacy),
    readSetting(db, LEGACY_COUNTRY_KEYS.matrix),
  ]);
  return describeCensoredCountries(
    legacyUnion({ curated, probe, vantage, privacy, matrix }),
    'legacy',
  );
}

/**
 * Validate an admin's whole new list. Unlike the read-side sanitizer it
 * refuses what it would otherwise drop, so the admin learns about a typo.
 * Returns the cleaned list or the reason it was refused.
 */
export function validateCensoredCountries(
  v: unknown,
): { ok: true; list: CensoredCountry[] } | { ok: false; message: string } {
  if (!Array.isArray(v)) return { ok: false, message: 'countries must be a list' };
  if (v.length > MAX_CENSORED_COUNTRIES)
    return { ok: false, message: `At most ${MAX_CENSORED_COUNTRIES} countries` };
  const seen = new Set<string>();
  for (const e of v) {
    const o = e && typeof e === 'object' ? (e as Record<string, unknown>) : null;
    const code = o ? normalizeCode(o.code) : null;
    if (!o || !code) return { ok: false, message: 'Each entry needs a two-letter country code' };
    if (seen.has(code)) return { ok: false, message: `${code} is listed twice` };
    // A flag left out is off; one given must be a boolean (a "true" string read
    // as off would silently stop checks while the save reports success).
    for (const flag of ['checkEdges', 'checkNamesInside'] as const)
      if (o[flag] !== undefined && typeof o[flag] !== 'boolean')
        return { ok: false, message: `${code}: ${flag} must be true or false` };
    seen.add(code);
  }
  return { ok: true, list: sanitizeCensoredCountries(v) ?? [] };
}

/** What changed between two lists, for the audit row (codes only). */
export function censoredCountriesDiff(
  before: readonly CensoredCountry[],
  after: readonly CensoredCountry[],
): { added: string[]; removed: string[]; flagsChanged: string[] } {
  const b = new Map(before.map((c) => [c.code, c]));
  const a = new Map(after.map((c) => [c.code, c]));
  return {
    added: after.filter((c) => !b.has(c.code)).map((c) => c.code),
    removed: before.filter((c) => !a.has(c.code)).map((c) => c.code),
    flagsChanged: after
      .filter((c) => {
        const old = b.get(c.code);
        return (
          !!old && (old.checkEdges !== c.checkEdges || old.checkNamesInside !== c.checkNamesInside)
        );
      })
      .map((c) => c.code),
  };
}
