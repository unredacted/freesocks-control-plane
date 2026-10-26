/**
 * Where candidate server names come from (pure; unit-tested; docs/edges.md
 * "Finding names"). Every source is passive: a list someone published, a
 * certificate a target already presents, a certificate-transparency log, or a
 * list an operator pastes. Nothing here dials anything; the actions do, and
 * only what these parsers hand them.
 */
import { getDomain } from 'tldts';
import { normalizeName } from '../../registration';
import { addressFamily } from '../../ip';

/** A candidate name as stored: a lowercase hostname with at least two labels, never a wildcard or an address. */
export function huntName(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const t = raw.trim();
  if (t.includes('*')) return null;
  const n = normalizeName(t);
  if (!n || addressFamily(n) || !n.includes('.')) return null;
  return n;
}

/** The registrable domain a name belongs to (public-suffix aware), else the name itself. */
export function siteOf(name: string): string {
  return getDomain(name, { allowPrivateDomains: false }) ?? name;
}

// --- the top-sites list (Tranco) ----------------------------------------------------------------

export const TRANCO_LATEST_URL = 'https://tranco-list.eu/api/lists/date/latest';

/** The latest list's id and date; null when the answer is not one. */
export function parseTrancoLatest(body: unknown): { listId: string; date: string } | null {
  const b = body as { list_id?: unknown; created_on?: unknown } | null;
  const listId = typeof b?.list_id === 'string' ? b.list_id : '';
  if (!/^[A-Z0-9]{3,12}$/.test(listId)) return null;
  const date = typeof b?.created_on === 'string' ? b.created_on.slice(0, 10) : '';
  return { listId, date };
}

/** The download address for the first `depth` entries of a list. */
export function trancoDownloadUrl(listId: string, depth: number): string {
  return `https://tranco-list.eu/download/${encodeURIComponent(listId)}/${depth}`;
}

export interface ListEntry {
  rank: number;
  name: string;
}

/**
 * What a sweep resolves, in order: every listed site up to `depth`, and right
 * after it its `www.` name while the rank is within `wwwDepth`. Lines that are
 * not `rank,name` with a usable name are skipped.
 */
export function trancoEntries(csv: string, depth: number, wwwDepth: number): ListEntry[] {
  const out: ListEntry[] = [];
  for (const line of csv.split(/\r?\n/)) {
    const comma = line.indexOf(',');
    if (comma <= 0) continue;
    const rank = Number(line.slice(0, comma));
    if (!Number.isInteger(rank) || rank < 1 || rank > depth) continue;
    const name = huntName(line.slice(comma + 1));
    if (!name) continue;
    out.push({ rank, name });
    if (rank <= wwwDepth && !name.startsWith('www.')) {
      const www = huntName(`www.${name}`);
      if (www) out.push({ rank, name: www });
    }
  }
  return out;
}

/** Entries per stored chunk of a sweep's list. */
export const SWEEP_CHUNK_ENTRIES = 10_000;

export function encodeChunk(entries: readonly ListEntry[]): string {
  return entries.map((e) => `${e.rank}\t${e.name}`).join('\n');
}

export function decodeChunk(text: string): ListEntry[] {
  const out: ListEntry[] = [];
  for (const line of text.split('\n')) {
    const tab = line.indexOf('\t');
    if (tab <= 0) continue;
    const rank = Number(line.slice(0, tab));
    const name = line.slice(tab + 1);
    if (Number.isInteger(rank) && name) out.push({ rank, name });
  }
  return out;
}

// --- certificate transparency (Cert Spotter) ------------------------------------------------------

/**
 * One page of issuances for a domain and its subdomains, after the last one
 * already read. Cert Spotter pages from the least recently discovered, so the
 * newest certificates are on the LAST pages: only reading until an empty page
 * makes an answer complete.
 */
export function certSpotterUrl(domain: string, after?: string): string {
  const q = new URLSearchParams({
    domain,
    include_subdomains: 'true',
    expand: 'dns_names',
  });
  if (after) q.set('after', after);
  return `https://api.certspotter.com/v1/issuances?${q.toString()}`;
}

/**
 * The names on one page and the id to continue after. `done` when the page is
 * empty (the end was reached). Null for an answer that is not a page.
 */
export function parseCertSpotterPage(
  body: unknown,
): { names: string[]; lastId: string | null; done: boolean } | null {
  if (!Array.isArray(body)) return null;
  const names = new Set<string>();
  let lastId: string | null = null;
  for (const row of body) {
    const r = row as { id?: unknown; dns_names?: unknown } | null;
    if (typeof r?.id === 'string' && /^\d{1,20}$/.test(r.id)) lastId = r.id;
    if (Array.isArray(r?.dns_names))
      for (const d of r.dns_names) {
        const n = huntName(d);
        if (n) names.add(n);
      }
  }
  return { names: [...names].sort(), lastId, done: body.length === 0 };
}

/** When to ask again after a 429: its Retry-After (seconds or a date), else an hour. */
export function retryAfterMs(header: string | null, now: number): number {
  const HOUR = 3_600_000;
  if (!header) return now + HOUR;
  const secs = Number(header);
  if (Number.isFinite(secs) && secs >= 0) return now + Math.min(secs * 1000, 24 * HOUR);
  const at = Date.parse(header);
  return Number.isFinite(at) && at > now ? Math.min(at, now + 24 * HOUR) : now + HOUR;
}

// --- a seed (a hand-run study's output) ------------------------------------------------------------

export interface SeedFamily {
  slug: string;
  label: string;
  targetAddress: string;
  targetPort: number;
  requireH2: boolean;
  names: string[];
  rank?: number;
}
export interface SeedNetwork {
  slug: string;
  label: string;
  asns: number[];
  families: SeedFamily[];
}

const SLUG = /^[a-z0-9][a-z0-9-]{0,39}$/;

/**
 * A seed: `{networks: [{network: {slug, label, asns}, families: [{create_family:
 * {slug, label, targetAddress, targetPort, requireH2}, import_names: {lines},
 * target?: {tranco_rank}}]}]}`. Unknown fields are ignored; an unusable network
 * or family is dropped, never half-read. Null when it is not a seed at all.
 */
export function parseSeed(body: unknown): SeedNetwork[] | null {
  const nets = (body as { networks?: unknown } | null)?.networks;
  if (!Array.isArray(nets)) return null;
  const out: SeedNetwork[] = [];
  for (const raw of nets.slice(0, 50)) {
    const n = (raw as { network?: Record<string, unknown> } | null)?.network;
    const slug = typeof n?.slug === 'string' ? n.slug.trim().toLowerCase() : '';
    if (!SLUG.test(slug)) continue;
    const asns = Array.isArray(n?.asns)
      ? n.asns.map(Number).filter((a) => Number.isInteger(a) && a > 0 && a <= 4_294_967_295)
      : [];
    const families: SeedFamily[] = [];
    const fams = (raw as { families?: unknown }).families;
    for (const f of Array.isArray(fams) ? fams.slice(0, 50) : []) {
      const c = (f as { create_family?: Record<string, unknown> } | null)?.create_family;
      const fslug = typeof c?.slug === 'string' ? c.slug.trim().toLowerCase() : '';
      const target = typeof c?.targetAddress === 'string' ? c.targetAddress.trim() : '';
      if (!SLUG.test(fslug) || !target) continue;
      const port = Number(c?.targetPort ?? 443);
      const lines = (f as { import_names?: { lines?: unknown } }).import_names?.lines;
      const names = [
        ...new Set(
          (Array.isArray(lines) ? lines.slice(0, 1000) : [])
            .map(huntName)
            .filter((x): x is string => !!x),
        ),
      ];
      const rank = Number((f as { target?: { tranco_rank?: unknown } }).target?.tranco_rank);
      families.push({
        slug: fslug,
        label: typeof c?.label === 'string' ? c.label.trim().slice(0, 80) || fslug : fslug,
        targetAddress: target.toLowerCase(),
        targetPort: Number.isInteger(port) && port > 0 && port < 65536 ? port : 443,
        requireH2: c?.requireH2 === true,
        names,
        ...(Number.isInteger(rank) && rank > 0 ? { rank } : {}),
      });
    }
    out.push({
      slug,
      label: typeof n?.label === 'string' ? n.label.trim().slice(0, 80) || slug : slug,
      asns: [...new Set(asns)].slice(0, 8),
      families,
    });
  }
  return out;
}
