/**
 * Evidence for shortlisted candidates (pure; unit-tested; docs/edges.md
 * "Finding names"): how near the node the endpoint REALITY would relay to
 * answers, what OONI's public data says per country, and what a real-site
 * check from inside a country read. All of it only feeds the score; nothing
 * here marks, adds or activates a name.
 */
import { normalizeCountry } from '../../probes/types';
import { nearPoints, SCORE_PARTS } from './score';

const DAY = 24 * 3_600_000;
/** Timing and OONI evidence count this long; older counts as missing (half). */
export const EVIDENCE_FRESH_MS = 14 * DAY;
/** OONI is asked again after this long. */
export const OONI_REFRESH_MS = 7 * DAY;
/** A name is checked from one country at most this often. */
export const COUNTRY_CHECK_EVERY_MS = 7 * DAY;
/** OONI's window. */
export const OONI_DAYS = 90;
/** The shortlist's last slots rotate among candidates without fresh evidence. */
export const ROTATING_SLOTS = 3;

export const isFresh = (at: number | undefined, now: number, ms = EVIDENCE_FRESH_MS) =>
  at !== undefined && now - at < ms;

// --- timing ---------------------------------------------------------------------------------------

export interface HuntPlace {
  country: string;
  city?: string;
}

/** A place as stored on a measurement: `CC` or `CC/City`. */
export const placeKey = (p: HuntPlace) => (p.city ? `${p.country}/${p.city}` : p.country);

/**
 * `HEAD /` over HTTPS from probes at the network's place, to an address
 * literal, presenting `host` (SNI and Host): the leg a REALITY node relays
 * every unauthenticated handshake over.
 */
export function timingRequest(
  t: { address: string; port: number; host: string },
  place: HuntPlace,
) {
  return {
    type: 'http' as const,
    target: t.address,
    inProgressUpdates: false,
    locations: [{ country: place.country, ...(place.city ? { city: place.city } : {}), limit: 2 }],
    measurementOptions: {
      protocol: 'HTTPS' as const,
      port: t.port,
      request: { method: 'HEAD' as const, path: '/', host: t.host },
    },
  };
}

const median = (xs: number[]) => {
  const s = [...xs].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m]! : Math.round((s[m - 1]! + s[m]!) / 2);
};

/**
 * The medians of the connect and handshake phases over the probes of the
 * place's country that finished with both; null when none did.
 */
export function timingOf(
  items: unknown,
  country: string,
): { connectMs: number; tlsMs?: number; probes: number } | null {
  if (!Array.isArray(items)) return null;
  const tcp: number[] = [];
  const tls: number[] = [];
  for (const it of items as Array<{
    probe?: { country?: unknown };
    result?: { status?: unknown; timings?: { tcp?: unknown; tls?: unknown } };
  }>) {
    if (normalizeCountry(it.probe?.country) !== country) continue;
    if (it.result?.status !== 'finished') continue;
    const c = Number(it.result.timings?.tcp);
    const t = Number(it.result.timings?.tls);
    if (!Number.isFinite(c) || c < 0) continue;
    tcp.push(c);
    if (Number.isFinite(t) && t >= 0) tls.push(t);
  }
  if (tcp.length === 0) return null;
  return {
    connectMs: median(tcp),
    ...(tls.length > 0 ? { tlsMs: median(tls) } : {}),
    probes: tcp.length,
  };
}

// --- OONI ---------------------------------------------------------------------------------------------

export type OoniStatus = 'ok' | 'mixed' | 'likely_blocked' | 'blocked' | 'thin' | 'no_data';

export function ooniUrl(domain: string, now: number): string {
  const until = new Date(now + DAY).toISOString().slice(0, 10);
  const since = new Date(now - OONI_DAYS * DAY).toISOString().slice(0, 10);
  const q = new URLSearchParams({
    domain,
    since,
    until,
    axis_x: 'probe_cc',
    test_name: 'web_connectivity',
  });
  return `https://api.ooni.org/api/v1/aggregation?${q.toString()}`;
}

/**
 * One country's counts as a status: `blocked` when confirmed blocks are a
 * fifth or more, `likely_blocked` when anomalies are half or more, `thin`
 * under 10 measurements, `ok` at 85% or more clean, else `mixed`.
 */
export function ooniStatus(c: {
  measurement_count: number;
  ok_count: number;
  anomaly_count: number;
  confirmed_count: number;
}): OoniStatus {
  const n = c.measurement_count;
  if (n <= 0) return 'no_data';
  if (c.confirmed_count > 0 && c.confirmed_count / n >= 0.2) return 'blocked';
  if (c.anomaly_count / n >= 0.5) return 'likely_blocked';
  if (n < 10) return 'thin';
  if (c.ok_count / n >= 0.85 && c.confirmed_count === 0) return 'ok';
  return 'mixed';
}

/** An aggregation answer, per curated country (one with no row reads `no_data`). Null when malformed. */
export function parseOoni(
  body: unknown,
  countries: readonly string[],
): Array<{ cc: string; status: OoniStatus; measurements: number }> | null {
  const rows = (body as { result?: unknown } | null)?.result;
  if (!Array.isArray(rows)) return null;
  const by = new Map<string, { status: OoniStatus; measurements: number }>();
  for (const r of rows as Array<Record<string, unknown>>) {
    const cc = normalizeCountry(r.probe_cc);
    if (!cc || !countries.includes(cc)) continue;
    const num = (k: string) => (Number.isFinite(Number(r[k])) ? Number(r[k]) : 0);
    const counts = {
      measurement_count: num('measurement_count'),
      ok_count: num('ok_count'),
      anomaly_count: num('anomaly_count'),
      confirmed_count: num('confirmed_count'),
    };
    by.set(cc, { status: ooniStatus(counts), measurements: counts.measurement_count });
  }
  return countries.map((cc) => ({ cc, ...(by.get(cc) ?? { status: 'no_data', measurements: 0 }) }));
}

// --- real-site checks from inside a country --------------------------------------------------------

export type CountryReading = 'ok' | 'interference' | 'inconclusive' | 'path';

interface BatchRow {
  key: string;
  results: ReadonlyArray<{ vantage?: string; asn?: string; network?: string; outcome: string }>;
}

const FAILS = new Set(['reset', 'timeout', 'cert_mismatch']);

/**
 * One batch's reading per name, paired like the vantage batches: a failure
 * counts as interference only when the SAME vantage got through for another
 * name of the batch (`singled`), from at least `minVantages` vantages on
 * `minNetworks` networks. A failure nothing paired is inconclusive (a broken
 * probe, a route, a site outage: no penalty). A batch where nothing got
 * through reads `path`. `ok` needs the same floors.
 */
export function readCountryBatch(
  rows: readonly BatchRow[],
  floors: { minVantages: number; minNetworks: number },
): Map<string, { reading: CountryReading; vantages: number; networks: number; singled: number }> {
  const okBy = new Map<string, Set<string>>(); // vantage -> keys it got through for
  for (const r of rows)
    for (const x of r.results)
      if (x.outcome === 'ok' && x.vantage)
        okBy.set(x.vantage, new Set([...(okBy.get(x.vantage) ?? []), r.key]));
  const anyOk = okBy.size > 0;
  const out = new Map<
    string,
    { reading: CountryReading; vantages: number; networks: number; singled: number }
  >();
  for (const r of rows) {
    const okV = new Set<string>();
    const okN = new Set<string>();
    const sV = new Set<string>();
    const sN = new Set<string>();
    for (const x of r.results) {
      if (!x.vantage) continue;
      const net = x.asn ?? x.network;
      if (x.outcome === 'ok') {
        okV.add(x.vantage);
        if (net) okN.add(net);
      } else if (FAILS.has(x.outcome)) {
        const others = okBy.get(x.vantage);
        if (others && [...others].some((k) => k !== r.key)) {
          sV.add(x.vantage);
          if (net) sN.add(net);
        }
      }
    }
    let reading: CountryReading;
    if (!anyOk) reading = 'path';
    else if (sV.size >= floors.minVantages && sN.size >= floors.minNetworks)
      reading = 'interference';
    else if (sV.size === 0 && okV.size >= floors.minVantages && okN.size >= floors.minNetworks)
      reading = 'ok';
    else reading = 'inconclusive';
    out.set(r.key, {
      reading,
      vantages: Math.max(okV.size, sV.size),
      networks: Math.max(okN.size, sN.size),
      singled: sV.size,
    });
  }
  return out;
}

// --- the evidence parts of a score -------------------------------------------------------------------

export interface EvidenceView {
  check?: { dialled?: string; port?: number } | null;
  timing?: { at: number; endpoint: string; port: number; connectMs: number } | null;
  ooni?: { at: number; exact: ReadonlyArray<{ cc: string; status: string }> } | null;
  countries?: ReadonlyArray<{ cc: string; at: number; reading: string }> | null;
}

/**
 * Near-the-node points from fresh timing of the endpoint the candidate is
 * checked on now (undefined: not measured, expired, or measured on an address
 * the check no longer dials).
 */
export function nearOf(c: EvidenceView, now: number): number | undefined {
  const t = c.timing;
  if (!t || !isFresh(t.at, now)) return undefined;
  if (!c.check?.dialled || c.check.dialled !== t.endpoint || (c.check.port ?? 443) !== t.port)
    return undefined;
  return nearPoints(t.connectMs);
}

/**
 * Standing per curated country: per country, a fresh in-country reading
 * decides when it is decisive (`ok` 1, `interference` 0), else OONI for the
 * exact name (`ok` 1, blocked or likely 0), else half. The part is 20 times
 * the mean; undefined when nothing decisive is known anywhere (it then counts
 * half, the same). Penalties: 40 when OONI has the exact name blocked or
 * likely blocked in a curated country, 8 for each country with interference.
 */
export function countryOf(
  c: EvidenceView,
  curated: readonly string[],
  now: number,
  windowMs = EVIDENCE_FRESH_MS,
): { points: number | undefined; penalty: number } {
  if (curated.length === 0) return { points: undefined, penalty: 0 };
  const ooniFresh = c.ooni && isFresh(c.ooni.at, now) ? c.ooni.exact : [];
  let decisive = false;
  let sum = 0;
  let penalty = 0;
  let blocked = false;
  for (const cc of curated) {
    const r = (c.countries ?? []).find((x) => x.cc === cc && isFresh(x.at, now, windowMs));
    const o = ooniFresh.find((x) => x.cc === cc)?.status;
    if (o === 'blocked' || o === 'likely_blocked') blocked = true;
    if (r?.reading === 'interference') penalty += 8;
    if (r?.reading === 'ok') {
      decisive = true;
      sum += 1;
    } else if (r?.reading === 'interference') {
      decisive = true;
    } else if (o === 'ok') {
      decisive = true;
      sum += 1;
    } else if (o === 'blocked' || o === 'likely_blocked') {
      decisive = true;
    } else sum += 0.5;
  }
  if (blocked) penalty += 40;
  const points = decisive
    ? Math.round((SCORE_PARTS.country * sum * 10) / curated.length) / 10
    : undefined;
  return { points, penalty };
}

// --- the shortlist ---------------------------------------------------------------------------------

export interface ShortlistRow {
  id: string;
  baseScore: number;
  passing: boolean;
  /** Fresh evidence it can have (timing where a place is set, OONI). */
  fresh: boolean;
  evidenceAskedAt?: number;
  measureAt?: number;
}

/**
 * Who gets evidence, by `baseScore` (never by `score`, so evidence cannot
 * keep anyone out): the top `size - 3` passing candidates, plus 3 rotating
 * slots for passing candidates without fresh evidence, the one asked about
 * longest ago (or never) first. A candidate an operator asked to measure is
 * always on it.
 */
export function shortlistOf(rows: readonly ShortlistRow[], size: number): Set<string> {
  const passing = rows.filter((r) => r.passing).sort((a, b) => b.baseScore - a.baseScore);
  const rotating = Math.min(ROTATING_SLOTS, Math.max(0, size - 1));
  const top = passing.slice(0, size - rotating);
  const out = new Set(top.map((r) => r.id));
  const waiting = passing
    .filter((r) => !out.has(r.id) && !r.fresh)
    .sort((a, b) => (a.evidenceAskedAt ?? 0) - (b.evidenceAskedAt ?? 0));
  for (const r of waiting.slice(0, rotating)) out.add(r.id);
  for (const r of rows) if (r.measureAt && r.passing) out.add(r.id);
  return out;
}
