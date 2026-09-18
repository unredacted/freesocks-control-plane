/**
 * RIPE Atlas (optional tertiary source): one-off `sslcert` measurements per
 * country (API key + credits). One measurement per requested country keeps the
 * result → country mapping trivial (no per-probe lookups). Vantage class is
 * `unknown` (Atlas probes are mixed home/hosting; the API does not say).
 *
 * A result identifies the PROBE, not its network, and a probe id is not a
 * network: the agreement rule counts distinct failing networks, so the probes'
 * ASNs are read from the probe registry once per run and attached to the
 * results. Probes whose ASN cannot be resolved stay network-less and collapse
 * into one bucket in `verdict.ts` rather than faking agreement.
 */
import {
  isBareConnect,
  shortError,
  type ProbeProtocol,
  type ProbeRequestOptions,
  type ProbeResult,
  type ProbeTarget,
} from './types';
import type { FetchLike } from './checkhost';

export const RIPE_ATLAS_BASE = 'https://atlas.ripe.net/api/v2';

export interface AtlasStarted {
  /** country → measurement id */
  measurements: Record<string, number>;
  /** The address family the measurements were created with. */
  af: 4 | 6;
  /** probe id → ASN, filled lazily by the poller (shared across its polls). */
  asnByProbe?: Record<number, string>;
  /**
   * What the run measures. A TLS alert is "the peer answered" for a bare
   * `tcp` probe (a REALITY edge presents no certificate for a random SNI) but a
   * FAILURE for a `tls` / `https` probe, whose measurement is the handshake.
   */
  protocol?: ProbeProtocol;
}

/**
 * Atlas needs an explicit address family even for a name, so a `requestedFamily`
 * of `any` is created as v4 (what every member's resolver reaches for first);
 * the run still records `any`, and the family a vantage actually used is not
 * observable here.
 */
export function atlasFamily(target: ProbeTarget): 4 | 6 {
  if (target.requestedFamily === 6) return 6;
  if (target.requestedFamily === 4) return 4;
  return target.ipVersion ?? 4;
}

export function ripeAtlasBody(target: ProbeTarget, country: string, requested: number) {
  return {
    definitions: [
      {
        type: 'sslcert',
        af: atlasFamily(target),
        target: target.address,
        port: target.port,
        // A name target is dialled by name and the handshake carries it as SNI:
        // an L7 front answers only for its own name.
        ...(target.addressKind === 'name' ? { hostname: target.address } : {}),
        // Non-identifying, and PRIVATE: Atlas measurements are public by
        // default, which would publish the probed addresses.
        description: 'tcp reachability',
        is_oneoff: true,
        is_public: false,
      },
    ],
    probes: [{ type: 'country', value: country, requested: Math.max(1, Math.min(requested, 10)) }],
    is_oneoff: true,
  };
}

export async function ripeAtlasStart(
  fetchFn: FetchLike,
  apiKey: string,
  target: ProbeTarget,
  opts: ProbeRequestOptions,
): Promise<AtlasStarted> {
  const measurements: Record<string, number> = {};
  for (const country of opts.countries) {
    const res = await fetchFn(`${RIPE_ATLAS_BASE}/measurements/`, {
      method: 'POST',
      headers: {
        authorization: `Key ${apiKey}`,
        'content-type': 'application/json',
        accept: 'application/json',
      },
      body: JSON.stringify(ripeAtlasBody(target, country, opts.perCountryLimit)),
    });
    if (!res.ok) throw new Error(`ripe atlas create (${country}): ${res.status}`);
    const body = (await res.json()) as { measurements?: unknown };
    const id = Array.isArray(body.measurements) ? body.measurements[0] : undefined;
    if (typeof id !== 'number') throw new Error('ripe atlas: no measurement id');
    measurements[country] = id;
  }
  return { measurements, af: atlasFamily(target), asnByProbe: {}, protocol: target.protocol };
}

function asnOfRow(raw: Record<string, unknown>, af: 4 | 6): string | undefined {
  // Some Atlas result formats carry the probe's network inline; prefer the
  // family that was measured, then anything else the row offers.
  const candidates = [
    raw[af === 6 ? 'asn_v6' : 'asn_v4'],
    raw.asn,
    raw[af === 6 ? 'asn_v4' : 'asn_v6'],
  ];
  for (const c of candidates) {
    if (typeof c === 'number' && Number.isFinite(c)) return `AS${c}`;
    if (typeof c === 'string' && /^\d+$/.test(c.trim())) return `AS${c.trim()}`;
  }
  return undefined;
}

/**
 * Parse one measurement's `/results/`: `rt`/`cert` = reachable; `err`
 * (connection-level) = not. A TLS `alert` depends on what was measured: for a
 * bare `tcp` probe the peer answered on the port (a REALITY edge will not
 * present a certificate for a random SNI; same rule as the internal probe),
 * for a `tls` / `https` probe the handshake IS the measurement and an alert is
 * a failure, or several alerting probes would become positive country evidence
 * for a front that cannot complete a handshake. The probe's ASN is the network;
 * the probe id never is.
 */
export function parseRipeAtlasResults(
  body: unknown,
  country: string,
  opts: { af?: 4 | 6; asnByProbe?: Record<number, string>; protocol?: ProbeProtocol } = {},
): ProbeResult[] {
  if (!Array.isArray(body)) return [];
  const af = opts.af ?? 4;
  const alertIsAnswer = isBareConnect(opts.protocol);
  const out: ProbeResult[] = [];
  for (const raw of body as Array<Record<string, unknown>>) {
    const prb = typeof raw.prb_id === 'number' ? raw.prb_id : Number(raw.prb_id);
    const asn = asnOfRow(raw, af) ?? (Number.isFinite(prb) ? opts.asnByProbe?.[prb] : undefined);
    const base = { country, ...(asn ? { asn } : {}), vantageClass: 'unknown' as const };
    if (raw.err !== undefined) {
      out.push({ ...base, ok: false, error: shortError(raw.err) });
    } else if (raw.alert !== undefined) {
      const rt = Number(raw.rt);
      out.push({
        ...base,
        ok: alertIsAnswer,
        rttMs: alertIsAnswer && Number.isFinite(rt) ? Math.round(rt) : undefined,
        error: 'tls_alert',
      });
    } else if (raw.rt !== undefined || Array.isArray(raw.cert)) {
      const rt = Number(raw.rt);
      out.push({ ...base, ok: true, rttMs: Number.isFinite(rt) ? Math.round(rt) : undefined });
    }
  }
  return out;
}

/** Probe ids seen in a results body (for the registry lookup). */
export function probeIdsOf(body: unknown): number[] {
  if (!Array.isArray(body)) return [];
  const ids = new Set<number>();
  for (const raw of body as Array<Record<string, unknown>>) {
    const n = typeof raw.prb_id === 'number' ? raw.prb_id : Number(raw.prb_id);
    if (Number.isFinite(n)) ids.add(n);
  }
  return [...ids];
}

/**
 * probe id → ASN from the public probe registry (one request per batch, ids
 * only). Best effort: a failure leaves the probes network-less, which is the
 * safe direction (no fabricated agreement).
 */
export async function fetchAtlasProbeAsns(
  fetchFn: FetchLike,
  apiKey: string,
  ids: readonly number[],
  af: 4 | 6,
): Promise<Record<number, string>> {
  const out: Record<number, string> = {};
  if (ids.length === 0) return out;
  const q = new URLSearchParams({
    id__in: ids.slice(0, 100).join(','),
    fields: 'id,asn_v4,asn_v6',
    page_size: '100',
  });
  try {
    const res = await fetchFn(`${RIPE_ATLAS_BASE}/probes/?${q.toString()}`, {
      headers: { authorization: `Key ${apiKey}`, accept: 'application/json' },
    });
    if (!res.ok) return out;
    const body = (await res.json()) as { results?: unknown };
    if (!Array.isArray(body.results)) return out;
    for (const raw of body.results as Array<Record<string, unknown>>) {
      const id = typeof raw.id === 'number' ? raw.id : Number(raw.id);
      const asn = asnOfRow(raw, af);
      if (Number.isFinite(id) && asn) out[id] = asn;
    }
  } catch {
    // Registry unavailable: results stay network-less on purpose.
  }
  return out;
}

export async function ripeAtlasPoll(
  fetchFn: FetchLike,
  apiKey: string,
  started: AtlasStarted,
  expectedPerCountry: number,
): Promise<{ status: 'running' | 'finished'; results: ProbeResult[] }> {
  const bodies: Array<{ country: string; body: unknown }> = [];
  let running = false;
  for (const [country, id] of Object.entries(started.measurements)) {
    const res = await fetchFn(`${RIPE_ATLAS_BASE}/measurements/${id}/results/`, {
      headers: { authorization: `Key ${apiKey}`, accept: 'application/json' },
    });
    if (!res.ok) throw new Error(`ripe atlas results (${country}): ${res.status}`);
    bodies.push({ country, body: await res.json() });
  }
  // One registry lookup for every probe whose ASN is not known yet.
  const cache = (started.asnByProbe ??= {});
  const missing = [
    ...new Set(bodies.flatMap((b) => probeIdsOf(b.body)).filter((id) => cache[id] === undefined)),
  ];
  if (missing.length > 0) {
    Object.assign(cache, await fetchAtlasProbeAsns(fetchFn, apiKey, missing, started.af));
  }
  const results: ProbeResult[] = [];
  for (const { country, body } of bodies) {
    const parsed = parseRipeAtlasResults(body, country, {
      af: started.af,
      asnByProbe: cache,
      protocol: started.protocol,
    });
    if (parsed.length < Math.max(1, expectedPerCountry)) running = true;
    results.push(...parsed);
  }
  return { status: running ? 'running' : 'finished', results };
}
