/**
 * RIPE Atlas (optional tertiary source): one-off `sslcert` measurements per
 * country (API key + credits). One measurement per requested country keeps the
 * result → country mapping trivial (no per-probe lookups). Vantage class is
 * `unknown` (Atlas probes are mixed home/hosting; the API does not say).
 */
import { shortError, type ProbeRequestOptions, type ProbeResult, type ProbeTarget } from './types';
import type { FetchLike } from './checkhost';

export const RIPE_ATLAS_BASE = 'https://atlas.ripe.net/api/v2';

export interface AtlasStarted {
  /** country → measurement id */
  measurements: Record<string, number>;
}

export function ripeAtlasBody(target: ProbeTarget, country: string, requested: number) {
  return {
    definitions: [
      {
        type: 'sslcert',
        af: target.ipVersion,
        target: target.address,
        port: target.port,
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
  return { measurements };
}

/**
 * Parse one measurement's `/results/`: `rt`/`cert` = reachable; a TLS `alert`
 * ALSO means reachable (the peer answered on the port — a REALITY edge will not
 * present a certificate for a random SNI; same rule as the internal probe);
 * only `err` (connection-level) = not.
 */
export function parseRipeAtlasResults(body: unknown, country: string): ProbeResult[] {
  if (!Array.isArray(body)) return [];
  const out: ProbeResult[] = [];
  for (const raw of body as Array<Record<string, unknown>>) {
    const prb = raw.prb_id != null ? `prb-${String(raw.prb_id)}` : undefined;
    const base = { country, network: prb, vantageClass: 'unknown' as const };
    if (raw.err !== undefined) {
      out.push({ ...base, ok: false, error: shortError(raw.err) });
    } else if (raw.alert !== undefined) {
      const rt = Number(raw.rt);
      out.push({
        ...base,
        ok: true,
        rttMs: Number.isFinite(rt) ? Math.round(rt) : undefined,
        error: 'tls_alert',
      });
    } else if (raw.rt !== undefined || Array.isArray(raw.cert)) {
      const rt = Number(raw.rt);
      out.push({ ...base, ok: true, rttMs: Number.isFinite(rt) ? Math.round(rt) : undefined });
    }
  }
  return out;
}

export async function ripeAtlasPoll(
  fetchFn: FetchLike,
  apiKey: string,
  started: AtlasStarted,
  expectedPerCountry: number,
): Promise<{ status: 'running' | 'finished'; results: ProbeResult[] }> {
  const results: ProbeResult[] = [];
  let running = false;
  for (const [country, id] of Object.entries(started.measurements)) {
    const res = await fetchFn(`${RIPE_ATLAS_BASE}/measurements/${id}/results/`, {
      headers: { authorization: `Key ${apiKey}`, accept: 'application/json' },
    });
    if (!res.ok) throw new Error(`ripe atlas results (${country}): ${res.status}`);
    const parsed = parseRipeAtlasResults(await res.json(), country);
    if (parsed.length < Math.max(1, expectedPerCountry)) running = true;
    results.push(...parsed);
  }
  return { status: running ? 'running' : 'finished', results };
}
