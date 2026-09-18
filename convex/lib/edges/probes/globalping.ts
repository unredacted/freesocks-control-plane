/**
 * Globalping (https://globalping.io) via the official `globalping` SDK. A `tcp`
 * target is a TCP "ping" from probes selected by country; a `tls`/`https`
 * target is an `http` measurement over HTTPS (Globalping has no bare-handshake
 * type, so the handshake is observed through the request: an HTTP status of any
 * kind means the handshake completed, a connect/TLS error means it did not).
 * The SDK client is injected so tests (and the isolate runtime) never construct
 * it; only the "use node" action does. Results carry the probe's
 * country/ASN/network and its tags, which classify the vantage
 * (`eyeball-network` vs `datacenter-network`).
 */
import {
  isBareConnect,
  normalizeCountry,
  shortError,
  type ProbeRequestOptions,
  type ProbeResult,
  type ProbeStarted,
  type ProbePoll,
  type ProbeTarget,
  type VantageClass,
} from './types';

/** The slice of the SDK surface this module uses (structural, for injection). */
export interface GlobalpingLike {
  createMeasurement(req: unknown): Promise<{ ok: boolean; data?: unknown; response?: Response }>;
  getMeasurement(id: string): Promise<{ ok: boolean; data?: unknown; response?: Response }>;
}

/** Which Globalping measurement type a probe protocol maps to. */
export type GlobalpingKind = 'ping' | 'http';

export function globalpingKind(target: Pick<ProbeTarget, 'protocol'>): GlobalpingKind {
  return isBareConnect(target.protocol) ? 'ping' : 'http';
}

/** `ipVersion` is only sent when FCP asked for a family: a name is left to the resolver. */
function ipVersionOf(target: ProbeTarget): { ipVersion?: 4 | 6 } {
  if (target.requestedFamily === 4 || target.requestedFamily === 6)
    return { ipVersion: target.requestedFamily };
  return {};
}

export function globalpingRequest(target: ProbeTarget, opts: ProbeRequestOptions) {
  const limit = Math.max(1, Math.min(opts.perCountryLimit, 10));
  const locations = opts.countries.map((country) => ({
    country,
    limit,
    ...(opts.preferEyeball ? { tags: ['eyeball-network'] } : {}),
  }));
  if (globalpingKind(target) === 'http') {
    return {
      type: 'http' as const,
      target: target.address,
      inProgressUpdates: false,
      locations,
      measurementOptions: {
        protocol: 'HTTPS' as const,
        port: target.port,
        // GET / with the target as Host/SNI: an L7 front answers only for its
        // own name. Nothing of the body is kept, only the status.
        request: { method: 'GET' as const, path: '/', host: target.address },
        ...ipVersionOf(target),
      },
    };
  }
  return {
    type: 'ping' as const,
    target: target.address,
    inProgressUpdates: false,
    locations,
    measurementOptions: {
      protocol: 'TCP' as const,
      port: target.port,
      packets: 3,
      ...ipVersionOf(target),
    },
  };
}

function vantageOf(tags: unknown): VantageClass {
  if (!Array.isArray(tags)) return 'unknown';
  const t = tags.map((x) => String(x).toLowerCase());
  if (t.includes('eyeball-network')) return 'eyeball';
  if (t.includes('datacenter-network')) return 'datacenter';
  return 'unknown';
}

interface ResultItem {
  probe?: { country?: unknown; asn?: unknown; network?: unknown; tags?: unknown };
  result?: {
    status?: unknown;
    stats?: { loss?: unknown; avg?: unknown };
    statusCode?: unknown;
    timings?: { total?: unknown };
    rawOutput?: unknown;
  };
}

/** A generic User-Agent: the measurement service learns nothing about who probes what. */
export const GLOBALPING_USER_AGENT = 'tcp-reachability-probe/1.0';

function probeBase(raw: ResultItem, country: string) {
  const asn = raw.probe?.asn != null ? `AS${String(raw.probe.asn)}` : undefined;
  const network = typeof raw.probe?.network === 'string' ? raw.probe.network : undefined;
  return { country, asn, network, vantageClass: vantageOf(raw.probe?.tags) };
}

/**
 * Map one finished measurement's result items to probe results. Only a probe
 * that actually ran the test is evidence: `offline` / `in-progress` probes and
 * `failed` ones (a PROBE-side error: the probe could not run the command) are
 * dropped rather than counted as an unreachable target.
 */
export function parseGlobalpingResults(items: unknown): ProbeResult[] {
  if (!Array.isArray(items)) return [];
  const out: ProbeResult[] = [];
  for (const raw of items as ResultItem[]) {
    const country = normalizeCountry(raw.probe?.country);
    if (!country) continue;
    const status = String(raw.result?.status ?? '');
    if (status !== 'finished') continue;
    const base = probeBase(raw, country);
    const loss = Number(raw.result?.stats?.loss ?? 100);
    const ok = Number.isFinite(loss) && loss < 100;
    const avg = raw.result?.stats?.avg;
    out.push({
      ...base,
      ok,
      rttMs: ok && typeof avg === 'number' ? Math.round(avg) : undefined,
      error: ok ? undefined : 'no_reply',
    });
  }
  return out;
}

/**
 * `http` measurement results. ANY HTTP status means the connection and the TLS
 * handshake completed, so it is reachable for both `https` and `tls` (the
 * handshake is what `tls` asked about; the status code is not judged). A
 * `failed` item is a connect/TLS error, which IS evidence of unreachability
 * here, unlike the ping parser, where `failed` means the probe could not run
 * the command at all. The raw output is never stored: only a short class,
 * scrubbed of the target's own name.
 */
export function parseGlobalpingHttpResults(items: unknown, redact: readonly string[] = []) {
  if (!Array.isArray(items)) return [];
  const out: ProbeResult[] = [];
  for (const raw of items as ResultItem[]) {
    const country = normalizeCountry(raw.probe?.country);
    if (!country) continue;
    const status = String(raw.result?.status ?? '');
    const base = probeBase(raw, country);
    const code = Number(raw.result?.statusCode);
    if (status === 'finished' && Number.isFinite(code) && code > 0) {
      const total = Number(raw.result?.timings?.total);
      out.push({
        ...base,
        ok: true,
        rttMs: Number.isFinite(total) ? Math.round(total) : undefined,
      });
    } else if (status === 'failed') {
      out.push({ ...base, ok: false, error: shortError(raw.result?.rawOutput, 60, redact) });
    }
    // else: still running, offline, or an answer with no status code: no evidence.
  }
  return out;
}

export function isMeasurementFinished(data: unknown): boolean {
  return !!data && typeof data === 'object' && (data as { status?: unknown }).status === 'finished';
}

export async function globalpingStart(
  client: GlobalpingLike,
  target: ProbeTarget,
  opts: ProbeRequestOptions,
): Promise<ProbeStarted> {
  const res = await client.createMeasurement(globalpingRequest(target, opts));
  if (!res.ok || !res.data) {
    throw new Error(`globalping create failed: ${res.response?.status ?? 'no response'}`);
  }
  const id = (res.data as { id?: unknown }).id;
  if (typeof id !== 'string') throw new Error('globalping create: no measurement id');
  return { externalId: id };
}

export async function globalpingPoll(
  client: GlobalpingLike,
  id: string,
  opts: { kind?: GlobalpingKind; redact?: readonly string[] } = {},
): Promise<ProbePoll> {
  const res = await client.getMeasurement(id);
  if (!res.ok || !res.data) {
    throw new Error(`globalping get failed: ${res.response?.status ?? 'no response'}`);
  }
  const data = res.data as { status?: unknown; results?: unknown };
  if (!isMeasurementFinished(data)) return { status: 'running', results: [] };
  return {
    status: 'finished',
    results:
      (opts.kind ?? 'ping') === 'http'
        ? parseGlobalpingHttpResults(data.results, opts.redact ?? [])
        : parseGlobalpingResults(data.results),
  };
}
