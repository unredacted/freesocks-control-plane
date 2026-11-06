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
  vantageHasNoRoute,
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
  /** `GET /v1/limits` (optional in fakes: no preflight without it). */
  getLimits?(): Promise<{ ok: boolean; data?: unknown; response?: Response }>;
  /** `GET /v1/probes`, free (optional in fakes: name checks plan nothing without it). */
  listProbes?(): Promise<{ ok: boolean; data?: unknown; response?: Response }>;
}

/** Probes asked for by one request (what Globalping's rate limit counts). */
export function globalpingTestsOf(req: { locations: ReadonlyArray<{ limit: number }> }): number {
  return req.locations.reduce((n, l) => n + l.limit, 0);
}

/**
 * What Globalping itself says about the allowance FCP's token (or, without
 * one, FCP's address) has: the free tests of the current hour window and the
 * credits left. Read from its `GET /v1/limits` answer or from a create's
 * response headers. FCP's own cap (`probe.globalpingTestsPerHour`) is a
 * separate number; the Probes page shows both so they can be told apart.
 */
export interface GlobalpingReading {
  /** `user` with a token, `ip` without one (limits answers only). */
  type?: 'user' | 'ip';
  /** Free tests in the window, spent or not. */
  limit: number;
  /** Free tests left in the window. */
  remaining: number;
  /**
   * Seconds until the window resets. The window opens with the first test
   * spent, so 0 with nothing spent means no window is open.
   */
  resetSec: number;
  /** Credits left (with a token). Globalping calls the header's figure approximate. */
  credits?: number;
  /** Credits this one request spent: tests past the free allowance (create headers only). */
  creditsConsumed?: number;
}

/** A finite, non-negative whole number, else undefined. */
function count(x: unknown): number | undefined {
  if (x === null || x === undefined || x === '') return undefined;
  const n = Number(x);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : undefined;
}

/** A `GET /v1/limits` answer as a reading; null for any other shape. */
export function readingFromLimits(data: unknown): GlobalpingReading | null {
  if (!data || typeof data !== 'object') return null;
  const d = data as {
    rateLimit?: { measurements?: { create?: Record<string, unknown> } };
    credits?: { remaining?: unknown };
  };
  const c = d.rateLimit?.measurements?.create;
  const limit = count(c?.limit);
  const remaining = count(c?.remaining);
  if (limit === undefined || remaining === undefined) return null;
  const credits = count(d.credits?.remaining);
  return {
    ...(c?.type === 'user' || c?.type === 'ip' ? { type: c.type } : {}),
    limit,
    remaining,
    resetSec: count(c?.reset) ?? 0,
    ...(credits !== undefined ? { credits } : {}),
  };
}

/** The headers of a create (`X-RateLimit-*`, `X-Credits-*`) as a reading; null without them. */
export function readingFromHeaders(
  headers: { get(name: string): string | null } | null | undefined,
): GlobalpingReading | null {
  if (!headers || typeof headers.get !== 'function') return null;
  const limit = count(headers.get('x-ratelimit-limit'));
  const remaining = count(headers.get('x-ratelimit-remaining'));
  if (limit === undefined || remaining === undefined) return null;
  const credits = count(headers.get('x-credits-remaining'));
  const consumed = count(headers.get('x-credits-consumed'));
  return {
    limit,
    remaining,
    resetSec: count(headers.get('x-ratelimit-reset')) ?? 0,
    ...(credits !== undefined ? { credits } : {}),
    ...(consumed !== undefined && consumed > 0 ? { creditsConsumed: consumed } : {}),
  };
}

/** Globalping's own answer about the allowance; null when it cannot be read. */
export async function globalpingLimits(client: GlobalpingLike): Promise<GlobalpingReading | null> {
  if (!client.getLimits) return null;
  try {
    const res = await client.getLimits();
    return res.ok ? readingFromLimits(res.data) : null;
  } catch {
    return null;
  }
}

/** One reading and when it was taken. */
export interface TimedReading {
  at: number;
  reading: GlobalpingReading;
}

/**
 * The same client, also handing every answer about the allowance to `sink`:
 * each limits read and each create's headers (refused creates too). The
 * action saves what it collected once it is done (`probes.noteGlobalping`).
 */
export function recordingClient(
  client: GlobalpingLike,
  sink: TimedReading[],
  now: () => number = Date.now,
): GlobalpingLike {
  const getLimits = client.getLimits?.bind(client);
  const listProbes = client.listProbes?.bind(client);
  return {
    createMeasurement: async (req) => {
      const res = await client.createMeasurement(req);
      const reading = readingFromHeaders(res.response?.headers);
      if (reading) sink.push({ at: now(), reading });
      return res;
    },
    getMeasurement: (id) => client.getMeasurement(id),
    ...(getLimits
      ? {
          getLimits: async () => {
            const res = await getLimits();
            const reading = res.ok ? readingFromLimits(res.data) : null;
            if (reading) sink.push({ at: now(), reading });
            return res;
          },
        }
      : {}),
    // Free: nothing to record.
    ...(listProbes ? { listProbes } : {}),
  };
}

/** Whether `tests` fit a reading: the free tests left in the window plus any credits. */
export function readingFits(r: GlobalpingReading, tests: number): boolean {
  return r.remaining + (r.credits ?? 0) >= tests;
}

/**
 * Whether the measurement fits what Globalping still allows: the rate-limit
 * points left in the window plus any credits. `null` when it cannot be told
 * (no limits call, an error, an unexpected shape): the create itself decides.
 */
export async function globalpingFits(
  client: GlobalpingLike,
  tests: number,
): Promise<boolean | null> {
  const r = await globalpingLimits(client);
  return r ? readingFits(r, tests) : null;
}

/** Which Globalping measurement type a probe protocol maps to. */
export type GlobalpingKind = 'ping' | 'http';

export function globalpingKind(target: Pick<ProbeTarget, 'protocol'>): GlobalpingKind {
  return isBareConnect(target.protocol) ? 'ping' : 'http';
}

/**
 * `ipVersion` pins the family a NAME resolves to, and only a name: Globalping
 * refuses it next to an IP literal (400, "not allowed when target is not a
 * domain"), so a literal's own family is the family. A name FCP asks for with
 * `any` is left to the resolver.
 */
function ipVersionOf(target: ProbeTarget): { ipVersion?: 4 | 6 } {
  if (
    target.addressKind === 'name' &&
    (target.requestedFamily === 4 || target.requestedFamily === 6)
  )
    return { ipVersion: target.requestedFamily };
  return {};
}

export function globalpingRequest(target: ProbeTarget, opts: ProbeRequestOptions) {
  const limit = Math.max(1, Math.min(opts.perCountryLimit, 10));
  const locations = [
    ...opts.countries.map((country) => ({
      country,
      limit,
      ...(opts.preferEyeball ? { tags: ['eyeball-network'] } : {}),
    })),
    // A control needs any vantage that answers, not a residential one.
    ...(opts.controls ?? []).map((country) => ({ country, limit: 1 })),
  ];
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
 * the command at all. A probe whose own error is "no route" could not test
 * (`vantageHasNoRoute`) and is dropped. The raw output is never stored: only a
 * short class, scrubbed of the target's own name.
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
    } else if (status === 'failed' && !vantageHasNoRoute(raw.result?.rawOutput)) {
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
