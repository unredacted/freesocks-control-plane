/**
 * Globalping (https://globalping.io) via the official `globalping` SDK: a TCP
 * "ping" from probes selected by country. The SDK client is injected so tests
 * (and the isolate runtime) never construct it; only the "use node" action
 * does. Results carry the probe's country/ASN/network and its tags, which
 * classify the vantage (`eyeball-network` vs `datacenter-network`).
 */
import {
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

export function globalpingRequest(target: ProbeTarget, opts: ProbeRequestOptions) {
  const limit = Math.max(1, Math.min(opts.perCountryLimit, 10));
  return {
    type: 'ping' as const,
    target: target.address,
    inProgressUpdates: false,
    locations: opts.countries.map((country) => ({
      country,
      limit,
      ...(opts.preferEyeball ? { tags: ['eyeball-network'] } : {}),
    })),
    measurementOptions: {
      protocol: 'TCP' as const,
      port: target.port,
      packets: 3,
      ipVersion: target.ipVersion,
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
  result?: { status?: unknown; stats?: { loss?: unknown; avg?: unknown }; rawOutput?: unknown };
}

/** Map one finished measurement's result items to probe results (offline probes are dropped). */
export function parseGlobalpingResults(items: unknown): ProbeResult[] {
  if (!Array.isArray(items)) return [];
  const out: ProbeResult[] = [];
  for (const raw of items as ResultItem[]) {
    const country = normalizeCountry(raw.probe?.country);
    if (!country) continue;
    const status = String(raw.result?.status ?? '');
    if (status === 'offline' || status === 'in-progress') continue;
    const asn = raw.probe?.asn != null ? `AS${String(raw.probe.asn)}` : undefined;
    const network = typeof raw.probe?.network === 'string' ? raw.probe.network : undefined;
    const base = { country, asn, network, vantageClass: vantageOf(raw.probe?.tags) };
    if (status === 'finished') {
      const loss = Number(raw.result?.stats?.loss ?? 100);
      const ok = Number.isFinite(loss) && loss < 100;
      const avg = raw.result?.stats?.avg;
      out.push({
        ...base,
        ok,
        rttMs: ok && typeof avg === 'number' ? Math.round(avg) : undefined,
        error: ok ? undefined : 'no_reply',
      });
    } else {
      out.push({ ...base, ok: false, error: shortError(status || 'failed') });
    }
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

export async function globalpingPoll(client: GlobalpingLike, id: string): Promise<ProbePoll> {
  const res = await client.getMeasurement(id);
  if (!res.ok || !res.data) {
    throw new Error(`globalping get failed: ${res.response?.status ?? 'no response'}`);
  }
  const data = res.data as { status?: unknown; results?: unknown };
  return {
    status: isMeasurementFinished(data) ? 'finished' : 'running',
    results: isMeasurementFinished(data) ? parseGlobalpingResults(data.results) : [],
  };
}
