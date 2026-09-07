/**
 * check-host.net: keyless TCP checks from its public node set. The API is
 * poll-based (`check-tcp` → request id, `check-result/<id>` until every node
 * answered) and REQUIRES `Accept: application/json`. Limits are undocumented,
 * so callers keep this to a few requests per minute and back off on non-200.
 * Vantages are small hosting networks → classified `datacenter`.
 */
import {
  normalizeCountry,
  shortError,
  type ProbeRequestOptions,
  type ProbeResult,
  type ProbeStarted,
  type ProbePoll,
  type ProbeTarget,
} from './types';

export const CHECKHOST_BASE = 'https://check-host.net';

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface CheckhostNode {
  host: string;
  country: string;
  asn?: string;
}

/** Parse `GET /nodes/hosts` → the node list with countries. */
export function parseCheckhostNodes(body: unknown): CheckhostNode[] {
  const nodes = (body as { nodes?: Record<string, unknown> } | null)?.nodes;
  if (!nodes || typeof nodes !== 'object') return [];
  const out: CheckhostNode[] = [];
  for (const [host, info] of Object.entries(nodes)) {
    const loc = (info as { location?: unknown; asn?: unknown } | null)?.location;
    const country = Array.isArray(loc) ? normalizeCountry(loc[0]) : null;
    if (!country) continue;
    const asnRaw = (info as { asn?: unknown }).asn;
    out.push({
      host,
      country,
      asn: typeof asnRaw === 'string' ? asnRaw.toUpperCase() : undefined,
    });
  }
  return out;
}

/** Pick up to `perCountryLimit` nodes per requested country. */
export function selectCheckhostNodes(
  nodes: readonly CheckhostNode[],
  countries: readonly string[],
  perCountryLimit: number,
): CheckhostNode[] {
  const out: CheckhostNode[] = [];
  for (const c of countries) {
    out.push(...nodes.filter((n) => n.country === c).slice(0, Math.max(1, perCountryLimit)));
  }
  return out;
}

export async function checkhostNodes(fetchFn: FetchLike): Promise<CheckhostNode[]> {
  const res = await fetchFn(`${CHECKHOST_BASE}/nodes/hosts`, {
    headers: { accept: 'application/json' },
  });
  if (!res.ok) throw new Error(`check-host nodes: ${res.status}`);
  return parseCheckhostNodes(await res.json());
}

/** Start a TCP check on the selected nodes; the response also maps node → country. */
export async function checkhostStart(
  fetchFn: FetchLike,
  target: ProbeTarget,
  opts: ProbeRequestOptions,
  nodes: readonly CheckhostNode[],
): Promise<ProbeStarted & { nodeCountries: Record<string, string> }> {
  const selected = selectCheckhostNodes(nodes, opts.countries, opts.perCountryLimit);
  if (selected.length === 0) throw new Error('check-host: no nodes for the requested countries');
  const hostPort =
    target.ipVersion === 6
      ? `[${target.address}]:${target.port}`
      : `${target.address}:${target.port}`;
  const q = new URLSearchParams({ host: hostPort });
  for (const n of selected) q.append('node', n.host);
  const res = await fetchFn(`${CHECKHOST_BASE}/check-tcp?${q.toString()}`, {
    headers: { accept: 'application/json' },
  });
  if (!res.ok) throw new Error(`check-host check-tcp: ${res.status}`);
  const body = (await res.json()) as { ok?: unknown; request_id?: unknown; nodes?: unknown };
  if (typeof body.request_id !== 'string') throw new Error('check-host: no request_id');
  const nodeCountries: Record<string, string> = {};
  for (const n of selected) nodeCountries[n.host] = n.country;
  if (body.nodes && typeof body.nodes === 'object') {
    for (const [host, info] of Object.entries(body.nodes as Record<string, unknown>)) {
      const c = Array.isArray(info) ? normalizeCountry(info[0]) : null;
      if (c) nodeCountries[host] = c;
    }
  }
  return { externalId: body.request_id, nodeCountries };
}

/**
 * Parse `GET /check-result/<id>`: per node `null` (pending), `[{time}]` (ok) or
 * `[{error}]` (fail). Pending nodes leave the poll `running`.
 */
export function parseCheckhostResult(
  body: unknown,
  nodeCountries: Record<string, string>,
  nodeAsns: Record<string, string | undefined> = {},
): ProbePoll {
  if (!body || typeof body !== 'object') return { status: 'running', results: [] };
  const results: ProbeResult[] = [];
  let pending = false;
  for (const [host, val] of Object.entries(body as Record<string, unknown>)) {
    const country = nodeCountries[host];
    if (!country) continue;
    if (val === null || val === undefined) {
      pending = true;
      continue;
    }
    const first = Array.isArray(val) ? (val[0] as Record<string, unknown> | null) : null;
    const base = {
      country,
      asn: nodeAsns[host],
      network: host.split('.')[0],
      vantageClass: 'datacenter' as const,
    };
    if (first && typeof first === 'object' && 'error' in first) {
      results.push({ ...base, ok: false, error: shortError(first.error) });
    } else if (first && typeof first === 'object' && 'time' in first) {
      const t = Number(first.time);
      results.push({
        ...base,
        ok: true,
        rttMs: Number.isFinite(t) ? Math.round(t * 1000) : undefined,
      });
    } else {
      results.push({ ...base, ok: false, error: 'unparsed' });
    }
  }
  return { status: pending ? 'running' : 'finished', results };
}

export async function checkhostPoll(
  fetchFn: FetchLike,
  id: string,
  nodeCountries: Record<string, string>,
  nodeAsns: Record<string, string | undefined> = {},
): Promise<ProbePoll> {
  const res = await fetchFn(`${CHECKHOST_BASE}/check-result/${encodeURIComponent(id)}`, {
    headers: { accept: 'application/json' },
  });
  if (!res.ok) throw new Error(`check-host check-result: ${res.status}`);
  return parseCheckhostResult(await res.json(), nodeCountries, nodeAsns);
}
