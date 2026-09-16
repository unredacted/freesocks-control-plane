/**
 * check-host.net: keyless checks from its public node set. The API is
 * poll-based (`check-tcp` / `check-http` → request id, `check-result/<id>`
 * until every node answered) and REQUIRES `Accept: application/json`. Limits
 * are undocumented, so callers keep this to a few requests per minute and back
 * off on non-200. Vantages are small hosting networks → classified
 * `datacenter`.
 *
 * `tcp` targets use `check-tcp` (a bare connect). `tls`/`https` targets use
 * `check-http` against `https://<name>:<port>/`: any HTTP answer means the
 * connection and handshake completed.
 */
import {
  normalizeCountry,
  shortError,
  targetHost,
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

/** Which check-host endpoint a probe protocol maps to. */
export function checkhostEndpoint(
  target: Pick<ProbeTarget, 'protocol'>,
): 'check-tcp' | 'check-http' {
  return target.protocol === 'tcp' ? 'check-tcp' : 'check-http';
}

/** What goes in the `host` parameter: `host:port` for tcp, a URL for http. */
export function checkhostHostParam(target: ProbeTarget): string {
  const hostPort = `${targetHost(target)}:${target.port}`;
  return checkhostEndpoint(target) === 'check-http' ? `https://${hostPort}/` : hostPort;
}

/** Start a check on the selected nodes; the response also maps node → country. */
export async function checkhostStart(
  fetchFn: FetchLike,
  target: ProbeTarget,
  opts: ProbeRequestOptions,
  nodes: readonly CheckhostNode[],
): Promise<ProbeStarted & { nodeCountries: Record<string, string> }> {
  const selected = selectCheckhostNodes(nodes, opts.countries, opts.perCountryLimit);
  if (selected.length === 0) throw new Error('check-host: no nodes for the requested countries');
  const endpoint = checkhostEndpoint(target);
  const q = new URLSearchParams({ host: checkhostHostParam(target) });
  for (const n of selected) q.append('node', n.host);
  const res = await fetchFn(`${CHECKHOST_BASE}/${endpoint}?${q.toString()}`, {
    headers: { accept: 'application/json' },
  });
  if (!res.ok) throw new Error(`check-host ${endpoint}: ${res.status}`);
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
 * Parse `GET /check-result/<id>`: per node `null` (pending), then either the
 * `check-tcp` shape (`[{time}]` ok, `[{error}]` fail) or the `check-http` shape
 * (`[[1, seconds, 'OK', '200', ip]]` ok, `[[0, seconds, '<error>']]` fail).
 * Pending nodes leave the poll `running`. A node that answered with no result
 * (`[null]`, an empty array or an unparsable shape) could not run the check: it
 * is dropped, never counted as a failed target. `redact` scrubs the target's
 * own spelling out of stored error text.
 */
export function parseCheckhostResult(
  body: unknown,
  nodeCountries: Record<string, string>,
  nodeAsns: Record<string, string | undefined> = {},
  redact: readonly string[] = [],
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
    const first: unknown = Array.isArray(val) ? val[0] : null;
    const base = {
      country,
      asn: nodeAsns[host],
      network: host.split('.')[0],
      vantageClass: 'datacenter' as const,
    };
    if (Array.isArray(first)) {
      // check-http: [ok, seconds, message, statusCode, ip]. Any HTTP answer is
      // a completed connection + handshake; `0` is a connect/TLS error.
      const ok = Number(first[0]) === 1;
      const t = Number(first[1]);
      results.push({
        ...base,
        ok,
        ...(ok
          ? { rttMs: Number.isFinite(t) ? Math.round(t * 1000) : undefined }
          : { error: shortError(first[2] ?? 'http_failed', 60, redact) }),
      });
    } else if (first && typeof first === 'object' && 'error' in first) {
      results.push({
        ...base,
        ok: false,
        error: shortError((first as { error: unknown }).error, 60, redact),
      });
    } else if (first && typeof first === 'object' && 'time' in first) {
      const t = Number((first as { time: unknown }).time);
      results.push({
        ...base,
        ok: true,
        rttMs: Number.isFinite(t) ? Math.round(t * 1000) : undefined,
      });
    }
    // else: node-side error / unparsed → no evidence either way.
  }
  return { status: pending ? 'running' : 'finished', results };
}

export async function checkhostPoll(
  fetchFn: FetchLike,
  id: string,
  nodeCountries: Record<string, string>,
  nodeAsns: Record<string, string | undefined> = {},
  redact: readonly string[] = [],
): Promise<ProbePoll> {
  const res = await fetchFn(`${CHECKHOST_BASE}/check-result/${encodeURIComponent(id)}`, {
    headers: { accept: 'application/json' },
  });
  if (!res.ok) throw new Error(`check-host check-result: ${res.status}`);
  return parseCheckhostResult(await res.json(), nodeCountries, nodeAsns, redact);
}
