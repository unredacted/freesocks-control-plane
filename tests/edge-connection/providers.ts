/**
 * The edge providers of the edge connection test: FCP's REAL adapters (UpCloud
 * at L4, Cloudflare at L7) talk to fake provider APIs, and the fakes wire the
 * real edges of the stack.
 *
 *  - UpCloud: a load-balancer create wires the TCP forwarder's frontend port to
 *    exactly the backend member FCP asked for, and the floating address handed
 *    back is the forwarder's client-network address;
 *  - Cloudflare: a proxied DNS record under the zone is what a CDN front is;
 *    every name of the zone already lands on the stack's front (its resolver
 *    answers the whole zone), which proxies to the origin hostname. The fake
 *    records what FCP asked the record to point at.
 *
 * Every other request goes to the real network only when its host is on the
 * allowlist (the panel); anything else is refused and recorded, so FCP cannot
 * reach the internet from this test without the test noticing.
 */
import { vi } from 'vitest';
import { ADDR, wireForwarder } from './stack';

export interface Call {
  method: string;
  path: string;
  body: unknown;
}

const json = (obj: unknown, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json' } });

async function capture(input: string | URL | Request, init: RequestInit = {}) {
  const url = new URL(
    typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
  );
  const method = (init.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
  let raw: string | undefined;
  if (typeof init.body === 'string') raw = init.body;
  else if (input instanceof Request && init.body === undefined)
    raw = await input
      .clone()
      .text()
      .catch(() => undefined);
  let body: unknown;
  if (raw)
    try {
      body = JSON.parse(raw);
    } catch {
      body = raw;
    }
  return { url, method, body };
}

interface LoadBalancer {
  uuid: string;
  name: string;
  zone: string;
  operational_state: string;
  frontends: Array<{ name: string; port: number; default_backend: string }>;
  backends: Array<{ name: string; members: Array<{ ip: string; port: number }> }>;
  ip_addresses: Array<{ address: string }>;
}

interface DnsRecord {
  id: string;
  name: string;
  type: string;
  content: string;
  proxied: boolean;
  ttl: number;
  comment: string | null;
  created_on: string;
  modified_on: string;
}

export function installProviderFakes(opts: { allowHosts: string[]; l7Zone: string }) {
  const realFetch = globalThis.fetch.bind(globalThis);
  const calls = { upcloud: [] as Call[], cloudflare: [] as Call[] };
  const refused: string[] = [];
  const lbs = new Map<string, LoadBalancer>();
  const records = new Map<string, DnsRecord>();
  let seq = 0;

  async function upcloud(method: string, path: string, body: any): Promise<Response> {
    calls.upcloud.push({ method, path, body });
    const p = path.replace(/^\/1\.3/, '');
    if (p === '/account' && method === 'GET') return json({ account: { username: 'ec-test' } });
    if (p === '/load-balancer/plans' && method === 'GET')
      return json({ plans: [{ name: 'development' }] });
    if (p === '/load-balancer' && method === 'GET') return json([...lbs.values()]);
    if (p === '/load-balancer' && method === 'POST') {
      const uuid = `0a000000-0000-4000-8000-${String(++seq).padStart(12, '0')}`;
      const lb: LoadBalancer = {
        uuid,
        name: body.name,
        zone: body.zone,
        operational_state: 'running',
        frontends: body.frontends ?? [],
        backends: body.backends ?? [],
        ip_addresses: [],
      };
      // What a provider's LB does: frontend port -> the backend members.
      for (const f of lb.frontends) {
        const member = lb.backends.find((b) => b.name === f.default_backend)?.members[0];
        if (!member) return json({ error: { error_code: 'BACKEND_INVALID' } }, 400);
        await wireForwarder(f.port, `${member.ip}:${member.port}`);
      }
      lbs.set(uuid, lb);
      return json(lb, 201);
    }
    if (p === '/ip_address' && method === 'GET')
      return json({
        ip_addresses: {
          ip_address: [...lbs.values()].flatMap((lb) =>
            lb.ip_addresses.map((a) => ({ address: a.address, floating: 'yes', family: 'IPv4' })),
          ),
        },
      });
    if (p === '/ip_address' && method === 'POST')
      return json(
        { ip_address: { address: ADDR.forwarder.client, floating: 'yes', family: 'IPv4' } },
        201,
      );
    const attach = p.match(/^\/load-balancer\/([^/]+)\/ip-addresses$/);
    if (attach && method === 'POST') {
      const lb = lbs.get(attach[1]!);
      if (!lb) return json({ error: { error_code: 'LB_NOT_FOUND' } }, 404);
      lb.ip_addresses.push(...(body.ip_addresses ?? []));
      return json({});
    }
    const one = p.match(/^\/load-balancer\/([^/]+)$/);
    if (one && method === 'GET') {
      const lb = lbs.get(one[1]!);
      return lb ? json(lb) : json({ error: { error_code: 'LB_NOT_FOUND' } }, 404);
    }
    if (one && method === 'DELETE') {
      lbs.delete(one[1]!);
      return new Response(null, { status: 204 });
    }
    if (/^\/ip_address\/[^/]+$/.test(p) && method === 'DELETE')
      return new Response(null, { status: 204 });
    refused.push(`upcloud ${method} ${p}`);
    return json({ error: { error_code: 'NOT_FOUND' } }, 404);
  }

  const envelope = (result: unknown, status = 200, extra: Record<string, unknown> = {}) =>
    json({ success: status < 300, errors: [], messages: [], result, ...extra }, status);

  async function cloudflare(
    method: string,
    path: string,
    query: URLSearchParams,
    body: any,
  ): Promise<Response> {
    calls.cloudflare.push({ method, path, body });
    const p = path.replace(/^\/client\/v4/, '');
    const zone = p.match(/^\/zones\/([^/]+)(\/.*)?$/);
    if (!zone) {
      refused.push(`cloudflare ${method} ${p}`);
      return envelope(null, 404);
    }
    const rest = zone[2] ?? '';
    if (rest === '/ssl/certificate_packs' && method === 'GET')
      return envelope(
        [
          {
            id: 'ec-pack',
            type: 'universal',
            hosts: [opts.l7Zone, `*.${opts.l7Zone}`],
            status: 'active',
          },
        ],
        200,
        { result_info: { page: 1, per_page: 50, count: 1, total_count: 1, total_pages: 1 } },
      );
    if (rest === '/dns_records' && method === 'GET') {
      const name = query.get('name.exact') ?? query.get('name');
      const list = [...records.values()].filter((r) => !name || r.name === name);
      return envelope(list, 200, {
        result_info: { page: 1, per_page: 100, count: list.length, total_count: list.length },
      });
    }
    if (rest === '/dns_records' && method === 'POST') {
      const now = new Date().toISOString();
      const rec: DnsRecord = {
        id: `ec${String(++seq).padStart(30, '0')}`,
        name: body.name,
        type: body.type,
        content: body.content,
        proxied: body.proxied === true,
        ttl: body.ttl ?? 1,
        comment: body.comment ?? null,
        created_on: now,
        modified_on: now,
      };
      records.set(rec.id, rec);
      return envelope(rec);
    }
    const rec = rest.match(/^\/dns_records\/([^/]+)$/);
    if (rec && method === 'GET') {
      const r = records.get(rec[1]!);
      return r
        ? envelope(r)
        : json(
            {
              success: false,
              errors: [{ code: 81044, message: 'Record does not exist.' }],
              messages: [],
              result: null,
            },
            404,
          );
    }
    if (rec && method === 'DELETE') {
      records.delete(rec[1]!);
      return envelope({ id: rec[1] });
    }
    refused.push(`cloudflare ${method} ${rest}`);
    return envelope(null, 404);
  }

  vi.stubGlobal('fetch', async (input: string | URL | Request, init: RequestInit = {}) => {
    const c = await capture(input, init);
    if (c.url.hostname === 'api.upcloud.com') return upcloud(c.method, c.url.pathname, c.body);
    if (c.url.hostname === 'api.cloudflare.com')
      return cloudflare(c.method, c.url.pathname, c.url.searchParams, c.body);
    if (opts.allowHosts.includes(c.url.hostname)) return realFetch(input, init);
    refused.push(`${c.method} ${c.url.hostname}`);
    throw new TypeError(`edge connection test: no network for ${c.url.hostname}`);
  });

  return { calls, refused, lbs, records };
}
