/**
 * The edge providers of the edge connection test: FCP's REAL adapters (UpCloud
 * at L4, Cloudflare at L7) talk to fake provider APIs, and the fakes wire the
 * real edges of the stack.
 *
 *  - UpCloud: every floating address FCP allocates is the next one of the
 *    forwarder's pool, and attaching it to a load balancer wires that address's
 *    frontend port to exactly the backend member FCP asked for;
 *  - Cloudflare: a proxied DNS record under the zone is what a CDN front is.
 *    Every name of the zone already lands on the stack's front (its resolver
 *    answers the whole zone); creating the record adds the front's route for
 *    that name to the record's content, on the zone's origin port or the one
 *    its Origin Rule sets, sending the member's address in CF-Connecting-IP
 *    unless the name's request-header Transform Rule removes it (and in
 *    X-Forwarded-For always, as Cloudflare does). The fake records what FCP
 *    asked for.
 *
 *  - Outline: the Outline Manager API of the stack's Outline server (whose data
 *    plane is real: `ec-outline`). Every key it hands out is a Shadowsocks key
 *    for that server, as one Outline server's keys all reach it.
 *
 * Every other request goes to the real network only when its host is on the
 * allowlist (the panel); anything else is refused and recorded, so FCP cannot
 * reach the internet from this test without the test noticing.
 */
import { vi } from 'vitest';
import { ADDR, routeFront, wireForwarder } from './stack';

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

/** The fake Outline Manager's host: an operator's `apiUrl` names it (with its secret path). */
export const OUTLINE_MANAGER_HOST = 'outline-manager.example';

export function installProviderFakes(opts: {
  allowHosts: string[];
  l7Zone: string;
  outline?: { address: string; port: number; password: string };
}) {
  const realFetch = globalThis.fetch.bind(globalThis);
  const calls = { upcloud: [] as Call[], cloudflare: [] as Call[], outline: [] as Call[] };
  const outlineKeys = new Map<
    string,
    { id: string; name: string; accessUrl: string; dataLimit?: { bytes: number } }
  >();
  const refused: string[] = [];
  const lbs = new Map<string, LoadBalancer>();
  const records = new Map<string, DnsRecord>();
  /** The zone's Origin Rules phase (one entry point ruleset), as the API keeps it. */
  let originPhase: { id: string; rules: Array<Record<string, unknown>> } | null = null;
  /** The zone's request-header Transform Rules phase, likewise. */
  let headerPhase: { id: string; rules: Array<Record<string, unknown>> } | null = null;
  const pool = [...ADDR.forwarderPool];
  let seq = 0;

  /** What the front dials for a record: its content, on the rule's port or the zone's 443. */
  const routeRecord = (rec: DnsRecord) => {
    const rule = originPhase?.rules.find((r) =>
      String(r.expression ?? '').includes(`"${rec.name}"`),
    ) as { action_parameters?: { origin?: { port?: number } } } | undefined;
    const port = rule?.action_parameters?.origin?.port ?? 443;
    // A rule may remove CF-Connecting-IP for the name; nothing removes X-Forwarded-For.
    const removesAddress = (headerPhase?.rules ?? []).some(
      (r) =>
        r.action === 'rewrite' &&
        String(r.expression ?? '').includes(`"${rec.name}"`) &&
        (r.action_parameters as { headers?: Record<string, { operation?: string }> } | undefined)
          ?.headers?.['cf-connecting-ip']?.operation === 'remove',
    );
    // A CNAME origin is dialled by its own name; an address origin is sent the
    // edge hostname as its server name (the record's name is all a CDN knows).
    return routeFront(
      rec.name,
      { host: rec.content, port },
      rec.type === 'CNAME' ? rec.content : rec.name,
      { clientAddress: !removesAddress },
    );
  };

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
      for (const f of lb.frontends)
        if (!lb.backends.find((b) => b.name === f.default_backend)?.members[0])
          return json({ error: { error_code: 'BACKEND_INVALID' } }, 400);
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
    if (p === '/ip_address' && method === 'POST') {
      const address = pool.shift();
      if (!address) return json({ error: { error_code: 'IP_ADDRESS_LIMIT' } }, 409);
      return json({ ip_address: { address, floating: 'yes', family: 'IPv4' } }, 201);
    }
    const attach = p.match(/^\/load-balancer\/([^/]+)\/ip-addresses$/);
    if (attach && method === 'POST') {
      const lb = lbs.get(attach[1]!);
      if (!lb) return json({ error: { error_code: 'LB_NOT_FOUND' } }, 404);
      // The documented shape: ONE address and the service network it listens
      // on (UpCloud's API reference and its official SDK); anything else is
      // refused, as UpCloud refuses it.
      if (typeof body.address !== 'string' || body.network_name !== 'public')
        return json({ error: { error_code: 'INVALID_REQUEST' } }, 400);
      const added: Array<{ address: string }> = [{ address: body.address }];
      lb.ip_addresses.push(...added);
      // What a provider's LB does from now on: address:frontend port -> the backend member.
      for (const { address } of added)
        for (const f of lb.frontends) {
          const member = lb.backends.find((b) => b.name === f.default_backend)!.members[0]!;
          await wireForwarder(f.port, `${member.ip}:${member.port}`, address);
        }
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
      await routeRecord(rec);
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
    // The Origin Rules phase: read, create (PUT on the entry point) and add a rule.
    if (rest === '/rulesets/phases/http_request_origin/entrypoint') {
      if (method === 'GET')
        return originPhase
          ? envelope({ ...originPhase, phase: 'http_request_origin', kind: 'zone' })
          : json(
              {
                success: false,
                errors: [{ code: 10003, message: 'not found' }],
                messages: [],
                result: null,
              },
              404,
            );
      if (method === 'PUT') {
        originPhase = {
          id: `ecrs${String(++seq).padStart(28, '0')}`,
          rules: (body.rules ?? []).map((r: Record<string, unknown>) => ({
            ...r,
            id: `ecr${String(++seq).padStart(29, '0')}`,
          })),
        };
        for (const r of records.values()) await routeRecord(r);
        return envelope({ ...originPhase, phase: 'http_request_origin', kind: 'zone' });
      }
    }
    // The request-header Transform Rules phase: the same three calls.
    if (rest === '/rulesets/phases/http_request_late_transform/entrypoint') {
      if (method === 'GET')
        return headerPhase
          ? envelope({ ...headerPhase, phase: 'http_request_late_transform', kind: 'zone' })
          : json(
              {
                success: false,
                errors: [{ code: 10003, message: 'not found' }],
                messages: [],
                result: null,
              },
              404,
            );
      if (method === 'PUT') {
        headerPhase = {
          id: `echs${String(++seq).padStart(28, '0')}`,
          rules: (body.rules ?? []).map((r: Record<string, unknown>) => ({
            ...r,
            id: `ech${String(++seq).padStart(29, '0')}`,
          })),
        };
        for (const r of records.values()) await routeRecord(r);
        return envelope({ ...headerPhase, phase: 'http_request_late_transform', kind: 'zone' });
      }
    }
    const addRule = rest.match(/^\/rulesets\/([^/]+)\/rules$/);
    const phaseOf = (id: string | undefined) =>
      originPhase && id === originPhase.id
        ? { phase: originPhase, name: 'http_request_origin' }
        : headerPhase && id === headerPhase.id
          ? { phase: headerPhase, name: 'http_request_late_transform' }
          : null;
    const into = phaseOf(addRule?.[1]);
    if (addRule && method === 'POST' && into) {
      const { zone_id: _zone, ...rule } = body ?? {};
      into.phase.rules.push({ ...rule, id: `ecr${String(++seq).padStart(29, '0')}` });
      for (const r of records.values()) await routeRecord(r);
      return envelope({ ...into.phase, phase: into.name, kind: 'zone' });
    }
    const oneRule = rest.match(/^\/rulesets\/([^/]+)\/rules\/([^/]+)$/);
    const from = phaseOf(oneRule?.[1]);
    if (oneRule && method === 'DELETE' && from) {
      from.phase.rules = from.phase.rules.filter((r) => r.id !== oneRule[2]);
      return envelope({ ...from.phase, phase: from.name, kind: 'zone' });
    }
    refused.push(`cloudflare ${method} ${rest}`);
    return envelope(null, 404);
  }

  /** The Outline Manager API (shadowbox), the paths FCP's provider calls under its secret prefix. */
  function outline(method: string, path: string, body: any): Response {
    calls.outline.push({ method, path, body });
    const o = opts.outline;
    if (!o) {
      refused.push(`outline ${method}`);
      return json({ message: 'no outline server' }, 404);
    }
    const p = path.replace(/^\/[^/]+/, ''); // drop the secret path segment
    if (p === '/access-keys' && method === 'POST') {
      const id = String(++seq);
      const userInfo = Buffer.from(`chacha20-ietf-poly1305:${o.password}`).toString('base64url');
      const key = {
        id,
        name: String(body?.name ?? ''),
        accessUrl: `ss://${userInfo}@${o.address}:${o.port}/?outline=1#${encodeURIComponent(String(body?.name ?? id))}`,
      };
      outlineKeys.set(id, key);
      return json(
        { ...key, port: o.port, method: 'chacha20-ietf-poly1305', password: o.password },
        201,
      );
    }
    if (p === '/access-keys' && method === 'GET')
      return json({ accessKeys: [...outlineKeys.values()] });
    if (p === '/metrics/transfer' && method === 'GET')
      return json({ bytesTransferredByUserId: {} });
    const limit = p.match(/^\/access-keys\/([^/]+)\/data-limit$/);
    if (limit) {
      const k = outlineKeys.get(limit[1]!);
      if (!k) return json({ message: 'not found' }, 404);
      if (method === 'PUT') k.dataLimit = body?.limit;
      if (method === 'DELETE') delete k.dataLimit;
      return new Response(null, { status: 204 });
    }
    const one = p.match(/^\/access-keys\/([^/]+)$/);
    if (one && method === 'GET') {
      const k = outlineKeys.get(one[1]!);
      return k ? json(k) : json({ message: 'not found' }, 404);
    }
    if (one && method === 'DELETE') {
      outlineKeys.delete(one[1]!);
      return new Response(null, { status: 204 });
    }
    refused.push(`outline ${method} ${p}`);
    return json({ message: 'not found' }, 404);
  }

  vi.stubGlobal('fetch', async (input: string | URL | Request, init: RequestInit = {}) => {
    const c = await capture(input, init);
    if (c.url.hostname === OUTLINE_MANAGER_HOST) return outline(c.method, c.url.pathname, c.body);
    if (c.url.hostname === 'api.upcloud.com') return upcloud(c.method, c.url.pathname, c.body);
    if (c.url.hostname === 'api.cloudflare.com')
      return cloudflare(c.method, c.url.pathname, c.url.searchParams, c.body);
    if (opts.allowHosts.includes(c.url.hostname)) return realFetch(input, init);
    refused.push(`${c.method} ${c.url.hostname}`);
    throw new TypeError(`edge connection test: no network for ${c.url.hostname}`);
  });

  return { calls, refused, lbs, records, outlineKeys };
}
