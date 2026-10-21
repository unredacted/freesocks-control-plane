/**
 * Test helper: the provider side of the edge machinery, composable with a
 * fake backend through `routeFetch` (mockFetch.ts).
 *
 *  - `createFakeUpcloud`: an UpCloud load-balancer API at `api.upcloud.com`;
 *    every create mints a fresh RFC 5737 address (`addressFor`), a chosen
 *    create can fail like a transient provider error;
 *  - `fakeEdgeWorld`: that provider plus a minimal backend whose Host table is
 *    observable (the publish rotation creates the FCP Host, the hides flip
 *    `isDisabled`), installed as the global fetch: the guided setup run tests'
 *    world.
 *
 * Not a test file itself. Every value is RFC 5737 / `*.example`.
 */
import { jsonRes, mockFetch, routeFetch, type FetchStub, type PartialHandler } from './mockFetch';

export interface FakeUpcloud {
  lbs: Map<string, { uuid: string; name: string; operational_state: string }>;
  lbCreates: () => number;
  /** Every load-balancer create body, in order. */
  lbBodies: () => unknown[];
  handle: PartialHandler;
}

export function createFakeUpcloud(
  opts: {
    /** Fail exactly the Nth load-balancer create (a transient provider error). */
    failCreateAt?: number;
    /** The public address the Nth floating address gets (default 198.51.100.10+). */
    addressFor?: (n: number) => string;
  } = {},
): FakeUpcloud {
  const lbs = new Map<string, { uuid: string; name: string; operational_state: string }>();
  let lbCreates = 0;
  const bodies: unknown[] = [];
  const addressFor = opts.addressFor ?? ((n: number) => `198.51.100.${10 + n}`);
  const handle: PartialHandler = (c) => {
    if (new URL(c.url).hostname !== 'api.upcloud.com') return null;
    if (c.path === '/1.3/load-balancer' && c.method === 'POST') {
      lbCreates++;
      bodies.push(c.body);
      if (opts.failCreateAt !== undefined && lbCreates === opts.failCreateAt)
        return jsonRes({ error: { error_code: 'INTERNAL' } }, 500);
      const uuid = `lb-${lbs.size + 1}`;
      lbs.set(uuid, {
        uuid,
        name: (c.body as { name: string }).name,
        operational_state: 'running',
      });
      return jsonRes(lbs.get(uuid));
    }
    if (c.path === '/1.3/ip_address' && c.method === 'POST')
      return jsonRes({ ip_address: { address: addressFor(lbs.size), floating: 'yes' } });
    if (/^\/1\.3\/load-balancer\/[^/]+\/ip-addresses$/.test(c.path) && c.method === 'POST')
      return jsonRes({});
    const get = c.path.match(/^\/1\.3\/load-balancer\/([^/]+)$/);
    if (get && c.method === 'GET') {
      const lb = lbs.get(get[1]!);
      return lb ? jsonRes(lb) : jsonRes({ error: { error_code: 'LB_NOT_FOUND' } }, 404);
    }
    if (get && c.method === 'DELETE') {
      lbs.delete(get[1]!);
      return jsonRes({});
    }
    throw new Error(`unexpected ${c.method} ${c.url}`);
  };
  return { lbs, lbCreates: () => lbCreates, lbBodies: () => bodies, handle };
}

export interface BackendAddress {
  uuid: string;
  remark: string;
  address: string;
  port: number;
  sni?: string;
  host?: string;
  isDisabled?: boolean;
  inbound: { configProfileUuid: string; configProfileInboundUuid: string };
}

/**
 * A fake UpCloud + a fake backend whose Hosts are observable (the publish
 * rotation creates the FCP Host), installed as the global fetch.
 */
export function fakeEdgeWorld(opts: { hosts: BackendAddress[]; failCreateAt?: number }): {
  stub: FetchStub;
  panelHosts: BackendAddress[];
  lbs: FakeUpcloud['lbs'];
  creates: () => number;
  lbCreates: () => number;
  /** Every load-balancer create body, in order. */
  lbBodies: () => unknown[];
} {
  const panelHosts = opts.hosts;
  let creates = 0;
  const upcloud = createFakeUpcloud({ failCreateAt: opts.failCreateAt });
  const panel: PartialHandler = (c) => {
    if (new URL(c.url).hostname !== 'panel.example') return null;
    if (c.path === '/api/hosts' && c.method === 'GET') return jsonRes({ response: panelHosts });
    if (c.path === '/api/hosts' && c.method === 'PATCH') {
      const body = c.body as Partial<BackendAddress> & { uuid: string };
      const h = panelHosts.find((x) => x.uuid === body.uuid);
      if (h) {
        if (body.address !== undefined) h.address = body.address;
        if (body.port !== undefined) h.port = body.port;
        if (body.sni !== undefined) h.sni = body.sni;
        if (body.host !== undefined) h.host = body.host;
        if (body.isDisabled !== undefined) h.isDisabled = body.isDisabled;
      }
      return jsonRes({ response: h ?? null });
    }
    if (c.path === '/api/hosts' && c.method === 'POST') {
      creates++;
      const body = c.body as BackendAddress;
      const uuid = `cccccccc-cccc-4ccc-8ccc-${String(creates).padStart(12, '0')}`;
      panelHosts.push({ ...body, uuid });
      return jsonRes({ response: { uuid } });
    }
    return jsonRes({ message: 'not found' }, 404);
  };
  const stub = mockFetch(routeFetch(panel, upcloud.handle));
  return {
    stub,
    panelHosts,
    lbs: upcloud.lbs,
    creates: () => creates,
    lbCreates: upcloud.lbCreates,
    lbBodies: upcloud.lbBodies,
  };
}
