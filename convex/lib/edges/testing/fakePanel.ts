/**
 * Test helper: a fake Remnawave panel (and a fake Outline server) behind the
 * routing fetch stub, with a mutable user table keyed by USERNAME so the
 * persisted mint operations can be exercised end to end through the real
 * provider code: create, re-find by name, delete, list Hosts, serve a
 * subscription body per user agent, list node inbounds. Every value is RFC
 * 5737 / `*.example`. Not a test file itself.
 */
import { jsonRes, mockFetch, type Captured, type FetchStub } from './mockFetch';

export interface FakePanelUser {
  uuid: string;
  shortUuid: string;
  username: string;
  vlessUuid: string;
  subscriptionUrl: string;
}

export interface FakePanelHost {
  uuid: string;
  remark: string;
  address: string;
  port: number;
  sni?: string | null;
  host?: string | null;
  isDisabled?: boolean;
  inbound?: { configProfileUuid: string; configProfileInboundUuid: string } | null;
}

export interface FakePanelOptions {
  baseUrl?: string;
  hosts?: FakePanelHost[];
  /**
   * The subscription body served for a short id + user agent (null = 404).
   * `user` is the panel user behind the short id when FCP created it here;
   * null for a member short id the test seeded directly.
   */
  body?: (user: FakePanelUser | null, userAgent: string, shortId: string) => string | null;
  /** `GET /api/nodes` + `GET /api/config-profiles/{uuid}` payloads for inbound discovery. */
  nodes?: unknown[];
  profiles?: Record<string, unknown>;
}

export interface FakePanel {
  stub: FetchStub;
  users: Map<string, FakePanelUser>;
  hosts: FakePanelHost[];
  /** Usernames created / uuids deleted, in order. */
  created: string[];
  deleted: string[];
  /** Fail the next create with this status (500 = ambiguous, 400 = definitive). */
  failCreateWith: number | null;
  /** Every delete answers this status while set. */
  failDeleteWith: number | null;
  /** Requests the panel saw, by method + path. */
  calls: Captured[];
}

let seq = 0;
function uuidLike(n: number): string {
  const h = n.toString(16).padStart(12, '0');
  return `00000000-0000-4000-8000-${h}`;
}

export function fakePanel(opts: FakePanelOptions = {}): FakePanel {
  const baseUrl = opts.baseUrl ?? 'https://panel.example';
  const users = new Map<string, FakePanelUser>();
  const panel: FakePanel = {
    stub: null as unknown as FetchStub,
    users,
    hosts: opts.hosts ? [...opts.hosts] : [],
    created: [],
    deleted: [],
    failCreateWith: null,
    failDeleteWith: null,
    calls: [],
  };
  const userJson = (u: FakePanelUser) => ({
    uuid: u.uuid,
    shortUuid: u.shortUuid,
    vlessUuid: u.vlessUuid,
    username: u.username,
    status: 'ACTIVE',
    trafficLimitBytes: 0,
    trafficLimitStrategy: 'MONTH',
    usedTrafficBytes: 0,
    expireAt: new Date(Date.now() + 365 * 86_400_000).toISOString(),
    hwidDeviceLimit: null,
    subscriptionUrl: u.subscriptionUrl,
  });
  const byUuid = (id: string) => [...users.values()].find((u) => u.uuid === id) ?? null;
  panel.stub = mockFetch(async (call) => {
    panel.calls.push(call);
    const { method, path } = call;
    let m: RegExpExecArray | null;
    if (method === 'POST' && path === '/api/users') {
      if (panel.failCreateWith !== null) {
        const status = panel.failCreateWith;
        panel.failCreateWith = null;
        return jsonRes({ message: 'create failed' }, status);
      }
      const body = call.body as { username: string };
      seq++;
      const u: FakePanelUser = {
        uuid: uuidLike(seq),
        shortUuid: `short${seq}`,
        username: body.username,
        vlessUuid: uuidLike(1_000_000 + seq),
        subscriptionUrl: `${baseUrl}/api/sub/short${seq}`,
      };
      users.set(u.username, u);
      panel.created.push(u.username);
      return jsonRes({ response: userJson(u) }, 201);
    }
    if (method === 'GET' && (m = /^\/api\/users\/by-username\/(.+)$/.exec(path))) {
      const u = users.get(decodeURIComponent(m[1]));
      return u ? jsonRes({ response: userJson(u) }) : jsonRes({ message: 'not found' }, 404);
    }
    if (method === 'GET' && (m = /^\/api\/users\/([^/]+)$/.exec(path))) {
      const u = byUuid(m[1]);
      return u ? jsonRes({ response: userJson(u) }) : jsonRes({ message: 'not found' }, 404);
    }
    if (method === 'DELETE' && (m = /^\/api\/users\/([^/]+)$/.exec(path))) {
      if (panel.failDeleteWith !== null) return jsonRes({ message: 'down' }, panel.failDeleteWith);
      const u = byUuid(m[1]);
      if (!u) return jsonRes({ message: 'not found' }, 404);
      users.delete(u.username);
      panel.deleted.push(u.uuid);
      return new Response(null, { status: 204 });
    }
    if (method === 'GET' && path === '/api/hosts') {
      return jsonRes({
        response: panel.hosts.map((h) => ({
          ...h,
          sni: h.sni ?? null,
          host: h.host ?? null,
          isDisabled: h.isDisabled ?? false,
          inbound: h.inbound ?? null,
        })),
      });
    }
    if (method === 'GET' && (m = /^\/api\/sub\/([^/]+)$/.exec(path))) {
      const u = [...users.values()].find((x) => x.shortUuid === m![1]) ?? null;
      const body = opts.body?.(u, call.headers['user-agent'] ?? '', m[1]) ?? null;
      if (body === null) return new Response('not found', { status: 404 });
      return new Response(body, { status: 200, headers: { 'content-type': 'text/plain' } });
    }
    if (method === 'GET' && path === '/api/nodes') return jsonRes({ response: opts.nodes ?? [] });
    if (method === 'GET' && (m = /^\/api\/config-profiles\/([^/]+)$/.exec(path))) {
      const p = opts.profiles?.[m[1]];
      return p ? jsonRes({ response: p }) : jsonRes({ message: 'not found' }, 404);
    }
    return jsonRes({ message: `unhandled ${method} ${path}` }, 404);
  });
  return panel;
}

export interface FakeOutline {
  stub: FetchStub;
  keys: Map<string, { id: string; name: string; accessUrl: string }>;
  created: string[];
  deleted: string[];
  failCreateWith: number | null;
  failDeleteWith: number | null;
  calls: Captured[];
}

/** A fake Outline management API: keys by id, named by the issued username. */
export function fakeOutline(opts: { origin?: string; port?: number } = {}): FakeOutline {
  const origin = opts.origin ?? '203.0.113.77';
  const port = opts.port ?? 8388;
  const keys = new Map<string, { id: string; name: string; accessUrl: string }>();
  const out: FakeOutline = {
    stub: null as unknown as FetchStub,
    keys,
    created: [],
    deleted: [],
    failCreateWith: null,
    failDeleteWith: null,
    calls: [],
  };
  let n = 0;
  out.stub = mockFetch(async (call) => {
    out.calls.push(call);
    const { method, path } = call;
    let m: RegExpExecArray | null;
    if (method === 'POST' && /\/access-keys$/.test(path)) {
      if (out.failCreateWith !== null) {
        const status = out.failCreateWith;
        out.failCreateWith = null;
        return jsonRes({ message: 'create failed' }, status);
      }
      n++;
      const name = (call.body as { name?: string } | undefined)?.name ?? '';
      const key = {
        id: String(n),
        name,
        accessUrl: `ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXQ@${origin}:${port}/?outline=1#${encodeURIComponent(name)}`,
      };
      keys.set(key.id, key);
      out.created.push(name);
      return jsonRes({ ...key, port, method: 'chacha20-ietf-poly1305', password: 'secret' }, 201);
    }
    if (method === 'GET' && /\/access-keys$/.test(path))
      return jsonRes({ accessKeys: [...keys.values()] });
    if (method === 'PUT' && /\/access-keys\/[^/]+\/data-limit$/.test(path))
      return new Response(null, { status: 204 });
    if (method === 'GET' && (m = /\/access-keys\/([^/]+)$/.exec(path))) {
      const k = keys.get(m[1]);
      return k
        ? jsonRes({ ...k, port, method: 'chacha20-ietf-poly1305', password: 'secret' })
        : jsonRes({}, 404);
    }
    if (method === 'DELETE' && (m = /\/access-keys\/([^/]+)$/.exec(path))) {
      if (out.failDeleteWith !== null) return jsonRes({ message: 'down' }, out.failDeleteWith);
      if (!keys.delete(m[1])) return jsonRes({}, 404);
      out.deleted.push(m[1]);
      return new Response(null, { status: 204 });
    }
    return jsonRes({ message: `unhandled ${method} ${path}` }, 404);
  });
  return out;
}
