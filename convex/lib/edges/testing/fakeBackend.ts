/**
 * Test helper: a fake Remnawave backend at `panel.example` with mutable tables
 * (config profiles, groups, Hosts, nodes, users), composable with other fakes
 * through `routeFetch` (mockFetch.ts). It answers what backend setup, node
 * enrollment, the activation runs and the edge machinery ask: profile create
 * and edit, group writes, Host create / update / delete, node create / update, user
 * issue / lookup / delete, and the subscription body, built from the ENABLED
 * Hosts in the format the user agent asks for (one entry per Host, remark =
 * the Host's, speaking its transport: REALITY over TCP or WebSocket over TLS).
 * Not a test file itself. Every value is RFC 5737 / `*.example`.
 */
import { realityPublicKey } from '../../backend/digest';
import { jsonRes, mockFetch, routeFetch, type Captured, type FetchStub } from './mockFetch';

export const FAKE_BACKEND_HOST = 'panel.example';
/** The protocol credential every fake user carries (what a body's entries hold). */
export const FAKE_BACKEND_USER_UUID = 'aaaaaaaa-1111-4222-8333-444444444444';

const UUID = (n: number) => `${String(n).padStart(8, '0')}-0000-4000-8000-000000000000`;

/* eslint-disable @typescript-eslint/no-explicit-any */
export interface FakeBackend {
  profiles: any[];
  squads: any[];
  hosts: any[];
  nodes: any[];
  users: any[];
  writes: { call: string; body: any }[];
  seq: number;
  /** The subscription body per user agent (replaceable, e.g. to drop an entry). */
  bodyFor: (ua: string) => string;
  /** Answers the backend's own calls; null for any other host. */
  handle: (call: Captured) => Response | null;
}

interface Entry {
  remark: string;
  address: string;
  port: number;
  kind: 'reality' | 'ws';
  /** A WS entry's security: the inbound's own unless the Host's `securityLayer` overrides it. */
  tls: boolean;
  sni: string;
  pk: string;
  path: string;
  host: string;
}

/** What one Host's transport speaks, from the profile that holds it. */
function entryOf(panel: FakeBackend, h: any): Entry {
  const ref = h.inbound?.configProfileInboundUuid as string | undefined;
  const profile = panel.profiles.find((p) => p.inbounds.some((i: any) => i.uuid === ref));
  const tag = profile?.inbounds.find((i: any) => i.uuid === ref)?.tag;
  const cfg = (profile?.config?.inbounds as any[] | undefined)?.find((i) => i.tag === tag);
  const ws = cfg?.streamSettings?.network === 'ws';
  return {
    remark: h.remark,
    address: h.address,
    port: h.port,
    kind: ws ? 'ws' : 'reality',
    // As the real backend renders it: a Host without `securityLayer` speaks the
    // inbound's own security (a loopback WebSocket's is none).
    tls:
      h.securityLayer === 'TLS' ||
      ((h.securityLayer ?? 'DEFAULT') === 'DEFAULT' && cfg?.streamSettings?.security === 'tls'),
    sni: h.sni ?? h.host ?? '',
    // The profile's REALITY public key (a test may replace it to force a mismatch).
    pk: (tag && profile?.publicKeyByTag?.[tag]) ?? 'pk',
    path: cfg?.streamSettings?.wsSettings?.path ?? '/ws',
    host: h.host || h.sni || '',
  };
}

function linkOf(e: Entry): string {
  if (e.kind === 'ws')
    return e.tls
      ? `vless://${FAKE_BACKEND_USER_UUID}@${e.address}:${e.port}?encryption=none&security=tls&type=ws&path=${encodeURIComponent(e.path)}&host=${e.host}&sni=${e.sni}&fp=chrome#${e.remark}`
      : `vless://${FAKE_BACKEND_USER_UUID}@${e.address}:${e.port}?encryption=none&security=none&type=ws&path=${encodeURIComponent(e.path)}&host=${e.host}#${e.remark}`;
  // The backend gives a REALITY account over raw TCP XTLS Vision, in every format.
  return `vless://${FAKE_BACKEND_USER_UUID}@${e.address}:${e.port}?encryption=none&flow=xtls-rprx-vision&security=reality&type=tcp&sni=${e.sni}&fp=chrome&pbk=${e.pk}&sid=#${e.remark}`;
}

function singboxOf(entries: Entry[]): string {
  return JSON.stringify({
    outbounds: entries.map((e) =>
      e.kind === 'ws'
        ? {
            type: 'vless',
            tag: e.remark,
            server: e.address,
            server_port: e.port,
            uuid: FAKE_BACKEND_USER_UUID,
            ...(e.tls ? { tls: { enabled: true, server_name: e.sni } } : {}),
            transport: { type: 'ws', path: e.path, headers: { Host: e.host } },
          }
        : {
            type: 'vless',
            tag: e.remark,
            server: e.address,
            server_port: e.port,
            uuid: FAKE_BACKEND_USER_UUID,
            flow: 'xtls-rprx-vision',
            tls: {
              enabled: true,
              server_name: e.sni,
              reality: { enabled: true, public_key: e.pk },
            },
          },
    ),
  });
}

function clashOf(entries: Entry[]): string {
  return `proxies:\n${entries
    .map((e) =>
      e.kind === 'ws'
        ? `  - name: ${e.remark}\n    type: vless\n    server: ${e.address}\n    port: ${e.port}\n    uuid: ${FAKE_BACKEND_USER_UUID}\n    tls: ${e.tls}\n${e.tls ? `    servername: ${e.sni}\n` : ''}    network: ws\n    ws-opts:\n      path: ${e.path}\n      headers:\n        Host: ${e.host}\n`
        : `  - name: ${e.remark}\n    type: vless\n    server: ${e.address}\n    port: ${e.port}\n    uuid: ${FAKE_BACKEND_USER_UUID}\n    flow: xtls-rprx-vision\n    servername: ${e.sni}\n    reality-opts:\n      public-key: ${e.pk}\n`,
    )
    .join('')}`;
}

export function createFakeBackend(opts: { host?: string } = {}): FakeBackend {
  const host = opts.host ?? FAKE_BACKEND_HOST;
  const panel: FakeBackend = {
    profiles: [],
    squads: [],
    hosts: [],
    nodes: [],
    users: [],
    writes: [],
    seq: 10,
    bodyFor: () => '',
    handle: () => null,
  };
  const json = (o: unknown, status = 200) => jsonRes({ response: o }, status);
  panel.bodyFor = (ua: string) => {
    const entries = panel.hosts.filter((h) => !h.isDisabled).map((h) => entryOf(panel, h));
    if (/sing-box/i.test(ua)) return singboxOf(entries);
    if (/clash|mihomo/i.test(ua)) return clashOf(entries);
    return entries.map(linkOf).join('\n');
  };
  panel.handle = (c) => {
    if (new URL(c.url).hostname !== host) return null;
    const path = c.path;
    const method = c.method;
    const body = (c.body ?? {}) as any;
    if (method === 'GET') {
      if (path === '/api/nodes') return json(panel.nodes.map((n) => ({ ...n, isConnected: true })));
      if (path === '/api/hosts') return json(panel.hosts);
      if (path === '/api/internal-squads') return json({ internalSquads: panel.squads });
      if (path === '/api/config-profiles') return json({ configProfiles: panel.profiles });
      if (path === '/api/keygen') return json({ pubKey: 'panel-node-secret-placeholder' });
      if (path === '/api/subscription-templates') return json([]);
      const p = panel.profiles.find((x) => path === `/api/config-profiles/${x.uuid}`);
      if (p) return json(p);
      const byName = path.match(/^\/api\/users\/by-username\/(.+)$/);
      if (byName) {
        const u = panel.users.find((x) => x.username === decodeURIComponent(byName[1]!));
        return u ? json(u) : jsonRes({ message: 'User not found' }, 404);
      }
      const u = panel.users.find((x) => path === `/api/users/${x.uuid}`);
      if (u) return json(u);
      if (path.startsWith('/api/hwid/devices/')) return json({ devices: [] });
      if (path.startsWith('/api/sub/'))
        return new Response(panel.bodyFor(c.headers['user-agent'] ?? ''), {
          status: 200,
          headers: { 'content-type': 'text/plain' },
        });
      return json({});
    }
    panel.writes.push({ call: `${method} ${path}`, body });
    if (path === '/api/config-profiles' && method === 'POST') {
      const uuid = UUID(++panel.seq);
      const inbounds = (body.config.inbounds as { tag: string }[]).map((i) => ({
        uuid: UUID(++panel.seq),
        tag: i.tag,
      }));
      const publicKeyByTag: Record<string, string> = {};
      for (const i of body.config.inbounds as any[])
        if (i.streamSettings?.realitySettings?.privateKey)
          publicKeyByTag[i.tag] =
            realityPublicKey(i.streamSettings.realitySettings.privateKey) ?? 'pk';
      panel.profiles.push({ uuid, name: body.name, config: body.config, inbounds, publicKeyByTag });
      return json({ uuid }, 201);
    }
    if (path === '/api/config-profiles' && method === 'PATCH') {
      // As the backend does (measured): the config is replaced wholesale, client
      // lists are cleared, a transport keeps its uuid while its tag holds, a new
      // tag gets a new one, and every node running the profile re-applies it.
      const p = panel.profiles.find((x) => x.uuid === body.uuid);
      if (p && body.config) {
        const cfg = structuredClone(body.config);
        for (const ib of cfg.inbounds ?? []) if (ib.settings?.clients) ib.settings.clients = [];
        p.config = cfg;
        p.inbounds = (cfg.inbounds as { tag: string }[]).map(
          (ib) =>
            (p.inbounds as { tag: string }[]).find((i) => i.tag === ib.tag) ?? {
              uuid: UUID(++panel.seq),
              tag: ib.tag,
            },
        );
        p.publicKeyByTag ??= {};
        for (const ib of cfg.inbounds as any[])
          if (ib.streamSettings?.realitySettings?.privateKey && !p.publicKeyByTag[ib.tag])
            p.publicKeyByTag[ib.tag] =
              realityPublicKey(ib.streamSettings.realitySettings.privateKey) ?? 'pk';
        for (const n of panel.nodes)
          if (n.configProfile?.activeConfigProfileUuid === p.uuid)
            n.lastStatusChange = `t${++panel.seq}`;
      }
      return json(p ?? null);
    }
    if (path === '/api/internal-squads' && method === 'POST') {
      const made = {
        uuid: UUID(++panel.seq),
        name: body.name,
        inbounds: (body.inbounds as string[]).map((uuid) => ({ uuid, tag: uuid })),
      };
      panel.squads.push(made);
      return json({ uuid: made.uuid }, 201);
    }
    if (path === '/api/internal-squads' && method === 'PATCH') {
      const s = panel.squads.find((x) => x.uuid === body.uuid)!;
      if (typeof body.name === 'string') s.name = body.name;
      if (Array.isArray(body.inbounds))
        s.inbounds = (body.inbounds as string[]).map((uuid) => ({ uuid, tag: uuid }));
      return json(s);
    }
    if (path === '/api/hosts' && method === 'POST') {
      const made = { uuid: UUID(++panel.seq), ...body, isDisabled: body.isDisabled === true };
      panel.hosts.push(made);
      return json({ uuid: made.uuid }, 201);
    }
    if (path === '/api/hosts' && method === 'PATCH') {
      const h = panel.hosts.find((x) => x.uuid === body.uuid);
      if (h) Object.assign(h, body);
      return json(h ?? null);
    }
    const hostDelete = path.match(/^\/api\/hosts\/([^/]+)$/);
    if (hostDelete && method === 'DELETE') {
      panel.hosts = panel.hosts.filter((x) => x.uuid !== hostDelete[1]);
      return json({ isDeleted: true });
    }
    if (path === '/api/nodes' && method === 'POST') {
      const made = {
        uuid: UUID(++panel.seq),
        name: body.name,
        address: body.address,
        port: body.port ?? 2222,
        countryCode: body.countryCode ?? 'XX',
        isDisabled: false,
        lastStatusChange: 't0',
        configProfile: {
          activeConfigProfileUuid: body.configProfile.activeConfigProfileUuid,
          activeInbounds: (body.configProfile.activeInbounds as string[]).map((uuid) => ({
            uuid,
            tag: uuid,
          })),
        },
      };
      panel.nodes.push(made);
      return json(made, 201);
    }
    if (path === '/api/nodes' && method === 'PATCH') {
      const n = panel.nodes.find((x) => x.uuid === body.uuid);
      if (n) {
        for (const k of ['name', 'address', 'port', 'countryCode'] as const)
          if (body[k] !== undefined) n[k] = body[k];
        if (body.configProfile)
          n.configProfile = {
            activeConfigProfileUuid: body.configProfile.activeConfigProfileUuid,
            activeInbounds: (body.configProfile.activeInbounds as string[]).map((uuid) => ({
              uuid,
              tag: uuid,
            })),
          };
      }
      return json(n ?? null);
    }
    if (path === '/api/users' && method === 'POST') {
      const made = {
        uuid: UUID(++panel.seq),
        shortUuid: `short-${panel.seq}`,
        vlessUuid: FAKE_BACKEND_USER_UUID,
        username: body.username,
        status: 'ACTIVE',
        subscriptionUrl: `https://${host}/api/sub/short-${panel.seq}`,
        trafficLimitBytes: 0,
        usedTrafficBytes: 0,
        hwidDeviceLimit: null,
        expireAt: body.expireAt ?? new Date(Date.now() + 86_400_000).toISOString(),
        activeInternalSquads: [],
      };
      panel.users.push(made);
      return json(made, 201);
    }
    const userDelete = path.match(/^\/api\/users\/([^/]+)$/);
    if (userDelete && method === 'DELETE') {
      panel.users = panel.users.filter((x) => x.uuid !== userDelete[1]);
      return json({ isDeleted: true });
    }
    return json({});
  };
  return panel;
}
/* eslint-enable @typescript-eslint/no-explicit-any */

/** The fake backend as the global fetch on its own (the activation tests' shape). */
export function installFakeBackend(): FakeBackend & { stub: FetchStub } {
  const panel = createFakeBackend();
  const stub = mockFetch(routeFetch(panel.handle));
  return Object.assign(panel, { stub });
}
