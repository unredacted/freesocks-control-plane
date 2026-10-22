/// <reference types="vite/client" />
/**
 * A key that moves IN PLACE (a connection-mode switch that keeps the row, the
 * backend user and the fronted token) is served the new placement at once:
 * the next `GET /api/v1/sub/<token>`, for every client family and whether or
 * not that family fetched before, carries the new mode's entries and none of
 * the old mode's. Nothing stored from the old placement answers it: not a
 * cached body, not the pin the cache token is read at, not the render
 * snapshot, not a mirror, and not what a fetch in flight across the switch
 * writes back (subscriptions.ts `invalidateDelivery`).
 *
 * One backend, three nodes: `node-ws` (WebSocket behind two L7 fronts, mode
 * `freedom-ws`), `node-r` (REALITY behind one L4 edge, `freedom-reality`) and
 * `node-p` (direct, `privacy-reality`). Fixtures use RFC 5737 addresses and
 * `*.example` names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import YAML from 'yaml';
import schema from './schema';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { qualificationBinding } from './lib/edges/frontCheck/binding';
import { classifyClient } from './lib/edges/clientFamilies';
import {
  insertPanelServer,
  realityListener,
  registerRelay,
  wsListener,
} from './lib/edges/testing/fixtures';
import { __setS3SendForTests, type S3Op } from './storage';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;

const UUID = '11111111-2222-4333-8444-555555555555';
const SQUAD = {
  ws: '33333333-3333-4333-8333-333333333333',
  r: '44444444-4444-4444-8444-444444444444',
  p: '55555555-5555-4555-8555-555555555555',
} as const;
type Place = keyof typeof SQUAD;
const MODE: Record<Place, string> = {
  ws: 'freedom-ws',
  r: 'freedom-reality',
  p: 'privacy-reality',
};

const WS_ORIGIN = '203.0.113.20';
const R_ORIGIN = '203.0.113.30';
const P_ADDRESS = '203.0.113.40';
const FRONTS = ['front-a.example', 'front-b.example'];
const L4_EDGE = '198.51.100.7';

/** What a member of each mode must find in a served body, and must never find once moved off it. */
const MARKS: Record<Place, string[]> = {
  ws: [...FRONTS, WS_ORIGIN],
  r: [L4_EDGE, R_ORIGIN],
  p: [P_ADDRESS],
};
const handedOut: Record<Place, string[]> = { ws: FRONTS, r: [L4_EDGE], p: [P_ADDRESS] };

/** One User-Agent per render family (and `curl`, the family nothing claims). */
const CLIENTS = [
  'SFA/1.10.0 (sing-box 1.10.0)',
  'clash-verge/v1.7.0',
  'v2rayNG/1.9.0',
  'Hiddify/2.5.7',
  'Streisand/1.6',
  'Happ/1.0',
  'Shadowrocket/2.2',
];

// --- the panel ---------------------------------------------------------------------------------

/** Each node's entry as the panel's Host carries it. */
const ENTRY: Record<
  Place,
  { tag: string; server: string; sni: string; ws: boolean; reality: boolean }
> = {
  ws: { tag: 'node-ws-relay-w', server: WS_ORIGIN, sni: 'ws.example', ws: true, reality: false },
  r: { tag: 'node-r-relay-a', server: L4_EDGE, sni: 'a.example', ws: false, reality: true },
  p: { tag: 'node-p | p.example', server: P_ADDRESS, sni: 'p.example', ws: false, reality: true },
};

function linkOf(place: Place): string {
  const e = ENTRY[place];
  const qs = e.ws
    ? `encryption=none&security=tls&sni=${e.sni}&fp=chrome&type=ws&path=%2Fws&host=${e.sni}`
    : `encryption=none&flow=xtls-rprx-vision&security=reality&sni=${e.sni}&fp=chrome&pbk=PUBKEY&sid=abcd&type=tcp`;
  return `vless://${UUID}@${e.server}:443?${qs}#${encodeURIComponent(e.tag)}`;
}

function singboxOf(place: Place): string {
  const e = ENTRY[place];
  const outbound = e.ws
    ? {
        type: 'vless',
        tag: e.tag,
        server: e.server,
        server_port: 443,
        uuid: UUID,
        tls: { enabled: true, server_name: e.sni },
        transport: { type: 'ws', path: '/ws', headers: { Host: e.sni } },
      }
    : {
        type: 'vless',
        tag: e.tag,
        server: e.server,
        server_port: 443,
        uuid: UUID,
        flow: 'xtls-rprx-vision',
        tls: {
          enabled: true,
          server_name: e.sni,
          reality: { enabled: true, public_key: 'PUBKEY', short_id: 'abcd' },
        },
      };
  return JSON.stringify({
    outbounds: [
      { type: 'selector', tag: 'proxy', outbounds: [e.tag, 'direct'], default: e.tag },
      outbound,
      { type: 'direct', tag: 'direct' },
    ],
    route: { final: 'proxy' },
  });
}

function clashOf(place: Place): string {
  const e = ENTRY[place];
  const proxy = e.ws
    ? {
        name: e.tag,
        type: 'vless',
        server: e.server,
        port: 443,
        uuid: UUID,
        tls: true,
        servername: e.sni,
        network: 'ws',
        'ws-opts': { path: '/ws', headers: { Host: e.sni } },
      }
    : {
        name: e.tag,
        type: 'vless',
        server: e.server,
        port: 443,
        uuid: UUID,
        tls: true,
        servername: e.sni,
        network: 'tcp',
        flow: 'xtls-rprx-vision',
        'reality-opts': { 'public-key': 'PUBKEY', 'short-id': 'abcd' },
      };
  return YAML.stringify({
    'mixed-port': 7890,
    proxies: [proxy],
    'proxy-groups': [{ name: 'proxy', type: 'select', proxies: [e.tag] }],
    rules: ['MATCH,proxy'],
  });
}

/** The body the panel serves a key in `place`'s group, in the format the client asks for. */
function panelBody(place: Place, ua: string): string {
  const format = classifyClient(ua).expectedFormat;
  return format === 'singbox-json'
    ? singboxOf(place)
    : format === 'clash-yaml'
      ? clashOf(place)
      : linkOf(place);
}

const PLACE_OF_SQUAD = Object.fromEntries(
  (Object.keys(SQUAD) as Place[]).map((p) => [SQUAD[p], p]),
) as Record<string, Place>;

/**
 * A panel whose subscription answer follows the key's group, which only its
 * user PATCH moves. `onFetch` runs while a subscription fetch is in flight,
 * after the panel has read the group (the fetch in flight across a switch).
 */
function stubPanel(start: Place) {
  const panel = {
    place: start,
    down: false,
    fetches: 0,
    onFetch: null as null | (() => Promise<void>),
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes('/api/users') && init?.method === 'PATCH') {
        const body = JSON.parse(String(init.body)) as { activeInternalSquads?: string[] };
        const squad = body.activeInternalSquads?.[0];
        if (squad) panel.place = PLACE_OF_SQUAD[squad]!;
        return new Response(
          JSON.stringify({
            response: {
              uuid: '550e8400-e29b-41d4-a716-446655440000',
              shortUuid: 'short-1',
              username: 'u',
              status: 'ACTIVE',
              trafficLimitBytes: null,
              trafficLimitStrategy: 'MONTH',
              userTraffic: { usedTrafficBytes: 0 },
              expireAt: new Date(Date.now() + 30 * 86_400_000).toISOString(),
              hwidDeviceLimit: null,
              subscriptionUrl: 'https://panel.example/sub/short-1',
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      if (panel.down) return new Response('unavailable', { status: 503 });
      panel.fetches += 1;
      const ua = new Headers(init?.headers).get('user-agent') ?? '';
      const body = panelBody(panel.place, ua);
      const hook = panel.onFetch;
      if (hook) {
        panel.onFetch = null;
        await hook();
      }
      return new Response(body, { status: 200, headers: { 'content-type': 'text/plain' } });
    }),
  );
  return panel;
}

// --- the world ---------------------------------------------------------------------------------

async function proveFront(t: T, edgeId: Id<'edges'>, hostname: string) {
  await t.run(async (ctx) => {
    const edge = (await ctx.db.get(edgeId))!;
    const listener = (await ctx.db.get(edge.listenerId))!;
    const intent = {
      hostname,
      zoneId: 'z'.repeat(32),
      zoneName: 'example',
      originTransport: listener.originTransport!,
      originPort: listener.originPort,
      zoneSslMode: 'full',
      templateHash: 'h1',
      templateParams: {},
    };
    const now = Date.now();
    await ctx.db.patch(edgeId, {
      layer: 'l7',
      addresses: { hostname },
      provisionIntent: JSON.stringify(intent),
      frontQualification: {
        ok: true,
        checkedAt: now,
        expiresAt: now + 3_600_000,
        binding: qualificationBinding({
          listener,
          intent,
          params: listener.transportParams ?? {},
        }) as NonNullable<Doc<'edges'>['frontQualification']>['binding'],
      },
    });
  });
}

async function seed(start: Place, opts: { mirror?: boolean } = {}) {
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
  const ws = await registerRelay(t, {
    slug: 'node-ws',
    nodeName: 'node-ws',
    originAddress: WS_ORIGIN,
    listeners: [wsListener()],
  });
  const r = await registerRelay(t, {
    slug: 'node-r',
    nodeName: 'node-r',
    originAddress: R_ORIGIN,
    listeners: [realityListener({ tlsNames: ['a.example'] })],
  });
  await t.mutation(internal.seed.seedConnectionModes, {});
  const subId = await t.run(async (ctx) => {
    for (const place of Object.keys(SQUAD) as Place[])
      await ctx.db.insert('modePlacements', {
        modeSlug: MODE[place],
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: [SQUAD[place]] }),
        updatedAt: Date.now(),
      });
    // `freedom-reality` ships dark.
    const reality = await ctx.db
      .query('connectionModes')
      .withIndex('by_slug', (q) => q.eq('slug', 'freedom-reality'))
      .unique();
    await ctx.db.patch(reality!._id, { enabled: true });
    const tierId = await ctx.db.insert('tiers', {
      slug: 'free',
      name: 'Free',
      backend: 'remnawave',
      monthlyTrafficGb: 50,
      deviceLimit: 1,
      hwidLimit: 1,
      hwidEnabled: false,
      trafficStrategy: 'MONTH',
      isDefaultFree: true,
      isActive: true,
      priority: 0,
      expirationDaysAfterMembershipLapse: 0,
      updatedAt: Date.now(),
    });
    const userId = await ctx.db.insert('users', {
      tierId,
      status: 'active',
      connectionModeId: MODE[start],
      updatedAt: Date.now(),
    });
    if (opts.mirror)
      await ctx.db.insert('mirrorProviders', {
        name: 'p1',
        endpoint: 'https://s3.invalid',
        bucket: 'b',
        publicUrl: 'https://mirror.example',
        region: 'auto',
        accessKeyId: 'ak',
        secretAccessKey: 'sk',
        isActive: true,
        priority: 0,
        updatedAt: Date.now(),
      });
    const subId = await ctx.db.insert('subscriptions', {
      userId,
      backend: 'remnawave',
      backendUserId: 'uuid-1',
      backendShortId: 'short-1',
      backendServerId: serverId,
      subscriptionUrl: 'https://panel.example/sub/short-1',
      subscriptionMirrors: opts.mirror
        ? [
            {
              provider: 'p1',
              publicUrl: 'https://mirror.example/mirrors/m1',
              objectPath: 'mirrors/m1',
              status: 'ok',
            },
          ]
        : [],
      ...(opts.mirror ? { rawContentHash: 'hash-of-the-old-body' } : {}),
      subToken: 'tok_one',
      backendPlacement: SQUAD[start],
      state: 'active',
      updatedAt: Date.now(),
    });
    await ctx.db.patch(userId, { currentSubscriptionId: subId });
    await upsertSettingRow(ctx, 'edge.render.enabled', 'true');
    return subId;
  });
  const fronts: Id<'edges'>[] = [];
  for (const [i, host] of FRONTS.entries()) {
    const e = await t.mutation(internal.relays.adoptEdge, {
      relayId: ws.relayId,
      listenerId: ws.listenerId,
      ipv4: `198.51.100.${i + 1}`,
      publish: true,
      verified: true,
    });
    await proveFront(t, e.edgeId as Id<'edges'>, host);
    fronts.push(e.edgeId as Id<'edges'>);
  }
  const l4 = await t.mutation(internal.relays.adoptEdge, {
    relayId: r.relayId,
    listenerId: r.listenerId,
    ipv4: L4_EDGE,
    publish: true,
    verified: true,
  });
  const userId = (await t.run((ctx) => ctx.db.get(subId)))!.userId;
  return { t, serverId, subId, userId, fronts, l4Edge: l4.edgeId as Id<'edges'> };
}

const get = (t: T, ua: string) => t.fetch('/api/v1/sub/tok_one', { headers: { 'user-agent': ua } });
const row = (t: T, subId: Id<'subscriptions'>) => t.run((ctx) => ctx.db.get(subId));

/** Every client family is handed `place` and nothing of `left`. */
async function expectServed(t: T, place: Place, left: Place, clients = CLIENTS) {
  for (const ua of clients) {
    const res = await get(t, ua);
    const body = await res.text();
    expect({ ua, status: res.status }).toEqual({ ua, status: 200 });
    for (const mark of handedOut[place])
      expect({ ua, has: body.includes(mark) }).toEqual({ ua, has: true });
    for (const mark of MARKS[left])
      expect({ ua, leaked: mark, found: body.includes(mark) }).toEqual({
        ua,
        leaked: mark,
        found: false,
      });
  }
}

beforeEach(() => {
  vi.stubEnv('DEV_MOCK_BACKEND', '');
  vi.stubEnv('ENVIRONMENT', 'production');
});
afterEach(() => {
  __setS3SendForTests(null);
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe('a key that switches mode in place', () => {
  test('L7 fronts to an L4 edge: every client family gets the new mode at once, nothing of the old', async () => {
    const panel = stubPanel('ws');
    const { t, subId, userId, l4Edge } = await seed('ws');
    // Warm what a member's apps leave behind: cached bodies, a pin, a snapshot.
    await expectServed(t, 'ws', 'r', CLIENTS.slice(0, 4));
    const before = (await row(t, subId))!;
    expect(before.pinnedNode).toBe('node-ws');
    expect(before.subCache).toBeDefined();
    expect(before.lastRender?.listenerKeys).toEqual(['w']);

    const res = await t.action(internal.account.switchMode, { userId, target: MODE.r });
    expect(res).toMatchObject({ ok: true, oldSubscriptionDeletedAt: null });
    expect(panel.place).toBe('r');
    const moved = (await row(t, subId))!;
    expect(moved.subToken).toBe('tok_one');
    expect(moved.backendPlacement).toBe(SQUAD.r);
    // Nothing describes the old placement any more.
    expect(moved.subCache).toBeUndefined();
    expect(moved.pinnedNode).toBeUndefined();
    expect(moved.lastRender).toBeUndefined();
    expect(moved.lastRenderedEpoch).toBeUndefined();
    expect(moved.deliveryRev).toBeGreaterThan(before.deliveryRev ?? 0);

    // The families that fetched before and the ones that never did.
    await expectServed(t, 'r', 'ws');
    const after = (await row(t, subId))!;
    expect(after.pinnedNode).toBe('node-r');
    expect(after.lastRender).toMatchObject({ listenerKeys: ['a'], primaryEdgeId: l4Edge });
  });

  test('an L4 edge to L7 fronts: the reverse holds too', async () => {
    stubPanel('r');
    const { t, subId, userId } = await seed('r');
    await expectServed(t, 'r', 'ws', CLIENTS.slice(0, 4));
    const res = await t.action(internal.account.switchMode, { userId, target: MODE.ws });
    expect(res).toMatchObject({ ok: true, oldSubscriptionDeletedAt: null });
    await expectServed(t, 'ws', 'r');
    expect((await row(t, subId))!.lastRender?.listenerKeys).toEqual(['w']);
  });

  test('to a direct privacy mode: the node itself, no front and no edge', async () => {
    stubPanel('ws');
    const { t, subId, userId } = await seed('ws');
    await expectServed(t, 'ws', 'p', CLIENTS.slice(0, 4));
    const res = await t.action(internal.account.switchMode, { userId, target: MODE.p });
    expect(res).toMatchObject({ ok: true, oldSubscriptionDeletedAt: null });
    await expectServed(t, 'p', 'ws');
    const after = (await row(t, subId))!;
    expect(after.pinnedNode).toBe('node-p');
    // Nothing was rendered, so no snapshot names the fronts it left.
    expect(after.lastRender).toBeUndefined();
  });

  test('a fetch in flight across the switch writes nothing of the old mode back', async () => {
    const ua = 'clash-verge/v1.7.0';
    const panel = stubPanel('ws');
    const { t, subId, userId } = await seed('ws');
    // The panel answers with the old group, then the switch lands before the
    // route stores that answer.
    panel.onFetch = async () => {
      const res = await t.action(internal.account.switchMode, { userId, target: MODE.r });
      expect(res).toMatchObject({ ok: true });
    };
    const racing = await get(t, ua);
    expect(racing.status).toBe(200);
    expect(await racing.text()).toContain(FRONTS[0]); // the one answer it was already giving
    const stored = (await row(t, subId))!;
    expect(stored.backendPlacement).toBe(SQUAD.r);
    // The same app's next poll is the new mode, not a cache hit on the old one.
    await expectServed(t, 'r', 'ws', [ua]);
    expect(stored.subCache).toBeUndefined();
    expect(stored.pinnedNode).toBeUndefined();
    expect(stored.lastRender).toBeUndefined();
    // A panel outage after that falls back to the new body only, never the old.
    panel.down = true;
    const fallback = await get(t, ua);
    expect(fallback.status).toBe(200);
    expect(await fallback.text()).toContain(L4_EDGE);
    // And a family with nothing cached for the new mode gets no old body either.
    const none = await get(t, 'Hiddify/2.5.7');
    expect(none.status).toBe(502);
    expect(await none.text()).not.toContain(FRONTS[0]);
  });

  test("the key's mirror is re-rendered for the new mode", async () => {
    const puts: Array<Extract<S3Op, { kind: 'put' }>> = [];
    __setS3SendForTests(async (_p, op) => {
      if (op.kind === 'put') puts.push(op);
    });
    stubPanel('ws');
    const { t, subId, userId } = await seed('ws', { mirror: true });
    await t.action(internal.account.switchMode, { userId, target: MODE.r });
    expect((await row(t, subId))!.rawContentHash).toBeUndefined();
    // The switch scheduled the refresh; run it as the scheduler would.
    const scheduled = await t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect());
    const refresh = scheduled.filter((f) => f.name.includes('refreshMirrorsForSubscription'));
    expect(refresh.map((f) => f.args[0])).toEqual([{ subscriptionId: subId }]);
    await t.action(internal.storage.refreshMirrorsForSubscription, { subscriptionId: subId });
    const put = puts.at(-1);
    expect(put?.key).toBe('mirrors/m1');
    expect(put?.body).toContain(L4_EDGE);
    for (const mark of MARKS.ws) expect(put?.body).not.toContain(mark);
    const after = (await row(t, subId))!;
    expect(after.pinnedNode).toBe('node-r');
    expect(after.rawContentHash).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('a server switch in place', () => {
  test("another group of the member's mode: the next fetch is that group's, the left node excluded", async () => {
    stubPanel('ws');
    const { t, subId, userId } = await seed('ws');
    // The member's mode spans two groups; the second one's node is `node-r`.
    await t.run(async (ctx) => {
      const pool = await ctx.db
        .query('modePlacements')
        .withIndex('by_mode_backend', (q) => q.eq('modeSlug', MODE.ws).eq('backend', 'remnawave'))
        .unique();
      await ctx.db.patch(pool!._id, {
        config: JSON.stringify({ squadUuids: [SQUAD.ws, SQUAD.r] }),
      });
    });
    await expectServed(t, 'ws', 'r', CLIENTS.slice(0, 4));
    const res = await t.action(internal.account.switchServer, { userId, reason: 'blocked' });
    expect(res).toMatchObject({ ok: true, inPlace: true, oldSubscriptionDeletedAt: null });
    const moved = (await row(t, subId))!;
    expect(moved).toMatchObject({ backendPlacement: SQUAD.r, excludeNode: 'node-ws' });
    expect(moved.subCache).toBeUndefined();
    expect(moved.pinnedNode).toBeUndefined();
    expect(moved.lastRender).toBeUndefined();
    await expectServed(t, 'r', 'ws');
  });
});

describe('a pin rotation (switch server)', () => {
  test('drops what was delivered from the node and refuses writes read before it', async () => {
    stubPanel('ws');
    const { t, subId } = await seed('ws');
    await expectServed(t, 'ws', 'r', ['v2rayNG/1.9.0']);
    const before = (await row(t, subId))!;
    expect(before.pinnedNode).toBe('node-ws');
    const rev = before.deliveryRev ?? 0;
    expect(await t.mutation(internal.subscriptions.rotateNodePin, { subscriptionId: subId })).toBe(
      'node-ws',
    );
    const rotated = (await row(t, subId))!;
    expect(rotated).toMatchObject({ excludeNode: 'node-ws', deliveryRev: rev + 1 });
    expect(rotated.subCache).toBeUndefined();
    expect(rotated.pinnedNode).toBeUndefined();
    expect(rotated.lastRender).toBeUndefined();
    // What a request that read the row before the rotation still tries to write.
    await t.mutation(internal.subscriptions.writeContentCache, {
      subscriptionId: subId,
      entry: before.subCache ? JSON.stringify(JSON.parse(before.subCache)[0]) : '{}',
      deliveryRev: rev,
    });
    await t.mutation(internal.subscriptions.recordPinnedNode, {
      subscriptionId: subId,
      node: 'node-ws',
      deliveryRev: rev,
    });
    const { at: _at, ...snapshot } = before.lastRender!;
    await t.mutation(internal.subscriptions.markDelivered, {
      subscriptionId: subId,
      contentAt: Date.now(),
      renderedEpoch: before.lastRenderedEpoch ?? null,
      render: snapshot,
      deliveryRev: rev,
    });
    const after = (await row(t, subId))!;
    expect(after.subCache).toBeUndefined();
    expect(after.pinnedNode).toBeUndefined();
    expect(after.lastRender).toBeUndefined();
    expect(after.lastRenderedEpoch).toBeUndefined();
  });
});
