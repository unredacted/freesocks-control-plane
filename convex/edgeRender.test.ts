/// <reference types="vite/client" />
/**
 * Relay rendering through the FCP-fronted subscription route under the
 * EDGE-REQUIRED delivery policy: a subscription whose resolved place a relay
 * covers is served a rendered body that passed every check, or a 503 with the
 * reason in `x-fcp-delivery`; the origin body only ever leaves for a place no
 * relay covers. The cache token follows the binding's policy version and the
 * origin's publication epoch, and every render is snapshotted on the row.
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { qualificationBinding } from './lib/edges/frontCheck/binding';
import { publishedEdgesOf } from './edgeRender';
import {
  FIXTURE_NODE,
  FIXTURE_ORIGIN,
  realityListener,
  seedEdgeFixture,
  wsListener,
  type ListenerSpecFixture,
} from './lib/edges/testing/fixtures';

const modules = import.meta.glob('./**/*.*s');

afterEach(() => vi.unstubAllGlobals());

const NODE = FIXTURE_NODE;
const ORIGIN = FIXTURE_ORIGIN;
const EDGE_A = '198.51.100.1';
const EDGE_A6 = '2001:db8::1';
const EDGE_B = '198.51.100.2';
const UUID = '11111111-2222-4333-8444-555555555555';
const REALITY_QS =
  'encryption=none&flow=xtls-rprx-vision&security=reality&sni=target.example&fp=chrome&pbk=PUBKEY&sid=abcd&type=tcp';
const NAMES = ['a.example', 'b.example', 'c.example'];
/** The REALITY listener's template Host remark (`<node>-relay-<listenerKey>`). */
const TEMPLATE = `${NODE}-relay-a`;
/** What the panel serves for the relay node: the template Host, pointing at the pool-index-0 edge. */
const panelBody = `vless://${UUID}@${EDGE_A}:443?${REALITY_QS}#${TEMPLATE}`;

let fetchCalls = 0;
function stubPanel(body = panelBody) {
  fetchCalls = 0;
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => {
      fetchCalls += 1;
      return new Response(body, { status: 200, headers: { 'content-type': 'text/plain' } });
    }),
  );
}

/**
 * An L7 front is only rendered while an authenticated end-to-end session has
 * PROVEN the configuration that would be published, so a hostname edge in a
 * test needs the same frozen intent + proof a provisioned one carries.
 */
async function proveFront(
  t: ReturnType<typeof convexTest>,
  edgeId: Id<'edges'>,
  hostname: string,
  ok = true,
) {
  await t.run(async (ctx) => {
    const edge = (await ctx.db.get(edgeId))!;
    const listener = (await ctx.db.get(edge.listenerId))!;
    const intent = {
      hostname,
      zoneId: 'z'.repeat(32),
      zoneName: 'example',
      originTransport: listener.originTransport ?? {
        scheme: 'https' as const,
        certPublic: true,
        certNames: [],
        acceptsHostHeader: 'any' as const,
      },
      originPort: listener.originPort,
      zoneSslMode: 'full',
      templateHash: 'h1',
      templateParams: {},
    };
    const now = Date.now();
    await ctx.db.patch(edgeId, {
      provisionIntent: JSON.stringify(intent),
      frontQualification: {
        ok,
        ...(ok ? {} : { code: 'front_error' }),
        checkedAt: now,
        expiresAt: now + 3_600_000,
        binding: qualificationBinding({ listener, intent, params: listener.transportParams ?? {} }),
      },
    });
  });
}

async function seed(
  opts: {
    renderEnabled?: boolean;
    pinned?: boolean;
    listeners?: ListenerSpecFixture[];
    publish?: boolean;
  } = {},
) {
  const t = convexTest(schema, modules);
  const fx = await seedEdgeFixture(t, {
    listeners: opts.listeners ?? [realityListener({ tlsNames: NAMES })],
  });
  const subId = await t.run(async (ctx) => {
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
      supportId: 'SUP-1',
      updatedAt: Date.now(),
    });
    const subId = await ctx.db.insert('subscriptions', {
      userId,
      backend: 'remnawave',
      backendUserId: 'uuid-1',
      backendShortId: 'short-1',
      backendServerId: fx.serverId,
      subscriptionUrl: 'https://panel.example/sub/short-1',
      subscriptionMirrors: [],
      subToken: 'tok_abc',
      state: 'active',
      ...(opts.pinned === false ? {} : { pinnedNode: NODE }),
      updatedAt: Date.now(),
    });
    await ctx.db.patch(userId, { currentSubscriptionId: subId });
    if (opts.renderEnabled !== false) await upsertSettingRow(ctx, 'edge.render.enabled', 'true');
    return subId;
  });
  const a = await t.mutation(internal.relays.adoptEdge, {
    relayId: fx.relayId,
    listenerId: fx.listenerId,
    ipv4: EDGE_A,
    ipv6: EDGE_A6,
    publish: opts.publish ?? true,
  });
  return {
    t,
    serverId: fx.serverId,
    subId,
    relayId: fx.relayId,
    listenerId: fx.listenerId,
    edgeA: a.edgeId as Id<'edges'>,
  };
}

const get = (t: ReturnType<typeof convexTest>, ua = 'v2rayNG/1.9.0') =>
  t.fetch('/api/v1/sub/tok_abc', { headers: { 'user-agent': ua } });

const proxyLines = (body: string) =>
  body.split('\n').filter((l) => /^(vless|ss|trojan):\/\//.test(l));
const labelOf = (line: string) => decodeURIComponent(line.split('#')[1] ?? '');

type CacheEntry = { relay: string | null; renderedEpoch: number | null; at: number };
const cacheOf = (sub: Doc<'subscriptions'>) => JSON.parse(sub.subCache!) as CacheEntry[];

async function expireCache(t: ReturnType<typeof convexTest>, subId: Id<'subscriptions'>) {
  await t.run(async (ctx) => {
    const s = (await ctx.db.get(subId))!;
    const entries = cacheOf(s);
    await ctx.db.patch(subId, {
      subCache: JSON.stringify(entries.map((e) => ({ ...e, at: e.at - 120_000 }))),
    });
  });
}

describe('edgeRender: fronted route (edge-required delivery)', () => {
  test('replaces the template with labelled primary (+ IPv6) entries, stores the string cache token and the render snapshot', async () => {
    stubPanel();
    const { t, subId, relayId, edgeA } = await seed();
    const res = await get(t);
    expect(res.status).toBe(200);
    const body = await res.text();
    const lines = proxyLines(body);
    expect(body).not.toContain(`#${TEMPLATE}`);
    expect(body).not.toContain(ORIGIN);
    const primary = lines.filter((l) => labelOf(l).startsWith('FreeSocks Primary'));
    expect(primary).toHaveLength(2); // v4 + v6 of the single published edge, no backup
    expect(primary[0]).toContain(`@${EDGE_A}:443?`);
    expect(primary[1]).toContain(`@[${EDGE_A6}]:443?`);
    // One SNI per emitted connection, from the listener's active names; REALITY params kept.
    for (const l of primary) {
      const qs = new URLSearchParams(l.slice(l.indexOf('?') + 1, l.indexOf('#')));
      expect(NAMES).toContain(qs.get('sni'));
      expect(qs.get('security')).toBe('reality');
      expect(qs.get('pbk')).toBe('PUBKEY');
    }
    expect(lines.some((l) => labelOf(l).startsWith('FreeSocks Backup'))).toBe(false);
    // The sub got a render key; the cache entry carries the `<policyVersion>:<epoch>` token.
    const sub = (await t.run((ctx) => ctx.db.get(subId)))!;
    const relay = (await t.run((ctx) => ctx.db.get(relayId)))!;
    expect(sub.renderKey).toMatch(/^[0-9a-f]{64}$/);
    const cache = cacheOf(sub);
    expect(cache[0].relay).toBe(`1:${relay.publicationEpoch}`);
    expect(cache[0].renderedEpoch).toBe(relay.publicationEpoch);
    // markDelivered persisted the eligibility snapshot of this render.
    expect(sub.lastRenderedEpoch).toBe(relay.publicationEpoch);
    expect(sub.lastRender).toMatchObject({
      epoch: relay.publicationEpoch,
      family: 'v2rayng',
      listenerKeys: ['a'],
      primaryEdgeId: edgeA,
    });
    expect(sub.lastRender!.backupEdgeId).toBeUndefined();
    expect(sub.lastRender!.at).toBeGreaterThan(0);
  });

  test('stable per subscriber: repeated fetches (cache hit and re-fetch) emit the same SNI', async () => {
    stubPanel();
    const { t, subId } = await seed();
    const first = await (await get(t)).text();
    expect(fetchCalls).toBe(1);
    const second = await (await get(t)).text();
    expect(fetchCalls).toBe(1); // cache hit: same UA, same token
    expect(second).toBe(first);
    // Expire the cache → re-fetch + re-render → byte-identical again (same renderKey + epoch).
    await expireCache(t, subId);
    const third = await (await get(t)).text();
    expect(fetchCalls).toBe(2);
    expect(third).toBe(first);
  });

  test('a pool change invalidates the cache within one request, adds the backup entry and updates the snapshot', async () => {
    stubPanel();
    const { t, subId, relayId, listenerId } = await seed();
    const first = await (await get(t)).text();
    expect(first).not.toContain('FreeSocks%20Backup');
    expect(fetchCalls).toBe(1);
    // Publish a second edge (epoch bump) → the fresh cache entry is no longer valid.
    const b = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      listenerId,
      ipv4: EDGE_B,
      publish: true,
    });
    const body = await (await get(t)).text();
    expect(fetchCalls).toBe(2);
    const lines = proxyLines(body);
    const labels = lines.map(labelOf);
    expect(labels.filter((l) => l.startsWith('FreeSocks Primary')).length).toBeGreaterThan(0);
    expect(labels.filter((l) => l.startsWith('FreeSocks Backup')).length).toBeGreaterThan(0);
    // Primary and backup are different edges.
    const addrOf = (l: string) => l.slice(l.indexOf('@') + 1, l.indexOf(':443'));
    const primaryAddr = addrOf(
      lines.find((l) => l.includes('FreeSocks%20Primary') && !l.includes('['))!,
    );
    const backupAddr = addrOf(lines.find((l) => l.includes('FreeSocks%20Backup'))!);
    expect(primaryAddr).not.toBe(backupAddr);
    expect([EDGE_A, EDGE_B]).toContain(primaryAddr);
    expect([EDGE_A, EDGE_B]).toContain(backupAddr);
    const sub = (await t.run((ctx) => ctx.db.get(subId)))!;
    expect(new Set([sub.lastRender!.primaryEdgeId, sub.lastRender!.backupEdgeId])).toEqual(
      new Set([b.edgeId, (await t.run((ctx) => ctx.db.get(relayId)))!.publishedEdgeIds[0]]),
    );
  });

  test('render switch off: 503 render_disabled (never the origin body); turning it on re-renders within one request', async () => {
    stubPanel();
    const { t, serverId } = await seed({ renderEnabled: false });
    const res = await get(t);
    expect(res.status).toBe(503);
    expect(res.headers.get('x-fcp-delivery')).toBe('render_disabled');
    expect(res.headers.get('cache-control')).toBe('private, no-store');
    expect(await res.text()).not.toContain('vless://');
    // The token says "edge-required, nothing publishable" while the switch is off.
    expect(
      await t.query(internal.edgeRender.epochFor, { backendServerId: serverId, nodeName: NODE }),
    ).toBe('1:-1');
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.render.enabled', 'true'));
    const after = await get(t);
    expect(after.status).toBe(200);
    expect(await after.text()).toContain('FreeSocks%20Primary');
    expect(fetchCalls).toBe(2);
  });

  test('a disabled relay: 503 relay_disabled', async () => {
    stubPanel();
    const { t, relayId, serverId } = await seed();
    await t.mutation(internal.relays.update, { id: relayId, enabled: false });
    const res = await get(t);
    expect(res.status).toBe(503);
    expect(res.headers.get('x-fcp-delivery')).toBe('relay_disabled');
    expect(
      await t.query(internal.edgeRender.epochFor, { backendServerId: serverId, nodeName: NODE }),
    ).toBe('1:-1');
  });

  test('a binding whose relay row is gone (keep-dark): 503 relay_missing', async () => {
    stubPanel();
    const { t, relayId, subId } = await seed();
    await t.run((ctx) => ctx.db.delete(relayId));
    expect(
      await t.query(internal.edgeRender.decideForSubscription, {
        subscriptionId: subId,
        family: 'other',
      }),
    ).toEqual({ kind: 'unavailable', reason: 'relay_missing', relaySlug: NODE });
    const res = await get(t);
    expect(res.status).toBe(503);
    expect(res.headers.get('x-fcp-delivery')).toBe('relay_missing');
  });

  test('a body without the listener template: 503 no_match, nothing cached, no snapshot', async () => {
    // A direct Host that is not this listener's template (and not at the origin).
    stubPanel(`vless://${UUID}@198.51.100.50:443?${REALITY_QS}#${NODE}-reality`);
    const { t, subId } = await seed();
    const res = await get(t);
    expect(res.status).toBe(503);
    // No listener resolves in the body, so every edge is ineligible and the
    // pipeline judges the pool empty before any codec runs.
    expect(res.headers.get('x-fcp-delivery')).toBe('empty_pool');
    const sub = (await t.run((ctx) => ctx.db.get(subId)))!;
    expect(sub.subCache).toBeUndefined();
    expect(sub.lastRender).toBeUndefined();
    expect(sub.lastRenderedEpoch).toBeUndefined();
  });

  test('a body that still hands out the origin address is refused: 503 leak_detected', async () => {
    stubPanel(
      [panelBody, `vless://${UUID}@${ORIGIN}:443?${REALITY_QS}#${NODE}-reality`].join('\n'),
    );
    const { t } = await seed();
    const res = await get(t);
    expect(res.status).toBe(503);
    expect(res.headers.get('x-fcp-delivery')).toBe('leak_detected');
  });

  test('a disabled client family is unavailable too (never the origin body) while others render', async () => {
    stubPanel();
    const { t } = await seed();
    await t.run((ctx) =>
      upsertSettingRow(ctx, 'edge.render.clients.v2rayng', JSON.stringify({ enabled: false })),
    );
    const v2 = await get(t, 'v2rayNG/1.9.0');
    expect(v2.status).toBe(503);
    expect(v2.headers.get('x-fcp-delivery')).toBe('render_disabled');
    const other = await get(t, 'curl/8.0');
    expect(other.status).toBe(200);
    expect(await other.text()).toContain('FreeSocks%20Primary');
  });

  test('the raw body is served ONLY for a place no relay covers (token null, decision raw)', async () => {
    const raw = `vless://${UUID}@198.51.100.60:443?${REALITY_QS}#node-nine-relay-a`;
    stubPanel(raw);
    const { t, subId, serverId } = await seed({ pinned: false });
    const res = await get(t);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(raw);
    const sub = (await t.run((ctx) => ctx.db.get(subId)))!;
    expect(sub.pinnedNode).toBe('node-nine');
    expect(cacheOf(sub)[0].relay).toBeNull();
    expect(sub.lastRender).toBeUndefined();
    expect(
      await t.query(internal.edgeRender.epochFor, {
        backendServerId: serverId,
        nodeName: 'node-nine',
      }),
    ).toBeNull();
    expect(
      await t.query(internal.edgeRender.decideForSubscription, {
        subscriptionId: subId,
        family: 'other',
      }),
    ).toEqual({ kind: 'raw' });
    expect(
      await t.query(internal.edgeRender.deliveryPolicy, {
        backendServerId: serverId,
        nodeName: 'node-nine',
      }),
    ).toEqual({ required: false, bindingVersion: null, relayId: null, relaySlug: null });
  });

  test('the cache token follows the delivery binding policy version', async () => {
    stubPanel();
    const { t, subId, serverId, relayId } = await seed();
    await get(t);
    const epoch = (await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch;
    expect(
      await t.query(internal.edgeRender.epochFor, { backendServerId: serverId, nodeName: NODE }),
    ).toBe(`1:${epoch}`);
    expect(
      await t.query(internal.edgeRender.deliveryPolicy, {
        backendServerId: serverId,
        nodeName: NODE,
      }),
    ).toEqual({ required: true, bindingVersion: 1, relayId, relaySlug: NODE });
    // The binding is re-claimed (policy version bump): the token changes and a
    // fresh cache entry is no longer valid even inside its TTL.
    await t.run(async (ctx) => {
      const b = (await ctx.db
        .query('edgeDeliveryBindings')
        .withIndex('by_server_node', (q) => q.eq('backendServerId', serverId).eq('nodeName', NODE))
        .unique())!;
      await ctx.db.patch(b._id, { policyVersion: b.policyVersion + 1 });
    });
    expect(
      await t.query(internal.edgeRender.epochFor, { backendServerId: serverId, nodeName: NODE }),
    ).toBe(`2:${epoch}`);
    expect(fetchCalls).toBe(1);
    await get(t);
    expect(fetchCalls).toBe(2);
    expect(cacheOf((await t.run((ctx) => ctx.db.get(subId)))!)[0].relay).toBe(`2:${epoch}`);
  });

  test('publishedEdgesOf returns the pool with listener matchers; decideForSubscription hands the route a render context', async () => {
    stubPanel();
    const { t, subId, relayId, listenerId, edgeA } = await seed();
    const view = await t.run(async (ctx) => publishedEdgesOf(ctx, (await ctx.db.get(relayId))!));
    expect(view.matchers).toEqual([
      {
        listenerKey: 'a',
        rule: { kind: 'remark', remark: TEMPLATE },
        legacyRemarks: [],
        proto: { protocol: 'vless', streamTransport: 'raw', security: 'reality' },
        originAddress: ORIGIN,
        originPort: 443,
      },
    ]);
    expect(view.published).toHaveLength(1);
    expect(view.published[0]).toMatchObject({
      edgeId: edgeA,
      poolIndex: 0,
      provider: 'adopted',
      listenerId,
      listenerKey: 'a',
      matchRule: { kind: 'remark', remark: TEMPLATE },
      proto: { protocol: 'vless', streamTransport: 'raw', security: 'reality' },
      layer: 'l4',
      addresses: { v4: EDGE_A, v6: EDGE_A6 },
    });
    expect(view.published[0].serverNames.map((s) => s.sni)).toEqual(NAMES);
    expect(view.published[0].eligible).toBeUndefined();
    // Before the first fetch there is no render key: the route mints one, so
    // the decision is still `render` (a never-rendered key must not 503 forever).
    const fresh = await t.query(internal.edgeRender.decideForSubscription, {
      subscriptionId: subId,
      family: 'singbox',
    });
    expect(fresh.kind).toBe('render');
    if (fresh.kind === 'render') expect(fresh.context.renderKey).toBeNull();
    await get(t);
    const decision = await t.query(internal.edgeRender.decideForSubscription, {
      subscriptionId: subId,
      family: 'singbox',
    });
    expect(decision.kind).toBe('render');
    if (decision.kind !== 'render') throw new Error('unreachable');
    expect(decision.context.published.map((p) => p.edgeId)).toEqual([edgeA]);
    expect(decision.context.matchers.map((m) => m.listenerKey)).toEqual(['a']);
    expect(decision.context.rule.autoGroup).toBe(true);
    expect(decision.context.originAddress).toBe(ORIGIN);
    expect(decision.context.deliveryStyle).toBe('subscription');
    expect(decision.context.renderKey).toMatch(/^[0-9a-f]{64}$/);
    // A disabled listener keeps its pool index but is ineligible (default view drops it).
    await t.run((ctx) => ctx.db.patch(listenerId, { enabled: false }));
    const relay = (await t.run((ctx) => ctx.db.get(relayId)))!;
    expect((await t.run((ctx) => publishedEdgesOf(ctx, relay))).published).toEqual([]);
    const all = await t.run((ctx) => publishedEdgesOf(ctx, relay, { includeIneligible: true }));
    expect(all.published[0]).toMatchObject({ edgeId: edgeA, poolIndex: 0, eligible: false });
    expect(all.matchers).toEqual([]);
  });

  test('an emptied pool is 503 empty_pool, never a body with the template dropped', async () => {
    stubPanel();
    const { t, relayId, edgeA, serverId } = await seed();
    const before = await (await get(t)).text();
    expect(before).toContain('FreeSocks%20Primary');
    const epochBefore = (await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch;
    await t.mutation(internal.relays.unpublishEdge, { relayId, edgeId: edgeA, keepActive: true });
    // The epoch bump invalidated the cache within one request.
    expect(
      await t.query(internal.edgeRender.epochFor, { backendServerId: serverId, nodeName: NODE }),
    ).toBe(`1:${epochBefore + 1}`);
    const res = await get(t);
    expect(res.status).toBe(503);
    expect(res.headers.get('x-fcp-delivery')).toBe('empty_pool');
    expect(fetchCalls).toBe(2);
  });

  test('an L7 (hostname) edge renders as ONE hostname entry; a failed requalification takes it out at once', async () => {
    const WS_TEMPLATE = `${NODE}-relay-w`;
    const wsBody = `vless://${UUID}@${EDGE_A}:443?encryption=none&security=tls&sni=ws.example&fp=chrome&type=ws&path=%2Fws&host=ws.example#${WS_TEMPLATE}`;
    stubPanel(wsBody);
    const { t, subId, edgeA, relayId } = await seed({ listeners: [wsListener()] });
    const HOSTNAME = 'front-a.example';
    // What the CDN provider's adapter leaves on the row: a hostname, no literal.
    await t.run((ctx) => ctx.db.patch(edgeA, { layer: 'l7', addresses: { hostname: HOSTNAME } }));
    await proveFront(t, edgeA, HOSTNAME);
    const view = await t.run(async (ctx) =>
      publishedEdgesOf(ctx, (await ctx.db.get(relayId))!, { includeIneligible: true }),
    );
    expect(view.published).toHaveLength(1);
    expect(view.published[0]).toMatchObject({ layer: 'l7', addresses: { hostname: HOSTNAME } });
    expect(view.published[0].eligible).toBeUndefined(); // a hostname IS a publish address
    const lines = proxyLines(await (await get(t)).text());
    const primary = lines.filter((l) => l.includes('FreeSocks%20Primary'));
    // One entry only: an L7 front has no address families of its own.
    expect(primary).toHaveLength(1);
    expect(primary[0]).toContain(`@${HOSTNAME}:443?`);
    const qs = new URLSearchParams(
      primary[0].slice(primary[0].indexOf('?') + 1, primary[0].indexOf('#')),
    );
    // The hostname is the SNI and the HTTP Host, whatever the listener's origin-facing names say.
    expect(qs.get('sni')).toBe(HOSTNAME);
    expect(qs.get('host')).toBe(HOSTNAME);
    expect(qs.get('path')).toBe('/ws');
    expect((await t.run((ctx) => ctx.db.get(subId)))!.lastRender).toMatchObject({
      listenerKeys: ['w'],
      primaryEdgeId: edgeA,
    });

    // A requalification that comes back FAILED takes the front out of
    // assignment at once: DNS keeps answering long after a front stops carrying
    // the transport, so the stored proof is the only thing that may keep it
    // live. Recording the failure also bumps the epoch, so cached bodies stop
    // handing the hostname out; with no other edge the pool is empty → 503.
    const epochBefore = (await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch;
    const binding = await t.run(async (ctx) => {
      const edge = (await ctx.db.get(edgeA))!;
      const listener = (await ctx.db.get(edge.listenerId))!;
      return qualificationBinding({
        listener,
        intent: JSON.parse(edge.provisionIntent!),
        params: listener.transportParams ?? {},
      });
    });
    const rec = await t.mutation(internal.frontQualify.record, {
      edgeId: edgeA,
      binding,
      result: { ok: false, code: 'front_error', steps: [], checkedAt: Date.now() },
    });
    expect(rec).toEqual({ ok: false, code: 'front_error' });
    const failed = await t.run(async (ctx) =>
      publishedEdgesOf(ctx, (await ctx.db.get(relayId))!, { includeIneligible: true }),
    );
    expect(failed.published[0].eligible).toBe(false);
    expect((await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch).toBe(epochBefore + 1);
    const res = await get(t);
    expect(res.status).toBe(503);
    expect(res.headers.get('x-fcp-delivery')).toBe('empty_pool');
    // A failed proof expires SOON (a few poll intervals), so the reconcile cron
    // re-runs the check instead of waiting out a whole qualification TTL.
    const after = await t.run((ctx) => ctx.db.get(edgeA));
    const q = after!.frontQualification!;
    expect(q.expiresAt - q.checkedAt).toBeLessThan(60 * 60_000);
  });

  test('panel outage: the stale fallback is served only while its edge token is still current', async () => {
    stubPanel();
    const { t, relayId, edgeA, subId } = await seed();
    const first = await (await get(t)).text();
    expect(first).toContain('FreeSocks%20Primary');
    // Panel down, pool unchanged → the last-known body for this UA is fine.
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('connect ECONNREFUSED');
      }),
    );
    await expireCache(t, subId);
    const stale = await get(t);
    expect(stale.status).toBe(200);
    expect(await stale.text()).toBe(first);
    // Unpublish (epoch bump) while the panel is still down: the cached body
    // carries the removed edge and must NOT be served as a fallback.
    await t.mutation(internal.relays.unpublishEdge, { relayId, edgeId: edgeA, keepActive: true });
    const refused = await get(t);
    expect(refused.status).toBe(502);
  });

  test('memberView: labels only from the persisted snapshot; known:false without one; nudge once the epoch moved', async () => {
    stubPanel();
    const { t, subId, relayId } = await seed();
    // Not fetched yet: no snapshot → labels unknown, no nudge (never rotated).
    let view = await t.query(internal.edgeRender.memberView, { subscriptionId: subId });
    expect(view).toEqual({ refreshSuggested: false, known: false, connections: [] });
    await get(t); // delivers + mints the render key + stores the snapshot
    view = await t.query(internal.edgeRender.memberView, { subscriptionId: subId });
    expect(view?.refreshSuggested).toBe(false);
    expect(view?.known).toBe(true);
    expect(view?.connections.map((c) => [c.role, c.family])).toEqual([
      ['primary', 'v4'],
      ['primary', 'v6'],
    ]);
    expect(view?.connections[0].label).toContain('FreeSocks Primary');
    expect(JSON.stringify(view)).not.toContain(EDGE_A);
    // The delivery stamped the epoch the body was rendered against.
    const relay = (await t.run((ctx) => ctx.db.get(relayId)))!;
    expect((await t.run((ctx) => ctx.db.get(subId)))!.lastRender!.epoch).toBe(
      relay.publicationEpoch,
    );
    // A rotation stamps lastRotatedAt but the epoch comparison is what counts
    // now: an unchanged epoch means the member already holds the current pool.
    await t.run((ctx) => ctx.db.patch(relayId, { lastRotatedAt: Date.now() + 1 }));
    view = await t.query(internal.edgeRender.memberView, { subscriptionId: subId });
    expect(view?.refreshSuggested).toBe(false);
    // Any epoch bump after this key's last render → nudge, and the stale
    // snapshot's labels are no longer trusted.
    await t.mutation(internal.relays.bumpEpoch, { relayId });
    view = await t.query(internal.edgeRender.memberView, { subscriptionId: subId });
    expect(view).toEqual({ refreshSuggested: true, known: false, connections: [] });
    // …until the next delivery renders against the new epoch.
    await get(t);
    view = await t.query(internal.edgeRender.memberView, { subscriptionId: subId });
    expect(view?.refreshSuggested).toBe(false);
    expect(view?.known).toBe(true);
    // A key behind a disabled relay gets null.
    await t.mutation(internal.relays.update, { id: relayId, enabled: false });
    expect(await t.query(internal.edgeRender.memberView, { subscriptionId: subId })).toBeNull();
  });
});

// The REAL topology: one squad per node, so every member body carries exactly
// ONE node. Pinning must still report that node (there is nothing to filter)
// or the pin is never recorded and the delivery policy never sees the place.
// Each body family is exercised with a sub that has NO stored pin.
describe('edgeRender: single-node bodies (one squad per node)', () => {
  const singleLinks = panelBody;
  const singleSingbox = JSON.stringify({
    outbounds: [
      { type: 'selector', tag: 'proxy', outbounds: [TEMPLATE, 'direct'], default: TEMPLATE },
      {
        type: 'vless',
        tag: TEMPLATE,
        server: EDGE_A,
        server_port: 443,
        uuid: UUID,
        flow: 'xtls-rprx-vision',
        tls: {
          enabled: true,
          server_name: 'target.example',
          reality: { enabled: true, public_key: 'PUBKEY', short_id: 'abcd' },
        },
      },
      { type: 'direct', tag: 'direct' },
    ],
    route: { final: 'proxy' },
  });
  const singleClash = [
    'mixed-port: 7890',
    'proxies:',
    `  - {name: ${TEMPLATE}, type: vless, server: ${EDGE_A}, port: 443, uuid: ${UUID}, tls: true, servername: target.example, network: tcp, flow: xtls-rprx-vision, reality-opts: {public-key: PUBKEY, short-id: abcd}}`,
    'proxy-groups:',
    `  - {name: proxy, type: select, proxies: [${TEMPLATE}]}`,
    'rules:',
    '  - MATCH,proxy',
  ].join('\n');

  test('links: the template line is replaced by the assigned edge, the pin is recorded, the token stored', async () => {
    stubPanel(singleLinks);
    const { t, subId, relayId } = await seed({ pinned: false });
    const body = await (await get(t)).text();
    const lines = proxyLines(body);
    expect(body).not.toContain(`#${TEMPLATE}`);
    const primary = lines.filter((l) => l.includes('FreeSocks%20Primary'));
    expect(primary).toHaveLength(2); // v4 + v6 of the one published edge
    expect(primary[0]).toContain(`@${EDGE_A}:443?`);
    const sub = (await t.run((ctx) => ctx.db.get(subId)))!;
    expect(sub.pinnedNode).toBe(NODE);
    expect(sub.renderKey).toMatch(/^[0-9a-f]{64}$/);
    const relay = (await t.run((ctx) => ctx.db.get(relayId)))!;
    expect(sub.lastRenderedEpoch).toBe(relay.publicationEpoch);
    expect(cacheOf(sub)[0].relay).toBe(`1:${relay.publicationEpoch}`);
    // Second poll: cache hit (the token computed from the recorded pin matches).
    await get(t);
    expect(fetchCalls).toBe(1);
  });

  test('sing-box: the template outbound is cloned per endpoint and the auto group added', async () => {
    stubPanel(singleSingbox);
    const { t, subId } = await seed({ pinned: false });
    const res = await get(t, 'SFA/1.10.0 (sing-box 1.10.0)');
    expect(res.status).toBe(200);
    const cfg = JSON.parse(await res.text()) as { outbounds: Array<Record<string, unknown>> };
    const tags = cfg.outbounds.map((o) => o.tag);
    expect(tags).not.toContain(TEMPLATE);
    expect(tags).toContain('FreeSocks Primary');
    expect(tags).toContain('FreeSocks Auto');
    const emitted = cfg.outbounds.find((o) => o.tag === 'FreeSocks Primary')!;
    expect(emitted).toMatchObject({ server: EDGE_A, server_port: 443, uuid: UUID });
    expect(NAMES).toContain((emitted.tls as { server_name: string }).server_name);
    const selector = cfg.outbounds.find((o) => o.type === 'selector')!;
    expect(selector.default).toBe('FreeSocks Auto');
    expect(JSON.stringify(cfg)).not.toContain(JSON.stringify(TEMPLATE));
    const sub = (await t.run((ctx) => ctx.db.get(subId)))!;
    expect(sub.pinnedNode).toBe(NODE);
    expect(sub.lastRender?.family).toBe('singbox');
  });

  test('Clash / Mihomo: the template proxy is cloned, the url-test group listed first', async () => {
    stubPanel(singleClash);
    const { t, subId } = await seed({ pinned: false });
    const res = await get(t, 'clash-verge/v1.7.0');
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).not.toContain(TEMPLATE);
    expect(text).toContain('FreeSocks Primary');
    expect(text).toContain('FreeSocks Auto');
    expect(text).toContain(`server: ${EDGE_A}`);
    expect((await t.run((ctx) => ctx.db.get(subId)))!.pinnedNode).toBe(NODE);
  });

  test('empty pool: every family gets 503 empty_pool (nothing of the former edge, and no empty body)', async () => {
    for (const [body, ua] of [
      [singleLinks, 'v2rayNG/1.9.0'],
      [singleSingbox, 'SFA/1.10.0 (sing-box 1.10.0)'],
      [singleClash, 'clash-verge/v1.7.0'],
    ] as const) {
      stubPanel(body);
      const { t, relayId, edgeA, subId } = await seed({ pinned: false });
      await t.mutation(internal.relays.unpublishEdge, { relayId, edgeId: edgeA, keepActive: true });
      const res = await get(t, ua);
      expect(res.status).toBe(503);
      expect(res.headers.get('x-fcp-delivery')).toBe('empty_pool');
      const text = await res.text();
      expect(text).not.toContain(TEMPLATE);
      expect(text).not.toContain(EDGE_A);
      // The pin was still recorded (the place is known), but nothing was cached.
      const sub = (await t.run((ctx) => ctx.db.get(subId)))!;
      expect(sub.pinnedNode).toBe(NODE);
      expect(sub.subCache).toBeUndefined();
    }
  });
});
