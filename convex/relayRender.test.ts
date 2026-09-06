/// <reference types="vite/client" />
/**
 * Relay rendering through the FCP-fronted subscription route: the pinned
 * node's template entry is replaced by the subscriber's assigned edges, the
 * cache token follows the publication epoch, and everything passes through
 * unchanged while rendering is off.
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { pickNode } from './lib/nodePinning';

const modules = import.meta.glob('./**/*.*s');

afterEach(() => vi.unstubAllGlobals());

// Pinning is a rendezvous pick on the sub's backendShortId ('short-1'): derive
// which of the two fixture nodes it lands on so the origin is that node.
const NODE = pickNode('short-1', ['node-one', 'node-two'])!;
const OTHER = NODE === 'node-one' ? 'node-two' : 'node-one';
const ORIGIN = '203.0.113.10';
const EDGE_A = '198.51.100.1';
const EDGE_A6 = '2001:db8::1';
const EDGE_B = '198.51.100.2';
const UUID = '11111111-2222-4333-8444-555555555555';
const REALITY_QS =
  'encryption=none&flow=xtls-rprx-vision&security=reality&sni=target.example&fp=chrome&pbk=PUBKEY&sid=abcd&type=tcp';

// What the panel serves for the shared relay squad: two nodes' relay templates
// (the template Host points at each node's pool-index-0 edge), plus a direct
// REALITY Host for node-one. Pinning keeps ONE node; rendering replaces its
// relay template.
const panelBody = [
  `vless://${UUID}@${EDGE_A}:443?${REALITY_QS}#${NODE}-relay-u`,
  `vless://${UUID}@${ORIGIN}:443?${REALITY_QS}#${NODE}-reality`,
  `vless://${UUID}@198.51.100.77:443?${REALITY_QS}#${OTHER}-relay-u`,
].join('\n');

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

async function seed(opts: { renderEnabled?: boolean } = {}) {
  const t = convexTest(schema, modules);
  const { serverId, subId } = await t.run(async (ctx) => {
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
    const serverId = await ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'panel-a',
      slug: 'panel-a',
      config: { type: 'remnawave', baseUrl: 'https://panel.example', apiToken: 'tok' },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: Date.now(),
    });
    const subId = await ctx.db.insert('subscriptions', {
      userId,
      backend: 'remnawave',
      backendUserId: 'uuid-1',
      backendShortId: 'short-1',
      backendServerId: serverId,
      subscriptionUrl: 'https://panel.example/sub/short-1',
      subscriptionMirrors: [],
      subToken: 'tok_abc',
      state: 'active',
      pinnedNode: NODE,
      updatedAt: Date.now(),
    });
    await ctx.db.patch(userId, { currentSubscriptionId: subId });
    if (opts.renderEnabled !== false) await upsertSettingRow(ctx, 'relay.render.enabled', 'true');
    return { serverId, subId };
  });
  await t.mutation(internal.relayProfiles.create, {
    slug: 'prof-u',
    name: 'Profile U',
    provider: 'upcloud',
    targetAddress: 'target.example',
    serverNames: ['a.example', 'b.example', 'c.example'],
  });
  const { id: originId } = await t.mutation(internal.relayOrigins.upsertBySlug, {
    slug: NODE,
    backendServerSlug: 'panel-a',
    nodeHostname: NODE,
    originAddress: ORIGIN,
  });
  const { id: slotId } = await t.mutation(internal.relaySlots.upsert, {
    originId,
    slotKey: 'u',
    profileSlug: 'prof-u',
    inboundTag: 'VLESS_RELAY_U',
    configProfileUuid: '11111111-1111-4111-8111-111111111111',
    configProfileInboundUuid: '22222222-2222-4222-8222-222222222222',
    originPort: 443,
  });
  const a = await t.mutation(internal.relayOrigins.adoptEdge, {
    originId,
    slotId,
    ipv4: EDGE_A,
    ipv6: EDGE_A6,
    publish: true,
  });
  return { t, serverId, subId, originId, slotId, edgeA: a.edgeId as Id<'relayEdges'> };
}

const get = (t: ReturnType<typeof convexTest>, ua = 'v2rayNG/1.9.0') =>
  t.fetch('/api/v1/sub/tok_abc', { headers: { 'user-agent': ua } });

function pickNodeFor(body: string): string[] {
  return body.split('\n').filter((l) => l.startsWith('vless://'));
}

describe('relayRender: fronted route', () => {
  test('replaces the pinned node template with labelled primary (+ IPv6) entries; other nodes and the origin never appear', async () => {
    stubPanel();
    const { t, subId } = await seed();
    const res = await get(t);
    expect(res.status).toBe(200);
    const body = await res.text();
    const lines = pickNodeFor(body);
    // Direct REALITY Host of the pinned node stays; node-two is pinned away; the
    // relay template is replaced by v4 + v6 primary entries (single published edge → no backup).
    expect(lines.some((l) => l.endsWith(`#${NODE}-reality`))).toBe(true);
    expect(body).not.toContain(OTHER);
    expect(body).not.toContain(`#${NODE}-relay-u`);
    const primary = lines.filter((l) =>
      decodeURIComponent(l.split('#')[1]).startsWith('FreeSocks Primary'),
    );
    expect(primary).toHaveLength(2);
    expect(primary[0]).toContain(`@${EDGE_A}:443?`);
    expect(primary[1]).toContain(`@[${EDGE_A6}]:443?`);
    // One SNI per emitted connection, from the profile's active set; REALITY params kept.
    for (const l of primary) {
      const qs = new URLSearchParams(l.slice(l.indexOf('?') + 1, l.indexOf('#')));
      expect(['a.example', 'b.example', 'c.example']).toContain(qs.get('sni'));
      expect(qs.get('security')).toBe('reality');
      expect(qs.get('pbk')).toBe('PUBKEY');
    }
    // The origin address appears only on its own direct line, never on a relay entry.
    expect(primary.some((l) => l.includes(ORIGIN))).toBe(false);
    // The sub got a render key; the cache entry carries the epoch token.
    const sub = (await t.run((ctx) => ctx.db.get(subId)))!;
    expect(sub.renderKey).toMatch(/^[0-9a-f]{64}$/);
    const cache = JSON.parse(sub.subCache!) as Array<{ relay: number | null }>;
    expect(cache[0].relay).toBeTypeOf('number');
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
    await t.run(async (ctx) => {
      const s = (await ctx.db.get(subId))!;
      const entries = JSON.parse(s.subCache!) as Array<{ at: number }>;
      await ctx.db.patch(subId, {
        subCache: JSON.stringify(entries.map((e) => ({ ...e, at: e.at - 120_000 }))),
      });
    });
    const third = await (await get(t)).text();
    expect(fetchCalls).toBe(2);
    expect(third).toBe(first);
  });

  test('a pool change invalidates the cache within one request and adds the backup entry', async () => {
    stubPanel();
    const { t, originId, slotId } = await seed();
    const first = await (await get(t)).text();
    expect(first).not.toContain('FreeSocks%20Backup');
    expect(fetchCalls).toBe(1);
    // Publish a second edge (epoch bump) → the fresh cache entry is no longer valid.
    await t.mutation(internal.relayOrigins.adoptEdge, {
      originId,
      slotId,
      ipv4: EDGE_B,
      publish: true,
    });
    const res = await get(t);
    const body = await res.text();
    expect(fetchCalls).toBe(2);
    const labels = pickNodeFor(body).map((l) => decodeURIComponent(l.split('#')[1]));
    expect(labels.filter((l) => l.startsWith('FreeSocks Primary')).length).toBeGreaterThan(0);
    expect(labels.filter((l) => l.startsWith('FreeSocks Backup')).length).toBeGreaterThan(0);
    // Primary and backup are different edges.
    const addrOf = (l: string) => l.slice(l.indexOf('@') + 1, l.indexOf(':443'));
    const lines = pickNodeFor(body);
    const primaryAddr = addrOf(
      lines.find((l) => l.includes('FreeSocks%20Primary') && !l.includes('['))!,
    );
    const backupAddr = addrOf(lines.find((l) => l.includes('FreeSocks%20Backup'))!);
    expect(primaryAddr).not.toBe(backupAddr);
    expect([EDGE_A, EDGE_B]).toContain(primaryAddr);
    expect([EDGE_A, EDGE_B]).toContain(backupAddr);
  });

  test('render switch off: the body passes through as the panel sent it (only pinned)', async () => {
    stubPanel();
    const { t } = await seed({ renderEnabled: false });
    const body = await (await get(t)).text();
    expect(body).toContain(`#${NODE}-relay-u`);
    expect(body).toContain(`#${NODE}-reality`);
    expect(body).not.toContain(OTHER);
    expect(body).not.toContain('FreeSocks');
    // Turning it on invalidates the cache (token null → epoch) without waiting for the TTL.
    await t.run((ctx) => upsertSettingRow(ctx, 'relay.render.enabled', 'true'));
    const after = await (await get(t)).text();
    expect(fetchCalls).toBe(2);
    expect(after).toContain('FreeSocks%20Primary');
  });

  test('a disabled client family passes through while others render', async () => {
    stubPanel();
    const { t } = await seed();
    await t.run((ctx) =>
      upsertSettingRow(ctx, 'relay.render.clients.v2rayng', JSON.stringify({ enabled: false })),
    );
    const v2 = await (await get(t, 'v2rayNG/1.9.0')).text();
    expect(v2).toContain(`#${NODE}-relay-u`);
    const other = await (await get(t, 'curl/8.0')).text();
    expect(other).toContain('FreeSocks%20Primary');
  });

  test('contextForSubscription is null without a pin, an origin, or a published edge', async () => {
    stubPanel();
    const { t, subId, originId, edgeA } = await seed();
    expect(
      await t.query(internal.relayRender.contextForSubscription, {
        subscriptionId: subId,
        family: 'other',
        nodeHostname: 'node-nine',
      }),
    ).toBeNull();
    const ctx1 = await t.query(internal.relayRender.contextForSubscription, {
      subscriptionId: subId,
      family: 'singbox',
    });
    expect(ctx1?.published.map((p) => p.edgeId)).toEqual([edgeA]);
    expect(ctx1?.templateRemarks).toEqual([`${NODE}-relay-u`]);
    expect(ctx1?.rule.autoGroup).toBe(true);
    await t.mutation(internal.relayOrigins.unpublishEdge, {
      originId,
      edgeId: edgeA,
      keepActive: true,
    });
    expect(
      await t.query(internal.relayRender.contextForSubscription, {
        subscriptionId: subId,
        family: 'other',
      }),
    ).toBeNull();
    expect(
      await t.query(internal.relayRender.epochFor, {
        backendServerId: (await t.run((ctx) => ctx.db.get(subId)))!.backendServerId!,
        nodeHostname: NODE,
      }),
    ).toBeNull();
  });
});
