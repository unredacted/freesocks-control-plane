/// <reference types="vite/client" />
/**
 * Edge attribution for member reports: which edge a "primary"/"backup" choice
 * denotes. The answer comes from the render snapshot persisted on the
 * subscription (what the subscriber was actually handed); an assignment is
 * never recomputed, because body-level listener eligibility and the client
 * family are unknown at report time.
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { resolveEdgeAttribution } from './edgeAttribution';
import { publishedEdgesOf } from './edgeRender';
import { relayForBackendNode } from './relays';
import { assignEndpoints } from './lib/edges/assignment';
import { realityListener, registerRelay } from './lib/edges/testing/fixtures';

const modules = import.meta.glob('./**/*.*s');

const ORIGIN = '203.0.113.10';
const EDGE_A = '198.51.100.1';
const EDGE_C = '198.51.100.3';
const EDGE_B6 = '2001:db8::2';

/** One origin with three published edges; the middle one is IPv6-only. */
async function seed() {
  const t = convexTest(schema, modules);
  const serverId = await t.run(async (ctx) => {
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
    await upsertSettingRow(ctx, 'edge.render.enabled', 'true');
    return serverId;
  });
  const { relayId, listenerId } = await registerRelay(t, {
    originAddress: ORIGIN,
    listeners: [
      realityListener({
        listenerKey: 'u',
        providerScope: { provider: 'upcloud' },
        panelBinding: {
          inboundTag: 'VLESS_RELAY_U',
          configProfileUuid: '11111111-1111-4111-8111-111111111111',
          configProfileInboundUuid: '22222222-2222-4222-8222-222222222222',
        },
      }),
    ],
  });
  await t.run((ctx) => ctx.db.patch(relayId, { desiredPublished: 3 }));
  const ids: Id<'edges'>[] = [];
  for (const ipv4 of [EDGE_A, '198.51.100.2', EDGE_C]) {
    const e = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      listenerId,
      ipv4,
      publish: true,
    });
    ids.push(e.edgeId as Id<'edges'>);
  }
  // The middle edge lives on IPv6 only: a family whose rule cannot emit IPv6
  // walks past it, a family that can lands on it.
  await t.run((ctx) => ctx.db.patch(ids[1], { addresses: { v6: EDGE_B6 } }));
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
    const relay = (await ctx.db.get(relayId))!;
    return await ctx.db.insert('subscriptions', {
      userId,
      backend: 'remnawave',
      backendUserId: 'uuid-1',
      backendShortId: 'short-1',
      backendServerId: serverId,
      subscriptionUrl: 'https://panel.example/sub/short-1',
      subscriptionMirrors: [],
      subToken: 'tok_1',
      state: 'active',
      pinnedNode: 'node-one',
      renderKey: 'a'.repeat(64),
      lastRenderedEpoch: relay.publicationEpoch,
      updatedAt: Date.now(),
    });
  });
  // A render key whose primary IS the v6-only edge while IPv6 may be emitted,
  // and something else when it may not: exactly the case the two rules disagree.
  const now = Date.now();
  const key = await t.run(async (ctx) => {
    const origin = (await ctx.db.get(relayId))!;
    const { published } = await publishedEdgesOf(ctx, origin, { includeIneligible: true });
    const opts = { now, preferDistinctProviders: false, includeBackup: true };
    for (let i = 0; i < 500; i++) {
      const candidate = ((i * 2654435761) >>> 0).toString(16).padStart(8, '0') + 'cd'.repeat(28);
      const withV6 = assignEndpoints(candidate, published, { ...opts, canEmitV6: true });
      const withoutV6 = assignEndpoints(candidate, published, { ...opts, canEmitV6: false });
      if (
        withV6.primary!.edge.edgeId === ids[1] &&
        withoutV6.primary!.edge.edgeId !== withV6.primary!.edge.edgeId
      ) {
        await ctx.db.patch(subId, { renderKey: candidate });
        return candidate;
      }
    }
    return null;
  });
  expect(key).not.toBeNull();
  return { t, relayId, subId, edges: ids, now };
}

describe('resolveEdgeAttribution: which relay, and whether the member has the current pool', () => {
  test('the origin is found by (backend server, pinned node); a whole-server relay covers unpinned keys; nothing else attributes', async () => {
    const s = await seed();
    await s.t.run(async (ctx) => {
      const sub = (await ctx.db.get(s.subId))!;
      // The panel-node relay by its node.
      expect(await relayForBackendNode(ctx.db, sub.backendServerId!, 'node-one')).toMatchObject({
        slug: 'node-one',
      });
      // Another node on the same panel: no relay (a node relay never covers its neighbours).
      expect(await relayForBackendNode(ctx.db, sub.backendServerId!, 'node-two')).toBeNull();
      // An unpinned key on the panel: no whole-server relay yet → null.
      expect(await relayForBackendNode(ctx.db, sub.backendServerId!, undefined)).toBeNull();
      expect(
        await resolveEdgeAttribution(ctx.db, { ...sub, pinnedNode: 'node-two' }, 'primary', s.now),
      ).toBeNull();
      expect(
        await resolveEdgeAttribution(ctx.db, { ...sub, pinnedNode: undefined }, 'primary', s.now),
      ).toBeNull();
      expect(await resolveEdgeAttribution(ctx.db, null, 'primary', s.now)).toBeNull();
    });
    // A whole-server relay on a SECOND panel covers every key of that panel, pinned or not.
    await s.t.run((ctx) =>
      ctx.db.insert('backendServers', {
        backend: 'outline',
        name: 'panel-b',
        slug: 'panel-b',
        config: {
          type: 'outline',
          apiUrl: 'https://outline.example/secret',
          websocketEnabled: false,
        },
        isActive: true,
        priority: 0,
        keyCount: 0,
        updatedAt: Date.now(),
      }),
    );
    await registerRelay(s.t, {
      slug: 'whole-b',
      kind: 'backend-server',
      backendSlug: 'panel-b',
      originAddress: '203.0.113.20',
      listeners: [{ ...realityListener(), panelBinding: undefined }],
    });
    await s.t.run(async (ctx) => {
      const b = (await ctx.db
        .query('backendServers')
        .withIndex('by_slug', (q) => q.eq('slug', 'panel-b'))
        .unique())!;
      expect(await relayForBackendNode(ctx.db, b._id, undefined)).toMatchObject({
        slug: 'whole-b',
      });
      expect(await relayForBackendNode(ctx.db, b._id, 'any-node')).toMatchObject({
        slug: 'whole-b',
      });
      // An unpinned subscription (Outline keys never carry a node) attributes to
      // the whole-server relay instead of losing its report.
      const sub = (await ctx.db.get(s.subId))!;
      const unpinned = { ...sub, backend: 'outline' as const, backendServerId: b._id };
      delete (unpinned as { pinnedNode?: string }).pinnedNode;
      expect(await resolveEdgeAttribution(ctx.db, unpinned, 'unsure', s.now)).toMatchObject({
        relaySlug: 'whole-b',
        relayEdgeId: null,
      });
    });
  });

  test('a key rendered against an OLDER epoch is on the old pool: origin-level only (refreshNotObserved)', async () => {
    const s = await seed();
    await s.t.run(async (ctx) => {
      const sub = (await ctx.db.get(s.subId))!;
      const stale = await resolveEdgeAttribution(
        ctx.db,
        { ...sub, lastRenderedEpoch: sub.lastRenderedEpoch! - 1 },
        'primary',
        s.now,
      );
      expect(stale).toEqual({ relaySlug: 'node-one', relayEdgeId: null, refreshNotObserved: true });
      // Keys never rendered since the epoch field exists fall back to delivery vs last rotation.
      const relay = (await ctx.db.get(s.relayId))!;
      await ctx.db.patch(s.relayId, { lastRotatedAt: s.now });
      const legacy = await resolveEdgeAttribution(
        ctx.db,
        { ...sub, lastRenderedEpoch: undefined, lastDeliveredContentAt: s.now - 1 },
        'primary',
        s.now,
      );
      expect(legacy!.refreshNotObserved).toBe(true);
      const fresh = await resolveEdgeAttribution(
        ctx.db,
        { ...sub, lastRenderedEpoch: undefined, lastDeliveredContentAt: s.now + 1 },
        'primary',
        s.now,
      );
      expect(fresh!.refreshNotObserved).toBe(false);
      await ctx.db.patch(s.relayId, { lastRotatedAt: relay.lastRotatedAt });
      // `unsure` / `direct` never name an edge; `auto` only over a single-edge pool.
      for (const choice of ['unsure', 'direct', 'auto'] as const) {
        expect((await resolveEdgeAttribution(ctx.db, sub, choice, s.now))!.relayEdgeId).toBeNull();
      }
      expect((await resolveEdgeAttribution(ctx.db, sub, null, s.now))!.relayEdgeId).toBeNull();
    });
  });
});

describe('resolveEdgeAttribution reads the persisted render snapshot, never a recomputation', () => {
  const snapshot = async (
    s: Awaited<ReturnType<typeof seed>>,
    snap: { primary?: Id<'edges'>; backup?: Id<'edges'>; epochDelta?: number },
  ) =>
    s.t.run(async (ctx) => {
      const relay = (await ctx.db.get(s.relayId))!;
      await ctx.db.patch(s.subId, {
        lastRender: {
          at: s.now,
          epoch: relay.publicationEpoch + (snap.epochDelta ?? 0),
          family: 'mihomo',
          listenerKeys: ['u'],
          primaryEdgeId: snap.primary,
          backupEdgeId: snap.backup,
        },
      });
    });

  test('primary / backup name exactly the edges the subscriber was handed', async () => {
    const s = await seed();
    await snapshot(s, { primary: s.edges[2], backup: s.edges[0] });
    await s.t.run(async (ctx) => {
      const sub = (await ctx.db.get(s.subId))!;
      const primary = await resolveEdgeAttribution(ctx.db, sub, 'primary', s.now);
      expect(primary).toMatchObject({ relaySlug: 'node-one', refreshNotObserved: false });
      expect(primary!.relayEdgeId).toBe(s.edges[2]);
      expect((await resolveEdgeAttribution(ctx.db, sub, 'backup', s.now))!.relayEdgeId).toBe(
        s.edges[0],
      );
      // `auto` is ambiguous while a backup was handed out; unsure / direct never name an edge.
      for (const choice of ['auto', 'unsure', 'direct'] as const)
        expect((await resolveEdgeAttribution(ctx.db, sub, choice, s.now))!.relayEdgeId).toBeNull();
    });
  });

  test('a body that resolved only one listener: the recomputed relay-wide pick is NOT used', async () => {
    const s = await seed();
    // The render key's pool-wide primary is the v6-only edge (seed), but this
    // subscriber's body only matched an entry the first edge could serve.
    await snapshot(s, { primary: s.edges[0] });
    await s.t.run(async (ctx) => {
      const sub = (await ctx.db.get(s.subId))!;
      expect((await resolveEdgeAttribution(ctx.db, sub, 'primary', s.now))!.relayEdgeId).toBe(
        s.edges[0],
      );
      // Nothing else was handed out, so `auto` denotes that one edge.
      expect((await resolveEdgeAttribution(ctx.db, sub, 'auto', s.now))!.relayEdgeId).toBe(
        s.edges[0],
      );
    });
  });

  test('no snapshot, or one from an older epoch, stays at origin level', async () => {
    const s = await seed();
    await s.t.run(async (ctx) => {
      const sub = (await ctx.db.get(s.subId))!;
      const out = await resolveEdgeAttribution(ctx.db, sub, 'primary', s.now);
      expect(out!.relaySlug).toBe('node-one');
      expect(out!.relayEdgeId).toBeNull();
    });
    await snapshot(s, { primary: s.edges[0], epochDelta: -1 });
    await s.t.run(async (ctx) => {
      const sub = (await ctx.db.get(s.subId))!;
      const out = await resolveEdgeAttribution(ctx.db, sub, 'primary', s.now);
      expect(out).toMatchObject({ relayEdgeId: null, refreshNotObserved: true });
    });
  });
});
