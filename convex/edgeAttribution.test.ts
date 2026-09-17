/// <reference types="vite/client" />
/**
 * Edge attribution for member reports: which edge a "primary"/"backup" choice
 * denotes. The member's client family is not recorded with the report and the
 * per-family render rules change the assignment (a family that cannot emit
 * IPv6 skips a v6-only edge), so an edge is named only when every enabled
 * family agrees on it.
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { resolveEdgeAttribution } from './edgeAttribution';
import { publishedEdgesOf } from './edgeRender';
import { assignEndpoints } from './lib/edges/assignment';

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
  await t.mutation(internal.protocolProfiles.create, {
    slug: 'prof-u',
    name: 'P',
    provider: 'upcloud',
    targetAddress: 'target.example',
    serverNames: ['a.example', 'b.example'],
  });
  const { id: relayId } = await t.mutation(internal.relays.upsertBySlug, {
    slug: 'node-one',
    backendServerSlug: 'panel-a',
    nodeHostname: 'node-one',
    originAddress: ORIGIN,
  });
  const { id: slotId } = await t.mutation(internal.relaySlots.upsert, {
    relayId,
    slotKey: 'u',
    profileSlug: 'prof-u',
    inboundTag: 'VLESS_RELAY_U',
    configProfileUuid: '11111111-1111-4111-8111-111111111111',
    configProfileInboundUuid: '22222222-2222-4222-8222-222222222222',
    originPort: 443,
  });
  await t.run((ctx) => ctx.db.patch(relayId, { desiredPublished: 3 }));
  const ids: Id<'edges'>[] = [];
  for (const ipv4 of [EDGE_A, '198.51.100.2', EDGE_C]) {
    const e = await t.mutation(internal.relays.adoptEdge, { relayId, slotId, ipv4, publish: true });
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

describe('resolveEdgeAttribution across client-family rules', () => {
  test('every family able to emit IPv6 → the v6-only edge is named', async () => {
    const s = await seed();
    await s.t.run(async (ctx) => {
      const sub = (await ctx.db.get(s.subId))!;
      const out = await resolveEdgeAttribution(ctx.db, sub, 'primary', s.now);
      expect(out).toMatchObject({ relaySlug: 'node-one', refreshNotObserved: false });
      expect(out!.relayEdgeId).toBe(s.edges[1]);
    });
  });

  test('one family at ipv6Mode:off disagrees → NO edge is named (never the neighbour)', async () => {
    const s = await seed();
    await s.t.run((ctx) =>
      upsertSettingRow(ctx, 'edge.render.clients.mihomo', JSON.stringify({ ipv6Mode: 'off' })),
    );
    await s.t.run(async (ctx) => {
      const sub = (await ctx.db.get(s.subId))!;
      const out = await resolveEdgeAttribution(ctx.db, sub, 'primary', s.now);
      // The report still counts at origin level, just not against an edge: the
      // rules point at different edges, and the neighbour is healthy.
      expect(out!.relaySlug).toBe('node-one');
      expect(out!.relayEdgeId).toBeNull();
    });
  });

  test('a family that is DISABLED does not veto the others', async () => {
    const s = await seed();
    await s.t.run((ctx) =>
      upsertSettingRow(
        ctx,
        'edge.render.clients.mihomo',
        JSON.stringify({ enabled: false, ipv6Mode: 'off' }),
      ),
    );
    await s.t.run(async (ctx) => {
      const sub = (await ctx.db.get(s.subId))!;
      const out = await resolveEdgeAttribution(ctx.db, sub, 'primary', s.now);
      expect(out!.relayEdgeId).toBe(s.edges[1]);
    });
  });

  test('rendering off entirely → no edge is named (the member never received a rendered pool)', async () => {
    const s = await seed();
    await s.t.run((ctx) => upsertSettingRow(ctx, 'edge.render.enabled', 'false'));
    await s.t.run(async (ctx) => {
      const sub = (await ctx.db.get(s.subId))!;
      const out = await resolveEdgeAttribution(ctx.db, sub, 'primary', s.now);
      expect(out!.relayEdgeId).toBeNull();
    });
  });
});
