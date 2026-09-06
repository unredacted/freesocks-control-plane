/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';

const modules = import.meta.glob('./**/*.*s');

async function seed() {
  const t = convexTest(schema, modules);
  const serverId = await t.run((ctx) =>
    ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'panel-a',
      slug: 'panel-a',
      config: { type: 'remnawave', baseUrl: 'https://panel.example', apiToken: 'tok' },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: Date.now(),
    }),
  );
  const { id: accountId } = await t.mutation(internal.relayProviderAccounts.create, {
    provider: 'gcore',
    name: 'acct-a',
    settings: { projectId: 11, regionId: 22 },
    credentials: { apiKey: 'k' },
  });
  const { id: profileId } = await t.mutation(internal.relayProfiles.create, {
    slug: 'prof-a',
    name: 'Profile A',
    provider: 'gcore',
    targetAddress: 'target.example',
    serverNames: ['a.example', 'b.example'],
  });
  const { id: originId } = await t.mutation(internal.relayOrigins.upsertBySlug, {
    slug: 'node-one',
    backendServerSlug: 'panel-a',
    nodeHostname: 'node-one',
    originAddress: '203.0.113.10',
  });
  const { id: slotId } = await t.mutation(internal.relaySlots.upsert, {
    originId,
    slotKey: 'a',
    profileSlug: 'prof-a',
    inboundTag: 'VLESS_RELAY_A',
    configProfileUuid: '11111111-1111-4111-8111-111111111111',
    configProfileInboundUuid: '22222222-2222-4222-8222-222222222222',
    originPort: 443,
  });
  return { t, serverId, accountId, profileId, originId, slotId };
}

describe('relayOrigins + slots + profiles', () => {
  test('upsertBySlug is idempotent, resolves the panel by slug and never flips autoRotate', async () => {
    const { t, originId, serverId } = await seed();
    const again = await t.mutation(internal.relayOrigins.upsertBySlug, {
      slug: 'node-one',
      backendServerSlug: 'panel-a',
      nodeHostname: 'node-one',
      originAddress: '203.0.113.10',
      autoRotate: true,
    });
    expect(again).toEqual({ id: originId, created: false });
    const row = await t.query(internal.relayOrigins.get, { id: originId });
    expect(row?.backendServerId).toBe(serverId);
    expect(row?.autoRotate).toBe(false);
    expect(row?.hostManaged).toBe(true);
    await expect(
      t.mutation(internal.relayOrigins.upsertBySlug, {
        slug: 'node-two',
        backendServerSlug: 'missing',
        nodeHostname: 'node-two',
        originAddress: '203.0.113.11',
      }),
    ).rejects.toThrow(/backendServerSlug/);
  });

  test('slot upsert derives the template remark and bumps the epoch; retire refuses while published', async () => {
    const { t, originId, slotId } = await seed();
    const slots = await t.query(internal.relaySlots.listByOrigin, { originId });
    expect(slots).toHaveLength(1);
    expect(slots[0]).toMatchObject({
      slotKey: 'a',
      templateHostRemark: 'node-one-relay-a',
      provider: 'gcore',
      profileSlug: 'prof-a',
    });
    const before = (await t.query(internal.relayOrigins.get, { id: originId }))!.publicationEpoch;
    // Same values → no rebind; changed inbound → rebind clears the template Host uuid.
    await t.mutation(internal.relaySlots.setTemplateHost, {
      slotId,
      templateHostUuid: '33333333-3333-4333-8333-333333333333',
    });
    await t.mutation(internal.relaySlots.upsert, {
      originId,
      slotKey: 'a',
      profileSlug: 'prof-a',
      inboundTag: 'VLESS_RELAY_A',
      configProfileUuid: '11111111-1111-4111-8111-111111111111',
      configProfileInboundUuid: '22222222-2222-4222-8222-222222222222',
      originPort: 443,
    });
    expect((await t.run((ctx) => ctx.db.get(slotId)))!.templateHostUuid).toBeDefined();
    await t.mutation(internal.relaySlots.upsert, {
      originId,
      slotKey: 'a',
      profileSlug: 'prof-a',
      inboundTag: 'VLESS_RELAY_A',
      configProfileUuid: '11111111-1111-4111-8111-111111111111',
      configProfileInboundUuid: '44444444-4444-4444-8444-444444444444',
      originPort: 443,
    });
    expect((await t.run((ctx) => ctx.db.get(slotId)))!.templateHostUuid).toBeUndefined();
    const after = (await t.query(internal.relayOrigins.get, { id: originId }))!.publicationEpoch;
    expect(after).toBeGreaterThan(before);

    const { edgeId } = await t.mutation(internal.relayOrigins.adoptEdge, {
      originId,
      slotId,
      ipv4: '198.51.100.7',
      publish: true,
    });
    await expect(
      t.mutation(internal.relaySlots.retire, { originId, slotKey: 'a' }),
    ).rejects.toThrow(/published edge/);
    await t.mutation(internal.relayOrigins.unpublishEdge, { originId, edgeId, keepActive: true });
    await t.mutation(internal.relaySlots.retire, { originId, slotKey: 'a' });
    expect((await t.run((ctx) => ctx.db.get(slotId)))!.retired).toBe(true);
  });

  test('adopt validates addresses (public, not the origin) and publishes at the next free pool index', async () => {
    const { t, originId, slotId } = await seed();
    await expect(
      t.mutation(internal.relayOrigins.adoptEdge, { originId, slotId, ipv4: '10.0.0.1' }),
    ).rejects.toThrow(/public IPv4/);
    await expect(
      t.mutation(internal.relayOrigins.adoptEdge, { originId, slotId, ipv4: '203.0.113.10' }),
    ).rejects.toThrow(/anti-leak/);
    await expect(
      t.mutation(internal.relayOrigins.adoptEdge, {
        originId,
        slotId,
        ipv4: '198.51.100.1',
        ipv6: '198.51.100.2',
      }),
    ).rejects.toThrow(/IPv6/);
    const a = await t.mutation(internal.relayOrigins.adoptEdge, {
      originId,
      slotId,
      ipv4: '198.51.100.1',
      ipv6: '2001:db8::1',
      publish: true,
    });
    const b = await t.mutation(internal.relayOrigins.adoptEdge, {
      originId,
      slotId,
      ipv4: '198.51.100.2',
      publish: true,
    });
    expect(a.poolIndex).toBe(0);
    expect(b.poolIndex).toBe(1);
    // desiredPublished defaults to 2 → pool is full.
    await expect(
      t.mutation(internal.relayOrigins.adoptEdge, {
        originId,
        slotId,
        ipv4: '198.51.100.3',
        publish: true,
      }),
    ).rejects.toThrow(/pool is full/);
    const origin = (await t.query(internal.relayOrigins.listForAdmin, {}))[0];
    expect(origin.publishedEdgeIds).toEqual([a.edgeId, b.edgeId]);
    expect(origin.publishedCount).toBe(2);
    const edge = await t.query(internal.relayEdges.getForAdmin, {
      id: a.edgeId as Id<'relayEdges'>,
    });
    expect(edge).toMatchObject({
      managed: false,
      publication: 'published',
      poolIndex: 0,
      addresses: { v4: '198.51.100.1', v6: '2001:db8::1' },
    });
    // Adopted, unmanaged edges never carry an account or ledger.
    expect(edge?.accountId).toBeNull();
    expect(edge?.resources).toEqual([]);
  });

  test('unpublish leaves a gap that the next publish inherits; epoch bumps each time', async () => {
    const { t, originId, slotId } = await seed();
    const a = await t.mutation(internal.relayOrigins.adoptEdge, {
      originId,
      slotId,
      ipv4: '198.51.100.1',
      publish: true,
    });
    const b = await t.mutation(internal.relayOrigins.adoptEdge, {
      originId,
      slotId,
      ipv4: '198.51.100.2',
      publish: true,
    });
    const c = await t.mutation(internal.relayOrigins.adoptEdge, {
      originId,
      slotId,
      ipv4: '198.51.100.3',
    });
    const e0 = (await t.query(internal.relayOrigins.get, { id: originId }))!.publicationEpoch;
    await t.mutation(internal.relayOrigins.unpublishEdge, {
      originId,
      edgeId: a.edgeId,
      drainMs: 1000,
    });
    let origin = (await t.query(internal.relayOrigins.get, { id: originId }))!;
    expect(origin.publishedEdgeIds).toEqual([null, b.edgeId]);
    expect(origin.publicationEpoch).toBe(e0 + 1);
    const drained = await t.query(internal.relayEdges.get, { id: a.edgeId });
    expect(drained).toMatchObject({ status: 'draining', publication: 'draining' });
    expect(drained?.poolIndex).toBeUndefined();
    const pub = await t.mutation(internal.relayOrigins.publishEdge, { originId, edgeId: c.edgeId });
    expect(pub.poolIndex).toBe(0);
    origin = (await t.query(internal.relayOrigins.get, { id: originId }))!;
    expect(origin.publishedEdgeIds).toEqual([c.edgeId, b.edgeId]);
    expect(origin.publicationEpoch).toBe(e0 + 2);
    // A draining edge can't be re-published; an occupied index is refused.
    await expect(
      t.mutation(internal.relayOrigins.publishEdge, { originId, edgeId: a.edgeId }),
    ).rejects.toThrow(/edge_not_active/);
    const d = await t.mutation(internal.relayOrigins.adoptEdge, {
      originId,
      slotId,
      ipv4: '198.51.100.4',
    });
    await expect(
      t.mutation(internal.relayOrigins.publishEdge, { originId, edgeId: d.edgeId, poolIndex: 1 }),
    ).rejects.toThrow(/occupied/);
  });

  test('publish preconditions: disabled profile / no active SNI / retired slot block publication', async () => {
    const { t, originId, slotId, profileId } = await seed();
    const e = await t.mutation(internal.relayOrigins.adoptEdge, {
      originId,
      slotId,
      ipv4: '198.51.100.1',
    });
    await t.mutation(internal.relayProfiles.update, { id: profileId, enabled: false });
    await expect(
      t.mutation(internal.relayOrigins.publishEdge, { originId, edgeId: e.edgeId }),
    ).rejects.toThrow(/profile_disabled/);
    await t.mutation(internal.relayProfiles.update, { id: profileId, enabled: true });
    await t.mutation(internal.relayProfiles.retireSni, { id: profileId, snis: ['a.example'] });
    // The mutation keeps ≥1 active name; force the all-retired state the way a
    // drained profile would look after an operator edit on the panel side.
    await expect(
      t.mutation(internal.relayProfiles.retireSni, { id: profileId, snis: ['b.example'] }),
    ).rejects.toThrow(/at least one active/);
    await t.run(async (ctx) => {
      const p = (await ctx.db.get(profileId))!;
      await ctx.db.patch(profileId, {
        serverNames: p.serverNames.map((s) => ({ ...s, status: 'retired' as const })),
      });
    });
    await expect(
      t.mutation(internal.relayOrigins.publishEdge, { originId, edgeId: e.edgeId }),
    ).rejects.toThrow(/profile_no_active_sni/);
    await t.mutation(internal.relayProfiles.reactivateSni, { id: profileId, snis: ['a.example'] });
    await t.mutation(internal.relaySlots.retire, { originId, slotKey: 'a' });
    await expect(
      t.mutation(internal.relayOrigins.publishEdge, { originId, edgeId: e.edgeId }),
    ).rejects.toThrow(/slot_not_deployed/);
  });

  test('profile update replaces the active set, retiring absent names with a drain window', async () => {
    const { t, profileId } = await seed();
    await t.mutation(internal.relayProfiles.update, {
      id: profileId,
      serverNames: ['b.example', 'c.example'],
    });
    const p = (await t.run((ctx) => ctx.db.get(profileId)))!;
    const byName = Object.fromEntries(p.serverNames.map((s) => [s.sni, s]));
    expect(byName['a.example'].status).toBe('retired');
    expect(byName['a.example'].drainUntil!).toBeGreaterThan(Date.now());
    expect(byName['b.example'].status).toBe('active');
    expect(byName['c.example'].status).toBe('active');
    // Ordering is preserved for the PRF: existing names keep their position.
    expect(p.serverNames.map((s) => s.sni)).toEqual(['a.example', 'b.example', 'c.example']);
    // Removing a profile still bound to a slot is refused.
    await expect(t.mutation(internal.relayProfiles.remove, { id: profileId })).rejects.toThrow();
  });

  test('requestDelete drains managed edges, forgets unmanaged ones, and finalizeDelete waits for teardown', async () => {
    const { t, originId, slotId, accountId } = await seed();
    const adopted = await t.mutation(internal.relayOrigins.adoptEdge, {
      originId,
      slotId,
      ipv4: '198.51.100.1',
      publish: true,
    });
    const planned = await t.mutation(internal.relayEdges.insertPlanned, {
      originId,
      slotId,
      accountId,
      templateHash: 'h',
      listeners: [{ edgePort: 443, originAddress: '203.0.113.10', originPort: 443 }],
      steps: [{ id: 'lb', kind: 'loadbalancer', resourceName: 'x' }],
    });
    await t.mutation(internal.relayEdges.patchEdge, { edgeId: planned.id, status: 'active' });
    const r = await t.mutation(internal.relayOrigins.requestDelete, { id: originId });
    expect(r).toEqual({ ok: true, deleted: false });
    expect((await t.query(internal.relayEdges.get, { id: adopted.edgeId }))?.status).toBe(
      'destroyed',
    );
    expect((await t.query(internal.relayEdges.get, { id: planned.id }))?.status).toBe('draining');
    let origin = (await t.query(internal.relayOrigins.get, { id: originId }))!;
    expect(origin.deleting).toBe(true);
    expect(origin.publishedEdgeIds).toEqual([]);
    expect(await t.mutation(internal.relayOrigins.finalizeDelete, { id: originId })).toEqual({
      removed: false,
    });
    await t.mutation(internal.relayEdges.patchEdge, { edgeId: planned.id, status: 'destroyed' });
    expect(await t.mutation(internal.relayOrigins.finalizeDelete, { id: originId })).toEqual({
      removed: true,
    });
    expect(await t.query(internal.relayOrigins.get, { id: originId })).toBeNull();
    expect(await t.run((ctx) => ctx.db.get(slotId))).toBeNull();
  });
});
