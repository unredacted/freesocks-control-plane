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
  const { id: accountId } = await t.mutation(internal.edgeProviderAccounts.create, {
    provider: 'gcore',
    name: 'acct-a',
    settings: { projectId: 11, regionId: 22 },
    credentials: { apiKey: 'k' },
  });
  const { id: profileId } = await t.mutation(internal.protocolProfiles.create, {
    slug: 'prof-a',
    name: 'Profile A',
    provider: 'gcore',
    targetAddress: 'target.example',
    serverNames: ['a.example', 'b.example'],
  });
  const { id: relayId } = await t.mutation(internal.relays.upsertBySlug, {
    slug: 'node-one',
    backendServerSlug: 'panel-a',
    nodeHostname: 'node-one',
    originAddress: '203.0.113.10',
  });
  const { id: slotId } = await t.mutation(internal.relaySlots.upsert, {
    relayId,
    slotKey: 'a',
    profileSlug: 'prof-a',
    inboundTag: 'VLESS_RELAY_A',
    configProfileUuid: '11111111-1111-4111-8111-111111111111',
    configProfileInboundUuid: '22222222-2222-4222-8222-222222222222',
    originPort: 443,
  });
  return { t, serverId, accountId, profileId, relayId, slotId };
}

describe('relayOrigins + slots + profiles', () => {
  test('upsertBySlug is idempotent, resolves the panel by slug and never flips autoRotate', async () => {
    const { t, relayId, serverId } = await seed();
    const again = await t.mutation(internal.relays.upsertBySlug, {
      slug: 'node-one',
      backendServerSlug: 'panel-a',
      nodeHostname: 'node-one',
      originAddress: '203.0.113.10',
      autoRotate: true,
    });
    expect(again).toEqual({ id: relayId, created: false });
    const row = await t.query(internal.relays.get, { id: relayId });
    expect(row?.backendServerId).toBe(serverId);
    expect(row?.autoRotate).toBe(false);
    expect(row?.hostManaged).toBe(true);
    await expect(
      t.mutation(internal.relays.upsertBySlug, {
        slug: 'node-two',
        backendServerSlug: 'missing',
        nodeHostname: 'node-two',
        originAddress: '203.0.113.11',
      }),
    ).rejects.toThrow(/backendServerSlug/);
  });

  test('slot upsert derives the template remark and bumps the epoch; retire refuses while published', async () => {
    const { t, relayId, slotId } = await seed();
    const slots = await t.query(internal.relaySlots.listByRelay, { relayId });
    expect(slots).toHaveLength(1);
    expect(slots[0]).toMatchObject({
      slotKey: 'a',
      templateHostRemark: 'node-one-relay-a',
      provider: 'gcore',
      profileSlug: 'prof-a',
    });
    const before = (await t.query(internal.relays.get, { id: relayId }))!.publicationEpoch;
    // Same values → no rebind; changed inbound → rebind clears the template Host uuid.
    await t.mutation(internal.relaySlots.setTemplateHost, {
      slotId,
      templateHostUuid: '33333333-3333-4333-8333-333333333333',
    });
    await t.mutation(internal.relaySlots.upsert, {
      relayId,
      slotKey: 'a',
      profileSlug: 'prof-a',
      inboundTag: 'VLESS_RELAY_A',
      configProfileUuid: '11111111-1111-4111-8111-111111111111',
      configProfileInboundUuid: '22222222-2222-4222-8222-222222222222',
      originPort: 443,
    });
    expect((await t.run((ctx) => ctx.db.get(slotId)))!.templateHostUuid).toBeDefined();
    await t.mutation(internal.relaySlots.upsert, {
      relayId,
      slotKey: 'a',
      profileSlug: 'prof-a',
      inboundTag: 'VLESS_RELAY_A',
      configProfileUuid: '11111111-1111-4111-8111-111111111111',
      configProfileInboundUuid: '44444444-4444-4444-8444-444444444444',
      originPort: 443,
    });
    expect((await t.run((ctx) => ctx.db.get(slotId)))!.templateHostUuid).toBeUndefined();
    const after = (await t.query(internal.relays.get, { id: relayId }))!.publicationEpoch;
    expect(after).toBeGreaterThan(before);

    const { edgeId } = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      slotId,
      ipv4: '198.51.100.7',
      publish: true,
    });
    await expect(t.mutation(internal.relaySlots.retire, { relayId, slotKey: 'a' })).rejects.toThrow(
      /published edge/,
    );
    // The edge (and its listener) target this inbound + port: no rebind or port
    // change under it. Same values (a role re-run) stay idempotent.
    for (const change of [
      { configProfileInboundUuid: '55555555-5555-4555-8555-555555555555' },
      { originPort: 8443 },
    ]) {
      await expect(
        t.mutation(internal.relaySlots.upsert, {
          relayId,
          slotKey: 'a',
          profileSlug: 'prof-a',
          inboundTag: 'VLESS_RELAY_A',
          configProfileUuid: '11111111-1111-4111-8111-111111111111',
          configProfileInboundUuid: '44444444-4444-4444-8444-444444444444',
          originPort: 443,
          ...change,
        }),
      ).rejects.toThrow(/still use slot/);
    }
    await t.mutation(internal.relaySlots.upsert, {
      relayId,
      slotKey: 'a',
      profileSlug: 'prof-a',
      inboundTag: 'VLESS_RELAY_A',
      configProfileUuid: '11111111-1111-4111-8111-111111111111',
      configProfileInboundUuid: '44444444-4444-4444-8444-444444444444',
      originPort: 443,
    });
    await t.mutation(internal.relays.unpublishEdge, { relayId, edgeId, keepActive: true });
    await t.mutation(internal.relaySlots.retire, { relayId, slotKey: 'a' });
    expect((await t.run((ctx) => ctx.db.get(slotId)))!.retired).toBe(true);
  });

  test('adopt validates addresses (public, not the origin) and publishes at the next free pool index', async () => {
    const { t, relayId, slotId } = await seed();
    await expect(
      t.mutation(internal.relays.adoptEdge, { relayId, slotId, ipv4: '10.0.0.1' }),
    ).rejects.toThrow(/public IPv4/);
    await expect(
      t.mutation(internal.relays.adoptEdge, { relayId, slotId, ipv4: '203.0.113.10' }),
    ).rejects.toThrow(/anti-leak/);
    await expect(
      t.mutation(internal.relays.adoptEdge, {
        relayId,
        slotId,
        ipv4: '198.51.100.1',
        ipv6: '198.51.100.2',
      }),
    ).rejects.toThrow(/IPv6/);
    const a = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      slotId,
      ipv4: '198.51.100.1',
      ipv6: '2001:db8::1',
      publish: true,
    });
    const b = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      slotId,
      ipv4: '198.51.100.2',
      publish: true,
    });
    expect(a.poolIndex).toBe(0);
    expect(b.poolIndex).toBe(1);
    // desiredPublished defaults to 2 → pool is full.
    await expect(
      t.mutation(internal.relays.adoptEdge, {
        relayId,
        slotId,
        ipv4: '198.51.100.3',
        publish: true,
      }),
    ).rejects.toThrow(/pool is full/);
    const origin = (await t.query(internal.relays.listForAdmin, {}))[0];
    expect(origin.publishedEdgeIds).toEqual([a.edgeId, b.edgeId]);
    expect(origin.publishedCount).toBe(2);
    const edge = await t.query(internal.edges.getForAdmin, {
      id: a.edgeId as Id<'edges'>,
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
    const { t, relayId, slotId } = await seed();
    const a = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      slotId,
      ipv4: '198.51.100.1',
      publish: true,
    });
    const b = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      slotId,
      ipv4: '198.51.100.2',
      publish: true,
    });
    const c = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      slotId,
      ipv4: '198.51.100.3',
    });
    const e0 = (await t.query(internal.relays.get, { id: relayId }))!.publicationEpoch;
    await t.mutation(internal.relays.unpublishEdge, {
      relayId,
      edgeId: a.edgeId,
      drainMs: 1000,
    });
    let origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.publishedEdgeIds).toEqual([null, b.edgeId]);
    expect(origin.publicationEpoch).toBe(e0 + 1);
    const drained = await t.query(internal.edges.get, { id: a.edgeId });
    expect(drained).toMatchObject({ status: 'draining', publication: 'draining' });
    expect(drained?.poolIndex).toBeUndefined();
    const pub = await t.mutation(internal.relays.publishEdge, { relayId, edgeId: c.edgeId });
    expect(pub.poolIndex).toBe(0);
    origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.publishedEdgeIds).toEqual([c.edgeId, b.edgeId]);
    expect(origin.publicationEpoch).toBe(e0 + 2);
    // A draining edge can't be re-published; an occupied index is refused.
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId, edgeId: a.edgeId }),
    ).rejects.toThrow(/edge_not_active/);
    const d = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      slotId,
      ipv4: '198.51.100.4',
    });
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId, edgeId: d.edgeId, poolIndex: 1 }),
    ).rejects.toThrow(/occupied/);
  });

  test('an account-scoped profile publishes only edges provisioned from that account', async () => {
    const { t, relayId, slotId, profileId, accountId } = await seed();
    const { id: otherAccount } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'gcore',
      name: 'acct-b',
      settings: { projectId: 33, regionId: 44 },
      credentials: { apiKey: 'k2' },
    });
    await t.mutation(internal.protocolProfiles.update, { id: profileId, accountId });
    const mk = (acct: typeof accountId) =>
      t.run((ctx) =>
        ctx.db.insert('edges', {
          relayId,
          slotId,
          accountId: acct,
          provider: 'gcore',
          managed: true,
          name: `fcp-relay-${acct}`,
          steps: [],
          resources: [],
          listeners: [],
          addresses: { v4: acct === accountId ? '198.51.100.21' : '198.51.100.22' },
          publication: 'unpublished',
          status: 'active',
          statusChangedAt: Date.now(),
          health: 'online',
          destroyAttempts: 0,
          updatedAt: Date.now(),
        }),
      );
    const foreign = await mk(otherAccount);
    const own = await mk(accountId);
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId, edgeId: foreign }),
    ).rejects.toThrow(/account_mismatch/);
    await t.mutation(internal.relays.publishEdge, { relayId, edgeId: own });
    expect((await t.query(internal.relays.get, { id: relayId }))!.publishedEdgeIds).toEqual([own]);
  });

  test('narrowing a profile scope refuses while published edges fall outside it; unpublished edges do not block', async () => {
    const { t, relayId, slotId, profileId } = await seed();
    const e = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      slotId,
      ipv4: '198.51.100.1',
      publish: true,
    });
    // The adopted edge carries no provider: any provider scope excludes it while published.
    await expect(
      t.mutation(internal.protocolProfiles.update, { id: profileId, provider: 'upcloud' }),
    ).rejects.toThrow(/outside the new scope/);
    // Widening to "any provider" is always fine; so is an unrelated edit.
    await t.mutation(internal.protocolProfiles.update, { id: profileId, provider: null });
    await t.mutation(internal.protocolProfiles.update, { id: profileId, name: 'Renamed' });
    // Drained/unpublished → the scope may narrow again.
    await t.mutation(internal.relays.unpublishEdge, {
      relayId,
      edgeId: e.edgeId,
      keepActive: true,
    });
    await t.mutation(internal.protocolProfiles.update, { id: profileId, provider: 'upcloud' });
    expect((await t.query(internal.protocolProfiles.get, { id: profileId }))?.provider).toBe(
      'upcloud',
    );
  });

  test('publish preconditions: disabled profile / no active SNI / retired slot block publication', async () => {
    const { t, relayId, slotId, profileId } = await seed();
    const e = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      slotId,
      ipv4: '198.51.100.1',
    });
    await t.mutation(internal.protocolProfiles.update, { id: profileId, enabled: false });
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId, edgeId: e.edgeId }),
    ).rejects.toThrow(/profile_disabled/);
    await t.mutation(internal.protocolProfiles.update, { id: profileId, enabled: true });
    await t.mutation(internal.protocolProfiles.retireSni, { id: profileId, snis: ['a.example'] });
    // The mutation keeps ≥1 active name; force the all-retired state the way a
    // drained profile would look after an operator edit on the panel side.
    await expect(
      t.mutation(internal.protocolProfiles.retireSni, { id: profileId, snis: ['b.example'] }),
    ).rejects.toThrow(/at least one active/);
    await t.run(async (ctx) => {
      const p = (await ctx.db.get(profileId))!;
      await ctx.db.patch(profileId, {
        serverNames: p.serverNames.map((s) => ({ ...s, status: 'retired' as const })),
      });
    });
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId, edgeId: e.edgeId }),
    ).rejects.toThrow(/profile_no_active_sni/);
    await t.mutation(internal.protocolProfiles.reactivateSni, {
      id: profileId,
      snis: ['a.example'],
    });
    await t.mutation(internal.relaySlots.retire, { relayId, slotKey: 'a' });
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId, edgeId: e.edgeId }),
    ).rejects.toThrow(/slot_not_deployed/);
  });

  test('profile update replaces the active set, retiring absent names with a drain window', async () => {
    const { t, profileId } = await seed();
    await t.mutation(internal.protocolProfiles.update, {
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
    await expect(t.mutation(internal.protocolProfiles.remove, { id: profileId })).rejects.toThrow();
  });

  test('requestDelete drains managed edges, forgets unmanaged ones, and finalizeDelete waits for teardown', async () => {
    const { t, relayId, slotId, accountId } = await seed();
    const adopted = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      slotId,
      ipv4: '198.51.100.1',
      publish: true,
    });
    const planned = await t.mutation(internal.edges.insertPlanned, {
      relayId,
      slotId,
      accountId,
      templateHash: 'h',
      listeners: [{ edgePort: 443, originAddress: '203.0.113.10', originPort: 443 }],
      steps: [{ id: 'lb', kind: 'loadbalancer', resourceName: 'x' }],
    });
    await t.mutation(internal.edges.patchEdge, { edgeId: planned.id, status: 'active' });
    const r = await t.mutation(internal.relays.requestDelete, { id: relayId });
    expect(r).toEqual({ ok: true, deleted: false });
    expect((await t.query(internal.edges.get, { id: adopted.edgeId }))?.status).toBe('destroyed');
    expect((await t.query(internal.edges.get, { id: planned.id }))?.status).toBe('draining');
    let origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.deleting).toBe(true);
    expect(origin.publishedEdgeIds).toEqual([]);
    expect(await t.mutation(internal.relays.finalizeDelete, { id: relayId })).toEqual({
      removed: false,
    });
    await t.mutation(internal.edges.patchEdge, { edgeId: planned.id, status: 'destroyed' });
    expect(await t.mutation(internal.relays.finalizeDelete, { id: relayId })).toEqual({
      removed: true,
    });
    expect(await t.query(internal.relays.get, { id: relayId })).toBeNull();
    expect(await t.run((ctx) => ctx.db.get(slotId))).toBeNull();
  });

  test('originAddress is locked while the origin has live edges; one origin per backend node', async () => {
    const { t, relayId, slotId } = await seed();
    const e = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      slotId,
      ipv4: '198.51.100.1',
    });
    await expect(
      t.mutation(internal.relays.update, { id: relayId, originAddress: '203.0.113.99' }),
    ).rejects.toThrow(/origin_address_locked/);
    await expect(
      t.mutation(internal.relays.upsertBySlug, {
        slug: 'node-one',
        backendServerSlug: 'panel-a',
        nodeHostname: 'node-one',
        originAddress: '203.0.113.99',
      }),
    ).rejects.toThrow(/origin_address_locked/);
    // The same address (or an unrelated field) is fine.
    await t.mutation(internal.relays.update, {
      id: relayId,
      originAddress: '203.0.113.10',
      drainMinutes: 30,
    });
    await t.mutation(internal.edges.patchEdge, { edgeId: e.edgeId, status: 'destroyed' });
    await t.mutation(internal.relays.update, { id: relayId, originAddress: '203.0.113.99' });
    expect((await t.query(internal.relays.get, { id: relayId }))!.originAddress).toBe(
      '203.0.113.99',
    );
    // A second slug for the same node on the same panel is refused (create + upsert).
    await expect(
      t.mutation(internal.relays.upsertBySlug, {
        slug: 'node-one-b',
        backendServerSlug: 'panel-a',
        nodeHostname: 'node-one',
        originAddress: '203.0.113.20',
      }),
    ).rejects.toThrow(/node_already_bound/);
    const { id: two } = await t.mutation(internal.relays.upsertBySlug, {
      slug: 'node-two',
      backendServerSlug: 'panel-a',
      nodeHostname: 'node-two',
      originAddress: '203.0.113.21',
    });
    await expect(
      t.mutation(internal.relays.update, { id: two, nodeHostname: 'node-one' }),
    ).rejects.toThrow(/node_already_bound/);
  });

  test("profile edits that change what renders bump every using origin's epoch; cosmetic ones do not", async () => {
    const { t, relayId, profileId } = await seed();
    const epoch = async () =>
      (await t.query(internal.relays.get, { id: relayId }))!.publicationEpoch;
    const e0 = await epoch();
    expect(
      await t.mutation(internal.protocolProfiles.retireSni, { id: profileId, snis: ['a.example'] }),
    ).toEqual({ ok: true, retired: 1 });
    expect(await epoch()).toBe(e0 + 1);
    expect(
      await t.mutation(internal.protocolProfiles.reactivateSni, {
        id: profileId,
        snis: ['a.example'],
      }),
    ).toEqual({ ok: true, reactivated: 1 });
    expect(await epoch()).toBe(e0 + 2);
    // Retiring a name that is not active changes nothing.
    await t.mutation(internal.protocolProfiles.reactivateSni, {
      id: profileId,
      snis: ['a.example'],
    });
    expect(await epoch()).toBe(e0 + 2);
    await t.mutation(internal.protocolProfiles.update, { id: profileId, notes: 'cosmetic' });
    expect(await epoch()).toBe(e0 + 2);
    await t.mutation(internal.protocolProfiles.update, { id: profileId, enabled: false });
    expect(await epoch()).toBe(e0 + 3);
    await t.mutation(internal.protocolProfiles.update, {
      id: profileId,
      serverNames: ['a.example', 'b.example', 'c.example'],
    });
    expect(await epoch()).toBe(e0 + 4);
  });

  test('a plain-protocol profile needs no target or names; its slot publishes and renders without an SNI', async () => {
    const { t, relayId, slotId } = await seed();
    await expect(
      t.mutation(internal.protocolProfiles.create, {
        slug: 'prof-p',
        name: 'Plain',
        protocol: 'plain',
        serverNames: ['x.example'],
      }),
    ).rejects.toThrow(/plain profile/);
    await expect(
      t.mutation(internal.protocolProfiles.create, {
        slug: 'prof-r',
        name: 'R',
        protocol: 'reality',
      }),
    ).rejects.toThrow(/targetAddress/);
    await t.mutation(internal.protocolProfiles.create, {
      slug: 'prof-p',
      name: 'Plain',
      protocol: 'plain',
    });
    const tcp = await t.mutation(internal.relaySlots.upsert, {
      relayId,
      slotKey: 't',
      profileSlug: 'prof-p',
      inboundTag: 'SS_PLAIN',
      configProfileUuid: '11111111-1111-4111-8111-111111111111',
      configProfileInboundUuid: '44444444-4444-4444-8444-444444444444',
      originPort: 8443,
    });
    const slots = await t.query(internal.relaySlots.listByRelay, { relayId });
    expect(slots.find((s) => s.slotKey === 't')).toMatchObject({
      protocol: 'plain',
      profileSlug: 'prof-p',
      provider: null,
    });
    expect(slots.find((s) => s.id === slotId)?.protocol).toBe('reality');
    const e = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      slotId: tcp.id,
      ipv4: '198.51.100.7',
      publish: true,
    });
    expect(e.poolIndex).toBe(0);
    const edge = (await t.query(internal.edges.get, { id: e.edgeId }))!;
    expect(edge.listeners[0]).toMatchObject({ originPort: 8443, transport: 'tcp' });
    const view = (await t.query(internal.edgeAdmin.endpoints, { relayId }))!;
    expect(view.published[0]).toMatchObject({ protocol: 'plain', activeServerNames: [] });
    expect(view.sample.primary).toEqual({ edgeId: e.edgeId, sni: null });
  });
});
