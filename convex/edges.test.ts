/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';

const modules = import.meta.glob('./**/*.*s');

async function seed(opts: { maxLiveEdges?: number; dailyAllocationBudget?: number } = {}) {
  const t = convexTest(schema, modules);
  await t.run((ctx) =>
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
    provider: 'upcloud',
    name: 'acct-u',
    settings: { zone: 'de-fra1' },
    credentials: { token: 'ucl_x' },
    ...(opts.maxLiveEdges !== undefined ? { maxLiveEdges: opts.maxLiveEdges } : {}),
    ...(opts.dailyAllocationBudget !== undefined
      ? { dailyAllocationBudget: opts.dailyAllocationBudget }
      : {}),
  });
  await t.mutation(internal.protocolProfiles.create, {
    slug: 'prof-u',
    name: 'Profile U',
    provider: 'upcloud',
    targetAddress: 'target.example',
    serverNames: ['a.example'],
  });
  const { id: relayId } = await t.mutation(internal.relays.upsertBySlug, {
    slug: 'node-one',
    backendServerSlug: 'panel-a',
    nodeHostname: 'node-one',
    originAddress: '203.0.113.10',
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
  return { t, accountId, relayId, slotId };
}

const plan = {
  templateHash: 'h1',
  listeners: [{ edgePort: 443, originAddress: '203.0.113.10', originPort: 443 }],
  steps: [
    { id: 'lb', kind: 'loadbalancer', resourceName: 'fcp-relay-x' },
    { id: 'ip', kind: 'floating_ip', resourceName: 'fcp-relay-x' },
  ],
};

describe('edges', () => {
  test('insertPlanned reserves capacity and budget atomically', async () => {
    const { t, accountId, relayId, slotId } = await seed({
      maxLiveEdges: 1,
      dailyAllocationBudget: 5,
    });
    const a = await t.mutation(internal.edges.insertPlanned, {
      relayId,
      slotId,
      accountId,
      ...plan,
    });
    expect(a.name).toMatch(/^fcp-relay-node-one-[0-9a-f]{8}$/);
    const row = (await t.query(internal.edges.get, { id: a.id }))!;
    expect(row.status).toBe('planning');
    expect(row.steps.map((s) => s.state)).toEqual(['pending', 'pending']);
    await expect(
      t.mutation(internal.edges.insertPlanned, { relayId, slotId, accountId, ...plan }),
    ).rejects.toThrow(/live-edge cap/);
    // Destroyed edges free capacity; the budget still counts.
    await t.mutation(internal.edges.patchEdge, { edgeId: a.id, status: 'destroyed' });
    await t.mutation(internal.edges.insertPlanned, { relayId, slotId, accountId, ...plan });
    const acct = (await t.run((ctx) => ctx.db.get(accountId)))!;
    expect(acct.allocationsToday).toBe(2);
  });

  test('budget exhaustion refuses the insert without leaving a row behind', async () => {
    const { t, accountId, relayId, slotId } = await seed({
      maxLiveEdges: 10,
      dailyAllocationBudget: 1,
    });
    await t.mutation(internal.edges.insertPlanned, { relayId, slotId, accountId, ...plan });
    await expect(
      t.mutation(internal.edges.insertPlanned, { relayId, slotId, accountId, ...plan }),
    ).rejects.toThrow(/budget/);
    const rows = await t.query(internal.edges.listByRelay, { relayId });
    expect(rows).toHaveLength(1);
  });

  test('claimOp: one op at a time; an expired allocating op can only be followed by an observing op', async () => {
    const { t, accountId, relayId, slotId } = await seed();
    const { id } = await t.mutation(internal.edges.insertPlanned, {
      relayId,
      slotId,
      accountId,
      ...plan,
    });
    const c1 = await t.mutation(internal.edges.claimOp, {
      edgeId: id,
      kind: 'provision_step',
      target: 'lb',
      claimMs: 60_000,
    });
    expect(c1.ok).toBe(true);
    const c2 = await t.mutation(internal.edges.claimOp, {
      edgeId: id,
      kind: 'provision_step',
      target: 'lb',
      claimMs: 60_000,
    });
    expect(c2).toEqual({ ok: false, code: 'edge.op_busy' });
    // Settling with the wrong opId is ignored.
    expect(await t.mutation(internal.edges.settleOp, { edgeId: id, opId: 'nope' })).toEqual({
      ok: false,
    });
    // Expire the claim by hand (simulates a crashed action).
    await t.run(async (ctx) => {
      const e = (await ctx.db.get(id))!;
      await ctx.db.patch(id, { currentOp: { ...e.currentOp!, expiresAt: Date.now() - 1 } });
    });
    const c3 = await t.mutation(internal.edges.claimOp, {
      edgeId: id,
      kind: 'provision_step',
      target: 'lb',
      claimMs: 60_000,
    });
    expect(c3).toEqual({ ok: false, code: 'edge.op_unsettled' });
    const c4 = await t.mutation(internal.edges.claimOp, {
      edgeId: id,
      kind: 'discover',
      target: 'lb',
      claimMs: 60_000,
    });
    expect(c4.ok).toBe(true);
    if (!c4.ok) throw new Error('unreachable');
    // Same target keeps counting attempts.
    expect(c4.attempt).toBe(2);
    await t.mutation(internal.edges.settleOp, {
      edgeId: id,
      opId: c4.opId,
      stepPatch: { stepId: 'lb', state: 'done', finished: true },
      addResources: [
        { kind: 'loadbalancer', resourceId: 'lb-1', ownership: 'created', meta: { region: 'r' } },
      ],
      addresses: { v4: '198.51.100.9' },
      status: 'provisioning',
    });
    const row = (await t.query(internal.edges.get, { id }))!;
    expect(row.currentOp).toBeUndefined();
    expect(row.steps[0]).toMatchObject({ state: 'done' });
    expect(row.steps[0].finishedAt).toBeDefined();
    expect(row.resources).toEqual([
      expect.objectContaining({
        stepId: 'lb',
        kind: 'loadbalancer',
        resourceId: 'lb-1',
        ownership: 'created',
        deleteState: 'present',
        meta: '{"region":"r"}',
      }),
    ]);
    expect(row.addresses.v4).toBe('198.51.100.9');
    expect(row.status).toBe('provisioning');
    // Re-adding a known resource is a no-op; delete states update by resource id.
    const c5 = await t.mutation(internal.edges.claimOp, {
      edgeId: id,
      kind: 'destroy_step',
      target: 'lb-1',
      claimMs: 60_000,
    });
    if (!c5.ok) throw new Error('unreachable');
    await t.mutation(internal.edges.settleOp, {
      edgeId: id,
      opId: c5.opId,
      addResources: [{ kind: 'loadbalancer', resourceId: 'lb-1', ownership: 'created' }],
      resourceDeleteState: [{ resourceId: 'lb-1', deleteState: 'delete_requested' }],
    });
    const after = (await t.query(internal.edges.get, { id }))!;
    expect(after.resources).toHaveLength(1);
    expect(after.resources[0].deleteState).toBe('delete_requested');
  });

  test('isDiscoverable + progress + describe(gone) transitions', async () => {
    const { t, accountId, relayId, slotId } = await seed();
    const { id } = await t.mutation(internal.edges.insertPlanned, {
      relayId,
      slotId,
      accountId,
      ...plan,
    });
    const { isDiscoverable, edgeProgress } = await import('./edges');
    let row = (await t.query(internal.edges.get, { id }))!;
    expect(isDiscoverable(row, Date.now())).toBe(false);
    expect(edgeProgress(row)).toEqual({ done: 0, total: 2, percent: 0 });
    await t.mutation(internal.edges.patchEdge, {
      edgeId: id,
      stepStates: [{ stepId: 'lb', state: 'requested' }],
    });
    row = (await t.query(internal.edges.get, { id }))!;
    expect(isDiscoverable(row, Date.now())).toBe(true);
    await t.mutation(internal.edges.patchEdge, {
      edgeId: id,
      stepStates: [{ stepId: 'lb', state: 'done' }],
    });
    row = (await t.query(internal.edges.get, { id }))!;
    expect(edgeProgress(row).percent).toBe(50);
    await t.mutation(internal.edges.recordDescribe, {
      edgeId: id,
      state: 'active',
      addresses: { v4: '198.51.100.9', v6: '2001:db8::9' },
      health: 'online',
      resources: [{ kind: 'floating_ip', resourceId: 'ip-1', ownership: 'created' }],
    });
    row = (await t.query(internal.edges.get, { id }))!;
    expect(row.health).toBe('online');
    expect(row.addresses).toEqual({ v4: '198.51.100.9', v6: '2001:db8::9' });
    expect(row.resources.map((r) => r.resourceId)).toEqual(['ip-1']);
    await t.mutation(internal.edges.recordDescribe, {
      edgeId: id,
      state: 'gone',
      addresses: {},
      health: 'unknown',
    });
    row = (await t.query(internal.edges.get, { id }))!;
    expect(row.status).toBe('destroyed');
    expect(row.destroyedAt).toBeDefined();
    // Addresses are kept for the ledger even when the LB is gone.
    expect(row.addresses.v4).toBe('198.51.100.9');
    const admin = (await t.query(internal.edges.getForAdmin, { id }))!;
    expect(admin.progress).toEqual({ done: 1, total: 2, percent: 50 });
    expect(admin.resources[0]).not.toHaveProperty('meta');
  });
});
