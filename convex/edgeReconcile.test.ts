/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';

import { jsonRes, mockFetch } from './lib/edges/testing/mockFetch';
import { upsertSettingRow } from './appSettings';
import { MAX_CONFIRM_ATTEMPTS, shouldReissueDelete } from './edgeReconcile';

const modules = import.meta.glob('./**/*.*s');

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

const ORIGIN = '203.0.113.10';

/** Fake UpCloud with a mutable LB table; records DELETEs. */
function fakeUpcloud(initial: Array<{ uuid: string; name: string }>) {
  const lbs = new Map(initial.map((l) => [l.uuid, { ...l, operational_state: 'running' }]));
  const deletes: string[] = [];
  const stub = mockFetch((c) => {
    if (new URL(c.url).hostname === 'panel.example') return jsonRes({ response: [] });
    if (c.path === '/1.3/load-balancer' && c.method === 'GET') return jsonRes([...lbs.values()]);
    const one = c.path.match(/^\/1\.3\/load-balancer\/([^/]+)$/);
    if (one && c.method === 'GET') {
      const lb = lbs.get(one[1]);
      return lb ? jsonRes(lb) : jsonRes({ error: { error_code: 'LB_NOT_FOUND' } }, 404);
    }
    if (one && c.method === 'DELETE') {
      deletes.push(one[1]);
      // A 2xx only REQUESTS the delete (the provider tears down in the
      // background); the re-issued DELETE answers 404 once it is gone.
      if (!lbs.has(one[1])) return jsonRes({ error: { error_code: 'LB_NOT_FOUND' } }, 404);
      lbs.delete(one[1]);
      return new Response(null, { status: 204 });
    }
    if (c.path === '/1.3/ip_address' && c.method === 'GET')
      return jsonRes({ ip_addresses: { ip_address: [] } });
    throw new Error(`unexpected ${c.method} ${c.url}`);
  });
  return { stub, lbs, deletes };
}

async function seed() {
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
  });
  await t.mutation(internal.edgeProviderAccounts.setQualified, { id: accountId, qualified: true });
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
  return { t, accountId, relayId, slotId };
}

/** A managed edge whose single `lb` step is done with one lb resource, in the given status. */
async function managedEdge(
  s: Awaited<ReturnType<typeof seed>>,
  lbId: string,
  patch: Record<string, unknown>,
) {
  const { id } = await s.t.mutation(internal.edges.insertPlanned, {
    relayId: s.relayId,
    slotId: s.slotId,
    accountId: s.accountId,
    templateHash: 'h',
    listeners: [{ edgePort: 443, originAddress: ORIGIN, originPort: 443 }],
    steps: [{ id: 'lb', kind: 'create_lb', resourceName: 'x', discoverability: 'by_name' }],
  });
  await s.t.run(async (ctx) => {
    const e = (await ctx.db.get(id))!;
    await ctx.db.patch(id, {
      steps: e.steps.map((st) => ({ ...st, state: 'done' as const, finishedAt: Date.now() })),
      resources: [
        {
          stepId: 'lb',
          kind: 'lb',
          resourceId: lbId,
          ownership: 'created' as const,
          deleteState: 'present' as const,
        },
      ],
      addresses: { v4: '198.51.100.9' },
      health: 'online',
      lastHealthAt: Date.now(),
      status: 'active',
      ...patch,
      updatedAt: Date.now(),
    });
  });
  return id;
}

/** A gcore-backed managed edge already `destroying`, with ONE resource in the given delete state. */
async function gcoreDestroyingEdge(
  s: Awaited<ReturnType<typeof seed>>,
  deleteState: 'present' | 'delete_requested',
  opts: { kind?: string; destroyAttempts?: number } = {},
) {
  const { id: accountId } = await s.t.mutation(internal.edgeProviderAccounts.create, {
    provider: 'gcore',
    name: 'acct-g',
    settings: { projectId: 11, regionId: 22 },
    credentials: { apiKey: 'k' },
  });
  await s.t.mutation(internal.protocolProfiles.create, {
    slug: 'prof-g',
    name: 'Profile G',
    provider: 'gcore',
    targetAddress: 'target-g.example',
    serverNames: ['g.example'],
  });
  const { id: slotId } = await s.t.mutation(internal.relaySlots.upsert, {
    relayId: s.relayId,
    slotKey: 'g',
    profileSlug: 'prof-g',
    inboundTag: 'VLESS_RELAY_G',
    configProfileUuid: '11111111-1111-4111-8111-111111111111',
    configProfileInboundUuid: '33333333-3333-4333-8333-333333333333',
    originPort: 8443,
  });
  const { id: edgeId } = await s.t.mutation(internal.edges.insertPlanned, {
    relayId: s.relayId,
    slotId,
    accountId,
    templateHash: 'h',
    listeners: [{ edgePort: 443, originAddress: ORIGIN, originPort: 8443 }],
    steps: [{ id: 'lb', kind: 'create_lb', resourceName: 'x', discoverability: 'by_name' }],
  });
  await s.t.run(async (ctx) => {
    const e = (await ctx.db.get(edgeId))!;
    await ctx.db.patch(edgeId, {
      steps: e.steps.map((st) => ({ ...st, state: 'done' as const })),
      resources: [
        {
          stepId: 'lb',
          kind: opts.kind ?? 'lb',
          resourceId: 'lb-g',
          ownership: 'created' as const,
          deleteState,
        },
      ],
      status: 'destroying',
      publication: 'unpublished',
      destroyAttempts: opts.destroyAttempts ?? 0,
    });
  });
  return edgeId;
}

const run = (t: ReturnType<typeof convexTest>) => t.action(internal.edgeReconcile.run, {});

describe('edgeReconcile', () => {
  test('drained edge → destroying → every child confirmed gone → destroyed (audited, no addresses)', async () => {
    const world = fakeUpcloud([{ uuid: 'lb-1', name: 'x' }]);
    const s = await seed();
    const edgeId = await managedEdge(s, 'lb-1', {
      status: 'draining',
      publication: 'draining',
      drainUntil: Date.now() - 1,
    });
    const r1 = await run(s.t);
    expect(r1.destroying).toBe(1);
    expect((await s.t.query(internal.edges.get, { id: edgeId }))!.status).toBe('destroying');
    // DELETE 2xx = requested, never assumed gone; the next pass re-issues the
    // idempotent DELETE and the 404 confirms it.
    const r2 = await run(s.t);
    expect(r2.destroyed).toBe(0);
    let edge = (await s.t.query(internal.edges.get, { id: edgeId }))!;
    expect(edge.status).toBe('destroying');
    expect(edge.resources[0].deleteState).toBe('delete_requested');
    const r3 = await run(s.t);
    expect(r3.destroyed).toBe(1);
    expect(world.deletes).toEqual(['lb-1', 'lb-1']);
    edge = (await s.t.query(internal.edges.get, { id: edgeId }))!;
    expect(edge.status).toBe('destroyed');
    expect(edge.resources[0].deleteState).toBe('confirmed_gone');
    expect(edge.currentOp).toBeUndefined();
    expect(edge.destroyAttempts).toBe(2);
    const audit = await s.t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.find((a) => a.action === 'edge.destroyed')?.payload).toMatchObject({
      relaySlug: 'node-one',
      provider: 'upcloud',
    });
    expect(JSON.stringify(audit)).not.toContain('198.51.100.9');
    // A further pass is a no-op.
    const r4 = await run(s.t);
    expect(r4.destroyed + r4.destroying + r4.errors).toBe(0);
  });

  test('a not-yet-drained edge is left alone; draining still gets its health refreshed', async () => {
    fakeUpcloud([{ uuid: 'lb-1', name: 'x' }]);
    const s = await seed();
    const edgeId = await managedEdge(s, 'lb-1', {
      status: 'draining',
      publication: 'draining',
      drainUntil: Date.now() + 60_000,
      lastHealthAt: undefined,
    });
    const r = await run(s.t);
    expect(r.destroying).toBe(0);
    expect(r.described).toBe(1);
    expect((await s.t.query(internal.edges.get, { id: edgeId }))!.status).toBe('draining');
  });

  test('a published edge the provider no longer has is dropped from the pool on the SECOND gone observation, atomically with its status', async () => {
    fakeUpcloud([]); // lb-1 does not exist any more
    const s = await seed();
    const edgeId = await managedEdge(s, 'lb-1', { lastHealthAt: undefined });
    await s.t.mutation(internal.relays.publishEdge, { relayId: s.relayId, edgeId });
    const before = (await s.t.query(internal.relays.get, { id: s.relayId }))!;
    expect(before.publishedEdgeIds).toEqual([edgeId]);
    // First gone: counted, nothing else moves (an auth-shaped 404 / a blip must not drop the pool).
    const r1 = await run(s.t);
    expect(r1.described).toBe(1);
    expect(r1.dropped).toBe(0);
    let origin = (await s.t.query(internal.relays.get, { id: s.relayId }))!;
    expect(origin.publishedEdgeIds).toEqual([edgeId]);
    expect(origin.publicationEpoch).toBe(before.publicationEpoch);
    let edge = (await s.t.query(internal.edges.get, { id: edgeId }))!;
    expect(edge).toMatchObject({ status: 'active', publication: 'published', goneObservations: 1 });
    // A non-gone describe in between would reset the counter.
    await s.t.mutation(internal.edges.recordDescribe, {
      edgeId,
      state: 'active',
      addresses: { v4: '198.51.100.9' },
      health: 'online',
    });
    expect((await s.t.query(internal.edges.get, { id: edgeId }))!.goneObservations).toBeUndefined();
    await s.t.run((ctx) => ctx.db.patch(edgeId, { lastHealthAt: undefined }));
    await run(s.t); // gone #1 again
    await s.t.run((ctx) => ctx.db.patch(edgeId, { lastHealthAt: undefined }));
    const r2 = await run(s.t); // gone #2: acts
    expect(r2.dropped).toBe(1);
    origin = (await s.t.query(internal.relays.get, { id: s.relayId }))!;
    expect(origin.publishedEdgeIds).toEqual([]);
    expect(origin.publicationEpoch).toBe(before.publicationEpoch + 1);
    edge = (await s.t.query(internal.edges.get, { id: edgeId }))!;
    expect(edge.status).toBe('destroyed');
    expect(edge.publication).toBe('unpublished');
    expect(edge.goneObservations).toBeUndefined();
    const audit = await s.t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.some((a) => a.action === 'edge.drift')).toBe(true);
    expect(audit.some((a) => a.action === 'edge.unpublished')).toBe(true);
  });

  test('a quarantined origin is hands-off for the cron: no describe, no drop', async () => {
    const world = fakeUpcloud([]);
    const s = await seed();
    const edgeId = await managedEdge(s, 'lb-1', { lastHealthAt: undefined });
    await s.t.mutation(internal.relays.publishEdge, { relayId: s.relayId, edgeId });
    const rotationId = await s.t.run((ctx) =>
      ctx.db.insert('edgeRotations', {
        relayId: s.relayId,
        kind: 'replace',
        trigger: 'manual',
        burn: false,
        force: false,
        phase: 'quarantined',
        stepVersion: 1,
        cancelRequested: false,
        hostPlan: [],
        flipAttempts: 0,
        rollbackAttempts: 0,
        pollAttempts: 0,
        events: [],
        startedAt: Date.now(),
        finishedAt: Date.now(),
        updatedAt: Date.now(),
      }),
    );
    await s.t.run((ctx) =>
      ctx.db.patch(s.relayId, {
        quarantine: { rotationId, since: Date.now(), reason: 'test' },
      }),
    );
    const r = await run(s.t);
    expect(r.described).toBe(0);
    expect(r.dropped).toBe(0);
    expect(world.stub.calls.filter((c) => c.path.startsWith('/1.3/'))).toHaveLength(0);
    expect((await s.t.query(internal.relays.get, { id: s.relayId }))!.publishedEdgeIds).toEqual([
      edgeId,
    ]);
  });

  test('failed edge with an unresolved step is DISCOVERED (never re-run): absent → settled → destroyed', async () => {
    const world = fakeUpcloud([]);
    const s = await seed();
    const { id: edgeId } = await s.t.mutation(internal.edges.insertPlanned, {
      relayId: s.relayId,
      slotId: s.slotId,
      accountId: s.accountId,
      templateHash: 'h',
      listeners: [{ edgePort: 443, originAddress: ORIGIN, originPort: 443 }],
      steps: [
        {
          id: 'lb',
          kind: 'create_lb',
          resourceName: 'fcp-relay-node-one-00000000',
          discoverability: 'by_name',
        },
      ],
    });
    await s.t.mutation(internal.edges.patchEdge, {
      edgeId,
      status: 'failed',
      stepStates: [{ stepId: 'lb', state: 'unresolved' }],
    });
    const r1 = await run(s.t);
    expect(r1.settled).toBe(1);
    let edge = (await s.t.query(internal.edges.get, { id: edgeId }))!;
    expect(edge.steps[0].state).toBe('done');
    expect(edge.status).toBe('failed');
    // Only the LIST (discovery) was called; never a POST.
    expect(world.stub.calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      'GET /1.3/load-balancer',
    ]);
    const r2 = await run(s.t);
    expect(r2.destroying).toBe(1);
    const r3 = await run(s.t);
    expect(r3.destroyed).toBe(1);
    edge = (await s.t.query(internal.edges.get, { id: edgeId }))!;
    expect(edge.status).toBe('destroyed');
    expect(world.deletes).toEqual([]);
  });

  test('failed edge whose step actually created the LB: discovery FINDS it and the destroy then deletes it', async () => {
    const world = fakeUpcloud([]);
    const s = await seed();
    const { id: edgeId, name } = await s.t.mutation(internal.edges.insertPlanned, {
      relayId: s.relayId,
      slotId: s.slotId,
      accountId: s.accountId,
      templateHash: 'h',
      listeners: [{ edgePort: 443, originAddress: ORIGIN, originPort: 443 }],
      steps: [
        {
          id: 'lb',
          kind: 'create_lb',
          resourceName: 'fcp-relay-node-one-00000000',
          discoverability: 'by_name',
        },
      ],
    });
    // The provider DID create the LB under the edge's name before the run died.
    world.lbs.set('lb-7', { uuid: 'lb-7', name, operational_state: 'running' });
    await s.t.mutation(internal.edges.patchEdge, {
      edgeId,
      status: 'failed',
      stepStates: [{ stepId: 'lb', state: 'unresolved' }],
    });
    await run(s.t);
    let edge = (await s.t.query(internal.edges.get, { id: edgeId }))!;
    expect(edge.resources).toEqual([
      expect.objectContaining({
        kind: 'lb',
        resourceId: 'lb-7',
        ownership: 'adopted',
        deleteState: 'present',
      }),
    ]);
    await run(s.t); // → destroying
    await run(s.t); // → DELETE requested
    await run(s.t); // → re-issued DELETE answers 404: confirmed gone
    edge = (await s.t.query(internal.edges.get, { id: edgeId }))!;
    expect(edge.status).toBe('destroyed');
    expect(world.deletes).toEqual(['lb-7', 'lb-7']);
  });

  test('destroy attempts cap parks the edge as needs_operator; retryDestroy resumes it', async () => {
    fakeUpcloud([{ uuid: 'lb-1', name: 'x' }]);
    const s = await seed();
    const edgeId = await managedEdge(s, 'lb-1', {
      status: 'destroying',
      publication: 'unpublished',
      destroyAttempts: 48,
    });
    await run(s.t);
    const edge = (await s.t.query(internal.edges.get, { id: edgeId }))!;
    expect(edge.status).toBe('needs_operator');
    const audit = await s.t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.find((a) => a.action === 'edge.destroy_failed')?.payload).toMatchObject({
      attempts: 48,
    });
    // `reactivate` on a row that came off the drain path clears the drain
    // metadata and puts it back among the selectable standbys.
    await s.t.run((ctx) =>
      ctx.db.patch(edgeId, { publication: 'draining', drainUntil: Date.now() - 1 }),
    );
    await s.t.mutation(internal.edgeAdmin.resolveOperator, { edgeId, action: 'reactivate' });
    const back = (await s.t.query(internal.edges.get, { id: edgeId }))!;
    expect(back).toMatchObject({ status: 'active', publication: 'unpublished' });
    expect(back.drainUntil).toBeUndefined();
    expect((await s.t.query(internal.relays.get, { id: s.relayId }))!.standbyEdgeIds).toContain(
      edgeId,
    );
    // Operator resolutions are audited under their own action, not `edge.delete`.
    const afterReactivate = await s.t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(afterReactivate.find((a) => a.action === 'edge.reactivate')?.payload).toMatchObject({
      relaySlug: 'node-one',
      edgeId,
      provider: 'upcloud',
    });
    expect(afterReactivate.some((a) => a.action === 'edge.delete')).toBe(false);
    await s.t.run((ctx) => ctx.db.patch(edgeId, { status: 'needs_operator' }));
    expect(await s.t.mutation(internal.edgeReconcileMutations.retryDestroy, { edgeId })).toEqual({
      ok: true,
    });
    // A refusal is an error (HTTP maps it), never a 200 with ok:false.
    await expect(
      s.t.mutation(internal.edgeReconcileMutations.retryDestroy, { edgeId }),
    ).rejects.toThrow(/not_destroyable|cannot be sent/);
    await run(s.t); // DELETE requested
    const r = await run(s.t); // re-issued DELETE → 404 → gone
    expect(r.destroyed).toBe(1);
    const trail = await s.t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(trail.some((a) => a.action === 'edge.retry_destroy')).toBe(true);
    const destroyed = (await s.t.query(internal.edges.get, { id: edgeId }))!;
    expect(destroyed.liveSnapshot).toBeUndefined();
  });

  test('resolveOperator forget/destroy heal the pool lists and audit as edge.forget / edge.destroy', async () => {
    fakeUpcloud([{ uuid: 'lb-1', name: 'x' }]);
    const s = await seed();
    const edgeId = await managedEdge(s, 'lb-1', { status: 'needs_operator' });
    // A stale standby listing + a live snapshot to clear.
    await s.t.run(async (ctx) => {
      const o = (await ctx.db.get(s.relayId))!;
      await ctx.db.patch(s.relayId, { standbyEdgeIds: [...o.standbyEdgeIds, edgeId] });
      await ctx.db.patch(edgeId, { liveSnapshot: '{"summary":{}}', liveAt: Date.now() });
    });
    await s.t.mutation(internal.edgeAdmin.resolveOperator, { edgeId, action: 'forget' });
    const edge = (await s.t.query(internal.edges.get, { id: edgeId }))!;
    expect(edge.status).toBe('destroyed');
    expect(edge.liveSnapshot).toBeUndefined();
    expect(edge.liveAt).toBeUndefined();
    expect((await s.t.query(internal.relays.get, { id: s.relayId }))!.standbyEdgeIds).not.toContain(
      edgeId,
    );
    const audit = await s.t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.find((a) => a.action === 'edge.forget')?.payload).toMatchObject({ edgeId });
    expect(audit.some((a) => a.action === 'edge.delete')).toBe(false);
  });

  test('stale rotation is re-kicked', async () => {
    vi.useFakeTimers();
    fakeUpcloud([]);
    const s = await seed();
    const { rotationId } = await s.t.mutation(internal.edgeRotations.start, {
      relayId: s.relayId,
      kind: 'provision',
      trigger: 'manual',
    });
    await s.t.run((ctx) => ctx.db.patch(rotationId, { nextStepAt: Date.now() - 120_000 }));
    const r = await run(s.t);
    expect(r.rekicked).toBe(1);
    const rot = (await s.t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(rot.events.map((e) => e.code)).toContain('rekicked');
    expect(rot.nextStepAt).toBeGreaterThan(Date.now() - 1000);
  });

  test('pool upkeep: a publishable standby fills a free non-zero index directly (only with edge.enabled)', async () => {
    fakeUpcloud([{ uuid: 'lb-1', name: 'x' }]);
    const s = await seed();
    await s.t.mutation(internal.relays.adoptEdge, {
      relayId: s.relayId,
      slotId: s.slotId,
      ipv4: '198.51.100.1',
      publish: true,
    });
    const standby = await managedEdge(s, 'lb-1', {});
    // Dormant by default: the master switch gates every automatic pool action.
    const off = await run(s.t);
    expect(off.published + off.started).toBe(0);
    await s.t.run((ctx) => upsertSettingRow(ctx, 'edge.enabled', 'true'));
    const r = await run(s.t);
    expect(r.published).toBe(1);
    expect(r.started).toBe(0);
    const origin = (await s.t.query(internal.relays.get, { id: s.relayId }))!;
    expect(origin.publishedEdgeIds[1]).toBe(standby);
    expect(origin.activeRotationId).toBeUndefined();
  });

  test('pool upkeep: index 0 on a Host-managed origin goes through a publish rotation, not a direct write', async () => {
    fakeUpcloud([{ uuid: 'lb-1', name: 'x' }]);
    const s = await seed();
    await s.t.run((ctx) => upsertSettingRow(ctx, 'edge.enabled', 'true'));
    await managedEdge(s, 'lb-1', {});
    const r = await run(s.t);
    expect(r.published).toBe(0);
    expect(r.started).toBe(1);
    const origin = (await s.t.query(internal.relays.get, { id: s.relayId }))!;
    expect(origin.activeRotationId).toBeDefined();
    expect(origin.publishedEdgeIds).toEqual([]);
    const rot = (await s.t.query(internal.edgeRotations.get, { id: origin.activeRotationId! }))!;
    expect(rot.kind).toBe('publish');
    // Started through `startRotation`: audited as a publish with the rotation id.
    const audit = await s.t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.find((a) => a.action === 'admin.edge.publish')?.payload).toMatchObject({
      trigger: 'reconcile',
      rotationId: rot._id,
    });
    // Next tick: the origin is busy → nothing else starts.
    const r2 = await run(s.t);
    expect(r2.started + r2.published).toBe(0);
  });

  test('pool upkeep: autoProvisionToDesired starts at most maxReconcileStartsPerTick provisions', async () => {
    fakeUpcloud([]);
    const s = await seed();
    await s.t.run((ctx) => upsertSettingRow(ctx, 'edge.enabled', 'true'));
    await s.t.run((ctx) => upsertSettingRow(ctx, 'edge.autoProvisionToDesired', 'true'));
    await s.t.mutation(internal.relays.upsertBySlug, {
      slug: 'node-two',
      backendServerSlug: 'panel-a',
      nodeHostname: 'node-two',
      originAddress: '203.0.113.11',
    });
    const two = (await s.t.query(internal.relays.getBySlug, { slug: 'node-two' }))!;
    await s.t.mutation(internal.relaySlots.upsert, {
      relayId: two._id,
      slotKey: 'u',
      profileSlug: 'prof-u',
      inboundTag: 'VLESS_RELAY_U',
      configProfileUuid: '11111111-1111-4111-8111-111111111111',
      configProfileInboundUuid: '33333333-3333-4333-8333-333333333333',
      originPort: 443,
    });
    const r = await run(s.t);
    expect(r.started).toBe(1);
    const origins = await s.t.query(internal.relays.listAll, {});
    expect(origins.filter((o) => o.activeRotationId).length).toBe(1);
    // Off by default: with the setting removed nothing starts for the other origin.
    await s.t.run(async (ctx) => {
      const row = await ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.eq('key', 'edge.autoProvisionToDesired'))
        .unique();
      if (row) await ctx.db.delete(row._id);
    });
    const r2 = await run(s.t);
    expect(r2.started).toBe(0);
  });

  test('deleting origin is finalized once nothing managed remains', async () => {
    fakeUpcloud([]);
    const s = await seed();
    await s.t.mutation(internal.relays.adoptEdge, {
      relayId: s.relayId,
      slotId: s.slotId,
      ipv4: '198.51.100.1',
      publish: true,
    });
    await s.t.mutation(internal.relays.requestDelete, { id: s.relayId });
    const r = await run(s.t);
    expect(r.finalizedDeletes).toBe(1);
    expect(await s.t.query(internal.relays.get, { id: s.relayId })).toBeNull();
  });

  test('the cron stamps a heartbeat outcome', async () => {
    fakeUpcloud([]);
    const s = await seed();
    await run(s.t);
    const hb = await s.t.run((ctx) => ctx.db.query('cronHeartbeats').collect());
    expect(hb.some((h) => h.name === 'edge-reconcile')).toBe(true);
  });

  test('discovery attempts persist on the step: an adapter needing two quiet looks reaches confirmed_absent on the second pass', async () => {
    // Gcore's discover says `unresolved` on the first miss (a create may still be
    // registering) and `confirmed_absent` from attempt 2. Each pass settles its
    // claim, so the count has to live on the step, not the claim.
    const stub = mockFetch((c) => {
      if (new URL(c.url).hostname === 'panel.example') return jsonRes({ response: [] });
      if (c.path === '/cloud/v1/loadbalancers/11/22' && c.method === 'GET')
        return jsonRes({ results: [] });
      throw new Error(`unexpected ${c.method} ${c.url}`);
    });
    const s = await seed();
    const { id: accountId } = await s.t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'gcore',
      name: 'acct-g',
      settings: { projectId: 11, regionId: 22 },
      credentials: { apiKey: 'k' },
    });
    await s.t.mutation(internal.edgeProviderAccounts.setQualified, {
      id: accountId,
      qualified: true,
    });
    await s.t.mutation(internal.protocolProfiles.create, {
      slug: 'prof-g',
      name: 'Profile G',
      provider: 'gcore',
      targetAddress: 'target-g.example',
      serverNames: ['g.example'],
    });
    const { id: slotId } = await s.t.mutation(internal.relaySlots.upsert, {
      relayId: s.relayId,
      slotKey: 'g',
      profileSlug: 'prof-g',
      inboundTag: 'VLESS_RELAY_G',
      configProfileUuid: '11111111-1111-4111-8111-111111111111',
      configProfileInboundUuid: '33333333-3333-4333-8333-333333333333',
      originPort: 8443,
    });
    const { id: edgeId } = await s.t.mutation(internal.edges.insertPlanned, {
      relayId: s.relayId,
      slotId,
      accountId,
      templateHash: 'h',
      listeners: [{ edgePort: 443, originAddress: ORIGIN, originPort: 8443 }],
      steps: [{ id: 'lb', kind: 'create_lb', resourceName: 'x', discoverability: 'by_name' }],
    });
    await s.t.mutation(internal.edges.patchEdge, {
      edgeId,
      status: 'failed',
      stepStates: [{ stepId: 'lb', state: 'unresolved' }],
    });
    const r1 = await run(s.t);
    expect(r1.settled).toBe(1);
    let edge = (await s.t.query(internal.edges.get, { id: edgeId }))!;
    expect(edge.steps[0]).toMatchObject({ state: 'unresolved', discoverAttempts: 1 });
    expect(edge.currentOp).toBeUndefined();
    const r2 = await run(s.t);
    expect(r2.settled).toBe(1);
    edge = (await s.t.query(internal.edges.get, { id: edgeId }))!;
    expect(edge.steps[0].state).toBe('done');
    expect(edge.steps[0].discoverAttempts).toBeUndefined();
    // Two LISTs, never a POST.
    expect(stub.calls.filter((c) => c.path.startsWith('/cloud/')).map((c) => c.method)).toEqual([
      'GET',
      'GET',
    ]);
  });

  test('a sync-delete provider is confirmed by re-issuing the delete, never by assuming it landed', async () => {
    const lbs = new Map([['lb-1', { uuid: 'lb-1', name: 'x', operational_state: 'running' }]]);
    const deletes: string[] = [];
    let failNext = true;
    mockFetch((c) => {
      if (new URL(c.url).hostname === 'panel.example') return jsonRes({ response: [] });
      const one = c.path.match(/^\/1\.3\/load-balancer\/([^/]+)$/);
      if (one && c.method === 'GET') {
        const lb = lbs.get(one[1]);
        return lb ? jsonRes(lb) : jsonRes({ error: { error_code: 'LB_NOT_FOUND' } }, 404);
      }
      if (one && c.method === 'DELETE') {
        deletes.push(one[1]);
        if (failNext) {
          failNext = false;
          return jsonRes({ error: { error_code: 'INTERNAL' } }, 500); // unknown outcome; LB stays
        }
        if (!lbs.has(one[1])) return jsonRes({ error: { error_code: 'LB_NOT_FOUND' } }, 404);
        lbs.delete(one[1]);
        return new Response(null, { status: 204 });
      }
      throw new Error(`unexpected ${c.method} ${c.url}`);
    });
    const s = await seed();
    const edgeId = await managedEdge(s, 'lb-1', {
      status: 'draining',
      publication: 'draining',
      drainUntil: Date.now() - 1,
    });
    await run(s.t); // → destroying
    const r2 = await run(s.t); // DELETE throws → delete_requested
    expect(r2.errors).toBe(1);
    let edge = (await s.t.query(internal.edges.get, { id: edgeId }))!;
    expect(edge.resources[0].deleteState).toBe('delete_requested');
    expect(edge.status).toBe('destroying');
    // Confirmation re-runs the idempotent DELETE: this one lands (2xx = requested,
    // the LB is really gone only now) and the NEXT re-issue's 404 confirms it.
    const r3 = await run(s.t);
    expect(r3.destroyed).toBe(0);
    expect(lbs.size).toBe(0);
    edge = (await s.t.query(internal.edges.get, { id: edgeId }))!;
    expect(edge.resources[0].deleteState).toBe('delete_requested');
    const r4 = await run(s.t);
    expect(r4.destroyed).toBe(1);
    edge = (await s.t.query(internal.edges.get, { id: edgeId }))!;
    expect(edge.status).toBe('destroyed');
    expect(deletes).toEqual(['lb-1', 'lb-1', 'lb-1']);
    // Decided on the reconcile side from the capability record, not by luck of the adapter.
    expect(shouldReissueDelete({ provider: 'upcloud', destroyConfirm: undefined }, 'lb-1')).toBe(
      true,
    );
    expect(shouldReissueDelete({ provider: 'gcore', destroyConfirm: undefined }, 'lb-1')).toBe(
      false,
    );
    expect(
      shouldReissueDelete(
        {
          provider: 'gcore',
          destroyConfirm: { resourceId: 'lb-1', attempts: MAX_CONFIRM_ATTEMPTS },
        },
        'lb-1',
      ),
    ).toBe(true);
    expect(
      shouldReissueDelete(
        { provider: 'gcore', destroyConfirm: { resourceId: 'other', attempts: 99 } },
        'lb-1',
      ),
    ).toBe(false);
  });

  test('an async-delete provider whose confirm never resolves gets the delete re-issued after N confirms', async () => {
    // Gcore: DELETE returns a task; confirm = GET (present → unresolved). The
    // resource is already `delete_requested` (a thrown runDestroy earlier), yet
    // the LB is still there because that DELETE never reached the provider.
    const calls: string[] = [];
    mockFetch((c) => {
      if (new URL(c.url).hostname === 'panel.example') return jsonRes({ response: [] });
      if (c.path === '/cloud/v1/loadbalancers/11/22/lb-g') {
        calls.push(c.method);
        // Read-back says the delete is in flight: `unresolved` (a not-deleting
        // LB would be `still_present`, covered by the next test).
        if (c.method === 'GET')
          return jsonRes({ id: 'lb-g', provisioning_status: 'PENDING_DELETE' });
        if (c.method === 'DELETE') return jsonRes({ tasks: ['t-1'] });
      }
      throw new Error(`unexpected ${c.method} ${c.url}`);
    });
    const s = await seed();
    const { id: accountId } = await s.t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'gcore',
      name: 'acct-g',
      settings: { projectId: 11, regionId: 22 },
      credentials: { apiKey: 'k' },
    });
    await s.t.mutation(internal.protocolProfiles.create, {
      slug: 'prof-g',
      name: 'Profile G',
      provider: 'gcore',
      targetAddress: 'target-g.example',
      serverNames: ['g.example'],
    });
    const { id: slotId } = await s.t.mutation(internal.relaySlots.upsert, {
      relayId: s.relayId,
      slotKey: 'g',
      profileSlug: 'prof-g',
      inboundTag: 'VLESS_RELAY_G',
      configProfileUuid: '11111111-1111-4111-8111-111111111111',
      configProfileInboundUuid: '33333333-3333-4333-8333-333333333333',
      originPort: 8443,
    });
    const { id: edgeId } = await s.t.mutation(internal.edges.insertPlanned, {
      relayId: s.relayId,
      slotId,
      accountId,
      templateHash: 'h',
      listeners: [{ edgePort: 443, originAddress: ORIGIN, originPort: 8443 }],
      steps: [{ id: 'lb', kind: 'create_lb', resourceName: 'x', discoverability: 'by_name' }],
    });
    await s.t.run(async (ctx) => {
      const e = (await ctx.db.get(edgeId))!;
      await ctx.db.patch(edgeId, {
        steps: e.steps.map((st) => ({ ...st, state: 'done' as const })),
        resources: [
          {
            stepId: 'lb',
            kind: 'lb',
            resourceId: 'lb-g',
            ownership: 'created' as const,
            deleteState: 'delete_requested' as const,
          },
        ],
        status: 'destroying',
        publication: 'unpublished',
      });
    });
    for (let i = 1; i <= MAX_CONFIRM_ATTEMPTS; i++) {
      await run(s.t);
      const e = (await s.t.query(internal.edges.get, { id: edgeId }))!;
      expect(e.destroyConfirm).toEqual({ resourceId: 'lb-g', attempts: i });
      expect(e.resources[0].deleteState).toBe('delete_requested');
    }
    expect(calls).toEqual(Array(MAX_CONFIRM_ATTEMPTS).fill('GET'));
    // Past the cap: the idempotent DELETE is re-issued and the counter resets.
    await run(s.t);
    expect(calls[calls.length - 1]).toBe('DELETE');
    const e = (await s.t.query(internal.edges.get, { id: edgeId }))!;
    expect(e.destroyConfirm).toBeUndefined();
    expect(e.resources[0].deleteState).toBe('delete_requested');
    expect(e.status).toBe('destroying');
  });
  test('a read-back that is NOT deleting (still_present) sends the resource back to present and the delete is re-issued', async () => {
    // Gcore: the resource is `delete_requested` (a thrown runDestroy earlier) but
    // the LB reads back ACTIVE → the delete never landed. Confirming would wait
    // forever, so the walk re-issues the DELETE on the very next pass.
    const calls: string[] = [];
    mockFetch((c) => {
      if (new URL(c.url).hostname === 'panel.example') return jsonRes({ response: [] });
      if (c.path === '/cloud/v1/loadbalancers/11/22/lb-g') {
        calls.push(c.method);
        if (c.method === 'GET') return jsonRes({ id: 'lb-g', provisioning_status: 'ACTIVE' });
        if (c.method === 'DELETE') return jsonRes({ tasks: ['t-1'] });
      }
      throw new Error(`unexpected ${c.method} ${c.url}`);
    });
    const s = await seed();
    const edgeId = await gcoreDestroyingEdge(s, 'delete_requested');
    await run(s.t); // confirm → still_present
    let e = (await s.t.query(internal.edges.get, { id: edgeId }))!;
    expect(e.resources[0].deleteState).toBe('present');
    expect(e.destroyConfirm).toBeUndefined();
    expect(e.destroyAttempts).toBe(1);
    expect(e.status).toBe('destroying');
    await run(s.t); // present → runDestroy re-issued
    e = (await s.t.query(internal.edges.get, { id: edgeId }))!;
    expect(calls).toEqual(['GET', 'DELETE']);
    expect(e.resources[0].deleteState).toBe('delete_requested');
    expect(e.destroyAttempts).toBe(2);
  });

  test('an unresolved destroy answer (a resource kind the adapter does not know) counts toward the attempt cap', async () => {
    const stub = mockFetch((c) => {
      if (new URL(c.url).hostname === 'panel.example') return jsonRes({ response: [] });
      throw new Error(`unexpected ${c.method} ${c.url}`);
    });
    const s = await seed();
    // One attempt short of the cap: this pass answers `unresolved` (never gone),
    // the next one parks the edge.
    const edgeId = await gcoreDestroyingEdge(s, 'present', {
      kind: 'mystery',
      destroyAttempts: 47,
    });
    const r1 = await run(s.t);
    expect(r1.errors).toBe(0);
    let e = (await s.t.query(internal.edges.get, { id: edgeId }))!;
    expect(e.resources[0].deleteState).toBe('present');
    expect(e.destroyAttempts).toBe(48);
    expect(e.status).toBe('destroying');
    await run(s.t);
    e = (await s.t.query(internal.edges.get, { id: edgeId }))!;
    expect(e.status).toBe('needs_operator');
    expect(e.failure?.code).toBe('destroy_attempts_exhausted');
    // The adapter never called the provider for a kind it does not know.
    expect(stub.calls.filter((c) => c.path.startsWith('/cloud/'))).toHaveLength(0);
  });

  test('a udp listener is refused at planning, before any provider call', async () => {
    const stub = mockFetch((c) => {
      if (new URL(c.url).hostname === 'panel.example') return jsonRes({ response: [] });
      throw new Error(`unexpected ${c.method} ${c.url}`);
    });
    const s = await seed();
    await expect(
      s.t.action(internal.edgeProviderOps.planProvision, {
        accountId: s.accountId,
        spec: {
          name: 'fcp-relay-node-one-00000000',
          listeners: [
            { edgePort: 443, members: [{ address: ORIGIN, port: 443 }], transport: 'udp' },
          ],
        },
        templateParams: {},
      }),
    ).rejects.toThrow(/transport_unsupported/);
    expect(stub.calls.filter((c) => c.path.startsWith('/1.3/'))).toHaveLength(0);
    // tcp (and the absent default) plan fine.
    const steps = await s.t.action(internal.edgeProviderOps.planProvision, {
      accountId: s.accountId,
      spec: {
        name: 'fcp-relay-node-one-00000000',
        listeners: [{ edgePort: 443, members: [{ address: ORIGIN, port: 443 }], transport: 'tcp' }],
      },
      templateParams: {},
    });
    expect(steps.length).toBeGreaterThan(0);
  });
});
