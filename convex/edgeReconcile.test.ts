/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';

import { jsonRes, mockFetch } from './lib/edges/testing/mockFetch';
import { upsertSettingRow } from './appSettings';
import { MAX_CONFIRM_ATTEMPTS, shouldReissueDelete } from './edgeReconcile';
import { __setEdgeProviderForTests, edgeProviderFor } from './lib/edges/providers/registry';
import { __setFrontChecker } from './frontQualifyOps';
import { publishedEdgesOf } from './edgeRender';
import { qualificationBinding } from './lib/edges/frontCheck/binding';
import type { Id } from './_generated/dataModel';
import { z } from 'zod';
import {
  adoptL4Edge,
  createAccount,
  FIXTURE_CONFIG_PROFILE,
  insertPanelServer,
  realityListener,
  registerRelay,
  shadowsocksListener,
  wsListener,
  type ListenerSpecFixture,
} from './lib/edges/testing/fixtures';

const modules = import.meta.glob('./**/*.*s');

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

const ORIGIN = '203.0.113.10';
const INBOUND_U = '22222222-2222-4222-8222-222222222222';
const INBOUND_G = '33333333-3333-4333-8333-333333333333';
const HOST_UUID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

interface PanelHost {
  uuid: string;
  remark: string;
  address: string;
  port: number;
  sni?: string | null;
  inbound: { configProfileUuid: string; configProfileInboundUuid: string } | null;
}

/**
 * Fake UpCloud with a mutable LB table; records DELETEs. The panel half keeps a
 * Host table too (GET lists, DELETE removes) so the Host cleanup is observable.
 */
function fakeUpcloud(
  initial: Array<{ uuid: string; name: string }>,
  opts: { panelHosts?: PanelHost[] } = {},
) {
  const lbs = new Map(initial.map((l) => [l.uuid, { ...l, operational_state: 'running' }]));
  const deletes: string[] = [];
  const panelHosts = opts.panelHosts ?? [];
  const panelCalls: string[] = [];
  const stub = mockFetch((c) => {
    if (new URL(c.url).hostname === 'panel.example') {
      panelCalls.push(`${c.method} ${c.path}`);
      if (c.path === '/api/hosts' && c.method === 'GET') return jsonRes({ response: panelHosts });
      const del = c.path.match(/^\/api\/hosts\/([^/]+)$/);
      if (del && c.method === 'DELETE') {
        const i = panelHosts.findIndex((h) => h.uuid === del[1]);
        if (i >= 0) panelHosts.splice(i, 1);
        return new Response(null, { status: 204 });
      }
      return jsonRes({ response: [] });
    }
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
  return { stub, lbs, deletes, panelHosts, panelCalls };
}

/** The REALITY listener `u`, scoped to the UpCloud network (the old "profile U"). */
function listenerU(over: Partial<ListenerSpecFixture> = {}): ListenerSpecFixture {
  return realityListener({
    listenerKey: 'u',
    tlsNames: ['a.example'],
    providerScope: { provider: 'upcloud' },
    panelBinding: {
      inboundTag: 'VLESS_RELAY_U',
      configProfileUuid: FIXTURE_CONFIG_PROFILE,
      configProfileInboundUuid: INBOUND_U,
    },
    ...over,
  });
}

/** The REALITY listener `g` on 8443, scoped to the Gcore network (the old "profile G"). */
function listenerG(): ListenerSpecFixture {
  return realityListener({
    listenerKey: 'g',
    originPort: 8443,
    tlsNames: ['g.example'],
    realityTarget: { address: 'target-g.example', port: 443 },
    providerScope: { provider: 'gcore' },
    panelBinding: {
      inboundTag: 'VLESS_RELAY_G',
      configProfileUuid: FIXTURE_CONFIG_PROFILE,
      configProfileInboundUuid: INBOUND_G,
    },
  });
}

async function seed() {
  const t = convexTest(schema, modules);
  await insertPanelServer(t);
  const accountId = await createAccount(t, {
    provider: 'upcloud',
    name: 'acct-u',
    qualified: true,
  });
  const { relayId, listenerId } = await registerRelay(t, { listeners: [listenerU()] });
  return { t, accountId, relayId, listenerId };
}

/** An admin-added Gcore-scoped listener `g` on the seeded relay, plus a Gcore account. */
async function gcoreListener(
  s: Awaited<ReturnType<typeof seed>>,
  opts: { qualified?: boolean } = {},
) {
  const accountId = await createAccount(s.t, {
    provider: 'gcore',
    name: 'acct-g',
    qualified: opts.qualified,
  });
  const { id: listenerId } = await s.t.mutation(internal.relayListeners.upsert, {
    relayId: s.relayId,
    spec: listenerG() as never,
  });
  return { accountId, listenerId };
}

/** A managed edge whose single `lb` step is done with one lb resource, in the given status. */
async function managedEdge(
  s: Awaited<ReturnType<typeof seed>>,
  lbId: string,
  patch: Record<string, unknown>,
  listenerId: Id<'relayListeners'> = s.listenerId,
) {
  const { id } = await s.t.mutation(internal.edges.insertPlanned, {
    relayId: s.relayId,
    listenerId,
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
  const { accountId, listenerId } = await gcoreListener(s);
  const { id: edgeId } = await s.t.mutation(internal.edges.insertPlanned, {
    relayId: s.relayId,
    listenerId,
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
    // The listener's template index is the rotation machine's job on a relay
    // whose Hosts FCP owns; these tests are about the reconcile loop, not the
    // flip, so the operator keeps the Hosts.
    await s.t.mutation(internal.relays.update, { id: s.relayId, hostMode: 'operator' });
    await s.t.mutation(internal.relays.publishEdge, { relayId: s.relayId, edgeId });
    const before = (await s.t.query(internal.relays.get, { id: s.relayId }))!;
    expect(before.publishedEdgeIds).toEqual([edgeId]);
    expect((await s.t.run((ctx) => ctx.db.get(s.listenerId)))!.templateEdgeId).toBe(edgeId);
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
    // The listener lost its template edge with the drop.
    expect((await s.t.run((ctx) => ctx.db.get(s.listenerId)))!.templateEdgeId).toBeUndefined();
    const audit = await s.t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.some((a) => a.action === 'edge.drift')).toBe(true);
    expect(audit.some((a) => a.action === 'edge.unpublished')).toBe(true);
  });

  test('a quarantined origin is hands-off for the cron: no describe, no drop', async () => {
    const world = fakeUpcloud([]);
    const s = await seed();
    const edgeId = await managedEdge(s, 'lb-1', { lastHealthAt: undefined });
    await s.t.mutation(internal.relays.update, { id: s.relayId, hostMode: 'operator' });
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
      listenerId: s.listenerId,
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
    expect(
      world.stub.calls
        .filter((c) => c.path.startsWith('/1.3/'))
        .map((c) => `${c.method} ${c.path}`),
    ).toEqual(['GET /1.3/load-balancer']);
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
      listenerId: s.listenerId,
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

  test('pool upkeep: a publishable standby of a listener that already has a template edge fills a free index directly (only with edge.enabled)', async () => {
    fakeUpcloud([{ uuid: 'lb-1', name: 'x' }]);
    const s = await seed();
    const { edgeId: adopted } = await adoptL4Edge(s.t, s.relayId, s.listenerId, {
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
    // The listener's template stays its lower-index edge.
    expect((await s.t.run((ctx) => ctx.db.get(s.listenerId)))!.templateEdgeId).toBe(adopted);
  });

  test('pool upkeep: a standby that would become its LISTENER’s template edge goes through a publish rotation, not a direct write', async () => {
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
    expect(rot.listenerId).toBe(s.listenerId);
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

  test('pool upkeep: the template rule is PER LISTENER: a free non-zero index still needs the rotation when the standby’s listener has no template yet', async () => {
    fakeUpcloud([{ uuid: 'lb-1', name: 'x' }]);
    const t = convexTest(schema, modules);
    await insertPanelServer(t);
    const accountId = await createAccount(t, {
      provider: 'upcloud',
      name: 'acct-u',
      qualified: true,
    });
    const { relayId, listenerIds } = await registerRelay(t, {
      listeners: [listenerU(), shadowsocksListener()],
    });
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.enabled', 'true'));
    // `u` holds index 0 (its template); `s` has nothing published yet.
    await adoptL4Edge(t, relayId, listenerIds.u, { ipv4: '198.51.100.1', publish: true });
    const s = { t, accountId, relayId, listenerId: listenerIds.u };
    const standbyS = await managedEdge(s, 'lb-1', {}, listenerIds.s);
    const r = await run(t);
    // Index 1 is free, but this edge becomes `s`'s template: the flip is owed.
    expect(r.published).toBe(0);
    expect(r.started).toBe(1);
    const origin = (await t.query(internal.relays.get, { id: relayId }))!;
    const rot = (await t.query(internal.edgeRotations.get, { id: origin.activeRotationId! }))!;
    expect(rot).toMatchObject({ kind: 'publish', toEdgeId: standbyS, listenerId: listenerIds.s });
  });

  test('pool upkeep: with the operator managing the Hosts, even the template index is a direct publish', async () => {
    fakeUpcloud([{ uuid: 'lb-1', name: 'x' }]);
    const s = await seed();
    await s.t.run((ctx) => upsertSettingRow(ctx, 'edge.enabled', 'true'));
    await s.t.mutation(internal.relays.update, { id: s.relayId, hostMode: 'operator' });
    const standby = await managedEdge(s, 'lb-1', {});
    const r = await run(s.t);
    expect(r.published).toBe(1);
    expect(r.started).toBe(0);
    const origin = (await s.t.query(internal.relays.get, { id: s.relayId }))!;
    expect(origin.publishedEdgeIds).toEqual([standby]);
    expect(origin.activeRotationId).toBeUndefined();
    expect((await s.t.run((ctx) => ctx.db.get(s.listenerId)))!.templateEdgeId).toBe(standby);
  });

  test('pool upkeep: autoProvisionToDesired starts at most maxReconcileStartsPerTick provisions', async () => {
    fakeUpcloud([]);
    const s = await seed();
    await s.t.run((ctx) => upsertSettingRow(ctx, 'edge.enabled', 'true'));
    await s.t.run((ctx) => upsertSettingRow(ctx, 'edge.autoProvisionToDesired', 'true'));
    await registerRelay(s.t, {
      slug: 'node-two',
      nodeName: 'node-two',
      originAddress: '203.0.113.11',
      listeners: [
        listenerU({
          panelBinding: {
            inboundTag: 'VLESS_RELAY_U',
            configProfileUuid: FIXTURE_CONFIG_PROFILE,
            configProfileInboundUuid: INBOUND_G,
          },
        }),
      ],
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

  test('maintenance: while frozen, upkeep admits nothing (no publish, no provision) but deletes still finish', async () => {
    fakeUpcloud([{ uuid: 'lb-1', name: 'x' }]);
    const s = await seed();
    await s.t.run((ctx) => upsertSettingRow(ctx, 'edge.enabled', 'true'));
    await s.t.run((ctx) => upsertSettingRow(ctx, 'edge.autoProvisionToDesired', 'true'));
    await adoptL4Edge(s.t, s.relayId, s.listenerId, { ipv4: '198.51.100.1', publish: true });
    const standby = await managedEdge(s, 'lb-1', {});
    // A second relay already marked for deletion, with nothing left to tear down.
    const { relayId: doomed } = await registerRelay(s.t, {
      slug: 'node-two',
      nodeName: 'node-two',
      originAddress: '203.0.113.11',
      listeners: [
        listenerU({
          panelBinding: {
            inboundTag: 'VLESS_RELAY_U',
            configProfileUuid: FIXTURE_CONFIG_PROFILE,
            configProfileInboundUuid: INBOUND_G,
          },
        }),
      ],
    });
    await s.t.mutation(internal.relays.requestDelete, {
      id: doomed,
      disposition: 'restore-direct',
    });
    await s.t.mutation(internal.edgeMaintenance.freeze, { reason: 'test' });
    const frozen = await run(s.t);
    expect(frozen.published + frozen.started).toBe(0);
    expect(frozen.finalizedDeletes).toBe(1);
    expect(await s.t.query(internal.relays.get, { id: doomed })).toBeNull();
    let origin = (await s.t.query(internal.relays.get, { id: s.relayId }))!;
    expect(origin.publishedEdgeIds).toHaveLength(1);
    expect(origin.activeRotationId).toBeUndefined();
    // Thawed: the very next tick publishes the standby.
    await s.t.mutation(internal.edgeMaintenance.thaw, {});
    const thawed = await run(s.t);
    expect(thawed.published).toBe(1);
    origin = (await s.t.query(internal.relays.get, { id: s.relayId }))!;
    expect(origin.publishedEdgeIds[1]).toBe(standby);
  });

  test('deleting origin is finalized once nothing managed remains and no FCP Host is left', async () => {
    fakeUpcloud([]);
    const s = await seed();
    await adoptL4Edge(s.t, s.relayId, s.listenerId, { ipv4: '198.51.100.1', publish: true });
    await expect(s.t.mutation(internal.relays.requestDelete, { id: s.relayId })).rejects.toThrow(
      /delivery_disposition_required/,
    );
    await s.t.mutation(internal.relays.requestDelete, {
      id: s.relayId,
      disposition: 'restore-direct',
    });
    const r = await run(s.t);
    expect(r.finalizedDeletes).toBe(1);
    expect(await s.t.query(internal.relays.get, { id: s.relayId })).toBeNull();
    expect(await s.t.run((ctx) => ctx.db.get(s.listenerId))).toBeNull();
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
    const { accountId, listenerId } = await gcoreListener(s, { qualified: true });
    const { id: edgeId } = await s.t.mutation(internal.edges.insertPlanned, {
      relayId: s.relayId,
      listenerId,
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
    // Two quiet looks are not enough on their own: this provider also needs its
    // SETTLE FLOOR to have passed since the step was first requested, so a slow
    // compound create is never declared absent seconds after the request. The
    // reconcile always supplies a reference time (the step's own `startedAt`,
    // else the claim, else the edge's creation), so the floor is provable.
    const r1b = await run(s.t);
    expect(r1b.settled).toBe(1);
    edge = (await s.t.query(internal.edges.get, { id: edgeId }))!;
    expect(edge.steps[0]).toMatchObject({ state: 'unresolved', discoverAttempts: 2 });
    // Age the step past the floor.
    await s.t.run(async (ctx) => {
      const e = (await ctx.db.get(edgeId))!;
      await ctx.db.patch(edgeId, {
        steps: e.steps.map((st) => ({ ...st, startedAt: Date.now() - 5 * 60_000 })),
      });
    });
    const r2 = await run(s.t);
    expect(r2.settled).toBe(1);
    edge = (await s.t.query(internal.edges.get, { id: edgeId }))!;
    expect(edge.steps[0].state).toBe('done');
    expect(edge.steps[0].discoverAttempts).toBeUndefined();
    // Only LISTs, never a POST.
    expect(stub.calls.filter((c) => c.path.startsWith('/cloud/')).map((c) => c.method)).toEqual([
      'GET',
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
    const edgeId = await gcoreDestroyingEdge(s, 'delete_requested');
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

describe('edgeReconcile: panel Host operations run every tick', () => {
  const presentHost = (ownership: 'fcp' | 'adopted' = 'fcp') => ({
    state: 'present' as const,
    uuid: HOST_UUID,
    ownership,
  });
  const panelHost = (): PanelHost => ({
    uuid: HOST_UUID,
    remark: 'node-one-relay-u',
    address: '198.51.100.1',
    port: 443,
    sni: 'a.example',
    inbound: { configProfileUuid: FIXTURE_CONFIG_PROFILE, configProfileInboundUuid: INBOUND_U },
  });

  test('nothing pending: the pass neither calls the panel nor errors', async () => {
    const world = fakeUpcloud([], { panelHosts: [panelHost()] });
    const s = await seed();
    await s.t.run((ctx) =>
      ctx.db.patch(s.listenerId, { host: presentHost(), updatedAt: Date.now() }),
    );
    const r = await run(s.t);
    expect(r.errors).toBe(0);
    expect(world.panelCalls).toEqual([]);
    expect(world.panelHosts).toHaveLength(1);
  });

  test('a retired listener’s FCP-owned Host is deleted, confirmed by the read-back, and the relay delete can then finish', async () => {
    const world = fakeUpcloud([], { panelHosts: [panelHost()] });
    const s = await seed();
    // The role dropped the listener from its body (pruned = retired) while FCP
    // still owned its Host.
    await s.t.run((ctx) =>
      ctx.db.patch(s.listenerId, {
        host: presentHost(),
        retired: true,
        deployed: false,
        updatedAt: Date.now(),
      }),
    );
    const r = await run(s.t);
    expect(r.errors).toBe(0);
    expect(world.panelCalls).toEqual([`DELETE /api/hosts/${HOST_UUID}`, 'GET /api/hosts']);
    expect(world.panelHosts).toEqual([]);
    expect((await s.t.run((ctx) => ctx.db.get(s.listenerId)))!.host).toEqual({ state: 'absent' });
    const audit = await s.t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.find((a) => a.action === 'relay.host.deleted')?.payload).toMatchObject({
      relaySlug: 'node-one',
      listenerKey: 'u',
    });
  });

  test('a deleting relay waits on its FCP Host: the tick removes the Host first, the row goes on the next', async () => {
    const world = fakeUpcloud([], { panelHosts: [panelHost()] });
    const s = await seed();
    await s.t.run((ctx) =>
      ctx.db.patch(s.listenerId, { host: presentHost(), updatedAt: Date.now() }),
    );
    await s.t.mutation(internal.relays.requestDelete, {
      id: s.relayId,
      disposition: 'keep-dark',
    });
    // Before the Host is gone the finalize refuses (hosts), and the pass runs
    // the Host cleanup before it tries.
    expect(await s.t.mutation(internal.relays.finalizeDelete, { id: s.relayId })).toEqual({
      removed: false,
      waitingOn: 'hosts',
    });
    const r = await run(s.t);
    expect(world.panelHosts).toEqual([]);
    // Same tick: the Host cleanup (step 4b) ran BEFORE the origin walk (step 6).
    expect(r.finalizedDeletes).toBe(1);
    expect(await s.t.query(internal.relays.get, { id: s.relayId })).toBeNull();
  });

  test('an adopted Host on a deleting relay is released, never deleted', async () => {
    const world = fakeUpcloud([], { panelHosts: [panelHost()] });
    const s = await seed();
    await s.t.run((ctx) =>
      ctx.db.patch(s.listenerId, { host: presentHost('adopted'), updatedAt: Date.now() }),
    );
    await s.t.mutation(internal.relays.requestDelete, {
      id: s.relayId,
      disposition: 'keep-dark',
    });
    const r = await run(s.t);
    expect(r.finalizedDeletes).toBe(1);
    expect(world.panelCalls.filter((c) => c.startsWith('DELETE'))).toEqual([]);
    expect(world.panelHosts).toHaveLength(1);
  });

  test('an EXPIRED unresolved create gets a discovery look each tick until it settles', async () => {
    vi.useFakeTimers({ now: 1_800_000_000_000 });
    const world = fakeUpcloud([], { panelHosts: [] });
    const s = await seed();
    const claim = await s.t.mutation(internal.hostOps.claimCreate, {
      listenerId: s.listenerId,
      target: { address: '198.51.100.1', port: 443, sni: 'a.example', host: null },
    });
    if (!claim.claimed) throw new Error('unreachable');
    await s.t.mutation(internal.hostOps.markUnresolved, {
      listenerId: s.listenerId,
      opId: claim.opId,
    });
    // Still inside the op's TTL: no look.
    await run(s.t);
    expect(world.panelCalls).toEqual([]);
    // Expired: a look; the panel holds the Host after all → present, owned by FCP.
    vi.setSystemTime(1_800_000_000_000 + 61_000);
    world.panelHosts.push(panelHost());
    await run(s.t);
    expect(world.panelCalls).toEqual(['GET /api/hosts']);
    const l = (await s.t.run((ctx) => ctx.db.get(s.listenerId)))!;
    expect(l.host).toMatchObject({ state: 'present', uuid: HOST_UUID, ownership: 'fcp' });
    expect(l.host!.op).toBeUndefined();
    // Settled: nothing more to look at.
    await run(s.t);
    expect(world.panelCalls).toEqual(['GET /api/hosts']);
  });
});

describe('edgeReconcile: observe-only edges', () => {
  /** An adopted, unmanaged edge in the given state. */
  async function adopted(s: Awaited<ReturnType<typeof seed>>, patch: Record<string, unknown>) {
    const { edgeId } = await adoptL4Edge(s.t, s.relayId, s.listenerId, { ipv4: '198.51.100.60' });
    await s.t.run((ctx) => ctx.db.patch(edgeId, patch));
    return edgeId;
  }

  test('a DRAINED observe-only edge is destroyed after its drain, without a provider call', async () => {
    const world = fakeUpcloud([]);
    const s = await seed();
    const edgeId = await adopted(s, {
      status: 'draining',
      publication: 'draining',
      drainUntil: Date.now() - 1,
    });
    const r = await run(s.t);
    expect(r.destroyed).toBe(1);
    expect((await s.t.query(internal.edges.get, { id: edgeId }))!.status).toBe('destroyed');
    // FCP never created it, so it never deletes it either.
    expect(world.deletes).toEqual([]);
  });

  test('an observe-only edge still inside its drain is left alone', async () => {
    fakeUpcloud([]);
    const s = await seed();
    const edgeId = await adopted(s, {
      status: 'draining',
      publication: 'draining',
      drainUntil: Date.now() + 60_000,
    });
    await run(s.t);
    expect((await s.t.query(internal.edges.get, { id: edgeId }))!.status).toBe('draining');
  });
});

describe('edgeReconcile: tearing a hostname off a SHARED resource', () => {
  afterEach(() => __setEdgeProviderForTests('cloudflare', null));

  /**
   * A front provider whose adopted domain sits on a service FCP does not own:
   * the service cannot be deleted, so removing one hostname from it is a
   * persisted version workflow the adapter drives one phase at a time.
   */
  function fakeSharedProvider(opts: { phases?: string[]; parkWith?: string } = {}) {
    const phases = opts.phases ?? ['clone', 'remove_domain', 'activate', 'done'];
    const steps: Array<{ phase: string; workVersion?: number }> = [];
    const destroyed: string[] = [];
    __setEdgeProviderForTests('cloudflare', {
      id: 'cloudflare',
      templateSchema: z.object({}).passthrough(),
      templateFields: [],
      defaultTemplate: {},
      testCredentials: async () => ({ ok: true }),
      planProvision: () => [],
      runStep: async () => ({ status: 'done', resources: [] }),
      discover: async () => ({ status: 'unresolved' }),
      describe: async () => ({ state: 'active', addresses: {}, health: 'unknown' }),
      inspect: async () => ({ summary: { addresses: [], members: [], listeners: [] }, raw: {} }),
      inventory: async () => ({ loadBalancers: [], ips: [], flavors: [] }),
      // The SHARED service is never in the destroy plan: FCP deletes only what
      // it owns on it (its domain, its DNS record).
      planDestroy: (_cfg: unknown, ledger: { resources: Array<Record<string, unknown>> }) =>
        ledger.resources.filter((r) => r.kind !== 'service' && r.deleteState !== 'confirmed_gone'),
      runDestroy: async (_cfg: unknown, r: { kind: string; resourceId: string }) => {
        destroyed.push(`${r.kind}:${r.resourceId}`);
        // A domain on a shared service is the workflow's job, never the walk's.
        return r.kind === 'domain' ? { status: 'unresolved' } : { status: 'confirmed_gone' };
      },
      sharedTeardown: {
        plan: (ledger: { resources: Array<Record<string, unknown>> }, opId: string) => {
          const svc = ledger.resources.find((r) => r.kind === 'service');
          if (!svc) return null;
          return {
            phase: phases[0],
            serviceId: String(svc.resourceId),
            fromVersion: 7,
            opId,
            attempts: 0,
            marker: `fcp-${opId}`,
          };
        },
        step: async (_cfg: unknown, state: { phase: string; workVersion?: number }) => {
          steps.push({ phase: state.phase, workVersion: state.workVersion });
          if (opts.parkWith) return { ...state, phase: 'needs_operator', code: opts.parkWith };
          const next = phases[phases.indexOf(state.phase) + 1] ?? 'done';
          return { ...state, phase: next, workVersion: (state.workVersion ?? 7) + 1 };
        },
      },
    } as never);
    return { steps, destroyed };
  }

  /** A destroying L7 edge whose ledger holds a shared service + the children FCP owns. */
  async function sharedEdge() {
    const t = convexTest(schema, modules);
    await insertPanelServer(t);
    const { id: accountId } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'cloudflare',
      name: 'acct-cf',
      settings: { zoneId: 'a'.repeat(32), zoneName: 'example.org' },
      credentials: { apiToken: 'cf' },
    });
    const { relayId, listenerId } = await registerRelay(t, {
      listeners: [
        wsListener({
          listenerKey: 'w',
          tlsNames: ['a.example'],
          panelBinding: {
            inboundTag: 'VLESS_RELAY_W',
            configProfileUuid: FIXTURE_CONFIG_PROFILE,
            configProfileInboundUuid: INBOUND_U,
          },
        }),
      ],
    });
    const child = (kind: string, resourceId: string, meta?: string) => ({
      stepId: 'adopted',
      kind,
      resourceId,
      ownership: 'adopted' as const,
      deleteState: 'present' as const,
      ...(meta ? { meta } : {}),
    });
    const edgeId = await t.run((ctx) =>
      ctx.db.insert('edges', {
        relayId,
        listenerId,
        accountId,
        provider: 'cloudflare',
        managed: true,
        name: 'adopted-node-one',
        steps: [],
        resources: [
          child('service', 'svc-1', JSON.stringify({ shared: true })),
          child('domain', 'dom-1'),
          child('dns_record', 'rec-1'),
        ],
        listeners: [{ edgePort: 443, originAddress: ORIGIN, originPort: 443 }],
        addresses: { hostname: 'front-a.example.org' },
        layer: 'l7',
        publication: 'unpublished',
        status: 'destroying',
        statusChangedAt: Date.now(),
        health: 'unknown',
        destroyAttempts: 0,
        updatedAt: Date.now(),
      }),
    );
    return { t, edgeId, relayId };
  }

  test('the version workflow is persisted and advanced ONE phase per pass, then the walk finishes', async () => {
    mockFetch(() => jsonRes({ response: [] }));
    const { steps, destroyed } = fakeSharedProvider();
    const { t, edgeId } = await sharedEdge();
    // Pass 1: the workflow is planned from the ledger and its first phase runs.
    await run(t);
    let edge = (await t.run((ctx) => ctx.db.get(edgeId)))!;
    expect(edge.sharedTeardown).toMatchObject({ phase: 'remove_domain', serviceId: 'svc-1' });
    // The driver's own extra fields survive as JSON.
    expect(JSON.parse(edge.sharedTeardownState!)).toMatchObject({ marker: expect.any(String) });
    expect(steps).toEqual([{ phase: 'clone', workVersion: undefined }]);
    // Each later pass advances exactly ONE phase: the service's version chain
    // is shared with every other adopted hostname on it.
    await run(t);
    edge = (await t.run((ctx) => ctx.db.get(edgeId)))!;
    expect(edge.sharedTeardown!.phase).toBe('activate');
    await run(t);
    edge = (await t.run((ctx) => ctx.db.get(edgeId)))!;
    expect(edge.sharedTeardown!.phase).toBe('done');
    // `done` means the hostname is off the shared service: only the DOMAIN the
    // workflow removed is gone. The DNS records live in another zone and the
    // workflow never touched them, so they are still the walk's to delete; the
    // SERVICE itself is untouched.
    expect(edge.resources.map((r) => [r.kind, r.deleteState])).toEqual([
      ['service', 'present'],
      ['domain', 'confirmed_gone'],
      ['dns_record', 'present'],
    ]);
    expect(destroyed).toEqual([]);
    // The ordinary walk now DELETES the records through the provider (the
    // workflow never touched them) and, with that last child gone, completes
    // the edge; the shared service was never its to delete.
    await run(t);
    edge = (await t.run((ctx) => ctx.db.get(edgeId)))!;
    expect(destroyed).toEqual(['dns_record:rec-1']);
    expect(edge.status).toBe('destroyed');
    expect(steps.map((s) => s.phase)).toEqual(['clone', 'remove_domain', 'activate']);
    // The version the workflow started from is remembered across re-entries.
    expect(edge.sharedTeardown!.fromVersion).toBe(7);
  });

  test('a workflow that cannot converge parks the edge with the driver code', async () => {
    mockFetch(() => jsonRes({ response: [] }));
    fakeSharedProvider({ parkWith: 'clone_lost' });
    const { t, edgeId } = await sharedEdge();
    await run(t);
    const edge = (await t.run((ctx) => ctx.db.get(edgeId)))!;
    expect(edge.status).toBe('needs_operator');
    expect(edge.failure).toMatchObject({ step: 'shared_teardown', code: 'clone_lost' });
  });

  test('a retry after an operator repair RESTARTS the workflow from its first phase', async () => {
    mockFetch(() => jsonRes({ response: [] }));
    fakeSharedProvider({ parkWith: 'clone_lost' });
    const { t, edgeId } = await sharedEdge();
    await run(t);
    let edge = (await t.run((ctx) => ctx.db.get(edgeId)))!;
    expect(edge.status).toBe('needs_operator');
    expect(edge.sharedTeardown?.phase).toBe('needs_operator');
    // The operator repairs the service by hand and retries: the terminal state
    // must not survive, or the driver would treat it as finished and the walk
    // could only answer `unresolved` for the shared domain.
    await t.mutation(internal.edgeReconcileMutations.retryDestroy, { edgeId });
    edge = (await t.run((ctx) => ctx.db.get(edgeId)))!;
    expect(edge.status).toBe('destroying');
    expect(edge.sharedTeardown).toBeUndefined();
    expect(edge.sharedTeardownState).toBeUndefined();
    const { steps } = fakeSharedProvider();
    await run(t);
    edge = (await t.run((ctx) => ctx.db.get(edgeId)))!;
    expect(edge.sharedTeardown).toMatchObject({ phase: 'remove_domain' });
    expect(steps).toEqual([{ phase: 'clone', workVersion: undefined }]);
  });

  test('out-of-rotation discovery RELEASES the shared-object lock once it has answered', async () => {
    mockFetch(() => jsonRes({ response: [] }));
    fakeSharedProvider();
    __setEdgeProviderForTests('cloudflare', {
      ...(edgeProviderFor('cloudflare') as object),
      testCredentials: async () => ({ ok: true }),
      discover: async () => ({ status: 'confirmed_absent' }),
      describe: async () => ({ state: 'active', addresses: {}, health: 'unknown' }),
      planDestroy: () => [],
      runDestroy: async () => ({ status: 'confirmed_gone' }),
    } as never);
    const { t, edgeId } = await sharedEdge();
    const zoneId = 'a'.repeat(32);
    // A cancelled run whose origin-rule write had an unknown outcome: the lock a
    // lost write left behind is expired and unsettled, and only the reconcile
    // discovery path will ever settle this edge again.
    await t.run((ctx) =>
      ctx.db.patch(edgeId, {
        status: 'cancelled',
        resources: [],
        steps: [
          {
            stepId: 'rule',
            kind: 'create_origin_rule',
            resourceName: 'adopted-node-one-rule',
            discoverability: 'by_name',
            state: 'unresolved',
            attempt: 1,
            startedAt: Date.now() - 600_000,
          },
        ],
        provisionIntent: JSON.stringify({
          hostname: 'front-a.example.org',
          zoneId,
          zoneName: 'example.org',
          originTransport: {
            scheme: 'https',
            certPublic: true,
            certNames: [],
            acceptsHostHeader: 'any',
          },
          originPort: 8443,
          templateHash: 'h',
          templateParams: {},
        }),
      }),
    );
    const key = `cloudflare-zone:${zoneId}`;
    await t.mutation(internal.edges.claimExternalLock, { key, edgeId, opId: 'lost', ttlMs: 1 });
    await t.run(async (ctx) => {
      const row = await ctx.db
        .query('externalLocks')
        .withIndex('by_key', (q) => q.eq('key', key))
        .unique();
      await ctx.db.patch(row!._id, { expiresAt: Date.now() - 1 });
    });
    await run(t);
    const edge = (await t.run((ctx) => ctx.db.get(edgeId)))!;
    expect(edge.steps[0]!.state).toBe('done');
    // The zone is free again for every later origin-rule write.
    const lock = await t.run((ctx) =>
      ctx.db
        .query('externalLocks')
        .withIndex('by_key', (q) => q.eq('key', key))
        .unique(),
    );
    expect(lock).toBeNull();
  });

  test('the operator "destroy" resolution restarts a parked workflow too', async () => {
    mockFetch(() => jsonRes({ response: [] }));
    fakeSharedProvider({ parkWith: 'clone_lost' });
    const { t, edgeId } = await sharedEdge();
    await run(t);
    await t.mutation(internal.edgeAdmin.resolveOperator, { edgeId, action: 'destroy' });
    const edge = (await t.run((ctx) => ctx.db.get(edgeId)))!;
    expect(edge.status).toBe('destroying');
    expect(edge.sharedTeardown).toBeUndefined();
    expect(edge.sharedTeardownState).toBeUndefined();
  });
});

describe('edgeReconcile: renewing a front qualification before it lapses', () => {
  afterEach(() => {
    __setEdgeProviderForTests('cloudflare', null);
    __setFrontChecker(null);
  });

  const HOSTNAME = 'a1b2c3d4e5f6.example.org';
  const QUALIFY_UUID = '99999999-9999-4999-8999-999999999999';

  /**
   * A published L7 front with a CURRENT proof that expires in `expiresInMs`.
   * Its health was just refreshed, so nothing but the proof clock can bring the
   * reconcile pass to it.
   */
  async function frontedRelay(expiresInMs: number[]) {
    const t = convexTest(schema, modules);
    await insertPanelServer(t);
    const { id: accountId } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'cloudflare',
      name: 'acct-cf',
      settings: { zoneId: 'a'.repeat(32), zoneName: 'example.org' },
      credentials: { apiToken: 'cf' },
    });
    const originTransport = {
      scheme: 'https' as const,
      certPublic: true,
      certNames: ['node-one.origin.example'],
      acceptsHostHeader: 'any' as const,
    };
    const { relayId, listenerId } = await registerRelay(t, {
      listeners: [
        wsListener({
          listenerKey: 'w',
          tlsNames: ['a.example'],
          originTransport,
          transportParams: { path: '/ws' },
          panelBinding: {
            inboundTag: 'VLESS_RELAY_W',
            configProfileUuid: FIXTURE_CONFIG_PROFILE,
            configProfileInboundUuid: INBOUND_U,
          },
        }),
      ],
    });
    await t.run((ctx) => ctx.db.patch(relayId, { qualificationUserId: QUALIFY_UUID }));
    const edgeIds = await t.run(async (ctx) => {
      const now = Date.now();
      const listener = (await ctx.db.get(listenerId))!;
      const ids: Id<'edges'>[] = [];
      for (const [i, ms] of expiresInMs.entries()) {
        const hostname = i === 0 ? HOSTNAME : `${i}${HOSTNAME}`;
        const intent = {
          hostname,
          zoneId: 'a'.repeat(32),
          zoneName: 'example.org',
          originTransport,
          originPort: 443,
          zoneSslMode: 'full',
          templateHash: 'h',
          templateParams: {},
        };
        const binding = qualificationBinding({
          listener,
          intent,
          params: listener.transportParams ?? {},
        });
        ids.push(
          await ctx.db.insert('edges', {
            relayId,
            listenerId,
            accountId,
            provider: 'cloudflare',
            managed: true,
            name: `fcp-node-one-${i}`,
            steps: [],
            resources: [],
            listeners: [{ edgePort: 443, originAddress: ORIGIN, originPort: 443 }],
            addresses: { hostname },
            layer: 'l7',
            provisionIntent: JSON.stringify(intent),
            frontQualification: {
              ok: true,
              checkedAt: now,
              expiresAt: now + ms,
              binding: {
                ...binding,
                listenerId: binding.listenerId as Id<'relayListeners'>,
              },
            },
            publication: 'published',
            poolIndex: i,
            status: 'active',
            statusChangedAt: now,
            health: 'unknown',
            lastHealthAt: now,
            destroyAttempts: 0,
            updatedAt: now,
          }),
        );
      }
      const relay = (await ctx.db.get(relayId))!;
      await ctx.db.patch(relayId, { publishedEdgeIds: ids, desiredPublished: ids.length });
      return { ids, epoch: relay.publicationEpoch };
    });
    return { t, relayId, edgeIds: edgeIds.ids };
  }

  /** The pool as the renderer sees it: `eligible:false` = the front is out. */
  async function renderable(t: ReturnType<typeof convexTest>, relayId: Id<'relays'>) {
    return await t.run(async (ctx) => {
      const origin = (await ctx.db.get(relayId))!;
      const { published } = await publishedEdgesOf(ctx, origin, { includeIneligible: true });
      return published.map((p) => ({ edgeId: p.edgeId, eligible: p.eligible !== false }));
    });
  }

  test('a proof about to expire is renewed this tick, so the front never drops out', async () => {
    mockFetch(() => jsonRes({ response: [] }));
    const checked: string[] = [];
    __setFrontChecker(async (args) => {
      checked.push(args.hostname);
      return { ok: true, steps: [], checkedAt: Date.now() };
    });
    // Ten minutes left on a 60-minute TTL: inside the renewal lead, and still
    // perfectly valid, so the edge is rendered before AND after the pass.
    const { t, relayId, edgeIds } = await frontedRelay([10 * 60_000]);
    expect(await renderable(t, relayId)).toEqual([{ edgeId: edgeIds[0], eligible: true }]);
    const before = (await t.run((ctx) => ctx.db.get(edgeIds[0])))!.frontQualification!.expiresAt;
    await run(t);
    expect(checked).toEqual([HOSTNAME]);
    const after = (await t.run((ctx) => ctx.db.get(edgeIds[0])))!.frontQualification!;
    expect(after.ok).toBe(true);
    expect(after.expiresAt).toBeGreaterThan(before);
    expect(await renderable(t, relayId)).toEqual([{ edgeId: edgeIds[0], eligible: true }]);
  });

  test('a proof with most of its life left is left alone', async () => {
    mockFetch(() => jsonRes({ response: [] }));
    const checked: string[] = [];
    __setFrontChecker(async (args) => {
      checked.push(args.hostname);
      return { ok: true, steps: [], checkedAt: Date.now() };
    });
    const { t } = await frontedRelay([50 * 60_000]);
    await run(t);
    expect(checked).toEqual([]);
  });

  test('the tick budget is config-driven and spends itself on the soonest expiry first', async () => {
    mockFetch(() => jsonRes({ response: [] }));
    const checked: string[] = [];
    __setFrontChecker(async (args) => {
      checked.push(args.hostname);
      return { ok: true, steps: [], checkedAt: Date.now() };
    });
    const { t } = await frontedRelay([9 * 60_000, 2 * 60_000, 5 * 60_000]);
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.l7.maxRequalifyPerTick', '2'));
    await run(t);
    // Two proofs this tick, the two closest to expiring, soonest first.
    expect(checked).toEqual([`1${HOSTNAME}`, `2${HOSTNAME}`]);
  });

  test('a re-proof that FAILS takes the front out at once', async () => {
    mockFetch(() => jsonRes({ response: [] }));
    __setFrontChecker(async () => ({
      ok: false,
      code: 'front_error',
      steps: [],
      checkedAt: Date.now(),
    }));
    const { t, relayId, edgeIds } = await frontedRelay([10 * 60_000]);
    await run(t);
    expect((await t.run((ctx) => ctx.db.get(edgeIds[0])))!.frontQualification!.ok).toBe(false);
    expect(await renderable(t, relayId)).toEqual([{ edgeId: edgeIds[0], eligible: false }]);
  });
});
