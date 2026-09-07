/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { jsonRes, mockFetch } from './lib/edges/testing/mockFetch';

const modules = import.meta.glob('./**/*.*s');

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

const ORIGIN = '203.0.113.10';
const OLD_EDGE = '198.51.100.1';
const NEW_EDGE = '198.51.100.50';
const HOST_UUID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const INBOUND = '22222222-2222-4222-8222-222222222222';

/**
 * A fake UpCloud + a fake panel behind one fetch stub. The panel keeps Host
 * state so PATCHes are observable and the next GET reflects them.
 */
function fakeWorld(
  opts: { hostPresent?: boolean; vanishAfterFirstPatch?: boolean; panelDown?: boolean } = {},
) {
  const panelHosts: Array<{
    uuid: string;
    remark: string;
    address: string;
    port: number;
    inbound: { configProfileUuid: string; configProfileInboundUuid: string };
  }> = [];
  if (opts.hostPresent !== false) {
    panelHosts.push({
      uuid: HOST_UUID,
      remark: 'node-one-relay-u',
      address: OLD_EDGE,
      port: 443,
      inbound: {
        configProfileUuid: '11111111-1111-4111-8111-111111111111',
        configProfileInboundUuid: INBOUND,
      },
    });
  }
  const lbs = new Map<string, { uuid: string; name: string; operational_state: string }>();
  let patches = 0;
  const stub = mockFetch((c) => {
    if (new URL(c.url).hostname === 'panel.example') {
      if (opts.panelDown) return jsonRes({ message: 'down' }, 503);
      if (c.path === '/api/hosts' && c.method === 'GET') return jsonRes({ response: panelHosts });
      if (c.path === '/api/hosts' && c.method === 'PATCH') {
        patches++;
        const body = c.body as { uuid: string; address: string; port: number };
        const h = panelHosts.find((x) => x.uuid === body.uuid);
        if (h) {
          h.address = body.address;
          h.port = body.port;
          if (opts.vanishAfterFirstPatch) panelHosts.splice(panelHosts.indexOf(h), 1);
        }
        return jsonRes({ response: h ?? null });
      }
      return jsonRes({ message: 'not found' }, 404);
    }
    // UpCloud
    if (c.path === '/1.3/load-balancer' && c.method === 'POST') {
      const uuid = `lb-${lbs.size + 1}`;
      lbs.set(uuid, {
        uuid,
        name: (c.body as { name: string }).name,
        operational_state: 'running',
      });
      return jsonRes(lbs.get(uuid));
    }
    if (c.path === '/1.3/ip_address' && c.method === 'POST')
      return jsonRes({ ip_address: { address: NEW_EDGE, floating: 'yes' } });
    const attach = c.path.match(/^\/1\.3\/load-balancer\/([^/]+)\/ip-addresses$/);
    if (attach && c.method === 'POST') return jsonRes({});
    const get = c.path.match(/^\/1\.3\/load-balancer\/([^/]+)$/);
    if (get && c.method === 'GET') {
      const lb = lbs.get(get[1]);
      return lb ? jsonRes(lb) : jsonRes({ error: { error_code: 'LB_NOT_FOUND' } }, 404);
    }
    throw new Error(`unexpected ${c.method} ${c.url}`);
  });
  return { stub, panelHosts, lbs, patches: () => patches };
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
  const { id: profileId } = await t.mutation(internal.protocolProfiles.create, {
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
    configProfileInboundUuid: INBOUND,
    originPort: 443,
  });
  // The hand-made edge FCP adopts (observe-only) and publishes at index 0.
  const { edgeId: oldEdgeId } = await t.mutation(internal.relays.adoptEdge, {
    relayId,
    slotId,
    ipv4: OLD_EDGE,
    publish: true,
  });
  return { t, accountId, profileId, relayId, slotId, oldEdgeId: oldEdgeId as Id<'edges'> };
}

/**
 * Drive the scheduler one step at a time until the rotation reaches a terminal
 * phase (plus one extra round for the follow-ups it schedules). A rotation is
 * one unbroken chain of runAfter(0) steps, so the all-at-once helper's pump
 * cap is not a fit here.
 */
async function drain(t: ReturnType<typeof convexTest>, rotationId: Id<'edgeRotations'>) {
  for (let i = 0; i < 400; i++) {
    await vi.runAllTimersAsync();
    await t.finishInProgressScheduledFunctions();
    const r = await t.query(internal.edgeRotations.get, { id: rotationId });
    if (r && ['done', 'failed', 'rolled_back', 'quarantined', 'cancelled'].includes(r.phase)) {
      await vi.runAllTimersAsync();
      await t.finishInProgressScheduledFunctions();
      return;
    }
  }
  throw new Error('drain: the rotation did not settle');
}

describe('relayRotations: replace', () => {
  test('full replace: provisions, verifies, publishes at index 0, flips the template Host, drains the old edge', async () => {
    vi.useFakeTimers();
    const world = fakeWorld();
    const { t, relayId, oldEdgeId, accountId } = await seed();
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: oldEdgeId,
    });
    const started = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(started.phase).toBe('select');
    const originBusy = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(originBusy.activeRotationId).toBe(rotationId);
    expect(originBusy.rotationsToday).toBe(1);
    // A second start is refused while one is running.
    await expect(
      t.mutation(internal.edgeRotations.start, {
        relayId,
        kind: 'replace',
        trigger: 'manual',
        targetEdgeId: oldEdgeId,
      }),
    ).rejects.toThrow(/already running/);

    await drain(t, rotationId);

    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(r.phase).toBe('done');
    expect(r.outcome).toBe('published');
    expect(r.hostPlan).toEqual([
      { uuid: HOST_UUID, oldAddress: OLD_EDGE, oldPort: 443, inboundUuid: INBOUND },
    ]);
    expect(r.previousBinding).toMatchObject({ edgeId: oldEdgeId, poolIndex: 0 });
    const codes = r.events.map((e) => e.code);
    expect(codes).toEqual(
      expect.arrayContaining([
        'started',
        'selected_provision',
        'provisioned',
        'verified',
        'published',
        'host_plan',
        'host_forward_written',
        'hosts_converged',
        'confirmed',
        'done',
      ]),
    );
    expect(codes).not.toContain('rolled_back');

    const origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.activeRotationId).toBeUndefined();
    expect(origin.publishedEdgeIds).toEqual([r.toEdgeId]);
    expect(origin.cooldownUntil).toBeGreaterThan(Date.now());
    expect(origin.lastRotatedAt).toBeDefined();

    const newEdge = (await t.query(internal.edges.get, { id: r.toEdgeId! }))!;
    expect(newEdge).toMatchObject({
      status: 'active',
      publication: 'published',
      poolIndex: 0,
      managed: true,
      provider: 'upcloud',
      health: 'online',
    });
    expect(newEdge.addresses.v4).toBe(NEW_EDGE);
    expect(newEdge.steps.map((s) => s.state)).toEqual(['done', 'done', 'done']);
    expect(newEdge.resources.map((x) => x.kind)).toEqual(['lb', 'floating_ip']);
    expect(newEdge.currentOp).toBeUndefined();
    expect(newEdge.name).toMatch(/^fcp-relay-node-one-[0-9a-f]{8}$/);
    // The provider saw the LB created under that exact name (discovery key).
    expect([...world.lbs.values()][0].name).toBe(newEdge.name);

    const oldEdge = (await t.query(internal.edges.get, { id: oldEdgeId }))!;
    expect(oldEdge).toMatchObject({ status: 'draining', publication: 'draining' });
    expect(oldEdge.poolIndex).toBeUndefined();
    expect(oldEdge.drainUntil).toBeGreaterThan(Date.now());
    expect(oldEdge.burnedAt).toBeUndefined();

    // Panel: exactly one PATCH, Host now points at the new edge (never at the origin).
    expect(world.patches()).toBe(1);
    expect(world.panelHosts[0]).toMatchObject({ address: NEW_EDGE, port: 443 });
    expect(world.panelHosts[0].address).not.toBe(ORIGIN);
    // The slot remembers its template Host uuid.
    const slot = (await t.query(internal.relaySlots.listByRelay, { relayId }))[0];
    expect(slot.templateHostUuid).toBe(HOST_UUID);
    // Budget consumed exactly once.
    const acct = (await t.run((ctx) => ctx.db.get(accountId)))!;
    expect(acct.allocationsToday).toBe(1);
    // Audits: rotated with ids/providers only, never addresses.
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    const rotated = audit.find((a) => a.action === 'edge.rotated');
    expect(rotated?.payload).toMatchObject({
      relaySlug: 'node-one',
      kind: 'replace',
      toProvider: 'upcloud',
      poolIndex: 0,
      hostsFlipped: 1,
    });
    expect(JSON.stringify(audit)).not.toContain(NEW_EDGE);
    expect(JSON.stringify(audit)).not.toContain(OLD_EDGE);
    // Admin progress view.
    const admin = (await t.query(internal.edgeRotations.getForAdmin, { id: rotationId }))!;
    expect(admin.progress).toEqual({ done: 3, total: 3, percent: 100 });
    expect(admin.terminal).toBe(true);
    // The rotation's own audit trail: the request, publish/unpublish and the outcome, oldest
    // first, every row tagged with this rotation's id, addresses absent.
    const trail = admin.audit.map((a) => a.action);
    expect(trail[0]).toBe('admin.edge.rotate');
    for (const a of ['edge.published', 'edge.unpublished', 'edge.rotated'])
      expect(trail).toContain(a);
    expect(trail.indexOf('edge.rotated')).toBeGreaterThan(trail.indexOf('edge.published'));
    for (const row of admin.audit)
      expect((row.payload as { rotationId?: string }).rotationId ?? rotationId).toBe(rotationId);
    expect(JSON.stringify(admin.audit)).not.toContain(NEW_EDGE);
  });

  test('burn: the old edge is marked burned with the shorter drain', async () => {
    vi.useFakeTimers();
    fakeWorld();
    const { t, relayId, oldEdgeId } = await seed();
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: oldEdgeId,
      burn: true,
    });
    await drain(t, rotationId);
    expect((await t.query(internal.edgeRotations.get, { id: rotationId }))!.phase).toBe('done');
    const oldEdge = (await t.query(internal.edges.get, { id: oldEdgeId }))!;
    expect(oldEdge.burnedAt).toBeDefined();
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.some((a) => a.action === 'edge.burned')).toBe(true);
    expect(audit.some((a) => a.action === 'admin.edge.burn')).toBe(true);
  });

  test('hosts_changed during the flip rolls back the complete binding; the new edge stays as a standby', async () => {
    vi.useFakeTimers();
    const world = fakeWorld({ vanishAfterFirstPatch: true });
    const { t, relayId, oldEdgeId } = await seed();
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: oldEdgeId,
    });
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    // The Host vanished after our write: the plan is missing → hosts_changed → rollback.
    // With the Host gone, the rollback itself cannot re-observe it → quarantine.
    expect(r.phase).toBe('quarantined');
    expect(r.outcome).toBe('hosts_changed');
    const origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.quarantine).toMatchObject({ rotationId });
    expect(origin.activeRotationId).toBeUndefined();
    // The DB half of the rollback happened before the quarantine: the old edge is published again.
    expect(origin.publishedEdgeIds).toEqual([oldEdgeId]);
    const oldEdge = (await t.query(internal.edges.get, { id: oldEdgeId }))!;
    expect(oldEdge).toMatchObject({ status: 'active', publication: 'published', poolIndex: 0 });
    const newEdge = (await t.query(internal.edges.get, { id: r.toEdgeId! }))!;
    expect(newEdge).toMatchObject({ status: 'quarantined', publication: 'unpublished' });
    expect(world.patches()).toBe(1);
    // Nothing bypasses the quarantine.
    await expect(
      t.mutation(internal.edgeRotations.start, {
        relayId,
        kind: 'replace',
        trigger: 'manual',
        targetEdgeId: oldEdgeId,
        force: true,
      }),
    ).rejects.toThrow(/quarantined/);
    await expect(t.mutation(internal.relays.requestDelete, { id: relayId })).rejects.toThrow(
      /quarantine/,
    );
    // Operator resolves keeping the previous binding.
    await t.mutation(internal.edgeRotations.resolveQuarantine, { relayId, keep: 'previous' });
    const after = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(after.quarantine).toBeUndefined();
    expect(after.publishedEdgeIds).toEqual([oldEdgeId]);
    expect((await t.query(internal.edges.get, { id: r.toEdgeId! }))!.status).toBe('active');
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.map((a) => a.action)).toEqual(
      expect.arrayContaining(['edge.quarantined', 'edge.quarantine_resolved']),
    );
  });

  test('panel down during the flip: attempts are capped, then a rollback restores the binding without Host writes', async () => {
    vi.useFakeTimers();
    const world = fakeWorld({ panelDown: true });
    const { t, relayId, oldEdgeId } = await seed();
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: oldEdgeId,
    });
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(r.phase).toBe('rolled_back');
    expect(r.outcome).toBe('panel_unreachable');
    expect(world.patches()).toBe(0);
    const origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.publishedEdgeIds).toEqual([oldEdgeId]);
    expect(origin.quarantine).toBeUndefined();
    expect(origin.activeRotationId).toBeUndefined();
    const newEdge = (await t.query(internal.edges.get, { id: r.toEdgeId! }))!;
    expect(newEdge).toMatchObject({ status: 'active', publication: 'unpublished' });
    expect(origin.standbyEdgeIds).toEqual([newEdge._id]);
  });

  test('no template Host on the panel: publish proceeds without a flip (bootstrap)', async () => {
    vi.useFakeTimers();
    const world = fakeWorld({ hostPresent: false });
    const { t, relayId, oldEdgeId } = await seed();
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: oldEdgeId,
    });
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(r.phase).toBe('done');
    expect(r.hostPlan).toEqual([]);
    expect(world.patches()).toBe(0);
  });

  test('start guards: hostManaged=false at index 0, cooldown, daily cap (force bypasses the last two only)', async () => {
    fakeWorld();
    const { t, relayId, oldEdgeId } = await seed();
    await t.mutation(internal.relays.update, { id: relayId, hostManaged: false });
    await expect(
      t.mutation(internal.edgeRotations.start, {
        relayId,
        kind: 'replace',
        trigger: 'manual',
        targetEdgeId: oldEdgeId,
      }),
    ).rejects.toThrow(/template Host/);
    await t.mutation(internal.relays.update, { id: relayId, hostManaged: true });
    await t.run((ctx) => ctx.db.patch(relayId, { cooldownUntil: Date.now() + 60_000 }));
    await expect(
      t.mutation(internal.edgeRotations.start, {
        relayId,
        kind: 'replace',
        trigger: 'manual',
        targetEdgeId: oldEdgeId,
      }),
    ).rejects.toThrow(/cooling down/);
    await t.run((ctx) =>
      ctx.db.patch(relayId, {
        cooldownUntil: undefined,
        rotationsDayKey: new Date().toISOString().slice(0, 10),
        rotationsToday: 99,
      }),
    );
    await expect(
      t.mutation(internal.edgeRotations.start, {
        relayId,
        kind: 'replace',
        trigger: 'manual',
        targetEdgeId: oldEdgeId,
      }),
    ).rejects.toThrow(/Daily rotation cap/);
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: oldEdgeId,
      force: true,
    });
    expect(rotationId).toBeDefined();
    // Detector-triggered starts need the global + per-origin opt-in.
    await t.mutation(internal.edgeRotations.requestCancel, { rotationId });
    await expect(
      t.mutation(internal.edgeRotations.start, {
        relayId,
        kind: 'replace',
        trigger: 'detector',
        targetEdgeId: oldEdgeId,
      }),
    ).rejects.toThrow(/already running|Automatic rotation/);
  });

  test('cancel during provisioning stops the run and marks the new edge cancelled', async () => {
    vi.useFakeTimers();
    fakeWorld();
    const { t, relayId, oldEdgeId } = await seed();
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: oldEdgeId,
    });
    // Run just the first scheduled step (select → commitSelection).
    await t.finishInProgressScheduledFunctions();
    await vi.advanceTimersByTimeAsync(1);
    await t.finishInProgressScheduledFunctions();
    const mid = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(['provisioning', 'select']).toContain(mid.phase);
    await t.mutation(internal.edgeRotations.requestCancel, { rotationId });
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(r.phase).toBe('cancelled');
    const origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.activeRotationId).toBeUndefined();
    expect(origin.publishedEdgeIds).toEqual([oldEdgeId]);
    if (r.toEdgeId) {
      const e = (await t.query(internal.edges.get, { id: r.toEdgeId }))!;
      expect(e.status).toBe('cancelled');
    }
  });
});

describe('relayRotations: provision + publish kinds', () => {
  test('provision with publishOnDone fills the next free pool index (index 1: no Host flip)', async () => {
    vi.useFakeTimers();
    const world = fakeWorld();
    const { t, relayId } = await seed();
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'provision',
      trigger: 'manual',
      publishOnDone: true,
    });
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(r.phase).toBe('done');
    expect(r.outcome).toBe('published');
    const origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.publishedEdgeIds).toHaveLength(2);
    expect(origin.publishedEdgeIds[1]).toBe(r.toEdgeId);
    expect(origin.cooldownUntil).toBeUndefined(); // not a rotation
    expect(world.patches()).toBe(0);
  });

  test('provision without publish leaves a standby; a later replace uses it instead of allocating', async () => {
    vi.useFakeTimers();
    const world = fakeWorld();
    const { t, relayId, oldEdgeId, accountId } = await seed();
    const first = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'provision',
      trigger: 'manual',
      publishOnDone: false,
    });
    await drain(t, first.rotationId);
    const r1 = (await t.query(internal.edgeRotations.get, { id: first.rotationId }))!;
    expect(r1.phase).toBe('done');
    expect(r1.outcome).toBe('standby');
    let origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.standbyEdgeIds).toEqual([r1.toEdgeId]);
    expect(origin.publishedEdgeIds).toEqual([oldEdgeId]);

    const second = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: oldEdgeId,
    });
    await drain(t, second.rotationId);
    const r2 = (await t.query(internal.edgeRotations.get, { id: second.rotationId }))!;
    expect(r2.phase).toBe('done');
    expect(r2.toEdgeId).toBe(r1.toEdgeId);
    expect(r2.events.map((e) => e.code)).toContain('selected_standby');
    origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.publishedEdgeIds).toEqual([r1.toEdgeId]);
    expect(origin.standbyEdgeIds).toEqual([]);
    // Only the first run allocated.
    expect((await t.run((ctx) => ctx.db.get(accountId)))!.allocationsToday).toBe(1);
    expect(world.lbs.size).toBe(1);
    expect(world.patches()).toBe(1);
  });

  test('selection fails cleanly when no qualified account exists for the slot provider', async () => {
    vi.useFakeTimers();
    fakeWorld();
    const { t, relayId, accountId } = await seed();
    await t.mutation(internal.edgeProviderAccounts.setQualified, {
      id: accountId,
      qualified: false,
    });
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'provision',
      trigger: 'manual',
      publishOnDone: true,
    });
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(r.phase).toBe('failed');
    expect(r.outcome).toBe('no_qualified_account');
    expect(r.toEdgeId).toBeUndefined();
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.find((a) => a.action === 'edge.rotation_failed')?.payload).toMatchObject({
      relaySlug: 'node-one',
      code: 'no_qualified_account',
    });
  });
});
