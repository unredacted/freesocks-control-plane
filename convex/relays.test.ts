/// <reference types="vite/client" />
/**
 * Relays under the generic-relay model: by-slug registration (idempotent,
 * ownership-aware, boundary-confined), origin kinds and the derived hostMode,
 * the delivery binding, edge adoption + the published-pool bookkeeping, the
 * publish gates (checkPublishable codes) and the per-listener template edge
 * that turns a direct publish into "needs a rotation".
 */
import { convexTest, type TestConvex } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import {
  FIXTURE_CONFIG_PROFILE,
  FIXTURE_NODE,
  FIXTURE_ORIGIN,
  FIXTURE_PANEL_SLUG,
  FIXTURE_RELAY_SLUG,
  adoptL4Edge,
  verifyL4Edge,
  createAccount,
  insertPanelServer,
  realityListener,
  registerRelay,
  seedEdgeFixture,
  shadowsocksListener,
  wsListener,
  type ListenerSpecFixture,
} from './lib/edges/testing/fixtures';

const modules = import.meta.glob('./**/*.*s');

async function seed() {
  const t = convexTest(schema, modules);
  return seedEdgeFixture(t);
}

type T = TestConvex<typeof schema>;

const mirrorRefreshes = (t: T) =>
  t.run(async (ctx) => {
    const rows = await ctx.db.system.query('_scheduled_functions').collect();
    return rows.filter((r) => r.name === 'storage:refreshActiveMirrors').length;
  });

const epochOf = async (t: T, relayId: Id<'relays'>) =>
  (await t.query(internal.relays.get, { id: relayId }))!.publicationEpoch;

const listenerRow = (t: T, id: Id<'relayListeners'>) => t.run((ctx) => ctx.db.get(id));

const audits = (t: T, action: string) =>
  t.run(async (ctx) =>
    (await ctx.db.query('auditLog').collect()).filter((a) => a.action === action),
  );

/** A rotation row in a non-terminal phase, pinned as the relay's active rotation. */
async function startFakeRotation(t: T, relayId: Id<'relays'>) {
  const rotationId = await t.run((ctx) =>
    ctx.db.insert('edgeRotations', {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      burn: false,
      force: false,
      phase: 'host_flipping',
      stepVersion: 1,
      cancelRequested: false,
      hostPlan: [],
      flipAttempts: 0,
      rollbackAttempts: 0,
      pollAttempts: 0,
      events: [],
      startedAt: Date.now(),
      updatedAt: Date.now(),
    }),
  );
  await t.run((ctx) => ctx.db.patch(relayId, { activeRotationId: rotationId }));
  return rotationId;
}

describe('relays: registration by slug', () => {
  test('an XHTTP listener registers with its mode (the wire validator accepts `transportParams.mode`)', async () => {
    const { t, relayId } = await seed();
    const r = await t.mutation(internal.relays.registerBySlug, {
      slug: FIXTURE_RELAY_SLUG,
      origin: { kind: 'panel-node', backendSlug: FIXTURE_PANEL_SLUG, nodeName: FIXTURE_NODE },
      originAddress: FIXTURE_ORIGIN,
      listeners: [
        realityListener(),
        {
          listenerKey: 'xh',
          protocol: 'vless',
          streamTransport: 'xhttp',
          security: 'tls',
          originPort: 443,
          tlsNames: ['x.example'],
          transportParams: { path: '/xh', mode: 'packet-up' },
        },
      ] as never,
    });
    expect(r.listeners.created).toEqual(['xh']);
    const rows = await t.run((ctx) =>
      ctx.db
        .query('relayListeners')
        .filter((q) => q.eq(q.field('relayId'), relayId))
        .collect(),
    );
    expect(rows.find((l) => l.listenerKey === 'xh')?.transportParams).toEqual({
      path: '/xh',
      mode: 'packet-up',
    });
    // An unknown mode is a validation refusal, not a stored value.
    await expect(
      t.mutation(internal.relays.registerBySlug, {
        slug: FIXTURE_RELAY_SLUG,
        origin: { kind: 'panel-node', backendSlug: FIXTURE_PANEL_SLUG, nodeName: FIXTURE_NODE },
        originAddress: FIXTURE_ORIGIN,
        listeners: [
          realityListener(),
          {
            listenerKey: 'xh',
            protocol: 'vless',
            streamTransport: 'xhttp',
            security: 'tls',
            originPort: 443,
            tlsNames: ['x.example'],
            transportParams: { path: '/xh', mode: 'warp-speed' },
          },
        ] as never,
      }),
    ).rejects.toThrow(/unknown xhttp mode/);
  });

  test('an identical body is idempotent: no listener revision bump, no epoch bump, no mirror refresh, only lastRegisteredAt moves', async () => {
    const { t, relayId, listenerId, serverId } = await seed();
    const row0 = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(row0).toMatchObject({
      backendServerId: serverId,
      nodeName: FIXTURE_NODE,
      hostMode: 'fcp',
      delivery: 'edge-required',
      autoRotate: false,
      enabled: true,
    });
    expect(row0.origin).toEqual({
      kind: 'panel-node',
      backendServerId: serverId,
      nodeName: FIXTURE_NODE,
    });
    const l0 = (await listenerRow(t, listenerId))!;
    expect(l0.revision).toBe(1);
    expect(l0.source).toBe('role');
    const e0 = row0.publicationEpoch;
    const m0 = await mirrorRefreshes(t);
    await t.run((ctx) => ctx.db.patch(relayId, { lastRegisteredAt: 1 }));
    // Same body, names in ANOTHER order: still identical (set semantics).
    const again = await registerRelay(t, {
      listeners: [realityListener({ tlsNames: ['b.example', 'a.example'] })],
    });
    expect(again).toMatchObject({ relayId, created: false, changed: false });
    const r = await t.mutation(internal.relays.registerBySlug, {
      slug: FIXTURE_RELAY_SLUG,
      origin: { kind: 'panel-node', backendSlug: FIXTURE_PANEL_SLUG, nodeName: FIXTURE_NODE },
      originAddress: FIXTURE_ORIGIN,
      listeners: [realityListener()] as never,
    });
    expect(r).toMatchObject({
      id: relayId,
      created: false,
      changed: false,
      listeners: {
        created: [],
        updated: [],
        unchanged: ['a'],
        retired: [],
        owned: [],
        blockedNames: [],
        changed: false,
      },
      adopted: null,
    });
    const l1 = (await listenerRow(t, listenerId))!;
    expect(l1.revision).toBe(1);
    // Persisted name order is the ORIGINAL body's, never re-sorted.
    expect(l1.tlsNames?.map((n) => n.name)).toEqual(['a.example', 'b.example']);
    const row1 = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(row1.publicationEpoch).toBe(e0);
    expect(row1.lastRegisteredAt).toBeGreaterThan(1);
    expect(row1.updatedAt).toBe(row0.updatedAt);
    expect(await mirrorRefreshes(t)).toBe(m0);
    // The audit says what happened, never the address.
    const regs = await audits(t, 'relay.registered');
    expect(regs[regs.length - 1].payload).toEqual({
      slug: FIXTURE_RELAY_SLUG,
      created: false,
      changed: false,
      listenersCreated: 0,
      listenersUpdated: 0,
      listenersRetired: 0,
    });
    expect(JSON.stringify(regs)).not.toContain('203.0.113');
    // An unknown backend slug is a validation error.
    await expect(
      registerRelay(t, { slug: 'node-two', backendSlug: 'missing', nodeName: 'node-two' }),
    ).rejects.toThrow(/unknown backend slug/);
  });

  test('a material change bumps the listener revision AND the epoch once, and refreshes the mirrors', async () => {
    const { t, relayId, listenerId } = await seed();
    const e0 = await epochOf(t, relayId);
    const m0 = await mirrorRefreshes(t);
    const r = await t.mutation(internal.relays.registerBySlug, {
      slug: FIXTURE_RELAY_SLUG,
      origin: { kind: 'panel-node', backendSlug: FIXTURE_PANEL_SLUG, nodeName: FIXTURE_NODE },
      originAddress: FIXTURE_ORIGIN,
      locationCode: 'XX1',
      listeners: [
        realityListener({ tlsNames: ['a.example', 'c.example'] }),
        shadowsocksListener(),
      ] as never,
    });
    expect(r.changed).toBe(true);
    expect(r.listeners).toMatchObject({ created: ['s'], updated: ['a'], changed: true });
    const l = (await listenerRow(t, listenerId))!;
    expect(l.revision).toBe(2);
    // `b.example` left the body: retired by the role with a drain; `c.example` appended.
    const byName = Object.fromEntries((l.tlsNames ?? []).map((n) => [n.name, n]));
    expect(byName['a.example'].status).toBe('active');
    expect(byName['b.example']).toMatchObject({ status: 'retired', retiredBy: 'role' });
    expect(byName['b.example'].drainUntil).toBeGreaterThan(Date.now());
    expect(byName['c.example'].status).toBe('active');
    expect(l.tlsNames?.map((n) => n.name)).toEqual(['a.example', 'b.example', 'c.example']);
    expect(await epochOf(t, relayId)).toBe(e0 + 1);
    expect(await mirrorRefreshes(t)).toBe(m0 + 1);
    expect((await t.query(internal.relays.get, { id: relayId }))!.locationCode).toBe('XX1');
    // The drain elapsing bumps the epoch again (retired names stop rendering).
    const scheduled = await t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect());
    expect(scheduled.some((s) => s.name === 'relayListeners:onNameDrainElapsed')).toBe(true);
  });

  test('a role body never reactivates an admin-retired name (blockedNames) but does reactivate its own', async () => {
    const { t, relayId, listenerId } = await seed();
    await t.mutation(internal.relayListeners.retireName, { id: listenerId, names: ['a.example'] });
    const e1 = await epochOf(t, relayId);
    // The role re-sends the full name list, including the burned name.
    const r = await registerRelay(t);
    expect(r.changed).toBe(false);
    const full = await t.mutation(internal.relays.registerBySlug, {
      slug: FIXTURE_RELAY_SLUG,
      origin: { kind: 'panel-node', backendSlug: FIXTURE_PANEL_SLUG, nodeName: FIXTURE_NODE },
      originAddress: FIXTURE_ORIGIN,
      listeners: [realityListener()] as never,
    });
    // Judged on what the body would change (nothing), yet the role is told, every
    // time, which name it wanted that an admin keeps retired.
    expect(full.listeners.blockedNames).toEqual(['a.example']);
    expect(full.changed).toBe(false);
    const l = (await listenerRow(t, listenerId))!;
    expect(l.tlsNames?.find((n) => n.name === 'a.example')).toMatchObject({
      status: 'retired',
      retiredBy: 'admin',
    });
    expect(await epochOf(t, relayId)).toBe(e1);
    // A changed body (a new name) re-merges: the admin-retired name stays retired and is reported.
    const changed = await t.mutation(internal.relays.registerBySlug, {
      slug: FIXTURE_RELAY_SLUG,
      origin: { kind: 'panel-node', backendSlug: FIXTURE_PANEL_SLUG, nodeName: FIXTURE_NODE },
      originAddress: FIXTURE_ORIGIN,
      listeners: [realityListener({ tlsNames: ['a.example', 'b.example', 'c.example'] })] as never,
    });
    expect(changed.listeners.blockedNames).toEqual(['a.example']);
    const l2 = (await listenerRow(t, listenerId))!;
    expect(l2.tlsNames?.find((n) => n.name === 'a.example')?.status).toBe('retired');
    expect(l2.tlsNames?.find((n) => n.name === 'c.example')?.status).toBe('active');
    // The role retires + reactivates its OWN names freely.
    await t.mutation(internal.relays.registerBySlug, {
      slug: FIXTURE_RELAY_SLUG,
      origin: { kind: 'panel-node', backendSlug: FIXTURE_PANEL_SLUG, nodeName: FIXTURE_NODE },
      originAddress: FIXTURE_ORIGIN,
      listeners: [realityListener({ tlsNames: ['b.example'] })] as never,
    });
    expect(
      (await listenerRow(t, listenerId))!.tlsNames?.find((n) => n.name === 'c.example'),
    ).toMatchObject({ status: 'retired', retiredBy: 'role' });
    const back = await t.mutation(internal.relays.registerBySlug, {
      slug: FIXTURE_RELAY_SLUG,
      origin: { kind: 'panel-node', backendSlug: FIXTURE_PANEL_SLUG, nodeName: FIXTURE_NODE },
      originAddress: FIXTURE_ORIGIN,
      listeners: [realityListener({ tlsNames: ['b.example', 'c.example'] })] as never,
    });
    expect(back.listeners.blockedNames).toEqual([]);
    expect(
      (await listenerRow(t, listenerId))!.tlsNames?.find((n) => n.name === 'c.example')?.status,
    ).toBe('active');
    // An admin reactivates the burned name explicitly.
    expect(
      await t.mutation(internal.relayListeners.reactivateName, {
        id: listenerId,
        names: ['a.example'],
      }),
    ).toEqual({ ok: true, reactivated: 1 });
  });

  test('prune touches only the caller’s own source; another source’s key is edge.listener_key_owned', async () => {
    const { t, relayId } = await seed();
    const admin = await t.mutation(internal.relayListeners.upsert, {
      relayId,
      spec: shadowsocksListener({ listenerKey: 'x' }) as never,
    });
    expect(admin).toMatchObject({
      created: true,
      changed: true,
      templateHostRemark: 'node-one-relay-x',
    });
    // The role's body omits `x`: the admin listener survives.
    const r1 = await registerRelay(t);
    expect(r1.changed).toBe(false);
    expect((await listenerRow(t, admin.id))!.retired).toBe(false);
    // The role's body omits its OWN `a`: pruned (retired, undeployed, revision bumped).
    const r2 = await t.mutation(internal.relays.registerBySlug, {
      slug: FIXTURE_RELAY_SLUG,
      origin: { kind: 'panel-node', backendSlug: FIXTURE_PANEL_SLUG, nodeName: FIXTURE_NODE },
      originAddress: FIXTURE_ORIGIN,
      listeners: [wsListener()] as never,
    });
    expect(r2.listeners).toMatchObject({ created: ['w'], retired: ['a'], changed: true });
    const a = (await t.run((ctx) =>
      ctx.db
        .query('relayListeners')
        .withIndex('by_relay_key', (q) => q.eq('relayId', relayId).eq('listenerKey', 'a'))
        .unique(),
    ))!;
    expect(a).toMatchObject({ retired: true, deployed: false, revision: 2 });
    // pruneListeners:false keeps everything.
    const r3 = await t.mutation(internal.relays.registerBySlug, {
      slug: FIXTURE_RELAY_SLUG,
      origin: { kind: 'panel-node', backendSlug: FIXTURE_PANEL_SLUG, nodeName: FIXTURE_NODE },
      originAddress: FIXTURE_ORIGIN,
      listeners: [] as never,
      pruneListeners: false,
    });
    expect(r3.changed).toBe(false);
    // The role naming the admin's key is refused (nothing applied).
    await expect(
      t.mutation(internal.relays.registerBySlug, {
        slug: FIXTURE_RELAY_SLUG,
        origin: { kind: 'panel-node', backendSlug: FIXTURE_PANEL_SLUG, nodeName: FIXTURE_NODE },
        originAddress: FIXTURE_ORIGIN,
        listeners: [
          wsListener(),
          shadowsocksListener({ listenerKey: 'x', originPort: 9999 }),
        ] as never,
      }),
    ).rejects.toThrow(/listener_key_owned/);
    expect((await listenerRow(t, admin.id))!.originPort).toBe(8388);
    // An admin body prunes admin listeners only: `w` (role) survives an empty admin body.
    const r4 = await t.mutation(internal.relays.registerBySlug, {
      slug: FIXTURE_RELAY_SLUG,
      origin: { kind: 'panel-node', backendSlug: FIXTURE_PANEL_SLUG, nodeName: FIXTURE_NODE },
      originAddress: FIXTURE_ORIGIN,
      listeners: [] as never,
      source: 'admin',
    });
    expect(r4.listeners.retired).toEqual(['x']);
    const w = await t.run((ctx) =>
      ctx.db
        .query('relayListeners')
        .withIndex('by_relay_key', (q) => q.eq('relayId', relayId).eq('listenerKey', 'w'))
        .unique(),
    );
    expect(w?.retired).toBe(false);
    // A retired key re-stated by its owner comes back as an UPDATE (revision bumps).
    const r5 = await registerRelay(t, { listeners: [wsListener(), realityListener()] });
    expect(r5.changed).toBe(true);
    const aBack = (await t.run((ctx) => ctx.db.get(a._id)))!;
    expect(aBack).toMatchObject({ retired: false, deployed: true, revision: 3 });
  });

  test('edge.listener_in_use: ANY non-destroyed edge (a standby included) blocks a rebind, a prune and a retire', async () => {
    const { t, relayId, listenerId } = await seed();
    // An unpublished adopted edge = a standby.
    const { edgeId } = await adoptL4Edge(t, relayId, listenerId, { publish: false });
    const body = (l: ListenerSpecFixture[]) =>
      t.mutation(internal.relays.registerBySlug, {
        slug: FIXTURE_RELAY_SLUG,
        origin: { kind: 'panel-node', backendSlug: FIXTURE_PANEL_SLUG, nodeName: FIXTURE_NODE },
        originAddress: FIXTURE_ORIGIN,
        listeners: l as never,
      });
    for (const change of [
      { originPort: 8443 },
      {
        panelBinding: {
          inboundTag: 'VLESS_RELAY_A',
          configProfileUuid: FIXTURE_CONFIG_PROFILE,
          configProfileInboundUuid: '55555555-5555-4555-8555-555555555555',
        },
      },
      { security: 'tls' as const, realityTarget: undefined },
    ]) {
      await expect(body([realityListener(change)])).rejects.toThrow(/listener_in_use/);
    }
    await expect(body([])).rejects.toThrow(/listener_in_use/);
    await expect(
      t.mutation(internal.relayListeners.retire, { relayId, listenerKey: 'a' }),
    ).rejects.toThrow(/listener_in_use/);
    // A name-only change is not a rebind: the edge keeps its listener.
    const r = await body([realityListener({ tlsNames: ['a.example', 'b.example', 'c.example'] })]);
    expect(r.listeners.updated).toEqual(['a']);
    // Destroyed: the listener is free again.
    await t.mutation(internal.edges.patchEdge, { edgeId, status: 'destroyed' });
    await body([
      realityListener({ originPort: 8443, tlsNames: ['a.example', 'b.example', 'c.example'] }),
    ]);
    expect((await listenerRow(t, listenerId))!.originPort).toBe(8443);
    await t.mutation(internal.relayListeners.retire, { relayId, listenerKey: 'a' });
    expect((await listenerRow(t, listenerId))!.retired).toBe(true);
  });

  test('a re-bound inbound forgets the listener’s panel Host; the rule set must stay unambiguous', async () => {
    const { t, relayId, listenerId } = await seed();
    await t.run((ctx) =>
      ctx.db.patch(listenerId, { host: { state: 'present', uuid: 'h-1', ownership: 'fcp' } }),
    );
    await registerRelay(t, {
      listeners: [
        realityListener({
          panelBinding: {
            inboundTag: 'VLESS_RELAY_A',
            configProfileUuid: FIXTURE_CONFIG_PROFILE,
            configProfileInboundUuid: '55555555-5555-4555-8555-555555555555',
          },
        }),
      ],
    });
    expect((await listenerRow(t, listenerId))!.host).toEqual({ state: 'absent' });
    // Two address-matched listeners on one port cannot coexist.
    await expect(
      registerRelay(t, {
        listeners: [
          realityListener({ panelBinding: undefined }),
          shadowsocksListener({ panelBinding: undefined, originPort: 443 }),
        ],
      }),
    ).rejects.toThrow(/match_rule_overlap/);
    // A whole-body rule beside another listener is ambiguous too.
    await expect(
      registerRelay(t, {
        listeners: [realityListener({ matchRule: { kind: 'whole-body' } }), shadowsocksListener()],
      }),
    ).rejects.toThrow(/match_rule_overlap/);
    // Invalid combinations have their own code.
    await expect(
      registerRelay(t, {
        listeners: [realityListener({ protocol: 'shadowsocks' })],
      }),
    ).rejects.toThrow(/invalid_combination/);
  });

  test('refused on a deleting relay; origin kind is locked; re-parenting is locked while edges exist', async () => {
    const { t, relayId, listenerId } = await seed();
    await insertPanelServer(t, { slug: 'panel-b' });
    await adoptL4Edge(t, relayId, listenerId);
    await expect(registerRelay(t, { backendSlug: 'panel-b' })).rejects.toThrow(
      /relay_reparent_locked/,
    );
    await expect(registerRelay(t, { kind: 'backend-server' })).rejects.toThrow(
      /origin_kind_locked/,
    );
    await t.mutation(internal.relays.requestDelete, { id: relayId, disposition: 'keep-dark' });
    await expect(registerRelay(t)).rejects.toThrow(/being deleted/);
  });

  test('re-parenting without edges moves the relay AND its delivery binding; the vacated node is claimable', async () => {
    const { t, relayId, serverId } = await seed();
    const before = await mirrorRefreshes(t);
    const r = await registerRelay(t, { nodeName: 'node-two' });
    expect(r).toMatchObject({ relayId, created: false, changed: true });
    // Unchanged listeners bump no epoch, yet the newly covered node's mirrors may
    // still hold its raw body: claiming the binding refreshes them at once.
    expect(await mirrorRefreshes(t)).toBeGreaterThan(before);
    const row = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(row.origin).toEqual({
      kind: 'panel-node',
      backendServerId: serverId,
      nodeName: 'node-two',
    });
    expect(row.nodeName).toBe('node-two');
    expect(
      await t.query(internal.relays.deliveryBinding, {
        backendServerId: serverId,
        nodeName: 'node-two',
      }),
    ).toMatchObject({ relaySlug: FIXTURE_RELAY_SLUG, state: 'active' });
    // The old node's binding row still exists (now pointing at this slug; the
    // relay's re-registration re-claimed it) but a new relay may take the node.
    const two = await registerRelay(t, {
      slug: 'node-one-again',
      nodeName: FIXTURE_NODE,
      originAddress: '203.0.113.11',
    });
    expect(two.created).toBe(true);
    expect(
      await t.query(internal.relays.deliveryBinding, {
        backendServerId: serverId,
        nodeName: FIXTURE_NODE,
      }),
    ).toMatchObject({ relaySlug: 'node-one-again', state: 'active' });
  });

  test('the qualification placement mode is settable by an operator: a known mode slug is stored, an unknown one refused, null clears it', async () => {
    const { t, relayId } = await seed();
    await t.mutation(internal.relays.update, {
      id: relayId,
      qualificationModeSlug: 'privacy-reality',
    });
    expect((await t.query(internal.relays.get, { id: relayId }))!.qualificationModeSlug).toBe(
      'privacy-reality',
    );
    await expect(
      t.mutation(internal.relays.update, { id: relayId, qualificationModeSlug: 'no-such-mode' }),
    ).rejects.toThrow(/names no connection mode/);
    await t.mutation(internal.relays.update, { id: relayId, qualificationModeSlug: null });
    expect(
      (await t.query(internal.relays.get, { id: relayId }))!.qualificationModeSlug,
    ).toBeUndefined();
  });

  test('one relay per place: node_already_bound / server_already_bound; a manual origin is unique by slug only', async () => {
    const { t } = await seed();
    await expect(
      registerRelay(t, { slug: 'node-one-b', originAddress: '203.0.113.20' }),
    ).rejects.toThrow(/node_already_bound/);
    await insertPanelServer(t, { slug: 'outline-a', backend: 'outline' });
    const whole = await registerRelay(t, {
      slug: 'whole-a',
      kind: 'backend-server',
      backendSlug: 'outline-a',
      originAddress: '203.0.113.30',
      listeners: [shadowsocksListener()],
    });
    expect(whole.created).toBe(true);
    await expect(
      registerRelay(t, {
        slug: 'whole-b',
        kind: 'backend-server',
        backendSlug: 'outline-a',
        originAddress: '203.0.113.31',
        listeners: [shadowsocksListener()],
      }),
    ).rejects.toThrow(/server_already_bound/);
    // A panel-node relay on a backend without nodes is refused.
    await expect(
      registerRelay(t, {
        slug: 'x',
        backendSlug: 'outline-a',
        nodeName: 'n',
        originAddress: '203.0.113.32',
      }),
    ).rejects.toThrow(/no nodes/);
    for (const slug of ['hand-a', 'hand-b']) {
      const m = await registerRelay(t, {
        slug,
        kind: 'manual',
        originAddress: `203.0.113.4${slug.endsWith('a') ? 0 : 1}`,
        listeners: [shadowsocksListener()],
      });
      expect(m.created).toBe(true);
    }
  });

  test('origin kinds derive hostMode: panel-node → fcp, backend-server / manual → none; operator only by request on a panel node', async () => {
    const { t, relayId } = await seed();
    expect((await t.query(internal.relays.get, { id: relayId }))!.hostMode).toBe('fcp');
    await insertPanelServer(t, { slug: 'outline-a', backend: 'outline' });
    const whole = await registerRelay(t, {
      slug: 'whole-a',
      kind: 'backend-server',
      backendSlug: 'outline-a',
      originAddress: '203.0.113.30',
      listeners: [shadowsocksListener()],
    });
    expect((await t.query(internal.relays.get, { id: whole.relayId }))!.hostMode).toBe('none');
    const manual = await registerRelay(t, {
      slug: 'hand-a',
      kind: 'manual',
      originAddress: '203.0.113.40',
      listeners: [shadowsocksListener()],
    });
    const mrow = (await t.query(internal.relays.get, { id: manual.relayId }))!;
    expect(mrow.hostMode).toBe('none');
    expect(mrow.backendServerId).toBeUndefined();
    expect(mrow.nodeName).toBeUndefined();
    // Operator-owned Hosts by request (legacy adoption), only where Hosts exist.
    const op = await registerRelay(t, {
      slug: 'legacy',
      nodeName: 'legacy',
      originAddress: '203.0.113.50',
      hostModeRequest: 'operator',
    });
    expect((await t.query(internal.relays.get, { id: op.relayId }))!.hostMode).toBe('operator');
    await expect(
      registerRelay(t, {
        slug: 'hand-b',
        kind: 'manual',
        originAddress: '203.0.113.41',
        listeners: [shadowsocksListener()],
        hostModeRequest: 'operator',
      }),
    ).rejects.toThrow(/host_mode_unsupported/);
    // Nor can an update grant a Host mode the origin cannot have.
    await expect(
      t.mutation(internal.relays.update, { id: manual.relayId, hostMode: 'fcp' }),
    ).rejects.toThrow(/host_mode_unsupported/);
    await expect(
      t.mutation(internal.relays.update, { id: relayId, hostMode: 'none' }),
    ).rejects.toThrow(/host_mode_unsupported/);
    // The admin projection carries the origin shape per kind.
    const list = await t.query(internal.relays.listForAdmin, {});
    expect(list.find((r) => r.slug === 'hand-a')?.origin).toEqual({ kind: 'manual' });
    expect(list.find((r) => r.slug === 'whole-a')?.origin).toMatchObject({
      kind: 'backend-server',
    });
    expect(list.find((r) => r.slug === FIXTURE_RELAY_SLUG)?.origin).toMatchObject({
      kind: 'panel-node',
      nodeName: FIXTURE_NODE,
      nodeUuid: null,
    });
  });

  test('hostMode handoff: fcp → operator adopts present Hosts; operator → fcp needs every remark listener’s Host present', async () => {
    const { t, relayId, listenerId } = await seed();
    await t.run((ctx) =>
      ctx.db.patch(listenerId, { host: { state: 'present', uuid: 'h-1', ownership: 'fcp' } }),
    );
    const e0 = await epochOf(t, relayId);
    await t.mutation(internal.relays.update, {
      id: relayId,
      hostMode: 'operator',
      autoRotate: true,
    });
    expect((await listenerRow(t, listenerId))!.host).toEqual({
      state: 'present',
      uuid: 'h-1',
      ownership: 'adopted',
    });
    // A hostMode change affects publication: epoch bump + audited flips (names + booleans, no values otherwise).
    expect(await epochOf(t, relayId)).toBe(e0 + 1);
    const upd = await audits(t, 'relay.update');
    expect(upd[upd.length - 1].payload).toEqual({
      slug: FIXTURE_RELAY_SLUG,
      changed: ['autoRotate', 'hostMode'],
      autoRotate: true,
      hostMode: 'operator',
    });
    // Back to fcp: fine while the Host is present ...
    await t.mutation(internal.relays.update, { id: relayId, hostMode: 'fcp' });
    expect((await t.query(internal.relays.get, { id: relayId }))!.hostMode).toBe('fcp');
    await t.mutation(internal.relays.update, { id: relayId, hostMode: 'operator' });
    // ... refused once a remark listener has no validated Host.
    await t.run((ctx) => ctx.db.patch(listenerId, { host: { state: 'absent' } }));
    await expect(
      t.mutation(internal.relays.update, { id: relayId, hostMode: 'fcp' }),
    ).rejects.toThrow(/host_adopt_required/);
    // And never while a rotation runs.
    await t.run((ctx) =>
      ctx.db.patch(listenerId, { host: { state: 'present', uuid: 'h-1', ownership: 'adopted' } }),
    );
    await startFakeRotation(t, relayId);
    await expect(
      t.mutation(internal.relays.update, { id: relayId, hostMode: 'fcp' }),
    ).rejects.toThrow(/rotation_running/);
  });

  test('a published edge address can never become an origin (edge.origin_is_edge)', async () => {
    const { t, relayId, listenerId } = await seed();
    await adoptL4Edge(t, relayId, listenerId, { ipv4: '198.51.100.7', publish: true });
    await expect(
      registerRelay(t, { slug: 'node-two', nodeName: 'node-two', originAddress: '198.51.100.7' }),
    ).rejects.toThrow(/origin_is_edge/);
    const two = await registerRelay(t, {
      slug: 'node-two',
      nodeName: 'node-two',
      originAddress: '203.0.113.11',
    });
    await expect(
      t.mutation(internal.relays.update, { id: two.relayId, originAddress: '198.51.100.7' }),
    ).rejects.toThrow(/origin_is_edge/);
    // Its own edge is not "another relay's edge" (the address check skips self).
    await t.run((ctx) => ctx.db.patch(relayId, { publishedEdgeIds: [] }));
  });

  test('a delivery binding is written on registration; delete needs a disposition; keep-dark survives, restore-direct releases', async () => {
    const { t, relayId, serverId } = await seed();
    const b = (await t.query(internal.relays.deliveryBinding, {
      backendServerId: serverId,
      nodeName: FIXTURE_NODE,
    }))!;
    expect(b).toMatchObject({
      backendServerId: serverId,
      nodeName: FIXTURE_NODE,
      policy: 'edge-required',
      policyVersion: 1,
      relaySlug: FIXTURE_RELAY_SLUG,
      state: 'active',
    });
    // Another node of the panel is not covered (no whole-server binding).
    expect(
      await t.query(internal.relays.deliveryBinding, {
        backendServerId: serverId,
        nodeName: 'other',
      }),
    ).toBeNull();
    // A whole-server relay covers every node of ITS server.
    await insertPanelServer(t, { slug: 'outline-a', backend: 'outline' });
    const whole = await registerRelay(t, {
      slug: 'whole-a',
      kind: 'backend-server',
      backendSlug: 'outline-a',
      originAddress: '203.0.113.30',
      listeners: [shadowsocksListener()],
    });
    const outlineId = (await t.query(internal.relays.get, { id: whole.relayId }))!.backendServerId!;
    const wholeBinding = (await t.query(internal.relays.deliveryBinding, {
      backendServerId: outlineId,
      nodeName: 'any',
    }))!;
    expect(wholeBinding).toMatchObject({ relaySlug: 'whole-a' });
    expect(wholeBinding.nodeName).toBeUndefined();
    // A manual origin writes no binding (it serves nothing FCP renders).
    await registerRelay(t, {
      slug: 'hand-a',
      kind: 'manual',
      originAddress: '203.0.113.40',
      listeners: [shadowsocksListener()],
    });
    expect(await t.run((ctx) => ctx.db.query('edgeDeliveryBindings').collect())).toHaveLength(2);

    // Deleting a covering relay must say what happens to its members.
    await expect(t.mutation(internal.relays.requestDelete, { id: relayId })).rejects.toThrow(
      /delivery_disposition_required/,
    );
    // Releasing the binding by hand is refused while the relay lives.
    await expect(t.mutation(internal.relays.releaseDeliveryBinding, { id: b._id })).rejects.toThrow(
      /still exists/,
    );
    // keep-dark: the binding stays active with the departed slug (members stay at 503).
    await t.mutation(internal.relays.requestDelete, { id: relayId, disposition: 'keep-dark' });
    expect(await t.run((ctx) => ctx.db.get(b._id))).toMatchObject({
      state: 'active',
      policyVersion: 1,
      relaySlug: FIXTURE_RELAY_SLUG,
    });
    const del = await audits(t, 'relay.delete');
    expect(del[0].payload).toEqual({
      slug: FIXTURE_RELAY_SLUG,
      force: false,
      disposition: 'keep-dark',
    });
    // The operator releases a dark binding once the relay is going.
    expect(await t.mutation(internal.relays.releaseDeliveryBinding, { id: b._id })).toEqual({
      ok: true,
    });
    expect(await t.run((ctx) => ctx.db.get(b._id))).toMatchObject({
      state: 'released',
      policyVersion: 2,
    });
    expect(
      await t.query(internal.relays.deliveryBinding, {
        backendServerId: serverId,
        nodeName: FIXTURE_NODE,
      }),
    ).toBeNull();
    expect((await audits(t, 'relay.delivery.released'))[0].payload).toEqual({
      relaySlug: FIXTURE_RELAY_SLUG,
    });
    // restore-direct releases it in the same call.
    await t.mutation(internal.relays.requestDelete, {
      id: whole.relayId,
      disposition: 'restore-direct',
    });
    expect(
      await t.query(internal.relays.deliveryBinding, {
        backendServerId: outlineId,
        nodeName: undefined,
      }),
    ).toBeNull();
    // A manual relay needs no disposition (it never bound anything).
    const hand = await t.query(internal.relays.getBySlug, { slug: 'hand-a' });
    expect(await t.mutation(internal.relays.requestDelete, { id: hand!._id })).toEqual({
      ok: true,
      deleted: false,
    });
    // A binding is re-claimed (version bumped) when a new relay registers the node.
    await t.mutation(internal.relays.finalizeDelete, { id: relayId });
    await registerRelay(t, { slug: 'node-one-v2' });
    expect(await t.run((ctx) => ctx.db.get(b._id))).toMatchObject({
      state: 'active',
      policyVersion: 3,
      relaySlug: 'node-one-v2',
    });
  });

  test('a register-scoped caller is confined to its boundary (assertWithinBoundary)', async () => {
    const { t, serverId } = await seed();
    const other = await insertPanelServer(t, { slug: 'panel-b' });
    const inside = { backendServerIds: [serverId] };
    const reg = (
      slug: string,
      backendSlug: string,
      boundary: { backendServerIds: Id<'backendServers'>[]; nodeNames?: string[] },
    ) =>
      t.mutation(internal.relays.registerBySlug, {
        slug,
        origin: { kind: 'panel-node', backendSlug, nodeName: slug },
        originAddress: '203.0.113.60',
        listeners: [realityListener()] as never,
        boundary,
      });
    await expect(reg('node-b', 'panel-b', inside)).rejects.toThrow(/registration_boundary/);
    await expect(
      reg('node-c', FIXTURE_PANEL_SLUG, { backendServerIds: [other], nodeNames: ['node-c'] }),
    ).rejects.toThrow(/registration_boundary/);
    await expect(
      reg('node-c', FIXTURE_PANEL_SLUG, { backendServerIds: [serverId], nodeNames: ['node-z'] }),
    ).rejects.toThrow(/registration_boundary/);
    // An EMPTY boundary registers nothing.
    await expect(reg('node-c', FIXTURE_PANEL_SLUG, { backendServerIds: [] })).rejects.toThrow(
      /registration_boundary/,
    );
    // A manual origin is never inside a boundary.
    await expect(
      t.mutation(internal.relays.registerBySlug, {
        slug: 'hand',
        origin: { kind: 'manual' },
        originAddress: '203.0.113.61',
        listeners: [shadowsocksListener({ panelBinding: undefined })] as never,
        boundary: inside,
      }),
    ).rejects.toThrow(/registration_boundary/);
    const ok = await reg('node-c', FIXTURE_PANEL_SLUG, {
      backendServerIds: [serverId],
      nodeNames: ['node-c'],
    });
    expect(ok.created).toBe(true);
    // The existing row is checked too: a body that would move it out of the boundary is refused,
    // and so is touching a relay that already sits outside it.
    await expect(
      t.mutation(internal.relays.registerBySlug, {
        slug: 'node-c',
        origin: { kind: 'panel-node', backendSlug: 'panel-b', nodeName: 'node-c' },
        originAddress: '203.0.113.60',
        listeners: [realityListener()] as never,
        boundary: { backendServerIds: [other] },
      }),
    ).rejects.toThrow(/registration_boundary/);
  });
});

describe('relays: operator knobs and epochs', () => {
  test('a publication-affecting update bumps the epoch AND schedules a mirror refresh; an unrelated one does neither', async () => {
    const { t, relayId } = await seed();
    const before = await epochOf(t, relayId);
    const scheduled0 = await mirrorRefreshes(t);
    await t.mutation(internal.relays.update, { id: relayId, cooldownMinutes: 45 });
    expect(await epochOf(t, relayId)).toBe(before);
    expect(await mirrorRefreshes(t)).toBe(scheduled0);
    await t.mutation(internal.relays.update, { id: relayId, enabled: false });
    expect(await epochOf(t, relayId)).toBe(before + 1);
    expect(await mirrorRefreshes(t)).toBe(scheduled0 + 1);
    // Knob validation.
    await expect(
      t.mutation(internal.relays.update, { id: relayId, desiredPublished: 9 }),
    ).rejects.toThrow(/desiredPublished/);
    await expect(t.mutation(internal.relays.update, { id: relayId, label: '' })).rejects.toThrow(
      /label/,
    );
  });

  test('a render.* config change bumps every enabled relay epoch (and only those)', async () => {
    const { t, relayId } = await seed();
    const { relayId: off } = await registerRelay(t, {
      slug: 'node-off',
      nodeName: 'node-off',
      originAddress: '203.0.113.99',
    });
    await t.mutation(internal.relays.update, { id: off, enabled: false });
    const before = await epochOf(t, relayId);
    const beforeOff = await epochOf(t, off);
    await t.mutation(internal.edgeAdmin.patchConfig, { patch: { pollSeconds: 30 } });
    expect(await epochOf(t, relayId)).toBe(before);
    const res = await t.mutation(internal.edgeAdmin.patchConfig, {
      patch: { render: { enabled: true, ipv6Mode: 'off' } },
    });
    expect(res.changedKeys.sort()).toEqual(['render.enabled', 'render.ipv6Mode']);
    expect(await epochOf(t, relayId)).toBe(before + 1);
    expect(await epochOf(t, off)).toBe(beforeOff);
  });

  test('originAddress is locked while the origin has live edges (update and registration alike)', async () => {
    const { t, relayId, listenerId } = await seed();
    const e = await adoptL4Edge(t, relayId, listenerId, { ipv4: '198.51.100.1' });
    await expect(
      t.mutation(internal.relays.update, { id: relayId, originAddress: '203.0.113.99' }),
    ).rejects.toThrow(/origin_address_locked/);
    await expect(registerRelay(t, { originAddress: '203.0.113.99' })).rejects.toThrow(
      /origin_address_locked/,
    );
    // The same address (or an unrelated field) is fine.
    await t.mutation(internal.relays.update, {
      id: relayId,
      originAddress: FIXTURE_ORIGIN,
      drainMinutes: 30,
    });
    await t.mutation(internal.edges.patchEdge, { edgeId: e.edgeId, status: 'destroyed' });
    await t.mutation(internal.relays.update, { id: relayId, originAddress: '203.0.113.99' });
    expect((await t.query(internal.relays.get, { id: relayId }))!.originAddress).toBe(
      '203.0.113.99',
    );
    // The role's next registration reports the address change as `changed`.
    const r = await registerRelay(t, { originAddress: '203.0.113.98' });
    expect(r.changed).toBe(true);
  });
});

describe('relays: adoption and the published pool', () => {
  test('adopt validates addresses (public, not the origin, listener of this relay) and publishes at the next free pool index', async () => {
    const { t, relayId, listenerId } = await seed();
    await expect(adoptL4Edge(t, relayId, listenerId, { ipv4: '10.0.0.1' })).rejects.toThrow(
      /public IPv4/,
    );
    await expect(adoptL4Edge(t, relayId, listenerId, { ipv4: FIXTURE_ORIGIN })).rejects.toThrow(
      /anti-leak/,
    );
    await expect(
      t.mutation(internal.relays.adoptEdge, {
        relayId,
        listenerId,
        ipv4: '198.51.100.1',
        ipv6: '198.51.100.2',
      }),
    ).rejects.toThrow(/IPv6/);
    const other = await registerRelay(t, {
      slug: 'node-two',
      nodeName: 'node-two',
      originAddress: '203.0.113.11',
    });
    await expect(adoptL4Edge(t, other.relayId, listenerId)).rejects.toThrow(/does not belong/);
    const a = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      listenerId,
      ipv4: '198.51.100.1',
      ipv6: '2001:db8::1',
      publish: true,
      verified: true,
    });
    const b = await adoptL4Edge(t, relayId, listenerId, { ipv4: '198.51.100.2', publish: true });
    expect(a.poolIndex).toBe(0);
    expect(b.poolIndex).toBe(1);
    // desiredPublished defaults to 2 → pool is full.
    await expect(
      adoptL4Edge(t, relayId, listenerId, { ipv4: '198.51.100.3', publish: true }),
    ).rejects.toThrow(/pool is full/);
    const origin = (await t.query(internal.relays.listForAdmin, {})).find(
      (r) => r.slug === FIXTURE_RELAY_SLUG,
    )!;
    expect(origin.publishedEdgeIds).toEqual([a.edgeId, b.edgeId]);
    expect(origin.publishedCount).toBe(2);
    const edge = await t.query(internal.edges.getForAdmin, { id: a.edgeId as Id<'edges'> });
    expect(edge).toMatchObject({
      managed: false,
      listenerId,
      publication: 'published',
      poolIndex: 0,
      addresses: { v4: '198.51.100.1', v6: '2001:db8::1' },
    });
    expect(edge?.accountId).toBeNull();
    expect(edge?.resources).toEqual([]);
    // The FIRST published edge became the listener's template edge.
    expect((await listenerRow(t, listenerId))!.templateEdgeId).toBe(a.edgeId);
    const raw = (await t.query(internal.edges.get, { id: a.edgeId }))!;
    expect(raw.listeners[0]).toMatchObject({
      originPort: 443,
      transport: 'tcp',
      originAddress: FIXTURE_ORIGIN,
    });
  });

  test('unpublish leaves a gap that the next publish inherits; epoch bumps each time; the template edge follows the lowest index', async () => {
    const { t, relayId, listenerId } = await seed();
    // Direct publishes into the template position need the Host flip on an
    // FCP-owned relay; this test is about pool bookkeeping, so leave the Hosts
    // to the operator.
    await t.mutation(internal.relays.update, { id: relayId, hostMode: 'operator' });
    const a = await adoptL4Edge(t, relayId, listenerId, { ipv4: '198.51.100.1', publish: true });
    const b = await adoptL4Edge(t, relayId, listenerId, { ipv4: '198.51.100.2', publish: true });
    const c = await adoptL4Edge(t, relayId, listenerId, { ipv4: '198.51.100.3' });
    const e0 = await epochOf(t, relayId);
    await t.mutation(internal.relays.unpublishEdge, { relayId, edgeId: a.edgeId, drainMs: 1000 });
    let origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.publishedEdgeIds).toEqual([null, b.edgeId]);
    expect(origin.publicationEpoch).toBe(e0 + 1);
    // The template moved to the remaining published edge.
    expect((await listenerRow(t, listenerId))!.templateEdgeId).toBe(b.edgeId);
    const drained = await t.query(internal.edges.get, { id: a.edgeId });
    expect(drained).toMatchObject({ status: 'draining', publication: 'draining' });
    expect(drained?.poolIndex).toBeUndefined();
    const pub = await t.mutation(internal.relays.publishEdge, { relayId, edgeId: c.edgeId });
    expect(pub.poolIndex).toBe(0);
    origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.publishedEdgeIds).toEqual([c.edgeId, b.edgeId]);
    expect(origin.publicationEpoch).toBe(e0 + 2);
    expect((await listenerRow(t, listenerId))!.templateEdgeId).toBe(c.edgeId);
    // A draining edge can't be re-published; an occupied index is refused.
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId, edgeId: a.edgeId }),
    ).rejects.toThrow(/edge_not_active/);
    const d = await adoptL4Edge(t, relayId, listenerId, { ipv4: '198.51.100.4' });
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId, edgeId: d.edgeId, poolIndex: 1 }),
    ).rejects.toThrow(/occupied/);
    // Unpublish with keepActive parks the edge as a standby; dropFromPool forgets it.
    await t.mutation(internal.relays.unpublishEdge, {
      relayId,
      edgeId: b.edgeId,
      keepActive: true,
    });
    origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.standbyEdgeIds).toEqual([b.edgeId]);
    expect((await t.query(internal.edges.get, { id: b.edgeId }))!.status).toBe('active');
    expect(
      await t.mutation(internal.relays.dropFromPool, { relayId, edgeId: b.edgeId, reason: 'test' }),
    ).toEqual({
      ok: true,
      dropped: true,
    });
    expect((await t.query(internal.relays.get, { id: relayId }))!.standbyEdgeIds).toEqual([]);
  });

  test('publishEdge refuses edge.needs_rotation when hostMode is fcp and the edge would become its LISTENER’s template edge', async () => {
    const { t, relayId, listenerId } = await seed();
    const first = await adoptL4Edge(t, relayId, listenerId, { ipv4: '198.51.100.31' });
    // No template yet: publishing anywhere makes this the template → flip needed.
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId, edgeId: first.edgeId }),
    ).rejects.toThrow(/needs_rotation/);
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId, edgeId: first.edgeId, poolIndex: 1 }),
    ).rejects.toThrow(/needs_rotation/);
    // Adoption that publishes seeds the template (the operator's word on a hand-made edge).
    const tpl = await adoptL4Edge(t, relayId, listenerId, { ipv4: '198.51.100.32', publish: true });
    expect(tpl.poolIndex).toBe(0);
    expect((await listenerRow(t, listenerId))!.templateEdgeId).toBe(tpl.edgeId);
    // Index 1 behind the template: a direct publish is fine.
    expect(
      await t.mutation(internal.relays.publishEdge, { relayId, edgeId: first.edgeId }),
    ).toMatchObject({
      poolIndex: 1,
    });
    expect((await listenerRow(t, listenerId))!.templateEdgeId).toBe(tpl.edgeId);
    // The template leaves (index 0 frees); the template becomes the index-1 edge.
    await t.mutation(internal.relays.unpublishEdge, {
      relayId,
      edgeId: tpl.edgeId,
      keepActive: true,
    });
    expect((await listenerRow(t, listenerId))!.templateEdgeId).toBe(first.edgeId);
    // Publishing at the now-free index 0 would put a new edge AHEAD of the template → flip needed,
    // even though a template exists: "not simply index 0".
    const third = await adoptL4Edge(t, relayId, listenerId, { ipv4: '198.51.100.33' });
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId, edgeId: third.edgeId }),
    ).rejects.toThrow(/needs_rotation/);
    // A SECOND listener has its own template: its first edge needs the flip even at a high index.
    await registerRelay(t, { listeners: [realityListener(), shadowsocksListener()] });
    const sId = (await t.run((ctx) =>
      ctx.db
        .query('relayListeners')
        .withIndex('by_relay_key', (q) => q.eq('relayId', relayId).eq('listenerKey', 's'))
        .unique(),
    ))!._id;
    await t.mutation(internal.relays.update, { id: relayId, desiredPublished: 4 });
    const ssEdge = await adoptL4Edge(t, relayId, sId, { ipv4: '198.51.100.34' });
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId, edgeId: ssEdge.edgeId, poolIndex: 3 }),
    ).rejects.toThrow(/needs_rotation/);
    // With the Hosts left to the operator there is nothing to flip: everything proceeds.
    await t.mutation(internal.relays.update, { id: relayId, hostMode: 'operator' });
    expect(
      await t.mutation(internal.relays.publishEdge, { relayId, edgeId: third.edgeId }),
    ).toMatchObject({
      poolIndex: 0,
    });
    expect((await listenerRow(t, listenerId))!.templateEdgeId).toBe(third.edgeId);
    expect(
      await t.mutation(internal.relays.publishEdge, { relayId, edgeId: ssEdge.edgeId }),
    ).toMatchObject({
      poolIndex: 2,
    });
    expect((await listenerRow(t, sId))!.templateEdgeId).toBe(ssEdge.edgeId);
  });

  test('checkPublishable: listener_retired / listener_not_deployed / listener_disabled / listener_no_active_name / transport_not_carried', async () => {
    const { t, relayId, listenerId } = await seed();
    await t.mutation(internal.relays.update, { id: relayId, hostMode: 'operator' });
    const e = await adoptL4Edge(t, relayId, listenerId, { ipv4: '198.51.100.1' });
    const publish = () => t.mutation(internal.relays.publishEdge, { relayId, edgeId: e.edgeId });
    await t.mutation(internal.relayListeners.setEnabled, { id: listenerId, enabled: false });
    await expect(publish()).rejects.toThrow(/listener_disabled/);
    await t.mutation(internal.relayListeners.setEnabled, { id: listenerId, enabled: true });
    // The mutation keeps ≥1 active name ...
    await t.mutation(internal.relayListeners.retireName, { id: listenerId, names: ['a.example'] });
    await expect(
      t.mutation(internal.relayListeners.retireName, { id: listenerId, names: ['b.example'] }),
    ).rejects.toThrow(/at least one active/);
    // ... so force the all-retired state the way an operator edit would leave it.
    await t.run(async (ctx) => {
      const l = (await ctx.db.get(listenerId))!;
      await ctx.db.patch(listenerId, {
        tlsNames: l.tlsNames!.map((n) => ({ ...n, status: 'retired' as const })),
      });
    });
    await expect(publish()).rejects.toThrow(/listener_no_active_name/);
    await t.mutation(internal.relayListeners.reactivateName, {
      id: listenerId,
      names: ['a.example'],
    });
    // Not deployed (the role says the inbound is not live yet).
    await registerRelay(t, { listeners: [realityListener({ deployed: false })] });
    await expect(publish()).rejects.toThrow(/listener_not_deployed/);
    await registerRelay(t, { listeners: [realityListener()] });
    // Retired listener: the edge must go first, so destroy it to retire, then check a fresh edge.
    await t.mutation(internal.edges.patchEdge, { edgeId: e.edgeId, status: 'destroyed' });
    await t.mutation(internal.relayListeners.retire, { relayId, listenerKey: 'a' });
    const orphan = await t.run((ctx) =>
      ctx.db.insert('edges', {
        relayId,
        listenerId,
        managed: false,
        name: 'adopted-orphan',
        steps: [],
        resources: [],
        listeners: [],
        addresses: { v4: '198.51.100.9' },
        publication: 'unpublished',
        status: 'active',
        statusChangedAt: Date.now(),
        health: 'unknown',
        destroyAttempts: 0,
        updatedAt: Date.now(),
      }),
    );
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId, edgeId: orphan }),
    ).rejects.toThrow(/listener_retired/);
    // A UDP listener: no provider forwards UDP today, so nothing can carry it.
    await t.run((ctx) => ctx.db.patch(orphan, { status: 'destroyed' }));
    await registerRelay(t, {
      listeners: [
        {
          listenerKey: 'h',
          protocol: 'hysteria2',
          streamTransport: 'udp',
          security: 'tls',
          originPort: 8443,
          tlsNames: ['h.example'],
          panelBinding: {
            inboundTag: 'HY2',
            configProfileUuid: FIXTURE_CONFIG_PROFILE,
            configProfileInboundUuid: '66666666-6666-4666-8666-666666666666',
          },
        },
      ],
    });
    const h = (await t.run((ctx) =>
      ctx.db
        .query('relayListeners')
        .withIndex('by_relay_key', (q) => q.eq('relayId', relayId).eq('listenerKey', 'h'))
        .unique(),
    ))!;
    expect(h.transport).toBe('udp');
    const udpEdge = await adoptL4Edge(t, relayId, h._id, { ipv4: '198.51.100.2' });
    expect(
      (await t.query(internal.edges.get, { id: udpEdge.edgeId }))!.listeners[0].transport,
    ).toBe('udp');
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId, edgeId: udpEdge.edgeId }),
    ).rejects.toThrow(/transport_not_carried/);
    await expect(
      adoptL4Edge(t, relayId, h._id, { ipv4: '198.51.100.3', publish: true }),
    ).rejects.toThrow(/transport_not_carried/);
  });

  test('a provider-scoped listener publishes only edges of that provider; an account-scoped one only edges of that account', async () => {
    const { t, relayId, accountId } = await seed();
    await t.mutation(internal.relays.update, { id: relayId, hostMode: 'operator' });
    const otherAccount = await createAccount(t, { provider: 'gcore', name: 'acct-b' });
    const upcloud = await createAccount(t, { provider: 'upcloud', name: 'acct-u' });
    const { listenerIds } = await registerRelay(t, {
      listeners: [
        realityListener({ providerScope: { provider: 'gcore', accountId } }),
        realityListener({
          listenerKey: 'g',
          providerScope: { provider: 'gcore' },
          panelBinding: {
            inboundTag: 'VLESS_RELAY_G',
            configProfileUuid: FIXTURE_CONFIG_PROFILE,
            configProfileInboundUuid: '77777777-7777-4777-8777-777777777777',
          },
        }),
      ],
    });
    const mk = (
      listenerId: Id<'relayListeners'>,
      acct: Id<'edgeProviderAccounts'>,
      provider: 'gcore' | 'upcloud',
      v4: string,
    ) =>
      t.run((ctx) =>
        ctx.db.insert('edges', {
          relayId,
          listenerId,
          accountId: acct,
          provider,
          managed: true,
          name: `fcp-relay-${v4}`,
          steps: [],
          resources: [],
          listeners: [],
          addresses: { v4 },
          publication: 'unpublished',
          status: 'active',
          statusChangedAt: Date.now(),
          health: 'online',
          destroyAttempts: 0,
          updatedAt: Date.now(),
        }),
      );
    const foreign = await mk(listenerIds.a, otherAccount, 'gcore', '198.51.100.21');
    const own = await mk(listenerIds.a, accountId, 'gcore', '198.51.100.22');
    const wrongProvider = await mk(listenerIds.g, upcloud, 'upcloud', '198.51.100.23');
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId, edgeId: foreign }),
    ).rejects.toThrow(/account_mismatch/);
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId, edgeId: wrongProvider }),
    ).rejects.toThrow(/provider_mismatch/);
    // An L4 endpoint publishes only once the operator confirmed it (the gate's last rule).
    await expect(t.mutation(internal.relays.publishEdge, { relayId, edgeId: own })).rejects.toThrow(
      /unverified_endpoint/,
    );
    await verifyL4Edge(t, own);
    await t.mutation(internal.relays.publishEdge, { relayId, edgeId: own });
    expect((await t.query(internal.relays.get, { id: relayId }))!.publishedEdgeIds).toEqual([own]);
    // Adoption checks the scope up front: an account of another provider is refused.
    await expect(
      adoptL4Edge(t, relayId, listenerIds.g, { ipv4: '198.51.100.24', accountId: upcloud }),
    ).rejects.toThrow(/provider scope/);
  });

  test('adoption that PUBLISHES runs the publish checks and refreshes the mirrors; a direct publish refreshes them too', async () => {
    const { t, relayId, listenerId } = await seed();
    await t.mutation(internal.relayListeners.setEnabled, { id: listenerId, enabled: false });
    await expect(
      adoptL4Edge(t, relayId, listenerId, { ipv4: '198.51.100.32', publish: true }),
    ).rejects.toThrow(/listener_disabled/);
    await t.mutation(internal.relayListeners.setEnabled, { id: listenerId, enabled: true });
    const m0 = await mirrorRefreshes(t);
    await adoptL4Edge(t, relayId, listenerId, { ipv4: '198.51.100.33', publish: true });
    expect(await mirrorRefreshes(t)).toBe(m0 + 1);
    await t.mutation(internal.relays.update, { id: relayId, hostMode: 'operator' });
    const { edgeId } = await adoptL4Edge(t, relayId, listenerId, { ipv4: '198.51.100.34' });
    const m1 = await mirrorRefreshes(t);
    await t.mutation(internal.relays.publishEdge, { relayId, edgeId });
    expect(await mirrorRefreshes(t)).toBe(m1 + 1);
  });

  test('a plain listener needs no names or target; its edge publishes and renders without an SNI', async () => {
    const { t, relayId } = await seed();
    await t.mutation(internal.relays.update, { id: relayId, hostMode: 'operator' });
    await expect(
      registerRelay(t, {
        listeners: [realityListener(), shadowsocksListener({ tlsNames: ['x.example'] })],
      }),
    ).rejects.toThrow(/presents no server name/);
    await expect(
      registerRelay(t, { listeners: [realityListener({ realityTarget: undefined })] }),
    ).rejects.toThrow(/realityTarget/);
    const { listenerIds } = await registerRelay(t, {
      listeners: [realityListener(), shadowsocksListener()],
    });
    const listeners = await t.query(internal.relayListeners.listByRelay, { relayId });
    expect(listeners.find((l) => l.listenerKey === 's')).toMatchObject({
      protocol: 'shadowsocks',
      streamTransport: 'raw',
      security: 'none',
      label: 'Shadowsocks',
      tlsNames: [],
      realityTarget: null,
      providerScope: null,
      templateHostRemark: 'node-one-relay-s',
      layers: ['l4'],
    });
    expect(listeners.find((l) => l.listenerKey === 'a')).toMatchObject({
      security: 'reality',
      label: 'VLESS + REALITY',
      realityTarget: { address: 'target.example', port: 443 },
    });
    const e = await adoptL4Edge(t, relayId, listenerIds.s, { ipv4: '198.51.100.7', publish: true });
    expect(e.poolIndex).toBe(0);
    const edge = (await t.query(internal.edges.get, { id: e.edgeId }))!;
    expect(edge.listeners[0]).toMatchObject({ originPort: 8388, transport: 'tcp' });
    const view = (await t.query(internal.edgeAdmin.endpoints, { relayId }))!;
    expect(view.published[0]).toMatchObject({
      listenerKey: 's',
      protocol: 'shadowsocks',
      security: 'none',
      activeNames: [],
      sni: null,
      hostHeader: null,
    });
    expect(view.sample.primary).toEqual({ edgeId: e.edgeId, sni: null });
  });
});

describe('relays: delete lifecycle', () => {
  const plan = {
    templateHash: 'h',
    listeners: [{ edgePort: 443, originAddress: FIXTURE_ORIGIN, originPort: 443 }],
    steps: [{ id: 'lb', kind: 'loadbalancer', resourceName: 'x' }],
  };

  test('requestDelete honours the relay drain window unless forced', async () => {
    const { t, relayId, listenerId, accountId } = await seed();
    const planned = await t.mutation(internal.edges.insertPlanned, {
      relayId,
      listenerId,
      accountId,
      ...plan,
    });
    await t.mutation(internal.edges.patchEdge, { edgeId: planned.id, status: 'active' });
    const relay = (await t.query(internal.relays.get, { id: relayId }))!;
    await t.mutation(internal.relays.requestDelete, { id: relayId, disposition: 'restore-direct' });
    const drained = (await t.query(internal.edges.get, { id: planned.id }))!;
    expect(drained.drainUntil).toBeGreaterThanOrEqual(Date.now() + relay.drainMs - 5_000);
    expect((await audits(t, 'relay.delete'))[0].payload).toEqual({
      slug: FIXTURE_RELAY_SLUG,
      force: false,
      disposition: 'restore-direct',
    });
    // Forced: the drain is skipped.
    const s2 = await seed();
    const p2 = await s2.t.mutation(internal.edges.insertPlanned, {
      relayId: s2.relayId,
      listenerId: s2.listenerId,
      accountId: s2.accountId,
      ...plan,
    });
    await s2.t.mutation(internal.edges.patchEdge, { edgeId: p2.id, status: 'active' });
    await s2.t.mutation(internal.relays.requestDelete, {
      id: s2.relayId,
      force: true,
      disposition: 'restore-direct',
    });
    expect((await s2.t.query(internal.edges.get, { id: p2.id }))!.drainUntil).toBeLessThanOrEqual(
      Date.now(),
    );
  });

  test('requestDelete drains managed edges, forgets unmanaged ones; finalizeDelete waits for edges, then Hosts, then removes everything', async () => {
    const { t, relayId, listenerId, accountId } = await seed();
    const adopted = await adoptL4Edge(t, relayId, listenerId, {
      ipv4: '198.51.100.1',
      publish: true,
    });
    const planned = await t.mutation(internal.edges.insertPlanned, {
      relayId,
      listenerId,
      accountId,
      ...plan,
    });
    await t.mutation(internal.edges.patchEdge, { edgeId: planned.id, status: 'active' });
    await t.run((ctx) =>
      ctx.db.patch(listenerId, { host: { state: 'present', uuid: 'h-1', ownership: 'fcp' } }),
    );
    const r = await t.mutation(internal.relays.requestDelete, {
      id: relayId,
      disposition: 'restore-direct',
    });
    expect(r).toEqual({ ok: true, deleted: false });
    expect((await t.query(internal.edges.get, { id: adopted.edgeId }))?.status).toBe('destroyed');
    expect((await t.query(internal.edges.get, { id: planned.id }))?.status).toBe('draining');
    const origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.deleting).toBe(true);
    expect(origin.enabled).toBe(false);
    expect(origin.publishedEdgeIds).toEqual([]);
    expect(await t.mutation(internal.relays.finalizeDelete, { id: relayId })).toEqual({
      removed: false,
      waitingOn: 'edges',
    });
    await t.mutation(internal.edges.patchEdge, { edgeId: planned.id, status: 'destroyed' });
    // Edges gone, but an FCP-owned panel Host remains: the Host cleanup goes first.
    expect(await t.mutation(internal.relays.finalizeDelete, { id: relayId })).toEqual({
      removed: false,
      waitingOn: 'hosts',
    });
    await t.run((ctx) => ctx.db.patch(listenerId, { host: { state: 'absent' } }));
    const rollup = (kind: 'edge' | 'relay', ref: string) =>
      t.run((ctx) =>
        ctx.db.insert('probeReachability', {
          targetKind: kind,
          targetRef: ref,
          country: 'IR',
          source: 'globalping',
          ipVersion: 4,
          okCount: 1,
          failCount: 0,
          verdict: 'reachable',
          updatedAt: Date.now(),
        }),
      );
    await rollup('relay', relayId);
    await rollup('edge', planned.id);
    await rollup('edge', adopted.edgeId);
    expect(await t.mutation(internal.relays.finalizeDelete, { id: relayId })).toEqual({
      removed: true,
      waitingOn: null,
    });
    expect(await t.query(internal.relays.get, { id: relayId })).toBeNull();
    expect(await listenerRow(t, listenerId)).toBeNull();
    expect(await t.run((ctx) => ctx.db.query('probeReachability').collect())).toEqual([]);
    expect(await t.run((ctx) => ctx.db.query('edges').collect())).toEqual([]);
    // An adopted (operator-owned) Host never blocks the removal.
    const s2 = await seed();
    await s2.t.run((ctx) =>
      ctx.db.patch(s2.listenerId, {
        host: { state: 'present', uuid: 'h-2', ownership: 'adopted' },
      }),
    );
    await s2.t.mutation(internal.relays.requestDelete, {
      id: s2.relayId,
      disposition: 'keep-dark',
    });
    expect(await s2.t.mutation(internal.relays.finalizeDelete, { id: s2.relayId })).toEqual({
      removed: true,
      waitingOn: null,
    });
    // finalizeDelete on a relay not marked for deletion does nothing.
    const s3 = await seed();
    expect(await s3.t.mutation(internal.relays.finalizeDelete, { id: s3.relayId })).toEqual({
      removed: false,
      waitingOn: null,
    });
  });

  test('requestDelete is refused mid-flip and cancels a running rotation otherwise', async () => {
    const { t, relayId } = await seed();
    const rotationId = await startFakeRotation(t, relayId);
    await expect(
      t.mutation(internal.relays.requestDelete, { id: relayId, disposition: 'keep-dark' }),
    ).rejects.toThrow(/busy/);
    await t.run((ctx) => ctx.db.patch(rotationId, { phase: 'provisioning' }));
    await t.mutation(internal.relays.requestDelete, { id: relayId, disposition: 'keep-dark' });
    expect((await t.run((ctx) => ctx.db.get(rotationId)))!.cancelRequested).toBe(true);
  });
});

describe('relays: layers, adoption by hostname and the L7 publish gates', () => {
  /** The fixture + a Cloudflare account + an L7-capable ws listener (https origin). */
  async function l7Seed() {
    const s = await seed();
    const cfAccount = await createAccount(s.t, { provider: 'cloudflare', name: 'acct-cf' });
    const { listenerIds } = await registerRelay(s.t, {
      listeners: [
        realityListener(),
        wsListener({
          tlsNames: ['a.example'],
          originTransport: {
            scheme: 'https',
            certPublic: true,
            certNames: ['a.example', 'b.example'],
            acceptsHostHeader: 'any',
          },
        }),
      ],
    });
    return { ...s, cfAccount, wsListener: listenerIds.w };
  }

  test('adoption by hostname records an L7 edge; an IP in the hostname field is refused', async () => {
    const { t, relayId, wsListener: w, cfAccount } = await l7Seed();
    const { edgeId } = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      listenerId: w,
      accountId: cfAccount,
      hostname: 'Front.Example.Org.',
    });
    const edge = (await t.query(internal.edges.get, { id: edgeId }))!;
    expect(edge.layer).toBe('l7');
    expect(edge.addresses).toEqual({ v4: undefined, v6: undefined, hostname: 'front.example.org' });
    for (const hostname of ['198.51.100.9', 'nodots']) {
      await expect(
        t.mutation(internal.relays.adoptEdge, {
          relayId,
          listenerId: w,
          accountId: cfAccount,
          hostname,
        }),
      ).rejects.toThrow(/valid hostname/);
    }
  });

  test('a hostname that IS the origin is refused (anti-leak), as an IP one is', async () => {
    const { t, relayId, wsListener: w, cfAccount } = await l7Seed();
    await t.mutation(internal.relays.update, { id: relayId, originAddress: 'node.example.net' });
    await expect(
      t.mutation(internal.relays.adoptEdge, {
        relayId,
        listenerId: w,
        accountId: cfAccount,
        hostname: 'node.example.net',
      }),
    ).rejects.toThrow(/origin itself/);
  });

  test('the address KIND follows the account: an L7 account refuses an IP, an L4 one a hostname', async () => {
    const { t, relayId, listenerId, wsListener: w, cfAccount, accountId } = await l7Seed();
    await expect(
      t.mutation(internal.relays.adoptEdge, {
        relayId,
        listenerId: w,
        accountId: cfAccount,
        ipv4: '198.51.100.9',
      }),
    ).rejects.toThrow(/hostname/);
    await expect(
      t.mutation(internal.relays.adoptEdge, {
        relayId,
        listenerId,
        accountId,
        hostname: 'front.example.org',
      }),
    ).rejects.toThrow(/IP literal/);
  });

  test('checkPublishable refuses a layer the chain cannot carry and a protocol the provider cannot', async () => {
    const { t, relayId, listenerId, cfAccount } = await l7Seed();
    // A Cloudflare (L7) edge on the REALITY listener: no origin transport, so
    // nothing but an L4 forwarder can front it.
    const { edgeId: mismatch } = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      listenerId,
      accountId: cfAccount,
      hostname: 'front.example.org',
    });
    await t.run((ctx) => ctx.db.patch(mismatch, { managed: true }));
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId, edgeId: mismatch }),
    ).rejects.toThrow(/protocol_not_carried|layer_mismatch/);
    // A Fastly account cannot carry gRPC even though it is an L7 front.
    const fastlyAccount = await createAccount(t, {
      provider: 'fastly',
      name: 'acct-fastly',
      settings: { dnsAccountId: cfAccount, certificateAuthority: 'certainly' },
      credentials: { apiToken: 'f' },
    });
    const { listenerIds } = await registerRelay(t, {
      listeners: [
        realityListener(),
        wsListener({
          tlsNames: ['a.example'],
          originTransport: {
            scheme: 'https',
            certPublic: true,
            certNames: ['a.example', 'b.example'],
            acceptsHostHeader: 'any',
          },
        }),
        wsListener({
          listenerKey: 'g',
          streamTransport: 'grpc',
          tlsNames: ['a.example'],
          transportParams: { serviceName: 'svc' },
          originTransport: {
            scheme: 'https',
            certPublic: true,
            certNames: ['a.example', 'b.example'],
            acceptsHostHeader: 'any',
          },
          panelBinding: {
            inboundTag: 'VLESS_RELAY_G',
            configProfileUuid: FIXTURE_CONFIG_PROFILE,
            configProfileInboundUuid: '55555555-5555-4555-8555-555555555555',
          },
        }),
      ],
    });
    const grpc = await t.query(internal.relayListeners.get, { id: listenerIds.g });
    expect(grpc?.transportParams).toEqual({ serviceName: 'svc' });
    const { edgeId: grpcEdge } = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      listenerId: listenerIds.g,
      accountId: fastlyAccount,
      hostname: 'grpc.example.org',
    });
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId, edgeId: grpcEdge }),
    ).rejects.toThrow(/protocol_not_carried/);
  });

  test('an L7 edge without a current front qualification is refused (front_unqualified)', async () => {
    const { t, relayId, wsListener: w, cfAccount } = await l7Seed();
    await t.mutation(internal.relays.update, { id: relayId, hostMode: 'operator' });
    const { edgeId } = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      listenerId: w,
      accountId: cfAccount,
      hostname: 'front.example.org',
    });
    await expect(t.mutation(internal.relays.publishEdge, { relayId, edgeId })).rejects.toThrow(
      /front_unqualified/,
    );
  });

  test('layers per listener: an https origin with public cert is L4+L7 for ws, L4-only for REALITY, L7-only when the origin is plaintext', async () => {
    const { t, relayId } = await l7Seed();
    const { listenerIds } = await registerRelay(t, {
      listeners: [
        realityListener(),
        wsListener({
          tlsNames: ['a.example'],
          originTransport: {
            scheme: 'https',
            certPublic: true,
            certNames: ['a.example', 'b.example'],
            acceptsHostHeader: 'any',
          },
        }),
        wsListener({
          listenerKey: 'p',
          tlsNames: [],
          originTransport: {
            scheme: 'http',
            certPublic: false,
            certNames: [],
            acceptsHostHeader: 'any',
          },
          panelBinding: {
            inboundTag: 'VLESS_WS_PLAIN',
            configProfileUuid: FIXTURE_CONFIG_PROFILE,
            configProfileInboundUuid: '88888888-8888-4888-8888-888888888888',
          },
        }),
      ],
    });
    expect(Object.keys(listenerIds).sort()).toEqual(['a', 'p', 'w']);
    const rows = await t.query(internal.relayListeners.listByRelay, { relayId });
    const by = Object.fromEntries(rows.map((r) => [r.listenerKey, r]));
    expect(by.a.layers).toEqual(['l4']);
    expect(by.a.excluded).toEqual({ l7: 'protocol_not_http_transport' });
    expect(by.w.layers).toEqual(['l4', 'l7']);
    expect(by.p.layers).toEqual(['l7']);
    expect(by.p.excluded).toEqual({ l4: 'origin_plaintext' });
  });

  test('retiring a listener is refused while a rotation runs on the relay', async () => {
    const { t, relayId } = await seed();
    await startFakeRotation(t, relayId);
    await expect(
      t.mutation(internal.relayListeners.retire, { relayId, listenerKey: 'a' }),
    ).rejects.toThrow(/rotation_running/);
  });
});
