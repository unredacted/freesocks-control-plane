/// <reference types="vite/client" />
import { withCooling } from './lib/edges/setState';
import { defaultLocationRow } from './lib/edges/testing/reads';
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { jsonRes, mockFetch } from './lib/edges/testing/mockFetch';
import {
  adoptL4Edge,
  createAccount,
  FIXTURE_CONFIG_PROFILE,
  insertPanelServer,
  realityListener,
  registerRelay,
  shadowsocksListener,
  verifyL4Edge,
  type ListenerSpecFixture,
} from './lib/edges/testing/fixtures';
import { upsertSettingRow } from './appSettings';
import { isStaleRotation, MAX_STEP_ERRORS, standbyReasonOf } from './edgeRotations';
import { isSpareProvision, providerAnswerOf } from './lib/edges/rotation';
import { resolveEdgeConfig } from './lib/edgeConfig';

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
const SS_INBOUND = '44444444-4444-4444-8444-444444444444';
const SS_HOST_UUID = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const SS_OLD_EDGE = '198.51.100.2';
const THIRD_EDGE = '198.51.100.60';

interface BackendAddress {
  uuid: string;
  remark: string;
  address: string;
  port: number;
  sni?: string;
  host?: string;
  inbound: { configProfileUuid: string; configProfileInboundUuid: string };
}

/**
 * A fake UpCloud + a fake backend behind one fetch stub. The backend keeps Host
 * state so PATCHes / POSTs are observable and the next GET reflects them.
 */
function fakeWorld(
  opts: {
    hostPresent?: boolean;
    vanishAfterFirstPatch?: boolean;
    panelDown?: boolean;
    /** The template Host points at the origin itself (leak). */
    hostLeaks?: boolean;
    /** Extra Hosts the backend starts with (other listeners). */
    extraHosts?: BackendAddress[];
    /** The addresses the fake provider mints, in order (then NEW_EDGE). */
    mint?: string[];
  } = {},
) {
  const panelHosts: BackendAddress[] = [];
  if (opts.hostPresent !== false) {
    panelHosts.push({
      uuid: HOST_UUID,
      remark: 'node-one-relay-u',
      address: opts.hostLeaks ? ORIGIN : OLD_EDGE,
      port: 443,
      sni: 'a.example',
      inbound: { configProfileUuid: FIXTURE_CONFIG_PROFILE, configProfileInboundUuid: INBOUND },
    });
  }
  panelHosts.push(...(opts.extraHosts ?? []));
  const lbs = new Map<string, { uuid: string; name: string; operational_state: string }>();
  let patches = 0;
  let creates = 0;
  let panelCalls = 0;
  let minted = 0;
  const stub = mockFetch((c) => {
    if (new URL(c.url).hostname === 'panel.example') {
      panelCalls++;
      if (opts.panelDown) return jsonRes({ message: 'down' }, 503);
      if (c.path === '/api/hosts' && c.method === 'GET') return jsonRes({ response: panelHosts });
      if (c.path === '/api/hosts' && c.method === 'PATCH') {
        patches++;
        const body = c.body as {
          uuid: string;
          address: string;
          port: number;
          sni?: string;
          host?: string;
        };
        const h = panelHosts.find((x) => x.uuid === body.uuid);
        if (h) {
          h.address = body.address;
          h.port = body.port;
          // The backend stores what it is sent; a cleared field arrives as ''.
          if (body.sni !== undefined) h.sni = body.sni;
          if (body.host !== undefined) h.host = body.host;
          if (opts.vanishAfterFirstPatch) panelHosts.splice(panelHosts.indexOf(h), 1);
        }
        return jsonRes({ response: h ?? null });
      }
      if (c.path === '/api/hosts' && c.method === 'POST') {
        creates++;
        const body = c.body as {
          remark: string;
          address: string;
          port: number;
          sni?: string;
          host?: string;
          inbound: BackendAddress['inbound'];
        };
        const uuid = `cccccccc-cccc-4ccc-8ccc-${String(creates).padStart(12, '0')}`;
        panelHosts.push({
          uuid,
          remark: body.remark,
          address: body.address,
          port: body.port,
          sni: body.sni,
          host: body.host,
          inbound: body.inbound,
        });
        return jsonRes({ response: { uuid } });
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
      return jsonRes({
        ip_address: { address: opts.mint?.[minted++] ?? NEW_EDGE, floating: 'yes' },
      });
    const attach = c.path.match(/^\/1\.3\/load-balancer\/([^/]+)\/ip-addresses$/);
    if (attach && c.method === 'POST') return jsonRes({});
    const get = c.path.match(/^\/1\.3\/load-balancer\/([^/]+)$/);
    if (get && c.method === 'GET') {
      const lb = lbs.get(get[1]);
      return lb ? jsonRes(lb) : jsonRes({ error: { error_code: 'LB_NOT_FOUND' } }, 404);
    }
    throw new Error(`unexpected ${c.method} ${c.url}`);
  });
  return {
    stub,
    panelHosts,
    lbs,
    patches: () => patches,
    creates: () => creates,
    panelCalls: () => panelCalls,
  };
}

/** The REALITY listener `u` (remark `node-one-origin-u`, one name). */
function listenerU(over: Partial<ListenerSpecFixture> = {}): ListenerSpecFixture {
  return realityListener({
    listenerKey: 'u',
    tlsNames: ['a.example'],
    panelBinding: {
      inboundTag: 'VLESS_RELAY_U',
      configProfileUuid: FIXTURE_CONFIG_PROFILE,
      configProfileInboundUuid: INBOUND,
    },
    ...over,
  });
}

/**
 * backend-a + a qualified UpCloud account + origin node-one (backend-node → hostMode
 * `fcp`) with the REALITY listener `u`, and a hand-made edge adopted and
 * published at index 0.
 */
async function seed(opts: { listeners?: ListenerSpecFixture[] } = {}) {
  const t = convexTest(schema, modules);
  await insertPanelServer(t);
  const accountId = await createAccount(t, {
    provider: 'upcloud',
    name: 'acct-u',
    qualified: true,
  });
  const { relayId, listenerIds } = await registerRelay(t, {
    listeners: opts.listeners ?? [listenerU()],
  });
  const listenerId = listenerIds.u;
  // The hand-made edge FCP adopts (observe-only) and publishes at index 0.
  const { edgeId: oldEdgeId } = await adoptL4Edge(t, relayId, listenerId, {
    ipv4: OLD_EDGE,
    publish: true,
  });
  return { t, accountId, relayId, listenerId, listenerIds, oldEdgeId: oldEdgeId as Id<'edges'> };
}

async function listenerRow(t: ReturnType<typeof convexTest>, id: Id<'relayListeners'>) {
  return (await t.run((ctx) => ctx.db.get(id)))!;
}

/** The listener's Host as FCP records it: present at HOST_UUID with this intent. */
async function setHostIntent(
  t: ReturnType<typeof convexTest>,
  id: Id<'relayListeners'>,
  tuple: { address: string; sni: string | null; host?: string | null },
) {
  await t.run((ctx) =>
    ctx.db.patch(id, {
      host: {
        state: 'present',
        uuid: HOST_UUID,
        ownership: 'fcp',
        intended: {
          remark: 'node-one-relay-u',
          address: tuple.address,
          port: 443,
          sni: tuple.sni,
          host: tuple.host ?? null,
          inboundUuid: INBOUND,
        },
      },
    }),
  );
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

/** Drive one step at a time until the rotation reaches `phase` (throws on a terminal one). */
async function driveUntil(
  t: ReturnType<typeof convexTest>,
  rotationId: Id<'edgeRotations'>,
  phase: string,
) {
  for (let i = 0; i < 400; i++) {
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    if (r.phase === phase) return r;
    if (['done', 'failed', 'rolled_back', 'quarantined', 'cancelled'].includes(r.phase))
      throw new Error(`driveUntil: reached terminal ${r.phase} before ${phase}`);
    // Run exactly one step by hand: the scheduled copies run later (in `drain`)
    // and are harmless — each step does one bounded unit of work off fresh state.
    await t.action(internal.edgeRotations.step, { rotationId });
  }
  throw new Error(`driveUntil: never reached ${phase}`);
}

/**
 * A TESTED spare on the listener: provisioned through the machine (the fake
 * provider mints NEW_EDGE), then confirmed by the operator. An L4 replace
 * switches only to such a spare (`edge.no_verified_spare` otherwise): the
 * publication gate never lets an untested L4 address into the pool.
 */
async function provisionSpare(
  t: ReturnType<typeof convexTest>,
  relayId: Id<'relays'>,
  listenerId?: Id<'relayListeners'>,
): Promise<Id<'edges'>> {
  const { rotationId } = await t.mutation(internal.edgeRotations.start, {
    relayId,
    kind: 'provision',
    trigger: 'manual',
    publishOnDone: false,
    ...(listenerId ? { listenerId } : {}),
  });
  await drain(t, rotationId);
  const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
  if (r.phase !== 'done' || !r.toEdgeId)
    throw new Error(`provisionSpare: ${r.phase} ${r.outcome ?? ''}`);
  await verifyL4Edge(t, r.toEdgeId);
  return r.toEdgeId;
}

/** Every rotation start-guard (quarantine / running rotation) must hold for these writers too. */
async function expectPoolWritersRefused(
  t: ReturnType<typeof convexTest>,
  relayId: Id<'relays'>,
  listenerId: Id<'relayListeners'>,
  edgeId: Id<'edges'>,
  code: RegExp,
) {
  await expect(
    t.mutation(internal.relays.publishEdge, { relayId, edgeId, poolIndex: 1 }),
  ).rejects.toThrow(code);
  await expect(t.mutation(internal.relays.unpublishEdge, { relayId, edgeId })).rejects.toThrow(
    code,
  );
  await expect(
    adoptL4Edge(t, relayId, listenerId, { ipv4: '198.51.100.77', publish: true }),
  ).rejects.toThrow(code);
  await expect(
    t.mutation(internal.relays.dropFromPool, { relayId, edgeId, reason: 'test' }),
  ).rejects.toThrow(code);
  await expect(t.mutation(internal.edgeAdmin.deleteEdge, { edgeId })).rejects.toThrow(
    /Unpublish|quarantin|rotation/,
  );
  await expect(
    t.mutation(internal.edgeAdmin.resolveOperator, { edgeId, action: 'reactivate' }),
  ).rejects.toThrow(/Unpublish|quarantin|rotation/);
  await expect(
    t.mutation(internal.edgeReconcileMutations.retryDestroy, { edgeId }),
  ).rejects.toThrow(/Unpublish|quarantin|rotation|published/);
}

describe('edgeRotations: replace', () => {
  test('full replace: provisions, verifies, publishes at index 0, flips the listener Host, drains the old edge', async () => {
    vi.useFakeTimers();
    const world = fakeWorld();
    const { t, relayId, listenerId, oldEdgeId, accountId } = await seed();
    // The adopted, published edge is the listener's template edge.
    expect((await listenerRow(t, listenerId)).templateEdgeId).toBe(oldEdgeId);
    // Without a tested spare an L4 replace is refused before anything is paid for.
    await expect(
      t.mutation(internal.edgeRotations.start, {
        relayId,
        kind: 'replace',
        trigger: 'manual',
        targetEdgeId: oldEdgeId,
      }),
    ).rejects.toThrow(/no_verified_spare/);
    const spare = await provisionSpare(t, relayId);
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: oldEdgeId,
    });
    const started = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(started.phase).toBe('select');
    // A replace binds to the target's listener.
    expect(started.listenerId).toBe(listenerId);
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
      {
        listenerKey: 'u',
        uuid: HOST_UUID,
        oldAddress: OLD_EDGE,
        oldPort: 443,
        inboundUuid: INBOUND,
        // A version-2 snapshot: the previous SNI/Host are known, so a rollback
        // can restore the whole tuple.
        snapshotVersion: 2,
        oldSni: 'a.example',
        oldHost: null,
      },
    ]);
    expect(r.previousBinding).toEqual({ edgeId: oldEdgeId, listenerId, poolIndex: 0 });
    const codes = r.events.map((e) => e.code);
    expect(codes).toEqual(
      expect.arrayContaining([
        'started',
        'selected_standby',
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
      listenerId,
      // This provider exposes no member health: a running service is `unknown`
      // (never `online`), which the verify gate accepts for it (capabilities.memberHealth).
      health: 'unknown',
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

    // Backend: exactly one PATCH, no create; the Host now points at the new edge (never at the origin).
    expect(world.patches()).toBe(1);
    expect(world.creates()).toBe(0);
    expect(world.panelHosts[0]).toMatchObject({ address: NEW_EDGE, port: 443 });
    expect(world.panelHosts[0].address).not.toBe(ORIGIN);
    // The listener records the Host the plan found: present, ADOPTED (the role
    // created it, not FCP), and its template edge followed the pool.
    const listener = await listenerRow(t, listenerId);
    expect(listener.host).toMatchObject({
      state: 'present',
      uuid: HOST_UUID,
      ownership: 'adopted',
    });
    expect(listener.host!.op).toBeUndefined();
    expect(listener.templateEdgeId).toBe(r.toEdgeId);
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
    // The row remembers every audit id it produced (the trail no longer scans "newest N").
    expect(r.auditIds!.length).toBeGreaterThanOrEqual(4);
    // The replace switched to the tested spare; the provision run created it.
    expect(r.toEdgeId).toBe(spare);
    expect(r.viaStandby).toBe(true);
    expect(r.createdEdgeId).toBeUndefined();
    expect(r.hostPlanCaptured).toBe(true);
    expect(r.forwardWriteAttempted).toBe(true);
    expect(r.listenerId).toBe(listenerId);

    // A SECOND replace (of the edge that is now the template) flips again: the
    // listener's template edge followed the first rotation, so the machine
    // still knows this listener's Host must move.
    await t.run((ctx) => ctx.db.patch(relayId, { cooldownUntil: undefined }));
    await provisionSpare(t, relayId);
    const second = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: r.toEdgeId!,
    });
    await drain(t, second.rotationId);
    const r2 = (await t.query(internal.edgeRotations.get, { id: second.rotationId }))!;
    expect([r2.phase, r2.outcome]).toEqual(['done', 'published']);
    expect(r2.hostPlan).toHaveLength(1);
    expect(r2.hostPlan[0]).toMatchObject({
      listenerKey: 'u',
      uuid: HOST_UUID,
      oldAddress: NEW_EDGE,
    });
    // The fake provider mints the same address again, so the Host already sits
    // at the target: planned, observed converged, and NOT rewritten.
    expect(r2.events.map((e) => e.code)).toEqual(
      expect.arrayContaining(['host_plan', 'hosts_converged']),
    );
    expect(world.patches()).toBe(1);
    expect((await listenerRow(t, listenerId)).templateEdgeId).toBe(r2.toEdgeId);
  });

  test('burn: the old edge is marked burned with the shorter drain', async () => {
    vi.useFakeTimers();
    fakeWorld();
    const { t, relayId, oldEdgeId } = await seed();
    await provisionSpare(t, relayId);
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
    // An operator's burn cools nothing: only the detector's does (D6).
    expect((await t.run((ctx) => ctx.db.get(relayId)))!.cooling).toBeUndefined();
  });

  test('a detector burn cools the burned address location on this origin', async () => {
    vi.useFakeTimers();
    fakeWorld();
    const { t, relayId, oldEdgeId } = await seed();
    await provisionSpare(t, relayId);
    // The burned address lives in a location (the pick that will cool).
    const acct = await createAccount(t, { provider: 'upcloud', name: 'acct-cool' });
    const where = (await defaultLocationRow(t, acct))!._id;
    await t.run((ctx) => ctx.db.patch(oldEdgeId, { locationId: where }));
    const old = (await t.query(internal.edges.get, { id: oldEdgeId }))!;
    // Automatic rotation on, fleet-wide and for this origin.
    await t.run(async (ctx) => {
      await upsertSettingRow(ctx, 'edge.enabled', 'true');
      await upsertSettingRow(ctx, 'edge.autoRotate', 'true');
      await ctx.db.patch(relayId, { autoRotate: true });
    });
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'detector',
      targetEdgeId: oldEdgeId,
      burn: true,
      forceGeoEvidence: true,
    });
    await drain(t, rotationId);
    expect((await t.query(internal.edgeRotations.get, { id: rotationId }))!.phase).toBe('done');
    const cooling = (await t.run((ctx) => ctx.db.get(relayId)))!.cooling ?? [];
    expect(cooling.map((c) => c.locationId)).toEqual([old.locationId]);
    expect(cooling[0]!.until).toBeGreaterThan(Date.now());
  });

  test('withCooling: the burned pick cools until its end, the later end wins, ended ones are pruned', () => {
    const now = 1_000;
    const a = 'loc-a' as Id<'edgeLocations'>;
    const b = 'loc-b' as Id<'edgeLocations'>;
    expect(withCooling(undefined, a, now + 60, now)).toEqual([{ locationId: a, until: now + 60 }]);
    expect(
      withCooling(
        [
          { locationId: a, until: now + 600 },
          { locationId: b, until: now - 1 },
        ],
        a,
        now + 60,
        now,
      ),
    ).toEqual([{ locationId: a, until: now + 600 }]);
  });

  test("the origin's own drain and cooldown win over the fleet's (one inheritance rule)", async () => {
    vi.useFakeTimers();
    fakeWorld();
    const { t, relayId, oldEdgeId } = await seed();
    // The fleet drains for a day; this origin set 7 minutes and a 15-minute cooldown.
    await t.mutation(internal.relays.update, { id: relayId, drainMinutes: 7, cooldownMinutes: 15 });
    await provisionSpare(t, relayId);
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: oldEdgeId,
    });
    await drain(t, rotationId);
    expect((await t.query(internal.edgeRotations.get, { id: rotationId }))!.phase).toBe('done');
    const oldEdge = (await t.query(internal.edges.get, { id: oldEdgeId }))!;
    expect(oldEdge.status).toBe('draining');
    // Stamped at publish and again at finalize (a poll later): minutes, never the fleet's day.
    const drainMs = oldEdge.drainUntil! - oldEdge.statusChangedAt!;
    expect(drainMs).toBeGreaterThanOrEqual(7 * 60_000);
    expect(drainMs).toBeLessThan(8 * 60_000);
    const origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.cooldownUntil! - origin.lastRotatedAt!).toBe(15 * 60_000);
    // Null clears the override: the origin follows the fleet again.
    await t.mutation(internal.relays.update, { id: relayId, drainMinutes: null });
    const cleared = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(cleared.drainMs).toBeUndefined();
    expect(cleared.cooldownMs).toBe(15 * 60_000);
  });

  test('hosts_changed during the flip rolls back the complete binding; the new edge stays as a standby', async () => {
    vi.useFakeTimers();
    const world = fakeWorld({ vanishAfterFirstPatch: true });
    const { t, relayId, listenerId, oldEdgeId } = await seed();
    await provisionSpare(t, relayId);
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
    await expect(
      t.mutation(internal.relays.requestDelete, { id: relayId, disposition: 'restore-direct' }),
    ).rejects.toThrow(/quarantine/);
    // ...including every other pool / edge writer.
    await expectPoolWritersRefused(t, relayId, listenerId, r.toEdgeId!, /quarantin/);
    await expect(
      t.mutation(internal.edgeAdmin.deleteEdge, { edgeId: r.toEdgeId! }),
    ).rejects.toThrow(/quarantin/);
    // Operator resolves keeping the previous binding.
    await t.mutation(internal.edgeRotations.resolveQuarantine, { relayId, keep: 'previous' });
    const after = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(after.quarantine).toBeUndefined();
    expect(after.publishedEdgeIds).toEqual([oldEdgeId]);
    expect((await t.query(internal.edges.get, { id: r.toEdgeId! }))!.status).toBe('active');
    expect((await listenerRow(t, listenerId)).templateEdgeId).toBe(oldEdgeId);
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.map((a) => a.action)).toEqual(
      expect.arrayContaining(['edge.quarantined', 'edge.quarantine_resolved']),
    );
  });

  test('a template Host pointing at the origin fails the flip and rolls back; it never counts as converged', async () => {
    vi.useFakeTimers();
    const world = fakeWorld({ hostLeaks: true });
    const { t, relayId, oldEdgeId } = await seed();
    await provisionSpare(t, relayId);
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: oldEdgeId,
    });
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(r.outcome).toBe('host_leaks_origin');
    expect(['rolled_back', 'quarantined']).toContain(r.phase);
    expect(world.patches()).toBe(0);
    expect(world.creates()).toBe(0);
    // The leaking Host is untouched and the previous binding is back.
    expect(world.panelHosts[0].address).toBe(ORIGIN);
    const origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.publishedEdgeIds).toEqual([oldEdgeId]);
  });

  test('resolving a quarantine with keep:current publishes the new edge at the saved index and drains the previous one', async () => {
    vi.useFakeTimers();
    fakeWorld({ vanishAfterFirstPatch: true });
    const { t, relayId, listenerId, oldEdgeId } = await seed();
    await provisionSpare(t, relayId);
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: oldEdgeId,
    });
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(r.phase).toBe('quarantined');
    // The rollback pass restored the previous binding before the quarantine...
    expect((await t.query(internal.relays.get, { id: relayId }))!.publishedEdgeIds).toEqual([
      oldEdgeId,
    ]);
    // ...so keeping the CURRENT edge must invert it, not merely flip a status.
    await t.mutation(internal.edgeRotations.resolveQuarantine, { relayId, keep: 'current' });
    const after = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(after.quarantine).toBeUndefined();
    expect(after.publishedEdgeIds).toEqual([r.toEdgeId]);
    expect(after.standbyEdgeIds).not.toContain(r.toEdgeId);
    expect(after.lastRotatedAt).toBeDefined();
    const newEdge = (await t.query(internal.edges.get, { id: r.toEdgeId! }))!;
    expect(newEdge).toMatchObject({ status: 'active', publication: 'published', poolIndex: 0 });
    const oldEdge = (await t.query(internal.edges.get, { id: oldEdgeId }))!;
    expect(oldEdge).toMatchObject({ status: 'draining', publication: 'draining' });
    expect(oldEdge.drainUntil).toBeGreaterThan(Date.now());
    expect((await t.query(internal.edgeRotations.get, { id: rotationId }))!.outcome).toBe(
      'quarantine_resolved:current',
    );
    // The listener's template edge follows the operator's choice.
    expect((await listenerRow(t, listenerId)).templateEdgeId).toBe(r.toEdgeId);
  });

  test('backend down during the flip: attempts are capped, then a rollback restores the binding without Host writes', async () => {
    vi.useFakeTimers();
    const world = fakeWorld({ panelDown: true });
    const { t, relayId, oldEdgeId } = await seed();
    await provisionSpare(t, relayId);
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

  test('no Host on the backend yet (hostMode fcp): FCP CREATES the listener Host at the new edge instead of flipping', async () => {
    vi.useFakeTimers();
    const world = fakeWorld({ hostPresent: false });
    const { t, relayId, listenerId, oldEdgeId } = await seed();
    await provisionSpare(t, relayId);
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: oldEdgeId,
    });
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect([r.phase, r.outcome]).toEqual(['done', 'published']);
    // Born at the target: nothing to flip, so the plan is empty and no PATCH ran.
    expect(r.hostPlan).toEqual([]);
    expect(world.patches()).toBe(0);
    expect(world.creates()).toBe(1);
    expect(world.panelHosts).toHaveLength(1);
    expect(world.panelHosts[0]).toMatchObject({
      remark: 'node-one-relay-u',
      address: NEW_EDGE,
      port: 443,
      sni: 'a.example',
      inbound: { configProfileUuid: FIXTURE_CONFIG_PROFILE, configProfileInboundUuid: INBOUND },
    });
    expect(world.panelHosts[0].address).not.toBe(ORIGIN);
    // The listener owns the Host it created (ownership fcp), with the persisted intent.
    const listener = await listenerRow(t, listenerId);
    expect(listener.host).toMatchObject({
      state: 'present',
      uuid: world.panelHosts[0].uuid,
      ownership: 'fcp',
      intended: { remark: 'node-one-relay-u', address: NEW_EDGE, port: 443, sni: 'a.example' },
    });
    expect(listener.host!.op).toBeUndefined();
    expect(listener.templateEdgeId).toBe(r.toEdgeId);
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.find((a) => a.action === 'relay.host.created')?.payload).toMatchObject({
      relaySlug: 'node-one',
      listenerKey: 'u',
    });
    expect(JSON.stringify(audit)).not.toContain(NEW_EDGE);
  });

  test("the listener's Host intent follows every flip, so a name resync never writes an old address back", async () => {
    vi.useFakeTimers();
    const world = fakeWorld({ hostPresent: false, mint: [NEW_EDGE, THIRD_EDGE] });
    const { t, relayId, listenerId, oldEdgeId } = await seed();
    // First replace: no Host yet, so FCP creates it at the new edge (its intent).
    await provisionSpare(t, relayId);
    const first = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: oldEdgeId,
    });
    await drain(t, first.rotationId);
    const r1 = (await t.query(internal.edgeRotations.get, { id: first.rotationId }))!;
    expect([r1.phase, r1.outcome]).toEqual(['done', 'published']);
    const created = (await listenerRow(t, listenerId)).host!;
    expect(created).toMatchObject({ state: 'present', ownership: 'fcp' });
    expect(created.intended).toMatchObject({ address: NEW_EDGE, port: 443, sni: 'a.example' });
    // Second replace: the Host exists, so the rotation FLIPS it to the third address.
    await t.run((ctx) => ctx.db.patch(relayId, { cooldownUntil: undefined }));
    await provisionSpare(t, relayId);
    const second = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: r1.toEdgeId!,
    });
    await drain(t, second.rotationId);
    const r2 = (await t.query(internal.edgeRotations.get, { id: second.rotationId }))!;
    expect([r2.phase, r2.outcome]).toEqual(['done', 'published']);
    expect(r2.events.map((e) => e.code)).toEqual(
      expect.arrayContaining(['host_forward_written', 'hosts_converged']),
    );
    expect(world.panelHosts[0]).toMatchObject({ uuid: created.uuid, address: THIRD_EDGE });
    // The intent moved with the Host: same Host, same owner, the flipped tuple.
    const flipped = (await listenerRow(t, listenerId)).host!;
    expect(flipped).toMatchObject({ state: 'present', uuid: created.uuid, ownership: 'fcp' });
    expect(flipped.intended).toEqual({
      ...created.intended,
      address: THIRD_EDGE,
      port: 443,
      sni: 'a.example',
      host: null,
    });
    // Why it matters: retiring the Host's name rewrites the Host from the intent
    // (address and port kept). It must write the address members are on now.
    await t.run((ctx) =>
      ctx.db.patch(listenerId, {
        tlsNames: [
          { name: 'a.example', status: 'retired', retiredAt: Date.now() },
          { name: 'b.example', status: 'active' },
        ],
      }),
    );
    expect(await t.query(internal.hostOps.resyncSniContext, { listenerId })).toMatchObject({
      kind: 'write',
      address: THIRD_EDGE,
      port: 443,
      sni: 'b.example',
    });
  });

  test('a Host create whose outcome is unknown parks the flip; the next pass discovers the Host and finishes', async () => {
    vi.useFakeTimers();
    const world = fakeWorld({ hostPresent: false });
    // The first POST dies after the backend created the row.
    let failedOnce = false;
    const inner = world.stub;
    const original = (
      globalThis.fetch as unknown as { getMockImplementation?: () => unknown }
    ).getMockImplementation?.() as ((...a: unknown[]) => Promise<Response>) | undefined;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL | Request, init: RequestInit = {}) => {
        const url =
          typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
        if (
          !failedOnce &&
          new URL(url).hostname === 'panel.example' &&
          new URL(url).pathname === '/api/hosts' &&
          (init.method ?? 'GET').toUpperCase() === 'POST'
        ) {
          failedOnce = true;
          // Let the backend do the create, then answer as if the connection dropped.
          await original!(input, init);
          return jsonRes({ message: 'gateway timeout' }, 504);
        }
        return original!(input, init);
      }),
    );
    void inner;
    const { t, relayId, listenerId, oldEdgeId } = await seed();
    await provisionSpare(t, relayId);
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: oldEdgeId,
    });
    await driveUntil(t, rotationId, 'host_flipping');
    // One pass: the create is claimed, the call "fails", the listener is parked.
    await t.action(internal.edgeRotations.step, { rotationId });
    expect((await listenerRow(t, listenerId)).host).toMatchObject({
      state: 'unresolved',
      op: { kind: 'create' },
    });
    expect((await t.query(internal.edgeRotations.get, { id: rotationId }))!.phase).toBe(
      'host_flipping',
    );
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect([r.phase, r.outcome]).toEqual(['done', 'published']);
    // Exactly one Host exists: discovery adopted the one the backend created,
    // it was never created twice.
    expect(world.creates()).toBe(1);
    expect(world.panelHosts).toHaveLength(1);
    expect((await listenerRow(t, listenerId)).host).toMatchObject({
      state: 'present',
      uuid: world.panelHosts[0].uuid,
      ownership: 'fcp',
    });
  });

  test('start guards: hostMode operator at the template edge, cooldown, daily cap (force bypasses all three)', async () => {
    fakeWorld();
    const { t, relayId, listenerId, oldEdgeId, accountId } = await seed();
    // A tested, managed spare so the replace guards (not the spare rule) are what refuse.
    await adoptL4Edge(t, relayId, listenerId, { ipv4: NEW_EDGE, accountId });
    // fcp → operator: FCP stops writing; a Host it knew becomes the operator's.
    await t.mutation(internal.relays.update, { id: relayId, hostMode: 'operator' });
    await expect(
      t.mutation(internal.edgeRotations.start, {
        relayId,
        kind: 'replace',
        trigger: 'manual',
        targetEdgeId: oldEdgeId,
      }),
    ).rejects.toThrow(/hosts_operator_managed|operator manages/);
    // operator → fcp needs every remark listener's Host adopted first.
    await expect(
      t.mutation(internal.relays.update, { id: relayId, hostMode: 'fcp' }),
    ).rejects.toThrow(/host_adopt_required/);
    await t.run((ctx) =>
      ctx.db.patch(listenerId, {
        host: { state: 'present', uuid: HOST_UUID, ownership: 'adopted' },
        updatedAt: Date.now(),
      }),
    );
    await t.mutation(internal.relays.update, { id: relayId, hostMode: 'fcp' });
    expect((await t.query(internal.relays.get, { id: relayId }))!.hostMode).toBe('fcp');
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

  test('hostMode operator: force replaces the template edge WITHOUT a Host write (the operator moves it)', async () => {
    vi.useFakeTimers();
    const world = fakeWorld();
    const { t, relayId, oldEdgeId } = await seed();
    await provisionSpare(t, relayId);
    await t.mutation(internal.relays.update, { id: relayId, hostMode: 'operator' });
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: oldEdgeId,
      force: true,
    });
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect([r.phase, r.outcome]).toEqual(['done', 'published']);
    expect(r.hostPlan).toEqual([]);
    expect(r.events.map((e) => e.code)).not.toContain('host_plan');
    expect(r.events.find((e) => e.code === 'published')?.detail).toMatch(/left to the operator/);
    expect(world.patches()).toBe(0);
    expect(world.creates()).toBe(0);
    expect(world.panelHosts[0].address).toBe(OLD_EDGE);
    expect((await t.query(internal.relays.get, { id: relayId }))!.publishedEdgeIds).toEqual([
      r.toEdgeId,
    ]);
  });

  test('cancel during provisioning stops the run and marks the new edge cancelled', async () => {
    vi.useFakeTimers();
    fakeWorld();
    const { t, relayId, oldEdgeId } = await seed();
    // Provisioning happens in a `provision` run (a replace switches to a tested spare).
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'provision',
      trigger: 'manual',
      publishOnDone: false,
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

describe('edgeRotations: hostMode none (no backend Host at all)', () => {
  test('a backend-server origin replaces its edge with no backend call whatsoever', async () => {
    vi.useFakeTimers();
    const world = fakeWorld();
    const t = convexTest(schema, modules);
    await insertPanelServer(t, { slug: 'panel-b' });
    await createAccount(t, { provider: 'upcloud', name: 'acct-u', qualified: true });
    const { relayId, listenerId } = await registerRelay(t, {
      slug: 'server-b',
      kind: 'backend-server',
      backendSlug: 'panel-b',
      originAddress: '203.0.113.20',
      listeners: [listenerU()],
    });
    const relay = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(relay.hostMode).toBe('none');
    // No backend binding on a whole-server origin: the listener matches by address.
    expect((await listenerRow(t, listenerId)).matchRule).toEqual({ kind: 'address' });
    const { edgeId: oldEdgeId } = await adoptL4Edge(t, relayId, listenerId, {
      ipv4: OLD_EDGE,
      publish: true,
    });
    await provisionSpare(t, relayId);
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: oldEdgeId,
    });
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect([r.phase, r.outcome]).toEqual(['done', 'published']);
    expect(r.hostPlan).toEqual([]);
    // No Host to flip: the publish goes straight to finalizing, no flip phase at all.
    const codes = r.events.map((e) => e.code);
    expect(codes).not.toContain('host_plan');
    expect(codes).not.toContain('host_forward_written');
    expect(r.hostPlanCaptured).toBe(false);
    expect(r.forwardWriteAttempted).toBe(false);
    expect(r.events.find((e) => e.code === 'published')?.detail).toMatch(/no backend Host/);
    expect(world.panelCalls()).toBe(0);
    expect((await t.query(internal.relays.get, { id: relayId }))!.publishedEdgeIds).toEqual([
      r.toEdgeId,
    ]);
    expect((await listenerRow(t, listenerId)).templateEdgeId).toBe(r.toEdgeId);
  });
});

describe('edgeRotations: per-listener template edges', () => {
  test('two listeners, two Hosts: replacing one re-plans ONLY its listener; the other Host is untouched', async () => {
    vi.useFakeTimers();
    const world = fakeWorld({
      extraHosts: [
        {
          uuid: SS_HOST_UUID,
          remark: 'node-one-relay-s',
          address: SS_OLD_EDGE,
          port: 8388,
          inbound: {
            configProfileUuid: FIXTURE_CONFIG_PROFILE,
            configProfileInboundUuid: SS_INBOUND,
          },
        },
      ],
    });
    const { t, relayId, listenerIds, oldEdgeId } = await seed({
      listeners: [listenerU(), shadowsocksListener()],
    });
    const ssListenerId = listenerIds.s;
    // The shadowsocks edge published at index 1 becomes ITS listener's template
    // (the first published edge bound to `s`), though it is not at index 0.
    const { edgeId: ssEdgeId, poolIndex } = await adoptL4Edge(t, relayId, ssListenerId, {
      ipv4: SS_OLD_EDGE,
      port: 8388,
      publish: true,
    });
    expect(poolIndex).toBe(1);
    expect((await listenerRow(t, listenerIds.u)).templateEdgeId).toBe(oldEdgeId);
    expect((await listenerRow(t, ssListenerId)).templateEdgeId).toBe(ssEdgeId);
    await provisionSpare(t, relayId, ssListenerId);

    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: ssEdgeId as Id<'edges'>,
    });
    expect((await t.query(internal.edgeRotations.get, { id: rotationId }))!.listenerId).toBe(
      ssListenerId,
    );
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect([r.phase, r.outcome]).toEqual(['done', 'published']);
    // Only the `s` listener was planned and flipped.
    expect(r.hostPlan).toEqual([
      expect.objectContaining({
        listenerKey: 's',
        uuid: SS_HOST_UUID,
        oldAddress: SS_OLD_EDGE,
        oldPort: 8388,
      }),
    ]);
    expect(r.previousBinding).toEqual({ edgeId: ssEdgeId, listenerId: ssListenerId, poolIndex: 1 });
    expect(world.patches()).toBe(1);
    const ssHost = world.panelHosts.find((h) => h.uuid === SS_HOST_UUID)!;
    const newEdge = (await t.query(internal.edges.get, { id: r.toEdgeId! }))!;
    expect(newEdge).toMatchObject({
      listenerId: ssListenerId,
      poolIndex: 1,
      publication: 'published',
    });
    expect(ssHost.address).toBe(NEW_EDGE);
    expect(ssHost.port).toBe(newEdge.listeners[0].edgePort);
    // Shadowsocks presents no name: the flip cleared nothing it did not own and
    // the REALITY listener's Host never moved.
    const uHost = world.panelHosts.find((h) => h.uuid === HOST_UUID)!;
    expect(uHost).toMatchObject({ address: OLD_EDGE, port: 443, sni: 'a.example' });
    // Per-listener template edges: `u` keeps its own, `s` follows the rotation.
    const pool = (await t.query(internal.relays.get, { id: relayId }))!.publishedEdgeIds;
    expect(pool).toEqual([oldEdgeId, r.toEdgeId]);
    expect((await listenerRow(t, listenerIds.u)).templateEdgeId).toBe(oldEdgeId);
    const ss = await listenerRow(t, ssListenerId);
    expect(ss.templateEdgeId).toBe(r.toEdgeId);
    expect(ss.host).toMatchObject({ state: 'present', uuid: SS_HOST_UUID, ownership: 'adopted' });
    expect((await listenerRow(t, listenerIds.u)).host?.state ?? 'absent').toBe('absent');
  });

  test('origins.refreshTemplateEdges: unpublish / drop / publish keep each listener pointing at its lowest published edge', async () => {
    fakeWorld();
    const { t, relayId, listenerIds, oldEdgeId } = await seed({
      listeners: [listenerU(), shadowsocksListener()],
    });
    const { edgeId: ssEdgeId } = await adoptL4Edge(t, relayId, listenerIds.s, {
      ipv4: SS_OLD_EDGE,
      port: 8388,
      publish: true,
    });
    // Unpublishing `u`'s only edge leaves that listener template-less; `s` is unaffected.
    await t.mutation(internal.relays.unpublishEdge, {
      relayId,
      edgeId: oldEdgeId,
      keepActive: true,
    });
    expect((await listenerRow(t, listenerIds.u)).templateEdgeId).toBeUndefined();
    expect((await listenerRow(t, listenerIds.s)).templateEdgeId).toBe(ssEdgeId);
    // Re-publishing it on a Host-managed origin is the rotation machine's job.
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId, edgeId: oldEdgeId }),
    ).rejects.toThrow(/needs_rotation/);
    // With no Host to flip (hostMode operator), the direct publish is allowed and the template follows.
    await t.mutation(internal.relays.update, { id: relayId, hostMode: 'operator' });
    await t.mutation(internal.relays.publishEdge, { relayId, edgeId: oldEdgeId });
    expect((await listenerRow(t, listenerIds.u)).templateEdgeId).toBe(oldEdgeId);
    // Dropping `s`'s edge clears `s`.
    await t.mutation(internal.relays.dropFromPool, {
      relayId,
      edgeId: ssEdgeId as Id<'edges'>,
      reason: 'test',
    });
    expect((await listenerRow(t, listenerIds.s)).templateEdgeId).toBeUndefined();
    expect((await listenerRow(t, listenerIds.u)).templateEdgeId).toBe(oldEdgeId);
  });
});

describe('edgeRotations: provision + publish kinds', () => {
  test('provision with publishOnDone fills the next free pool index (index 1, same listener: no Host flip)', async () => {
    vi.useFakeTimers();
    const world = fakeWorld();
    const { t, relayId, listenerId, oldEdgeId } = await seed();
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'provision',
      trigger: 'manual',
      publishOnDone: true,
    });
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    // A freshly provisioned L4 edge is never published untested: the run ends
    // with the edge as a spare (`unverified_standby`), nothing destroyed.
    expect(r.phase).toBe('done');
    expect(r.outcome).toBe('standby');
    expect(r.events.map((e) => e.code)).toContain('unverified_standby');
    let origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.publishedEdgeIds).toEqual([oldEdgeId]);
    expect(origin.standbyEdgeIds).toEqual([r.toEdgeId]);
    expect((await t.query(internal.edges.get, { id: r.toEdgeId! }))!).toMatchObject({
      status: 'active',
      publication: 'unpublished',
    });
    // Once the operator confirms it, a publish run fills the next free index.
    await verifyL4Edge(t, r.toEdgeId!);
    const pub = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'publish',
      trigger: 'manual',
      toEdgeId: r.toEdgeId!,
    });
    await drain(t, pub.rotationId);
    expect((await t.query(internal.edgeRotations.get, { id: pub.rotationId }))!.outcome).toBe(
      'published',
    );
    origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.publishedEdgeIds).toHaveLength(2);
    expect(origin.publishedEdgeIds[1]).toBe(r.toEdgeId);
    expect(origin.cooldownUntil).toBeUndefined(); // not a rotation
    expect(world.patches()).toBe(0);
    expect(world.creates()).toBe(0);
    // The listener's template stays the lower-index edge.
    expect((await listenerRow(t, listenerId)).templateEdgeId).toBe(oldEdgeId);
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

    // Untested, the spare does not count: the replace is refused, not provisioned.
    await expect(
      t.mutation(internal.edgeRotations.start, {
        relayId,
        kind: 'replace',
        trigger: 'manual',
        targetEdgeId: oldEdgeId,
      }),
    ).rejects.toThrow(/no_verified_spare/);
    await verifyL4Edge(t, r1.toEdgeId!);
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

  test('a publish the pool holds back ends a standby, and says so on the run and in the activity', async () => {
    vi.useFakeTimers();
    fakeWorld();
    // `u` is published; `s` has nothing, so the one free slot is held for it.
    const { t, relayId, listenerIds } = await seed({
      listeners: [listenerU(), shadowsocksListener()],
    });
    expect((await t.query(internal.relays.get, { id: relayId }))!.desiredPublished).toBe(2);
    const { edgeId: second } = await adoptL4Edge(t, relayId, listenerIds.u, { ipv4: NEW_EDGE });
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'publish',
      trigger: 'manual',
      toEdgeId: second,
    });
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect([r.phase, r.outcome]).toEqual(['done', 'standby']);
    expect(r.events.map((e) => e.code)).toContain('pool_reserved_standby');
    const origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.publishedEdgeIds.filter(Boolean)).toHaveLength(1);
    expect(origin.standbyEdgeIds).toContain(second);
    // The run says why it ended a standby; a plain published run says nothing.
    const admin = (await t.query(internal.edgeRotations.getForAdmin, { id: rotationId }))!;
    expect(admin.standbyReason).toBe('pool_reserved');
    expect(admin.audit.map((a) => a.action)).toContain('edge.publish_held');
    const held = (await t.run((ctx) => ctx.db.query('auditLog').collect())).find(
      (a) => a.action === 'edge.publish_held',
    );
    expect(held?.payload).toEqual({
      relaySlug: 'node-one',
      edgeId: second,
      code: 'pool_reserved',
      rotationId,
    });
    // The node's activity carries it.
    const timeline = await t.query(internal.edgeOperator.timeline, { relayId });
    expect(timeline.entries.map((e) => e.action)).toContain('edge.publish_held');
  });

  test('standbyReasonOf: only a standby outcome, from the last pool refusal event', () => {
    const ev = (code: string) => ({ at: 0, level: 'warn' as const, code });
    expect(standbyReasonOf({ outcome: 'standby', events: [ev('pool_full_standby')] })).toBe(
      'pool_full',
    );
    expect(standbyReasonOf({ outcome: 'standby', events: [ev('unverified_standby')] })).toBeNull();
    expect(
      standbyReasonOf({ outcome: 'published', events: [ev('pool_reserved_standby')] }),
    ).toBeNull();
  });

  test('selection fails cleanly when no qualified account exists for the listener', async () => {
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

describe('edgeRotations: recovery, guards and bounds', () => {
  /** A rotation parked in `rolling_back` with a captured plan; the caller sets the backend state. */
  async function rollingBackRow(
    t: ReturnType<typeof convexTest>,
    relayId: Id<'relays'>,
    listenerId: Id<'relayListeners'>,
    oldEdgeId: Id<'edges'>,
    extra: Record<string, unknown>,
    /** Absent = a LEGACY plan (no snapshot version): SNI/Host are unknown. */
    hostPlan: Array<Record<string, unknown>> = [
      { uuid: HOST_UUID, oldAddress: OLD_EDGE, oldPort: 443, inboundUuid: INBOUND },
    ],
  ) {
    const { edgeId: newEdgeId } = await adoptL4Edge(t, relayId, listenerId, { ipv4: NEW_EDGE });
    const now = Date.now();
    const rotationId = await t.run(async (ctx) => {
      const id = await ctx.db.insert('edgeRotations', {
        relayId,
        kind: 'replace',
        trigger: 'manual',
        burn: false,
        force: false,
        targetEdgeId: oldEdgeId,
        toEdgeId: newEdgeId,
        listenerId,
        viaStandby: true,
        phase: 'rolling_back',
        stepVersion: 7,
        cancelRequested: false,
        outcome: 'hosts_changed',
        hostPlan,
        hostPlanCaptured: true,
        previousBinding: { edgeId: oldEdgeId, listenerId, poolIndex: 0 },
        flipAttempts: 1,
        rollbackAttempts: 0,
        pollAttempts: 0,
        events: [],
        startedAt: now,
        updatedAt: now,
        ...extra,
      } as never);
      await ctx.db.patch(relayId, { activeRotationId: id, updatedAt: now });
      // The pool already says "new edge at index 0" (the publish landed).
      await ctx.db.patch(oldEdgeId, {
        publication: 'draining',
        status: 'draining',
        poolIndex: undefined,
        drainUntil: now + 60_000,
        updatedAt: now,
      });
      await ctx.db.patch(newEdgeId, { publication: 'published', poolIndex: 0, updatedAt: now });
      await ctx.db.patch(relayId, { publishedEdgeIds: [newEdgeId], updatedAt: now });
      await ctx.scheduler.runAfter(0, internal.edgeRotations.step, { rotationId: id });
      await ctx.db.patch(id, { nextStepAt: now });
      return id;
    });
    return { rotationId, newEdgeId };
  }

  test('rollback after a forward PATCH that landed but never settled re-observes the backend and writes the old address back', async () => {
    vi.useFakeTimers();
    const world = fakeWorld();
    const { t, relayId, listenerId, oldEdgeId } = await seed();
    // The PATCH reached the backend (Host now points at the new edge)...
    world.panelHosts[0].address = NEW_EDGE;
    // ...but the action died before settling: no flippedAt, no success event,
    // only the claim-time flag says a write was attempted.
    const { rotationId } = await rollingBackRow(t, relayId, listenerId, oldEdgeId, {
      forwardWriteAttempted: true,
    });
    // A cancel during the rollback is recorded, not honoured.
    const cancel = await t.mutation(internal.edgeRotations.requestCancel, { rotationId });
    expect(cancel).toMatchObject({ ok: true, phase: 'rolling_back', deferred: true });
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(r.phase).toBe('rolled_back');
    expect(r.events.map((e) => e.code)).toContain('cancel_requested');
    // The backend and the DB agree on the previous binding again.
    expect(world.panelHosts[0].address).toBe(OLD_EDGE);
    expect(world.patches()).toBe(1);
    const origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.publishedEdgeIds).toEqual([oldEdgeId]);
    expect(origin.activeRotationId).toBeUndefined();
    expect((await listenerRow(t, listenerId)).templateEdgeId).toBe(oldEdgeId);
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.find((a) => a.action === 'admin.edge.cancel')?.payload).toMatchObject({
      deferred: true,
    });
  });

  test('legacy rows without the flag still take the "nothing written" shortcut (event inference)', async () => {
    vi.useFakeTimers();
    const world = fakeWorld();
    const { t, relayId, listenerId, oldEdgeId } = await seed();
    const { rotationId } = await rollingBackRow(t, relayId, listenerId, oldEdgeId, {});
    await drain(t, rotationId);
    expect((await t.query(internal.edgeRotations.get, { id: rotationId }))!.phase).toBe(
      'rolled_back',
    );
    expect(world.patches()).toBe(0);
  });

  test('a LEGACY plan restores address and port ONLY: unknown is never written as a clear', async () => {
    vi.useFakeTimers();
    const world = fakeWorld();
    const { t, relayId, listenerId, oldEdgeId } = await seed();
    // The backend holds the new edge (the forward PATCH landed) with a name the
    // operator, not FCP, put there.
    world.panelHosts[0].address = NEW_EDGE;
    world.panelHosts[0].sni = 'operator.example';
    await setHostIntent(t, listenerId, { address: NEW_EDGE, sni: 'operator.example' });
    const { rotationId } = await rollingBackRow(
      t,
      relayId,
      listenerId,
      oldEdgeId,
      { forwardWriteAttempted: true },
      // A rotation captured before the full-tuple snapshot existed.
      [{ uuid: HOST_UUID, oldAddress: OLD_EDGE, oldPort: 443, inboundUuid: INBOUND }],
    );
    await drain(t, rotationId);
    expect((await t.query(internal.edgeRotations.get, { id: rotationId }))!.phase).toBe(
      'rolled_back',
    );
    expect(world.panelHosts[0].address).toBe(OLD_EDGE);
    // The name the plan knows nothing about is untouched.
    expect(world.panelHosts[0].sni).toBe('operator.example');
    // The intent follows the Host back: the address, with the unknown name kept.
    expect((await listenerRow(t, listenerId)).host!.intended).toMatchObject({
      address: OLD_EDGE,
      port: 443,
      sni: 'operator.example',
    });
  });

  test('a version-2 plan restores the WHOLE tuple, clears included (an L7 flip rolled back)', async () => {
    vi.useFakeTimers();
    const world = fakeWorld();
    const { t, relayId, listenerId, oldEdgeId } = await seed();
    // The flip had pointed the Host at a CDN hostname: address, SNI and Host.
    world.panelHosts[0].address = 'front.example.org';
    world.panelHosts[0].sni = 'front.example.org';
    world.panelHosts[0].host = 'front.example.org';
    // The flip had converged, so the listener's intent followed it to the front.
    await setHostIntent(t, listenerId, {
      address: 'front.example.org',
      sni: 'front.example.org',
      host: 'front.example.org',
    });
    const { rotationId } = await rollingBackRow(
      t,
      relayId,
      listenerId,
      oldEdgeId,
      { forwardWriteAttempted: true },
      [
        {
          listenerKey: 'u',
          uuid: HOST_UUID,
          oldAddress: OLD_EDGE,
          oldPort: 443,
          inboundUuid: INBOUND,
          snapshotVersion: 2,
          oldSni: 'a.example',
          // The previous L4 binding carried no Host header: restoring it means
          // CLEARING the CDN hostname, not leaving it behind.
          oldHost: null,
        },
      ],
    );
    await drain(t, rotationId);
    expect((await t.query(internal.edgeRotations.get, { id: rotationId }))!.phase).toBe(
      'rolled_back',
    );
    expect(world.panelHosts[0]).toMatchObject({
      address: OLD_EDGE,
      port: 443,
      sni: 'a.example',
      host: '',
    });
    // The intent is the restored tuple again, the cleared Host header included.
    expect((await listenerRow(t, listenerId)).host!.intended).toMatchObject({
      address: OLD_EDGE,
      port: 443,
      sni: 'a.example',
      host: null,
    });
  });

  test('a running rotation blocks every other pool writer and a hostMode change', async () => {
    // The clock stands still, so the run stays where `start` left it. On real
    // timers it advances while the writers below are tried, and how far it gets
    // (past cancellation, or done) depends on which modules earlier tests loaded.
    vi.useFakeTimers();
    fakeWorld();
    const { t, relayId, listenerId, oldEdgeId, accountId } = await seed();
    // A tested, managed spare: what the replace will switch to.
    const { edgeId: standby } = await adoptL4Edge(t, relayId, listenerId, {
      ipv4: NEW_EDGE,
      accountId,
    });
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: oldEdgeId,
    });
    await expectPoolWritersRefused(t, relayId, listenerId, standby, /rotation is running/);
    await expect(
      t.mutation(internal.relays.update, { id: relayId, hostMode: 'operator' }),
    ).rejects.toThrow(/rotation/);
    // Listener writes are pool writes too.
    await expect(
      t.mutation(internal.relayListeners.setEnabled, { id: listenerId, enabled: false }),
    ).rejects.toThrow(/rotation/);
    // Other origin edits are fine.
    await t.mutation(internal.relays.update, { id: relayId, probeNode: true });
    await t.mutation(internal.edgeRotations.requestCancel, { rotationId });
  });

  test('hostMode handed to the operator mid-rotation fails the replace with a rollback instead of "converging"', async () => {
    vi.useFakeTimers();
    const world = fakeWorld();
    const { t, relayId, oldEdgeId } = await seed();
    await provisionSpare(t, relayId);
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: oldEdgeId,
    });
    await driveUntil(t, rotationId, 'host_flipping');
    await t.run((ctx) => ctx.db.patch(relayId, { hostMode: 'operator' }));
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(r.phase).toBe('rolled_back');
    expect(r.outcome).toBe('hosts_operator_managed');
    expect(world.patches()).toBe(0);
    const origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.publishedEdgeIds).toEqual([oldEdgeId]);
  });

  test('a standby provision is finalized even when its listener was disabled mid-run', async () => {
    vi.useFakeTimers();
    fakeWorld();
    const { t, relayId, listenerId } = await seed();
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'provision',
      trigger: 'manual',
      publishOnDone: false,
    });
    await driveUntil(t, rotationId, 'provisioning');
    // The listener MUTATION is refused while a rotation runs (docs/edges.md), so
    // the row is patched directly: the point of this test is that the run
    // survives observing a disabled listener, whatever put it there.
    await expect(
      t.mutation(internal.relayListeners.setEnabled, { id: listenerId, enabled: false }),
    ).rejects.toThrow(/rotation_running/);
    await t.run((ctx) => ctx.db.patch(listenerId, { enabled: false }));
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(r.phase).toBe('done');
    expect(r.outcome).toBe('standby');
    const edge = (await t.query(internal.edges.get, { id: r.toEdgeId! }))!;
    expect(edge).toMatchObject({ status: 'active', publication: 'unpublished' });
    const origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.standbyEdgeIds).toEqual([r.toEdgeId]);
  });

  test('a requested listener that is retired fails the run (listener_not_found) instead of picking another', async () => {
    vi.useFakeTimers();
    fakeWorld();
    const { t, relayId, listenerId } = await seed();
    // A second, healthy listener the picker would otherwise fall back to.
    await t.mutation(internal.relayListeners.upsert, {
      relayId,
      spec: listenerU({
        listenerKey: 'v',
        originPort: 8443,
        panelBinding: {
          inboundTag: 'VLESS_RELAY_V',
          configProfileUuid: FIXTURE_CONFIG_PROFILE,
          configProfileInboundUuid: SS_INBOUND,
        },
      }) as never,
    });
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'provision',
      trigger: 'manual',
      publishOnDone: false,
      listenerId,
    });
    expect((await t.query(internal.edgeRotations.get, { id: rotationId }))!.listenerId).toBe(
      listenerId,
    );
    // Retire it between start and select.
    await t.run((ctx) => ctx.db.patch(listenerId, { retired: true, updatedAt: Date.now() }));
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(r.phase).toBe('failed');
    expect(r.outcome).toBe('listener_not_found');
    expect(r.toEdgeId).toBeUndefined();
    // And a start naming a retired listener is refused outright.
    await expect(
      t.mutation(internal.edgeRotations.start, {
        relayId,
        kind: 'provision',
        trigger: 'manual',
        listenerId,
      }),
    ).rejects.toThrow(/listener_not_found|retired/);
  });

  test('a start naming a listener that is disabled, undeployed or nameless is refused (listener_unusable)', async () => {
    fakeWorld();
    const { t, relayId, listenerId } = await seed();
    const start = () =>
      t.mutation(internal.edgeRotations.start, {
        relayId,
        kind: 'provision',
        trigger: 'manual',
        listenerId,
      });
    await t.run((ctx) => ctx.db.patch(listenerId, { enabled: false }));
    await expect(start()).rejects.toThrow(/listener_unusable/);
    await t.run((ctx) => ctx.db.patch(listenerId, { enabled: true, deployed: false }));
    await expect(start()).rejects.toThrow(/listener_unusable/);
    // A REALITY listener behind an L4 forwarder needs one of its own names.
    await t.run((ctx) =>
      ctx.db.patch(listenerId, {
        deployed: true,
        tlsNames: [{ name: 'a.example', status: 'retired', retiredAt: Date.now() }],
      }),
    );
    await expect(start()).rejects.toThrow(/listener_unusable/);
    await t.run((ctx) =>
      ctx.db.patch(listenerId, { tlsNames: [{ name: 'a.example', status: 'active' }] }),
    );
    const { rotationId } = await start();
    await t.mutation(internal.edgeRotations.requestCancel, { rotationId });
  });

  test('wall-clock cap: an over-long flip rolls back; a confirming run past the cap quarantines', async () => {
    vi.useFakeTimers();
    const world = fakeWorld();
    const { t, relayId, oldEdgeId } = await seed();
    await provisionSpare(t, relayId);
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: oldEdgeId,
    });
    await driveUntil(t, rotationId, 'host_flipping');
    await t.run((ctx) => ctx.db.patch(rotationId, { startedAt: Date.now() - 3 * 3600_000 }));
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(r.phase).toBe('rolled_back');
    expect(r.outcome).toBe('rotation_timeout');
    expect(world.patches()).toBe(0);
    expect((await t.query(internal.relays.get, { id: relayId }))!.publishedEdgeIds).toEqual([
      oldEdgeId,
    ]);

    // Second run: reach confirming, then exhaust the step-error budget.
    const second = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: oldEdgeId,
      force: true,
    });
    await driveUntil(t, second.rotationId, 'confirming');
    await t.run((ctx) => ctx.db.patch(second.rotationId, { stepErrors: MAX_STEP_ERRORS }));
    await drain(t, second.rotationId);
    const r2 = (await t.query(internal.edgeRotations.get, { id: second.rotationId }))!;
    expect(r2.phase).toBe('quarantined');
    const origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.quarantine?.reason).toMatch(/step_errors_exhausted during confirming/);
  });

  test('an unexpected step throw is counted on the row (stepErrors)', async () => {
    fakeWorld();
    const { t, relayId } = await seed();
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'provision',
      trigger: 'manual',
    });
    const before = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    await t.mutation(internal.edgeRotations.advance, {
      rotationId,
      stepVersion: before.stepVersion,
      event: { type: 'progress', delayMs: 0, detail: 'step error: boom', countError: true },
    });
    const after = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(after.stepErrors).toBe(1);
    expect(after.stepVersion).toBe(before.stepVersion + 1);
    await t.mutation(internal.edgeRotations.requestCancel, { rotationId });
  });

  test('rekick fences the stale actor: the step version bumps and its later write is ignored', async () => {
    fakeWorld();
    const { t, relayId } = await seed();
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'provision',
      trigger: 'manual',
    });
    const before = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    await t.mutation(internal.edgeRotations.rekick, { rotationId });
    const after = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(after.stepVersion).toBe(before.stepVersion + 1);
    expect(after.events.map((e) => e.code)).toContain('rekicked');
    // The actor that read the old version gets nothing through.
    const stale = await t.mutation(internal.edgeRotations.advance, {
      rotationId,
      stepVersion: before.stepVersion,
      event: { type: 'fail', code: 'stale_actor', rollback: false },
    });
    expect(stale).toEqual({ ok: false });
    expect((await t.query(internal.edgeRotations.get, { id: rotationId }))!.phase).toBe('select');
    await t.mutation(internal.edgeRotations.requestCancel, { rotationId });
  });

  test('isStaleRotation: scheduled-not-started vs started-and-hung', () => {
    const now = 10_000_000;
    // Scheduled long ago, never started → stale.
    expect(isStaleRotation({ nextStepAt: now - 120_000, stepStartedAt: undefined }, now)).toBe(
      true,
    );
    // Scheduled long ago, but the step started recently → running, not stale.
    expect(isStaleRotation({ nextStepAt: now - 120_000, stepStartedAt: now - 5_000 }, now)).toBe(
      false,
    );
    // Started, but too long ago → the action died → stale.
    expect(
      isStaleRotation({ nextStepAt: now - 20 * 60_000, stepStartedAt: now - 15 * 60_000 }, now),
    ).toBe(true);
    // A start that predates the schedule belongs to the previous step → not started.
    expect(isStaleRotation({ nextStepAt: now - 120_000, stepStartedAt: now - 130_000 }, now)).toBe(
      true,
    );
    // Within grace → never stale.
    expect(isStaleRotation({ nextStepAt: now - 1_000, stepStartedAt: undefined }, now)).toBe(false);
  });

  test('template changed before any provider call: the run fails and the allocation is refunded', async () => {
    vi.useFakeTimers();
    fakeWorld();
    const { t, relayId, accountId } = await seed();
    const { id: templateId } = await t.mutation(internal.edgeTemplates.create, {
      provider: 'upcloud',
      name: 'tpl-u',
      params: {},
      accountId,
      isDefault: true,
    });
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'provision',
      trigger: 'manual',
    });
    await driveUntil(t, rotationId, 'provisioning');
    expect((await t.run((ctx) => ctx.db.get(accountId)))!.allocationsToday).toBe(1);
    await t.mutation(internal.edgeTemplates.update, {
      id: templateId,
      params: { plan: 'production-small' },
    });
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(r.phase).toBe('failed');
    expect(r.outcome).toBe('template_changed');
    expect(r.events.map((e) => e.code)).toContain('allocation_refunded');
    expect((await t.run((ctx) => ctx.db.get(accountId)))!.allocationsToday).toBe(0);
  });

  test('keep:current at resolve time re-checks publishability of the new edge', async () => {
    vi.useFakeTimers();
    fakeWorld({ vanishAfterFirstPatch: true });
    const { t, relayId, listenerId, oldEdgeId } = await seed();
    await provisionSpare(t, relayId);
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: oldEdgeId,
    });
    await drain(t, rotationId);
    expect((await t.query(internal.edgeRotations.get, { id: rotationId }))!.phase).toBe(
      'quarantined',
    );
    // Nothing bypasses a quarantine, listener writes included, so the row is
    // patched directly to put the edge in the state the resolve must refuse.
    await expect(
      t.mutation(internal.relayListeners.setEnabled, { id: listenerId, enabled: false }),
    ).rejects.toThrow(/quarantined/);
    await t.run((ctx) => ctx.db.patch(listenerId, { enabled: false }));
    await expect(
      t.mutation(internal.edgeRotations.resolveQuarantine, { relayId, keep: 'current' }),
    ).rejects.toThrow(/listener_disabled/);
    await t.run((ctx) => ctx.db.patch(listenerId, { enabled: true }));
    await t.mutation(internal.edgeRotations.resolveQuarantine, { relayId, keep: 'current' });
    expect((await t.query(internal.relays.get, { id: relayId }))!.quarantine).toBeUndefined();
  });

  test('publishStandby goes through the start guards: the concurrency cap holds and the run is audited as a publish', async () => {
    fakeWorld();
    const { t, relayId, listenerId } = await seed();
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.enabled', 'true'));
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.maxConcurrentRotations', '1'));
    // Free the listener's template index on a Host-managed origin + a publishable standby.
    await t.mutation(internal.relays.unpublishEdge, {
      relayId,
      edgeId: (await t.query(internal.relays.get, { id: relayId }))!.publishedEdgeIds[0]!,
      keepActive: true,
    });
    const { edgeId: standby } = await adoptL4Edge(t, relayId, listenerId, { ipv4: NEW_EDGE });
    // Another origin already holds the single allowed rotation.
    const { relayId: other } = await registerRelay(t, {
      slug: 'node-two',
      nodeName: 'node-two',
      originAddress: '203.0.113.11',
      listeners: [
        listenerU({
          panelBinding: {
            inboundTag: 'VLESS_RELAY_U',
            configProfileUuid: FIXTURE_CONFIG_PROFILE,
            configProfileInboundUuid: '55555555-5555-4555-8555-555555555555',
          },
        }),
      ],
    });
    const busy = await t.mutation(internal.edgeRotations.start, {
      relayId: other,
      kind: 'provision',
      trigger: 'manual',
    });
    const blocked = await t.mutation(internal.edgeReconcileMutations.publishStandby, {
      relayId,
      candidates: [standby],
    });
    expect(blocked).toEqual({ published: false, rotationId: null, awaitingVerification: false });
    await t.mutation(internal.edgeRotations.requestCancel, { rotationId: busy.rotationId });
    await t.run((ctx) =>
      ctx.db.patch(busy.rotationId, { phase: 'cancelled', finishedAt: Date.now() }),
    );
    const started = await t.mutation(internal.edgeReconcileMutations.publishStandby, {
      relayId,
      candidates: [standby],
    });
    expect(started.published).toBe(false);
    expect(started.rotationId).not.toBeNull();
    const rot = (await t.query(internal.edgeRotations.get, { id: started.rotationId! }))!;
    expect(rot).toMatchObject({
      kind: 'publish',
      trigger: 'reconcile',
      toEdgeId: standby,
      listenerId,
    });
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.find((a) => a.action === 'admin.edge.publish')?.payload).toMatchObject({
      slug: 'node-one',
      trigger: 'reconcile',
      rotationId: started.rotationId,
      edgeId: standby,
    });
  });
});

describe('edgeRotations: a test block drives the real automatic replace', () => {
  test('simulated block → detector suspects → burn onto the tested spare, consumed with the start, burned drain, epoch +1', async () => {
    vi.useFakeTimers();
    vi.stubEnv('EDGE_SIMULATOR_ALLOW', 'simulate-blocks');
    fakeWorld();
    try {
      const { t, relayId, oldEdgeId } = await seed();
      const spare = await provisionSpare(t, relayId);
      await t.run(async (ctx) => {
        await upsertSettingRow(ctx, 'edge.enabled', 'true');
        await upsertSettingRow(ctx, 'edge.autoRotate', 'true');
        await upsertSettingRow(ctx, 'edge.probe.enabled', 'true');
        await ctx.db.patch(relayId, { autoRotate: true });
      });
      const before = (await t.query(internal.relays.get, { id: relayId }))!;
      const { simulationId } = await t.mutation(internal.edgeSimulations.start, {
        edgeId: oldEdgeId,
        country: 'IR',
      });
      expect((await t.action(internal.edgeDetector.run, {})).rotated).toBe(1);
      const rotationId = (await t.query(internal.relays.get, { id: relayId }))!.activeRotationId!;
      expect(await t.query(internal.edgeRotations.get, { id: rotationId })).toMatchObject({
        trigger: 'detector',
        burn: true,
        targetEdgeId: oldEdgeId,
        simulationId,
        affectedCountries: ['IR'],
      });
      await drain(t, rotationId);
      const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
      expect([r.phase, r.outcome, r.toEdgeId]).toEqual(['done', 'published', spare]);
      const after = (await t.query(internal.relays.get, { id: relayId }))!;
      expect(after.publishedEdgeIds[0]).toBe(spare);
      expect(after.publicationEpoch).toBeGreaterThan(before.publicationEpoch);
      const cfg = await t.run((ctx) => resolveEdgeConfig(ctx.db));
      const old = (await t.run((ctx) => ctx.db.get(oldEdgeId)))!;
      expect(old.burnedAt).toBeDefined();
      expect(old.drainUntil! - r.finishedAt!).toBeGreaterThanOrEqual(
        cfg.burnedDrainMinutes * 60_000 - 1_000,
      );
      expect(old.drainUntil! - r.finishedAt!).toBeLessThanOrEqual(
        cfg.burnedDrainMinutes * 60_000 + 1_000,
      );
      expect(
        await t.run((ctx) => ctx.db.get(simulationId as Id<'edgeBlockSimulations'>)),
      ).toMatchObject({ endReason: 'consumed', rotationId });
    } finally {
      vi.unstubAllEnvs();
    }
  });
});

describe('edgeRotations: per-country checks before a replacement goes out', () => {
  /** A settled round for an edge: IR working or failing from three networks, controls working. */
  async function landRound(
    t: ReturnType<typeof convexTest>,
    edgeId: Id<'edges'>,
    ir: 'ok' | 'fail',
  ) {
    await t.run(async (ctx) => {
      const edge = (await ctx.db.get(edgeId))!;
      const now = Date.now();
      const base = {
        targetKind: 'edge' as const,
        targetRef: edgeId as string,
        target: `${edge.addresses.v4}:${edge.listeners[0]!.edgePort}`,
        port: edge.listeners[0]!.edgePort,
        ipVersion: 4 as const,
        addressKind: 'ip' as const,
        requestedFamily: 4 as const,
        status: 'finished' as const,
        trigger: 'qualification' as const,
        requestedAt: now,
        finishedAt: now,
        roundId: `edge:${edgeId}:${now}`,
      };
      await ctx.db.insert('probeRuns', {
        ...base,
        source: 'globalping',
        probeProtocol: 'tcp',
        controls: ['DE', 'US'],
        results: [
          ...[1, 2, 3].map((k) => ({
            country: 'IR',
            asn: `AS${k}`,
            vantageClass: 'eyeball' as const,
            ok: ir === 'ok',
          })),
          ...['DE', 'US'].map((country) => ({
            country,
            asn: `AS9${country}`,
            vantageClass: 'eyeball' as const,
            ok: true,
            control: true,
          })),
        ],
      });
      await ctx.db.insert('probeRuns', {
        ...base,
        source: 'internal',
        probeProtocol: 'tls-sni',
        results: [{ country: 'XX', vantageClass: 'datacenter' as const, ok: true }],
      });
    });
  }

  async function detectorReplace(ir: 'ok' | 'fail') {
    vi.useFakeTimers();
    vi.stubEnv('EDGE_SIMULATOR_ALLOW', 'simulate-blocks');
    fakeWorld();
    const { t, relayId, oldEdgeId } = await seed();
    const spare = await provisionSpare(t, relayId);
    await t.run(async (ctx) => {
      await upsertSettingRow(ctx, 'edge.enabled', 'true');
      await upsertSettingRow(ctx, 'edge.autoRotate', 'true');
      await upsertSettingRow(ctx, 'edge.probe.enabled', 'true');
      await upsertSettingRow(ctx, 'edge.country.enabled', 'true');
      await ctx.db.patch(relayId, { autoRotate: true });
    });
    await t.mutation(internal.edgeSimulations.start, { edgeId: oldEdgeId, country: 'IR' });
    expect((await t.action(internal.edgeDetector.run, {})).rotated).toBe(1);
    const rotationId = (await t.query(internal.relays.get, { id: relayId }))!.activeRotationId!;
    // The spare's first round since the replacement started.
    await landRound(t, spare, ir);
    await drain(t, rotationId);
    return {
      t,
      relayId,
      oldEdgeId,
      spare,
      r: (await t.query(internal.edgeRotations.get, { id: rotationId }))!,
    };
  }

  test('a detector replacement blocked in a country that triggered it fails and leaves the pool alone', async () => {
    try {
      const { t, relayId, oldEdgeId, r } = await detectorReplace('fail');
      expect(r.outcome).toBe('replacement_blocked');
      expect(JSON.stringify(r.events)).toContain('replacement_blocked');
      expect(r.events.find((e) => e.code === 'replacement_blocked')?.detail).toBe('IR');
      const origin = (await t.query(internal.relays.get, { id: relayId }))!;
      expect(origin.publishedEdgeIds[0]).toBe(oldEdgeId);
    } finally {
      vi.unstubAllEnvs();
    }
  });

  test('a replacement that works from there goes out as before', async () => {
    try {
      const { t, relayId, spare, r } = await detectorReplace('ok');
      expect([r.phase, r.outcome, r.toEdgeId]).toEqual(['done', 'published', spare]);
      expect((await t.query(internal.relays.get, { id: relayId }))!.publishedEdgeIds[0]).toBe(
        spare,
      );
    } finally {
      vi.unstubAllEnvs();
    }
  });
});

describe('edgeRotations: delivery by country holds a block it already routes around', () => {
  test('steer on: a test block on an edge blocked in IR, beside a published edge that is not, is vetoed country_scoped', async () => {
    vi.useFakeTimers();
    vi.stubEnv('EDGE_SIMULATOR_ALLOW', 'simulate-blocks');
    fakeWorld();
    try {
      const { t, relayId, oldEdgeId } = await seed();
      const spare = await provisionSpare(t, relayId);
      await t.run(async (ctx) => {
        await upsertSettingRow(ctx, 'edge.enabled', 'true');
        await upsertSettingRow(ctx, 'edge.autoRotate', 'true');
        await upsertSettingRow(ctx, 'edge.probe.enabled', 'true');
        await ctx.db.patch(relayId, { autoRotate: true, desiredPublished: 2 });
      });
      // A second published edge on the same listener, not blocked in IR.
      await t.mutation(internal.relays.publishEdge, { relayId, edgeId: spare, poolIndex: 1 });
      await t.run(async (ctx) => {
        await ctx.db.patch(oldEdgeId, {
          countryState: {
            byCountry: [{ country: 'IR', state: 'blocked', from: 'mark' }],
            updatedAt: Date.now(),
          },
        });
      });
      // Members' bodies are rendered (steering orders what is rendered), and the
      // listener's transport is a freedom-family mode's (only those are steered).
      await t.run(async (ctx) => {
        await upsertSettingRow(ctx, 'edge.render.enabled', 'true');
        const relay = (await ctx.db.get(relayId))!;
        const listener = (
          await ctx.db
            .query('relayListeners')
            .withIndex('by_relay', (q) => q.eq('relayId', relayId))
            .collect()
        )[0]!;
        let setup = await ctx.db
          .query('panelSetups')
          .withIndex('by_server', (q) => q.eq('backendServerId', relay.backendServerId!))
          .unique();
        if (!setup) {
          const now = Date.now();
          await ctx.db.insert('panelSetups', {
            backendServerId: relay.backendServerId!,
            desired: '{}',
            desiredHash: 'fixture',
            generation: 1,
            state: 'ready',
            profileName: 'FreeSocks-Config',
            modes: [],
            templates: [],
            originDns: null,
            adopted: false,
            gateVersion: 0,
            createdAt: now,
            updatedAt: now,
          });
          setup = await ctx.db
            .query('panelSetups')
            .withIndex('by_server', (q) => q.eq('backendServerId', relay.backendServerId!))
            .unique();
        }
        await ctx.db.patch(setup!._id, {
          modes: [
            {
              slug: 'freedom-reality',
              name: 'Freedom',
              shape: { transport: 'reality', fronting: 'edge-l4' },
              acceptProxyProtocol: false,
              tag: listener.panelBinding!.inboundTag,
              placement: 'bound',
              family: 'none',
            },
          ],
        });
      });
      // Long enough to outlast the steering's settle time below.
      await t.mutation(internal.edgeSimulations.start, {
        edgeId: oldEdgeId,
        country: 'IR',
        minutes: 180,
      });
      const veto = async () =>
        (await t.query(internal.relays.get, { id: relayId }))!.suspicion?.veto;
      // Steering off: the block is acted on as before (no spare is left, so the
      // start is refused, but nothing vetoes it).
      await t.run((ctx) => upsertSettingRow(ctx, 'delivery.country.steer', 'false'));
      await t.action(internal.edgeDetector.run, {});
      expect(await veto()).toBeNull();
      // Steering just turned on: members still hold the old order for one
      // refresh interval, so nothing is vetoed yet.
      await t.run((ctx) => upsertSettingRow(ctx, 'delivery.country.steer', 'true'));
      await t.mutation(internal.edgeRender.steeringChanged, { on: true });
      await t.action(internal.edgeDetector.run, {});
      expect(await veto()).toBeNull();
      // One refresh interval later members in IR already get the other edge; nothing is burned.
      vi.setSystemTime(Date.now() + 71 * 60_000);
      expect((await t.action(internal.edgeDetector.run, {})).rotated).toBe(0);
      const origin = (await t.query(internal.relays.get, { id: relayId }))!;
      expect(origin.suspicion?.veto).toBe('country_scoped');
      expect(origin.activeRotationId).toBeUndefined();
    } finally {
      vi.unstubAllEnvs();
    }
  });
});

describe('edgeRotations: a provision step that keeps failing', () => {
  /**
   * UpCloud where the load balancer is created but the floating IP never is
   * (a 500 on every allocation, and no floating IP to discover), plus a backend
   * with no Hosts. Records every LB create and every delete.
   */
  function ipNeverAllocates() {
    const lbs = new Map<string, { uuid: string; name: string; operational_state: string }>();
    const deletes: string[] = [];
    let lbCreates = 0;
    mockFetch((c) => {
      if (new URL(c.url).hostname === 'panel.example') {
        if (c.path === '/api/hosts' && c.method === 'GET') return jsonRes({ response: [] });
        return jsonRes({ message: 'not found' }, 404);
      }
      if (c.path === '/1.3/load-balancer' && c.method === 'POST') {
        lbCreates++;
        const uuid = `lb-${lbCreates}`;
        lbs.set(uuid, {
          uuid,
          name: (c.body as { name: string }).name,
          operational_state: 'running',
        });
        return jsonRes(lbs.get(uuid));
      }
      if (c.path === '/1.3/load-balancer' && c.method === 'GET') return jsonRes([...lbs.values()]);
      if (c.path === '/1.3/ip_address' && c.method === 'POST')
        return jsonRes({ error: { error_code: 'INTERNAL_ERROR' } }, 500);
      if (c.path === '/1.3/ip_address' && c.method === 'GET')
        return jsonRes({ ip_addresses: { ip_address: [] } });
      const one = c.path.match(/^\/1\.3\/load-balancer\/([^/]+)$/);
      if (one && c.method === 'GET') {
        const lb = lbs.get(one[1]);
        return lb ? jsonRes(lb) : jsonRes({ error: { error_code: 'LB_NOT_FOUND' } }, 404);
      }
      if (one && c.method === 'DELETE') {
        if (!lbs.has(one[1])) return jsonRes({ error: { error_code: 'LB_NOT_FOUND' } }, 404);
        lbs.delete(one[1]);
        deletes.push(one[1]);
        return new Response(null, { status: 204 });
      }
      return jsonRes({ message: 'not found' }, 404);
    });
    return { lbs, deletes, lbCreates: () => lbCreates };
  }

  /** backend-a + a qualified UpCloud account + origin node-one with listener `u`, nothing published. */
  async function bareSeed() {
    const t = convexTest(schema, modules);
    await insertPanelServer(t);
    await createAccount(t, { provider: 'upcloud', name: 'acct-u', qualified: true });
    const { relayId } = await registerRelay(t, { listeners: [listenerU()] });
    return { t, relayId };
  }

  test('retries exhausted after the load balancer was built: the failed edge is destroyed with it', async () => {
    vi.useFakeTimers();
    const w = ipNeverAllocates();
    const { t, relayId } = await bareSeed();
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'provision',
      trigger: 'manual',
      publishOnDone: false,
    });
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(r.phase).toBe('failed');
    expect(r.outcome).toBe('step_retries_exhausted');
    const failed = (await t.query(internal.edges.get, { id: r.toEdgeId! }))!;
    expect(failed.status).toBe('failed');
    expect(failed.resources.map((x) => x.resourceId)).toEqual(['lb-1']);
    // Nothing exists for the step that never succeeded, so nothing holds the
    // edge back from the destroy walk: the load balancer it paid for goes.
    expect(failed.steps.find((s) => s.stepId === 'ip')!.state).toBe('pending');
    for (let i = 0; i < 3; i++) {
      await vi.advanceTimersByTimeAsync(6 * 60_000);
      await t.action(internal.edgeReconcile.run, {});
    }
    expect(w.deletes).toEqual(['lb-1']);
    expect((await t.query(internal.edges.get, { id: r.toEdgeId! }))!.status).toBe('destroyed');
  });

  test('a create the provider refuses for good ends the run at once, with its words, and is never sent again', async () => {
    vi.useFakeTimers();
    let lbCreates = 0;
    mockFetch((c) => {
      if (new URL(c.url).hostname === 'panel.example') {
        if (c.path === '/api/hosts' && c.method === 'GET') return jsonRes({ response: [] });
        return jsonRes({ message: 'not found' }, 404);
      }
      if (c.path === '/1.3/load-balancer' && c.method === 'POST') {
        lbCreates++;
        return jsonRes(
          {
            error: {
              error_code: 'INVALID_FIELD',
              error_message: 'Allowed range 192.0.2.10/24 is not a valid network address.',
            },
          },
          400,
        );
      }
      if (c.path === '/1.3/load-balancer' && c.method === 'GET') return jsonRes([]);
      return jsonRes({ message: 'not found' }, 404);
    });
    // A key long enough to be redacted in place (a shorter one keeps no words at all).
    const t = convexTest(schema, modules);
    await insertPanelServer(t);
    await createAccount(t, {
      provider: 'upcloud',
      name: 'acct-u',
      qualified: true,
      credentials: { token: 'SECRET_UPCLOUD_TOKEN' },
    });
    const { relayId } = await registerRelay(t, { listeners: [listenerU()] });
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'provision',
      trigger: 'manual',
      publishOnDone: false,
    });
    await drain(t, rotationId);
    // One request: the same one would be refused the same way.
    expect(lbCreates).toBe(1);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(r.phase).toBe('failed');
    expect(r.outcome).toBe('create_refused');
    expect(r.events.some((e) => e.code === 'step_retries_exhausted')).toBe(false);
    const error = r.events.find((e) => e.level === 'error');
    expect(error).toMatchObject({ code: 'create_refused' });
    expect(error?.detail).toContain('is not a valid network address');
    // The provider's reason is kept, never an address. The refused create was
    // the provider's first call and built nothing, so the edge fails like any
    // other (nothing billed, no operator needed), the day's allocation comes
    // back, and the node's automatic work keeps out of the location for a while.
    const edge = (await t.query(internal.edges.get, { id: r.toEdgeId! }))!;
    expect(edge.status).toBe('failed');
    expect(edge.failure).toMatchObject({ step: 'lb', code: 'create_refused', status: 400 });
    expect(edge.failure?.detail).toContain('is not a valid network address');
    expect(JSON.stringify([r.events, edge.failure])).not.toContain('192.0.2.10');
    expect(edge.resources).toEqual([]);
    expect(r.events.map((e) => e.code)).toEqual(
      expect.arrayContaining(['location_held', 'allocation_refunded']),
    );
    const origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.refusedLocations).toEqual([
      expect.objectContaining({ locationId: edge.locationId, code: 'create_refused' }),
    ]);
    const attention = await t.query(internal.edgeOperator.attention, {});
    expect(attention.items.some((i) => i.kind === 'needs_operator')).toBe(false);
    expect(attention.items.find((i) => i.kind === 'location_refused')).toMatchObject({
      relayId,
      code: 'create_refused',
    });
    // A spare that could not be built, named as one, with the provider's reason from the
    // first (only) answer: in attention and in activity.
    const failed = attention.items.find((i) => i.kind === 'rotation_failed');
    expect(failed).toMatchObject({
      rotationId,
      code: 'create_refused',
      facts: { kind: 'provision', spare: true },
    });
    expect(failed?.facts.answer).toContain('is not a valid network address');
    const audit = (await t.run((ctx) => ctx.db.query('auditLog').collect())).find(
      (a) => a.action === 'edge.rotation_failed',
    );
    expect(audit?.payload).toMatchObject({
      kind: 'provision',
      spare: true,
      code: 'create_refused',
    });
    expect(String((audit?.payload as { answer?: string }).answer)).toContain(
      'is not a valid network address',
    );
  });

  test("a spare that could not be built is named as one, with the provider's words, in attention and activity", async () => {
    vi.useFakeTimers();
    fakeWorld();
    const { t, relayId, listenerId } = await seed();
    // A spare's provision whose create step the provider refused in words (kept,
    // redacted, on its edge), about to run out of retries.
    const { edgeId } = await adoptL4Edge(t, relayId, listenerId, { ipv4: NEW_EDGE });
    const now = Date.now();
    const rotationId = await t.run(async (ctx) => {
      await ctx.db.patch(edgeId as Id<'edges'>, {
        status: 'provisioning',
        failure: { step: 'ip', code: 'INVALID_INPUT', status: 400, detail: '1 input is not valid' },
      });
      const id = await ctx.db.insert('edgeRotations', {
        relayId,
        kind: 'provision',
        trigger: 'manual',
        burn: false,
        force: false,
        toEdgeId: edgeId,
        createdEdgeId: edgeId,
        viaStandby: false,
        listenerId,
        publishOnDone: false,
        phase: 'provisioning',
        stepVersion: 3,
        cancelRequested: false,
        hostPlan: [],
        hostPlanCaptured: false,
        flipAttempts: 0,
        rollbackAttempts: 0,
        pollAttempts: 0,
        events: [],
        startedAt: now,
        updatedAt: now,
      } as never);
      await ctx.db.patch(relayId, { activeRotationId: id });
      return id;
    });
    await t.mutation(internal.edgeRotations.advance, {
      rotationId,
      stepVersion: 3,
      event: { type: 'fail', code: 'step_retries_exhausted', detail: 'ip', rollback: false },
    });
    expect((await t.query(internal.edgeRotations.get, { id: rotationId }))!.phase).toBe('failed');
    // Attention: what the run was and what the provider said; it opens the run.
    const { items } = await t.query(internal.edgeOperator.attention, {});
    expect(items.find((i) => i.kind === 'rotation_failed')).toMatchObject({
      rotationId,
      code: 'step_retries_exhausted',
      action: 'open_relay',
      facts: { kind: 'provision', spare: true, answer: '1 input is not valid' },
    });
    // Activity: the same, on the audit row the node page words.
    const audit = (await t.run((ctx) => ctx.db.query('auditLog').collect())).find(
      (a) => a.action === 'edge.rotation_failed',
    );
    expect(audit?.payload).toMatchObject({
      relaySlug: 'node-one',
      kind: 'provision',
      spare: true,
      code: 'step_retries_exhausted',
      answer: '1 input is not valid',
      rotationId,
    });
    expect(JSON.stringify(audit?.payload)).not.toContain(NEW_EDGE);
  });

  test("providerAnswerOf: the edge's kept answer, else the newest event that carried one", () => {
    expect(providerAnswerOf([], { detail: ' 1 input is not valid ' })).toBe('1 input is not valid');
    expect(
      providerAnswerOf(
        [
          { detail: 'step lb threw: 400. The provider answered: old words' },
          { detail: 'step ip threw: 400 x. The provider answered: newer words' },
          { detail: 'step ip still unresolved' },
        ],
        { detail: '' },
      ),
    ).toBe('newer words');
    expect(providerAnswerOf([{ detail: 'step ip threw: 500' }, {}], null)).toBeNull();
    expect(providerAnswerOf([], { detail: 'x'.repeat(500) })!.length).toBe(200);
    // This run's own words win over what an edge kept.
    expect(
      providerAnswerOf([{ detail: 'step ip threw: 400. The provider answered: this run' }], {
        detail: 'kept',
      }),
    ).toBe('this run');
  });

  test('isSpareProvision: a provision kept unused, never a setup run candidate or a fill', () => {
    expect(isSpareProvision({ kind: 'provision', publishOnDone: false })).toBe(true);
    expect(isSpareProvision({ kind: 'provision' })).toBe(true);
    expect(isSpareProvision({ kind: 'provision', publishOnDone: true })).toBe(false);
    // A guided setup's candidate is put in use at go-live: not a spare.
    expect(
      isSpareProvision({ kind: 'provision', publishOnDone: false, setupRun: { runId: 'r' } }),
    ).toBe(false);
    expect(isSpareProvision({ kind: 'publish' })).toBe(false);
    expect(isSpareProvision({ kind: 'replace' })).toBe(false);
  });

  test("a failed publish never quotes the standby's older provider answer", async () => {
    vi.useFakeTimers();
    fakeWorld();
    const { t, relayId, listenerId } = await seed();
    // A standby that once had a provider refusal, then recovered.
    const { edgeId } = await adoptL4Edge(t, relayId, listenerId, { ipv4: NEW_EDGE });
    const now = Date.now();
    const rotationId = await t.run(async (ctx) => {
      await ctx.db.patch(edgeId as Id<'edges'>, {
        failure: { step: 'ip', code: 'INVALID_INPUT', detail: 'an old answer' },
      });
      const id = await ctx.db.insert('edgeRotations', {
        relayId,
        kind: 'publish',
        trigger: 'manual',
        burn: false,
        force: false,
        toEdgeId: edgeId,
        viaStandby: true,
        listenerId,
        phase: 'publishing',
        stepVersion: 2,
        cancelRequested: false,
        hostPlan: [],
        hostPlanCaptured: false,
        flipAttempts: 0,
        rollbackAttempts: 0,
        pollAttempts: 0,
        events: [],
        startedAt: now,
        updatedAt: now,
      } as never);
      await ctx.db.patch(relayId, { activeRotationId: id });
      return id;
    });
    await t.mutation(internal.edgeRotations.advance, {
      rotationId,
      stepVersion: 2,
      event: { type: 'fail', code: 'not_publishable', rollback: false },
    });
    const { items } = await t.query(internal.edgeOperator.attention, {});
    const item = items.find((i) => i.kind === 'rotation_failed')!;
    expect(item.facts).toMatchObject({ kind: 'publish', spare: false });
    expect(item.facts).not.toHaveProperty('answer');
    const audit = (await t.run((ctx) => ctx.db.query('auditLog').collect())).find(
      (a) => a.action === 'edge.rotation_failed',
    );
    expect(audit?.payload).toMatchObject({ kind: 'publish', spare: false });
    expect(audit?.payload).not.toHaveProperty('answer');
  });

  test('automatic upkeep does not provision again right after its provision failed', async () => {
    vi.useFakeTimers();
    const w = ipNeverAllocates();
    const { t, relayId } = await bareSeed();
    await t.run(async (ctx) => {
      await upsertSettingRow(ctx, 'edge.enabled', 'true');
      await upsertSettingRow(ctx, 'edge.autoProvisionToDesired', 'true');
    });
    await t.action(internal.edgeReconcile.run, {});
    const first = (await t.query(internal.relays.get, { id: relayId }))!.activeRotationId!;
    expect(first).toBeDefined();
    await drain(t, first);
    expect((await t.query(internal.edgeRotations.get, { id: first }))!.phase).toBe('failed');
    // The next ticks inside the back-off clean up and start nothing new.
    for (let i = 0; i < 3; i++) {
      await vi.advanceTimersByTimeAsync(6 * 60_000);
      await t.action(internal.edgeReconcile.run, {});
      expect((await t.query(internal.relays.get, { id: relayId }))!.activeRotationId).toBe(
        undefined,
      );
    }
    expect(w.lbCreates()).toBe(1);
    expect(w.deletes).toEqual(['lb-1']);
    // Past the back-off, upkeep tries again.
    await vi.advanceTimersByTimeAsync(60 * 60_000);
    await t.action(internal.edgeReconcile.run, {});
    expect((await t.query(internal.relays.get, { id: relayId }))!.activeRotationId).toBeDefined();
  });
});

describe('edgeRotations: cancel while a create is in flight', () => {
  test('the cancelled edge keeps what the create built and the reconcile destroys it', async () => {
    vi.useFakeTimers();
    const lbs = new Map<string, { uuid: string; name: string; operational_state: string }>();
    const deletes: string[] = [];
    const hook: {
      t?: ReturnType<typeof convexTest>;
      rotationId?: Id<'edgeRotations'>;
      fired: boolean;
    } = { fired: false };
    mockFetch(async (c) => {
      if (new URL(c.url).hostname === 'panel.example') {
        if (c.path === '/api/hosts' && c.method === 'GET') return jsonRes({ response: [] });
        return jsonRes({ message: 'not found' }, 404);
      }
      if (c.path === '/1.3/load-balancer' && c.method === 'POST') {
        const uuid = `lb-${lbs.size + 1}`;
        lbs.set(uuid, {
          uuid,
          name: (c.body as { name: string }).name,
          operational_state: 'running',
        });
        if (!hook.fired) {
          hook.fired = true;
          // The operator cancels while the create is out; the cancel's own step
          // runs, and so does a reconcile pass, before the create answers.
          await hook.t!.mutation(internal.edgeRotations.requestCancel, {
            rotationId: hook.rotationId!,
          });
          await hook.t!.action(internal.edgeRotations.step, { rotationId: hook.rotationId! });
          await hook.t!.action(internal.edgeReconcile.run, {});
        }
        return jsonRes(lbs.get(uuid));
      }
      if (c.path === '/1.3/load-balancer' && c.method === 'GET') return jsonRes([...lbs.values()]);
      const one = c.path.match(/^\/1\.3\/load-balancer\/([^/]+)$/);
      if (one && c.method === 'GET') {
        const lb = lbs.get(one[1]);
        return lb ? jsonRes(lb) : jsonRes({ error: { error_code: 'LB_NOT_FOUND' } }, 404);
      }
      if (one && c.method === 'DELETE') {
        if (!lbs.has(one[1])) return jsonRes({ error: { error_code: 'LB_NOT_FOUND' } }, 404);
        lbs.delete(one[1]);
        deletes.push(one[1]);
        return new Response(null, { status: 204 });
      }
      return jsonRes({ message: 'not found' }, 404);
    });
    const t = convexTest(schema, modules);
    hook.t = t;
    await insertPanelServer(t);
    await createAccount(t, { provider: 'upcloud', name: 'acct-u', qualified: true });
    const { relayId } = await registerRelay(t, { listeners: [listenerU()] });
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'provision',
      trigger: 'manual',
      publishOnDone: false,
    });
    hook.rotationId = rotationId;
    const r0 = await driveUntil(t, rotationId, 'provisioning');
    // The step that claims `create_lb` and calls the provider (the hook fires inside it).
    await t.action(internal.edgeRotations.step, { rotationId });
    expect((await t.query(internal.edgeRotations.get, { id: rotationId }))!.phase).toBe(
      'cancelled',
    );
    const edge = (await t.query(internal.edges.get, { id: r0.toEdgeId! }))!;
    // The late answer is recorded on the edge, which stays cancelled.
    expect(edge.status).toBe('cancelled');
    expect(edge.resources.map((x) => x.resourceId)).toEqual(['lb-1']);
    for (let i = 0; i < 3; i++) {
      await vi.advanceTimersByTimeAsync(6 * 60_000);
      await t.action(internal.edgeReconcile.run, {});
    }
    expect(deletes).toEqual(['lb-1']);
    expect((await t.query(internal.edges.get, { id: r0.toEdgeId! }))!.status).toBe('destroyed');
  });
});

describe('edgeRotations: the replaced edge while a replace is still running', () => {
  /** UpCloud + a backend whose Host table can go down; every LB delete recorded. */
  function world() {
    const panelHosts: BackendAddress[] = [];
    const lbs = new Map<string, { uuid: string; name: string; operational_state: string }>();
    const deletes: string[] = [];
    let ips = 0;
    const state = { panelDown: false };
    mockFetch((c) => {
      if (new URL(c.url).hostname === 'panel.example') {
        if (state.panelDown) return jsonRes({ message: 'down' }, 503);
        if (c.path === '/api/hosts' && c.method === 'GET') return jsonRes({ response: panelHosts });
        if (c.path === '/api/hosts' && c.method === 'PATCH') {
          const body = c.body as { uuid: string; address: string; port: number };
          const h = panelHosts.find((x) => x.uuid === body.uuid)!;
          h.address = body.address;
          h.port = body.port;
          return jsonRes({ response: h });
        }
        if (c.path === '/api/hosts' && c.method === 'POST') {
          const body = c.body as Omit<BackendAddress, 'uuid'>;
          panelHosts.push({ ...body, uuid: HOST_UUID });
          return jsonRes({ response: { uuid: HOST_UUID } });
        }
        return jsonRes({ message: 'not found' }, 404);
      }
      if (c.path === '/1.3/load-balancer' && c.method === 'POST') {
        const uuid = `lb-${lbs.size + deletes.length + 1}`;
        lbs.set(uuid, {
          uuid,
          name: (c.body as { name: string }).name,
          operational_state: 'running',
        });
        return jsonRes(lbs.get(uuid));
      }
      if (c.path === '/1.3/load-balancer' && c.method === 'GET') return jsonRes([...lbs.values()]);
      if (c.path === '/1.3/ip_address' && c.method === 'POST')
        return jsonRes({ ip_address: { address: `198.51.100.${60 + ++ips}`, floating: 'yes' } });
      if (/^\/1\.3\/load-balancer\/[^/]+\/ip-addresses$/.test(c.path) && c.method === 'POST')
        return jsonRes({});
      const one = c.path.match(/^\/1\.3\/load-balancer\/([^/]+)$/);
      if (one && c.method === 'GET') {
        const lb = lbs.get(one[1]);
        return lb ? jsonRes(lb) : jsonRes({ error: { error_code: 'LB_NOT_FOUND' } }, 404);
      }
      if (one && c.method === 'DELETE') {
        if (!lbs.has(one[1])) return jsonRes({ error: { error_code: 'LB_NOT_FOUND' } }, 404);
        lbs.delete(one[1]);
        deletes.push(one[1]);
        return new Response(null, { status: 204 });
      }
      if (/^\/1\.3\/ip_address\/[^/]+$/.test(c.path) && c.method === 'DELETE')
        return new Response(null, { status: 204 });
      return jsonRes({ message: 'not found' }, 404);
    });
    return { state, deletes };
  }

  /** Origin node-one with listener `u`: a managed edge A published by a publish run, and a tested spare B. */
  async function published() {
    const t = convexTest(schema, modules);
    await insertPanelServer(t);
    await createAccount(t, { provider: 'upcloud', name: 'acct-u', qualified: true });
    const { relayId } = await registerRelay(t, { listeners: [listenerU()] });
    const a = await provisionSpare(t, relayId);
    const pub = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'publish',
      trigger: 'manual',
      toEdgeId: a,
    });
    await drain(t, pub.rotationId);
    expect((await t.query(internal.edgeRotations.get, { id: pub.rotationId }))!.phase).toBe('done');
    await provisionSpare(t, relayId);
    // A short drain (the minimum allowed is one minute), and past any cooldown.
    await t.run((ctx) => ctx.db.patch(relayId, { drainMs: 60_000 }));
    vi.setSystemTime(Date.now() + 3 * 60 * 60_000);
    return { t, relayId, a };
  }

  test('its drain ending mid-run does not destroy it, and the rollback serves it again', async () => {
    vi.useFakeTimers();
    const w = world();
    const { t, relayId, a } = await published();
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: a,
    });
    await driveUntil(t, rotationId, 'host_flipping');
    // The backend is unreachable during the flip; the drain runs out; a reconcile pass runs.
    w.state.panelDown = true;
    vi.setSystemTime(Date.now() + 2 * 60_000);
    await t.action(internal.edgeReconcile.run, {});
    expect((await t.query(internal.edges.get, { id: a }))!.status).toBe('draining');
    expect(w.deletes).toEqual([]);
    // The operator cancels: the rollback puts A back, and A still exists.
    w.state.panelDown = false;
    await t.mutation(internal.edgeRotations.requestCancel, { rotationId });
    await drain(t, rotationId);
    expect((await t.query(internal.edgeRotations.get, { id: rotationId }))!.phase).toBe(
      'rolled_back',
    );
    const after = (await t.query(internal.edges.get, { id: a }))!;
    expect(after.status).toBe('active');
    expect(after.publication).toBe('published');
    expect(w.deletes).toEqual([]);
  });

  test('the rollback never publishes a replaced edge that is being destroyed', async () => {
    vi.useFakeTimers();
    world();
    const { t, relayId, a } = await published();
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: a,
    });
    await driveUntil(t, rotationId, 'host_flipping');
    await t.run((ctx) => ctx.db.patch(a, { status: 'destroying' }));
    await t.mutation(internal.edgeRotations.requestCancel, { rotationId });
    await drain(t, rotationId);
    const after = (await t.query(internal.edges.get, { id: a }))!;
    expect(after.status).toBe('destroying');
    expect(after.publication).not.toBe('published');
    expect((await t.query(internal.relays.get, { id: relayId }))!.publishedEdgeIds).not.toContain(
      a,
    );
  });
});
