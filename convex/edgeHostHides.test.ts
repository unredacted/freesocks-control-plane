/// <reference types="vite/client" />
/**
 * The direct-Host hide ledger (convex/edgeHostHides.ts): the row exists before
 * every write, a claimed row is settled only by observation (never by a lease
 * expiry alone), a late-landing disable is caught rather than reversed, the
 * reconcile pass retries an unsettled disable and re-hides a reappeared direct
 * Host on a bound guided relay (or raises `direct_host_reappeared`), and
 * delivery stays fail-closed (`leak_detected`) in between. Plus the pure
 * classifier and the cohort walk.
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { classifyDirectHosts, listingHash } from './lib/edges/directHosts';
import { cohortReportForOrigin } from './lib/edges/cohorts';
import { HIDE_MAX_ATTEMPTS, judgeLook } from './edgeHostHides';
import { HOST_OP_TTL_MS, HOST_SETTLE_MS } from './hostOps';
import { fakeHostPanel, type PanelHostRow } from './lib/edges/testing/fakeHostPanel';
import {
  FIXTURE_CONFIG_PROFILE,
  FIXTURE_INBOUND,
  FIXTURE_NODE,
  FIXTURE_ORIGIN,
  adoptL4Edge,
  realityListener,
  seedEdgeFixture,
} from './lib/edges/testing/fixtures';

const modules = import.meta.glob('./**/*.*s');

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

const NOW = 1_800_000_000_000;
const EDGE_A = '198.51.100.1';
const WS_INBOUND = '33333333-3333-4333-8333-333333333333';
const FCP_UUID = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
const D1 = 'd1d1d1d1-d1d1-4d1d-8d1d-d1d1d1d1d1d1';
const D2 = 'd2d2d2d2-d2d2-4d2d-8d2d-d2d2d2d2d2d2';
const TEMPLATE = `${FIXTURE_NODE}-relay-a`;

const inbound = (uuid: string) => ({
  configProfileUuid: FIXTURE_CONFIG_PROFILE,
  configProfileInboundUuid: uuid,
});

/** The panel's Hosts on the node: FCP's template + a covered direct Host (+ an uncovered one). */
function panelHosts(opts: { uncovered?: boolean; d1Disabled?: boolean } = {}): PanelHostRow[] {
  return [
    {
      uuid: FCP_UUID,
      remark: TEMPLATE,
      address: EDGE_A,
      port: 443,
      sni: 'a.example',
      isDisabled: false,
      inbound: inbound(FIXTURE_INBOUND),
    },
    {
      uuid: D1,
      remark: `${FIXTURE_NODE}-reality`,
      address: FIXTURE_ORIGIN,
      port: 443,
      sni: 'target.example',
      isDisabled: opts.d1Disabled ?? false,
      inbound: inbound(FIXTURE_INBOUND),
    },
    ...(opts.uncovered
      ? [
          {
            uuid: D2,
            remark: `${FIXTURE_NODE}-ws`,
            address: FIXTURE_ORIGIN,
            port: 8443,
            sni: null,
            isDisabled: false,
            inbound: inbound(WS_INBOUND),
          },
        ]
      : []),
  ];
}

/**
 * The world: panel + relay `node-one` (REALITY listener `a`, FCP Hosts) with a
 * verified, published L4 edge at EDGE_A, one member key pinned to the node,
 * rendering on. `deferred` = a guided relay before go-live (no binding).
 */
async function world(
  opts: { deferred?: boolean; hosts?: PanelHostRow[]; mode?: 'apply' | 'ignore' | 'fail' } = {},
) {
  const panel = fakeHostPanel(opts.hosts ?? panelHosts(), opts.mode);
  const t = convexTest(schema, modules);
  const fx = await seedEdgeFixture(t, { listeners: [realityListener()] });
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
    const subId = await ctx.db.insert('subscriptions', {
      userId,
      backend: 'remnawave',
      backendUserId: 'uuid-1',
      backendShortId: 'short-1',
      backendServerId: fx.serverId,
      subscriptionUrl: 'https://panel.example/sub/short-1',
      subscriptionMirrors: [],
      subToken: 'tok_abc',
      backendPlacement: 'squad-1',
      state: 'active',
      pinnedNode: FIXTURE_NODE,
      updatedAt: Date.now(),
    });
    await ctx.db.patch(userId, { currentSubscriptionId: subId });
    await upsertSettingRow(ctx, 'edge.render.enabled', 'true');
    return subId;
  });
  const a = await adoptL4Edge(t, fx.relayId, fx.listenerId, { ipv4: EDGE_A, publish: true });
  if (opts.deferred) {
    await t.run(async (ctx) => {
      await ctx.db.patch(fx.relayId, {
        bindingDeferred: true,
        setupOwned: true,
        setupStage: 'publish',
      });
      for (const b of await ctx.db.query('edgeDeliveryBindings').collect())
        await ctx.db.delete(b._id);
    });
  } else {
    await t.run((ctx) => ctx.db.patch(fx.relayId, { setupStage: 'done' }));
  }
  let n = 0;
  /** A member download through the real fronted route (a fresh UA each time: no cache). */
  const download = async () => {
    const res = await t.fetch('/api/v1/sub/tok_abc', {
      headers: { 'user-agent': `client-${++n}/1.0` },
    });
    return {
      status: res.status,
      body: await res.text(),
      reason: res.headers.get('x-fcp-delivery'),
    };
  };
  const relay = async () => (await t.run((ctx) => ctx.db.get(fx.relayId)))!;
  const rows = () =>
    t.run((ctx) =>
      ctx.db
        .query('edgeHostHides')
        .withIndex('by_relay', (q) => q.eq('relayId', fx.relayId))
        .collect(),
    );
  return { ...fx, panel, subId, edgeId: a.edgeId as Id<'edges'>, download, relay, rows };
}

describe('classifyDirectHosts (pure)', () => {
  const ctx = {
    originAddress: FIXTURE_ORIGIN,
    nodeInboundUuids: [FIXTURE_INBOUND, WS_INBOUND],
    fcpRemarks: [TEMPLATE],
    legacyHostUuids: [],
    coveredInboundUuids: [FIXTURE_INBOUND],
  };

  test('enabled Hosts on the node inbounds at the origin address, not FCP, not legacy; covered by listener inbound', () => {
    const { covered, uncovered } = classifyDirectHosts(panelHosts({ uncovered: true }), ctx);
    expect(covered.map((h) => h.uuid)).toEqual([D1]);
    expect(uncovered.map((h) => h.uuid)).toEqual([D2]);
    expect(covered[0]).toMatchObject({
      remark: `${FIXTURE_NODE}-reality`,
      inboundUuid: FIXTURE_INBOUND,
      port: 443,
    });
  });

  test('a disabled Host, another node’s inbound, an edge address, an FCP remark and a legacy uuid are never direct', () => {
    const hosts: PanelHostRow[] = [
      ...panelHosts({ d1Disabled: true }),
      {
        uuid: 'other',
        remark: 'node-two-reality',
        address: FIXTURE_ORIGIN,
        port: 443,
        isDisabled: false,
        inbound: inbound('99999999-9999-4999-8999-999999999999'),
      },
      {
        uuid: 'legacy',
        remark: 'old-name',
        address: FIXTURE_ORIGIN,
        port: 443,
        isDisabled: false,
        inbound: inbound(FIXTURE_INBOUND),
      },
    ];
    const r = classifyDirectHosts(hosts, { ...ctx, legacyHostUuids: ['legacy'] });
    expect(r).toEqual({ covered: [], uncovered: [] });
  });

  test('the listing hash covers direct + FCP Hosts and their disabled bit only', async () => {
    const a = await listingHash(panelHosts(), ctx);
    const b = await listingHash(panelHosts({ d1Disabled: true }), ctx);
    const c = await listingHash(
      [
        ...panelHosts(),
        {
          uuid: 'x',
          remark: 'elsewhere',
          address: '198.51.100.99',
          port: 1,
          isDisabled: false,
          inbound: inbound(FIXTURE_INBOUND),
        },
      ],
      ctx,
    );
    expect(a).not.toBe(b);
    expect(c).toBe(a);
  });
});

describe('judgeLook (pure)', () => {
  const base = {
    intent: 'disable' as const,
    state: 'written' as const,
    opId: 'op',
    expiresAt: NOW + HOST_OP_TTL_MS,
    quietLooks: 0,
    attempt: 1,
  };

  test('disabled = confirmed; gone = released; enabled before the lease expired = wait', () => {
    expect(judgeLook(base, { isDisabled: true }, NOW, 'settle')).toMatchObject({
      state: 'confirmed',
    });
    expect(judgeLook(base, null, NOW, 'settle')).toMatchObject({
      state: 'released',
      releasedReason: 'gone',
    });
    expect(judgeLook(base, { isDisabled: false }, NOW + 1, 'settle')).toEqual({
      state: null,
      retry: false,
    });
    expect(
      judgeLook(base, { isDisabled: false }, NOW + HOST_OP_TTL_MS + HOST_SETTLE_MS + 1, 'readback'),
    ).toEqual({ state: null, retry: false });
  });

  test('after the lease: quiet looks, then settled only past the floor AND two looks (released under settle, retried under reconcile)', () => {
    const t1 = NOW + HOST_OP_TTL_MS + 1;
    expect(judgeLook(base, { isDisabled: false }, t1, 'settle')).toEqual({
      state: 'unresolved',
      quietLooks: 1,
      retry: false,
    });
    // Two looks inside the floor are not enough.
    expect(judgeLook({ ...base, quietLooks: 1 }, { isDisabled: false }, t1 + 1, 'settle')).toEqual({
      state: 'unresolved',
      quietLooks: 2,
      retry: false,
    });
    // Past the floor with one look is not enough either.
    const t2 = NOW + HOST_OP_TTL_MS + HOST_SETTLE_MS + 1;
    expect(judgeLook(base, { isDisabled: false }, t2, 'settle')).toEqual({
      state: 'unresolved',
      quietLooks: 1,
      retry: false,
    });
    expect(
      judgeLook({ ...base, quietLooks: 1 }, { isDisabled: false }, t2, 'settle'),
    ).toMatchObject({ state: 'released', releasedReason: 'settled' });
    expect(judgeLook({ ...base, quietLooks: 1 }, { isDisabled: false }, t2, 'reconcile')).toEqual({
      state: 'unresolved',
      quietLooks: 2,
      retry: true,
    });
    expect(
      judgeLook(
        { ...base, quietLooks: 1, attempt: HIDE_MAX_ATTEMPTS },
        { isDisabled: false },
        t2,
        'reconcile',
      ),
    ).toEqual({ state: 'unresolved', quietLooks: 2, retry: false });
  });

  test('a restore row: enabled = released (restored); still disabled after settlement = retried', () => {
    const r = { ...base, intent: 'restore' as const };
    expect(judgeLook(r, { isDisabled: false }, NOW, 'settle')).toMatchObject({
      state: 'released',
      releasedReason: 'restored',
    });
    expect(
      judgeLook(
        { ...r, quietLooks: 1 },
        { isDisabled: true },
        NOW + HOST_OP_TTL_MS + HOST_SETTLE_MS + 1,
        'settle',
      ),
    ).toEqual({ state: 'unresolved', quietLooks: 2, retry: true });
  });
});

describe('edgeHostHides.hide', () => {
  test('hides every covered direct Host, the approved uncovered ones, reports the rest as reviewChanged; the row is confirmed by read-back and audited', async () => {
    const { t, panel, relayId, rows } = await world({
      deferred: true,
      hosts: panelHosts({ uncovered: true }),
    });
    const r = await t.action(internal.edgeHostHides.hide, {
      relayId,
      runId: 'run-1',
      approvedUuids: [],
      nodeInboundUuids: [FIXTURE_INBOUND, WS_INBOUND],
    });
    expect(r).toEqual({
      state: 'confirmed',
      hidden: 1,
      pending: 0,
      failed: 0,
      reviewChanged: [{ uuid: D2, remark: `${FIXTURE_NODE}-ws` }],
    });
    expect(panel.find(D1).isDisabled).toBe(true);
    expect(panel.find(D2).isDisabled).toBe(false);
    expect(panel.find(FCP_UUID).isDisabled).toBe(false);
    expect(panel.patches).toEqual([{ uuid: D1, isDisabled: true }]);
    const [row] = await rows();
    expect(row).toMatchObject({
      hostUuid: D1,
      intent: 'disable',
      state: 'confirmed',
      runId: 'run-1',
      attempt: 1,
    });
    expect(row.opId).toBeUndefined();
    expect(row.observed).toMatchObject({
      remark: `${FIXTURE_NODE}-reality`,
      address: FIXTURE_ORIGIN,
      port: 443,
      inboundUuid: FIXTURE_INBOUND,
      isDisabled: false,
    });
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.find((a) => a.action === 'edge.host.hidden')?.payload).toMatchObject({
      count: 1,
      remarks: [`${FIXTURE_NODE}-reality`],
      runId: 'run-1',
    });
    // Approving D2 hides it too; D1 is already confirmed and is not written again.
    const again = await t.action(internal.edgeHostHides.hide, {
      relayId,
      approvedUuids: [D2],
      nodeInboundUuids: [FIXTURE_INBOUND, WS_INBOUND],
    });
    expect(again).toMatchObject({ state: 'confirmed', hidden: 1, reviewChanged: [] });
    expect(panel.patches).toEqual([
      { uuid: D1, isDisabled: true },
      { uuid: D2, isDisabled: true },
    ]);
    expect(await t.query(internal.edgeHostHides.status, { relayId })).toMatchObject({
      outstanding: 0,
      confirmed: 2,
      unresolved: 0,
      failed: 0,
    });
  });

  test('a Host the operator disabled themselves is not FCP’s to restore: no row', async () => {
    const { t, relayId, rows, panel } = await world({
      deferred: true,
      hosts: panelHosts({ d1Disabled: true }),
    });
    const r = await t.action(internal.edgeHostHides.hide, { relayId, approvedUuids: [] });
    expect(r).toMatchObject({ hidden: 0, pending: 0, failed: 0 });
    expect(await rows()).toEqual([]);
    expect(panel.patches).toEqual([]);
  });

  test('refused while a restore workflow runs (freeze)', async () => {
    const { t, relayId, panel } = await world({ deferred: true });
    await t.mutation(internal.edgeRestore.start, { relayId, purpose: 'cancel_setup' });
    await expect(
      t.action(internal.edgeHostHides.hide, { relayId, approvedUuids: [] }),
    ).rejects.toThrow(/restore_in_progress/);
    expect(panel.patches).toEqual([]);
  });
});

describe('acceptance 4: a partial Host-disable (the write did not land)', () => {
  test('a PATCH the panel accepted but did not apply leaves the row written; the reconcile pass confirms it once the disable lands late', async () => {
    vi.useFakeTimers({ now: NOW });
    const { t, panel, relayId, rows } = await world({ deferred: true, mode: 'ignore' });
    const r = await t.action(internal.edgeHostHides.hide, { relayId, approvedUuids: [] });
    expect(r).toMatchObject({ state: 'pending', hidden: 0, pending: 1 });
    let [row] = await rows();
    expect(row).toMatchObject({ state: 'written', attempt: 1 });
    expect(row.opId).toBeDefined();
    // A reconcile pass inside the lease: nothing changes, nothing is re-issued.
    await t.action(internal.hostOps.reconcileHosts, {});
    expect((await rows())[0].state).toBe('written');
    expect(panel.patches).toHaveLength(1);
    // The panel applies it late: the next look confirms (never reverses).
    panel.find(D1).isDisabled = true;
    await t.action(internal.hostOps.reconcileHosts, {});
    [row] = await rows();
    expect(row).toMatchObject({ state: 'confirmed' });
    expect(row.opId).toBeUndefined();
    expect(panel.patches).toHaveLength(1);
  });

  test('a PATCH that threw is unresolved (possibly written); the reconcile pass re-issues it only after the settle floor and two quiet looks', async () => {
    vi.useFakeTimers({ now: NOW });
    const { t, panel, relayId, rows } = await world({ deferred: true, mode: 'fail' });
    const r = await t.action(internal.edgeHostHides.hide, { relayId, approvedUuids: [] });
    expect(r).toMatchObject({ state: 'pending', pending: 1 });
    expect((await rows())[0].state).toBe('unresolved');
    // Lease expired: look 1 (quiet).
    vi.setSystemTime(NOW + HOST_OP_TTL_MS + 1);
    await t.action(internal.hostOps.reconcileHosts, {});
    expect((await rows())[0]).toMatchObject({ state: 'unresolved', quietLooks: 1, attempt: 1 });
    expect(panel.patches).toHaveLength(1);
    // Past the floor: look 2 settles it and the disable is re-issued (attempt 2), this time applied.
    panel.setPatchMode('apply');
    vi.setSystemTime(NOW + HOST_OP_TTL_MS + HOST_SETTLE_MS + 1);
    await t.action(internal.hostOps.reconcileHosts, {});
    expect(panel.patches).toHaveLength(2);
    expect((await rows())[0]).toMatchObject({ state: 'confirmed', attempt: 2 });
    expect(panel.find(D1).isDisabled).toBe(true);
  });

  test('cancel during `written` settles first (released after the floor, never restored), then the workflow finishes with the direct Host untouched', async () => {
    vi.useFakeTimers({ now: NOW });
    const { t, panel, relayId, rows, relay } = await world({ deferred: true, mode: 'ignore' });
    await t.action(internal.edgeHostHides.hide, { relayId, approvedUuids: [] });
    expect((await rows())[0].state).toBe('written');
    await t.mutation(internal.edgeRestore.start, { relayId, purpose: 'cancel_setup' });
    expect(await t.action(internal.edgeRestore.step, { relayId })).toMatchObject({
      phase: 'settle',
      advanced: true,
    });
    // Inside the lease: the phase waits.
    expect(await t.action(internal.edgeRestore.step, { relayId })).toMatchObject({
      phase: 'settle',
      advanced: false,
      error: 'hides_outstanding:1',
    });
    vi.setSystemTime(NOW + HOST_OP_TTL_MS + 1);
    expect(await t.action(internal.edgeRestore.step, { relayId })).toMatchObject({
      phase: 'settle',
      advanced: false,
    });
    expect((await rows())[0]).toMatchObject({ state: 'unresolved', quietLooks: 1 });
    vi.setSystemTime(NOW + HOST_OP_TTL_MS + HOST_SETTLE_MS + 1);
    expect(await t.action(internal.edgeRestore.step, { relayId })).toMatchObject({
      phase: 'release_binding',
      advanced: true,
    });
    expect((await rows())[0]).toMatchObject({ state: 'released', releasedReason: 'settled' });
    // No opposing write was ever issued: the one PATCH is the original disable.
    expect(panel.patches).toEqual([{ uuid: D1, isDisabled: true }]);
    for (const phase of ['restore', 'verify_direct', 'finish']) {
      expect((await t.action(internal.edgeRestore.step, { relayId })).phase).toBe(phase);
    }
    expect(await t.action(internal.edgeRestore.step, { relayId })).toMatchObject({ done: true });
    expect(panel.patches).toHaveLength(1);
    expect(panel.find(D1).isDisabled).toBe(false);
    expect((await relay()).restore).toBeUndefined();
  });

  test('a disable landing late during the cancel is observed (confirmed) and then restored, not reversed blindly', async () => {
    vi.useFakeTimers({ now: NOW });
    const { t, panel, relayId, rows } = await world({ deferred: true, mode: 'ignore' });
    await t.action(internal.edgeHostHides.hide, { relayId, approvedUuids: [] });
    await t.mutation(internal.edgeRestore.start, { relayId, purpose: 'cancel_setup' });
    await t.action(internal.edgeRestore.step, { relayId }); // -> settle
    vi.setSystemTime(NOW + HOST_OP_TTL_MS + 1);
    await t.action(internal.edgeRestore.step, { relayId }); // quiet look 1
    // The panel applies the disable after the lease expired.
    panel.find(D1).isDisabled = true;
    panel.setPatchMode('apply');
    vi.setSystemTime(NOW + HOST_OP_TTL_MS + HOST_SETTLE_MS + 1);
    expect(await t.action(internal.edgeRestore.step, { relayId })).toMatchObject({
      phase: 'release_binding',
    });
    expect((await rows())[0]).toMatchObject({ state: 'confirmed' });
    await t.action(internal.edgeRestore.step, { relayId }); // -> restore
    expect(await t.action(internal.edgeRestore.step, { relayId })).toMatchObject({
      phase: 'verify_direct',
    });
    expect(panel.patches).toEqual([
      { uuid: D1, isDisabled: true },
      { uuid: D1, isDisabled: false },
    ]);
    expect(panel.find(D1).isDisabled).toBe(false);
    const all = await rows();
    expect(all.map((r) => [r.intent, r.state, r.releasedReason])).toEqual([
      ['disable', 'released', 'restored'],
      ['restore', 'released', 'restored'],
    ]);
  });
});

describe('acceptance 18: settlement of a claimed `intended` row', () => {
  async function claimed() {
    vi.useFakeTimers({ now: NOW });
    const w = await world({ deferred: true });
    const claim = await t(w).mutation(internal.edgeHostHides.claim, {
      relayId: w.relayId,
      backendServerId: w.serverId,
      hostUuid: D1,
      observed: {
        remark: `${FIXTURE_NODE}-reality`,
        address: FIXTURE_ORIGIN,
        port: 443,
        sni: 'target.example',
        host: null,
        inboundUuid: FIXTURE_INBOUND,
        isDisabled: false,
      },
      intent: 'disable',
    });
    expect(claim.claimed).toBe(true);
    return w;
  }
  const t = (w: Awaited<ReturnType<typeof world>>) => w.t;

  test('is re-observed and never released on lease expiry alone; a disable landing after expiry is caught by the next look', async () => {
    const w = await claimed();
    await w.t.mutation(internal.edgeRestore.start, { relayId: w.relayId, purpose: 'cancel_setup' });
    await w.t.action(internal.edgeRestore.step, { relayId: w.relayId }); // -> settle
    vi.setSystemTime(NOW + HOST_OP_TTL_MS + 1);
    await w.t.action(internal.edgeRestore.step, { relayId: w.relayId });
    expect((await w.rows())[0]).toMatchObject({ state: 'unresolved', quietLooks: 1 });
    // Long past the floor, still enabled: ONE look past the floor is not settlement... the second is.
    vi.setSystemTime(NOW + HOST_OP_TTL_MS + 10 * HOST_SETTLE_MS);
    // ...but a disable that landed meanwhile is observed, and confirmed.
    w.panel.find(D1).isDisabled = true;
    await w.t.action(internal.edgeRestore.step, { relayId: w.relayId });
    expect((await w.rows())[0]).toMatchObject({ state: 'confirmed' });
    expect(w.panel.patches).toEqual([]);
  });

  test('release only after the settle floor and two quiet looks', async () => {
    const w = await claimed();
    await w.t.mutation(internal.edgeRestore.start, { relayId: w.relayId, purpose: 'cancel_setup' });
    await w.t.action(internal.edgeRestore.step, { relayId: w.relayId });
    // Past the floor at once: the first look is still a quiet look.
    vi.setSystemTime(NOW + HOST_OP_TTL_MS + HOST_SETTLE_MS + 1);
    await w.t.action(internal.edgeRestore.step, { relayId: w.relayId });
    expect((await w.rows())[0]).toMatchObject({ state: 'unresolved', quietLooks: 1 });
    await w.t.action(internal.edgeRestore.step, { relayId: w.relayId });
    expect((await w.rows())[0]).toMatchObject({ state: 'released', releasedReason: 'settled' });
    expect(w.panel.patches).toEqual([]);
  });

  test('outside a restore the reconcile pass retries the write instead of releasing', async () => {
    const w = await claimed();
    vi.setSystemTime(NOW + HOST_OP_TTL_MS + HOST_SETTLE_MS + 1);
    await w.t.action(internal.hostOps.reconcileHosts, {});
    expect((await w.rows())[0]).toMatchObject({ state: 'unresolved', quietLooks: 1 });
    await w.t.action(internal.hostOps.reconcileHosts, {});
    expect(w.panel.patches).toEqual([{ uuid: D1, isDisabled: true }]);
    expect((await w.rows())[0]).toMatchObject({ state: 'confirmed', attempt: 2 });
  });
});

describe('acceptance 17: a direct Host reappears on a bound guided relay', () => {
  test('delivery answers leak_detected (never the origin body); reconcile re-hides a covered one and delivery serves again', async () => {
    const { t, panel, relayId, download, relay } = await world();
    const hid = await t.action(internal.edgeHostHides.hide, { relayId, approvedUuids: [] });
    expect(hid).toMatchObject({ hidden: 1 });
    const ok = await download();
    expect(ok.status).toBe(200);
    expect(ok.body).toContain(EDGE_A);
    expect(ok.body).not.toContain(FIXTURE_ORIGIN);
    // Someone re-enables the direct Host in the panel.
    panel.find(D1).isDisabled = false;
    const leak = await download();
    expect(leak.status).toBe(503);
    expect(leak.reason).toBe('leak_detected');
    expect(leak.body).not.toContain(FIXTURE_ORIGIN);
    // The reconcile pass re-hides it (a hide row exists for it, and its inbound is covered).
    const r = await t.action(internal.edgeHostHides.reobserveDirect, {});
    expect(r).toEqual({ relays: 1, rehidden: 1, alerted: 0 });
    expect(panel.find(D1).isDisabled).toBe(true);
    expect((await relay()).directHostAlert).toBeUndefined();
    const again = await download();
    expect(again.status).toBe(200);
    expect(again.body).not.toContain(FIXTURE_ORIGIN);
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.filter((a) => a.action === 'edge.host.hidden').at(-1)?.payload).toMatchObject({
      rehidden: true,
      count: 1,
    });
  });

  test('an uncovered, never-approved direct Host raises direct_host_reappeared instead of a write; suppressed while a restore runs', async () => {
    const { t, panel, relayId, relay } = await world();
    await t.action(internal.edgeHostHides.hide, { relayId, approvedUuids: [] });
    // A new direct Host on an inbound no listener covers appears.
    panel.hosts.push({
      uuid: D2,
      remark: `${FIXTURE_NODE}-ws`,
      address: FIXTURE_ORIGIN,
      port: 8443,
      isDisabled: false,
      inbound: inbound(WS_INBOUND),
    });
    const r1 = await t.action(internal.edgeHostHides.reobserveDirect, {});
    expect(r1).toEqual({ relays: 1, rehidden: 0, alerted: 1 });
    expect(panel.find(D2).isDisabled).toBe(false);
    expect(panel.patches.filter((p) => p.uuid === D2)).toEqual([]);
    const alert = (await relay()).directHostAlert;
    expect(alert?.hosts.map((h) => h.uuid)).toEqual([D2]);
    const attention = await t.query(internal.edgeOperator.attention, {});
    expect(attention.items.find((i) => i.kind === 'direct_host_reappeared')).toMatchObject({
      severity: 'critical',
      action: 'open_relay',
      facts: { count: 1, remarks: [`${FIXTURE_NODE}-ws`] },
    });
    // Hidden by the operator: the alert clears on the next pass.
    panel.find(D2).isDisabled = true;
    await t.action(internal.hostOps.reconcileHosts, {});
    expect((await relay()).directHostAlert).toBeUndefined();
    // While a restore workflow runs nothing is re-hidden and nothing is alerted.
    panel.find(D1).isDisabled = false;
    await t.mutation(internal.edgeRestore.start, { relayId, purpose: 'release_requirement' });
    const before = panel.patches.length;
    await t.action(internal.hostOps.reconcileHosts, {});
    expect(panel.patches).toHaveLength(before);
    expect((await relay()).directHostAlert).toBeUndefined();
  });
});

describe('cohorts', () => {
  test('one representative per placement among the active keys pinned to the node, every page walked, total reported', async () => {
    const { t, serverId, subId } = await world({ deferred: true });
    await t.run(async (ctx) => {
      const sub = (await ctx.db.get(subId))!;
      for (let i = 0; i < 450; i++) {
        await ctx.db.insert('subscriptions', {
          userId: sub.userId,
          backend: 'remnawave',
          backendUserId: `u-${i}`,
          backendShortId: `s-${i}`,
          backendServerId: serverId,
          subscriptionUrl: `https://panel.example/sub/s-${i}`,
          subscriptionMirrors: [],
          state: i % 7 === 0 ? 'deleted' : 'active',
          pinnedNode: i % 5 === 0 ? 'node-two' : FIXTURE_NODE,
          backendPlacement: i % 3 === 0 ? 'squad-2' : i % 3 === 1 ? undefined : 'squad-1',
          updatedAt: Date.now(),
        });
      }
    });
    const report = await t.run((ctx) =>
      cohortReportForOrigin(ctx, { backendServerId: serverId, nodeName: FIXTURE_NODE }),
    );
    expect(report.cohorts.map((c) => c.key).sort()).toEqual(['default', 'squad-1', 'squad-2']);
    expect(report.cohorts.find((c) => c.key === 'squad-1')?.subscriptionId).toBe(subId);
    // 1 seeded + the inserted rows that are active AND pinned to node-one.
    let expected = 1;
    for (let i = 0; i < 450; i++) if (i % 7 !== 0 && i % 5 !== 0) expected++;
    expect(report.total).toBe(expected);
    const other = await t.run((ctx) =>
      cohortReportForOrigin(ctx, { backendServerId: serverId, nodeName: 'node-nine' }),
    );
    expect(other).toEqual({ cohorts: [], total: 0 });
  });
});
