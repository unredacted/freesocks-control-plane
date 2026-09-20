/// <reference types="vite/client" />
/**
 * The restore workflow (convex/edgeRestore.ts), for all three purposes, with a
 * member download through the real fronted route between EVERY phase:
 * settle -> raw FCP body verified -> binding released with the origin enabled
 * and its edges published -> direct Hosts restored -> direct body verified ->
 * the purpose's finish. A direct Host is never enabled while the origin is
 * bound (pinned by an ordering assertion inside the backend write itself).
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { judgeRawBody } from './edgeRestore';
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

function panelHosts(): PanelHostRow[] {
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
      isDisabled: false,
      inbound: inbound(FIXTURE_INBOUND),
    },
    {
      uuid: D2,
      remark: `${FIXTURE_NODE}-ws`,
      address: FIXTURE_ORIGIN,
      port: 8443,
      sni: null,
      isDisabled: false,
      inbound: inbound(WS_INBOUND),
    },
  ];
}

/**
 * Backend + origin `node-one` (REALITY listener `a`) with a verified published L4
 * edge at EDGE_A, one member key pinned to the node, rendering on, and BOTH
 * direct Hosts hidden through the ledger (D2 approved). `bound` = the delivery
 * binding is claimed (a go-live happened); otherwise a guided origin before it.
 */
async function world(opts: { bound: boolean }) {
  const panel = fakeHostPanel(panelHosts());
  const t = convexTest(schema, modules);
  const fx = await seedEdgeFixture(t, { listeners: [realityListener()] });
  await t.run(async (ctx) => {
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
    await upsertSettingRow(ctx, 'edge.enabled', 'true');
    await upsertSettingRow(ctx, 'edge.autoProvisionToDesired', 'true');
  });
  const a = await adoptL4Edge(t, fx.relayId, fx.listenerId, { ipv4: EDGE_A, publish: true });
  await t.run(async (ctx) => {
    await ctx.db.patch(fx.relayId, {
      setupStage: opts.bound ? 'done' : 'publish',
      ...(opts.bound ? {} : { bindingDeferred: true, setupOwned: true }),
    });
    if (!opts.bound)
      for (const b of await ctx.db.query('edgeDeliveryBindings').collect())
        await ctx.db.delete(b._id);
  });
  const hid = await t.action(internal.edgeHostHides.hide, {
    relayId: fx.relayId,
    runId: 'run-1',
    approvedUuids: [D2],
    nodeInboundUuids: [FIXTURE_INBOUND, WS_INBOUND],
  });
  expect(hid).toMatchObject({ state: 'confirmed', hidden: 2 });
  let n = 0;
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
  const edge = async () => (await t.run((ctx) => ctx.db.get(a.edgeId as Id<'edges'>)))!;
  const binding = async () =>
    (await t.run((ctx) => ctx.db.query('edgeDeliveryBindings').collect())).find(
      (b) => b.relaySlug === 'node-one',
    ) ?? null;
  const rows = () =>
    t.run((ctx) =>
      ctx.db
        .query('edgeHostHides')
        .withIndex('by_relay', (q) => q.eq('relayId', fx.relayId))
        .collect(),
    );
  const step = () => t.action(internal.edgeRestore.step, { relayId: fx.relayId });
  return {
    ...fx,
    panel,
    download,
    relay,
    edge,
    binding,
    rows,
    step,
    edgeId: a.edgeId as Id<'edges'>,
  };
}

describe('judgeRawBody (pure)', () => {
  const ctx = {
    originAddress: FIXTURE_ORIGIN,
    fcpRemarks: [TEMPLATE],
    nodeName: FIXTURE_NODE,
    edgeAddresses: [EDGE_A],
  };
  const line = (addr: string, remark: string) =>
    `vless://u@${addr}:443?security=reality&sni=x.example&pbk=P&type=tcp#${remark}`;

  test('counts FCP entries (remark or edge address) and origin entries (address); unreadable when nothing parses', () => {
    expect(
      judgeRawBody(
        [line(EDGE_A, TEMPLATE), line(FIXTURE_ORIGIN, 'node-one-reality')].join('\n'),
        ctx,
      ),
    ).toEqual({ entries: 2, fcp: 1, direct: 1, unreadable: false });
    expect(judgeRawBody(line('198.51.100.9', TEMPLATE), ctx)).toMatchObject({ fcp: 1, direct: 0 });
    expect(judgeRawBody(line(EDGE_A, 'renamed'), ctx)).toMatchObject({ fcp: 1, direct: 0 });
    expect(judgeRawBody(line('198.51.100.9', 'renamed'), ctx)).toMatchObject({ fcp: 0, direct: 0 });
    expect(judgeRawBody('', ctx).unreadable).toBe(true);
    expect(judgeRawBody('not a body', ctx).unreadable).toBe(true);
  });
});

describe('acceptance 14: restore-direct deletion of a guided origin, a download between every phase', () => {
  test('settle -> raw FCP body verified -> binding released with the origin enabled and edges published -> direct Hosts restored -> drain; a direct Host is never enabled while bound', async () => {
    const w = await world({ bound: true });
    // Bound: the member gets the rendered body (edge address, never the origin).
    const rendered = await w.download();
    expect(rendered.status).toBe(200);
    expect(rendered.body).toContain(EDGE_A);
    expect(rendered.body).not.toContain(FIXTURE_ORIGIN);
    // THE ordering pin: every enable write happens with the binding already released.
    const enablesSeen: string[] = [];
    w.panel.onPatch(async (p) => {
      if (p.isDisabled) return;
      const b = await w.binding();
      const r = await w.relay();
      expect(b?.state).toBe('released');
      expect(r.enabled).toBe(true);
      expect(r.publishedEdgeIds.filter(Boolean)).toHaveLength(1);
      enablesSeen.push(p.uuid);
    });

    const res = await w.t.mutation(internal.relays.requestDelete, {
      id: w.relayId,
      disposition: 'restore-direct',
    });
    expect(res).toEqual({ ok: true, deleted: false, restore: true });
    let relay = await w.relay();
    expect(relay.restore).toMatchObject({ purpose: 'delete_relay', phase: 'freeze' });
    expect(relay.deleting).toBeUndefined();
    expect(relay.enabled).toBe(true);
    expect((await w.edge()).publication).toBe('published');
    expect((await w.binding())?.state).toBe('active');
    // Attention says so; a second workflow and a second delete are refused.
    const att = await w.t.query(internal.edgeOperator.attention, {});
    expect(att.items.find((i) => i.kind === 'restore_in_progress')).toMatchObject({
      severity: 'info',
      facts: { purpose: 'delete_relay', phase: 'freeze' },
    });
    await expect(
      w.t.mutation(internal.relays.requestDelete, { id: w.relayId, disposition: 'restore-direct' }),
    ).rejects.toThrow(/restore_in_progress/);
    await expect(
      w.t.mutation(internal.edgeRestore.start, { relayId: w.relayId, purpose: 'cancel_setup' }),
    ).rejects.toThrow(/restore_in_progress/);
    // Pool writes wait too.
    await expect(
      w.t.mutation(internal.relays.unpublishEdge, { relayId: w.relayId, edgeId: w.edgeId }),
    ).rejects.toThrow(/restore_in_progress/);

    const stillRendered = async () => {
      const d = await w.download();
      expect(d.status).toBe(200);
      expect(d.body).toContain(EDGE_A);
      expect(d.body).not.toContain(FIXTURE_ORIGIN);
    };
    expect(await w.step()).toMatchObject({ phase: 'settle', advanced: true });
    await stillRendered();
    expect(await w.step()).toMatchObject({ phase: 'verify_fcp_raw', advanced: true });
    await stillRendered();
    expect(await w.step()).toMatchObject({ phase: 'release_binding', advanced: true });
    await stillRendered();
    // Phase 4: the binding goes while the origin stays enabled and its edge published.
    expect(await w.step()).toMatchObject({ phase: 'restore', advanced: true });
    expect((await w.binding())?.state).toBe('released');
    relay = await w.relay();
    expect(relay.enabled).toBe(true);
    expect((await w.edge()).publication).toBe('published');
    // Raw delivery of the FCP-Host body: the member keeps the protected entry; the direct Hosts are still hidden.
    const raw = await w.download();
    expect(raw.status).toBe(200);
    expect(raw.body).toContain(EDGE_A);
    expect(raw.body).not.toContain(FIXTURE_ORIGIN);
    expect(w.panel.find(D1).isDisabled).toBe(true);
    expect(w.panel.find(D2).isDisabled).toBe(true);
    // Phase 5: the direct Hosts come back (read-back confirmed).
    expect(await w.step()).toMatchObject({ phase: 'verify_direct', advanced: true });
    expect(enablesSeen.sort()).toEqual([D1, D2].sort());
    expect(w.panel.find(D1).isDisabled).toBe(false);
    expect(w.panel.find(D2).isDisabled).toBe(false);
    const direct = await w.download();
    expect(direct.status).toBe(200);
    expect(direct.reason).toBeNull();
    expect(direct.body).toContain(FIXTURE_ORIGIN);
    expect((await w.rows()).map((r) => r.state)).toEqual([
      'released',
      'released',
      'released',
      'released',
    ]);
    expect(await w.step()).toMatchObject({ phase: 'finish', advanced: true });
    // Phase 7: only now the deletion body runs.
    expect(await w.step()).toMatchObject({ done: true, advanced: true });
    relay = await w.relay();
    expect(relay).toMatchObject({ deleting: true, enabled: false, publishedEdgeIds: [] });
    expect(relay.restore).toBeUndefined();
    expect((await w.edge()).status).toBe('destroyed'); // observe-only import: forgotten at once
    const after = await w.download();
    expect(after.status).toBe(200);
    expect(after.body).toContain(FIXTURE_ORIGIN);
    const audit = (await w.t.run((ctx) => ctx.db.query('auditLog').collect())).map((a) => a.action);
    expect(audit).toContain('edge.relay.restore_started');
    expect(audit).toContain('relay.delivery.released');
    expect(audit).toContain('edge.host.restored');
    expect(audit).toContain('edge.relay.restore_finished');
    expect(audit.filter((a) => a === 'relay.delete')).toHaveLength(1);
    // The reconcile cron finishes the delete as before.
    await w.t.action(internal.edgeReconcile.run, {});
    expect(await w.t.run((ctx) => ctx.db.get(w.relayId))).toBeNull();
  });

  test('keep-dark keeps the binding, restores nothing and tears down at once (unchanged)', async () => {
    const w = await world({ bound: true });
    const res = await w.t.mutation(internal.relays.requestDelete, {
      id: w.relayId,
      disposition: 'keep-dark',
    });
    expect(res).toEqual({ ok: true, deleted: false });
    const relay = await w.relay();
    expect(relay).toMatchObject({ deleting: true, enabled: false });
    expect(relay.restore).toBeUndefined();
    expect((await w.binding())?.state).toBe('active');
    expect(w.panel.find(D1).isDisabled).toBe(true);
    expect(w.panel.patches.filter((p) => !p.isDisabled)).toEqual([]);
    expect((await w.rows()).every((r) => r.state === 'confirmed')).toBe(true);
    const d = await w.download();
    expect(d.status).toBe(503);
    expect(d.reason).toBe('relay_disabled');
  });

  test('a role-registered origin that never hid a Host still tears down at once', async () => {
    const panel = fakeHostPanel(panelHosts());
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t, { listeners: [realityListener()] });
    const res = await t.mutation(internal.relays.requestDelete, {
      id: fx.relayId,
      disposition: 'restore-direct',
    });
    expect(res).toEqual({ ok: true, deleted: false });
    expect((await t.run((ctx) => ctx.db.get(fx.relayId)))!.deleting).toBe(true);
    expect(panel.patches).toEqual([]);
  });
});

describe('acceptance 5 + 25: cancel_setup after publication', () => {
  test('edges stay published; settle + restore (an admin-edited Host released untouched); origin retained, owned + unbound, go_live_pending; upkeep still skips it', async () => {
    const w = await world({ bound: false });
    // Not bound: the member already gets the raw FCP-only body.
    const before = await w.download();
    expect(before.status).toBe(200);
    expect(before.body).toContain(EDGE_A);
    expect(before.body).not.toContain(FIXTURE_ORIGIN);
    // An administrator re-ENABLED D2 meanwhile: it is theirs again, released
    // without a write. (A Host merely re-pointed while still disabled is NOT
    // theirs: the bit is the one FCP wrote, and the restore re-enables it.)
    w.panel.find(D2).isDisabled = false;
    await w.t.mutation(internal.edgeRestore.start, {
      relayId: w.relayId,
      purpose: 'cancel_setup',
      actorAdminId: undefined,
    });
    const phases: string[] = [];
    for (let i = 0; i < 10; i++) {
      const r = await w.step();
      const d = await w.download();
      expect(d.status).toBe(200);
      expect(d.reason).toBeNull();
      if (r.done) break;
      phases.push(r.phase!);
      expect(r.advanced).toBe(true);
    }
    // Not bound: verify_fcp_raw is skipped; release_binding is a no-op phase.
    expect(phases).toEqual(['settle', 'release_binding', 'restore', 'verify_direct', 'finish']);
    // D1 restored; D2 released without a write.
    expect(w.panel.patches.filter((p) => !p.isDisabled)).toEqual([{ uuid: D1, isDisabled: false }]);
    expect(w.panel.find(D1).isDisabled).toBe(false);
    expect(w.panel.find(D2).isDisabled).toBe(false);
    const rows = await w.rows();
    expect(rows.find((r) => r.hostUuid === D2 && r.intent === 'disable')).toMatchObject({
      state: 'released',
      releasedReason: 'changed',
    });
    expect(rows.find((r) => r.hostUuid === D1 && r.intent === 'disable')).toMatchObject({
      state: 'released',
      releasedReason: 'restored',
    });
    const relay = await w.relay();
    expect(relay.restore).toBeUndefined();
    expect(relay).toMatchObject({ setupOwned: true, bindingDeferred: true, enabled: true });
    expect(relay.deleting).toBeUndefined();
    expect((await w.edge()).publication).toBe('published');
    expect(await w.binding()).toBeNull();
    const att = await w.t.query(internal.edgeOperator.attention, {});
    expect(
      att.items.some((i) => i.kind === 'go_live_pending' && i.relayId === (w.relayId as string)),
    ).toBe(true);
    expect(att.items.some((i) => i.kind === 'restore_in_progress')).toBe(false);
    // Upkeep skips an owned origin: no rotation, the pool untouched.
    const rep = await w.t.action(internal.edgeReconcile.run, {});
    expect(rep.started).toBe(0);
    expect((await w.relay()).activeRotationId).toBeUndefined();
    expect((await w.edge()).publication).toBe('published');
    // The direct body is back for members.
    const after = await w.download();
    expect(after.body).toContain(FIXTURE_ORIGIN);
  });
});

describe('acceptance 25: release_requirement', () => {
  test('retains everything (origin enabled, edges published), releases the binding after the raw FCP check, restores the Hosts and leaves the origin re-activatable', async () => {
    const w = await world({ bound: true });
    expect((await w.download()).body).toContain(EDGE_A);
    await w.t.mutation(internal.edgeRestore.start, {
      relayId: w.relayId,
      purpose: 'release_requirement',
    });
    // A hide is refused while it runs (freeze).
    await expect(
      w.t.action(internal.edgeHostHides.hide, { relayId: w.relayId, approvedUuids: [] }),
    ).rejects.toThrow(/restore_in_progress/);
    const phases: string[] = [];
    for (let i = 0; i < 10; i++) {
      const r = await w.step();
      const d = await w.download();
      expect(d.status).toBe(200);
      expect(d.reason).toBeNull();
      if (r.done) break;
      phases.push(r.phase!);
    }
    expect(phases).toEqual([
      'settle',
      'verify_fcp_raw',
      'release_binding',
      'restore',
      'verify_direct',
      'finish',
    ]);
    const relay = await w.relay();
    expect(relay.restore).toBeUndefined();
    expect(relay).toMatchObject({ enabled: true, bindingDeferred: true });
    expect(relay.setupOwned).toBeUndefined();
    expect(relay.deleting).toBeUndefined();
    expect((await w.edge()).publication).toBe('published');
    expect((await w.binding())?.state).toBe('released');
    expect(w.panel.find(D1).isDisabled).toBe(false);
    expect(w.panel.find(D2).isDisabled).toBe(false);
    expect((await w.download()).body).toContain(FIXTURE_ORIGIN);
    // Re-activatable: the go-live card is offered again.
    const att = await w.t.query(internal.edgeOperator.attention, {});
    expect(att.items.some((i) => i.kind === 'go_live_pending')).toBe(true);
  });

  test('verify_fcp_raw refuses to release while a raw body still carries the origin address', async () => {
    const w = await world({ bound: true });
    await w.t.mutation(internal.edgeRestore.start, {
      relayId: w.relayId,
      purpose: 'release_requirement',
    });
    await w.step(); // settle
    await w.step(); // -> verify_fcp_raw
    // Someone re-enabled D1: the raw body carries the origin again.
    w.panel.find(D1).isDisabled = false;
    expect(await w.step()).toMatchObject({
      phase: 'verify_fcp_raw',
      advanced: false,
      error: 'direct_entry_present:squad-1',
    });
    expect((await w.binding())?.state).toBe('active');
    expect((await w.relay()).restore).toMatchObject({
      phase: 'verify_fcp_raw',
      attempt: 1,
      lastError: 'direct_entry_present:squad-1',
    });
    w.panel.find(D1).isDisabled = true;
    expect(await w.step()).toMatchObject({ phase: 'release_binding', advanced: true });
  });
});
