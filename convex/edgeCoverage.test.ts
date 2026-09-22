/// <reference types="vite/client" />
/**
 * Coverage model, deferred binding and the automation switch (docs/edges.md
 * § Publication, § Reconcile cron, § Operator endpoints). Every address is
 * RFC 5737 / `*.example`; no provider call is made (adopted edges only), so a
 * fetch that reaches the network is a test failure.
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { claimDeliveryBinding } from './relays';
import { scopeFor } from './httpEdges';
import {
  adoptL4Edge,
  createAccount,
  FIXTURE_CONFIG_PROFILE,
  FIXTURE_NODE,
  FIXTURE_ORIGIN,
  FIXTURE_PANEL_SLUG,
  insertPanelServer,
  realityListener,
  registerRelay,
  shadowsocksListener,
  wsListener,
} from './lib/edges/testing/fixtures';

const modules = import.meta.glob('./**/*.*s');

afterEach(() => {
  vi.unstubAllGlobals();
});

/** No test here may reach a provider or the backend. */
function forbidNetwork() {
  vi.stubGlobal('fetch', async (input: RequestInfo | URL) => {
    throw new Error(`unexpected fetch ${String(input)}`);
  });
}

async function world(opts: { hostMode?: 'operator'; listeners?: 'as' | 'a' } = {}) {
  forbidNetwork();
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
  const accountId = await createAccount(t, { provider: 'gcore', name: 'acct-a', qualified: true });
  const listeners =
    opts.listeners === 'a' ? [realityListener()] : [realityListener(), shadowsocksListener()];
  const { relayId, listenerIds } = await registerRelay(t, { listeners });
  if (opts.hostMode)
    await t.mutation(internal.relays.update, { id: relayId, hostMode: opts.hostMode });
  return { t, serverId, accountId, relayId, listenerIds };
}

const relayOf = (t: ReturnType<typeof convexTest>, id: Id<'relays'>) =>
  t.query(internal.relays.get, { id }).then((r) => r!);
const listenerOf = (t: ReturnType<typeof convexTest>, id: Id<'relayListeners'>) =>
  t.run((ctx) => ctx.db.get(id)).then((l) => l!);
const audits = (t: ReturnType<typeof convexTest>, action: string) =>
  t
    .run((ctx) => ctx.db.query('auditLog').collect())
    .then((rows) => rows.filter((a) => a.action === action));
const run = (t: ReturnType<typeof convexTest>) => t.action(internal.edgeReconcile.run, {});

/** Flip a listener's `enabled` bit WITHOUT the capacity hook (a pre-existing state). */
const setEnabledRaw = (
  t: ReturnType<typeof convexTest>,
  id: Id<'relayListeners'>,
  enabled: boolean,
) => t.run((ctx) => ctx.db.patch(id, { enabled }));

describe('coverage: capacity follows the deployed listeners', () => {
  test('by-slug registration raises desiredPublished to the listener count and warns edge.pool_raised', async () => {
    forbidNetwork();
    const t = convexTest(schema, modules);
    await insertPanelServer(t);
    const r = await t.mutation(internal.relays.registerBySlug, {
      slug: 'node-three',
      origin: { kind: 'panel-node', backendSlug: FIXTURE_PANEL_SLUG, nodeName: FIXTURE_NODE },
      originAddress: FIXTURE_ORIGIN,
      listeners: [
        realityListener(),
        shadowsocksListener(),
        wsListener({ originPort: 8443 }),
      ] as never,
      source: 'role',
    });
    expect(r.warnings).toEqual(['edge.pool_raised']);
    expect((await relayOf(t, r.id)).desiredPublished).toBe(3);
    const [reg] = await audits(t, 'relay.registered');
    expect(reg?.payload).toMatchObject({ poolRaised: true });
    // An identical re-registration changes nothing and warns nothing.
    const again = await t.mutation(internal.relays.registerBySlug, {
      slug: 'node-three',
      origin: { kind: 'panel-node', backendSlug: FIXTURE_PANEL_SLUG, nodeName: FIXTURE_NODE },
      originAddress: FIXTURE_ORIGIN,
      listeners: [
        realityListener(),
        shadowsocksListener(),
        wsListener({ originPort: 8443 }),
      ] as never,
      source: 'role',
    });
    expect(again.warnings).toEqual([]);
    expect(again.changed).toBe(false);
  });

  test('adding a listener in the CMS raises the pool too; the bound is 8', async () => {
    const { t, relayId } = await world({ listeners: 'a' });
    await t.mutation(internal.relays.update, { id: relayId, desiredPublished: 1 });
    const added = await t.mutation(internal.relayListeners.upsert, {
      relayId,
      spec: shadowsocksListener() as never,
    });
    expect(added.warnings).toEqual(['edge.pool_raised']);
    expect((await relayOf(t, relayId)).desiredPublished).toBe(2);
    await expect(
      t.mutation(internal.relays.update, { id: relayId, desiredPublished: 9 }),
    ).rejects.toThrow(/1\.\.8/);
    await t.mutation(internal.relays.update, { id: relayId, desiredPublished: 8 });
    expect((await relayOf(t, relayId)).desiredPublished).toBe(8);
    // Lowering the pool under the two coverage listeners is refused (the next
    // tick would only raise it back); the coverage count itself is allowed.
    await expect(
      t.mutation(internal.relays.update, { id: relayId, desiredPublished: 1 }),
    ).rejects.toThrow(/pool_below_coverage/);
    await t.mutation(internal.relays.update, { id: relayId, desiredPublished: 2 });
    expect((await relayOf(t, relayId)).desiredPublished).toBe(2);
    // Once a listener is disabled it no longer counts.
    await t.mutation(internal.relayListeners.setEnabled, { id: added.id, enabled: false });
    await t.mutation(internal.relays.update, { id: relayId, desiredPublished: 1 });
    expect((await relayOf(t, relayId)).desiredPublished).toBe(1);
  });

  test('a ninth deployed, enabled listener is refused (edge.listener_cap) at registration and at the CMS upsert; eight are fine', async () => {
    forbidNetwork();
    const t = convexTest(schema, modules);
    await insertPanelServer(t);
    const listener = (i: number) =>
      realityListener({
        listenerKey: `l${i}`,
        originPort: 10000 + i,
        panelBinding: {
          inboundTag: `VLESS_RELAY_L${i}`,
          configProfileUuid: FIXTURE_CONFIG_PROFILE,
          configProfileInboundUuid: `44444444-4444-4444-8444-4444444444${String(i).padStart(2, '0')}`,
        },
      });
    const body = (n: number) => ({
      slug: 'node-cap',
      origin: {
        kind: 'panel-node' as const,
        backendSlug: FIXTURE_PANEL_SLUG,
        nodeName: FIXTURE_NODE,
      },
      originAddress: FIXTURE_ORIGIN,
      listeners: Array.from({ length: n }, (_, i) => listener(i + 1)) as never,
      source: 'role' as const,
    });
    await expect(t.mutation(internal.relays.registerBySlug, body(9))).rejects.toThrow(
      /listener_cap.*at most 8|at most 8/,
    );
    const eight = await t.mutation(internal.relays.registerBySlug, body(8));
    expect((await relayOf(t, eight.id)).desiredPublished).toBe(8);
    // The identical body again is not "a ninth".
    expect((await t.mutation(internal.relays.registerBySlug, body(8))).changed).toBe(false);
    await expect(t.mutation(internal.relays.registerBySlug, body(9))).rejects.toThrow(
      /listener_cap/,
    );
    await expect(
      t.mutation(internal.relayListeners.upsert, { relayId: eight.id, spec: listener(9) as never }),
    ).rejects.toThrow(/listener_cap/);
    // An undeployed ninth is not a coverage listener and passes.
    await t.mutation(internal.relayListeners.upsert, {
      relayId: eight.id,
      spec: { ...listener(9), deployed: false } as never,
    });
    expect((await relayOf(t, eight.id)).desiredPublished).toBe(8);
  });

  test('a new origin carries no standbyPerListener override: the global default applies until the origin sets its own', async () => {
    const { t, relayId, listenerIds } = await world({ listeners: 'a', hostMode: 'operator' });
    expect((await relayOf(t, relayId)).standbyPerListener).toBeUndefined();
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.enabled', 'true'));
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.autoProvisionToDesired', 'true'));
    await t.mutation(internal.relays.update, { id: relayId, desiredPublished: 1 });
    await adoptL4Edge(t, relayId, listenerIds.a, { ipv4: '198.51.100.1', publish: true });
    expect((await run(t)).started).toBe(0);
    // A later change of the GLOBAL applies to the origin (no stale copy on the row).
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.standbyPerListener', '1'));
    expect((await run(t)).started).toBe(1);
    expect((await relayOf(t, relayId)).standbyPerListener).toBeUndefined();
  });
});

describe('coverage: reserved allocation on the direct publish path', () => {
  test('a second edge for A is refused while B is uncovered; B takes the reserved slot; then the pool is full', async () => {
    const { t, relayId, listenerIds } = await world();
    const a1 = await adoptL4Edge(t, relayId, listenerIds.a, {
      ipv4: '198.51.100.1',
      publish: true,
    });
    expect(a1.poolIndex).toBe(0);
    await expect(
      adoptL4Edge(t, relayId, listenerIds.a, { ipv4: '198.51.100.2', publish: true }),
    ).rejects.toThrow(/pool_reserved/);
    const s1 = await adoptL4Edge(t, relayId, listenerIds.s, {
      ipv4: '198.51.100.3',
      publish: true,
    });
    expect(s1.poolIndex).toBe(1);
    expect((await listenerOf(t, listenerIds.s)).templateEdgeId).toBe(s1.edgeId);
    await expect(
      adoptL4Edge(t, relayId, listenerIds.a, { ipv4: '198.51.100.4', publish: true }),
    ).rejects.toThrow(/pool_full/);
    // publishEdge obeys the same rule for a standby.
    await t.mutation(internal.relays.update, { id: relayId, desiredPublished: 3 });
    const a2 = await adoptL4Edge(t, relayId, listenerIds.a, { ipv4: '198.51.100.5' });
    const pub = await t.mutation(internal.relays.publishEdge, { relayId, edgeId: a2.edgeId });
    expect(pub.poolIndex).toBe(2);
  });
});

describe('coverage: repairing a pre-existing full pool', () => {
  test('two published A edges + uncovered B + desired 2 -> the reconcile expands to 3 (audited) and covers B', async () => {
    const { t, relayId, listenerIds } = await world({ hostMode: 'operator' });
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.enabled', 'true'));
    // The legacy state: B was disabled when both A edges were published.
    await setEnabledRaw(t, listenerIds.s, false);
    await adoptL4Edge(t, relayId, listenerIds.a, { ipv4: '198.51.100.1', publish: true });
    await adoptL4Edge(t, relayId, listenerIds.a, { ipv4: '198.51.100.2', publish: true });
    await setEnabledRaw(t, listenerIds.s, true);
    const standbyS = await adoptL4Edge(t, relayId, listenerIds.s, { ipv4: '198.51.100.3' });
    expect((await relayOf(t, relayId)).desiredPublished).toBe(2);
    const r = await run(t);
    expect(r.published).toBe(1);
    const relay = await relayOf(t, relayId);
    expect(relay.desiredPublished).toBe(3);
    expect(relay.publishedEdgeIds[2]).toBe(standbyS.edgeId);
    expect((await listenerOf(t, listenerIds.s)).templateEdgeId).toBe(standbyS.edgeId);
    const [expanded] = await audits(t, 'edge.pool_expanded');
    expect(expanded?.payload).toMatchObject({ from: 2, to: 3, blocked: 0 });
  });

  test('at the cap: attention pool_rebalance; rebalance unpublishes only the non-template duplicate', async () => {
    const { t, relayId, listenerIds } = await world({ hostMode: 'operator' });
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.enabled', 'true'));
    await t.mutation(internal.relays.update, { id: relayId, desiredPublished: 8 });
    await setEnabledRaw(t, listenerIds.s, false);
    const aEdges: Id<'edges'>[] = [];
    for (let i = 1; i <= 8; i++) {
      const e = await adoptL4Edge(t, relayId, listenerIds.a, {
        ipv4: `198.51.100.${i}`,
        publish: true,
      });
      aEdges.push(e.edgeId);
    }
    await setEnabledRaw(t, listenerIds.s, true);
    // No expansion is possible: the reconcile leaves the pool as it is.
    const r = await run(t);
    expect(r.published + r.started).toBe(0);
    expect((await relayOf(t, relayId)).desiredPublished).toBe(8);
    expect(await audits(t, 'edge.pool_expanded')).toEqual([]);
    const attention = await t.query(internal.edgeOperator.attention, {});
    const item = attention.items.find((i) => i.kind === 'pool_rebalance');
    expect(item).toMatchObject({
      action: 'rebalance',
      listenerKey: 's',
      facts: { published: 8, desired: 8, uncovered: 1 },
    });
    // The operator makes room: the HIGHEST-index duplicate goes back to standby.
    const e0 = (await relayOf(t, relayId)).publicationEpoch;
    const res = await t.mutation(internal.relays.rebalance, { relayId });
    expect(res).toMatchObject({ ok: true, edgeId: aEdges[7], poolIndex: 7, epoch: e0 + 1 });
    const relay = await relayOf(t, relayId);
    expect(relay.publishedEdgeIds).toEqual(aEdges.slice(0, 7));
    expect(relay.standbyEdgeIds).toEqual([aEdges[7]]);
    expect(await t.query(internal.edges.get, { id: aEdges[7] })).toMatchObject({
      status: 'active',
      publication: 'unpublished',
    });
    // The template edge of A is untouched.
    expect((await listenerOf(t, listenerIds.a)).templateEdgeId).toBe(aEdges[0]);
    expect((await audits(t, 'edge.relay.rebalanced'))[0]?.payload).toMatchObject({
      edgeId: aEdges[7],
      poolIndex: 7,
    });
    // Upkeep now publishes B into the freed slot (reserved for it: an A standby may not take it).
    const standbyS = await adoptL4Edge(t, relayId, listenerIds.s, { ipv4: '198.51.100.9' });
    const r2 = await run(t);
    expect(r2.published).toBe(1);
    expect((await relayOf(t, relayId)).publishedEdgeIds[7]).toBe(standbyS.edgeId);
    // Nothing left to rebalance once every published edge is a template edge.
    const { t: t2, relayId: relay2, listenerIds: l2 } = await world({ listeners: 'a' });
    await adoptL4Edge(t2, relay2, l2.a, { ipv4: '198.51.100.1', publish: true });
    await expect(t2.mutation(internal.relays.rebalance, { relayId: relay2 })).rejects.toThrow(
      /no_duplicate/,
    );
  });
});

describe('coverage: listener-aware reconcile upkeep', () => {
  test('a standby of A never counts for B: B gets its own provision, A keeps its standby', async () => {
    const { t, relayId, listenerIds } = await world({ hostMode: 'operator' });
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.enabled', 'true'));
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.autoProvisionToDesired', 'true'));
    await adoptL4Edge(t, relayId, listenerIds.a, { ipv4: '198.51.100.1', publish: true });
    const standbyA = await adoptL4Edge(t, relayId, listenerIds.a, { ipv4: '198.51.100.2' });
    const r = await run(t);
    expect(r.published).toBe(0);
    expect(r.started).toBe(1);
    const relay = await relayOf(t, relayId);
    expect(relay.publishedEdgeIds).toHaveLength(1);
    const rot = (await t.query(internal.edgeRotations.get, { id: relay.activeRotationId! }))!;
    expect(rot).toMatchObject({
      kind: 'provision',
      listenerId: listenerIds.s,
      publishOnDone: true,
    });
    expect(await t.query(internal.edges.get, { id: standbyA.edgeId })).toMatchObject({
      publication: 'unpublished',
    });
  });

  test('per-listener spares: standbyPerListener provisions an unpublished edge for the listener that is short', async () => {
    const { t, relayId, listenerIds } = await world({ listeners: 'a', hostMode: 'operator' });
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.enabled', 'true'));
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.autoProvisionToDesired', 'true'));
    await t.mutation(internal.relays.update, { id: relayId, desiredPublished: 1 });
    await adoptL4Edge(t, relayId, listenerIds.a, { ipv4: '198.51.100.1', publish: true });
    // Default 0 spares of either kind: nothing starts.
    expect((await run(t)).started).toBe(0);
    await t.mutation(internal.relays.update, { id: relayId, standbyPerListener: 1 });
    expect((await run(t)).started).toBe(1);
    const relay = await relayOf(t, relayId);
    const rot = (await t.query(internal.edgeRotations.get, { id: relay.activeRotationId! }))!;
    expect(rot).toMatchObject({
      kind: 'provision',
      listenerId: listenerIds.a,
      publishOnDone: false,
    });
    await expect(
      t.mutation(internal.relays.update, { id: relayId, standbyPerListener: 3 }),
    ).rejects.toThrow(/0\.\.2/);
  });

  test('a setupOwned origin is skipped by upkeep even with a standby and the switches on', async () => {
    forbidNetwork();
    const t = convexTest(schema, modules);
    const serverId = await insertPanelServer(t);
    await createAccount(t, { provider: 'gcore', name: 'acct-a', qualified: true });
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.enabled', 'true'));
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.autoProvisionToDesired', 'true'));
    const { id: relayId } = await t.mutation(internal.relays.create, {
      slug: 'guided',
      origin: { kind: 'panel-node', backendServerId: serverId, nodeName: FIXTURE_NODE },
      originAddress: FIXTURE_ORIGIN,
      hostMode: 'operator',
      listeners: [realityListener()] as never,
      deferBinding: true,
      setupOwned: true,
    });
    const listener = await t.run((ctx) =>
      ctx.db
        .query('relayListeners')
        .withIndex('by_relay', (q) => q.eq('relayId', relayId))
        .unique(),
    );
    await adoptL4Edge(t, relayId, listener!._id, { ipv4: '198.51.100.2' });
    const r = await run(t);
    expect(r.published + r.started).toBe(0);
    expect((await relayOf(t, relayId)).publishedEdgeIds).toEqual([]);
    // Nor can a hand-started rotation touch it: only the run's own starts do.
    const adopted = await adoptL4Edge(t, relayId, listener!._id, { ipv4: '198.51.100.3' });
    await expect(
      t.mutation(internal.edgeRotations.start, {
        relayId,
        kind: 'publish',
        trigger: 'manual',
        toEdgeId: adopted.edgeId as Id<'edges'>,
      }),
    ).rejects.toMatchObject({ data: { code: 'edge.setup_owned' } });
  });
});

describe('deferred binding and setup ownership', () => {
  async function guided() {
    forbidNetwork();
    const t = convexTest(schema, modules);
    const serverId = await insertPanelServer(t);
    await createAccount(t, { provider: 'gcore', name: 'acct-a', qualified: true });
    const { id: relayId } = await t.mutation(internal.relays.create, {
      slug: 'guided',
      origin: { kind: 'panel-node', backendServerId: serverId, nodeName: FIXTURE_NODE },
      originAddress: FIXTURE_ORIGIN,
      hostMode: 'operator',
      listeners: [realityListener()] as never,
      deferBinding: true,
      setupOwned: true,
    });
    const listener = (await t.run((ctx) =>
      ctx.db
        .query('relayListeners')
        .withIndex('by_relay', (q) => q.eq('relayId', relayId))
        .unique(),
    ))!;
    const policy = () =>
      t.query(internal.edgeRender.deliveryPolicy, {
        backendServerId: serverId,
        nodeName: FIXTURE_NODE,
      });
    return { t, serverId, relayId, listenerId: listener._id, policy };
  }

  test('a deferred insert serves raw; a published edge does NOT bind it (no shortcut)', async () => {
    const { t, relayId, listenerId, policy } = await guided();
    const relay = await relayOf(t, relayId);
    expect(relay).toMatchObject({ bindingDeferred: true, setupOwned: true });
    expect((await policy()).required).toBe(false);
    expect(await t.run((ctx) => ctx.db.query('edgeDeliveryBindings').collect())).toEqual([]);
    await adoptL4Edge(t, relayId, listenerId, { ipv4: '198.51.100.1', publish: true });
    expect((await policy()).required).toBe(false);
    // The admin view says so; the create audit records the deferral (a boolean).
    const view = await t.query(internal.relays.listForAdmin, {});
    expect(view.find((r) => r.slug === 'guided')).toMatchObject({
      bindingDeferred: true,
      setupOwned: true,
    });
    expect((await audits(t, 'relay.create'))[0]?.payload).toMatchObject({ bindingDeferred: true });
  });

  test('by-slug registration binds immediately, and a re-registration of a deferred origin keeps it deferred', async () => {
    const { t, serverId, relayId, policy } = await guided();
    // A by-slug re-registration of the guided origin (identical origin; the CMS
    // path, since the listener is admin-owned): still no binding.
    await t.mutation(internal.relays.registerBySlug, {
      slug: 'guided',
      origin: { kind: 'panel-node', backendSlug: FIXTURE_PANEL_SLUG, nodeName: FIXTURE_NODE },
      originAddress: FIXTURE_ORIGIN,
      listeners: [realityListener()] as never,
      source: 'admin',
      pruneListeners: false,
    });
    expect((await relayOf(t, relayId)).bindingDeferred).toBe(true);
    expect((await policy()).required).toBe(false);
    // A fresh role registration of another node binds at once.
    const other = await t.mutation(internal.relays.registerBySlug, {
      slug: 'node-two',
      origin: { kind: 'panel-node', backendSlug: FIXTURE_PANEL_SLUG, nodeName: 'node-two' },
      originAddress: '203.0.113.11',
      listeners: [
        realityListener({
          panelBinding: {
            inboundTag: 'VLESS_RELAY_A',
            configProfileUuid: FIXTURE_CONFIG_PROFILE,
            configProfileInboundUuid: '55555555-5555-4555-8555-555555555555',
          },
        }),
      ] as never,
      source: 'role',
    });
    expect((await relayOf(t, other.id)).bindingDeferred).toBeUndefined();
    expect(
      (
        await t.query(internal.edgeRender.deliveryPolicy, {
          backendServerId: serverId,
          nodeName: 'node-two',
        })
      ).required,
    ).toBe(true);
  });

  test('claimDeliveryBinding binds, bumps the policy version, refreshes mirrors and clears the flag', async () => {
    const { t, relayId, policy } = await guided();
    const scheduled = vi.fn();
    await t.run(async (ctx) => {
      const relay = (await ctx.db.get(relayId))!;
      await claimDeliveryBinding(
        {
          ...ctx,
          scheduler: { ...ctx.scheduler, runAfter: scheduled },
        } as never,
        relay,
      );
    });
    expect((await relayOf(t, relayId)).bindingDeferred).toBeUndefined();
    const p = await policy();
    expect(p).toMatchObject({ required: true, bindingVersion: 1, relaySlug: 'guided' });
    expect(scheduled).toHaveBeenCalledTimes(1);
    // Claiming again bumps the version (the sub cache re-keys) and stays idempotent otherwise.
    await t.run(async (ctx) => claimDeliveryBinding(ctx as never, (await ctx.db.get(relayId))!));
    expect((await policy()).bindingVersion).toBe(2);
  });

  test('setup-status warns binding_deferred on the publish step; attention raises go_live_pending once an edge is published', async () => {
    const { t, relayId, listenerId } = await guided();
    const before = await t.query(internal.edgeOperator.attention, {});
    expect(before.items.some((i) => i.kind === 'go_live_pending')).toBe(false);
    expect(before.items.some((i) => i.kind === 'members_dark')).toBe(false);
    await adoptL4Edge(t, relayId, listenerId, { ipv4: '198.51.100.1', publish: true });
    const status = await t.query(internal.edgeOperator.setupStatus, { relaySlug: 'guided' });
    const publish = status.steps.find((s) => s.id === 'publish')!;
    expect(publish.warnings.map((w) => w.code)).toContain('binding_deferred');
    expect(
      status.steps.flatMap((s) => [...s.blockers, ...s.warnings]).map((b) => b.code),
    ).not.toContain('members_dark');
    const after = await t.query(internal.edgeOperator.attention, {});
    const item = after.items.find((i) => i.kind === 'go_live_pending');
    expect(item).toMatchObject({
      action: 'require_edges',
      relaySlug: 'guided',
      edgeId: null,
      facts: { published: 1 },
    });
  });
});

describe('the automation switch', () => {
  test('sets exactly the listed keys, touches no origin row, and audits the boolean', async () => {
    const { t, relayId } = await world({ listeners: 'a' });
    const setting = (key: string) =>
      t
        .run((ctx) =>
          ctx.db
            .query('appSettings')
            .withIndex('by_key', (q) => q.eq('key', key))
            .unique(),
        )
        .then((row) => (row ? JSON.parse(row.value) : undefined));
    const before = await relayOf(t, relayId);
    const on = await t.mutation(internal.edgeAdmin.setAutomation, { on: true });
    expect(on.changedKeys.sort()).toEqual(
      [
        'edge.enabled',
        'edge.autoRotate',
        'edge.probe.enabled',
        'edge.autoProvisionToDesired',
        'edge.standbyPerListener',
      ].sort(),
    );
    expect(await setting('edge.enabled')).toBe(true);
    expect(await setting('edge.autoRotate')).toBe(true);
    expect(await setting('edge.probe.enabled')).toBe(true);
    expect(await setting('edge.autoProvisionToDesired')).toBe(true);
    expect(await setting('edge.standbyPerListener')).toBe(1);
    expect(await setting('edge.render.enabled')).toBeUndefined();
    expect(await setting('edge.l7.autoSelect')).toBeUndefined();
    const cfg = await t.query(internal.edgeReconcileMutations.configSnapshot, {});
    expect(cfg).toMatchObject({
      enabled: true,
      autoRotate: true,
      autoProvisionToDesired: true,
      standbyPerListener: 1,
      probe: { enabled: true },
      render: { enabled: false },
      l7: { autoSelect: false },
    });
    // No origin row changed (its own autoRotate keeps its meaning under the gate).
    expect(await relayOf(t, relayId)).toEqual(before);
    expect((await audits(t, 'edge.automation.set'))[0]?.payload).toEqual({ on: true });
    // Off: the four switches go off; the spare count is left as it was.
    const off = await t.mutation(internal.edgeAdmin.setAutomation, { on: false });
    expect(off.changedKeys).not.toContain('edge.standbyPerListener');
    expect(await setting('edge.enabled')).toBe(false);
    expect(await setting('edge.autoProvisionToDesired')).toBe(false);
    expect(await setting('edge.standbyPerListener')).toBe(1);
    // The route is a settings write, like `config`.
    expect(scopeFor(['automation'], 'POST')).toBe('admin:settings:write');
    expect(scopeFor(['relays', 'r', 'rebalance'], 'POST')).toBe('admin:servers:write');
  });
});
