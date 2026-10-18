/// <reference types="vite/client" />
/**
 * The one origin status, end to end: the attention response carries one status
 * per origin (deleting ones included, slug order) and the fleet headline, both
 * judged by lib/edges/originStatus.ts on the facts the attention query reads;
 * the per-origin setup status carries the same delivery judgement plus the
 * sample render. Fixtures only (RFC 5737, `*.example`).
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { defaultLocationOf } from './edgeLocations';
import { adoptL4Edge, registerRelay, seedEdgeFixture } from './lib/edges/testing/fixtures';
import { AttentionResponse, SetupStatusResponse } from '../src/shared/contracts/edges';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;

beforeEach(() => {
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

async function quarantine(t: T, relayId: Id<'relays'>) {
  const rotationId = await t.run((ctx) =>
    ctx.db.insert('edgeRotations', {
      relayId,
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
      updatedAt: Date.now(),
    }),
  );
  await t.run((ctx) =>
    ctx.db.patch(relayId, {
      quarantine: { rotationId, since: Date.now(), reason: 'hosts_changed' },
    }),
  );
}

/** A guided setup run row parked on the operator at `try_it`. */
async function parkedRun(
  t: T,
  opts: {
    relayId: Id<'relays'>;
    slug: string;
    serverId: Id<'backendServers'>;
    accountId: Id<'edgeProviderAccounts'>;
    kind?: 'reprotect';
  },
) {
  const now = Date.now();
  return t.run(async (ctx) => {
    const account = (await ctx.db.get(opts.accountId))!;
    const location = (await defaultLocationOf(ctx.db, account))!;
    return ctx.db.insert('edgeSetupRuns', {
      relayId: opts.relayId,
      relaySlug: opts.slug,
      backendServerId: opts.serverId,
      nodeName: opts.slug,
      nodeUuid: '55555555-5555-4555-8555-555555555555',
      picks: [{ locationId: location._id, accountId: opts.accountId }],
      plan: '{}',
      planHash: 'fixture',
      planRevision: 1,
      approvedHideUuids: [],
      ...(opts.kind ? { kind: opts.kind } : {}),
      stage: 'try_it',
      state: 'needs_you',
      need: { code: 'try_it' },
      generation: 1,
      stepVersion: 1,
      listeners: [],
      stageEnteredAt: now,
      events: [],
      startedAt: now,
      updatedAt: now,
    });
  });
}

describe('the attention response carries the one origin status', () => {
  test('one row per origin in slug order, the kinds the facts call for, and the fleet', async () => {
    const t = convexTest(schema, modules);
    const f = await seedEdgeFixture(t);
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.render.enabled', 'true'));
    // node-one: bound, one edge published, render on.
    await adoptL4Edge(t, f.relayId, f.listenerId, { publish: true });
    // node-two: bound, nothing published.
    const empty = await registerRelay(t, { slug: 'node-two', nodeName: 'node-two' });
    // node-three: quarantined.
    const frozen = await registerRelay(t, { slug: 'node-three', nodeName: 'node-three' });
    await quarantine(t, frozen.relayId);
    // node-four: a live guided setup run waiting on the operator at `try_it`.
    const guided = await registerRelay(t, { slug: 'node-four', nodeName: 'node-four' });
    const runId = await parkedRun(t, {
      relayId: guided.relayId,
      slug: 'node-four',
      serverId: f.serverId,
      accountId: f.accountId,
      kind: 'reprotect',
    });
    // node-five: being deleted.
    const leaving = await registerRelay(t, { slug: 'node-five', nodeName: 'node-five' });
    await t.run((ctx) => ctx.db.patch(leaving.relayId, { deleting: true }));

    const a = AttentionResponse.parse(await t.query(internal.edgeOperator.attention, {}));
    expect(a.origins.map((o) => o.relaySlug)).toEqual([
      'node-five',
      'node-four',
      'node-one',
      'node-three',
      'node-two',
    ]);
    const of = (slug: string) => a.origins.find((o) => o.relaySlug === slug)!.status;

    expect(a.origins.find((o) => o.relaySlug === 'node-one')!.relayId).toBe(f.relayId);
    expect(of('node-one')).toMatchObject({
      kind: 'protected',
      dot: 'green',
      code: null,
      runId: null,
      published: 1,
      standbys: 0,
      offline: 0,
      layers: ['l4'],
      delivery: { kind: 'serving', code: null },
    });
    expect(of('node-one').worstHealth).not.toBeNull();

    expect(of('node-two')).toMatchObject({
      kind: 'unprotected',
      dot: 'red',
      published: 0,
      worstHealth: null,
      layers: [],
      attention: true,
      delivery: { kind: 'dark', code: 'empty_pool' },
    });
    expect(
      a.items.find((i) => i.kind === 'members_dark' && i.relayId === empty.relayId),
    ).toMatchObject({ severity: 'critical', code: 'empty_pool', relaySlug: 'node-two' });

    expect(of('node-three')).toMatchObject({ kind: 'paused', dot: 'red', attention: true });

    expect(of('node-four')).toMatchObject({
      kind: 'needs-you',
      dot: 'amber',
      code: 'try_it',
      step: 3,
      runId,
      runKind: 'reprotect',
    });

    // The attention loop skips a deleting origin's items, never its status.
    expect(of('node-five')).toMatchObject({
      kind: 'removing',
      dot: 'grey',
      code: 'deleting',
      attention: false,
      delivery: { kind: 'dark', code: 'empty_pool' },
    });

    expect(a.fleet).toEqual({ kind: 'needs-you', dot: 'amber', count: 3, total: 5, protected: 1 });
  });

  test("a node's binding left by a departed origin is not this origin's: members are dark (relay_missing)", async () => {
    const t = convexTest(schema, modules);
    const f = await seedEdgeFixture(t);
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.render.enabled', 'true'));
    await adoptL4Edge(t, f.relayId, f.listenerId, { publish: true });
    // The binding still names the origin deleted keep-dark before this one.
    await t.run(async (ctx) => {
      const binding = (await ctx.db.query('edgeDeliveryBindings').collect()).find(
        (b) => b.relaySlug === 'node-one',
      )!;
      await ctx.db.patch(binding._id, { relaySlug: 'node-gone' });
    });
    const a = AttentionResponse.parse(await t.query(internal.edgeOperator.attention, {}));
    const st = a.origins.find((o) => o.relayId === f.relayId)!.status;
    expect(st.delivery).toEqual({ kind: 'dark', code: 'relay_missing' });
    expect([st.kind, st.code]).toEqual(['needs-you', 'members_dark']);
    expect(a.items.find((i) => i.kind === 'members_dark' && i.relayId === f.relayId)).toMatchObject(
      { severity: 'critical', code: 'relay_missing' },
    );
    const setup = SetupStatusResponse.parse(
      await t.query(internal.edgeOperator.setupStatus, { relaySlug: 'node-one' }),
    );
    expect(setup.delivery).toEqual({ kind: 'dark', code: 'relay_missing' });
  });

  test('a finished run no longer counts, and an empty fleet says so', async () => {
    const t = convexTest(schema, modules);
    let a = AttentionResponse.parse(await t.query(internal.edgeOperator.attention, {}));
    expect(a.origins).toEqual([]);
    expect(a.fleet).toEqual({ kind: 'empty', dot: 'grey', count: 0, total: 0, protected: 0 });

    const f = await seedEdgeFixture(t);
    const runId = await parkedRun(t, {
      relayId: f.relayId,
      slug: 'node-one',
      serverId: f.serverId,
      accountId: f.accountId,
    });
    a = AttentionResponse.parse(await t.query(internal.edgeOperator.attention, {}));
    expect(a.origins[0].status).toMatchObject({ kind: 'needs-you', runId, runKind: 'protect' });
    expect(a.fleet).toMatchObject({ kind: 'needs-you', count: 1, total: 1 });
    await t.run((ctx) => ctx.db.patch(runId, { state: 'failed' }));
    a = AttentionResponse.parse(await t.query(internal.edgeOperator.attention, {}));
    // Rendering ships off: the bound origin's members are dark (empty pool first).
    expect(a.origins[0].status).toMatchObject({
      kind: 'unprotected',
      runId: null,
      delivery: { kind: 'dark', code: 'empty_pool' },
    });
  });
});

describe('setup-status carries the delivery', () => {
  test('relay scope judges delivery with the sample render; draft and fleet scope carry none', async () => {
    const t = convexTest(schema, modules);
    const f = await seedEdgeFixture(t);
    let s = SetupStatusResponse.parse(
      await t.query(internal.edgeOperator.setupStatus, { relaySlug: 'node-one' }),
    );
    expect(s.scope).toBe('relay');
    expect(s.delivery).toEqual({ kind: 'dark', code: 'empty_pool' });

    await adoptL4Edge(t, f.relayId, f.listenerId, { publish: true });
    s = SetupStatusResponse.parse(
      await t.query(internal.edgeOperator.setupStatus, { relaySlug: 'node-one' }),
    );
    // Rendering ships off.
    expect(s.delivery).toEqual({ kind: 'dark', code: 'render_disabled' });

    await t.run((ctx) => upsertSettingRow(ctx, 'edge.render.enabled', 'true'));
    s = SetupStatusResponse.parse(
      await t.query(internal.edgeOperator.setupStatus, { relaySlug: 'node-one' }),
    );
    expect(s.steps.find((x) => x.id === 'rendering')!.blockers).toEqual([]);
    expect(s.delivery).toEqual({ kind: 'serving', code: null });

    // The same judgement as the attention status (which has no sample render).
    const a = AttentionResponse.parse(await t.query(internal.edgeOperator.attention, {}));
    expect(a.origins[0].status.delivery).toEqual({ kind: 'serving', code: null });

    const fleet = SetupStatusResponse.parse(await t.query(internal.edgeOperator.setupStatus, {}));
    expect(fleet.scope).toBe('fleet');
    expect(fleet.delivery).toBeNull();
    const draft = SetupStatusResponse.parse(
      await t.query(internal.edgeOperator.setupStatus, {
        draft: { origin: { kind: 'manual' }, listeners: [] },
      }),
    );
    expect(draft.scope).toBe('draft');
    expect(draft.delivery).toBeNull();
  });
});
