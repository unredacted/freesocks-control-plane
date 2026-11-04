/// <reference types="vite/client" />
/**
 * Automatic upkeep never buys an address nobody asked for (docs/edges.md
 * § "Reconcile cron", § "Provider sets"). Every address is RFC 5737; no
 * provider call is made (adopted edges only; a started provision's step is
 * never run here), so a fetch that reaches the network is a test failure.
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import {
  adoptL4Edge,
  createAccount,
  insertPanelServer,
  realityListener,
  registerRelay,
} from './lib/edges/testing/fixtures';

const modules = import.meta.glob('./**/*.*s');

afterEach(() => {
  vi.unstubAllGlobals();
});

function forbidNetwork() {
  vi.stubGlobal('fetch', async (input: RequestInfo | URL) => {
    throw new Error(`unexpected fetch ${String(input)}`);
  });
}

const run = (t: ReturnType<typeof convexTest>) => t.action(internal.edgeReconcile.run, {});

/**
 * A node no setup owns, protected from locations A and B of one provider (two
 * accounts, one location each). It has one address in use, at A. `bTrusted`:
 * whether B already holds a tested address somewhere (its trust).
 */
async function twoLocations(opts: { bTrusted: boolean; desired?: number }) {
  forbidNetwork();
  const t = convexTest(schema, modules);
  await insertPanelServer(t);
  const accountA = await createAccount(t, { name: 'acct-a', qualified: true });
  const accountB = await createAccount(t, { name: 'acct-b', qualified: opts.bTrusted });
  for (const id of [accountA, accountB])
    await t.mutation(internal.edgeProviderAccounts.recordTest, { id, ok: true });
  const { relayId, listenerId } = await registerRelay(t, { listeners: [realityListener()] });
  const locationOf = (accountId: Id<'edgeProviderAccounts'>) =>
    t.run(async (c) =>
      (await c.db.query('edgeLocations').collect()).find((l) => l.accountId === accountId)!,
    );
  const a = await locationOf(accountA);
  const b = await locationOf(accountB);
  await t.run((c) =>
    c.db.patch(relayId, {
      desiredPublished: opts.desired ?? 1,
      providerSet: [
        { locationId: a._id, addedAt: Date.now() },
        { locationId: b._id, addedAt: Date.now() },
      ],
    }),
  );
  await adoptL4Edge(t, relayId, listenerId, {
    ipv4: '198.51.100.1',
    publish: true,
    accountId: accountA,
  });
  await t.run((ctx) => upsertSettingRow(ctx, 'edge.enabled', 'true'));
  await t.run((ctx) => upsertSettingRow(ctx, 'edge.autoProvisionToDesired', 'true'));
  return { t, relayId, listenerId, accountA, accountB, a, b };
}

const rotationsOf = (t: ReturnType<typeof convexTest>, relayId: Id<'relays'>) =>
  t.run(async (ctx) =>
    (await ctx.db.query('edgeRotations').collect()).filter((r) => r.relayId === relayId),
  );

describe('a spare that waits on its test holds a new purchase', () => {
  test('an untested spare at the missing location: no provision', async () => {
    const w = await twoLocations({ bTrusted: true, desired: 2 });
    await adoptL4Edge(w.t, w.relayId, w.listenerId, {
      ipv4: '198.51.100.2',
      accountId: w.accountB,
      verified: false,
    });
    const r = await run(w.t);
    expect(r.started).toBe(0);
    expect(await rotationsOf(w.t, w.relayId)).toEqual([]);
  });

  test('with spares published by hand only (autoPublishStandby off), an untested spare still holds it', async () => {
    const w = await twoLocations({ bTrusted: true, desired: 2 });
    await w.t.run((ctx) => upsertSettingRow(ctx, 'edge.autoPublishStandby', 'false'));
    await adoptL4Edge(w.t, w.relayId, w.listenerId, {
      ipv4: '198.51.100.2',
      accountId: w.accountB,
      verified: false,
    });
    const r = await run(w.t);
    expect(r.started).toBe(0);
    expect(await rotationsOf(w.t, w.relayId)).toEqual([]);
  });

  test('with spares published by hand only, a tested spare that would take the slot holds it too', async () => {
    const w = await twoLocations({ bTrusted: true, desired: 2 });
    await w.t.run((ctx) => upsertSettingRow(ctx, 'edge.autoPublishStandby', 'false'));
    await adoptL4Edge(w.t, w.relayId, w.listenerId, {
      ipv4: '198.51.100.2',
      accountId: w.accountB,
    });
    const r = await run(w.t);
    expect(r.started + r.published).toBe(0);
    expect(await rotationsOf(w.t, w.relayId)).toEqual([]);
  });

  test('an untested spare added where the node already has its address, the missing location untrusted: no provision', async () => {
    // "Add a spare address" on Automatic: the untrusted location is passed
    // over, so the spare lands at A, where it cannot take the held slot.
    const w = await twoLocations({ bTrusted: false });
    await adoptL4Edge(w.t, w.relayId, w.listenerId, {
      ipv4: '198.51.100.2',
      accountId: w.accountA,
      verified: false,
    });
    const r = await run(w.t);
    expect(r.started).toBe(0);
    expect(await rotationsOf(w.t, w.relayId)).toEqual([]);
  });
});

describe('a set location automatic work cannot use yet', () => {
  test('an untrusted location in the set: upkeep buys nothing in the other one', async () => {
    const w = await twoLocations({ bTrusted: false });
    const r = await run(w.t);
    expect(r.started).toBe(0);
    expect(await rotationsOf(w.t, w.relayId)).toEqual([]);
    // The slot stays held for it: its first tested address there goes in use.
    const relay = (await w.t.query(internal.relays.get, { id: w.relayId }))!;
    expect(relay.desiredPublished).toBe(2);
    expect(await w.t.query(internal.edgeRotations.upkeepFillRefusal, { relayId: w.relayId })).toBe(
      'pool_reserved',
    );
  });

  test('once trusted, the same tick buys the missing address', async () => {
    const w = await twoLocations({ bTrusted: true });
    expect(
      await w.t.query(internal.edgeRotations.upkeepFillRefusal, { relayId: w.relayId }),
    ).toBeNull();
    const r = await run(w.t);
    expect(r.started).toBe(1);
    const [rot] = await rotationsOf(w.t, w.relayId);
    expect(rot).toMatchObject({ kind: 'provision', trigger: 'reconcile', publishOnDone: true });
  });

  test('the words name it: a first address there is made and tested by hand', async () => {
    const w = await twoLocations({ bTrusted: false });
    await run(w.t);
    const view = (await w.t.query(internal.edgeProviderSets.view, { relayId: w.relayId }))!;
    expect(view.missing).toEqual([
      expect.objectContaining({ locationId: w.b._id, trusted: false }),
    ]);
    // Attention sends the operator to the node page rather than offering a
    // provision that would buy an address elsewhere, to stay a spare.
    const { items } = await w.t.query(internal.edgeOperator.attention, {});
    expect(items.find((i) => i.kind === 'pool_below_desired')).toMatchObject({
      code: 'location_untrusted',
      action: 'open_relay',
    });
  });
});

describe('the back-off after a failed automatic provision', () => {
  async function failedThenManual(manual: 'done' | 'none') {
    const w = await twoLocations({ bTrusted: true });
    const finish = (rotationId: Id<'edgeRotations'>, phase: 'failed' | 'done') =>
      w.t.run(async (ctx) => {
        await ctx.db.patch(rotationId, { phase, finishedAt: Date.now() });
        await ctx.db.patch(w.relayId, { activeRotationId: undefined });
      });
    const auto = await w.t.mutation(internal.edgeRotations.start, {
      relayId: w.relayId,
      kind: 'provision',
      trigger: 'reconcile',
      publishOnDone: true,
    });
    await finish(auto.rotationId, 'failed');
    if (manual === 'done') {
      const byHand = await w.t.mutation(internal.edgeRotations.start, {
        relayId: w.relayId,
        kind: 'provision',
        trigger: 'manual',
        publishOnDone: false,
        listenerId: w.listenerId,
        requestedLocationId: w.b._id,
      });
      await finish(byHand.rotationId, 'done');
    }
    return w;
  }
  const backingOff = (w: Awaited<ReturnType<typeof twoLocations>>, now = Date.now()) =>
    w.t.query(internal.edgeRotations.autoProvisionBackingOff, { relayId: w.relayId, now });

  test('a failed automatic provision holds upkeep for the back-off', async () => {
    const w = await failedThenManual('none');
    expect(await backingOff(w)).toBe(true);
    expect(await backingOff(w, Date.now() + 61 * 60_000)).toBe(false);
  });

  test('a manual provision that succeeds since does not lift it', async () => {
    const w = await failedThenManual('done');
    expect(await backingOff(w)).toBe(true);
    const r = await run(w.t);
    expect(r.started).toBe(0);
  });
});
