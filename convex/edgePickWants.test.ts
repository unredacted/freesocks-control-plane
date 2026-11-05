/// <reference types="vite/client" />
/**
 * Addresses per location end to end (docs/edges.md "Addresses per location"):
 * saving a pick's count (checked, audited), the preview before saving (what
 * it adds, its cost, the cap), the reconcile's step 5W (a spare there first,
 * else a provision at that location only, never where something holds it
 * back), lane cleanup keeping a counted address, attention `location_short`
 * with its cause, and the rollback helper. Adopted RFC 5737 edges only: no
 * provider call is made.
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

/** A node protected from locations A and B (two accounts), one address in use at A. */
async function world(opts: { aTrusted?: boolean; provision?: boolean } = {}) {
  forbidNetwork();
  const t = convexTest(schema, modules);
  await insertPanelServer(t);
  const accountA = await createAccount(t, { name: 'acct-a', qualified: opts.aTrusted !== false });
  const accountB = await createAccount(t, { name: 'acct-b', qualified: true });
  for (const id of [accountA, accountB])
    await t.mutation(internal.edgeProviderAccounts.recordTest, { id, ok: true });
  const { relayId, listenerId } = await registerRelay(t, { listeners: [realityListener()] });
  const locationOf = (accountId: Id<'edgeProviderAccounts'>) =>
    t.run(async (c) =>
      (await c.db.query('edgeLocations').collect()).find((l) => l.accountId === accountId)!,
    );
  const a = await locationOf(accountA);
  const b = await locationOf(accountB);
  await t.run(async (c) => {
    await c.db.patch(relayId, {
      desiredPublished: 2,
      providerSet: [
        { locationId: a._id, addedAt: Date.now() },
        { locationId: b._id, addedAt: Date.now() },
      ],
    });
    // Whether a location is trusted is its own: an adopted edge does not set it.
    await c.db.patch(a._id, { qualified: opts.aTrusted !== false });
  });
  await adoptL4Edge(t, relayId, listenerId, {
    ipv4: '198.51.100.1',
    publish: true,
    accountId: accountA,
  });
  await adoptL4Edge(t, relayId, listenerId, {
    ipv4: '198.51.100.2',
    publish: true,
    accountId: accountB,
  });
  await t.run(async (ctx) => {
    await upsertSettingRow(ctx, 'edge.enabled', 'true');
    if (opts.provision !== false)
      await upsertSettingRow(ctx, 'edge.autoProvisionToDesired', 'true');
  });
  return { t, relayId, listenerId, accountA, accountB, a, b };
}
type World = Awaited<ReturnType<typeof world>>;

const relayOf = (w: World) => w.t.run(async (c) => (await c.db.get(w.relayId))!);
const reconcile = (w: World) => w.t.action(internal.edgeReconcile.run, {});
const rotations = (w: World) =>
  w.t.run(async (c) =>
    (await c.db.query('edgeRotations').collect()).filter((r) => r.relayId === w.relayId),
  );
const setWant = (w: World, want: number | null, at = w.a._id) =>
  w.t.mutation(internal.edgePickWants.setPickWant, { relayId: w.relayId, locationId: at, want });

describe('saving a count', () => {
  test('1 to 8 or none, on a picked location; audited; the same count again changes nothing', async () => {
    const w = await world();
    for (const bad of [0, 9, 1.5]) await expect(setWant(w, bad)).rejects.toThrow(/1 to 8/);
    const accountC = await createAccount(w.t, { name: 'acct-c', qualified: true });
    const other = await w.t.run(
      async (c) =>
        (await c.db.query('edgeLocations').collect()).find((l) => l.accountId === accountC)!._id,
    );
    await expect(setWant(w, 2, other)).rejects.toThrow(/not picked/);
    expect(await setWant(w, 3)).toMatchObject({ ok: true, changed: true, want: 3, adds: 2 });
    expect((await relayOf(w)).providerSet!.find((p) => p.locationId === w.a._id)!.want).toBe(3);
    expect(await setWant(w, 3)).toMatchObject({ changed: false });
    const audit = await w.t.run((c) =>
      c.db
        .query('auditLog')
        .filter((q) => q.eq(q.field('action'), 'edge.relay.pick_want'))
        .collect(),
    );
    expect(audit).toHaveLength(1);
    expect(audit[0]!.payload).toMatchObject({ want: 3, adds: 2 });
    expect(await setWant(w, null)).toMatchObject({ changed: true, want: null });
    expect(
      (await relayOf(w)).providerSet!.find((p) => p.locationId === w.a._id)!.want,
    ).toBeUndefined();
  });

  test('the preview says what it adds and whether it fits under the monthly cap', async () => {
    const w = await world();
    const preview = (want: number | null) =>
      w.t.query(internal.edgePickWants.wantPreview, {
        relayId: w.relayId,
        locationId: w.a._id,
        want,
      });
    const p = await preview(3);
    expect(p).toMatchObject({ want: 3, adds: 2, fits: 2, tooLarge: false });
    expect(p.carries).toHaveLength(1);
    expect((await preview(1)).adds).toBe(0);
    // A cap the account is already at: none of them fits.
    await w.t.run((c) =>
      c.db.patch(w.accountA, {
        cost: { paid: 'amount', perEdgeMonthly: 10, currency: 'EUR', monthlyCap: 5 },
      } as never),
    );
    expect(await preview(3)).toMatchObject({ adds: 2, fits: 0 });
  });
});

describe('upkeep fills a count (step 5W)', () => {
  test('a spare at that location goes in use first', async () => {
    const w = await world();
    const spare = await adoptL4Edge(w.t, w.relayId, w.listenerId, {
      ipv4: '198.51.100.3',
      publish: false,
      accountId: w.accountA,
    });
    await setWant(w, 2);
    await reconcile(w);
    const relay = await relayOf(w);
    expect(relay.publishedEdgeIds).toContain(spare.edgeId);
  });

  test('without a spare, a provision for that transport at that location only', async () => {
    const w = await world();
    await setWant(w, 2);
    await reconcile(w);
    const rs = await rotations(w);
    expect(rs).toHaveLength(1);
    expect(rs[0]).toMatchObject({
      kind: 'provision',
      onlyLocationId: w.a._id,
      listenerId: w.listenerId,
    });
  });

  test('nothing is bought where a location is not trusted yet; attention says why', async () => {
    const w = await world({ aTrusted: false });
    await setWant(w, 2);
    await reconcile(w);
    expect((await rotations(w)).filter((r) => r.onlyLocationId)).toEqual([]);
    const items = (await w.t.query(internal.edgeOperator.attention, {})).items.filter(
      (i: { kind: string }) => i.kind === 'location_short',
    );
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      code: 'location_untrusted',
      facts: { location: w.a.label, wanted: 2, inUse: 1, count: 1 },
    });
  });

  test('without counts upkeep does what it always did', async () => {
    const w = await world();
    await reconcile(w);
    expect((await rotations(w)).filter((r) => r.onlyLocationId)).toEqual([]);
    const items = (await w.t.query(internal.edgeOperator.attention, {})).items.filter(
      (i: { kind: string }) => i.kind === 'location_short',
    );
    expect(items).toEqual([]);
  });
});

describe('rollback', () => {
  test('every count goes; the addresses stay', async () => {
    const w = await world();
    await setWant(w, 2);
    const before = (await relayOf(w)).publishedEdgeIds.filter(Boolean).length;
    expect(await w.t.mutation(internal.edgePickWants.clearPickWantsForRollback, {})).toEqual({
      cleared: 1,
    });
    const relay = await relayOf(w);
    expect(relay.providerSet!.every((p) => p.want === undefined)).toBe(true);
    expect(relay.publishedEdgeIds.filter(Boolean).length).toBe(before);
  });
});

describe('with address lanes on', () => {
  test('cleanup keeps the counted address; the pool holds the count; 5W fills it', async () => {
    const w = await world();
    // A third address in use, at B, in the trusted lane: the lanes are full but
    // for one open address too many (A's and B's, for a target of one).
    await w.t.run((c) => c.db.patch(w.relayId, { desiredPublished: 3 }));
    const third = await adoptL4Edge(w.t, w.relayId, w.listenerId, {
      ipv4: '198.51.100.4',
      publish: true,
      accountId: w.accountB,
    });
    await w.t.run(async (c) => {
      await c.db.patch(w.relayId, { edgePick: 'hrw1' });
      await c.db.patch(third.edgeId, { lane: 'trusted' });
    });
    await w.t.mutation(internal.edgeLanes.setLanes, {
      relayId: w.relayId,
      lanes: { open: 1, trusted: 1 },
    });
    await setWant(w, 3);
    for (let i = 0; i < 3; i++) await reconcile(w);
    const relay = await relayOf(w);
    const published = await w.t.run(async (c) =>
      Promise.all(relay.publishedEdgeIds.filter(Boolean).map((id) => c.db.get(id!))),
    );
    // The address at A is the count's: lane cleanup never takes it.
    expect(
      published.filter((e) => e?.locationId === w.a._id && e.publication === 'published'),
    ).toHaveLength(1);
    // Room for the two more the count asks for, beside what the lanes need.
    expect(relay.desiredPublished).toBeGreaterThanOrEqual(published.length + 2);
    // And upkeep asks for one there, at A only.
    expect((await rotations(w)).some((r) => r.onlyLocationId === w.a._id)).toBe(true);
  });
});
