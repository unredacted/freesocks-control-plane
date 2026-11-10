/// <reference types="vite/client" />
/**
 * Where a replacement is built on a node whose locations are all one account's,
 * and what the account's monthly cap does to the refill of a location that
 * lost its address (docs/edges.md § "Provider sets", "Selection with a set";
 * § "Plans and prices", "The budget guard").
 *
 * A node has three locations of one account, in set order: Place A, Place B,
 * Place C, each asked for "at least one address". The account's cap fits six
 * addresses at 10 a month each. Every address is RFC 5737 and every place is
 * made up; no provider call is made (a fetch that reaches the network fails
 * the test).
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { selectionContext } from './edgeRotations';
import { resolveEdgeConfig } from './lib/edgeConfig';
import {
  createAccount,
  insertPanelServer,
  realityListener,
  registerRelay,
} from './lib/edges/testing/fixtures';
import { defaultLocationRow } from './lib/edges/testing/reads';
import { providerPickWords } from '../src/client/routes/admin/edges/simple/runWords';
import { attentionFactsLine } from '../src/client/routes/admin/edges/lib/attention';

const modules = import.meta.glob('./**/*.*s');

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

type T = ReturnType<typeof convexTest>;

async function world(opts: { desired?: number } = {}) {
  vi.stubGlobal('fetch', async (input: RequestInfo | URL) => {
    throw new Error(`unexpected fetch ${String(input)}`);
  });
  const t = convexTest(schema, modules);
  await insertPanelServer(t);
  const accountId = await createAccount(t, { name: 'acct', qualified: true });
  await t.mutation(internal.edgeProviderAccounts.recordTest, { id: accountId, ok: true });
  // What the operator pays per address a month, and a cap that fits six.
  await t.mutation(internal.edgePlans.setAccountCost, {
    id: accountId,
    cost: { paid: 'amount', perEdgeMonthly: 10, currency: 'EUR', monthlyCap: 60 },
  });
  const a = (await defaultLocationRow(t, accountId))!._id;
  const place = async (regionId: number, label: string) => {
    const id = (
      await t.mutation(internal.edgeLocations.create, {
        accountId,
        placement: { projectId: 11, regionId },
        label,
      })
    ).id as Id<'edgeLocations'>;
    await t.mutation(internal.edgeLocations.setQualified, { id, qualified: true });
    return id;
  };
  const b = await place(33, 'Place B');
  const c = await place(44, 'Place C');
  const { relayId, listenerId } = await registerRelay(t, { listeners: [realityListener()] });
  await t.run((ctx) =>
    ctx.db.patch(relayId, {
      desiredPublished: opts.desired ?? 3,
      providerSet: [
        { locationId: a, addedAt: 1 },
        { locationId: b, addedAt: 2 },
        { locationId: c, addedAt: 3 },
      ],
    }),
  );
  await t.run((ctx) => upsertSettingRow(ctx, 'edge.enabled', 'true'));
  await t.run((ctx) => upsertSettingRow(ctx, 'edge.autoProvisionToDesired', 'true'));
  // A second node of the same account, to hold addresses that count against the cap.
  const other = await registerRelay(t, {
    slug: 'node-two',
    nodeName: 'node-two',
    originAddress: '203.0.113.20',
    listeners: [realityListener()],
  });
  await t.run((ctx) => ctx.db.patch(other.relayId, { desiredPublished: 4 }));
  let n = 0;
  /** An address FCP manages in the account at `locationId` (in use unless told otherwise). */
  const address = async (
    locationId: Id<'edgeLocations'>,
    o: { publish?: boolean; elsewhere?: boolean } = {},
  ) => {
    const { edgeId } = await t.mutation(internal.relays.adoptEdge, {
      relayId: o.elsewhere ? other.relayId : relayId,
      listenerId: o.elsewhere ? other.listenerId : listenerId,
      ipv4: `198.51.100.${++n}`,
      accountId,
      locationId,
      publish: o.publish ?? true,
      verified: true,
    });
    // One FCP made and pays for (an import is observe-only, and costs nothing).
    await t.run((ctx) => ctx.db.patch(edgeId as Id<'edges'>, { managed: true }));
    return edgeId as Id<'edges'>;
  };
  return { t, accountId, relayId, listenerId, a, b, c, address };
}

/** Where the detector's replacement of `targetEdgeId` would be built. */
const replacementOf = (t: T, relayId: Id<'relays'>, targetEdgeId: Id<'edges'>) =>
  t.run(async (ctx) =>
    selectionContext(
      ctx,
      { kind: 'replace', trigger: 'detector' },
      (await ctx.db.get(relayId))!,
      (await ctx.db.get(targetEdgeId))!,
      await resolveEdgeConfig(ctx.db),
    ),
  );

const rotationsOf = (t: T, relayId: Id<'relays'>) =>
  t.run(async (ctx) =>
    (await ctx.db.query('edgeRotations').collect()).filter((r) => r.relayId === relayId),
  );

const upkeep = (t: T) => t.action(internal.edgeReconcile.run, {});

describe('where a blocked address is replaced', () => {
  test("a location's last address is replaced in that location, not in the first one", async () => {
    const w = await world();
    await w.address(w.a);
    const b1 = await w.address(w.b);
    const c1 = await w.address(w.c);
    // Judged with the blocked address still counted, no location added
    // anything and set order sent every replacement to Place A: Place B was
    // left empty, the pool grew by one to refill it, and the fleet cost one
    // address more after every such replace.
    expect((await replacementOf(w.t, w.relayId, b1)).account?.locationId).toBe(w.b);
    expect((await replacementOf(w.t, w.relayId, c1)).account?.locationId).toBe(w.c);
  });

  test('an address that is not the last one there goes where the node lacks one', async () => {
    const w = await world({ desired: 4 });
    const a1 = await w.address(w.a);
    await w.address(w.a);
    await w.address(w.c);
    // Place B is empty: a replacement of one of Place A's two addresses lowers
    // the deficit there, so it is built in Place B.
    expect((await replacementOf(w.t, w.relayId, a1)).account?.locationId).toBe(w.b);
  });

  test('with nothing missing anywhere, set order decides as before', async () => {
    const w = await world({ desired: 4 });
    await w.address(w.a);
    const b1 = await w.address(w.b);
    await w.address(w.b);
    await w.address(w.c);
    // Place B keeps an address without the blocked one: the first pick takes it.
    expect((await replacementOf(w.t, w.relayId, b1)).account?.locationId).toBe(w.a);
  });

  test('a location that still cools after a block is passed over, as before', async () => {
    const w = await world();
    await w.address(w.a);
    const b1 = await w.address(w.b);
    await w.address(w.c);
    await w.t.run((ctx) =>
      ctx.db.patch(w.relayId, { cooling: [{ locationId: w.b, until: Date.now() + 3_600_000 }] }),
    );
    expect((await replacementOf(w.t, w.relayId, b1)).account?.locationId).toBe(w.a);
  });
});

describe('the monthly cap and the refill of a location that lost its address', () => {
  /**
   * Place A holds three addresses, Places B and C none, and the node wants
   * five in use. `live`: how many addresses the account holds in all (the
   * rest are on another node).
   */
  async function emptied(live: 5 | 6) {
    const w = await world({ desired: 5 });
    for (let i = 0; i < 3; i++) await w.address(w.a);
    for (let i = 3; i < live; i++) await w.address(w.a, { elsewhere: true });
    return w;
  }
  const otherNodesAddress = (w: Awaited<ReturnType<typeof world>>) =>
    w.t.run(async (ctx) =>
      (await ctx.db.query('edges').collect()).find((e) => e.relayId !== w.relayId)!,
    );

  test('at the cap upkeep starts nothing, so nothing fails and nothing backs off', async () => {
    const w = await emptied(6);
    expect(await w.t.query(internal.edgeRotations.upkeepFillRefusal, { relayId: w.relayId })).toBe(
      'account_spend_cap_reached',
    );
    const r = await upkeep(w.t);
    expect(r.started).toBe(0);
    expect(await rotationsOf(w.t, w.relayId)).toEqual([]);
    expect(
      await w.t.query(internal.edgeRotations.autoProvisionBackingOff, {
        relayId: w.relayId,
        now: Date.now(),
      }),
    ).toBe(false);
  });

  test('the first pass with room under the cap refills the empty location', async () => {
    const w = await emptied(6);
    expect((await upkeep(w.t)).started).toBe(0);
    // A drained address is destroyed: five are live and the cap fits six.
    const gone = await otherNodesAddress(w);
    await w.t.run((ctx) =>
      ctx.db.patch(gone._id, { status: 'destroyed', publication: 'unpublished' }),
    );
    expect(
      await w.t.query(internal.edgeRotations.upkeepFillRefusal, { relayId: w.relayId }),
    ).toBeNull();
    // A cap refusal held no location: the fill goes to an empty one.
    const origin = (await w.t.query(internal.relays.get, { id: w.relayId }))!;
    expect(origin.refusedLocations ?? []).toEqual([]);
    expect(origin.cooling ?? []).toEqual([]);
    const sel = await w.t.run(async (ctx) =>
      selectionContext(
        ctx,
        { kind: 'provision', trigger: 'reconcile', publishOnDone: true },
        (await ctx.db.get(w.relayId))!,
        null,
        await resolveEdgeConfig(ctx.db),
      ),
    );
    expect(sel.account?.locationId).toBe(w.b);
    expect((await upkeep(w.t)).started).toBe(1);
    const [rot] = await rotationsOf(w.t, w.relayId);
    expect(rot).toMatchObject({ kind: 'provision', trigger: 'reconcile', publishOnDone: true });
  });

  test('the rows say how many addresses the cap fits and how many are wanted', async () => {
    const w = await emptied(6);
    const { items } = await w.t.query(internal.edgeOperator.attention, {});
    const below = items.find((i) => i.kind === 'pool_below_desired')!;
    // Six live, all of them staying, and two missing: eight wanted, six fit.
    expect(below).toMatchObject({
      code: 'account_spend_cap_reached',
      action: 'open_account',
      accountId: w.accountId,
      facts: { published: 3, desired: 5, capFits: 6, capWanted: 8 },
    });
    expect(attentionFactsLine(below as never)).toBe(
      '3 of 5 published · The cap fits 6 addresses, 8 wanted',
    );
    // The node page no longer promises that upkeep adds them.
    const view = (await w.t.query(internal.edgeProviderSets.view, { relayId: w.relayId }))!;
    expect(view.upkeepHold).toEqual({
      code: 'account_spend_cap_reached',
      capFits: 6,
      capWanted: 8,
    });
    expect(providerPickWords(view as never, { upkeepAdds: true }).notes).toEqual([
      "2 addresses are still missing (Place B, Place C). The account's monthly spend cap holds them back. The cap fits 6 addresses and 8 are wanted, and a replacement needs room for one more. Raise the cap on the account, or remove an address.",
    ]);
  });

  test('an address on its way out still costs but is not wanted', async () => {
    const w = await emptied(6);
    const leaving = await otherNodesAddress(w);
    await w.t.run((ctx) =>
      ctx.db.patch(leaving._id, { status: 'draining', publication: 'draining' }),
    );
    const view = (await w.t.query(internal.edgeProviderSets.view, { relayId: w.relayId }))!;
    expect(view.upkeepHold).toEqual({
      code: 'account_spend_cap_reached',
      capFits: 6,
      capWanted: 7,
    });
  });

  test('a run the cap refused says the same on its failed row', async () => {
    const w = await emptied(6);
    // A run from before upkeep asked first: started, then refused at its selection.
    await w.t.run(async (ctx) => {
      await ctx.db.insert('edgeRotations', {
        relayId: w.relayId,
        kind: 'provision',
        trigger: 'reconcile',
        publishOnDone: true,
        burn: false,
        force: false,
        phase: 'failed',
        outcome: 'account_spend_cap_reached',
        stepVersion: 2,
        cancelRequested: false,
        hostPlan: [],
        flipAttempts: 0,
        rollbackAttempts: 0,
        pollAttempts: 0,
        events: [],
        startedAt: Date.now() - 60_000,
        finishedAt: Date.now(),
        updatedAt: Date.now(),
      });
    });
    const { items } = await w.t.query(internal.edgeOperator.attention, {});
    expect(items.find((i) => i.kind === 'rotation_failed')).toMatchObject({
      code: 'account_spend_cap_reached',
      facts: { kind: 'provision', spare: false, capFits: 6, capWanted: 8 },
    });
  });

  test('with room under the cap the node page says upkeep adds them', async () => {
    const w = await emptied(5);
    const view = (await w.t.query(internal.edgeProviderSets.view, { relayId: w.relayId }))!;
    expect(view.upkeepHold).toBeNull();
    expect(providerPickWords(view as never, { upkeepAdds: true }).notes).toEqual([
      '2 addresses are still missing (Place B, Place C); automatic upkeep adds them.',
    ]);
  });
});
