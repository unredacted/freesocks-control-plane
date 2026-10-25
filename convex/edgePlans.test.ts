/**
 * Plans and prices (convex/edgePlans.ts, docs/edges.md § "Plans and prices"):
 * a location's plans stored whole and kept on a failed read, what one edge
 * there costs as the account's choice says, the account's monthly estimate,
 * the budget guard (protect plan, selection, preflight, the insert), the
 * attention item at the cap, the cron's pick of stale locations, and the read
 * through the adapter. Fixtures only (RFC 5737, `*.example`).
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import {
  FIXTURE_CONFIG_PROFILE,
  FIXTURE_INBOUND,
  createAccount,
  insertPanelServer,
  realityListener,
  registerRelay,
} from './lib/edges/testing/fixtures';
import { defaultLocationRow, insertPlanned } from './lib/edges/testing/reads';
import { __setEdgeProviderForTests, edgeProviderFor } from './lib/edges/providers/registry';
import { selectionContext } from './edgeRotations';
import { __setPlanOpsForTests, refuseSet } from './edgeSetupPlan';
import type { BackendTransport } from './lib/backends/types';
import { resolveEdgeConfig } from './lib/edgeConfig';
import { PLANS_RETRY_MS, PLANS_STALE_MS, type ProviderPlan } from './lib/edges/pricing';
import { SPEND_CAP_REACHED } from './edgePlans';
import type { EdgeProvider } from './lib/edges/providers/types';
import { EdgeProviderAccountAdmin, SetupPlanResponse } from '../src/shared/contracts/edges';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;

const PROJECT = '66666666-7777-4888-8999-000000000000';

afterEach(() => {
  __setEdgeProviderForTests('scaleway', null);
  __setPlanOpsForTests(null);
});

/** The four Scaleway offers, as the catalog prices them (per node an hour). */
const SCALEWAY_PLANS: ProviderPlan[] = [
  ['LB-S', 0.023, 200, false],
  ['LB-GP-M', 0.054, 500, false],
  ['LB-GP-L', 0.094, 1000, true],
  ['LB-GP-XL', 0.941, 4000, true],
].map(([size, perHour, bandwidthMbps, acceptsOutsideNode]) => ({
  size: size as string,
  label: size as string,
  perHour: perHour as number,
  perMonth: null,
  currency: 'EUR',
  traffic: { kind: 'unlimited' },
  bandwidthMbps: bandwidthMbps as number,
  acceptsOutsideNode: acceptsOutsideNode as boolean,
  source: 'api',
}));

/** A trusted Scaleway account (its location names a project) and a node with a REALITY transport. */
async function world() {
  const t = convexTest(schema, modules);
  await insertPanelServer(t);
  const accountId = await createAccount(t, {
    provider: 'scaleway',
    name: 'acct-s',
    qualified: true,
    maxLiveEdges: 10,
    dailyAllocationBudget: 10,
    settings: { accessKey: 'SCWXXXXXXXXXXXXXXXXX', zone: 'fr-par-1', projectId: PROJECT },
    credentials: { secretKey: '11111111-2222-4333-8444-555555555555' },
  });
  await t.mutation(internal.edgeProviderAccounts.recordTest, { id: accountId, ok: true });
  const r = await registerRelay(t, { listeners: [realityListener()] });
  const locationId = (await defaultLocationRow(t, accountId))!._id;
  return { t, accountId, relayId: r.relayId, listenerId: r.listenerId, locationId };
}

const record = (t: T, locationId: Id<'edgeLocations'>, plans = SCALEWAY_PLANS) =>
  t.mutation(internal.edgePlans.record, { locationId, plans });
const sizeAt = (t: T, id: Id<'edgeLocations'>, type: string) =>
  t.run((ctx) => ctx.db.patch(id, { regionalParams: JSON.stringify({ type }) }));
const setCost = (t: T, id: Id<'edgeProviderAccounts'>, cost: unknown) =>
  t.mutation(internal.edgePlans.setAccountCost, { id, cost: cost as never });
const locationView = async (t: T, accountId: Id<'edgeProviderAccounts'>) =>
  (await t.query(internal.edgeProviderAccounts.getForAdmin, { id: accountId }))!.locations[0]!;
const edgePlan = {
  templateHash: 'h1',
  listeners: [{ edgePort: 443, originAddress: '203.0.113.10', originPort: 443 }],
  steps: [{ id: 'lb', kind: 'create_lb', resourceName: 'fcp-relay-x' }],
};

async function refusal(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (err) {
    return String((err as { data?: { code?: string } }).data?.code ?? err);
  }
  return 'no refusal';
}

describe('a location’s plans', () => {
  test('stored whole on each read; a failed read keeps them and says why', async () => {
    const { t, locationId } = await world();
    await record(t, locationId);
    const rows = () =>
      t.run((ctx) =>
        ctx.db
          .query('edgePlans')
          .withIndex('by_location_size', (q) => q.eq('locationId', locationId))
          .collect(),
      );
    expect((await rows()).map((r) => r.sizeKey).sort()).toEqual([
      'lb-gp-l',
      'lb-gp-m',
      'lb-gp-xl',
      'lb-s',
    ]);
    const loc = await t.run((ctx) => ctx.db.get(locationId));
    expect(loc!.plansAt).toBeGreaterThan(0);
    await t.mutation(internal.edgePlans.record, { locationId, error: 'timeout' });
    expect(await rows()).toHaveLength(4);
    expect((await t.run((ctx) => ctx.db.get(locationId)))!).toMatchObject({
      plansError: 'timeout',
      plansAt: loc!.plansAt,
    });
    // A size the provider no longer lists goes; a success clears the error.
    await record(t, locationId, SCALEWAY_PLANS.slice(2));
    expect((await rows()).map((r) => r.size).sort()).toEqual(['LB-GP-L', 'LB-GP-XL']);
    expect((await t.run((ctx) => ctx.db.get(locationId)))!.plansError).toBeUndefined();
  });

  test('the account page: every plan cheapest first, the size it builds priced, refused sizes marked', async () => {
    const { t, accountId, locationId } = await world();
    expect((await locationView(t, accountId)).pricing).toMatchObject({
      size: 'LB-S',
      plan: null,
      plans: [],
      plansAt: null,
    });
    await record(t, locationId);
    const p = (await locationView(t, accountId)).pricing!;
    expect(p.plans.map((x) => [x.size, x.perMonth, x.refusal])).toEqual([
      ['LB-S', 16.79, 'size_not_multicloud'],
      ['LB-GP-M', 39.42, 'size_not_multicloud'],
      ['LB-GP-L', 68.62, null],
      ['LB-GP-XL', 686.93, null],
    ]);
    expect(p.plan).toMatchObject({ size: 'LB-S', refusal: 'size_not_multicloud' });
    expect(p.cost).toEqual({
      monthly: 16.79,
      currency: 'EUR',
      basis: 'list',
      plusTraffic: false,
      listMonthly: 16.79,
      listCurrency: 'EUR',
    });
    // A plan chosen for the location: priced at once.
    await sizeAt(t, locationId, 'lb-gp-l');
    expect((await locationView(t, accountId)).pricing!.cost.monthly).toBe(68.62);
  });

  test('choosing a size that takes Scaleway servers only for a location is refused', async () => {
    const { t, accountId, locationId } = await world();
    expect(
      await refusal(
        t.mutation(internal.edgeLocations.update, {
          id: locationId,
          regionalParams: { type: 'LB-GP-M' },
        }),
      ),
    ).toBe('edge.size_not_multicloud');
    await t.mutation(internal.edgeLocations.update, {
      id: locationId,
      regionalParams: { type: 'LB-GP-XL' },
    });
    expect((await locationView(t, accountId)).regionalParams).toEqual({ type: 'LB-GP-XL' });
  });

  test('a removed location takes its plans with it', async () => {
    const { t, locationId } = await world();
    await record(t, locationId);
    await t.mutation(internal.edgeLocations.remove, { id: locationId });
    expect(await t.run((ctx) => ctx.db.query('edgePlans').collect())).toEqual([]);
  });
});

describe('what the account costs', () => {
  test('free, an amount, or back to the list price; validated and audited', async () => {
    const { t, accountId, locationId } = await world();
    await record(t, locationId);
    expect(await refusal(setCost(t, accountId, { paid: 'amount', perEdgeMonthly: 5 }))).toBe(
      'validation',
    );
    await setCost(t, accountId, { paid: 'free', note: '  credits   until  spring ' });
    let v = await locationView(t, accountId);
    expect(v.pricing!.cost).toMatchObject({ monthly: 0, basis: 'free', listMonthly: 16.79 });
    // Each plan says what one edge of its size would cost, the account's choice laid over.
    expect(v.pricing!.plans.find((p) => p.size === 'LB-GP-XL')!.cost).toMatchObject({
      monthly: 0,
      basis: 'free',
      listMonthly: 686.93,
    });
    await setCost(t, accountId, { paid: 'amount', perEdgeMonthly: 12.5, currency: 'usd' });
    v = await locationView(t, accountId);
    expect(v.pricing!.cost).toMatchObject({ monthly: 12.5, currency: 'USD', basis: 'amount' });
    const acct = await t.query(internal.edgeProviderAccounts.getForAdmin, { id: accountId });
    expect(acct!.cost).toMatchObject({ paid: 'amount', perEdgeMonthly: 12.5, currency: 'USD' });
    // The admin contract reads the account, its cost and its locations' plans as served.
    const parsed = EdgeProviderAccountAdmin.parse(acct);
    expect(parsed.cost?.spend.edges).toBe(0);
    expect(parsed.locations[0]!.pricing?.plans).toHaveLength(4);
    await setCost(t, accountId, null);
    expect((await locationView(t, accountId)).pricing!.cost.basis).toBe('list');
    const audit = await t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .filter((q) => q.eq(q.field('action'), 'edge.provider_account.cost_changed'))
        .collect(),
    );
    expect(audit).toHaveLength(3);
    // The note is the operator's own text: never in the audit row.
    expect(JSON.stringify(audit[0]!.payload)).not.toContain('credits');
  });

  test('a CDN account has no list price: it reads "no price set" until the operator says', async () => {
    const t = convexTest(schema, modules);
    const accountId = await createAccount(t, {
      provider: 'cloudflare',
      name: 'cdn',
      frontsTraffic: true,
    });
    expect(await refusal(setCost(t, accountId, { paid: 'list' }))).toBe('validation');
    const view = async () =>
      (await t.query(internal.edgeProviderAccounts.getForAdmin, { id: accountId }))!;
    const loc = (await view()).locations[0];
    if (loc) expect(loc.pricing!.cost.basis).toBe('unset');
    await setCost(t, accountId, { paid: 'free' });
    expect((await view()).cost).toMatchObject({ paid: 'free' });
  });
});

describe('the budget guard', () => {
  async function capped(cap: number) {
    const w = await world();
    await sizeAt(w.t, w.locationId, 'LB-GP-L');
    await record(w.t, w.locationId);
    await setCost(w.t, w.accountId, { paid: 'list', currency: 'EUR', monthlyCap: cap });
    return w;
  }

  test('the estimate counts each live edge at its frozen size; the insert refuses past the cap', async () => {
    const { t, accountId, relayId, listenerId } = await capped(100);
    const first = await insertPlanned(t, {
      relayId,
      listenerId,
      accountId,
      ...edgePlan,
      planSize: 'LB-GP-L',
    });
    expect((await t.run((ctx) => ctx.db.get(first.id)))!.planSize).toBe('LB-GP-L');
    expect(await t.query(internal.edgePlans.spendOfAccount, { id: accountId })).toMatchObject({
      monthlyCap: 100,
      spend: {
        edges: 1,
        monthly: 68.62,
        atCap: false,
        totals: [{ currency: 'EUR', monthly: 68.62 }],
      },
    });
    // A second one would take it to 137.24 a month: refused, nothing reserved.
    expect(
      await refusal(
        insertPlanned(t, { relayId, listenerId, accountId, ...edgePlan, planSize: 'LB-GP-L' }),
      ),
    ).toBe(`edge.${SPEND_CAP_REACHED}`);
    expect((await t.run((ctx) => ctx.db.get(accountId)))!.allocationsToday).toBe(1);
    // Raised: it fits.
    await setCost(t, accountId, { paid: 'list', currency: 'EUR', monthlyCap: 200 });
    await insertPlanned(t, { relayId, listenerId, accountId, ...edgePlan, planSize: 'LB-GP-L' });
  });

  test('an edge from before sizes were frozen is counted at what its location builds', async () => {
    const { t, accountId, relayId, listenerId } = await capped(1000);
    await insertPlanned(t, { relayId, listenerId, accountId, ...edgePlan });
    expect(
      (await t.query(internal.edgePlans.spendOfAccount, { id: accountId }))!.spend.monthly,
    ).toBe(68.62);
  });

  test('at the cap: attention, the protect plan refuses the account, selection and preflight too', async () => {
    const { t, accountId, relayId, listenerId, locationId } = await capped(60);
    await t.run((ctx) => ctx.db.patch(accountId, { cost: undefined }));
    await insertPlanned(t, { relayId, listenerId, accountId, ...edgePlan, planSize: 'LB-GP-L' });
    await setCost(t, accountId, { paid: 'list', currency: 'EUR', monthlyCap: 60 });
    const { items } = await t.query(internal.edgeOperator.attention, {});
    expect(items.find((i) => i.kind === 'account_spend_cap')).toMatchObject({
      accountId,
      facts: { monthly: 68.62, cap: 60, currency: 'EUR' },
      action: 'open_account',
    });
    const select = (rotation: Parameters<typeof selectionContext>[1]) =>
      t.run(async (ctx) =>
        selectionContext(
          ctx,
          rotation,
          (await ctx.db.get(relayId))!,
          null,
          await resolveEdgeConfig(ctx.db),
        ),
      );
    const named = await select({
      kind: 'provision',
      trigger: 'manual',
      listenerId,
      requestedLocationId: locationId,
    });
    expect(named.accountFailure).toBe(SPEND_CAP_REACHED);
    const automatic = await select({ kind: 'provision', trigger: 'manual', listenerId });
    expect(automatic.accountFailure).toBe(SPEND_CAP_REACHED);
    const pre = await t.query(internal.edgeOperator.preflight, {
      relayId,
      kind: 'provision',
      listenerKey: 'a',
      locationId,
      publish: false,
    });
    expect(pre.blockers.map((b) => b.code)).toContain(SPEND_CAP_REACHED);
    // Off again: selection picks it.
    await setCost(t, accountId, null);
    expect(
      (await select({ kind: 'provision', trigger: 'manual', listenerId })).account?.locationId,
    ).toBe(locationId);
  });

  test('what picks cost before anything exists: each at the size its options build', async () => {
    const { t, locationId } = await capped(100);
    const cost = (options: Record<string, unknown>, count: number) =>
      t.query(internal.edgePlans.costOfPicks, { picks: [{ locationId, options, count }] });
    const plain = await cost({}, 1);
    expect(plain.lines[0]).toMatchObject({
      size: 'LB-GP-L',
      count: 1,
      cost: { monthly: 68.62, currency: 'EUR', basis: 'list' },
      source: 'api',
    });
    expect(plain.total).toEqual({
      totals: [{ currency: 'EUR', monthly: 68.62 }],
      unpriced: 0,
      plusTraffic: false,
    });
    expect(plain.capReached).toEqual([]);
    const big = await cost({ type: 'LB-GP-XL' }, 2);
    expect(big.lines[0]).toMatchObject({ size: 'LB-GP-XL', count: 2 });
    expect(big.total.totals).toEqual([{ currency: 'EUR', monthly: 1373.86 }]);
    expect(big.capReached).toHaveLength(1);
  });
});

describe('the protect sheet says what the picks cost before anything is created', () => {
  const NODE_UUID = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
  const inbound: BackendTransport = {
    tag: 'VLESS_RELAY_A',
    configProfileUuid: FIXTURE_CONFIG_PROFILE,
    configProfileInboundUuid: FIXTURE_INBOUND,
    protocol: 'vless',
    port: 443,
    network: 'tcp',
    security: 'reality',
    reality: { target: 'target.example:443', serverNames: ['a.example'] },
    active: true,
  };

  test('the set carries each pick’s monthly cost and the total; past the cap it is refused', async () => {
    const t = convexTest(schema, modules);
    const serverId = await insertPanelServer(t);
    const accountId = await createAccount(t, {
      provider: 'scaleway',
      name: 'acct-s',
      maxLiveEdges: 10,
      dailyAllocationBudget: 10,
      settings: { accessKey: 'SCWXXXXXXXXXXXXXXXXX', zone: 'fr-par-1', projectId: PROJECT },
      credentials: { secretKey: '11111111-2222-4333-8444-555555555555' },
    });
    await t.mutation(internal.edgeProviderAccounts.recordTest, { id: accountId, ok: true });
    const locationId = (await defaultLocationRow(t, accountId))!._id;
    await sizeAt(t, locationId, 'LB-GP-L');
    await record(t, locationId);
    await t.run((ctx) =>
      ctx.db.insert('backendNodeInventory', {
        backendServerId: serverId,
        nodeUuid: NODE_UUID,
        name: 'node-one',
        usersOnline: 0,
        online: true,
        lastStatsAt: Date.now(),
        address: '203.0.113.10',
        port: 443,
      }),
    );
    // No Host at the node: its REALITY test entry is built (the panel describes it).
    __setPlanOpsForTests({
      listNodeInbounds: async () => [inbound],
      listHosts: async () => [],
      synthesisReady: async () => true,
    });
    const plan = (pickOptions?: Record<string, unknown>) =>
      t.action(internal.edgeSetupPlan.plan, {
        backendServerId: serverId,
        nodeUuid: NODE_UUID,
        picks: [locationId],
        ...(pickOptions ? { pickOptions } : {}),
      });
    const set = SetupPlanResponse.parse(await plan()).set!;
    expect(set.cost?.lines).toEqual([
      expect.objectContaining({
        locationId,
        count: 1,
        size: 'LB-GP-L',
        cost: expect.objectContaining({ monthly: 68.62, currency: 'EUR', basis: 'list' }),
      }),
    ]);
    expect(set.cost?.total.totals).toEqual([{ currency: 'EUR', monthly: 68.62 }]);
    expect(set.problems).toEqual([]);
    // The node's own size option there: priced at that size.
    const xl = (await plan({ [locationId]: { type: 'LB-GP-XL' } })).set!;
    expect(xl.cost?.total.totals).toEqual([{ currency: 'EUR', monthly: 686.93 }]);
    // A cap these addresses would pass: a problem of the pick, refused at create.
    await setCost(t, accountId, { paid: 'list', currency: 'EUR', monthlyCap: 50 });
    const over = (await plan()).set!;
    expect(over.problems).toContainEqual({ locationId, reason: SPEND_CAP_REACHED });
    expect(() => refuseSet(over as never)).toThrow();
    try {
      refuseSet(over as never);
    } catch (err) {
      expect((err as { data: { code: string } }).data.code).toBe(`edge.${SPEND_CAP_REACHED}`);
    }
  });
});

describe('rollback', () => {
  test('clearForRollback removes every plan and every field an older build lacks', async () => {
    const { t, accountId, relayId, listenerId, locationId } = await world();
    await record(t, locationId);
    await setCost(t, accountId, { paid: 'free' });
    const e = await insertPlanned(t, {
      relayId,
      listenerId,
      accountId,
      ...edgePlan,
      planSize: 'LB-GP-L',
    });
    expect(await t.mutation(internal.edgePlans.clearForRollback, {})).toEqual({ done: true });
    expect(await t.run((ctx) => ctx.db.query('edgePlans').collect())).toEqual([]);
    expect((await t.run((ctx) => ctx.db.get(accountId)))!.cost).toBeUndefined();
    const loc = (await t.run((ctx) => ctx.db.get(locationId)))!;
    expect([loc.plansAt, loc.plansTriedAt, loc.plansError]).toEqual([
      undefined,
      undefined,
      undefined,
    ]);
    expect((await t.run((ctx) => ctx.db.get(e.id)))!.planSize).toBeUndefined();
  });

  test('more plans than one pass holds: paged until none is left, then the edges', async () => {
    vi.useFakeTimers();
    try {
      const { t, accountId, relayId, listenerId, locationId } = await world();
      await t.run(async (ctx) => {
        for (let i = 0; i < 450; i++)
          await ctx.db.insert('edgePlans', {
            accountId,
            locationId,
            provider: 'scaleway',
            size: `S-${i}`,
            sizeKey: `s-${i}`,
            label: `S-${i}`,
            traffic: { kind: 'unknown' },
            source: 'catalog',
            pricedAt: 0,
          });
      });
      await setCost(t, accountId, { paid: 'free' });
      const e = await insertPlanned(t, {
        relayId,
        listenerId,
        accountId,
        ...edgePlan,
        planSize: 'LB-GP-L',
      });
      // The first pass is one page of plans: not done, and the rest is scheduled.
      expect(await t.mutation(internal.edgePlans.clearForRollback, {})).toEqual({ done: false });
      await t.finishAllScheduledFunctions(vi.runAllTimers);
      expect(await t.run((ctx) => ctx.db.query('edgePlans').collect())).toEqual([]);
      expect((await t.run((ctx) => ctx.db.get(accountId)))!.cost).toBeUndefined();
      expect((await t.run((ctx) => ctx.db.get(e.id)))!.planSize).toBeUndefined();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('reading plans', () => {
  test('the cron takes never-read and day-old locations; a failed read waits an hour', async () => {
    const { t, locationId } = await world();
    const now = Date.now();
    const due = (at: number) => t.query(internal.edgePlans.staleForRefresh, { now: at, limit: 5 });
    expect((await due(now)).map((d) => d.locationId)).toEqual([locationId]);
    // A read that failed: tried again only an hour later.
    await t.mutation(internal.edgePlans.record, { locationId, error: 'timeout' });
    expect(await due(Date.now() + 60_000)).toEqual([]);
    expect(await due(Date.now() + PLANS_RETRY_MS + 1)).toHaveLength(1);
    // Read: due again once a day old.
    await record(t, locationId);
    expect(await due(Date.now() + PLANS_RETRY_MS + 1)).toEqual([]);
    expect(await due(Date.now() + PLANS_STALE_MS + 1)).toHaveLength(1);
    // A switched-off location is never read by the cron.
    await t.run((ctx) => ctx.db.patch(locationId, { enabled: false }));
    expect(await due(Date.now() + PLANS_STALE_MS + 1)).toEqual([]);
  });

  test('refreshPlans asks the adapter and stores what it says; a failure is recorded', async () => {
    const { t, accountId, locationId } = await world();
    let answer: () => Promise<ProviderPlan[]> = async () => SCALEWAY_PLANS;
    __setEdgeProviderForTests('scaleway', {
      ...edgeProviderFor('scaleway'),
      plans: () => answer(),
    } as EdgeProvider);
    expect(
      await t.action(internal.edgeProviderOps.refreshPlans, { accountId, locationId, force: true }),
    ).toEqual({ refreshed: true, error: null });
    expect((await locationView(t, accountId)).pricing!.plans).toHaveLength(4);
    // Within the floor: answered from the stored rows.
    expect(
      await t.action(internal.edgeProviderOps.refreshPlans, { accountId, locationId }),
    ).toEqual({
      refreshed: false,
      error: null,
    });
    answer = async () => {
      throw new Error('catalog down');
    };
    const failed = await t.action(internal.edgeProviderOps.refreshPlans, {
      accountId,
      locationId,
      force: true,
    });
    expect(failed.refreshed).toBe(false);
    expect(failed.error).toBeTruthy();
    const view = (await locationView(t, accountId)).pricing!;
    expect(view.plans).toHaveLength(4);
    expect(view.plansError).toBe(failed.error);
  });
});
