/**
 * Plans and prices (docs/edges.md § "Plans and prices"): every load balancer
 * size a location offers, with its list price, traffic terms and what it
 * accepts, as last read (`edgePlans`), and what the operator says an account
 * really pays (`edgeProviderAccounts.cost`).
 *
 *  - Read by `edgeProviderOps.refreshPlans`: with every inventory pull of a
 *    location (a new location's first one included), from the reconcile cron
 *    once a location's plans are a day old, and on an admin's Refresh. A
 *    failed read keeps the stored plans and records why.
 *  - What an edge costs is `lib/edges/pricing.ts edgeCostOf`: the plan its
 *    size names at its location, with the account's choice laid over it. An
 *    edge's size is frozen on it when it is planned (`edges.planSize`).
 *  - The budget guard: an account with a monthly cap gets no new edge once
 *    its estimate over its live edges, plus the new ones, would pass it
 *    (`capRefusal`, `account_spend_cap_reached`), checked by the protect plan,
 *    by selection and again where the edge row is inserted.
 *
 * Rows are operator-scale: a handful per location, read by index.
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import type { DatabaseReader, DatabaseWriter, MutationCtx } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { resolveBuildFor } from './edgeTemplates';
import { EDGE_LIVE_STATUSES, LIVE_EDGE_SCAN_LIMIT } from './lib/edges/pool';
import { parseOptionValues } from './lib/edges/providers/options';
import { edgeLayerOf } from './lib/edges/providers/capabilities';
import { assertAdmission } from './lib/edges/maintenance';
import { sizeProblemOf } from './lib/edges/sizeCheck';
import {
  MAX_PLANS_PER_LOCATION,
  PLANS_RETRY_MS,
  PLANS_STALE_MS,
  atCap,
  costSettingsProblem,
  edgeCostOf,
  monthlyOf,
  passesCap,
  sizeKey,
  sizeKeyOf,
  sizeOf,
  spendViewOf,
  totalOf,
  type AccountCost,
  type CostTotal,
  type EdgeCost,
  type SpendView,
  type StoredPlan,
} from './lib/edges/pricing';

type Account = Doc<'edgeProviderAccounts'>;
type Location = Doc<'edgeLocations'>;
type PlanRow = Doc<'edgePlans'>;

/** The refusal code of the budget guard (setup plan, selection, the insert). */
export const SPEND_CAP_REACHED = 'account_spend_cap_reached';

const traffic = v.object({
  kind: v.union(
    v.literal('unlimited'),
    v.literal('included'),
    v.literal('per_gb'),
    v.literal('unknown'),
  ),
  includedGb: v.optional(v.number()),
  perGb: v.optional(v.number()),
});

/** One plan as an adapter reads it (`ProviderPlan`). */
export const providerPlanValidator = v.object({
  size: v.string(),
  label: v.string(),
  perHour: v.union(v.number(), v.null()),
  perMonth: v.union(v.number(), v.null()),
  currency: v.union(v.string(), v.null()),
  traffic,
  bandwidthMbps: v.union(v.number(), v.null()),
  acceptsOutsideNode: v.union(v.boolean(), v.null()),
  source: v.union(v.literal('api'), v.literal('catalog')),
  catalogAsOf: v.optional(v.string()),
});

/** The operator's cost settings of an account (`edgeProviderAccounts.cost`). */
export const accountCostValidator = v.object({
  paid: v.union(v.literal('list'), v.literal('free'), v.literal('amount')),
  perEdgeMonthly: v.optional(v.number()),
  currency: v.optional(v.string()),
  note: v.optional(v.string()),
  monthlyCap: v.optional(v.number()),
});

// --- reads ---------------------------------------------------------------------------

/** Every stored plan of a location, cheapest first (unpriced last). */
export async function plansOfLocation(
  db: DatabaseReader,
  locationId: Id<'edgeLocations'>,
): Promise<PlanRow[]> {
  const rows = await db
    .query('edgePlans')
    .withIndex('by_location_size', (q) => q.eq('locationId', locationId))
    .take(MAX_PLANS_PER_LOCATION);
  const price = (r: PlanRow) => monthlyOf(r) ?? Number.POSITIVE_INFINITY;
  return rows.sort((a, b) => price(a) - price(b) || a.sizeKey.localeCompare(b.sizeKey));
}

/** The stored plan of one size at a location (sizes compare without regard to case). */
export async function planRowAt(
  db: DatabaseReader,
  locationId: Id<'edgeLocations'>,
  size: string | null,
): Promise<PlanRow | null> {
  if (!size) return null;
  return db
    .query('edgePlans')
    .withIndex('by_location_size', (q) =>
      q.eq('locationId', locationId).eq('sizeKey', sizeKey(size)),
    )
    .first();
}

export function storedPlanOf(row: PlanRow | null): StoredPlan | null {
  if (!row) return null;
  return {
    size: row.size,
    label: row.label,
    ...(row.perHour !== undefined ? { perHour: row.perHour } : {}),
    ...(row.perMonth !== undefined ? { perMonth: row.perMonth } : {}),
    ...(row.currency !== undefined ? { currency: row.currency } : {}),
    traffic: row.traffic,
    ...(row.bandwidthMbps !== undefined ? { bandwidthMbps: row.bandwidthMbps } : {}),
    ...(row.acceptsOutsideNode !== undefined ? { acceptsOutsideNode: row.acceptsOutsideNode } : {}),
    source: row.source,
    ...(row.catalogAsOf !== undefined ? { catalogAsOf: row.catalogAsOf } : {}),
    pricedAt: row.pricedAt,
  };
}

/** The account's cost settings (null: the default, list price for a load balancer, none for a CDN). */
export function accountCostOf(account: Pick<Account, 'cost'>): AccountCost | null {
  return account.cost ?? null;
}

/**
 * The size a pick at this location builds: the template it resolves, its
 * regional values, the node's own choices laid over (null for a CDN, which
 * has no size).
 */
export async function sizeAt(
  ctx: { db: DatabaseReader },
  account: Pick<Account, '_id' | 'provider' | 'defaultTemplateId'>,
  location: Pick<Location, 'defaultTemplateId' | 'regionalParams'>,
  choices: Record<string, unknown> | null,
  explicitTemplateId?: Id<'edgeTemplates'> | null,
): Promise<string | null> {
  if (!sizeKeyOf(account.provider)) return null;
  const built = await resolveBuildFor(
    ctx,
    account.provider,
    explicitTemplateId ?? null,
    account.defaultTemplateId ?? null,
    account._id,
    location,
    choices,
  );
  return sizeOf(account.provider, built.params);
}

/** What one edge of `size` at this location costs a month, and the plan it was read from. */
export async function edgeCostAt(
  db: DatabaseReader,
  account: Pick<Account, 'provider' | 'cost'>,
  locationId: Id<'edgeLocations'> | null,
  size: string | null,
): Promise<{ cost: EdgeCost; plan: PlanRow | null }> {
  const plan =
    locationId && edgeLayerOf(account.provider) === 'l4'
      ? await planRowAt(db, locationId, size)
      : null;
  return { cost: edgeCostOf(account.provider, accountCostOf(account), storedPlanOf(plan)), plan };
}

/** Live edges FCP manages in the account (bounded per status, like the capacity reads). */
async function managedLiveEdgesOf(
  db: DatabaseReader,
  accountId: Id<'edgeProviderAccounts'>,
): Promise<Doc<'edges'>[]> {
  const out: Doc<'edges'>[] = [];
  for (const status of EDGE_LIVE_STATUSES)
    out.push(
      ...(await db
        .query('edges')
        .withIndex('by_account_status', (q) => q.eq('accountId', accountId).eq('status', status))
        .take(LIVE_EDGE_SCAN_LIMIT)),
    );
  return out.filter((e) => e.managed);
}

/**
 * The account's monthly estimate: each live edge FCP manages, at its frozen
 * size (an edge from before sizes were frozen: what its location builds with
 * its choices), priced at its location.
 */
export async function spendOf(
  ctx: { db: DatabaseReader },
  account: Pick<Account, '_id' | 'provider' | 'defaultTemplateId' | 'cost'>,
): Promise<SpendView> {
  const edges = await managedLiveEdgesOf(ctx.db, account._id);
  const locations = new Map<string, Location | null>();
  const sizes = new Map<string, string | null>();
  const counted = new Map<string, { cost: EdgeCost; count: number }>();
  for (const e of edges) {
    let size = e.planSize ?? null;
    if (!size && e.locationId && sizeKeyOf(account.provider)) {
      const memo = `${e.locationId}|${e.templateId ?? ''}|${e.choices ?? ''}`;
      if (!sizes.has(memo)) {
        if (!locations.has(e.locationId))
          locations.set(e.locationId, await ctx.db.get(e.locationId));
        const loc = locations.get(e.locationId);
        sizes.set(
          memo,
          loc
            ? await sizeAt(
                ctx,
                account,
                loc,
                e.choices ? parseOptionValues(e.choices) : null,
                e.templateId ?? null,
              )
            : null,
        );
      }
      size = sizes.get(memo) ?? null;
    }
    const key = `${e.locationId ?? ''}|${size ? sizeKey(size) : ''}`;
    const seen = counted.get(key);
    if (seen) seen.count++;
    else
      counted.set(key, {
        cost: (await edgeCostAt(ctx.db, account, e.locationId ?? null, size)).cost,
        count: 1,
      });
  }
  return spendViewOf(accountCostOf(account), [...counted.values()]);
}

/**
 * The budget guard: `account_spend_cap_reached` when the account is at its
 * cap already, or `adding` edges at `each` would take it past (an edge whose
 * cost is not known adds nothing). Null without a cap.
 */
export async function capRefusal(
  ctx: { db: DatabaseReader },
  account: Pick<Account, '_id' | 'provider' | 'defaultTemplateId' | 'cost'>,
  each: EdgeCost,
  adding = 1,
): Promise<typeof SPEND_CAP_REACHED | null> {
  if (typeof account.cost?.monthlyCap !== 'number') return null;
  const spend = await spendOf(ctx, account);
  return atCap(spend) || passesCap(spend, each, adding) ? SPEND_CAP_REACHED : null;
}

// --- admin views -----------------------------------------------------------------------

/** One plan in its admin shape. `refusal`: why the size cannot carry an FCP node there (#173 codes). */
export function planAdmin(row: PlanRow, refusal: string | null) {
  return {
    size: row.size,
    label: row.label,
    perHour: row.perHour ?? null,
    perMonth: monthlyOf(row),
    currency: row.currency ?? null,
    traffic: {
      kind: row.traffic.kind,
      includedGb: row.traffic.includedGb ?? null,
      perGb: row.traffic.perGb ?? null,
    },
    bandwidthMbps: row.bandwidthMbps ?? null,
    acceptsOutsideNode: row.acceptsOutsideNode ?? (refusal ? false : null),
    refusal,
    source: row.source,
    catalogAsOf: row.catalogAsOf ?? null,
    pricedAt: new Date(row.pricedAt).toISOString(),
  };
}
export type PlanAdmin = ReturnType<typeof planAdmin>;

/** One edge's cost in its admin shape. */
export function costAdmin(c: EdgeCost) {
  return {
    monthly: c.monthly,
    currency: c.currency,
    basis: c.basis,
    plusTraffic: c.plusTraffic,
    listMonthly: c.listMonthly,
    listCurrency: c.listCurrency,
  };
}

/** Why a size cannot carry an FCP node at this place (a Scaleway size that is not multi-cloud), or null. */
function sizeRefusalAt(
  provider: Account['provider'],
  location: Pick<Location, 'inventorySnapshot'>,
  size: string,
): string | null {
  const key = sizeKeyOf(provider);
  return key ? sizeProblemOf(provider, { [key]: size }, location.inventorySnapshot) : null;
}

/**
 * A location's plans and what one edge there costs now (the size it builds
 * with, priced, the account's choice laid over): the location rows of the
 * account page and every picker. A CDN location has no plans; its cost is the
 * account's own.
 */
export async function locationCostAdmin(
  ctx: { db: DatabaseReader },
  account: Pick<Account, '_id' | 'provider' | 'defaultTemplateId' | 'cost'>,
  location: Location,
) {
  const l4 = edgeLayerOf(account.provider) === 'l4';
  const rows = l4 ? await plansOfLocation(ctx.db, location._id) : [];
  const size = l4 ? await sizeAt(ctx, account, location, null) : null;
  const here = size ? (rows.find((r) => r.sizeKey === sizeKey(size)) ?? null) : null;
  const cost = edgeCostOf(account.provider, accountCostOf(account), storedPlanOf(here));
  return {
    size,
    plan: here ? planAdmin(here, sizeRefusalAt(account.provider, location, here.size)) : null,
    cost: costAdmin(cost),
    plans: rows.map((r) => planAdmin(r, sizeRefusalAt(account.provider, location, r.size))),
    plansAt: location.plansAt ? new Date(location.plansAt).toISOString() : null,
    plansError: location.plansError ?? null,
  };
}
export type LocationCostAdmin = Awaited<ReturnType<typeof locationCostAdmin>>;

/** The account's cost settings and its monthly estimate, in their admin shape. */
export function accountCostAdmin(
  account: Pick<Account, 'cost'>,
  spend: SpendView,
): AccountCostAdmin {
  const c = accountCostOf(account);
  return {
    paid: c?.paid ?? null,
    perEdgeMonthly: c?.perEdgeMonthly ?? null,
    currency: c?.currency ?? null,
    note: c?.note ?? null,
    monthlyCap: c?.monthlyCap ?? null,
    spend: {
      edges: spend.edges,
      totals: spend.total.totals,
      unpriced: spend.total.unpriced,
      plusTraffic: spend.total.plusTraffic,
      monthly: spend.monthly,
      atCap: atCap(spend),
    },
  };
}

export interface AccountCostAdmin {
  paid: AccountCost['paid'] | null;
  perEdgeMonthly: number | null;
  currency: string | null;
  note: string | null;
  monthlyCap: number | null;
  spend: {
    edges: number;
    totals: Array<{ currency: string; monthly: number }>;
    unpriced: number;
    plusTraffic: boolean;
    monthly: number;
    atCap: boolean;
  };
}

// --- cost of what is about to be created ------------------------------------------------

/**
 * What a protect plan's picks cost a month before anything is created: per
 * pick, the edges it gets (`count`) at the size it builds (its options laid
 * over the location's template), priced; the total per currency; and the
 * accounts whose cap the new edges would pass (`capReached`, the budget guard).
 */
export const costOfPicks = internalQuery({
  args: {
    picks: v.array(
      v.object({ locationId: v.id('edgeLocations'), options: v.any(), count: v.number() }),
    ),
  },
  handler: async (ctx, a) => {
    const lines: Array<{
      locationId: string;
      count: number;
      size: string | null;
      label: string | null;
      cost: ReturnType<typeof costAdmin>;
      source: 'api' | 'catalog' | null;
      catalogAsOf: string | null;
      pricedAt: string | null;
    }> = [];
    const byAccount = new Map<
      string,
      { account: Account; costs: Array<{ cost: EdgeCost; count: number }> }
    >();
    const costs: Array<{ cost: EdgeCost; count: number }> = [];
    for (const p of a.picks) {
      const location = await ctx.db.get(p.locationId);
      const account = location ? await ctx.db.get(location.accountId) : null;
      if (!location || !account) continue;
      const options =
        p.options && typeof p.options === 'object' ? (p.options as Record<string, unknown>) : null;
      const size = await sizeAt(ctx, account, location, options);
      const { cost, plan } = await edgeCostAt(ctx.db, account, location._id, size);
      lines.push({
        locationId: location._id as string,
        count: p.count,
        size,
        label: plan?.label ?? size,
        cost: costAdmin(cost),
        source: plan?.source ?? null,
        catalogAsOf: plan?.catalogAsOf ?? null,
        pricedAt: plan ? new Date(plan.pricedAt).toISOString() : null,
      });
      costs.push({ cost, count: p.count });
      const mine = byAccount.get(account._id as string) ?? { account, costs: [] };
      mine.costs.push({ cost, count: p.count });
      byAccount.set(account._id as string, mine);
    }
    const capReached: string[] = [];
    for (const [id, { account, costs: theirs }] of byAccount) {
      if (typeof account.cost?.monthlyCap !== 'number') continue;
      const spend = await spendOf(ctx, account);
      const adding = theirs.reduce(
        (n, c) =>
          n +
          (c.cost.monthly !== null && c.cost.currency === spend.currency
            ? c.cost.monthly * c.count
            : 0),
        0,
      );
      if (atCap(spend) || spend.monthly + adding > (spend.cap ?? Number.POSITIVE_INFINITY))
        capReached.push(id);
    }
    const total: CostTotal = totalOf(costs);
    return { lines, total, capReached };
  },
});

/** One account's monthly estimate (the account page and the attention list). */
export const spendOfAccount = internalQuery({
  args: { id: v.id('edgeProviderAccounts') },
  handler: async (ctx, { id }) => {
    const account = await ctx.db.get(id);
    return account ? accountCostAdmin(account, await spendOf(ctx, account)) : null;
  },
});

// --- writes --------------------------------------------------------------------------------

/**
 * Store one read of a location's plans: on success the rows are replaced whole
 * (a size the provider no longer lists goes); a failed read keeps them and
 * records the code. Either way the attempt is stamped (the cron's retry clock).
 */
export const record = internalMutation({
  args: {
    locationId: v.id('edgeLocations'),
    plans: v.optional(v.array(providerPlanValidator)),
    error: v.optional(v.string()),
  },
  handler: async (ctx, a) => {
    const location = await ctx.db.get(a.locationId);
    if (!location) return null;
    const now = Date.now();
    if (a.plans === undefined) {
      await ctx.db.patch(location._id, {
        plansTriedAt: now,
        plansError: (a.error ?? 'error').slice(0, 64),
      });
      return null;
    }
    for (const row of await plansOfLocation(ctx.db, location._id)) await ctx.db.delete(row._id);
    const seen = new Set<string>();
    for (const p of a.plans.slice(0, MAX_PLANS_PER_LOCATION)) {
      const key = sizeKey(p.size);
      if (!key || seen.has(key)) continue;
      seen.add(key);
      const num = (n: number | null) =>
        n !== null && Number.isFinite(n) && n >= 0 ? n : undefined;
      await ctx.db.insert('edgePlans', {
        accountId: location.accountId,
        locationId: location._id,
        provider: location.provider,
        size: p.size.trim().slice(0, 64),
        sizeKey: key.slice(0, 64),
        label: p.label.replace(/\s+/g, ' ').trim().slice(0, 120) || p.size,
        ...(num(p.perHour) !== undefined ? { perHour: num(p.perHour) } : {}),
        ...(num(p.perMonth) !== undefined ? { perMonth: num(p.perMonth) } : {}),
        ...(p.currency ? { currency: p.currency.toUpperCase().slice(0, 3) } : {}),
        traffic: {
          kind: p.traffic.kind,
          ...(num(p.traffic.includedGb ?? null) !== undefined
            ? { includedGb: p.traffic.includedGb }
            : {}),
          ...(num(p.traffic.perGb ?? null) !== undefined ? { perGb: p.traffic.perGb } : {}),
        },
        ...(num(p.bandwidthMbps) !== undefined ? { bandwidthMbps: num(p.bandwidthMbps) } : {}),
        ...(p.acceptsOutsideNode !== null ? { acceptsOutsideNode: p.acceptsOutsideNode } : {}),
        source: p.source,
        ...(p.catalogAsOf ? { catalogAsOf: p.catalogAsOf.slice(0, 10) } : {}),
        pricedAt: now,
      });
    }
    await ctx.db.patch(location._id, { plansAt: now, plansTriedAt: now, plansError: undefined });
    return null;
  },
});

/** When a location's plans were last read (the refresh action's floor check). */
export const plansAtOf = internalQuery({
  args: { locationId: v.id('edgeLocations') },
  handler: async (ctx, { locationId }) => (await ctx.db.get(locationId))?.plansAt ?? null,
});

/**
 * The locations whose plans the reconcile cron reads next (or, with
 * `accountId`, one account's after its regions were listed again):
 * switched-on places of enabled load balancer accounts never read or read
 * over a day ago (a failed read waits an hour), oldest first, at most `limit`.
 */
export const staleForRefresh = internalQuery({
  args: {
    now: v.number(),
    limit: v.number(),
    /** One account's locations only (its regions were just listed again). */
    accountId: v.optional(v.id('edgeProviderAccounts')),
  },
  handler: async (ctx, { now, limit, accountId }) => {
    const due: Array<{
      accountId: Id<'edgeProviderAccounts'>;
      locationId: Id<'edgeLocations'>;
      at: number;
    }> = [];
    const accounts = accountId
      ? [await ctx.db.get(accountId)].filter((a): a is Account => a !== null)
      : await ctx.db.query('edgeProviderAccounts').collect();
    for (const account of accounts) {
      if (!account.enabled || edgeLayerOf(account.provider) !== 'l4') continue;
      const rows = await ctx.db
        .query('edgeLocations')
        .withIndex('by_account', (q) => q.eq('accountId', account._id).eq('enabled', true))
        .collect();
      for (const l of rows) {
        if ((l.plansAt ?? 0) + PLANS_STALE_MS > now) continue;
        if ((l.plansTriedAt ?? 0) + PLANS_RETRY_MS > now) continue;
        due.push({ accountId: account._id, locationId: l._id, at: l.plansAt ?? 0 });
      }
    }
    return due
      .sort((a, b) => a.at - b.at)
      .slice(0, limit)
      .map(({ accountId, locationId }) => ({ accountId, locationId }));
  },
});

/**
 * What the operator says an account costs (`null` = back to the default: the
 * list price for a load balancer account, none for a CDN): what it pays per
 * edge, and the monthly cap that stops new edges (off when absent).
 */
export const setAccountCost = internalMutation({
  args: {
    id: v.id('edgeProviderAccounts'),
    cost: v.union(v.null(), accountCostValidator),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    await assertAdmission(ctx.db, 'provider.write');
    const row = await ctx.db.get(a.id);
    if (!row) throw new ConvexError({ code: 'not_found', message: 'Account not found' });
    const cost = a.cost ? cleanCost(a.cost) : null;
    if (cost) {
      const problem = costSettingsProblem(row.provider, cost);
      if (problem) throw new ConvexError({ code: 'validation', message: problem });
    }
    await ctx.db.patch(row._id, { cost: cost ?? undefined, updatedAt: Date.now() });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'edge.provider_account.cost_changed',
      targetType: 'edge_provider_account',
      targetId: row._id,
      payload: {
        name: row.name,
        provider: row.provider,
        paid: cost?.paid ?? null,
        perEdgeMonthly: cost?.perEdgeMonthly ?? null,
        currency: cost?.currency ?? null,
        monthlyCap: cost?.monthlyCap ?? null,
      },
    });
    return { ok: true as const };
  },
});

/** The cost settings as stored: an amount only with `amount`, the note trimmed, the currency upper case. */
function cleanCost(c: AccountCost): AccountCost {
  const note = c.note?.replace(/\s+/g, ' ').trim();
  return {
    paid: c.paid,
    ...(c.paid === 'amount' && c.perEdgeMonthly !== undefined
      ? { perEdgeMonthly: c.perEdgeMonthly }
      : {}),
    ...(c.currency ? { currency: c.currency.trim().toUpperCase() } : {}),
    ...(note ? { note } : {}),
    ...(c.monthlyCap !== undefined ? { monthlyCap: c.monthlyCap } : {}),
  };
}

/** A location's plans go with it (the location delete calls this). */
export async function deletePlansOfLocation(
  ctx: { db: DatabaseWriter },
  locationId: Id<'edgeLocations'>,
): Promise<void> {
  for (const row of await plansOfLocation(ctx.db, locationId)) await ctx.db.delete(row._id);
}

/** An account's plans go with it (the account delete calls this). */
export async function deletePlansOfAccount(
  ctx: Pick<MutationCtx, 'db'>,
  accountId: Id<'edgeProviderAccounts'>,
): Promise<void> {
  const rows = await ctx.db
    .query('edgePlans')
    .withIndex('by_account', (q) => q.eq('accountId', accountId))
    .take(1000);
  for (const r of rows) await ctx.db.delete(r._id);
}

/** Edges cleared per pass of the rollback helper (one bounded page). */
const ROLLBACK_EDGES_PER_PASS = 200;

/**
 * Rollback helper: run BEFORE deploying a build from before plans and prices.
 * That build's schema has no `edgePlans` table rows to keep, no
 * `edgeProviderAccounts.cost`, no `edgeLocations.plans*` and no
 * `edges.planSize` (Convex refuses a deploy while a row holds a field its
 * schema lacks). The first pass deletes the plans and clears the account and
 * location fields; every pass clears one page of edges and schedules the
 * next, so the edges table is walked in bounded pages. `{ done }` once the
 * last page is cleared.
 */
export const clearForRollback = internalMutation({
  args: { cursor: v.optional(v.union(v.string(), v.null())) },
  handler: async (ctx, { cursor }) => {
    if (!cursor) {
      for (const r of await ctx.db.query('edgePlans').take(4000)) await ctx.db.delete(r._id);
      for (const a of await ctx.db.query('edgeProviderAccounts').collect())
        if (a.cost !== undefined) await ctx.db.patch(a._id, { cost: undefined });
      for (const l of await ctx.db.query('edgeLocations').collect())
        if (l.plansAt !== undefined || l.plansTriedAt !== undefined || l.plansError !== undefined)
          await ctx.db.patch(l._id, {
            plansAt: undefined,
            plansTriedAt: undefined,
            plansError: undefined,
          });
    }
    const page = await ctx.db
      .query('edges')
      .paginate({ cursor: cursor ?? null, numItems: ROLLBACK_EDGES_PER_PASS });
    for (const e of page.page)
      if (e.planSize !== undefined) await ctx.db.patch(e._id, { planSize: undefined });
    if (!page.isDone)
      await ctx.scheduler.runAfter(0, internal.edgePlans.clearForRollback, {
        cursor: page.continueCursor,
      });
    return { done: page.isDone };
  },
});
