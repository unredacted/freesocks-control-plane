/**
 * Plans and prices (docs/edges.md § "Plans and prices"): what one load
 * balancer SIZE costs, carries and accepts at one location, and what the
 * operator says an account really pays. Pure and isolate-safe: the adapters
 * produce `ProviderPlan`s, `convex/edgePlans.ts` stores them, and every cost
 * shown before an edge is created is worked out here.
 *
 *  - A plan's monthly price is the provider's own monthly figure when it gives
 *    one, else its hourly price times `HOURS_PER_MONTH` (730, the hours of an
 *    average month, which is how hourly billing is capped by the providers
 *    that cap it).
 *  - What an edge costs is the account's choice (`AccountCost.paid`): the list
 *    price (a load balancer account's default), free (credits), or the
 *    operator's own amount per edge a month. A CDN account is never priced on
 *    its own: until the operator sets it, its cost is not known.
 *  - Amounts in different currencies are never added together or compared;
 *    totals are kept per currency.
 */
import type { EdgeProviderId } from '../edgeProviderIds';
import { EDGE_TEMPLATES } from './providers/templates';
import { edgeLayerOf } from './providers/capabilities';

/** Hours in an average month (365 × 24 / 12): an hourly price times this is its monthly one. */
export const HOURS_PER_MONTH = 730;

/** A location's plans are read again once they are this old (the reconcile cron). */
export const PLANS_STALE_MS = 24 * 60 * 60 * 1000;
/** A read this soon after the last one answers from the stored rows. */
export const PLANS_REFRESH_FLOOR_MS = 60 * 1000;
/** A failed read is tried again by the cron no sooner than this. */
export const PLANS_RETRY_MS = 60 * 60 * 1000;
/** Locations whose plans the reconcile cron reads per pass. */
export const PLANS_PER_TICK = 2;
/** Most plans kept per location (a provider lists a handful of sizes). */
export const MAX_PLANS_PER_LOCATION = 50;

export type PlanTrafficKind = 'unlimited' | 'included' | 'per_gb' | 'unknown';

/**
 * What a plan's traffic costs: `unlimited` = no traffic charge, `included` =
 * `includedGb` a month, then `perGb` (when known) for each GB past it,
 * `per_gb` = `perGb` for every GB, `unknown` = the source does not say.
 */
export interface PlanTraffic {
  kind: PlanTrafficKind;
  includedGb?: number;
  perGb?: number;
}

/** One size an adapter offers at a location, with its list price where it is known. */
export interface ProviderPlan {
  /** The value the template's size field takes (a Gcore flavor, an UpCloud plan, a Scaleway type, an OVH flavor id). */
  size: string;
  label: string;
  perHour: number | null;
  perMonth: number | null;
  /** ISO 4217 code, upper case; null when no price is known. */
  currency: string | null;
  traffic: PlanTraffic;
  bandwidthMbps: number | null;
  /**
   * The size takes a backend server outside the provider's own cloud. Null =
   * the provider does not say (every provider but Scaleway takes one).
   */
  acceptsOutsideNode: boolean | null;
  /** `api`: the provider's own price list; `catalog`: FCP's dated table. */
  source: 'api' | 'catalog';
  /** A `catalog` price: the day the table was read (YYYY-MM-DD). */
  catalogAsOf?: string;
}

/** A stored plan as the cost math reads it (`edgePlans` rows). */
export interface StoredPlan {
  size: string;
  label: string;
  perHour?: number;
  perMonth?: number;
  currency?: string;
  traffic: PlanTraffic;
  bandwidthMbps?: number;
  acceptsOutsideNode?: boolean;
  source: 'api' | 'catalog';
  catalogAsOf?: string;
  pricedAt: number;
}

/** What the operator says an account costs (`edgeProviderAccounts.cost`). */
export interface AccountCost {
  paid: 'list' | 'free' | 'amount';
  perEdgeMonthly?: number;
  currency?: string;
  note?: string;
  monthlyCap?: number;
}

/** The template key of a provider's load balancer size (`from: 'flavors'`), or null (a CDN). */
export function sizeKeyOf(provider: EdgeProviderId | string): string | null {
  const def = EDGE_TEMPLATES[provider as EdgeProviderId];
  return def?.fields.find((f) => f.from === 'flavors')?.key ?? null;
}

/** The size an effective template builds (null when it names none). */
export function sizeOf(
  provider: EdgeProviderId | string,
  params: Record<string, unknown> | null | undefined,
): string | null {
  const key = sizeKeyOf(provider);
  const v = key && params ? params[key] : undefined;
  return typeof v === 'string' && v.trim() !== '' ? v.trim() : null;
}

/** How sizes are compared and stored: trimmed, lower case (Scaleway lists `LB-GP-L`, docs say `lb-gp-l`). */
export function sizeKey(size: string): string {
  return size.trim().toLowerCase();
}

/** Round to the cent (a list price is never more precise than the provider's own). */
function cents(n: number): number {
  return Math.round(n * 100) / 100;
}

/** A plan's monthly list price: its own monthly figure, else hourly × 730; null when unpriced. */
export function monthlyOf(plan: Pick<StoredPlan, 'perHour' | 'perMonth'> | null): number | null {
  if (!plan) return null;
  if (typeof plan.perMonth === 'number' && Number.isFinite(plan.perMonth)) return plan.perMonth;
  if (typeof plan.perHour === 'number' && Number.isFinite(plan.perHour))
    return cents(plan.perHour * HOURS_PER_MONTH);
  return null;
}

/** Whether a plan's traffic is charged on top of its monthly price (per GB, or past an allowance). */
export function plusTraffic(traffic: PlanTraffic | undefined): boolean {
  return traffic?.kind === 'per_gb' || traffic?.kind === 'included';
}

/** The cost basis of one edge: where its number comes from. */
export type CostBasis = 'list' | 'free' | 'amount' | 'unset';

/** What one edge costs a month, as the account's choice says. */
export interface EdgeCost {
  /** Null = not known (no price read for the plan, or a CDN account with none set). */
  monthly: number | null;
  currency: string | null;
  basis: CostBasis;
  /** Traffic is charged on top (a per-GB plan at its list price). */
  plusTraffic: boolean;
  /** The list price, shown next to what is paid (load balancers only). */
  listMonthly: number | null;
  listCurrency: string | null;
}

/**
 * What one edge of this account costs a month: the operator's choice laid
 * over the plan's list price. A CDN account is never priced on its own
 * (`unset` until the operator says free or an amount); a load balancer
 * account pays the list price unless told otherwise.
 */
export function edgeCostOf(
  provider: EdgeProviderId | string,
  cost: AccountCost | null | undefined,
  plan: StoredPlan | null,
): EdgeCost {
  const l4 = edgeLayerOf(provider as EdgeProviderId) === 'l4';
  const listMonthly = l4 ? monthlyOf(plan) : null;
  const listCurrency = l4 && listMonthly !== null ? (plan?.currency ?? null) : null;
  const list = { listMonthly, listCurrency };
  if (cost?.paid === 'free')
    return {
      monthly: 0,
      currency: cost.currency ?? listCurrency,
      basis: 'free',
      plusTraffic: false,
      ...list,
    };
  if (cost?.paid === 'amount' && typeof cost.perEdgeMonthly === 'number' && cost.currency)
    return {
      monthly: cost.perEdgeMonthly,
      currency: cost.currency,
      basis: 'amount',
      plusTraffic: false,
      ...list,
    };
  if (!l4) return { monthly: null, currency: null, basis: 'unset', plusTraffic: false, ...list };
  return {
    monthly: listMonthly,
    currency: listCurrency,
    basis: 'list',
    plusTraffic: listMonthly !== null && plusTraffic(plan?.traffic),
    ...list,
  };
}

/** Monthly amounts summed per currency; edges with no known cost are counted apart. */
export interface CostTotal {
  totals: Array<{ currency: string; monthly: number }>;
  /** Edges whose cost is not known (no price read, or a CDN with none set). */
  unpriced: number;
  /** At least one edge's traffic is charged on top. */
  plusTraffic: boolean;
}

export function totalOf(costs: ReadonlyArray<{ cost: EdgeCost; count: number }>): CostTotal {
  const by = new Map<string, number>();
  let unpriced = 0;
  let traffic = false;
  for (const { cost, count } of costs) {
    if (count <= 0) continue;
    if (cost.plusTraffic) traffic = true;
    if (cost.monthly === null) {
      unpriced += count;
      continue;
    }
    // A free edge with no currency adds nothing anywhere.
    if (cost.monthly === 0 && !cost.currency) continue;
    const cur = cost.currency ?? '';
    by.set(cur, cents((by.get(cur) ?? 0) + cost.monthly * count));
  }
  return {
    totals: [...by.entries()]
      .filter(([cur]) => cur !== '')
      .map(([currency, monthly]) => ({ currency, monthly }))
      .sort((a, b) => a.currency.localeCompare(b.currency)),
    unpriced,
    plusTraffic: traffic,
  };
}

/** An account's monthly estimate over its live edges, against its cap (`AccountCost.monthlyCap`). */
export interface SpendView {
  /** Live edges FCP manages in the account. */
  edges: number;
  /** Their monthly cost, per currency (unpriced ones counted apart). */
  total: CostTotal;
  cap: number | null;
  /** The cap's currency (the account's `cost.currency`). */
  currency: string | null;
  /** The estimate in the cap's currency (what the cap is compared with). */
  monthly: number;
}

/** The monthly estimate of `costs` against the account's cost settings. */
export function spendViewOf(
  cost: AccountCost | null | undefined,
  costs: ReadonlyArray<{ cost: EdgeCost; count: number }>,
): SpendView {
  const total = totalOf(costs);
  const currency = cost?.currency ?? null;
  const cap = typeof cost?.monthlyCap === 'number' && currency ? cost.monthlyCap : null;
  return {
    edges: costs.reduce((n, c) => n + c.count, 0),
    total,
    cap,
    currency,
    monthly: total.totals.find((t) => t.currency === currency)?.monthly ?? 0,
  };
}

/**
 * Whether `adding` more edges at `each` a month would take the account past
 * its cap. No cap: never. An edge whose cost is not known, or is in another
 * currency than the cap, adds nothing (FCP cannot prove it passes the cap).
 */
export function passesCap(spend: SpendView, each: EdgeCost, adding: number): boolean {
  if (spend.cap === null || adding <= 0) return false;
  const add = each.monthly !== null && each.currency === spend.currency ? each.monthly * adding : 0;
  return cents(spend.monthly + add) > spend.cap;
}

/** Whether the account is already at or past its cap (no new edge fits, whatever it costs). */
export function atCap(spend: SpendView): boolean {
  return spend.cap !== null && spend.monthly >= spend.cap;
}

/**
 * The cheaper of two candidates' monthly costs, for a tie between accounts of
 * the same priority: negative when `a` is cheaper. Costs in different
 * currencies, or not known, are no preference (0).
 */
export function cheaperFirst(
  a: { monthlyCost?: number | null; costCurrency?: string | null },
  b: { monthlyCost?: number | null; costCurrency?: string | null },
): number {
  if (typeof a.monthlyCost !== 'number' || typeof b.monthlyCost !== 'number') return 0;
  if (!a.costCurrency || a.costCurrency !== b.costCurrency) return 0;
  return a.monthlyCost - b.monthlyCost;
}

/** The checks an operator's cost settings must pass (`validation` message, or null). */
export function costSettingsProblem(
  provider: EdgeProviderId | string,
  cost: AccountCost,
): string | null {
  const l4 = edgeLayerOf(provider as EdgeProviderId) === 'l4';
  if (cost.paid === 'list' && !l4)
    return 'A CDN account has no list price: set it free, or the amount you pay';
  if (cost.currency !== undefined && !/^[A-Z]{3}$/.test(cost.currency))
    return 'currency must be a three-letter code like EUR';
  const amountOk = (n: number | undefined) =>
    n === undefined || (Number.isFinite(n) && n >= 0 && n <= 1_000_000);
  if (!amountOk(cost.perEdgeMonthly) || !amountOk(cost.monthlyCap))
    return 'amounts must be between 0 and 1,000,000';
  if (cost.paid === 'amount' && (cost.perEdgeMonthly === undefined || !cost.currency))
    return 'Say what you pay per edge a month, and in which currency';
  if (cost.monthlyCap !== undefined && (cost.monthlyCap <= 0 || !cost.currency))
    return 'A monthly cap needs an amount above zero and a currency';
  if (cost.note !== undefined && cost.note.length > 120) return 'note is at most 120 characters';
  return null;
}
