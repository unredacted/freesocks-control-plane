/**
 * Plans and prices in words (docs/edges.md § "Plans and prices"): what a load
 * balancer size costs, carries and accepts, what one edge costs as the
 * account's choice says, and what a set of new edges adds up to a month. Pure,
 * no Svelte; amounts are never added across currencies.
 *
 * Exports:
 *   money(amount, currency)       '€16.79', or '16.79 XYZ' for a code Intl cannot format
 *   planPriceWords(plan)          '€16.79 a month (€0.023 an hour)' / 'No price read'
 *   trafficWords(traffic)         'Traffic included' / '1,000 GB a month included, then charged' ...
 *   bandwidthWords(mbps)          '200 Mbps' / '1 Gbps' / ''
 *   outsideWords(plan)            whether the size takes a node outside the provider
 *   sourceWords(plan, now?)       'Provider price, read 3 h ago' / 'List price as of 2026-10-22'
 *   planRefused(plan)             FCP refuses the size for a node (`size_not_multicloud`)
 *   planOptionLabel(plan)         one line for a size picker
 *   costWords(cost)               what one edge costs, next to the list price
 *   totalWords(total)             'About €33.58 a month, plus traffic' / null for nothing to say
 */
import type {
  EdgeCostTotal,
  EdgeCostView,
  EdgePlanAdmin,
  EdgePlanTraffic,
} from '@shared/contracts/edges';
import { relativeTime } from './time';

/** The plan fields the words read (a stored plan, or one read live for a new location). */
export type PlanLike = Pick<
  EdgePlanAdmin,
  'size' | 'label' | 'perHour' | 'perMonth' | 'currency' | 'bandwidthMbps' | 'acceptsOutsideNode'
> & {
  traffic: { kind: EdgePlanTraffic['kind']; includedGb?: number | null; perGb?: number | null };
  source: 'api' | 'catalog';
  catalogAsOf?: string | null;
  pricedAt?: string;
  refusal?: string | null;
};

/** Hours in an average month (convex/lib/edges/pricing.ts `HOURS_PER_MONTH`). */
const HOURS_PER_MONTH = 730;

export function money(amount: number, currency: string, opts: { precise?: boolean } = {}): string {
  try {
    return new Intl.NumberFormat('en', {
      style: 'currency',
      currency,
      minimumFractionDigits: 2,
      maximumFractionDigits: opts.precise ? 4 : 2,
    }).format(amount);
  } catch {
    return `${amount.toFixed(2)} ${currency}`;
  }
}

/** A plan's monthly price: its own monthly figure, else hourly × 730. */
export function monthlyOfPlan(plan: Pick<PlanLike, 'perHour' | 'perMonth'>): number | null {
  if (plan.perMonth !== null) return plan.perMonth;
  if (plan.perHour !== null) return Math.round(plan.perHour * HOURS_PER_MONTH * 100) / 100;
  return null;
}

export function planPriceWords(plan: PlanLike): string {
  const monthly = monthlyOfPlan(plan);
  if (monthly === null || !plan.currency) return 'No price read';
  const hourly =
    plan.perHour !== null
      ? ` (${money(plan.perHour, plan.currency, { precise: true })} an hour)`
      : '';
  return `${money(monthly, plan.currency)} a month${hourly}`;
}

export function trafficWords(traffic: PlanLike['traffic']): string {
  switch (traffic.kind) {
    case 'unlimited':
      return 'Traffic included';
    case 'included':
      return `${(traffic.includedGb ?? 0).toLocaleString('en')} GB a month included, then charged`;
    case 'per_gb':
      return traffic.perGb !== null && traffic.perGb !== undefined
        ? `Traffic charged per GB (${traffic.perGb})`
        : 'Traffic charged per GB';
    default:
      return 'Traffic terms not published';
  }
}

export function bandwidthWords(mbps: number | null): string {
  if (mbps === null || mbps <= 0) return '';
  return mbps >= 1000 && mbps % 1000 === 0 ? `${mbps / 1000} Gbps` : `${mbps} Mbps`;
}

export function outsideWords(plan: Pick<PlanLike, 'acceptsOutsideNode' | 'refusal'>): string {
  if (planRefused(plan)) return "Takes the provider's own servers only";
  return plan.acceptsOutsideNode === true ? 'Takes a node outside the provider' : '';
}

export function sourceWords(
  plan: Pick<PlanLike, 'source' | 'catalogAsOf' | 'pricedAt'>,
  now: number = Date.now(),
): string {
  if (plan.source === 'catalog')
    return plan.catalogAsOf ? `List price as of ${plan.catalogAsOf}` : 'List price from FCP';
  return plan.pricedAt
    ? `Provider price, read ${relativeTime(plan.pricedAt, now)}`
    : 'Provider price';
}

/** A size that cannot carry an FCP node (a Scaleway size that takes Scaleway servers only). */
export function planRefused(plan: Pick<PlanLike, 'acceptsOutsideNode' | 'refusal'>): boolean {
  return plan.refusal === 'size_not_multicloud' || plan.acceptsOutsideNode === false;
}

/** One line for a size picker: the size, its monthly price, its bandwidth. */
export function planOptionLabel(plan: PlanLike): string {
  const monthly = monthlyOfPlan(plan);
  const parts = [
    monthly !== null && plan.currency ? `${money(monthly, plan.currency)} a month` : null,
    bandwidthWords(plan.bandwidthMbps) || null,
    planRefused(plan) ? 'not for an FCP node' : null,
  ].filter(Boolean);
  return parts.length > 0 ? `${plan.label} · ${parts.join(', ')}` : plan.label;
}

/** What one edge costs, as the account's choice says, with the list price beside what is paid. */
export function costWords(cost: EdgeCostView): string {
  const list =
    cost.listMonthly !== null && cost.listCurrency
      ? `list price ${money(cost.listMonthly, cost.listCurrency)}`
      : null;
  switch (cost.basis) {
    case 'free':
      return list ? `Free (credits), ${list}` : 'Free (credits)';
    case 'amount':
      return cost.monthly !== null && cost.currency
        ? `${money(cost.monthly, cost.currency)} a month (what you pay)${list ? `, ${list}` : ''}`
        : 'No price set';
    case 'unset':
      return 'No price set';
    default:
      return cost.monthly !== null && cost.currency
        ? `${money(cost.monthly, cost.currency)} a month at list price${cost.plusTraffic ? ', plus traffic' : ''}`
        : 'No price read yet';
  }
}

/** A set of new edges a month: per currency, plus traffic, and what has no price. */
export function totalWords(total: EdgeCostTotal): string | null {
  const sums = total.totals.map((t) => money(t.monthly, t.currency));
  if (sums.length === 0 && total.unpriced === 0) return null;
  const parts: string[] = [];
  if (sums.length > 0)
    parts.push(`About ${sums.join(' and ')} a month${total.plusTraffic ? ', plus traffic' : ''}`);
  if (total.unpriced > 0)
    parts.push(
      `${total.unpriced} address${total.unpriced === 1 ? '' : 'es'} with no price ${sums.length > 0 ? 'on top' : 'known'}`,
    );
  return `${parts.join('. ')}.`;
}
