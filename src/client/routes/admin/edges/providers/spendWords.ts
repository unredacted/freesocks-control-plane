/**
 * What the provider accounts cost, against their monthly spend caps, in words
 * (pure; unit-tested in spendWords.test.ts). Reads only `account.cost`, which
 * the providers list already carries (the estimate over each account's live
 * edges and its cap, docs/edges.md "Plans and prices").
 *
 * Exports:
 *   spendSummary(accounts)        -> the estimate summed per currency, the caps per currency,
 *                                    and the accounts at their cap
 *   spendSummaryWords(summary)    -> the Providers list's sentences (empty when nothing is known)
 *   accountSpendWords(cost)       -> one account's spend against its cap, or null
 */
import type { EdgeAccountCost, EdgeCostTotal } from '../../../../../shared/contracts/edges';
import { money, totalWords } from '../lib/planWords';

interface AccountLike {
  name: string;
  cost: EdgeAccountCost | null;
}

export interface CapTotal {
  currency: string;
  /** The capped accounts' estimate, in the caps' currency. */
  spend: number;
  cap: number;
  accounts: number;
}

export interface SpendSummary {
  /** Every account's estimate, summed per currency. */
  estimate: EdgeCostTotal;
  /** Accounts with a cap, summed per cap currency. */
  caps: CapTotal[];
  /** The names of the accounts at their cap (no new edge is made there). */
  atCap: string[];
}

const round2 = (n: number) => Math.round(n * 100) / 100;

export function spendSummary(accounts: readonly AccountLike[]): SpendSummary {
  const totals = new Map<string, number>();
  const caps = new Map<string, CapTotal>();
  let unpriced = 0;
  let plusTraffic = false;
  const atCap: string[] = [];
  for (const a of accounts) {
    const c = a.cost;
    if (!c) continue;
    for (const t of c.spend.totals)
      totals.set(t.currency, (totals.get(t.currency) ?? 0) + t.monthly);
    unpriced += c.spend.unpriced;
    plusTraffic ||= c.spend.plusTraffic && c.spend.totals.length > 0;
    if (c.monthlyCap !== null && c.currency) {
      const cur = caps.get(c.currency) ?? { currency: c.currency, spend: 0, cap: 0, accounts: 0 };
      cur.spend += c.spend.monthly;
      cur.cap += c.monthlyCap;
      cur.accounts += 1;
      caps.set(c.currency, cur);
    }
    if (c.spend.atCap) atCap.push(a.name);
  }
  const byCurrency = (x: { currency: string }, y: { currency: string }) =>
    x.currency.localeCompare(y.currency);
  return {
    estimate: {
      totals: [...totals]
        .map(([currency, monthly]) => ({ currency, monthly: round2(monthly) }))
        .sort(byCurrency),
      unpriced,
      plusTraffic,
    },
    caps: [...caps.values()]
      .map((c) => ({ ...c, spend: round2(c.spend), cap: round2(c.cap) }))
      .sort(byCurrency),
    atCap,
  };
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export function spendSummaryWords(s: SpendSummary): string[] {
  const out: string[] = [];
  const total = totalWords(s.estimate);
  if (total) out.push(`Spend: ${total.charAt(0).toLowerCase()}${total.slice(1)}`);
  if (s.caps.length > 0) {
    const parts = s.caps.map(
      (c) =>
        `${money(c.spend, c.currency)} of ${money(c.cap, c.currency)} on ${plural(c.accounts, 'account')}`,
    );
    out.push(`Against caps: ${parts.join(', and ')}.`);
  }
  if (s.atCap.length > 0) out.push(`At the cap, so no new addresses: ${s.atCap.join(', ')}.`);
  return out;
}

export function accountSpendWords(cost: EdgeAccountCost | null): string | null {
  if (!cost) return null;
  const s = cost.spend;
  const unpriced =
    s.unpriced > 0 ? ` ${plural(s.unpriced, 'address', 'addresses')} with no price.` : '';
  if (cost.monthlyCap !== null && cost.currency) {
    const of = `${money(s.monthly, cost.currency)} of its ${money(cost.monthlyCap, cost.currency)} cap a month`;
    return s.atCap ? `At its cap: ${of}.${unpriced}` : `About ${of}.${unpriced}`;
  }
  if (s.edges === 0) return null;
  return totalWords(s);
}
