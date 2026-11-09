import { describe, expect, it } from 'vitest';
import type { EdgeAccountCost } from '../../../../../shared/contracts/edges';
import { accountSpendWords, spendSummary, spendSummaryWords } from './spendWords';

function cost(
  over: Omit<Partial<EdgeAccountCost>, 'spend'> & {
    spend?: Partial<EdgeAccountCost['spend']>;
  } = {},
) {
  const { spend, ...rest } = over;
  return {
    paid: null,
    perEdgeMonthly: null,
    currency: null,
    note: null,
    monthlyCap: null,
    ...rest,
    spend: {
      totals: [],
      unpriced: 0,
      plusTraffic: false,
      edges: 0,
      monthly: 0,
      atCap: false,
      ...spend,
    },
  } satisfies EdgeAccountCost;
}

describe('spendSummary', () => {
  it('sums the estimate per currency and the caps per cap currency', () => {
    const s = spendSummary([
      {
        name: 'A',
        cost: cost({
          currency: 'EUR',
          monthlyCap: 90,
          spend: { totals: [{ currency: 'EUR', monthly: 30 }], edges: 3, monthly: 30 },
        }),
      },
      {
        name: 'B',
        cost: cost({
          currency: 'EUR',
          monthlyCap: 10,
          spend: {
            totals: [{ currency: 'EUR', monthly: 10.005 }],
            edges: 1,
            monthly: 10,
            atCap: true,
          },
        }),
      },
      {
        name: 'C',
        cost: cost({ spend: { totals: [{ currency: 'USD', monthly: 5 }], edges: 1, unpriced: 2 } }),
      },
      { name: 'D', cost: null },
    ]);
    expect(s.estimate.totals).toEqual([
      { currency: 'EUR', monthly: 40.01 },
      { currency: 'USD', monthly: 5 },
    ]);
    expect(s.estimate.unpriced).toBe(2);
    expect(s.caps).toEqual([{ currency: 'EUR', spend: 40, cap: 100, accounts: 2 }]);
    expect(s.atCap).toEqual(['B']);
  });

  it('is empty without any cost', () => {
    const s = spendSummary([{ name: 'A', cost: null }]);
    expect(spendSummaryWords(s)).toEqual([]);
  });
});

describe('spendSummaryWords', () => {
  it('says the spend, the caps and who is at the cap', () => {
    const words = spendSummaryWords({
      estimate: { totals: [{ currency: 'EUR', monthly: 45 }], unpriced: 0, plusTraffic: true },
      caps: [{ currency: 'EUR', spend: 30, cap: 90, accounts: 2 }],
      atCap: ['B'],
    });
    expect(words).toEqual([
      'Spend: about €45.00 a month, plus traffic.',
      'Against caps: €30.00 of €90.00 on 2 accounts.',
      'At the cap, so no new addresses: B.',
    ]);
    for (const w of words) expect(w).not.toMatch(/[—–]/);
  });
  it('leaves out caps when none is set', () => {
    expect(
      spendSummaryWords({
        estimate: { totals: [], unpriced: 1, plusTraffic: false },
        caps: [],
        atCap: [],
      }),
    ).toEqual(['Spend: 1 address with no price known.']);
  });
});

describe('accountSpendWords', () => {
  it('is nothing without a cost, or with no edge and no cap', () => {
    expect(accountSpendWords(null)).toBeNull();
    expect(accountSpendWords(cost())).toBeNull();
  });
  it('says the spend against the cap', () => {
    expect(
      accountSpendWords(
        cost({ currency: 'EUR', monthlyCap: 45, spend: { edges: 1, monthly: 15 } }),
      ),
    ).toBe('About €15.00 of its €45.00 cap a month.');
    expect(
      accountSpendWords(
        cost({
          currency: 'EUR',
          monthlyCap: 45,
          spend: { edges: 3, monthly: 45, atCap: true, unpriced: 1 },
        }),
      ),
    ).toBe('At its cap: €45.00 of its €45.00 cap a month. 1 address with no price.');
  });
  it('says the estimate when there is no cap', () => {
    expect(
      accountSpendWords(cost({ spend: { edges: 2, totals: [{ currency: 'EUR', monthly: 8 }] } })),
    ).toBe('About €8.00 a month.');
  });
});
