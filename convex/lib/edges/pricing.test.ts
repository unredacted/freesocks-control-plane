import { describe, expect, test } from 'vitest';
import {
  HOURS_PER_MONTH,
  atCap,
  costTieKeys,
  costSettingsProblem,
  edgeCostOf,
  monthlyOf,
  passesCap,
  plusTraffic,
  sizeKey,
  sizeKeyOf,
  sizeOf,
  spendViewOf,
  totalOf,
  type StoredPlan,
} from './pricing';

const plan = (over: Partial<StoredPlan> = {}): StoredPlan => ({
  size: 'lb-1',
  label: 'lb-1',
  perHour: 0.023,
  currency: 'EUR',
  traffic: { kind: 'unlimited' },
  source: 'api',
  pricedAt: 0,
  ...over,
});

describe('plans', () => {
  test('a monthly price is the provider’s own figure, else hourly × 730', () => {
    expect(HOURS_PER_MONTH).toBe(730);
    expect(monthlyOf(plan({ perHour: 0.023 }))).toBe(16.79);
    expect(monthlyOf(plan({ perHour: 0.0083, perMonth: 6 }))).toBe(6);
    expect(monthlyOf(plan({ perHour: undefined, perMonth: undefined }))).toBeNull();
    expect(monthlyOf(null)).toBeNull();
  });

  test('traffic is "plus" for per-GB plans and past an allowance', () => {
    expect(plusTraffic({ kind: 'unlimited' })).toBe(false);
    expect(plusTraffic({ kind: 'unknown' })).toBe(false);
    expect(plusTraffic({ kind: 'per_gb', perGb: 0.01 })).toBe(true);
    expect(plusTraffic({ kind: 'included', includedGb: 1000 })).toBe(true);
  });

  test('the size field of each load balancer provider; a CDN has none', () => {
    expect(sizeKeyOf('gcore')).toBe('flavor');
    expect(sizeKeyOf('upcloud')).toBe('plan');
    expect(sizeKeyOf('scaleway')).toBe('type');
    expect(sizeKeyOf('ovh')).toBe('flavorId');
    expect(sizeKeyOf('cloudflare')).toBeNull();
    expect(sizeOf('scaleway', { type: ' LB-GP-L ' })).toBe('LB-GP-L');
    expect(sizeOf('ovh', { flavorId: '' })).toBeNull();
    expect(sizeKey('LB-GP-L')).toBe('lb-gp-l');
  });
});

describe('what one edge costs', () => {
  test('a load balancer account pays the list price unless told otherwise', () => {
    expect(edgeCostOf('scaleway', null, plan())).toMatchObject({
      monthly: 16.79,
      currency: 'EUR',
      basis: 'list',
      plusTraffic: false,
      listMonthly: 16.79,
    });
    expect(
      edgeCostOf('ovh', null, plan({ traffic: { kind: 'included', includedGb: 1000 } })),
    ).toMatchObject({ basis: 'list', plusTraffic: true });
    // No plan read for the size: not known.
    expect(edgeCostOf('gcore', null, null)).toMatchObject({ monthly: null, basis: 'list' });
  });

  test('free and the operator’s own amount win, with the list price kept beside them', () => {
    expect(edgeCostOf('upcloud', { paid: 'free' }, plan())).toMatchObject({
      monthly: 0,
      basis: 'free',
      plusTraffic: false,
      listMonthly: 16.79,
      listCurrency: 'EUR',
    });
    expect(
      edgeCostOf('gcore', { paid: 'amount', perEdgeMonthly: 9.5, currency: 'USD' }, plan()),
    ).toMatchObject({ monthly: 9.5, currency: 'USD', basis: 'amount', listMonthly: 16.79 });
  });

  test('a CDN account is never priced on its own: unset until the operator says', () => {
    expect(edgeCostOf('cloudflare', null, plan())).toMatchObject({
      monthly: null,
      basis: 'unset',
      listMonthly: null,
    });
    expect(edgeCostOf('fastly', { paid: 'free' }, null)).toMatchObject({
      monthly: 0,
      basis: 'free',
    });
    expect(
      edgeCostOf('fastly', { paid: 'amount', perEdgeMonthly: 5, currency: 'EUR' }, null),
    ).toMatchObject({ monthly: 5, basis: 'amount' });
  });
});

describe('totals and the cap', () => {
  const eur = edgeCostOf('scaleway', null, plan());
  const usd = edgeCostOf(
    'gcore',
    null,
    plan({ perHour: undefined, perMonth: 10, currency: 'USD' }),
  );
  const unknown = edgeCostOf('gcore', null, null);

  test('totals are kept per currency, never added across; unpriced edges counted apart', () => {
    expect(
      totalOf([
        { cost: eur, count: 2 },
        { cost: usd, count: 1 },
        { cost: unknown, count: 3 },
      ]),
    ).toEqual({
      totals: [
        { currency: 'EUR', monthly: 33.58 },
        { currency: 'USD', monthly: 10 },
      ],
      unpriced: 3,
      plusTraffic: false,
    });
  });

  test('the cap compares the estimate in its own currency; unknown costs add nothing', () => {
    const spend = spendViewOf({ paid: 'list', currency: 'EUR', monthlyCap: 40 }, [
      { cost: eur, count: 2 },
      { cost: usd, count: 5 },
    ]);
    expect(spend).toMatchObject({ edges: 7, monthly: 33.58, cap: 40, currency: 'EUR' });
    expect(atCap(spend)).toBe(false);
    expect(passesCap(spend, eur, 1)).toBe(true);
    expect(passesCap(spend, usd, 10)).toBe(false);
    expect(passesCap(spend, unknown, 10)).toBe(false);
    expect(atCap({ ...spend, monthly: 40 })).toBe(true);
    // No cap: never.
    expect(passesCap(spendViewOf(null, [{ cost: eur, count: 100 }]), eur, 100)).toBe(false);
  });

  test('the tie-break keys: a rank by cost within each priority and currency; unknown ranks first', () => {
    const c = (
      id: string,
      priority: number,
      monthlyCost: number | null,
      costCurrency?: string,
    ) => ({
      id,
      priority,
      monthlyCost,
      costCurrency: costCurrency ?? null,
    });
    const eur20 = c('eur20', 1, 20, 'EUR');
    const usd5 = c('usd5', 1, 5, 'USD');
    const eur10 = c('eur10', 1, 10, 'EUR');
    const eur10b = c('eur10b', 1, 10, 'EUR');
    const unknown = c('unknown', 1, null);
    const other = c('other', 2, 1, 'EUR');
    const keys = costTieKeys([eur20, usd5, eur10, eur10b, unknown, other]);
    expect([eur20, usd5, eur10, eur10b, unknown, other].map((x) => keys.get(x))).toEqual([
      1, 0, 0, 0, 0, 0,
    ]);
  });
});

describe('cost settings', () => {
  test('what the operator may say', () => {
    expect(costSettingsProblem('gcore', { paid: 'list' })).toBeNull();
    expect(costSettingsProblem('fastly', { paid: 'list' })).toMatch(/no list price/);
    expect(costSettingsProblem('gcore', { paid: 'amount', perEdgeMonthly: 5 })).toMatch(/currency/);
    expect(
      costSettingsProblem('gcore', { paid: 'amount', perEdgeMonthly: 5, currency: 'eur' }),
    ).toMatch(/three-letter/);
    expect(costSettingsProblem('gcore', { paid: 'list', monthlyCap: 50 })).toMatch(/cap/);
    expect(costSettingsProblem('gcore', { paid: 'list', monthlyCap: 0, currency: 'EUR' })).toMatch(
      /cap/,
    );
    expect(
      costSettingsProblem('gcore', { paid: 'list', monthlyCap: 50, currency: 'EUR' }),
    ).toBeNull();
    expect(costSettingsProblem('cloudflare', { paid: 'free' })).toBeNull();
  });
});
