import { readFileSync } from 'node:fs';
import { describe, expect, test } from 'vitest';
import {
  bandwidthWords,
  costWords,
  money,
  outsideWords,
  planOptionLabel,
  planPriceWords,
  planRefused,
  sourceWords,
  totalWords,
  trafficWords,
  type PlanLike,
} from './planWords';

const plan = (over: Partial<PlanLike> = {}): PlanLike => ({
  size: 'LB-GP-L',
  label: 'LB-GP-L',
  perHour: 0.094,
  perMonth: null,
  currency: 'EUR',
  traffic: { kind: 'unlimited' },
  bandwidthMbps: 1000,
  acceptsOutsideNode: true,
  source: 'api',
  ...over,
});

describe('plan words', () => {
  test('a price a month (hourly × 730 when the provider gives none), and an hour', () => {
    expect(planPriceWords(plan())).toBe('€68.62 a month (€0.094 an hour)');
    expect(planPriceWords(plan({ perHour: null, perMonth: 30 }))).toBe('€30.00 a month');
    expect(planPriceWords(plan({ perHour: null, currency: null }))).toBe('No price read');
    expect(money(10, 'USD')).toBe('$10.00');
    expect(money(10, 'XYZ1')).toBe('10.00 XYZ1');
  });

  test('traffic, bandwidth, what the size accepts, where the price comes from', () => {
    expect(trafficWords({ kind: 'unlimited' })).toBe('Traffic included');
    expect(trafficWords({ kind: 'included', includedGb: 1000 })).toBe(
      '1,000 GB a month included, then charged',
    );
    expect(trafficWords({ kind: 'unknown' })).toBe('Traffic terms not published');
    expect(bandwidthWords(200)).toBe('200 Mbps');
    expect(bandwidthWords(4000)).toBe('4 Gbps');
    expect(bandwidthWords(null)).toBe('');
    expect(outsideWords(plan({ acceptsOutsideNode: false }))).toBe(
      "Takes the provider's own servers only",
    );
    expect(outsideWords(plan({ acceptsOutsideNode: null }))).toBe('');
    expect(sourceWords(plan({ source: 'catalog', catalogAsOf: '2026-10-22' }))).toBe(
      'List price as of 2026-10-22',
    );
    expect(sourceWords(plan({ pricedAt: new Date(0).toISOString() }), 3_600_000 * 3)).toMatch(
      /^Provider price, read 3 h ago$/,
    );
  });

  test('a size FCP refuses for a node is marked in the picker', () => {
    expect(planRefused(plan({ refusal: 'size_not_multicloud' }))).toBe(true);
    expect(planRefused(plan({ acceptsOutsideNode: false }))).toBe(true);
    expect(planRefused(plan())).toBe(false);
    expect(
      planOptionLabel(
        plan({ label: 'LB-S', perHour: 0.023, bandwidthMbps: 200, acceptsOutsideNode: false }),
      ),
    ).toBe('LB-S · €16.79 a month, 200 Mbps, not for an FCP node');
  });
});

describe('cost words', () => {
  const list = {
    monthly: 68.62,
    currency: 'EUR',
    basis: 'list' as const,
    plusTraffic: false,
    listMonthly: 68.62,
    listCurrency: 'EUR',
  };

  test('what is paid, with the list price beside it', () => {
    expect(costWords(list)).toBe('€68.62 a month at list price');
    expect(costWords({ ...list, plusTraffic: true })).toBe(
      '€68.62 a month at list price, plus traffic',
    );
    expect(costWords({ ...list, monthly: 0, basis: 'free' })).toBe(
      'Free (credits), list price €68.62',
    );
    expect(costWords({ ...list, monthly: 40, currency: 'USD', basis: 'amount' })).toBe(
      '$40.00 a month (what you pay), list price €68.62',
    );
    expect(
      costWords({
        monthly: null,
        currency: null,
        basis: 'unset',
        plusTraffic: false,
        listMonthly: null,
        listCurrency: null,
      }),
    ).toBe('No price set');
    expect(costWords({ ...list, monthly: null, currency: null })).toBe('No price read yet');
  });

  test('a total per currency, plus traffic, and what has no price', () => {
    expect(
      totalWords({ totals: [{ currency: 'EUR', monthly: 33.58 }], unpriced: 0, plusTraffic: true }),
    ).toBe('About €33.58 a month, plus traffic.');
    expect(
      totalWords({
        totals: [
          { currency: 'EUR', monthly: 10 },
          { currency: 'USD', monthly: 5 },
        ],
        unpriced: 1,
        plusTraffic: false,
      }),
    ).toBe('About €10.00 and $5.00 a month. 1 address with no price on top.');
    expect(totalWords({ totals: [], unpriced: 2, plusTraffic: false })).toBe(
      '2 addresses with no price known.',
    );
    expect(totalWords({ totals: [], unpriced: 0, plusTraffic: false })).toBeNull();
  });

  test('no em-dash and no API path in these words', () => {
    const text = readFileSync(new URL('./planWords.ts', import.meta.url), 'utf8');
    expect(text).not.toContain('—');
    expect(text).not.toContain('/api/');
  });
});
