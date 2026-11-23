/**
 * Sanitizer coverage for the BTCPay per-invoice checkout knobs
 * (`billing.btcpay.*`). These go straight onto a Greenfield invoice, so a value
 * that survives sanitization but BTCPay rejects means a broken checkout page for
 * a paying member — and BTCPay's failure mode for a bad `defaultPaymentMethod`
 * is to silently ignore it, so nothing surfaces the mistake.
 *
 * Exercised through `billingConfigWrites` (the admin PATCH path) because the
 * individual coercers are module-private; that is also the boundary an operator
 * actually reaches.
 */
import { describe, expect, test } from 'vitest';
import {
  BILLING_DEFAULTS,
  BILLING_KEYS,
  billingConfigWrites,
  directCoinsFrom,
  directEnabled,
  sanitizeDirectCoins,
  sanitizeTickerList,
  type BillingConfig,
  withinUnderpaymentTolerance,
  type DirectCoin,
} from './lib/billingConfig';
import { coinUnit, networkLabel } from './lib/cryptoNetworks';

/** The JSON-decoded value written for `key`, or undefined if not written. */
function written(patch: unknown, key: string): unknown {
  const hit = billingConfigWrites(patch).find((w) => w.key === key);
  return hit ? JSON.parse(hit.value) : undefined;
}

const method = (v: unknown) =>
  written(
    { btcpayCheckout: { defaultPaymentMethod: v } },
    BILLING_KEYS.btcpay_defaultPaymentMethod,
  );
const expiry = (v: unknown) =>
  written({ btcpayCheckout: { expirationMinutes: v } }, BILLING_KEYS.btcpay_expirationMinutes);

describe('btcpayCheckout.defaultPaymentMethod', () => {
  test('preserves case — BTCPay ids are mixed-case and case-folding breaks them', () => {
    // The regression this test exists for: an earlier version upper-cased, which
    // turns a real id into one BTCPay does not recognize. BTCPay then ignores the
    // preselection silently, so there is no error to notice.
    expect(method('BTC_LightningLike')).toBe('BTC_LightningLike');
    expect(method('BTC-CHAIN')).toBe('BTC-CHAIN');
    expect(method('BTC-LN')).toBe('BTC-LN');
    expect(method('XMR-CHAIN')).toBe('XMR-CHAIN');
  });

  test('empty means "let BTCPay choose" and is a legal value, not a fallback', () => {
    expect(method('')).toBe('');
    expect(method('   ')).toBe(''); // trimmed to empty, still legal
  });

  test('rejects shapes that could never be a method id, keeping the default', () => {
    const def = BILLING_DEFAULTS.btcpayCheckout.defaultPaymentMethod;
    expect(method('BTC LN')).toBe(def); // space
    expect(method('BTC/LN')).toBe(def); // slash
    expect(method('a'.repeat(33))).toBe(def); // over the 32-char cap
    expect(method(42)).toBe(def);
    expect(method(null)).toBe(def);
  });
});

describe('btcpayCheckout.expirationMinutes', () => {
  test('accepts a sane window and rejects non-integers', () => {
    const def = BILLING_DEFAULTS.btcpayCheckout.expirationMinutes;
    expect(expiry(90)).toBe(90);
    expect(expiry(1)).toBe(1);
    expect(expiry(0)).toBe(def);
    expect(expiry(1.5)).toBe(def);
    expect(expiry(60 * 24 * 30)).toBe(60 * 24 * 30); // 30 days, the cap
    expect(expiry(60 * 24 * 31)).toBe(def);
  });

  test('the compiled default beats BTCPay own 15-minute default', () => {
    // The whole point of overriding: 15 minutes expires before a payer in a
    // censored region can acquire crypto and send it.
    expect(BILLING_DEFAULTS.btcpayCheckout.expirationMinutes).toBeGreaterThan(15);
  });
});

describe('billingConfigWrites shape', () => {
  test('only writes the keys present in the patch', () => {
    const keys = billingConfigWrites({ btcpayCheckout: { expirationMinutes: 120 } }).map(
      (w) => w.key,
    );
    expect(keys).toEqual([BILLING_KEYS.btcpay_expirationMinutes]);
  });

  test('an empty btcpayCheckout object writes nothing', () => {
    expect(billingConfigWrites({ btcpayCheckout: {} })).toEqual([]);
  });
});

describe('underpaymentTolerancePct', () => {
  const tol = (v: unknown) =>
    written({ underpaymentTolerancePct: v }, BILLING_KEYS.underpaymentTolerancePct);

  test('defaults to 5%: covers a flat exchange withdrawal fee on the cheapest crypto term', () => {
    expect(BILLING_DEFAULTS.underpaymentTolerancePct).toBe(5);
  });

  test('accepts 0..10 (0 = exact payments only), fractional allowed', () => {
    expect(tol(0)).toBe(0);
    expect(tol(2.5)).toBe(2.5);
    expect(tol(10)).toBe(10);
  });

  test('out-of-range or non-numeric falls back to the default', () => {
    const def = BILLING_DEFAULTS.underpaymentTolerancePct;
    for (const bad of [-1, 10.5, 50, Number.NaN, '5', null]) expect(tol(bad)).toBe(def);
  });

  test('absent from the patch writes nothing', () => {
    expect(billingConfigWrites({ enabled: true }).map((w) => w.key)).not.toContain(
      BILLING_KEYS.underpaymentTolerancePct,
    );
  });
});

describe('withinUnderpaymentTolerance', () => {
  test('the two reported exchange-fee payments pass at 5%', () => {
    expect(withinUnderpaymentTolerance(40.404061 / 42.404061, 5)).toBe(true); // TRX, 4.7% short
    expect(withinUnderpaymentTolerance(46.538109 / 46.73810961, 5)).toBe(true); // XTZ, 0.4% short
  });

  test('exactly on the boundary passes; past it fails', () => {
    expect(withinUnderpaymentTolerance(0.95, 5)).toBe(true);
    expect(withinUnderpaymentTolerance(0.9499, 5)).toBe(false);
  });

  test('0% means exact; an unmeasured shortfall never passes', () => {
    expect(withinUnderpaymentTolerance(0.999, 0)).toBe(false);
    expect(withinUnderpaymentTolerance(1, 0)).toBe(true);
    expect(withinUnderpaymentTolerance(null, 10)).toBe(false);
    expect(withinUnderpaymentTolerance(Number.NaN, 10)).toBe(false);
  });
});

describe('direct checkout config', () => {
  const written = (patch: unknown, key: string): unknown => {
    const row = billingConfigWrites(patch).find((w) => w.key === key);
    return row ? JSON.parse(row.value) : undefined;
  };

  test('defaults are hosted on both crypto rails', () => {
    expect(BILLING_DEFAULTS.direct.nowpayments.style).toBe('hosted');
    expect(BILLING_DEFAULTS.direct.btcpay.style).toBe('hosted');
    expect(directEnabled(BILLING_DEFAULTS, 'nowpayments')).toBe(false);
    expect(directEnabled(BILLING_DEFAULTS, 'btcpay')).toBe(false);
  });

  test('direct needs a non-empty list; card rails are never direct', () => {
    const on = (coins: DirectCoin[]) => ({
      ...BILLING_DEFAULTS,
      direct: {
        nowpayments: {
          style: 'direct' as const,
          source: 'list' as const,
          coins,
          exclude: [],
          pinned: [],
        },
        btcpay: { style: 'direct' as const, methods: [] },
      },
    });
    expect(directEnabled(on(BILLING_DEFAULTS.direct.nowpayments.coins), 'nowpayments')).toBe(true);
    expect(directEnabled(on([]), 'nowpayments')).toBe(false);
    expect(directEnabled(on([]), 'btcpay')).toBe(false);
    expect(directEnabled(on(BILLING_DEFAULTS.direct.nowpayments.coins), 'stripe')).toBe(false);
  });

  test('coins: lowercased, deduped (first wins), bad rows dropped, memo opt-in only', () => {
    const coins = sanitizeDirectCoins([
      { ticker: ' USDTTRC20 ', label: 'USDT', network: 'Tron (TRC-20)', allowMemo: 'yes' },
      { ticker: 'usdttrc20', label: 'dup', network: 'dup' },
      { ticker: 'x', label: 'too short', network: 'n' },
      { ticker: 'xlm', label: 'XLM', network: 'Stellar', allowMemo: true },
      { ticker: 'btc', label: '', network: 'Bitcoin' },
      { ticker: 'ltc', label: 'LTC', network: 'bad\u0007bell' },
      'garbage',
    ]);
    expect(coins).toEqual([
      { ticker: 'usdttrc20', label: 'USDT', network: 'Tron (TRC-20)', allowMemo: false },
      { ticker: 'xlm', label: 'XLM', network: 'Stellar', allowMemo: true },
    ]);
  });

  test('an explicitly empty coin list is kept (direct then stays hosted)', () => {
    expect(sanitizeDirectCoins([])).toEqual([]);
    expect(sanitizeDirectCoins(undefined)).toEqual(BILLING_DEFAULTS.direct.nowpayments.coins);
  });

  test('admin writes: style is an enum, coins must be a list, methods are shape-checked', () => {
    expect(
      written(
        { direct: { nowpayments: { style: 'direct' } } },
        BILLING_KEYS.nowpayments_checkoutStyle,
      ),
    ).toBe('direct');
    expect(
      written(
        { direct: { nowpayments: { style: 'iframe' } } },
        BILLING_KEYS.nowpayments_checkoutStyle,
      ),
    ).toBe('hosted');
    expect(() => billingConfigWrites({ direct: { nowpayments: { coins: 'btc' } } })).toThrow();
    expect(
      written(
        { direct: { btcpay: { methods: ['BTC-LN', 'BTC-LN', 'bad id!', 'BTC-CHAIN'] } } },
        BILLING_KEYS.btcpay_directMethods,
      ),
    ).toEqual(['BTC-LN', 'BTC-CHAIN']);
  });
});

describe('direct coins from the NOWPayments account', () => {
  const cfg = (np: Partial<BillingConfig['direct']['nowpayments']> = {}): BillingConfig => ({
    ...BILLING_DEFAULTS,
    direct: {
      ...BILLING_DEFAULTS.direct,
      nowpayments: { ...BILLING_DEFAULTS.direct.nowpayments, style: 'direct', ...np },
    },
  });
  const cache = {
    fetchedAt: 1,
    coins: [
      { ticker: 'usdterc20', network: 'eth', memo: false },
      { ticker: 'xrp', network: 'xrp', memo: true },
      { ticker: 'usdttrc20', network: 'trx', memo: false },
      { ticker: 'btc', network: 'btc', memo: false },
      { ticker: 'eth', network: 'eth', memo: false },
      { ticker: 'weird', network: 'zzchain', memo: false },
    ],
  };

  test('default source is the account; pinned first, then by unit and network', () => {
    expect(BILLING_DEFAULTS.direct.nowpayments.source).toBe('account');
    const coins = directCoinsFrom(cfg({ pinned: ['usdttrc20', 'btc'] }), cache);
    expect(coins.map((c) => c.ticker)).toEqual([
      'usdttrc20',
      'btc',
      'eth',
      'usdterc20',
      'weird',
      'xrp',
    ]);
    expect(coins[0]).toMatchObject({ label: 'USDT', network: 'Tron (TRC-20)', allowMemo: true });
    expect(coins.find((c) => c.ticker === 'eth')?.network).toBe('Ethereum');
    expect(coins.find((c) => c.ticker === 'usdterc20')?.network).toBe('Ethereum (ERC-20)');
    expect(coins.find((c) => c.ticker === 'xrp')).toMatchObject({
      network: 'XRP Ledger',
      memo: true,
    });
    // An unknown network is the bare code, never a guess.
    expect(coins.find((c) => c.ticker === 'weird')?.network).toBe('ZZCHAIN');
  });

  test('exclude, hosted style and an empty cache all yield no coins to offer', () => {
    expect(directCoinsFrom(cfg({ exclude: ['xrp'] }), cache).map((c) => c.ticker)).not.toContain(
      'xrp',
    );
    expect(directCoinsFrom(cfg({ style: 'hosted' }), cache)).toEqual([]);
    expect(directCoinsFrom(cfg(), null)).toEqual([]);
  });

  test('source "list" ignores the cache', () => {
    const coins = directCoinsFrom(cfg({ source: 'list' }), cache);
    expect(coins.map((c) => c.ticker)).toEqual(
      BILLING_DEFAULTS.direct.nowpayments.coins.map((c) => c.ticker),
    );
  });

  test('ticker lists are lowercased, shape-checked and deduped', () => {
    expect(sanitizeTickerList([' BTC ', 'btc', 'bad ticker', 'xmr'], [])).toEqual(['btc', 'xmr']);
    expect(sanitizeTickerList('nope', ['btc'])).toEqual(['btc']);
  });

  test('units and network names', () => {
    expect(coinUnit('usdttrc20', 'trx')).toBe('USDT');
    expect(coinUnit('usdtbsc', 'bsc')).toBe('USDT');
    expect(coinUnit('bnbbsc', 'bsc')).toBe('BNB');
    expect(coinUnit('trx', 'trx')).toBe('TRX');
    expect(coinUnit('usdc', 'eth')).toBe('USDC');
    expect(networkLabel('bsc', 'BNB')).toBe('BNB Smart Chain');
    expect(networkLabel('bsc', 'USDT')).toBe('BNB Smart Chain (BEP-20)');
  });
});
