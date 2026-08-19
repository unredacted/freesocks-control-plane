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
import { BILLING_DEFAULTS, BILLING_KEYS, billingConfigWrites } from './lib/billingConfig';

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
