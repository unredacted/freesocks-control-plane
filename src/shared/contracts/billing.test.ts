/**
 * Deploy-skew guards on the admin billing contract.
 *
 * The SPA and the Convex backend ship independently, so for a window the SPA can
 * be NEWER than the backend and receive a config object missing fields it knows
 * about. `AdminBilling.svelte` deep-clones the parsed config into an editable
 * draft and binds inputs straight to nested objects (`draft.btcpayCheckout.…`),
 * so a missing nested object is not a cosmetic gap — it is a null-deref on a page
 * the operator needs in order to fix billing. These tests pin the `.default()`s
 * that prevent that.
 */
import { describe, expect, test } from 'vitest';
import { BillingConfigView } from './billing';

/** A backend response predating both nested config blocks. */
const legacyConfig = {
  enabled: true,
  rails: { nowpayments: true, btcpay: true, stripe: false, paypal: false },
  currency: 'USD',
  tierSlug: 'member',
  durations: [{ months: 1, amountCents: 500 }],
  cryptoMinMonths: 3,
};

describe('BillingConfigView deploy-skew defaults', () => {
  test('a config with no btcpayCheckout still parses, with usable defaults', () => {
    const parsed = BillingConfigView.parse(legacyConfig);
    // Present and complete — every field the admin page binds an input to.
    expect(parsed.btcpayCheckout).toEqual({
      expirationMinutes: 90,
      monitoringMinutes: 1440,
      paymentTolerance: 0,
      defaultPaymentMethod: '',
    });
    // 15 minutes is BTCPay's own default and is too short for a payer who has to
    // go acquire crypto first; the fallback must not silently reintroduce it.
    expect(parsed.btcpayCheckout.expirationMinutes).toBeGreaterThan(15);
    // Tolerance defaults to exact-amount: never forgo revenue by omission.
    expect(parsed.btcpayCheckout.paymentTolerance).toBe(0);
  });

  test('the other nested blocks keep their skew defaults too', () => {
    const parsed = BillingConfigView.parse(legacyConfig);
    expect(parsed.btcpayMinMonths).toBe(1);
    expect(parsed.donation.bonusWindowDays).toBe(30);
  });

  test('a real backend value overrides the default rather than merging oddly', () => {
    const parsed = BillingConfigView.parse({
      ...legacyConfig,
      btcpayCheckout: {
        expirationMinutes: 120,
        monitoringMinutes: 2880,
        paymentTolerance: 1.5,
        defaultPaymentMethod: 'BTC-LN',
      },
    });
    expect(parsed.btcpayCheckout.expirationMinutes).toBe(120);
    expect(parsed.btcpayCheckout.paymentTolerance).toBe(1.5);
    expect(parsed.btcpayCheckout.defaultPaymentMethod).toBe('BTC-LN');
  });

  test('every field the admin draft binds to is non-optional after parse', () => {
    // AdminBilling.svelte does `draft.btcpayCheckout.<field> = …` on input, so a
    // partial nested object would throw at edit time rather than at parse time.
    const parsed = BillingConfigView.parse(legacyConfig);
    for (const key of [
      'expirationMinutes',
      'monitoringMinutes',
      'paymentTolerance',
      'defaultPaymentMethod',
    ] as const) {
      expect(parsed.btcpayCheckout[key]).toBeDefined();
    }
  });
});
