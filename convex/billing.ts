/**
 * Self-service membership billing: the domain core every payment rail converges
 * on. A signed-in member starts a checkout → we mint an opaque order bound to
 * their userId, create a processor-hosted invoice, and redirect. A signed
 * webhook later flips the order to `paid` EXACTLY ONCE and extends membership
 * via the shared `applyMembership` seam (the same one W4 code redemption uses).
 *
 * Plain actions/mutations (V8: fetch + crypto.subtle — no "use node"). Secrets
 * (processor API keys / IPN secrets) are env-only and read here, never stored.
 * NO payer PII is persisted: orders hold only the opaque ref + amount + tier +
 * duration + status, and the deduped webhookEvents payload is the adapter's
 * REDACTED summary.
 *
 * Self-file `internal.billing.*` references carry explicit handler return types
 * to break Convex's inference cycle (same convention as lifecycle.ts).
 */
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { ActionCtx, DatabaseReader, MutationCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { ConvexError, v } from 'convex/values';
import { randomHex, sha256Hex } from './lib/crypto';
import { generateMembershipCode, membershipCodePrefix } from './lib/membershipCode';
import { applyMembership } from './lifecycle';
import { writeAuditLog } from './lib/audit';
import { recordDonation, subtractDonation } from './lib/donationBonus';
import {
  ACCOUNT_COINS_KEY,
  directEnabled,
  findDuration,
  minMonthsForProcessor,
  resolveBillingConfig,
  readAccountCoins,
  resolveDirectCoins,
  resolveProcessorSecrets,
  withinUnderpaymentTolerance,
} from './lib/billingConfig';
import { knownNetwork } from './lib/cryptoNetworks';
import { sanitizeBotUsername } from './lib/telegramConfig';
import { runWithCronOutcome } from './cronHeartbeat';
import type {
  AccountCoinsCache,
  BillingConfig,
  BtcpayCheckoutConfig,
  DirectCoin,
  ProcessorSecrets,
  ResolvedCoin,
} from './lib/billingConfig';
import {
  DirectPaymentError,
  directPaymentLive,
  directPaymentValidator,
  type DirectPayment,
} from './lib/directPayment';
import * as nowpayments from './lib/processors/nowpayments';
import * as btcpay from './lib/processors/btcpay';
import * as stripe from './lib/processors/stripe';
import * as paypal from './lib/processors/paypal';
import type {
  CheckoutParams,
  CheckoutResult,
  OrderProcessorId,
  OrderStatus,
  ProcessorId,
  VerifyResult,
} from './lib/processors/types';

const DAY_MS = 86_400_000;
const AVG_DAYS_PER_MONTH = 30.44; // 1→30, 3→91, 6→183, 12→365 — fair, day-based like W4 codes.
const monthsToDays = (months: number): number => Math.round(months * AVG_DAYS_PER_MONTH);

// Gift purchases: how many shareable codes one order may mint.
const MAX_GIFT_QUANTITY = 50;

const orderKindValidator = v.union(v.literal('self'), v.literal('gift'), v.literal('donation'));

// The hosted rails: the ones with a checkout to create and an IPN to verify.
const processorValidator = v.union(
  v.literal('nowpayments'),
  v.literal('btcpay'),
  v.literal('stripe'),
  v.literal('paypal'),
);
// Every processor an order can carry: the hosted rails plus Telegram Stars,
// which the bot sells through Telegram's own invoice (no checkout, no IPN).
const orderProcessorValidator = v.union(
  v.literal('nowpayments'),
  v.literal('btcpay'),
  v.literal('stripe'),
  v.literal('paypal'),
  v.literal('telegram_stars'),
);
const orderStatusValidator = v.union(
  v.literal('pending'),
  v.literal('confirming'),
  v.literal('paid'),
  v.literal('failed'),
  v.literal('expired'),
  v.literal('underpaid'),
);

// --- processor dispatch (credentials resolved from DB/env, passed in) --------

/** The deployment's public origin, for building absolute IPN/return URLs. */
function publicBaseUrl(secrets: ProcessorSecrets): string {
  if (!secrets.publicBaseUrl) {
    throw new ConvexError({
      code: 'billing.unavailable',
      message: 'Billing is not fully configured (no public base URL)',
    });
  }
  return secrets.publicBaseUrl.replace(/\/$/, '');
}

/** A Telegram bot username exactly as BotFather allows it (no @, no spaces). */
function isTelegramBotUsername(name: string | undefined | null): name is string {
  return typeof name === 'string' && name !== '' && sanitizeBotUsername(name) === name;
}

/** The deep link that returns a Telegram buyer to the bot's payment check. */
function telegramReturnUrl(botUsername: string, orderRef: string): string {
  return `https://t.me/${botUsername}?start=o_${orderRef}`;
}

/** Mint `n` gift codes with the CSPRNG (actions only): plaintext + hash + prefix. */
async function mintGiftCodes(n: number): Promise<GiftCode[]> {
  const codes: GiftCode[] = [];
  for (let i = 0; i < n; i++) {
    const plaintext = generateMembershipCode();
    codes.push({
      plaintext,
      hash: await sha256Hex(plaintext),
      prefix: membershipCodePrefix(plaintext),
    });
  }
  return codes;
}

async function createCheckoutForProcessor(
  processor: ProcessorId,
  params: CheckoutParams,
  secrets: ProcessorSecrets,
  btcpayCheckout?: BtcpayCheckoutConfig,
  underpaymentTolerancePct?: number,
): Promise<CheckoutResult> {
  switch (processor) {
    case 'nowpayments': {
      if (!secrets.nowpayments.apiKey) throw new Error('NOWPayments API key not configured');
      return nowpayments.createCheckout(
        { apiUrl: secrets.nowpayments.apiUrl, apiKey: secrets.nowpayments.apiKey },
        params,
      );
    }
    case 'btcpay': {
      const bp = secrets.btcpay;
      if (!bp.apiUrl || !bp.storeId || !bp.apiKey) throw new Error('BTCPay not configured');
      return btcpay.createCheckout(
        {
          apiUrl: bp.apiUrl,
          storeId: bp.storeId,
          apiKey: bp.apiKey,
          // Per-invoice checkout overrides from the admin-editable catalog. Only
          // this rail takes them — the hosted rails have no equivalent.
          ...(btcpayCheckout ?? {}),
          // BTCPay settles exactly what FCP would grant (see BtcpayConfig).
          ...(underpaymentTolerancePct !== undefined
            ? { paymentTolerancePct: underpaymentTolerancePct }
            : {}),
        },
        params,
      );
    }
    case 'stripe': {
      if (!secrets.stripe.apiKey) throw new Error('Stripe API key not configured');
      return stripe.createCheckout({ apiKey: secrets.stripe.apiKey }, params);
    }
    case 'paypal': {
      const pp = secrets.paypal;
      if (!pp.clientId || !pp.secret || !pp.webhookId) throw new Error('PayPal not configured');
      return paypal.createCheckout(pp, params);
    }
  }
}

/**
 * The direct-checkout step on an invoice createCheckoutForProcessor just made:
 * NOWPayments creates the payment on it in the picked coin; BTCPay reads its
 * activated payment methods. Throws DirectPaymentError.
 */
async function directPaymentForProcessor(
  processor: ProcessorId,
  secrets: ProcessorSecrets,
  config: BillingConfig,
  result: CheckoutResult,
  orderRef: string,
  coin: DirectCoin | null,
): Promise<DirectPayment> {
  const now = Date.now();
  if (processor === 'nowpayments' && coin && secrets.nowpayments.apiKey) {
    return nowpayments.createInvoicePayment(
      { apiUrl: secrets.nowpayments.apiUrl, apiKey: secrets.nowpayments.apiKey },
      { invoiceId: result.processorRef, orderRef, coin, hostedUrl: result.redirectUrl, now },
    );
  }
  const bp = secrets.btcpay;
  if (processor === 'btcpay' && bp.apiUrl && bp.storeId && bp.apiKey) {
    return btcpay.directPaymentMethods(
      { apiUrl: bp.apiUrl, storeId: bp.storeId, apiKey: bp.apiKey },
      {
        invoiceId: result.processorRef,
        allowed: config.direct.btcpay.methods,
        hostedUrl: result.redirectUrl,
        expiresAt: result.expiresAt,
        now,
      },
    );
  }
  throw new DirectPaymentError('unavailable', `${processor}: direct checkout not configured`);
}

/** Verify + parse a processor webhook. Throws billing.not_configured if its secret is unset. */
async function verifyForProcessor(
  ctx: ActionCtx,
  processor: ProcessorId,
  rawBody: string,
  signature: string | null,
  headers: Record<string, string>,
  secrets: ProcessorSecrets,
): Promise<VerifyResult> {
  const notConfigured = (name: string) =>
    new ConvexError({
      code: 'billing.not_configured',
      message: `${name} webhooks are not configured`,
    });
  switch (processor) {
    case 'nowpayments': {
      if (!secrets.nowpayments.ipnSecret) throw notConfigured('NOWPayments');
      return nowpayments.verifyAndParse({
        rawBody,
        signature,
        ipnSecret: secrets.nowpayments.ipnSecret,
        // Optional: enables the API-postback fallback for an IPN whose HMAC we
        // can't reproduce (the canonicalization is a reconstruction of their
        // serializer and has corners) — the payment is re-verified straight
        // from the NOWPayments API instead of lost as a stuck-pending order.
        postback: secrets.nowpayments.apiKey
          ? {
              cfg: { apiUrl: secrets.nowpayments.apiUrl, apiKey: secrets.nowpayments.apiKey },
              reserve: async () => {
                const limit = await ctx.runMutation(internal.rateLimits.checkAndIncrement, {
                  bucket: 'billing:nowpayments:postback',
                  max: 30,
                  windowMs: 60_000,
                });
                if (!limit.allowed) {
                  throw new ConvexError({ code: 'billing.postback_rate_limited' });
                }
              },
            }
          : undefined,
      });
    }
    case 'btcpay': {
      if (!secrets.btcpay.webhookSecret) throw notConfigured('BTCPay');
      const bp = secrets.btcpay;
      return btcpay.verifyAndParse({
        rawBody,
        signature,
        webhookSecret: bp.webhookSecret,
        // Optional: fetches the invoice amount on settle so the grant path
        // cross-checks it (a store settle-tolerance can't grant a partial).
        cfg:
          bp.apiUrl && bp.storeId && bp.apiKey
            ? { apiUrl: bp.apiUrl, storeId: bp.storeId, apiKey: bp.apiKey }
            : undefined,
      });
    }
    case 'stripe': {
      if (!secrets.stripe.webhookSecret) throw notConfigured('Stripe');
      return stripe.verifyAndParse({
        rawBody,
        signature,
        secret: secrets.stripe.webhookSecret,
        // Optional: lets refund/dispute events recover the order ref from the
        // PaymentIntent's metadata (one API read). Without it they ack unmapped.
        apiKey: secrets.stripe.apiKey || undefined,
      });
    }
    case 'paypal': {
      const pp = secrets.paypal;
      if (!pp.clientId || !pp.secret || !pp.webhookId) throw notConfigured('PayPal');
      return paypal.verifyAndParse({ rawBody, headers, cfg: pp });
    }
  }
}

/** Internal-only: resolve all processor credentials (DB rows, env fallback). */
export const resolveSecrets = internalQuery({
  args: {},
  handler: (ctx): Promise<ProcessorSecrets> => resolveProcessorSecrets(ctx.db),
});

// --- checkout ----------------------------------------------------------------

/** Resolve the billing config + the membership tierId for the checkout action. */
export const checkoutContext = internalQuery({
  args: {},
  handler: async (
    ctx,
  ): Promise<{
    config: BillingConfig;
    tierId: Id<'tiers'> | null;
    directCoins: ResolvedCoin[];
  }> => {
    const config = await resolveBillingConfig(ctx.db);
    const tier = await ctx.db
      .query('tiers')
      .withIndex('by_slug', (q) => q.eq('slug', config.tierSlug))
      .unique();
    return {
      config,
      tierId: tier?._id ?? null,
      directCoins: await resolveDirectCoins(ctx.db, config),
    };
  },
});

/**
 * Persist a pending order AFTER the hosted invoice was created (so a failed
 * create never leaves an orphan); audit the checkout. `userId` absent = an
 * anonymous donation order (the checkout action enforces kind==='donation').
 */
export const insertOrder = internalMutation({
  args: {
    processor: processorValidator,
    opaqueRef: v.string(),
    processorRef: v.string(),
    userId: v.optional(v.id('users')),
    // Absent for a donation-only order (no membership tier).
    tierId: v.optional(v.id('tiers')),
    durationDays: v.number(),
    amountCents: v.number(),
    // The donation portion of amountCents (0 for a pure membership order).
    donationCents: v.optional(v.number()),
    currency: v.string(),
    months: v.number(),
    kind: orderKindValidator,
    quantity: v.number(),
    // Direct checkout: the payment details shown on our own page.
    directPayment: v.optional(directPaymentValidator),
    // 'telegram' = a Telegram gift-shop order (userless gift).
    channel: v.optional(v.literal('telegram')),
  },
  handler: async (ctx, a): Promise<Id<'billingOrders'>> => {
    const now = Date.now();
    const orderId = await ctx.db.insert('billingOrders', {
      processor: a.processor,
      ...(a.channel ? { channel: a.channel } : {}),
      opaqueRef: a.opaqueRef,
      processorRef: a.processorRef,
      userId: a.userId,
      tierId: a.tierId,
      durationDays: a.durationDays,
      amountCents: a.amountCents,
      donationCents: a.donationCents,
      currency: a.currency,
      status: 'pending',
      kind: a.kind,
      quantity: a.quantity,
      ...(a.directPayment ? { directPayment: a.directPayment } : {}),
      updatedAt: now,
    });
    await writeAuditLog(ctx, {
      actorType: a.userId ? 'member' : 'anonymous',
      actorId: a.userId,
      action: 'billing.checkout.created',
      targetType: 'billing_order',
      targetId: orderId,
      payload: {
        processor: a.processor,
        months: a.months,
        kind: a.kind,
        quantity: a.quantity,
        donationCents: a.donationCents ?? 0,
        // Which checkout style ran (no payment details: they are payer-specific).
        direct: a.directPayment !== undefined,
        channel: a.channel ?? 'web',
      },
    });
    return orderId;
  },
});

/**
 * Start a checkout for a signed-in member. Validates the rail + duration against
 * the resolved catalog, creates the hosted invoice, and ONLY THEN persists a
 * pending order bound to `userId` — so a processor/config failure can't leave an
 * orphaned `pending` row (the member sees a clean error and can retry). The
 * member identity is NEVER sent to the processor — only `opaqueRef`.
 */
export const createCheckout = internalAction({
  args: {
    // Absent = anonymous checkout: allowed for kind 'donation' ONLY (enforced
    // below) — memberships and gifts always bind to an account.
    userId: v.optional(v.id('users')),
    processor: processorValidator,
    // Required for a membership (self/gift); omitted for a standalone donation.
    months: v.optional(v.number()),
    // 'gift' mints `quantity` shareable codes; 'donation' is a standalone donation
    // (no membership); absent ⇒ self-upgrade. quantity applies to 'gift' only.
    kind: v.optional(orderKindValidator),
    quantity: v.optional(v.number()),
    // Optional donation in cents — added on top of a membership, or the whole
    // charge for kind:'donation'.
    donationCents: v.optional(v.number()),
    // Direct NOWPayments checkout: the coin the member picked (a ticker on the
    // admin's allowlist). Absent = hosted, which is also how an older SPA that
    // never sends it keeps working against a direct-style rail.
    payCurrency: v.optional(v.string()),
    // The Telegram gift shop: a userless gift order whose return URL leads
    // back into the bot (t.me/<botUsername>?start=o_<ref>). Never set by the
    // public checkout route, which keeps refusing anonymous gifts.
    channel: v.optional(v.literal('telegram')),
    botUsername: v.optional(v.string()),
  },
  handler: async (ctx, a): Promise<{ redirectUrl: string; orderRef: string; direct: boolean }> => {
    const { config, tierId, directCoins } = await ctx.runQuery(
      internal.billing.checkoutContext,
      {},
    );
    if (!config.enabled) {
      throw new ConvexError({
        code: 'billing.disabled',
        message: 'Membership purchases are not available',
      });
    }
    if (!config.rails[a.processor]) {
      throw new ConvexError({
        code: 'billing.disabled',
        message: 'That payment method is not available',
      });
    }

    const kind = a.kind ?? 'self';
    const telegram = a.channel === 'telegram';
    if (telegram) {
      // The bot sells gift codes and nothing else, to nobody in particular:
      // no account, no donation add-on, and a return link back into the bot.
      if (a.userId || kind !== 'gift' || (a.donationCents ?? 0) > 0) {
        throw new ConvexError({
          code: 'billing.invalid_order',
          message: 'The Telegram shop sells gift codes only',
        });
      }
      if (!isTelegramBotUsername(a.botUsername)) {
        throw new ConvexError({
          code: 'billing.unavailable',
          message: 'The Telegram shop is not configured (no bot username)',
        });
      }
    } else if (!a.userId && kind !== 'donation') {
      // Belt-and-braces: the HTTP route already 401s unauthenticated
      // non-donation checkouts; a membership/gift order without a user to
      // grant to must never exist.
      throw new ConvexError({
        code: 'auth.unauthenticated',
        message: 'Sign in to buy a membership',
      });
    }
    const donationCents = telegram ? 0 : Math.max(0, Math.floor(a.donationCents ?? 0));

    // Resolve the charge amount, tier/duration, and label per kind. A donation-only
    // order carries no tier/duration; a membership may ride an optional donation.
    let amountCents: number;
    let orderTierId: Id<'tiers'> | undefined;
    let durationDays = 0;
    let months = 0;
    let quantity = 1;
    let description: string;

    if (kind === 'donation') {
      if (!config.donation.enabled) {
        throw new ConvexError({ code: 'billing.disabled', message: 'Donations are not available' });
      }
      if (donationCents < config.donation.minAmountCents) {
        throw new ConvexError({
          code: 'billing.invalid_amount',
          message: 'Donation is below the minimum.',
        });
      }
      amountCents = donationCents;
      description = 'FreeSocks donation';
    } else {
      if (!a.months) {
        throw new ConvexError({
          code: 'billing.invalid_duration',
          message: 'Unknown membership duration',
        });
      }
      const duration = findDuration(config, a.months);
      if (!duration) {
        throw new ConvexError({
          code: 'billing.invalid_duration',
          message: 'Unknown membership duration',
        });
      }
      // Crypto carries a per-coin minimum (XMR's is high) and the payer picks the
      // coin on the hosted page, so we floor the term here. The SPA hides these,
      // but a crafted request must still be refused.
      if (a.months < minMonthsForProcessor(config, a.processor)) {
        throw new ConvexError({
          code: 'billing.duration_unavailable',
          message: 'That term is not available for this payment method.',
        });
      }
      if (!tierId) {
        throw new ConvexError({
          code: 'billing.tier_missing',
          message: 'Membership tier is not configured',
        });
      }
      // Gift: buy N shareable codes (each granting `months`); amount scales by N.
      quantity = kind === 'gift' ? Math.floor(a.quantity ?? 1) : 1;
      if (
        kind === 'gift' &&
        (!Number.isFinite(quantity) || quantity < 1 || quantity > MAX_GIFT_QUANTITY)
      ) {
        throw new ConvexError({
          code: 'billing.invalid_quantity',
          message: `Number of codes must be between 1 and ${MAX_GIFT_QUANTITY}`,
        });
      }
      // An optional donation rides on the same charge (ignored if donations are off).
      const donationAdd = config.donation.enabled ? donationCents : 0;
      amountCents = duration.amountCents * quantity + donationAdd;
      orderTierId = tierId;
      durationDays = monthsToDays(a.months);
      months = a.months;
      const monthLabel = `${a.months} month${a.months === 1 ? '' : 's'}`;
      const suffix = donationAdd > 0 ? ' + donation' : '';
      description =
        kind === 'gift'
          ? `FreeSocks Membership gift — ${quantity} × ${monthLabel}${suffix}`
          : `FreeSocks Membership — ${monthLabel}${suffix}`;
    }

    // The donation portion actually recorded on the order (0 when donations are off).
    const orderDonationCents =
      kind === 'donation' ? donationCents : config.donation.enabled ? donationCents : 0;

    // Direct checkout: resolve the picked coin BEFORE any invoice exists, so a
    // crafted or stale ticker fails without leaving anything at the processor.
    let directCoin: DirectCoin | null = null;
    if (a.processor === 'nowpayments' && a.payCurrency && directCoins.length > 0) {
      const ticker = a.payCurrency.trim().toLowerCase();
      directCoin = directCoins.find((c) => c.ticker === ticker) ?? null;
      if (!directCoin) {
        throw new ConvexError({
          code: 'billing.invalid_coin',
          message: 'That coin is not available.',
        });
      }
    }
    const wantDirect =
      directCoin !== null || (a.processor === 'btcpay' && directEnabled(config, 'btcpay'));

    const secrets = await ctx.runQuery(internal.billing.resolveSecrets, {});
    const base = publicBaseUrl(secrets);
    const opaqueRef = randomHex(16);
    // A Telegram buyer goes back into the bot, whose /start o_<ref> runs the
    // payment check (the bot stores no chat to message later).
    const botReturn = telegram ? telegramReturnUrl(a.botUsername as string, opaqueRef) : null;
    const params: CheckoutParams = {
      orderRef: opaqueRef,
      amountCents,
      currency: config.currency,
      description,
      ipnUrl: `${base}/api/webhooks/${a.processor}`,
      // Anonymous donors have no /account to return to: they land on the
      // public /donate page, whose ?order= poll works without a session.
      successUrl: botReturn ?? `${base}${a.userId ? '/account' : '/donate'}?order=${opaqueRef}`,
      cancelUrl:
        botReturn ?? `${base}${a.userId ? '/account' : '/donate'}?order=${opaqueRef}&cancel=1`,
    };

    // Create the invoice FIRST. On failure, nothing is persisted (no orphaned
    // pending order). The processor's real error is logged server-side for the
    // operator; the member only ever sees the generic message.
    let result: CheckoutResult;
    try {
      result = await createCheckoutForProcessor(
        a.processor,
        params,
        secrets,
        config.btcpayCheckout,
        config.underpaymentTolerancePct,
      );
    } catch (err) {
      console.error(
        `[billing] ${a.processor} checkout create failed:`,
        err instanceof Error ? err.message : String(err),
      );
      throw new ConvexError({
        code: 'billing.unavailable',
        message: 'Could not start checkout. Please try again.',
      });
    }

    // Direct style: read the payment details for our own page. The invoice
    // above is unchanged (its id stays the order's processorRef, so the webhook
    // and grant cross-checks don't change). A payer-fixable refusal (below the
    // coin's minimum, a memo coin the operator hasn't allowed) is an error the
    // form explains; any other failure falls back to the hosted page, logged.
    let directPayment: DirectPayment | undefined;
    if (wantDirect) {
      try {
        directPayment = await directPaymentForProcessor(
          a.processor,
          secrets,
          config,
          result,
          opaqueRef,
          directCoin,
        );
      } catch (err) {
        const kind = err instanceof DirectPaymentError ? err.kind : 'unavailable';
        console.warn(
          `[billing] ${a.processor} direct checkout (${kind}):`,
          err instanceof Error ? err.message : String(err),
        );
        if (kind === 'below_minimum') {
          throw new ConvexError({
            code: 'billing.coin_minimum',
            message: 'This amount is below the minimum for that coin.',
          });
        }
        if (kind === 'memo_refused') {
          throw new ConvexError({
            code: 'billing.invalid_coin',
            message: 'That coin is not available.',
          });
        }
      }
    }

    await ctx.runMutation(internal.billing.insertOrder, {
      processor: a.processor,
      opaqueRef,
      processorRef: result.processorRef,
      userId: a.userId,
      tierId: orderTierId,
      durationDays,
      amountCents,
      donationCents: orderDonationCents,
      currency: config.currency,
      months,
      kind,
      quantity,
      directPayment,
      ...(telegram ? { channel: 'telegram' as const } : {}),
    });
    // `redirectUrl` stays the hosted page even for a direct order: the SPA
    // offers it as a fallback, and an older SPA simply redirects as before.
    return { redirectUrl: result.redirectUrl, orderRef: opaqueRef, direct: !!directPayment };
  },
});

// --- webhook ingest ----------------------------------------------------------

// Monotonic status precedence (Review #8): webhooks can arrive out of order
// (esp. NOWPayments under retry, whose dedupe id is per-(payment,status) so a
// late distinct status is NOT a duplicate). A non-paid update only ever advances
// the order forward — a late 'pending' after 'confirming', or 'confirming' after
// a terminal 'failed'/'expired', is ignored rather than walking the lifecycle
// backward. 'paid' is terminal and guarded separately at the top of applyEvent.
// 'underpaid' outranks 'expired': money arrived, so neither a late expiry event
// nor an order the stale sweep already expired can bury it. 'failed' outranks
// 'underpaid': a refund/reversal (or BTCPay invalidating the payment) closes a
// held short payment, and a late out-of-order partial event can't reopen it.
const STATUS_RANK: Record<OrderStatus, number> = {
  pending: 0,
  confirming: 1,
  expired: 2,
  underpaid: 3,
  failed: 4,
  paid: 5,
};

/**
 * A settled order carried a donation: add it to the shared monthly pool, stamp the
 * buyer's durable donor marker (set-once — backs the account badge), and schedule
 * the free-fleet bandwidth re-cap. No-op when the order carried no donation.
 */
async function fundDonation(
  ctx: MutationCtx,
  userId: Id<'users'> | undefined,
  donationCents: number | undefined,
  now: number,
  orderId?: Id<'billingOrders'>,
): Promise<void> {
  const cents = donationCents ?? 0;
  if (cents <= 0) return;
  // Record WHICH pool bucket this order funded: a UTC day can hold several once
  // an admin retunes the window, so a later refund needs the exact one or it
  // could drain a neighbouring gift and leave this money live.
  const bucketExpiresAt = await recordDonation(ctx, cents, now);
  if (orderId && bucketExpiresAt !== null) {
    await ctx.db.patch(orderId, { donationBucketExpiresAt: bucketExpiresAt });
  }
  // Anonymous donation (no userId): the pool funding above is the whole story —
  // there is no account to stamp a badge or lifetime totals on.
  const u = userId ? await ctx.db.get(userId) : null;
  if (userId && u) {
    // Lifetime aggregates on the user row (billing-order retention pruning must
    // never shrink the donor's displayed totals), plus the first-donor badge.
    await ctx.db.patch(userId, {
      donatedCentsTotal: (u.donatedCentsTotal ?? 0) + cents,
      donationCount: (u.donationCount ?? 0) + 1,
      ...(u.firstDonatedAt == null ? { firstDonatedAt: now } : {}),
      updatedAt: now,
    });
  }
  await ctx.scheduler.runAfter(0, internal.donations.applyFreeBonus, {});
  // Refresh the "free accounts reached" impact stat NOW: freeActive is
  // otherwise recounted only by the daily reconcile, so a donor would stare
  // at a stale figure right after giving. (Targeted recount; the daily full
  // reconcile stays as the self-healing backstop.)
  await ctx.scheduler.runAfter(0, internal.userStats.refreshFreeActive, {});
}

type GiftCode = { plaintext: string; hash: string; prefix: string };

/**
 * Settle an order as paid and deliver what it bought: a donation funds the
 * shared pool, a gift mints its codes (pre-generated by the calling action,
 * where the CSPRNG lives), a membership extends the buyer. Callers guarantee
 * EXACTLY ONCE by checking the order isn't already `paid` inside the same
 * serializable mutation. Shared by the webhook grant (applyEvent) and the
 * operator granting an order from Admin → Billing (grantOrderByAdmin).
 */
async function grantOrder(
  ctx: MutationCtx,
  order: Doc<'billingOrders'>,
  g: {
    processor: OrderProcessorId;
    processorRef: string;
    giftCodes?: GiftCode[];
    /** Set when the payment was short but accepted: recorded on the order. */
    paidRatio?: number | null;
    actorType: 'webhook' | 'admin';
    actorId?: string;
  },
): Promise<{ applied: boolean; granted: boolean }> {
  const now = Date.now();
  // A short payment accepted within the tolerance credits only the share of a
  // donation that actually arrived (rounded down), so the shared pool and the
  // donor's totals never count money that wasn't sent. The credited amount is
  // written back as the order's donationCents, so a later refund unwinds
  // exactly what was credited. The membership/gift part is delivered in full.
  const requestedDonation =
    order.kind === 'donation'
      ? (order.donationCents ?? order.amountCents)
      : (order.donationCents ?? 0);
  const donated =
    g.paidRatio != null && g.paidRatio < 1
      ? Math.floor(requestedDonation * g.paidRatio)
      : requestedDonation;
  const donationPatch = donated !== requestedDonation ? { donationCents: donated } : {};
  // Standalone donation order: record the donation + fund the free-bandwidth
  // pool + stamp the donor badge; NO tier/membership grant. (Modeled on the
  // gift branch — "paid, but don't extend the buyer's own membership".)
  if (order.kind === 'donation') {
    await ctx.db.patch(order._id, {
      status: 'paid',
      directPayment: undefined,
      paidAt: now,
      processorRef: g.processorRef || order.processorRef,
      ...(g.paidRatio != null ? { paidRatio: g.paidRatio } : {}),
      ...donationPatch,
      updatedAt: now,
    });
    await fundDonation(ctx, order.userId, donated, now, order._id);
    await writeAuditLog(ctx, {
      actorType: g.actorType,
      actorId: g.actorId,
      action: 'billing.order.paid',
      targetType: 'billing_order',
      targetId: order._id,
      payload: {
        processor: g.processor,
        amountCents: order.amountCents,
        kind: 'donation',
        donationCents: donated,
      },
    });
    return { applied: true, granted: true };
  }

  // Membership orders (self/gift) are user-bound, with one exception: a
  // Telegram gift-shop order is a userless gift by design (its codes are bound
  // to nobody, so a Telegram identity never meets a FreeSocks account). Any
  // other userId-less membership row would be corrupt: refuse rather than
  // guessing an owner.
  const buyerId = order.userId;
  const botGift = !buyerId && order.channel === 'telegram' && order.kind === 'gift';
  if (!buyerId && !botGift) return { applied: false, granted: false };

  // Membership orders (self/gift) always carry a tier.
  const tierId = order.tierId;
  if (!tierId) return { applied: false, granted: false };
  const tier = await ctx.db.get(tierId);

  // Gift order: mint `quantity` shareable codes bound to the buyer (hash-only)
  // instead of extending the buyer's own membership. The plaintext lives only
  // in the transient giftReveal buffer until the buyer acknowledges saving it.
  if (order.kind === 'gift') {
    const codes = g.giftCodes ?? [];
    await ctx.db.patch(order._id, {
      status: 'paid',
      directPayment: undefined,
      paidAt: now,
      processorRef: g.processorRef || order.processorRef,
      ...(g.paidRatio != null ? { paidRatio: g.paidRatio } : {}),
      ...donationPatch,
      giftReveal: codes.map((c) => c.plaintext),
      giftRevealPending: true, // sweep/ack clears it — see retention.clearStaleGiftReveals (Review #5)
      updatedAt: now,
    });
    for (const c of codes) {
      // Uniqueness read-check (no UNIQUE constraint in Convex): a codeHash
      // dup would break redeem's .unique() lookup. A collision throws, the
      // claim marks failed, and the processor's retry re-mints fresh codes
      // (the paid-order guard keeps it exactly-once).
      const clash = await ctx.db
        .query('redemptionCodes')
        .withIndex('by_code_hash', (q) => q.eq('codeHash', c.hash))
        .unique();
      if (clash) throw new Error('code hash collision');
      await ctx.db.insert('redemptionCodes', {
        codeHash: c.hash,
        codePrefix: c.prefix,
        tierId,
        durationDays: order.durationDays,
        status: 'active',
        // A bot gift's codes are bound to nobody (no buyer, no order id).
        ...(buyerId ? { purchasedByUserId: buyerId } : {}),
        updatedAt: now,
      });
    }
    // A donation may ride a gift purchase too.
    await fundDonation(ctx, buyerId, donated, now, order._id);
    await writeAuditLog(ctx, {
      actorType: g.actorType,
      actorId: g.actorId,
      action: 'billing.order.paid',
      targetType: 'billing_order',
      targetId: order._id,
      payload: {
        processor: g.processor,
        tierSlug: tier?.slug,
        durationDays: order.durationDays,
        amountCents: order.amountCents,
        kind: 'gift',
        quantity: codes.length,
        donationCents: donated,
        channel: order.channel ?? 'web',
      },
    });
    return { applied: true, granted: true };
  }

  if (!buyerId) return { applied: false, granted: false };
  const user = await ctx.db.get(buyerId);
  if (!user) return { applied: false, granted: false };
  await ctx.db.patch(order._id, {
    status: 'paid',
    directPayment: undefined,
    paidAt: now,
    processorRef: g.processorRef || order.processorRef,
    ...(g.paidRatio != null ? { paidRatio: g.paidRatio } : {}),
    ...donationPatch,
    updatedAt: now,
  });
  const expiresAtMs = Math.max(now, user.membershipExpiresAt ?? 0) + order.durationDays * DAY_MS;
  await applyMembership(ctx, {
    userId: buyerId,
    tierId,
    expiresAtMs,
    reason: `billing.${g.processor}`,
    triggeredBy: g.actorType,
  });
  // Apply any optional donation that rode on the membership charge.
  await fundDonation(ctx, buyerId, donated, now, order._id);
  await writeAuditLog(ctx, {
    actorType: g.actorType,
    actorId: g.actorId,
    action: 'billing.order.paid',
    targetType: 'billing_order',
    targetId: order._id,
    payload: {
      processor: g.processor,
      tierSlug: tier?.slug,
      durationDays: order.durationDays,
      amountCents: order.amountCents,
      donationCents: donated,
    },
  });
  return { applied: true, granted: true };
}

/**
 * Serializable order-status apply + single grant. Looks the order up by our
 * opaque ref (every rail echoes it: NOWPayments order_id, Stripe
 * client_reference_id, PayPal custom_id). Once `paid`, all further events are
 * no-ops — so two concurrent "paid" webhooks grant membership EXACTLY ONCE
 * (the loser re-reads status==='paid'). Non-paid statuses advance the order
 * forward only (monotonic — see STATUS_RANK).
 */
export const applyEvent = internalMutation({
  args: {
    processor: orderProcessorValidator,
    orderRef: v.optional(v.string()),
    status: orderStatusValidator,
    processorRef: v.string(),
    // Grant cross-checks from the parsed event (see ParsedEvent in
    // lib/processors/types.ts): the checkout-minted processor id and the
    // reported paid amount, when the rail carries them.
    checkoutRef: v.optional(v.union(v.string(), v.null())),
    amountMinor: v.optional(v.union(v.number(), v.null())),
    amountCurrency: v.optional(v.union(v.string(), v.null())),
    // Underpayment signal from the adapter (see ParsedEvent.underpaid/paidRatio):
    // the payer delivered less than the invoice. Granted within the
    // underpayment tolerance, otherwise held as `underpaid`; audited either way.
    underpaid: v.optional(v.boolean()),
    paidRatio: v.optional(v.union(v.number(), v.null())),
    // See ParsedEvent.detailUnavailable: the granting transition's amount +
    // settle-tolerance cross-checks could not be read back (BTCPay API key
    // missing canviewinvoices). Audited so the weakened guard is visible.
    detailUnavailable: v.optional(v.boolean()),
    // For a 'gift' order being paid: the codes the caller pre-generated (CSPRNG
    // runs in the ingest action). Inserted hash-only into redemptionCodes here;
    // the plaintext is stashed in the order's transient giftReveal buffer.
    giftCodes: v.optional(
      v.array(v.object({ plaintext: v.string(), hash: v.string(), prefix: v.string() })),
    ),
  },
  handler: async (ctx, a): Promise<{ applied: boolean; granted: boolean }> => {
    if (!a.orderRef) return { applied: false, granted: false };
    const order = await ctx.db
      .query('billingOrders')
      .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', a.orderRef as string))
      .unique();
    if (!order) return { applied: false, granted: false };
    // Single-grant guard: once paid, ignore everything (idempotent re-delivery)
    // — EXCEPT two operator-signal cases: a refund/reversal-class event for a
    // paid order is audited (billing.refund_seen), and a SECOND paid event with
    // a DIFFERENT payment id is audited (billing.overpayment_seen: the buyer
    // paid twice on one invoice, e.g. a NOWPayments underpayment topped up by a
    // second transaction — the first already granted). Membership is
    // deliberately NOT auto-revoked (a refund may be partial/mistaken); the
    // audit rows are the operator's action queue.
    if (order.status === 'paid') {
      // PayPal's NORMAL two-event flow would otherwise false-positive here:
      // CHECKOUT.ORDER.APPROVED (resource id = order id) and
      // PAYMENT.CAPTURE.COMPLETED (resource id = capture id) arrive with
      // distinct payment ids for ONE payment. The capture event's checkoutRef
      // (the linked ORDER id) matches the stored processorRef, so it's the same
      // payment — only a paid event that matches NEITHER id is a real second
      // payment. (Review C-F1: every PayPal order poisoned this audit queue.)
      const isSamePayment =
        a.processorRef === order.processorRef ||
        (a.checkoutRef != null && a.checkoutRef === order.processorRef);
      if (a.status === 'paid' && order.processorRef && !isSamePayment) {
        await writeAuditLog(ctx, {
          actorType: 'webhook',
          actorId: order.userId,
          action: 'billing.overpayment_seen',
          targetType: 'billing_order',
          targetId: order._id,
          payload: {
            processor: a.processor,
            amountCents: order.amountCents,
            reportedMinor: a.amountMinor ?? null,
          },
        });
      }
      // A Stars refund names the exact payment it returns. The bot refunds a
      // second payment on a paid order right away; that refund is not this
      // order's (the payment that paid it stands), so it changes nothing.
      const otherStarsPayment = a.processor === 'telegram_stars' && !isSamePayment;
      if (a.status === 'failed' && !otherStarsPayment) {
        await writeAuditLog(ctx, {
          actorType: 'webhook',
          actorId: order.userId,
          action: 'billing.refund_seen',
          targetType: 'billing_order',
          targetId: order._id,
          payload: {
            processor: a.processor,
            amountCents: order.amountCents,
            reportedMinor: a.amountMinor ?? null,
          },
        });
        // Refund unwind (the membership itself is deliberately NOT auto-revoked
        // — a refund may be partial/mistaken; billing.refund_seen is the
        // operator's action queue):
        // 1. The order's donation leaves the shared free-bandwidth pool (it was
        //    funded by money that no longer exists) — ONCE per order. Stripe
        //    emits one charge.refunded per (partial) refund, each a distinct
        //    dedupe id; without donationUnwoundAt every event re-subtracted the
        //    FULL donation, so two $1 chargebacks wiped a $100 pool contribution.
        //    (Review C-F2.) The donor's lifetime aggregates + badge unwind with
        //    it (C-F5: they previously survived a full chargeback).
        const donated = order.donationCents ?? (order.kind === 'donation' ? order.amountCents : 0);
        if (donated > 0 && order.donationUnwoundAt == null) {
          const refundNow = Date.now();
          await ctx.db.patch(order._id, { donationUnwoundAt: refundNow, updatedAt: refundNow });
          // `paidAt` identifies the pool bucket this order actually funded, so the
          // unwind takes the money back out of ITS day rather than off whatever
          // landed most recently (which would cancel unrelated later funding).
          await subtractDonation(
            ctx,
            donated,
            refundNow,
            order.paidAt,
            order.donationBucketExpiresAt,
          );
          // Re-cap the fleet NOW (symmetric with fundDonation): without this the
          // refunded bonus bandwidth lingered until the next hourly reconcile.
          await ctx.scheduler.runAfter(0, internal.donations.applyFreeBonus, {});
          // Anonymous donation: no donor row to unwind aggregates on.
          const donor = order.userId ? await ctx.db.get(order.userId) : null;
          if (order.userId && donor) {
            const count = Math.max(0, (donor.donationCount ?? 0) - 1);
            await ctx.db.patch(order.userId, {
              donatedCentsTotal: Math.max(0, (donor.donatedCentsTotal ?? 0) - donated),
              donationCount: count,
              ...(count === 0 ? { firstDonatedAt: undefined } : {}),
              updatedAt: refundNow,
            });
          }
        }
        // 2. Referral rewards the refunded purchase triggered never vest (only
        //    pending/converted rows — an already-rewarded row stays, same
        //    not-auto-revoked posture as the membership). Anonymous orders have
        //    no referee to look up.
        const refs = order.userId
          ? await ctx.db
              .query('referrals')
              .withIndex('by_referee', (q) => q.eq('refereeUserId', order.userId!))
              .collect()
          : [];
        for (const r of refs) {
          if (r.status !== 'pending' && r.status !== 'converted') continue;
          await ctx.db.patch(r._id, {
            status: 'void',
            voidReason: 'refund',
            updatedAt: Date.now(),
          });
          await writeAuditLog(ctx, {
            actorType: 'system',
            action: 'referral.void',
            targetType: 'referral',
            targetId: r._id,
            payload: { reason: 'refund', referrerUserId: r.referrerUserId },
          });
        }
      }
      return { applied: false, granted: false };
    }

    // The granting transition's cross-checks were unavailable (see
    // ParsedEvent.detailUnavailable). This DOES still grant — the checkoutRef
    // binding holds — but the amount + PaidPartial guards are off, so make the
    // misconfiguration loud. Deduped by the webhook claim id like the
    // underpayment audit below.
    if (a.detailUnavailable) {
      await writeAuditLog(ctx, {
        actorType: 'webhook',
        actorId: order.userId,
        action: 'billing.settle_detail_unavailable',
        targetType: 'billing_order',
        targetId: order._id,
        payload: { processor: a.processor },
      });
    }

    const now = Date.now();
    // Money arrived: a paid-class event, or a short payment the rail held back.
    if (a.status === 'paid' || a.underpaid === true) {
      // Defense-in-depth grant refusals (never advance the order, loudly
      // audited): a paid event whose checkout id doesn't match the invoice/
      // session/order FCP itself minted, or whose reported amount/currency
      // undershoots the order, is a processor-side anomaly — e.g. a 1-cent
      // invoice forged with a victim's orderRef on a shared store/account.
      const refuse = async (
        reason: 'ref_mismatch' | 'amount_mismatch' | 'dismissed',
      ): Promise<{ applied: boolean; granted: boolean }> => {
        console.warn(
          `[billing] grant refused (${reason}) for order ${order.opaqueRef.slice(0, 8)}…`,
        );
        await writeAuditLog(ctx, {
          actorType: 'webhook',
          actorId: order.userId,
          action: 'billing.grant_refused',
          targetType: 'billing_order',
          targetId: order._id,
          payload: {
            processor: a.processor,
            reason,
            expectedMinor: order.amountCents,
            reportedMinor: a.amountMinor ?? null,
            reportedCurrency: a.amountCurrency ?? null,
            refMatched:
              reason !== 'ref_mismatch' &&
              !(a.checkoutRef && order.processorRef && a.checkoutRef !== order.processorRef),
          },
        });
        return { applied: false, granted: false };
      };
      // An operator dismissed this order (refunded or settled it off-platform):
      // that decision is final, so a later payment event (a top-up, a status
      // flipped by hand on the processor) is refused and audited, never granted.
      if (order.dismissedAt != null) return refuse('dismissed');
      if (a.processor === 'paypal' || order.processor === 'paypal') {
        if (a.processor !== order.processor || !a.checkoutRef || !order.processorRef) {
          return refuse('ref_mismatch');
        }
        if (a.amountMinor == null || !a.amountCurrency || a.amountMinor < order.amountCents) {
          return refuse('amount_mismatch');
        }
      }
      if (a.checkoutRef && order.processorRef && a.checkoutRef !== order.processorRef) {
        return refuse('ref_mismatch');
      }
      if (a.amountMinor != null) {
        const currencyMismatch =
          a.amountCurrency != null &&
          a.amountCurrency.toUpperCase() !== order.currency.toUpperCase();
        // 1-cent tolerance absorbs decimal-string round-tripping; anything more
        // is a real underpayment/mismatch.
        if (currencyMismatch || a.amountMinor < order.amountCents - 1) {
          return refuse('amount_mismatch');
        }
      }
    }

    // Underpayment: the payer delivered less than the invoice, most often
    // because an exchange took its withdrawal fee out of the amount sent. A
    // paid-class event still grants when the measured shortfall is within the
    // admin-editable tolerance; anything further short, unmeasurable, or never
    // final on the rail (BTCPay expired holding a partial payment) holds the
    // order as `underpaid` for the operator to grant or dismiss from Admin →
    // Billing. The stale-order sweep never expires it, so the payer's money
    // can't silently time out. Audited once per event (the webhook claim id
    // dedupes a redelivery).
    if (a.underpaid) {
      const { underpaymentTolerancePct } = await resolveBillingConfig(ctx.db);
      const paidRatio = a.paidRatio ?? null;
      const accepted =
        a.status === 'paid' && withinUnderpaymentTolerance(paidRatio, underpaymentTolerancePct);
      await writeAuditLog(ctx, {
        actorType: 'webhook',
        actorId: order.userId,
        action: accepted ? 'billing.underpayment_accepted' : 'billing.underpayment_seen',
        targetType: 'billing_order',
        targetId: order._id,
        payload: {
          processor: a.processor,
          expectedMinor: order.amountCents,
          reportedMinor: a.amountMinor ?? null,
          paidPermille: paidRatio != null ? Math.round(paidRatio * 1000) : null,
          tolerancePct: underpaymentTolerancePct,
        },
      });
      if (!accepted) {
        // processorRef deliberately untouched: it stays the id FCP minted at
        // checkout, so a top-up payment on the same invoice still passes the
        // ref cross-check and grants.
        // On an order already held, keep the BEST measured ratio: a further
        // short payment (or a later read of BTCPay's cumulative total) only
        // adds to what arrived, and the admin view + a later grant's donation
        // credit read it. Money leaving goes through `failed`, never here.
        const holds = STATUS_RANK.underpaid > STATUS_RANK[order.status];
        const bestRatio = paidRatio != null ? Math.max(paidRatio, order.paidRatio ?? 0) : null;
        if (holds || order.status === 'underpaid') {
          await ctx.db.patch(order._id, {
            ...(holds ? { status: 'underpaid' as const } : {}),
            // Money arrived short: the order is out of the payable states, so
            // the payer-specific deposit details go (see lib/directPayment.ts).
            directPayment: undefined,
            ...(bestRatio != null ? { paidRatio: bestRatio } : {}),
            updatedAt: now,
          });
        }
        return { applied: true, granted: false };
      }
    }

    if (a.status === 'paid') {
      return grantOrder(ctx, order, {
        processor: a.processor,
        processorRef: a.processorRef,
        giftCodes: a.giftCodes,
        paidRatio: a.underpaid ? (a.paidRatio ?? null) : null,
        actorType: 'webhook',
        actorId: order.userId,
      });
    }

    // Non-paid update (pending/confirming/failed/expired): advance the order
    // FORWARD only, so an out-of-order or re-delivered webhook can't walk it
    // backward (e.g. a late 'pending' after 'confirming'). (Review #8.)
    if (STATUS_RANK[a.status] > STATUS_RANK[order.status]) {
      await ctx.db.patch(order._id, {
        status: a.status,
        ...(directPaymentLive(a.status) ? {} : { directPayment: undefined }),
        updatedAt: now,
      });
    }
    return { applied: true, granted: false };
  },
});

/**
 * Peek at an order's gift-mint plan (by opaque ref) so the ingest action knows
 * whether — and how many — shareable codes to pre-generate before the grant.
 */
export const orderMintPlan = internalQuery({
  args: { orderRef: v.string() },
  handler: async (
    ctx,
    { orderRef },
  ): Promise<{
    kind: 'self' | 'gift' | 'donation';
    quantity: number;
    alreadyPaid: boolean;
  } | null> => {
    const order = await ctx.db
      .query('billingOrders')
      .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', orderRef))
      .unique();
    if (!order) return null;
    return {
      kind: order.kind ?? 'self',
      quantity: order.quantity ?? 1,
      alreadyPaid: order.status === 'paid',
    };
  },
});

// --- admin: resolve an order by hand (Admin → Billing) ------------------------

// Orders an operator may grant from the order itself: a held underpaid payment,
// or one whose payment the processor shows but FCP never saw settle (a webhook
// that never arrived, or a short payment that stalled before the tolerance
// existed). Never `paid` (double grant) or `failed` (refunded / dismissed).
const ADMIN_GRANTABLE: ReadonlySet<OrderStatus> = new Set([
  'underpaid',
  'confirming',
  'pending',
  'expired',
]);

async function loadOrderForAdmin(
  ctx: MutationCtx,
  orderId: string,
  allowed: ReadonlySet<OrderStatus>,
): Promise<Doc<'billingOrders'>> {
  const id = ctx.db.normalizeId('billingOrders', orderId);
  const order = id ? await ctx.db.get(id) : null;
  if (!order) throw new ConvexError({ code: 'not_found', message: 'Order not found' });
  if (!allowed.has(order.status)) {
    throw new ConvexError({
      code: 'conflict',
      message: `This order is ${order.status} and can't be changed here`,
    });
  }
  return order;
}

/** What the grant action must pre-generate (gift codes) before granting. */
export const adminGrantPlan = internalQuery({
  args: { orderId: v.string() },
  handler: async (
    ctx,
    { orderId },
  ): Promise<{ kind: 'self' | 'gift' | 'donation'; quantity: number } | null> => {
    const id = ctx.db.normalizeId('billingOrders', orderId);
    const order = id ? await ctx.db.get(id) : null;
    if (!order || !ADMIN_GRANTABLE.has(order.status)) return null;
    return { kind: order.kind ?? 'self', quantity: order.quantity ?? 1 };
  },
});

/**
 * Operator grants an order from Admin → Billing: the same grant a full payment
 * gets (membership, gift codes, or donation), audited as an admin action. The
 * status is re-checked inside this serializable mutation, so a double click or
 * a racing webhook can't grant twice.
 */
export const grantOrderByAdmin = internalMutation({
  args: {
    orderId: v.string(),
    giftCodes: v.optional(
      v.array(v.object({ plaintext: v.string(), hash: v.string(), prefix: v.string() })),
    ),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a): Promise<{ granted: boolean; kind: 'self' | 'gift' | 'donation' }> => {
    const order = await loadOrderForAdmin(ctx, a.orderId, ADMIN_GRANTABLE);
    const res = await grantOrder(ctx, order, {
      processor: order.processor,
      processorRef: order.processorRef ?? '',
      giftCodes: a.giftCodes,
      paidRatio: order.paidRatio ?? null,
      actorType: 'admin',
      actorId: a.actorAdminId,
    });
    if (!res.granted) {
      // The buyer or the order's tier no longer exists: nothing to deliver to.
      throw new ConvexError({
        code: 'conflict',
        message: 'This order can no longer be granted (its account or tier is gone)',
      });
    }
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId,
      action: 'admin.billing.order_granted',
      targetType: 'billing_order',
      targetId: order._id,
      payload: {
        processor: order.processor,
        fromStatus: order.status,
        kind: order.kind ?? 'self',
        amountCents: order.amountCents,
        paidPermille: order.paidRatio != null ? Math.round(order.paidRatio * 1000) : null,
      },
    });
    return { granted: true, kind: order.kind ?? 'self' };
  },
});

/**
 * Action wrapper: gift orders need their codes minted with the CSPRNG first.
 * The codes go ONLY to the buyer: grantOrder stores them in the order's
 * one-time reveal, which the buyer's /account opens on their next visit
 * (pendingGiftReveal), or which a Telegram buyer pulls with the bot's payment
 * check (botOrderStatus). The operator never sees them.
 */
export const adminGrantOrder = internalAction({
  args: { orderId: v.string(), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, a): Promise<{ granted: boolean; kind: 'self' | 'gift' | 'donation' }> => {
    const plan = await ctx.runQuery(internal.billing.adminGrantPlan, { orderId: a.orderId });
    const giftCodes = plan?.kind === 'gift' ? await mintGiftCodes(plan.quantity) : undefined;
    return ctx.runMutation(internal.billing.grantOrderByAdmin, {
      orderId: a.orderId,
      giftCodes,
      actorAdminId: a.actorAdminId,
    });
  },
});

/**
 * Operator dismisses a held underpaid order (refunded off-platform, or not
 * worth granting): it leaves the queue as `failed` and grants nothing.
 */
export const dismissUnderpaidOrder = internalMutation({
  args: { orderId: v.string(), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, a): Promise<{ ok: true }> => {
    const order = await loadOrderForAdmin(ctx, a.orderId, new Set<OrderStatus>(['underpaid']));
    const now = Date.now();
    await ctx.db.patch(order._id, {
      status: 'failed',
      dismissedAt: now,
      directPayment: undefined,
      updatedAt: now,
    });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId,
      action: 'admin.billing.underpaid_dismissed',
      targetType: 'billing_order',
      targetId: order._id,
      payload: {
        processor: order.processor,
        amountCents: order.amountCents,
        paidPermille: order.paidRatio != null ? Math.round(order.paidRatio * 1000) : null,
      },
    });
    return { ok: true };
  },
});

/**
 * Ingest a processor webhook: verify authenticity, dedupe (per payment×status
 * transition), then apply. Throws billing.not_configured (→503) when the rail's
 * secret is unset, or a generic Error (→400) on a verify failure. The persisted
 * webhookEvents payload is the adapter's REDACTED summary (no payer PII).
 */
export const ingestEvent = internalAction({
  args: {
    processor: processorValidator,
    rawBody: v.string(),
    signature: v.optional(v.string()),
    // PayPal verifies over a set of `paypal-*` request headers, not a single
    // signature; the webhook route collects them here. Unused by np/stripe.
    headers: v.optional(v.record(v.string(), v.string())),
  },
  handler: async (ctx, a): Promise<{ ok: true; duplicate?: boolean; applied: boolean }> => {
    const secrets = await ctx.runQuery(internal.billing.resolveSecrets, {});
    const verified = await verifyForProcessor(
      ctx,
      a.processor,
      a.rawBody,
      a.signature ?? null,
      a.headers ?? {},
      secrets,
    );
    if (!verified.ok) throw new Error(`webhook verify failed: ${verified.reason}`);

    // Claim the dedupe id: a `processed` replay never reapplies, but a claim
    // whose grant threw stays retryable (see webhooks.claimEvent). applyEvent's
    // own `status === 'paid'` guard keeps a retry-after-commit exactly-once.
    const claim = await ctx.runMutation(internal.webhooks.claimEvent, {
      eventId: verified.dedupeId,
      source: `billing.${a.processor}`,
      payload: JSON.stringify(verified.summary),
    });
    if (!claim.proceed) return { ok: true, duplicate: true, applied: false };

    try {
      // Gift order being paid: pre-generate the shareable codes here (CSPRNG lives
      // in the action) so applyEvent can insert them hash-only + stash the plaintext
      // reveal atomically with the single-grant status flip.
      let giftCodes: GiftCode[] | undefined;
      if (verified.status === 'paid' && verified.orderRef) {
        const plan = await ctx.runQuery(internal.billing.orderMintPlan, {
          orderRef: verified.orderRef,
        });
        if (plan && plan.kind === 'gift' && !plan.alreadyPaid) {
          giftCodes = await mintGiftCodes(plan.quantity);
        }
      }

      const res = await ctx.runMutation(internal.billing.applyEvent, {
        processor: a.processor,
        orderRef: verified.orderRef ?? undefined,
        status: verified.status,
        processorRef: verified.processorRef,
        checkoutRef: verified.checkoutRef ?? null,
        amountMinor: verified.amountMinor ?? null,
        amountCurrency: verified.amountCurrency ?? null,
        underpaid: verified.underpaid === true,
        paidRatio: verified.paidRatio ?? null,
        detailUnavailable: verified.detailUnavailable === true,
        giftCodes,
      });
      await ctx.runMutation(internal.webhooks.markEventProcessed, {
        eventId: verified.dedupeId,
      });
      return { ok: true, applied: res.applied };
    } catch (err) {
      await ctx.runMutation(internal.webhooks.markEventFailed, { eventId: verified.dedupeId });
      throw err;
    }
  },
});

// --- admin: direct-checkout coin check (Admin → Billing "Check coins") --------

// --- direct checkout: the NOWPayments account's coin list ---------------------

/** Store a fresh account coin list (source "account"). */
export const storeAccountCoins = internalMutation({
  args: {
    coins: v.array(v.object({ ticker: v.string(), network: v.string(), memo: v.boolean() })),
  },
  handler: async (ctx, { coins }) => {
    const value: AccountCoinsCache = { fetchedAt: Date.now(), coins };
    const row = await ctx.db
      .query('appState')
      .withIndex('by_key', (q) => q.eq('key', ACCOUNT_COINS_KEY))
      .unique();
    const doc = { key: ACCOUNT_COINS_KEY, value: JSON.stringify(value), updatedAt: Date.now() };
    if (row) await ctx.db.patch(row._id, doc);
    else await ctx.db.insert('appState', doc);
  },
});

/** Whether the account list should be kept fresh, plus the API config to do it. */
export const accountCoinsContext = internalQuery({
  args: {},
  handler: async (ctx): Promise<{ wanted: boolean }> => {
    const np = (await resolveBillingConfig(ctx.db)).direct.nowpayments;
    return { wanted: np.style === 'direct' && np.source === 'account' };
  },
});

/**
 * Re-read the coins switched on in the NOWPayments dashboard (source
 * "account"). On a failed read the last good list stays: a blip at NOWPayments
 * must not switch direct checkout off. Hourly cron, after an admin config save,
 * and from "Check coins". Returns the number of coins now cached (null = kept).
 */
async function refreshAccountCoinsNow(ctx: ActionCtx): Promise<number | null> {
  const secrets = await ctx.runQuery(internal.billing.resolveSecrets, {});
  if (!secrets.nowpayments.apiKey) return null;
  const coins = await nowpayments.accountCoins({
    apiUrl: secrets.nowpayments.apiUrl,
    apiKey: secrets.nowpayments.apiKey,
  });
  if (!coins) {
    console.warn('[billing] nowpayments account coin list unreadable; keeping the last one');
    return null;
  }
  await ctx.runMutation(internal.billing.storeAccountCoins, { coins });
  return coins.length;
}

export const refreshAccountCoins = internalAction({
  args: {},
  handler: async (ctx): Promise<null> =>
    runWithCronOutcome(ctx, 'billing-nowpayments-coins', async () => {
      const { wanted } = await ctx.runQuery(internal.billing.accountCoinsContext, {});
      if (wanted) await refreshAccountCoinsNow(ctx);
      return null;
    }),
});

/** The member coin picker's list (public, `GET /api/v1/billing/coins`). */
export const publicDirectCoins = internalQuery({
  args: {},
  handler: async (
    ctx,
  ): Promise<{
    coins: Array<{
      ticker: string;
      label: string;
      network: string;
      memo: boolean;
      pinned: boolean;
    }>;
  }> => {
    const config = await resolveBillingConfig(ctx.db);
    if (!config.enabled || !config.rails.nowpayments) return { coins: [] };
    const coins = await resolveDirectCoins(ctx.db, config);
    return {
      coins: coins.map(({ ticker, label, network, memo, pinned }) => ({
        ticker,
        label,
        network,
        memo,
        pinned,
      })),
    };
  },
});

/**
 * Admin -> Billing "Check coins", read-only at NOWPayments (it only refreshes
 * our cache). Source "account": re-reads the account list, then checks the
 * first coins members see (pinned first). Source "list": checks the whole
 * hand-written list. Per coin: switched on in the dashboard, network, memo use,
 * and an indicative minimum next to the cheapest crypto term.
 */
const CHECK_MAX_COINS = 16;
export const checkDirectCoins = internalAction({
  args: {},
  handler: async (
    ctx,
  ): Promise<{
    ok: boolean;
    error: string | null;
    cheapestCryptoCents: number | null;
    /** Source "account": coins now offered (null = the account list was unreadable). */
    accountCoinCount: number | null;
    /** Source "account": network codes with no member-facing name (shown as the bare code). */
    unnamedNetworks: string[];
    coins: nowpayments.CoinCheck[];
  }> => {
    const [secrets, { config }] = await Promise.all([
      ctx.runQuery(internal.billing.resolveSecrets, {}),
      ctx.runQuery(internal.billing.checkoutContext, {}),
    ]);
    // By PRICE, not by term: prices needn't rise with the term, and the coin
    // minimum bites on the cheapest thing a crypto payer can buy.
    const eligible = config.durations.filter((d) => d.months >= config.cryptoMinMonths);
    const cheapestCryptoCents = eligible.length
      ? Math.min(...eligible.map((d) => d.amountCents))
      : null;
    const empty = { accountCoinCount: null, unnamedNetworks: [], coins: [] };
    if (!secrets.nowpayments.apiKey) {
      return { ok: false, error: 'API key not configured', cheapestCryptoCents, ...empty };
    }
    const np = config.direct.nowpayments;
    let accountCoinCount: number | null = null;
    let unnamedNetworks: string[] = [];
    let tickers = np.coins.map((c) => c.ticker);
    if (np.source === 'account') {
      accountCoinCount = await refreshAccountCoinsNow(ctx);
      const { directCoins } = await ctx.runQuery(internal.billing.checkoutContext, {});
      const cache = await ctx.runQuery(internal.billing.accountCoinsCache, {});
      unnamedNetworks = [
        ...new Set((cache?.coins ?? []).map((c) => c.network).filter((n) => !knownNetwork(n))),
      ];
      // directCoins is empty while the style is hosted; check the cache order then.
      tickers = (
        directCoins.length
          ? directCoins.map((c) => c.ticker)
          : (cache?.coins ?? []).map((c) => c.ticker)
      ).slice(0, CHECK_MAX_COINS);
      if (accountCoinCount === null) {
        return {
          ok: false,
          error: 'NOWPayments did not return a readable coin list',
          cheapestCryptoCents,
          ...empty,
        };
      }
    }
    const coins = await nowpayments.checkCoins(
      { apiUrl: secrets.nowpayments.apiUrl, apiKey: secrets.nowpayments.apiKey },
      tickers,
      config.currency,
    );
    return { ok: true, error: null, cheapestCryptoCents, accountCoinCount, unnamedNetworks, coins };
  },
});

export const accountCoinsCache = internalQuery({
  args: {},
  handler: (ctx): Promise<AccountCoinsCache | null> => readAccountCoins(ctx.db),
});

// --- admin: live credential probe (Admin → Billing "test connection") ---------

/**
 * Ping a processor's API with the STORED credentials (never round-tripped to
 * the client). Beyond the config-presence readiness check: proves the key
 * actually authenticates. The result is an ok/error pair — the error text is
 * status-only (never secret material).
 */
export const testProcessorConnection = internalAction({
  args: { processor: processorValidator },
  handler: async (ctx, { processor }): Promise<{ ok: boolean; error: string | null }> => {
    const secrets = await ctx.runQuery(internal.billing.resolveSecrets, {});
    const fail = (error: string) => ({ ok: false, error });
    let res: { ok: true } | { ok: false; error: string };
    switch (processor) {
      case 'nowpayments': {
        if (!secrets.nowpayments.apiKey) return fail('API key not configured');
        res = await nowpayments.testConnection({
          apiUrl: secrets.nowpayments.apiUrl,
          apiKey: secrets.nowpayments.apiKey,
        });
        break;
      }
      case 'btcpay': {
        const bp = secrets.btcpay;
        if (!bp.apiUrl || !bp.storeId || !bp.apiKey) return fail('Not fully configured');
        res = await btcpay.testConnection({
          apiUrl: bp.apiUrl,
          storeId: bp.storeId,
          apiKey: bp.apiKey,
        });
        break;
      }
      case 'stripe': {
        if (!secrets.stripe.apiKey) return fail('API key not configured');
        res = await stripe.testConnection({ apiKey: secrets.stripe.apiKey });
        break;
      }
      case 'paypal': {
        const pp = secrets.paypal;
        if (!pp.clientId || !pp.secret) return fail('Not fully configured');
        res = await paypal.testConnection(pp);
        break;
      }
    }
    return res.ok ? { ok: true, error: null } : { ok: false, error: res.error };
  },
});

// --- member order polling ----------------------------------------------------

/**
 * Order status for the return-page poll, SCOPED to the requesting member: a
 * member can only see their own order (cross-user ref → null → 404). Returns the
 * member's current membership expiry so the SPA can confirm the extension landed.
 */
/** The direct-checkout details as the order poll returns them (see OrderPayment contract). */
interface DirectPaymentView {
  processor: ProcessorId;
  methods: DirectPayment['methods'];
  expiresAt: string | null;
  hostedUrl: string;
}

/**
 * The payment details for the return page, only while the order can still be
 * paid (pending / confirming). The terminal transitions wipe the row's copy
 * too; this check also covers an order whose wipe raced the poll.
 */
function directPaymentView(order: Doc<'billingOrders'>): DirectPaymentView | null {
  const p = order.directPayment;
  // Stars orders never carry deposit details (Telegram shows its own invoice).
  if (!p || !directPaymentLive(order.status) || order.processor === 'telegram_stars') return null;
  return {
    processor: order.processor,
    methods: p.methods,
    expiresAt: p.expiresAt !== undefined ? new Date(p.expiresAt).toISOString() : null,
    hostedUrl: p.hostedUrl,
  };
}

export const getOrderStatus = internalQuery({
  args: { opaqueRef: v.string(), userId: v.id('users') },
  handler: async (
    ctx,
    { opaqueRef, userId },
  ): Promise<{
    status: OrderStatus;
    membershipExpiresAt: string | null;
    kind: 'self' | 'gift' | 'donation';
    // The freshly-minted gift codes, revealed ONCE on the return poll: present
    // only for a paid, not-yet-acknowledged gift order (cleared on ack/sweep).
    giftCodes: string[];
    payment: DirectPaymentView | null;
  } | null> => {
    const order = await ctx.db
      .query('billingOrders')
      .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', opaqueRef))
      .unique();
    if (!order || order.userId !== userId) return null;
    const user = await ctx.db.get(userId);
    const membershipExpiresAt = user?.membershipExpiresAt
      ? new Date(user.membershipExpiresAt).toISOString()
      : null;
    return {
      status: order.status,
      membershipExpiresAt,
      kind: order.kind ?? 'self',
      giftCodes: order.kind === 'gift' && !order.giftRevealAck ? (order.giftReveal ?? []) : [],
      payment: directPaymentView(order),
    };
  },
});

/**
 * Status poll for an ANONYMOUS donation order: no session, the unguessable
 * 128-bit opaque ref is the capability. Deliberately narrow — it answers ONLY
 * for orders that are both anonymous (no userId) and kind 'donation', and
 * returns the same shape as getOrderStatus with the member-only fields blanked,
 * so the SPA's one order-status contract covers both. A user-bound ref through
 * this path is a 404 (sign in to see it), never a data leak.
 */
export const getAnonOrderStatus = internalQuery({
  args: { opaqueRef: v.string() },
  handler: async (
    ctx,
    { opaqueRef },
  ): Promise<{
    status: OrderStatus;
    membershipExpiresAt: string | null;
    kind: 'self' | 'gift' | 'donation';
    giftCodes: string[];
    payment: DirectPaymentView | null;
  } | null> => {
    const order = await ctx.db
      .query('billingOrders')
      .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', opaqueRef))
      .unique();
    if (!order || order.userId !== undefined || order.kind !== 'donation') return null;
    return {
      status: order.status,
      membershipExpiresAt: null,
      kind: 'donation',
      giftCodes: [],
      payment: directPaymentView(order),
    };
  },
});

/**
 * Buyer acknowledges they've saved the revealed gift codes → clear the transient
 * plaintext buffer (so the reveal is truly once). Member-scoped. The gift-reveal
 * sweep is the backstop for buyers who never return.
 */
/**
 * The member's oldest paid gift order whose codes they haven't seen yet (an
 * unacknowledged one-time reveal), so /account can open the reveal on their next
 * visit instead of only on the checkout return link. That matters whenever the
 * codes are minted after the buyer left: a slow crypto confirmation, a short
 * payment topped up later, or an operator's grant. Null when none.
 */
export const pendingGiftReveal = internalQuery({
  args: { userId: v.id('users') },
  handler: (ctx, { userId }): Promise<string | null> => pendingGiftRevealOf(ctx.db, userId),
});

/** `pendingGiftReveal` for a caller already in a query (the account view). */
export async function pendingGiftRevealOf(
  db: DatabaseReader,
  userId: Id<'users'>,
): Promise<string | null> {
  // Straight to this member's pending reveals (oldest first), however many
  // other orders they have: a late-paid gift can be older than any number of
  // later checkouts. Only paid gift orders ever carry the flag.
  const pending = await db
    .query('billingOrders')
    .withIndex('by_user_gift_reveal_pending', (q) =>
      q.eq('userId', userId).eq('giftRevealPending', true),
    )
    .take(10);
  const next = pending.find(
    (o) => o.kind === 'gift' && o.status === 'paid' && (o.giftReveal?.length ?? 0) > 0,
  );
  return next?.opaqueRef ?? null;
}

export const ackGiftReveal = internalMutation({
  args: { opaqueRef: v.string(), userId: v.id('users') },
  handler: async (ctx, { opaqueRef, userId }): Promise<{ ok: boolean }> => {
    const order = await ctx.db
      .query('billingOrders')
      .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', opaqueRef))
      .unique();
    if (!order || order.userId !== userId) return { ok: false };
    await ctx.db.patch(order._id, {
      giftReveal: undefined,
      giftRevealAck: true,
      giftRevealPending: undefined, // leaves the by_gift_reveal_pending_paid index (Review #5)
      updatedAt: Date.now(),
    });
    return { ok: true };
  },
});

// --- Telegram gift shop ------------------------------------------------------
//
// The bot (convex/telegramBot.ts) sells gift codes and nothing else. Its orders
// are userless (`channel: 'telegram'`); their codes are bound to nobody; the
// bot keeps no chat id. The 128-bit opaque ref is the buyer's only handle: the
// bot puts it in its buttons and in the processor's return link, and reads the
// order back through the two functions below, which answer ONLY for
// telegram-channel orders.

/**
 * A pending Telegram Stars gift order. The caller (the bot action) mints the
 * opaque ref (the CSPRNG lives in actions) and prices it from `telegram.*`;
 * the duration, quantity and tier are checked against the billing catalog
 * here, the same way a hosted checkout checks them.
 */
export const createStarsOrder = internalMutation({
  args: {
    opaqueRef: v.string(),
    months: v.number(),
    quantity: v.number(),
    // The Stars price of ONE code for this duration (telegram.stars.prices).
    starsPerCode: v.number(),
  },
  handler: async (ctx, a): Promise<{ orderRef: string; totalStars: number }> => {
    const config = await resolveBillingConfig(ctx.db);
    if (!config.enabled) {
      throw new ConvexError({
        code: 'billing.disabled',
        message: 'Membership purchases are not available',
      });
    }
    if (!findDuration(config, a.months)) {
      throw new ConvexError({
        code: 'billing.invalid_duration',
        message: 'Unknown membership duration',
      });
    }
    const quantity = Math.floor(a.quantity);
    if (!Number.isFinite(quantity) || quantity < 1 || quantity > MAX_GIFT_QUANTITY) {
      throw new ConvexError({
        code: 'billing.invalid_quantity',
        message: `Number of codes must be between 1 and ${MAX_GIFT_QUANTITY}`,
      });
    }
    if (!Number.isInteger(a.starsPerCode) || a.starsPerCode < 1) {
      throw new ConvexError({ code: 'billing.invalid_amount', message: 'No Stars price' });
    }
    const tier = await ctx.db
      .query('tiers')
      .withIndex('by_slug', (q) => q.eq('slug', config.tierSlug))
      .unique();
    if (!tier) {
      throw new ConvexError({
        code: 'billing.tier_missing',
        message: 'Membership tier is not configured',
      });
    }
    const totalStars = a.starsPerCode * quantity;
    const now = Date.now();
    const orderId = await ctx.db.insert('billingOrders', {
      processor: 'telegram_stars',
      channel: 'telegram',
      opaqueRef: a.opaqueRef,
      tierId: tier._id,
      durationDays: monthsToDays(a.months),
      // Minor units of XTR are whole Stars.
      amountCents: totalStars,
      donationCents: 0,
      currency: 'XTR',
      status: 'pending',
      kind: 'gift',
      quantity,
      updatedAt: now,
    });
    await writeAuditLog(ctx, {
      actorType: 'anonymous',
      action: 'billing.checkout.created',
      targetType: 'billing_order',
      targetId: orderId,
      payload: {
        processor: 'telegram_stars',
        months: a.months,
        kind: 'gift',
        quantity,
        donationCents: 0,
        direct: false,
        channel: 'telegram',
      },
    });
    return { orderRef: a.opaqueRef, totalStars };
  },
});

/**
 * Telegram's pre-checkout question for a Stars invoice: may this payment go
 * ahead? Yes only for a pending Stars order of exactly this amount in XTR.
 * (Telegram asks once per payment attempt and waits at most 10 seconds.)
 */
export const starsPreCheckout = internalQuery({
  args: { orderRef: v.string(), totalAmount: v.number(), currency: v.string() },
  handler: async (
    ctx,
    a,
  ): Promise<{ ok: true } | { ok: false; reason: 'not_found' | 'not_pending' | 'amount' }> => {
    const order = await ctx.db
      .query('billingOrders')
      .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', a.orderRef))
      .unique();
    if (!order || order.processor !== 'telegram_stars' || order.channel !== 'telegram') {
      return { ok: false, reason: 'not_found' };
    }
    if (order.status !== 'pending' || order.dismissedAt != null) {
      return { ok: false, reason: 'not_pending' };
    }
    if (a.currency !== 'XTR' || a.totalAmount !== order.amountCents) {
      return { ok: false, reason: 'amount' };
    }
    return { ok: true };
  },
});

/**
 * Settle (or record the refund of) a Telegram Stars payment through the same
 * exactly-once path as a processor webhook: claim the dedupe id, pre-mint the
 * gift codes, applyEvent, mark processed. The claim payload is a short summary,
 * never the Telegram update (it names the chat). Telegram resends an update
 * it saw no 200 for, so a replay must be a no-op: the claim and applyEvent's
 * paid guard both see to that.
 */
export const ingestStarsPayment = internalAction({
  args: {
    orderRef: v.string(),
    // telegram_payment_charge_id: Telegram's id for this payment.
    chargeId: v.string(),
    totalAmount: v.number(),
    currency: v.string(),
    event: v.union(v.literal('paid'), v.literal('refunded')),
  },
  handler: async (ctx, a): Promise<{ duplicate: boolean; applied: boolean; granted: boolean }> => {
    const eventId = `telegram_stars:${a.chargeId}:${a.event}`;
    const claim = await ctx.runMutation(internal.webhooks.claimEvent, {
      eventId,
      source: 'billing.telegram_stars',
      payload: JSON.stringify({ event: a.event, amount: a.totalAmount, currency: a.currency }),
    });
    if (!claim.proceed) return { duplicate: true, applied: false, granted: false };
    try {
      let giftCodes: GiftCode[] | undefined;
      if (a.event === 'paid') {
        const plan = await ctx.runQuery(internal.billing.orderMintPlan, { orderRef: a.orderRef });
        if (plan && plan.kind === 'gift' && !plan.alreadyPaid) {
          giftCodes = await mintGiftCodes(plan.quantity);
        }
      }
      const res = await ctx.runMutation(internal.billing.applyEvent, {
        processor: 'telegram_stars',
        orderRef: a.orderRef,
        status: a.event === 'paid' ? 'paid' : 'failed',
        processorRef: a.chargeId,
        checkoutRef: null,
        amountMinor: a.totalAmount,
        amountCurrency: a.currency,
        giftCodes,
      });
      await ctx.runMutation(internal.webhooks.markEventProcessed, { eventId });
      return { duplicate: false, ...res };
    } catch (err) {
      await ctx.runMutation(internal.webhooks.markEventFailed, { eventId });
      throw err;
    }
  },
});

export type BotOrderStatus = {
  status: OrderStatus;
  processor: OrderProcessorId;
  months: number;
  quantity: number;
  /** The one-time reveal: present while paid and not yet acknowledged. */
  giftCodes: string[];
  /** Deposit details while a direct crypto order can still be paid. */
  payment: DirectPaymentView | null;
};

/** A Telegram gift-shop order by its ref (null for any other order). */
export const botOrderStatus = internalQuery({
  args: { orderRef: v.string() },
  handler: async (ctx, { orderRef }): Promise<BotOrderStatus | null> => {
    const order = await ctx.db
      .query('billingOrders')
      .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', orderRef))
      .unique();
    if (!order || order.channel !== 'telegram' || order.kind !== 'gift') return null;
    return {
      status: order.status,
      processor: order.processor,
      months: Math.max(1, Math.round(order.durationDays / AVG_DAYS_PER_MONTH)),
      quantity: order.quantity ?? 1,
      giftCodes: order.status === 'paid' && !order.giftRevealAck ? (order.giftReveal ?? []) : [],
      payment: directPaymentView(order),
    };
  },
});

/** The Telegram buyer saved the codes: clear the plaintext (as ackGiftReveal does). */
export const ackBotGiftReveal = internalMutation({
  args: { orderRef: v.string() },
  handler: async (ctx, { orderRef }): Promise<{ ok: boolean }> => {
    const order = await ctx.db
      .query('billingOrders')
      .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', orderRef))
      .unique();
    if (!order || order.channel !== 'telegram' || order.status !== 'paid') return { ok: false };
    await ctx.db.patch(order._id, {
      giftReveal: undefined,
      giftRevealAck: true,
      giftRevealPending: undefined,
      updatedAt: Date.now(),
    });
    return { ok: true };
  },
});
