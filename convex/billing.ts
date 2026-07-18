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
import type { MutationCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { ConvexError, v } from 'convex/values';
import { randomHex, sha256Hex } from './lib/crypto';
import { generateMembershipCode, membershipCodePrefix } from './lib/membershipCode';
import { applyMembership } from './lifecycle';
import { writeAuditLog } from './lib/audit';
import { recordDonation } from './lib/donationBonus';
import {
  findDuration,
  minMonthsForProcessor,
  resolveBillingConfig,
  resolveProcessorSecrets,
} from './lib/billingConfig';
import type { BillingConfig, ProcessorSecrets } from './lib/billingConfig';
import * as nowpayments from './lib/processors/nowpayments';
import * as btcpay from './lib/processors/btcpay';
import * as stripe from './lib/processors/stripe';
import * as paypal from './lib/processors/paypal';
import type {
  CheckoutParams,
  CheckoutResult,
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

const processorValidator = v.union(
  v.literal('nowpayments'),
  v.literal('btcpay'),
  v.literal('stripe'),
  v.literal('paypal'),
);
const orderStatusValidator = v.union(
  v.literal('pending'),
  v.literal('confirming'),
  v.literal('paid'),
  v.literal('failed'),
  v.literal('expired'),
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

async function createCheckoutForProcessor(
  processor: ProcessorId,
  params: CheckoutParams,
  secrets: ProcessorSecrets,
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
        { apiUrl: bp.apiUrl, storeId: bp.storeId, apiKey: bp.apiKey },
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

/** Verify + parse a processor webhook. Throws billing.not_configured if its secret is unset. */
async function verifyForProcessor(
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
  handler: async (ctx): Promise<{ config: BillingConfig; tierId: Id<'tiers'> | null }> => {
    const config = await resolveBillingConfig(ctx.db);
    const tier = await ctx.db
      .query('tiers')
      .withIndex('by_slug', (q) => q.eq('slug', config.tierSlug))
      .unique();
    return { config, tierId: tier?._id ?? null };
  },
});

/**
 * Persist a pending order bound to the member's userId AFTER the hosted invoice
 * was created (so a failed create never leaves an orphan); audit the checkout.
 */
export const insertOrder = internalMutation({
  args: {
    processor: processorValidator,
    opaqueRef: v.string(),
    processorRef: v.string(),
    userId: v.id('users'),
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
  },
  handler: async (ctx, a): Promise<Id<'billingOrders'>> => {
    const now = Date.now();
    const orderId = await ctx.db.insert('billingOrders', {
      processor: a.processor,
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
      updatedAt: now,
    });
    await writeAuditLog(ctx, {
      actorType: 'member',
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
    userId: v.id('users'),
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
  },
  handler: async (ctx, a): Promise<{ redirectUrl: string; orderRef: string }> => {
    const { config, tierId } = await ctx.runQuery(internal.billing.checkoutContext, {});
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
    const donationCents = Math.max(0, Math.floor(a.donationCents ?? 0));

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

    const secrets = await ctx.runQuery(internal.billing.resolveSecrets, {});
    const base = publicBaseUrl(secrets);
    const opaqueRef = randomHex(16);
    const params: CheckoutParams = {
      orderRef: opaqueRef,
      amountCents,
      currency: config.currency,
      description,
      ipnUrl: `${base}/api/webhooks/${a.processor}`,
      successUrl: `${base}/account?order=${opaqueRef}`,
      cancelUrl: `${base}/account?order=${opaqueRef}&cancel=1`,
    };

    // Create the invoice FIRST. On failure, nothing is persisted (no orphaned
    // pending order). The processor's real error is logged server-side for the
    // operator; the member only ever sees the generic message.
    let result: CheckoutResult;
    try {
      result = await createCheckoutForProcessor(a.processor, params, secrets);
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
    });
    return { redirectUrl: result.redirectUrl, orderRef: opaqueRef };
  },
});

// --- webhook ingest ----------------------------------------------------------

// Monotonic status precedence (Review #8): webhooks can arrive out of order
// (esp. NOWPayments under retry, whose dedupe id is per-(payment,status) so a
// late distinct status is NOT a duplicate). A non-paid update only ever advances
// the order forward — a late 'pending' after 'confirming', or 'confirming' after
// a terminal 'failed'/'expired', is ignored rather than walking the lifecycle
// backward. 'paid' is terminal and guarded separately at the top of applyEvent.
const STATUS_RANK: Record<OrderStatus, number> = {
  pending: 0,
  confirming: 1,
  failed: 2,
  expired: 2,
  paid: 3,
};

/**
 * A settled order carried a donation: add it to the shared monthly pool, stamp the
 * buyer's durable donor marker (set-once — backs the account badge), and schedule
 * the free-fleet bandwidth re-cap. No-op when the order carried no donation.
 */
async function fundDonation(
  ctx: MutationCtx,
  userId: Id<'users'>,
  donationCents: number | undefined,
  now: number,
): Promise<void> {
  const cents = donationCents ?? 0;
  if (cents <= 0) return;
  await recordDonation(ctx, cents, now);
  const u = await ctx.db.get(userId);
  if (u && u.firstDonatedAt == null) {
    await ctx.db.patch(userId, { firstDonatedAt: now, updatedAt: now });
  }
  await ctx.scheduler.runAfter(0, internal.donations.applyFreeBonus, {});
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
    processor: processorValidator,
    orderRef: v.optional(v.string()),
    status: orderStatusValidator,
    processorRef: v.string(),
    // Grant cross-checks from the parsed event (see ParsedEvent in
    // lib/processors/types.ts): the checkout-minted processor id and the
    // reported paid amount, when the rail carries them.
    checkoutRef: v.optional(v.union(v.string(), v.null())),
    amountMinor: v.optional(v.union(v.number(), v.null())),
    amountCurrency: v.optional(v.union(v.string(), v.null())),
    // Settle-tolerance signal from the adapter (see ParsedEvent.underpaid): a
    // paid-class transition for an incompletely-paid invoice was downgraded to
    // confirming — audit it so the underpayment is a visible operator signal
    // instead of a silently-stalled order.
    underpaid: v.optional(v.boolean()),
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
      if (a.status === 'paid' && order.processorRef && a.processorRef !== order.processorRef) {
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
      if (a.status === 'failed') {
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
      }
      return { applied: false, granted: false };
    }

    // An underpaid settle (merchant settle-tolerance) never grants, but must
    // not be invisible: audit once per event so the operator can follow up
    // (refund / ask for a top-up). Deduped by the webhook claim id, so a
    // redelivery of the same underpaid transition doesn't re-audit.
    if (a.underpaid) {
      await writeAuditLog(ctx, {
        actorType: 'webhook',
        actorId: order.userId,
        action: 'billing.underpayment_seen',
        targetType: 'billing_order',
        targetId: order._id,
        payload: {
          processor: a.processor,
          expectedMinor: order.amountCents,
          reportedMinor: a.amountMinor ?? null,
        },
      });
    }

    const now = Date.now();
    if (a.status === 'paid') {
      // Defense-in-depth grant refusals (never advance the order, loudly
      // audited): a paid event whose checkout id doesn't match the invoice/
      // session/order FCP itself minted, or whose reported amount/currency
      // undershoots the order, is a processor-side anomaly — e.g. a 1-cent
      // invoice forged with a victim's orderRef on a shared store/account.
      const refuse = async (
        reason: 'ref_mismatch' | 'amount_mismatch',
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
            refMatched: !(
              a.checkoutRef &&
              order.processorRef &&
              a.checkoutRef !== order.processorRef
            ),
          },
        });
        return { applied: false, granted: false };
      };
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
      // Standalone donation order: record the donation + fund the free-bandwidth
      // pool + stamp the donor badge; NO tier/membership grant. (Modeled on the
      // gift branch — "paid, but don't extend the buyer's own membership".)
      if (order.kind === 'donation') {
        await ctx.db.patch(order._id, {
          status: 'paid',
          paidAt: now,
          processorRef: a.processorRef || order.processorRef,
          updatedAt: now,
        });
        await fundDonation(ctx, order.userId, order.donationCents ?? order.amountCents, now);
        await writeAuditLog(ctx, {
          actorType: 'webhook',
          actorId: order.userId,
          action: 'billing.order.paid',
          targetType: 'billing_order',
          targetId: order._id,
          payload: {
            processor: a.processor,
            amountCents: order.amountCents,
            kind: 'donation',
            donationCents: order.donationCents ?? order.amountCents,
          },
        });
        return { applied: true, granted: true };
      }

      // Membership orders (self/gift) always carry a tier.
      const tierId = order.tierId;
      if (!tierId) return { applied: false, granted: false };
      const tier = await ctx.db.get(tierId);

      // Gift order: mint `quantity` shareable codes bound to the buyer (hash-only)
      // instead of extending the buyer's own membership. The plaintext lives only
      // in the transient giftReveal buffer until the buyer acknowledges saving it.
      if (order.kind === 'gift') {
        const codes = a.giftCodes ?? [];
        await ctx.db.patch(order._id, {
          status: 'paid',
          paidAt: now,
          processorRef: a.processorRef || order.processorRef,
          giftReveal: codes.map((c) => c.plaintext),
          giftRevealPending: true, // sweep/ack clears it — see retention.clearStaleGiftReveals (Review #5)
          updatedAt: now,
        });
        for (const c of codes) {
          await ctx.db.insert('redemptionCodes', {
            codeHash: c.hash,
            codePrefix: c.prefix,
            tierId,
            durationDays: order.durationDays,
            status: 'active',
            purchasedByUserId: order.userId,
            purchasedByOrderId: order._id,
            updatedAt: now,
          });
        }
        // A donation may ride a gift purchase too.
        await fundDonation(ctx, order.userId, order.donationCents, now);
        await writeAuditLog(ctx, {
          actorType: 'webhook',
          actorId: order.userId,
          action: 'billing.order.paid',
          targetType: 'billing_order',
          targetId: order._id,
          payload: {
            processor: a.processor,
            tierSlug: tier?.slug,
            durationDays: order.durationDays,
            amountCents: order.amountCents,
            kind: 'gift',
            quantity: codes.length,
            donationCents: order.donationCents ?? 0,
          },
        });
        return { applied: true, granted: true };
      }

      const user = await ctx.db.get(order.userId);
      if (!user) return { applied: false, granted: false };
      await ctx.db.patch(order._id, {
        status: 'paid',
        paidAt: now,
        processorRef: a.processorRef || order.processorRef,
        updatedAt: now,
      });
      const expiresAtMs =
        Math.max(now, user.membershipExpiresAt ?? 0) + order.durationDays * DAY_MS;
      await applyMembership(ctx, {
        userId: order.userId,
        tierId,
        expiresAtMs,
        reason: `billing.${a.processor}`,
        triggeredBy: 'webhook',
      });
      // Apply any optional donation that rode on the membership charge.
      await fundDonation(ctx, order.userId, order.donationCents, now);
      await writeAuditLog(ctx, {
        actorType: 'webhook',
        actorId: order.userId,
        action: 'billing.order.paid',
        targetType: 'billing_order',
        targetId: order._id,
        payload: {
          processor: a.processor,
          tierSlug: tier?.slug,
          durationDays: order.durationDays,
          amountCents: order.amountCents,
          donationCents: order.donationCents ?? 0,
        },
      });
      return { applied: true, granted: true };
    }

    // Non-paid update (pending/confirming/failed/expired): advance the order
    // FORWARD only, so an out-of-order or re-delivered webhook can't walk it
    // backward (e.g. a late 'pending' after 'confirming'). (Review #8.)
    if (STATUS_RANK[a.status] > STATUS_RANK[order.status]) {
      await ctx.db.patch(order._id, { status: a.status, updatedAt: now });
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
      let giftCodes: { plaintext: string; hash: string; prefix: string }[] | undefined;
      if (verified.status === 'paid' && verified.orderRef) {
        const plan = await ctx.runQuery(internal.billing.orderMintPlan, {
          orderRef: verified.orderRef,
        });
        if (plan && plan.kind === 'gift' && !plan.alreadyPaid) {
          giftCodes = [];
          for (let i = 0; i < plan.quantity; i++) {
            const plaintext = generateMembershipCode();
            giftCodes.push({
              plaintext,
              hash: await sha256Hex(plaintext),
              prefix: membershipCodePrefix(plaintext),
            });
          }
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

// --- member order polling ----------------------------------------------------

/**
 * Order status for the return-page poll, SCOPED to the requesting member: a
 * member can only see their own order (cross-user ref → null → 404). Returns the
 * member's current membership expiry so the SPA can confirm the extension landed.
 */
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
    };
  },
});

/**
 * Buyer acknowledges they've saved the revealed gift codes → clear the transient
 * plaintext buffer (so the reveal is truly once). Member-scoped. The gift-reveal
 * sweep is the backstop for buyers who never return.
 */
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
      giftRevealPending: undefined, // leaves the by_gift_reveal_pending index (Review #5)
      updatedAt: Date.now(),
    });
    return { ok: true };
  },
});
