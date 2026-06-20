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
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { ConvexError, v } from 'convex/values';
import { randomHex, sha256Hex } from './lib/crypto';
import { generateMembershipCode, membershipCodePrefix } from './lib/membershipCode';
import { applyMembership } from './lifecycle';
import { writeAuditLog } from './lib/audit';
import {
  findDuration,
  minMonthsForProcessor,
  resolveBillingConfig,
  resolveProcessorSecrets,
} from './lib/billingConfig';
import type { BillingConfig, ProcessorSecrets } from './lib/billingConfig';
import * as nowpayments from './lib/processors/nowpayments';
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

const orderKindValidator = v.union(v.literal('self'), v.literal('gift'));

const processorValidator = v.union(
  v.literal('nowpayments'),
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
    case 'stripe': {
      if (!secrets.stripe.webhookSecret) throw notConfigured('Stripe');
      return stripe.verifyAndParse({ rawBody, signature, secret: secrets.stripe.webhookSecret });
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
    tierId: v.id('tiers'),
    durationDays: v.number(),
    amountCents: v.number(),
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
      payload: { processor: a.processor, months: a.months, kind: a.kind, quantity: a.quantity },
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
    months: v.number(),
    // 'gift' mints `quantity` shareable codes for the buyer instead of extending
    // their own membership. Absent ⇒ self-upgrade, quantity 1.
    kind: v.optional(orderKindValidator),
    quantity: v.optional(v.number()),
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
    const kind = a.kind ?? 'self';
    const quantity = kind === 'gift' ? Math.floor(a.quantity ?? 1) : 1;
    if (
      kind === 'gift' &&
      (!Number.isFinite(quantity) || quantity < 1 || quantity > MAX_GIFT_QUANTITY)
    ) {
      throw new ConvexError({
        code: 'billing.invalid_quantity',
        message: `Number of codes must be between 1 and ${MAX_GIFT_QUANTITY}`,
      });
    }
    const amountCents = duration.amountCents * quantity;

    const secrets = await ctx.runQuery(internal.billing.resolveSecrets, {});
    const base = publicBaseUrl(secrets);
    const opaqueRef = randomHex(16);
    const monthLabel = `${a.months} month${a.months === 1 ? '' : 's'}`;
    const params: CheckoutParams = {
      orderRef: opaqueRef,
      amountCents,
      currency: config.currency,
      description:
        kind === 'gift'
          ? `FreeSocks Membership gift — ${quantity} × ${monthLabel}`
          : `FreeSocks Membership — ${monthLabel}`,
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
      tierId,
      durationDays: monthsToDays(a.months),
      amountCents,
      currency: config.currency,
      months: a.months,
      kind,
      quantity,
    });
    return { redirectUrl: result.redirectUrl, orderRef: opaqueRef };
  },
});

// --- webhook ingest ----------------------------------------------------------

/**
 * Serializable order-status apply + single grant. Looks the order up by our
 * opaque ref (every rail echoes it: NOWPayments order_id, Stripe
 * client_reference_id, PayPal custom_id). Once `paid`, all further events are
 * no-ops — so two concurrent "paid" webhooks grant membership EXACTLY ONCE
 * (the loser re-reads status==='paid'). Non-paid statuses just advance the order.
 */
export const applyEvent = internalMutation({
  args: {
    processor: processorValidator,
    orderRef: v.optional(v.string()),
    status: orderStatusValidator,
    processorRef: v.string(),
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
    // Single-grant guard: once paid, ignore everything (idempotent re-delivery).
    if (order.status === 'paid') return { applied: false, granted: false };

    const now = Date.now();
    if (a.status === 'paid') {
      const tier = await ctx.db.get(order.tierId);

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
          updatedAt: now,
        });
        for (const c of codes) {
          await ctx.db.insert('redemptionCodes', {
            codeHash: c.hash,
            codePrefix: c.prefix,
            tierId: order.tierId,
            durationDays: order.durationDays,
            status: 'active',
            purchasedByUserId: order.userId,
            purchasedByOrderId: order._id,
            updatedAt: now,
          });
        }
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
        tierId: order.tierId,
        expiresAtMs,
        reason: `billing.${a.processor}`,
        triggeredBy: 'webhook',
      });
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
        },
      });
      return { applied: true, granted: true };
    }

    // Non-paid update (waiting/confirming/failed/expired): advance the order only.
    if (order.status !== a.status) {
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
  ): Promise<{ kind: 'self' | 'gift'; quantity: number; alreadyPaid: boolean } | null> => {
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

    const dedupe = await ctx.runMutation(internal.webhooks.recordEvent, {
      eventId: verified.dedupeId,
      source: `billing.${a.processor}`,
      payload: JSON.stringify(verified.summary),
    });
    if (dedupe.duplicate) return { ok: true, duplicate: true, applied: false };

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
      giftCodes,
    });
    return { ok: true, applied: res.applied };
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
    kind: 'self' | 'gift';
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
      updatedAt: Date.now(),
    });
    return { ok: true };
  },
});
