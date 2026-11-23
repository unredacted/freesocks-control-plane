/**
 * Generic webhook seam (P7): the single transport integration point the future
 * billing portal plugs into to drive entitlements. HMAC-verified + deduped,
 * then mapped onto the lifecycle `setMembership` seam keyed by the member's
 * support ID. CiviCRM's bespoke webhook is gone; this is intentionally
 * provider-agnostic.
 *
 * Contract (POST /api/webhooks/billing, header `x-signature: <hex hmac-sha256>`):
 *   { eventId, supportId, tierSlug, issuedAtMs, expiresAtMs? }
 * The signature is HMAC-SHA256(WEBHOOK_SIGNING_SECRET, rawBody). Unknown
 * user/tier is ACKed (200, applied:false) so the sender doesn't retry forever;
 * a replayed eventId is a no-op.
 */
import { internalAction, internalMutation } from './_generated/server';
import { internal } from './_generated/api';
import { ConvexError, v } from 'convex/values';
import { hmacSha256Hex, timingSafeEqual } from './lib/crypto';
import { writeAuditLog } from './lib/audit';
import { applyMembership } from './lifecycle';

const BILLING_EVENT_MAX_AGE_MS = 86_400_000;
const BILLING_EVENT_CLOCK_SKEW_MS = 60_000;

function isCurrentBillingEvent(issuedAtMs: unknown): issuedAtMs is number {
  const now = Date.now();
  return (
    typeof issuedAtMs === 'number' &&
    Number.isSafeInteger(issuedAtMs) &&
    issuedAtMs >= now - BILLING_EVENT_MAX_AGE_MS &&
    issuedAtMs <= now + BILLING_EVENT_CLOCK_SKEW_MS
  );
}

type IngestResult = { ok: true; duplicate?: boolean; applied: boolean; reason?: string };

export const ingest = internalAction({
  args: { rawBody: v.string(), signature: v.optional(v.string()) },
  handler: async (ctx, { rawBody, signature }): Promise<IngestResult> => {
    const secret = process.env.WEBHOOK_SIGNING_SECRET;
    // Typed throw so the HTTP route can answer a distinct 503 webhook.not_configured
    // instead of the misleading generic 400 "invalid signature or payload".
    if (!secret) {
      throw new ConvexError({
        code: 'webhook.not_configured',
        message: 'WEBHOOK_SIGNING_SECRET must be set before billing webhooks can be ingested',
      });
    }
    const expected = await hmacSha256Hex(secret, rawBody);
    if (!signature || !timingSafeEqual(expected, signature)) {
      throw new Error('invalid signature');
    }

    let payload: {
      eventId?: string;
      supportId?: string;
      accountId?: unknown;
      tierSlug?: string;
      expiresAtMs?: number | null;
      issuedAtMs?: number;
    };
    try {
      payload = JSON.parse(rawBody);
    } catch {
      throw new Error('invalid JSON body');
    }
    const { eventId, supportId, tierSlug, issuedAtMs, expiresAtMs } = payload;
    if (
      typeof eventId !== 'string' ||
      !eventId ||
      typeof tierSlug !== 'string' ||
      !tierSlug ||
      typeof supportId !== 'string' ||
      !/^FS-[A-Z0-9]{4}-[A-Z0-9]{4}$/i.test(supportId) ||
      'accountId' in payload
    ) {
      throw new Error('eventId, supportId, and tierSlug required');
    }

    const current = isCurrentBillingEvent(issuedAtMs);
    // Ahead of our clock: refuse (non-2xx, nothing claimed) so the sender
    // retries once the clocks agree, rather than dropping a paid grant.
    if (!current && typeof issuedAtMs === 'number' && issuedAtMs > Date.now()) {
      throw new Error('billing event issued in the future');
    }

    // Claim the eventId first: a `processed` replay never reapplies, but a
    // `failed` (or crashed-mid-flight `pending`) claim stays retryable so a
    // grant that threw isn't silently dropped by the sender's retry. Keep the
    // support ID out of the stored event payload.
    // The dedupe id is namespaced (`generic:`) so a generic-seam eventId can
    // never pre-claim a processor rail's id (their adapters prefix their own).
    const dedupeId = `generic:${eventId}`;
    const safePayload = JSON.stringify({
      eventId,
      tierSlug,
      expiresAtMs: expiresAtMs ?? null,
    });
    const claim = await ctx.runMutation(internal.webhooks.claimEvent, {
      eventId: dedupeId,
      source: 'billing',
      payload: safePayload,
    });
    if (!claim.proceed) return { ok: true, duplicate: true, applied: false };

    if (!current) {
      // Too old to trust as fresh: ACK so the sender stops, and leave one trace
      // (the claim makes a replay of the same event a silent duplicate) for the
      // operator to grant by hand if it was a real late delivery.
      await ctx.runMutation(internal.audit.record, {
        actorType: 'webhook',
        action: 'billing.webhook.stale_event',
        targetType: 'webhookEvent',
        payload: { issuedAtMs: typeof issuedAtMs === 'number' ? issuedAtMs : null },
      });
      await ctx.runMutation(internal.webhooks.markEventProcessed, { eventId: dedupeId });
      return { ok: true, applied: false, reason: 'stale_event' };
    }

    try {
      // Validate/coerce expiresAtMs INSIDE the claim, before any side effect:
      // a permanently-malformed value (non-number) is ACKed processed (no retry
      // churn on an event that can never succeed), and a seconds-unit sender is
      // auto-corrected (a raw seconds value would otherwise store a 1970 expiry
      // — an instantly-lapsed member). Only an EXCEPTION stays retryable.
      let expiryMs: number | null = null;
      if (expiresAtMs != null) {
        if (typeof expiresAtMs !== 'number' || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
          await ctx.runMutation(internal.webhooks.markEventProcessed, { eventId: dedupeId });
          return { ok: true, applied: false, reason: 'invalid_expiresAtMs' };
        }
        // < 1e12 is before Sep 2001 in ms — the sender meant seconds.
        expiryMs = expiresAtMs < 1e12 ? Math.round(expiresAtMs * 1000) : Math.round(expiresAtMs);
      }

      // A reference is only for lookup; the portal signature authorizes the grant.
      const userId = await ctx.runQuery(internal.supportId.findBySupportId, { input: supportId });
      const user = userId ? await ctx.runQuery(internal.users.get, { id: userId }) : null;
      // Unknown user/tier is a permanent ACK (the sender must stop retrying),
      // so mark processed — only an exception below leaves the claim retryable.
      if (!user) {
        await ctx.runMutation(internal.webhooks.markEventProcessed, { eventId: dedupeId });
        return { ok: true, applied: false, reason: 'unknown_user' };
      }

      const tier = await ctx.runQuery(internal.tiers.getBySlug, { slug: tierSlug });
      if (!tier) {
        await ctx.runMutation(internal.webhooks.markEventProcessed, { eventId: dedupeId });
        return { ok: true, applied: false, reason: 'unknown_tier' };
      }

      const applied = await ctx.runMutation(internal.webhooks.applyLegacyGrant, {
        userId: user._id,
        tierId: tier._id,
        expiresAtMs: expiryMs,
        issuedAtMs: issuedAtMs as number, // isCurrentBillingEvent checked it
        eventId: dedupeId,
      });
      return applied ? { ok: true, applied } : { ok: true, applied, reason: 'stale_replay' };
    } catch (err) {
      await ctx.runMutation(internal.webhooks.markEventFailed, { eventId: dedupeId });
      throw err;
    }
  },
});

/** Order grants and commit the receipt with the membership update. */
export const applyLegacyGrant = internalMutation({
  args: {
    userId: v.id('users'),
    tierId: v.id('tiers'),
    expiresAtMs: v.union(v.number(), v.null()),
    issuedAtMs: v.number(),
    eventId: v.string(),
  },
  handler: async (ctx, a): Promise<boolean> => {
    const user = await ctx.db.get(a.userId);
    const applied = Boolean(
      user &&
      user.status !== 'deleted' &&
      isCurrentBillingEvent(a.issuedAtMs) &&
      // >= : distinct events can share a timestamp (one batch, coarse clocks);
      // the eventId claim already stops a replay of the same event.
      a.issuedAtMs >= (user.lastGenericBillingEventAt ?? 0) &&
      (a.expiresAtMs === null ||
        user.membershipExpiresAt == null ||
        a.expiresAtMs >= user.membershipExpiresAt),
    );
    if (applied) {
      await applyMembership(ctx, {
        userId: a.userId,
        tierId: a.tierId,
        expiresAtMs: a.expiresAtMs,
        reason: 'billing.webhook',
        triggeredBy: 'webhook',
      });
      await ctx.db.patch(a.userId, { lastGenericBillingEventAt: a.issuedAtMs });
    }
    await ctx.runMutation(internal.webhooks.markEventProcessed, { eventId: a.eventId });
    return applied;
  },
});

/**
 * Serializable dedupe claim shared by every webhook ingest path. Outcomes:
 * no row → insert a 'pending' claim and proceed; 'processed' (or a legacy row
 * with no status — written by the pre-claim code only for completed ingests)
 * → terminal duplicate; 'pending'/'failed' → re-claim and proceed, so a grant
 * that crashed or threw is re-applied by the sender's retry instead of lost.
 * Serializable OCC guarantees one winner when two claims race on the insert.
 */
export const claimEvent = internalMutation({
  args: { eventId: v.string(), source: v.string(), payload: v.string() },
  handler: async (ctx, { eventId, source, payload }) => {
    const existing = await ctx.db
      .query('webhookEvents')
      .withIndex('by_event_id', (q) => q.eq('eventId', eventId))
      .unique();
    if (!existing) {
      await ctx.db.insert('webhookEvents', { eventId, source, payload, status: 'pending' });
      return { proceed: true as const, retry: false };
    }
    if (existing.status === 'pending' || existing.status === 'failed') {
      await ctx.db.patch(existing._id, { status: 'pending' });
      return { proceed: true as const, retry: true };
    }
    return { proceed: false as const };
  },
});

export const markEventProcessed = internalMutation({
  args: { eventId: v.string() },
  handler: async (ctx, { eventId }) => {
    const row = await ctx.db
      .query('webhookEvents')
      .withIndex('by_event_id', (q) => q.eq('eventId', eventId))
      .unique();
    if (row) await ctx.db.patch(row._id, { status: 'processed', processedAt: Date.now() });
  },
});

export const markEventFailed = internalMutation({
  args: { eventId: v.string() },
  handler: async (ctx, { eventId }) => {
    const row = await ctx.db
      .query('webhookEvents')
      .withIndex('by_event_id', (q) => q.eq('eventId', eventId))
      .unique();
    if (row) {
      await ctx.db.patch(row._id, { status: 'failed' });
      // A failed claim is retryable ONLY by the sender's redelivery, and senders
      // give up (Stripe ~3 days, NOWPayments a handful of attempts) — after
      // which a paid-but-ungranted order would be invisible. Audit it so the
      // admin billing page + audit log surface the money-at-risk event.
      await writeAuditLog(ctx, {
        actorType: 'webhook',
        action: 'billing.webhook.grant_failed',
        targetType: 'webhook_event',
        targetId: eventId,
        payload: { source: row.source },
      });
    }
  },
});
