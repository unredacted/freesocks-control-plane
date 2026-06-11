/**
 * Generic webhook seam (P7): the single inbound integration point the future
 * billing portal plugs into to drive entitlements. HMAC-verified + deduped,
 * then mapped onto the lifecycle `setMembership` seam keyed by the member's
 * account number. CiviCRM's bespoke webhook is gone; this is intentionally
 * provider-agnostic.
 *
 * Contract (POST /api/webhooks/billing, header `x-signature: <hex hmac-sha256>`):
 *   { eventId, accountId, tierSlug, expiresAtMs? }
 * The signature is HMAC-SHA256(WEBHOOK_SIGNING_SECRET, rawBody). Unknown
 * user/tier is ACKed (200, applied:false) so the sender doesn't retry forever;
 * a replayed eventId is a no-op.
 */
import { internalAction, internalMutation } from './_generated/server';
import { api, internal } from './_generated/api';
import { ConvexError, v } from 'convex/values';
import { hmacSha256Hex, timingSafeEqual } from './lib/crypto';
import { hashAccountId, normalizeAccountId } from './lib/accountId';

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
      accountId?: string;
      tierSlug?: string;
      expiresAtMs?: number | null;
    };
    try {
      payload = JSON.parse(rawBody);
    } catch {
      throw new Error('invalid JSON body');
    }
    const { eventId, accountId, tierSlug, expiresAtMs } = payload;
    if (!eventId || !accountId || !tierSlug)
      throw new Error('eventId, accountId, tierSlug required');

    // Dedupe first: a replayed eventId never reapplies. Persist a REDACTED
    // payload: the raw body carries the account-number plaintext, which must
    // never be stored; keep only the 4-digit prefix for tracing.
    const safePayload = JSON.stringify({
      eventId,
      accountIdPrefix: normalizeAccountId(accountId).slice(0, 4),
      tierSlug,
      expiresAtMs: expiresAtMs ?? null,
    });
    const dedupe = await ctx.runMutation(internal.webhooks.recordEvent, {
      eventId,
      source: 'billing',
      payload: safePayload,
    });
    if (dedupe.duplicate) return { ok: true, duplicate: true, applied: false };

    // Map account number → user (status-blind so a lapsed account can renew).
    const accountHash = await hashAccountId(accountId);
    const user = await ctx.runQuery(internal.users.byAccountIdHashInternal, {
      accountIdHash: accountHash,
    });
    if (!user) return { ok: true, applied: false, reason: 'unknown_user' };

    const tier = await ctx.runQuery(api.tiers.getBySlug, { slug: tierSlug });
    if (!tier) return { ok: true, applied: false, reason: 'unknown_tier' };

    await ctx.runMutation(internal.lifecycle.setMembership, {
      userId: user._id,
      tierId: tier._id,
      expiresAtMs: expiresAtMs ?? null,
      reason: 'billing.webhook',
      triggeredBy: 'webhook',
    });
    return { ok: true, applied: true };
  },
});

export const recordEvent = internalMutation({
  args: { eventId: v.string(), source: v.string(), payload: v.string() },
  handler: async (ctx, { eventId, source, payload }) => {
    const existing = await ctx.db
      .query('webhookEvents')
      .withIndex('by_event_id', (q) => q.eq('eventId', eventId))
      .unique();
    if (existing) return { duplicate: true as const };
    await ctx.db.insert('webhookEvents', { eventId, source, payload, processedAt: Date.now() });
    return { duplicate: false as const };
  },
});
