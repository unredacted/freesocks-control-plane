/**
 * Session store (P6): replaces the KV `sessions` namespace. A signed cookie
 * carries the opaque `sid`; the row holds the bound identity + expiry. The sid
 * is minted in an action (CSPRNG) and handed to `create`; cookie signing lives
 * in lib/cookies. All functions are internal; only the HTTP actions touch them.
 *
 * `bySid` treats an expired row as absent (defence-in-depth alongside the daily
 * sweep), so a stale-but-unswept cookie never authenticates.
 */
import { internalMutation, internalQuery } from './_generated/server';
import { v } from 'convex/values';

export const create = internalMutation({
  args: {
    sid: v.string(),
    kind: v.union(v.literal('member'), v.literal('admin')),
    userId: v.optional(v.id('users')),
    adminUserId: v.optional(v.id('adminUsers')),
    ttlMs: v.number(),
    // Proof-of-possession binding (CDN-blinding Phase 2). When the client
    // minted a session key it posts the raw P-256 public point here; the
    // session is then PoP-bound (cookie alone is insufficient). Absent for
    // clients that could not run the signing worker (legacy fallback).
    popPublicKey: v.optional(v.string()),
    popAlg: v.optional(v.string()),
    // The public per-session token (binds each PoP signature to this session).
    // Stored only when the session is PoP-bound (popPublicKey present).
    popSessionToken: v.optional(v.string()),
  },
  handler: async (
    ctx,
    { sid, kind, userId, adminUserId, ttlMs, popPublicKey, popAlg, popSessionToken },
  ) => {
    await ctx.db.insert('sessions', {
      sid,
      kind,
      userId,
      adminUserId,
      expiresAt: Date.now() + ttlMs,
      ...(popPublicKey
        ? { popPublicKey, popAlg: popAlg ?? 'ES256', popBoundAt: Date.now(), popSessionToken }
        : {}),
    });
    return null;
  },
});

export const bySid = internalQuery({
  args: { sid: v.string() },
  handler: async (ctx, { sid }) => {
    const row = await ctx.db
      .query('sessions')
      .withIndex('by_sid', (q) => q.eq('sid', sid))
      .unique();
    if (!row || row.expiresAt < Date.now()) return null;
    return row;
  },
});

export const deleteBySid = internalMutation({
  args: { sid: v.string() },
  handler: async (ctx, { sid }) => {
    const row = await ctx.db
      .query('sessions')
      .withIndex('by_sid', (q) => q.eq('sid', sid))
      .unique();
    if (row) await ctx.db.delete(row._id);
    return null;
  },
});

/** Cron: delete a page of expired sessions; returns how many to drive re-runs. */
export const sweepExpired = internalMutation({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }) => {
    const now = Date.now();
    const expired = await ctx.db
      .query('sessions')
      .withIndex('by_expires', (q) => q.lt('expiresAt', now))
      .take(limit ?? 500);
    for (const row of expired) await ctx.db.delete(row._id);
    return { removed: expired.length };
  },
});
