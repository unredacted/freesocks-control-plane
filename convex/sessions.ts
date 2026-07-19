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
import { internal } from './_generated/api';
import { recordHeartbeat } from './cronHeartbeat';
import { v } from 'convex/values';
import { b64UrlToBytes } from '../src/shared/crypto/envelope';
import { POP_ALG, POP_ALG_ED } from '../src/shared/crypto/pop';

/** Matches retention.ts: bound the immediate re-run chain (see sweepExpired). */
const MAX_DRAIN_ROUNDS = 50;

/** True when the base64url raw public key decodes to the byte length its PoP
 *  algorithm requires (Ed25519 = 32, P-256 uncompressed point = 65). */
function popKeyMatchesAlg(popPublicKey: string, alg: string): boolean {
  try {
    const len = b64UrlToBytes(popPublicKey).length;
    return alg === POP_ALG_ED ? len === 32 : len === 65;
  } catch {
    return false;
  }
}

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
    // PoP binding (CDN-blinding Phase 2). Normalize the client-reported algorithm
    // to the allowlist (unknown → ES256, the P-256 fallback) and bind only if the
    // public key actually decodes to that scheme's length. An inconsistent pair
    // would only break the caller's OWN session, so we fail safe to an unbound
    // session (re-auth under POP_REQUIRED) rather than throw.
    const boundAlg = popAlg === POP_ALG_ED ? POP_ALG_ED : POP_ALG;
    const bound = popPublicKey !== undefined && popKeyMatchesAlg(popPublicKey, boundAlg);
    await ctx.db.insert('sessions', {
      sid,
      kind,
      userId,
      adminUserId,
      expiresAt: Date.now() + ttlMs,
      ...(bound ? { popPublicKey, popAlg: boundAlg, popSessionToken } : {}),
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

/** Cron: delete a page of expired sessions. A FULL page re-runs immediately
 *  (drain-chain, same pattern as retention.ts) — one 500-row page/day can't
 *  keep up once more than that expires daily. */
export const sweepExpired = internalMutation({
  args: { limit: v.optional(v.number()), rounds: v.optional(v.number()) },
  handler: async (ctx, { limit, rounds }) => {
    await recordHeartbeat(ctx, 'session-sweep');
    const now = Date.now();
    const page = limit ?? 500;
    const expired = await ctx.db
      .query('sessions')
      .withIndex('by_expires', (q) => q.lt('expiresAt', now))
      .take(page);
    for (const row of expired) await ctx.db.delete(row._id);
    if (expired.length === page) {
      const n = rounds ?? 0;
      if (n >= MAX_DRAIN_ROUNDS) console.warn('[session-sweep] drain cap hit; remainder next run');
      else await ctx.scheduler.runAfter(0, internal.sessions.sweepExpired, { rounds: n + 1 });
    }
    return { removed: expired.length };
  },
});
