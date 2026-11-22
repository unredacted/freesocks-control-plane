/**
 * Session store (P6): replaces the KV `sessions` namespace. A signed cookie
 * carries the opaque `sid`; the row holds the bound identity + expiry. The sid
 * is minted in an action (CSPRNG) and handed to `create`; cookie signing lives
 * in lib/cookies. All functions are internal; only the HTTP actions touch them.
 *
 * `bySid` treats an expired row as absent (defence-in-depth alongside the daily
 * sweep), so a stale-but-unswept cookie never authenticates.
 *
 * Every insert/delete here ALSO bumps the `stats:sessionCounts` counter
 * (lib/statusCounters.ts) that `adminApi.statusSummary` reads for the PoP
 * readiness tally — keep that invariant when adding a write path (the only
 * other one is the lifecycle hard-delete cascade).
 */
import { internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import { recordHeartbeat } from './cronHeartbeat';
import { bumpSessionCounts, sessionBucket, type SessionBump } from './lib/statusCounters';
import { ConvexError } from 'convex/values';
import { v } from 'convex/values';
import { b64UrlToBytes } from '../src/shared/crypto/envelope';
import { POP_ALG, POP_ALG_ED } from '../src/shared/crypto/pop';

/** Matches retention.ts: bound the immediate re-run chain (see sweepExpired). */
const MAX_DRAIN_ROUNDS = 50;
// Only a newly established member session can manage login credentials.
const CREDENTIAL_MANAGEMENT_WINDOW_MS = 5 * 60_000;

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
    verifiedMemberPasskey: v.optional(
      v.object({
        id: v.id('memberPasskeyCredentials'),
        previousCounter: v.number(),
        newCounter: v.number(),
      }),
    ),
    verifiedAdminPasskey: v.optional(
      v.object({
        id: v.id('passkeyCredentials'),
        previousCounter: v.number(),
        newCounter: v.number(),
      }),
    ),
  },
  handler: async (
    ctx,
    {
      sid,
      kind,
      userId,
      adminUserId,
      ttlMs,
      popPublicKey,
      popAlg,
      popSessionToken,
      verifiedAdminPasskey,
      verifiedMemberPasskey,
    },
  ) => {
    // Verify the assertion's credential still exists and belongs to an active
    // admin in the same transaction as session creation.
    if (verifiedAdminPasskey) {
      const credential = await ctx.db.get(verifiedAdminPasskey.id);
      const admin = adminUserId ? await ctx.db.get(adminUserId) : null;
      if (
        kind !== 'admin' ||
        !admin?.isActive ||
        !credential ||
        credential.adminUserId !== admin._id ||
        credential.counter !== verifiedAdminPasskey.previousCounter
      ) {
        throw new ConvexError({
          code: 'auth.forbidden',
          message: 'Passkey is no longer authorized',
        });
      }
      await ctx.db.patch(credential._id, {
        counter: verifiedAdminPasskey.newCounter,
        lastUsedAt: Date.now(),
      });
    }
    if (verifiedMemberPasskey) {
      const credential = await ctx.db.get(verifiedMemberPasskey.id);
      const user = userId ? await ctx.db.get(userId) : null;
      if (
        kind !== 'member' ||
        !user ||
        user.status === 'deleted' ||
        (user.status === 'disabled' && user.disabledReason !== 'membership_lapsed') ||
        !credential ||
        credential.userId !== user._id ||
        credential.counter !== verifiedMemberPasskey.previousCounter
      ) {
        throw new ConvexError({
          code: 'auth.forbidden',
          message: 'Passkey is no longer authorized',
        });
      }
      await ctx.db.patch(credential._id, {
        counter: verifiedMemberPasskey.newCounter,
        lastUsedAt: Date.now(),
      });
    }
    // PoP binding (CDN-blinding Phase 2). Normalize the client-reported algorithm
    // to the allowlist (unknown → ES256, the P-256 fallback). A supplied key that
    // does not decode to its scheme's length is a client bug or a mangled proxy:
    // fail LOUDLY (the login attempt errors and the client re-binds) rather than
    // silently mint an unbound session that 401s every request under POP_REQUIRED
    // — or worse, a cookie-only session when POP_REQUIRED is off.
    const boundAlg = popAlg === POP_ALG_ED ? POP_ALG_ED : POP_ALG;
    if (popPublicKey !== undefined && !popKeyMatchesAlg(popPublicKey, boundAlg)) {
      throw new ConvexError({
        code: 'session.pop_bind_invalid',
        message: 'The session key could not be bound; please try signing in again.',
      });
    }
    const bound = popPublicKey !== undefined;
    // Uniqueness read-check on the sid (the codebase convention): a 256-bit
    // CSPRNG collision is unreachable, but the `by_sid` `.unique()` readers
    // throw on any dup, so fail the insert instead of poisoning sessions.
    const clash = await ctx.db
      .query('sessions')
      .withIndex('by_sid', (q) => q.eq('sid', sid))
      .unique();
    if (clash) throw new Error('session sid collision');
    const id = await ctx.db.insert('sessions', {
      sid,
      kind,
      userId,
      adminUserId,
      expiresAt: Date.now() + ttlMs,
      adminPasskeyId: verifiedAdminPasskey?.id,
      memberPasskeyId: kind === 'member' ? (verifiedMemberPasskey?.id ?? null) : undefined,
      ...(bound ? { popPublicKey, popAlg: boundAlg, popSessionToken } : {}),
    });
    // Counter bump keyed on the row's own _creationTime (the reconcile journal
    // boundary) — read it back rather than assume Date.now() matches.
    const inserted = await ctx.db.get(id);
    await bumpSessionCounts(
      ctx,
      [{ bucket: sessionBucket({ kind, popPublicKey }), creationTime: inserted!._creationTime }],
      1,
    );
    return null;
  },
});

export const bySid = internalQuery({
  args: { sid: v.string(), recentMember: v.optional(v.boolean()) },
  handler: async (ctx, { sid, recentMember }) => {
    const row = await ctx.db
      .query('sessions')
      .withIndex('by_sid', (q) => q.eq('sid', sid))
      .unique();
    const now = Date.now();
    if (!row || row.expiresAt <= now) return null;
    if (
      recentMember &&
      (row.kind !== 'member' || row._creationTime <= now - CREDENTIAL_MANAGEMENT_WINDOW_MS)
    )
      return null;
    if (row.kind === 'admin' && row.adminUserId) {
      if (row.adminPasskeyId) {
        const credential = await ctx.db.get(row.adminPasskeyId);
        if (!credential || credential.adminUserId !== row.adminUserId) return null;
      } else if ((await ctx.db.get(row.adminUserId))?.legacySessionsRevoked) {
        // Earlier admin sessions lack credential provenance.
        return null;
      }
    }
    if (row.kind === 'member' && row.userId) {
      if (row.memberPasskeyId) {
        const credential = await ctx.db.get(row.memberPasskeyId);
        if (!credential || credential.userId !== row.userId) return null;
      } else if (
        row.memberPasskeyId === undefined &&
        (await ctx.db.get(row.userId))?.legacySessionsRevoked
      ) {
        // Older member sessions do not distinguish passkey and account-number login.
        return null;
      }
    }
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
    if (row) {
      await ctx.db.delete(row._id);
      await bumpSessionCounts(
        ctx,
        [{ bucket: sessionBucket(row), creationTime: row._creationTime }],
        -1,
      );
    }
    return null;
  },
});

/**
 * Revoke every member session for a user EXCEPT `keepSid` (the caller's current
 * session, when cookie-authenticated). Used by account-number rotation: the old
 * credential dies at rotation, so every session minted from it must die too —
 * otherwise an attacker holding a session keeps access for up to the 30-day TTL
 * even after the victim rotates (the advertised compromise remediation).
 */
export const deleteAllForUserExcept = internalMutation({
  args: { userId: v.id('users'), keepSid: v.optional(v.string()) },
  handler: async (ctx, { userId, keepSid }) => {
    const rows = await ctx.db
      .query('sessions')
      .withIndex('by_user', (q) => q.eq('userId', userId))
      .collect();
    let removed = 0;
    const bumps: SessionBump[] = [];
    for (const row of rows) {
      if (keepSid !== undefined && row.sid === keepSid) continue;
      await ctx.db.delete(row._id);
      bumps.push({ bucket: sessionBucket(row), creationTime: row._creationTime });
      removed++;
    }
    await bumpSessionCounts(ctx, bumps, -1);
    return { removed };
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
    const bumps: SessionBump[] = [];
    for (const row of expired) {
      await ctx.db.delete(row._id);
      bumps.push({ bucket: sessionBucket(row), creationTime: row._creationTime });
    }
    await bumpSessionCounts(ctx, bumps, -1);
    if (expired.length === page) {
      const n = rounds ?? 0;
      if (n >= MAX_DRAIN_ROUNDS) console.warn('[session-sweep] drain cap hit; remainder next run');
      else await ctx.scheduler.runAfter(0, internal.sessions.sweepExpired, { rounds: n + 1 });
    }
    return { removed: expired.length };
  },
});
