/**
 * Member passkey data layer — the queries/mutations the member WebAuthn
 * ceremonies (convex/memberWebauthn.ts, a "use node" module) orchestrate. The
 * MEMBER analogue of the admin half of convex/admins.ts, keyed to `users` rather
 * than `adminUsers`.
 *
 * These tables are DELIBERATELY separate from the admin passkey tables so that:
 *   - member verify can only ever match a member credential (cross-realm
 *     isolation: an admin passkey can't assert a member session, or vice-versa),
 *   - the admin last-admin invariants stay confined to admins.ts.
 *
 * A member passkey is opt-in convenience: the 32-digit account number remains a
 * valid login + the portable recovery secret, so revoke has NO last-credential
 * guard (unlike admins) — losing every passkey never locks a member out.
 *
 * Challenge consume + counter bump are mutations (serializable), giving the same
 * replay/TOCTOU guarantees as the admin path. All functions are internal.
 */
import { internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import { recordHeartbeat } from './cronHeartbeat';
import { v } from 'convex/values';
import { writeAuditLog } from './lib/audit';

// --- registration challenges -------------------------------------------------

export const insertRegistrationChallenge = internalMutation({
  args: { userId: v.id('users'), challenge: v.string(), ttlMs: v.number() },
  handler: async (ctx, { userId, challenge, ttlMs }) => {
    await ctx.db.insert('memberWebauthnRegistrationChallenges', {
      userId,
      challenge,
      expiresAt: Date.now() + ttlMs,
    });
    return null;
  },
});

/**
 * Consume the newest valid registration challenge for a member and return its
 * challenge string. Marked consumed BEFORE the caller verifies (replay guard); a
 * legitimate retry just restarts the ceremony. Returns null if none valid.
 */
export const consumeLatestRegistrationChallenge = internalMutation({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }) => {
    const now = Date.now();
    const rows = await ctx.db
      .query('memberWebauthnRegistrationChallenges')
      .withIndex('by_user_expires', (q) => q.eq('userId', userId).gt('expiresAt', now))
      .collect();
    const row = rows
      .filter((r) => !r.consumedAt)
      .sort((a, b) => b._creationTime - a._creationTime)[0];
    if (!row) return null;
    await ctx.db.patch(row._id, { consumedAt: now });
    return { challenge: row.challenge };
  },
});

// --- credentials -------------------------------------------------------------

export const insertCredential = internalMutation({
  args: {
    userId: v.id('users'),
    credentialId: v.string(),
    publicKey: v.string(),
    counter: v.number(),
    transports: v.optional(v.string()),
    deviceLabel: v.optional(v.string()),
    aaguid: v.optional(v.string()),
  },
  handler: async (ctx, a) => {
    // Uniqueness read-check (no UNIQUE constraint in Convex): a credentialId
    // dup would silently break the sign-in lookup's .unique().
    const clash = await ctx.db
      .query('memberPasskeyCredentials')
      .withIndex('by_credential_id', (q) => q.eq('credentialId', a.credentialId))
      .unique();
    if (clash) throw new Error('credential id collision');
    await ctx.db.insert('memberPasskeyCredentials', a);
    return null;
  },
});

export const credentialIdsByUser = internalQuery({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }) => {
    const rows = await ctx.db
      .query('memberPasskeyCredentials')
      .withIndex('by_user', (q) => q.eq('userId', userId))
      .collect();
    return rows.map((r) => r.credentialId);
  },
});

export const credentialByCredentialId = internalQuery({
  args: { credentialId: v.string() },
  handler: (ctx, { credentialId }) =>
    ctx.db
      .query('memberPasskeyCredentials')
      .withIndex('by_credential_id', (q) => q.eq('credentialId', credentialId))
      .unique(),
});

export const bumpCredentialCounter = internalMutation({
  args: { credentialId: v.string(), newCounter: v.number() },
  handler: async (ctx, { credentialId, newCounter }) => {
    const row = await ctx.db
      .query('memberPasskeyCredentials')
      .withIndex('by_credential_id', (q) => q.eq('credentialId', credentialId))
      .unique();
    if (row) await ctx.db.patch(row._id, { counter: newCounter, lastUsedAt: Date.now() });
    return null;
  },
});

// --- assertion challenges ----------------------------------------------------

export const insertAuthChallenge = internalMutation({
  args: {
    challengeId: v.string(),
    challenge: v.string(),
    userId: v.optional(v.id('users')),
    ttlMs: v.number(),
  },
  handler: async (ctx, { challengeId, challenge, userId, ttlMs }) => {
    await ctx.db.insert('memberWebauthnAuthChallenges', {
      challengeId,
      challenge,
      userId,
      expiresAt: Date.now() + ttlMs,
    });
    return null;
  },
});

/** Consume an assertion challenge by id (consume-before-verify). */
export const consumeAuthChallenge = internalMutation({
  args: { challengeId: v.string() },
  handler: async (ctx, { challengeId }) => {
    const now = Date.now();
    const row = await ctx.db
      .query('memberWebauthnAuthChallenges')
      .withIndex('by_challenge_id', (q) => q.eq('challengeId', challengeId))
      .unique();
    if (!row || row.consumedAt || row.expiresAt <= now) return null;
    await ctx.db.patch(row._id, { consumedAt: now });
    return { challenge: row.challenge };
  },
});

// --- management (Security-tab list + revoke) ---------------------------------

/** A masked passkey list for one member (drives the Security-tab manager). */
export const listCredentials = internalQuery({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }) => {
    const rows = await ctx.db
      .query('memberPasskeyCredentials')
      .withIndex('by_user', (q) => q.eq('userId', userId))
      .collect();
    // Never return publicKey/counter — only the non-secret display fields.
    return rows.map((r) => ({
      id: r._id as string,
      deviceLabel: r.deviceLabel ?? null,
      aaguid: r.aaguid ?? null,
      lastUsedAt: r.lastUsedAt ? new Date(r.lastUsedAt).toISOString() : null,
      createdAt: new Date(r._creationTime).toISOString(),
    }));
  },
});

/**
 * Revoke (delete) one of the CALLER's passkeys. Ownership-checked against the
 * resolved member (a member can only remove their own credential). No
 * last-credential guard: the account number is always a valid fallback login, so
 * removing the last passkey can't lock anyone out. Idempotent: a missing or
 * foreign credential is a no-op (never an existence oracle for another account).
 */
export const revokeCredential = internalMutation({
  args: { credentialId: v.string(), userId: v.id('users') },
  handler: async (ctx, { credentialId, userId }) => {
    // normalizeId validates the string is an id for this table (a malformed or
    // foreign id → null → treated as "nothing to revoke", no error/oracle).
    const id = ctx.db.normalizeId('memberPasskeyCredentials', credentialId);
    const cred = id ? await ctx.db.get(id) : null;
    if (!cred || cred.userId !== userId) return { ok: true as const, revoked: false };
    await ctx.db.delete(cred._id);
    await writeAuditLog(ctx, {
      actorType: 'member',
      actorId: userId,
      action: 'account.passkey.revoke',
      targetType: 'user',
      targetId: userId,
      payload: { deviceLabel: cred.deviceLabel ?? null },
    });
    return { ok: true as const, revoked: true };
  },
});

// --- retention crons ---------------------------------------------------------

/** Matches retention.ts: bound the immediate re-run chain (sweeps below). */
const MAX_DRAIN_ROUNDS = 50;

export const sweepExpiredRegistrationChallenges = internalMutation({
  args: { limit: v.optional(v.number()), rounds: v.optional(v.number()) },
  handler: async (ctx, { limit, rounds }) => {
    await recordHeartbeat(ctx, 'retention-member-webauthn-reg');
    const page = limit ?? 500;
    const expired = await ctx.db
      .query('memberWebauthnRegistrationChallenges')
      .withIndex('by_expires', (q) => q.lt('expiresAt', Date.now()))
      .take(page);
    for (const row of expired) await ctx.db.delete(row._id);
    if (expired.length === page) {
      const n = rounds ?? 0;
      if (n >= MAX_DRAIN_ROUNDS)
        console.warn('[retention-member-webauthn-reg] drain cap hit; remainder next run');
      else
        await ctx.scheduler.runAfter(
          0,
          internal.memberPasskeys.sweepExpiredRegistrationChallenges,
          { rounds: n + 1 },
        );
    }
    return { removed: expired.length };
  },
});

export const sweepExpiredAuthChallenges = internalMutation({
  args: { limit: v.optional(v.number()), rounds: v.optional(v.number()) },
  handler: async (ctx, { limit, rounds }) => {
    await recordHeartbeat(ctx, 'retention-member-webauthn-auth');
    const page = limit ?? 500;
    const expired = await ctx.db
      .query('memberWebauthnAuthChallenges')
      .withIndex('by_expires', (q) => q.lt('expiresAt', Date.now()))
      .take(page);
    for (const row of expired) await ctx.db.delete(row._id);
    if (expired.length === page) {
      const n = rounds ?? 0;
      if (n >= MAX_DRAIN_ROUNDS)
        console.warn('[retention-member-webauthn-auth] drain cap hit; remainder next run');
      else
        await ctx.scheduler.runAfter(0, internal.memberPasskeys.sweepExpiredAuthChallenges, {
          rounds: n + 1,
        });
    }
    return { removed: expired.length };
  },
});
