/**
 * Admin + passkey data layer (P6c). The WebAuthn ceremonies themselves live in
 * convex/webauthn.ts (a "use node" action module, since @simplewebauthn needs
 * Node); this file holds the queries + mutations they orchestrate via
 * ctx.runQuery/runMutation. Challenge consume + counter bump are mutations so
 * they're race-safe (serializable), giving the replay/TOCTOU guarantees the old
 * Hono+D1 code relied on transactions for.
 */
import { internalMutation, internalQuery, type MutationCtx } from './_generated/server';
import { recordHeartbeat } from './cronHeartbeat';
import type { Id } from './_generated/dataModel';
import { ConvexError, v } from 'convex/values';
import { writeAuditLog } from './lib/audit';

// --- bootstrap status (drives the SPA's bootstrap-vs-login decision, served
//     via GET /api/admin/auth/status; internal so the raw channel can't read it) ---

/**
 * Whether any admin has completed registration (≥1 passkey), and whether the
 * first-run bootstrap path is open. An admin_users row with no credential is an
 * abandoned bootstrap attempt and doesn't count. `signedIn` is added by the
 * HTTP layer (it reads the cookie); this query is cookie-blind.
 */
export const bootstrapStatus = internalQuery({
  args: {},
  handler: async (ctx) => {
    const oneCred = await ctx.db.query('passkeyCredentials').take(1);
    const hasAdmins = oneCred.length > 0;
    return {
      hasAdmins,
      bootstrapAvailable: !hasAdmins && Boolean(process.env.ADMIN_BOOTSTRAP_SECRET),
    };
  },
});

/** Internal boolean for the node actions' TOCTOU re-checks. */
export const hasActiveAdmin = internalQuery({
  args: {},
  handler: async (ctx) => (await ctx.db.query('passkeyCredentials').take(1)).length > 0,
});

// --- admin rows ---

export const byUsername = internalQuery({
  args: { username: v.string() },
  handler: (ctx, { username }) =>
    ctx.db
      .query('adminUsers')
      .withIndex('by_username', (q) => q.eq('username', username))
      .unique(),
});

export const getById = internalQuery({
  args: { adminUserId: v.id('adminUsers') },
  handler: (ctx, { adminUserId }) => ctx.db.get(adminUserId),
});

/** Reuse a row from an abandoned bootstrap attempt with the same username. */
export const upsertByUsername = internalMutation({
  args: { username: v.string(), displayName: v.string() },
  handler: async (ctx, { username, displayName }) => {
    const existing = await ctx.db
      .query('adminUsers')
      .withIndex('by_username', (q) => q.eq('username', username))
      .unique();
    if (existing) return existing._id;
    return ctx.db.insert('adminUsers', {
      username,
      displayName,
      isActive: true,
      updatedAt: Date.now(),
    });
  },
});

export const touchLogin = internalMutation({
  args: { adminUserId: v.id('adminUsers') },
  handler: async (ctx, { adminUserId }) => {
    await ctx.db.patch(adminUserId, { lastLoginAt: Date.now(), updatedAt: Date.now() });
    return null;
  },
});

// --- registration challenges ---

export const insertRegistrationChallenge = internalMutation({
  args: { adminUserId: v.id('adminUsers'), challenge: v.string(), ttlMs: v.number() },
  handler: async (ctx, { adminUserId, challenge, ttlMs }) => {
    await ctx.db.insert('webauthnRegistrationChallenges', {
      adminUserId,
      challenge,
      expiresAt: Date.now() + ttlMs,
    });
    return null;
  },
});

/**
 * Consume the newest valid registration challenge for an admin and return its
 * challenge string. Marked consumed BEFORE the caller verifies (replay guard);
 * a legitimate retry just restarts the ceremony. Returns null if none valid.
 */
export const consumeLatestRegistrationChallenge = internalMutation({
  args: { adminUserId: v.id('adminUsers') },
  handler: async (ctx, { adminUserId }) => {
    const now = Date.now();
    // Range-scan only the unexpired suffix (TTL is minutes, so this is a handful
    // of rows at most) instead of collecting the admin's full challenge history.
    const rows = await ctx.db
      .query('webauthnRegistrationChallenges')
      .withIndex('by_admin_expires', (q) => q.eq('adminUserId', adminUserId).gt('expiresAt', now))
      .collect();
    const row = rows
      .filter((r) => !r.consumedAt)
      .sort((a, b) => b._creationTime - a._creationTime)[0];
    if (!row) return null;
    await ctx.db.patch(row._id, { consumedAt: now });
    return { challenge: row.challenge };
  },
});

// --- credentials ---

export const insertCredential = internalMutation({
  args: {
    adminUserId: v.id('adminUsers'),
    credentialId: v.string(),
    publicKey: v.string(),
    counter: v.number(),
    transports: v.optional(v.string()),
    deviceLabel: v.optional(v.string()),
    aaguid: v.optional(v.string()),
  },
  handler: async (ctx, a) => {
    await ctx.db.insert('passkeyCredentials', a);
    return null;
  },
});

/**
 * Bootstrap-only credential insert: atomically re-checks that NO credential
 * exists yet and inserts the first one. The registerBootstrapVerify action does
 * the slow crypto verify FIRST (after its own pre-check), so two parties racing
 * the ceremony can both pass the earlier query-time check — but only one wins
 * this serializable claim; the loser gets auth.forbidden and must restart.
 * (Invite registration uses insertCredential: an admin already exists there.)
 */
export const bootstrapInsertCredential = internalMutation({
  args: {
    adminUserId: v.id('adminUsers'),
    credentialId: v.string(),
    publicKey: v.string(),
    counter: v.number(),
    transports: v.optional(v.string()),
    deviceLabel: v.optional(v.string()),
    aaguid: v.optional(v.string()),
  },
  handler: async (ctx, a) => {
    if ((await ctx.db.query('passkeyCredentials').take(1)).length > 0) {
      throw new ConvexError({
        code: 'auth.forbidden',
        message: 'Bootstrap closed: an admin already exists',
      });
    }
    await ctx.db.insert('passkeyCredentials', a);
    return null;
  },
});

export const credentialIdsByAdmin = internalQuery({
  args: { adminUserId: v.id('adminUsers') },
  handler: async (ctx, { adminUserId }) => {
    const rows = await ctx.db
      .query('passkeyCredentials')
      .withIndex('by_admin', (q) => q.eq('adminUserId', adminUserId))
      .collect();
    return rows.map((r) => r.credentialId);
  },
});

export const credentialByCredentialId = internalQuery({
  args: { credentialId: v.string() },
  handler: (ctx, { credentialId }) =>
    ctx.db
      .query('passkeyCredentials')
      .withIndex('by_credential_id', (q) => q.eq('credentialId', credentialId))
      .unique(),
});

export const bumpCredentialCounter = internalMutation({
  args: { credentialId: v.string(), newCounter: v.number() },
  handler: async (ctx, { credentialId, newCounter }) => {
    const row = await ctx.db
      .query('passkeyCredentials')
      .withIndex('by_credential_id', (q) => q.eq('credentialId', credentialId))
      .unique();
    if (row) await ctx.db.patch(row._id, { counter: newCounter, lastUsedAt: Date.now() });
    return null;
  },
});

// --- assertion challenges (replaces the webauthn:assert:<id> KV entry) ---

export const insertAuthChallenge = internalMutation({
  args: {
    challengeId: v.string(),
    challenge: v.string(),
    adminUserId: v.optional(v.id('adminUsers')),
    ttlMs: v.number(),
  },
  handler: async (ctx, { challengeId, challenge, adminUserId, ttlMs }) => {
    await ctx.db.insert('webauthnAuthChallenges', {
      challengeId,
      challenge,
      adminUserId,
      expiresAt: Date.now() + ttlMs,
    });
    return null;
  },
});

/** Consume an assertion challenge by id (consume-before-verify). Returns its challenge string. */
export const consumeAuthChallenge = internalMutation({
  args: { challengeId: v.string() },
  handler: async (ctx, { challengeId }) => {
    const now = Date.now();
    const row = await ctx.db
      .query('webauthnAuthChallenges')
      .withIndex('by_challenge_id', (q) => q.eq('challengeId', challengeId))
      .unique();
    if (!row || row.consumedAt || row.expiresAt <= now) return null;
    await ctx.db.patch(row._id, { consumedAt: now });
    return { challenge: row.challenge };
  },
});

// --- admin management + invites (multi-admin onboarding) ---

/**
 * Every admin row with its passkey count + pending-invite flag, for the admins
 * management page. Timestamps are ISO strings (the wire convention). The set of
 * admins is small (operators), so the per-admin credential/invite reads are fine.
 */
export const listAdminsWithCounts = internalQuery({
  args: {},
  handler: async (ctx) => {
    const now = Date.now();
    const admins = await ctx.db.query('adminUsers').collect();
    const out = [];
    for (const a of admins) {
      const creds = await ctx.db
        .query('passkeyCredentials')
        .withIndex('by_admin', (q) => q.eq('adminUserId', a._id))
        .collect();
      const invites = await ctx.db
        .query('adminInvites')
        .withIndex('by_admin', (q) => q.eq('adminUserId', a._id))
        .collect();
      out.push({
        id: a._id,
        username: a.username,
        displayName: a.displayName,
        isActive: a.isActive,
        passkeyCount: creds.length,
        pendingInvite: invites.some((i) => !i.consumedAt && i.expiresAt > now),
        lastLoginAt: a.lastLoginAt ? new Date(a.lastLoginAt).toISOString() : null,
        createdAt: new Date(a._creationTime).toISOString(),
      });
    }
    return out;
  },
});

// --- admin lifecycle (W3-8a): deactivate / reactivate + per-passkey revoke ----

/**
 * Count the admins who can ACTUALLY sign in right now — active rows that still
 * have ≥1 passkey. The last-admin guard keys off this so a deactivate or a
 * passkey-revoke can never lock everyone out (the bootstrap secret is the only
 * other way back in, and it may be unset in prod, so we never rely on it).
 * `excludeAdminId` drops one admin from the tally (the one being deactivated);
 * `excludeCredentialId` drops one credential (the one being revoked) when
 * judging whether its owner would still be signable afterwards.
 */
async function effectiveAdminCount(
  ctx: MutationCtx,
  opts: { excludeAdminId?: Id<'adminUsers'>; excludeCredentialId?: Id<'passkeyCredentials'> } = {},
): Promise<number> {
  const admins = await ctx.db.query('adminUsers').collect();
  let n = 0;
  for (const a of admins) {
    if (!a.isActive) continue;
    if (opts.excludeAdminId && a._id === opts.excludeAdminId) continue;
    const creds = await ctx.db
      .query('passkeyCredentials')
      .withIndex('by_admin', (q) => q.eq('adminUserId', a._id))
      .collect();
    const usable = creds.filter((c) => c._id !== opts.excludeCredentialId);
    if (usable.length > 0) n++;
  }
  return n;
}

/** A masked passkey list for one admin (drives the management UI's revoke). */
export const listCredentials = internalQuery({
  args: { adminUserId: v.id('adminUsers') },
  handler: async (ctx, { adminUserId }) => {
    const rows = await ctx.db
      .query('passkeyCredentials')
      .withIndex('by_admin', (q) => q.eq('adminUserId', adminUserId))
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
 * Activate / deactivate an admin. A deactivated admin is rejected by
 * `resolveAdmin` (existing sessions die on their next request) AND by the login
 * verify path (no fresh session). LAST-ADMIN GUARD: refuse to deactivate the
 * final admin who can still sign in — that would lock everyone out.
 * Reactivation is unguarded. Idempotent (no-op + audit skip when unchanged).
 */
export const setAdminActive = internalMutation({
  args: {
    adminUserId: v.id('adminUsers'),
    isActive: v.boolean(),
    actorAdminId: v.id('adminUsers'),
  },
  handler: async (ctx, { adminUserId, isActive, actorAdminId }) => {
    const target = await ctx.db.get(adminUserId);
    if (!target) throw new ConvexError({ code: 'not_found', message: 'Admin not found' });
    if (target.isActive === isActive) {
      return { ok: true as const, isActive, username: target.username };
    }
    if (!isActive && (await effectiveAdminCount(ctx, { excludeAdminId: adminUserId })) < 1) {
      throw new ConvexError({
        code: 'admin.last_admin',
        message:
          'Cannot deactivate the last admin who can still sign in. Add or activate another admin with a passkey first.',
      });
    }
    await ctx.db.patch(adminUserId, { isActive, updatedAt: Date.now() });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId,
      action: isActive ? 'admin.admin.reactivate' : 'admin.admin.deactivate',
      targetType: 'adminUser',
      targetId: adminUserId,
      payload: { username: target.username },
    });
    return { ok: true as const, isActive, username: target.username };
  },
});

/**
 * Revoke (delete) one passkey credential. LAST-ADMIN GUARD: refuse if removing
 * it would leave zero admins able to sign in (it is the owner's last passkey
 * AND no other active admin has one). Idempotent: a missing credential is a
 * no-op, not an error.
 */
export const revokeCredential = internalMutation({
  args: { credentialId: v.id('passkeyCredentials'), actorAdminId: v.id('adminUsers') },
  handler: async (ctx, { credentialId, actorAdminId }) => {
    const cred = await ctx.db.get(credentialId);
    if (!cred) return { ok: true as const, revoked: false };
    if ((await effectiveAdminCount(ctx, { excludeCredentialId: credentialId })) < 1) {
      throw new ConvexError({
        code: 'admin.last_admin',
        message:
          'Cannot revoke the last passkey that can sign in. Register another passkey (or admin) first.',
      });
    }
    await ctx.db.delete(credentialId);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId,
      action: 'admin.passkey.revoke',
      targetType: 'adminUser',
      targetId: cred.adminUserId,
      payload: { deviceLabel: cred.deviceLabel ?? null },
    });
    return { ok: true as const, revoked: true };
  },
});

export const insertInvite = internalMutation({
  args: {
    adminUserId: v.id('adminUsers'),
    tokenHash: v.string(),
    tokenPrefix: v.string(),
    createdByAdminId: v.id('adminUsers'),
    ttlMs: v.number(),
  },
  handler: async (ctx, { adminUserId, tokenHash, tokenPrefix, createdByAdminId, ttlMs }) => {
    await ctx.db.insert('adminInvites', {
      adminUserId,
      tokenHash,
      tokenPrefix,
      createdByAdminId,
      expiresAt: Date.now() + ttlMs,
      updatedAt: Date.now(),
    });
    return null;
  },
});

/** Resolve a valid (unconsumed, unexpired) invite by its token hash. */
export const inviteByTokenHash = internalQuery({
  args: { tokenHash: v.string() },
  handler: async (ctx, { tokenHash }) => {
    const row = await ctx.db
      .query('adminInvites')
      .withIndex('by_token_hash', (q) => q.eq('tokenHash', tokenHash))
      .unique();
    if (!row || row.consumedAt || row.expiresAt <= Date.now()) return null;
    return { inviteId: row._id, adminUserId: row.adminUserId };
  },
});

/**
 * Atomically mark an invite consumed (single-use gate). Returns {ok:false} if it
 * was already consumed (a race), so the caller can abort before inserting a
 * second credential.
 */
export const consumeInvite = internalMutation({
  args: { inviteId: v.id('adminInvites') },
  handler: async (ctx, { inviteId }) => {
    const row = await ctx.db.get(inviteId);
    if (!row || row.consumedAt) return { ok: false as const };
    await ctx.db.patch(inviteId, { consumedAt: Date.now(), updatedAt: Date.now() });
    return { ok: true as const };
  },
});

/** Cron: delete a page of expired invite rows (consumed ones age out by expiry too). */
export const sweepExpiredInvites = internalMutation({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }) => {
    await recordHeartbeat(ctx, 'admin-invite-sweep');
    const expired = await ctx.db
      .query('adminInvites')
      .withIndex('by_expires', (q) => q.lt('expiresAt', Date.now()))
      .take(limit ?? 500);
    for (const row of expired) await ctx.db.delete(row._id);
    return { removed: expired.length };
  },
});
