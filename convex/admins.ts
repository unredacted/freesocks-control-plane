/**
 * Admin + passkey data layer (P6c). The WebAuthn ceremonies themselves live in
 * convex/webauthn.ts (a "use node" action module, since @simplewebauthn needs
 * Node); this file holds the queries + mutations they orchestrate via
 * ctx.runQuery/runMutation. Challenge consume + counter bump are mutations so
 * they're race-safe (serializable), giving the replay/TOCTOU guarantees the old
 * Hono+D1 code relied on transactions for.
 */
import { internalMutation, internalQuery, query } from './_generated/server';
import { v } from 'convex/values';

// --- bootstrap status (PUBLIC: drives the SPA's bootstrap-vs-login decision) ---

/**
 * Whether any admin has completed registration (≥1 passkey), and whether the
 * first-run bootstrap path is open. An admin_users row with no credential is an
 * abandoned bootstrap attempt and doesn't count. `signedIn` is added by the
 * HTTP layer (it reads the cookie); this query is cookie-blind.
 */
export const bootstrapStatus = query({
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
    const rows = await ctx.db
      .query('webauthnRegistrationChallenges')
      .withIndex('by_admin_expires', (q) => q.eq('adminUserId', adminUserId))
      .collect();
    const row = rows
      .filter((r) => !r.consumedAt && r.expiresAt > now)
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
