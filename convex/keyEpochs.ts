/**
 * Epoch-key store (CDN-blinding Phase 3). Rows are minted by the rotate cron
 * (which calls the "use node" generator in lib/e2eeCrypto.ts, the only place the
 * X-Wing keypair + manifest signature can be produced) and read on the login
 * path: the current epoch key is published via /config, and openRequest resolves
 * an inbound envelope's epoch kid back to its seed here.
 *
 * The `seed` field is a short-lived secret destroyed by sweepExpired; never log
 * it or return it from a public query. `current`/`byKid` deliberately return the
 * fields the caller needs (public key, sig, validity) plus the seed only to the
 * internal open path.
 */
import { internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import { recordHeartbeat } from './cronHeartbeat';
import { v } from 'convex/values';

/** Keep an expired epoch openable for this long so in-flight requests sealed to a
 *  just-retired key still decrypt, then destroy its secret. */
export const EPOCH_SWEEP_GRACE_MS = 10 * 60_000;

/**
 * Cron entry point for epoch rotation. Gates in the ISOLATE runtime: while
 * E2EE ships dark (FS_MANIFEST_SK unset) the 10-min cron used to cold-start a
 * Node action 144x/day just to early-return. Per-tick gating (not conditional
 * cron registration) so `convex env set FS_MANIFEST_SK` activates rotation on
 * the next tick without a redeploy; rotateEpochKey keeps its own skip as
 * belt-and-braces.
 */
export const maybeRotate = internalMutation({
  args: {},
  handler: async (ctx) => {
    await recordHeartbeat(ctx, 'epoch-key-rotate');
    if (!process.env.FS_MANIFEST_SK) return null;
    await ctx.scheduler.runAfter(0, internal.lib.e2eeCrypto.rotateEpochKey, {});
    return null;
  },
});

export const insert = internalMutation({
  args: {
    kid: v.string(),
    publicKey: v.string(),
    seed: v.string(),
    manifestSig: v.string(),
    manifestSigPq: v.optional(v.string()),
    notBefore: v.number(),
    notAfter: v.number(),
  },
  handler: async (ctx, row) => {
    await ctx.db.insert('keyEpochs', row);
    return null;
  },
});

/** The newest currently-valid epoch (notBefore <= now < notAfter), or null. */
export const current = internalQuery({
  args: {},
  handler: async (ctx) => {
    const now = Date.now();
    const row = await ctx.db
      .query('keyEpochs')
      .withIndex('by_not_before', (q) => q.lte('notBefore', now))
      .order('desc')
      .first();
    if (!row || row.notAfter <= now) return null;
    return {
      kid: row.kid,
      publicKey: row.publicKey,
      manifestSig: row.manifestSig,
      manifestSigPq: row.manifestSigPq,
      notBefore: row.notBefore,
      notAfter: row.notAfter,
    };
  },
});

/** Resolve an epoch by kid for the open path (returns the seed). Null if unknown. */
export const byKid = internalQuery({
  args: { kid: v.string() },
  handler: async (ctx, { kid }) => {
    const row = await ctx.db
      .query('keyEpochs')
      .withIndex('by_kid', (q) => q.eq('kid', kid))
      .unique();
    if (!row) return null;
    return { seed: row.seed, notAfter: row.notAfter };
  },
});

/** Cron: destroy epochs whose validity + grace has elapsed (forward secrecy). */
export const sweepExpired = internalMutation({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }) => {
    await recordHeartbeat(ctx, 'epoch-key-sweep');
    const cutoff = Date.now() - EPOCH_SWEEP_GRACE_MS;
    const expired = await ctx.db
      .query('keyEpochs')
      .withIndex('by_expires', (q) => q.lt('notAfter', cutoff))
      .take(limit ?? 100);
    for (const row of expired) await ctx.db.delete(row._id);
    return { removed: expired.length };
  },
});
