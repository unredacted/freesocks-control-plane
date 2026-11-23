/**
 * Epoch-key store (CDN-blinding Phase 3). Rows are minted by the rotate cron
 * (which calls the "use node" generator in lib/hpkeCrypto.ts, the only place the
 * X-Wing keypair + manifest signature can be produced) and read on the login
 * path: the current epoch public key is published by the key endpoint.
 * Private seeds live in the separate volatile seed store.
 */
import { internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import { recordHeartbeat } from './cronHeartbeat';
import { v } from 'convex/values';
import { writeAuditLog } from './lib/audit';

/** Keep an expired epoch openable for this long so in-flight requests sealed to a
 *  just-retired key still decrypt, then destroy its secret. */
export const EPOCH_SWEEP_GRACE_MS = 10 * 60_000;

/** Matches retention.ts: bound the immediate re-run chain (see sweepExpired). */
const MAX_DRAIN_ROUNDS = 50;

/**
 * Cron entry point for epoch rotation. Gates in the ISOLATE runtime: while
 * HPKE ships dark (FS_MANIFEST_SK unset) each cron tick would cold-start a
 * Node action just to early-return. Per-tick gating (not conditional
 * cron registration) so `convex env set FS_MANIFEST_SK` activates rotation on
 * the next tick without a redeploy; rotateEpochKey keeps its own skip as
 * belt-and-braces.
 */
export const maybeRotate = internalMutation({
  args: {},
  handler: async (ctx) => {
    await recordHeartbeat(ctx, 'epoch-key-rotate');
    if (!process.env.FS_MANIFEST_SK) return null;
    // Rotation-gap alarm: epochs EXIST but none is currently valid — at least
    // 3 consecutive rotates failed (10-min cadence, 30-min validity), and
    // manifest-pinned clients cannot send sealed requests. (First-ever run,
    // zero rows, is fine: maintenance mints the first epoch.)
    const now = Date.now();
    const latest = await ctx.db
      .query('keyEpochs')
      .withIndex('by_not_before', (q) => q.lte('notBefore', now))
      .order('desc')
      .first();
    // The cron ticks every minute: alarm at the start of a gap, then hourly.
    const gapMinutes = latest ? Math.floor((now - latest.notAfter) / 60_000) : -1;
    if (latest && latest.notAfter <= now && gapMinutes % 60 === 0) {
      console.warn(
        `[keyEpochs] no currently-valid epoch while FS_MANIFEST_SK is set — ` +
          `rotation appears wedged; manifest-pinned clients cannot send sealed requests`,
      );
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'hpke.epoch_gap',
        targetType: 'key_epoch',
        payload: { lastNotAfter: latest.notAfter },
      });
    }
    await ctx.scheduler.runAfter(0, internal.lib.hpkeCrypto.maintainEpoch, {});
    return null;
  },
});

const REMINT_KEY = 'hpke:remintRequestedAt';
const REMINT_THROTTLE_MS = 20_000;

/**
 * The key endpoint found no live epoch (the volatile store restarted, or a
 * rotation failed): mint one now instead of at the next cron tick, since a
 * manifest-pinned client cannot seal a login until one exists. Throttled so a
 * burst of clients schedules one maintenance run, not one each.
 */
export const requestRemint = internalMutation({
  args: {},
  handler: async (ctx) => {
    if (!process.env.FS_MANIFEST_SK) return null;
    const now = Date.now();
    const row = await ctx.db
      .query('appState')
      .withIndex('by_key', (q) => q.eq('key', REMINT_KEY))
      .unique();
    if (row && now - Number(row.value) < REMINT_THROTTLE_MS) return null;
    if (row) await ctx.db.patch(row._id, { value: String(now), updatedAt: now });
    else await ctx.db.insert('appState', { key: REMINT_KEY, value: String(now), updatedAt: now });
    await ctx.scheduler.runAfter(0, internal.lib.hpkeCrypto.maintainEpoch, {});
    return null;
  },
});

export const insert = internalMutation({
  args: {
    kid: v.string(),
    publicKey: v.string(),
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
    if (!row || row.seed !== undefined || row.notAfter <= now) return null;
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

/** Resolve the public lifetime for a kid before using the separate seed store. */
export const byKid = internalQuery({
  args: { kid: v.string() },
  handler: async (ctx, { kid }) => {
    const row = await ctx.db
      .query('keyEpochs')
      .withIndex('by_kid', (q) => q.eq('kid', kid))
      .unique();
    if (!row || row.seed !== undefined || row.notAfter + EPOCH_SWEEP_GRACE_MS <= Date.now())
      return null;
    return { notAfter: row.notAfter };
  },
});

/** Purge private seed fields left by older deployments or an old snapshot. */
export const stripLegacySeeds = internalMutation({
  args: { cursor: v.union(v.string(), v.null()) },
  handler: async (ctx, { cursor }) => {
    const batch = await ctx.db.query('keyEpochs').paginate({ cursor, numItems: 200 });
    for (const row of batch.page) {
      if (row.seed !== undefined) await ctx.db.delete(row._id);
    }
    return { cursor: batch.continueCursor, isDone: batch.isDone };
  },
});

/** Cron: remove public metadata after an epoch's validity and grace have elapsed.
 *  A FULL page re-runs immediately (drain-chain, same pattern as retention.ts)
 *  — 144 epochs mint/day vs a 100-row page means one page/day falls behind. */
export const sweepExpired = internalMutation({
  args: { limit: v.optional(v.number()), rounds: v.optional(v.number()) },
  handler: async (ctx, { limit, rounds }) => {
    await recordHeartbeat(ctx, 'epoch-key-sweep');
    const cutoff = Date.now() - EPOCH_SWEEP_GRACE_MS;
    const page = limit ?? 100;
    const expired = await ctx.db
      .query('keyEpochs')
      .withIndex('by_expires', (q) => q.lt('notAfter', cutoff))
      .take(page);
    for (const row of expired) await ctx.db.delete(row._id);
    if (expired.length === page) {
      const n = rounds ?? 0;
      if (n >= MAX_DRAIN_ROUNDS)
        console.warn('[epoch-key-sweep] drain cap hit; remainder next run');
      else await ctx.scheduler.runAfter(0, internal.keyEpochs.sweepExpired, { rounds: n + 1 });
    }
    return { removed: expired.length };
  },
});
