/**
 * Rate-limit counters (P6): replaces the KV `rateLimit` namespace. Unlike the
 * old best-effort KV limiter (which could be raced past its cap because KV is
 * eventually-consistent and non-transactional), this is a STRICT counter:
 * `checkAndIncrement` runs as a serializable mutation, so concurrent callers
 * conflict on the bucket row and the cap holds exactly. A fixed window anchored
 * at the first hit; the row resets once it expires (and a daily cron sweeps
 * stragglers). The bucket key encodes the subject + window granularity, e.g.
 * `account-login:ip:<ipHash>` or `account-login:prefix:<1234>`.
 *
 * W2 (launch): `enforce` is the policy-driven entry point — it resolves an
 * admin-tunable {max, windowMs, enabled} from appSettings (fail-safe fallback to
 * the compiled default) and then runs the same strict counter. Call sites pass a
 * policy key + an already-shaped subject (hashed IP, userId, 4-digit prefix, …).
 */
import { internalMutation, internalQuery } from './_generated/server';
import type { MutationCtx } from './_generated/server';
import { internal } from './_generated/api';
import { recordHeartbeat } from './cronHeartbeat';
import { ConvexError, v } from 'convex/values';
import {
  RATE_LIMIT_DEFAULTS,
  RATE_LIMIT_KEYS,
  isRateLimitPolicyKey,
  policySettingKey,
  resolvePolicy,
  type RateLimitPolicyKey,
} from './lib/rateLimitPolicy';
import { writeAuditLog } from './lib/audit';

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterMs: number;
}

/** Matches retention.ts: bound the immediate re-run chain (see sweepExpired). */
const MAX_DRAIN_ROUNDS = 50;

/** The strict fixed-window counter, shared by checkAndIncrement + enforce. */
async function incrementBucket(
  ctx: MutationCtx,
  bucket: string,
  max: number,
  windowMs: number,
): Promise<RateLimitResult> {
  const now = Date.now();
  const row = await ctx.db
    .query('rateLimits')
    .withIndex('by_bucket', (q) => q.eq('bucket', bucket))
    .unique();

  // No row, or the window has elapsed → start a fresh window.
  if (!row || row.expiresAt <= now) {
    if (row) await ctx.db.patch(row._id, { count: 1, expiresAt: now + windowMs });
    else await ctx.db.insert('rateLimits', { bucket, count: 1, expiresAt: now + windowMs });
    return { allowed: true, remaining: Math.max(0, max - 1), retryAfterMs: 0 };
  }

  if (row.count >= max) {
    return { allowed: false, remaining: 0, retryAfterMs: row.expiresAt - now };
  }
  await ctx.db.patch(row._id, { count: row.count + 1 });
  return { allowed: true, remaining: Math.max(0, max - row.count - 1), retryAfterMs: 0 };
}

export const checkAndIncrement = internalMutation({
  args: { bucket: v.string(), max: v.number(), windowMs: v.number() },
  handler: (ctx, { bucket, max, windowMs }) => incrementBucket(ctx, bucket, max, windowMs),
});

/**
 * Policy-driven limit. Resolves the admin-tunable policy for `policyKey`, and if
 * enabled runs the strict counter on `<policyKey>:<subject>`. A disabled policy
 * is allowed-through (the operator's deliberate choice). An UNKNOWN key throws
 * (fail closed): a call-site typo must be a loud 500 during development, never
 * a silently unthrottled route.
 */
export const enforce = internalMutation({
  args: { policyKey: v.string(), subject: v.string() },
  handler: async (ctx, { policyKey, subject }): Promise<RateLimitResult> => {
    if (!isRateLimitPolicyKey(policyKey)) {
      throw new Error(`[rateLimits] enforce called with unknown policy key "${policyKey}"`);
    }
    const policy = await resolvePolicy(ctx.db, policyKey);
    if (!policy.enabled) return { allowed: true, remaining: -1, retryAfterMs: 0 };
    return incrementBucket(ctx, `${policyKey}:${subject}`, policy.max, policy.windowMs);
  },
});

/**
 * Compensating decrement: hand one unit back on a bucket (floored at 0). Used
 * only by flows that RESERVE a slot (increment) before a fallible side effect —
 * e.g. free-account creation — so a transient failure doesn't burn the subject's
 * daily allowance. No-op if the bucket is missing/empty (policy disabled, or the
 * window already reset). Never fails open (it only ever LOWERS a counter).
 */
export const release = internalMutation({
  args: { policyKey: v.string(), subject: v.string() },
  handler: async (ctx, { policyKey, subject }) => {
    if (!isRateLimitPolicyKey(policyKey)) return null;
    const row = await ctx.db
      .query('rateLimits')
      .withIndex('by_bucket', (q) => q.eq('bucket', `${policyKey}:${subject}`))
      .unique();
    if (row && row.count > 0) await ctx.db.patch(row._id, { count: row.count - 1 });
    return null;
  },
});

/** Resolve a single policy (used by actions that need `max` up front, e.g. the free cap). */
export const getPolicy = internalQuery({
  args: { policyKey: v.string() },
  handler: async (ctx, { policyKey }) => {
    if (!isRateLimitPolicyKey(policyKey)) return null;
    return resolvePolicy(ctx.db, policyKey);
  },
});

/** All policies with their resolved (effective) values + whether each is a default. */
export const listPolicies = internalQuery({
  args: {},
  handler: async (ctx) => {
    const out = [];
    for (const key of RATE_LIMIT_KEYS) {
      const effective = await resolvePolicy(ctx.db, key);
      const def = RATE_LIMIT_DEFAULTS[key];
      out.push({
        key,
        max: effective.max,
        windowMs: effective.windowMs,
        enabled: effective.enabled,
        isDefault:
          effective.max === def.max &&
          effective.windowMs === def.windowMs &&
          effective.enabled === def.enabled,
        default: def,
      });
    }
    return out;
  },
});

export const RATE_LIMIT_POLICY_KEYS: readonly RateLimitPolicyKey[] = RATE_LIMIT_KEYS;

const DAY_MS = 7 * 86_400_000;

/**
 * Admin write: retune one rate-limit policy (W2). Validates the values, persists
 * the override as a JSON appSettings row under `ratelimit.<key>`, and audits the
 * change. Setting a policy back to its compiled default still writes a row (so
 * the audit trail shows the deliberate choice); the resolver treats it as the
 * default value either way.
 */
export const setPolicy = internalMutation({
  args: {
    policyKey: v.string(),
    max: v.number(),
    windowMs: v.number(),
    enabled: v.boolean(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { policyKey, max, windowMs, enabled, actorAdminId }) => {
    if (!isRateLimitPolicyKey(policyKey)) {
      throw new ConvexError({
        code: 'validation',
        message: `Unknown rate-limit policy "${policyKey}"`,
      });
    }
    if (!Number.isInteger(max) || max < 1 || max > 1_000_000) {
      throw new ConvexError({
        code: 'validation',
        message: 'max must be an integer in [1, 1000000]',
      });
    }
    if (!Number.isInteger(windowMs) || windowMs < 1000 || windowMs > DAY_MS) {
      throw new ConvexError({
        code: 'validation',
        message: 'windowMs must be an integer in [1000, 604800000] (1s..7d)',
      });
    }
    const settingKey = policySettingKey(policyKey);
    const value = JSON.stringify({ max, windowMs, enabled });
    const existing = await ctx.db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', settingKey))
      .unique();
    const now = Date.now();
    if (existing)
      await ctx.db.patch(existing._id, { value, updatedByAdminId: actorAdminId, updatedAt: now });
    else
      await ctx.db.insert('appSettings', {
        key: settingKey,
        value,
        updatedByAdminId: actorAdminId,
        updatedAt: now,
      });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId,
      action: 'settings.ratelimit_change',
      targetType: 'rate_limit_policy',
      targetId: policyKey,
      payload: { policyKey, max, windowMs, enabled },
    });
    return { ok: true as const };
  },
});

/**
 * Admin write: revert one policy to its compiled default by DELETING the stored
 * `ratelimit.<key>` override row (so `resolvePolicy` falls back to the compiled
 * default). Idempotent — a policy that's already at the default (no row) is a
 * no-op that still audits the deliberate action. Audited under the same
 * `settings.ratelimit_change` action, with the compiled-default values in the
 * payload so the log reads consistently with a set.
 */
export const resetPolicy = internalMutation({
  args: {
    policyKey: v.string(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { policyKey, actorAdminId }) => {
    if (!isRateLimitPolicyKey(policyKey)) {
      throw new ConvexError({
        code: 'validation',
        message: `Unknown rate-limit policy "${policyKey}"`,
      });
    }
    const settingKey = policySettingKey(policyKey);
    const existing = await ctx.db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', settingKey))
      .unique();
    if (existing) await ctx.db.delete(existing._id);
    const def = RATE_LIMIT_DEFAULTS[policyKey];
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId,
      action: 'settings.ratelimit_change',
      targetType: 'rate_limit_policy',
      targetId: policyKey,
      payload: {
        policyKey,
        max: def.max,
        windowMs: def.windowMs,
        enabled: def.enabled,
      },
    });
    return { ok: true as const };
  },
});

/** Cron: delete a page of elapsed rate-limit windows. A FULL page re-runs
 *  immediately (drain-chain, same pattern as retention.ts). */
export const sweepExpired = internalMutation({
  args: { limit: v.optional(v.number()), rounds: v.optional(v.number()) },
  handler: async (ctx, { limit, rounds }) => {
    await recordHeartbeat(ctx, 'rate-limit-sweep');
    const now = Date.now();
    const page = limit ?? 500;
    const expired = await ctx.db
      .query('rateLimits')
      .withIndex('by_expires', (q) => q.lt('expiresAt', now))
      .take(page);
    for (const row of expired) await ctx.db.delete(row._id);
    if (expired.length === page) {
      const n = rounds ?? 0;
      if (n >= MAX_DRAIN_ROUNDS)
        console.warn('[rate-limit-sweep] drain cap hit; remainder next run');
      else await ctx.scheduler.runAfter(0, internal.rateLimits.sweepExpired, { rounds: n + 1 });
    }
    return { removed: expired.length };
  },
});
