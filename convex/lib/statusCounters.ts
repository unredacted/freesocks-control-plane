/**
 * Maintained user-status counters (M2 / WS3). `adminApi.statusSummary` used to
 * `collect()` the whole users table — an O(users) read that throws past Convex's
 * per-query read limit (500-ing the /status health-gate). Instead we keep a single
 * hot counter row in `appState` (key `stats:userCounts`), bumped on every status
 * transition, and `reconcileUserCounts` (userStats.ts) rebuilds it exactly + self-
 * heals any drift. Read-modify-write inside the caller's own transaction; the
 * Math.max(0,…) clamp keeps it fail-safe before the first reconcile/backfill.
 */
import type { MutationCtx, DatabaseReader } from '../_generated/server';

export const USER_COUNTS_KEY = 'stats:userCounts';

export type UserStatusName = 'active' | 'grace' | 'disabled' | 'deleted' | 'inactive';

export interface UserCounts {
  active: number;
  grace: number;
  disabled: number;
  deleted: number;
  inactive: number;
  /** Users whose last backend push failed and hasn't recovered (entitlement drift). */
  backendDrift: number;
}

const ZERO: UserCounts = {
  active: 0,
  grace: 0,
  disabled: 0,
  deleted: 0,
  inactive: 0,
  backendDrift: 0,
};

export async function readUserCounts(db: DatabaseReader): Promise<UserCounts> {
  const row = await db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', USER_COUNTS_KEY))
    .unique();
  if (!row) return { ...ZERO };
  try {
    return { ...ZERO, ...(JSON.parse(row.value) as Partial<UserCounts>) };
  } catch {
    return { ...ZERO };
  }
}

export async function writeUserCounts(ctx: MutationCtx, counts: UserCounts): Promise<void> {
  const row = await ctx.db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', USER_COUNTS_KEY))
    .unique();
  const value = JSON.stringify(counts);
  if (row) await ctx.db.patch(row._id, { value, updatedAt: Date.now() });
  else await ctx.db.insert('appState', { key: USER_COUNTS_KEY, value, updatedAt: Date.now() });
}

/**
 * Apply a status transition to the counter. `statusFrom`/`statusTo` null = "none"
 * (creation → only `statusTo`; hard-delete → only `statusFrom`). Reading `statusFrom`
 * from the row at the call site makes a no-op transition (from===to) self-cancel and
 * a re-applied transition idempotent. `driftDelta` bumps the backend-drift tally.
 */
export async function applyCountsDelta(
  ctx: MutationCtx,
  d: { statusFrom?: UserStatusName | null; statusTo?: UserStatusName | null; driftDelta?: number },
): Promise<void> {
  const counts = await readUserCounts(ctx.db);
  if (d.statusFrom) counts[d.statusFrom] = Math.max(0, counts[d.statusFrom] - 1);
  if (d.statusTo) counts[d.statusTo] = Math.max(0, counts[d.statusTo] + 1);
  if (d.driftDelta) counts.backendDrift = Math.max(0, counts.backendDrift + d.driftDelta);
  await writeUserCounts(ctx, counts);
}
