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
  /** Active users on a default-free tier — the "free users helped" impact stat.
   *  Maintained by the daily reconcile ONLY (a status delta doesn't know tier
   *  membership); per-transition bumps preserve it via read-full/write-full. */
  freeActive: number;
}

const ZERO: UserCounts = {
  active: 0,
  grace: 0,
  disabled: 0,
  deleted: 0,
  inactive: 0,
  backendDrift: 0,
  freeActive: 0,
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

// === Session counter (2026-09-04 prod incident) =============================
// `adminApi.statusSummary` used to `.collect()` every live session for the PoP
// readiness tally; prod crossed Convex's per-execution read limit (32k docs) and
// the whole endpoint 500-ed. Same cure as userCounts: one hot `appState` row
// (`stats:sessionCounts`) bumped at every session insert/delete (all of which
// live in sessions.ts + the lifecycle hard-delete cascade), rebuilt exactly by
// `userStats.reconcileSessionCounts`. The counter tracks rows PRESENT, so a
// session that silently ages past its TTL is counted until the (daily) sweep
// deletes it — a conservative, bounded overstatement (≈ one day of expiries).

export const SESSION_COUNTS_KEY = 'stats:sessionCounts';

export type SessionBucket = 'bound' | 'unboundMember' | 'unboundAdmin';

export interface SessionCounts {
  /** PoP-bound sessions (member or admin) — a captured cookie alone can't replay. */
  bound: number;
  unboundMember: number;
  unboundAdmin: number;
}

export const ZERO_SESSION_COUNTS: SessionCounts = { bound: 0, unboundMember: 0, unboundAdmin: 0 };

/** Which counter bucket a session row belongs to. */
export function sessionBucket(row: {
  kind: 'member' | 'admin';
  popPublicKey?: string | undefined;
}): SessionBucket {
  if (row.popPublicKey != null) return 'bound';
  return row.kind === 'admin' ? 'unboundAdmin' : 'unboundMember';
}

export async function readSessionCounts(db: DatabaseReader): Promise<SessionCounts> {
  const row = await db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', SESSION_COUNTS_KEY))
    .unique();
  if (!row) return { ...ZERO_SESSION_COUNTS };
  try {
    return { ...ZERO_SESSION_COUNTS, ...(JSON.parse(row.value) as Partial<SessionCounts>) };
  } catch {
    return { ...ZERO_SESSION_COUNTS };
  }
}

export async function writeSessionCounts(ctx: MutationCtx, counts: SessionCounts): Promise<void> {
  const row = await ctx.db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', SESSION_COUNTS_KEY))
    .unique();
  const value = JSON.stringify(counts);
  if (row) await ctx.db.patch(row._id, { value, updatedAt: Date.now() });
  else await ctx.db.insert('appState', { key: SESSION_COUNTS_KEY, value, updatedAt: Date.now() });
}

/** Bump buckets by signed deltas inside the caller's transaction (clamped ≥ 0 so
 *  a pre-reconcile deployment never goes negative). A no-op for all-zero deltas. */
export async function applySessionDelta(
  ctx: MutationCtx,
  deltas: Partial<Record<SessionBucket, number>>,
): Promise<void> {
  const entries = Object.entries(deltas).filter(([, d]) => d !== 0) as [SessionBucket, number][];
  if (entries.length === 0) return;
  const counts = await readSessionCounts(ctx.db);
  for (const [bucket, d] of entries) counts[bucket] = Math.max(0, counts[bucket] + d);
  await writeSessionCounts(ctx, counts);
}
