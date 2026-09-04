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
//
// Exactness under concurrency (review P1): a reconcile scan spans many
// transactions, so a write landing mid-scan is ambiguous — is it already in the
// scanned total or not? We remove the ambiguity by construction:
//   • `begin` pins startTs = the newest session's _creationTime visible to it.
//     Every later commit gets a larger _creationTime, so the scan (≤ startTs)
//     covers a FIXED set of rows and a create during the scan is never in it.
//   • While a reconcile is open, bumps for rows with _creationTime > startTs
//     (all creates, and deletes of those creates) are ALSO recorded in a
//     `journal`. Deletes of rows ≤ startTs are not journaled: the scan already
//     accounts for them (absent if deleted before the page was read; present
//     — a one-off overcount in the safe direction — if deleted after).
//   • `finish` writes scanned + journal, replacing the live figures.
// The row also carries `initialized` (review P2): until the first successful
// reconcile the counts are unknown, statusSummary reports NOT ready, and bumps
// on a missing row are no-ops (finish overwrites whatever they'd have built).

export const SESSION_COUNTS_KEY = 'stats:sessionCounts';

export type SessionBucket = 'bound' | 'unboundMember' | 'unboundAdmin';

export interface SessionCounts {
  /** PoP-bound sessions (member or admin) — a captured cookie alone can't replay. */
  bound: number;
  unboundMember: number;
  unboundAdmin: number;
}

export const ZERO_SESSION_COUNTS: SessionCounts = { bound: 0, unboundMember: 0, unboundAdmin: 0 };

/** Persisted shape of the `stats:sessionCounts` row's JSON value. */
interface SessionCounterState extends SessionCounts {
  /** False until the first reconcile finished (counts are meaningless before). */
  initialized: boolean;
  /** Present only while a reconcile is in flight (begin → finish). */
  reconcile?: { startTs: number; journal: SessionCounts };
}

/** Which counter bucket a session row belongs to. */
export function sessionBucket(row: {
  kind: 'member' | 'admin';
  popPublicKey?: string | undefined;
}): SessionBucket {
  if (row.popPublicKey != null) return 'bound';
  return row.kind === 'admin' ? 'unboundAdmin' : 'unboundMember';
}

function parseState(value: string): SessionCounterState {
  try {
    const raw = JSON.parse(value) as Partial<SessionCounterState>;
    return {
      ...ZERO_SESSION_COUNTS,
      initialized: raw.initialized === true,
      ...(raw.reconcile
        ? {
            reconcile: {
              startTs: raw.reconcile.startTs,
              journal: { ...ZERO_SESSION_COUNTS, ...raw.reconcile.journal },
            },
          }
        : {}),
      bound: raw.bound ?? 0,
      unboundMember: raw.unboundMember ?? 0,
      unboundAdmin: raw.unboundAdmin ?? 0,
    };
  } catch {
    return { ...ZERO_SESSION_COUNTS, initialized: false };
  }
}

async function readRow(db: DatabaseReader) {
  return db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', SESSION_COUNTS_KEY))
    .unique();
}

async function writeState(ctx: MutationCtx, state: SessionCounterState): Promise<void> {
  const row = await readRow(ctx.db);
  const value = JSON.stringify(state);
  if (row) await ctx.db.patch(row._id, { value, updatedAt: Date.now() });
  else await ctx.db.insert('appState', { key: SESSION_COUNTS_KEY, value, updatedAt: Date.now() });
}

/** The live counts + whether they mean anything yet. Missing row ⇒ uninitialized
 *  zeros (statusSummary fails CLOSED on readiness until the first reconcile). */
export async function readSessionCounts(
  db: DatabaseReader,
): Promise<{ counts: SessionCounts; initialized: boolean }> {
  const row = await readRow(db);
  if (!row) return { counts: { ...ZERO_SESSION_COUNTS }, initialized: false };
  const st = parseState(row.value);
  return {
    counts: { bound: st.bound, unboundMember: st.unboundMember, unboundAdmin: st.unboundAdmin },
    initialized: st.initialized,
  };
}

/** One session row's contribution: its bucket + its _creationTime (the journal
 *  boundary test). `sign` = +1 for an insert, −1 for a delete. */
export interface SessionBump {
  bucket: SessionBucket;
  creationTime: number;
}

/** Apply inserts/deletes to the live counter inside the caller's transaction
 *  (clamped ≥ 0). No-op while the row doesn't exist yet — the first reconcile
 *  creates it. While a reconcile is open, rows newer than its startTs are also
 *  journaled (see the header). */
export async function bumpSessionCounts(
  ctx: MutationCtx,
  rows: readonly SessionBump[],
  sign: 1 | -1,
): Promise<void> {
  if (rows.length === 0) return;
  const row = await readRow(ctx.db);
  if (!row) return;
  const st = parseState(row.value);
  for (const r of rows) {
    st[r.bucket] = Math.max(0, st[r.bucket] + sign);
    if (st.reconcile && r.creationTime > st.reconcile.startTs) {
      st.reconcile.journal[r.bucket] += sign;
    }
  }
  await ctx.db.patch(row._id, { value: JSON.stringify(st), updatedAt: Date.now() });
}

/** Open a reconcile: pin the scan boundary + a fresh journal. Creates the row
 *  (uninitialized) when absent. Returns the boundary the scan must use
 *  (`_creationTime <= startTs`). A second `begin` while one is open simply
 *  supersedes it — the stale `finish` then sees a mismatched startTs and skips. */
export async function beginSessionReconcile(ctx: MutationCtx): Promise<number> {
  const newest = await ctx.db.query('sessions').order('desc').first();
  const startTs = newest?._creationTime ?? 0;
  const row = await readRow(ctx.db);
  const st: SessionCounterState = row
    ? parseState(row.value)
    : { ...ZERO_SESSION_COUNTS, initialized: false };
  st.reconcile = { startTs, journal: { ...ZERO_SESSION_COUNTS } };
  await writeState(ctx, st);
  return startTs;
}

/** Close the reconcile opened with `startTs`: live = scanned + journal, mark
 *  initialized. Returns false (no write) if another reconcile superseded it. */
export async function finishSessionReconcile(
  ctx: MutationCtx,
  startTs: number,
  scanned: SessionCounts,
): Promise<boolean> {
  const row = await readRow(ctx.db);
  if (!row) return false;
  const st = parseState(row.value);
  if (!st.reconcile || st.reconcile.startTs !== startTs) return false;
  const next: SessionCounterState = {
    bound: Math.max(0, scanned.bound + st.reconcile.journal.bound),
    unboundMember: Math.max(0, scanned.unboundMember + st.reconcile.journal.unboundMember),
    unboundAdmin: Math.max(0, scanned.unboundAdmin + st.reconcile.journal.unboundAdmin),
    initialized: true,
  };
  await ctx.db.patch(row._id, { value: JSON.stringify(next), updatedAt: Date.now() });
  return true;
}
