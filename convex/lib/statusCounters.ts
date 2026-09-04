/**
 * Maintained counters (M2 / WS3 + the 2026-09-04 prod incident). Reading a
 * traffic-scaled table wholesale trips Convex's per-execution read limit
 * (32k documents / 8 MiB) — `adminApi.statusSummary` 500-ed on it twice: the
 * users tally (2026-06) and the live-sessions PoP tally (2026-09-04). Each
 * figure therefore lives in a hot `appState` row bumped inside the transaction
 * that changes it, and is rebuilt exactly by a paginated reconcile.
 *
 * Exactness under concurrency (the naive live+(scanned−baseline) delta write
 * double-applied any change landing before the scan reached its row — review
 * P1). One protocol for every counter here:
 *   • `begin` pins startTs = the newest row's `_creationTime` visible to it.
 *     Every later commit gets a strictly larger `_creationTime`, so the scan
 *     covers a FIXED set of rows (≤ startTs) and a row created mid-scan is
 *     never in it.
 *   • The scan advances a `scanPos` boundary; each page is read AND its
 *     scanPos recorded in the SAME mutation, so for any concurrent change on
 *     row c there is no gap: either the scan already saw c's new state
 *     (c > scanPos when the change committed → nothing to add) or the scan
 *     will never see it (c ≤ scanPos, already read with the old state — or
 *     c > startTs, outside the set) → the change is recorded in a `journal`.
 *     A page that ends on a shared `_creationTime` pulls the rest of that
 *     timestamp in, so scanPos never splits equal timestamps.
 *   • `finish` writes scanned + journal, and skips if a newer `begin`
 *     superseded it.
 * The row also carries `initialized` (review P2): until the first reconcile
 * completed, the counts are unknown — readers that make safety decisions on
 * them (`pop.readyToEnable`) fail CLOSED. Rows written before the flag existed
 * read as `legacyInitialized` (users: exact prod rows → true).
 */
import type { MutationCtx, DatabaseReader } from '../_generated/server';
import type { Doc, TableNames } from '../_generated/dataModel';

// ---------------------------------------------------------------------------
// Generic protocol
// ---------------------------------------------------------------------------

export interface CounterSpec<C extends Record<string, number>, T extends TableNames> {
  /** The `appState` key. */
  key: string;
  /** The table the reconcile scans. */
  table: T;
  zero: C;
  /** How a row lacking the `initialized` field reads. */
  legacyInitialized: boolean;
  /** Bumps on a missing row: create it (legacy behaviour) or no-op (fail-closed;
   *  the first reconcile creates the row and overwrites anything bumps would
   *  have built). */
  createOnBump: boolean;
}

interface ReconcileState<C> {
  /** Run token (a persisted sequence, so two `begin`s that pin the same
   *  boundary are still told apart); `finish` must present it. */
  token: number;
  startTs: number;
  /** `_creationTime` up to which the scan has read (inclusive). -1 = nothing yet. */
  scanPos: number;
  scanned: C;
  journal: C;
}

type CounterState<C> = {
  counts: C;
  initialized: boolean;
  /** Monotonic reconcile-run counter (survives finish, so tokens never repeat). */
  runSeq: number;
  reconcile?: ReconcileState<C>;
};

function pickCounts<C extends Record<string, number>>(zero: C, raw: unknown): C {
  const out = { ...zero };
  if (raw && typeof raw === 'object') {
    for (const k of Object.keys(zero) as (keyof C)[]) {
      const v = (raw as Record<string, unknown>)[k as string];
      if (typeof v === 'number' && Number.isFinite(v)) out[k] = v as C[keyof C];
    }
  }
  return out;
}

function parseState<C extends Record<string, number>, T extends TableNames>(
  spec: CounterSpec<C, T>,
  value: string,
): CounterState<C> {
  try {
    const raw = JSON.parse(value) as Record<string, unknown>;
    const st: CounterState<C> = {
      counts: pickCounts(spec.zero, raw),
      initialized: typeof raw.initialized === 'boolean' ? raw.initialized : spec.legacyInitialized,
      runSeq: typeof raw.runSeq === 'number' ? raw.runSeq : 0,
    };
    const rec = raw.reconcile as Partial<ReconcileState<unknown>> | undefined;
    if (rec && typeof rec.startTs === 'number' && typeof rec.token === 'number') {
      st.reconcile = {
        token: rec.token,
        startTs: rec.startTs,
        scanPos: typeof rec.scanPos === 'number' ? rec.scanPos : -1,
        scanned: pickCounts(spec.zero, rec.scanned),
        journal: pickCounts(spec.zero, rec.journal),
      };
    }
    return st;
  } catch {
    return { counts: { ...spec.zero }, initialized: false, runSeq: 0 };
  }
}

/** Flat storage: the count fields at the top level (backward compatible with
 *  the pre-protocol rows) + the two meta fields. */
function serialize<C extends Record<string, number>>(st: CounterState<C>): string {
  return JSON.stringify({
    ...st.counts,
    initialized: st.initialized,
    runSeq: st.runSeq,
    ...(st.reconcile ? { reconcile: st.reconcile } : {}),
  });
}

async function readRow(db: DatabaseReader, key: string) {
  return db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', key))
    .unique();
}

async function writeState<C extends Record<string, number>, T extends TableNames>(
  ctx: MutationCtx,
  spec: CounterSpec<C, T>,
  st: CounterState<C>,
  rowId?: Doc<'appState'>['_id'],
): Promise<void> {
  const value = serialize(st);
  if (rowId) await ctx.db.patch(rowId, { value, updatedAt: Date.now() });
  else await ctx.db.insert('appState', { key: spec.key, value, updatedAt: Date.now() });
}

export async function readCounter<C extends Record<string, number>, T extends TableNames>(
  db: DatabaseReader,
  spec: CounterSpec<C, T>,
): Promise<{ counts: C; initialized: boolean }> {
  const row = await readRow(db, spec.key);
  if (!row) return { counts: { ...spec.zero }, initialized: false };
  const st = parseState(spec, row.value);
  return { counts: st.counts, initialized: st.initialized };
}

export interface CounterDelta<C> {
  delta: Partial<C>;
  /** `_creationTime` of the row the change is about (the journal boundary test). */
  creationTime: number;
}

/** Apply signed deltas inside the caller's transaction (clamped ≥ 0) and, while
 *  a reconcile is open, journal the ones the scan cannot account for. */
export async function applyCounterDeltas<C extends Record<string, number>, T extends TableNames>(
  ctx: MutationCtx,
  spec: CounterSpec<C, T>,
  items: readonly CounterDelta<C>[],
): Promise<void> {
  const live = items.filter((it) => Object.values(it.delta).some((d) => d !== 0 && d != null));
  if (live.length === 0) return;
  const row = await readRow(ctx.db, spec.key);
  if (!row && !spec.createOnBump) return;
  const st: CounterState<C> = row
    ? parseState(spec, row.value)
    : { counts: { ...spec.zero }, initialized: spec.legacyInitialized, runSeq: 0 };
  for (const it of live) {
    const rec = st.reconcile;
    const journal =
      rec != null && (it.creationTime > rec.startTs || it.creationTime <= rec.scanPos);
    for (const [k, d] of Object.entries(it.delta) as [keyof C, number | undefined][]) {
      if (!d) continue;
      st.counts[k] = Math.max(0, st.counts[k] + d) as C[keyof C];
      if (journal && rec) rec.journal[k] = (rec.journal[k] + d) as C[keyof C];
    }
  }
  await writeState(ctx, spec, st, row?._id);
}

/** Overwrite selected count fields, preserving the others + the meta fields.
 *  (A targeted recount such as `refreshFreeActive`.) */
export async function patchCounterCounts<C extends Record<string, number>, T extends TableNames>(
  ctx: MutationCtx,
  spec: CounterSpec<C, T>,
  partial: Partial<C>,
): Promise<void> {
  const row = await readRow(ctx.db, spec.key);
  const st: CounterState<C> = row
    ? parseState(spec, row.value)
    : { counts: { ...spec.zero }, initialized: spec.legacyInitialized, runSeq: 0 };
  for (const [k, v] of Object.entries(partial) as [keyof C, number | undefined][]) {
    if (v != null) st.counts[k] = Math.max(0, v) as C[keyof C];
  }
  await writeState(ctx, spec, st, row?._id);
}

/** Open a reconcile: pin the scan boundary, reset the scan + journal. Creates
 *  the row (uninitialized) when absent. Returns the run token `finish` needs.
 *  A second `begin` while one is open supersedes it. */
export async function beginCounterReconcile<C extends Record<string, number>, T extends TableNames>(
  ctx: MutationCtx,
  spec: CounterSpec<C, T>,
): Promise<number> {
  const newest = await ctx.db.query(spec.table).order('desc').first();
  const startTs = newest?._creationTime ?? 0;
  const row = await readRow(ctx.db, spec.key);
  const st: CounterState<C> = row
    ? parseState(spec, row.value)
    : { counts: { ...spec.zero }, initialized: false, runSeq: 0 };
  const token = st.runSeq + 1;
  st.runSeq = token;
  st.reconcile = {
    token,
    startTs,
    scanPos: -1,
    scanned: { ...spec.zero },
    journal: { ...spec.zero },
  };
  await writeState(ctx, spec, st, row?._id);
  return token;
}

/** Read the next page of rows (scanPos, startTs], tally them into `scanned`,
 *  and advance scanPos — atomically, so no concurrent change can fall between
 *  "page read" and "boundary recorded". Returns whether the scan is complete.
 *  Bounded: pageSize rows + the tail of a shared timestamp. */
export async function scanCounterPage<C extends Record<string, number>, T extends TableNames>(
  ctx: MutationCtx,
  spec: CounterSpec<C, T>,
  tally: (row: Doc<T>) => Partial<C>,
  pageSize: number,
): Promise<{ done: boolean; rows: number }> {
  const row = await readRow(ctx.db, spec.key);
  if (!row) return { done: true, rows: 0 };
  const st = parseState(spec, row.value);
  const rec = st.reconcile;
  if (!rec || rec.scanPos >= rec.startTs) return { done: true, rows: 0 };
  const page = await ctx.db
    .query(spec.table)
    // `as never`: over a generic table name TS cannot resolve `_creationTime`'s
    // field type (it is `number` on every table); the values are plain numbers.
    .withIndex('by_creation_time', (q) =>
      q.gt('_creationTime', rec.scanPos as never).lte('_creationTime', rec.startTs as never),
    )
    .take(pageSize);
  if (page.length === 0) {
    rec.scanPos = rec.startTs;
    await writeState(ctx, spec, st, row._id);
    return { done: true, rows: 0 };
  }
  const last = page[page.length - 1]!._creationTime;
  let rows: Doc<T>[] = page as Doc<T>[];
  const full = page.length >= pageSize;
  if (full) {
    // Never leave part of a shared timestamp unscanned behind scanPos.
    const twins = await ctx.db
      .query(spec.table)
      .withIndex('by_creation_time', (q) => q.eq('_creationTime', last as never))
      .collect();
    const seen = new Set(page.map((r) => r._id as string));
    rows = rows.concat((twins as Doc<T>[]).filter((r) => !seen.has(r._id as string)));
  }
  for (const r of rows) {
    for (const [k, d] of Object.entries(tally(r)) as [keyof C, number | undefined][]) {
      if (d) rec.scanned[k] = (rec.scanned[k] + d) as C[keyof C];
    }
  }
  const done = !full || last >= rec.startTs;
  rec.scanPos = done ? rec.startTs : last;
  await writeState(ctx, spec, st, row._id);
  return { done, rows: rows.length };
}

/** Close the reconcile holding `token`: counts = scanned + journal, mark
 *  initialized. Returns false (no write) when a newer reconcile superseded it
 *  or the scan has not reached its boundary yet. */
export async function finishCounterReconcile<
  C extends Record<string, number>,
  T extends TableNames,
>(ctx: MutationCtx, spec: CounterSpec<C, T>, token: number): Promise<boolean> {
  const row = await readRow(ctx.db, spec.key);
  if (!row) return false;
  const st = parseState(spec, row.value);
  const rec = st.reconcile;
  // Wrong token = a newer run superseded this one; scanPos short of the boundary
  // = the scan is incomplete. Either way, writing would publish a partial count.
  if (!rec || rec.token !== token || rec.scanPos < rec.startTs) return false;
  const counts = { ...spec.zero };
  for (const k of Object.keys(spec.zero) as (keyof C)[]) {
    counts[k] = Math.max(0, rec.scanned[k] + rec.journal[k]) as C[keyof C];
  }
  await writeState(ctx, spec, { counts, initialized: true, runSeq: st.runSeq }, row._id);
  return true;
}

// ---------------------------------------------------------------------------
// Users: `stats:userCounts`
// ---------------------------------------------------------------------------

export const USER_COUNTS_KEY = 'stats:userCounts';

export type UserStatusName = 'active' | 'grace' | 'disabled' | 'deleted' | 'inactive';

// `type` (not `interface`): an interface has no implicit index signature and
// would not satisfy the generic `Record<string, number>` constraint above.
export type UserCounts = {
  active: number;
  grace: number;
  disabled: number;
  deleted: number;
  inactive: number;
  /** Users whose last backend push failed and hasn't recovered (entitlement drift). */
  backendDrift: number;
  /** Active users on a default-free tier — the "free users helped" impact stat.
   *  Maintained by the reconcile + `refreshFreeActive` ONLY (a status delta
   *  doesn't know tier membership); per-transition bumps leave it alone. */
  freeActive: number;
};

export const ZERO_USER_COUNTS: UserCounts = {
  active: 0,
  grace: 0,
  disabled: 0,
  deleted: 0,
  inactive: 0,
  backendDrift: 0,
  freeActive: 0,
};

export const USER_COUNTER: CounterSpec<UserCounts, 'users'> = {
  key: USER_COUNTS_KEY,
  table: 'users',
  zero: ZERO_USER_COUNTS,
  // Prod rows predate the flag and were exact; nothing safety-critical reads it.
  legacyInitialized: true,
  createOnBump: true,
};

export async function readUserCounts(db: DatabaseReader): Promise<UserCounts> {
  return (await readCounter(db, USER_COUNTER)).counts;
}

/**
 * Apply a status transition to the counter. `statusFrom`/`statusTo` null = "none"
 * (creation → only `statusTo`; hard-delete → only `statusFrom`). Reading `statusFrom`
 * from the row at the call site makes a no-op transition (from===to) self-cancel and
 * a re-applied transition idempotent. `driftDelta` bumps the backend-drift tally.
 * `creationTime` = the user row's `_creationTime` (reconcile journal boundary).
 */
export async function applyCountsDelta(
  ctx: MutationCtx,
  d: {
    statusFrom?: UserStatusName | null;
    statusTo?: UserStatusName | null;
    driftDelta?: number;
    creationTime: number;
  },
): Promise<void> {
  const delta: Partial<UserCounts> = {};
  if (d.statusFrom) delta[d.statusFrom] = (delta[d.statusFrom] ?? 0) - 1;
  if (d.statusTo) delta[d.statusTo] = (delta[d.statusTo] ?? 0) + 1;
  if (d.driftDelta) delta.backendDrift = d.driftDelta;
  await applyCounterDeltas(ctx, USER_COUNTER, [{ delta, creationTime: d.creationTime }]);
}

// ---------------------------------------------------------------------------
// Sessions: `stats:sessionCounts` (statusSummary's PoP readiness tally)
// ---------------------------------------------------------------------------

export const SESSION_COUNTS_KEY = 'stats:sessionCounts';

export type SessionBucket = 'bound' | 'unboundMember' | 'unboundAdmin';

export type SessionCounts = {
  /** PoP-bound sessions (member or admin) — a captured cookie alone can't replay. */
  bound: number;
  unboundMember: number;
  unboundAdmin: number;
};

export const ZERO_SESSION_COUNTS: SessionCounts = { bound: 0, unboundMember: 0, unboundAdmin: 0 };

export const SESSION_COUNTER: CounterSpec<SessionCounts, 'sessions'> = {
  key: SESSION_COUNTS_KEY,
  table: 'sessions',
  zero: ZERO_SESSION_COUNTS,
  // `pop.readyToEnable` is a safety decision: unknown until the first reconcile.
  legacyInitialized: false,
  createOnBump: false,
};

/** Which counter bucket a session row belongs to. The counter tracks rows
 *  PRESENT, so a session that silently ages past its TTL is counted until the
 *  (daily) sweep deletes it — a conservative, bounded overstatement. */
export function sessionBucket(row: {
  kind: 'member' | 'admin';
  popPublicKey?: string | undefined;
}): SessionBucket {
  if (row.popPublicKey != null) return 'bound';
  return row.kind === 'admin' ? 'unboundAdmin' : 'unboundMember';
}

export async function readSessionCounts(
  db: DatabaseReader,
): Promise<{ counts: SessionCounts; initialized: boolean }> {
  return readCounter(db, SESSION_COUNTER);
}

/** One session row's contribution: its bucket + its `_creationTime`. */
export interface SessionBump {
  bucket: SessionBucket;
  creationTime: number;
}

/** +1 (insert) / −1 (delete) per row. Every session write path — sessions.ts +
 *  the lifecycle hard-delete cascade — must call this. */
export async function bumpSessionCounts(
  ctx: MutationCtx,
  rows: readonly SessionBump[],
  sign: 1 | -1,
): Promise<void> {
  await applyCounterDeltas(
    ctx,
    SESSION_COUNTER,
    rows.map((r) => ({
      delta: { [r.bucket]: sign } as Partial<SessionCounts>,
      creationTime: r.creationTime,
    })),
  );
}
