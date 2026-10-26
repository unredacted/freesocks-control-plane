/**
 * Suspicion, the DB half (docs/edges.md "Address enumeration"; the rules are
 * lib/edges/trust.ts). Every delivery path records the FIRST time a trusted
 * address is handed to an account (`edgeExposures`); the first time a trusted
 * address is judged blocked, its fresh holders get a strike (`noteBlocked`,
 * claimed once per address); an account with enough strikes is suspected and
 * draws from the open lane (convex/edgeLanes.ts `memberLaneOfUser`) until they
 * expire. Accounts are named only by their mark. Nothing here writes a log
 * line or an audit row about an account, a mark or an address.
 */
import { v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { DatabaseReader, DatabaseWriter, MutationCtx } from './_generated/server';
import type { Id } from './_generated/dataModel';
import { internal } from './_generated/api';
import { readStateJson, writeStateJson } from './lib/appStateJson';
import { resolveTrustSettings } from './lib/edgeConfig';
import {
  attributable,
  freshWindow,
  isSuspected,
  liveStrikes,
  trustExpiresAt,
  trustMark,
  trustPepper,
  withStrike,
  type TrustSettings,
} from './lib/edges/trust';
import { scheduleMirrorRefresh } from './lib/edges/relayGuards';
import { recordHeartbeat } from './cronHeartbeat';

/** When suspicion started recording: addresses published before it never strike anyone. */
const SINCE_KEY = 'edge:trustSince';
/** Today's counts for the admin (no account in them). */
const DAILY_KEY = 'edge:trustDaily';
const dayKey = (now: number) => new Date(now).toISOString().slice(0, 10);

/** The account's mark under this deployment's pepper (null: no pepper, nothing recorded). */
export function markOf(userId: Id<'users'>): string | null {
  return trustMark(trustPepper(process.env), userId);
}

// --- who was handed what ----------------------------------------------------------------------

/**
 * Record that these addresses were handed to the account, the first time for
 * each trusted one (an open address is not recorded: everybody may have it).
 * Never rewritten, so a long-time holder never looks fresh.
 */
export async function noteExposures(
  ctx: MutationCtx,
  userId: Id<'users'>,
  edgeIds: ReadonlyArray<Id<'edges'> | null | undefined>,
  now: number,
): Promise<number> {
  const mark = markOf(userId);
  if (!mark) return 0;
  let added = 0;
  for (const edgeId of new Set(edgeIds.filter((x): x is Id<'edges'> => !!x))) {
    const edge = await ctx.db.get(edgeId);
    if (!edge || edge.lane !== 'trusted') continue;
    const seen = await ctx.db
      .query('edgeExposures')
      .withIndex('by_mark_edge', (q) => q.eq('mark', mark).eq('edgeId', edgeId))
      .first();
    if (seen) continue;
    await ctx.db.insert('edgeExposures', { mark, edgeId, at: now });
    added++;
  }
  return added;
}

/** The raw-config view and the mirror renders: what they handed out. */
export const noteExposure = internalMutation({
  args: { subscriptionId: v.id('subscriptions'), edgeIds: v.array(v.id('edges')) },
  handler: async (ctx, { subscriptionId, edgeIds }) => {
    const sub = await ctx.db.get(subscriptionId);
    if (!sub) return 0;
    return noteExposures(ctx, sub.userId, edgeIds, Date.now());
  },
});

// --- strikes ----------------------------------------------------------------------------------

async function sinceOf(db: DatabaseWriter, now: number): Promise<number> {
  const v = await readStateJson<{ at?: number }>(db, SINCE_KEY);
  if (v && typeof v.at === 'number') return v.at;
  await writeStateJson(db, SINCE_KEY, { at: now });
  return now;
}

/** `seed:seedCutover`: start recording at the first deploy (idempotent). */
export const ensureSince = internalMutation({
  args: {},
  handler: async (ctx) => sinceOf(ctx.db, Date.now()),
});

async function countToday(db: DatabaseWriter, now: number, strikes: number, demotions: number) {
  if (strikes === 0 && demotions === 0) return;
  const v = await readStateJson<{ day?: string; strikes?: number; demotions?: number }>(
    db,
    DAILY_KEY,
  );
  const today = dayKey(now);
  const same = v?.day === today;
  await writeStateJson(db, DAILY_KEY, {
    day: today,
    strikes: (same ? (v?.strikes ?? 0) : 0) + strikes,
    demotions: (same ? (v?.demotions ?? 0) : 0) + demotions,
  });
}

/** One strike for the account behind `mark`; true when it just became suspected. */
async function strike(
  ctx: MutationCtx,
  mark: string,
  now: number,
  s: TrustSettings,
): Promise<{ counted: boolean; suspectedNow: boolean }> {
  const row = await ctx.db
    .query('edgeTrust')
    .withIndex('by_mark', (q) => q.eq('mark', mark))
    .first();
  const before = row?.strikes ?? [];
  const next = withStrike(before, now, s);
  if (!next.added) return { counted: false, suspectedNow: false };
  const expiresAt = trustExpiresAt(next.strikes, s);
  if (row) await ctx.db.patch(row._id, { strikes: next.strikes, expiresAt });
  else await ctx.db.insert('edgeTrust', { mark, strikes: next.strikes, expiresAt });
  return {
    counted: true,
    suspectedNow: !isSuspected(before, now, s) && isSuspected(next.strikes, now, s),
  };
}

/**
 * A trusted address judged blocked, its evidence beginning at `evidenceAt`:
 * claimed once per address (repeated detector passes, a manual mark and a
 * country round all land here); its fresh holders (handed it in the window
 * before the evidence, after its first wave) each get a strike when they are
 * few enough to say something. An address published before suspicion
 * started recording strikes nobody (its first exposures are not all known).
 * A demotion renders every mirror again, so no object keeps a trusted body for
 * an account that is now in the open lane.
 */
export async function noteBlockedIn(
  ctx: MutationCtx,
  edgeId: Id<'edges'>,
  evidenceAt: number,
  now: number,
): Promise<{ claimed: boolean; fresh: number; struck: number; demoted: number }> {
  const none = { claimed: false, fresh: 0, struck: 0, demoted: 0 };
  const edge = await ctx.db.get(edgeId);
  if (!edge || edge.lane !== 'trusted' || edge.blockClaim) return none;
  const since = await sinceOf(ctx.db, now);
  await ctx.db.patch(edgeId, { blockClaim: { at: now, evidenceAt } });
  if (edge.publishedAt === undefined || edge.publishedAt <= since)
    return { ...none, claimed: true };
  const s = await resolveTrustSettings(ctx.db);
  const { from, to } = freshWindow(evidenceAt, edge.publishedAt, s);
  const fresh = await ctx.db
    .query('edgeExposures')
    .withIndex('by_edge_at', (q) => q.eq('edgeId', edgeId).gte('at', from).lt('at', to))
    .take(s.maxFreshHolders + 1);
  if (!attributable(fresh.length, s)) return { ...none, claimed: true, fresh: fresh.length };
  let struck = 0;
  let demoted = 0;
  for (const row of fresh) {
    const r = await strike(ctx, row.mark, now, s);
    if (r.counted) struck++;
    if (r.suspectedNow) demoted++;
  }
  await countToday(ctx.db, now, struck, demoted);
  if (demoted > 0) await scheduleMirrorRefresh(ctx);
  return { claimed: true, fresh: fresh.length, struck, demoted };
}

export const noteBlocked = internalMutation({
  args: { edgeId: v.id('edges'), evidenceAt: v.number() },
  handler: async (ctx, { edgeId, evidenceAt }) =>
    noteBlockedIn(ctx, edgeId, evidenceAt, Date.now()),
});

/** Whether the account is suspected now (it then draws from the open lane). */
export async function suspectedOf(db: DatabaseReader, userId: Id<'users'>): Promise<boolean> {
  const mark = markOf(userId);
  if (!mark) return false;
  const row = await db
    .query('edgeTrust')
    .withIndex('by_mark', (q) => q.eq('mark', mark))
    .first();
  if (!row) return false;
  return isSuspected(row.strikes, Date.now(), await resolveTrustSettings(db));
}

// --- what the admin sees: counts only ---------------------------------------------------------

/** One page of the counts (the summary below walks every page). */
export const summaryPage = internalQuery({
  args: { cursor: v.union(v.string(), v.null()), now: v.number() },
  handler: async (ctx, { cursor, now }) => {
    const s = await resolveTrustSettings(ctx.db);
    const page = await ctx.db.query('edgeTrust').paginate({ cursor, numItems: 1000 });
    let suspected = 0;
    let withStrikes = 0;
    for (const row of page.page) {
      if (liveStrikes(row.strikes, now, s) === 0) continue;
      withStrikes++;
      if (isSuspected(row.strikes, now, s)) suspected++;
    }
    return { suspected, withStrikes, isDone: page.isDone, continueCursor: page.continueCursor };
  },
});

export const summaryState = internalQuery({
  args: { now: v.number() },
  handler: async (ctx, { now }) => {
    const daily = await readStateJson<{ day?: string; strikes?: number; demotions?: number }>(
      ctx.db,
      DAILY_KEY,
    );
    const today = daily?.day === dayKey(now);
    const since = await readStateJson<{ at?: number }>(ctx.db, SINCE_KEY);
    return {
      strikesToday: today ? (daily?.strikes ?? 0) : 0,
      demotionsToday: today ? (daily?.demotions ?? 0) : 0,
      since: typeof since?.at === 'number' ? new Date(since.at).toISOString() : null,
    };
  },
});

/** Every account with a strike still counting, page by page: never a truncated total. */
export const summary = internalAction({
  args: {},
  handler: async (
    ctx,
  ): Promise<{
    suspected: number;
    withStrikes: number;
    strikesToday: number;
    demotionsToday: number;
    since: string | null;
  }> => {
    const now = Date.now();
    let suspected = 0;
    let withStrikes = 0;
    let cursor: string | null = null;
    for (;;) {
      const page: {
        suspected: number;
        withStrikes: number;
        isDone: boolean;
        continueCursor: string;
      } = await ctx.runQuery(internal.edgeTrust.summaryPage, { cursor, now });
      suspected += page.suspected;
      withStrikes += page.withStrikes;
      if (page.isDone) break;
      cursor = page.continueCursor;
    }
    return {
      suspected,
      withStrikes,
      ...(await ctx.runQuery(internal.edgeTrust.summaryState, { now })),
    };
  },
});

// --- retention --------------------------------------------------------------------------------

/**
 * The daily sweep (`edge-trust-sweep`): an account's row goes once its newest
 * strike stops counting; a first-exposure row goes once its address is
 * destroyed, gone or no longer trusted. Pages itself until done.
 */
export const sweep = internalMutation({
  args: { cursor: v.optional(v.union(v.string(), v.null())) },
  handler: async (ctx, { cursor }) => {
    const now = Date.now();
    let removed = 0;
    if (!cursor) await recordHeartbeat(ctx, 'edge-trust-sweep');
    if (!cursor) {
      // Judged under the window that holds NOW: a row whose stored deadline was
      // set under a shorter `strikeDays` keeps living while a strike counts.
      const s = await resolveTrustSettings(ctx.db);
      for (const row of await ctx.db
        .query('edgeTrust')
        .withIndex('by_expires', (q) => q.lt('expiresAt', now))
        .take(500)) {
        if (liveStrikes(row.strikes, now, s) > 0) {
          await ctx.db.patch(row._id, { expiresAt: trustExpiresAt(row.strikes, s) });
          continue;
        }
        await ctx.db.delete(row._id);
        removed++;
      }
    }
    const page = await ctx.db
      .query('edgeExposures')
      .paginate({ cursor: cursor ?? null, numItems: 500 });
    const alive = new Map<string, boolean>();
    for (const row of page.page) {
      const key = row.edgeId as string;
      if (!alive.has(key)) {
        const e = await ctx.db.get(row.edgeId);
        alive.set(key, !!e && e.status !== 'destroyed' && e.lane === 'trusted');
      }
      if (alive.get(key)) continue;
      await ctx.db.delete(row._id);
      removed++;
    }
    if (!page.isDone)
      await ctx.scheduler.runAfter(0, internal.edgeTrust.sweep, { cursor: page.continueCursor });
    return { removed, done: page.isDone };
  },
});

/** An account deleted: its strikes and first exposures go with it. */
export async function forgetAccount(ctx: MutationCtx, userId: Id<'users'>): Promise<void> {
  const mark = markOf(userId);
  if (!mark) return;
  for (const row of await ctx.db
    .query('edgeTrust')
    .withIndex('by_mark', (q) => q.eq('mark', mark))
    .collect())
    await ctx.db.delete(row._id);
  await forgetExposures(ctx, mark);
}

const FORGET_PAGE = 500;

/** Delete an account's first exposures a page at a time, scheduling itself until none is left. */
async function forgetExposures(ctx: MutationCtx, mark: string): Promise<void> {
  const rows = await ctx.db
    .query('edgeExposures')
    .withIndex('by_mark_edge', (q) => q.eq('mark', mark))
    .take(FORGET_PAGE);
  for (const row of rows) await ctx.db.delete(row._id);
  if (rows.length === FORGET_PAGE)
    await ctx.scheduler.runAfter(0, internal.edgeTrust.forgetMark, { mark });
}

/** The rest of a deleted account's first exposures (`forgetAccount`). */
export const forgetMark = internalMutation({
  args: { mark: v.string() },
  handler: async (ctx, { mark }) => forgetExposures(ctx, mark),
});

// --- rolling back -----------------------------------------------------------------------------

/**
 * The step before rolling back to a build without suspicion (docs/edges.md §
 * "Deploy notes"): every first-exposure row, every strike row, every block
 * claim and the two state keys go, page by page, scheduling itself.
 */
export const clearForRollback = internalMutation({
  args: {
    phase: v.optional(v.union(v.literal('exposures'), v.literal('trust'), v.literal('edges'))),
    cursor: v.optional(v.union(v.string(), v.null())),
  },
  handler: async (ctx, { phase, cursor }) => {
    const at = phase ?? 'exposures';
    let cleared = 0;
    const next = (args: { phase: 'exposures' | 'trust' | 'edges'; cursor?: string }) =>
      ctx.scheduler.runAfter(0, internal.edgeTrust.clearForRollback, args);
    if (at === 'exposures' || at === 'trust') {
      const table = at === 'exposures' ? 'edgeExposures' : 'edgeTrust';
      const rows = await ctx.db.query(table).take(500);
      for (const r of rows) await ctx.db.delete(r._id);
      cleared = rows.length;
      await next(
        rows.length === 500 ? { phase: at } : { phase: at === 'exposures' ? 'trust' : 'edges' },
      );
      return { cleared, done: false };
    }
    const page = await ctx.db.query('edges').paginate({ cursor: cursor ?? null, numItems: 200 });
    for (const e of page.page)
      if (e.blockClaim !== undefined) {
        await ctx.db.patch(e._id, { blockClaim: undefined });
        cleared++;
      }
    if (!page.isDone) {
      await next({ phase: 'edges', cursor: page.continueCursor });
      return { cleared, done: false };
    }
    for (const key of [SINCE_KEY, DAILY_KEY]) {
      const row = await ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', key))
        .first();
      if (row) await ctx.db.delete(row._id);
    }
    return { cleared, done: true };
  },
});
