/**
 * A country list's names into finding names (docs/edges.md "Country lists",
 * "Names into finding names"). A list may feed networks and families (none by
 * default); each feed takes the version in use's names as candidates of
 * source `list`, through the same rules as every source (already there, held
 * by a family, ignored, past a scope's 2,000), and qualification checks them
 * as usual. Wildcards are not names and are skipped.
 *
 * A feed is a RUN: a walk of one version's names, a page at a time, fenced by
 * a generation. A run starts when a feed is added (the backfill of the version
 * in use), when a new version goes into use, on "Feed again", and daily for a
 * feed whose last run was capped while its scope has room again. A run behind
 * the list's version, or of a feed taken away, stops; a stalled one is picked
 * up by the daily sweep. Candidates a run added stay when it stops.
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, type DatabaseReader, type MutationCtx } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { internal } from './_generated/api';
import { writeAuditLog } from './lib/audit';
import { resolveEdgeConfig } from './lib/edgeConfig';
import { isFresh, MAX_LISTS } from './lib/edges/lists/facts';
import { scopeRow } from './lib/edges/sni/hunt/store';
import { addListCandidates, MAX_CANDIDATES_PER_SCOPE } from './sniHunt';
import { MAX_LIST_FEEDS } from '../src/shared/contracts/countryLists';

type List = Doc<'countryLists'>;
type Run = Doc<'countryListFeedRuns'>;
export type Feed = NonNullable<List['feeds']>[number];

/** Feeds one list may have. */
export const MAX_FEEDS = MAX_LIST_FEEDS;
/** Names per step: each is a handful of index reads, inside one step's 4,096. */
const FEED_PAGE = 250;
const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
/** A running run that has not stepped for this long stalled. */
const RUN_STALE_MS = HOUR;
/** Finished runs kept, for the list page's "last fed". */
const RUN_RETENTION_MS = 30 * DAY;

const zero = () => ({
  added: 0,
  known: 0,
  ignored: 0,
  inFamily: 0,
  invalid: 0,
  capped: 0,
  wildcards: 0,
});

function refuse(code: string, message: string): never {
  throw new ConvexError({ code, message });
}

export const feedKeyOf = (f: Feed) =>
  'networkId' in f ? `network:${f.networkId}` : `family:${f.familyId}`;

/** A feed's scope as finding names keys it: a family carries its network (sniHunt `scopeOf`). */
async function scopeOfFeed(
  db: DatabaseReader,
  f: Feed,
): Promise<{ networkId?: Id<'edgeNetworks'>; familyId?: Id<'sniFamilies'> } | null> {
  if ('networkId' in f) return (await db.get(f.networkId)) ? { networkId: f.networkId } : null;
  const fam = await db.get(f.familyId);
  if (!fam) return null;
  return { familyId: fam._id, ...(fam.networkId ? { networkId: fam.networkId } : {}) };
}

/** Whether a list's names may be fed now: the switch on, the list on, fresh, with a version in use. */
async function feedable(db: DatabaseReader, list: List, now: number): Promise<boolean> {
  const cfg = await resolveEdgeConfig(db);
  return (
    cfg.lists.enabled &&
    list.enabled &&
    !!list.activeVersionId &&
    isFresh(list, cfg.lists.staleDays, now)
  );
}

async function latestRun(db: DatabaseReader, listId: Id<'countryLists'>, feedKey: string) {
  return db
    .query('countryListFeedRuns')
    .withIndex('by_list_feed', (q) => q.eq('listId', listId).eq('feedKey', feedKey))
    .order('desc')
    .first();
}

async function stop(ctx: MutationCtx, run: Run, why: string) {
  await ctx.db.patch(run._id, { state: 'stopped', stopped: why, updatedAt: Date.now() });
}

/**
 * Start a run of the version in use for each feed (or the given ones). A run
 * of the same feed still going is stopped first. Returns how many started.
 */
export async function startFeedRuns(
  ctx: MutationCtx,
  list: List,
  keys?: readonly string[],
): Promise<number> {
  const now = Date.now();
  if (!(await feedable(ctx.db, list, now))) return 0;
  let started = 0;
  for (const feed of list.feeds ?? []) {
    const feedKey = feedKeyOf(feed);
    if (keys && !keys.includes(feedKey)) continue;
    const last = await latestRun(ctx.db, list._id, feedKey);
    if (last?.state === 'running') await stop(ctx, last, 'restarted');
    const gen = (last?.gen ?? 0) + 1;
    const runId = await ctx.db.insert('countryListFeedRuns', {
      listId: list._id,
      feedKey,
      versionId: list.activeVersionId!,
      state: 'running',
      gen,
      counts: zero(),
      startedAt: now,
      updatedAt: now,
    });
    await ctx.scheduler.runAfter(0, internal.countryListFeeds.feedStep, { runId, gen });
    started++;
  }
  return started;
}

/** One page of a run: the next names into the feed's scope. */
export const feedStep = internalMutation({
  args: { runId: v.id('countryListFeedRuns'), gen: v.number() },
  handler: async (ctx, a) => {
    const run = await ctx.db.get(a.runId);
    if (!run || run.state !== 'running' || run.gen !== a.gen) return;
    const list = await ctx.db.get(run.listId);
    if (!list) return stop(ctx, run, 'list_removed');
    const feed = (list.feeds ?? []).find((f) => feedKeyOf(f) === run.feedKey);
    if (!feed) return stop(ctx, run, 'feed_removed');
    // A newer version went into use: its own run takes the names from here.
    if (list.activeVersionId !== run.versionId) return stop(ctx, run, 'superseded');
    const now = Date.now();
    if (!(await feedable(ctx.db, list, now))) return stop(ctx, run, 'not_feedable');
    const scope = await scopeOfFeed(ctx.db, feed);
    if (!scope) return stop(ctx, run, 'scope_gone');
    const page = await ctx.db
      .query('countryListMembers')
      .withIndex('by_version_name', (q) => q.eq('versionId', run.versionId))
      .paginate({ numItems: FEED_PAGE, cursor: run.cursor ?? null });
    const names = page.page.filter((m) => !m.wildcard).map((m) => m.name);
    const tally = await addListCandidates(ctx, scope, names, now);
    const counts = {
      added: run.counts.added + tally.added,
      known: run.counts.known + tally.known,
      ignored: run.counts.ignored + tally.ignored,
      inFamily: run.counts.inFamily + tally.inFamily,
      invalid: run.counts.invalid + tally.invalid,
      capped: run.counts.capped + tally.capped,
      wildcards: run.counts.wildcards + (page.page.length - names.length),
    };
    if (!page.isDone) {
      await ctx.db.patch(run._id, { cursor: page.continueCursor, counts, updatedAt: now });
      await ctx.scheduler.runAfter(0, internal.countryListFeeds.feedStep, a);
      return;
    }
    await ctx.db.patch(run._id, { state: 'done', cursor: undefined, counts, updatedAt: now });
    // The new candidates carry no list facts yet.
    await ctx.scheduler.runAfter(0, internal.countryListFacts.kick, {});
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'edge.sni.hunt.list_feed',
      targetType: 'country_list',
      payload: { listId: list._id, kind: run.feedKey.split(':')[0], ...counts },
    });
  },
});

/** A list's feeds by slug: networks and families, at most 10. */
export const setFeeds = internalMutation({
  args: {
    listId: v.id('countryLists'),
    feeds: v.array(v.object({ network: v.optional(v.string()), family: v.optional(v.string()) })),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const list = await ctx.db.get(a.listId);
    if (!list) refuse('not_found', 'No such list');
    const feeds: Feed[] = [];
    for (const f of a.feeds) {
      if (f.network) {
        const n = await ctx.db
          .query('edgeNetworks')
          .withIndex('by_slug', (q) => q.eq('slug', f.network!))
          .unique();
        if (!n) refuse('not_found', 'No such network');
        feeds.push({ networkId: n._id });
      } else if (f.family) {
        const fam = await ctx.db
          .query('sniFamilies')
          .withIndex('by_slug', (q) => q.eq('slug', f.family!))
          .unique();
        if (!fam) refuse('not_found', 'No such family');
        feeds.push({ familyId: fam._id });
      } else refuse('validation', 'A feed is a network or a family');
    }
    const unique = [...new Map(feeds.map((f) => [feedKeyOf(f), f])).values()];
    if (unique.length > MAX_FEEDS)
      refuse('edge.list.feeds_cap', `A list feeds at most ${MAX_FEEDS} networks and families`);
    const before = new Set((list.feeds ?? []).map(feedKeyOf));
    const after = new Set(unique.map(feedKeyOf));
    await ctx.db.patch(list._id, { feeds: unique, updatedAt: Date.now() });
    for (const key of before)
      if (!after.has(key)) {
        const last = await latestRun(ctx.db, list._id, key);
        if (last?.state === 'running') await stop(ctx, last, 'feed_removed');
      }
    // A new feed takes the version in use now (the backfill).
    const added = [...after].filter((k) => !before.has(k));
    const started = added.length
      ? await startFeedRuns(ctx, (await ctx.db.get(list._id))!, added)
      : 0;
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'admin.edge.list.feeds',
      targetType: 'country_list',
      payload: { listId: list._id, feeds: unique.length, started },
    });
    return { ok: true as const, started };
  },
});

/** "Feed again": a new run of the version in use for every feed. */
export const feedAgain = internalMutation({
  args: { listId: v.id('countryLists'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, a) => {
    const list = await ctx.db.get(a.listId);
    if (!list) refuse('not_found', 'No such list');
    if ((list.feeds ?? []).length === 0) refuse('edge.list.no_feeds', 'This list feeds nothing');
    if (!(await feedable(ctx.db, list, Date.now())))
      refuse(
        'edge.list.not_feedable',
        'Only a list that is on, fresh and has a version in use can feed names',
      );
    const started = await startFeedRuns(ctx, list);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'admin.edge.list.refeed',
      targetType: 'country_list',
      payload: { listId: list._id, started },
    });
    return { ok: true as const, started };
  },
});

/** A list's feeds as its page shows them, each with its last run. */
export async function feedViews(db: DatabaseReader, list: List) {
  const out = [];
  for (const f of list.feeds ?? []) {
    const target = 'networkId' in f ? await db.get(f.networkId) : await db.get(f.familyId);
    const last = await latestRun(db, list._id, feedKeyOf(f));
    out.push({
      kind: 'networkId' in f ? ('network' as const) : ('family' as const),
      slug: target?.slug ?? null,
      label: target?.label ?? null,
      run: last
        ? {
            state: last.state,
            stopped: last.stopped ?? null,
            counts: last.counts,
            at: new Date(last.updatedAt).toISOString(),
            current: last.versionId === list.activeVersionId,
          }
        : null,
    });
  }
  return out;
}

/**
 * Daily (from `countryLists.sweep`): resume stalled runs, retry a feed whose
 * last run was capped once its scope has room, and drop old finished runs.
 */
export async function sweepFeeds(ctx: MutationCtx, now: number) {
  const counts = { resumed: 0, retried: 0, dropped: 0 };
  for (const run of await ctx.db
    .query('countryListFeedRuns')
    .withIndex('by_state_updated', (q) =>
      q.eq('state', 'running').lt('updatedAt', now - RUN_STALE_MS),
    )
    .take(50)) {
    const gen = run.gen + 1;
    await ctx.db.patch(run._id, { gen, updatedAt: now });
    await ctx.scheduler.runAfter(0, internal.countryListFeeds.feedStep, { runId: run._id, gen });
    counts.resumed++;
  }
  for (const list of await ctx.db.query('countryLists').take(MAX_LISTS)) {
    const retry: string[] = [];
    for (const f of list.feeds ?? []) {
      const key = feedKeyOf(f);
      const last = await latestRun(ctx.db, list._id, key);
      if (last?.state !== 'done' || last.counts.capped === 0) continue;
      if (last.versionId !== list.activeVersionId) continue;
      const scope = await scopeOfFeed(ctx.db, f);
      if (!scope) continue;
      const total = (await scopeRow(ctx.db, scope))?.total ?? 0;
      if (total < MAX_CANDIDATES_PER_SCOPE) retry.push(key);
    }
    if (retry.length > 0) counts.retried += await startFeedRuns(ctx, list, retry);
  }
  for (const state of ['done', 'stopped'] as const)
    for (const run of await ctx.db
      .query('countryListFeedRuns')
      .withIndex('by_state_updated', (q) =>
        q.eq('state', state).lt('updatedAt', now - RUN_RETENTION_MS),
      )
      .take(200)) {
      await ctx.db.delete(run._id);
      counts.dropped++;
    }
  return counts;
}
