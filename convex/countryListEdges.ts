/**
 * Edge addresses against watched allowlists (docs/edges.md "Edge addresses
 * against allowlists"). Under a whitelist both the dialled address and the
 * server name must be listed: this keeps, per active edge, list and address
 * family, whether the list's version in use holds the address (the rules are
 * pure, in lib/edges/lists/edgeMarks.ts). Evidence only: nothing here changes
 * what members get.
 *
 *  - A recheck walks the active edges a page at a time and looks up only what
 *    changed (a new version, a new address, a new edge): an unchanged mark is
 *    not read again. Then it drops the marks of edges that are no longer
 *    active.
 *  - It runs after anything that moves what the lists say (the list-facts
 *    generation: a version going into use, an edit, freshness, the switch),
 *    when a list starts or stops being watched, and at the end of the hourly
 *    `country-lists` pass (new edges, new addresses).
 *  - A start while a recheck runs asks it to go round once more.
 */
import { ConvexError, v } from 'convex/values';
import {
  internalMutation,
  internalQuery,
  type DatabaseReader,
  type MutationCtx,
} from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { internal } from './_generated/api';
import { readStateJson, writeStateJson } from './lib/appStateJson';
import { writeAuditLog } from './lib/audit';
import { resolveEdgeConfig } from './lib/edgeConfig';
import {
  edgeWatchLists,
  versionHoldsAddress,
  watchedAllowlists,
  type Active,
} from './lib/edges/lists/facts';
import { addressKey } from './lib/edges/lists/intervals';
import {
  MARK_FAMILIES,
  leftNeedsLook,
  markSince,
  markState,
  nextMark,
  type MarkFamily,
  type MarkState,
} from './lib/edges/lists/edgeMarks';

type Mark = Doc<'countryListEdgeMarks'>;

const RUN_KEY = 'countryLists:edgeRecheck';
/** A recheck chain that has not stepped for this long crashed; a start begins it again. */
const RUNNING_STALE_MS = 15 * 60 * 1000;
/** Edges per step: each costs one read of its marks and up to two lookups per watched list. */
const EDGES_PAGE = 20;
/** Marks per step of the cleanup: one read of the edge each. */
const MARKS_PAGE = 200;
/** Active edges a view counts (a fleet is far smaller). */
const VIEW_EDGES = 1000;
/** Marks one read takes per list (two per active edge at most). */
const MARKS_PER_LIST = 2 * VIEW_EDGES;

interface RunState {
  at: number;
  again?: boolean;
}

/** The edge's address of one family, when it is an IP address (an L7 front has none). */
export function edgeAddressOf(e: Doc<'edges'>, family: MarkFamily): string | undefined {
  const a = e.addresses[family];
  if (!a) return undefined;
  const k = addressKey(a);
  return k && k.family === family ? a : undefined;
}

/** Start a recheck, or ask the one running to go round once more. */
export async function startEdgeRecheck(ctx: MutationCtx): Promise<void> {
  const now = Date.now();
  const run = await readStateJson<RunState>(ctx.db, RUN_KEY);
  if (run && run.at > 0 && now - run.at < RUNNING_STALE_MS) {
    if (!run.again) await writeStateJson(ctx.db, RUN_KEY, { ...run, again: true });
    return;
  }
  await writeStateJson(ctx.db, RUN_KEY, { at: now });
  await ctx.scheduler.runAfter(0, internal.countryListEdges.recheck, { phase: 'edges' });
}

/** The hourly pass: new edges and new addresses get their marks. */
export const kick = internalMutation({
  args: {},
  handler: async (ctx) => {
    await startEdgeRecheck(ctx);
  },
});

async function checkEdge(
  ctx: MutationCtx,
  e: Doc<'edges'>,
  lists: readonly Active[],
  now: number,
): Promise<number> {
  // At most two per list: a selective range.
  const marks = await ctx.db
    .query('countryListEdgeMarks')
    .withIndex('by_edge', (q) => q.eq('edgeId', e._id))
    .collect();
  let looked = 0;
  for (const a of lists)
    for (const family of MARK_FAMILIES) {
      const address = edgeAddressOf(e, family);
      const mark = marks.find((m) => m.listId === a.list._id && m.family === family) ?? null;
      if (address === undefined) {
        if (mark) await ctx.db.delete(mark._id);
        continue;
      }
      if (mark && mark.address === address && mark.versionId === a.versionId) continue;
      const listed = await versionHoldsAddress(ctx.db, a.versionId, address);
      const doc = {
        edgeId: e._id,
        listId: a.list._id,
        family,
        ...nextMark(mark, { address, versionId: a.versionId, listed, now }),
      };
      if (mark) await ctx.db.replace(mark._id, doc);
      else await ctx.db.insert('countryListEdgeMarks', doc);
      looked++;
    }
  return looked;
}

/**
 * One step of a recheck. `edges`: a page of active edges against every
 * watched list the rechecks read now. `marks`: a page of marks, dropping those
 * whose edge is gone, no longer active or without that family's address.
 */
export const recheck = internalMutation({
  args: {
    phase: v.union(v.literal('edges'), v.literal('marks')),
    cursor: v.optional(v.string()),
  },
  handler: async (ctx, a) => {
    const now = Date.now();
    if (a.phase === 'edges') {
      const lists = await edgeWatchLists(ctx.db, now);
      let looked = 0;
      let done = true;
      let cursor: string | undefined;
      if (lists.length > 0) {
        const page = await ctx.db
          .query('edges')
          .withIndex('by_status', (q) => q.eq('status', 'active'))
          .paginate({ numItems: EDGES_PAGE, cursor: a.cursor ?? null });
        for (const e of page.page) looked += await checkEdge(ctx, e, lists, now);
        done = page.isDone;
        cursor = page.continueCursor;
      }
      await writeStateJson(ctx.db, RUN_KEY, {
        ...((await readStateJson<RunState>(ctx.db, RUN_KEY)) ?? {}),
        at: now,
      });
      await ctx.scheduler.runAfter(
        0,
        internal.countryListEdges.recheck,
        done ? { phase: 'marks' } : { phase: 'edges', cursor },
      );
      return { looked };
    }
    const page = await ctx.db
      .query('countryListEdgeMarks')
      .paginate({ numItems: MARKS_PAGE, cursor: a.cursor ?? null });
    let dropped = 0;
    const lists = new Map<string, boolean>();
    for (const m of page.page) {
      const e = await ctx.db.get(m.edgeId);
      if (!lists.has(m.listId)) lists.set(m.listId, !!(await ctx.db.get(m.listId)));
      if (e && e.status === 'active' && edgeAddressOf(e, m.family) && lists.get(m.listId)) continue;
      await ctx.db.delete(m._id);
      dropped++;
    }
    const run = (await readStateJson<RunState>(ctx.db, RUN_KEY)) ?? { at: 0 };
    if (!page.isDone) {
      await writeStateJson(ctx.db, RUN_KEY, { ...run, at: now });
      await ctx.scheduler.runAfter(0, internal.countryListEdges.recheck, {
        phase: 'marks',
        cursor: page.continueCursor,
      });
    } else if (run.again) {
      // Something moved during this pass: go round once more.
      await writeStateJson(ctx.db, RUN_KEY, { at: now });
      await ctx.scheduler.runAfter(0, internal.countryListEdges.recheck, { phase: 'edges' });
    } else await writeStateJson(ctx.db, RUN_KEY, { at: 0 });
    return { dropped };
  },
});

// --- reads ----------------------------------------------------------------------------------------

async function marksOfList(db: DatabaseReader, listId: Id<'countryLists'>): Promise<Mark[]> {
  return db
    .query('countryListEdgeMarks')
    .withIndex('by_list_edge', (q) => q.eq('listId', listId))
    .take(MARKS_PER_LIST);
}

export interface AddressLeft {
  listId: Id<'countryLists'>;
  label: string;
  country: string;
  family: MarkFamily;
  address: string;
  leftAt: number | null;
}

/**
 * Per edge, the addresses that left a watched list nobody said they saw
 * (the attention item `list_address_left`). Only lists the rechecks read now:
 * a stale, switched-off or unwatched list raises nothing.
 */
export async function addressesLeft(
  db: DatabaseReader,
  now: number,
): Promise<Map<string, AddressLeft[]>> {
  const out = new Map<string, AddressLeft[]>();
  for (const a of await edgeWatchLists(db, now))
    for (const m of await marksOfList(db, a.list._id)) {
      if (!leftNeedsLook(m, { address: m.address, activeVersionId: a.versionId })) continue;
      const rows = out.get(m.edgeId) ?? [];
      rows.push({
        listId: a.list._id,
        label: a.list.label,
        country: a.list.country,
        family: m.family,
        address: m.address,
        leftAt: m.leftAt ?? null,
      });
      out.set(m.edgeId, rows);
    }
  return out;
}

export interface EdgeListMark {
  listId: Id<'countryLists'>;
  label: string;
  country: string;
  family: MarkFamily;
  state: MarkState;
  at: number | null;
}

/** For the country view: what each list the rechecks read says about each active edge's addresses. */
export async function marksByEdge(
  db: DatabaseReader,
  edges: readonly Doc<'edges'>[],
  now: number,
): Promise<Map<string, EdgeListMark[]>> {
  const out = new Map<string, EdgeListMark[]>();
  const lists = await edgeWatchLists(db, now);
  if (lists.length === 0) return out;
  const marks = new Map<string, Mark>();
  for (const a of lists)
    for (const m of await marksOfList(db, a.list._id))
      marks.set(`${m.listId}:${m.edgeId}:${m.family}`, m);
  for (const e of edges) {
    const rows: EdgeListMark[] = [];
    for (const a of lists)
      for (const family of MARK_FAMILIES) {
        const address = edgeAddressOf(e, family);
        if (address === undefined) continue;
        const m = marks.get(`${a.list._id}:${e._id}:${family}`) ?? null;
        const state = markState(m, { address, activeVersionId: a.versionId });
        rows.push({
          listId: a.list._id,
          label: a.list.label,
          country: a.list.country,
          family,
          state,
          at: markSince(m, state),
        });
      }
    if (rows.length > 0) out.set(e._id, rows);
  }
  return out;
}

/** For a list's page: how its watched edge addresses stand. Null when it is not watched. */
export async function edgeCountsOf(
  db: DatabaseReader,
  list: Doc<'countryLists'>,
): Promise<Record<MarkState, number> | null> {
  if (list.regime !== 'allowlist' || list.watchEdges !== true) return null;
  const counts: Record<MarkState, number> = { listed: 0, not_listed: 0, left: 0, checking: 0 };
  const marks = new Map<string, Mark>();
  for (const m of await marksOfList(db, list._id)) marks.set(`${m.edgeId}:${m.family}`, m);
  const edges = await db
    .query('edges')
    .withIndex('by_status', (q) => q.eq('status', 'active'))
    .take(VIEW_EDGES);
  for (const e of edges)
    for (const family of MARK_FAMILIES) {
      const address = edgeAddressOf(e, family);
      if (address === undefined) continue;
      const m = marks.get(`${e._id}:${family}`) ?? null;
      counts[markState(m, { address, activeVersionId: list.activeVersionId })]++;
    }
  return counts;
}

/** `GET lists/marks?edge=`: what every watched allowlist says about one edge's addresses. */
export const forEdge = internalQuery({
  args: { edgeId: v.id('edges') },
  handler: async (ctx, { edgeId }) => {
    const now = Date.now();
    const cfg = await resolveEdgeConfig(ctx.db);
    const e = await ctx.db.get(edgeId);
    if (!e) throw new ConvexError({ code: 'not_found', message: 'No such edge' });
    const marks = await ctx.db
      .query('countryListEdgeMarks')
      .withIndex('by_edge', (q) => q.eq('edgeId', edgeId))
      .collect();
    const lists = [];
    for (const a of await watchedAllowlists(ctx.db, now)) {
      const addresses = [];
      for (const family of MARK_FAMILIES) {
        const address = e.status === 'active' ? edgeAddressOf(e, family) : undefined;
        if (address === undefined) continue;
        const m = marks.find((x) => x.listId === a.list._id && x.family === family) ?? null;
        const at = { address, activeVersionId: a.versionId };
        const state = markState(m, at);
        const since = markSince(m, state);
        addresses.push({
          family,
          address,
          state,
          since: since ? new Date(since).toISOString() : null,
          checkedAt: m ? new Date(m.checkedAt).toISOString() : null,
          markId: m ? (m._id as string) : null,
          needsLook: leftNeedsLook(m, at),
        });
      }
      lists.push({
        listId: a.list._id as string,
        label: a.list.label,
        country: a.list.country,
        checked: a.checked,
        fresh: a.fresh,
        enabled: a.list.enabled,
        addresses,
      });
    }
    lists.sort((x, y) => x.country.localeCompare(y.country) || x.label.localeCompare(y.label));
    return { enabled: cfg.lists.enabled, lists };
  },
});

/** "Seen it": the address that left this list asks nothing until it is listed again and leaves again. */
export const markSeen = internalMutation({
  args: {
    listId: v.id('countryLists'),
    markId: v.id('countryListEdgeMarks'),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const mark = await ctx.db.get(a.markId);
    if (!mark || mark.listId !== a.listId)
      throw new ConvexError({ code: 'not_found', message: 'No such address on this list' });
    if (mark.listed || mark.lastListedAt === undefined)
      throw new ConvexError({
        code: 'edge.list.mark_not_left',
        message: 'Only an address that left the list can be marked seen',
      });
    await ctx.db.patch(mark._id, { seenAt: Date.now() });
    await writeAuditLog(ctx, {
      actorType: a.actorAdminId ? 'admin' : 'system',
      actorId: a.actorAdminId ?? undefined,
      action: 'admin.edge.list.mark_seen',
      targetType: 'country_list',
      payload: { listId: mark.listId, edgeId: mark.edgeId, family: mark.family },
    });
    return { ok: true as const };
  },
});
