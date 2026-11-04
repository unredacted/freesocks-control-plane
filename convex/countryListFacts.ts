/**
 * What the country lists say about each finding-names candidate and each
 * family name, stored on the row (docs/edges.md "Country lists", "Names into
 * finding names"). A scope's rescore reads up to 2,000 candidates, and one
 * query may read at most 4,096 index ranges, so reading the lists there would
 * not fit; the facts are kept on the rows instead.
 *
 *  - A deployment-wide generation (`appState countryLists:factsGen`) moves
 *    whenever what evidence may read changes: a version goes into use, a
 *    list is edited, removed, switched off, turns stale or fresh again, or
 *    the switch or the stale window changes.
 *  - A paged refresh then rewrites every row behind the generation, and marks
 *    the scope of each candidate whose facts changed for a rescore.
 *  - New rows (a sweep's finds, a family's new names) carry no generation;
 *    the hourly `country-lists` pass picks them up.
 *
 * Until a list ever moved the generation (0), nothing runs and rows carry
 * nothing.
 */
import { v } from 'convex/values';
import { internalMutation, type DatabaseReader, type MutationCtx } from './_generated/server';
import { internal } from './_generated/api';
import { readStateJson, writeStateJson } from './lib/appStateJson';
import { evidenceLists, storedFactsOf, type StoredFact } from './lib/edges/lists/facts';
import { candidateScope, touchScope } from './lib/edges/sni/hunt/store';
import { startEdgeRecheck } from './countryListEdges';

const GEN_KEY = 'countryLists:factsGen';
const runningKey = (table: FactsTable) => `countryLists:factsRefresh:${table}`;
/** A refresh chain that has not stepped for this long crashed; a kick starts it again. */
const RUNNING_STALE_MS = 15 * 60 * 1000;
/** Rows per step: each name is a few index reads, inside one step's 4,096. */
const PAGE = 200;

const TABLES = ['sniCandidates', 'sniNames'] as const;
type FactsTable = (typeof TABLES)[number];
const tableV = v.union(v.literal('sniCandidates'), v.literal('sniNames'));

export async function factsGen(db: DatabaseReader): Promise<number> {
  return (await readStateJson<number>(db, GEN_KEY)) ?? 0;
}

async function startRefresh(ctx: MutationCtx, table: FactsTable, now: number) {
  const running = await readStateJson<number>(ctx.db, runningKey(table));
  if (running && now - running < RUNNING_STALE_MS) return;
  await writeStateJson(ctx.db, runningKey(table), now);
  await ctx.scheduler.runAfter(0, internal.countryListFacts.refresh, { table });
}

/**
 * What evidence may read changed: move the generation and refresh every row
 * behind it. Edge addresses are checked against the same lists, so their
 * recheck starts too.
 */
export async function bumpFactsGen(ctx: MutationCtx): Promise<void> {
  const now = Date.now();
  await writeStateJson(ctx.db, GEN_KEY, (await factsGen(ctx.db)) + 1);
  for (const table of TABLES) await startRefresh(ctx, table, now);
  await startEdgeRecheck(ctx);
}

const same = (a: readonly StoredFact[] | undefined, b: readonly StoredFact[]) =>
  JSON.stringify(a ?? []) === JSON.stringify(b);

/** One page of rows behind the generation: rewrite their facts, then the next page. */
export const refresh = internalMutation({
  args: { table: tableV },
  handler: async (ctx, { table }) => {
    const now = Date.now();
    const gen = await factsGen(ctx.db);
    // Rows without a generation sort first, so they are behind any generation.
    const rows =
      gen === 0
        ? []
        : table === 'sniCandidates'
          ? await ctx.db
              .query('sniCandidates')
              .withIndex('by_on_lists_gen', (q) => q.lt('onListsGen', gen))
              .take(PAGE)
          : await ctx.db
              .query('sniNames')
              .withIndex('by_on_lists_gen', (q) => q.lt('onListsGen', gen))
              .take(PAGE);
    const lists = rows.length > 0 ? await evidenceLists(ctx.db, now) : [];
    let changed = 0;
    for (const r of rows) {
      const facts = await storedFactsOf(ctx.db, lists, r.name);
      const moved = !same(r.onLists, facts);
      await ctx.db.patch(r._id, {
        onLists: facts.length > 0 ? facts : undefined,
        onListsGen: gen,
      });
      if (!moved) continue;
      changed++;
      // A candidate's score reads its facts: its scope is recounted.
      if (table === 'sniCandidates' && 'sources' in r)
        await touchScope(ctx.db, candidateScope(r), now);
    }
    if (rows.length === PAGE) {
      await writeStateJson(ctx.db, runningKey(table), now);
      await ctx.scheduler.runAfter(0, internal.countryListFacts.refresh, { table });
    } else await writeStateJson(ctx.db, runningKey(table), 0);
    return { rows: rows.length, changed };
  },
});

/** Start a refresh for any table with rows behind the generation (new rows, a crashed chain). */
export const kick = internalMutation({
  args: {},
  handler: async (ctx) => {
    const gen = await factsGen(ctx.db);
    if (gen === 0) return { kicked: [] as string[] };
    const now = Date.now();
    const kicked: string[] = [];
    for (const table of TABLES) {
      const behind =
        table === 'sniCandidates'
          ? await ctx.db
              .query('sniCandidates')
              .withIndex('by_on_lists_gen', (q) => q.lt('onListsGen', gen))
              .first()
          : await ctx.db
              .query('sniNames')
              .withIndex('by_on_lists_gen', (q) => q.lt('onListsGen', gen))
              .first();
      if (!behind) continue;
      await startRefresh(ctx, table, now);
      kicked.push(table);
    }
    return { kicked };
  },
});
