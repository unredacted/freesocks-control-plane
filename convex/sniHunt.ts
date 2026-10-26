/**
 * Finding names (docs/edges.md "Finding names"): the only writer of
 * `sniCandidates` (but for the family import marking a held name `added`,
 * `lib/edges/sni/hunt/store.ts`), `sniHuntIgnores`, `sniHuntRuns`,
 * `sniHuntCt`, `sniHuntCalls` and `sniHuntScopes`.
 *
 * Candidate REALITY server names come from passive sources only: the
 * certificate a family's target already presents, a pasted list or seed, a
 * top-sites list resolved by ordinary DNS lookups and matched to a network's
 * stored ranges, and certificate transparency. No IP range is ever scanned.
 * A candidate is shown with qualification's own verdict and a score; adding
 * one goes through the family's normal qualification (`sniFamilies.importNames`).
 * Nothing here adds, activates or marks a name by itself.
 *
 * The network work runs in `sniHuntOps.ts` (actions, under the 120 s action
 * limit): the sweep is a chain of short steps holding a lease, and every
 * result is written back with a compare-and-set, so a cancelled run or a
 * duplicate step changes nothing.
 *
 * Audit payloads carry slugs and COUNTS only, never a name or an address.
 */
import { ConvexError, v } from 'convex/values';
import {
  internalMutation,
  internalQuery,
  type MutationCtx,
  type QueryCtx,
} from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { internal } from './_generated/api';
import { writeAuditLog } from './lib/audit';
import { recordHeartbeat } from './cronHeartbeat';
import { admitted, assertAdmission } from './lib/edges/maintenance';
import { hasPrefixes, type NetworkPrefixes } from './lib/edges/networks';
import { readStateJson, writeStateJson } from './lib/appStateJson';
import { resolveSniHuntConfig } from './lib/sniConfig';
import { huntName, parseSeed, siteOf, type SeedNetwork } from './lib/edges/sni/hunt/sources';
import { candidateScope, scopeRow, touchScope } from './lib/edges/sni/hunt/store';
import { MAX_NETWORKS } from './edgeNetworks';
import {
  passesAfterCheck,
  scoreCandidate,
  stateAfterCheck,
  type CandidateState,
} from './lib/edges/sni/hunt/score';

type Candidate = Doc<'sniCandidates'>;
type Source = Candidate['sources'][number];
interface Scope {
  networkId?: Id<'edgeNetworks'>;
  familyId?: Id<'sniFamilies'>;
}

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
/** Candidates one network or family holds. */
export const MAX_CANDIDATES_PER_SCOPE = 2000;
/** A step or a check run holds its lease this long (above the 120 s action limit). */
export const HUNT_LEASE_MS = 3 * MIN;
/** A candidate that left its network is deleted after this long. */
const GONE_KEEP_MS = 30 * DAY;
/** A complete certificate-transparency answer is reused this long. */
const CT_FRESH_MS = 7 * DAY;
/** An errored certificate-transparency read is tried again after this long. */
const CT_ERROR_RETRY_MS = 6 * HOUR;
/** Request rows are kept this long (the budgets look back one hour). */
const CALLS_KEEP_MS = 2 * HOUR;
/** A list download that never finished is given up after this long. */
const DOWNLOAD_TIMEOUT_MS = 30 * MIN;
/** Rows walked per claim to find the due candidates. */
const CHECK_SCAN_CAP = 400;
/** Domains one certificate-transparency request may name. */
const CT_DOMAINS_PER_REQUEST = 10;
/** Lines one import may carry. */
const MAX_IMPORT_LINES = 1000;
/** What one seed may carry: each name costs a few index reads in the one mutation. */
const SEED_MAX_NAMES = 800;
const SEED_MAX_FAMILIES = 100;
/** Dirty scopes recounted per cron tick, before the one in turn. */
const DIRTY_SCOPES_PER_TICK = 2;
/** List chunks deleted per mutation (each holds up to SWEEP_CHUNK_ENTRIES lines). */
const CHUNK_DROP_PAGE = 16;

const actor = { actorAdminId: v.optional(v.id('adminUsers')) };
const refuse = (code: string, message: string): never => {
  throw new ConvexError({ code, message });
};

async function audit(
  ctx: MutationCtx,
  action: string,
  actorAdminId: Id<'adminUsers'> | undefined,
  payload: Record<string, unknown>,
) {
  await writeAuditLog(ctx, {
    actorType: actorAdminId ? 'admin' : 'system',
    actorId: actorAdminId ?? undefined,
    action,
    targetType: 'sni_hunt',
    payload,
  });
}

const iso = (ms: number | undefined) => (ms ? new Date(ms).toISOString() : null);
const sameScope = (c: Scope, s: Scope) => c.networkId === s.networkId && c.familyId === s.familyId;
/** Ready: not ignored, added, gone or failing, and passed its last check. */
const passing = (c: Pick<Candidate, 'state' | 'check'>) =>
  c.state === 'new' && c.check?.code === null;

// --- scopes ----------------------------------------------------------------------------------

/** A family scope carries the family's network too, so its names are judged on it. */
async function scopeOf(
  db: QueryCtx['db'],
  a: { network?: string; family?: string },
): Promise<{
  scope: Scope;
  network: Doc<'edgeNetworks'> | null;
  family: Doc<'sniFamilies'> | null;
}> {
  if (a.family) {
    const f = await db
      .query('sniFamilies')
      .withIndex('by_slug', (q) => q.eq('slug', a.family!))
      .unique();
    if (!f) return refuse('not_found', 'No such family');
    const network = f.networkId ? await db.get(f.networkId) : null;
    return {
      scope: { familyId: f._id, ...(f.networkId ? { networkId: f.networkId } : {}) },
      network,
      family: f,
    };
  }
  if (a.network) {
    const n = await db
      .query('edgeNetworks')
      .withIndex('by_slug', (q) => q.eq('slug', a.network!))
      .unique();
    if (!n) return refuse('not_found', 'No such network');
    return { scope: { networkId: n._id }, network: n, family: null };
  }
  return refuse('edge.sni.hunt.no_scope', 'Name a network or a family');
}

function scopeRows(db: QueryCtx['db'], s: Scope) {
  return db
    .query('sniCandidates')
    .withIndex('by_scope_base', (q) => q.eq('networkId', s.networkId).eq('familyId', s.familyId));
}

/** Whether an operator ignored this name, or its site, here or everywhere. */
async function isIgnored(db: QueryCtx['db'], name: string, site: string, s: Scope) {
  for (const [kind, key] of [
    ['name', name],
    ['site', site],
  ] as const) {
    for await (const r of db.query('sniHuntIgnores').withIndex('by_key', (q) => q.eq('key', key))) {
      if (r.kind !== kind) continue;
      if ((!r.networkId && !r.familyId) || sameScope(r, s)) return true;
    }
  }
  return false;
}

export interface UpsertTally {
  added: number;
  known: number;
  ignored: number;
  inFamily: number;
  invalid: number;
  capped: number;
}
const emptyTally = (): UpsertTally => ({
  added: 0,
  known: 0,
  ignored: 0,
  inFamily: 0,
  invalid: 0,
  capped: 0,
});

/**
 * Add names to a scope as candidates from one source. A name already there
 * gains the source (and the better rank); a name a family already holds, an
 * ignored one and one past the scope's cap are counted, never added.
 */
async function upsertNames(
  ctx: MutationCtx,
  s: Scope,
  source: Source,
  items: ReadonlyArray<{ name: string; rank?: number }>,
  now: number,
): Promise<UpsertTally> {
  const t = emptyTally();
  let size: number | null = null;
  for (const item of items) {
    const name = huntName(item.name);
    if (!name) {
      t.invalid++;
      continue;
    }
    const rank = item.rank && item.rank > 0 ? item.rank : undefined;
    const mine = await ctx.db
      .query('sniCandidates')
      .withIndex('by_name_scope', (q) =>
        q.eq('name', name).eq('networkId', s.networkId).eq('familyId', s.familyId),
      )
      .first();
    if (mine) {
      const sources = mine.sources.includes(source) ? mine.sources : [...mine.sources, source];
      const better = rank !== undefined && (mine.rank === undefined || rank < mine.rank);
      if (sources !== mine.sources || better)
        await ctx.db.patch(mine._id, {
          sources,
          ...(better ? { rank } : {}),
          updatedAt: now,
        });
      t.known++;
      continue;
    }
    const held = await ctx.db
      .query('sniNames')
      .withIndex('by_name', (q) => q.eq('name', name))
      .first();
    if (held) {
      t.inFamily++;
      continue;
    }
    const site = siteOf(name);
    if (await isIgnored(ctx.db, name, site, s)) {
      t.ignored++;
      continue;
    }
    // The scope's count (inserts add to it at once, so it never runs short).
    size ??= (await scopeRow(ctx.db, s))?.total ?? 0;
    if (size >= MAX_CANDIDATES_PER_SCOPE) {
      t.capped++;
      continue;
    }
    await ctx.db.insert('sniCandidates', {
      name,
      site,
      ...(s.networkId ? { networkId: s.networkId } : {}),
      ...(s.familyId ? { familyId: s.familyId } : {}),
      sources: [source],
      ...(rank !== undefined ? { rank } : {}),
      state: 'new',
      checkGen: 0,
      checkDueAt: 0,
      passes: 0,
      baseScore: 0,
      score: 0,
      firstSeenAt: now,
      updatedAt: now,
    });
    size++;
    t.added++;
  }
  if (t.added > 0) await touchScope(ctx.db, s, now, t.added);
  return t;
}

/** Names from an action (a target's certificate) into a family's scope. */
export const addFamilyCandidates = internalMutation({
  args: {
    slug: v.string(),
    source: v.union(v.literal('cert'), v.literal('ct')),
    names: v.array(v.string()),
    ...actor,
  },
  handler: async (ctx, a) => {
    const { scope, family } = await scopeOf(ctx.db, { family: a.slug });
    const tally = await upsertNames(
      ctx,
      scope,
      a.source,
      a.names.slice(0, MAX_IMPORT_LINES).map((name) => ({ name })),
      Date.now(),
    );
    await audit(ctx, 'edge.sni.hunt.cert', a.actorAdminId, { slug: family!.slug, ...tally });
    return tally;
  },
});

// --- imports -------------------------------------------------------------------------------------

/**
 * A pasted list (into a network or a family) or a seed. A seed only makes
 * candidates: for each of its networks FCP has, the family targets become
 * network candidates; for each of its families FCP has, its names become that
 * family's candidates (otherwise the network's). What the seed describes that
 * FCP lacks comes back as `proposals`, for the operator to create; nothing is
 * created here.
 */
export const importCandidates = internalMutation({
  args: {
    network: v.optional(v.string()),
    family: v.optional(v.string()),
    lines: v.optional(v.array(v.string())),
    seed: v.optional(v.any()),
    ...actor,
  },
  handler: async (ctx, a) => {
    const now = Date.now();
    const total = emptyTally();
    const sum = (t: UpsertTally) => {
      for (const k of Object.keys(total) as (keyof UpsertTally)[]) total[k] += t[k];
    };
    const proposals: {
      networks: { slug: string; label: string; asns: number[] }[];
      families: Array<SeedNetwork['families'][number] & { network: string }>;
    } = { networks: [], families: [] };
    if (a.seed !== undefined) {
      const seed = parseSeed(a.seed);
      if (!seed) return refuse('edge.sni.hunt.bad_seed', 'That is not a seed');
      const families = seed.flatMap((n) => n.families);
      const names = families.reduce((sum, f) => sum + 1 + f.names.length, 0);
      if (names > SEED_MAX_NAMES || families.length > SEED_MAX_FAMILIES)
        return refuse(
          'edge.sni.hunt.too_many',
          `A seed holds at most ${SEED_MAX_NAMES} names in ${SEED_MAX_FAMILIES} families at a time`,
        );
      for (const n of seed) {
        const net = await ctx.db
          .query('edgeNetworks')
          .withIndex('by_slug', (q) => q.eq('slug', n.slug))
          .unique();
        if (!net) proposals.networks.push({ slug: n.slug, label: n.label, asns: n.asns });
        for (const f of n.families) {
          const fam = await ctx.db
            .query('sniFamilies')
            .withIndex('by_slug', (q) => q.eq('slug', f.slug))
            .unique();
          if (fam) {
            sum(
              await upsertNames(
                ctx,
                { familyId: fam._id, ...(fam.networkId ? { networkId: fam.networkId } : {}) },
                'seed',
                f.names.map((name) => ({ name })),
                now,
              ),
            );
            continue;
          }
          proposals.families.push({ ...f, network: n.slug });
          if (!net) continue;
          // No family yet: the target and its names wait on the network.
          sum(
            await upsertNames(
              ctx,
              { networkId: net._id },
              'seed',
              [{ name: f.targetAddress, rank: f.rank }, ...f.names.map((name) => ({ name }))],
              now,
            ),
          );
        }
      }
      await audit(ctx, 'edge.sni.hunt.import', a.actorAdminId, { kind: 'seed', ...total });
      return { ...total, proposals };
    }
    const { scope, network, family } = await scopeOf(ctx.db, a);
    const lines = (a.lines ?? []).map((l) => l.trim()).filter(Boolean);
    if (lines.length > MAX_IMPORT_LINES)
      return refuse('edge.sni.hunt.too_many', `At most ${MAX_IMPORT_LINES} lines at a time`);
    sum(
      await upsertNames(
        ctx,
        scope,
        'pasted',
        lines.map((name) => ({ name })),
        now,
      ),
    );
    await audit(ctx, 'edge.sni.hunt.import', a.actorAdminId, {
      kind: 'lines',
      slug: family?.slug ?? network?.slug,
      ...total,
    });
    return { ...total, proposals };
  },
});

// --- operator actions on candidates ----------------------------------------------------------

/** A scope's candidates of one site, through its index (never the whole scope). */
function siteRows(db: QueryCtx['db'], s: Scope, site: string) {
  return db
    .query('sniCandidates')
    .withIndex('by_scope_site', (q) =>
      q.eq('networkId', s.networkId).eq('familyId', s.familyId).eq('site', site),
    )
    .take(MAX_CANDIDATES_PER_SCOPE);
}

/** The names and sites ignored for a scope or everywhere, read once. */
async function ignoredIn(db: QueryCtx['db'], s: Scope) {
  const names = new Set<string>();
  const sites = new Set<string>();
  const keep = (r: Doc<'sniHuntIgnores'>) => (r.kind === 'name' ? names : sites).add(r.key);
  for await (const r of s.familyId
    ? db.query('sniHuntIgnores').withIndex('by_family', (q) => q.eq('familyId', s.familyId))
    : db.query('sniHuntIgnores').withIndex('by_network', (q) => q.eq('networkId', s.networkId)))
    if (sameScope(r, s)) keep(r);
  for await (const r of db
    .query('sniHuntIgnores')
    .withIndex('by_network', (q) => q.eq('networkId', undefined)))
    if (!r.familyId) keep(r);
  return { names, sites };
}

export const setCandidates = internalMutation({
  args: {
    ids: v.array(v.string()),
    action: v.union(v.literal('ignore'), v.literal('unignore'), v.literal('recheck')),
    kind: v.optional(v.union(v.literal('name'), v.literal('site'))),
    ...actor,
  },
  handler: async (ctx, a) => {
    const now = Date.now();
    let changed = 0;
    // A site is handled once per scope, however many of its names were picked.
    const sitesDone = new Set<string>();
    const touched = new Map<string, Scope>();
    for (const raw of a.ids.slice(0, 200)) {
      const id = ctx.db.normalizeId('sniCandidates', raw);
      const c = id ? await ctx.db.get(id) : null;
      if (!c) continue;
      const scope = candidateScope(c);
      const scopeKey = `${scope.networkId ?? ''}|${scope.familyId ?? ''}`;
      if (a.action === 'recheck') {
        if (c.state === 'ignored' || c.state === 'added') continue;
        await ctx.db.patch(c._id, { checkDueAt: 0, updatedAt: now });
        changed++;
        continue;
      }
      const kind = a.kind ?? 'name';
      const key = kind === 'site' ? c.site : c.name;
      if (a.action === 'ignore') {
        if (kind === 'site') {
          if (sitesDone.has(`${scopeKey}|${c.site}`)) continue;
          sitesDone.add(`${scopeKey}|${c.site}`);
        }
        let existing = false;
        for await (const r of ctx.db
          .query('sniHuntIgnores')
          .withIndex('by_key', (q) => q.eq('key', key)))
          if (r.kind === kind && sameScope(r, scope)) existing = true;
        if (!existing)
          await ctx.db.insert('sniHuntIgnores', {
            kind,
            key,
            ...scope,
            at: now,
            ...(a.actorAdminId ? { by: a.actorAdminId } : {}),
          });
        const rows = kind === 'site' ? await siteRows(ctx.db, scope, c.site) : [c];
        for (const r of rows)
          if (r.state !== 'added' && r.state !== 'ignored') {
            await ctx.db.patch(r._id, { state: 'ignored', updatedAt: now });
            touched.set(scopeKey, scope);
            changed++;
          }
        continue;
      }
      // unignore: the name's and its site's ignores in this scope go. A site's
      // ignore covered every name of the site here, so all of them come back
      // (unless a name of theirs is ignored on its own), and are checked again.
      if (sitesDone.has(`${scopeKey}|${c.site}`)) continue;
      let siteRule = false;
      for (const [k, key2] of [
        ['name', c.name],
        ['site', c.site],
      ] as const) {
        const rows = await ctx.db
          .query('sniHuntIgnores')
          .withIndex('by_key', (q) => q.eq('key', key2))
          .collect();
        for (const r of rows)
          if (r.kind === k && sameScope(r, scope)) {
            await ctx.db.delete(r._id);
            if (k === 'site') siteRule = true;
          }
      }
      if (siteRule) sitesDone.add(`${scopeKey}|${c.site}`);
      const back = siteRule ? await siteRows(ctx.db, scope, c.site) : [c];
      // What is still ignored, read once for the site's names (never per name).
      const still = siteRule ? await ignoredIn(ctx.db, scope) : null;
      for (const r of back) {
        if (r.state !== 'ignored') continue;
        if (r._id !== c._id && still && (still.names.has(r.name) || still.sites.has(r.site)))
          continue;
        await ctx.db.patch(r._id, { state: 'new', checkDueAt: 0, updatedAt: now });
        touched.set(scopeKey, scope);
        changed++;
      }
    }
    for (const scope of touched.values()) await touchScope(ctx.db, scope, now);
    await audit(ctx, `edge.sni.hunt.${a.action}`, a.actorAdminId, {
      count: changed,
      ...(a.action === 'ignore' ? { kind: a.kind ?? 'name' } : {}),
    });
    return { changed };
  },
});

// --- the top-sites sweep -------------------------------------------------------------------------

async function activeRun(db: QueryCtx['db']) {
  for (const state of ['running', 'downloading'] as const) {
    const r = await db
      .query('sniHuntRuns')
      .withIndex('by_state', (q) => q.eq('state', state))
      .first();
    if (r) return r;
  }
  return null;
}

async function huntingNetworks(db: QueryCtx['db']) {
  const out: { id: Id<'edgeNetworks'>; prefixes: NetworkPrefixes }[] = [];
  for (const n of await db.query('edgeNetworks').take(200))
    if (n.hunt?.enabled && hasPrefixes(n.prefixes)) out.push({ id: n._id, prefixes: n.prefixes });
  return out;
}

/** The networks a sweep matches against (with ranges, hunting on). */
export const sweepNetworks = internalQuery({
  args: {},
  handler: async (ctx) =>
    (await huntingNetworks(ctx.db)).map((n) => ({ key: n.id as string, prefixes: n.prefixes })),
});

/**
 * A run's stored list goes once the run ends, a page of chunks per mutation:
 * a full list is far more than one transaction may read.
 */
async function dropChunks(ctx: MutationCtx, run: Doc<'sniHuntRuns'>) {
  await ctx.scheduler.runAfter(0, internal.sniHunt.dropRunChunks, { runId: run._id });
}

export const dropRunChunks = internalMutation({
  args: { runId: v.id('sniHuntRuns') },
  handler: async (ctx, a) => {
    const page = await ctx.db
      .query('sniHuntChunks')
      .withIndex('by_run_index', (q) => q.eq('runId', a.runId))
      .take(CHUNK_DROP_PAGE);
    for (const c of page) await ctx.db.delete(c._id);
    if (page.length === CHUNK_DROP_PAGE)
      await ctx.scheduler.runAfter(0, internal.sniHunt.dropRunChunks, a);
    return { deleted: page.length };
  },
});

/** A candidate goes (its scope is recounted). */
async function deleteCandidate(ctx: MutationCtx, c: Candidate) {
  await ctx.db.delete(c._id);
  await touchScope(ctx.db, candidateScope(c), Date.now());
}

/** One chunk of a downloading run's list, kept only while that download is current. */
export const storeChunk = internalMutation({
  args: { runId: v.id('sniHuntRuns'), gen: v.number(), index: v.number(), text: v.string() },
  handler: async (ctx, a) => {
    const run = await ctx.db.get(a.runId);
    if (!run || run.gen !== a.gen || run.state !== 'downloading') return null;
    return await ctx.db.insert('sniHuntChunks', { runId: a.runId, index: a.index, text: a.text });
  },
});

/** A chunk's text for a step (null once the run dropped it). */
export const chunkText = internalQuery({
  args: { id: v.id('sniHuntChunks') },
  handler: async (ctx, a) => (await ctx.db.get(a.id))?.text ?? null,
});

async function startSweepCore(
  ctx: MutationCtx,
  by: Id<'adminUsers'> | undefined,
  now: number,
): Promise<Id<'sniHuntRuns'>> {
  const cfg = await resolveSniHuntConfig(ctx.db);
  if (!cfg.enabled) return refuse('edge.sni.hunt.off', 'Finding names is switched off');
  if (await activeRun(ctx.db)) return refuse('edge.sni.hunt.sweep_running', 'A sweep is running');
  if ((await huntingNetworks(ctx.db)).length === 0)
    return refuse('edge.sni.hunt.no_network', 'No network with ranges is being searched');
  const runId = await ctx.db.insert('sniHuntRuns', {
    state: 'downloading',
    gen: 1,
    depth: cfg.depth,
    wwwDepth: cfg.wwwDepth,
    chunks: [],
    total: 0,
    cursor: 0,
    hits: 0,
    lookups: 0,
    leaseUntil: 0,
    startedAt: now,
    ...(by ? { by } : {}),
    updatedAt: now,
  });
  await ctx.scheduler.runAfter(0, internal.sniHuntOps.downloadList, { runId, gen: 1 });
  return runId;
}

export const startSweep = internalMutation({
  args: { ...actor },
  handler: async (ctx, a) => {
    await assertAdmission(ctx.db, 'probe.request');
    const runId = await startSweepCore(ctx, a.actorAdminId, Date.now());
    await audit(ctx, 'edge.sni.hunt.sweep', a.actorAdminId, { action: 'start' });
    return { runId: runId as string };
  },
});

export const cancelSweep = internalMutation({
  args: { ...actor },
  handler: async (ctx, a) => {
    const run = await activeRun(ctx.db);
    if (!run) return refuse('edge.sni.hunt.no_sweep', 'No sweep is running');
    const now = Date.now();
    // A new generation: whatever a step still has in flight is discarded at its checkpoint.
    await ctx.db.patch(run._id, {
      state: 'cancelled',
      gen: run.gen + 1,
      leaseUntil: 0,
      chunks: [],
      finishedAt: now,
      updatedAt: now,
    });
    await dropChunks(ctx, run);
    await audit(ctx, 'edge.sni.hunt.sweep', a.actorAdminId, { action: 'cancel' });
    return { ok: true as const };
  },
});

/** What the download needs: the run's size, while it is still this generation's download. */
export const runInfo = internalQuery({
  args: { runId: v.id('sniHuntRuns'), gen: v.number() },
  handler: async (ctx, a) => {
    const run = await ctx.db.get(a.runId);
    if (!run || run.gen !== a.gen || run.state !== 'downloading') return null;
    return { depth: run.depth, wwwDepth: run.wwwDepth };
  },
});

/** The download stored the list: the run starts resolving (unless it was cancelled meanwhile). */
export const listReady = internalMutation({
  args: {
    runId: v.id('sniHuntRuns'),
    gen: v.number(),
    chunks: v.array(v.id('sniHuntChunks')),
    total: v.number(),
    listId: v.string(),
    listDate: v.string(),
  },
  handler: async (ctx, a) => {
    const run = await ctx.db.get(a.runId);
    if (!run || run.gen !== a.gen || run.state !== 'downloading') {
      for (const id of a.chunks) if (await ctx.db.get(id)) await ctx.db.delete(id);
      return { ok: false };
    }
    const now = Date.now();
    await ctx.db.patch(run._id, {
      state: a.total > 0 ? 'running' : 'done',
      chunks: a.total > 0 ? a.chunks : [],
      total: a.total,
      listId: a.listId,
      listDate: a.listDate,
      ...(a.total > 0 ? {} : { finishedAt: now }),
      updatedAt: now,
    });
    if (a.total === 0) {
      for (const id of a.chunks) if (await ctx.db.get(id)) await ctx.db.delete(id);
    } else {
      // The first step of the chain starts at once.
      await ctx.scheduler.runAfter(0, internal.sniHuntOps.sweepStep, { runId: run._id });
    }
    return { ok: true };
  },
});

export const runFailed = internalMutation({
  args: { runId: v.id('sniHuntRuns'), gen: v.number(), error: v.string() },
  handler: async (ctx, a) => {
    const run = await ctx.db.get(a.runId);
    if (!run || run.gen !== a.gen || (run.state !== 'downloading' && run.state !== 'running'))
      return { ok: false };
    const now = Date.now();
    await ctx.db.patch(run._id, {
      state: 'failed',
      error: a.error.slice(0, 40),
      chunks: [],
      leaseUntil: 0,
      finishedAt: now,
      updatedAt: now,
    });
    await dropChunks(ctx, run);
    return { ok: true };
  },
});

/**
 * A step takes the run: only a running run, of the generation it reads, whose
 * lease has lapsed. A second step finds the lease held and leaves.
 */
export const stepClaim = internalMutation({
  args: { runId: v.id('sniHuntRuns'), leaseId: v.string(), now: v.optional(v.number()) },
  handler: async (ctx, a) => {
    const now = a.now ?? Date.now();
    const run = await ctx.db.get(a.runId);
    if (!run || run.state !== 'running' || run.leaseUntil > now) return null;
    const cfg = await resolveSniHuntConfig(ctx.db);
    if (!cfg.enabled || !(await admitted(ctx.db))) return null;
    await ctx.db.patch(run._id, {
      leaseUntil: now + HUNT_LEASE_MS,
      leaseId: a.leaseId,
      lastStepAt: now,
      updatedAt: now,
    });
    return {
      gen: run.gen,
      cursor: run.cursor,
      total: run.total,
      chunks: run.chunks as string[],
      lookupsPerSecond: cfg.lookupsPerSecond,
    };
  },
});

/**
 * One chunk's results. Applied only under the claimed generation and lease,
 * from the cursor the step started at: a cancelled run, a step that lost its
 * lease, or one that another step overtook writes nothing.
 */
export const stepCheckpoint = internalMutation({
  args: {
    runId: v.id('sniHuntRuns'),
    gen: v.number(),
    leaseId: v.string(),
    from: v.number(),
    to: v.number(),
    lookups: v.number(),
    hits: v.array(v.object({ name: v.string(), rank: v.number(), networks: v.array(v.string()) })),
    now: v.optional(v.number()),
  },
  handler: async (ctx, a) => {
    const now = a.now ?? Date.now();
    const run = await ctx.db.get(a.runId);
    if (
      !run ||
      run.state !== 'running' ||
      run.gen !== a.gen ||
      run.leaseId !== a.leaseId ||
      run.cursor !== a.from ||
      a.to <= a.from
    )
      return { ok: false as const };
    let added = 0;
    const byNetwork = new Map<string, { name: string; rank: number }[]>();
    for (const h of a.hits)
      for (const key of h.networks) byNetwork.set(key, [...(byNetwork.get(key) ?? []), h]);
    for (const [key, items] of byNetwork) {
      const id = ctx.db.normalizeId('edgeNetworks', key);
      const n = id ? await ctx.db.get(id) : null;
      // A network switched off (or removed) since the step read the list keeps nothing.
      if (!n?.hunt?.enabled) continue;
      added += (await upsertNames(ctx, { networkId: n._id }, 'toplist', items, now)).added;
    }
    const to = Math.min(a.to, run.total);
    const done = to >= run.total;
    await ctx.db.patch(run._id, {
      cursor: to,
      hits: run.hits + added,
      lookups: run.lookups + a.lookups,
      leaseUntil: done ? 0 : now + HUNT_LEASE_MS,
      ...(done ? { state: 'done' as const, finishedAt: now, chunks: [] } : {}),
      updatedAt: now,
    });
    if (done) {
      await dropChunks(ctx, run);
      await audit(ctx, 'edge.sni.hunt.sweep', undefined, {
        action: 'done',
        hits: run.hits + added,
        lookups: run.lookups + a.lookups,
      });
    }
    return { ok: true as const, done };
  },
});

/** A step that ends before the run does hands the lease back. */
export const stepRelease = internalMutation({
  args: { runId: v.id('sniHuntRuns'), leaseId: v.string() },
  handler: async (ctx, a) => {
    const run = await ctx.db.get(a.runId);
    if (run && run.leaseId === a.leaseId && run.state === 'running')
      await ctx.db.patch(run._id, { leaseUntil: 0, updatedAt: Date.now() });
  },
});

// --- checks ----------------------------------------------------------------------------------------

export interface ClaimedCheck {
  id: Id<'sniCandidates'>;
  gen: number;
  name: string;
  /** The family's target (a family candidate), or null: the candidate is its own target. */
  target: { address: string; port: number; requireH2: boolean } | null;
  /** The key of its network in `networks`, when it has one. */
  network?: string;
}

/**
 * The due candidates for one check run, each claimed under a new generation
 * and a lease. Ignored and added candidates step aside (they are not checked);
 * a candidate whose family or network is gone is deleted; one whose network has
 * no ranges yet waits.
 */
export const claimChecks = internalMutation({
  args: { now: v.optional(v.number()) },
  handler: async (ctx, a) => {
    const now = a.now ?? Date.now();
    const cfg = await resolveSniHuntConfig(ctx.db);
    const empty = { checks: [] as ClaimedCheck[], networks: {} as Record<string, NetworkPrefixes> };
    if (!cfg.enabled || !(await admitted(ctx.db))) return empty;
    const later = now + cfg.recheckHours * HOUR;
    const out: ClaimedCheck[] = [];
    const nets = new Map<string, NetworkPrefixes | null>();
    const fams = new Map<string, Doc<'sniFamilies'> | null>();
    const due = await ctx.db
      .query('sniCandidates')
      .withIndex('by_check_due', (q) => q.lte('checkDueAt', now))
      .take(CHECK_SCAN_CAP);
    for (const c of due) {
      if (out.length >= cfg.checksPerTick) break;
      if (c.state === 'ignored' || c.state === 'added') {
        await ctx.db.patch(c._id, { checkDueAt: later });
        continue;
      }
      if (c.checkLeaseUntil && c.checkLeaseUntil > now) continue;
      let target: ClaimedCheck['target'] = null;
      if (c.familyId) {
        const k = c.familyId as string;
        if (!fams.has(k)) fams.set(k, await ctx.db.get(c.familyId));
        const f = fams.get(k);
        // Gone, or moved to another network since it was found: its scope is no more.
        if (!f || f.networkId !== c.networkId) {
          await deleteCandidate(ctx, c);
          continue;
        }
        target = { address: f.target.address, port: f.target.port, requireH2: f.requireH2 };
      }
      if (c.networkId) {
        const k = c.networkId as string;
        if (!nets.has(k)) {
          const n = await ctx.db.get(c.networkId);
          nets.set(k, n ? (hasPrefixes(n.prefixes) ? n.prefixes : null) : null);
          if (!n) {
            await deleteCandidate(ctx, c);
            continue;
          }
        }
        if (!nets.get(k)) {
          await ctx.db.patch(c._id, { checkDueAt: later });
          continue;
        }
      }
      const gen = c.checkGen + 1;
      await ctx.db.patch(c._id, { checkGen: gen, checkLeaseUntil: now + HUNT_LEASE_MS });
      out.push({
        id: c._id,
        gen,
        name: c.name,
        target,
        ...(c.networkId ? { network: c.networkId as string } : {}),
      });
    }
    const used = new Set(out.map((o) => o.network).filter((k): k is string => !!k));
    return {
      checks: out,
      networks: Object.fromEntries(
        [...nets].filter(([k, p]) => used.has(k) && p) as [string, NetworkPrefixes][],
      ),
    };
  },
});

/** One check's result, kept only under the generation it was claimed with. */
export const recordCheck = internalMutation({
  args: {
    id: v.id('sniCandidates'),
    gen: v.number(),
    at: v.number(),
    code: v.union(v.string(), v.null()),
    tlsVersion: v.optional(v.string()),
    alpn: v.optional(v.string()),
    answers: v.object({
      v4: v.number(),
      v6: v.number(),
      onNetwork: v.union(
        v.literal('all'),
        v.literal('some'),
        v.literal('none'),
        v.literal('unknown'),
      ),
    }),
    shown: v.array(v.string()),
    extra: v.optional(
      v.object({
        x25519: v.optional(v.boolean()),
        mlkem: v.optional(v.boolean()),
        error: v.optional(v.string()),
      }),
    ),
  },
  handler: async (ctx, a) => {
    const c = await ctx.db.get(a.id);
    if (!c || c.checkGen !== a.gen) return { ok: false as const };
    const cfg = await resolveSniHuntConfig(ctx.db);
    const wasOnNetwork = c.check?.answers.onNetwork === 'all' || c.passes > 0;
    const state: CandidateState = stateAfterCheck(c.state, a.code, wasOnNetwork);
    const passes = passesAfterCheck(c, a.code === null, a.at);
    // The extra handshakes run only after a pass; without one the last facts are dropped.
    const extra =
      a.code === null && a.extra ? { at: a.at, ...a.extra } : a.code === null ? c.extra : undefined;
    const scored = scoreCandidate({
      rank: c.rank,
      code: a.code,
      alpn: a.alpn,
      mlkem: extra?.mlkem,
      passes: passes.passes,
      cluster: c.scoreParts?.cluster ?? 1,
      near: c.scoreParts?.near ?? undefined,
      country: c.scoreParts?.country ?? undefined,
      penalty: c.scoreParts?.penalty,
    });
    await ctx.db.patch(c._id, {
      check: {
        at: a.at,
        code: a.code,
        ...(a.tlsVersion ? { tlsVersion: a.tlsVersion } : {}),
        ...(a.alpn ? { alpn: a.alpn } : {}),
        answers: a.answers,
        shown: a.shown.slice(0, 4),
      },
      extra,
      state,
      goneAt: state === 'gone' ? (c.goneAt ?? a.at) : undefined,
      passes: passes.passes,
      lastPassAt: passes.lastPassAt,
      checkDueAt: a.at + cfg.recheckHours * HOUR,
      checkLeaseUntil: undefined,
      baseScore: scored.baseScore,
      score: scored.score,
      scoreParts: scored.parts,
      updatedAt: a.at,
    });
    if (passing(c) !== (state === 'new' && a.code === null))
      await touchScope(ctx.db, candidateScope(c), a.at);
    return { ok: true as const, state };
  },
});

/** Claimed candidates a run did not reach go back to the queue at once. */
export const releaseChecks = internalMutation({
  args: { items: v.array(v.object({ id: v.id('sniCandidates'), gen: v.number() })) },
  handler: async (ctx, a) => {
    for (const it of a.items) {
      const c = await ctx.db.get(it.id);
      if (c && c.checkGen === it.gen) await ctx.db.patch(c._id, { checkLeaseUntil: undefined });
    }
  },
});

// --- certificate names and certificate transparency ------------------------------------------

/** A family's target, for reading the names on its certificate. */
export const certTarget = internalQuery({
  args: { slug: v.string() },
  handler: async (ctx, a) => {
    const f = await ctx.db
      .query('sniFamilies')
      .withIndex('by_slug', (q) => q.eq('slug', a.slug))
      .unique();
    if (!f) return refuse('not_found', 'No such family');
    const cfg = await resolveSniHuntConfig(ctx.db);
    if (!cfg.enabled) return refuse('edge.sni.hunt.off', 'Finding names is switched off');
    // A maintenance freeze starts no new work, this handshake included.
    await assertAdmission(ctx.db, 'probe.request');
    // The name to present: the target's own hostname, else a name the family already has.
    const literal = /^[0-9.]+$/.test(f.target.address) || f.target.address.includes(':');
    const first = literal
      ? await ctx.db
          .query('sniNames')
          .withIndex('by_family_seq', (q) => q.eq('familyId', f._id))
          .first()
      : null;
    const servername = literal ? first?.name : f.target.address;
    if (!servername)
      return refuse('edge.sni.hunt.no_servername', 'The family has no name to present yet');
    return { address: f.target.address, port: f.target.port, servername };
  },
});

/**
 * Ask for the certificate-transparency names of some domains, for a scope. A
 * domain is reduced to its registrable domain. A complete answer younger than
 * a week is reused; a truncated one reads further from where it stopped; one
 * older than a week starts again.
 */
export const requestCt = internalMutation({
  args: {
    domains: v.array(v.string()),
    network: v.optional(v.string()),
    family: v.optional(v.string()),
    ...actor,
  },
  handler: async (ctx, a) => {
    const cfg = await resolveSniHuntConfig(ctx.db);
    if (!cfg.enabled) return refuse('edge.sni.hunt.off', 'Finding names is switched off');
    if (cfg.ctRequestsPerHour === 0)
      return refuse('edge.sni.hunt.ct_off', 'Certificate-transparency reads are set to none');
    const { scope, network, family } = await scopeOf(ctx.db, a);
    const now = Date.now();
    const domains = [
      ...new Set(
        a.domains
          .map((d) => huntName(d))
          .filter((d): d is string => !!d)
          .map(siteOf),
      ),
    ];
    if (domains.length > CT_DOMAINS_PER_REQUEST)
      return refuse(
        'edge.sni.hunt.too_many',
        `At most ${CT_DOMAINS_PER_REQUEST} domains at a time`,
      );
    let queued = 0;
    let cached = 0;
    for (const domain of domains) {
      let row: Doc<'sniHuntCt'> | null = null;
      for await (const r of ctx.db
        .query('sniHuntCt')
        .withIndex('by_domain', (q) => q.eq('domain', domain)))
        if (sameScope(r, scope)) {
          row = r;
          break;
        }
      if (row?.state === 'complete' && (row.completedAt ?? 0) + CT_FRESH_MS > now) {
        cached++;
        continue;
      }
      if (row) {
        const restart = row.state === 'complete';
        await ctx.db.patch(row._id, {
          state: row.state === 'rate_limited' ? 'rate_limited' : 'partial',
          ...(restart ? { after: undefined, names: 0, completedAt: undefined } : {}),
          pages: 0,
          error: undefined,
          nextAt: Math.max(now, row.backoffUntil ?? 0),
          requestedAt: now,
          updatedAt: now,
        });
      } else
        await ctx.db.insert('sniHuntCt', {
          domain,
          ...scope,
          state: 'partial',
          pages: 0,
          names: 0,
          nextAt: now,
          requestedAt: now,
          updatedAt: now,
        });
      queued++;
    }
    if (queued > 0) await ctx.scheduler.runAfter(0, internal.sniHuntOps.ctStep, {});
    await audit(ctx, 'edge.sni.hunt.ct', a.actorAdminId, {
      slug: family?.slug ?? network?.slug,
      queued,
      cached,
    });
    return { queued, cached };
  },
});

async function callsThisHour(db: QueryCtx['db'], kind: 'ct' | 'timing', now: number, cap: number) {
  return (
    await db
      .query('sniHuntCalls')
      .withIndex('by_kind_at', (q) => q.eq('kind', kind).gt('at', now - HOUR))
      .take(cap + 1)
  ).length;
}

/** The states a read can continue from; `complete` and `truncated` never stand in the queue. */
const CT_READABLE = ['partial', 'rate_limited', 'error'] as const;

/** The row due longest, among the readable states, whose lease and backoff have passed. */
async function dueCtRow(db: QueryCtx['db'], now: number) {
  let best: Doc<'sniHuntCt'> | null = null;
  for (const state of CT_READABLE)
    for (const row of await db
      .query('sniHuntCt')
      .withIndex('by_state_next', (q) => q.eq('state', state).lte('nextAt', now))
      .take(20)) {
      if ((row.leaseUntil ?? 0) > now || (row.backoffUntil ?? 0) > now) continue;
      if (!best || row.nextAt < best.nextAt) best = row;
      break;
    }
  return best;
}

/**
 * One certificate-transparency request: within the hourly budget (every
 * request counts, whatever its answer, and is counted BEFORE it is made), the
 * row that has waited longest.
 */
export const claimCt = internalMutation({
  args: { now: v.optional(v.number()) },
  handler: async (ctx, a) => {
    const now = a.now ?? Date.now();
    const cfg = await resolveSniHuntConfig(ctx.db);
    if (!cfg.enabled || !(await admitted(ctx.db))) return null;
    if ((await callsThisHour(ctx.db, 'ct', now, cfg.ctRequestsPerHour)) >= cfg.ctRequestsPerHour)
      return null;
    const row = await dueCtRow(ctx.db, now);
    if (!row) return null;
    await ctx.db.insert('sniHuntCalls', { kind: 'ct', at: now });
    await ctx.db.patch(row._id, { leaseUntil: now + HUNT_LEASE_MS, updatedAt: now });
    return { id: row._id, domain: row.domain, after: row.after ?? null };
  },
});

export const recordCt = internalMutation({
  args: {
    id: v.id('sniHuntCt'),
    outcome: v.union(
      v.object({
        kind: v.literal('page'),
        names: v.array(v.string()),
        lastId: v.union(v.string(), v.null()),
        done: v.boolean(),
      }),
      v.object({ kind: v.literal('rate_limited'), retryAt: v.number() }),
      v.object({ kind: v.literal('error'), code: v.string() }),
    ),
    now: v.optional(v.number()),
  },
  handler: async (ctx, a) => {
    const now = a.now ?? Date.now();
    const row = await ctx.db.get(a.id);
    if (!row) return { ok: false };
    const o = a.outcome;
    if (o.kind === 'rate_limited') {
      await ctx.db.patch(row._id, {
        state: 'rate_limited',
        backoffUntil: o.retryAt,
        nextAt: o.retryAt,
        leaseUntil: undefined,
        updatedAt: now,
      });
      return { ok: true };
    }
    if (o.kind === 'error') {
      await ctx.db.patch(row._id, {
        state: 'error',
        error: o.code.slice(0, 40),
        nextAt: now + CT_ERROR_RETRY_MS,
        leaseUntil: undefined,
        updatedAt: now,
      });
      return { ok: true };
    }
    const cfg = await resolveSniHuntConfig(ctx.db);
    const scope: Scope = {
      ...(row.networkId ? { networkId: row.networkId } : {}),
      ...(row.familyId ? { familyId: row.familyId } : {}),
    };
    const exists = scope.familyId
      ? await ctx.db.get(scope.familyId)
      : scope.networkId
        ? await ctx.db.get(scope.networkId)
        : null;
    if (!exists) {
      await ctx.db.delete(row._id);
      return { ok: false };
    }
    // Only names of the domain asked about count (a certificate lists others too).
    const mine = o.names.filter((n) => n === row.domain || n.endsWith(`.${row.domain}`));
    const t = await upsertNames(
      ctx,
      scope,
      'ct',
      mine.map((name) => ({ name })),
      now,
    );
    const pages = row.pages + 1;
    const state = o.done ? 'complete' : pages >= cfg.ctPagesPerDomain ? 'truncated' : 'partial';
    await ctx.db.patch(row._id, {
      state,
      after: o.lastId ?? row.after,
      pages,
      names: row.names + t.added,
      error: undefined,
      backoffUntil: undefined,
      nextAt: now,
      leaseUntil: undefined,
      ...(o.done ? { completedAt: now } : {}),
      updatedAt: now,
    });
    return { ok: true, state };
  },
});

// --- upkeep --------------------------------------------------------------------------------------

/**
 * Recompute one scope's scores: how many passing candidates share each first
 * address (the "names the address serves" part) is a property of the scope,
 * not of one row.
 */
async function rescoreScope(ctx: MutationCtx, s: Scope, now: number) {
  const rows = await scopeRows(ctx.db, s).take(MAX_CANDIDATES_PER_SCOPE);
  const clusters = new Map<string, number>();
  for (const r of rows)
    if (r.check?.code === null && r.check.shown[0])
      clusters.set(r.check.shown[0], (clusters.get(r.check.shown[0]) ?? 0) + 1);
  let changed = 0;
  for (const r of rows) {
    if (!r.check) continue;
    const scored = scoreCandidate({
      rank: r.rank,
      code: r.check.code,
      alpn: r.check.alpn,
      mlkem: r.extra?.mlkem,
      passes: r.passes,
      cluster: r.check.shown[0] ? (clusters.get(r.check.shown[0]) ?? 1) : 1,
      near: r.scoreParts?.near ?? undefined,
      country: r.scoreParts?.country ?? undefined,
      penalty: r.scoreParts?.penalty,
    });
    if (scored.baseScore !== r.baseScore || scored.score !== r.score) {
      await ctx.db.patch(r._id, {
        baseScore: scored.baseScore,
        score: scored.score,
        scoreParts: scored.parts,
        updatedAt: now,
      });
      changed++;
    }
  }
  await recountScope(ctx, s, rows, now);
  return changed;
}

/** A scope's counts from its rows; a scope left empty drops out of the rotation. */
async function recountScope(ctx: MutationCtx, s: Scope, rows: readonly Candidate[], now: number) {
  const row = await scopeRow(ctx.db, s);
  if (rows.length === 0) {
    if (row) await ctx.db.delete(row._id);
    return;
  }
  const counts = { total: rows.length, ready: rows.filter(passing).length };
  if (!row)
    await ctx.db.insert('sniHuntScopes', {
      ...candidateScope(s),
      kind: s.familyId ? 'family' : 'network',
      ...counts,
      countedAt: now,
      updatedAt: now,
    });
  else await ctx.db.patch(row._id, { ...counts, dirty: undefined, countedAt: now, updatedAt: now });
}

const scopeOfRow = (r: Doc<'sniHuntScopes'>): Scope => candidateScope(r);

/** The `_creationTime` of the scope rescored last in turn. */
const RESCORE_KEY = 'sni:hunt:rescore';

/**
 * Cron `sni-hunt` (10 min). It does no network work itself: it keeps the
 * sweep's chain of steps alive (a step that died is taken over once its lease
 * lapses), starts the next sweep when one is due, schedules one check run and
 * one certificate-transparency read when something is due, rescores one scope,
 * and deletes what aged out.
 */
export const tick = internalMutation({
  args: { now: v.optional(v.number()) },
  handler: async (ctx, a) => {
    await recordHeartbeat(ctx, 'sni-hunt');
    const now = a.now ?? Date.now();
    // Housekeeping runs even when switched off.
    for (const g of await ctx.db
      .query('sniCandidates')
      .withIndex('by_gone', (q) => q.gt('goneAt', 0).lt('goneAt', now - GONE_KEEP_MS))
      .take(100))
      await deleteCandidate(ctx, g);
    for (const kind of ['ct', 'timing'] as const)
      for (const c of await ctx.db
        .query('sniHuntCalls')
        .withIndex('by_kind_at', (q) => q.eq('kind', kind).lt('at', now - CALLS_KEEP_MS))
        .take(200))
        await ctx.db.delete(c._id);
    const cfg = await resolveSniHuntConfig(ctx.db);
    if (!cfg.enabled) return { reason: 'off' };
    if (!(await admitted(ctx.db))) return { reason: 'maintenance' };
    const scheduled: string[] = [];
    // The sweep.
    const run = await activeRun(ctx.db);
    if (run?.state === 'downloading' && run.startedAt < now - DOWNLOAD_TIMEOUT_MS) {
      await ctx.db.patch(run._id, {
        state: 'failed',
        error: 'download_timeout',
        gen: run.gen + 1,
        finishedAt: now,
        updatedAt: now,
      });
      await dropChunks(ctx, run);
    } else if (run?.state === 'running' && run.leaseUntil <= now) {
      await ctx.scheduler.runAfter(0, internal.sniHuntOps.sweepStep, { runId: run._id });
      scheduled.push('sweep');
    } else if (!run) {
      const last = await ctx.db.query('sniHuntRuns').withIndex('by_started').order('desc').first();
      const due = !last || (last.finishedAt ?? last.startedAt) + cfg.sweepEveryDays * DAY <= now;
      if (due && (await huntingNetworks(ctx.db)).length > 0) {
        await startSweepCore(ctx, undefined, now);
        scheduled.push('sweep_start');
      }
    }
    // One check run when anything is due.
    const dueCheck = await ctx.db
      .query('sniCandidates')
      .withIndex('by_check_due', (q) => q.lte('checkDueAt', now))
      .first();
    if (dueCheck) {
      await ctx.scheduler.runAfter(0, internal.sniHuntOps.check, {});
      scheduled.push('check');
    }
    // One certificate-transparency read when one is due and the budget has room.
    const dueCt = await dueCtRow(ctx.db, now);
    if (
      dueCt &&
      (await callsThisHour(ctx.db, 'ct', now, cfg.ctRequestsPerHour)) < cfg.ctRequestsPerHour
    ) {
      await ctx.scheduler.runAfter(0, internal.sniHuntOps.ctStep, {});
      scheduled.push('ct');
    }
    // Scopes whose candidates changed are recounted first; then one in turn,
    // through every scope holding candidates (however many there are).
    const done = new Set<string>();
    for (const r of await ctx.db
      .query('sniHuntScopes')
      .withIndex('by_dirty', (q) => q.eq('dirty', true))
      .take(DIRTY_SCOPES_PER_TICK)) {
      await rescoreScope(ctx, scopeOfRow(r), now);
      done.add(r._id);
    }
    const after = (await readStateJson<number>(ctx.db, RESCORE_KEY)) ?? 0;
    const turn =
      (await ctx.db
        .query('sniHuntScopes')
        .withIndex('by_creation_time', (q) => q.gt('_creationTime', after))
        .first()) ?? (await ctx.db.query('sniHuntScopes').withIndex('by_creation_time').first());
    if (turn) {
      if (!done.has(turn._id)) await rescoreScope(ctx, scopeOfRow(turn), now);
      await writeStateJson(ctx.db, RESCORE_KEY, turn._creationTime);
    }
    return { reason: null, scheduled };
  },
});

/**
 * Everything found for a scope that is going away (a network or a family
 * deleted): its candidates, its certificate-log reads and its ignores, a page
 * of each per run, again until none is left.
 */
export const dropScope = internalMutation({
  args: { networkId: v.optional(v.id('edgeNetworks')), familyId: v.optional(v.id('sniFamilies')) },
  handler: async (ctx, a) => {
    const PAGE = 200;
    const fam = a.familyId;
    const net = a.networkId;
    if (!fam && !net) return { deleted: 0 };
    const candidates = fam
      ? await ctx.db
          .query('sniCandidates')
          .withIndex('by_family', (q) => q.eq('familyId', fam))
          .take(PAGE)
      : await ctx.db
          .query('sniCandidates')
          .withIndex('by_scope_base', (q) => q.eq('networkId', net))
          .take(PAGE);
    // A network's own reads and ignores (a family's live under its familyId).
    const ct = fam
      ? await ctx.db
          .query('sniHuntCt')
          .withIndex('by_family', (q) => q.eq('familyId', fam))
          .take(PAGE)
      : await ctx.db
          .query('sniHuntCt')
          .withIndex('by_network', (q) => q.eq('networkId', net))
          .take(PAGE);
    const ignores = fam
      ? await ctx.db
          .query('sniHuntIgnores')
          .withIndex('by_family', (q) => q.eq('familyId', fam))
          .take(PAGE)
      : await ctx.db
          .query('sniHuntIgnores')
          .withIndex('by_network', (q) => q.eq('networkId', net))
          .take(PAGE);
    for (const r of [...candidates, ...ct, ...ignores]) await ctx.db.delete(r._id);
    const more = [candidates, ct, ignores].some((rows) => rows.length === PAGE);
    if (more) await ctx.scheduler.runAfter(0, internal.sniHunt.dropScope, a);
    else
      // Its counts rows go last (a network's include its families' scopes on it).
      for (const r of fam
        ? await ctx.db
            .query('sniHuntScopes')
            .withIndex('by_family', (q) => q.eq('familyId', fam))
            .collect()
        : await ctx.db
            .query('sniHuntScopes')
            .withIndex('by_scope', (q) => q.eq('networkId', net))
            .collect())
        await ctx.db.delete(r._id);
    return { deleted: candidates.length + ct.length + ignores.length };
  },
});

/**
 * Rollback one-off (docs/edges.md "Finding names"): before a build without
 * finding names is deployed over this one, its rows must be gone (a schema
 * push refuses documents it does not describe). Deletes a page of every
 * finding-names table and clears `edgeNetworks.hunt`; run it again until it
 * answers `left: 0`. Deletes found candidates only: no family, name or
 * network is touched otherwise.
 */
export const clearForRollback = internalMutation({
  args: {},
  handler: async (ctx) => {
    const PAGE = 500;
    let deleted = 0;
    let left = 0;
    for (const table of [
      'sniCandidates',
      'sniHuntIgnores',
      'sniHuntChunks',
      'sniHuntRuns',
      'sniHuntCt',
      'sniHuntCalls',
      'sniHuntScopes',
    ] as const) {
      const rows = await ctx.db.query(table).take(PAGE);
      for (const r of rows) {
        await ctx.db.delete(r._id);
      }
      deleted += rows.length;
      if (rows.length === PAGE) left++;
    }
    for (const n of await ctx.db.query('edgeNetworks').take(200))
      if (n.hunt !== undefined) await ctx.db.patch(n._id, { hunt: undefined });
    for (const key of [RESCORE_KEY])
      for (const row of await ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', key))
        .take(1))
        await ctx.db.delete(row._id);
    return { deleted, left };
  },
});

// --- views -----------------------------------------------------------------------------------

function candidateView(c: Candidate, inFamily: { slug: string; label: string } | null) {
  return {
    id: c._id as string,
    name: c.name,
    site: c.site,
    sources: c.sources,
    rank: c.rank ?? null,
    state: c.state,
    inFamily,
    check: c.check
      ? {
          at: new Date(c.check.at).toISOString(),
          code: c.check.code,
          tlsVersion: c.check.tlsVersion ?? null,
          alpn: c.check.alpn ?? null,
          answers: c.check.answers,
          shown: c.check.shown,
        }
      : null,
    extra: c.extra
      ? {
          x25519: c.extra.x25519 ?? null,
          mlkem: c.extra.mlkem ?? null,
          error: c.extra.error ?? null,
        }
      : null,
    passes: c.passes,
    baseScore: c.baseScore,
    score: c.score,
    parts: c.scoreParts ?? null,
    firstSeenAt: new Date(c.firstSeenAt).toISOString(),
  };
}

function ctView(r: Doc<'sniHuntCt'>) {
  return {
    domain: r.domain,
    state: r.state,
    pages: r.pages,
    names: r.names,
    error: r.error ?? null,
    backoffUntil: iso(r.backoffUntil),
    completedAt: iso(r.completedAt),
  };
}

/** Candidates per page of a scope's list. */
const VIEW_PAGE = 200;
const STATES = ['new', 'added', 'ignored', 'gone', 'failing'] as const;

/**
 * One network's or family's candidates, best first, a page at a time, of one
 * state (or all of them): ignored and added rows never take the place of the
 * ones still to decide. With the sites grouped by the first address they live
 * on, and the certificate-log reads for the scope.
 */
export const scopeView = internalQuery({
  args: {
    network: v.optional(v.string()),
    family: v.optional(v.string()),
    state: v.optional(v.union(...STATES.map((x) => v.literal(x)), v.literal('all'))),
    cursor: v.optional(v.union(v.string(), v.null())),
  },
  handler: async (ctx, a) => {
    const { scope, network, family } = await scopeOf(ctx.db, a);
    const state = a.state ?? 'new';
    const base =
      state === 'all'
        ? ctx.db
            .query('sniCandidates')
            .withIndex('by_scope_score', (q) =>
              q.eq('networkId', scope.networkId).eq('familyId', scope.familyId),
            )
        : ctx.db
            .query('sniCandidates')
            .withIndex('by_scope_state_score', (q) =>
              q.eq('networkId', scope.networkId).eq('familyId', scope.familyId).eq('state', state),
            );
    const page = await base
      .order('desc')
      .paginate({ numItems: VIEW_PAGE, cursor: a.cursor ?? null });
    const all = await scopeRows(ctx.db, scope).take(MAX_CANDIDATES_PER_SCOPE);
    const counts = { new: 0, failing: 0, gone: 0, ignored: 0, added: 0, unchecked: 0 };
    for (const c of all) {
      counts[c.state]++;
      if (!c.check && c.state === 'new') counts.unchecked++;
    }
    const families = new Map<string, { slug: string; label: string } | null>();
    const out = [];
    for (const c of page.page) {
      let inFamily: { slug: string; label: string } | null = null;
      if (c.state === 'added') {
        const held = await ctx.db
          .query('sniNames')
          .withIndex('by_name', (q) => q.eq('name', c.name))
          .first();
        if (held) {
          const k = held.familyId as string;
          if (!families.has(k)) {
            const f = await ctx.db.get(held.familyId);
            families.set(k, f ? { slug: f.slug, label: f.label } : null);
          }
          inFamily = families.get(k) ?? null;
        }
      }
      out.push(candidateView(c, inFamily));
    }
    // What each first address serves (a possible target and its names), over the whole scope.
    const groups = new Map<
      string,
      { address: string; names: number; passing: number; best: string; bestScore: number }
    >();
    for (const c of all) {
      if (c.state === 'ignored' || c.state === 'added') continue;
      const address = c.check?.shown[0];
      if (!address) continue;
      const g = groups.get(address) ?? {
        address,
        names: 0,
        passing: 0,
        best: c.name,
        bestScore: -1,
      };
      g.names++;
      if (c.check?.code === null) {
        g.passing++;
        if (c.score > g.bestScore) {
          g.best = c.name;
          g.bestScore = c.score;
        }
      }
      groups.set(address, g);
    }
    const ctRows = family
      ? await ctx.db
          .query('sniHuntCt')
          .withIndex('by_family', (q) => q.eq('familyId', family._id))
          .take(100)
      : await ctx.db
          .query('sniHuntCt')
          .withIndex('by_network', (q) => q.eq('networkId', network!._id))
          .take(100);
    return {
      scope: {
        kind: family ? ('family' as const) : ('network' as const),
        slug: family?.slug ?? network!.slug,
        label: family?.label ?? network!.label,
        network: network ? { slug: network.slug, label: network.label } : null,
        target: family ? { address: family.target.address, port: family.target.port } : null,
        hunt: network?.hunt
          ? { enabled: network.hunt.enabled, place: network.hunt.place ?? null }
          : null,
      },
      candidates: out,
      page: { cursor: page.isDone ? null : page.continueCursor, done: page.isDone },
      groups: [...groups.values()]
        .sort((x, y) => y.passing - x.passing || y.names - x.names)
        .slice(0, 50)
        .map(({ bestScore: _s, ...g }) => g),
      counts,
      ct: ctRows.filter((r) => sameScope(r, scope)).map(ctView),
    };
  },
});

/** The page's head: the settings, the sweep, and what each network and family holds. */
export const overview = internalQuery({
  args: {},
  handler: async (ctx) => {
    const config = await resolveSniHuntConfig(ctx.db);
    const run =
      (await activeRun(ctx.db)) ??
      (await ctx.db.query('sniHuntRuns').withIndex('by_started').order('desc').first());
    // Counts as the scopes' last recount left them (`sniHuntScopes`): a scope
    // whose candidates changed is recounted by the next cron tick.
    const networks = [];
    for (const n of await ctx.db.query('edgeNetworks').take(MAX_NETWORKS)) {
      const row = await scopeRow(ctx.db, { networkId: n._id });
      networks.push({
        slug: n.slug,
        label: n.label,
        hunt: { enabled: !!n.hunt?.enabled, place: n.hunt?.place ?? null },
        ranges: { v4: n.prefixes.v4.length, v6: n.prefixes.v6.length },
        candidates: { total: row?.total ?? 0, ready: row?.ready ?? 0 },
      });
    }
    // Every family holding candidates (a family that moved network may hold two scopes).
    const byFamily = new Map<string, { total: number; ready: number }>();
    for await (const r of ctx.db
      .query('sniHuntScopes')
      .withIndex('by_kind', (q) => q.eq('kind', 'family'))) {
      if (!r.familyId || r.total === 0) continue;
      const had = byFamily.get(r.familyId) ?? { total: 0, ready: 0 };
      byFamily.set(r.familyId, { total: had.total + r.total, ready: had.ready + r.ready });
    }
    const families = [];
    for (const [id, candidates] of byFamily) {
      const f = await ctx.db.get(id as Id<'sniFamilies'>);
      if (f) families.push({ slug: f.slug, label: f.label, candidates });
    }
    networks.sort((x, y) => x.label.localeCompare(y.label));
    families.sort((x, y) => x.label.localeCompare(y.label));
    return {
      config,
      sweep: run
        ? {
            state: run.state,
            listDate: run.listDate ?? null,
            depth: run.depth,
            wwwDepth: run.wwwDepth,
            total: run.total,
            cursor: run.cursor,
            hits: run.hits,
            lookups: run.lookups,
            error: run.error ?? null,
            startedAt: new Date(run.startedAt).toISOString(),
            finishedAt: iso(run.finishedAt),
          }
        : null,
      networks,
      families,
    };
  },
});
