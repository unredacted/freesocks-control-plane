/**
 * A country on its own addresses (docs/edges.md "A country on its own
 * addresses"; pure rules in lib/edges/ownPools.ts).
 *
 * A node that keeps addresses for a country (`relays.providerSet[].audiences`,
 * convex/edgeAudiences.ts) may cut that country over (`relays.ownPools[]`):
 *  - its members are handed their own addresses first, for the primary and the
 *    backup; a shared one only as a fallback (`assignEndpoints` `ownPool`);
 *  - once the cutover has settled, its evidence never replaces a shared
 *    address on the node (veto `own_pool`, lib/edges/scoring.ts);
 *  - its own addresses are replaced under its own daily budget, outside the
 *    node's daily cap, its cooldown and the fleet's caps (`edge.audience_budget`).
 *
 * Prerequisites of a cutover: ordering by country and the country question
 * on, the rendezvous walk on the node, and the country's own addresses there
 * at their count, none blocked there. Stopping is one click (the country's
 * members get today's order again). Every change bumps the node's publication
 * epoch and refreshes the mirrors.
 */
import { ConvexError, v } from 'convex/values';
import { internal } from './_generated/api';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { DatabaseReader, MutationCtx, QueryCtx } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { assertAdmission } from './lib/edges/maintenance';
import { resolveCensoredCountries } from './lib/censoredCountries';
import { COUNTRY_QUESTION_KEY } from './lib/memberCountry';
import { resolveMemberCountryConfig } from './memberCountry';
import { countDeficit } from './lib/edges/providerSet';
import { setStateOf } from './lib/edges/setState';
import {
  assertNoRotationOrQuarantine,
  assertNoRunningSetup,
  bumpEpochAndRefresh,
} from './lib/edges/relayGuards';
import { MAX_AUDIENCE_REPLACES_PER_DAY, resolveEdgeConfig } from './lib/edgeConfig';
import { cutoverRehearsal, ownCodesOf, type CutoverRehearsal } from './lib/edges/ownPools';
import { publishedEdgesOf } from './edgeRender';
import { FRONT_KEYS_PAGE, keyInUse } from './lib/edges/frontKeys';
import { ROTATION_PHASES, isTerminalPhase } from './lib/edges/rotation';
import { AUDIENCE_NEEDS_SPREAD } from './edgeAudiences';

/** How often the keys of a cut-over country still on a body from before its cutover are counted. */
export const OWN_POOL_STALE_EVERY_MS = 60 * 60_000;

async function countryQuestionOn(db: DatabaseReader): Promise<boolean> {
  const row = await db
    .query('appSettings')
    .withIndex('by_key', (q) => q.eq('key', COUNTRY_QUESTION_KEY))
    .unique();
  if (!row) return false;
  try {
    return JSON.parse(row.value) === true;
  } catch {
    return false;
  }
}

type Refusal = { code: string; message: string };

/**
 * Why `code` may not be cut over on this node now, or null. Judged on what
 * the node has in use: its own addresses for that country at their count (in
 * every entry naming it), and none of them blocked there.
 */
export async function cutoverRefusal(
  ctx: { db: QueryCtx['db'] },
  relay: Doc<'relays'>,
  code: string,
  now: number,
): Promise<Refusal | null> {
  const db = ctx.db;
  if (!(await resolveCensoredCountries(db)).codes.includes(code))
    return { code: 'validation', message: `${code} is not on the censored-country list` };
  if (!(await resolveMemberCountryConfig(db)).steer)
    return {
      code: 'edge.audience_needs_steering',
      message: 'Turn on ordering by country under Settings first',
    };
  if (!(await countryQuestionOn(db)))
    return {
      code: 'edge.audience_needs_ask',
      message:
        'Turn on the country question first ("Where members connect from"): a mirror without the member’s answer can only carry shared addresses',
    };
  if (relay.edgePick !== 'hrw1') return AUDIENCE_NEEDS_SPREAD;
  const state = await setStateOf(db, relay, now);
  const wants = state.requirement.audienceWants.filter((w) => w.codes.includes(code));
  if (wants.length === 0)
    return {
      code: 'edge.audience_no_pool',
      message: `No location of this node keeps addresses for ${code}: add them first`,
    };
  if (countDeficit({ ...state.requirement, wants: [], audienceWants: wants }, state.published) > 0)
    return {
      code: 'edge.audience_pool_short',
      message: `${code}’s own addresses here are fewer than their count: let upkeep make them first`,
    };
  const { published } = await publishedEdgesOf(
    ctx,
    relay,
    { kind: 'member' },
    { includeIneligible: true },
  );
  const own = published.filter((e) => e.audience?.includes(code));
  if (own.some((e) => (e.blockedIn ?? []).includes(code)))
    return {
      code: 'edge.audience_pool_blocked',
      message: `An address of ${code}’s own here is blocked there: replace it first`,
    };
  return null;
}

/** The sample render options a rehearsal uses (as the node's members are assigned). */
async function rehearsalOf(
  ctx: { db: QueryCtx['db'] },
  relay: Doc<'relays'>,
  code: string,
): Promise<CutoverRehearsal> {
  const cfg = await resolveEdgeConfig(ctx.db);
  const { published } = await publishedEdgesOf(
    ctx,
    relay,
    { kind: 'member' },
    { includeIneligible: true },
  );
  return cutoverRehearsal(published, code, {
    now: Date.now(),
    preferDistinctProviders: cfg.render.preferDistinctProviders,
    ...(relay.edgePick ? { edgePick: relay.edgePick } : {}),
    includeBackup: true,
    canEmitV6: true,
    minProvenForExclusive: cfg.country.minProvenForExclusive,
  });
}

function normalize(code: string): string {
  return code.trim().toUpperCase();
}

/**
 * The preview before a cutover: whether it may happen now and what it changes
 * for that country's members on this node (synthetic seats).
 */
export const cutoverPreview = internalQuery({
  args: { relayId: v.id('relays'), code: v.string() },
  handler: async (ctx, a) => {
    const relay = await ctx.db.get(a.relayId);
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Node not found' });
    const code = normalize(a.code);
    const own = ownCodesOf(relay).includes(code);
    return {
      code,
      own,
      refusal: own ? null : await cutoverRefusal(ctx, relay, code, Date.now()),
      rehearsal: await rehearsalOf(ctx, relay, code),
    };
  },
});

async function applyOwnPool(
  ctx: MutationCtx,
  relay: Doc<'relays'>,
  code: string,
  own: boolean,
  actorAdminId: Id<'adminUsers'> | undefined,
): Promise<boolean> {
  const was = ownCodesOf(relay).includes(code);
  if (was === own) return false;
  const now = Date.now();
  // The epoch bump below moves the node to `publicationEpoch + 1`.
  const ownPools = own
    ? [...(relay.ownPools ?? []), { code, since: now, epoch: relay.publicationEpoch + 1 }]
    : (relay.ownPools ?? []).filter((p) => p.code !== code);
  await ctx.db.patch(relay._id, {
    ownPools: ownPools.length > 0 ? ownPools : undefined,
    updatedAt: now,
  });
  // What the country's members are handed changes: new epoch, mirrors refreshed.
  await bumpEpochAndRefresh(ctx, (await ctx.db.get(relay._id))!);
  await writeAuditLog(ctx, {
    actorType: 'admin',
    actorId: actorAdminId ?? undefined,
    action: 'edge.relay.own_pool',
    targetType: 'relay',
    targetId: relay._id,
    payload: { relaySlug: relay.slug, country: code, own },
  });
  return true;
}

/** Cut a country over on one node (`own: true`), or stop (`own: false`, never refused). */
export const setOwnPool = internalMutation({
  args: {
    relayId: v.id('relays'),
    code: v.string(),
    own: v.boolean(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const relay = await ctx.db.get(a.relayId);
    if (!relay || relay.deleting)
      throw new ConvexError({ code: 'not_found', message: 'Node not found' });
    const code = normalize(a.code);
    // Only a cutover is new work: stopping is never refused (maintenance, a
    // setup run or a rotation would otherwise pin the country to its own).
    if (a.own) {
      await assertAdmission(ctx.db, 'setup.start');
      await assertNoRunningSetup(ctx.db, relay);
      await assertNoRotationOrQuarantine(ctx.db, relay);
      const refusal = await cutoverRefusal(ctx, relay, code, Date.now());
      if (refusal) throw new ConvexError(refusal);
    }
    const changed = await applyOwnPool(ctx, relay, code, a.own, a.actorAdminId);
    return { ok: true as const, changed };
  },
});

/** A node's guard refusal (a running setup, a rotation or quarantine), as its code, or null. */
async function guardRefusal(db: DatabaseReader, relay: Doc<'relays'>): Promise<string | null> {
  try {
    await assertNoRunningSetup(db, relay);
    await assertNoRotationOrQuarantine(db, relay);
    return null;
  } catch (err) {
    if (err instanceof ConvexError) return String((err.data as { code?: string }).code ?? 'error');
    throw err;
  }
}

/**
 * Cut a country over on every node where it may be now (or stop it on every
 * node): one result per node that keeps addresses for it, with its refusal.
 */
export const setOwnPoolEverywhere = internalMutation({
  args: {
    code: v.string(),
    own: v.boolean(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    if (a.own) await assertAdmission(ctx.db, 'setup.start');
    const code = normalize(a.code);
    const results: Array<{ relaySlug: string; changed: boolean; refusal: string | null }> = [];
    for (const relay of await ctx.db.query('relays').collect()) {
      if (relay.deleting) continue;
      const keeps = (relay.providerSet ?? []).some((p) =>
        (p.audiences ?? []).some((x) => x.codes.includes(code)),
      );
      const isOwn = ownCodesOf(relay).includes(code);
      if (!keeps && !isOwn) continue;
      if (a.own && !isOwn) {
        // The same guards as one node's cutover, each node's refusal reported.
        const guard = await guardRefusal(ctx.db, relay);
        if (guard) {
          results.push({ relaySlug: relay.slug, changed: false, refusal: guard });
          continue;
        }
        const refusal = await cutoverRefusal(ctx, relay, code, Date.now());
        if (refusal) {
          results.push({ relaySlug: relay.slug, changed: false, refusal: refusal.code });
          continue;
        }
      }
      const changed = await applyOwnPool(ctx, relay, code, a.own, a.actorAdminId);
      results.push({ relaySlug: relay.slug, changed, refusal: null });
    }
    return { ok: true as const, results };
  },
});

/**
 * This node's own daily budget for the replacements of its cut-over countries'
 * addresses (`null` = follow the country's, else the fleet's).
 */
export const setOwnBudget = internalMutation({
  args: {
    relayId: v.id('relays'),
    perDay: v.union(v.number(), v.null()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const relay = await ctx.db.get(a.relayId);
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Node not found' });
    if (
      a.perDay !== null &&
      (!Number.isInteger(a.perDay) || a.perDay < 0 || a.perDay > MAX_AUDIENCE_REPLACES_PER_DAY)
    )
      throw new ConvexError({
        code: 'validation',
        message: `Replacements a day must be 0 to ${MAX_AUDIENCE_REPLACES_PER_DAY}, or none to follow the fleet`,
      });
    const perDay = a.perDay ?? undefined;
    if (relay.audienceReplacesPerDay === perDay) return { ok: true as const, changed: false };
    await ctx.db.patch(relay._id, { audienceReplacesPerDay: perDay, updatedAt: Date.now() });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'edge.relay.own_budget',
      targetType: 'relay',
      targetId: relay._id,
      payload: { relaySlug: relay.slug, perDay: a.perDay ?? -1 },
    });
    return { ok: true as const, changed: true };
  },
});

// --- keys still on a body from before the cutover (hourly, counts only) ------------------------

/** Whether a node's stale-key count is due (the reconcile asks once an hour per node). */
export function staleCountDue(relay: Doc<'relays'>, now: number): boolean {
  return (relay.ownPools ?? []).some(
    (p) => !p.stale || now - p.stale.at >= OWN_POOL_STALE_EVERY_MS,
  );
}

/**
 * A key of a cut-over country still on a body from before its cutover: its
 * last render was shaped for that country before the cutover, and nothing it
 * was handed since (a fetch, or a mirror refresh, which moves only the
 * rendered epoch) was rendered at the cutover's epoch or later.
 */
export function staleForPool(
  key: { lastRender?: { country?: string; at: number }; lastRenderedEpoch?: number },
  pool: { code: string; since: number; epoch?: number },
): boolean {
  if (key.lastRender?.country !== pool.code || key.lastRender.at >= pool.since) return false;
  return !(pool.epoch !== undefined && (key.lastRenderedEpoch ?? -1) >= pool.epoch);
}

/** One page of a node's keys in one state: per cut-over country, those whose last body predates it. */
export const stalePage = internalQuery({
  args: {
    backendServerId: v.id('backendServers'),
    nodeName: v.string(),
    state: v.union(v.literal('active'), v.literal('disabled')),
    pools: v.array(
      v.object({ code: v.string(), since: v.number(), epoch: v.optional(v.number()) }),
    ),
    now: v.number(),
    cursor: v.union(v.string(), v.null()),
    numItems: v.number(),
  },
  handler: async (ctx, a) => {
    const res = await ctx.db
      .query('subscriptions')
      .withIndex('by_backend_server_pinned', (q) =>
        q
          .eq('backendServerId', a.backendServerId)
          .eq('pinnedNode', a.nodeName)
          .eq('state', a.state),
      )
      .paginate({ cursor: a.cursor, numItems: a.numItems });
    const inUse = res.page.filter((s) => keyInUse(s, a.now));
    return {
      counts: a.pools.map((p) => inUse.filter((s) => staleForPool(s, p)).length),
      isDone: res.isDone,
      continueCursor: res.continueCursor,
    };
  },
});

/** Store the counts on each country still cut over since the same moment. */
export const recordStale = internalMutation({
  args: {
    relayId: v.id('relays'),
    nodeName: v.string(),
    at: v.number(),
    counts: v.array(v.object({ code: v.string(), since: v.number(), keys: v.number() })),
  },
  handler: async (ctx, a) => {
    const relay = await ctx.db.get(a.relayId);
    // A node rename moves the keys' pins page by page: that count saw part of them.
    if (!relay || relay.renaming || relay.nodeName !== a.nodeName || !relay.ownPools) return null;
    const ownPools = relay.ownPools.map((p) => {
      const c = a.counts.find((x) => x.code === p.code && x.since === p.since);
      return c ? { ...p, stale: { at: a.at, keys: c.keys } } : p;
    });
    await ctx.db.patch(relay._id, { ownPools });
    return null;
  },
});

/** Count, per cut-over country, the node's keys of it whose last body predates the cutover. */
export const countStale = internalAction({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }): Promise<{ counts: number[] } | null> => {
    const relay: Doc<'relays'> | null = await ctx.runQuery(internal.edgeOwnPools.relayOf, {
      relayId,
    });
    if (!relay?.backendServerId || !relay.nodeName || relay.renaming || !relay.ownPools?.length)
      return null;
    const pools = relay.ownPools.map((p) => ({
      code: p.code,
      since: p.since,
      ...(p.epoch !== undefined ? { epoch: p.epoch } : {}),
    }));
    const now = Date.now();
    const counts = pools.map(() => 0);
    for (const state of ['active', 'disabled'] as const) {
      let cursor: string | null = null;
      for (;;) {
        const page: { counts: number[]; isDone: boolean; continueCursor: string } =
          await ctx.runQuery(internal.edgeOwnPools.stalePage, {
            backendServerId: relay.backendServerId,
            nodeName: relay.nodeName,
            state,
            pools,
            now,
            cursor,
            numItems: FRONT_KEYS_PAGE,
          });
        page.counts.forEach((n, i) => (counts[i]! += n));
        if (page.isDone) break;
        cursor = page.continueCursor;
      }
    }
    await ctx.runMutation(internal.edgeOwnPools.recordStale, {
      relayId,
      nodeName: relay.nodeName,
      at: now,
      counts: pools.map((p, i) => ({ code: p.code, since: p.since, keys: counts[i]! })),
    });
    return { counts };
  },
});

export const relayOf = internalQuery({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }) => ctx.db.get(relayId),
});

// --- rollback ---------------------------------------------------------------------------------

/**
 * Before deploying a build without countries on their own addresses (docs/edges.md
 * Deploy notes): every node's cutovers, budgets and counts go (its epoch moves and
 * the mirrors are refreshed, so the countries' members get today's order again),
 * then every rotation forgets it was one of theirs, a page at a time in the
 * background. Refused while one of those rotations is in flight.
 */
export const clearOwnPoolsForRollback = internalMutation({
  args: {
    stage: v.optional(v.literal('rotations')),
    cursor: v.optional(v.union(v.string(), v.null())),
  },
  handler: async (ctx, a): Promise<{ cleared: number; done: boolean; stage: string }> => {
    let cleared = 0;
    if (!a.stage) {
      for (const phase of ROTATION_PHASES) {
        if (isTerminalPhase(phase)) continue;
        const busy = await ctx.db
          .query('edgeRotations')
          .withIndex('by_phase', (q) => q.eq('phase', phase))
          .filter((q) => q.eq(q.field('ownPool'), true))
          .first();
        if (busy)
          throw new ConvexError({
            code: 'edge.busy',
            message: 'A replacement of a country’s own address is running: let it finish first',
          });
      }
      for (const r of await ctx.db.query('relays').collect()) {
        if (
          r.ownPools === undefined &&
          r.audienceReplaces === undefined &&
          r.audienceReplacesPerDay === undefined
        )
          continue;
        const hadOwn = (r.ownPools?.length ?? 0) > 0;
        await ctx.db.patch(r._id, {
          ownPools: undefined,
          audienceReplaces: undefined,
          audienceReplacesPerDay: undefined,
        });
        if (hadOwn) await bumpEpochAndRefresh(ctx, (await ctx.db.get(r._id))!);
        cleared++;
      }
      await ctx.scheduler.runAfter(0, internal.edgeOwnPools.clearOwnPoolsForRollback, {
        stage: 'rotations',
        cursor: null,
      });
      return { cleared, done: false, stage: 'started' };
    }
    const page = await ctx.db
      .query('edgeRotations')
      .paginate({ cursor: a.cursor ?? null, numItems: 200 });
    for (const r of page.page)
      if (r.ownPool !== undefined) {
        await ctx.db.patch(r._id, { ownPool: undefined });
        cleared++;
      }
    if (!page.isDone)
      await ctx.scheduler.runAfter(0, internal.edgeOwnPools.clearOwnPoolsForRollback, {
        stage: 'rotations',
        cursor: page.continueCursor,
      });
    return { cleared, done: page.isDone, stage: a.stage };
  },
});
