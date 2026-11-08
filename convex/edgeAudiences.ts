/**
 * Addresses only for some countries: storage (docs/edges.md "Addresses only for
 * some countries"; the rules are pure in lib/edges/audience.ts).
 *
 *  - `audienceForPublish`: what an address's FIRST publication does to its
 *    audience, called by every path that publishes one (a rotation's publish,
 *    upkeep's publish of a spare, the operator's publish, an adoption). At an
 *    only location an address that cannot take the audience is never published.
 *  - `setOnly`: switch a location to only for its countries (guarded) or back
 *    (every address there becomes everyone's for good).
 *  - the rollback helpers: no contained address may be left where a build that
 *    knows no audience could hand it to everyone.
 */
import { ConvexError, v } from 'convex/values';
import { internal } from './_generated/api';
import { internalMutation, internalQuery } from './_generated/server';
import type { DatabaseReader, MutationCtx } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { assertAdmission } from './lib/edges/maintenance';
import { audienceAtPublish, onlyCodesOf, sameCodes } from './lib/edges/audience';
import { resolveCensoredCountries } from './lib/censoredCountries';
import { MAX_PICK_WANT } from './lib/edges/providerSet';
import { seenBefore } from './edgeLanes';
import { resolveMemberCountryConfig } from './memberCountry';
import { listenersOf } from './relayListeners';
import { carries, setPicksOf, setStateOf } from './lib/edges/setState';
import { websocketNodeOf } from './lib/edges/websocketNode';
import { ACCOUNT_EDGE_SCAN_LIMIT } from './lib/edges/pool';
import {
  assertNoRotationOrQuarantine,
  assertNoRunningSetup,
  bumpEpochAndRefresh,
  scheduleMirrorRefresh,
} from './lib/edges/relayGuards';
import { edgeMs, MAX_DESIRED_PUBLISHED, resolveEdgeConfig } from './lib/edgeConfig';
import { unpublishFromPool } from './relays';

type Edge = Doc<'edges'>;

/**
 * The audience patch for an address published now, or why it may not be.
 * One published before keeps what it has (contained or everyone's), except at
 * an only location, where one everyone may be handed is never published again
 * (`audience_tainted`). `replacing`: the address a replace swaps out.
 */
export async function audienceForPublish(
  db: DatabaseReader,
  edge: Edge,
  replacing?: Edge | null,
): Promise<
  | { patch: { audience?: string[]; contained?: true }; contained: boolean }
  | { refused: 'audience_tainted' | 'audience_replaces_everyone' | 'audience_needs_spread' }
> {
  // Published before as a contained address: it stays one (and stays its countries').
  if (edge.audience?.length) return { patch: {}, contained: true };
  const location = edge.locationId ? await db.get(edge.locationId) : null;
  // Made for some countries (a node's pick for them): theirs wherever it is.
  const made = edge.audienceIntent?.length ? edge.audienceIntent : null;
  if (!made && !onlyCodesOf(location?.forCountries)) return { patch: {}, contained: false };
  if (edge.publishedAt !== undefined) return { refused: 'audience_tainted' };
  const at = audienceAtPublish({
    edge,
    location: location?.forCountries ?? null,
    seenBefore: await seenBefore(db, edge),
    replacing: replacing ? { audience: replacing.audience } : null,
    made,
  });
  if (at.kind === 'refused') return { refused: at.reason };
  if (at.kind === 'everyone') return { patch: {}, contained: false };
  // A contained seat on a modulus pool would move every member when it is added.
  if ((await db.get(edge.relayId))?.edgePick !== 'hrw1')
    return { refused: 'audience_needs_spread' };
  return { patch: { audience: at.audience, contained: true }, contained: true };
}

/** The nodes with a pick at this location (their provider set names it). */
async function nodesPicking(db: DatabaseReader, locationId: Id<'edgeLocations'>) {
  const out: Doc<'relays'>[] = [];
  for (const r of await db.query('relays').collect())
    if (r.providerSet?.some((p) => p.locationId === locationId)) out.push(r);
  return out;
}

/**
 * Why a location may not become only for its countries, or null. Steering
 * must be on (only steered members can ever be handed a contained address),
 * every node picking it must walk its pool by rendezvous (a modulus pool moves
 * everyone when it grows), and every transport the location carries for such
 * a node must have another pick that carries it for everyone.
 */
async function onlyRefusal(
  db: DatabaseReader,
  location: Doc<'edgeLocations'>,
): Promise<{ code: string; message: string } | null> {
  if (!location.forCountries?.codes.length)
    return { code: 'validation', message: 'Pick the countries this location is for first' };
  if (!(await resolveMemberCountryConfig(db)).steer)
    return {
      code: 'edge.audience_needs_steering',
      message:
        'Turn on ordering by country under Settings first: only members whose country is known can be handed these addresses',
    };
  for (const node of await nodesPicking(db, location._id))
    if (node.providerSet?.some((p) => p.locationId === location._id && p.audiences?.length))
      return AUDIENCE_ON_PICK(node);
  for (const node of await nodesPicking(db, location._id)) {
    if (node.edgePick !== 'hrw1')
      return {
        code: 'edge.audience_needs_spread',
        message: `${node.label ?? node.slug} still uses the old pool walk: switch it to the rendezvous walk first`,
      };
    const picks = (await setPicksOf(db, node)) ?? [];
    const websocketNode = await websocketNodeOf(db, node.origin);
    const listeners = (await listenersOf({ db }, node._id)).filter(
      (l) => l.deployed && l.enabled && !l.retired,
    );
    for (const l of listeners) {
      const opts = { websocketNode, originAddress: node.originAddress };
      const here = picks.find((p) => p.pick.locationId === (location._id as string));
      if (!here || !carries(here, l, opts)) continue;
      const elsewhere = picks.some(
        (p) =>
          p.pick.locationId !== (location._id as string) &&
          p.usable &&
          !p.pick.onlyCodes?.length &&
          carries(p, l, opts),
      );
      if (!elsewhere)
        return {
          code: 'edge.audience_leaves_none',
          message: `${node.label ?? node.slug} has no other location carrying ${l.listenerKey} for everyone: add one first`,
        };
    }
  }
  return null;
}

/** Move the epoch of every origin with an address in use at this location (and refresh mirrors once). */
async function bumpOriginsAt(ctx: MutationCtx, locationId: Id<'edgeLocations'>): Promise<number> {
  const relayIds = new Set<Id<'relays'>>();
  for (const e of await ctx.db
    .query('edges')
    .withIndex('by_location_status', (q) => q.eq('locationId', locationId).eq('status', 'active'))
    .take(ACCOUNT_EDGE_SCAN_LIMIT))
    if (e.publication === 'published') relayIds.add(e.relayId);
  const now = Date.now();
  for (const id of relayIds) {
    const r = await ctx.db.get(id);
    if (r) await ctx.db.patch(id, { publicationEpoch: r.publicationEpoch + 1, updatedAt: now });
  }
  if (relayIds.size > 0) await scheduleMirrorRefresh(ctx);
  return relayIds.size;
}

/**
 * `POST providers/{id}/locations/{locationId}/only {only}`: addresses made at
 * this location from now on are handed only to members in its countries
 * (`only: true`, refused by `onlyRefusal`), or every address there becomes
 * everyone's for good (`only: false`; switching on again starts from new
 * addresses). Audited `edge.location.only`.
 */
export const setOnly = internalMutation({
  args: {
    id: v.id('edgeLocations'),
    only: v.boolean(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    await assertAdmission(ctx.db, 'provider.write');
    const location = await ctx.db.get(a.id);
    if (!location) throw new ConvexError({ code: 'not_found', message: 'Location not found' });
    const was = !!location.forCountries?.only;
    if (was === a.only) return { ok: true as const, changed: false, widened: 0, nodes: 0 };
    const now = Date.now();
    let widened = 0;
    let nodes = 0;
    if (a.only) {
      const refusal = await onlyRefusal(ctx.db, location);
      if (refusal) throw new ConvexError(refusal);
      await ctx.db.patch(location._id, {
        forCountries: { ...location.forCountries!, only: { since: now }, updatedAt: now },
        updatedAt: now,
      });
    } else {
      const { only: _o, ...rest } = location.forCountries!;
      void _o;
      await ctx.db.patch(location._id, {
        forCountries: { ...rest, updatedAt: now },
        updatedAt: now,
      });
      // Everyone's for good: members of every country are handed them from now.
      for (const e of await ctx.db
        .query('edges')
        .withIndex('by_location_status', (q) => q.eq('locationId', location._id))
        .take(ACCOUNT_EDGE_SCAN_LIMIT)) {
        if (!e.audience?.length) continue;
        await ctx.db.patch(e._id, { audience: undefined, contained: undefined, updatedAt: now });
        widened++;
      }
      nodes = await bumpOriginsAt(ctx, location._id);
    }
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'edge.location.only',
      targetType: 'edge_location',
      targetId: location._id,
      payload: {
        placeKey: location.placeKey,
        countries: (location.forCountries?.codes ?? []).join(' '),
        only: a.only,
        widened,
        nodes,
      },
    });
    return { ok: true as const, changed: true, widened, nodes };
  },
});

/** The admin's view of what switching a location to only would do, or why it may not. */
export const onlyPreview = internalQuery({
  args: { id: v.id('edgeLocations') },
  handler: async (ctx, { id }) => {
    const location = await ctx.db.get(id);
    if (!location) throw new ConvexError({ code: 'not_found', message: 'Location not found' });
    const refusal = location.forCountries?.only ? null : await onlyRefusal(ctx.db, location);
    const contained = (
      await ctx.db
        .query('edges')
        .withIndex('by_location_status', (q) => q.eq('locationId', id).eq('status', 'active'))
        .take(ACCOUNT_EDGE_SCAN_LIMIT)
    ).filter((e) => e.audience?.length).length;
    return { only: !!location.forCountries?.only, refusal, contained };
  },
});

/**
 * Whether a node holds anything contained: an address with an audience (any
 * status but destroyed) or a pick at an only location. Such a node may not go
 * back to the legacy pool walk (a modulus pool moves everyone when it grows).
 */
export async function holdsContainment(db: DatabaseReader, relay: Doc<'relays'>): Promise<boolean> {
  if (relay.providerSet?.some((p) => p.audiences?.length)) return true;
  for (const p of relay.providerSet ?? []) {
    const l = await db.get(p.locationId);
    if (l?.forCountries?.only) return true;
  }
  const contained = await db
    .query('edges')
    .withIndex('by_contained', (q) => q.eq('contained', true))
    .collect();
  return contained.some((e) => e.relayId === relay._id && e.status !== 'destroyed');
}

const AUDIENCE_ON_PICK = (node: Doc<'relays'>) => ({
  code: 'edge.audience_on_pick',
  message: `${node.label ?? node.slug} keeps addresses for some countries here: a location only for some countries holds no node's own`,
});

// --- countries with their own addresses (a node's picks) -------------------------------------

/** Countries one pick entry may name: listed ones, at most this many. */
export const MAX_AUDIENCE_CODES = 4;

/** Why a node may not keep addresses for some countries at one of its picks, or null. */
async function pickAudienceRefusal(
  db: DatabaseReader,
  relay: Doc<'relays'>,
  location: Doc<'edgeLocations'>,
): Promise<{ code: string; message: string } | null> {
  if (location.forCountries?.only)
    return {
      code: 'edge.audience_on_only_location',
      message:
        'This location is only for some countries already: every address made there is theirs',
    };
  if (!(await resolveMemberCountryConfig(db)).steer)
    return {
      code: 'edge.audience_needs_steering',
      message:
        'Turn on ordering by country under Settings first: only members whose country is known can be handed these addresses',
    };
  if (relay.edgePick !== 'hrw1') return AUDIENCE_NEEDS_SPREAD;
  return null;
}

/**
 * Whether every transport the pick carries for this node keeps another pick
 * that carries it for everyone (a pick serving its countries only, or a
 * location only for some, never covers anyone else).
 */
async function leavesNone(
  db: DatabaseReader,
  relay: Doc<'relays'>,
  locationId: Id<'edgeLocations'>,
): Promise<string | null> {
  const picks = (await setPicksOf(db, relay)) ?? [];
  const websocketNode = await websocketNodeOf(db, relay.origin);
  const here = picks.find((p) => p.pick.locationId === (locationId as string));
  if (!here) return null;
  const opts = { websocketNode, originAddress: relay.originAddress };
  for (const l of (await listenersOf({ db }, relay._id)).filter(
    (x) => x.deployed && x.enabled && !x.retired,
  )) {
    if (!carries(here, l, opts)) continue;
    const elsewhere = picks.some(
      (p) =>
        p.pick.locationId !== (locationId as string) &&
        p.usable &&
        !p.pick.onlyCodes?.length &&
        !p.pick.audienceOnly &&
        carries(p, l, opts),
    );
    if (!elsewhere) return l.listenerKey;
  }
  return null;
}

/**
 * `POST relays/{id}/providers/{locationId}/audiences {codes, want}`: this node
 * keeps addresses only for these countries at this pick (docs/edges.md
 * "Countries with their own addresses"): `want` of each transport the pick
 * carries, counted over every pick holding the same countries (null: a place
 * for theirs that asks for none of its own, where a replacement goes when the
 * first place cannot take it). Saving the same countries again changes the
 * count; `remove: true` drops the entry (addresses made for it stay theirs
 * and keep serving; nothing new is made for them here). Dormant until saved;
 * refused at a location only for some countries, without steering, on a node
 * still on the old pool walk, and past the pool's size. Audited
 * `edge.relay.pick_audience`.
 */
export const setPickAudience = internalMutation({
  args: {
    relayId: v.id('relays'),
    locationId: v.id('edgeLocations'),
    codes: v.array(v.string()),
    want: v.optional(v.union(v.number(), v.null())),
    remove: v.optional(v.boolean()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    await assertAdmission(ctx.db, 'setup.start');
    const relay = await ctx.db.get(a.relayId);
    if (!relay || relay.deleting)
      throw new ConvexError({ code: 'not_found', message: 'Node not found' });
    await assertNoRunningSetup(ctx.db, relay);
    await assertNoRotationOrQuarantine(ctx.db, relay);
    const pick = relay.providerSet?.find((p) => p.locationId === a.locationId);
    if (!pick)
      throw new ConvexError({ code: 'validation', message: 'That location is not picked' });
    const location = await ctx.db.get(a.locationId);
    if (!location) throw new ConvexError({ code: 'not_found', message: 'Location not found' });
    const codes = [...new Set(a.codes.map((c) => c.trim().toUpperCase()).filter(Boolean))].sort();
    if (codes.length === 0 || codes.length > MAX_AUDIENCE_CODES)
      throw new ConvexError({
        code: 'validation',
        message: `Name 1 to ${MAX_AUDIENCE_CODES} countries`,
      });
    const entries = pick.audiences ?? [];
    const at = entries.findIndex((x) => sameCodes(x.codes, codes));
    const now = Date.now();
    let next: typeof entries;
    let want: number | null = null;
    if (a.remove) {
      if (at < 0) return { ok: true as const, changed: false };
      next = entries.filter((_, i) => i !== at);
    } else {
      const refusal = await pickAudienceRefusal(ctx.db, relay, location);
      if (refusal) throw new ConvexError(refusal);
      const listed = (await resolveCensoredCountries(ctx.db)).codes;
      const unlisted = codes.find((c) => !listed.includes(c));
      if (unlisted)
        throw new ConvexError({
          code: 'validation',
          message: `${unlisted} is not on the censored-country list`,
        });
      want = a.want ?? null;
      if (want !== null && (!Number.isInteger(want) || want < 1 || want > MAX_PICK_WANT))
        throw new ConvexError({
          code: 'validation',
          message: `Addresses for them must be 1 to ${MAX_PICK_WANT}, or none here`,
        });
      // One pick's entries never share a country: each address there is one entry's.
      const clash = entries.find((x, i) => i !== at && x.codes.some((c) => codes.includes(c)));
      if (clash)
        throw new ConvexError({
          code: 'validation',
          message: `This location already keeps addresses for ${clash.codes.join(', ')}`,
        });
      const entry = {
        codes,
        ...(want !== null ? { want } : {}),
        addedAt: at >= 0 ? entries[at]!.addedAt : now,
      };
      if (at >= 0 && (entries[at]!.want ?? null) === want)
        return { ok: true as const, changed: false };
      next = at >= 0 ? entries.map((x, i) => (i === at ? entry : x)) : [...entries, entry];
    }
    const providerSet = relay.providerSet!.map((p) => {
      if (p.locationId !== a.locationId) return p;
      const { audiences: _a, audienceOnly: _o, ...rest } = p;
      void _a;
      void _o;
      // A pick serving its countries only, with none left, serves everyone again.
      return next.length > 0
        ? { ...rest, audiences: next, ...(p.audienceOnly ? { audienceOnly: true as const } : {}) }
        : rest;
    });
    // The pool must hold what the set now asks for (as a pick's own count).
    const after = await setStateOf(ctx.db, { ...relay, providerSet, cooling: [] }, now);
    if (after.published.length + after.deficit > MAX_DESIRED_PUBLISHED)
      throw new ConvexError({
        code: 'edge.set_too_large',
        message: `The set would ask for ${after.published.length + after.deficit} addresses in use; one node publishes at most ${MAX_DESIRED_PUBLISHED}`,
      });
    await ctx.db.patch(relay._id, { providerSet, updatedAt: now });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'edge.relay.pick_audience',
      targetType: 'relay',
      targetId: relay._id,
      payload: {
        relaySlug: relay.slug,
        placeKey: location.placeKey,
        countries: codes.join(' '),
        want: a.remove ? -1 : (want ?? 0),
      },
    });
    return { ok: true as const, changed: true };
  },
});

/**
 * `POST relays/{id}/providers/{locationId}/audience-only {only}`: the pick
 * serves its countries only (a zone or a location kept for them on this node):
 * no address everyone is handed is made there from now on. Needs an entry
 * first, no count of everyone's there, and another pick carrying each of its
 * transports for everyone. Addresses everyone is handed there now stay (the
 * pool never shrinks by itself). Audited `edge.relay.pick_audience_only`.
 */
export const setPickAudienceOnly = internalMutation({
  args: {
    relayId: v.id('relays'),
    locationId: v.id('edgeLocations'),
    only: v.boolean(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    await assertAdmission(ctx.db, 'setup.start');
    const relay = await ctx.db.get(a.relayId);
    if (!relay || relay.deleting)
      throw new ConvexError({ code: 'not_found', message: 'Node not found' });
    await assertNoRunningSetup(ctx.db, relay);
    await assertNoRotationOrQuarantine(ctx.db, relay);
    const pick = relay.providerSet?.find((p) => p.locationId === a.locationId);
    if (!pick)
      throw new ConvexError({ code: 'validation', message: 'That location is not picked' });
    if (!!pick.audienceOnly === a.only) return { ok: true as const, changed: false };
    if (a.only) {
      if (!pick.audiences?.length)
        throw new ConvexError({
          code: 'validation',
          message: 'Name the countries this location keeps addresses for first',
        });
      if (pick.want !== undefined)
        throw new ConvexError({
          code: 'validation',
          message: 'Clear the count of addresses for everyone here first',
        });
      const left = await leavesNone(ctx.db, relay, a.locationId);
      if (left)
        throw new ConvexError({
          code: 'edge.audience_leaves_none',
          message: `${relay.label ?? relay.slug} has no other location carrying ${left} for everyone: add one first`,
        });
    }
    const now = Date.now();
    const providerSet = relay.providerSet!.map((p) => {
      if (p.locationId !== a.locationId) return p;
      const { audienceOnly: _o, ...rest } = p;
      void _o;
      return a.only ? { ...rest, audienceOnly: true as const } : rest;
    });
    await ctx.db.patch(relay._id, { providerSet, updatedAt: now });
    const location = await ctx.db.get(a.locationId);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'edge.relay.pick_audience_only',
      targetType: 'relay',
      targetId: relay._id,
      payload: { relaySlug: relay.slug, placeKey: location?.placeKey ?? null, only: a.only },
    });
    return { ok: true as const, changed: true };
  },
});

/**
 * Before deploying a build older than countries on picks: every node's
 * entries and "countries only" flags go (nothing new is made for them), and
 * every row forgets what it was made for (`edges.audienceIntent`,
 * `edgeRotations.audience`). Addresses already contained stay contained (the
 * build before knows them: locations only for some countries); go further
 * back with `retireAudiencesForRollback`. A spare made for some countries and
 * never published becomes an ordinary spare: nobody was handed it. Refused
 * while a run for some countries is in flight. Pages until done; safe to run
 * again.
 */
export const clearAudiencePicksForRollback = internalMutation({
  args: {
    stage: v.optional(v.union(v.literal('rotations'), v.literal('edges'))),
    cursor: v.optional(v.union(v.string(), v.null())),
  },
  handler: async (ctx, a) => {
    const now = Date.now();
    if (!a.stage) {
      const relays = await ctx.db.query('relays').collect();
      for (const r of relays) {
        if (!r.activeRotationId) continue;
        const run = await ctx.db.get(r.activeRotationId);
        if (run?.audience?.length)
          throw new ConvexError({
            code: 'edge.audience_rollback_busy',
            message: `${r.label ?? r.slug} has a run for some countries in flight: wait for it or cancel it, then run this again`,
          });
      }
      let picks = 0;
      for (const r of relays) {
        if (!r.providerSet?.some((p) => p.audiences !== undefined || p.audienceOnly)) continue;
        await ctx.db.patch(r._id, {
          providerSet: r.providerSet.map(({ audiences: _a, audienceOnly: _o, ...p }) => {
            void _a;
            void _o;
            return p;
          }),
          updatedAt: now,
        });
        picks++;
      }
      await ctx.scheduler.runAfter(0, internal.edgeAudiences.clearAudiencePicksForRollback, {
        stage: 'rotations',
      });
      return { stage: 'picks', cleared: picks, done: false };
    }
    if (a.stage === 'rotations') {
      const page = await ctx.db
        .query('edgeRotations')
        .paginate({ cursor: a.cursor ?? null, numItems: 200 });
      let cleared = 0;
      for (const run of page.page)
        if (run.audience !== undefined) {
          await ctx.db.patch(run._id, { audience: undefined });
          cleared++;
        }
      await ctx.scheduler.runAfter(0, internal.edgeAudiences.clearAudiencePicksForRollback, {
        stage: page.isDone ? 'edges' : 'rotations',
        cursor: page.isDone ? null : page.continueCursor,
      });
      return { stage: 'rotations', cleared, done: false };
    }
    const page = await ctx.db.query('edges').paginate({ cursor: a.cursor ?? null, numItems: 200 });
    let cleared = 0;
    for (const e of page.page)
      if (e.audienceIntent !== undefined) {
        await ctx.db.patch(e._id, { audienceIntent: undefined });
        cleared++;
      }
    if (!page.isDone)
      await ctx.scheduler.runAfter(0, internal.edgeAudiences.clearAudiencePicksForRollback, {
        stage: 'edges',
        cursor: page.continueCursor,
      });
    return { stage: 'edges', cleared, done: page.isDone };
  },
});

export const AUDIENCE_NEEDS_SPREAD = {
  code: 'edge.audience_needs_spread',
  message:
    'This node hands out addresses only for some countries (or picks a location that does): it keeps the rendezvous walk',
};

// --- rollback --------------------------------------------------------------------------------

/** Every contained address that is not destroyed yet (the `by_contained` index: contained rows only). */
async function containedEdges(db: DatabaseReader): Promise<Edge[]> {
  const rows = await db
    .query('edges')
    .withIndex('by_contained', (q) => q.eq('contained', true))
    .collect();
  return rows.filter((e) => e.status !== 'destroyed');
}

/**
 * Before deploying a build that knows no audience (run before
 * `edgeLocations:clearCountriesForRollback`): no contained address may be left
 * where such a build could publish it for everyone. Refused while a rotation,
 * a setup run or a restore holds a node with one (wait, or cancel it). Then
 * every location stops being only (nothing new becomes contained), and every
 * contained address goes: one in use drains for the burned drain and is
 * destroyed when it ends; a spare is destroyed at once; one already draining
 * keeps going. `widen: true` instead makes those in use everyone's for good
 * (when losing their addresses is worse); spares are destroyed either way.
 * Safe to run again; `edgeAudiences:clearAudiencesForRollback` follows.
 */
export const retireAudiencesForRollback = internalMutation({
  args: { widen: v.optional(v.boolean()) },
  handler: async (ctx, a) => {
    const now = Date.now();
    const contained = await containedEdges(ctx.db);
    const nodes = new Map<Id<'relays'>, Doc<'relays'>>();
    for (const e of contained) {
      const r = await ctx.db.get(e.relayId);
      if (r) nodes.set(r._id, r);
    }
    for (const r of nodes.values())
      if (r.activeRotationId || r.setupOwned || r.restore)
        throw new ConvexError({
          code: 'edge.audience_rollback_busy',
          message: `${r.label ?? r.slug} has a run in flight: wait for it or cancel it, then run this again`,
        });
    for (const l of await ctx.db.query('edgeLocations').collect())
      if (l.forCountries?.only) {
        const { only: _o, ...rest } = l.forCountries;
        void _o;
        await ctx.db.patch(l._id, { forCountries: { ...rest, updatedAt: now }, updatedAt: now });
      }
    const cfg = await resolveEdgeConfig(ctx.db);
    let drained = 0;
    let destroyed = 0;
    let widened = 0;
    for (const e of contained) {
      const origin = nodes.get(e.relayId) ?? null;
      if (e.publication === 'published' && e.status === 'active') {
        if (a.widen) {
          await ctx.db.patch(e._id, { audience: undefined, contained: undefined, updatedAt: now });
          if (origin) await bumpEpochAndRefresh(ctx, (await ctx.db.get(origin._id))!);
          widened++;
        } else if (origin) {
          await unpublishFromPool(ctx, origin, e, { drainMs: edgeMs.burnedDrain(cfg) });
          drained++;
        }
      } else if (e.status === 'active') {
        // A spare: gone now, so nothing can publish it again.
        await ctx.db.patch(e._id, {
          status: 'draining',
          publication: 'draining',
          drainUntil: now,
          statusChangedAt: now,
          updatedAt: now,
        });
        if (origin)
          await ctx.db.patch(origin._id, {
            standbyEdgeIds: (await ctx.db.get(origin._id))!.standbyEdgeIds.filter(
              (x) => x !== e._id,
            ),
            updatedAt: now,
          });
        destroyed++;
      }
    }
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'edge.audience_rollback',
      targetType: 'edge',
      targetId: 'all',
      payload: { drained, destroyed, widened },
    });
    return { drained, destroyed, widened, left: contained.length - widened };
  },
});

/**
 * The second step: refused while any contained address is not destroyed yet
 * (`left`); then every audience is cleared from the rows that remain (their
 * history) and the build without audiences may deploy.
 */
export const clearAudiencesForRollback = internalMutation({
  args: {},
  handler: async (ctx) => {
    const left = await containedEdges(ctx.db);
    if (left.length > 0)
      throw new ConvexError({
        code: 'edge.audience_rollback_pending',
        message: `${left.length} contained address(es) are not destroyed yet: wait for their drain, then run this again`,
      });
    // Destroyed contained rows, a page at a time (each cleared row leaves the index).
    const page = await ctx.db
      .query('edges')
      .withIndex('by_contained', (q) => q.eq('contained', true).eq('status', 'destroyed'))
      .take(500);
    for (const e of page) await ctx.db.patch(e._id, { audience: undefined, contained: undefined });
    if (page.length === 500)
      await ctx.scheduler.runAfter(0, internal.edgeAudiences.clearAudiencesForRollback, {});
    return { cleared: page.length, done: page.length < 500 };
  },
});
