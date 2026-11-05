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
import { audienceAtPublish, onlyCodesOf } from './lib/edges/audience';
import { seenBefore } from './edgeLanes';
import { resolveMemberCountryConfig } from './memberCountry';
import { listenersOf } from './relayListeners';
import { carries, setPicksOf } from './lib/edges/setState';
import { websocketNodeOf } from './lib/edges/websocketNode';
import { ACCOUNT_EDGE_SCAN_LIMIT, EDGE_LIVE_STATUSES } from './lib/edges/pool';
import { bumpEpochAndRefresh, scheduleMirrorRefresh } from './lib/edges/relayGuards';
import { edgeMs, resolveEdgeConfig } from './lib/edgeConfig';
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
  | { patch: { audience?: string[] } }
  | { refused: 'audience_tainted' | 'audience_replaces_everyone' }
> {
  if (edge.audience?.length) return { patch: {} };
  const location = edge.locationId ? await db.get(edge.locationId) : null;
  if (!onlyCodesOf(location?.forCountries)) return { patch: {} };
  if (edge.publishedAt !== undefined) return { refused: 'audience_tainted' };
  const at = audienceAtPublish({
    edge,
    location: location?.forCountries ?? null,
    seenBefore: await seenBefore(db, edge),
    replacing: replacing ? { audience: replacing.audience } : null,
  });
  if (at.kind === 'refused') return { refused: at.reason };
  return { patch: at.kind === 'contained' ? { audience: at.audience } : {} };
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
        await ctx.db.patch(e._id, { audience: undefined, updatedAt: now });
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
  for (const p of relay.providerSet ?? []) {
    const l = await db.get(p.locationId);
    if (l?.forCountries?.only) return true;
  }
  const edges = await db
    .query('edges')
    .withIndex('by_relay_status', (q) => q.eq('relayId', relay._id))
    .take(ACCOUNT_EDGE_SCAN_LIMIT);
  return edges.some((e) => e.status !== 'destroyed' && !!e.audience?.length);
}

export const AUDIENCE_NEEDS_SPREAD = {
  code: 'edge.audience_needs_spread',
  message:
    'This node hands out addresses only for some countries (or picks a location that does): it keeps the rendezvous walk',
};

// --- rollback --------------------------------------------------------------------------------

/** Every contained address that is not destroyed yet (any live status). */
async function containedEdges(db: DatabaseReader): Promise<Edge[]> {
  const out: Edge[] = [];
  for (const status of EDGE_LIVE_STATUSES)
    for (const e of await db
      .query('edges')
      .withIndex('by_status', (q) => q.eq('status', status))
      .take(ACCOUNT_EDGE_SCAN_LIMIT))
      if (e.audience?.length) out.push(e);
  return out;
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
          await ctx.db.patch(e._id, { audience: undefined, updatedAt: now });
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
    let cleared = 0;
    for (const e of await ctx.db
      .query('edges')
      .withIndex('by_status', (q) => q.eq('status', 'destroyed'))
      .take(5000))
      if (e.audience?.length) {
        await ctx.db.patch(e._id, { audience: undefined });
        cleared++;
      }
    return { cleared, done: cleared < 5000 };
  },
});
