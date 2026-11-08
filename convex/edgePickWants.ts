/**
 * Addresses per location (docs/edges.md "Addresses per location"): a pick of a
 * node's provider set may ask for a COUNT, this many published addresses of
 * each transport it carries (`relays.providerSet[].want`, 1..8). The
 * requirement and its cover take it (lib/edges/providerSet.ts `wants`, count
 * targets after the rest of the cover), so pool admission, sizing and
 * rebalance follow it; the reconcile fills it (step 5W: a spare there, else a
 * provision in that location only, under the usual switches); lane cleanup
 * keeps it. Absent = the rule without it: at least one address of any
 * transport.
 *
 * `POST relays/{id}/providers/{locationId}/want {want}` saves it (null clears
 * it); `…/want/preview` says first what it adds and what that costs a month,
 * and whether it fits under the account's monthly cap. Audited
 * `edge.relay.pick_want` (the location and the count: an operator setting).
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import type { DatabaseReader } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { MAX_DESIRED_PUBLISHED, resolveEdgeConfig } from './lib/edgeConfig';
import { pickUsable } from './lib/edges/assignedLocation';
import { edgeLayerOf } from './lib/edges/providers/capabilities';
import { clientCheckReadiness } from './edgeClientCheck';
import { assertAdmission } from './lib/edges/maintenance';
import { assertNoRunningSetup, assertNoRotationOrQuarantine } from './lib/edges/relayGuards';
import { MAX_PICK_WANT, pickWant } from './lib/edges/providerSet';
import { carries, coolingOf, setStateOf, type SetState } from './lib/edges/setState';
import { parseOptionValues } from './lib/edges/providers/options';
import { hasPublishableAddress } from './lib/edges/ip';
import { audienceForPublish } from './edgeAudiences';
import { sameCodes } from './lib/edges/audience';
import { capRefusal, costAdmin, edgeCostAt, sizeAt, spendOf } from './edgePlans';
import { atCap } from './lib/edges/pricing';

/**
 * Why automatic upkeep cannot buy an address a count asks for (null: it can),
 * as the codes that already say it: the pick cools, the location refused a
 * create for this node, no address there was tested yet, the account's
 * monthly cap.
 */
export type LocationShortCause =
  'pick_cooling' | 'locations_refused' | 'location_untrusted' | 'account_spend_cap_reached';

/** One transport of one counted pick that holds fewer published addresses than asked. */
export interface CountGap {
  locationId: Id<'edgeLocations'>;
  label: string;
  accountId: Id<'edgeProviderAccounts'>;
  accountName: string;
  listenerId: Id<'relayListeners'>;
  listenerKey: string;
  want: number;
  inUse: number;
  /** Tested or not, active spares of that transport there (upkeep publishes one first). */
  spares: Id<'edges'>[];
  cause: LocationShortCause | null;
  /**
   * The count some countries' own addresses ask for (`relays.providerSet[]
   * .audiences`): counted over every pick holding them, made at the first one
   * nothing holds back (`locationId`), contained to exactly these.
   */
  audience?: string[];
}

/**
 * Every counted pick's transports short of their count, with what holds each
 * back. Read by the reconcile (step 5W) and by attention (`location_short`).
 * Cooling picks are named too (their need is not part of the deficit while
 * they cool, but the operator should see it).
 */
export async function countGapsOf(
  db: DatabaseReader,
  relay: Doc<'relays'>,
  now: number,
  state?: SetState,
): Promise<CountGap[]> {
  if (
    !relay.providerSet?.some(
      (p) => pickWant(p.want) !== undefined || p.audiences?.some((a) => pickWant(a.want)),
    )
  )
    return [];
  const s = state ?? (await setStateOf(db, relay, now));
  const cooling = coolingOf(relay, now);
  // A location not trusted yet is usable when FCP's own client check can
  // prove what is made there (lib/edges/assignedLocation.ts `pickUsable`).
  const ccReady = (await clientCheckReadiness(db, await resolveEdgeConfig(db), now)) === 'ready';
  // The node's spares as upkeep finds them: active, not in use, with an address.
  const standbys = (
    await db
      .query('edges')
      .withIndex('by_relay_status', (q) => q.eq('relayId', relay._id).eq('status', 'active'))
      .collect()
  ).filter((e) => e.publication === 'unpublished' && hasPublishableAddress(e));
  const causeAt = async (
    p: NonNullable<Doc<'relays'>['providerSet']>[number],
    row: NonNullable<SetState['picks']>[number],
  ): Promise<LocationShortCause | null> =>
    cooling.has(p.locationId as string)
      ? 'pick_cooling'
      : (relay.refusedLocations ?? []).some((r) => r.locationId === p.locationId && r.until > now)
        ? 'locations_refused'
        : !pickUsable(row.location, {
              l4: edgeLayerOf(row.account.provider) === 'l4',
              clientCheckReady: ccReady,
            })
          ? 'location_untrusted'
          : (await capHit(db, row.account, row.location, p.options))
            ? 'account_spend_cap_reached'
            : null;
  const gaps: CountGap[] = [];
  for (const p of relay.providerSet) {
    const want = pickWant(p.want);
    if (want === undefined || p.audienceOnly) continue;
    const row = s.picks?.find((r) => r.pick.locationId === (p.locationId as string));
    if (!row || !row.usable) continue;
    const listeners = s.listeners.filter((l) =>
      carries(row, l, { websocketNode: s.websocketNode, originAddress: relay.originAddress }),
    );
    // At an only location, the addresses contained there count: one an edit of
    // the countries left out of date holds its place until step 5O renews it.
    const only = row.pick.onlyCodes;
    const counts = (x: { audience?: readonly string[] }) => !only || !!x.audience?.length;
    for (const l of listeners) {
      const inUse = s.published.filter(
        (x) =>
          x.listenerKey === l.listenerKey && x.locationId === (p.locationId as string) && counts(x),
      ).length;
      if (inUse >= want) continue;
      const cause = await causeAt(p, row);
      gaps.push({
        locationId: p.locationId,
        label: row.location.label,
        accountId: row.account._id,
        accountName: row.account.name,
        listenerId: l._id,
        listenerKey: l.listenerKey,
        want,
        inUse,
        spares: await sparesTakingAudience(
          db,
          standbys.filter(
            (e) =>
              e.listenerId === l._id && e.locationId === p.locationId && !e.audienceIntent?.length,
          ),
          !!only,
        ),
        cause,
      });
    }
  }
  // Some countries' own addresses: per transport, over every pick holding them.
  for (const w of s.requirement.audienceWants) {
    const l = s.listeners.find((x) => x.listenerKey === w.listenerKey);
    if (!l) continue;
    const inUse = s.published.filter(
      (x) =>
        x.listenerKey === w.listenerKey && !!x.audience?.length && sameCodes(x.audience, w.codes),
    ).length;
    if (inUse >= w.want) continue;
    // The places in set order, cooling ones included (named, never bought into).
    const places: Array<{
      p: NonNullable<Doc<'relays'>['providerSet']>[number];
      row: NonNullable<SetState['picks']>[number];
    }> = [];
    for (const p of relay.providerSet) {
      if (!p.audiences?.some((a) => sameCodes(a.codes, w.codes))) continue;
      const row = s.picks?.find((r) => r.pick.locationId === (p.locationId as string));
      if (!row || !row.usable) continue;
      if (!carries(row, l, { websocketNode: s.websocketNode, originAddress: relay.originAddress }))
        continue;
      places.push({ p, row });
    }
    let chosen: (typeof places)[number] | null = null;
    let cause: LocationShortCause | null = null;
    for (const place of places) {
      const c = await causeAt(place.p, place.row);
      if (c === null) {
        chosen = place;
        cause = null;
        break;
      }
      if (!chosen) {
        chosen = place;
        cause = c;
      }
    }
    if (!chosen) continue;
    gaps.push({
      locationId: chosen.p.locationId,
      label: chosen.row.location.label,
      accountId: chosen.row.account._id,
      accountName: chosen.row.account.name,
      listenerId: l._id,
      listenerKey: l.listenerKey,
      want: w.want,
      inUse,
      // A spare made for exactly these countries, wherever it is (it is theirs).
      spares: await sparesTakingAudience(
        db,
        standbys.filter(
          (e) =>
            e.listenerId === l._id &&
            !!e.audienceIntent?.length &&
            sameCodes(e.audienceIntent, w.codes) &&
            !cooling.has(e.locationId as string),
        ),
        true,
      ),
      cause,
      audience: w.codes,
    });
  }
  return gaps;
}

/**
 * The spares that could fill a count: at an only location, only one that can
 * still take its audience (a spare made before the switch never will, and must
 * not hold a fresh one back).
 */
async function sparesTakingAudience(
  db: DatabaseReader,
  spares: readonly Doc<'edges'>[],
  onlyHere: boolean,
): Promise<Id<'edges'>[]> {
  const out: Id<'edges'>[] = [];
  for (const e of spares)
    if (!onlyHere || !('refused' in (await audienceForPublish(db, e)))) out.push(e._id);
  return out;
}

/** Whether one more address at this location would pass the account's monthly cap. */
async function capHit(
  db: DatabaseReader,
  account: Doc<'edgeProviderAccounts'>,
  location: Doc<'edgeLocations'>,
  options: string | undefined,
): Promise<boolean> {
  if (typeof account.cost?.monthlyCap !== 'number') return false;
  const size = await sizeAt({ db }, account, location, optionsOf(options));
  const { cost } = await edgeCostAt(db, account, location._id, size);
  return (await capRefusal({ db }, account, cost)) !== null;
}

const optionsOf = (raw: string | undefined) => (raw !== undefined ? parseOptionValues(raw) : null);

/**
 * The reconcile's step 5W (edgeReconcile.ts): the first count it can act on.
 * A spare there is published whatever holds new purchases back (it costs
 * nothing new), never into a cooling pick; a provision is asked only where
 * nothing holds it back.
 */
export const nextCountGap = internalQuery({
  args: { relayId: v.id('relays') },
  handler: async (
    ctx,
    { relayId },
  ): Promise<{
    listenerId: Id<'relayListeners'>;
    locationId: Id<'edgeLocations'>;
    spares: Id<'edges'>[];
    mayProvision: boolean;
    audience?: string[];
  } | null> => {
    const relay = await ctx.db.get(relayId);
    if (!relay) return null;
    const gaps = await countGapsOf(ctx.db, relay, Date.now());
    const withSpare = gaps.find((g) => g.cause !== 'pick_cooling' && g.spares.length > 0);
    if (withSpare)
      return {
        listenerId: withSpare.listenerId,
        locationId: withSpare.locationId,
        spares: withSpare.spares,
        mayProvision: false,
        ...(withSpare.audience ? { audience: withSpare.audience } : {}),
      };
    const buy = gaps.find((g) => g.cause === null);
    return buy
      ? {
          listenerId: buy.listenerId,
          locationId: buy.locationId,
          spares: [],
          mayProvision: true,
          ...(buy.audience ? { audience: buy.audience } : {}),
        }
      : null;
  },
});

/** What a count would change at one pick: addresses it adds, their monthly cost, the cap. */
async function wantEffect(
  db: DatabaseReader,
  relay: Doc<'relays'>,
  locationId: Id<'edgeLocations'>,
  want: number | null,
) {
  const now = Date.now();
  const pick = relay.providerSet?.find((p) => p.locationId === locationId);
  if (!pick) throw new ConvexError({ code: 'validation', message: 'That location is not picked' });
  const next = (relay.providerSet ?? []).map((p) =>
    p.locationId === locationId ? { ...p, want: want ?? undefined } : p,
  );
  // Judged as the set will stand once nothing cools: a count saved while its
  // pick cools must not overflow the pool when the cooling ends.
  const eventual = (providerSet: NonNullable<Doc<'relays'>['providerSet']>) =>
    setStateOf(db, { ...relay, providerSet, cooling: [] }, now);
  const before = await eventual(relay.providerSet ?? []);
  const after = await eventual(next);
  const row = after.picks?.find((r) => r.pick.locationId === (locationId as string));
  const here = (s: SetState) => s.targets.filter((t) => t.locationId === (locationId as string));
  const adds = Math.max(0, here(after).length - here(before).length);
  let total = after.published.length + after.deficit;
  // A location that cannot take an address now (switched off, its account
  // untested) asks for nothing yet; it will once it can: counted as if it could.
  if (row && !row.usable && want !== null)
    for (const l of after.listeners)
      if (
        carries(row, l, { websocketNode: after.websocketNode, originAddress: relay.originAddress })
      )
        total += Math.max(
          0,
          want -
            after.published.filter(
              (x) => x.listenerKey === l.listenerKey && x.locationId === (locationId as string),
            ).length,
        );
  let monthly: ReturnType<typeof costAdmin> | null = null;
  let fits = adds;
  if (row) {
    const size = await sizeAt({ db }, row.account, row.location, optionsOf(pick.options));
    const { cost } = await edgeCostAt(db, row.account, locationId, size);
    monthly = costAdmin(cost);
    // How many of the new addresses fit under the account's cap (all of them without one).
    if (typeof row.account.cost?.monthlyCap === 'number' && adds > 0) {
      const spend = await spendOf({ db }, row.account);
      if (atCap(spend)) fits = 0;
      else
        for (fits = adds; fits > 0; fits--)
          if ((await capRefusal({ db }, row.account, cost, fits)) === null) break;
    }
  }
  return {
    carries: [...new Set(here(after).map((t) => t.listenerKey))],
    adds,
    fits,
    each: monthly,
    total,
    tooLarge: total > MAX_DESIRED_PUBLISHED,
  };
}

/** `POST relays/{id}/providers/{locationId}/want/preview {want}`: read only. */
export const wantPreview = internalQuery({
  args: {
    relayId: v.id('relays'),
    locationId: v.id('edgeLocations'),
    want: v.union(v.number(), v.null()),
  },
  handler: async (ctx, a) => {
    const relay = await ctx.db.get(a.relayId);
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Node not found' });
    const want = cleanWant(a.want);
    return { want, ...(await wantEffect(ctx.db, relay, a.locationId, want)) };
  },
});

function cleanWant(want: number | null): number | null {
  if (want === null) return null;
  if (!Number.isInteger(want) || want < 1 || want > MAX_PICK_WANT)
    throw new ConvexError({
      code: 'validation',
      message: `Addresses here must be 1 to ${MAX_PICK_WANT}, or none`,
    });
  return want;
}

/**
 * `POST relays/{id}/providers/{locationId}/want {want}`: save one pick's count
 * (null clears it). Refused while a setup run, a rotation or a restore owns the
 * node, and when the set would ask for more addresses than one origin
 * publishes (`edge.set_too_large`). The pool grows to hold it at once
 * (`ensurePoolCapacity` runs on the next reconcile pass); lowering a count
 * retires nothing (the pool never shrinks by itself: rebalance makes room).
 */
export const setPickWant = internalMutation({
  args: {
    relayId: v.id('relays'),
    locationId: v.id('edgeLocations'),
    want: v.union(v.number(), v.null()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    await assertAdmission(ctx.db, 'setup.start');
    const relay = await ctx.db.get(a.relayId);
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Node not found' });
    await assertNoRunningSetup(ctx.db, relay);
    await assertNoRotationOrQuarantine(ctx.db, relay);
    const want = cleanWant(a.want);
    // A pick serving its countries only makes nothing for everyone: a count
    // there would wait unseen and come back over the pool's size later.
    if (
      want !== null &&
      relay.providerSet?.find((p) => p.locationId === a.locationId)?.audienceOnly
    )
      throw new ConvexError({
        code: 'validation',
        message:
          'This location keeps addresses for its countries only: switch that off before setting a count for everyone',
      });
    const effect = await wantEffect(ctx.db, relay, a.locationId, want);
    if (effect.tooLarge)
      throw new ConvexError({
        code: 'edge.set_too_large',
        message: `The set would ask for ${effect.total} addresses in use; one node publishes at most ${MAX_DESIRED_PUBLISHED}`,
      });
    const before = pickWant(relay.providerSet?.find((p) => p.locationId === a.locationId)?.want);
    if ((before ?? null) === want) return { ok: true as const, changed: false, want, adds: 0 };
    const next = (relay.providerSet ?? []).map((p) => {
      if (p.locationId !== a.locationId) return p;
      const { want: _was, ...rest } = p;
      void _was;
      return want === null ? rest : { ...rest, want };
    });
    await ctx.db.patch(relay._id, { providerSet: next, updatedAt: Date.now() });
    const location = await ctx.db.get(a.locationId);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'edge.relay.pick_want',
      targetType: 'relay',
      targetId: relay._id,
      payload: {
        relaySlug: relay.slug,
        placeKey: location?.placeKey ?? null,
        want: want ?? 0,
        adds: effect.adds,
      },
    });
    return { ok: true as const, changed: true, want, adds: effect.adds };
  },
});

/**
 * Before deploying a build older than counts: every pick's count goes. The
 * requirement is back to one address per pick; addresses a count made stay
 * published (the pool never shrinks by itself; rebalance makes room). Pages
 * until done; safe to run again.
 */
export const clearPickWantsForRollback = internalMutation({
  args: { cursor: v.optional(v.union(v.string(), v.null())) },
  handler: async (ctx, a) => {
    const page = await ctx.db.query('relays').paginate({ cursor: a.cursor ?? null, numItems: 100 });
    let cleared = 0;
    for (const relay of page.page) {
      if (!relay.providerSet?.some((p) => p.want !== undefined)) continue;
      await ctx.db.patch(relay._id, {
        providerSet: relay.providerSet.map(({ want: _w, ...p }) => {
          void _w;
          return p;
        }),
        updatedAt: Date.now(),
      });
      cleared++;
    }
    // Page after page in transactions of their own, until every node is clean.
    if (!page.isDone)
      await ctx.scheduler.runAfter(0, internal.edgePickWants.clearPickWantsForRollback, {
        cursor: page.continueCursor,
      });
    return { cleared, done: page.isDone };
  },
});
