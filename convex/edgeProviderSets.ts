/**
 * A node's provider set, edited by hand (`POST relays/{id}/providers {add?, remove?}`;
 * docs/edges.md § "Provider sets").
 *
 *  - Add: on a node live behind this origin and enrolled, an `add` re-protect
 *    run (new addresses in the added locations, a review when they are a new
 *    shape, nothing retired); on any other origin the set is saved, and the
 *    operator adds a spare there and puts it in use.
 *  - Remove: allowed only when what SURVIVES still serves every transport and
 *    meets the requirement the remaining picks make (`edge.set_would_uncover`
 *    otherwise, naming the transports). A survivor is a published, active,
 *    addressed edge outside the removed picks whose verification is current
 *    (an L4 tick, an L7 proof): an untested spare or a pick with no address
 *    never counts. The removed picks' published addresses then drain and their
 *    spares are cancelled.
 *
 * Refused while a setup run owns the origin, a rotation or a restore runs, the
 * origin is quarantined, or edges are frozen. Audited `edge.relay.providers_changed`.
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { MAX_DESIRED_PUBLISHED } from './lib/edgeConfig';
import { assertAdmission } from './lib/edges/maintenance';
import { assertNoRunningSetup, assertNoRotationOrQuarantine } from './lib/edges/relayGuards';
import { coverTargets, MAX_PROVIDER_PICKS, requirementOf } from './lib/edges/providerSet';
import { carries, publishedRefOf, setPicksOf } from './lib/edges/setState';
import type { PublishedRef } from './lib/edges/providerSet';
import { verificationListenersOf } from './lib/edges/verificationContext';
import { needsEndpointVerification, verificationCurrent } from './lib/edges/verification';
import { l7QualificationCurrent } from './edgeRender';
import { unpublishFromPool } from './relays';
import { liveEdgesOfRelay } from './lib/edges/relayGuards';
import { listenersOf } from './relayListeners';
import { boundToRelay, startReprotect } from './edgeSetupRuns';
import { EDGE_LIVE_STATUSES } from './lib/edges/pool';

const LIVE: ReadonlySet<string> = new Set(EDGE_LIVE_STATUSES);

export const change = internalMutation({
  args: {
    relayId: v.id('relays'),
    add: v.optional(v.array(v.id('edgeLocations'))),
    remove: v.optional(v.array(v.id('edgeLocations'))),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    // New work: held while the edges maintenance switch is on.
    await assertAdmission(ctx.db, 'setup.start');
    const relay = await ctx.db.get(a.relayId);
    if (!relay || relay.deleting)
      throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    if (relay.setupOwned)
      throw new ConvexError({
        code: 'edge.setup_run_active',
        message: 'A setup run owns this node; wait for it to finish',
      });
    await assertNoRunningSetup(ctx.db, relay);
    await assertNoRotationOrQuarantine(ctx.db, relay);
    const add = [...new Set(a.add ?? [])];
    const remove = [...new Set(a.remove ?? [])];
    if (add.length === 0 && remove.length === 0)
      throw new ConvexError({ code: 'validation', message: 'Name a location to add or remove' });
    if (add.some((id) => remove.includes(id)))
      throw new ConvexError({
        code: 'validation',
        message: 'A location is both added and removed',
      });
    const before = relay.providerSet ?? (await impliedSetOf(ctx, relay));
    for (const id of add) {
      const loc = await ctx.db.get(id);
      const account = loc ? await ctx.db.get(loc.accountId) : null;
      if (!loc || !account)
        throw new ConvexError({ code: 'not_found', message: 'Location not found' });
      if (!loc.enabled || !account.enabled)
        throw new ConvexError({
          code: 'edge.account_incompatible',
          message: 'That location or its account is switched off',
        });
      if (before.some((p) => p.locationId === id))
        throw new ConvexError({ code: 'validation', message: 'That location is already picked' });
    }
    for (const id of remove)
      if (!before.some((p) => p.locationId === id))
        throw new ConvexError({ code: 'validation', message: 'That location is not picked' });
    const remaining = before.filter((p) => !remove.includes(p.locationId));
    if (remaining.length + add.length > MAX_PROVIDER_PICKS)
      throw new ConvexError({
        code: 'edge.set_too_large',
        message: `A node is protected from at most ${MAX_PROVIDER_PICKS} locations`,
      });
    if (remaining.length + add.length === 0)
      throw new ConvexError({
        code: 'validation',
        message: 'Keep at least one location (remove protection to serve the node directly)',
      });
    const now = Date.now();
    let drained = 0;
    if (remove.length > 0)
      drained = await removePicks(ctx, relay, remaining, remove, a.actorAdminId);
    let runId: Id<'edgeSetupRuns'> | null = null;
    const fresh = (await ctx.db.get(relay._id))!;
    const origin = fresh.origin;
    const enrolled =
      origin.kind === 'panel-node'
        ? await ctx.db
            .query('panelNodeIntents')
            .withIndex('by_server_name', (q) =>
              q.eq('backendServerId', origin.backendServerId).eq('name', origin.nodeName),
            )
            .unique()
        : null;
    if (add.length > 0 && enrolled && (await boundToRelay(ctx, fresh))) {
      // A live enrolled node gets its new addresses through a run (tested,
      // reviewed when they are a new shape, rehearsed, committed). The set
      // becomes the union at its go-live.
      if (!fresh.providerSet)
        await ctx.db.patch(fresh._id, { providerSet: remaining, updatedAt: now });
      const res = await startReprotect(ctx, {
        relayId: fresh._id,
        mode: 'add',
        addPicks: add,
        actorAdminId: a.actorAdminId,
      });
      runId = res.runId;
    } else {
      await ctx.db.patch(fresh._id, {
        providerSet: [...remaining, ...add.map((locationId) => ({ locationId, addedAt: now }))],
        updatedAt: now,
      });
    }
    await writeAuditLog(ctx, {
      actorType: a.actorAdminId ? 'admin' : 'system',
      actorId: a.actorAdminId ?? undefined,
      action: 'edge.relay.providers_changed',
      targetType: 'relay',
      targetId: relay._id,
      payload: {
        relaySlug: relay.slug,
        added: add.length,
        removed: remove.length,
        drained,
        picks: remaining.length + add.length,
        run: runId !== null,
      },
    });
    return { ok: true as const, runId, drained };
  },
});

/** A node without a recorded set: the locations its published edges come from. */
async function impliedSetOf(
  ctx: { db: import('./_generated/server').DatabaseReader },
  relay: Doc<'relays'>,
): Promise<NonNullable<Doc<'relays'>['providerSet']>> {
  const out: NonNullable<Doc<'relays'>['providerSet']> = [];
  for (const id of relay.publishedEdgeIds) {
    if (!id) continue;
    const e = await ctx.db.get(id);
    if (e?.locationId && !out.some((p) => p.locationId === e.locationId))
      out.push({ locationId: e.locationId, addedAt: e.publishedAt ?? e._creationTime });
  }
  return out;
}

/**
 * Remove picks after checking the survivors (see the module doc), then drain
 * the removed picks' published addresses and cancel their spares. Returns how
 * many addresses drain.
 */
async function removePicks(
  ctx: import('./_generated/server').MutationCtx,
  relay: Doc<'relays'>,
  remaining: NonNullable<Doc<'relays'>['providerSet']>,
  remove: Id<'edgeLocations'>[],
  actorAdminId: Id<'adminUsers'> | undefined,
): Promise<number> {
  const listeners = (
    await verificationListenersOf(ctx.db, relay, await listenersOf(ctx, relay._id))
  ).filter((l) => !l.retired && l.deployed && l.enabled);
  const removed = new Set(remove as string[]);
  const now = Date.now();
  const survivors: PublishedRef[] = [];
  for (const id of relay.publishedEdgeIds) {
    if (!id) continue;
    const e = await ctx.db.get(id);
    if (!e || e.publication !== 'published' || e.status !== 'active') continue;
    if (e.locationId && removed.has(e.locationId as string)) continue;
    if (!e.addresses.v4 && !e.addresses.v6 && !e.addresses.hostname) continue;
    const l = listeners.find((x) => x._id === e.listenerId);
    if (!l) continue;
    const current =
      (e.layer ?? 'l4') === 'l7'
        ? await l7QualificationCurrent(e, l, now)
        : !needsEndpointVerification(e) || verificationCurrent(e, l);
    if (current) survivors.push(publishedRefOf(e, l.listenerKey));
  }
  // The requirement the remaining picks make, met by the survivors alone.
  const picks = (await setPicksOf(ctx.db, { providerSet: remaining })) ?? [];
  const req = requirementOf(
    listeners.map((l) => ({
      listenerKey: l.listenerKey,
      carriers: picks.filter((p) => p.usable && carries(p, l)).map((p) => p.pick.locationId),
    })),
    picks.map((p) => p.pick),
  );
  const short = [
    ...new Set([
      // Basic coverage on its own (a transport whose picks are gone asks for nothing else).
      ...listeners
        .filter((l) => !survivors.some((s) => s.listenerKey === l.listenerKey))
        .map((l) => l.listenerKey),
      ...coverTargets(req, survivors)
        .filter((t) => t.coversListener)
        .map((t) => t.listenerKey),
    ]),
  ];
  if (short.length > 0)
    throw new ConvexError({
      code: 'edge.set_would_uncover',
      message: `Removing it would leave ${short.join(', ')} without a tested address elsewhere; publish one first`,
    });
  // Drain the removed picks' published addresses; cancel their spares.
  let drained = 0;
  for (const e of await liveEdgesOfRelay(ctx.db, relay._id)) {
    if (!e.locationId || !removed.has(e.locationId as string)) continue;
    if (e.publication === 'published') {
      await unpublishFromPool(ctx, relay, e, actorAdminId ? { actorAdminId } : {});
      drained++;
    } else if (e.publication === 'unpublished' && LIVE.has(e.status) && e.status !== 'draining')
      await ctx.db.patch(e._id, { status: 'cancelled', statusChangedAt: now, updatedAt: now });
  }
  // The pool keeps room for what remains: never below the survivors.
  const after = (await ctx.db.get(relay._id))!;
  const desired = Math.min(
    MAX_DESIRED_PUBLISHED,
    Math.max(survivors.length + coverTargets(req, survivors).length, listeners.length),
  );
  if (after.desiredPublished !== desired)
    await ctx.db.patch(relay._id, {
      desiredPublished: Math.max(desired, survivors.length),
      updatedAt: now,
    });
  return drained;
}
