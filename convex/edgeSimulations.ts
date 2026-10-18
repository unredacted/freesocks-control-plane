/**
 * Test block evidence (docs/edges.md "Simulating a block on a test
 * deployment"). On a deployment that opts in (`EDGE_SIMULATOR_ALLOW` or local
 * development, `lib/edges/simulation.ts`), an operator makes the block
 * detector believe one published edge is blocked in one country, so the
 * automatic path runs for real: the detector suspects, the start checks run,
 * the rotation replaces the edge, members move. Nothing fake is written to the
 * detector's real inputs; the detector overlays the live simulations on a copy
 * of them.
 *
 * One simulation drives at most one rotation: the detector starts its rotation
 * through `startSimulatedRotation`, which consumes the simulation in the same
 * transaction that creates the rotation row. A refused start rolls back with it
 * and leaves the simulation live.
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { MutationCtx, QueryCtx } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { resolveEdgeConfig } from './lib/edgeConfig';
import { startRotation } from './edgeRotations';
import {
  MAX_LIVE_SIMULATIONS,
  SIMULATION_DEFAULT_MINUTES,
  SIMULATION_MINUTES,
  SIMULATION_REPORTERS,
  SIMULATION_RETENTION_MS,
  blockSimulatorAllowedIn,
  defaultSimulatedReporters,
} from './lib/edges/simulation';

type Simulation = Doc<'edgeBlockSimulations'>;
type EndReason = NonNullable<Simulation['endReason']>;

const MIN = 60_000;

/** Read on every call: removing the opt-in silences every simulation at once. */
export const simulatorAllowed = (): boolean => blockSimulatorAllowedIn(process.env);

function refuse(code: string, message: string): never {
  throw new ConvexError({ code, message });
}

/** The simulations of an origin that are live now (not ended, not expired). */
async function liveOfRelay(
  db: QueryCtx['db'],
  relayId: Id<'relays'>,
  now: number,
): Promise<Simulation[]> {
  return db
    .query('edgeBlockSimulations')
    .withIndex('by_relay_live', (q) =>
      q.eq('relayId', relayId).eq('endedAt', undefined).gt('expiresAt', now),
    )
    .take(20);
}

async function endSimulation(
  ctx: MutationCtx,
  sim: Simulation,
  reason: EndReason,
  now: number,
  extra: { rotationId?: Id<'edgeRotations'>; actorAdminId?: Id<'adminUsers'> } = {},
): Promise<void> {
  await ctx.db.patch(sim._id, {
    endedAt: now,
    endReason: reason,
    ...(extra.rotationId ? { rotationId: extra.rotationId } : {}),
  });
  const origin = await ctx.db.get(sim.relayId);
  await writeAuditLog(ctx, {
    actorType: extra.actorAdminId ? 'admin' : 'system',
    actorId: extra.actorAdminId,
    action: 'edge.block_simulation.ended',
    targetType: 'relay',
    targetId: sim.relayId,
    payload: { relaySlug: origin?.slug ?? null, reason },
  });
}

/**
 * Start test block evidence on a published edge for one country. Refused
 * (`edge.*`) unless the deployment opts in, the edge is published, probes are
 * on (the probe side of the evidence needs them) and the country is one edges
 * are checked from (elsewhere it would score nothing).
 */
export const start = internalMutation({
  args: {
    edgeId: v.id('edges'),
    country: v.string(),
    reporters: v.optional(v.number()),
    minutes: v.optional(v.number()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    if (!simulatorAllowed())
      refuse(
        'edge.simulator_disabled',
        'This deployment does not accept test block evidence (EDGE_SIMULATOR_ALLOW is not set)',
      );
    const edge = await ctx.db.get(a.edgeId);
    if (!edge) refuse('not_found', 'Edge not found');
    const origin = await ctx.db.get(edge.relayId);
    if (!origin) refuse('not_found', 'Origin not found');
    if (
      edge.publication !== 'published' ||
      edge.status !== 'active' ||
      !origin.publishedEdgeIds.some((id) => id === edge._id)
    )
      refuse('edge.not_published', 'Only a published edge can be blocked for a test');
    // The detector evaluates enabled origins only, and never one being deleted:
    // a test block there would never count, only wait out its time.
    if (!origin.enabled || origin.deleting)
      refuse(
        'edge.simulation_origin_off',
        'The detector does not look at this origin (disabled or being deleted)',
      );
    const cfg = await resolveEdgeConfig(ctx.db);
    if (!cfg.probe.enabled)
      refuse('edge.simulation_needs_probes', 'Turn reachability probes on first');
    const country = a.country.trim().toUpperCase();
    if (!cfg.probe.countries.includes(country))
      refuse('edge.simulation_country', 'Pick a country edges are checked from');
    const reporters = a.reporters ?? defaultSimulatedReporters(cfg.detect.minReporters);
    if (
      !Number.isInteger(reporters) ||
      reporters < SIMULATION_REPORTERS.min ||
      reporters > SIMULATION_REPORTERS.max
    )
      refuse(
        'validation',
        `reporters must be a whole number from ${SIMULATION_REPORTERS.min} to ${SIMULATION_REPORTERS.max}`,
      );
    const minutes = a.minutes ?? SIMULATION_DEFAULT_MINUTES;
    if (
      !Number.isInteger(minutes) ||
      minutes < SIMULATION_MINUTES.min ||
      minutes > SIMULATION_MINUTES.max
    )
      refuse(
        'validation',
        `minutes must be a whole number from ${SIMULATION_MINUTES.min} to ${SIMULATION_MINUTES.max}`,
      );
    const now = Date.now();
    // Live rows only, read as a range on expiry: rows a stalled sweep left open
    // after they expired never hide a live one from these limits.
    const onEdge = await ctx.db
      .query('edgeBlockSimulations')
      .withIndex('by_edge_live', (q) =>
        q.eq('edgeId', edge._id).eq('endedAt', undefined).gt('expiresAt', now),
      )
      .first();
    if (onEdge) refuse('edge.simulation_active', 'This edge already has a test block running');
    const anywhere = await ctx.db
      .query('edgeBlockSimulations')
      .withIndex('by_live', (q) => q.eq('endedAt', undefined).gt('expiresAt', now))
      .take(MAX_LIVE_SIMULATIONS);
    if (anywhere.length >= MAX_LIVE_SIMULATIONS)
      refuse(
        'edge.simulation_limit',
        `At most ${MAX_LIVE_SIMULATIONS} test blocks can run at once; end one first`,
      );
    const simulationId = await ctx.db.insert('edgeBlockSimulations', {
      relayId: origin._id,
      edgeId: edge._id,
      country,
      reporters,
      startedAt: now,
      expiresAt: now + minutes * MIN,
      ...(a.actorAdminId ? { startedBy: a.actorAdminId } : {}),
    });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId,
      action: 'edge.block_simulation.started',
      targetType: 'relay',
      targetId: origin._id,
      payload: { relaySlug: origin.slug, country, reporters, minutes },
    });
    return { ok: true as const, simulationId: simulationId as string };
  },
});

/** End every live test block on an edge (allowed whatever the opt-in says: ending is cleanup). */
export const end = internalMutation({
  args: { edgeId: v.id('edges'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { edgeId, actorAdminId }) => {
    const now = Date.now();
    // The live ones (expired rows are the sweep's to close).
    const rows = await ctx.db
      .query('edgeBlockSimulations')
      .withIndex('by_edge_live', (q) =>
        q.eq('edgeId', edgeId).eq('endedAt', undefined).gt('expiresAt', now),
      )
      .take(20);
    for (const sim of rows) await endSimulation(ctx, sim, 'ended', now, { actorAdminId });
    return { ok: true as const, ended: rows.length };
  },
});

/**
 * The live simulations of an origin as the detector overlays them. The
 * detector asks only while the deployment opts in.
 */
export const liveForRelay = internalQuery({
  args: { relayId: v.id('relays'), now: v.number() },
  handler: async (ctx, { relayId, now }) =>
    (await liveOfRelay(ctx.db, relayId, now)).map((s) => ({
      id: s._id,
      edgeId: s.edgeId as string,
      country: s.country,
      reporters: s.reporters,
    })),
});

/** The origin page's view: whether test blocks are accepted here, the live ones, the last few that ended. */
export const viewForRelay = internalQuery({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }) => {
    const now = Date.now();
    const live = await liveOfRelay(ctx.db, relayId, now);
    const recent = await ctx.db
      .query('edgeBlockSimulations')
      .withIndex('by_relay_live', (q) => q.eq('relayId', relayId).gt('endedAt', 0))
      .order('desc')
      .take(5);
    const iso = (ms: number) => new Date(ms).toISOString();
    return {
      available: simulatorAllowed(),
      live: live.map((s) => ({
        id: s._id as string,
        edgeId: s.edgeId as string,
        country: s.country,
        reporters: s.reporters,
        startedAt: iso(s.startedAt),
        expiresAt: iso(s.expiresAt),
      })),
      recent: recent.map((s) => ({
        id: s._id as string,
        edgeId: s.edgeId as string,
        country: s.country,
        endReason: s.endReason ?? 'ended',
        endedAt: iso(s.endedAt ?? s.startedAt),
        rotationId: (s.rotationId as string | undefined) ?? null,
      })),
    };
  },
});

/**
 * The detector's start for a target a test block names, in ONE transaction:
 * the simulation is re-read and must still be live, on this origin and this
 * edge, with the edge still published and the opt-in still set; the rotation
 * is started through the same `startRotation` every start uses (every guard
 * applies; a refusal throws and rolls this whole mutation back, leaving the
 * simulation live and no rotation); and the simulation is consumed with the
 * rotation's id. A concurrent start either retries and finds it consumed or is
 * refused by the one-rotation-per-origin guard, so one simulation drives at
 * most one rotation, whatever that rotation's outcome.
 */
export const startSimulatedRotation = internalMutation({
  args: {
    simulationId: v.id('edgeBlockSimulations'),
    relayId: v.id('relays'),
    targetEdgeId: v.id('edges'),
    reason: v.string(),
    affectedCountries: v.array(v.string()),
  },
  handler: async (ctx, a) => {
    if (!simulatorAllowed())
      refuse('edge.simulator_disabled', 'This deployment does not accept test block evidence');
    const now = Date.now();
    const sim = await ctx.db.get(a.simulationId);
    if (!sim || sim.endedAt !== undefined || sim.expiresAt <= now)
      refuse('edge.simulation_ended', 'The test block is no longer live');
    const edge = await ctx.db.get(a.targetEdgeId);
    if (
      sim.relayId !== a.relayId ||
      sim.edgeId !== a.targetEdgeId ||
      !edge ||
      edge.publication !== 'published'
    )
      refuse('edge.simulation_moved', 'The test block no longer names this published edge');
    const { rotationId } = await startRotation(ctx, {
      relayId: a.relayId,
      kind: 'replace',
      trigger: 'detector',
      burn: true,
      targetEdgeId: a.targetEdgeId,
      reason: a.reason,
      affectedCountries: a.affectedCountries,
      simulationId: a.simulationId,
    });
    await endSimulation(ctx, sim, 'consumed', now, { rotationId });
    return { rotationId };
  },
});

/**
 * Each detector pass: end what expired, what no longer names a published edge
 * and, once the opt-in is gone, everything; delete ended rows past retention.
 * Bounded per pass.
 */
export const sweep = internalMutation({
  args: { now: v.number() },
  handler: async (ctx, { now }) => {
    const allowed = simulatorAllowed();
    let ended = 0;
    // Expired first (oldest expiry first), then the live ones: each read is its
    // own bounded range, so neither kind can starve the other.
    const expired = await ctx.db
      .query('edgeBlockSimulations')
      .withIndex('by_live', (q) => q.eq('endedAt', undefined).lte('expiresAt', now))
      .take(50);
    for (const sim of expired) {
      await endSimulation(ctx, sim, allowed ? 'expired' : 'disabled', now);
      ended++;
    }
    const live = await ctx.db
      .query('edgeBlockSimulations')
      .withIndex('by_live', (q) => q.eq('endedAt', undefined).gt('expiresAt', now))
      .take(50);
    for (const sim of live) {
      let reason: EndReason | null = null;
      if (!allowed) reason = 'disabled';
      else {
        const edge = await ctx.db.get(sim.edgeId);
        const origin = await ctx.db.get(sim.relayId);
        if (!edge || edge.publication !== 'published') reason = 'ended';
        else if (!origin || !origin.enabled || origin.deleting) reason = 'ended';
      }
      if (reason) {
        await endSimulation(ctx, sim, reason, now);
        ended++;
      }
    }
    const old = await ctx.db
      .query('edgeBlockSimulations')
      .withIndex('by_live', (q) => q.gt('endedAt', 0).lt('endedAt', now - SIMULATION_RETENTION_MS))
      .take(50);
    for (const s of old) await ctx.db.delete(s._id);
    return { ended, deleted: old.length };
  },
});
