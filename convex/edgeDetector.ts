/**
 * Block detector (`edge-block-detector` cron): per enabled origin, gather the
 * detector window (attributed member reports, node load, probe verdicts), score
 * it (lib/edges/scoring.ts), persist the suspicion state + a baseline sample,
 * audit transitions, ask for detector-triggered probes when reports alone
 * raise suspicion, and — only with edge-level evidence, every gate open and the
 * operator's opt-in — start a burn rotation of the suspected edge.
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { ActionCtx, QueryCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { runWithCronOutcome } from './cronHeartbeat';
import {
  EDGE_PLUMBING,
  originPolicy,
  resolveEdgeConfig,
  edgeMs,
  type EdgeConfig,
} from './lib/edgeConfig';
import { resolveCensoredCountries } from './lib/censoredCountries';
import { deliveryPathsOf } from './lib/edges/render';
import { deliveryStyleOf, publishedEdgesOf } from './edgeRender';
import { heldCountries } from './edgeCountry';
import { steeringSettleMs, steeringSince } from './edgeRender';
import { listenersOf } from './relayListeners';
import { resolveModeCatalog } from './lib/connectionModes';
import { resolveMemberCountryConfig } from './memberCountry';
import { todayKey } from './relays';
import { isTerminalRunState } from './lib/edges/setupRuns';
import { liveEdgesOfRelay } from './lib/edges/relayGuards';
import { sustainedCountriesOf } from './lib/edges/probes/sustained';
import { familyKeyOf } from './probes';
import {
  fleetBrakeEngages,
  fleetRotationsToday,
  readFleetBrake,
  writeFleetBrake,
} from './lib/edges/fleet';
import {
  autoRotateDecision,
  evaluate,
  type BaselineSample,
  type EdgeProbeState,
  type Evaluation,
  type SteeringInput,
  type WindowReports,
} from './lib/edges/scoring';
import type { Verdict } from './lib/edges/probes/verdict';
import { lanesOn } from './lib/edges/lanes';
import { openBudgetLeft } from './edgeLanes';
import {
  applySimulatedEvidence,
  blockSimulatorAllowedIn,
  type SimulatedEvidence,
} from './lib/edges/simulation';

const MIN = 60_000;
const DAY = 24 * 60 * MIN;
const SAMPLE_RETENTION_MS = 7 * DAY;
const LOAD_STALE_MS = 20 * MIN;
/** Report rows read per page while aggregating one detector window. */
const REPORT_PAGE_SIZE = 200;

type Origin = Doc<'relays'>;

/** One page of an origin's detector window, aggregated (the drain merges pages). */
export interface WindowPage {
  reports: number;
  distinctReporters: number;
  countries: Record<string, number>;
  byEdge: Record<string, { count: number; countries: Record<string, number> }>;
  scanned: number;
  isDone: boolean;
  continueCursor: string;
}

/**
 * ONE page of the report window (one `paginate` per query: Convex runs a single
 * paginated query per function). The action-driven drain (`relayWindow`) walks
 * the pages up to `detect.maxReportRowsPerEval`, so no transaction reads more
 * than a page however busy the origin is.
 */
export const reportPage = internalQuery({
  args: {
    relaySlug: v.string(),
    since: v.number(),
    /** The evaluation time: every page reads the same window, whatever lands meanwhile. */
    until: v.number(),
    cursor: v.union(v.string(), v.null()),
    numItems: v.number(),
  },
  handler: async (ctx, { relaySlug, since, until, cursor, numItems }): Promise<WindowPage> => {
    const page = await ctx.db
      .query('issueReports')
      // Up to the END of the evaluation's millisecond (`_creationTime` is finer
      // than `now`): a report created during the drain is the next window's.
      .withIndex('by_relay', (q) =>
        q
          .eq('relaySlug', relaySlug)
          .gte('_creationTime', since)
          .lt('_creationTime', until + 1),
      )
      .paginate({ cursor, numItems: Math.max(1, Math.min(REPORT_PAGE_SIZE, numItems)) });
    const out: WindowPage = {
      reports: 0,
      distinctReporters: 0,
      countries: {},
      byEdge: {},
      scanned: page.page.length,
      isDone: page.isDone,
      continueCursor: page.continueCursor,
    };
    for (const r of page.page) {
      if (r.kind !== 'report') continue;
      out.reports += 1;
      // detectorWeight 0 = a repeat by the same member inside the window (the
      // peppered dedupe mark), or a report recorded while no mark pepper was
      // configured (fail closed); it never adds a reporter, at origin OR edge
      // level. A missing weight is treated the same way.
      const weight = r.detectorWeight ?? 0;
      out.distinctReporters += weight;
      const c = r.country ?? r.detectedCountry;
      if (c) out.countries[c] = (out.countries[c] ?? 0) + 1;
      if (r.relayEdgeId && weight > 0) {
        const e = (out.byEdge[r.relayEdgeId] ??= { count: 0, countries: {} });
        e.count += weight;
        if (c) e.countries[c] = (e.countries[c] ?? 0) + weight;
      }
    }
    return out;
  },
});

/**
 * Walk the report window page by page up to the cap. A plain `.take(N)` is not
 * enough: zero-weight duplicates can fill N before the first distinct reporter
 * appears, so the pages are walked with a cursor, and when the cap is reached
 * the window is marked INCOMPLETE rather than scored truncated. Never reads
 * past the cap, so the cap really is the evaluation's read budget; a window
 * that ends exactly ON it counts as truncated (the paginator cannot tell
 * "exactly the last row" from "one more page"), which is the safe direction.
 */
async function drainReportWindow(
  ctx: ActionCtx,
  relaySlug: string,
  since: number,
  until: number,
  cap: number,
): Promise<WindowReports> {
  const window: WindowReports = { reports: 0, distinctReporters: 0, countries: {}, byEdge: {} };
  let cursor: string | null = null;
  let scanned = 0;
  for (;;) {
    const remaining = cap - scanned;
    if (remaining <= 0) {
      window.incomplete = true;
      break;
    }
    const page: WindowPage = await ctx.runQuery(internal.edgeDetector.reportPage, {
      relaySlug,
      since,
      until,
      cursor,
      numItems: Math.min(REPORT_PAGE_SIZE, remaining),
    });
    window.reports += page.reports;
    window.distinctReporters += page.distinctReporters;
    for (const [c, n] of Object.entries(page.countries))
      window.countries[c] = (window.countries[c] ?? 0) + n;
    for (const [edgeId, e] of Object.entries(page.byEdge)) {
      const into = (window.byEdge[edgeId] ??= { count: 0, countries: {} });
      into.count += e.count;
      for (const [c, n] of Object.entries(e.countries))
        into.countries[c] = (into.countries[c] ?? 0) + n;
    }
    scanned += page.scanned;
    if (page.isDone) break;
    cursor = page.continueCursor;
  }
  return window;
}

/** Everything one evaluation needs besides the report window, read in one query. */
async function loadRelayContext(ctx: QueryCtx, relayId: Id<'relays'>, now: number) {
  const origin = await ctx.db.get(relayId);
  if (!origin) return null;
  const cfg = await resolveEdgeConfig(ctx.db);
  const samples = await ctx.db
    .query('relaySamples')
    .withIndex('by_relay_at', (q) => q.eq('relayId', relayId).gte('at', now - SAMPLE_RETENTION_MS))
    .collect();
  const baseline: BaselineSample[] = samples.map((s) => ({
    at: s.at,
    reports: s.reports,
    distinctReporters: s.distinctReporters,
    usersOnline: s.usersOnline,
  }));
  // Only a backend node has a load / online signal (backend node inventory).
  const panelNode = origin.origin.kind === 'panel-node' ? origin.origin : null;
  const inv = panelNode
    ? await ctx.db
        .query('backendNodeInventory')
        .withIndex('by_server_name', (q) =>
          q.eq('backendServerId', panelNode.backendServerId).eq('name', panelNode.nodeName),
        )
        .unique()
    : null;
  const usersOnline = inv ? inv.usersOnline : null;
  const loadStale = inv ? now - inv.lastStatsAt > LOAD_STALE_MS : true;
  const nodeOnline = inv ? inv.online : null;
  const edges: EdgeProbeState[] = [];
  const published: Array<{ edgeId: string; poolIndex: number }> = [];
  // Every live address of the node, published or not: sustained
  // unreachability needs another one of the same listener reached from the
  // same country.
  const live = await liveEdgesOfRelay(ctx.db, relayId);
  for (let i = 0; i < origin.publishedEdgeIds.length; i++) {
    const id = origin.publishedEdgeIds[i];
    if (!id) continue;
    const e = await ctx.db.get(id);
    if (!e) continue;
    published.push({ edgeId: e._id, poolIndex: e.poolIndex ?? i });
    // Reachability history per country (bounded: countries × sources ×
    // families): a country is block evidence only once the edge has been
    // reachable from it before (the IPv4 path, what members receive).
    const history = await ctx.db
      .query('probeReachability')
      .withIndex('by_target_country', (q) => q.eq('targetKind', 'edge').eq('targetRef', e._id))
      .collect();
    // The member-facing path: IPv4 for an L4 edge, the NAME for an L7 one
    // (`familyKeyOf`). `lastOkAt` is the signal, so a country that only ever
    // saw a degraded verdict still counts as having reached the edge.
    const wasReachable = (country: string) =>
      history.some(
        (r) =>
          r.country === country &&
          familyKeyOf(r) !== 6 &&
          (r.lastOkAt !== undefined || r.lastReachableAt !== undefined),
      );
    const entries = e.reachability?.byCountry ?? [];
    const external = entries.filter((c) => c.country !== 'XX');
    // Never reached from a listed country while another address of the node
    // is (lib/edges/probes/verdict.ts `sustainedCountries`): evidence like a
    // transition. An outage is vetoed by `evaluate`, as for any probe verdict.
    const sustained = sustainedCountriesOf(e, live, cfg, now);
    edges.push({
      edgeId: e._id,
      byCountry: external.map((c) => ({
        country: c.country,
        verdict: c.verdict as Verdict,
        // The summary judges the transition PER PORT (a port blocked since it
        // appeared is not evidence even if another port was reached); the
        // country-wide history is only the fallback for summaries written
        // before the marker existed.
        wasReachable: c.wasReachable ?? wasReachable(c.country),
        sustained: sustained.includes(c.country),
        // Each country's own freshness: a summary refreshed by one source
        // must not make another country's old verdict look current.
        ageMs: now - c.lastAt,
      })),
      internalVerdict: entries.find((c) => c.country === 'XX')?.verdict ?? 'unknown',
      providerHealth: e.health,
      probeAgeMs: external.length ? now - Math.max(...external.map((c) => c.lastAt)) : null,
    });
  }
  const rotation = origin.activeRotationId ? await ctx.db.get(origin.activeRotationId) : null;
  const rotationActive =
    !!rotation &&
    !['done', 'failed', 'rolled_back', 'quarantined', 'cancelled'].includes(rotation.phase);
  // A guided setup owns the origin only while one of its runs is live; the
  // leftover of a cancelled or failed one has simply not gone live.
  let setupRunLive = false;
  if (origin.setupOwned && origin.backendServerId && origin.nodeName) {
    const runs = await ctx.db
      .query('edgeSetupRuns')
      .withIndex('by_origin', (q) =>
        q.eq('backendServerId', origin.backendServerId!).eq('nodeName', origin.nodeName!),
      )
      .order('desc')
      .take(5);
    setupRunLive = runs.some((r) => !isTerminalRunState(r.state));
  }
  return {
    origin,
    cfg,
    // Lanes on: the open addresses, and whether their own budget has one left.
    lanes: lanesOn(origin)
      ? {
          openEdgeIds: await openEdgeIdsOf(ctx, published),
          openBudgetLeft: await openBudgetLeft(ctx.db, origin, cfg, now),
        }
      : null,
    steering: await steeringInputFor(ctx, origin, cfg, now),
    since: now - edgeMs.detectWindow(cfg),
    baseline,
    usersOnline,
    loadStale,
    nodeOnline,
    edges,
    published,
    rotationActive,
    setupRunLive,
  };
}

/**
 * The steering vetoes' inputs (delivery by country, docs/edges.md), or null
 * while `delivery.country.steer` is off: the origin's published edges as the
 * assignment sees them (their per-country state included), every delivery
 * path its members' bodies can take, and where the country-wide guard holds.
 */
async function steeringInputFor(
  ctx: QueryCtx,
  origin: Origin,
  cfg: EdgeConfig,
  now: number,
): Promise<SteeringInput | null> {
  if (!(await resolveMemberCountryConfig(ctx.db)).steer) return null;
  // A veto assumes members already hold the steered order: one refresh
  // interval (and the revalidation window) after steering was turned on.
  const since = await steeringSince(ctx.db);
  if (since === null || now - since < steeringSettleMs(cfg)) return null;
  const { published } = await publishedEdgesOf(
    ctx,
    origin,
    { kind: 'member' },
    { includeIneligible: true },
  );
  const style = origin.backendServerId
    ? await deliveryStyleOf(ctx, origin.backendServerId)
    : 'subscription';
  return {
    published,
    paths: deliveryPathsOf(cfg.render, style),
    checked: cfg.probe.countries,
    curated: (await resolveCensoredCountries(ctx.db)).codes,
    held: await heldCountries(ctx.db, cfg.probe.countries, now),
    freedomListeners: await freedomListenersOf(ctx, origin),
    ...(lanesOn(origin) ? { lanes: true } : {}),
  };
}

async function openEdgeIdsOf(
  ctx: QueryCtx,
  published: ReadonlyArray<{ edgeId: string }>,
): Promise<string[]> {
  const out: string[] = [];
  for (const p of published) {
    const e = await ctx.db.get(p.edgeId as Id<'edges'>);
    if (e && e.lane !== 'trusted') out.push(p.edgeId);
  }
  return out;
}

/**
 * The origin's listeners whose transport only freedom-family modes use (the
 * backend setup's modes by transport tag, judged against the mode catalog).
 * Fails closed: a listener without a binding, a tag no mode claims, or one a
 * privacy-family mode also uses is not on the list.
 */
async function freedomListenersOf(ctx: QueryCtx, origin: Origin): Promise<string[]> {
  if (!origin.backendServerId) return [];
  const setup = await ctx.db
    .query('panelSetups')
    .withIndex('by_server', (q) => q.eq('backendServerId', origin.backendServerId!))
    .first();
  if (!setup) return [];
  const catalog = await resolveModeCatalog(ctx.db);
  const familyOfTag = (tag: string) => {
    const families = setup.modes
      .filter((m) => m.tag === tag)
      .map((m) => catalog.modes.find((c) => c.id === m.slug)?.family ?? null);
    return families.length > 0 && families.every((f) => f === 'freedom');
  };
  return (await listenersOf(ctx, origin._id))
    .filter((l) => l.panelBinding && familyOfTag(l.panelBinding.inboundTag))
    .map((l) => l.listenerKey);
}

export const relayContext = internalQuery({
  args: { relayId: v.id('relays'), now: v.number() },
  handler: (ctx, { relayId, now }) => loadRelayContext(ctx, relayId, now),
});

export type RelayWindow = NonNullable<Awaited<ReturnType<typeof loadRelayContext>>> & {
  window: WindowReports;
};

/** Everything one evaluation needs: the context query plus the drained report window. */
export const relayWindow = internalAction({
  args: { relayId: v.id('relays'), now: v.number() },
  handler: async (ctx, { relayId, now }): Promise<RelayWindow | null> => {
    const c = await ctx.runQuery(internal.edgeDetector.relayContext, { relayId, now });
    if (!c) return null;
    const cap = Math.max(1, EDGE_PLUMBING.maxReportRowsPerEval);
    const window = await drainReportWindow(ctx, c.origin.slug, c.since, now, cap);
    return { ...c, window };
  },
});

/** Persist one evaluation: suspicion state, a baseline sample, transition audits, sample retention. */
export const recordEvaluation = internalMutation({
  args: {
    relayId: v.id('relays'),
    now: v.number(),
    evaluation: v.any(),
    usersOnline: v.union(v.number(), v.null()),
    veto: v.union(v.string(), v.null()),
    lastRotateError: v.optional(v.union(v.string(), v.null())),
    rotationActive: v.optional(v.boolean()),
    /** The node's stats were stale for this evaluation (no live user count). */
    loadStale: v.optional(v.boolean()),
    /** The window's own counts: the only place `relaySamples` is written from. */
    windowReports: v.optional(v.number()),
    windowDistinctReporters: v.optional(v.number()),
    windowIncomplete: v.optional(v.boolean()),
    /** Test block evidence took part (edgeSimulations.ts): kept on the suspicion and in its audit. */
    simulated: v.optional(v.boolean()),
  },
  handler: async (ctx, a) => {
    const origin = await ctx.db.get(a.relayId);
    if (!origin) return null;
    const ev = a.evaluation as Evaluation;
    const prev = origin.suspicion;
    // The baseline describes NORMAL operation. A sample taken while the origin
    // is suspected, rotating, cooling down after a rotation or behind an
    // offline node would teach the detector that a block looks normal, so it
    // is not appended to the ring. Nor is one whose numbers are not the truth:
    // a stale node reading has no live user count to compare against, and an
    // incomplete window undercounts its reports.
    const baselineEligible =
      ev.state !== 'suspected' &&
      !a.rotationActive &&
      !ev.nodeOffline &&
      !a.loadStale &&
      !a.windowIncomplete &&
      !(origin.cooldownUntil !== undefined && origin.cooldownUntil > a.now);
    await ctx.db.patch(a.relayId, {
      suspicion: {
        state: ev.state,
        hintLevel: ev.hintLevel,
        score: round3(ev.score),
        reportScore: round3(ev.reportScore),
        loadScore: round3(ev.loadScore),
        probeScore: round3(ev.probeScore),
        scope: ev.scope,
        countries: ev.countries.slice(0, 10),
        edgeEvidence: ev.edgeEvidence.map((e) => ({
          edgeId: e.edgeId as Id<'edges'>,
          source: e.source,
          countries: e.countries.slice(0, 10),
          ...(e.neverReached ? { neverReached: e.neverReached.slice(0, 10) } : {}),
        })),
        firstSeenAt: ev.firstSeenAt,
        lastEvalAt: a.now,
        quietEvals: ev.quietEvals,
        baselineWarm: ev.baselineWarm,
        veto: a.veto,
        hint: hintText(ev, a.veto),
        lastRotateError:
          a.lastRotateError === undefined
            ? prev?.lastRotateError
            : (a.lastRotateError ?? undefined),
        ...(a.simulated ? { simulated: true } : {}),
      },
      updatedAt: a.now,
    });
    if (baselineEligible) {
      // Written ONCE, with one meaning: `reports` is the window's row count and
      // `distinctReporters` its deduplicated member count, both straight from
      // the window. (They used to be inserted as a country total with a zero
      // reporter count and then patched by a second mutation, so a sample read
      // between the two (or one whose patch never landed) carried a different
      // quantity than the rest of the ring.)
      await ctx.db.insert('relaySamples', {
        relayId: a.relayId,
        at: a.now,
        reports: a.windowReports ?? 0,
        distinctReporters: a.windowDistinctReporters ?? 0,
        usersOnline: a.usersOnline,
      });
    }
    // Retention: drop the oldest samples past 7 days (bounded per tick).
    const old = await ctx.db
      .query('relaySamples')
      .withIndex('by_relay_at', (q) =>
        q.eq('relayId', a.relayId).lt('at', a.now - SAMPLE_RETENTION_MS),
      )
      .take(50);
    for (const s of old) await ctx.db.delete(s._id);
    if (ev.transition === 'suspected') {
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'edge.block_suspected',
        targetType: 'relay',
        targetId: a.relayId,
        payload: {
          relaySlug: origin.slug,
          hintLevel: ev.hintLevel,
          score: round3(ev.score),
          reporters: Math.round(ev.countries.reduce((acc, c) => acc + c.count, 0)),
          topCountry: ev.countries[0]?.code ?? null,
          scope: ev.scope,
          autoRotate: origin.autoRotate,
          simulated: a.simulated === true,
        },
      });
    } else if (ev.transition === 'cleared') {
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'edge.block_cleared',
        targetType: 'relay',
        targetId: a.relayId,
        payload: { relaySlug: origin.slug, reason: 'score_below_threshold' },
      });
    }
    return null;
  },
});

function round3(x: number): number {
  return Math.round(x * 1000) / 1000;
}

function hintText(ev: Evaluation, veto: string | null): string | undefined {
  if (ev.state !== 'suspected') return undefined;
  const where = ev.countries[0] ? ` (mostly ${ev.countries[0].code})` : '';
  if (ev.nodeOffline) {
    return `Node offline: an outage, not a block${where}${veto ? `; automatic rotation held (${veto})` : ''}`;
  }
  const how =
    ev.hintLevel === 'corroborated'
      ? 'members and probes agree'
      : ev.hintLevel === 'probes'
        ? 'external probes cannot reach an edge'
        : ev.hintLevel === 'reports'
          ? 'members report failures'
          : 'load dropped';
  return `Possible block${where}: ${how}${veto ? `; automatic rotation held (${veto})` : ''}`;
}

/** Expired dedupe marks (bounded per tick). */
export const sweepMarks = internalMutation({
  args: { now: v.number() },
  handler: async (ctx, { now }) => {
    const rows = await ctx.db
      .query('relayReportMarks')
      .withIndex('by_expiresAt', (q) => q.lt('expiresAt', now))
      .take(200);
    for (const r of rows) await ctx.db.delete(r._id);
    return { deleted: rows.length };
  },
});

export interface DetectorReport {
  evaluated: number;
  suspected: number;
  rotated: number;
  probesRequested: number;
  errors: number;
  /** The fleet brake held every automatic rotation this pass. */
  braked: boolean;
}

/**
 * The fleet brake's verdict for one detector pass (lib/edges/fleet.ts):
 * engaged while more than `detect.fleetBreakerPct` percent of the evaluated
 * origins are suspected; released on the first pass back under it. Audited
 * on each transition, never per pass.
 */
export const recordFleetBrake = internalMutation({
  args: { suspected: v.number(), evaluated: v.number(), now: v.number() },
  handler: async (ctx, { suspected, evaluated, now }) => {
    const cfg = await resolveEdgeConfig(ctx.db);
    const threshold = cfg.detect.fleetBreakerPct;
    const engaged = fleetBrakeEngages({ suspected, evaluated, thresholdPct: threshold });
    const prev = await readFleetBrake(ctx.db);
    await writeFleetBrake(ctx.db, {
      engaged,
      since: engaged ? (prev.engaged ? prev.since : now) : null,
      suspected,
      evaluated,
      threshold,
      updatedAt: now,
    });
    if (engaged !== prev.engaged)
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'edge.fleet_brake',
        targetType: 'edge_fleet',
        payload: { engaged, suspected, evaluated, threshold },
      });
    return { engaged, rotationsToday: await fleetRotationsToday(ctx.db, now) };
  },
});

interface Evaluated {
  origin: Origin;
  w: RelayWindow;
  ev: Evaluation;
  /** The live test blocks laid over this origin's inputs (empty unless the deployment opts in). */
  sims: Array<SimulatedEvidence & { id: Id<'edgeBlockSimulations'> }>;
}

/** The countries the evaluation's evidence names for one edge (a detector start's snapshot). */
function evidenceCountries(ev: Evaluation, edgeId: string): string[] {
  const out = new Set<string>();
  for (const e of ev.edgeEvidence) if (e.edgeId === edgeId) for (const c of e.countries) out.add(c);
  return [...out];
}

export const run = internalAction({
  args: {},
  handler: async (ctx): Promise<DetectorReport> =>
    runWithCronOutcome(ctx, 'edge-block-detector', async () => {
      const report: DetectorReport = {
        evaluated: 0,
        suspected: 0,
        rotated: 0,
        probesRequested: 0,
        errors: 0,
        braked: false,
      };
      const now = Date.now();
      await ctx.runMutation(internal.edgeDetector.sweepMarks, { now });
      // Test blocks (edgeSimulations.ts): end what expired or lost its edge, and
      // everything once the deployment's opt-in is gone.
      await ctx.runMutation(internal.edgeSimulations.sweep, { now });
      const simulatorOn = blockSimulatorAllowedIn(process.env);
      const origins: Origin[] = await ctx.runQuery(internal.relays.listEnabled, {});
      // Maintenance: detection is new work (it can start a rotation); skip the tick.
      if ((await ctx.runQuery(internal.edgeMaintenance.state, {})).frozen) return report;
      // Pass 1: evaluate every origin. The fleet brake is judged over the whole
      // pass BEFORE any rotation starts, so a mass block never replaces the
      // first origins of the list and only then notices the rest.
      let brakeSuspected = 0;
      const evaluated: Evaluated[] = [];
      for (const o of origins) {
        if (o.deleting) continue;
        try {
          const w = await ctx.runAction(internal.edgeDetector.relayWindow, {
            relayId: o._id,
            now,
          });
          if (!w) continue;
          // A live test block is laid over a COPY of the inputs: the real
          // window still reaches the record (and the baseline sample) below.
          const sims = simulatorOn
            ? await ctx.runQuery(internal.edgeSimulations.liveForRelay, { relayId: o._id, now })
            : [];
          const inputs =
            sims.length > 0
              ? applySimulatedEvidence(w.window, w.edges, sims)
              : { window: w.window, edges: w.edges };
          const ev = evaluate({
            now,
            window: inputs.window,
            baseline: w.baseline,
            usersOnline: w.usersOnline,
            loadStale: w.loadStale,
            nodeOnline: w.nodeOnline,
            edges: inputs.edges,
            cfg: w.cfg,
            prev: w.origin.suspicion
              ? {
                  state: w.origin.suspicion.state,
                  firstSeenAt: w.origin.suspicion.firstSeenAt,
                  quietEvals: w.origin.suspicion.quietEvals,
                }
              : null,
          });
          report.evaluated++;
          if (ev.state === 'suspected') {
            report.suspected++;
            // A node whose only evidence is on open addresses (lanes on: they
            // are expected to be blocked) is no sign of a mass block.
            const openOnly =
              !!w.lanes &&
              ev.edgeEvidence.length > 0 &&
              ev.edgeEvidence.every((x) => w.lanes!.openEdgeIds.includes(x.edgeId));
            if (!openOnly) brakeSuspected++;
          }
          evaluated.push({ origin: o, w, ev, sims });
        } catch (err) {
          report.errors++;
          console.warn(
            `[relay-detector] ${o.slug}: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
      }
      const fleet = await ctx.runMutation(internal.edgeDetector.recordFleetBrake, {
        suspected: brakeSuspected,
        evaluated: report.evaluated,
        now,
      });
      report.braked = fleet.engaged;
      // Started this pass; the start mutation counts each one against the cap too.
      let rotationsToday = fleet.rotationsToday;
      // Pass 2: per origin, the automatic decision, the record and the probes.
      for (const { origin: o, w, ev, sims } of evaluated) {
        try {
          const decision = autoRotateDecision({
            evaluation: ev,
            cfg: w.cfg,
            origin: {
              autoRotate: w.origin.autoRotate,
              setupOwned: w.origin.setupOwned === true && w.setupRunLive,
              notLive: w.origin.setupOwned === true && !w.setupRunLive,
              quarantined: !!w.origin.quarantine,
              rotationActive: w.rotationActive,
              cooldownUntil: w.origin.cooldownUntil ?? null,
              rotationsToday:
                w.origin.rotationsDayKey === todayKey(now) ? w.origin.rotationsToday : 0,
              maxRotationsPerDay: originPolicy(w.origin, w.cfg).maxRotationsPerDay,
              // Only an operator-managed Host blocks a rotation at index 0.
              hostManaged: w.origin.hostMode !== 'operator',
            },
            published: w.published,
            now,
            fleet: {
              brakeEngaged: fleet.engaged,
              rotationsToday,
              rotationsPerDay: w.cfg.detect.fleetRotationsPerDay,
            },
            ...(w.steering ? { steering: w.steering } : {}),
            ...(w.lanes ? { lanes: w.lanes } : {}),
          });
          const veto = 'veto' in decision ? decision.veto : null;
          let lastRotateError: string | null | undefined = undefined;
          if (!('veto' in decision)) {
            // The countries this start answers to, from THIS evaluation (the
            // record below rewrites the suspicion; later passes again).
            const affectedCountries = evidenceCountries(ev, decision.edgeId);
            const sim = sims.find((s) => s.edgeId === decision.edgeId);
            try {
              if (sim)
                // Consumed in the transaction that creates the rotation.
                await ctx.runMutation(internal.edgeSimulations.startSimulatedRotation, {
                  simulationId: sim.id,
                  relayId: o._id,
                  targetEdgeId: decision.edgeId as Id<'edges'>,
                  reason: `detector:${decision.source}:simulated`,
                  affectedCountries,
                });
              else
                await ctx.runMutation(internal.edgeRotations.start, {
                  relayId: o._id,
                  kind: 'replace',
                  trigger: 'detector',
                  burn: true,
                  targetEdgeId: decision.edgeId as Id<'edges'>,
                  reason: `detector:${decision.source}`,
                  affectedCountries,
                });
              report.rotated++;
              rotationsToday++;
              lastRotateError = null;
            } catch (err) {
              lastRotateError =
                err instanceof ConvexError
                  ? String((err.data as { code?: string }).code ?? 'error')
                  : 'error';
              // A replacement blocked again soon after it went into use: hold
              // automatic replacement of its transport instead of retrying every
              // pass until the daily cap (the operator resumes it). Asked on any
              // refusal: another blocker (a fleet brake, the daily cap) may be
              // the one the start named.
              if (lastRotateError !== 'edge.auto_replace_held')
                await ctx.runMutation(internal.edgeRotations.holdAutoReplace, {
                  relayId: o._id,
                  edgeId: decision.edgeId as Id<'edges'>,
                  code: 'replacement_reblocked',
                  ifReblocked: true,
                });
            }
          }
          await ctx.runMutation(internal.edgeDetector.recordEvaluation, {
            relayId: o._id,
            now,
            evaluation: ev,
            usersOnline: w.usersOnline,
            veto,
            rotationActive: w.rotationActive || !('veto' in decision),
            loadStale: w.loadStale,
            windowReports: w.window.reports,
            windowDistinctReporters: w.window.distinctReporters,
            windowIncomplete: w.window.incomplete ?? false,
            ...(sims.length > 0 ? { simulated: true } : {}),
            ...(lastRotateError !== undefined ? { lastRotateError } : {}),
          });
          // Reports alone raised suspicion: ask the probes for edge-level evidence now.
          if (ev.transition === 'suspected' && ev.hintLevel === 'reports' && w.cfg.probe.enabled) {
            // Stagger like a batch: offsets are CUMULATIVE runs-per-source of the
            // targets scheduled ahead (a two-port dual-stack edge occupies four
            // slots, not one), and the batch total is known up front so the
            // spacing shrinks to fit one interval instead of piling up at the cap.
            const costs: number[] = [];
            for (const p of w.published) {
              const plan = await ctx.runQuery(internal.probes.planFor, {
                target: { kind: 'edge', ref: p.edgeId },
              });
              costs.push(plan.runsPerSource);
            }
            const batchRunsPerSource = costs.reduce((a, b) => a + b, 0);
            let staggerOffset = 0;
            for (const [i, p] of w.published.entries()) {
              if (costs[i] === 0) continue;
              try {
                const r = await ctx.runMutation(internal.probes.requestProbes, {
                  target: { kind: 'edge', ref: p.edgeId },
                  trigger: 'detector',
                  staggerOffset,
                  batchRunsPerSource,
                });
                report.probesRequested += r.runIds.length;
                staggerOffset += r.runsPerSource;
              } catch {
                /* budget/edge state: best effort */
                staggerOffset += costs[i] ?? 0;
              }
            }
          }
        } catch (err) {
          report.errors++;
          console.warn(
            `[relay-detector] ${o.slug}: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
      }
      return report;
    }),
});
