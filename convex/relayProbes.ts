/**
 * Reachability probes, DB half: probe runs (`relayProbeRuns`), the per-edge
 * per-country per-source rollup (`relayEdgeReachability`), the edge's
 * cross-source summary (`relayEdges.reachability`), scheduling (the
 * `relay-probe` cron + manual "probe now"), and the admin reads.
 *
 * A run is started by a mutation that also schedules the "use node" executor
 * (relayProbeOps.execute), so the request and its work are one transaction.
 * Rollup semantics: a reachability row describes the LAST finished run for its
 * (edge, country, source); the edge summary combines the sources per country
 * with the agreement rules in lib/relays/probes/verdict.ts.
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { MutationCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { recordHeartbeat, runWithCronOutcome } from './cronHeartbeat';
import { resolveRelayConfig, resolveRelaySecrets, type RelayConfig } from './lib/relayConfig';
import {
  countryVerdict,
  sourceVerdict,
  type SourceSummary,
  type Verdict,
} from './lib/relays/probes/verdict';
import type { ProbeResult, ProbeSource } from './lib/relays/probes/types';

const MIN = 60_000;
/** Settled probe runs are evidence history, not a ledger: 14 days is plenty for the admin view. */
const PROBE_RUN_RETENTION_MS = 14 * 24 * 60 * 60_000;
const MAX_SWEEP_ROUNDS = 20;
const RUN_TIMEOUT_MS = 10 * MIN;

const probeSource = v.union(
  v.literal('globalping'),
  v.literal('checkhost'),
  v.literal('ripeatlas'),
  v.literal('internal'),
);
const probeTrigger = v.union(
  v.literal('cron'),
  v.literal('manual'),
  v.literal('detector'),
  v.literal('qualification'),
);
const probeResult = v.object({
  country: v.string(),
  asn: v.optional(v.string()),
  network: v.optional(v.string()),
  vantageClass: v.union(v.literal('eyeball'), v.literal('datacenter'), v.literal('unknown')),
  ok: v.boolean(),
  rttMs: v.optional(v.number()),
  error: v.optional(v.string()),
});

export function mapRunAdmin(r: Doc<'relayProbeRuns'>) {
  return {
    id: r._id as string,
    edgeId: r.edgeId as string,
    source: r.source,
    ipVersion: r.ipVersion,
    status: r.status,
    trigger: r.trigger,
    requestedAt: new Date(r.requestedAt).toISOString(),
    finishedAt: r.finishedAt ? new Date(r.finishedAt).toISOString() : null,
    okVantages: r.results.filter((x) => x.ok).length,
    failVantages: r.results.filter((x) => !x.ok).length,
    results: r.results.map((x) => ({
      country: x.country,
      asn: x.asn ?? null,
      network: x.network ?? null,
      vantageClass: x.vantageClass,
      ok: x.ok,
      rttMs: x.rttMs ?? null,
      error: x.error ?? null,
    })),
  };
}

/** Sources enabled by config and usable (a key-requiring source needs its key). */
export function enabledSources(
  cfg: RelayConfig,
  secrets: { globalpingToken: string; ripeAtlasKey: string },
): ProbeSource[] {
  const out: ProbeSource[] = [];
  if (cfg.probe.sources.globalping) out.push('globalping');
  if (cfg.probe.sources.checkhost) out.push('checkhost');
  if (cfg.probe.sources.ripeatlas && secrets.ripeAtlasKey.length > 0) out.push('ripeatlas');
  if (cfg.probe.sources.internal) out.push('internal');
  return out;
}

// --- runs ---------------------------------------------------------------------------------------

async function insertRun(
  ctx: MutationCtx,
  a: {
    edgeId: Id<'relayEdges'>;
    source: ProbeSource;
    target: string;
    ipVersion: 4 | 6;
    trigger: 'cron' | 'manual' | 'detector' | 'qualification';
  },
): Promise<Id<'relayProbeRuns'>> {
  const now = Date.now();
  const runId = await ctx.db.insert('relayProbeRuns', {
    edgeId: a.edgeId,
    source: a.source,
    target: a.target,
    ipVersion: a.ipVersion,
    status: 'requested',
    trigger: a.trigger,
    requestedAt: now,
    results: [],
  });
  await ctx.scheduler.runAfter(0, internal.relayProbeOps.execute, { runId });
  await writeAuditLog(ctx, {
    actorType: 'system',
    action: 'relay.probe.run',
    targetType: 'relay_edge',
    targetId: a.edgeId,
    payload: { edgeId: a.edgeId, source: a.source, trigger: a.trigger },
  });
  return runId;
}

/**
 * Request probes for one edge from every enabled source (v4 always; v6 when the
 * edge has one and IPv6 rendering is not off). Used by the cron, the detector
 * and the admin "Probe now".
 */
export const requestProbes = internalMutation({
  args: {
    edgeId: v.id('relayEdges'),
    trigger: probeTrigger,
    sources: v.optional(v.array(probeSource)),
  },
  handler: async (ctx, { edgeId, trigger, sources }) => {
    const edge = await ctx.db.get(edgeId);
    if (!edge) throw new ConvexError({ code: 'not_found', message: 'Edge not found' });
    if (!edge.addresses.v4 && !edge.addresses.v6) {
      throw new ConvexError({ code: 'relay.no_address', message: 'Edge has no address yet' });
    }
    const cfg = await resolveRelayConfig(ctx.db);
    const secrets = await resolveRelaySecrets(ctx.db);
    const use = sources ?? enabledSources(cfg, secrets);
    const port = edge.listeners[0]?.edgePort ?? 443;
    const runIds: Id<'relayProbeRuns'>[] = [];
    for (const source of use) {
      if (edge.addresses.v4) {
        runIds.push(
          await insertRun(ctx, {
            edgeId,
            source,
            target: `${edge.addresses.v4}:${port}`,
            ipVersion: 4,
            trigger,
          }),
        );
      }
      if (edge.addresses.v6 && cfg.render.ipv6Mode !== 'off') {
        runIds.push(
          await insertRun(ctx, {
            edgeId,
            source,
            target: `[${edge.addresses.v6}]:${port}`,
            ipVersion: 6,
            trigger,
          }),
        );
      }
    }
    return { runIds };
  },
});

export const markRunning = internalMutation({
  args: { runId: v.id('relayProbeRuns'), externalId: v.optional(v.string()) },
  handler: async (ctx, { runId, externalId }) => {
    const run = await ctx.db.get(runId);
    if (!run || run.status !== 'requested') return null;
    await ctx.db.patch(runId, { status: 'running', externalId: externalId?.slice(0, 200) });
    return null;
  },
});

export const failRun = internalMutation({
  args: { runId: v.id('relayProbeRuns'), error: v.string(), timeout: v.optional(v.boolean()) },
  handler: async (ctx, { runId, error, timeout }) => {
    const run = await ctx.db.get(runId);
    if (!run || run.status === 'finished' || run.status === 'failed' || run.status === 'timeout')
      return null;
    const now = Date.now();
    void error; // kept out of the row: failure text is operational, not evidence
    await ctx.db.patch(runId, { status: timeout ? 'timeout' : 'failed', finishedAt: now });
    return null;
  },
});

/** Record results, roll them up per country for this source, and refresh the edge summary. */
export const finishRun = internalMutation({
  args: { runId: v.id('relayProbeRuns'), results: v.array(probeResult) },
  handler: async (ctx, { runId, results }) => {
    const run = await ctx.db.get(runId);
    if (!run || run.status === 'finished') return null;
    const now = Date.now();
    await ctx.db.patch(runId, { status: 'finished', finishedAt: now, results });
    const cfg = await resolveRelayConfig(ctx.db);
    const edge = await ctx.db.get(run.edgeId);
    if (!edge) return null;
    // Per-country rollup for THIS source.
    const byCountry = new Map<string, ProbeResult[]>();
    for (const r of results) byCountry.set(r.country, [...(byCountry.get(r.country) ?? []), r]);
    const existing = await ctx.db
      .query('relayEdgeReachability')
      .withIndex('by_edge_country', (q) => q.eq('edgeId', run.edgeId))
      .collect();
    for (const [country, rs] of byCountry) {
      // The internal probe is one authoritative vantage (FCP's own host); the
      // agreement rule is for third-party vantage sets.
      const summary: SourceSummary =
        run.source === 'internal'
          ? {
              source: 'internal',
              verdict: rs.some((r) => r.ok)
                ? 'reachable'
                : rs.length > 0
                  ? 'unreachable'
                  : 'unknown',
              okVantages: rs.filter((r) => r.ok).length,
              failVantages: rs.filter((r) => !r.ok).length,
              failNetworks: rs.some((r) => !r.ok) ? ['internal'] : [],
            }
          : sourceVerdict(run.source, rs, cfg.probe.agreementVantages);
      // One rollup row per (country, source, address family): a dual-stack edge's
      // v6 result must never overwrite its v4 verdict or vice versa.
      const row = existing.find(
        (x) =>
          x.country === country && x.source === run.source && (x.ipVersion ?? 4) === run.ipVersion,
      );
      const patch = {
        okCount: summary.okVantages,
        failCount: summary.failVantages,
        lastOkAt: summary.okVantages > 0 ? now : row?.lastOkAt,
        lastFailAt: summary.failVantages > 0 ? now : row?.lastFailAt,
        verdict: summary.verdict,
        updatedAt: now,
      };
      if (row) await ctx.db.patch(row._id, patch);
      else
        await ctx.db.insert('relayEdgeReachability', {
          edgeId: run.edgeId,
          country,
          source: run.source,
          ipVersion: run.ipVersion,
          ...patch,
        });
      if (!row || row.verdict !== summary.verdict) {
        await writeAuditLog(ctx, {
          actorType: 'system',
          action: 'relay.probe.verdict',
          targetType: 'relay_edge',
          targetId: run.edgeId,
          payload: { edgeId: run.edgeId, source: run.source, country, verdict: summary.verdict },
        });
      }
    }
    await refreshEdgeSummary(ctx, run.edgeId, now);
    return null;
  },
});

/** Cross-source summary per country onto the edge row (what the detector + admin read). */
async function refreshEdgeSummary(ctx: MutationCtx, edgeId: Id<'relayEdges'>, now: number) {
  const rows = await ctx.db
    .query('relayEdgeReachability')
    .withIndex('by_edge_country', (q) => q.eq('edgeId', edgeId))
    .collect();
  const staleBefore = now - 6 * 60 * MIN;
  const countries = [...new Set(rows.map((r) => r.country))].sort();
  const byCountry = countries.map((country) => {
    const fresh = rows.filter((r) => r.country === country && r.updatedAt >= staleBefore);
    // The country verdict follows the IPv4 path (what every member receives);
    // IPv6 rows summarise separately as `v6Verdict` and only stand in for the
    // verdict when the edge was probed over v6 alone.
    const v4Rows = fresh.filter((r) => (r.ipVersion ?? 4) === 4);
    const v6Rows = fresh.filter((r) => r.ipVersion === 6);
    const primaryRows = v4Rows.length > 0 ? v4Rows : v6Rows;
    const summarise = (subset: typeof fresh): SourceSummary[] =>
      subset.map((r) => ({
        source: r.source,
        verdict: r.verdict as Verdict,
        okVantages: r.okCount,
        failVantages: r.failCount,
        // An `unreachable` source verdict already proved ≥ agreementVantages
        // distinct failing networks; reconstruct that many placeholders.
        failNetworks:
          r.verdict === 'unreachable'
            ? Array.from({ length: Math.max(2, r.failCount) }, (_, i) => `${r.source}:${i}`)
            : r.failCount > 0
              ? [`${r.source}:0`]
              : [],
      }));
    const verdictOf = (perSource: SourceSummary[]): Verdict =>
      country === 'XX' ? internalVerdict(perSource) : countryVerdict(perSource);
    const perSource = summarise(primaryRows);
    const v6 = v4Rows.length > 0 && v6Rows.length > 0 ? verdictOf(summarise(v6Rows)) : undefined;
    return {
      country,
      verdict: verdictOf(perSource),
      ...(v6 ? { v6Verdict: v6 } : {}),
      okVantages: perSource.reduce((a, s) => a + s.okVantages, 0),
      failVantages: perSource.reduce((a, s) => a + s.failVantages, 0),
      lastAt: Math.max(0, ...rows.filter((r) => r.country === country).map((r) => r.updatedAt)),
    };
  });
  await ctx.db.patch(edgeId, { reachability: { byCountry, updatedAt: now }, updatedAt: now });
}

/** The internal probe is a single vantage: its own result IS the verdict. */
function internalVerdict(perSource: SourceSummary[]): Verdict {
  const s = perSource.find((x) => x.source === 'internal');
  if (!s) return 'unknown';
  if (s.okVantages > 0) return 'reachable';
  if (s.failVantages > 0) return 'unreachable';
  return 'unknown';
}

// --- reads -------------------------------------------------------------------------------------

export const runContext = internalQuery({
  args: { runId: v.id('relayProbeRuns') },
  handler: async (ctx, { runId }) => {
    const run = await ctx.db.get(runId);
    if (!run) return null;
    const cfg = await resolveRelayConfig(ctx.db);
    const secrets = await resolveRelaySecrets(ctx.db);
    return { run, cfg, secrets };
  },
});

export const listByEdge = internalQuery({
  args: { edgeId: v.id('relayEdges'), take: v.optional(v.number()) },
  handler: async (ctx, { edgeId, take }) =>
    (
      await ctx.db
        .query('relayProbeRuns')
        .withIndex('by_edge_requested', (q) => q.eq('edgeId', edgeId))
        .order('desc')
        .take(Math.min(take ?? 20, 100))
    ).map(mapRunAdmin),
});

/** Per-edge, per-country verdict matrix for one origin's live edges (admin). */
export const reachabilityForOrigin = internalQuery({
  args: { originId: v.id('relayOrigins') },
  handler: async (ctx, { originId }) => {
    const edges = await ctx.db
      .query('relayEdges')
      .withIndex('by_origin_status', (q) => q.eq('originId', originId))
      .collect();
    const cfg = await resolveRelayConfig(ctx.db);
    return {
      countries: cfg.probe.countries,
      edges: edges
        .filter((e) => e.status !== 'destroyed')
        .map((e) => ({
          edgeId: e._id as string,
          publication: e.publication,
          poolIndex: e.poolIndex ?? null,
          provider: e.provider ?? null,
          byCountry: (e.reachability?.byCountry ?? []).map((c) => ({
            ...c,
            lastAt: new Date(c.lastAt).toISOString(),
          })),
          updatedAt: e.reachability ? new Date(e.reachability.updatedAt).toISOString() : null,
        })),
    };
  },
});

// --- scheduling ----------------------------------------------------------------------------------

/** Published edges due for a probe round, with the hour's spend so the cron can budget. */
export const due = internalQuery({
  args: { now: v.number() },
  handler: async (ctx, { now }) => {
    const cfg = await resolveRelayConfig(ctx.db);
    const secrets = await resolveRelaySecrets(ctx.db);
    const origins = await ctx.db
      .query('relayOrigins')
      .withIndex('by_enabled', (q) => q.eq('enabled', true))
      .collect();
    const dueEdges: Array<{ edgeId: Id<'relayEdges'>; suspected: boolean }> = [];
    let spentThisHour = 0;
    const hourStart = now - 60 * MIN;
    for (const origin of origins) {
      const suspected = origin.suspicion?.state === 'suspected';
      const interval =
        (suspected ? cfg.probe.suspectedIntervalMinutes : cfg.probe.intervalMinutes) * MIN;
      for (const edgeId of origin.publishedEdgeIds) {
        if (!edgeId) continue;
        const edge = await ctx.db.get(edgeId);
        if (!edge || edge.status !== 'active' || !edge.addresses.v4) continue;
        const recent = await ctx.db
          .query('relayProbeRuns')
          .withIndex('by_edge_requested', (q) =>
            q.eq('edgeId', edgeId).gte('requestedAt', hourStart),
          )
          .collect();
        spentThisHour += recent.length;
        const last = recent.reduce((m, r) => Math.max(m, r.requestedAt), 0);
        if (last === 0 || now - last >= interval) dueEdges.push({ edgeId, suspected });
      }
    }
    // Suspected origins first so a tight budget goes where it matters.
    dueEdges.sort((a, b) => Number(b.suspected) - Number(a.suspected));
    return {
      enabled: cfg.probe.enabled,
      sources: enabledSources(cfg, secrets),
      hourlyBudget: cfg.probe.hourlyBudget,
      spentThisHour,
      dueEdges,
    };
  },
});

/** Runs stuck in requested/running past the executor's ceiling → timeout. */
export const sweepStuck = internalMutation({
  args: { now: v.number() },
  handler: async (ctx, { now }) => {
    let n = 0;
    for (const status of ['requested', 'running'] as const) {
      const rows = await ctx.db
        .query('relayProbeRuns')
        .withIndex('by_status', (q) => q.eq('status', status))
        .take(200);
      for (const r of rows) {
        if (r.requestedAt + RUN_TIMEOUT_MS <= now) {
          await ctx.db.patch(r._id, { status: 'timeout', finishedAt: now });
          n++;
        }
      }
    }
    return { timedOut: n };
  },
});

/** Settled runs (finished / failed / timeout) older than the retention window are deleted in bounded pages. */
export const sweepFinished = internalMutation({
  args: {
    now: v.optional(v.number()),
    limit: v.optional(v.number()),
    rounds: v.optional(v.number()),
  },
  handler: async (ctx, { now: nowArg, limit, rounds }) => {
    const now = nowArg ?? Date.now();
    if ((rounds ?? 0) === 0) await recordHeartbeat(ctx, 'retention-relay-probes');
    const cutoff = now - PROBE_RUN_RETENTION_MS;
    const page = limit ?? 200;
    let removed = 0;
    for (const status of ['finished', 'failed', 'timeout'] as const) {
      const rows = await ctx.db
        .query('relayProbeRuns')
        .withIndex('by_status_requested', (q) => q.eq('status', status).lt('requestedAt', cutoff))
        .take(page);
      for (const r of rows) await ctx.db.delete(r._id);
      removed += rows.length;
      if (rows.length === page) {
        const n = rounds ?? 0;
        if (n < MAX_SWEEP_ROUNDS)
          await ctx.scheduler.runAfter(0, internal.relayProbes.sweepFinished, {
            now,
            limit: page,
            rounds: n + 1,
          });
        break;
      }
    }
    return { removed };
  },
});

/** The `relay-probe` cron tick: budget-aware round for every due published edge. */
export const run = internalAction({
  args: {},
  handler: async (ctx): Promise<{ requested: number; skipped: number; timedOut: number }> =>
    runWithCronOutcome(ctx, 'relay-probe', async () => {
      const now = Date.now();
      const { timedOut } = await ctx.runMutation(internal.relayProbes.sweepStuck, { now });
      const plan = await ctx.runQuery(internal.relayProbes.due, { now });
      if (!plan.enabled || plan.sources.length === 0) return { requested: 0, skipped: 0, timedOut };
      let spent = plan.spentThisHour;
      let requested = 0;
      let skipped = 0;
      for (const d of plan.dueEdges) {
        // Each source is one run (two with IPv6); reserve the worst case.
        const cost = plan.sources.length * 2;
        if (spent + cost > plan.hourlyBudget) {
          skipped++;
          continue;
        }
        const res = await ctx.runMutation(internal.relayProbes.requestProbes, {
          edgeId: d.edgeId,
          trigger: 'cron',
          sources: plan.sources,
        });
        spent += res.runIds.length;
        requested += res.runIds.length;
      }
      return { requested, skipped, timedOut };
    }),
});
