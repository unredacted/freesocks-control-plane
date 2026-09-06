/**
 * Block detector (`relay-block-detector` cron): per enabled origin, gather the
 * detector window (attributed member reports, node load, probe verdicts), score
 * it (lib/relays/scoring.ts), persist the suspicion state + a baseline sample,
 * audit transitions, ask for detector-triggered probes when reports alone
 * raise suspicion, and — only with edge-level evidence, every gate open and the
 * operator's opt-in — start a burn rotation of the suspected edge.
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { runWithCronOutcome } from './cronHeartbeat';
import { resolveRelayConfig, relayMs } from './lib/relayConfig';
import { todayKey } from './relayOrigins';
import {
  autoRotateDecision,
  evaluate,
  type BaselineSample,
  type EdgeProbeState,
  type Evaluation,
  type WindowReports,
} from './lib/relays/scoring';
import type { Verdict } from './lib/relays/probes/verdict';

const MIN = 60_000;
const DAY = 24 * 60 * MIN;
const SAMPLE_RETENTION_MS = 7 * DAY;
const LOAD_STALE_MS = 20 * MIN;

type Origin = Doc<'relayOrigins'>;

/** Everything one evaluation needs, read in one query. */
export const originWindow = internalQuery({
  args: { originId: v.id('relayOrigins'), now: v.number() },
  handler: async (ctx, { originId, now }) => {
    const origin = await ctx.db.get(originId);
    if (!origin) return null;
    const cfg = await resolveRelayConfig(ctx.db);
    const since = now - relayMs.detectWindow(cfg);
    const reports = await ctx.db
      .query('issueReports')
      .withIndex('by_relay', (q) => q.eq('relaySlug', origin.slug).gte('_creationTime', since))
      .collect();
    const window: WindowReports = { reports: 0, distinctReporters: 0, countries: {}, byEdge: {} };
    for (const r of reports) {
      if (r.kind !== 'report') continue;
      window.reports += 1;
      window.distinctReporters += r.detectorWeight ?? 1;
      const c = r.country ?? r.detectedCountry;
      if (c) window.countries[c] = (window.countries[c] ?? 0) + 1;
      if (r.relayEdgeId) {
        const e = (window.byEdge[r.relayEdgeId] ??= { count: 0, countries: {} });
        e.count += 1;
        if (c) e.countries[c] = (e.countries[c] ?? 0) + 1;
      }
    }
    const samples = await ctx.db
      .query('relayOriginSamples')
      .withIndex('by_origin_at', (q) =>
        q.eq('originId', originId).gte('at', now - SAMPLE_RETENTION_MS),
      )
      .collect();
    const baseline: BaselineSample[] = samples.map((s) => ({
      reports: s.reports,
      distinctReporters: s.distinctReporters,
      usersOnline: s.usersOnline,
    }));
    const inv = await ctx.db
      .query('backendNodeInventory')
      .withIndex('by_server_name', (q) =>
        q.eq('backendServerId', origin.backendServerId).eq('name', origin.nodeHostname),
      )
      .unique();
    const usersOnline = inv ? inv.usersOnline : null;
    const loadStale = inv ? now - inv.lastStatsAt > LOAD_STALE_MS : true;
    const edges: EdgeProbeState[] = [];
    const published: Array<{ edgeId: string; poolIndex: number }> = [];
    for (let i = 0; i < origin.publishedEdgeIds.length; i++) {
      const id = origin.publishedEdgeIds[i];
      if (!id) continue;
      const e = await ctx.db.get(id);
      if (!e) continue;
      published.push({ edgeId: e._id, poolIndex: e.poolIndex ?? i });
      const byCountry = (e.reachability?.byCountry ?? []).map((c) => ({
        country: c.country,
        verdict: c.verdict as Verdict,
      }));
      edges.push({
        edgeId: e._id,
        byCountry: byCountry.filter((c) => c.country !== 'XX'),
        internalVerdict: byCountry.find((c) => c.country === 'XX')?.verdict ?? 'unknown',
        providerHealth: e.health,
        probeAgeMs: e.reachability ? now - e.reachability.updatedAt : null,
      });
    }
    const rotation = origin.activeRotationId ? await ctx.db.get(origin.activeRotationId) : null;
    const rotationActive =
      !!rotation &&
      !['done', 'failed', 'rolled_back', 'quarantined', 'cancelled'].includes(rotation.phase);
    return {
      origin,
      cfg,
      window,
      baseline,
      usersOnline,
      loadStale,
      edges,
      published,
      rotationActive,
    };
  },
});

/** Persist one evaluation: suspicion state, a baseline sample, transition audits, sample retention. */
export const recordEvaluation = internalMutation({
  args: {
    originId: v.id('relayOrigins'),
    now: v.number(),
    evaluation: v.any(),
    usersOnline: v.union(v.number(), v.null()),
    veto: v.union(v.string(), v.null()),
    lastRotateError: v.optional(v.union(v.string(), v.null())),
  },
  handler: async (ctx, a) => {
    const origin = await ctx.db.get(a.originId);
    if (!origin) return null;
    const ev = a.evaluation as Evaluation;
    const prev = origin.suspicion;
    await ctx.db.patch(a.originId, {
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
          edgeId: e.edgeId as Id<'relayEdges'>,
          source: e.source,
          countries: e.countries.slice(0, 10),
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
      },
      updatedAt: a.now,
    });
    await ctx.db.insert('relayOriginSamples', {
      originId: a.originId,
      at: a.now,
      reports: ev.countries.reduce((acc, c) => acc + c.count, 0),
      distinctReporters: 0,
      usersOnline: a.usersOnline,
    });
    // Retention: drop the oldest samples past 7 days (bounded per tick).
    const old = await ctx.db
      .query('relayOriginSamples')
      .withIndex('by_origin_at', (q) =>
        q.eq('originId', a.originId).lt('at', a.now - SAMPLE_RETENTION_MS),
      )
      .take(50);
    for (const s of old) await ctx.db.delete(s._id);
    if (ev.transition === 'suspected') {
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'relay.block_suspected',
        targetType: 'relay_origin',
        targetId: a.originId,
        payload: {
          originSlug: origin.slug,
          hintLevel: ev.hintLevel,
          score: round3(ev.score),
          reporters: Math.round(ev.countries.reduce((acc, c) => acc + c.count, 0)),
          topCountry: ev.countries[0]?.code ?? null,
          scope: ev.scope,
          autoRotate: origin.autoRotate,
        },
      });
    } else if (ev.transition === 'cleared') {
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'relay.block_cleared',
        targetType: 'relay_origin',
        targetId: a.originId,
        payload: { originSlug: origin.slug, reason: 'score_below_threshold' },
      });
    }
    return null;
  },
});

/** The real sample counts come from the window (the evaluation only carries country totals). */
export const recordSampleCounts = internalMutation({
  args: {
    originId: v.id('relayOrigins'),
    at: v.number(),
    reports: v.number(),
    distinctReporters: v.number(),
  },
  handler: async (ctx, a) => {
    const row = await ctx.db
      .query('relayOriginSamples')
      .withIndex('by_origin_at', (q) => q.eq('originId', a.originId).eq('at', a.at))
      .unique();
    if (row)
      await ctx.db.patch(row._id, { reports: a.reports, distinctReporters: a.distinctReporters });
    return null;
  },
});

function round3(x: number): number {
  return Math.round(x * 1000) / 1000;
}

function hintText(ev: Evaluation, veto: string | null): string | undefined {
  if (ev.state !== 'suspected') return undefined;
  const where = ev.countries[0] ? ` (mostly ${ev.countries[0].code})` : '';
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
}

export const run = internalAction({
  args: {},
  handler: async (ctx): Promise<DetectorReport> =>
    runWithCronOutcome(ctx, 'relay-block-detector', async () => {
      const report: DetectorReport = {
        evaluated: 0,
        suspected: 0,
        rotated: 0,
        probesRequested: 0,
        errors: 0,
      };
      const now = Date.now();
      await ctx.runMutation(internal.relayDetector.sweepMarks, { now });
      const origins: Origin[] = await ctx.runQuery(internal.relayOrigins.listEnabled, {});
      for (const o of origins) {
        if (o.deleting) continue;
        try {
          const w = await ctx.runQuery(internal.relayDetector.originWindow, {
            originId: o._id,
            now,
          });
          if (!w) continue;
          const ev = evaluate({
            now,
            window: w.window,
            baseline: w.baseline,
            usersOnline: w.usersOnline,
            loadStale: w.loadStale,
            edges: w.edges,
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
          if (ev.state === 'suspected') report.suspected++;
          const decision = autoRotateDecision({
            evaluation: ev,
            cfg: w.cfg,
            origin: {
              autoRotate: w.origin.autoRotate,
              quarantined: !!w.origin.quarantine,
              rotationActive: w.rotationActive,
              cooldownUntil: w.origin.cooldownUntil ?? null,
              rotationsToday:
                w.origin.rotationsDayKey === todayKey(now) ? w.origin.rotationsToday : 0,
              maxRotationsPerDay: w.origin.maxRotationsPerDay,
              hostManaged: w.origin.hostManaged,
            },
            published: w.published,
            now,
          });
          const veto = 'veto' in decision ? decision.veto : null;
          let lastRotateError: string | null | undefined = undefined;
          if (!('veto' in decision)) {
            try {
              await ctx.runMutation(internal.relayRotations.start, {
                originId: o._id,
                kind: 'replace',
                trigger: 'detector',
                burn: true,
                targetEdgeId: decision.edgeId as Id<'relayEdges'>,
                reason: `detector:${decision.source}`,
              });
              report.rotated++;
              lastRotateError = null;
            } catch (err) {
              lastRotateError =
                err instanceof ConvexError
                  ? String((err.data as { code?: string }).code ?? 'error')
                  : 'error';
            }
          }
          await ctx.runMutation(internal.relayDetector.recordEvaluation, {
            originId: o._id,
            now,
            evaluation: ev,
            usersOnline: w.usersOnline,
            veto,
            ...(lastRotateError !== undefined ? { lastRotateError } : {}),
          });
          await ctx.runMutation(internal.relayDetector.recordSampleCounts, {
            originId: o._id,
            at: now,
            reports: w.window.reports,
            distinctReporters: w.window.distinctReporters,
          });
          // Reports alone raised suspicion: ask the probes for edge-level evidence now.
          if (ev.transition === 'suspected' && ev.hintLevel === 'reports' && w.cfg.probe.enabled) {
            for (const p of w.published) {
              try {
                const r = await ctx.runMutation(internal.relayProbes.requestProbes, {
                  edgeId: p.edgeId as Id<'relayEdges'>,
                  trigger: 'detector',
                });
                report.probesRequested += r.runIds.length;
              } catch {
                /* budget/edge state: best effort */
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
