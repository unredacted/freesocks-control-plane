/**
 * Reachability probes, DB half: probe runs (`probeRuns`), the per-target
 * per-country per-source rollup (`probeReachability`), each target's
 * cross-source summary (`edges.reachability`, `relays.reachability`,
 * `probeTargets.reachability`), scheduling (the `edge-probe` cron + manual
 * "probe now"), and the admin reads (Telemetry → Probes).
 *
 * A TARGET is one of: an edge (its public address, per family), a relay node
 * (its origin address, when the relay opts in with `probeNode`), or an
 * operator-entered custom host:port (`probeTargets`). Only EDGE evidence feeds
 * the block detector; the other kinds are operator evidence.
 *
 * A run is started by a mutation that also schedules the "use node" executor
 * (probeOps.execute), so the request and its work are one transaction. Rollup
 * semantics: a reachability row describes the LAST finished run for its
 * (target, country, source, address family); the summary combines the sources
 * per country with the agreement rules in lib/edges/probes/verdict.ts.
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { MutationCtx, QueryCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { recordHeartbeat, runWithCronOutcome } from './cronHeartbeat';
import { resolveEdgeConfig, resolveEdgeSecrets, type EdgeConfig } from './lib/edgeConfig';
import { addressFamily, bracketIfV6 } from './lib/edges/ip';
import {
  countryVerdict,
  sourceVerdict,
  type SourceSummary,
  type Verdict,
} from './lib/edges/probes/verdict';
import type { ProbeResult, ProbeSource } from './lib/edges/probes/types';

const MIN = 60_000;
/** Settled probe runs are evidence history, not a ledger: 14 days is plenty for the admin view. */
const PROBE_RUN_RETENTION_MS = 14 * 24 * 60 * 60_000;
const MAX_SWEEP_ROUNDS = 20;
const RUN_TIMEOUT_MS = 10 * MIN;

export const PROBE_TARGET_KINDS = ['edge', 'relay', 'custom'] as const;
export type ProbeTargetKind = (typeof PROBE_TARGET_KINDS)[number];
export interface ProbeTargetRef {
  kind: ProbeTargetKind;
  ref: string;
}

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
const probeTargetRef = v.object({
  kind: v.union(v.literal('edge'), v.literal('relay'), v.literal('custom')),
  ref: v.string(),
});
const probeResult = v.object({
  country: v.string(),
  asn: v.optional(v.string()),
  network: v.optional(v.string()),
  vantageClass: v.union(v.literal('eyeball'), v.literal('datacenter'), v.literal('unknown')),
  ok: v.boolean(),
  rttMs: v.optional(v.number()),
  error: v.optional(v.string()),
});

/** `<kind>:<ref>`: the stable string form used by the routes, the audit log and the client. */
export function targetKeyOf(t: ProbeTargetRef): string {
  return `${t.kind}:${t.ref}`;
}
export function parseTargetKey(key: string): ProbeTargetRef | null {
  const i = key.indexOf(':');
  if (i < 0) return null;
  const kind = key.slice(0, i);
  const ref = key.slice(i + 1);
  if (!(PROBE_TARGET_KINDS as readonly string[]).includes(kind) || !ref) return null;
  return { kind: kind as ProbeTargetKind, ref };
}

export function mapRunAdmin(r: Doc<'probeRuns'>) {
  return {
    id: r._id as string,
    target: { kind: r.targetKind, ref: r.targetRef, key: `${r.targetKind}:${r.targetRef}` },
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

type Summary = NonNullable<Doc<'edges'>['reachability']>;

export function mapSummaryAdmin(s: Summary | undefined) {
  return {
    byCountry: (s?.byCountry ?? []).map((c) => ({
      ...c,
      v6Verdict: c.v6Verdict ?? undefined,
      lastAt: new Date(c.lastAt).toISOString(),
    })),
    updatedAt: s ? new Date(s.updatedAt).toISOString() : null,
  };
}

/** Sources enabled by config and usable (a key-requiring source needs its key). */
export function enabledSources(
  cfg: EdgeConfig,
  secrets: { globalpingToken: string; ripeAtlasKey: string },
): ProbeSource[] {
  const out: ProbeSource[] = [];
  if (cfg.probe.sources.globalping) out.push('globalping');
  if (cfg.probe.sources.checkhost) out.push('checkhost');
  if (cfg.probe.sources.ripeatlas && secrets.ripeAtlasKey.length > 0) out.push('ripeatlas');
  if (cfg.probe.sources.internal) out.push('internal');
  return out;
}

// --- targets -----------------------------------------------------------------------------------

interface ResolvedTarget {
  label: string;
  /** Address per family; a hostname counts as the v4 path (the resolver decides). */
  addresses: { v4?: string; v6?: string };
  port: number;
}

/** Resolve what a target ref points at right now, or null when it is gone. */
async function resolveTarget(
  ctx: { db: QueryCtx['db'] },
  t: ProbeTargetRef,
): Promise<ResolvedTarget | null> {
  if (t.kind === 'edge') {
    const edge = await ctx.db.get(t.ref as Id<'edges'>);
    if (!edge) return null;
    const relay = await ctx.db.get(edge.relayId);
    return {
      label: `${relay?.slug ?? 'relay'} edge${edge.poolIndex !== undefined ? ` #${edge.poolIndex}` : ''}${edge.provider ? ` (${edge.provider})` : ''}`,
      addresses: { v4: edge.addresses.v4, v6: edge.addresses.v6 },
      port: edge.listeners[0]?.edgePort ?? 443,
    };
  }
  if (t.kind === 'relay') {
    const relay = await ctx.db.get(t.ref as Id<'relays'>);
    if (!relay) return null;
    const slots = await ctx.db
      .query('relaySlots')
      .withIndex('by_relay', (q) => q.eq('relayId', relay._id))
      .collect();
    const deployed = slots.filter((s) => s.deployed && !s.retired);
    const port = deployed.sort((a, b) => a.slotKey.localeCompare(b.slotKey))[0]?.originPort ?? 443;
    return {
      label: `${relay.slug} node`,
      addresses: splitByFamily(relay.originAddress),
      port,
    };
  }
  const row = await ctx.db.get(t.ref as Id<'probeTargets'>);
  if (!row) return null;
  return { label: row.label, addresses: splitByFamily(row.address), port: row.port };
}

function splitByFamily(address: string): { v4?: string; v6?: string } {
  return addressFamily(address) === 'v6' ? { v6: address } : { v4: address };
}

// --- runs ---------------------------------------------------------------------------------------

async function insertRun(
  ctx: MutationCtx,
  a: {
    target: ProbeTargetRef;
    source: ProbeSource;
    address: string;
    port: number;
    ipVersion: 4 | 6;
    trigger: 'cron' | 'manual' | 'detector' | 'qualification';
  },
): Promise<Id<'probeRuns'>> {
  const now = Date.now();
  const runId = await ctx.db.insert('probeRuns', {
    targetKind: a.target.kind,
    targetRef: a.target.ref,
    source: a.source,
    target: `${bracketIfV6(a.address)}:${a.port}`,
    ipVersion: a.ipVersion,
    status: 'requested',
    trigger: a.trigger,
    requestedAt: now,
    results: [],
  });
  await ctx.scheduler.runAfter(0, internal.probeOps.execute, { runId });
  await writeAuditLog(ctx, {
    actorType: 'system',
    action: 'probe.run',
    targetType: 'probe_target',
    targetId: targetKeyOf(a.target),
    payload: { targetKey: targetKeyOf(a.target), source: a.source, trigger: a.trigger },
  });
  return runId;
}

/**
 * Start one probe round for one target from every enabled source (v4 always;
 * v6 when the target has one and IPv6 rendering is not off).
 */
export async function requestProbesFor(
  ctx: MutationCtx,
  target: ProbeTargetRef,
  trigger: 'cron' | 'manual' | 'detector' | 'qualification',
  sources?: ProbeSource[],
): Promise<Id<'probeRuns'>[]> {
  const resolved = await resolveTarget(ctx, target);
  if (!resolved) throw new ConvexError({ code: 'not_found', message: 'Probe target not found' });
  if (!resolved.addresses.v4 && !resolved.addresses.v6) {
    throw new ConvexError({ code: 'edge.no_address', message: 'The target has no address yet' });
  }
  const cfg = await resolveEdgeConfig(ctx.db);
  const secrets = await resolveEdgeSecrets(ctx.db);
  const use = sources ?? enabledSources(cfg, secrets);
  const runIds: Id<'probeRuns'>[] = [];
  for (const source of use) {
    if (resolved.addresses.v4) {
      runIds.push(
        await insertRun(ctx, {
          target,
          source,
          address: resolved.addresses.v4,
          port: resolved.port,
          ipVersion: 4,
          trigger,
        }),
      );
    }
    if (resolved.addresses.v6 && (cfg.render.ipv6Mode !== 'off' || !resolved.addresses.v4)) {
      runIds.push(
        await insertRun(ctx, {
          target,
          source,
          address: resolved.addresses.v6,
          port: resolved.port,
          ipVersion: 6,
          trigger,
        }),
      );
    }
  }
  return runIds;
}

/** One target (the cron, the detector, the per-edge admin button). */
export const requestProbes = internalMutation({
  args: {
    target: probeTargetRef,
    trigger: probeTrigger,
    sources: v.optional(v.array(probeSource)),
  },
  handler: async (ctx, { target, trigger, sources }) => ({
    runIds: await requestProbesFor(ctx, target, trigger, sources),
  }),
});

/**
 * Several targets at once (Telemetry → Probes "Probe now"). Audited once as the
 * operator's request; every run still writes its own `edge.probe.run` row.
 */
export const requestMany = internalMutation({
  args: {
    targets: v.array(probeTargetRef),
    sources: v.optional(v.array(probeSource)),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { targets, sources, actorAdminId }) => {
    if (targets.length === 0 || targets.length > 50)
      throw new ConvexError({ code: 'validation', message: 'targets must hold 1..50 entries' });
    const runIds: Id<'probeRuns'>[] = [];
    const skipped: string[] = [];
    for (const t of targets) {
      try {
        runIds.push(...(await requestProbesFor(ctx, t, 'manual', sources)));
      } catch (err) {
        skipped.push(
          `${targetKeyOf(t)}: ${err instanceof ConvexError ? String((err.data as { code?: string }).code ?? 'error') : 'error'}`,
        );
      }
    }
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'probe.requested',
      targetType: 'probe_target',
      payload: {
        targets: targets.length,
        runs: runIds.length,
        sources: sources ?? null,
      },
    });
    return { runIds, skipped };
  },
});

export const markRunning = internalMutation({
  args: { runId: v.id('probeRuns'), externalId: v.optional(v.string()) },
  handler: async (ctx, { runId, externalId }) => {
    const run = await ctx.db.get(runId);
    if (!run || run.status !== 'requested') return null;
    await ctx.db.patch(runId, { status: 'running', externalId: externalId?.slice(0, 200) });
    return null;
  },
});

export const failRun = internalMutation({
  args: { runId: v.id('probeRuns'), error: v.string(), timeout: v.optional(v.boolean()) },
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

/** Record results, roll them up per country for this source, and refresh the target summary. */
export const finishRun = internalMutation({
  args: { runId: v.id('probeRuns'), results: v.array(probeResult) },
  handler: async (ctx, { runId, results }) => {
    const run = await ctx.db.get(runId);
    if (!run || run.status === 'finished') return null;
    const now = Date.now();
    await ctx.db.patch(runId, { status: 'finished', finishedAt: now, results });
    const cfg = await resolveEdgeConfig(ctx.db);
    const target: ProbeTargetRef = { kind: run.targetKind, ref: run.targetRef };
    // Per-country rollup for THIS source.
    const byCountry = new Map<string, ProbeResult[]>();
    for (const r of results) byCountry.set(r.country, [...(byCountry.get(r.country) ?? []), r]);
    const existing = await ctx.db
      .query('probeReachability')
      .withIndex('by_target_country', (q) =>
        q.eq('targetKind', run.targetKind).eq('targetRef', run.targetRef),
      )
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
      // One rollup row per (country, source, address family): a dual-stack
      // target's v6 result must never overwrite its v4 verdict or vice versa.
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
        await ctx.db.insert('probeReachability', {
          targetKind: run.targetKind,
          targetRef: run.targetRef,
          country,
          source: run.source,
          ipVersion: run.ipVersion,
          ...patch,
        });
      if (!row || row.verdict !== summary.verdict) {
        await writeAuditLog(ctx, {
          actorType: 'system',
          action: 'probe.verdict',
          targetType: 'probe_target',
          targetId: targetKeyOf(target),
          payload: {
            targetKey: targetKeyOf(target),
            source: run.source,
            country,
            ipVersion: run.ipVersion,
            verdict: summary.verdict,
          },
        });
      }
    }
    await refreshTargetSummary(ctx, target, now);
    return null;
  },
});

/** Cross-source summary per country onto the target's own row (what the detector + admin read). */
async function refreshTargetSummary(ctx: MutationCtx, target: ProbeTargetRef, now: number) {
  const rows = await ctx.db
    .query('probeReachability')
    .withIndex('by_target_country', (q) =>
      q.eq('targetKind', target.kind).eq('targetRef', target.ref),
    )
    .collect();
  const staleBefore = now - 6 * 60 * MIN;
  const countries = [...new Set(rows.map((r) => r.country))].sort();
  const byCountry = countries.map((country) => {
    const fresh = rows.filter((r) => r.country === country && r.updatedAt >= staleBefore);
    // The country verdict follows the IPv4 path (what every member receives);
    // IPv6 rows summarise separately as `v6Verdict` and only stand in for the
    // verdict when the target was probed over v6 alone.
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
  const reachability = { byCountry, updatedAt: now };
  if (target.kind === 'edge') {
    if (await ctx.db.get(target.ref as Id<'edges'>))
      await ctx.db.patch(target.ref as Id<'edges'>, { reachability, updatedAt: now });
  } else if (target.kind === 'relay') {
    if (await ctx.db.get(target.ref as Id<'relays'>))
      await ctx.db.patch(target.ref as Id<'relays'>, { reachability, updatedAt: now });
  } else if (await ctx.db.get(target.ref as Id<'probeTargets'>)) {
    await ctx.db.patch(target.ref as Id<'probeTargets'>, { reachability, updatedAt: now });
  }
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
  args: { runId: v.id('probeRuns') },
  handler: async (ctx, { runId }) => {
    const run = await ctx.db.get(runId);
    if (!run) return null;
    const cfg = await resolveEdgeConfig(ctx.db);
    const secrets = await resolveEdgeSecrets(ctx.db);
    return { run, cfg, secrets };
  },
});

/** Run history of one target, newest first. */
export const listRuns = internalQuery({
  args: { target: probeTargetRef, take: v.optional(v.number()) },
  handler: async (ctx, { target, take }) =>
    (
      await ctx.db
        .query('probeRuns')
        .withIndex('by_target_requested', (q) =>
          q.eq('targetKind', target.kind).eq('targetRef', target.ref),
        )
        .order('desc')
        .take(Math.min(take ?? 20, 100))
    ).map(mapRunAdmin),
});

/**
 * The reachability matrix over every probe target: live edges of every relay,
 * relay nodes that opted in (or were ever probed), and custom targets. Small by
 * construction (operator-scale tables).
 */
export const matrix = internalQuery({
  args: {},
  handler: async (ctx) => {
    const cfg = await resolveEdgeConfig(ctx.db);
    const relays = (await ctx.db.query('relays').collect()).sort((a, b) =>
      a.slug.localeCompare(b.slug),
    );
    const targets = [];
    for (const relay of relays) {
      if (relay.probeNode || relay.reachability) {
        targets.push({
          key: `relay:${relay._id}`,
          kind: 'relay' as const,
          ref: relay._id as string,
          label: `${relay.slug} node`,
          detail: relay.probeNode ? 'scheduled' : 'manual only',
          enabled: relay.probeNode ?? false,
          reachability: mapSummaryAdmin(relay.reachability),
        });
      }
      const edges = await ctx.db
        .query('edges')
        .withIndex('by_relay_status', (q) => q.eq('relayId', relay._id))
        .collect();
      for (const e of edges.filter((x) => x.status !== 'destroyed')) {
        targets.push({
          key: `edge:${e._id}`,
          kind: 'edge' as const,
          ref: e._id as string,
          label: `${relay.slug} edge${e.poolIndex !== undefined ? ` #${e.poolIndex}` : ''}`,
          detail: `${e.publication} · ${e.provider ?? 'adopted'}`,
          enabled: e.publication === 'published' && e.status === 'active',
          reachability: mapSummaryAdmin(e.reachability),
        });
      }
    }
    for (const t of await ctx.db.query('probeTargets').collect()) {
      targets.push({
        key: `custom:${t._id}`,
        kind: 'custom' as const,
        ref: t._id as string,
        label: t.label,
        detail: `${bracketIfV6(t.address)}:${t.port}`,
        enabled: t.enabled,
        reachability: mapSummaryAdmin(t.reachability),
      });
    }
    return { countries: cfg.probe.countries, targets };
  },
});

/**
 * Time-bucketed probe outcomes for the Telemetry → Probes chart: per bucket
 * (hourly on short ranges, daily otherwise) the failing and succeeding vantage
 * counts, split per country, plus per-country totals. Reads finished runs by
 * (status, requestedAt): bounded by the 14-day retention and the span clamp.
 */
export const summary = internalQuery({
  args: {
    windowMs: v.optional(v.number()),
    sinceMs: v.optional(v.number()),
    untilMs: v.optional(v.number()),
  },
  handler: async (ctx, a) => {
    const DAY = 24 * 60 * MIN;
    const now = Date.now();
    const until = Math.min(a.untilMs ?? now, now);
    const rawSince = a.sinceMs ?? until - Math.min(Math.max(a.windowMs ?? 7 * DAY, MIN), 366 * DAY);
    const since = Math.max(rawSince, until - 366 * DAY);
    const span = Math.max(until - since, MIN);
    const bucketMs = span <= 3 * DAY ? 60 * MIN : DAY;
    const n = Math.ceil(span / bucketMs);
    const buckets = Array.from({ length: n }, (_, i) => ({
      start: since + i * bucketMs,
      ok: 0,
      fail: 0,
      runs: 0,
      byCountry: {} as Record<string, { ok: number; fail: number }>,
    }));
    const rows = await ctx.db
      .query('probeRuns')
      .withIndex('by_status_requested', (q) =>
        q.eq('status', 'finished').gte('requestedAt', since).lt('requestedAt', until),
      )
      .take(5000);
    const totals = { runs: 0, ok: 0, fail: 0 };
    const byCountry: Record<string, { ok: number; fail: number }> = {};
    const bySource: Record<string, { runs: number; ok: number; fail: number }> = {};
    for (const r of rows) {
      const b = buckets[Math.floor((r.requestedAt - since) / bucketMs)];
      if (!b) continue;
      b.runs++;
      totals.runs++;
      const src = (bySource[r.source] ??= { runs: 0, ok: 0, fail: 0 });
      src.runs++;
      for (const x of r.results) {
        const k = x.ok ? 'ok' : 'fail';
        b[k]++;
        totals[k]++;
        src[k]++;
        (b.byCountry[x.country] ??= { ok: 0, fail: 0 })[k]++;
        (byCountry[x.country] ??= { ok: 0, fail: 0 })[k]++;
      }
    }
    return {
      sinceMs: since,
      untilMs: until,
      bucketMs,
      buckets,
      totals,
      byCountry: Object.entries(byCountry)
        .map(([country, c]) => ({ country, ...c }))
        .sort((x, y) => x.country.localeCompare(y.country)),
      bySource: Object.entries(bySource)
        .map(([source, c]) => ({ source, ...c }))
        .sort((x, y) => x.source.localeCompare(y.source)),
      truncated: rows.length >= 5000,
    };
  },
});

/** Recent probe-related audit rows (the Telemetry → Probes feed), newest first. */
export const auditFeed = internalQuery({
  args: { take: v.optional(v.number()) },
  handler: async (ctx, { take }) => {
    const n = Math.min(take ?? 50, 200);
    const actions = [
      'probe.requested',
      'probe.run',
      'probe.verdict',
      'probe.target.create',
      'probe.target.update',
      'probe.target.delete',
      'admin.edge.probe.change',
    ];
    const rows = [];
    for (const action of actions) {
      rows.push(
        ...(await ctx.db
          .query('auditLog')
          .withIndex('by_action', (q) => q.eq('action', action))
          .order('desc')
          .take(n)),
      );
    }
    rows.sort((a, b) => b._creationTime - a._creationTime);
    return rows.slice(0, n).map((r) => ({
      id: r._id as string,
      actorType: r.actorType,
      actorId: r.actorId ?? null,
      action: r.action,
      targetType: r.targetType ?? null,
      targetId: r.targetId ?? null,
      payload: r.payload ?? null,
      requestId: r.requestId ?? null,
      createdAt: new Date(r._creationTime).toISOString(),
    }));
  },
});

// --- scheduling ----------------------------------------------------------------------------------

/**
 * Targets due for a probe round, with the hour's spend so the cron can budget:
 * published edges of enabled relays (suspected relays first), relay nodes that
 * opted in, and enabled custom targets.
 */
export const due = internalQuery({
  args: { now: v.number() },
  handler: async (ctx, { now }) => {
    const cfg = await resolveEdgeConfig(ctx.db);
    const secrets = await resolveEdgeSecrets(ctx.db);
    const relays = await ctx.db
      .query('relays')
      .withIndex('by_enabled', (q) => q.eq('enabled', true))
      .collect();
    const dueTargets: Array<{ target: ProbeTargetRef; suspected: boolean }> = [];
    let spentThisHour = 0;
    const hourStart = now - 60 * MIN;
    const consider = async (target: ProbeTargetRef, interval: number, suspected: boolean) => {
      const recent = await ctx.db
        .query('probeRuns')
        .withIndex('by_target_requested', (q) =>
          q.eq('targetKind', target.kind).eq('targetRef', target.ref).gte('requestedAt', hourStart),
        )
        .collect();
      spentThisHour += recent.length;
      const last = recent.reduce((m, r) => Math.max(m, r.requestedAt), 0);
      if (last === 0 || now - last >= interval) dueTargets.push({ target, suspected });
    };
    const baseInterval = cfg.probe.intervalMinutes * MIN;
    for (const relay of relays) {
      const suspected = relay.suspicion?.state === 'suspected';
      const interval = suspected ? cfg.probe.suspectedIntervalMinutes * MIN : baseInterval;
      for (const edgeId of relay.publishedEdgeIds) {
        if (!edgeId) continue;
        const edge = await ctx.db.get(edgeId);
        if (!edge || edge.status !== 'active' || !edge.addresses.v4) continue;
        await consider({ kind: 'edge', ref: edgeId }, interval, suspected);
      }
      if (relay.probeNode) await consider({ kind: 'relay', ref: relay._id }, baseInterval, false);
    }
    for (const t of await ctx.db
      .query('probeTargets')
      .withIndex('by_enabled', (q) => q.eq('enabled', true))
      .collect()) {
      await consider({ kind: 'custom', ref: t._id }, baseInterval, false);
    }
    // Suspected relays' edges first so a tight budget goes where it matters.
    dueTargets.sort((a, b) => Number(b.suspected) - Number(a.suspected));
    return {
      enabled: cfg.probe.enabled,
      sources: enabledSources(cfg, secrets),
      hourlyBudget: cfg.probe.hourlyBudget,
      spentThisHour,
      dueTargets,
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
        .query('probeRuns')
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
    if ((rounds ?? 0) === 0) await recordHeartbeat(ctx, 'retention-edge-probes');
    const cutoff = now - PROBE_RUN_RETENTION_MS;
    const page = limit ?? 200;
    let removed = 0;
    for (const status of ['finished', 'failed', 'timeout'] as const) {
      const rows = await ctx.db
        .query('probeRuns')
        .withIndex('by_status_requested', (q) => q.eq('status', status).lt('requestedAt', cutoff))
        .take(page);
      for (const r of rows) await ctx.db.delete(r._id);
      removed += rows.length;
      if (rows.length === page) {
        const n = rounds ?? 0;
        if (n < MAX_SWEEP_ROUNDS)
          await ctx.scheduler.runAfter(0, internal.probes.sweepFinished, {
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

/** The `edge-probe` cron tick: budget-aware round for every due target. */
export const run = internalAction({
  args: {},
  handler: async (ctx): Promise<{ requested: number; skipped: number; timedOut: number }> =>
    runWithCronOutcome(ctx, 'edge-probe', async () => {
      const now = Date.now();
      const { timedOut } = await ctx.runMutation(internal.probes.sweepStuck, { now });
      const plan = await ctx.runQuery(internal.probes.due, { now });
      if (!plan.enabled || plan.sources.length === 0) return { requested: 0, skipped: 0, timedOut };
      let spent = plan.spentThisHour;
      let requested = 0;
      let skipped = 0;
      for (const d of plan.dueTargets) {
        // Each source is one run (two with IPv6); reserve the worst case.
        const cost = plan.sources.length * 2;
        if (spent + cost > plan.hourlyBudget) {
          skipped++;
          continue;
        }
        try {
          const res = await ctx.runMutation(internal.probes.requestProbes, {
            target: d.target,
            trigger: 'cron',
            sources: plan.sources,
          });
          spent += res.runIds.length;
          requested += res.runIds.length;
        } catch {
          skipped++; // a target that vanished between the plan and the request
        }
      }
      return { requested, skipped, timedOut };
    }),
});
