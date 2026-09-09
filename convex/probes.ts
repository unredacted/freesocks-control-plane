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
 * (target, country, source, address family, listener port); the summary
 * combines the sources per port with the agreement rules in
 * lib/edges/probes/verdict.ts, then the ports per country (`portRollup`: a
 * blocked listener blocks that slot).
 *
 * The hourly budget (`probe.hourlyBudget`) is reserved INSIDE the requesting
 * mutation for every path (cron, manual, detector): the hour's runs are counted
 * and the inserts are the reservation, so two concurrent requests cannot both
 * spend the last slot.
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
  portRollup,
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
/** Distinct failing networks kept per rollup row (the agreement rule needs a handful). */
const MAX_FAIL_NETWORKS = 16;

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
    port: portOfRun(r) ?? null,
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
  /** Every port the target listens on (one run per port: a block can be per port). */
  ports: number[];
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
      ports: distinctPorts(edge.listeners.map((l) => l.edgePort)),
    };
  }
  if (t.kind === 'relay') {
    const relay = await ctx.db.get(t.ref as Id<'relays'>);
    if (!relay) return null;
    const slots = await ctx.db
      .query('relaySlots')
      .withIndex('by_relay', (q) => q.eq('relayId', relay._id))
      .collect();
    const deployed = slots
      .filter((s) => s.deployed && !s.retired)
      .sort((a, b) => a.slotKey.localeCompare(b.slotKey));
    return {
      label: `${relay.slug} node`,
      addresses: splitByFamily(relay.originAddress),
      ports: distinctPorts(deployed.map((s) => s.originPort)),
    };
  }
  const row = await ctx.db.get(t.ref as Id<'probeTargets'>);
  if (!row) return null;
  return { label: row.label, addresses: splitByFamily(row.address), ports: [row.port] };
}

function distinctPorts(ports: number[]): number[] {
  const out = [...new Set(ports.filter((p) => Number.isInteger(p) && p > 0))];
  return out.length > 0 ? out : [443];
}

function splitByFamily(address: string): { v4?: string; v6?: string } {
  return addressFamily(address) === 'v6' ? { v6: address } : { v4: address };
}

/** Which address families a resolved target is probed over (v4 always; v6 when present and rendering allows, or v6-only). */
function familiesOf(resolved: ResolvedTarget, cfg: EdgeConfig): Array<4 | 6> {
  const out: Array<4 | 6> = [];
  if (resolved.addresses.v4) out.push(4);
  if (resolved.addresses.v6 && (cfg.render.ipv6Mode !== 'off' || !resolved.addresses.v4))
    out.push(6);
  return out;
}

// --- runs ---------------------------------------------------------------------------------------

/** Listener port of a run: the stored field, else parsed out of a legacy row's "ip:port" target. */
function portOfRun(run: { port?: number; target: string }): number | undefined {
  if (run.port !== undefined) return run.port;
  const m = /:(\d+)$/.exec(run.target);
  return m ? Number(m[1]) : undefined;
}

/**
 * Runs requested in the last hour — EVERY trigger (cron, manual, detector,
 * qualification) in EVERY state — bounded per status by the budget itself
 * (anything beyond it is simply "spent"; never an unbounded collect).
 */
async function spentThisHour(
  db: QueryCtx['db'],
  now: number,
  hourlyBudget: number,
): Promise<number> {
  const hourStart = now - 60 * MIN;
  const cap = hourlyBudget + 1;
  let spent = 0;
  for (const status of ['requested', 'running', 'finished', 'failed', 'timeout'] as const) {
    spent += (
      await db
        .query('probeRuns')
        .withIndex('by_status_requested', (q) =>
          q.eq('status', status).gte('requestedAt', hourStart),
        )
        .take(cap)
    ).length;
  }
  return spent;
}

/**
 * What the hour's budget still allows, read inside the requesting mutation.
 * Serializable: the inserts that follow ARE the reservation, so a concurrent
 * request over the same slot retries and sees them.
 */
async function remainingBudget(db: QueryCtx['db'], cfg: EdgeConfig, now: number): Promise<number> {
  const spent = await spentThisHour(db, now, cfg.probe.hourlyBudget);
  return Math.max(0, cfg.probe.hourlyBudget - spent);
}

const budgetExhausted = () =>
  new ConvexError({
    code: 'probe.budget_exhausted',
    message:
      'The hourly probe budget is spent; wait for the hour to roll or raise probe.hourlyBudget',
  });

function codeOf(err: unknown): string {
  return err instanceof ConvexError
    ? String((err.data as { code?: string }).code ?? 'error')
    : 'error';
}

async function insertRun(
  ctx: MutationCtx,
  a: {
    target: ProbeTargetRef;
    source: ProbeSource;
    address: string;
    port: number;
    ipVersion: 4 | 6;
    trigger: 'cron' | 'manual' | 'detector' | 'qualification';
    /** Executor start delay: staggers a batch's runs against one external service. */
    delayMs: number;
  },
): Promise<Id<'probeRuns'>> {
  const now = Date.now();
  const delayMs = Math.max(0, Math.floor(a.delayMs));
  const runId = await ctx.db.insert('probeRuns', {
    targetKind: a.target.kind,
    targetRef: a.target.ref,
    source: a.source,
    target: `${bracketIfV6(a.address)}:${a.port}`,
    port: a.port,
    ipVersion: a.ipVersion,
    status: 'requested',
    trigger: a.trigger,
    requestedAt: now,
    scheduledAt: now + delayMs,
    results: [],
  });
  await ctx.scheduler.runAfter(delayMs, internal.probeOps.execute, { runId });
  await writeAuditLog(ctx, {
    actorType: 'system',
    action: 'probe.run',
    targetType: 'probe_target',
    targetId: targetKeyOf(a.target),
    payload: { targetKey: targetKeyOf(a.target), source: a.source, trigger: a.trigger },
  });
  return runId;
}

/** One target's probe round, resolved and costed but not yet inserted. */
interface TargetPlan {
  target: ProbeTargetRef;
  resolved: ResolvedTarget;
  cfg: EdgeConfig;
  sources: ProbeSource[];
  families: Array<4 | 6>;
  /** Runs one source costs for this target (ports × address families). */
  runsPerSource: number;
  /** Runs the round costs in total (sources × runsPerSource): its hourly-budget reservation. */
  cost: number;
}

async function planTarget(
  ctx: { db: import('./_generated/server').DatabaseReader },
  target: ProbeTargetRef,
  sources?: ProbeSource[],
): Promise<TargetPlan> {
  const resolved = await resolveTarget(ctx, target);
  if (!resolved) throw new ConvexError({ code: 'not_found', message: 'Probe target not found' });
  if (!resolved.addresses.v4 && !resolved.addresses.v6) {
    throw new ConvexError({ code: 'edge.no_address', message: 'The target has no address yet' });
  }
  const cfg = await resolveEdgeConfig(ctx.db);
  const secrets = await resolveEdgeSecrets(ctx.db);
  const use = sources ?? enabledSources(cfg, secrets);
  const families = familiesOf(resolved, cfg);
  const runsPerSource = families.length * resolved.ports.length;
  return {
    target,
    resolved,
    cfg,
    sources: use,
    families,
    runsPerSource,
    cost: use.length * runsPerSource,
  };
}

/**
 * How a target's runs are staggered inside the caller's batch. Runs against
 * the same EXTERNAL source are scheduled `probe.sourceSpacingMs` apart across
 * the batch, so one tick never fires N simultaneous requests at a keyless
 * service; the internal probe is never delayed.
 */
export interface StaggerOpts {
  /** The target's position in the batch (each position = this target's own runsPerSource). */
  staggerIndex?: number;
  /** Runs-per-source scheduled ahead of this target in the batch (exact; wins over staggerIndex). */
  staggerOffset?: number;
  /**
   * The batch's total runs per source. When known, the spacing SHRINKS so the
   * whole batch fits inside one probe interval; when unknown, each run's delay
   * is clamped to that span instead.
   */
  batchRunsPerSource?: number;
}

/** A batch's last run is never scheduled further out than one probe interval. */
function staggerSpanCap(cfg: EdgeConfig): number {
  return cfg.probe.intervalMinutes * MIN;
}

function staggerSpacing(cfg: EdgeConfig, source: ProbeSource, batchRunsPerSource?: number): number {
  if (source === 'internal') return 0;
  const total = Math.floor(batchRunsPerSource ?? 0);
  if (total > 1)
    return Math.min(cfg.probe.sourceSpacingMs, Math.floor(staggerSpanCap(cfg) / (total - 1)));
  return cfg.probe.sourceSpacingMs;
}

/** Insert a planned round: one run per source per port per address family. */
async function insertPlanned(
  ctx: MutationCtx,
  plan: TargetPlan,
  trigger: 'cron' | 'manual' | 'detector' | 'qualification',
  opts: StaggerOpts,
): Promise<Id<'probeRuns'>[]> {
  const offset = Math.max(
    0,
    Math.floor(opts.staggerOffset ?? (opts.staggerIndex ?? 0) * plan.runsPerSource),
  );
  const spanCap = staggerSpanCap(plan.cfg);
  const runIds: Id<'probeRuns'>[] = [];
  for (const source of plan.sources) {
    const spacing = staggerSpacing(plan.cfg, source, opts.batchRunsPerSource);
    let k = 0;
    for (const ipVersion of plan.families) {
      const address = ipVersion === 4 ? plan.resolved.addresses.v4! : plan.resolved.addresses.v6!;
      for (const port of plan.resolved.ports) {
        runIds.push(
          await insertRun(ctx, {
            target: plan.target,
            source,
            address,
            port,
            ipVersion,
            trigger,
            delayMs: Math.min((offset + k) * spacing, spanCap),
          }),
        );
        k++;
      }
    }
  }
  return runIds;
}

/**
 * Start one probe round for one target from every enabled source, for every
 * listener port, per address family (v4 always; v6 when the target has one and
 * IPv6 rendering is not off, or when v6 is all it has). Reserves the round's
 * cost from the hourly budget first: a round that does not fit is refused
 * whole (`probe.budget_exhausted`), never partially inserted.
 */
export async function requestProbesFor(
  ctx: MutationCtx,
  target: ProbeTargetRef,
  trigger: 'cron' | 'manual' | 'detector' | 'qualification',
  sources?: ProbeSource[],
  opts: StaggerOpts = {},
): Promise<Id<'probeRuns'>[]> {
  const plan = await planTarget(ctx, target, sources);
  if (plan.cost > (await remainingBudget(ctx.db, plan.cfg, Date.now()))) throw budgetExhausted();
  return insertPlanned(ctx, plan, trigger, opts);
}

/** One target (the cron, the detector, the per-edge admin button). A manual request is audited like requestMany. */
export const requestProbes = internalMutation({
  args: {
    target: probeTargetRef,
    trigger: probeTrigger,
    sources: v.optional(v.array(probeSource)),
    staggerIndex: v.optional(v.number()),
    staggerOffset: v.optional(v.number()),
    batchRunsPerSource: v.optional(v.number()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { target, trigger, sources, actorAdminId, ...stagger }) => {
    const plan = await planTarget(ctx, target, sources);
    if (plan.cost > (await remainingBudget(ctx.db, plan.cfg, Date.now()))) throw budgetExhausted();
    const runIds = await insertPlanned(ctx, plan, trigger, stagger);
    if (trigger === 'manual') {
      await writeAuditLog(ctx, {
        actorType: 'admin',
        actorId: actorAdminId ?? undefined,
        action: 'probe.requested',
        targetType: 'probe_target',
        targetId: targetKeyOf(target),
        payload: { targets: 1, runs: runIds.length, sources: sources ?? null },
      });
    }
    // The batch caller (detector) accumulates this into the next target's offset.
    return { runIds, runsPerSource: plan.runsPerSource };
  },
});

/**
 * The cost of one round for one target WITHOUT inserting anything: how many
 * runs per source it will schedule (0 when it cannot be probed). A batch
 * caller sums these first so every target's stagger offset is cumulative and
 * the whole batch is spaced inside one interval, like the cron pass.
 */
export const planFor = internalQuery({
  args: { target: probeTargetRef, sources: v.optional(v.array(probeSource)) },
  handler: async (ctx, { target, sources }): Promise<{ runsPerSource: number }> => {
    try {
      const plan = await planTarget(ctx, target, sources);
      return { runsPerSource: plan.runsPerSource };
    } catch (err) {
      if (err instanceof ConvexError) return { runsPerSource: 0 };
      throw err;
    }
  },
});

/**
 * Several targets at once (Telemetry → Probes "Probe now"). Duplicates collapse
 * to one target; the batch is truncated to what the hourly budget still allows
 * (whole targets, in request order; the rest come back in `skipped` as
 * `<key>: probe.budget_exhausted`) and refused outright when nothing fits.
 * Audited once as the operator's request; every run still writes its own
 * `probe.run` row.
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
    // The same target twice is one request (a duplicate would double-spend the budget).
    const unique = [...new Map(targets.map((t) => [targetKeyOf(t), t])).values()];
    const cfg = await resolveEdgeConfig(ctx.db);
    let remaining = await remainingBudget(ctx.db, cfg, Date.now());
    if (remaining <= 0) throw budgetExhausted();
    const skipped: string[] = [];
    // Resolve everything first: the batch's total decides the stagger spacing.
    const plans: TargetPlan[] = [];
    for (const t of unique) {
      try {
        plans.push(await planTarget(ctx, t, sources));
      } catch (err) {
        skipped.push(`${targetKeyOf(t)}: ${codeOf(err)}`);
      }
    }
    // Reserve whole targets in request order; one that no longer fits is skipped, not split.
    const fitting: TargetPlan[] = [];
    for (const p of plans) {
      if (p.cost > remaining) {
        skipped.push(`${targetKeyOf(p.target)}: probe.budget_exhausted`);
        continue;
      }
      remaining -= p.cost;
      fitting.push(p);
    }
    if (fitting.length === 0 && plans.length > 0) throw budgetExhausted();
    const batchRunsPerSource = fitting.reduce((a, p) => a + p.runsPerSource, 0);
    const runIds: Id<'probeRuns'>[] = [];
    let offset = 0;
    for (const p of fitting) {
      runIds.push(
        ...(await insertPlanned(ctx, p, 'manual', { staggerOffset: offset, batchRunsPerSource })),
      );
      offset += p.runsPerSource;
    }
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'probe.requested',
      targetType: 'probe_target',
      payload: {
        targets: unique.length,
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
    await ctx.db.patch(runId, {
      status: 'running',
      startedAt: Date.now(),
      externalId: externalId?.slice(0, 200),
    });
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
    // Only an in-flight run settles: one already finished, failed (e.g. its
    // target changed under it) or timed out keeps its state.
    if (!run || (run.status !== 'requested' && run.status !== 'running')) return null;
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
      // One rollup row per (country, source, address family, listener port): a
      // dual-stack target's v6 result must never overwrite its v4 verdict, and
      // a multi-port edge's ports must not overwrite each other in completion
      // order. A row written before ports were kept (no `port`) is the legacy
      // single-port row: the first run on its path adopts and stamps it.
      const port = portOfRun(run);
      const samePath = existing.filter(
        (x) =>
          x.country === country && x.source === run.source && (x.ipVersion ?? 4) === run.ipVersion,
      );
      const row =
        samePath.find((x) => x.port === port) ?? samePath.find((x) => x.port === undefined);
      const patch = {
        port,
        okCount: summary.okVantages,
        failCount: summary.failVantages,
        lastOkAt: summary.okVantages > 0 ? now : row?.lastOkAt,
        lastFailAt: summary.failVantages > 0 ? now : row?.lastFailAt,
        // The transition marker the detector needs: this country has reached
        // the target before, so a later `unreachable` is a change, not a constant.
        lastReachableAt: summary.verdict === 'reachable' ? now : row?.lastReachableAt,
        // The real distinct failing networks (bounded) behind this verdict.
        failNetworks: summary.failNetworks.slice(0, MAX_FAIL_NETWORKS),
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
  const cfg = await resolveEdgeConfig(ctx.db);
  const secrets = await resolveEdgeSecrets(ctx.db);
  const sources = new Set<string>(enabledSources(cfg, secrets));
  const allRows = await ctx.db
    .query('probeReachability')
    .withIndex('by_target_country', (q) =>
      q.eq('targetKind', target.kind).eq('targetRef', target.ref),
    )
    .collect();
  // Evidence expires at the detector's own freshness window (two probe
  // intervals) and comes only from sources that are still enabled: a stale
  // verdict from a disabled or failing source must not keep authorizing an
  // automatic rotation because an unrelated (e.g. internal) run refreshed
  // the summary. Countries left without fresh evidence drop out.
  const staleBefore = now - 2 * cfg.probe.intervalMinutes * MIN;
  const rows = allRows.filter((r) => sources.has(r.source));
  const countries = [...new Set(rows.map((r) => r.country))]
    .filter((c) => rows.some((r) => r.country === c && r.updatedAt >= staleBefore))
    .sort();
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
        // The persisted distinct failing networks. A row written before they
        // were kept counts as ONE network (never reconstructed: the
        // cross-source rule must count real vantages, and the row refreshes
        // at the next run anyway).
        failNetworks: r.failNetworks ?? (r.failCount > 0 ? [`${r.source}:legacy`] : []),
      }));
    const verdictOf = (perSource: SourceSummary[]): Verdict =>
      country === 'XX' ? internalVerdict(perSource) : countryVerdict(perSource);
    // Sources agree PER PORT (a source's rows for different ports are different
    // measurements), then the ports roll up: any blocked listener blocks the
    // slot (portRollup). Legacy rows without a port form their own group.
    const acrossPorts = (subset: typeof fresh): Verdict => {
      const ports = [...new Set(subset.map((r) => r.port ?? -1))];
      return portRollup(
        ports.map((p) => verdictOf(summarise(subset.filter((r) => (r.port ?? -1) === p)))),
      );
    };
    const perSource = summarise(primaryRows);
    const v6 = v4Rows.length > 0 && v6Rows.length > 0 ? acrossPorts(v6Rows) : undefined;
    const verdict = acrossPorts(primaryRows);
    // The reachable→unreachable transition is judged PER PORT: a port that is
    // unreachable now counts only if THAT port was reached from this country
    // before. Another port's reachable history must not make a listener that
    // was blocked since it appeared look like a fresh block.
    const wasReachable = (() => {
      const ports = [...new Set(primaryRows.map((r) => r.port ?? -1))];
      const portRows = (p: number) => primaryRows.filter((r) => (r.port ?? -1) === p);
      const reachedBefore = (rs: typeof primaryRows) =>
        rs.some((r) => r.lastReachableAt !== undefined);
      if (verdict !== 'unreachable') return reachedBefore(primaryRows);
      return ports.some(
        (p) => verdictOf(summarise(portRows(p))) === 'unreachable' && reachedBefore(portRows(p)),
      );
    })();
    return {
      country,
      verdict,
      wasReachable,
      ...(v6 ? { v6Verdict: v6 } : {}),
      okVantages: perSource.reduce((a, s) => a + s.okVantages, 0),
      failVantages: perSource.reduce((a, s) => a + s.failVantages, 0),
      // THIS country's own freshness (its newest contributing row), never the
      // summary's: the detector ages each country's evidence separately.
      lastAt: Math.max(0, ...primaryRows.map((r) => r.updatedAt)),
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
    // Buckets sit on clock boundaries of their size (whole hours / UTC days),
    // so the first one may start before `since` and cover a partial span.
    const alignedSince = Math.floor(since / bucketMs) * bucketMs;
    const n = Math.ceil((until - alignedSince) / bucketMs);
    const buckets = Array.from({ length: n }, (_, i) => ({
      start: alignedSince + i * bucketMs,
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
      // Newest first: when the window holds more than the cap, the OLDEST
      // measurements fall off, never the current ones (bucketing is order-free).
      .order('desc')
      .take(5000);
    const totals = { runs: 0, ok: 0, fail: 0 };
    const byCountry: Record<string, { ok: number; fail: number }> = {};
    const bySource: Record<string, { runs: number; ok: number; fail: number }> = {};
    for (const r of rows) {
      const b = buckets[Math.floor((r.requestedAt - alignedSince) / bucketMs)];
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
        // The internal probe ('XX') is not a country: it shows under bySource only.
        if (x.country === 'XX') continue;
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
    const dueTargets: Array<{
      target: ProbeTargetRef;
      suspected: boolean;
      /** Runs one source will cost for this target (ports × address families). */
      runsPerSource: number;
    }> = [];
    // The hour's spend counts EVERY run of the hour — cron, manual, detector,
    // qualification, whatever its state — not only the due candidates' runs.
    // (The plan's estimate; requestProbes re-checks and reserves atomically.)
    const spent = await spentThisHour(ctx.db, now, cfg.probe.hourlyBudget);
    const consider = async (target: ProbeTargetRef, interval: number, suspected: boolean) => {
      const newest = await ctx.db
        .query('probeRuns')
        .withIndex('by_target_requested', (q) =>
          q.eq('targetKind', target.kind).eq('targetRef', target.ref),
        )
        .order('desc')
        .first();
      const last = newest?.requestedAt ?? 0;
      if (last !== 0 && now - last < interval) return;
      const resolved = await resolveTarget(ctx, target);
      if (!resolved || (!resolved.addresses.v4 && !resolved.addresses.v6)) return;
      dueTargets.push({
        target,
        suspected,
        runsPerSource: Math.max(1, familiesOf(resolved, cfg).length * resolved.ports.length),
      });
    };
    const baseInterval = cfg.probe.intervalMinutes * MIN;
    for (const relay of relays) {
      const suspected = relay.suspicion?.state === 'suspected';
      const interval = suspected ? cfg.probe.suspectedIntervalMinutes * MIN : baseInterval;
      for (const edgeId of relay.publishedEdgeIds) {
        if (!edgeId) continue;
        const edge = await ctx.db.get(edgeId);
        // v6-only edges are probed too (over v6; requestProbesFor's family rules).
        if (!edge || edge.status !== 'active' || (!edge.addresses.v4 && !edge.addresses.v6))
          continue;
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
      spentThisHour: spent,
      dueTargets,
    };
  },
});

/**
 * Runs stuck in requested/running past the executor's ceiling → timeout. The
 * clock starts when the executor was DUE (`scheduledAt`: a staggered run may
 * sit `requested` for most of a probe interval by design) or, once running,
 * when it started — never at the request itself.
 */
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
        const since = Math.max(r.requestedAt, r.scheduledAt ?? 0, r.startedAt ?? 0);
        if (since + RUN_TIMEOUT_MS <= now) {
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
      // Fit the batch to the budget first (the plan's estimate; each request
      // re-checks and reserves for real), so its total is known and the
      // stagger spacing can shrink to keep the whole tick inside one interval.
      let spent = plan.spentThisHour;
      let skipped = 0;
      const batch: typeof plan.dueTargets = [];
      for (const d of plan.dueTargets) {
        // One run per source per port per address family.
        const cost = plan.sources.length * d.runsPerSource;
        if (spent + cost > plan.hourlyBudget) {
          skipped++;
          continue;
        }
        spent += cost;
        batch.push(d);
      }
      const batchRunsPerSource = batch.reduce((a, d) => a + d.runsPerSource, 0);
      let requested = 0;
      let offset = 0;
      for (const d of batch) {
        try {
          const res = await ctx.runMutation(internal.probes.requestProbes, {
            target: d.target,
            trigger: 'cron',
            sources: plan.sources,
            staggerOffset: offset,
            batchRunsPerSource,
          });
          requested += res.runIds.length;
        } catch {
          // A target that vanished between the plan and the request, or the
          // budget moved under the plan (the mutation is authoritative).
          skipped++;
        }
        offset += d.runsPerSource;
      }
      return { requested, skipped, timedOut };
    }),
});
