/**
 * Reachability probes, DB half: probe runs (`probeRuns`), the per-target
 * per-country per-source rollup (`probeReachability`), each target's
 * cross-source summary (`edges.reachability`, `origins.reachability`,
 * `probeTargets.reachability`), scheduling (the `edge-probe` cron + manual
 * "probe now"), and the admin reads (Telemetry → Probes).
 *
 * A TARGET is one of: an edge (its public address, per family), an origin node
 * (its origin address, when the origin opts in with `probeNode`), or an
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
import {
  EDGE_PLUMBING,
  controlCountriesOf,
  resolveEdgeConfig,
  resolveEdgeSecrets,
  type EdgeConfig,
} from './lib/edgeConfig';
import { resolveCensoredCountries } from './lib/censoredCountries';
import {
  failureCode,
  sourceHealth,
  type GlobalpingCap,
  type SourceHealth,
} from './lib/edges/country/sourceHealth';
import { networkIdOf } from './lib/edges/country/verdict';
import { settleRoundIfDone, dueRepeatEdges } from './edgeCountry';
import { addressFamily, bracketIfV6 } from './lib/edges/ip';
import { isValidHostname } from './lib/edges/hostname';
import {
  countryVerdict,
  portRollup,
  sourceVerdict,
  type SourceSummary,
  type Verdict,
} from './lib/edges/probes/verdict';
import {
  literalFamilies,
  type ProbeAddressKind,
  type ProbeProtocol,
  type ProbeResult,
  type ProbeSource,
  type RequestedFamily,
} from './lib/edges/probes/types';
import { checkhostTakes } from './lib/edges/probes/checkhost';
import { assertAdmission } from './lib/edges/maintenance';
import { shapeProtocolFor } from './lib/edges/verifyRung';
import { hostSniOf } from './relayListeners';
import { refreshPartialRung } from './edgeVerification';

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
  control: v.optional(v.boolean()),
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
    /** The OBSERVED family; null for a run addressed by name. */
    ipVersion: r.ipVersion ?? null,
    addressKind: r.addressKind ?? 'ip',
    probeProtocol: r.probeProtocol ?? 'tcp',
    requestedFamily: r.requestedFamily ?? r.ipVersion ?? 4,
    port: portOfRun(r) ?? null,
    status: r.status,
    trigger: r.trigger,
    requestedAt: new Date(r.requestedAt).toISOString(),
    finishedAt: r.finishedAt ? new Date(r.finishedAt).toISOString() : null,
    // Control vantages (uncensored countries asked in the same measurement)
    // are not the target's countries: they are counted apart.
    okVantages: r.results.filter((x) => x.ok && !x.control).length,
    failVantages: r.results.filter((x) => !x.ok && !x.control).length,
    roundId: r.roundId ?? null,
    tests: r.tests ?? null,
    controls: r.controls ?? [],
    error: r.error ?? null,
    results: r.results.map((x) => ({
      control: x.control === true,
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
      nameVerdict: c.nameVerdict ?? undefined,
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

export interface ResolvedTarget {
  kind: ProbeTargetKind;
  label: string;
  /**
   * What is probed: IP literals per family, or a NAME (an L7 edge's fronted
   * hostname, an origin whose origin is a name, a custom name target). A name has
   * no family of its own: the vantage's resolver picks one.
   */
  addresses: { v4?: string; v6?: string; name?: string };
  /** Every port the target listens on (one run per port: a block can be per port). */
  ports: number[];
  /** What the probe speaks against this target (see `ProbeProtocol`). */
  probeProtocol: ProbeProtocol;
  /**
   * What the INTERNAL source speaks when it differs: the protocol-shape check
   * of an L4 edge (`tls-sni` behind a REALITY / TLS listener, with the
   * listener's first active name as `servername`; `tcp` behind a plaintext
   * one). Outside vantages keep `probeProtocol` (a bare connect: they cannot
   * present an SNI to an IP literal).
   */
  internalProbeProtocol?: ProbeProtocol;
  servername?: string;
  /** Deployed UDP listeners left out of `ports` (origin targets; the probes are TCP connects). */
  udpListeners?: number;
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
    const label = `${relay?.slug ?? 'relay'} edge${edge.poolIndex !== undefined ? ` #${edge.poolIndex}` : ''}${edge.provider ? ` (${edge.provider})` : ''}`;
    const ports = distinctPorts(edge.listeners.map((l) => l.edgePort));
    // An L7 edge IS a hostname, and the front only answers for its own name:
    // the probe must complete a real TLS handshake with that SNI, so a
    // certificate or handshake failure is a genuine outage rather than the
    // "something answered" signal a REALITY listener gives on bare TCP.
    const hostname = edge.addresses.hostname;
    if (hostname && isValidHostname(hostname)) {
      return { kind: t.kind, label, addresses: { name: hostname }, ports, probeProtocol: 'tls' };
    }
    // An L4 edge: outside vantages do a bare connect; the internal source runs
    // the protocol-SHAPE check the listener's security calls for (`tls-sni`
    // with one of its active names, or `tcp` for a plaintext listener).
    const listener = await ctx.db.get(edge.listenerId);
    const shape = listener ? shapeProtocolFor(listener) : 'tcp';
    const servername =
      listener && shape === 'tls-sni' ? (hostSniOf(listener) ?? undefined) : undefined;
    return {
      kind: t.kind,
      label,
      addresses: { v4: edge.addresses.v4, v6: edge.addresses.v6 },
      ports,
      probeProtocol: 'tcp',
      // Without an active name there is nothing to verify against: bare tcp.
      ...(servername ? { internalProbeProtocol: shape, servername } : {}),
    };
  }
  if (t.kind === 'relay') {
    const relay = await ctx.db.get(t.ref as Id<'relays'>);
    if (!relay) return null;
    const listeners = await ctx.db
      .query('relayListeners')
      .withIndex('by_relay', (q) => q.eq('relayId', relay._id))
      .collect();
    // UDP listeners are not probeable (the probes are TCP connects).
    const deployed = listeners
      .filter((s) => s.deployed && !s.retired && s.transport === 'tcp')
      .sort((a, b) => a.listenerKey.localeCompare(b.listenerKey));
    return {
      kind: t.kind,
      label: `${relay.slug} node`,
      // An origin origin keeps the bare connect whatever its address kind: a
      // REALITY or plaintext origin would fail a handshake probe and look
      // blocked when it is serving members perfectly well.
      addresses: splitByKind(relay.originAddress),
      ports: distinctPorts(deployed.map((s) => s.originPort)),
      probeProtocol: 'tcp',
      udpListeners: listeners.filter((s) => s.deployed && !s.retired && s.transport === 'udp')
        .length,
    };
  }
  const row = await ctx.db.get(t.ref as Id<'probeTargets'>);
  if (!row) return null;
  return {
    kind: t.kind,
    label: row.label,
    addresses: splitByKind(row.address),
    ports: [row.port],
    probeProtocol: row.probeProtocol ?? 'tcp',
  };
}

/**
 * The target's distinct listener ports. EMPTY when it has none: a target with
 * no listeners (an edge whose slots were retired, an origin with nothing
 * deployed) is not probeable, and guessing 443 would measure a port nobody
 * serves and record its silence as a block.
 */
function distinctPorts(ports: number[]): number[] {
  return [...new Set(ports.filter((p) => Number.isInteger(p) && p > 0))];
}

function splitByKind(address: string): { v4?: string; v6?: string; name?: string } {
  const fam = addressFamily(address);
  if (fam === 'v6') return { v6: address };
  if (fam === 'v4') return { v4: address };
  return { name: address };
}

/**
 * Which address families a resolved target is probed over. A NAME is probed
 * once with no family requested (`any`): whichever record the vantage's
 * resolver follows is the path its members would take. For literals, v4 always,
 * and v6 when the deployment probes it: the RENDER setting for edges (a family
 * members are never handed is not evidence about them) and the probe's own
 * `probe.ipv6` knob for origin origins and custom targets, which are operator
 * evidence and have nothing to do with what is rendered. A v6-only target is
 * probed over v6 either way.
 */
export function familiesOf(resolved: ResolvedTarget, cfg: EdgeConfig): RequestedFamily[] {
  if (resolved.addresses.name) return ['any'];
  return literalFamilies(
    resolved.addresses,
    resolved.kind === 'edge' ? cfg.render.ipv6Mode !== 'off' : cfg.probe.ipv6,
  );
}

/**
 * The families one SOURCE probes a target over: every family of the target,
 * except an IPv6 literal for check-host, which refuses one (`checkhostTakes`).
 * A family no source takes is not tested, never a failed run.
 */
function sourceFamilies(source: ProbeSource, families: RequestedFamily[]): RequestedFamily[] {
  if (source !== 'checkhost') return families;
  return families.filter((f) =>
    checkhostTakes({ addressKind: f === 'any' ? 'name' : 'ip', family: f }),
  );
}

/** The rollup key a run or a row belongs to: the observed family, else the name path. */
export function familyKeyOf(r: {
  ipVersion?: 4 | 6;
  addressKind?: ProbeAddressKind;
}): 4 | 6 | 'name' {
  if (r.ipVersion !== undefined) return r.ipVersion;
  // Rows written before families were kept are the v4 path; only an explicit
  // `name` means "probed by name, no family".
  return r.addressKind === 'name' ? 'name' : 4;
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
    addressKind: ProbeAddressKind;
    probeProtocol: ProbeProtocol;
    requestedFamily: RequestedFamily;
    trigger: 'cron' | 'manual' | 'detector' | 'qualification';
    /** Executor start delay: staggers a batch's runs against one external service. */
    delayMs: number;
    roundId: string;
    /** Control countries asked in the same measurement (external sources only). */
    controls: string[];
    /** What the run costs at Globalping (Globalping runs only). */
    tests?: number;
  },
): Promise<Id<'probeRuns'>> {
  const now = Date.now();
  const delayMs = Math.max(0, Math.floor(a.delayMs));
  const runId = await ctx.db.insert('probeRuns', {
    roundId: a.roundId,
    ...(a.controls.length > 0 ? { controls: a.controls } : {}),
    ...(a.tests !== undefined ? { tests: a.tests } : {}),
    targetKind: a.target.kind,
    targetRef: a.target.ref,
    source: a.source,
    target: `${bracketIfV6(a.address)}:${a.port}`,
    port: a.port,
    // The OBSERVED family: a literal's own, absent for a name (the vantage's
    // resolver decides, and FCP never learns which record it followed).
    ...(a.requestedFamily === 'any' ? {} : { ipVersion: a.requestedFamily }),
    addressKind: a.addressKind,
    probeProtocol: a.probeProtocol,
    requestedFamily: a.requestedFamily,
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
  families: RequestedFamily[];
  /**
   * Runs one source costs for this target (ports × address families), the
   * most any source takes (check-host takes no IPv6 literal): the stagger unit.
   */
  runsPerSource: number;
  /** Runs the round costs in total (each source's own runs): its hourly-budget reservation. */
  cost: number;
  /**
   * Control countries every external run of the round also asks (one vantage
   * each): only for edges, only with per-country checks on (edge.country.*).
   */
  controls: string[];
  /** Globalping probes one Globalping run asks for (countries × vantages + controls). */
  testsPerRun: number;
}

async function planTarget(
  ctx: { db: import('./_generated/server').DatabaseReader },
  target: ProbeTargetRef,
  sources?: ProbeSource[],
): Promise<TargetPlan> {
  const resolved = await resolveTarget(ctx, target);
  if (!resolved) throw new ConvexError({ code: 'not_found', message: 'Probe target not found' });
  if (!hasAddress(resolved)) {
    throw new ConvexError({ code: 'edge.no_address', message: 'The target has no address yet' });
  }
  if (resolved.ports.length === 0 && (resolved.udpListeners ?? 0) > 0) {
    // Every deployed listener is UDP: say so instead of "no listeners".
    throw new ConvexError({
      code: 'probe.udp_unsupported',
      message: 'The target only has UDP listeners; the probes are TCP connects',
    });
  }
  if (resolved.ports.length === 0) {
    throw new ConvexError({
      code: 'probe.no_listeners',
      message: 'The target has no listener port to probe',
    });
  }
  const cfg = await resolveEdgeConfig(ctx.db);
  const secrets = await resolveEdgeSecrets(ctx.db);
  const families = familiesOf(resolved, cfg);
  const asked = sources ?? enabledSources(cfg, secrets);
  // A source that takes none of the target's families sits the round out
  // (check-host and an IPv6-only literal); with none left, nothing can check it.
  const use = asked.filter((s) => sourceFamilies(s, families).length > 0);
  if (asked.length > 0 && use.length === 0) {
    throw new ConvexError({
      code: 'probe.no_source',
      message: 'No probe source in use can check this address family',
    });
  }
  const runsPerSource = families.length * resolved.ports.length;
  const controls =
    cfg.country.enabled && target.kind === 'edge'
      ? controlCountriesOf(cfg, (await resolveCensoredCountries(ctx.db)).codes)
      : [];
  return {
    target,
    resolved,
    cfg,
    sources: use,
    families,
    runsPerSource,
    cost: costOf(use, families, resolved.ports.length),
    controls,
    testsPerRun: globalpingTestsPerRun(cfg, controls.length),
  };
}

/** The runs a round of these sources costs (each source over the families it takes). */
function costOf(sources: ProbeSource[], families: RequestedFamily[], ports: number): number {
  return sources.reduce((n, s) => n + sourceFamilies(s, families).length * ports, 0);
}

/** What one Globalping run asks for: every checked country's vantages, plus one per control. */
export function globalpingTestsPerRun(cfg: EdgeConfig, controls: number): number {
  return (
    cfg.probe.countries.length * Math.max(1, Math.min(cfg.probe.perCountryLimit, 10)) + controls
  );
}

/**
 * One source's runs requested since `since`, whatever their state, bounded
 * like `spentThisHour`'s five status reads (the run budget caps how many
 * there can be).
 */
function sourceRunsSince(
  db: QueryCtx['db'],
  source: ProbeSource,
  since: number,
  hourlyBudget: number,
) {
  return db
    .query('probeRuns')
    .withIndex('by_source_requested', (q) => q.eq('source', source).gte('requestedAt', since))
    .take(5 * (hourlyBudget + 1));
}

/** Globalping probes asked for in the last hour (`probeRuns.tests`). */
async function globalpingTestsThisHour(
  db: QueryCtx['db'],
  now: number,
  hourlyBudget: number,
): Promise<number> {
  let tests = 0;
  for (const r of await sourceRunsSince(db, 'globalping', now - 60 * MIN, hourlyBudget))
    tests += r.tests ?? 0;
  return tests;
}

/**
 * The last hour's cron rounds, and how many of them ran without Globalping.
 * The cron asks every enabled source, so a cron round with runs of the other
 * sources and none of Globalping is one the hourly cap left it out of
 * (`fitGlobalpingTests`), whatever the round's own size (families x ports).
 */
async function roundsWithoutGlobalping(
  db: QueryCtx['db'],
  sources: readonly ProbeSource[],
  now: number,
  hourlyBudget: number,
): Promise<{ rounds: number; skipped: number }> {
  const hourStart = now - 60 * MIN;
  const rounds = new Set<string>();
  // A round's runs are inserted in one mutation, Globalping's first: look a
  // minute further back for them so a round on the hour's edge is not miscounted.
  const withGlobalping = new Set<string>();
  for (const r of await sourceRunsSince(db, 'globalping', hourStart - MIN, hourlyBudget)) {
    if (!r.roundId) continue;
    withGlobalping.add(r.roundId);
    if (r.trigger === 'cron' && r.requestedAt >= hourStart) rounds.add(r.roundId);
  }
  for (const source of sources) {
    if (source === 'globalping') continue;
    for (const r of await sourceRunsSince(db, source, hourStart, hourlyBudget))
      if (r.trigger === 'cron' && r.roundId) rounds.add(r.roundId);
  }
  return {
    rounds: rounds.size,
    skipped: [...rounds].filter((id) => !withGlobalping.has(id)).length,
  };
}

/**
 * A round whose Globalping runs would pass `probe.globalpingTestsPerHour`
 * runs without Globalping (the other sources still measure). `spent` is the
 * hour's tests so far; the plan comes back adjusted, with what it now spends.
 */
function fitGlobalpingTests(plan: TargetPlan, spent: number): { plan: TargetPlan; tests: number } {
  if (!plan.sources.includes('globalping')) return { plan, tests: 0 };
  const tests = plan.testsPerRun * plan.runsPerSource;
  if (spent + tests <= plan.cfg.probe.globalpingTestsPerHour) return { plan, tests };
  const sources = plan.sources.filter((s) => s !== 'globalping');
  return {
    plan: {
      ...plan,
      sources,
      cost: costOf(sources, plan.families, plan.resolved.ports.length),
    },
    tests: 0,
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
    return Math.min(
      EDGE_PLUMBING.probeSourceSpacingMs,
      Math.floor(staggerSpanCap(cfg) / (total - 1)),
    );
  return EDGE_PLUMBING.probeSourceSpacingMs;
}

/** Insert a planned round: one run per source per port per address family the source takes. */
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
  // One round = this call's runs for this target (edgeCountry.ts settles it).
  const roundId = `${targetKeyOf(plan.target)}:${Date.now()}:${Math.random().toString(36).slice(2, 10)}`;
  for (const source of plan.sources) {
    const spacing = staggerSpacing(plan.cfg, source, opts.batchRunsPerSource);
    let k = 0;
    for (const requestedFamily of sourceFamilies(source, plan.families)) {
      const address = addressForFamily(plan.resolved, requestedFamily);
      for (const port of plan.resolved.ports) {
        runIds.push(
          await insertRun(ctx, {
            target: plan.target,
            source,
            address,
            port,
            addressKind: requestedFamily === 'any' ? 'name' : 'ip',
            probeProtocol:
              source === 'internal'
                ? (plan.resolved.internalProbeProtocol ?? plan.resolved.probeProtocol)
                : plan.resolved.probeProtocol,
            requestedFamily,
            trigger,
            delayMs: Math.min((offset + k) * spacing, spanCap),
            roundId,
            controls: source === 'internal' ? [] : plan.controls,
            ...(source === 'globalping' ? { tests: plan.testsPerRun } : {}),
          }),
        );
        k++;
      }
    }
  }
  return runIds;
}

function hasAddress(r: ResolvedTarget): boolean {
  return !!(r.addresses.v4 || r.addresses.v6 || r.addresses.name);
}

function addressForFamily(r: ResolvedTarget, family: RequestedFamily): string {
  if (family === 'any') return r.addresses.name!;
  return family === 4 ? r.addresses.v4! : r.addresses.v6!;
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
): Promise<{ runIds: Id<'probeRuns'>[]; runsPerSource: number }> {
  const now = Date.now();
  const planned = await planTarget(ctx, target, sources);
  const { plan } = fitGlobalpingTests(
    planned,
    await globalpingTestsThisHour(ctx.db, now, planned.cfg.probe.hourlyBudget),
  );
  if (plan.sources.length === 0) throw budgetExhausted();
  if (plan.cost > (await remainingBudget(ctx.db, plan.cfg, now))) throw budgetExhausted();
  const runIds = await insertPlanned(ctx, plan, trigger, opts);
  return { runIds, runsPerSource: plan.runsPerSource };
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
    // The authoritative maintenance check for EVERY single-target admission
    // (the cron, a detector tick that passed its own check just before a
    // freeze, the per-edge admin button). A qualification probe belongs to a
    // rotation already in flight: completion, so it stays admitted.
    if (trigger !== 'qualification') await assertAdmission(ctx.db, 'probe.request');
    const { runIds, runsPerSource } = await requestProbesFor(
      ctx,
      target,
      trigger,
      sources,
      stagger,
    );
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
    return { runIds, runsPerSource };
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
    await assertAdmission(ctx.db, 'probe.request');
    if (targets.length === 0 || targets.length > 50)
      throw new ConvexError({ code: 'validation', message: 'targets must hold 1..50 entries' });
    // The same target twice is one request (a duplicate would double-spend the budget).
    const unique = [...new Map(targets.map((t) => [targetKeyOf(t), t])).values()];
    const cfg = await resolveEdgeConfig(ctx.db);
    const now = Date.now();
    let remaining = await remainingBudget(ctx.db, cfg, now);
    if (remaining <= 0) throw budgetExhausted();
    const skipped: string[] = [];
    // Resolve everything first: the batch's total decides the stagger spacing.
    // A target whose Globalping runs no longer fit the tests budget goes without them.
    let tests = await globalpingTestsThisHour(ctx.db, now, cfg.probe.hourlyBudget);
    const plans: TargetPlan[] = [];
    for (const t of unique) {
      try {
        const fit = fitGlobalpingTests(await planTarget(ctx, t, sources), tests);
        if (fit.plan.sources.length === 0) {
          skipped.push(`${targetKeyOf(t)}: probe.budget_exhausted`);
          continue;
        }
        tests += fit.tests;
        plans.push(fit.plan);
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
    // Only a short class is kept (never the service text): the Probes page and
    // the `probe_source_failing` attention item say why a source gives nothing.
    await ctx.db.patch(runId, {
      status: timeout ? 'timeout' : 'failed',
      finishedAt: now,
      error: timeout ? 'timeout' : failureCode(error),
    });
    // A failed run is never evidence about the address (its vantages could not
    // test: lib/edges/probes/types.ts `RunOutcome`); the rung is re-read on
    // what the other runs show.
    if (run.targetKind === 'edge') await refreshPartialRung(ctx, run.targetRef as Id<'edges'>, now);
    // A failed run is no evidence, but it may be the last of its round.
    if (run.roundId) await settleRoundIfDone(ctx, run.roundId, now);
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
    // Results from the run's CONTROL countries are tagged: they feed only the
    // per-country round verdict, never the rollup below (nor the detector,
    // scoring or the verification rung, which read it).
    const controls = new Set(run.controls ?? []);
    const tagged = results.map((r) =>
      controls.has(r.country) && run.source !== 'internal' ? { ...r, control: true } : r,
    );
    await ctx.db.patch(runId, { status: 'finished', finishedAt: now, results: tagged });
    const cfg = await resolveEdgeConfig(ctx.db);
    const target: ProbeTargetRef = { kind: run.targetKind, ref: run.targetRef };
    // Per-country rollup for THIS source.
    const byCountry = new Map<string, ProbeResult[]>();
    for (const r of tagged) {
      if (r.control) continue;
      byCountry.set(r.country, [...(byCountry.get(r.country) ?? []), r]);
    }
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
      // One rollup row per (country, source, family, listener port), where the
      // family is the observed one or `name`: a dual-stack target's v6 result
      // must never overwrite its v4 verdict, a hostname's result is neither,
      // and a multi-port edge's ports must not overwrite each other in
      // completion order. A row written before ports were kept (no `port`) is
      // the legacy single-port row: the first run on its path adopts and
      // stamps it.
      const port = portOfRun(run);
      const runFamily = familyKeyOf(run);
      const samePath = existing.filter(
        (x) => x.country === country && x.source === run.source && familyKeyOf(x) === runFamily,
      );
      const row =
        samePath.find((x) => x.port === port) ?? samePath.find((x) => x.port === undefined);
      const streak = failStreakAfter(row, rs, now);
      const patch = {
        port,
        addressKind: run.addressKind ?? 'ip',
        probeProtocol: run.probeProtocol ?? 'tcp',
        okCount: summary.okVantages,
        failCount: summary.failVantages,
        lastOkAt: summary.okVantages > 0 ? now : row?.lastOkAt,
        lastFailAt: summary.failVantages > 0 ? now : row?.lastFailAt,
        // Kept for the admin view ("last fully reachable"). The transition
        // marker the detector needs is `lastOkAt`: a country that only ever
        // reached the target through a degraded (`mixed`) verdict never gets a
        // `lastReachableAt`, and would otherwise be unable to ever arm.
        lastReachableAt: summary.verdict === 'reachable' ? now : row?.lastReachableAt,
        // The real distinct failing networks (bounded) behind this verdict.
        failNetworks: summary.failNetworks.slice(0, MAX_FAIL_NETWORKS),
        ...streak,
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
    // The L4 verification rung follows the evidence (never past `partial`).
    if (run.targetKind === 'edge') await refreshPartialRung(ctx, run.targetRef as Id<'edges'>, now);
    if (run.roundId) await settleRoundIfDone(ctx, run.roundId, now);
    return null;
  },
});

/**
 * A rollup row's failing streak after one run's results from its country: any
 * vantage that connected resets it; otherwise the failing vantages add to it,
 * with the real networks among them (`networkIdOf`: a vantage that names no
 * ASN or network adds none, so missing metadata never makes a spread). A run
 * whose vantages could not test leaves no result and never gets here.
 */
function failStreakAfter(
  row:
    | Pick<Doc<'probeReachability'>, 'failStreak' | 'failStreakSince' | 'streakNetworks'>
    | undefined,
  rs: readonly ProbeResult[],
  now: number,
): Pick<Doc<'probeReachability'>, 'failStreak' | 'failStreakSince' | 'streakNetworks'> {
  if (rs.some((r) => r.ok))
    return { failStreak: 0, failStreakSince: undefined, streakNetworks: undefined };
  const failing = rs.filter((r) => !r.ok);
  if (failing.length === 0)
    return {
      failStreak: row?.failStreak,
      failStreakSince: row?.failStreakSince,
      streakNetworks: row?.streakNetworks,
    };
  const networks = new Set(row?.streakNetworks ?? []);
  for (const r of failing) {
    const id = networkIdOf(r);
    if (id && networks.size < MAX_FAIL_NETWORKS) networks.add(id);
  }
  return {
    failStreak: (row?.failStreak ?? 0) + failing.length,
    failStreakSince: row?.failStreakSince ?? now,
    streakNetworks: [...networks],
  };
}

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
    // The country verdict follows the IPv4 path (what every member receives),
    // or the NAME path for a target that is a hostname (an L7 front has no
    // family of its own). IPv6 and name rows summarise separately as
    // `v6Verdict` / `nameVerdict` and only stand in for the verdict when the
    // target was probed over that path alone.
    const ofFamily = (subset: typeof fresh, family: 4 | 6 | 'name') =>
      subset.filter((r) => familyKeyOf(r) === family);
    const v4Rows = ofFamily(fresh, 4);
    const v6Rows = ofFamily(fresh, 6);
    const nameRows = ofFamily(fresh, 'name');
    const primaryFamily: 4 | 6 | 'name' = v4Rows.length > 0 ? 4 : nameRows.length > 0 ? 'name' : 6;
    const primaryRows = v4Rows.length > 0 ? v4Rows : nameRows.length > 0 ? nameRows : v6Rows;
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
    const v6 = primaryFamily !== 6 && v6Rows.length > 0 ? acrossPorts(v6Rows) : undefined;
    const name =
      primaryFamily !== 'name' && nameRows.length > 0 ? acrossPorts(nameRows) : undefined;
    const verdict = acrossPorts(primaryRows);
    // The reachable→unreachable transition is judged PER PORT: a port that is
    // unreachable now counts only if THAT port was reached from this country
    // before. Another port's reachable history must not make a listener that
    // was blocked since it appeared look like a fresh block.
    //
    // History is read over the UNFILTERED rows (any source, any age) while
    // the verdict above stays on fresh rows from enabled sources. Otherwise
    // disabling a source, or simply letting its rows age out, erases the
    // target's reachable history and silently disarms the transition marker
    // exactly when the evidence matters. `lastOkAt` is the signal, not
    // `lastReachableAt`: a country that only ever saw a degraded (`mixed`)
    // verdict still reached the target.
    const history = allRows.filter(
      (r) => r.country === country && familyKeyOf(r) === primaryFamily,
    );
    const reachedBefore = (rs: typeof allRows) =>
      rs.some((r) => r.lastOkAt !== undefined || r.lastReachableAt !== undefined);
    const wasReachable = (() => {
      const portKey = (r: { port?: number }) => r.port ?? -1;
      if (verdict !== 'unreachable') return reachedBefore(history);
      const ports = [...new Set(primaryRows.map(portKey))];
      return ports.some(
        (p) =>
          verdictOf(summarise(primaryRows.filter((r) => portKey(r) === p))) === 'unreachable' &&
          reachedBefore(history.filter((r) => portKey(r) === p)),
      );
    })();
    // Sustained unreachability's own half (lib/edges/probes/verdict.ts
    // `sustainedBlock`): never reached from here over the member-facing path,
    // by any source on any port, and the failing checks on record since the
    // first. Never the IPv6 path: a vantage without IPv6 that still answers
    // can look exactly like a block.
    const neverReached = (() => {
      if (primaryFamily === 6 || reachedBefore(history)) return undefined;
      const streaks = history.filter(
        (r) => (r.failStreak ?? 0) > 0 && r.failStreakSince !== undefined,
      );
      if (streaks.length === 0) return undefined;
      return {
        checks: streaks.reduce((a, r) => a + (r.failStreak ?? 0), 0),
        networks: new Set(streaks.flatMap((r) => r.streakNetworks ?? [])).size,
        since: Math.min(...streaks.map((r) => r.failStreakSince!)),
        lastAt: Math.max(...streaks.map((r) => r.lastFailAt ?? r.updatedAt)),
      };
    })();
    return {
      country,
      verdict,
      wasReachable,
      ...(neverReached ? { neverReached } : {}),
      ...(v6 ? { v6Verdict: v6 } : {}),
      ...(name ? { nameVerdict: name } : {}),
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

// --- rollback ----------------------------------------------------------------------------------

type ReachabilitySummary = NonNullable<Doc<'edges'>['reachability']>;

/** A summary without its never-reached records (null when it carries none). */
function withoutNeverReached(r: ReachabilitySummary | undefined): ReachabilitySummary | null {
  if (!r || !r.byCountry.some((c) => c.neverReached !== undefined)) return null;
  return {
    ...r,
    byCountry: r.byCountry.map((c) => {
      const { neverReached, ...rest } = c;
      void neverReached;
      return rest;
    }),
  };
}

/**
 * Before deploying a build older than sustained unreachability (docs/edges.md
 * "Deploy notes"): clears the fields it added, page by page, scheduling itself
 * through the rollup rows, the edges, the origins (their summaries and the
 * suspicion's evidence) and the custom targets. An older schema refuses them.
 */
export const clearSustainedForRollback = internalMutation({
  args: {
    step: v.optional(
      v.union(v.literal('rollups'), v.literal('edges'), v.literal('relays'), v.literal('targets')),
    ),
    cursor: v.optional(v.union(v.string(), v.null())),
  },
  handler: async (ctx, a) => {
    const step = a.step ?? 'rollups';
    const next = { rollups: 'edges', edges: 'relays', relays: 'targets', targets: null } as const;
    const PAGE = 200;
    const cursor = a.cursor ?? null;
    let page: { isDone: boolean; continueCursor: string };
    if (step === 'rollups') {
      const p = await ctx.db.query('probeReachability').paginate({ cursor, numItems: PAGE });
      for (const r of p.page)
        if (
          r.failStreak !== undefined ||
          r.failStreakSince !== undefined ||
          r.streakNetworks !== undefined
        )
          await ctx.db.patch(r._id, {
            failStreak: undefined,
            failStreakSince: undefined,
            streakNetworks: undefined,
          });
      page = p;
    } else if (step === 'edges') {
      const p = await ctx.db.query('edges').paginate({ cursor, numItems: PAGE });
      for (const e of p.page) {
        const reachability = withoutNeverReached(e.reachability);
        if (reachability) await ctx.db.patch(e._id, { reachability });
      }
      page = p;
    } else if (step === 'relays') {
      const p = await ctx.db.query('relays').paginate({ cursor, numItems: PAGE });
      for (const r of p.page) {
        const reachability = withoutNeverReached(r.reachability);
        const suspicion = r.suspicion?.edgeEvidence.some((e) => e.neverReached !== undefined)
          ? {
              ...r.suspicion,
              edgeEvidence: r.suspicion.edgeEvidence.map((e) => {
                const { neverReached, ...rest } = e;
                void neverReached;
                return rest;
              }),
            }
          : null;
        if (reachability || suspicion)
          await ctx.db.patch(r._id, {
            ...(reachability ? { reachability } : {}),
            ...(suspicion ? { suspicion } : {}),
          });
      }
      page = p;
    } else {
      const p = await ctx.db.query('probeTargets').paginate({ cursor, numItems: PAGE });
      for (const t of p.page) {
        const reachability = withoutNeverReached(t.reachability);
        if (reachability) await ctx.db.patch(t._id, { reachability });
      }
      page = p;
    }
    const following = page.isDone ? next[step] : step;
    if (following)
      await ctx.scheduler.runAfter(0, internal.probes.clearSustainedForRollback, {
        step: following,
        cursor: page.isDone ? null : page.continueCursor,
      });
    return { step, done: following === null };
  },
});

// --- reads -------------------------------------------------------------------------------------

/** The newest runs per source a source's health is judged on (one indexed read each). */
const SOURCE_HEALTH_RUNS = 50;
/**
 * How far back that read looks for them: `no_route` runs (a family FCP's host
 * lacks) say nothing about the source and are skipped before the bound, or a
 * host probing many IPv6 targets would push every run that counts out of it.
 */
const SOURCE_HEALTH_SCAN = SOURCE_HEALTH_RUNS * 4;

/**
 * Whether each ENABLED source is giving evidence (lib/edges/country/sourceHealth.ts):
 * a source that keeps failing makes every country it alone covers read "not
 * known", so the failure itself is shown (Probes page, attention).
 */
export async function probeSourceHealth(db: QueryCtx['db'], now: number): Promise<SourceHealth[]> {
  const cfg = await resolveEdgeConfig(db);
  const secrets = await resolveEdgeSecrets(db);
  const sources = enabledSources(cfg, secrets);
  if (!cfg.probe.enabled || sources.length === 0) return [];
  const runs = [];
  for (const source of sources)
    for (const r of (
      await db
        .query('probeRuns')
        .withIndex('by_source_requested', (q) => q.eq('source', source))
        .order('desc')
        .take(SOURCE_HEALTH_SCAN)
    )
      .filter((x) => x.error !== 'no_route')
      .slice(0, SOURCE_HEALTH_RUNS))
      runs.push({
        source: r.source,
        status: r.status,
        requestedAt: r.requestedAt,
        ...(r.finishedAt !== undefined ? { finishedAt: r.finishedAt } : {}),
        results: r.results.length,
        ...(r.error !== undefined ? { error: r.error } : {}),
      });
  const health = sourceHealth(sources, runs, now);
  if (!sources.includes('globalping')) return health;
  // A round that would pass Globalping's hourly cap runs without it: no failed
  // run says so, only the cap's use and the rounds it left out do.
  const controls = cfg.country.enabled
    ? controlCountriesOf(cfg, (await resolveCensoredCountries(db)).codes).length
    : 0;
  const cap: GlobalpingCap = {
    used: await globalpingTestsThisHour(db, now, cfg.probe.hourlyBudget),
    perHour: cfg.probe.globalpingTestsPerHour,
    perRun: globalpingTestsPerRun(cfg, controls),
    ...(await roundsWithoutGlobalping(db, sources, now, cfg.probe.hourlyBudget)),
  };
  return health.map((h) => (h.source === 'globalping' ? { ...h, cap } : h));
}

const isoOrNull = (n: number | null) => (n === null ? null : new Date(n).toISOString());

export function mapSourceHealthAdmin(h: SourceHealth) {
  return { ...h, lastOkAt: isoOrNull(h.lastOkAt), lastFailAt: isoOrNull(h.lastFailAt) };
}

export const sourceHealthView = internalQuery({
  args: {},
  handler: async (ctx) => ({
    sources: (await probeSourceHealth(ctx.db, Date.now())).map(mapSourceHealthAdmin),
  }),
});

/**
 * "Check it from every country now" for one edge (Edges -> Countries): one
 * manual round, the same budget as any other request.
 */
export const requestCountryCheck = internalMutation({
  args: { edgeId: v.id('edges'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { edgeId, actorAdminId }) => {
    await assertAdmission(ctx.db, 'probe.request');
    const edge = await ctx.db.get(edgeId);
    if (!edge || edge.status === 'destroyed')
      throw new ConvexError({ code: 'not_found', message: 'Edge not found' });
    const { runIds } = await requestProbesFor(ctx, { kind: 'edge', ref: edgeId }, 'manual');
    const relay = await ctx.db.get(edge.relayId);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'edge.country.check',
      targetType: 'edge',
      targetId: edgeId,
      payload: { relaySlug: relay?.slug ?? '' },
    });
    return { runIds };
  },
});

export const runContext = internalQuery({
  args: { runId: v.id('probeRuns') },
  handler: async (ctx, { runId }) => {
    const run = await ctx.db.get(runId);
    if (!run) return null;
    const cfg = await resolveEdgeConfig(ctx.db);
    const secrets = await resolveEdgeSecrets(ctx.db);
    // A `tls-sni` run presents the listener's first ACTIVE name at execution
    // time (never stored on the run: a name retire between request and run
    // must not be probed for).
    let servername: string | undefined;
    if (run.source === 'internal' && run.probeProtocol === 'tls-sni' && run.targetKind === 'edge') {
      const edge = await ctx.db.get(run.targetRef as Id<'edges'>);
      const listener = edge ? await ctx.db.get(edge.listenerId) : null;
      servername = listener ? (hostSniOf(listener) ?? undefined) : undefined;
    }
    return { run, cfg, secrets, servername: servername ?? null };
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
 * The reachability matrix over every probe target: live edges of every origin,
 * origin nodes that opted in (or were ever probed), and custom targets. Small by
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
    return {
      countries: cfg.probe.countries,
      targets,
      sources: (await probeSourceHealth(ctx.db, Date.now())).map(mapSourceHealthAdmin),
    };
  },
});

/** Finished runs one summary page reads (one query execution, far under the read limit). */
const SUMMARY_PAGE = 2000;
/** Pages one summary reads at most; past it the answer says `truncated` (the 14-day retention keeps a window well below it). */
const SUMMARY_MAX_PAGES = 100;

type Tally = { ok: number; fail: number };

/**
 * One page of the probe chart: the finished runs of the window, in
 * (status, requestedAt) order from `cursor`, tallied per bucket index,
 * country and source. `summary` drives the pages and merges them.
 */
export const summaryPage = internalQuery({
  args: {
    since: v.number(),
    until: v.number(),
    alignedSince: v.number(),
    bucketMs: v.number(),
    cursor: v.union(v.string(), v.null()),
  },
  handler: async (ctx, a) => {
    const page = await ctx.db
      .query('probeRuns')
      .withIndex('by_status_requested', (q) =>
        q.eq('status', 'finished').gte('requestedAt', a.since).lt('requestedAt', a.until),
      )
      .paginate({ cursor: a.cursor, numItems: SUMMARY_PAGE });
    const buckets = new Map<number, Tally & { runs: number; byCountry: Map<string, Tally> }>();
    const bySource = new Map<string, Tally & { runs: number }>();
    for (const r of page.page) {
      const i = Math.floor((r.requestedAt - a.alignedSince) / a.bucketMs);
      let b = buckets.get(i);
      if (!b) buckets.set(i, (b = { runs: 0, ok: 0, fail: 0, byCountry: new Map() }));
      b.runs++;
      let src = bySource.get(r.source);
      if (!src) bySource.set(r.source, (src = { runs: 0, ok: 0, fail: 0 }));
      src.runs++;
      for (const x of r.results) {
        const k = x.ok ? 'ok' : 'fail';
        b[k]++;
        src[k]++;
        // The internal probe ('XX') is not a country, and a control vantage is
        // not a checked one: both show under bySource only.
        if (x.country === 'XX' || x.control) continue;
        let c = b.byCountry.get(x.country);
        if (!c) b.byCountry.set(x.country, (c = { ok: 0, fail: 0 }));
        c[k]++;
      }
    }
    return {
      buckets: [...buckets].map(([i, b]) => ({
        i,
        runs: b.runs,
        ok: b.ok,
        fail: b.fail,
        byCountry: [...b.byCountry].map(([country, c]) => ({ country, ...c })),
      })),
      bySource: [...bySource].map(([source, c]) => ({ source, ...c })),
      continueCursor: page.continueCursor,
      isDone: page.isDone,
    };
  },
});

/**
 * Time-bucketed probe outcomes for the Probes chart (Edges, Advanced): per
 * bucket (hourly on short ranges, daily otherwise) the failing and succeeding
 * vantage counts, split per country, plus per-country and per-source totals.
 * Every finished run of the window counts: the window is read page by page
 * (`summaryPage`, one query each), bounded by the 14-day retention, the span
 * clamp and SUMMARY_MAX_PAGES (`truncated` past it).
 */
export const summary = internalAction({
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
      byCountry: {} as Record<string, Tally>,
    }));
    const totals = { runs: 0, ok: 0, fail: 0 };
    const byCountry: Record<string, Tally> = {};
    const bySource: Record<string, Tally & { runs: number }> = {};
    let cursor: string | null = null;
    let truncated = true;
    for (let pages = 0; pages < SUMMARY_MAX_PAGES; pages++) {
      const p: {
        buckets: Array<
          { i: number; runs: number; byCountry: Array<{ country: string } & Tally> } & Tally
        >;
        bySource: Array<{ source: string; runs: number } & Tally>;
        continueCursor: string;
        isDone: boolean;
      } = await ctx.runQuery(internal.probes.summaryPage, {
        since,
        until,
        alignedSince,
        bucketMs,
        cursor,
      });
      for (const pb of p.buckets) {
        const b = buckets[pb.i];
        if (!b) continue;
        b.runs += pb.runs;
        b.ok += pb.ok;
        b.fail += pb.fail;
        totals.runs += pb.runs;
        totals.ok += pb.ok;
        totals.fail += pb.fail;
        for (const c of pb.byCountry) {
          const bc = (b.byCountry[c.country] ??= { ok: 0, fail: 0 });
          bc.ok += c.ok;
          bc.fail += c.fail;
          const tc = (byCountry[c.country] ??= { ok: 0, fail: 0 });
          tc.ok += c.ok;
          tc.fail += c.fail;
        }
      }
      for (const src of p.bySource) {
        const t = (bySource[src.source] ??= { runs: 0, ok: 0, fail: 0 });
        t.runs += src.runs;
        t.ok += src.ok;
        t.fail += src.fail;
      }
      if (p.isDone) {
        truncated = false;
        break;
      }
      cursor = p.continueCursor;
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
      truncated,
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
 * published edges of enabled origins (suspected origins first), origin nodes that
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
      /**
       * Who goes first when the budget is short: 0 a repeat round a country
       * verdict waits for, 1 a suspected origin's edge, 2 a published edge or
       * an operator target, 3 a spare.
       */
      rank: number;
      /** Runs one source will cost for this target (ports × address families). */
      runsPerSource: number;
      /** Runs the round costs over every enabled source (`costOf`). */
      cost: number;
    }> = [];
    const sources = enabledSources(cfg, secrets);
    // The hour's spend counts EVERY run of the hour — cron, manual, detector,
    // qualification, whatever its state — not only the due candidates' runs.
    // (The plan's estimate; requestProbes re-checks and reserves atomically.)
    const spent = await spentThisHour(ctx.db, now, cfg.probe.hourlyBudget);
    const seen = new Set<string>();
    /** `dueSince`: a round requested at or after it is the one owed (a repeat). */
    const consider = async (
      target: ProbeTargetRef,
      interval: number,
      suspected: boolean,
      rank: number,
      dueSince?: number,
    ) => {
      const key = targetKeyOf(target);
      if (seen.has(key)) return;
      const newest = await ctx.db
        .query('probeRuns')
        .withIndex('by_target_requested', (q) =>
          q.eq('targetKind', target.kind).eq('targetRef', target.ref),
        )
        .order('desc')
        .first();
      const last = newest?.requestedAt ?? 0;
      if (dueSince !== undefined ? last >= dueSince : last !== 0 && now - last < interval) return;
      const resolved = await resolveTarget(ctx, target);
      // No address, or no listener port to aim at: not probeable (probing a
      // guessed port would record its silence as a block).
      if (!resolved || !hasAddress(resolved) || resolved.ports.length === 0) return;
      const families = familiesOf(resolved, cfg);
      const runsPerSource = families.length * resolved.ports.length;
      // No family any enabled source takes (an IPv6-only literal and check-host alone).
      if (runsPerSource === 0 || costOf(sources, families, resolved.ports.length) === 0) return;
      seen.add(key);
      dueTargets.push({
        target,
        suspected,
        rank,
        runsPerSource,
        cost: costOf(sources, families, resolved.ports.length),
      });
    };
    const probeable = (edge: Doc<'edges'> | null): edge is Doc<'edges'> =>
      !!edge &&
      edge.status === 'active' &&
      !!(edge.addresses.v4 || edge.addresses.v6 || edge.addresses.hostname);
    // Per-country checks: a blocked round waiting for its repeat goes first.
    if (cfg.country.enabled) {
      for (const due of await dueRepeatEdges(ctx.db, now)) {
        if (!probeable(await ctx.db.get(due.edgeId))) continue;
        await consider({ kind: 'edge', ref: due.edgeId }, 0, false, 0, due.repeatAt);
      }
    }
    const baseInterval = cfg.probe.intervalMinutes * MIN;
    for (const relay of relays) {
      const suspected = relay.suspicion?.state === 'suspected';
      const interval = suspected ? cfg.probe.suspectedIntervalMinutes * MIN : baseInterval;
      for (const edgeId of relay.publishedEdgeIds) {
        if (!edgeId) continue;
        const edge = await ctx.db.get(edgeId);
        // v6-only and hostname (L7) edges are probed too; `consider` applies
        // the family rules and skips a target with nothing to aim at.
        if (!probeable(edge)) continue;
        await consider({ kind: 'edge', ref: edgeId }, interval, suspected, suspected ? 1 : 2);
      }
      if (relay.probeNode)
        await consider({ kind: 'relay', ref: relay._id }, baseInterval, false, 2);
    }
    for (const t of await ctx.db
      .query('probeTargets')
      .withIndex('by_enabled', (q) => q.eq('enabled', true))
      .collect()) {
      await consider({ kind: 'custom', ref: t._id }, baseInterval, false, 2);
    }
    // Spares are checked from every country too (less often): a standby that
    // turns active gets its first round at the next tick, so what is known per
    // country is there before it is ever published.
    if (cfg.country.enabled) {
      const standbyInterval = cfg.country.standbyRecheckHours * 60 * MIN;
      for (const relay of relays)
        for (const edgeId of relay.standbyEdgeIds) {
          const edge = await ctx.db.get(edgeId);
          if (!probeable(edge) || edge.publication !== 'unpublished') continue;
          await consider({ kind: 'edge', ref: edgeId }, standbyInterval, false, 3);
        }
    }
    // Repeats, then suspected origins' edges, so a tight budget goes where it matters.
    dueTargets.sort((a, b) => a.rank - b.rank);
    return {
      enabled: cfg.probe.enabled,
      sources,
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
    const rounds = new Set<string>();
    for (const status of ['requested', 'running'] as const) {
      const rows = await ctx.db
        .query('probeRuns')
        .withIndex('by_status', (q) => q.eq('status', status))
        .take(200);
      for (const r of rows) {
        const since = Math.max(r.requestedAt, r.scheduledAt ?? 0, r.startedAt ?? 0);
        if (since + RUN_TIMEOUT_MS <= now) {
          await ctx.db.patch(r._id, { status: 'timeout', finishedAt: now, error: 'timeout' });
          if (r.roundId) rounds.add(r.roundId);
          n++;
        }
      }
    }
    // A timed-out run may be the last open one of its round.
    for (const roundId of rounds) await settleRoundIfDone(ctx, roundId, now);
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
        // One run per source per port per address family the source takes.
        if (spent + d.cost > plan.hourlyBudget) {
          skipped++;
          continue;
        }
        spent += d.cost;
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
