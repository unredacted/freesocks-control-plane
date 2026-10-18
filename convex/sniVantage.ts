/**
 * Checks of server names from inside a country, DB half (docs/edges.md "Checks
 * from inside a country"): the `sni-vantage` cron (at most ONE batch per tick,
 * plus a sweep), the batch lifecycle the executor (sniVantageOps.ts) drives,
 * the per-(name, country) evidence, auto-apply, and the operator's "check now"
 * and "apply". The only writer of `sniVantageProbes` and `sniVantageEvidence`.
 *
 * Safety rules that are code, not settings: only published L4 edges in front
 * of a REALITY listener, or origin nodes that opted into probing, are ever
 * dialled; an address the address-level probes find unreachable from the
 * country is skipped; a name, its control included, is never checked from a
 * country more often than the interval; every gate is checked again when the
 * executor runs; and nothing runs while edges are frozen for maintenance.
 * Audit payloads carry slugs, the country, the source and counts, never a
 * hostname or an address.
 */
import { ConvexError, v } from 'convex/values';
import {
  internalMutation,
  internalQuery,
  type MutationCtx,
  type QueryCtx,
} from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { internal } from './_generated/api';
import { writeAuditLog } from './lib/audit';
import { recordHeartbeat } from './cronHeartbeat';
import { EDGE_PLUMBING, resolveEdgeConfig, resolveEdgeSecrets } from './lib/edgeConfig';
import { admitted, assertAdmission } from './lib/edges/maintenance';
import { normalizeName } from './lib/edges/registration';
import { SUSPECT_DEFAULTS, dayOf, suspectNames, type NameCount } from './lib/edges/sni/health';
import {
  aggregateEvidence,
  countriesForTick,
  decide,
  pickBatchNames,
  pickTargetIndex,
  preferredTarget,
  rotateForTick,
  suggest,
  type AddressVerdict,
  type Mark,
  type Measurement,
  type PlanName,
} from './lib/edges/sni/vantage';
import type { VantageSource } from './lib/edges/probes/nameCheck';
import {
  resolveSniConfig,
  resolveSniVantageConfig,
  usableSources,
  vantageCountries,
  type SniVantageConfig,
} from './lib/sniConfig';
import { writeCountryMarks } from './sniFamilies';
import { lastBatchAt, noteNameBatch } from './edgeCountry';

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
/** The cron's cadence (crons.ts `sni-vantage`). */
export const TICK_MS = 10 * MIN;
/** A measurement still open this long after it was due is timed out. */
const RUN_TIMEOUT_MS = 15 * MIN;
/** Documents one planning pass may read (a read limit is a 500). */
const MAX_SCAN = 3000;
/** Measurements of one (name, country) read to refresh its evidence, newest first. */
const MAX_HISTORY = 40;
/** Rows read to learn which of a name's addresses it was checked on last. */
const MAX_TARGET_HISTORY = 30;
/** Evidence rows the sweep re-aggregates per run as their oldest measurement leaves the window. */
const AGE_PER_SWEEP = 20;
/** Batches whose last open rows timed out that one sweep settles. */
const SETTLE_PER_SWEEP = 5;
/** Names one "check now" may ask for. */
export const MANUAL_MAX_NAMES = 6;
/** A name checked from a country this recently is not checked again on request. */
const MANUAL_MIN_GAP_MS = HOUR;
/** Report rows read per country (newest days first). */
const REPORT_ROWS = 8000;

const refuse = (code: string, message: string): never => {
  throw new ConvexError({ code, message });
};

type Db = QueryCtx['db'];

// --- what can be dialled ------------------------------------------------------------------------

/** One member-facing address of one REALITY listener. */
interface Target {
  kind: 'edge' | 'relay';
  ref: string;
  address: string;
  port: number;
  /** `<kind>:<ref>:<address>:<port>`: what a measurement's evidence is pooled by. */
  key: string;
  listener: Doc<'relayListeners'>;
  /** The address-level verdict from the country being planned (null = none yet). */
  verdict: AddressVerdict;
  /** Per-country checks on: when this edge's address was last batched from there (null = never). */
  lastBatchAt?: number | null;
}

/** The address a measurement dialled, as evidence pools it (an address that moved is another one). */
export const targetKeyOf = (t: {
  kind?: string;
  targetKind?: string;
  ref?: string;
  targetRef?: string;
  address: string;
  port: number;
}) => `${t.kind ?? t.targetKind}:${t.ref ?? t.targetRef}:${t.address}:${t.port}`;

const isReality = (l: Doc<'relayListeners'> | null): l is Doc<'relayListeners'> =>
  !!l && l.security === 'reality' && !l.retired && l.enabled && l.deployed && l.transport === 'tcp';

function verdictIn(
  r: { byCountry: Array<{ country: string; verdict: string }> } | undefined,
  country: string,
): AddressVerdict {
  const v = r?.byCountry.find((c) => c.country === country)?.verdict;
  return v === 'reachable' || v === 'unreachable' || v === 'mixed' || v === 'unknown' ? v : null;
}

/**
 * Every address a check may dial, for one country: the published, active L4
 * edges of enabled origins in front of a REALITY listener, and the REALITY
 * listeners of origin nodes that opted into probing (`probeNode`). Nothing
 * else: a standby, a candidate, an L7 front or a fronted origin that did not
 * opt in is never dialled. Stable order (origin slug, pool index).
 */
async function targetsFor(db: Db, country: string): Promise<Target[]> {
  const countryChecks = (await resolveEdgeConfig(db)).country.enabled;
  const relays = (
    await db
      .query('relays')
      .withIndex('by_enabled', (q) => q.eq('enabled', true))
      .collect()
  ).sort((a, b) => a.slug.localeCompare(b.slug));
  const out: Target[] = [];
  const push = (t: Omit<Target, 'key'>) => out.push({ ...t, key: targetKeyOf(t) });
  for (const relay of relays) {
    for (const edgeId of relay.publishedEdgeIds) {
      if (!edgeId) continue;
      const edge = await db.get(edgeId);
      if (!edge || edge.status !== 'active' || edge.publication !== 'published') continue;
      if (edge.addresses.hostname || edge.layer === 'l7') continue;
      const address = edge.addresses.v4 ?? edge.addresses.v6;
      if (!address) continue;
      const listener = await db.get(edge.listenerId);
      if (!isReality(listener)) continue;
      push({
        kind: 'edge',
        ref: edge._id,
        address,
        port: edge.listeners[0]?.edgePort ?? 443,
        listener,
        verdict: verdictIn(edge.reachability, country),
        ...(countryChecks ? { lastBatchAt: await lastBatchAt(db, edge._id, country) } : {}),
      });
    }
    if (relay.probeNode) {
      const listeners = await db
        .query('relayListeners')
        .withIndex('by_relay', (q) => q.eq('relayId', relay._id))
        .collect();
      for (const l of listeners.sort((a, b) => a.listenerKey.localeCompare(b.listenerKey))) {
        if (!isReality(l)) continue;
        push({
          kind: 'relay',
          ref: relay._id,
          address: relay.originAddress,
          port: l.originPort,
          listener: l,
          verdict: verdictIn(relay.reachability, country),
        });
      }
    }
  }
  return out;
}

/** Group targets by listener (edges of one listener carry the same names) and pick one each. */
function oneTargetPerListener(targets: readonly Target[]): Target[] {
  const byListener = new Map<string, Target[]>();
  for (const t of targets) {
    const k = t.listener._id as string;
    byListener.set(k, [...(byListener.get(k) ?? []), t]);
  }
  const out: Target[] = [];
  for (const group of byListener.values()) {
    const i = pickTargetIndex(
      group.map((t) => t.verdict),
      group.some((t) => t.lastBatchAt !== undefined)
        ? group.map((t) => t.lastBatchAt ?? null)
        : undefined,
    );
    if (i >= 0) out.push(group[i]!);
  }
  return out;
}

const activeNames = (l: Doc<'relayListeners'>) =>
  (l.tlsNames ?? []).filter((n) => n.status === 'active').map((n) => n.name);

/** name -> the keys of the addresses carrying it, in the stable target order. */
function carriersOf(targets: readonly Target[]): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const t of targets)
    for (const name of activeNames(t.listener)) out.set(name, [...(out.get(name) ?? []), t.key]);
  return out;
}

/** address key -> when this name was last put into a batch there, for this country. */
async function lastByTarget(db: Db, name: string, country: string) {
  const rows = await db
    .query('sniVantageProbes')
    .withIndex('by_name_country_requested', (q) => q.eq('name', name).eq('country', country))
    .order('desc')
    .take(MAX_TARGET_HISTORY);
  const out = new Map<string, number>();
  for (const r of rows) {
    const k = targetKeyOf(r);
    out.set(k, Math.max(out.get(k) ?? 0, r.requestedAt));
  }
  return { last: out, read: rows.length };
}

// --- reports, the other evidence --------------------------------------------------------------------

/** One country's attributed report counts in the window, newest days first, bounded per country. */
async function reportCounts(db: Db, country: string, windowDays: number, now: number) {
  const since = dayOf(now - windowDays * DAY);
  const out: NameCount[] = [];
  for (const row of await db
    .query('sniReportCounts')
    .withIndex('by_country_day', (q) => q.eq('country', country).gte('day', since))
    .order('desc')
    .take(REPORT_ROWS))
    out.push({ name: row.name, country: row.country, weight: row.weight });
  return out;
}

/** The names of one family that member reports single out in `country` (`suspectNames`). */
async function reportSuspects(
  db: Db,
  familyId: Id<'sniFamilies'>,
  country: string,
  now: number,
): Promise<Set<string>> {
  const { reportWindowDays } = await resolveSniConfig(db);
  const mine = new Set(
    (
      await db
        .query('sniNames')
        .withIndex('by_family_seq', (q) => q.eq('familyId', familyId))
        .collect()
    ).map((n) => n.name),
  );
  const counts = (await reportCounts(db, country, reportWindowDays, now)).filter((c) =>
    mine.has(c.name),
  );
  const out = new Set<string>();
  for (const [name, countries] of suspectNames(counts))
    if (countries.includes(country)) out.add(name);
  return out;
}

async function markOf(db: Db, name: string, country: string): Promise<Mark | null> {
  const row = await db
    .query('sniNameCountry')
    .withIndex('by_name_country', (q) => q.eq('name', name).eq('country', country))
    .unique();
  return row ? { state: row.state, source: row.source } : null;
}

const evidenceOf = (db: Db, name: string, country: string) =>
  db
    .query('sniVantageEvidence')
    .withIndex('by_name_country', (q) => q.eq('name', name).eq('country', country))
    .unique();

/** A family name that may be checked: active, qualified, its family enabled. */
async function checkableName(
  db: Db,
  name: string,
  families: Map<string, boolean>,
): Promise<Doc<'sniNames'> | null> {
  const n = await db
    .query('sniNames')
    .withIndex('by_name', (q) => q.eq('name', name))
    .unique();
  if (!n || n.status !== 'active' || n.qualification.state !== 'ok') return null;
  const key = n.familyId as string;
  if (!families.has(key)) families.set(key, (await db.get(n.familyId))?.enabled ?? false);
  return families.get(key) ? n : null;
}

// --- budget -----------------------------------------------------------------------------------------

async function spentThisHour(db: Db, now: number, budget: number): Promise<number> {
  return (
    await db
      .query('sniVantageProbes')
      .withIndex('by_requested', (q) => q.gte('requestedAt', now - HOUR))
      .take(budget + 1)
  ).length;
}

// --- starting a batch -------------------------------------------------------------------------------

interface BatchPlan {
  target: Target;
  country: string;
  names: Doc<'sniNames'>[];
}

async function startBatch(
  ctx: MutationCtx,
  plan: BatchPlan,
  sources: VantageSource[],
  trigger: 'cron' | 'manual',
  now: number,
): Promise<{ batch: string; measurements: number }> {
  const { target, country } = plan;
  // The port too: one origin can have two REALITY listeners on one address.
  const batch = `${target.kind}:${target.ref}:${target.port}:${country}:${now}`;
  let measurements = 0;
  for (const source of sources) {
    for (const n of plan.names) {
      await ctx.db.insert('sniVantageProbes', {
        name: n.name,
        familyId: n.familyId,
        country,
        source,
        batch,
        targetKind: target.kind,
        targetRef: target.ref,
        address: target.address,
        port: target.port,
        trigger,
        status: 'requested',
        requestedAt: now,
        scheduledAt: now,
        results: [],
      });
      measurements++;
    }
    // One executor per source; calls inside it are spaced (probe.sourceSpacingMs).
    await ctx.scheduler.runAfter(0, internal.sniVantageOps.executeBatch, { batch, source });
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'edge.sni.vantage.batch',
      targetType: 'sni_vantage',
      payload: { country, source, targetKind: target.kind, count: plan.names.length, trigger },
    });
  }
  // The interval's clock, for every name of the batch (its control included):
  // none of them is due again until the interval passes.
  for (const n of plan.names) {
    const ev = await evidenceOf(ctx.db, n.name, country);
    if (ev) await ctx.db.patch(ev._id, { lastRequestedAt: now });
    else
      await ctx.db.insert('sniVantageEvidence', {
        familyId: n.familyId,
        name: n.name,
        country,
        lastRequestedAt: now,
        measurements: 0,
        okVantages: 0,
        okNetworks: 0,
        latest: 'none',
        updatedAt: now,
      });
  }
  return { batch, measurements };
}

/**
 * The cron's one batch for one country. Listeners are scanned from a position
 * that rotates every tick (the scan is bounded; it must not always stop on the
 * same prefix). A name is due when it was not checked from there within the
 * interval, and it is due on ONE of its addresses: the one it was checked on
 * longest ago. The first listener with a batch that member reports point at
 * wins, else the first with any batch (`pickBatchNames`; a lone due name with
 * no spare control waits).
 */
async function planForCountry(
  db: Db,
  country: string,
  cfg: SniVantageConfig,
  now: number,
): Promise<BatchPlan | null> {
  const { reportWindowDays } = await resolveSniConfig(db);
  const weights = new Map<string, number>();
  const reports = await reportCounts(db, country, reportWindowDays, now);
  for (const c of reports) weights.set(c.name, (weights.get(c.name) ?? 0) + c.weight);
  let reads = reports.length;
  const dueBefore = now - cfg.intervalHours * HOUR;
  const families = new Map<string, boolean>();
  const all = oneTargetPerListener(await targetsFor(db, country));
  const carriers = carriersOf(all);
  const seen = new Map<
    string,
    { n: Doc<'sniNames'> | null; ev: Doc<'sniVantageEvidence'> | null; prefers?: string | null }
  >();
  let first: BatchPlan | null = null;
  for (const target of rotateForTick(all, now, TICK_MS)) {
    const candidates: PlanName[] = [];
    const docs = new Map<string, Doc<'sniNames'>>();
    for (const name of activeNames(target.listener)) {
      if (reads > MAX_SCAN) break;
      let s = seen.get(name);
      if (!s) {
        const n = await checkableName(db, name, families);
        s = { n, ev: n ? await evidenceOf(db, name, country) : null };
        seen.set(name, s);
        reads += 2;
      }
      if (!s.n) continue;
      const dueAnywhere = !s.ev || s.ev.lastRequestedAt <= dueBefore;
      const keys = carriers.get(name) ?? [];
      if (dueAnywhere && keys.length > 1 && s.prefers === undefined) {
        const h = await lastByTarget(db, name, country);
        s.prefers = preferredTarget(keys, h.last);
        reads += h.read + 1;
      }
      docs.set(name, s.n);
      candidates.push({
        name,
        seq: s.n.seq,
        due: dueAnywhere && (keys.length <= 1 || s.prefers === target.key),
        spare: dueAnywhere,
        priority: (weights.get(name) ?? 0) >= SUSPECT_DEFAULTS.minWeight,
        lastRequestedAt: s.ev?.lastRequestedAt ?? null,
        lastOkAt: s.ev?.lastOkAt ?? null,
      });
    }
    const picked = pickBatchNames(candidates, cfg.batchNames);
    if (picked.length > 0) {
      const plan = { target, country, names: picked.map((n) => docs.get(n)!) };
      if (candidates.some((c) => c.due && c.priority && picked.includes(c.name))) return plan;
      first ??= plan;
    }
    if (reads > MAX_SCAN) break;
  }
  return first;
}

/** Trim a batch to what the hour still allows; a batch keeps its control or does not run. */
function fitToBudget(names: Doc<'sniNames'>[], sources: number, remaining: number) {
  const max = Math.floor(remaining / Math.max(1, sources));
  if (max <= 0) return [];
  if (names.length >= 2 && max < 2) return [];
  return names.slice(0, max);
}

// --- the cron -------------------------------------------------------------------------------------------

export const tick = internalMutation({
  args: { now: v.optional(v.number()) },
  handler: async (ctx, a) => {
    await recordHeartbeat(ctx, 'sni-vantage');
    const now = a.now ?? Date.now();
    // Housekeeping in its own transaction (its own read budget).
    await ctx.scheduler.runAfter(0, internal.sniVantage.sweep, {});
    const cfg = await resolveSniVantageConfig(ctx.db);
    const sni = await resolveSniConfig(ctx.db);
    const idle = (reason: string) => ({ started: 0, measurements: 0, reason });
    if (!sni.enabled || !cfg.enabled) return idle('off');
    if (!(await admitted(ctx.db))) return idle('maintenance');
    const countries = vantageCountries(cfg, sni.curatedCountries);
    if (countries.length === 0) return idle('no_country');
    const sources = usableSources(cfg, await resolveEdgeSecrets(ctx.db));
    if (sources.length === 0) return idle('no_source');
    const remaining = cfg.hourlyBudget - (await spentThisHour(ctx.db, now, cfg.hourlyBudget));
    if (remaining <= 0) return idle('budget');
    for (const country of countriesForTick(countries, now, TICK_MS)) {
      const plan = await planForCountry(ctx.db, country, cfg, now);
      if (!plan) continue;
      const names = fitToBudget(plan.names, sources.length, remaining);
      if (names.length === 0) return idle('budget');
      const r = await startBatch(ctx, { ...plan, names }, sources, 'cron', now);
      return { started: 1, measurements: r.measurements, reason: null };
    }
    return idle('nothing_due');
  },
});

/**
 * Housekeeping, every tick: measurements left open past their ceiling time out
 * (and a batch whose last open rows timed out is settled, so its auto-apply is
 * not lost); evidence whose oldest measurement has left the window is
 * aggregated again (a suggestion must never outlive the measurements it rests
 * on); rows past the window are deleted. Each part is bounded per run.
 */
export const sweep = internalMutation({
  args: { now: v.optional(v.number()) },
  handler: async (ctx, a) => {
    const now = a.now ?? Date.now();
    const cfg = await resolveSniVantageConfig(ctx.db);
    const cutoff = now - cfg.windowDays * DAY;
    let timedOut = 0;
    const touched = new Set<string>();
    for (const status of ['requested', 'running'] as const) {
      const rows = await ctx.db
        .query('sniVantageProbes')
        .withIndex('by_status_requested', (q) => q.eq('status', status))
        .take(100);
      for (const r of rows)
        if (Math.max(r.scheduledAt, r.startedAt ?? 0) + RUN_TIMEOUT_MS <= now) {
          await ctx.db.patch(r._id, { status: 'timeout', finishedAt: now, error: 'timeout' });
          touched.add(r.batch);
          timedOut++;
        }
    }
    for (const batch of [...touched].slice(0, SETTLE_PER_SWEEP)) await settleBatch(ctx, batch, now);
    const old = await ctx.db
      .query('sniVantageProbes')
      .withIndex('by_requested', (q) => q.lt('requestedAt', cutoff))
      .take(200);
    for (const r of old) await ctx.db.delete(r._id);
    // `gt(0)` keeps rows with no measurement in the window out of the range.
    const aging = await ctx.db
      .query('sniVantageEvidence')
      .withIndex('by_oldest', (q) => q.gt('oldestAt', 0).lt('oldestAt', cutoff))
      .take(AGE_PER_SWEEP);
    for (const ev of aging) await refreshEvidence(ctx, ev.name, ev.country, now);
    return { timedOut, deleted: old.length, aged: aging.length };
  },
});

// --- the executor's half ------------------------------------------------------------------------------

/**
 * What the executor needs, with every gate and every row's target checked
 * again NOW: between the plan and the run, checks may have been switched off,
 * the country or the source taken out, or edges frozen. A closed gate comes
 * back as `gate` and the executor settles the rows without dialling anything.
 */
export const batchContext = internalQuery({
  args: { batch: v.string(), source: v.union(v.literal('globalping'), v.literal('ripeatlas')) },
  handler: async (ctx, { batch, source }) => {
    const rows = (
      await ctx.db
        .query('sniVantageProbes')
        .withIndex('by_batch_source', (q) => q.eq('batch', batch).eq('source', source))
        .collect()
    ).filter((r) => r.status === 'requested');
    if (rows.length === 0) return null;
    const cfg = await resolveSniVantageConfig(ctx.db);
    const sni = await resolveSniConfig(ctx.db);
    const edgeCfg = await resolveEdgeConfig(ctx.db);
    const secrets = await resolveEdgeSecrets(ctx.db);
    const country = rows[0]!.country;
    const gate =
      !sni.enabled || !cfg.enabled
        ? 'gate_off'
        : !vantageCountries(cfg, sni.curatedCountries).includes(country)
          ? 'gate_country'
          : !usableSources(cfg, secrets).includes(source)
            ? 'gate_source'
            : !(await admitted(ctx.db))
              ? 'gate_maintenance'
              : null;
    const current = gate
      ? []
      : (await targetsFor(ctx.db, country)).filter(
          (t) => t.kind === rows[0]!.targetKind && t.ref === rows[0]!.targetRef,
        );
    return {
      gate,
      country,
      perCountryLimit: cfg.perCountryLimit,
      preferEyeball: edgeCfg.probe.preferEyeball,
      spacingMs: EDGE_PLUMBING.probeSourceSpacingMs,
      secrets,
      rows: rows.map((r) => ({
        id: r._id,
        name: r.name,
        address: r.address,
        port: r.port,
        // The address moved, the listener went, or the name left it: not dialled.
        valid: current.some(
          (t) =>
            t.address === r.address &&
            t.port === r.port &&
            activeNames(t.listener).includes(r.name),
        ),
      })),
    };
  },
});

export const markRunning = internalMutation({
  args: { ids: v.array(v.id('sniVantageProbes')) },
  handler: async (ctx, { ids }) => {
    const now = Date.now();
    for (const id of ids) {
      const r = await ctx.db.get(id);
      if (r?.status === 'requested') await ctx.db.patch(id, { status: 'running', startedAt: now });
    }
    return null;
  },
});

const vantageResult = v.object({
  asn: v.optional(v.string()),
  network: v.optional(v.string()),
  vantageClass: v.union(v.literal('eyeball'), v.literal('datacenter'), v.literal('unknown')),
  outcome: v.union(
    v.literal('ok'),
    v.literal('answered'),
    v.literal('cert_mismatch'),
    v.literal('reset'),
    v.literal('timeout'),
    v.literal('refused'),
    v.literal('error'),
  ),
  rttMs: v.optional(v.number()),
  error: v.optional(v.string()),
});

const isOpen = (r: Doc<'sniVantageProbes'> | null) =>
  !!r && (r.status === 'requested' || r.status === 'running');

/** Settle one source's measurements of a batch, then the batch. */
export const finishBatch = internalMutation({
  args: {
    batch: v.string(),
    done: v.array(
      v.object({
        id: v.id('sniVantageProbes'),
        externalId: v.optional(v.string()),
        results: v.array(vantageResult),
      }),
    ),
    failed: v.array(v.object({ id: v.id('sniVantageProbes'), error: v.string() })),
  },
  handler: async (ctx, a) => {
    const now = Date.now();
    for (const d of a.done) {
      const r = await ctx.db.get(d.id);
      if (!isOpen(r) || r!.batch !== a.batch) continue;
      await ctx.db.patch(d.id, {
        status: 'finished',
        finishedAt: now,
        results: d.results.slice(0, 20),
        ...(d.externalId ? { externalId: d.externalId.slice(0, 120) } : {}),
      });
    }
    for (const f of a.failed) {
      const r = await ctx.db.get(f.id);
      if (!isOpen(r) || r!.batch !== a.batch) continue;
      await ctx.db.patch(f.id, {
        status: f.error === 'timeout' ? 'timeout' : 'failed',
        finishedAt: now,
        error: f.error.slice(0, 40),
      });
    }
    await settleBatch(ctx, a.batch, now);
    return null;
  },
});

/**
 * Refresh every name of a batch (what the page shows follows each source as it
 * lands), and auto-apply only once EVERY source of the batch has settled: the
 * sources are one look, and a first source's answer is not the batch's.
 */
async function settleBatch(ctx: MutationCtx, batch: string, now: number) {
  const rows = await ctx.db
    .query('sniVantageProbes')
    .withIndex('by_batch_source', (q) => q.eq('batch', batch))
    .collect();
  if (rows.length === 0) return;
  const country = rows[0]!.country;
  const names = [...new Map(rows.map((r) => [r.name, r.familyId])).entries()];
  for (const [name] of names) await refreshEvidence(ctx, name, country, now);
  if (rows.some(isOpen)) return;
  await autoApply(ctx, names, country, now);
  // The whole look, every source settled: what it says about the ADDRESS from
  // there feeds the edge's handshake track (edgeCountry.ts; a batch in which no
  // name got through is an address fact only when paired with working TCP).
  const first = rows[0]!;
  await noteNameBatch(ctx, {
    targetKind: first.targetKind,
    targetRef: first.targetRef,
    address: first.address,
    port: first.port,
    country,
    measurements: rows
      .filter((r) => r.status === 'finished')
      .map((r) => ({ name: r.name, results: r.results })),
    at: Math.max(...rows.map((r) => r.finishedAt ?? r.requestedAt)),
  });
}

/**
 * Re-aggregate one (name, country) from its measurements inside the window
 * and their batches' controls. Only measurements taken while the name was in
 * its CURRENT family count (a name removed and imported elsewhere starts over).
 */
async function refreshEvidence(ctx: MutationCtx, name: string, country: string, now: number) {
  const cfg = await resolveSniVantageConfig(ctx.db);
  const current = await ctx.db
    .query('sniNames')
    .withIndex('by_name', (q) => q.eq('name', name))
    .unique();
  const ev = await evidenceOf(ctx.db, name, country);
  if (!current) {
    if (ev) await ctx.db.delete(ev._id);
    return;
  }
  const own = (
    await ctx.db
      .query('sniVantageProbes')
      .withIndex('by_name_country_requested', (q) =>
        q
          .eq('name', name)
          .eq('country', country)
          .gte('requestedAt', now - cfg.windowDays * DAY),
      )
      .order('desc')
      .take(MAX_HISTORY)
  ).filter((r) => r.status === 'finished' && r.familyId === current.familyId);
  const measurements = new Map<string, Measurement>();
  const toMeasurement = (r: Doc<'sniVantageProbes'>): Measurement => ({
    batch: r.batch,
    source: r.source,
    target: targetKeyOf(r),
    name: r.name,
    at: r.finishedAt ?? r.requestedAt,
    results: r.results,
  });
  for (const r of own) measurements.set(r._id, toMeasurement(r));
  for (const batch of new Set(own.map((r) => r.batch)))
    for (const r of await ctx.db
      .query('sniVantageProbes')
      .withIndex('by_batch_source', (q) => q.eq('batch', batch))
      .collect())
      if (r.status === 'finished') measurements.set(r._id, toMeasurement(r));
  const agg = aggregateEvidence(name, [...measurements.values()], ev?.everOkAt ?? null);
  const everOkAt = Math.max(ev?.everOkAt ?? 0, agg.lastOkAt ?? 0) || undefined;
  const row = {
    familyId: current.familyId,
    measurements: agg.measurements,
    okVantages: agg.okVantages,
    okNetworks: agg.okNetworks,
    lastOkAt: agg.lastOkAt ?? undefined,
    everOkAt,
    lastFailAt: agg.lastFailAt ?? undefined,
    lastAt: agg.lastAt ?? undefined,
    // When the aggregate must be redone: its oldest measurement leaves the window.
    oldestAt: own.length > 0 ? Math.min(...own.map((r) => r.requestedAt)) : undefined,
    latest: agg.latest,
    streak: agg.streak ?? undefined,
    updatedAt: now,
  };
  // `undefined` removes a field: a streak that ended is gone, not kept stale.
  if (ev) await ctx.db.patch(ev._id, row);
  else await ctx.db.insert('sniVantageEvidence', { name, country, lastRequestedAt: now, ...row });
}

/**
 * Would marking `name` blocked in `country` leave some listener that carries it
 * with no name usable from there? Then it is not applied by itself.
 */
async function wouldEmptyListener(db: Db, name: string, country: string): Promise<boolean> {
  for (const l of await db.query('relayListeners').collect()) {
    if (l.retired) continue;
    const active = (l.tlsNames ?? []).filter((n) => n.status === 'active');
    if (!active.some((n) => n.name === name)) continue;
    const left = active.filter((n) => n.name !== name && !(n.blockedIn ?? []).includes(country));
    if (left.length === 0) return true;
  }
  return false;
}

/**
 * `edge.sni.vantage.autoApply`: write the suggestion as a `probe` mark where
 * nobody has judged the name there or the checks judged it themselves; never
 * over an operator's mark, never a `blocked` that would empty a listener.
 */
async function autoApply(
  ctx: MutationCtx,
  names: Array<[string, Id<'sniFamilies'>]>,
  country: string,
  now: number,
) {
  const cfg = await resolveSniVantageConfig(ctx.db);
  const sni = await resolveSniConfig(ctx.db);
  if (!cfg.autoApply || !cfg.enabled || !sni.enabled) return;
  if (!vantageCountries(cfg, sni.curatedCountries).includes(country)) return;
  const suspects = new Map<string, Set<string>>();
  const applied = new Map<
    string,
    { slug: string; proven: string[]; blocked: string[]; held: number }
  >();
  for (const [name] of names) {
    const ev = await evidenceOf(ctx.db, name, country);
    if (!ev) continue;
    const familyId = ev.familyId;
    const key = familyId as string;
    if (!suspects.has(key)) suspects.set(key, await reportSuspects(ctx.db, familyId, country, now));
    const s = suggest(evidenceShape(ev), {
      reportSuspect: suspects.get(key)!.has(name),
      minVantages: cfg.minVantages,
      minNetworks: cfg.minNetworks,
    });
    if (decide(s.suggestion, await markOf(ctx.db, name, country)) !== 'suggest' || !s.suggestion)
      continue;
    const fam = await ctx.db.get(familyId);
    if (!fam) continue;
    const at = applied.get(key) ?? { slug: fam.slug, proven: [], blocked: [], held: 0 };
    applied.set(key, at);
    if (s.suggestion === 'proven') {
      at.proven.push(name);
      continue;
    }
    // One block at a time, each written before the next is weighed: two names
    // of one listener must not both pass the "would it empty it" check.
    if (await wouldEmptyListener(ctx.db, name, country)) at.held++;
    else {
      await writeCountryMarks(ctx, [name], country, 'blocked', 'probe');
      at.blocked.push(name);
    }
  }
  for (const at of applied.values()) {
    if (at.proven.length > 0) await writeCountryMarks(ctx, at.proven, country, 'proven', 'probe');
    for (const state of ['proven', 'blocked'] as const) {
      const count = at[state].length;
      if (count === 0 && !(state === 'blocked' && at.held > 0)) continue;
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'edge.sni.vantage.auto_apply',
        targetType: 'sni_family',
        payload: { slug: at.slug, country, state, count, held: state === 'blocked' ? at.held : 0 },
      });
    }
  }
}

/** A stored evidence row in the shape the pure scoring reads. */
export function evidenceShape(ev: Doc<'sniVantageEvidence'>) {
  return {
    measurements: ev.measurements,
    okVantages: ev.okVantages,
    okNetworks: ev.okNetworks,
    lastOkAt: ev.lastOkAt ?? null,
    lastFailAt: ev.lastFailAt ?? null,
    lastAt: ev.lastAt ?? null,
    latest: ev.latest,
    streak: ev.streak ?? null,
  };
}

// --- the operator's buttons -------------------------------------------------------------------------

async function familyNames(db: Db, slug: string, names: readonly string[]) {
  const f = await db
    .query('sniFamilies')
    .withIndex('by_slug', (q) => q.eq('slug', slug))
    .unique();
  if (!f) return refuse('not_found', 'No such family');
  const wanted = [...new Set(names.map((n) => normalizeName(n)).filter((n): n is string => !!n))];
  const rows: Doc<'sniNames'>[] = [];
  for (const name of wanted) {
    const n = await db
      .query('sniNames')
      .withIndex('by_name', (q) => q.eq('name', name))
      .unique();
    if (n && n.familyId === f._id) rows.push(n);
  }
  return { family: f, rows };
}

/**
 * "Check now" for picked names from one country: the same gates as the cron
 * (switch, opted-in country, a usable source, no maintenance freeze), the same
 * budget, one batch per address (each name on the address it was checked on
 * longest ago). A lone name gets a control that was not checked from there
 * within the hour either, else it goes alone. A name checked from there within
 * the last hour is skipped.
 */
export const requestNow = internalMutation({
  args: {
    slug: v.string(),
    names: v.array(v.string()),
    country: v.string(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    await assertAdmission(ctx.db, 'probe.request');
    const now = Date.now();
    const country = a.country.trim().toUpperCase();
    const sni = await resolveSniConfig(ctx.db);
    const cfg = await resolveSniVantageConfig(ctx.db);
    if (!sni.enabled || !cfg.enabled)
      refuse('edge.sni.vantage_off', 'Checks from inside countries are switched off');
    if (!vantageCountries(cfg, sni.curatedCountries).includes(country))
      refuse('edge.sni.vantage_country', 'That country is not opted in to checks');
    const sources = usableSources(cfg, await resolveEdgeSecrets(ctx.db));
    if (sources.length === 0)
      refuse('edge.sni.vantage_no_source', 'No measurement source is usable');
    if (a.names.length === 0 || a.names.length > MANUAL_MAX_NAMES)
      refuse('validation', `Pick 1 to ${MANUAL_MAX_NAMES} names`);
    const { family, rows } = await familyNames(ctx.db, a.slug, a.names);
    const families = new Map<string, boolean>();
    const recent = (ev: Doc<'sniVantageEvidence'> | null) =>
      !!ev && ev.lastRequestedAt > now - MANUAL_MIN_GAP_MS;
    const picked: Doc<'sniNames'>[] = [];
    let skipped = 0;
    for (const n of rows) {
      if (!(await checkableName(ctx.db, n.name, families))) skipped++;
      else if (recent(await evidenceOf(ctx.db, n.name, country))) skipped++;
      else picked.push(n);
    }
    if (picked.length === 0)
      refuse('edge.sni.vantage_too_soon', 'Nothing to check: those names were checked just now');
    const targets = oneTargetPerListener(await targetsFor(ctx.db, country));
    const carriers = carriersOf(targets);
    const plans = new Map<string, BatchPlan>();
    for (const n of picked) {
      const keys = carriers.get(n.name) ?? [];
      const key =
        keys.length > 1
          ? preferredTarget(keys, (await lastByTarget(ctx.db, n.name, country)).last)
          : (keys[0] ?? null);
      const t = targets.find((x) => x.key === key);
      if (!t) {
        skipped++;
        continue;
      }
      const plan = plans.get(t.key) ?? { target: t, country, names: [] };
      plan.names.push(n);
      plans.set(t.key, plan);
    }
    if (plans.size === 0)
      refuse('edge.sni.vantage_no_target', 'No published address carries those names');
    for (const plan of plans.values()) {
      if (plan.names.length !== 1) continue;
      const lone = plan.names[0]!;
      const candidates: PlanName[] = [
        {
          name: lone.name,
          seq: lone.seq,
          due: true,
          spare: true,
          priority: false,
          lastRequestedAt: null,
          lastOkAt: null,
        },
      ];
      const docs = new Map<string, Doc<'sniNames'>>();
      for (const name of activeNames(plan.target.listener)) {
        if (name === lone.name || candidates.length > 20) continue;
        const n = await checkableName(ctx.db, name, families);
        if (!n) continue;
        const ev = await evidenceOf(ctx.db, name, country);
        docs.set(name, n);
        candidates.push({
          name,
          seq: n.seq,
          due: false,
          spare: !recent(ev),
          priority: false,
          lastRequestedAt: ev?.lastRequestedAt ?? null,
          lastOkAt: ev?.lastOkAt ?? null,
        });
      }
      const control = pickBatchNames(candidates, 1)[1];
      if (control) plan.names.push(docs.get(control)!);
    }
    const cost = [...plans.values()].reduce((s, p) => s + p.names.length * sources.length, 0);
    if (cost > cfg.hourlyBudget - (await spentThisHour(ctx.db, now, cfg.hourlyBudget)))
      refuse('edge.sni.vantage_budget', 'The hourly budget for checks is spent; try again later');
    let measurements = 0;
    for (const plan of plans.values())
      measurements += (await startBatch(ctx, plan, sources, 'manual', now)).measurements;
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'edge.sni.vantage.request',
      targetType: 'sni_family',
      payload: { slug: family.slug, country, count: picked.length, batches: plans.size },
    });
    return { batches: plans.size, measurements, skipped };
  },
});

/**
 * "Apply": record each picked name's CURRENT suggestion from `country` as the
 * operator's own mark (it is their judgement now). Names without a suggestion,
 * or whose mark already says the same, are left alone and counted.
 */
export const applySuggestions = internalMutation({
  args: {
    slug: v.string(),
    names: v.array(v.string()),
    country: v.string(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const country = a.country.trim().toUpperCase();
    const sni = await resolveSniConfig(ctx.db);
    if (!sni.curatedCountries.includes(country))
      refuse('edge.sni.country_not_curated', 'That country is not on the curated list');
    const cfg = await resolveSniVantageConfig(ctx.db);
    const { family, rows } = await familyNames(ctx.db, a.slug, a.names);
    const suspects = await reportSuspects(ctx.db, family._id, country, Date.now());
    const by: Record<'proven' | 'blocked', string[]> = { proven: [], blocked: [] };
    let skipped = 0;
    for (const n of rows) {
      const ev = await evidenceOf(ctx.db, n.name, country);
      const s = ev
        ? suggest(evidenceShape(ev), {
            reportSuspect: suspects.has(n.name),
            minVantages: cfg.minVantages,
            minNetworks: cfg.minNetworks,
          })
        : null;
      const mark = await markOf(ctx.db, n.name, country);
      if (!s?.suggestion || (mark?.state === s.suggestion && mark.source === 'operator')) {
        skipped++;
        continue;
      }
      by[s.suggestion].push(n.name);
    }
    for (const state of ['proven', 'blocked'] as const)
      if (by[state].length > 0) await writeCountryMarks(ctx, by[state], country, state, 'operator');
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'edge.sni.vantage.apply',
      targetType: 'sni_family',
      payload: {
        slug: family.slug,
        country,
        proven: by.proven.length,
        blocked: by.blocked.length,
      },
    });
    return { proven: by.proven.length, blocked: by.blocked.length, skipped };
  },
});
