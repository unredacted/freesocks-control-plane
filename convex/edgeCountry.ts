/**
 * Per-country checks of edges, DB half (docs/edges.md "Countries: checks and
 * delivery"): settling a probe ROUND into the address track, a #126 name
 * batch into the handshake track, the (provider, location) grades, operator
 * marks, the effective state copied onto `edges.countryState`, the expiry
 * worker, and the reads the setup runs, rotations and the admin use. The only
 * writer of `edgeCountryEvidence`, `countryGroupGrades`, `countryMarks` and
 * `edges.countryState`. The pure rules live in lib/edges/country/.
 *
 * Dormant behind `edge.country.enabled`: with it off nothing here records
 * anything (the expiry worker still lets old rows lapse).
 *
 * Infrastructure only: an operator-owned edge, third-party vantages and the
 * operator's marks. No member data anywhere; audit payloads carry slugs,
 * countries and states, never an address or a hostname.
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { DatabaseReader, MutationCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { recordHeartbeat } from './cronHeartbeat';
import {
  EDGE_PLUMBING,
  controlCountriesOf,
  resolveEdgeConfig,
  type EdgeConfig,
} from './lib/edgeConfig';
import { liveEdgesOfRelay } from './lib/edges/relayGuards';
import { edgeOutage, sustainedCountriesOf } from './lib/edges/probes/sustained';
import { resolveCensoredCountries } from './lib/censoredCountries';
import { resolveSniVantageConfig } from './lib/sniConfig';
import { addressFamily } from './lib/edges/ip';
import {
  EMPTY_ADDRESS_TRACK,
  EMPTY_HANDSHAKE_TRACK,
  batchReading,
  combinedState,
  expireAddressTrack,
  expireHandshakeTrack,
  nextAddressTrack,
  nextHandshakeTrack,
  roundVerdict,
  stateUntil,
  trackUntil,
  type AddressTrack,
  type BatchMeasurement,
  type HandshakeTrack,
  type PathFamily,
  type RoundRun,
  type TrackState,
} from './lib/edges/country/verdict';
import {
  countryGroupKey,
  effectiveState,
  gradeOf,
  liveCountryState,
  providerOfGroup,
  type GroupGrade,
} from './lib/edges/country/group';

const DAY = 24 * 60 * 60_000;
/** Rows one expiry pass handles per step before it schedules itself again. */
const EXPIRY_PAGE = 200;
const MAX_EXPIRY_ROUNDS = 20;
/**
 * (group, country) pairs one expiry step regrades, and edges whose copied
 * state it rewrites (5 reads each): the rest continue in their own
 * transaction (`settleExpiry`), so a run stays inside one execution's reads.
 */
const PAIRS_PER_STEP = 50;
const EDGES_PER_STEP = 200;

type Evidence = Doc<'edgeCountryEvidence'>;

const isL7 = (e: Doc<'edges'>) => e.layer === 'l7' || !!e.addresses.hostname;

/** `ip:port` / `[v6]:port` / `name:port` as a run stored it. */
function addressOfRun(target: string): string {
  const m = /^\[?([^\]]+?)\]?:(\d+)$/.exec(target);
  return m ? m[1]! : target;
}

function familyOfRun(r: Doc<'probeRuns'>): PathFamily {
  if (r.ipVersion !== undefined) return r.ipVersion;
  return r.addressKind === 'name' ? 'name' : 4;
}

function portOfRun(r: Doc<'probeRuns'>): number {
  if (r.port !== undefined) return r.port;
  const m = /:(\d+)$/.exec(r.target);
  return m ? Number(m[1]) : 0;
}

export function toRoundRun(r: Doc<'probeRuns'>): RoundRun {
  return {
    source: r.source,
    status: r.status,
    family: familyOfRun(r),
    port: portOfRun(r),
    address: addressOfRun(r.target),
    probeProtocol: r.probeProtocol ?? 'tcp',
    results: r.results,
  };
}

/** The edge presents a name: an L7 front, or an L4 edge in front of a REALITY / TLS listener. */
async function tlsAppliesTo(db: DatabaseReader, edge: Doc<'edges'>): Promise<boolean> {
  if (isL7(edge)) return true;
  const listener = await db.get(edge.listenerId);
  return !!listener && listener.security !== 'none';
}

function evidenceOf(db: DatabaseReader, edgeId: Id<'edges'>, country: string) {
  return db
    .query('edgeCountryEvidence')
    .withIndex('by_edge_country', (q) => q.eq('edgeId', edgeId).eq('country', country))
    .unique();
}

function gradeRowOf(db: DatabaseReader, groupKey: string, country: string) {
  return db
    .query('countryGroupGrades')
    .withIndex('by_group_country', (q) => q.eq('groupKey', groupKey).eq('country', country))
    .unique();
}

async function groupBlockedIn(
  db: DatabaseReader,
  groupKey: string,
  country: string,
  now: number,
): Promise<boolean> {
  const g = await gradeRowOf(db, groupKey, country);
  if (g?.state === 'blocked' && (g.until === undefined || g.until > now)) return true;
  const mark = await db
    .query('countryMarks')
    .withIndex('by_group_country', (q) => q.eq('groupKey', groupKey).eq('country', country))
    .first();
  return mark?.scope === 'group' && mark.state === 'blocked';
}

/**
 * The country-wide guard: a censor does not block every provider at once, an
 * outage or a probe problem does. When this round's block would make at least
 * `countryWideShare` of the edges checked there within the window blocked,
 * across enough groups and edges, the new block is held as unknown.
 */
async function countryWideHold(
  db: DatabaseReader,
  country: string,
  edgeId: Id<'edges'>,
  groupKey: string,
  now: number,
): Promise<boolean> {
  const P = EDGE_PLUMBING;
  // The WHOLE window (one row per edge checked there within it: bounded by the
  // edges, never truncated, so the newest rounds always count).
  const rows = await db
    .query('edgeCountryEvidence')
    .withIndex('by_country_round', (q) =>
      q.eq('country', country).gte('lastRoundAt', now - P.countryWideWindowMs),
    )
    .collect();
  const others = rows.filter((r) => r.edgeId !== edgeId);
  const blocked = others.filter((r) => r.lastRound?.result === 'blocked');
  const edges = others.length + 1;
  const blockedEdges = blocked.length + 1;
  const groups = new Set([groupKey, ...blocked.map((r) => r.groupKey)]);
  return (
    edges >= P.countryWideMinEdges &&
    groups.size >= P.countryWideMinGroups &&
    blockedEdges / edges >= P.countryWideShare
  );
}

/** Write one row (insert or patch), recomputing what derives from the two tracks. */
async function writeEvidence(
  ctx: MutationCtx,
  edge: Doc<'edges'>,
  country: string,
  prev: Evidence | null,
  next: {
    address: AddressTrack;
    handshake: HandshakeTrack;
    lastRound?: Evidence['lastRound'];
    paths?: Evidence['paths'];
    lastRoundAt?: number;
  },
  now: number,
): Promise<{ before: TrackState; after: TrackState }> {
  const combined = combinedState(next.address, next.handshake);
  const until = trackUntil(next.address, next.handshake);
  const row = {
    edgeId: edge._id,
    relayId: edge.relayId,
    groupKey: countryGroupKey(edge),
    country,
    address: next.address,
    handshake: next.handshake,
    combined,
    stateUntil: stateUntil(next.address, next.handshake),
    until,
    ...(next.lastRound !== undefined ? { lastRound: next.lastRound } : {}),
    ...(next.paths !== undefined ? { paths: next.paths } : {}),
    ...(next.lastRoundAt !== undefined ? { lastRoundAt: next.lastRoundAt } : {}),
    updatedAt: now,
  };
  if (prev) await ctx.db.replace(prev._id, { ...stripId(prev), ...row });
  else await ctx.db.insert('edgeCountryEvidence', row);
  return { before: prev?.combined ?? 'unknown', after: combined };
}

/**
 * How long a row's combined state holds (`stateUntil`; a row written before it
 * existed falls back to the earliest track's expiry).
 */
function lifetimeOf(r: Evidence): number | undefined {
  return r.stateUntil ?? r.until;
}

function withoutControl<T extends { control?: boolean }>(x: T): Omit<T, 'control'> {
  const { control, ...rest } = x;
  void control;
  return rest;
}

function stripId(r: Evidence) {
  const { _id, _creationTime, ...rest } = r;
  void _id;
  void _creationTime;
  return rest;
}

async function auditState(
  ctx: MutationCtx,
  edge: Doc<'edges'>,
  country: string,
  track: 'address' | 'handshake' | 'expiry',
  t: { before: TrackState; after: TrackState },
  reason: string | null,
) {
  if (t.before === t.after) return;
  const relay = await ctx.db.get(edge.relayId);
  await writeAuditLog(ctx, {
    actorType: 'system',
    action: 'edge.country.state',
    targetType: 'edge',
    targetId: edge._id,
    payload: { relaySlug: relay?.slug ?? '', country, track, state: t.after, reason },
  });
}

// --- rounds ----------------------------------------------------------------------------------------

/**
 * Called whenever a run of a round settles (finished, failed, timed out). Once
 * EVERY run of the round has settled, the round is read per checked country
 * into the address track, exactly once (a row already holding this round is
 * left alone; two runs settling together serialize, and only the second sees
 * the round complete).
 */
export async function settleRoundIfDone(
  ctx: MutationCtx,
  roundId: string,
  now: number,
): Promise<void> {
  const runs = await ctx.db
    .query('probeRuns')
    .withIndex('by_round', (q) => q.eq('roundId', roundId))
    .collect();
  if (runs.length === 0 || runs.some((r) => r.status === 'requested' || r.status === 'running'))
    return;
  const first = runs[0]!;
  if (first.targetKind !== 'edge') return;
  const cfg = await resolveEdgeConfig(ctx.db);
  if (!cfg.country.enabled) return;
  const edge = await ctx.db.get(first.targetRef as Id<'edges'>);
  if (!edge) return;
  const tlsApplies = await tlsAppliesTo(ctx.db, edge);
  const groupKey = countryGroupKey(edge);
  const roundRuns = runs.map(toRoundRun);
  const at = Math.max(...runs.map((r) => r.finishedAt ?? r.requestedAt));
  const windowMs = cfg.country.windowDays * DAY;
  // Never reached from a country while another address of the node is: a
  // block there however thin each round alone is (the edge's summary was
  // refreshed by the run that settled the round).
  const sustained = await sustainedIn(ctx.db, edge, cfg, now);
  const changed: string[] = [];
  for (const country of cfg.probe.countries) {
    const prev = await evidenceOf(ctx.db, edge._id, country);
    if (prev?.lastRound?.roundId === roundId) continue;
    const verdict = roundVerdict(roundRuns, country, cfg.country, tlsApplies);
    const isSustained = sustained.includes(country);
    const hold =
      verdict.result === 'blocked' || isSustained
        ? await countryWideHold(ctx.db, country, edge._id, groupKey, now)
        : false;
    const address = nextAddressTrack(
      expireAddressTrack(prev?.address ?? EMPTY_ADDRESS_TRACK, now),
      { result: verdict.result, reason: verdict.reason, at },
      {
        blockedRounds: cfg.country.blockedRounds,
        windowMs,
        repeatMs: EDGE_PLUMBING.countryRepeatMs,
        groupBlocked: await groupBlockedIn(ctx.db, groupKey, country, now),
        countryWideHold: hold,
        sustained: isSustained,
      },
    );
    const handshake = expireHandshakeTrack(prev?.handshake ?? EMPTY_HANDSHAKE_TRACK, now);
    const t = await writeEvidence(
      ctx,
      edge,
      country,
      prev,
      {
        address,
        handshake,
        lastRound: {
          roundId,
          at,
          result: verdict.result,
          ...(verdict.reason ? { reason: verdict.reason } : {}),
          ok: verdict.ok,
          fail: verdict.fail,
          networks: verdict.networks,
          controlsOk: verdict.controlsOk,
          ...(verdict.v6Result ? { v6Result: verdict.v6Result } : {}),
        },
        paths: verdict.paths.map((p) => ({
          family: p.family,
          port: p.port,
          address: p.address,
          tcp: p.tcp,
          at,
        })),
        lastRoundAt: at,
      },
      now,
    );
    await auditState(ctx, edge, country, 'address', t, address.reason ?? null);
    changed.push(country);
  }
  // A group whose grade moved in several countries refreshes its edges once.
  let moved = false;
  for (const country of changed) moved = (await regradeGroup(ctx, groupKey, country, now)) || moved;
  if (moved)
    for (const e of await edgesOfGroup(ctx.db, groupKey))
      await refreshEdgeCountryState(ctx, e._id, now);
  await refreshEdgeCountryState(ctx, edge._id, now);
}

/**
 * The checked countries an edge is sustained-unreachable from
 * (lib/edges/probes/sustained.ts), against the other live addresses of its
 * node. Nothing during an outage: the node offline, the address's provider
 * reporting it offline, or FCP's own check of it failing.
 */
export async function sustainedIn(
  db: DatabaseReader,
  edge: Doc<'edges'>,
  cfg: EdgeConfig,
  now: number,
): Promise<string[]> {
  if (edgeOutage(edge)) return [];
  const relay = await db.get(edge.relayId);
  if (!relay) return [];
  if (relay.origin.kind === 'panel-node') {
    const node = relay.origin;
    const inv = await db
      .query('backendNodeInventory')
      .withIndex('by_server_name', (q) =>
        q.eq('backendServerId', node.backendServerId).eq('name', node.nodeName),
      )
      .unique();
    if (inv?.online === false) return [];
  }
  return sustainedCountriesOf(edge, await liveEdgesOfRelay(db, edge.relayId), cfg, now);
}

/** Edges whose blocked round waits for its repeat (the probe planner takes them first). */
export async function dueRepeatEdges(
  db: DatabaseReader,
  now: number,
): Promise<Array<{ edgeId: Id<'edges'>; repeatAt: number }>> {
  const rows = await db
    .query('edgeCountryEvidence')
    .withIndex('by_repeat', (q) => q.gte('address.repeatAt', 0).lte('address.repeatAt', now))
    .take(50);
  const out = new Map<string, { edgeId: Id<'edges'>; repeatAt: number }>();
  for (const r of rows) {
    const at = r.address.repeatAt!;
    const cur = out.get(r.edgeId);
    if (!cur || at < cur.repeatAt) out.set(r.edgeId, { edgeId: r.edgeId, repeatAt: at });
  }
  return [...out.values()];
}

// --- name batches (#126) ----------------------------------------------------------------------------

/**
 * One finished batch of names on one address from one country (every source
 * settled), from sniVantage. A batch in which no name got through counts
 * towards a handshake block only when PAIRED with a working TCP reading of the
 * same address, port, family and country from a round within the pairing
 * window; an unpaired one asks for a round at once (the next batch can pair).
 */
export async function noteNameBatch(
  ctx: MutationCtx,
  b: {
    targetKind: string;
    targetRef: string;
    address: string;
    port: number;
    country: string;
    measurements: BatchMeasurement[];
    at: number;
  },
): Promise<void> {
  if (b.targetKind !== 'edge') return;
  const cfg = await resolveEdgeConfig(ctx.db);
  if (!cfg.country.enabled || !cfg.probe.countries.includes(b.country)) return;
  const edge = await ctx.db.get(b.targetRef as Id<'edges'>);
  if (!edge) return;
  const vcfg = await resolveSniVantageConfig(ctx.db);
  const { reading } = batchReading(b.measurements, {
    minVantages: vcfg.minVantages,
    minNetworks: vcfg.minNetworks,
  });
  const now = Date.now();
  const prev = await evidenceOf(ctx.db, edge._id, b.country);
  if (reading === 'none' && !prev) return;
  const family: PathFamily = addressFamily(b.address) === 'v6' ? 6 : 4;
  const paired =
    reading === 'path' &&
    (prev?.paths ?? []).some(
      (p) =>
        p.address === b.address &&
        p.port === b.port &&
        p.family === family &&
        p.tcp === 'works' &&
        Math.abs(b.at - p.at) <= EDGE_PLUMBING.countryHandshakePairMs,
    );
  const groupKey = countryGroupKey(edge);
  const handshake = nextHandshakeTrack(
    expireHandshakeTrack(prev?.handshake ?? EMPTY_HANDSHAKE_TRACK, now),
    { reading, at: b.at, paired },
    {
      windowMs: cfg.country.windowDays * DAY,
      repeatMs: EDGE_PLUMBING.countryHandshakeRepeatMs,
      groupBlocked: await groupBlockedIn(ctx.db, groupKey, b.country, now),
    },
  );
  let address = expireAddressTrack(prev?.address ?? EMPTY_ADDRESS_TRACK, now);
  if (reading === 'path' && !paired)
    address = { ...address, repeatAt: Math.min(address.repeatAt ?? now, now) };
  const t = await writeEvidence(ctx, edge, b.country, prev, { address, handshake }, now);
  await auditState(ctx, edge, b.country, 'handshake', t, handshake.reason ?? null);
  await refreshGroup(ctx, groupKey, b.country, now);
  await refreshEdgeCountryState(ctx, edge._id, now);
}

/** When the handshake track last saw a batch of this edge from there (the name planner's turn). */
export async function lastBatchAt(
  db: DatabaseReader,
  edgeId: Id<'edges'>,
  country: string,
): Promise<number | null> {
  return (await evidenceOf(db, edgeId, country))?.handshake.lastBatchAt ?? null;
}

// --- groups and the effective state -----------------------------------------------------------------

/** The active edges (operator-scale: one bounded read). */
const activeEdges = (db: DatabaseReader) =>
  db
    .query('edges')
    .withIndex('by_status', (q) => q.eq('status', 'active'))
    .take(2000);

/** The active edges of a group; `active` when the caller already read them. */
async function edgesOfGroup(
  db: DatabaseReader,
  groupKey: string,
  active?: Doc<'edges'>[],
): Promise<Doc<'edges'>[]> {
  const [head, rest] = [groupKey.split(':')[0], groupKey.slice(groupKey.indexOf(':') + 1)];
  if (head === 'adopted' || head === 'edge') {
    const e = await db.get(rest as Id<'edges'>);
    return e ? [e] : [];
  }
  return (active ?? (await activeEdges(db))).filter((e) => countryGroupKey(e) === groupKey);
}

/** Regrade one (group, country); when the grade moved, every edge of the group is refreshed. */
async function refreshGroup(
  ctx: MutationCtx,
  groupKey: string,
  country: string,
  now: number,
): Promise<void> {
  if (await regradeGroup(ctx, groupKey, country, now))
    for (const e of await edgesOfGroup(ctx.db, groupKey))
      await refreshEdgeCountryState(ctx, e._id, now);
}

/** Regrade one (group, country). True when its state moved (the group's edges need a refresh). */
async function regradeGroup(
  ctx: MutationCtx,
  groupKey: string,
  country: string,
  now: number,
): Promise<boolean> {
  const rows = await ctx.db
    .query('edgeCountryEvidence')
    .withIndex('by_group_country', (q) => q.eq('groupKey', groupKey).eq('country', country))
    .take(500);
  const g = gradeOf(
    rows.map((r) => {
      const until = lifetimeOf(r);
      return { state: r.combined, ...(until !== undefined ? { until } : {}) };
    }),
    now,
  );
  const prev = await gradeRowOf(ctx.db, groupKey, country);
  if (rows.length === 0) {
    if (prev) await ctx.db.delete(prev._id);
  } else {
    const same =
      prev &&
      prev.state === g.state &&
      prev.until === g.until &&
      prev.counts.edges === g.counts.edges &&
      prev.counts.proven === g.counts.proven &&
      prev.counts.blocked === g.counts.blocked;
    if (same) return false;
    const row = {
      groupKey,
      country,
      state: g.state,
      counts: g.counts,
      until: g.until,
      updatedAt: now,
    };
    if (prev) await ctx.db.replace(prev._id, row);
    else await ctx.db.insert('countryGroupGrades', row);
  }
  return (prev?.state ?? 'unknown') !== (rows.length === 0 ? 'unknown' : g.state);
}

/**
 * Rewrite `edges.countryState` from the edge's own evidence, its group's
 * grades and the marks (lib/edges/country/group.ts `effectiveState`). Decided
 * entries only; written only when something changed.
 */
export async function refreshEdgeCountryState(
  ctx: MutationCtx,
  edgeId: Id<'edges'>,
  now: number,
): Promise<void> {
  const edge = await ctx.db.get(edgeId);
  if (!edge || edge.status === 'destroyed') return;
  const groupKey = countryGroupKey(edge);
  const [own, grades, edgeMarks, groupMarks] = await Promise.all([
    ctx.db
      .query('edgeCountryEvidence')
      .withIndex('by_edge_country', (q) => q.eq('edgeId', edgeId))
      .take(100),
    ctx.db
      .query('countryGroupGrades')
      .withIndex('by_group_country', (q) => q.eq('groupKey', groupKey))
      .take(100),
    ctx.db
      .query('countryMarks')
      .withIndex('by_edge_country', (q) => q.eq('edgeId', edgeId))
      .take(100),
    ctx.db
      .query('countryMarks')
      .withIndex('by_group_country', (q) => q.eq('groupKey', groupKey))
      .take(100),
  ]);
  const countries = [
    ...new Set([...own, ...grades, ...edgeMarks, ...groupMarks].map((r) => r.country)),
  ].sort();
  const byCountry: NonNullable<Doc<'edges'>['countryState']>['byCountry'] = [];
  for (const country of countries) {
    const o = own.find((r) => r.country === country);
    const ownUntil = o ? lifetimeOf(o) : undefined;
    const g = grades.find((r) => r.country === country);
    const eff = effectiveState({
      edgeMark: edgeMarks.find((m) => m.country === country && m.scope === 'edge')?.state ?? null,
      groupMark:
        groupMarks.find((m) => m.country === country && m.scope === 'group')?.state ?? null,
      own: o ? { state: o.combined, ...(ownUntil !== undefined ? { until: ownUntil } : {}) } : null,
      grade: g
        ? { state: g.state as GroupGrade, ...(g.until !== undefined ? { until: g.until } : {}) }
        : null,
      now,
    });
    if (eff.state === 'unknown' || !eff.from) continue;
    byCountry.push({
      country,
      state: eff.state,
      from: eff.from,
      ...(eff.until !== undefined ? { until: eff.until } : {}),
    });
  }
  const before = JSON.stringify(edge.countryState?.byCountry ?? []);
  if (before === JSON.stringify(byCountry)) return;
  await ctx.db.patch(edge._id, {
    countryState: byCountry.length > 0 ? { byCountry, updatedAt: now } : undefined,
  });
}

// --- reads for the setup runs and rotations ---------------------------------------------------------

/**
 * The newest round of an edge requested at or after `since`, read per checked
 * country (whether or not it has settled: an open round says what it has so
 * far). `blockedIn` lists the countries whose round result is `blocked`.
 */
export const preUse = internalQuery({
  args: { edgeId: v.id('edges'), since: v.number() },
  handler: async (ctx, { edgeId, since }) => {
    const cfg = await resolveEdgeConfig(ctx.db);
    // Nothing to wait for while probes are off: no round would ever come.
    const enabled = cfg.country.enabled && cfg.probe.enabled;
    const none = {
      enabled,
      waitMs: cfg.country.preUseWaitMinutes * 60_000,
      state: 'none' as 'none' | 'open' | 'settled',
      requestedAt: null as number | null,
      blockedIn: [] as string[],
      results: [] as Array<{ country: string; result: string; reason: string | null }>,
    };
    const edge = await ctx.db.get(edgeId);
    if (!edge || !enabled) return none;
    const runs = (
      await ctx.db
        .query('probeRuns')
        .withIndex('by_target_requested', (q) =>
          q.eq('targetKind', 'edge').eq('targetRef', edgeId).gte('requestedAt', since),
        )
        .order('desc')
        .take(100)
    ).filter((r) => r.roundId !== undefined);
    if (runs.length === 0) return none;
    const roundId = runs[0]!.roundId!;
    const round = runs.filter((r) => r.roundId === roundId);
    const open = round.some((r) => r.status === 'requested' || r.status === 'running');
    const tlsApplies = await tlsAppliesTo(ctx.db, edge);
    const results = cfg.probe.countries.map((country) => {
      const verdict = roundVerdict(round.map(toRoundRun), country, cfg.country, tlsApplies);
      return { country, result: verdict.result as string, reason: verdict.reason };
    });
    return {
      ...none,
      state: open ? ('open' as const) : ('settled' as const),
      requestedAt: Math.min(...round.map((r) => r.requestedAt)),
      blockedIn: results.filter((r) => r.result === 'blocked').map((r) => r.country),
      results,
    };
  },
});

/**
 * Checked countries where the country-wide guard holds new blocks right now
 * (a row checked there within the guard's window carries `country_wide`): the
 * detector's `country_wide` veto reads them.
 */
export async function heldCountries(
  db: DatabaseReader,
  countries: readonly string[],
  now: number,
): Promise<string[]> {
  const out: string[] = [];
  for (const country of countries) {
    // The whole window, newest first (one row per edge checked there within
    // it): a hold on the newest round is never cut off by a read cap.
    const rows = await db
      .query('edgeCountryEvidence')
      .withIndex('by_country_round', (q) =>
        q.eq('country', country).gte('lastRoundAt', now - EDGE_PLUMBING.countryWideWindowMs),
      )
      .order('desc')
      .collect();
    if (rows.some((r) => r.address.reason === 'country_wide')) out.push(country);
  }
  return out;
}

/** How many checked countries a spare is effectively blocked in (publishStandby prefers fewer). */
export function blockedCountries(edge: Doc<'edges'>, now: number): number {
  return liveCountryState(edge.countryState?.byCountry, now).filter((c) => c.state === 'blocked')
    .length;
}

// --- marks ------------------------------------------------------------------------------------------

const GROUP_KEY_RE = /^[a-z0-9-]+:[A-Za-z0-9_.:-]{1,120}$/;

/**
 * An operator's word about an edge or a group in one country (`state: null`
 * removes it). Checks never override a mark; a mark never expires.
 */
export const setMark = internalMutation({
  args: {
    scope: v.union(v.literal('edge'), v.literal('group')),
    ref: v.string(),
    country: v.string(),
    state: v.union(v.literal('proven'), v.literal('blocked'), v.null()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const country = a.country.trim().toUpperCase();
    const listed = (await resolveCensoredCountries(ctx.db)).codes;
    if (!listed.includes(country))
      throw new ConvexError({
        code: 'validation',
        message: 'The country is not on the censored-country list',
      });
    const now = Date.now();
    let edges: Doc<'edges'>[];
    let existing: Doc<'countryMarks'> | null;
    let groupKey: string | null = null;
    let edgeId: Id<'edges'> | null = null;
    if (a.scope === 'edge') {
      const edge = await ctx.db.get(a.ref as Id<'edges'>);
      if (!edge || edge.status === 'destroyed')
        throw new ConvexError({ code: 'not_found', message: 'Edge not found' });
      edgeId = edge._id;
      edges = [edge];
      existing = await ctx.db
        .query('countryMarks')
        .withIndex('by_edge_country', (q) => q.eq('edgeId', edge._id).eq('country', country))
        .unique();
    } else {
      if (!GROUP_KEY_RE.test(a.ref))
        throw new ConvexError({ code: 'validation', message: 'Not a group key' });
      groupKey = a.ref;
      edges = await edgesOfGroup(ctx.db, a.ref);
      existing = await ctx.db
        .query('countryMarks')
        .withIndex('by_group_country', (q) => q.eq('groupKey', a.ref).eq('country', country))
        .unique();
    }
    if (a.state === null) {
      if (existing) await ctx.db.delete(existing._id);
    } else {
      const row = {
        scope: a.scope,
        ...(edgeId ? { edgeId } : {}),
        ...(groupKey ? { groupKey } : {}),
        country,
        state: a.state,
        at: now,
        ...(a.actorAdminId ? { by: a.actorAdminId } : {}),
      };
      if (existing) await ctx.db.replace(existing._id, row);
      else await ctx.db.insert('countryMarks', row);
    }
    for (const e of edges) await refreshEdgeCountryState(ctx, e._id, now);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'edge.country.mark',
      targetType: a.scope === 'edge' ? 'edge' : 'edge_group',
      targetId: a.scope === 'edge' ? (edgeId as string) : undefined,
      payload: { scope: a.scope, country, state: a.state, count: edges.length },
    });
    return { ok: true as const, edges: edges.length };
  },
});

// --- the expiry worker ------------------------------------------------------------------------------

/**
 * `edge-country-expiry` (hourly, whether or not probes run): decided tracks
 * past their `until` lapse to unknown, the grades and every edge's
 * `countryState` follow, and rows past the window are deleted. Bounded pages;
 * a full page schedules the next one.
 */
export const expire = internalMutation({
  args: { now: v.optional(v.number()), rounds: v.optional(v.number()) },
  handler: async (ctx, a) => {
    const now = a.now ?? Date.now();
    const rounds = a.rounds ?? 0;
    if (rounds === 0) await recordHeartbeat(ctx, 'edge-country-expiry');
    const cfg = await resolveEdgeConfig(ctx.db);
    const groups = new Set<string>();
    const edges = new Set<Id<'edges'>>();
    let full = false;
    const due = await ctx.db
      .query('edgeCountryEvidence')
      .withIndex('by_until', (q) => q.gte('until', 0).lte('until', now))
      .take(EXPIRY_PAGE);
    full ||= due.length === EXPIRY_PAGE;
    for (const row of due) {
      const address = expireAddressTrack(row.address, now);
      const handshake = expireHandshakeTrack(row.handshake, now);
      const edge = await ctx.db.get(row.edgeId);
      const combined = combinedState(address, handshake);
      await ctx.db.patch(row._id, {
        address,
        handshake,
        combined,
        stateUntil: stateUntil(address, handshake),
        until: trackUntil(address, handshake),
        updatedAt: now,
      });
      if (edge && combined !== row.combined)
        await auditState(
          ctx,
          edge,
          row.country,
          'expiry',
          { before: row.combined, after: combined },
          'expired',
        );
      groups.add(`${row.groupKey}|${row.country}`);
      edges.add(row.edgeId);
    }
    // Rows nothing has touched for the whole window: their edge is long gone
    // or no longer checked from there. Deleted (a decided one expired above first).
    const stale = await ctx.db
      .query('edgeCountryEvidence')
      .withIndex('by_updated', (q) => q.lt('updatedAt', now - cfg.country.windowDays * DAY))
      .take(EXPIRY_PAGE);
    full ||= stale.length === EXPIRY_PAGE;
    for (const row of stale) {
      if (row.until !== undefined && row.until > now) continue;
      await ctx.db.delete(row._id);
      groups.add(`${row.groupKey}|${row.country}`);
      edges.add(row.edgeId);
    }
    const grades = await ctx.db
      .query('countryGroupGrades')
      .withIndex('by_until', (q) => q.gte('until', 0).lte('until', now))
      .take(EXPIRY_PAGE);
    for (const g of grades) groups.add(`${g.groupKey}|${g.country}`);
    // An edge whose copied state carries an entry past its expiry (a mark or a
    // grade moved elsewhere, or a pass was missed) is rewritten too.
    const active = await activeEdges(ctx.db);
    for (const e of active)
      if ((e.countryState?.byCountry ?? []).some((c) => c.until !== undefined && c.until <= now))
        edges.add(e._id);
    await settleGroupsAndEdges(ctx, [...groups], [...edges], now, active);
    if (full && rounds < MAX_EXPIRY_ROUNDS)
      await ctx.scheduler.runAfter(0, internal.edgeCountry.expire, { now, rounds: rounds + 1 });
    return { expired: due.length, deleted: stale.length };
  },
});

/**
 * Regrade the (group, country) pairs, then rewrite the copied state of every
 * edge they moved and of `edges`, each edge once. A bounded step per
 * transaction: the rest continue in `settleExpiry`, the edges only once every
 * pair is regraded (an edge reads its group's grades).
 */
async function settleGroupsAndEdges(
  ctx: MutationCtx,
  pairs: readonly string[],
  edgeIds: readonly Id<'edges'>[],
  now: number,
  active?: Doc<'edges'>[],
): Promise<void> {
  const edges = new Set(edgeIds);
  for (const k of pairs.slice(0, PAIRS_PER_STEP)) {
    const i = k.lastIndexOf('|');
    const groupKey = k.slice(0, i);
    if (!(await regradeGroup(ctx, groupKey, k.slice(i + 1), now))) continue;
    active ??= await activeEdges(ctx.db);
    for (const e of await edgesOfGroup(ctx.db, groupKey, active)) edges.add(e._id);
  }
  const rest = pairs.slice(PAIRS_PER_STEP);
  const ids = [...edges];
  if (rest.length === 0)
    for (const id of ids.splice(0, EDGES_PER_STEP)) await refreshEdgeCountryState(ctx, id, now);
  if (rest.length > 0 || ids.length > 0)
    await ctx.scheduler.runAfter(0, internal.edgeCountry.settleExpiry, {
      pairs: rest,
      edgeIds: ids,
      now,
    });
}

/** The rest of an expiry run's regrades and refreshes (`settleGroupsAndEdges`). */
export const settleExpiry = internalMutation({
  args: { pairs: v.array(v.string()), edgeIds: v.array(v.id('edges')), now: v.number() },
  handler: async (ctx, a) => {
    await settleGroupsAndEdges(ctx, a.pairs, a.edgeIds, a.now);
    return null;
  },
});

// --- the admin read ---------------------------------------------------------------------------------

/** Audit rows of one edge read to find when each country's block began (newest first). */
const SINCE_AUDIT_ROWS = 100;

/**
 * When the edge's own state turned blocked in each country it is blocked in
 * now: the newest `edge.country.state` transition per country, when it is a
 * block (the tracks keep only the last confirmation, which moves forward on
 * every blocked round). Null where the audit rows read do not reach it.
 */
async function blockedSinceOf(
  db: DatabaseReader,
  edgeId: Id<'edges'>,
): Promise<Map<string, number | null>> {
  const rows = await db
    .query('auditLog')
    .withIndex('by_target', (q) => q.eq('targetType', 'edge').eq('targetId', edgeId))
    .order('desc')
    .take(SINCE_AUDIT_ROWS);
  const out = new Map<string, number | null>();
  for (const r of rows) {
    if (r.action !== 'edge.country.state') continue;
    const p = (r.payload ?? {}) as { country?: unknown; state?: unknown };
    if (typeof p.country !== 'string' || out.has(p.country)) continue;
    out.set(p.country, p.state === 'blocked' ? r._creationTime : null);
  }
  return out;
}

/**
 * Everything the checks know, for Edges -> Countries (PR 3 draws it): the
 * checked and control countries, every group's grade, every edge's tracks per
 * country with its effective state, and the marks. Never an address.
 */
export const overview = internalQuery({
  args: {},
  handler: async (ctx) => {
    const cfg = await resolveEdgeConfig(ctx.db);
    const listed = (await resolveCensoredCountries(ctx.db)).codes;
    const now = Date.now();
    const rows = await ctx.db
      .query('edgeCountryEvidence')
      .withIndex('by_updated')
      .order('desc')
      .take(3000);
    const grades = await ctx.db.query('countryGroupGrades').take(2000);
    const marks = await ctx.db.query('countryMarks').take(2000);
    const iso = (n?: number) => (n !== undefined ? new Date(n).toISOString() : null);
    const byEdge = new Map<string, Evidence[]>();
    for (const r of rows) byEdge.set(r.edgeId, [...(byEdge.get(r.edgeId) ?? []), r]);
    const edges = [];
    for (const [edgeId, list] of byEdge) {
      const edge = await ctx.db.get(edgeId as Id<'edges'>);
      const relay = await ctx.db.get(list[0]!.relayId);
      const effective = liveCountryState(edge?.countryState?.byCountry, now);
      const since = list.some((r) => r.combined === 'blocked')
        ? await blockedSinceOf(ctx.db, edgeId as Id<'edges'>)
        : new Map<string, number | null>();
      edges.push({
        edgeId,
        relaySlug: relay?.slug ?? null,
        groupKey: list[0]!.groupKey,
        provider: edge?.provider ?? null,
        status: edge?.status ?? 'destroyed',
        publication: edge?.publication ?? null,
        countries: list
          .sort((x, y) => x.country.localeCompare(y.country))
          .map((r) => ({
            country: r.country,
            combined: r.combined,
            /** When the edge's own state turned blocked there (null: not blocked, or not on record). */
            blockedSince: r.combined === 'blocked' ? iso(since.get(r.country) ?? undefined) : null,
            effective: effective.find((c) => c.country === r.country) ?? null,
            address: {
              state: r.address.state,
              reason: r.address.reason ?? null,
              decidedAt: iso(r.address.decidedAt),
              until: iso(r.address.until),
              blockedRounds: r.address.blockedRounds,
              repeatAt: iso(r.address.repeatAt),
            },
            handshake: {
              state: r.handshake.state,
              reason: r.handshake.reason ?? null,
              until: iso(r.handshake.until),
              pathBatches: r.handshake.pathBatches.length,
              lastBatchAt: iso(r.handshake.lastBatchAt),
            },
            lastRound: r.lastRound
              ? {
                  roundId: r.lastRound.roundId,
                  at: iso(r.lastRound.at),
                  result: r.lastRound.result,
                  reason: r.lastRound.reason ?? null,
                  ok: r.lastRound.ok,
                  fail: r.lastRound.fail,
                  networks: r.lastRound.networks,
                  controlsOk: r.lastRound.controlsOk,
                  v6Result: r.lastRound.v6Result ?? null,
                }
              : null,
          })),
      });
    }
    return {
      enabled: cfg.country.enabled,
      countries: cfg.probe.countries,
      controls: controlCountriesOf(cfg, listed),
      groups: grades.map((g) => ({
        groupKey: g.groupKey,
        provider: providerOfGroup(g.groupKey),
        country: g.country,
        state: g.state,
        counts: g.counts,
        until: iso(g.until),
      })),
      edges,
      marks: marks.map((m) => ({
        scope: m.scope,
        edgeId: (m.edgeId as string | undefined) ?? null,
        groupKey: m.groupKey ?? null,
        country: m.country,
        state: m.state,
        at: iso(m.at),
      })),
    };
  },
});

// --- reads for attention ---------------------------------------------------------------------------

/**
 * Rows (one per edge checked there) one country's scan for holds reads at most.
 * Newest round first, so a recent mass failure is always inside it; past it
 * the fleet is far beyond operator scale.
 */
const COUNTRY_WIDE_SCAN = 2000;

/**
 * Countries where the country-wide guard holds new blocks (attention
 * `country_wide_failure`): edges whose round there within `windowMs` came back
 * blocked but was held as `country_wide`. Most of what is checked there failed
 * at once: an outage or a probe problem, not a censor, so nothing turned
 * blocked; the operator should look at the sources.
 */
export async function countryWideHolds(
  db: DatabaseReader,
  countries: readonly string[],
  now: number,
  windowMs: number,
): Promise<Array<{ country: string; edges: number; groups: number; since: number }>> {
  const out = [];
  for (const country of countries) {
    const held: Evidence[] = [];
    let scanned = 0;
    for await (const r of db
      .query('edgeCountryEvidence')
      .withIndex('by_country_round', (q) =>
        q.eq('country', country).gte('lastRoundAt', now - windowMs),
      )
      .order('desc')) {
      if (r.address.reason === 'country_wide') held.push(r);
      if (++scanned >= COUNTRY_WIDE_SCAN) break;
    }
    if (held.length === 0) continue;
    out.push({
      country,
      edges: held.length,
      groups: new Set(held.map((r) => r.groupKey)).size,
      since: Math.min(...held.map((r) => r.lastRoundAt ?? r.updatedAt)),
    });
  }
  return out;
}

/**
 * The checked countries a NEW edge (active, never in use) is blocked in
 * (attention `new_edge_blocked_in`): its round there came back blocked and it
 * was never proven there (a block waiting for its repeat counts), or its
 * combined state is blocked. A country-wide hold is not the edge's own block,
 * and a country the operator marked is left to the mark.
 */
export async function newEdgeBlockedIn(
  db: DatabaseReader,
  edge: Doc<'edges'>,
  countries: readonly string[],
): Promise<Array<{ country: string; at: number }>> {
  if (edge.status !== 'active' || edge.publication !== 'unpublished' || edge.publishedAt) return [];
  const marked = new Set(
    (edge.countryState?.byCountry ?? []).filter((c) => c.from === 'mark').map((c) => c.country),
  );
  const rows = await db
    .query('edgeCountryEvidence')
    .withIndex('by_edge_country', (q) => q.eq('edgeId', edge._id))
    .take(100);
  const out = [];
  for (const r of rows) {
    if (!countries.includes(r.country) || marked.has(r.country)) continue;
    const roundBlocked =
      r.lastRound?.result === 'blocked' &&
      r.address.state !== 'proven' &&
      r.address.reason !== 'country_wide';
    if (r.combined !== 'blocked' && !roundBlocked) continue;
    out.push({ country: r.country, at: r.address.decidedAt ?? r.lastRound?.at ?? r.updatedAt });
  }
  return out.sort((a, b) => a.country.localeCompare(b.country));
}

// --- rollback ---------------------------------------------------------------------------------------

/**
 * Before deploying a build older than per-country checks: removes every row
 * and field this feature wrote, page by page (Convex refuses an older schema
 * while they exist). `table` walks the work in order.
 */
export const purgeForRollback = internalMutation({
  args: {
    step: v.optional(
      v.union(
        v.literal('evidence'),
        v.literal('grades'),
        v.literal('marks'),
        v.literal('edges'),
        v.literal('runs'),
      ),
    ),
    cursor: v.optional(v.union(v.string(), v.null())),
  },
  handler: async (ctx, a) => {
    const step = a.step ?? 'evidence';
    const next = {
      evidence: 'grades',
      grades: 'marks',
      marks: 'edges',
      edges: 'runs',
      runs: null,
    } as const;
    const PAGE = 200;
    let done: boolean;
    let cursor: string | null = null;
    if (step === 'evidence' || step === 'grades' || step === 'marks') {
      const rows =
        step === 'evidence'
          ? await ctx.db.query('edgeCountryEvidence').take(PAGE)
          : step === 'grades'
            ? await ctx.db.query('countryGroupGrades').take(PAGE)
            : await ctx.db.query('countryMarks').take(PAGE);
      for (const r of rows) await ctx.db.delete(r._id);
      done = rows.length < PAGE;
    } else if (step === 'edges') {
      const page = await ctx.db
        .query('edges')
        .paginate({ cursor: a.cursor ?? null, numItems: PAGE });
      for (const e of page.page)
        if (e.countryState) await ctx.db.patch(e._id, { countryState: undefined });
      done = page.isDone;
      cursor = page.continueCursor;
    } else {
      const page = await ctx.db
        .query('probeRuns')
        .paginate({ cursor: a.cursor ?? null, numItems: PAGE });
      for (const r of page.page) {
        if (
          r.roundId === undefined &&
          r.tests === undefined &&
          r.controls === undefined &&
          r.error === undefined &&
          !r.results.some((x) => x.control !== undefined)
        )
          continue;
        await ctx.db.patch(r._id, {
          roundId: undefined,
          tests: undefined,
          controls: undefined,
          error: undefined,
          results: r.results.filter((x) => !x.control).map(withoutControl),
        });
      }
      done = page.isDone;
      cursor = page.continueCursor;
    }
    const following = done ? next[step] : step;
    if (following)
      await ctx.scheduler.runAfter(0, internal.edgeCountry.purgeForRollback, {
        step: following,
        cursor: done ? null : cursor,
      });
    return { step, done };
  },
});
