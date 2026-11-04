/**
 * Measured member legs for latency ordering (docs/edges.md "Latency over the
 * whole path"; the path math is pure in lib/edges/latency.ts).
 *
 * One row per (L4 location, country): the median round trip of a bare TCP
 * connect from vantages IN that country to the location's addresses, over the
 * last week of probe runs that already happen (no probe is asked for here).
 * Each hourly pass merges only the runs since the last one into the kept
 * samples (`edgeLatencySamples`, at most `PER_HOUR` per hour), so the figure
 * covers the whole week however often addresses are probed, and what a render
 * reads (`edgeLatency`) stays a handful of small rows.
 * Only Globalping's TCP ping and check-host's TCP check time a bare connect
 * (RIPE Atlas includes the TLS handshake, the internal source is FCP's own
 * host), only IPv4, never a control vantage. A figure counts once it rests on
 * `MIN_SAMPLES` results from `MIN_NETWORKS` networks with the newest under
 * `FRESH_MS` old; a location without one is estimated from distance instead.
 *
 * What delivery reads (`ms`) moves only on a real change (more than 15% and
 * more than 10 ms) or when the figure appears or lapses, so a member's band
 * moves rarely; when it moves while latency ordering is on, every origin with
 * an address in use there moves its epoch (cached bodies and mirrors follow).
 * Infrastructure only: addresses and third-party vantages, nothing about a
 * member.
 */
import { internalMutation, internalQuery } from './_generated/server';
import type { DatabaseReader, MutationCtx } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { v } from 'convex/values';
import { internal } from './_generated/api';
import { recordHeartbeat } from './cronHeartbeat';
import { locationKeyOf } from './lib/edges/locations';
import { edgeLayerOf } from './lib/edges/providers/capabilities';
import type { LatencyInputs } from './lib/edges/latency';
import type { PublishedEdge } from './lib/edges/assignment';
import { scheduleMirrorRefresh } from './lib/edges/relayGuards';
import { MEMBER_COUNTRY_KEYS, type MemberCountryConfig } from './lib/memberCountry';
import { resolveMemberCountryConfig } from './memberCountry';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
/** The window of probe runs a figure is taken over. */
export const WINDOW_MS = 7 * DAY;
export const MIN_SAMPLES = 5;
export const MIN_NETWORKS = 2;
/** The newest result a figure rests on must be younger than this. */
export const FRESH_MS = 48 * HOUR;
/** A committed figure moves only past both of these. */
export const MOVE_RATIO = 0.15;
export const MOVE_MS = 10;
/** At most this many samples per clock hour are kept (a week stays bounded and even). */
export const PER_HOUR = 12;
/** A pass reads runs requested up to this long ago (they have finished by then). */
const SETTLE_LAG_MS = 30 * 60_000;
/** The first pass reads this far back: as far as a figure stays fresh, so none lapses at deploy. */
const FIRST_PASS_MS = FRESH_MS;
/** Where the passes are up to (`appState`): runs requested before it are merged. */
export const THROUGH_KEY = 'edgeLatency:through';
/** Bounds per pass: locations, live addresses per location, runs per address and source. */
const LOCATION_SCAN = 1000;
const EDGE_SCAN = 1000;
const RUNS_PER_PASS = 2000;
const ROW_SCAN = 5000;

/** One kept sample: when, the round trip, and the vantage's network (null: none named). */
export interface LegSample {
  at: number;
  ms: number;
  net: string | null;
}

/** The results of one probe run that time a member's leg, by country. */
export function legResultsOf(
  run: Doc<'probeRuns'>,
): Array<{ country: string; ms: number; network: string | null; at: number }> {
  if (run.status !== 'finished') return [];
  if (run.source !== 'globalping' && run.source !== 'checkhost') return [];
  if ((run.probeProtocol ?? 'tcp') !== 'tcp') return [];
  if (run.addressKind === 'name' || (run.ipVersion ?? 4) !== 4) return [];
  const at = run.finishedAt ?? run.requestedAt;
  return run.results
    .filter(
      (r) => r.ok && !r.control && typeof r.rttMs === 'number' && r.rttMs > 0 && r.country !== 'XX',
    )
    .map((r) => ({
      country: r.country.toUpperCase(),
      ms: r.rttMs!,
      network: r.asn ?? r.network ?? null,
      at,
    }));
}

/**
 * The samples kept after adding `fresh`: only those inside the window, at most
 * `PER_HOUR` per clock hour (the first ones of each hour), oldest first. So a
 * week of samples stays bounded and spread over the whole week, however often
 * the location is probed.
 */
export function keptSamples(
  kept: readonly LegSample[],
  fresh: readonly LegSample[],
  now: number,
): LegSample[] {
  const perHour = new Map<number, number>();
  const out: LegSample[] = [];
  for (const s of [...kept, ...fresh].sort((a, b) => a.at - b.at)) {
    if (now - s.at > WINDOW_MS) continue;
    const hour = Math.floor(s.at / HOUR);
    const n = perHour.get(hour) ?? 0;
    if (n >= PER_HOUR) continue;
    perHour.set(hour, n + 1);
    out.push(s);
  }
  return out;
}

function median(values: readonly number[]): number {
  const s = [...values].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 === 1 ? s[m]! : (s[m - 1]! + s[m]!) / 2;
}

/** How the kept samples stand: the facts a figure rests on. */
export function sampleFacts(samples: readonly LegSample[]) {
  const networks = new Set(samples.map((s) => s.net).filter((n): n is string => !!n));
  return {
    samples: samples.length,
    networks: networks.size,
    newestAt: samples.reduce((m, s) => Math.max(m, s.at), 0),
  };
}

/** The figure the kept samples support, or null (estimate instead). */
export function figureOf(samples: readonly LegSample[], now: number): number | null {
  const f = sampleFacts(samples);
  if (f.samples < MIN_SAMPLES || f.networks < MIN_NETWORKS) return null;
  if (now - f.newestAt > FRESH_MS) return null;
  return Math.round(median(samples.map((s) => s.ms)));
}

/** Whether a newly taken figure replaces the committed one. */
export function figureMoves(committed: number, fresh: number): boolean {
  const d = Math.abs(fresh - committed);
  return d > MOVE_MS && d > committed * MOVE_RATIO;
}

/**
 * `edge-latency` (hourly): the probe runs requested since the last pass (up to
 * half an hour ago, so they have finished) are merged location by location,
 * one job per L4 location (`refreshLocation`). The first pass reads two days
 * back (as long as a figure stays fresh); after that each pass reads only what
 * is new, so nothing caps how much of the week a figure rests on.
 */
export const refresh = internalMutation({
  args: { now: v.optional(v.number()) },
  handler: async (ctx, a) => {
    await recordHeartbeat(ctx, 'edge-latency');
    const now = a.now ?? Date.now();
    const state = await ctx.db
      .query('appState')
      .withIndex('by_key', (q) => q.eq('key', THROUGH_KEY))
      .unique();
    const through = state ? Number(state.value) : now - FIRST_PASS_MS;
    const to = Math.max(through, now - SETTLE_LAG_MS);
    if (!state)
      await ctx.db.insert('appState', { key: THROUGH_KEY, value: String(to), updatedAt: now });
    else if (to > through) await ctx.db.patch(state._id, { value: String(to), updatedAt: now });
    const keys = new Set<string>();
    for (const loc of await ctx.db.query('edgeLocations').take(LOCATION_SCAN)) {
      if (edgeLayerOf(loc.provider) !== 'l4') continue;
      keys.add(locationKeyOf(loc.provider, loc.placeKey));
      await ctx.scheduler.runAfter(0, internal.edgeLatency.refreshLocation, {
        locationId: loc._id,
        from: through,
        to,
        now,
      });
    }
    // A location that is gone leaves nothing behind.
    for (const r of await ctx.db.query('edgeLatencySamples').take(ROW_SCAN))
      if (!keys.has(r.groupKey)) await ctx.db.delete(r._id);
    for (const r of await ctx.db.query('edgeLatency').take(ROW_SCAN))
      if (!keys.has(r.groupKey)) await ctx.db.delete(r._id);
    return { locations: keys.size, from: through, to };
  },
});

/**
 * One L4 location's pass: the new runs of its live addresses (Globalping and
 * check-host only) are added to the kept samples per country, the figures are
 * taken again, and the ones that moved are committed. While latency ordering
 * is on, every origin with an address in use here then moves its epoch.
 */
export const refreshLocation = internalMutation({
  args: { locationId: v.id('edgeLocations'), from: v.number(), to: v.number(), now: v.number() },
  handler: async (ctx, a) => {
    const loc = await ctx.db.get(a.locationId);
    if (!loc) return { committed: 0 };
    const groupKey = locationKeyOf(loc.provider, loc.placeKey);
    const edges = (
      await ctx.db
        .query('edges')
        .withIndex('by_location_status', (q) => q.eq('locationId', loc._id).eq('status', 'active'))
        .take(EDGE_SCAN)
    ).filter((e) => (e.layer ?? 'l4') === 'l4');
    const fresh = new Map<string, LegSample[]>();
    if (a.to > a.from)
      for (const e of edges)
        for (const source of ['globalping', 'checkhost'] as const) {
          const runs = await ctx.db
            .query('probeRuns')
            .withIndex('by_target_source_requested', (q) =>
              q
                .eq('targetKind', 'edge')
                .eq('targetRef', e._id)
                .eq('source', source)
                .gte('requestedAt', a.from)
                .lt('requestedAt', a.to),
            )
            .take(RUNS_PER_PASS);
          for (const run of runs)
            for (const r of legResultsOf(run)) {
              const list = fresh.get(r.country) ?? [];
              list.push({ at: r.at, ms: r.ms, net: r.network });
              fresh.set(r.country, list);
            }
        }
    const keptRows = await ctx.db
      .query('edgeLatencySamples')
      .withIndex('by_group_country', (q) => q.eq('groupKey', groupKey))
      .collect();
    const figureRows = await ctx.db
      .query('edgeLatency')
      .withIndex('by_group_country', (q) => q.eq('groupKey', groupKey))
      .collect();
    const countries = new Set([
      ...fresh.keys(),
      ...keptRows.map((r) => r.country),
      ...figureRows.map((r) => r.country),
    ]);
    let committed = 0;
    for (const country of countries) {
      const keptRow = keptRows.find((r) => r.country === country);
      const samples = keptSamples(keptRow?.samples ?? [], fresh.get(country) ?? [], a.now);
      if (samples.length === 0) {
        if (keptRow) await ctx.db.delete(keptRow._id);
      } else if (keptRow) await ctx.db.patch(keptRow._id, { samples, updatedAt: a.now });
      else
        await ctx.db.insert('edgeLatencySamples', { groupKey, country, samples, updatedAt: a.now });
      const figure = figureOf(samples, a.now);
      const facts = sampleFacts(samples);
      const row = figureRows.find((r) => r.country === country);
      if (figure === null) {
        if (row) {
          await ctx.db.delete(row._id);
          committed++;
        }
      } else if (!row) {
        await ctx.db.insert('edgeLatency', {
          groupKey,
          country,
          ms: figure,
          ...facts,
          updatedAt: a.now,
        });
        committed++;
      } else if (figureMoves(row.ms, figure)) {
        await ctx.db.patch(row._id, { ms: figure, ...facts, updatedAt: a.now });
        committed++;
      } else {
        await ctx.db.patch(row._id, facts);
      }
    }
    const cfg = await resolveMemberCountryConfig(ctx.db);
    const relays = [
      ...new Set(edges.filter((e) => e.publication === 'published').map((e) => e.relayId)),
    ];
    if (committed > 0 && cfg.steer && cfg.latency && relays.length > 0)
      await bumpRelays(ctx, relays, a.now);
    return { committed };
  },
});

async function bumpRelays(ctx: MutationCtx, ids: readonly Id<'relays'>[], now: number) {
  for (const id of ids) {
    const r = await ctx.db.get(id);
    if (r) await ctx.db.patch(id, { publicationEpoch: r.publicationEpoch + 1, updatedAt: now });
  }
  await scheduleMirrorRefresh(ctx);
}

/**
 * A backend server's map position changed (adminApi): every node path on it
 * may have changed band, so its origins move their epoch and the mirrors are
 * refreshed, as for a moved figure. Nothing while latency ordering is off.
 */
export async function nodePositionMoved(
  ctx: MutationCtx,
  backendServerId: Id<'backendServers'>,
): Promise<void> {
  const cfg = await resolveMemberCountryConfig(ctx.db);
  if (!cfg.steer || !cfg.latency) return;
  const relays = await ctx.db
    .query('relays')
    .withIndex('by_backend_server', (q) => q.eq('backendServerId', backendServerId))
    .collect();
  if (relays.length > 0)
    await bumpRelays(
      ctx,
      relays.map((r) => r._id),
      Date.now(),
    );
}

/**
 * What a render on `origin` knows about paths (lib/edges/latency.ts), or null
 * while latency ordering is off: the node's map position (its backend
 * server's), and the committed member legs of the pool's L4 locations.
 */
export async function latencyInputsFor(
  db: DatabaseReader,
  origin: Doc<'relays'>,
  published: readonly PublishedEdge[],
  /** The member-country settings when the caller already read them. */
  known?: Pick<MemberCountryConfig, 'steer' | 'latency'>,
): Promise<LatencyInputs | null> {
  const cfg = known ?? (await resolveMemberCountryConfig(db));
  if (!cfg.steer || !cfg.latency) return null;
  const server = origin.backendServerId ? await db.get(origin.backendServerId) : null;
  const node =
    server && typeof server.locationLat === 'number' && typeof server.locationLng === 'number'
      ? { lat: server.locationLat, lng: server.locationLng }
      : null;
  const measured: LatencyInputs['measured'] = {};
  const groups = new Set(
    published.filter((e) => (e.layer ?? 'l4') === 'l4' && e.locationKey).map((e) => e.locationKey!),
  );
  for (const groupKey of groups) {
    const rows = await db
      .query('edgeLatency')
      .withIndex('by_group_country', (q) => q.eq('groupKey', groupKey))
      .collect();
    if (rows.length > 0)
      measured[groupKey] = Object.fromEntries(rows.map((r) => [r.country, r.ms]));
  }
  return { node, measured };
}

/** The committed figures, for the admin (country view): `<provider>:<placeKey>` -> country -> row. */
export const figures = internalQuery({
  args: {},
  handler: async (ctx) => {
    const rows = await ctx.db.query('edgeLatency').take(2000);
    return rows.map((r) => ({
      groupKey: r.groupKey,
      country: r.country,
      ms: r.ms,
      samples: r.samples,
      networks: r.networks,
      newestAt: r.newestAt,
    }));
  },
});

/**
 * Before deploying a build older than latency ordering: every figure and kept
 * sample goes, and the switch's key and the passes' mark with them (run
 * `memberCountry:clearWideForRollback` first). Pages until done (`done`);
 * safe to run again.
 */
export const purgeForRollback = internalMutation({
  args: {},
  handler: async (ctx) => {
    const rows = [
      ...(await ctx.db.query('edgeLatency').take(250)),
      ...(await ctx.db.query('edgeLatencySamples').take(250)),
    ];
    for (const r of rows) await ctx.db.delete(r._id);
    if (rows.length > 0) {
      await ctx.scheduler.runAfter(0, internal.edgeLatency.purgeForRollback, {});
      return { deleted: rows.length, done: false };
    }
    const key = await ctx.db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', MEMBER_COUNTRY_KEYS.latency))
      .unique();
    if (key) await ctx.db.delete(key._id);
    const through = await ctx.db
      .query('appState')
      .withIndex('by_key', (q) => q.eq('key', THROUGH_KEY))
      .unique();
    if (through) await ctx.db.delete(through._id);
    return { deleted: 0, done: true };
  },
});
