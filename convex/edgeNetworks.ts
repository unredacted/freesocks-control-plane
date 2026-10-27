/**
 * Networks (docs/edges.md "Networks"): where a REALITY transport's target, its
 * server names and the addresses members dial come from, so all three can sit
 * on ONE provider network. A censor resolving a name, or an active prober
 * looking at the certificate behind an address, then sees one consistent
 * network.
 *
 *  - A network is ASNs plus the ranges they announce (refreshed daily; the
 *    request carries the ASN and nothing else) and ranges entered by hand.
 *    Every membership check is local (lib/edges/networks.ts).
 *  - A family may be on a network (sniFamilies.networkId): its target and
 *    every name must resolve inside it to qualify.
 *  - A transport bound to such a family is fronted only by locations on the
 *    network (`relayListeners.networkId`, `carries`), and an address off it is
 *    never published (`off_network`).
 *  - A location's network is set by an operator, or learned here from the
 *    addresses of its edges.
 *
 * No provider is named anywhere: networks are data.
 */
import { ConvexError, v } from 'convex/values';
import {
  internalAction,
  internalMutation,
  internalQuery,
  type MutationCtx,
} from './_generated/server';
import type { DatabaseReader } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { internal } from './_generated/api';
import { writeAuditLog } from './lib/audit';
import { runWithCronOutcome } from './cronHeartbeat';
import { assertAdmission } from './lib/edges/maintenance';
import {
  announcedPrefixesUrl,
  combinePrefixes,
  edgeNetworkVerdict,
  hasPrefixes,
  MAX_MANUAL_PREFIXES,
  MAX_NETWORK_ASNS,
  mergePrefixes,
  NETWORK_REFRESH_MS,
  normalizeAsn,
  normalizePrefix,
  parseAnnouncedPrefixes,
  samePrefixes,
  type NetworkPrefixes,
  type NetworkRefreshError,
} from './lib/edges/networks';

type Network = Doc<'edgeNetworks'>;

const actor = { actorAdminId: v.optional(v.id('adminUsers')) };
const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,39}$/;
const REFRESH_TIMEOUT_MS = 15_000;
const MAX_ANSWER_BYTES = 16 * 1024 * 1024;
/** Networks refreshed per cron pass (each is one request per ASN). */
const REFRESH_PER_PASS = 4;
/** Networks a deployment may hold: every list, refresh and learning pass reads them all. */
export const MAX_NETWORKS = 200;
/** Names marked due per page when a network's ranges move. */
const REQUEUE_PAGE = 500;

function refuse(code: string, message: string): never {
  throw new ConvexError({ code, message });
}

// --- membership, for the rest of the edges code ---------------------------------------------

/** The ranges every membership check reads; null for no network or one without ranges yet. */
export async function networkPrefixes(
  db: DatabaseReader,
  networkId: Id<'edgeNetworks'> | null | undefined,
): Promise<NetworkPrefixes | null> {
  if (!networkId) return null;
  const n = await db.get(networkId);
  return n && hasPrefixes(n.prefixes) ? n.prefixes : null;
}

async function bySlug(db: DatabaseReader, slug: string): Promise<Network> {
  const n = await db
    .query('edgeNetworks')
    .withIndex('by_slug', (q) => q.eq('slug', slug))
    .unique();
  if (!n) refuse('not_found', 'No such network');
  return n;
}

/** A network by slug, for the family and location routes (null for `null`). */
export async function networkIdOfSlug(
  db: DatabaseReader,
  slug: string | null,
): Promise<Id<'edgeNetworks'> | null> {
  return slug === null ? null : (await bySlug(db, slug))._id;
}

function cleanAsns(raw: unknown): number[] {
  if (!Array.isArray(raw)) refuse('validation', 'asns must be a list');
  const out = [...new Set(raw.map(normalizeAsn))];
  if (out.some((n) => n === null)) refuse('edge.network.bad_asn', 'Each ASN is a number');
  if (out.length > MAX_NETWORK_ASNS)
    refuse('edge.network.bad_asn', `A network has at most ${MAX_NETWORK_ASNS} ASNs`);
  return (out as number[]).sort((a, b) => a - b);
}

/** A network is something: at least one ASN or one range by hand. */
function assertDefined(asns: readonly number[], manual: readonly string[]) {
  if (asns.length === 0 && manual.length === 0)
    refuse('edge.network.empty', 'A network needs an ASN or a range');
}

function cleanManual(raw: unknown): string[] {
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) refuse('validation', 'manualPrefixes must be a list');
  const out = raw.map(normalizePrefix);
  if (out.some((p) => p === null))
    refuse('edge.network.bad_prefix', 'Each range is an address and a length, like 192.0.2.0/24');
  if (out.length > MAX_MANUAL_PREFIXES)
    refuse('edge.network.bad_prefix', `At most ${MAX_MANUAL_PREFIXES} ranges by hand`);
  return [...new Set(out as string[])].sort();
}

function combined(n: Pick<Network, 'announced' | 'manualPrefixes'>) {
  return combinePrefixes([...n.announced.v4, ...n.announced.v6], n.manualPrefixes);
}

/**
 * A network's effective ranges moved: every name of a family on it is due for
 * qualification again (a name qualified against the old ranges may now resolve
 * off the network), and every location may belong elsewhere now.
 */
async function rangesMoved(
  ctx: MutationCtx,
  networkId: Id<'edgeNetworks'>,
  before: NetworkPrefixes,
  after: NetworkPrefixes,
): Promise<void> {
  if (samePrefixes(before, after)) return;
  for (const f of await ctx.db
    .query('sniFamilies')
    .withIndex('by_network', (q) => q.eq('networkId', networkId))
    .collect())
    await ctx.scheduler.runAfter(0, internal.edgeNetworks.requeueFamilyNames, {
      familyId: f._id,
    });
  await ctx.scheduler.runAfter(0, internal.edgeNetworks.learnLocations, {});
}

/** Names of one family due for qualification again, a page at a time (it may hold thousands). */
export const requeueFamilyNames = internalMutation({
  args: { familyId: v.id('sniFamilies'), afterSeq: v.optional(v.number()) },
  handler: async (ctx, { familyId, afterSeq }) => {
    const page = await ctx.db
      .query('sniNames')
      .withIndex('by_family_seq', (q) =>
        afterSeq === undefined
          ? q.eq('familyId', familyId)
          : q.eq('familyId', familyId).gt('seq', afterSeq),
      )
      .take(REQUEUE_PAGE);
    for (const n of page)
      if ((n.status === 'active' || n.status === 'suspended') && n.checkedAt !== 0)
        await ctx.db.patch(n._id, { checkedAt: 0, updatedAt: Date.now() });
    if (page.length === REQUEUE_PAGE)
      await ctx.scheduler.runAfter(0, internal.edgeNetworks.requeueFamilyNames, {
        familyId,
        afterSeq: page[page.length - 1]!.seq,
      });
    return { requeued: page.length };
  },
});

// --- admin view ---------------------------------------------------------------------------------

export const list = internalQuery({
  args: {},
  handler: async (ctx) => {
    const networks = await ctx.db.query('edgeNetworks').take(MAX_NETWORKS);
    const out = [];
    for (const n of networks) {
      const families = await ctx.db
        .query('sniFamilies')
        .withIndex('by_network', (q) => q.eq('networkId', n._id))
        .take(50);
      const locations = await ctx.db
        .query('edgeLocations')
        .withIndex('by_network', (q) => q.eq('networkId', n._id))
        .take(100);
      out.push({
        id: n._id as string,
        slug: n.slug,
        label: n.label,
        asns: n.asns,
        manualPrefixes: n.manualPrefixes,
        ranges: { v4: n.prefixes.v4.length, v6: n.prefixes.v6.length },
        truncated: !!n.truncated,
        refreshedAt: n.refreshedAt ? new Date(n.refreshedAt).toISOString() : null,
        refreshError: n.refreshError ?? null,
        hunt: { enabled: !!n.hunt?.enabled, place: n.hunt?.place ?? null },
        families: families.map((f) => ({ slug: f.slug, label: f.label })),
        locations: locations.map((l) => ({
          id: l._id as string,
          label: l.label,
          provider: l.provider,
          source: l.networkSource ?? 'operator',
        })),
      });
    }
    out.sort((a, b) => a.label.localeCompare(b.label));
    return { networks: out };
  },
});

// --- writes ---------------------------------------------------------------------------------------

export const create = internalMutation({
  args: {
    slug: v.string(),
    label: v.string(),
    asns: v.array(v.union(v.number(), v.string())),
    manualPrefixes: v.optional(v.array(v.string())),
    ...actor,
  },
  handler: async (ctx, a) => {
    await assertAdmission(ctx.db, 'provider.write');
    const slug = a.slug.trim();
    if (!SLUG_RE.test(slug))
      refuse('validation', 'The short id is lowercase letters, digits and dashes');
    const label = a.label.trim().slice(0, 80);
    if (!label) refuse('validation', 'A network needs a name');
    const exists = await ctx.db
      .query('edgeNetworks')
      .withIndex('by_slug', (q) => q.eq('slug', slug))
      .unique();
    if (exists) refuse('conflict', 'A network with that short id exists');
    if ((await ctx.db.query('edgeNetworks').take(MAX_NETWORKS)).length >= MAX_NETWORKS)
      refuse('edge.network.cap', `A deployment holds at most ${MAX_NETWORKS} networks`);
    const asns = cleanAsns(a.asns);
    const manualPrefixes = cleanManual(a.manualPrefixes);
    assertDefined(asns, manualPrefixes);
    const announced = { v4: [] as string[], v6: [] as string[] };
    const merged = combined({ announced, manualPrefixes });
    const id = await ctx.db.insert('edgeNetworks', {
      slug,
      label,
      asns,
      announced,
      manualPrefixes,
      prefixes: { v4: merged.v4, v6: merged.v6 },
      updatedAt: Date.now(),
    });
    if (asns.length > 0) await ctx.scheduler.runAfter(0, internal.edgeNetworks.refresh, { slug });
    // Ranges by hand are effective at once: locations can learn them now.
    if (manualPrefixes.length > 0)
      await ctx.scheduler.runAfter(0, internal.edgeNetworks.learnLocations, {});
    await audit(ctx, 'edge.network.create', a.actorAdminId, { slug, asns: asns.length });
    return { id: id as string, slug };
  },
});

export const update = internalMutation({
  args: {
    slug: v.string(),
    label: v.optional(v.string()),
    asns: v.optional(v.array(v.union(v.number(), v.string()))),
    manualPrefixes: v.optional(v.array(v.string())),
    ...actor,
  },
  handler: async (ctx, a) => {
    await assertAdmission(ctx.db, 'provider.write');
    const n = await bySlug(ctx.db, a.slug);
    const patch: Partial<Network> = { updatedAt: Date.now() };
    if (a.label !== undefined) {
      const label = a.label.trim().slice(0, 80);
      if (!label) refuse('validation', 'A network needs a name');
      patch.label = label;
    }
    let asnsMoved = false;
    if (a.asns !== undefined) {
      patch.asns = cleanAsns(a.asns);
      asnsMoved = patch.asns.join(',') !== n.asns.join(',');
    }
    if (a.manualPrefixes !== undefined) patch.manualPrefixes = cleanManual(a.manualPrefixes);
    assertDefined(patch.asns ?? n.asns, patch.manualPrefixes ?? n.manualPrefixes);
    // New ASNs: what was announced by the old ones no longer counts.
    const announced = asnsMoved ? { v4: [], v6: [] } : n.announced;
    if (asnsMoved) {
      patch.announced = announced;
      patch.refreshedAt = undefined;
      patch.refreshError = undefined;
    }
    const merged = combined({
      announced,
      manualPrefixes: patch.manualPrefixes ?? n.manualPrefixes,
    });
    patch.prefixes = { v4: merged.v4, v6: merged.v6 };
    patch.truncated = merged.truncated || undefined;
    await ctx.db.patch(n._id, patch);
    await rangesMoved(ctx, n._id, n.prefixes, patch.prefixes);
    if (asnsMoved && (patch.asns ?? n.asns).length > 0)
      await ctx.scheduler.runAfter(0, internal.edgeNetworks.refresh, { slug: n.slug });
    await audit(ctx, 'edge.network.update', a.actorAdminId, {
      slug: n.slug,
      asns: (patch.asns ?? n.asns).length,
      manualPrefixes: (patch.manualPrefixes ?? n.manualPrefixes).length,
    });
    return { ok: true as const };
  },
});

export const remove = internalMutation({
  args: { slug: v.string(), ...actor },
  handler: async (ctx, a) => {
    await assertAdmission(ctx.db, 'provider.write');
    const n = await bySlug(ctx.db, a.slug);
    const family = await ctx.db
      .query('sniFamilies')
      .withIndex('by_network', (q) => q.eq('networkId', n._id))
      .first();
    if (family)
      refuse('edge.network.in_use', 'A server-name family is on this network. Change it first');
    const listener = (await ctx.db.query('relayListeners').collect()).find(
      (l) => l.networkId === n._id && !l.retired,
    );
    if (listener) refuse('edge.network.in_use', 'A transport is scoped to this network');
    for (const loc of await ctx.db
      .query('edgeLocations')
      .withIndex('by_network', (q) => q.eq('networkId', n._id))
      .collect())
      await ctx.db.patch(loc._id, {
        networkId: undefined,
        networkSource: undefined,
        updatedAt: Date.now(),
      });
    await ctx.db.delete(n._id);
    // Names found on it go with it (docs/edges.md "Finding names").
    await ctx.scheduler.runAfter(0, internal.sniHunt.dropScope, { networkId: n._id });
    await audit(ctx, 'edge.network.delete', a.actorAdminId, { slug: n.slug });
    return { ok: true as const };
  },
});

/**
 * Finding names on a network (docs/edges.md "Finding names"): whether the
 * top-sites sweep matches against it, and where its nodes are, a place name
 * (an ISO country and an optional city) for the timing checks. Never an address.
 */
export const setHunt = internalMutation({
  args: {
    slug: v.string(),
    enabled: v.boolean(),
    place: v.optional(v.object({ country: v.string(), city: v.optional(v.string()) })),
    ...actor,
  },
  handler: async (ctx, a) => {
    const n = await bySlug(ctx.db, a.slug);
    let place: { country: string; city?: string } | undefined;
    if (a.place) {
      const country = a.place.country.trim().toUpperCase();
      if (!/^[A-Z]{2}$/.test(country))
        refuse('edge.network.bad_place', 'A place is a two-letter country code and a city');
      const city = a.place.city?.trim().replace(/\s+/g, ' ').slice(0, 60);
      if (city !== undefined && city !== '' && !/^[\p{L}\p{M} .'-]+$/u.test(city))
        refuse('edge.network.bad_place', 'A place is a two-letter country code and a city');
      place = { country, ...(city ? { city } : {}) };
    }
    // A place taken from a node stays marked so while it is sent back unchanged.
    const same =
      place &&
      n.hunt?.place?.country === place.country &&
      (n.hunt.place.city ?? '') === (place.city ?? '');
    await ctx.db.patch(n._id, {
      hunt: {
        enabled: a.enabled,
        ...(place ? { place } : {}),
        ...(same && n.hunt?.placeFrom ? { placeFrom: n.hunt.placeFrom } : {}),
      },
      updatedAt: Date.now(),
    });
    await audit(ctx, 'edge.network.hunt', a.actorAdminId, {
      slug: n.slug,
      enabled: a.enabled,
      place: !!place,
    });
    return { ok: true as const };
  },
});

/**
 * A location's network, set by an operator (`null` clears it, after which the
 * addresses of its edges may teach it again). Set, it is never overwritten by
 * what is learned.
 */
export const setLocationNetwork = internalMutation({
  args: {
    locationId: v.id('edgeLocations'),
    network: v.union(v.string(), v.null()),
    ...actor,
  },
  handler: async (ctx, a) => {
    await assertAdmission(ctx.db, 'provider.write');
    const loc = await ctx.db.get(a.locationId);
    if (!loc) refuse('not_found', 'Location not found');
    const networkId = await networkIdOfSlug(ctx.db, a.network);
    await ctx.db.patch(loc._id, {
      networkId: networkId ?? undefined,
      networkSource: networkId ? 'operator' : undefined,
      updatedAt: Date.now(),
    });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'edge.location.network',
      targetType: 'edge_location',
      targetId: loc._id,
      payload: { placeKey: loc.placeKey, network: a.network ?? 'none' },
    });
    // Cleared, its addresses may teach it a network again; set, nothing else moves.
    if (!networkId) await ctx.scheduler.runAfter(0, internal.edgeNetworks.learnLocations, {});
    return { ok: true as const };
  },
});

async function audit(
  ctx: MutationCtx,
  action: string,
  actorAdminId: Id<'adminUsers'> | undefined,
  payload: Record<string, unknown>,
) {
  await writeAuditLog(ctx, {
    actorType: actorAdminId ? 'admin' : 'system',
    actorId: actorAdminId ?? undefined,
    action,
    targetType: 'edge_network',
    payload,
  });
}

// --- refresh ----------------------------------------------------------------------------------------

/** The networks whose announced ranges are older than a day (or never read), oldest first. */
export const dueForRefresh = internalQuery({
  args: { slug: v.optional(v.string()), now: v.number() },
  handler: async (ctx, { slug, now }) => {
    const rows = slug
      ? [await bySlug(ctx.db, slug)]
      : (await ctx.db.query('edgeNetworks').take(MAX_NETWORKS))
          .filter((n) => !n.refreshTriedAt || now - n.refreshTriedAt >= NETWORK_REFRESH_MS)
          .sort((a, b) => (a.refreshTriedAt ?? 0) - (b.refreshTriedAt ?? 0))
          .slice(0, REFRESH_PER_PASS);
    // A network of ranges by hand only has nothing to read.
    return rows
      .filter((n) => n.asns.length > 0)
      .map((n) => ({ id: n._id, slug: n.slug, asns: n.asns }));
  },
});

export const recordRefresh = internalMutation({
  args: {
    id: v.id('edgeNetworks'),
    asns: v.array(v.number()),
    prefixes: v.optional(v.array(v.string())),
    error: v.optional(v.string()),
  },
  handler: async (ctx, a) => {
    const n = await ctx.db.get(a.id);
    if (!n) return null;
    const now = Date.now();
    // The ASNs changed while this refresh ran: its answer is for the old ones.
    if (n.asns.join(',') !== a.asns.join(',')) return null;
    if (a.error || !a.prefixes) {
      await ctx.db.patch(n._id, {
        refreshError: a.error ?? 'bad_answer',
        refreshTriedAt: now,
        updatedAt: now,
      });
      return null;
    }
    const announced = mergePrefixes([a.prefixes]);
    const merged = combined({
      announced: { v4: announced.v4, v6: announced.v6 },
      manualPrefixes: n.manualPrefixes,
    });
    await ctx.db.patch(n._id, {
      announced: { v4: announced.v4, v6: announced.v6 },
      prefixes: { v4: merged.v4, v6: merged.v6 },
      truncated: announced.truncated || merged.truncated || undefined,
      refreshedAt: now,
      refreshTriedAt: now,
      refreshError: undefined,
      updatedAt: now,
    });
    await rangesMoved(ctx, n._id, n.prefixes, { v4: merged.v4, v6: merged.v6 });
    return null;
  },
});

type FetchLike = (
  url: string,
  init: { signal: AbortSignal; redirect: 'error'; headers: Record<string, string> },
) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>;
let fetchImpl: FetchLike = (url, init) => fetch(url, init);
/** Test seam: the HTTP call the refresh makes. */
export function __setNetworkFetchForTests(f: FetchLike | null): void {
  fetchImpl = f ?? ((url, init) => fetch(url, init));
}

async function announcedOf(
  asn: number,
): Promise<{ prefixes: string[] } | { error: NetworkRefreshError }> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), REFRESH_TIMEOUT_MS);
  try {
    const res = await fetchImpl(announcedPrefixesUrl(asn), {
      signal: ctl.signal,
      redirect: 'error',
      headers: { accept: 'application/json' },
    });
    if (!res.ok) return { error: res.status === 429 ? 'rate_limited' : 'service_error' };
    const text = await res.text();
    if (text.length > MAX_ANSWER_BYTES) return { error: 'too_large' };
    const parsed = parseAnnouncedPrefixes(JSON.parse(text));
    return parsed.ok ? { prefixes: parsed.prefixes } : { error: parsed.error };
  } catch (e) {
    return {
      error: ctl.signal.aborted
        ? 'timeout'
        : e instanceof SyntaxError
          ? 'bad_answer'
          : 'unreachable',
    };
  } finally {
    clearTimeout(timer);
  }
}

/** Read the announced ranges of one network (by slug) or of every network due. */
export const refresh = internalAction({
  args: { slug: v.optional(v.string()) },
  handler: async (ctx, { slug }): Promise<{ refreshed: number; failed: number }> => {
    const due = await ctx.runQuery(internal.edgeNetworks.dueForRefresh, {
      ...(slug ? { slug } : {}),
      now: Date.now(),
    });
    let refreshed = 0;
    let failed = 0;
    for (const n of due) {
      const all: string[] = [];
      let error: string | undefined;
      for (const asn of n.asns) {
        const r = await announcedOf(asn);
        if ('error' in r) {
          error = r.error;
          break;
        }
        all.push(...r.prefixes);
      }
      await ctx.runMutation(internal.edgeNetworks.recordRefresh, {
        id: n.id,
        asns: n.asns,
        ...(error ? { error } : { prefixes: all }),
      });
      if (error) failed++;
      else refreshed++;
    }
    if (refreshed > 0) await ctx.runMutation(internal.edgeNetworks.learnLocations, {});
    return { refreshed, failed };
  },
});

/**
 * Teach each location its network from the addresses of its newest edges: the
 * network every one of those addresses lies on (none when they disagree, or no
 * network holds them). An operator's choice is never overwritten.
 */
export const learnLocations = internalMutation({
  args: {},
  handler: async (ctx) => {
    const networks = (await ctx.db.query('edgeNetworks').take(MAX_NETWORKS)).filter((n) =>
      hasPrefixes(n.prefixes),
    );
    let changed = 0;
    for (const loc of await ctx.db.query('edgeLocations').take(1000)) {
      if (loc.networkSource === 'operator') continue;
      const edges = await ctx.db
        .query('edges')
        // Live edges only (a destroyed one keeps its address for a while), the
        // newest first: equal index keys order by creation.
        .withIndex('by_location_status', (q) => q.eq('locationId', loc._id).eq('status', 'active'))
        .order('desc')
        .take(10);
      const addressed = edges.filter(
        (e) => (e.layer ?? 'l4') === 'l4' && (e.addresses.v4 || e.addresses.v6),
      );
      if (addressed.length === 0) continue;
      const on = networks.find((n) =>
        addressed.every((e) => edgeNetworkVerdict(e.addresses, n.prefixes) === 'on'),
      );
      const next = on?._id;
      if (next === loc.networkId) continue;
      await ctx.db.patch(loc._id, {
        networkId: next,
        networkSource: next ? 'address' : undefined,
        updatedAt: Date.now(),
      });
      changed++;
    }
    return { changed };
  },
});

/** Cron `edge-networks` (hourly): refresh what is due, then learn locations. */
export const tick = internalAction({
  args: {},
  handler: async (ctx): Promise<void> =>
    runWithCronOutcome(ctx, 'edge-networks', async () => {
      await ctx.runAction(internal.edgeNetworks.refresh, {});
      await ctx.runMutation(internal.edgeNetworks.learnLocations, {});
    }),
});
