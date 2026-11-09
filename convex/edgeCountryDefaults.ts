/**
 * A country's default picks (docs/edges.md "A country's default picks"; pure
 * planner in lib/edges/countryDefaults.ts).
 *
 * The fleet keeps, per country (or a few countries together), the picks its
 * own addresses go to on every freedom node (`countryDefaults` rows). Upkeep
 * writes them onto each ready node as entries of its picks (marked
 * `fromDefault`), adding a location the node did not pick as a pick serving
 * its countries only; from there everything of § "Countries with their own
 * addresses" applies (step 5W makes the addresses, they are contained at
 * first publication). A node's own entry for one of those countries wins, a
 * node may opt out, and nothing is written on a node a guided setup owns, one
 * without the rendezvous walk (attention `country_defaults_waiting`: switching
 * it moves members, so it is the operator's) or one whose pool would grow past
 * its size. Cutting a country over stays per node (convex/edgeOwnPools.ts).
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { DatabaseReader, MutationCtx } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { assertAdmission } from './lib/edges/maintenance';
import { resolveCensoredCountries } from './lib/censoredCountries';
import { resolveMemberCountryConfig } from './memberCountry';
import { MAX_DESIRED_PUBLISHED } from './lib/edgeConfig';
import { MAX_PICK_WANT, MAX_PROVIDER_PICKS } from './lib/edges/providerSet';
import { checkPickOptions } from './edgeTemplates';
import { carries, setPicksOf, setStateOf } from './lib/edges/setState';
import { websocketNodeOf } from './lib/edges/websocketNode';
import { listenersOf } from './relayListeners';
import { liveEdgesOfRelay } from './lib/edges/relayGuards';
import { isTerminalPhase } from './lib/edges/rotation';
import { freedomListenersOf } from './edgeDetector';
import { MAX_AUDIENCE_CODES } from './edgeAudiences';
import { costAdmin, edgeCostAt, sizeAt } from './edgePlans';
import { parseOptionValues } from './lib/edges/providers/options';
import { defaultsPlan, type CountryDefault, type DefaultsPick } from './lib/edges/countryDefaults';

type Relay = Doc<'relays'>;

/** The most picks one country's defaults may name (a place, its fallbacks). */
export const MAX_DEFAULT_PICKS = 4;

const sortCodes = (codes: readonly string[]) =>
  [...new Set(codes.map((c) => c.trim().toUpperCase()).filter(Boolean))].sort();

async function storedDefaults(db: DatabaseReader): Promise<CountryDefault[]> {
  return (await db.query('countryDefaults').collect()).map((r) => ({
    codes: r.codes,
    picks: r.picks.map((p) => ({
      locationId: p.locationId as string,
      ...(p.want !== undefined ? { want: p.want } : {}),
    })),
  }));
}

/** Why the defaults are not written on a node at all (none = they may be). */
function notReady(relay: Relay): string | null {
  if (relay.deleting) return 'deleting';
  if (!relay.enabled) return 'disabled';
  if (relay.setupOwned) return 'setup_owned';
  // The safety workflows hold the set still: quarantine, a restore.
  if (relay.quarantine) return 'quarantined';
  if (relay.restore) return 'restore_in_progress';
  return null;
}

/**
 * The node's provider set with the defaults written in (the planner), and
 * what applying it needs: whether it adds anything, and the refusal that
 * keeps the node waiting (no steering, no rendezvous walk, too large a pool).
 */
async function nodePlan(
  db: DatabaseReader,
  relay: Relay,
  defaults: readonly CountryDefault[],
  now: number,
) {
  const listeners = (await listenersOf({ db }, relay._id)).filter(
    (l) => l.deployed && l.enabled && !l.retired,
  );
  const freedom = new Set(await freedomListenersOf({ db }, relay));
  const websocketNode = await websocketNodeOf(db, relay.origin);
  const locations = [...new Set(defaults.flatMap((d) => d.picks.map((p) => p.locationId)))];
  const rows =
    (await setPicksOf(db, {
      providerSet: locations.map((locationId) => ({
        locationId: locationId as Id<'edgeLocations'>,
        addedAt: 0,
      })),
    })) ?? [];
  const opts = { websocketNode, originAddress: relay.originAddress };
  const carried = new Set(
    rows
      .filter((row) => listeners.some((l) => freedom.has(l.listenerKey) && carries(row, l, opts)))
      .map((row) => row.pick.locationId as string),
  );
  const live = new Set(
    (await liveEdgesOfRelay(db, relay._id)).map((e) => e.locationId as string | undefined),
  );
  // A pick the defaults add starts from its account's defaults, copied in (as
  // any pick joining a node), so a later account edit does not move it.
  const picked = new Set((relay.providerSet ?? []).map((p) => p.locationId as string));
  const options = new Map<string, string>();
  for (const row of rows) {
    const id = row.pick.locationId as string;
    if (picked.has(id) || !carried.has(id)) continue;
    const r = await checkPickOptions({ db }, row.location, row.account, {});
    if (r.ok) options.set(id, JSON.stringify(r.options));
  }
  const plan = defaultsPlan({
    providerSet: (relay.providerSet ?? []) as unknown as DefaultsPick[],
    defaults,
    optOut: relay.countryDefaultsOptOut ?? [],
    carries: (id) => carried.has(id),
    liveAt: (id) => live.has(id),
    optionsOf: (id) => options.get(id),
    now,
  });
  let refusal: string | null = null;
  if (plan.changed) {
    const before = relay.providerSet?.length ?? 0;
    if (plan.providerSet.length > MAX_PROVIDER_PICKS && plan.providerSet.length > before)
      refusal = 'edge.set_too_many_picks';
    else if (plan.added.length > 0 && !(await resolveMemberCountryConfig(db)).steer)
      refusal = 'edge.audience_needs_steering';
    else if (plan.added.length > 0 && relay.edgePick !== 'hrw1')
      refusal = 'edge.audience_needs_spread';
    else {
      // Judged as the set will stand: nothing cooling, and the defaults'
      // locations as if usable (one switched off now asks once it is on). A
      // change (an entry added, a count raised) that grows the pool past its
      // size waits; one that shrinks it never does.
      const size = async (providerSet: Relay['providerSet']) => {
        const s = await setStateOf(db, { ...relay, providerSet, cooling: [] }, now, {
          assumeUsable: locations,
        });
        return s.published.length + s.deficit;
      };
      const after = await size(plan.providerSet as Relay['providerSet']);
      if (after > MAX_DESIRED_PUBLISHED && after > (await size(relay.providerSet)))
        refusal = 'edge.set_too_large';
    }
  }
  return { plan, refusal };
}

async function rotationRunning(db: DatabaseReader, relay: Relay): Promise<boolean> {
  if (!relay.activeRotationId) return false;
  const r = await db.get(relay.activeRotationId);
  return !!r && !isTerminalPhase(r.phase);
}

/**
 * Upkeep (edgeReconcile.ts, before step 5W): bring one node's entries in step
 * with the defaults. Skips a node a setup owns or with a rotation running
 * (the next pass applies); records why it waits otherwise.
 */
export const applyToNode = internalMutation({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay || notReady(relay)) return { changed: false };
    const defaults = await storedDefaults(ctx.db);
    const holds = (relay.providerSet ?? []).some(
      (p) => p.fromDefault || (p.audiences ?? []).some((x) => x.fromDefault),
    );
    if (defaults.length === 0 && !holds && !relay.countryDefaultsWaiting) return { changed: false };
    if (await rotationRunning(ctx.db, relay)) return { changed: false };
    const now = Date.now();
    const { plan, refusal } = await nodePlan(ctx.db, relay, defaults, now);
    if (refusal) {
      if (relay.countryDefaultsWaiting?.code !== refusal)
        await ctx.db.patch(relay._id, { countryDefaultsWaiting: { code: refusal, at: now } });
      return { changed: false, waiting: refusal };
    }
    if (!plan.changed) {
      if (relay.countryDefaultsWaiting)
        await ctx.db.patch(relay._id, { countryDefaultsWaiting: undefined });
      return { changed: false };
    }
    await ctx.db.patch(relay._id, {
      providerSet: plan.providerSet as Relay['providerSet'],
      countryDefaultsWaiting: undefined,
      updatedAt: now,
    });
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'edge.relay.country_defaults',
      targetType: 'relay',
      targetId: relay._id,
      payload: {
        relaySlug: relay.slug,
        added: plan.added.join('; '),
        removed: plan.removed.join('; '),
      },
    });
    return { changed: true, added: plan.added, removed: plan.removed };
  },
});

const picksArg = v.array(
  v.object({
    locationId: v.id('edgeLocations'),
    want: v.optional(v.union(v.number(), v.null())),
  }),
);

/** Why a country's defaults may not be saved as given, or null. */
async function defaultRefusal(
  db: DatabaseReader,
  codes: string[],
  picks: ReadonlyArray<{ locationId: Id<'edgeLocations'>; want?: number | null }>,
): Promise<{ code: string; message: string } | null> {
  const bad = (message: string) => ({ code: 'validation', message });
  if (codes.length === 0 || codes.length > MAX_AUDIENCE_CODES)
    return bad(`Name 1 to ${MAX_AUDIENCE_CODES} countries`);
  const listed = (await resolveCensoredCountries(db)).codes;
  const unlisted = codes.find((c) => !listed.includes(c));
  if (unlisted) return bad(`${unlisted} is not on the censored-country list`);
  if (!(await resolveMemberCountryConfig(db)).steer)
    return {
      code: 'edge.audience_needs_steering',
      message: 'Turn on ordering by country under Settings first',
    };
  if (picks.length === 0 || picks.length > MAX_DEFAULT_PICKS)
    return bad(`Name 1 to ${MAX_DEFAULT_PICKS} locations`);
  if (new Set(picks.map((p) => p.locationId)).size !== picks.length)
    return bad('A location is named twice');
  if (!picks.some((p) => typeof p.want === 'number'))
    return bad('At least one location needs a count of addresses');
  for (const p of picks) {
    if (
      p.want !== undefined &&
      p.want !== null &&
      (!Number.isInteger(p.want) || p.want < 1 || p.want > MAX_PICK_WANT)
    )
      return bad(`Addresses must be 1 to ${MAX_PICK_WANT}, or none for a fallback place`);
    const loc = await db.get(p.locationId);
    if (!loc) return { code: 'not_found', message: 'Location not found' };
    if (loc.forCountries?.only)
      return {
        code: 'edge.audience_on_only_location',
        message: `${loc.label ?? loc.placeKey} is only for some countries already`,
      };
  }
  for (const other of await db.query('countryDefaults').collect()) {
    if (other.codes.join(' ') === codes.join(' ')) continue;
    const shared = other.codes.find((c) => codes.includes(c));
    if (shared) return bad(`${shared} already has default picks (with ${other.codes.join(', ')})`);
  }
  return null;
}

/**
 * Save one country's default picks (or a few countries' together): the
 * locations their own addresses go to on every freedom node, in order, each
 * with a count (or none: a fallback place). Upkeep writes them onto each ready
 * node at its next pass. Billable once applied: see the preview first.
 */
export const setCountryDefault = internalMutation({
  args: {
    codes: v.array(v.string()),
    picks: picksArg,
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    await assertAdmission(ctx.db, 'setup.start');
    const codes = sortCodes(a.codes);
    const refusal = await defaultRefusal(ctx.db, codes, a.picks);
    if (refusal) throw new ConvexError(refusal);
    const picks = a.picks.map((p) => ({
      locationId: p.locationId,
      ...(typeof p.want === 'number' ? { want: p.want } : {}),
    }));
    const now = Date.now();
    const row = (await ctx.db.query('countryDefaults').collect()).find(
      (r) => r.codes.join(' ') === codes.join(' '),
    );
    if (row && JSON.stringify(row.picks) === JSON.stringify(picks))
      return { ok: true as const, changed: false };
    if (row) await ctx.db.patch(row._id, { picks, updatedAt: now });
    else await ctx.db.insert('countryDefaults', { codes, picks, updatedAt: now });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'edge.country_default',
      targetType: 'countryDefaults',
      targetId: codes.join(' '),
      payload: { countries: codes.join(' '), picks: picks.length, removed: false },
    });
    return { ok: true as const, changed: true };
  },
});

/** Remove a country's default picks: upkeep takes their entries away (addresses stay theirs). */
export const removeCountryDefault = internalMutation({
  args: { codes: v.array(v.string()), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, a) => {
    const codes = sortCodes(a.codes);
    const row = (await ctx.db.query('countryDefaults').collect()).find(
      (r) => r.codes.join(' ') === codes.join(' '),
    );
    if (!row) return { ok: true as const, changed: false };
    await ctx.db.delete(row._id);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'edge.country_default',
      targetType: 'countryDefaults',
      targetId: codes.join(' '),
      payload: { countries: codes.join(' '), picks: 0, removed: true },
    });
    return { ok: true as const, changed: true };
  },
});

/** The stored defaults, with their locations named. */
export const listCountryDefaults = internalQuery({
  args: {},
  handler: async (ctx) => {
    const out = [];
    for (const r of await ctx.db.query('countryDefaults').collect()) {
      const picks = [];
      for (const p of r.picks) {
        const loc = await ctx.db.get(p.locationId);
        picks.push({
          locationId: p.locationId,
          label: loc?.label ?? loc?.placeKey ?? null,
          want: p.want ?? null,
        });
      }
      out.push({ codes: r.codes, picks, updatedAt: r.updatedAt });
    }
    return out;
  },
});

/**
 * What the defaults (the stored ones, with `codes`' replaced by `picks` when
 * given, or removed with `picks: []`) would write on every node, and what the
 * addresses they ask for cost a month: per node, what it adds and removes,
 * why it would wait, and per location the new addresses and their price.
 */
export const preview = internalQuery({
  args: {
    codes: v.optional(v.array(v.string())),
    picks: v.optional(picksArg),
  },
  handler: async (ctx, a) => {
    const now = Date.now();
    let defaults = await storedDefaults(ctx.db);
    if (a.codes) {
      const codes = sortCodes(a.codes);
      defaults = defaults.filter((d) => d.codes.join(' ') !== codes.join(' '));
      if (a.picks && a.picks.length > 0) {
        const refusal = await defaultRefusal(ctx.db, codes, a.picks);
        if (refusal) return { refusal, nodes: [], totals: [] };
        defaults.push({
          codes,
          picks: a.picks.map((p) => ({
            locationId: p.locationId as string,
            ...(typeof p.want === 'number' ? { want: p.want } : {}),
          })),
        });
      }
    }
    const nodes = [];
    const totals = new Map<string, number>();
    for (const relay of await ctx.db.query('relays').collect()) {
      const skip = notReady(relay);
      if (skip === 'deleting') continue;
      const { plan, refusal } = await nodePlan(ctx.db, relay, defaults, now);
      if (!plan.changed && !skip) continue;
      const eventual = (providerSet: Relay['providerSet']) =>
        setStateOf(ctx.db, { ...relay, providerSet, cooling: [] }, now);
      const before = await eventual(relay.providerSet);
      const after = await eventual(plan.providerSet as Relay['providerSet']);
      const rows = after.picks ?? [];
      const perLocation = new Map<string, number>();
      for (const t of after.targets)
        if (t.count && t.audience?.length && t.locationId)
          perLocation.set(t.locationId, (perLocation.get(t.locationId) ?? 0) + 1);
      for (const t of before.targets)
        if (t.count && t.audience?.length && t.locationId && perLocation.has(t.locationId))
          perLocation.set(t.locationId, perLocation.get(t.locationId)! - 1);
      const places = [];
      for (const [locationId, adds] of perLocation) {
        if (adds <= 0) continue;
        const row = rows.find((r) => (r.pick.locationId as string) === locationId);
        if (!row) continue;
        const pick = plan.providerSet.find((p) => p.locationId === locationId);
        const size = await sizeAt(
          { db: ctx.db },
          row.account,
          row.location,
          pick?.options !== undefined ? parseOptionValues(pick.options) : null,
        );
        const { cost } = await edgeCostAt(ctx.db, row.account, row.location._id, size);
        const each = costAdmin(cost);
        if (typeof each.monthly === 'number' && each.currency)
          totals.set(each.currency, (totals.get(each.currency) ?? 0) + each.monthly * adds);
        places.push({ locationId, label: row.location.label ?? row.location.placeKey, adds, each });
      }
      nodes.push({
        relaySlug: relay.slug,
        waiting: skip ?? refusal,
        added: plan.added,
        removed: plan.removed,
        places,
      });
    }
    return {
      refusal: null,
      nodes,
      totals: [...totals].map(([currency, monthly]) => ({ currency, monthly })),
    };
  },
});

/** A node takes no default picks for this country (`optOut: false` takes them again). */
export const setOptOut = internalMutation({
  args: {
    relayId: v.id('relays'),
    code: v.string(),
    optOut: v.boolean(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const relay = await ctx.db.get(a.relayId);
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Node not found' });
    const code = a.code.trim().toUpperCase();
    const was = relay.countryDefaultsOptOut ?? [];
    if (was.includes(code) === a.optOut) return { ok: true as const, changed: false };
    const next = a.optOut ? [...was, code].sort() : was.filter((c) => c !== code);
    await ctx.db.patch(relay._id, {
      countryDefaultsOptOut: next.length > 0 ? next : undefined,
      updatedAt: Date.now(),
    });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'edge.relay.country_defaults_opt_out',
      targetType: 'relay',
      targetId: relay._id,
      payload: { relaySlug: relay.slug, country: code, optOut: a.optOut },
    });
    return { ok: true as const, changed: true };
  },
});

// --- rollback ---------------------------------------------------------------------------------

async function stripDefaults(ctx: MutationCtx, relay: Relay): Promise<boolean> {
  const marked =
    relay.countryDefaultsOptOut !== undefined ||
    relay.countryDefaultsWaiting !== undefined ||
    (relay.providerSet ?? []).some(
      (p) => p.fromDefault || (p.audiences ?? []).some((x) => x.fromDefault),
    );
  if (!marked) return false;
  await ctx.db.patch(relay._id, {
    countryDefaultsOptOut: undefined,
    countryDefaultsWaiting: undefined,
    ...(relay.providerSet
      ? {
          providerSet: relay.providerSet.map(({ fromDefault: _f, audiences, ...p }) => {
            void _f;
            return audiences
              ? {
                  ...p,
                  audiences: audiences.map(({ fromDefault: _d, ...x }) => {
                    void _d;
                    return x;
                  }),
                }
              : p;
          }),
        }
      : {}),
  });
  return true;
}

/**
 * Before deploying a build without country defaults (docs/edges.md Deploy
 * notes): every default goes, and every node keeps what they wrote as its own
 * entries (so its countries' addresses stay as they are).
 */
export const clearCountryDefaultsForRollback = internalMutation({
  args: {},
  handler: async (ctx) => {
    let rows = 0;
    for (const r of await ctx.db.query('countryDefaults').collect()) {
      await ctx.db.delete(r._id);
      rows++;
    }
    let nodes = 0;
    for (const relay of await ctx.db.query('relays').collect())
      if (await stripDefaults(ctx, relay)) nodes++;
    return { rows, nodes };
  },
});
