/**
 * Where a member connects from: storage (docs/privacy.md "Where a member
 * connects from"; the rules are pure in lib/memberCountry.ts).
 *
 * THE INVARIANT: a subscription row's STORED country is its choice (`ZZ` =
 * none), else its live guess, else none; every other copy of a country on the
 * row (today: a cached body's `region`) is absent or equal to it. So the
 * indexes on the choice and the guess find every row that holds a country
 * anywhere. Three rules keep it true:
 *  - every change of the stored country goes through `setStoredCountry`, which
 *    bumps `countryRev` and drops the copies that no longer match, in the same
 *    transaction;
 *  - `subscriptions.writeContentCache` refuses a copy that differs from the
 *    stored country at write time;
 *  - a transient country (detection off) is stored nowhere.
 *
 * Nothing here takes a client address: the HTTP actions compare it with the
 * own-exit set (lib/ownExits.ts) and pass only a boolean.
 */
import { internalMutation, internalQuery } from './_generated/server';
import type { DatabaseReader, MutationCtx } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { internal } from './_generated/api';
import { ConvexError, v } from 'convex/values';
import { resolveCensoredCountries } from './lib/censoredCountries';
import {
  ELSEWHERE,
  MEMBER_COUNTRY_KEYS,
  liveChoice,
  memberCountryConfig,
  memberCountryView,
  nextGuess,
  storedCountry,
  type CountryFields,
  type MemberCountryConfig,
  type MemberFamily,
} from './lib/memberCountry';
import { familyOfPlacement, familyReads, memberFamilyOf } from './lib/memberFamily';
import { EMPTY_OWN_EXITS, type OwnExits } from './lib/ownExits';
import { OWN_EXITS_STATE_KEY } from './ownExits';
import { recordHeartbeat } from './cronHeartbeat';

const DAY = 86_400_000;
const PAGE = 200;

async function readSetting(db: DatabaseReader, key: string): Promise<unknown> {
  const row = await db
    .query('appSettings')
    .withIndex('by_key', (q) => q.eq('key', key))
    .unique();
  if (!row) return undefined;
  try {
    return JSON.parse(row.value);
  } catch {
    return undefined;
  }
}

export async function resolveMemberCountryConfig(db: DatabaseReader): Promise<MemberCountryConfig> {
  const keys = Object.values(MEMBER_COUNTRY_KEYS);
  const values = await Promise.all(keys.map((k) => readSetting(db, k)));
  return memberCountryConfig(Object.fromEntries(keys.map((k, i) => [k, values[i]])));
}

async function settingsAndList(db: DatabaseReader) {
  const [cfg, censored] = await Promise.all([
    resolveMemberCountryConfig(db),
    resolveCensoredCountries(db),
  ]);
  return { cfg, listed: censored.codes };
}

function fieldsOf(sub: Doc<'subscriptions'>): CountryFields {
  return {
    sniRegion: sub.sniRegion ?? null,
    regionSeenCountry: sub.regionSeenCountry ?? null,
    regionSeenFirstAt: sub.regionSeenFirstAt ?? null,
    regionSeenAt: sub.regionSeenAt ?? null,
  };
}

/** The cached bodies that may stay: no region, or the row's stored country. */
function keptCache(blob: string | undefined, stored: string | null): string | undefined {
  if (!blob) return blob;
  let entries: unknown[];
  try {
    const parsed = JSON.parse(blob) as unknown;
    entries = Array.isArray(parsed) ? parsed : parsed && typeof parsed === 'object' ? [parsed] : [];
  } catch {
    return undefined;
  }
  const kept = entries.filter((e) => {
    const region = e && typeof e === 'object' ? (e as { region?: unknown }).region : undefined;
    return region === undefined || region === null || region === stored;
  });
  if (kept.length === entries.length) return blob;
  return kept.length > 0 ? JSON.stringify(kept) : undefined;
}

/**
 * The render snapshot with its country-bearing fields kept only while they
 * name the stored country (`country`, `primaryTier`, `backupTier`): the
 * snapshot is one more stored copy of the member's country.
 */
export function keptSnapshot(
  snap: Doc<'subscriptions'>['lastRender'],
  stored: string | null,
): Doc<'subscriptions'>['lastRender'] {
  if (!snap || snap.country === undefined || snap.country === stored) return snap;
  const { country, primaryTier, backupTier, ...rest } = snap;
  void country;
  void primaryTier;
  void backupTier;
  return rest;
}

/**
 * THE way to change a row's stored country. `choice` / `guess`: `undefined`
 * keeps the field, `null` clears it. Bumps `countryRev` whenever what is stored
 * changes (a refresh of the same guess's last-seen time does not), drops every
 * cached body whose region no longer matches, and strips a render snapshot's
 * country (and tiers) that no longer matches.
 */
export async function setStoredCountry(
  ctx: MutationCtx,
  sub: Doc<'subscriptions'>,
  change: {
    choice?: string | null;
    guess?: { country: string; firstAt: number; at: number } | null;
  },
  ctxValues?: { cfg: MemberCountryConfig; listed: readonly string[]; now?: number },
): Promise<Doc<'subscriptions'>> {
  const { cfg, listed } = ctxValues ?? (await settingsAndList(ctx.db));
  const now = ctxValues?.now ?? Date.now();
  const before = fieldsOf(sub);
  const after: CountryFields = {
    ...before,
    ...(change.choice !== undefined ? { sniRegion: change.choice } : {}),
    ...(change.guess !== undefined
      ? {
          regionSeenCountry: change.guess?.country ?? null,
          regionSeenFirstAt: change.guess?.firstAt ?? null,
          regionSeenAt: change.guess?.at ?? null,
        }
      : {}),
  };
  const storedBefore = storedCountry(before, cfg, listed, now);
  const storedAfter = storedCountry(after, cfg, listed, now);
  const identityChanged =
    before.sniRegion !== after.sniRegion || before.regionSeenCountry !== after.regionSeenCountry;
  const bump = identityChanged || storedBefore !== storedAfter;
  const subCache = keptCache(sub.subCache, storedAfter);
  const lastRender = keptSnapshot(sub.lastRender, storedAfter);
  const patch: Partial<Doc<'subscriptions'>> = {
    sniRegion: after.sniRegion ?? undefined,
    regionSeenCountry: after.regionSeenCountry ?? undefined,
    regionSeenFirstAt: after.regionSeenFirstAt ?? undefined,
    regionSeenAt: after.regionSeenAt ?? undefined,
    ...(subCache !== sub.subCache ? { subCache } : {}),
    ...(lastRender !== sub.lastRender ? { lastRender } : {}),
    ...(bump ? { countryRev: (sub.countryRev ?? 0) + 1 } : {}),
  };
  await ctx.db.patch(sub._id, patch);
  return { ...sub, ...patch } as Doc<'subscriptions'>;
}

/** Clear every stored copy of the member's country (the choice too unless `keepChoice`). */
export async function clearMemberCountry(
  ctx: MutationCtx,
  sub: Doc<'subscriptions'>,
  opts: { keepChoice?: boolean } = {},
): Promise<Doc<'subscriptions'>> {
  return setStoredCountry(ctx, sub, { guess: null, ...(opts.keepChoice ? {} : { choice: null }) });
}

/** Does the row hold a country anywhere? */
export function holdsCountry(sub: Doc<'subscriptions'>): boolean {
  return !!(sub.sniRegion || sub.regionSeenCountry || sub.regionSeenAt);
}

/** Apply one CDN reading to one row; the decision is re-taken on the current row. */
async function applyReading(
  ctx: MutationCtx,
  sub: Doc<'subscriptions'>,
  family: MemberFamily,
  reading: { country: string | null; ownExit: boolean },
  c: { cfg: MemberCountryConfig; listed: readonly string[]; now: number },
): Promise<Doc<'subscriptions'>> {
  const update = nextGuess({
    family,
    sub: fieldsOf(sub),
    cfg: c.cfg,
    listed: c.listed,
    now: c.now,
    reading: reading.country,
    ownExit: reading.ownExit,
  });
  switch (update.kind) {
    case 'none':
      return sub;
    case 'set':
      return setStoredCountry(
        ctx,
        sub,
        { guess: { country: update.country, firstAt: c.now, at: c.now } },
        c,
      );
    case 'refresh':
      return setStoredCountry(
        ctx,
        sub,
        {
          guess: {
            country: sub.regionSeenCountry!,
            firstAt: sub.regionSeenFirstAt ?? c.now,
            at: c.now,
          },
        },
        c,
      );
    case 'clear':
      return setStoredCountry(ctx, sub, { guess: null }, c);
  }
}

/** The fields the fronted route needs back after a reading. */
const fieldsOut = (s: Doc<'subscriptions'>) => ({
  sniRegion: s.sniRegion ?? null,
  regionSeenCountry: s.regionSeenCountry ?? null,
  regionSeenFirstAt: s.regionSeenFirstAt ?? null,
  regionSeenAt: s.regionSeenAt ?? null,
  countryRev: s.countryRev ?? 0,
});

/**
 * One reading on the fronted subscription route. Applied only when the row is
 * still at the revision the request read (a transition in between wins) and
 * not deleted. Returns the row's country fields afterwards, or null when
 * nothing could be applied.
 */
export const noteSeenCountry = internalMutation({
  args: {
    subscriptionId: v.id('subscriptions'),
    countryRev: v.number(),
    country: v.union(v.string(), v.null()),
    ownExit: v.boolean(),
  },
  handler: async (ctx, a) => {
    const sub = await ctx.db.get(a.subscriptionId);
    if (!sub || sub.state === 'deleted' || (sub.countryRev ?? 0) !== a.countryRev) return null;
    const { cfg, listed } = await settingsAndList(ctx.db);
    const family = await memberFamilyOf(ctx.db, sub);
    const after = await applyReading(
      ctx,
      sub,
      family,
      { country: a.country, ownExit: a.ownExit },
      { cfg, listed, now: Date.now() },
    );
    return fieldsOut(after);
  },
});

/**
 * One reading on the account view: every active freedom-family key of the
 * member. Returns what their current key uses and where it came from (the mode
 * suggestion reads it: a stored "Somewhere else" is an answer, not "unknown").
 */
export const noteSeenCountryForUser = internalMutation({
  args: {
    userId: v.id('users'),
    country: v.union(v.string(), v.null()),
    ownExit: v.boolean(),
  },
  handler: async (
    ctx,
    a,
  ): Promise<{ effective: string | null; source: 'choice' | 'guess' | 'none' }> => {
    const nothing = { effective: null, source: 'none' as const };
    const user = await ctx.db.get(a.userId);
    if (!user) return nothing;
    const { cfg, listed } = await settingsAndList(ctx.db);
    const now = Date.now();
    const subs = await ctx.db
      .query('subscriptions')
      .withIndex('by_user_state', (q) => q.eq('userId', a.userId).eq('state', 'active'))
      .collect();
    const currentId = (subs.find((s) => s._id === user.currentSubscriptionId) ?? subs[0])?._id;
    let current: { effective: string | null; source: 'choice' | 'guess' | 'none' } = nothing;
    for (const s of subs) {
      const family = await memberFamilyOf(ctx.db, s, user);
      if (family !== 'freedom') continue;
      const after = await applyReading(
        ctx,
        s,
        family,
        { country: a.country, ownExit: a.ownExit },
        { cfg, listed, now },
      );
      if (s._id === currentId) {
        const view = memberCountryView(family, fieldsOf(after), cfg, listed, now);
        current = { effective: view.effective, source: view.source };
      }
    }
    return current;
  },
});

/**
 * What the delivery routes need to decide where the member is
 * (lib/subscriptionDelivery.ts `locateMember` / `locateAt`): the key's family
 * judged at `nodeName` (the node the body resolves to, default the stored pin),
 * the settings, the list and the own-exit set.
 */
export const contextFor = internalQuery({
  args: { subscriptionId: v.id('subscriptions'), nodeName: v.optional(v.string()) },
  handler: async (ctx, { subscriptionId, nodeName }) => {
    const sub = await ctx.db.get(subscriptionId);
    const { cfg, listed } = await settingsAndList(ctx.db);
    const family: MemberFamily = sub
      ? await memberFamilyOf(ctx.db, { ...sub, pinnedNode: nodeName ?? sub.pinnedNode })
      : 'none';
    const exits = cfg.detect ? await readOwnExits(ctx.db) : EMPTY_OWN_EXITS;
    return { family, cfg, listed, ownExits: exits };
  },
});

/** The account route's reading: whether detection is on, and the own-exit set to compare with. */
export const readingContext = internalQuery({
  args: {},
  handler: async (ctx) => {
    const cfg = await resolveMemberCountryConfig(ctx.db);
    return {
      detect: cfg.detect,
      ownExits: cfg.detect ? await readOwnExits(ctx.db) : EMPTY_OWN_EXITS,
    };
  },
});

/** The client-ip diagnostic: the own-exit set whatever detection says. */
export const ownExitsForDiagnostic = internalQuery({
  args: {},
  handler: async (ctx) => ({ ownExits: await readOwnExits(ctx.db) }),
});

export async function readOwnExits(db: DatabaseReader): Promise<OwnExits> {
  const row = await db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', OWN_EXITS_STATE_KEY))
    .unique();
  let value: Partial<OwnExits> | undefined;
  try {
    value = row ? (JSON.parse(row.value) as Partial<OwnExits>) : undefined;
  } catch {
    value = undefined;
  }
  return value && Array.isArray(value.v4)
    ? {
        v4: value.v4,
        v6Prefixes: Array.isArray(value.v6Prefixes) ? value.v6Prefixes : [],
        cidrs: Array.isArray(value.cidrs) ? value.cidrs : [],
      }
    : EMPTY_OWN_EXITS;
}

// --- the member's own answer ----------------------------------------------------------

/** The account page's control: the member's current key, as they see it. */
export const memberView = internalQuery({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }) => {
    const user = await ctx.db.get(userId);
    const { cfg, listed } = await settingsAndList(ctx.db);
    const subs = await ctx.db
      .query('subscriptions')
      .withIndex('by_user_state', (q) => q.eq('userId', userId).eq('state', 'active'))
      .collect();
    const sub = subs.find((s) => s._id === user?.currentSubscriptionId) ?? subs[0] ?? null;
    const family: MemberFamily = sub ? await memberFamilyOf(ctx.db, sub, user) : 'none';
    const view = memberCountryView(family, sub ? fieldsOf(sub) : {}, cfg, listed, Date.now());
    return {
      ...view,
      options: view.applies ? listed : [],
      detect: cfg.detect,
      stickyDays: cfg.stickyDays,
    };
  },
});

/**
 * "Where are you connecting from?": a listed country, `ZZ`, or null
 * (Automatic). Written on every active freedom-family key of the member; a
 * choice clears any guess. Refused when no key of theirs has a country at all.
 */
export const setChoice = internalMutation({
  args: { userId: v.id('users'), region: v.union(v.string(), v.null()) },
  handler: async (ctx, { userId, region }) => {
    const user = await ctx.db.get(userId);
    const { cfg, listed } = await settingsAndList(ctx.db);
    const next = region ? region.trim().toUpperCase() : null;
    if (next && next !== ELSEWHERE && !listed.includes(next))
      throw new ConvexError({ code: 'validation', message: 'unknown region' });
    const subs = await ctx.db
      .query('subscriptions')
      .withIndex('by_user_state', (q) => q.eq('userId', userId).eq('state', 'active'))
      .collect();
    let applied = 0;
    for (const s of subs) {
      if ((await memberFamilyOf(ctx.db, s, user)) !== 'freedom') continue;
      await setStoredCountry(ctx, s, next ? { choice: next, guess: null } : { choice: null }, {
        cfg,
        listed,
      });
      applied++;
    }
    if (next && applied === 0)
      throw new ConvexError({
        code: 'validation',
        message: 'Your connection mode does not use a country',
      });
    return { region: next };
  },
});

// --- transitions ----------------------------------------------------------------------

/** The in-place mode switch moved the key into this placement: a privacy-family one clears. */
export async function onPlacementChanged(
  ctx: MutationCtx,
  sub: Doc<'subscriptions'>,
  placement: string | null,
): Promise<void> {
  if (!holdsCountry(sub)) return;
  if ((await familyOfPlacement(ctx.db, placement)) === 'freedom') return;
  await clearMemberCountry(ctx, sub);
}

/** What a newly issued key inherits from the key it replaces. */
export async function carriedCountry(
  db: DatabaseReader,
  from: Doc<'subscriptions'> | null,
  placement: string | null | undefined,
  what: 'choice' | 'choice_and_guess',
): Promise<Partial<Doc<'subscriptions'>>> {
  if (!from || !holdsCountry(from)) return {};
  if ((await familyOfPlacement(db, placement)) !== 'freedom') return {};
  return {
    ...(from.sniRegion ? { sniRegion: from.sniRegion } : {}),
    ...(what === 'choice_and_guess' && from.regionSeenCountry
      ? {
          regionSeenCountry: from.regionSeenCountry,
          regionSeenFirstAt: from.regionSeenFirstAt,
          regionSeenAt: from.regionSeenAt,
        }
      : {}),
  };
}

// --- sweeps ------------------------------------------------------------------------------

/**
 * Daily (`region-seen-expire`): guesses past `stickyDays`, and every guess
 * while detection is off. Bounded pages, rescheduled until done, with no cap on
 * the rounds: a cleared row leaves the index, so the walk ends, and no guess
 * the run is due to clear waits for another day.
 */
export const sweepGuesses = internalMutation({
  args: { now: v.optional(v.number()), rounds: v.optional(v.number()) },
  handler: async (ctx, a) => {
    if ((a.rounds ?? 0) === 0) await recordHeartbeat(ctx, 'region-seen-expire');
    const now = a.now ?? Date.now();
    const { cfg, listed } = await settingsAndList(ctx.db);
    const cutoff = cfg.detect ? now - cfg.stickyDays * DAY : Number.MAX_SAFE_INTEGER;
    const rows = await ctx.db
      .query('subscriptions')
      .withIndex('by_region_seen_at', (q) => q.gt('regionSeenAt', 0).lt('regionSeenAt', cutoff))
      .take(PAGE);
    for (const s of rows) await setStoredCountry(ctx, s, { guess: null }, { cfg, listed, now });
    if (rows.length === PAGE)
      await ctx.scheduler.runAfter(0, internal.memberCountry.sweepGuesses, {
        now,
        rounds: (a.rounds ?? 0) + 1,
      });
    return { cleared: rows.length };
  },
});

/** A country left the censored-country list: no choice or guess of it may remain. */
export const sweepCountry = internalMutation({
  args: { country: v.string(), rounds: v.optional(v.number()) },
  handler: async (ctx, a) => {
    const { cfg, listed } = await settingsAndList(ctx.db);
    if (listed.includes(a.country)) return { cleared: 0 };
    const choices = await ctx.db
      .query('subscriptions')
      .withIndex('by_sni_region', (q) => q.eq('sniRegion', a.country))
      .take(PAGE);
    for (const s of choices) await setStoredCountry(ctx, s, { choice: null }, { cfg, listed });
    const guesses = await ctx.db
      .query('subscriptions')
      .withIndex('by_region_seen_country', (q) => q.eq('regionSeenCountry', a.country))
      .take(PAGE);
    for (const s of guesses) {
      const fresh = (await ctx.db.get(s._id))!;
      await setStoredCountry(ctx, fresh, { guess: null }, { cfg, listed });
    }
    // Until done: every cleared row leaves both indexes, so the walk ends; a
    // country removed from the list is never swept again by anything else.
    if (choices.length === PAGE || guesses.length === PAGE)
      await ctx.scheduler.runAfter(0, internal.memberCountry.sweepCountry, {
        country: a.country,
        rounds: (a.rounds ?? 0) + 1,
      });
    return { cleared: choices.length + guesses.length };
  },
});

/**
 * Idempotent clean-up (every deploy, `seedCutover` schedules it): a stored
 * choice that is no longer on the list, and any country on a key that is not
 * freedom-family. Walks only rows that hold a choice or a guess. What judging
 * a key reads beyond the key and its member is read once per page, so a page
 * stays far inside one execution's reads however many modes are bound.
 */
export const cleanStoredCountries = internalMutation({
  args: { cursor: v.optional(v.union(v.string(), v.null())), pass: v.optional(v.string()) },
  handler: async (ctx, a) => {
    const pass = a.pass ?? 'choice';
    const { cfg, listed } = await settingsAndList(ctx.db);
    const page =
      pass === 'choice'
        ? await ctx.db
            .query('subscriptions')
            .withIndex('by_sni_region', (q) => q.gt('sniRegion', ''))
            .paginate({ cursor: a.cursor ?? null, numItems: PAGE })
        : await ctx.db
            .query('subscriptions')
            .withIndex('by_region_seen_at', (q) => q.gt('regionSeenAt', 0))
            .paginate({ cursor: a.cursor ?? null, numItems: PAGE });
    const reads = familyReads();
    let cleared = 0;
    for (const s of page.page) {
      if ((await memberFamilyOf(ctx.db, s, undefined, reads)) !== 'freedom') {
        await setStoredCountry(ctx, s, { guess: null, choice: null }, { cfg, listed });
        cleared++;
      } else if (s.sniRegion && !liveChoice(fieldsOf(s), listed)) {
        await setStoredCountry(ctx, s, { choice: null }, { cfg, listed });
        cleared++;
      }
    }
    if (!page.isDone)
      await ctx.scheduler.runAfter(0, internal.memberCountry.cleanStoredCountries, {
        cursor: page.continueCursor,
        pass,
      });
    else if (pass === 'choice')
      await ctx.scheduler.runAfter(0, internal.memberCountry.cleanStoredCountries, {
        cursor: null,
        pass: 'guess',
      });
    return { cleared };
  },
});

// --- the admin view -------------------------------------------------------------------------

async function edgeLabel(db: DatabaseReader, id: Id<'edges'> | undefined): Promise<string | null> {
  if (!id) return null;
  const edge = await db.get(id);
  if (!edge) return 'an address that is gone';
  const location = edge.locationId ? await db.get(edge.locationId) : null;
  return [edge.provider ?? 'adopted', location?.label ?? null].filter(Boolean).join(' · ');
}

/**
 * Admin -> Users -> Live details: per active key, the family, the member's
 * choice, the guess (first and last seen), what delivery uses and what the
 * last render handed out. Not audited (docs/privacy.md).
 */
export const adminView = internalQuery({
  args: { userId: v.string() },
  handler: async (ctx, a) => {
    const userId = ctx.db.normalizeId('users', a.userId);
    const user = userId ? await ctx.db.get(userId) : null;
    if (!userId || !user) return null;
    const { cfg, listed } = await settingsAndList(ctx.db);
    const now = Date.now();
    const subs = await ctx.db
      .query('subscriptions')
      .withIndex('by_user_state', (q) => q.eq('userId', userId).eq('state', 'active'))
      .collect();
    const keys = [];
    for (const s of subs) {
      const family = await memberFamilyOf(ctx.db, s, user);
      const view = memberCountryView(family, fieldsOf(s), cfg, listed, now);
      keys.push({
        current: s._id === user.currentSubscriptionId,
        backend: s.backend,
        family,
        ...view,
        delivered: s.lastRender
          ? {
              at: s.lastRender.at,
              primary: await edgeLabel(ctx.db, s.lastRender.primaryEdgeId),
              backup: await edgeLabel(ctx.db, s.lastRender.backupEdgeId),
            }
          : null,
      });
    }
    return { detect: cfg.detect, stickyDays: cfg.stickyDays, keys };
  },
});
