/// <reference types="vite/client" />
/**
 * Tier-gated locations end to end (convex/lib/locationAccess.ts): a
 * members-only location is listed for everyone but never takes a key of
 * another tier (a HARD filter, unlike the soft location pick); "Switch
 * location" moves a member's key and keeps the link; a tier that keeps its
 * first location cannot change it; "Switch server" stays in the key's
 * location; and a key left on a location its tier lost is moved off. The
 * development mock backend issues the keys.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { resolveLocations } from './lib/locations';
import { resolvePlacementTarget } from './lib/remnawavePlacement';
import { locationTierSlugs, serverAllowsTier, tierCanSwitchLocation } from './lib/locationAccess';

const modules = import.meta.glob('./**/*.*s');

beforeEach(() => {
  vi.stubEnv('DEV_MOCK_BACKEND', 'true');
  vi.stubEnv('ENVIRONMENT', 'development');
});
afterEach(() => {
  vi.unstubAllEnvs();
});

const SQUAD_MCI = '11111111-2222-3333-4444-00000000000a';
const SQUAD_CHI = '11111111-2222-3333-4444-00000000000b';
const SQUAD_MCI_2 = '11111111-2222-3333-4444-00000000000c';

/**
 * Two locations: Kansas City (open to every tier) and Chicago (members only).
 * Chicago is the less loaded one, so only the tier filter keeps a free key out.
 * The user holds a key on `keyAt` (none when null).
 */
async function world(
  o: {
    member?: boolean;
    keyAt?: 'MCI' | 'CHI' | null;
    preferredLocation?: string;
    /** A second Kansas City group (another server in the same location). */
    secondMciGroup?: boolean;
  } = {},
) {
  const t = convexTest(schema, modules);
  const ids = await t.run(async (ctx) => {
    const now = Date.now();
    const tier = (slug: string, isDefaultFree: boolean, priority: number) =>
      ctx.db.insert('tiers', {
        slug,
        name: slug,
        backend: 'remnawave',
        monthlyTrafficGb: isDefaultFree ? 50 : 0,
        deviceLimit: 1,
        hwidLimit: 1,
        hwidEnabled: false,
        trafficStrategy: 'MONTH',
        isDefaultFree,
        isActive: true,
        priority,
        expirationDaysAfterMembershipLapse: 0,
        updatedAt: now,
      });
    const free = await tier('free', true, 0);
    const member = await tier('member', false, 10);
    const server = (slug: string, location: string, label: string, allowed?: Id<'tiers'>[]) =>
      ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: slug,
        slug,
        location,
        locationLabel: label,
        ...(allowed ? { allowedTierIds: allowed } : {}),
        config: { type: 'remnawave', baseUrl: `https://${slug}.example`, apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 0,
        lastHealthOkAt: now,
        updatedAt: now,
      });
    const mci = await server('mci', 'MCI', 'Kansas City, MO');
    const chi = await server('chi', 'CHI', 'Chicago, IL', [member]);
    const squads = [SQUAD_MCI, SQUAD_CHI, ...(o.secondMciGroup ? [SQUAD_MCI_2] : [])];
    await ctx.db.insert('modePlacements', {
      modeSlug: 'freedom-ws',
      backend: 'remnawave',
      config: JSON.stringify({ squadUuids: squads }),
      updatedAt: now,
    });
    for (const [serverId, placement, usersOnline] of [
      [mci, SQUAD_MCI, 50],
      [chi, SQUAD_CHI, 0],
      ...(o.secondMciGroup ? ([[mci, SQUAD_MCI_2, 60]] as const) : []),
    ] as const)
      await ctx.db.insert('remnawaveNodeStats', {
        backendServerId: serverId,
        placement,
        usersOnline,
        online: true,
        nodeCount: 1,
        lastStatsAt: now,
        updatedAt: now,
      });
    const userId = await ctx.db.insert('users', {
      tierId: o.member ? member : free,
      status: 'active',
      connectionModeId: 'freedom-ws',
      ...(o.preferredLocation ? { preferredLocation: o.preferredLocation } : {}),
      updatedAt: now,
    });
    let subId: Id<'subscriptions'> | null = null;
    if (o.keyAt) {
      subId = await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'old-key-uuid',
        backendShortId: 'oldshort',
        backendServerId: o.keyAt === 'CHI' ? chi : mci,
        backendPlacement: o.keyAt === 'CHI' ? SQUAD_CHI : SQUAD_MCI,
        subscriptionUrl: 'https://panel.example/sub/oldshort',
        subToken: 'tok-abc',
        subscriptionMirrors: [],
        state: 'active',
        updatedAt: now,
      });
      await ctx.db.patch(userId, { currentSubscriptionId: subId });
    }
    return { userId, free, member, mci, chi, subId };
  });
  return { t, ...ids };
}
type World = Awaited<ReturnType<typeof world>>;

const activeSub = (w: World) =>
  w.t.run(
    async (ctx) =>
      (await ctx.db.query('subscriptions').collect()).find(
        (s) => s.state === 'active',
      ) as Doc<'subscriptions'>,
  );
const userOf = (w: World) => w.t.run((ctx) => ctx.db.get(w.userId));

describe('lib/locationAccess', () => {
  test('an instance with no list takes every tier; a list takes only its tiers', () => {
    expect(serverAllowsTier({}, 'any')).toBe(true);
    expect(serverAllowsTier({ allowedTierIds: [] }, 'any')).toBe(true);
    const listed = { allowedTierIds: ['m' as Id<'tiers'>] };
    expect(serverAllowsTier(listed, 'm')).toBe(true);
    expect(serverAllowsTier(listed, 'f')).toBe(false);
    // No tier given = no filter (FCP's own checks).
    expect(serverAllowsTier(listed, null)).toBe(true);
  });

  test('switching location defaults to paid tiers; an explicit flag wins', () => {
    expect(tierCanSwitchLocation({ isDefaultFree: true })).toBe(false);
    expect(tierCanSwitchLocation({ isDefaultFree: false })).toBe(true);
    expect(tierCanSwitchLocation({ isDefaultFree: true, canSwitchLocation: true })).toBe(true);
    expect(tierCanSwitchLocation({ isDefaultFree: false, canSwitchLocation: false })).toBe(false);
  });

  test('a location is open to everyone when any of its instances is; else the union, by slug', () => {
    const tiers = [
      { _id: 'f' as Id<'tiers'>, slug: 'free', priority: 0 },
      { _id: 'm' as Id<'tiers'>, slug: 'member', priority: 10 },
    ];
    expect(locationTierSlugs([{ allowedTierIds: ['m' as Id<'tiers'>] }, {}], tiers)).toBeNull();
    expect(
      locationTierSlugs(
        [{ allowedTierIds: ['m' as Id<'tiers'>] }, { allowedTierIds: ['gone' as Id<'tiers'>] }],
        tiers,
      ),
    ).toEqual(['member']);
  });
});

describe('the public catalog', () => {
  test('lists the members-only location with its tiers, the open one with null', async () => {
    const w = await world();
    const locations = await w.t.run((ctx) => resolveLocations(ctx.db));
    expect(locations.find((l) => l.code === 'MCI')?.tiers).toBeNull();
    expect(locations.find((l) => l.code === 'CHI')?.tiers).toEqual(['member']);
  });
});

describe('issuance never places a tier where it is not allowed', () => {
  test('the placement filter is hard: a pick of the members-only location does not hold', async () => {
    const w = await world();
    const free = await w.t.run((ctx) =>
      resolvePlacementTarget(ctx.db, 'freedom-ws', { location: 'CHI', tierId: w.free }),
    );
    expect(free).toEqual({ placement: SQUAD_MCI, serverId: w.mci });
    const member = await w.t.run((ctx) =>
      resolvePlacementTarget(ctx.db, 'freedom-ws', { location: 'CHI', tierId: w.member }),
    );
    expect(member).toEqual({ placement: SQUAD_CHI, serverId: w.chi });
  });

  test('pinned to a panel the tier may not use: nothing (the caller re-issues elsewhere)', async () => {
    const w = await world();
    const target = await w.t.run((ctx) =>
      resolvePlacementTarget(ctx.db, 'freedom-ws', { onlyServerId: w.chi, tierId: w.free }),
    );
    expect(target).toEqual({ placement: null, serverId: null });
  });

  test("a free member's first key stays in Kansas City though Chicago is less loaded", async () => {
    const w = await world({ keyAt: null });
    await w.t.action(internal.account.regenerate, { userId: w.userId, location: 'CHI' });
    expect((await activeSub(w)).backendPlacement).toBe(SQUAD_MCI);
  });

  test("a member's first key can go to the members-only location", async () => {
    const w = await world({ member: true, keyAt: null });
    await w.t.action(internal.account.regenerate, { userId: w.userId, location: 'CHI' });
    expect((await activeSub(w)).backendPlacement).toBe(SQUAD_CHI);
  });

  test('no instance takes the tier: nothing is placed', async () => {
    const w = await world();
    await w.t.run((ctx) => ctx.db.patch(w.mci, { allowedTierIds: [w.member] }));
    const target = await w.t.run((ctx) =>
      resolvePlacementTarget(ctx.db, 'freedom-ws', { tierId: w.free }),
    );
    expect(target).toEqual({ placement: null, serverId: null });
  });
});

describe('the location choice check', () => {
  const check = (w: World, location: string | null) =>
    w.t.query(internal.account.locationChoiceCheck, { userId: w.userId, location });

  test('a members-only location is refused to a free member', async () => {
    const w = await world({ keyAt: null });
    expect(await check(w, 'CHI')).toMatchObject({ code: 'location.members_only', status: 403 });
    expect(await check(w, 'MCI')).toBeNull();
    expect(await check(w, null)).toBeNull();
    expect(await check(w, 'NOPE')).toMatchObject({ code: 'validation', status: 400 });
  });

  test('a free member with a key keeps their location; a member may change it', async () => {
    const free = await world({ keyAt: 'MCI', preferredLocation: 'MCI' });
    expect(await check(free, 'MCI')).toBeNull();
    expect(await check(free, null)).toMatchObject({
      code: 'location.switch_requires_membership',
    });
    const member = await world({ member: true, keyAt: 'MCI' });
    expect(await check(member, 'CHI')).toBeNull();
  });
});

describe('Switch location', () => {
  test('moves a member key to the location, keeps the link and saves the pick', async () => {
    const w = await world({ member: true, keyAt: 'MCI' });
    const res = await w.t.action(internal.account.switchLocation, {
      userId: w.userId,
      location: 'CHI',
    });
    expect(res).toMatchObject({ ok: true, inPlace: false });
    const fresh = await activeSub(w);
    expect(fresh._id).not.toBe(w.subId);
    expect(fresh.backendPlacement).toBe(SQUAD_CHI);
    expect(fresh.subToken).toBe('tok-abc');
    expect((await userOf(w))!.preferredLocation).toBe('CHI');
    const audit = await w.t.run(async (ctx) =>
      (await ctx.db.query('auditLog').collect()).filter(
        (r) => r.action === 'subscription.switch_location',
      ),
    );
    expect(audit).toHaveLength(1);
  });

  test('a free member is refused before anything moves', async () => {
    const w = await world({ keyAt: 'MCI' });
    const res = await w.t.action(internal.account.switchLocation, {
      userId: w.userId,
      location: 'CHI',
    });
    expect(res).toMatchObject({ ok: false, code: 'location.switch_requires_membership' });
    expect((await activeSub(w))._id).toBe(w.subId);
  });

  test('the location the key is already in is no move', async () => {
    const w = await world({ member: true, keyAt: 'MCI' });
    const res = await w.t.action(internal.account.switchLocation, {
      userId: w.userId,
      location: 'MCI',
    });
    expect(res).toMatchObject({ ok: false, code: 'location.same' });
    expect((await activeSub(w))._id).toBe(w.subId);
  });

  test("a location the member's tier is not on is refused", async () => {
    const w = await world({ member: true, keyAt: 'MCI' });
    await w.t.run((ctx) => ctx.db.patch(w.chi, { allowedTierIds: [w.free] }));
    const res = await w.t.action(internal.account.switchLocation, {
      userId: w.userId,
      location: 'CHI',
    });
    expect(res).toMatchObject({ ok: false, code: 'location.members_only' });
  });
});

describe('Switch server stays in the location', () => {
  test('with another server only in another location, there is nothing to switch to', async () => {
    const w = await world({ member: true, keyAt: 'MCI' });
    expect(await w.t.query(internal.account.switchServerAvailable, { userId: w.userId })).toBe(
      false,
    );
    const res = await w.t.action(internal.account.switchServer, {
      userId: w.userId,
      reason: 'slow',
    });
    expect(res).toMatchObject({ ok: false, code: 'server.no_alternative' });
    expect((await activeSub(w))._id).toBe(w.subId);
  });
  test('another server in the same location is a move', async () => {
    const w = await world({ member: true, keyAt: 'MCI', secondMciGroup: true });
    expect(await w.t.query(internal.account.switchServerAvailable, { userId: w.userId })).toBe(
      true,
    );
    const res = await w.t.action(internal.account.switchServer, {
      userId: w.userId,
      reason: 'slow',
    });
    expect(res).toMatchObject({ ok: true });
    expect((await activeSub(w)).backendPlacement).toBe(SQUAD_MCI_2);
  });
});

describe('a key left where its tier may no longer go', () => {
  test('is moved off with its link, and the unusable pick is cleared', async () => {
    const w = await world({ member: true, keyAt: 'CHI', preferredLocation: 'CHI' });
    expect(await w.t.query(internal.account.relocationNeeded, { userId: w.userId })).toBe(false);
    // The membership lapses: the member is on the free tier now.
    await w.t.run((ctx) => ctx.db.patch(w.userId, { tierId: w.free }));
    expect(await w.t.query(internal.account.relocationNeeded, { userId: w.userId })).toBe(true);
    await w.t.action(internal.account.relocateForTier, { userId: w.userId });
    const fresh = await activeSub(w);
    expect(fresh._id).not.toBe(w.subId);
    expect(fresh.backendPlacement).toBe(SQUAD_MCI);
    expect(fresh.subToken).toBe('tok-abc');
    expect((await userOf(w))!.preferredLocation).toBeUndefined();
  });

  test('the tier push schedules the move', async () => {
    vi.useFakeTimers();
    try {
      const w = await world({ keyAt: 'CHI' });
      await w.t.action(internal.lifecycle.pushTierToBackend, { userId: w.userId });
      await w.t.finishAllScheduledFunctions(vi.runAllTimers);
      expect((await activeSub(w)).backendPlacement).toBe(SQUAD_MCI);
    } finally {
      vi.useRealTimers();
    }
  });
});
