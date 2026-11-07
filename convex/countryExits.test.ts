/// <reference types="vite/client" />
/**
 * Exit location by country end to end (convex/countryExits.ts, docs/edges.md
 * "Exit location by country"): the codes a new key narrows to (the member's own
 * choice only, on Automatic, a freedom mode, steering on), a regenerate that
 * lands there, the account page's suggestion and its one-time move (the link
 * carried, the member left on Automatic, nothing about the country audited),
 * and the rollback helper. The development mock backend issues the keys.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Doc } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { CENSORED_COUNTRIES_KEY } from './lib/censoredCountries';
import { COUNTRY_EXITS_KEY } from './lib/countryExits';

const modules = import.meta.glob('./**/*.*s');

beforeEach(() => {
  vi.stubEnv('DEV_MOCK_BACKEND', 'true');
  vi.stubEnv('ENVIRONMENT', 'development');
});
afterEach(() => {
  vi.unstubAllEnvs();
});

const SQUAD_A = '11111111-2222-3333-4444-00000000000a';
const SQUAD_B = '11111111-2222-3333-4444-00000000000b';
const SQUAD_P = '11111111-2222-3333-4444-00000000000c';

/**
 * Two locations: the member's key on loc-a (the less loaded one), loc-b mapped
 * as Iran's exit. The member chose Iran themselves unless `sub` says otherwise.
 */
async function world(
  o: {
    sub?: Partial<Doc<'subscriptions'>>;
    mode?: string;
    preferredLocation?: string;
    steer?: boolean;
    bOnline?: boolean;
  } = {},
) {
  const t = convexTest(schema, modules);
  const ids = await t.run(async (ctx) => {
    const now = Date.now();
    const tierId = await ctx.db.insert('tiers', {
      slug: 'free',
      name: 'Free',
      backend: 'remnawave',
      monthlyTrafficGb: 50,
      deviceLimit: 1,
      hwidLimit: 1,
      hwidEnabled: false,
      trafficStrategy: 'MONTH',
      isDefaultFree: true,
      isActive: true,
      priority: 0,
      expirationDaysAfterMembershipLapse: 0,
      updatedAt: now,
    });
    const userId = await ctx.db.insert('users', {
      tierId,
      status: 'active',
      connectionModeId: o.mode ?? 'freedom-ws',
      ...(o.preferredLocation ? { preferredLocation: o.preferredLocation } : {}),
      updatedAt: now,
    });
    const server = (slug: string, location: string, online: boolean) =>
      ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: slug,
        slug,
        location,
        locationLabel: `Label ${location}`,
        config: { type: 'remnawave', baseUrl: `https://${slug}.example`, apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 0,
        ...(online ? { lastHealthOkAt: now } : {}),
        updatedAt: now,
      });
    const a = await server('a', 'loc-a', true);
    const b = await server('b', 'loc-b', o.bOnline ?? true);
    for (const [modeSlug, squads] of [
      ['freedom-ws', [SQUAD_A, SQUAD_B]],
      ['privacy-reality', [SQUAD_P]],
    ] as const)
      await ctx.db.insert('modePlacements', {
        modeSlug,
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: squads }),
        updatedAt: now,
      });
    // loc-b's node load is unknown, so without an exit the pick is always loc-a.
    for (const [serverId, placement, online] of [
      [a, SQUAD_A, true],
      [b, SQUAD_B, false],
      [a, SQUAD_P, true],
    ] as const)
      await ctx.db.insert('remnawaveNodeStats', {
        backendServerId: serverId,
        placement,
        usersOnline: 0,
        online,
        nodeCount: 1,
        lastStatsAt: now,
        updatedAt: now,
      });
    const subId = await ctx.db.insert('subscriptions', {
      userId,
      backend: 'remnawave',
      backendUserId: 'old-key-uuid',
      backendShortId: 'oldshort',
      backendServerId: a,
      backendPlacement: o.mode === 'privacy-reality' ? SQUAD_P : SQUAD_A,
      subscriptionUrl: 'https://a.example/sub/oldshort',
      subToken: 'tok-abc',
      subscriptionMirrors: [],
      state: 'active',
      sniRegion: 'IR',
      updatedAt: now,
      ...o.sub,
    });
    await ctx.db.patch(userId, { currentSubscriptionId: subId });
    await upsertSettingRow(
      ctx,
      CENSORED_COUNTRIES_KEY,
      JSON.stringify(
        ['IR', 'RU'].map((code) => ({ code, checkEdges: true, checkNamesInside: false })),
      ),
    );
    await upsertSettingRow(ctx, 'delivery.country.detect', 'true');
    await upsertSettingRow(ctx, 'delivery.country.steer', JSON.stringify(o.steer ?? true));
    await upsertSettingRow(
      ctx,
      COUNTRY_EXITS_KEY,
      JSON.stringify([{ country: 'IR', locations: ['loc-gone', 'loc-b'] }]),
    );
    return { userId, a, b, subId };
  });
  return { t, ...ids };
}
type World = Awaited<ReturnType<typeof world>>;

const forIssue = (w: World, modeId: string | null = 'freedom-ws') =>
  w.t.query(internal.countryExits.forIssue, { userId: w.userId, backend: 'remnawave', modeId });
const activeSub = (w: World) =>
  w.t.run(async (ctx) =>
    (await ctx.db.query('subscriptions').collect()).find((s) => s.state === 'active')!,
  );

describe('the codes a new key narrows to', () => {
  test("a member on Automatic who chose a country, on a freedom mode: that country's locations", async () => {
    expect(await forIssue(await world())).toEqual(['loc-gone', 'loc-b']);
  });

  test('nothing for a guess, the opt-out, a location pick, steering off or a privacy mode', async () => {
    const now = Date.now();
    const guessOnly = await world({
      sub: {
        sniRegion: undefined,
        regionSeenCountry: 'IR',
        regionSeenAt: now,
        regionSeenFirstAt: now,
      },
    });
    expect(await forIssue(guessOnly)).toEqual([]);
    expect(await forIssue(await world({ sub: { sniRegion: 'ZZ' } }))).toEqual([]);
    expect(await forIssue(await world({ preferredLocation: 'loc-a' }))).toEqual([]);
    expect(await forIssue(await world({ steer: false }))).toEqual([]);
    const privacy = await world({ mode: 'privacy-reality' });
    expect(await forIssue(privacy, 'privacy-reality')).toEqual([]);
    // A switch from a freedom key into a privacy mode: the new key's mode decides.
    expect(await forIssue(await world(), 'privacy-reality')).toEqual([]);
  });

  test('a regenerate without an exit goes least-loaded, as before', async () => {
    const w = await world({ sub: { sniRegion: 'ZZ' } });
    await w.t.action(internal.account.regenerate, { userId: w.userId });
    expect((await activeSub(w)).backendPlacement).toBe(SQUAD_A);
  });

  test('a regenerate lands at the exit location, though the other one is less loaded', async () => {
    const w = await world();
    await w.t.action(internal.account.regenerate, { userId: w.userId });
    // The exit location's mode group (the development mock records no backend server).
    expect((await activeSub(w)).backendPlacement).toBe(SQUAD_B);
    // The member is still on Automatic.
    expect((await w.t.run((ctx) => ctx.db.get(w.userId)))!.preferredLocation).toBeUndefined();
  });
});

describe("the account page's one-time move", () => {
  test('offered while the key is elsewhere; it moves the key once, keeping the link', async () => {
    const w = await world();
    expect(await w.t.query(internal.countryExits.memberExit, { userId: w.userId })).toEqual({
      country: 'IR',
      code: 'loc-b',
      label: 'Label loc-b',
    });
    const res = await w.t.action(internal.account.moveToCountryExit, { userId: w.userId });
    expect(res).toMatchObject({ ok: true, inPlace: false });
    const fresh = await activeSub(w);
    expect(fresh.backendPlacement).toBe(SQUAD_B);
    expect(fresh.subToken).toBe('tok-abc');
    expect(fresh.sniRegion).toBe('IR');
    expect((await w.t.run((ctx) => ctx.db.get(w.userId)))!.preferredLocation).toBeUndefined();
    // Nothing is offered once the key is there (a real backend records the pinned server).
    await w.t.run((ctx) => ctx.db.patch(fresh._id, { backendServerId: w.b }));
    expect(await w.t.query(internal.countryExits.memberExit, { userId: w.userId })).toBeNull();
    // Audited without the country or the location.
    const audit = await w.t.run(async (ctx) =>
      (await ctx.db.query('auditLog').collect()).filter(
        (r) => r.action === 'subscription.move_location',
      ),
    );
    expect(audit).toHaveLength(1);
    expect(JSON.stringify(audit[0]!.payload ?? {})).not.toMatch(/IR|loc-b/);
  });

  test('nothing offered, and nothing moved, when the exit location is offline or the key is there', async () => {
    const offline = await world({ bOnline: false });
    expect(
      await offline.t.query(internal.countryExits.memberExit, { userId: offline.userId }),
    ).toBeNull();
    expect(
      await offline.t.action(internal.account.moveToCountryExit, { userId: offline.userId }),
    ).toMatchObject({ ok: false, code: 'exit.none' });
    expect((await activeSub(offline))._id).toBe(offline.subId);

    const there = await world();
    await there.t.run((ctx) => ctx.db.patch(there.subId, { backendServerId: there.b }));
    expect(
      await there.t.query(internal.countryExits.memberExit, { userId: there.userId }),
    ).toBeNull();
  });
});

describe('a key that carries no backend (an older one)', () => {
  test('its mode group tells where it is: no offer at the exit, one elsewhere, none when unknown', async () => {
    const atExit = await world({ sub: { backendServerId: undefined, backendPlacement: SQUAD_B } });
    expect(
      await atExit.t.query(internal.countryExits.memberExit, { userId: atExit.userId }),
    ).toBeNull();
    const elsewhere = await world({ sub: { backendServerId: undefined } });
    expect(
      await elsewhere.t.query(internal.countryExits.memberExit, { userId: elsewhere.userId }),
    ).toMatchObject({ code: 'loc-b' });
    const unknown = await world({
      sub: { backendServerId: undefined, backendPlacement: 'not-attributed' },
    });
    expect(
      await unknown.t.query(internal.countryExits.memberExit, { userId: unknown.userId }),
    ).toBeNull();
  });
});

describe('rollback', () => {
  test('clearForRollback deletes the setting; new keys go least-loaded again', async () => {
    const w = await world();
    expect(await w.t.mutation(internal.countryExits.clearForRollback, {})).toEqual({
      cleared: true,
    });
    expect(await forIssue(w)).toEqual([]);
    expect(await w.t.mutation(internal.countryExits.clearForRollback, {})).toEqual({
      cleared: false,
    });
  });
});

describe('the first key at sign-up', () => {
  /** The world without a key: the member is about to get their first one. */
  async function noKey(o: Parameters<typeof world>[0] = {}) {
    const w = await world(o);
    await w.t.run(async (ctx) => {
      await ctx.db.delete(w.subId);
      await ctx.db.patch(w.userId, { currentSubscriptionId: undefined });
    });
    return w;
  }
  const forFirstKey = (w: World, choiceHint: string) =>
    w.t.query(internal.countryExits.forIssue, {
      userId: w.userId,
      backend: 'remnawave',
      modeId: 'freedom-ws',
      choiceHint,
    });

  test('with no key, the sign-up country (a listed one) picks the exit locations', async () => {
    const w = await noKey();
    expect(await forFirstKey(w, 'IR')).toEqual(['loc-gone', 'loc-b']);
    expect(await forFirstKey(w, 'ir')).toEqual(['loc-gone', 'loc-b']);
    // Not on the list, or the opt-out: today's choice.
    expect(await forFirstKey(w, 'DE')).toEqual([]);
    expect(await forFirstKey(w, 'ZZ')).toEqual([]);
  });

  test("a key's own choice wins over the hint", async () => {
    const w = await world({ sub: { sniRegion: 'ZZ' } });
    expect(await forFirstKey(w, 'IR')).toEqual([]);
  });

  test("the first key lands at the exit of the request's country; an answer wins over it", async () => {
    const w = await noKey();
    await w.t.action(internal.account.regenerate, { userId: w.userId, geoCountry: 'IR' });
    expect((await activeSub(w)).backendPlacement).toBe(SQUAD_B);

    const opted = await noKey();
    await opted.t.action(internal.account.regenerate, {
      userId: opted.userId,
      region: 'ZZ',
      geoCountry: 'IR',
    });
    expect((await activeSub(opted)).backendPlacement).toBe(SQUAD_A);
  });
});

describe('suggestions for the sign-up question', () => {
  test("each answer gets the country's preferred mode and its locations", async () => {
    const w = await world();
    await w.t.run((ctx) =>
      upsertSettingRow(
        ctx,
        'delivery.country.modes',
        JSON.stringify([{ country: 'IR', modes: ['no-such-mode', 'privacy-reality'] }]),
      ),
    );
    const s = await w.t.query(internal.censoredCountries.suggestionsForCountries, {
      userId: w.userId,
      countries: ['IR', 'RU', 'ZZ'],
    });
    expect(s.IR).toEqual({ modeId: 'privacy-reality', locations: ['loc-gone', 'loc-b'] });
    expect(s.RU!.locations).toEqual([]);
    expect(s.ZZ!.locations).toEqual([]);
    expect(s.RU!.modeId).not.toBe('no-such-mode');
  });

  test('locations stay empty with ordering by country off', async () => {
    const w = await world({ steer: false });
    const s = await w.t.query(internal.censoredCountries.suggestionsForCountries, {
      userId: w.userId,
      countries: ['IR'],
    });
    expect(s.IR!.locations).toEqual([]);
  });
});
