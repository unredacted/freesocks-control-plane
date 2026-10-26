/// <reference types="vite/client" />
/**
 * Where a member connects from (convex/memberCountry.ts, lib/memberCountry.ts):
 * the readings on the fronted subscription route, the guess and its rules, the
 * member's choice, every transition that must clear a stored country (some of
 * them made WHILE a request is fetching from the backend), the sweeps, the
 * carries, and the invariant: every stored copy equals the row's stored country.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { CENSORED_COUNTRIES_KEY } from './lib/censoredCountries';

const modules = import.meta.glob('./**/*.*s');
type T = ReturnType<typeof convexTest>;

const FREEDOM_SQUAD = '11111111-2222-3333-4444-000000000001';
const PRIVACY_SQUAD = '11111111-2222-3333-4444-000000000002';
const MEMBER_IP = '192.0.2.50';
const EXIT_IP = '198.51.100.7';

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
  vi.stubEnv('CF_FRONTED', 'true');
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

/** The backend's answer; `during` runs while the route waits for it. */
let during: (() => Promise<void>) | null = null;
function stubBackend(): void {
  during = null;
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => {
      const hook = during;
      during = null;
      if (hook) await hook();
      return new Response('RAW-CONFIG', { status: 200, headers: { 'content-type': 'text/plain' } });
    }),
  );
}

async function world(
  o: {
    mode?: string;
    detect?: boolean;
    placement?: string;
    listed?: string[];
    /** Convex's per-execution limits (db calls, documents) enforced. */
    limits?: boolean;
  } = {},
) {
  const t = convexTest({ schema, modules, transactionLimits: o.limits ?? false });
  stubBackend();
  const ids = await t.run(async (ctx) => {
    const tierId = await ctx.db.insert('tiers', {
      slug: 'free',
      name: 'Free',
      backend: 'remnawave',
      monthlyTrafficGb: 50,
      deviceLimit: 1,
      hwidLimit: 1,
      hwidEnabled: true,
      trafficStrategy: 'MONTH',
      isDefaultFree: true,
      isActive: true,
      priority: 0,
      expirationDaysAfterMembershipLapse: 0,
      updatedAt: Date.now(),
    });
    const userId = await ctx.db.insert('users', {
      tierId,
      status: 'active',
      connectionModeId: o.mode ?? 'freedom-ws',
      updatedAt: Date.now(),
    });
    const serverId = await ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'RW',
      slug: 'rw-1',
      config: { type: 'remnawave', baseUrl: 'https://panel.example', apiToken: 'tok' },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: Date.now(),
    });
    for (const [modeSlug, squad] of [
      ['freedom-ws', FREEDOM_SQUAD],
      ['privacy-reality', PRIVACY_SQUAD],
    ] as const)
      await ctx.db.insert('modePlacements', {
        modeSlug,
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: [squad] }),
        updatedAt: Date.now(),
      });
    const subId = await ctx.db.insert('subscriptions', {
      userId,
      backend: 'remnawave',
      backendUserId: 'uuid-1',
      backendShortId: 'short-1',
      backendServerId: serverId,
      backendPlacement: o.placement ?? FREEDOM_SQUAD,
      subscriptionUrl: 'https://panel.example/sub/short-1',
      subscriptionMirrors: [],
      subToken: 'tok_abc',
      state: 'active',
      updatedAt: Date.now(),
    });
    await ctx.db.patch(userId, { currentSubscriptionId: subId });
    await upsertSettingRow(
      ctx,
      CENSORED_COUNTRIES_KEY,
      JSON.stringify(
        (o.listed ?? ['IR', 'RU', 'TR']).map((code) => ({
          code,
          checkEdges: true,
          checkNamesInside: false,
        })),
      ),
    );
    await upsertSettingRow(ctx, 'delivery.country.detect', JSON.stringify(o.detect ?? true));
    await upsertSettingRow(
      ctx,
      'delivery.country.ownExitRanges',
      JSON.stringify(['198.51.100.0/24']),
    );
    return { userId, subId, serverId };
  });
  await t.mutation(internal.ownExits.refresh, {});
  return { t, ...ids };
}

const fetchSub = (t: T, o: { country?: string; ip?: string; ua?: string } = {}) =>
  t.fetch('/api/v1/sub/tok_abc', {
    headers: {
      'user-agent': o.ua ?? 'app/1',
      'cf-connecting-ip': o.ip ?? MEMBER_IP,
      ...(o.country ? { 'cf-ipcountry': o.country } : {}),
    },
  });

const row = (t: T, id: Id<'subscriptions'>) =>
  t.run((ctx) => ctx.db.get(id)) as Promise<Doc<'subscriptions'>>;
const regions = (sub: Doc<'subscriptions'>) =>
  (sub.subCache ? (JSON.parse(sub.subCache) as { region?: string | null }[]) : []).map(
    (e) => e.region ?? null,
  );
/** Every country held anywhere on the row. */
const countriesOn = (sub: Doc<'subscriptions'>) =>
  [sub.sniRegion, sub.regionSeenCountry, ...regions(sub)].filter(
    (c): c is string => typeof c === 'string' && c !== 'ZZ',
  );

describe('readings on the fronted route', () => {
  test('detection off: the CDN country is used once and stored nowhere', async () => {
    const { t, subId } = await world({ detect: false });
    const res = await fetchSub(t, { country: 'IR' });
    expect(res.status).toBe(200);
    const sub = await row(t, subId);
    expect(sub.regionSeenCountry).toBeUndefined();
    expect(countriesOn(sub)).toEqual([]);
  });

  test('detection on: a listed reading is stored; elsewhere keeps it; a new listed one replaces it', async () => {
    const { t, subId } = await world();
    await fetchSub(t, { country: 'IR' });
    let sub = await row(t, subId);
    expect(sub.regionSeenCountry).toBe('IR');
    // No origin covers this place, so nothing is rendered by country and the body
    // is cached without one (edgeRender.test.ts covers a covered place).
    expect(regions(sub)).toEqual([null]);
    const rev = sub.countryRev;
    await fetchSub(t, { country: 'DE', ua: 'app/2' });
    sub = await row(t, subId);
    expect(sub.regionSeenCountry).toBe('IR');
    await fetchSub(t, { country: 'RU', ua: 'app/3' });
    sub = await row(t, subId);
    expect(sub.regionSeenCountry).toBe('RU');
    expect(sub.countryRev).toBeGreaterThan(rev ?? 0);
    // The IR bodies went with the IR guess.
    expect(regions(sub)).not.toContain('IR');
    expect(countriesOn(sub).every((c) => c === 'RU')).toBe(true);
  });

  test('a privacy-family key: nothing read, nothing stored', async () => {
    for (const o of [{ mode: 'privacy-reality' }, { placement: PRIVACY_SQUAD }]) {
      const { t, subId } = await world(o);
      await fetchSub(t, { country: 'IR' });
      expect(countriesOn(await row(t, subId))).toEqual([]);
    }
  });

  test("a reading from one of FCP's own exits never sets a guess, only keeps one alive", async () => {
    const { t, subId } = await world();
    await fetchSub(t, { country: 'IR', ip: EXIT_IP });
    expect((await row(t, subId)).regionSeenCountry).toBeUndefined();
    const old = Date.now() - 7 * 3_600_000;
    await t.run((ctx) =>
      ctx.db.patch(subId, { regionSeenCountry: 'IR', regionSeenAt: old, regionSeenFirstAt: old }),
    );
    await fetchSub(t, { country: 'TR', ip: EXIT_IP, ua: 'app/2' });
    const sub = await row(t, subId);
    expect(sub.regionSeenCountry).toBe('IR');
    expect(sub.regionSeenAt).toBeGreaterThan(old);
    expect(sub.regionSeenFirstAt).toBe(old);
  });

  test("the member's choice stops detection; ZZ clears the guess; Automatic clears the choice", async () => {
    const { t, subId, userId } = await world();
    await fetchSub(t, { country: 'IR' });
    await t.mutation(internal.memberCountry.setChoice, { userId, region: 'ru' });
    let sub = await row(t, subId);
    expect([sub.sniRegion, sub.regionSeenCountry]).toEqual(['RU', undefined]);
    expect(regions(sub)).not.toContain('IR');
    await fetchSub(t, { country: 'TR', ua: 'app/2' });
    expect((await row(t, subId)).regionSeenCountry).toBeUndefined();
    await t.mutation(internal.memberCountry.setChoice, { userId, region: 'ZZ' });
    sub = await row(t, subId);
    expect(sub.sniRegion).toBe('ZZ');
    expect(countriesOn(sub)).toEqual([]);
    await t.mutation(internal.memberCountry.setChoice, { userId, region: null });
    expect((await row(t, subId)).sniRegion).toBeUndefined();
    await expect(
      t.mutation(internal.memberCountry.setChoice, { userId, region: 'DE' }),
    ).rejects.toThrow(/unknown region/);
  });

  test('a stale reading (another transition got there first) is not applied', async () => {
    const { t, subId } = await world();
    await t.run((ctx) => ctx.db.patch(subId, { countryRev: 5 }));
    expect(
      await t.mutation(internal.memberCountry.noteSeenCountry, {
        subscriptionId: subId,
        countryRev: 4,
        country: 'IR',
        ownExit: false,
      }),
    ).toBeNull();
    expect((await row(t, subId)).regionSeenCountry).toBeUndefined();
  });
});

// The clearing on each transition, over HTTP. That a resumed request cannot
// write a country-shaped body back is covered at a place an origin covers
// (edgeRender.test.ts "where a member connects from").
describe('transitions made while a request is fetching from the backend', () => {
  /** A first request stores IR (and an IR body); the second runs `transition` mid-fetch. */
  async function midFetch(transition: (w: Awaited<ReturnType<typeof world>>) => Promise<unknown>) {
    const w = await world();
    await fetchSub(w.t, { country: 'IR' });
    expect((await row(w.t, w.subId)).regionSeenCountry).toBe('IR');
    let ran = false;
    during = async () => {
      ran = true;
      await transition(w);
    };
    const res = await fetchSub(w.t, { country: 'IR', ua: 'app/2' });
    expect(res.status).toBe(200);
    expect(ran).toBe(true); // the transition really happened mid-request
    await w.t.finishInProgressScheduledFunctions();
    return { ...w, sub: await row(w.t, w.subId) };
  }

  test('"Somewhere else"', async () => {
    const { sub } = await midFetch(({ t, userId }) =>
      t.mutation(internal.memberCountry.setChoice, { userId, region: 'ZZ' }).then(() => {}),
    );
    expect(sub.sniRegion).toBe('ZZ');
    expect(countriesOn(sub)).toEqual([]);
  });

  test('the key is deleted', async () => {
    const { sub } = await midFetch(({ t, subId }) =>
      t.mutation(internal.subscriptions.markSubscriptionDeleted, { subscriptionId: subId }),
    );
    expect(sub.state).toBe('deleted');
    expect(countriesOn(sub)).toEqual([]);
    expect(sub.subCache).toBeUndefined();
    expect(sub.lastRender).toBeUndefined();
  });

  test('an in-place switch into a privacy-family mode', async () => {
    const { sub } = await midFetch(({ t, subId }) =>
      t.mutation(internal.subscriptions.setPlacementAndClearCache, {
        subscriptionId: subId,
        placement: PRIVACY_SQUAD,
      }),
    );
    expect(countriesOn(sub)).toEqual([]);
  });

  test('two user agents: the guess moves to RU, then IR leaves the list, then the IR request resumes', async () => {
    const { sub } = await midFetch(async ({ t, subId }) => {
      const now = (await row(t, subId)).countryRev ?? 0;
      await t.mutation(internal.memberCountry.noteSeenCountry, {
        subscriptionId: subId,
        countryRev: now,
        country: 'RU',
        ownExit: false,
      });
      await t.mutation(internal.censoredCountries.set, {
        countries: ['RU', 'TR'].map((code) => ({ code, checkEdges: true })),
      });
      await t.finishInProgressScheduledFunctions();
    });
    expect(sub.regionSeenCountry).toBe('RU');
    expect(countriesOn(sub)).not.toContain('IR');
  });
});

describe('the cache keeps no body for another country', () => {
  test('a write for a country that is not the stored one is refused, and old ones are dropped', async () => {
    const { t, subId } = await world();
    await t.run((ctx) =>
      ctx.db.patch(subId, {
        regionSeenCountry: 'RU',
        regionSeenAt: Date.now(),
        regionSeenFirstAt: Date.now(),
        subCache: JSON.stringify([
          { content: 'x', contentType: 'text/plain', ua: 'a', at: 1, region: 'IR' },
        ]),
      }),
    );
    // The account's address lane rides on every entry the route writes (a new account: open).
    const entry = (ua: string, region: string | null) =>
      JSON.stringify({
        content: 'y',
        contentType: 'text/plain',
        ua,
        at: Date.now(),
        region,
        lane: 'open',
      });
    await t.mutation(internal.subscriptions.writeContentCache, {
      subscriptionId: subId,
      entry: entry('b', 'IR'),
    });
    expect(regions(await row(t, subId))).toEqual(['IR']); // refused: nothing written
    await t.mutation(internal.subscriptions.writeContentCache, {
      subscriptionId: subId,
      entry: entry('c', null),
    });
    expect(regions(await row(t, subId))).toEqual([null]); // and the stale IR one dropped
    await t.mutation(internal.subscriptions.writeContentCache, {
      subscriptionId: subId,
      entry: entry('d', 'RU'),
    });
    expect(regions(await row(t, subId)).sort()).toEqual([null, 'RU'].sort());
  });
});

describe('sweeps', () => {
  test('guesses past the sticky window go, and every guess while detection is off', async () => {
    const { t, subId } = await world();
    const day = 86_400_000;
    await t.run((ctx) =>
      ctx.db.patch(subId, {
        regionSeenCountry: 'IR',
        regionSeenAt: Date.now() - 31 * day,
        regionSeenFirstAt: Date.now() - 40 * day,
      }),
    );
    await t.mutation(internal.memberCountry.sweepGuesses, {});
    expect((await row(t, subId)).regionSeenCountry).toBeUndefined();
    await t.run(async (ctx) => {
      await ctx.db.patch(subId, {
        regionSeenCountry: 'IR',
        regionSeenAt: Date.now(),
        regionSeenFirstAt: Date.now(),
      });
      await upsertSettingRow(ctx, 'delivery.country.detect', 'false');
    });
    await t.mutation(internal.memberCountry.sweepGuesses, {});
    expect((await row(t, subId)).regionSeenCountry).toBeUndefined();
  });

  test('with detection off the sweep runs until no guess is left, however many rounds that takes', async () => {
    vi.useFakeTimers();
    const { t, subId, userId, serverId } = await world();
    await t.run(async (ctx) => {
      const sub = (await ctx.db.get(subId))!;
      const { _id, _creationTime, ...base } = sub;
      void _id;
      void _creationTime;
      // One page and one more, met by a run already deep into its rounds.
      for (let i = 0; i < 201; i++)
        await ctx.db.insert('subscriptions', {
          ...base,
          userId,
          backendServerId: serverId,
          backendUserId: `uuid-g${i}`,
          subToken: `tok_g${i}`,
          regionSeenCountry: 'IR',
          regionSeenFirstAt: Date.now(),
          regionSeenAt: Date.now(),
        });
      await upsertSettingRow(ctx, 'delivery.country.detect', 'false');
    });
    await t.mutation(internal.memberCountry.sweepGuesses, { rounds: 50 });
    await t.finishAllScheduledFunctions(vi.runAllTimers);
    const left = await t.run(
      async (ctx) =>
        (
          await ctx.db
            .query('subscriptions')
            .withIndex('by_region_seen_at', (q) => q.gt('regionSeenAt', 0))
            .collect()
        ).length,
    );
    expect(left).toBe(0);
  });

  test('the deploy clean-up drops choices off the list and any country on a privacy key', async () => {
    const { t, subId, userId } = await world();
    await t.run((ctx) => ctx.db.patch(subId, { sniRegion: 'DE' }));
    await t.mutation(internal.memberCountry.cleanStoredCountries, {});
    await t.finishInProgressScheduledFunctions();
    expect((await row(t, subId)).sniRegion).toBeUndefined();
    await t.run(async (ctx) => {
      await ctx.db.patch(subId, { sniRegion: 'IR' });
      await ctx.db.patch(userId, { connectionModeId: 'privacy-reality' });
    });
    await t.mutation(internal.memberCountry.cleanStoredCountries, {});
    await t.finishInProgressScheduledFunctions();
    expect(countriesOn(await row(t, subId))).toEqual([]);
  });
});

describe('the deploy clean-up at scale', () => {
  test('a full page of Automatic members whose default turned privacy, with every mode bound, stays within one execution', async () => {
    vi.useFakeTimers();
    const { t, serverId } = await world({ limits: true });
    await t.run(async (ctx) => {
      // Four bound modes: judging an Automatic key reads every bound pool.
      for (const [modeSlug, n] of [
        ['freedom-reality', 3],
        ['freedom-xhttp', 4],
      ] as const)
        await ctx.db.insert('modePlacements', {
          modeSlug,
          backend: 'remnawave',
          config: JSON.stringify({ squadUuids: [`11111111-2222-3333-4444-00000000000${n}`] }),
          updatedAt: Date.now(),
        });
      await upsertSettingRow(ctx, 'connectionMode.default', JSON.stringify('privacy-reality'));
    });
    // More than a page of members who answered, each judged privacy now.
    await t.run(async (ctx) => {
      const tierId = (await ctx.db.query('tiers').first())!._id;
      for (let i = 0; i < 250; i++) {
        const userId = await ctx.db.insert('users', {
          tierId,
          status: 'active',
          updatedAt: Date.now(),
        });
        await ctx.db.insert('subscriptions', {
          userId,
          backend: 'remnawave',
          backendUserId: `uuid-c${i}`,
          backendShortId: `short-c${i}`,
          backendServerId: serverId,
          backendPlacement: FREEDOM_SQUAD,
          subscriptionUrl: `https://panel.example/sub/short-c${i}`,
          subscriptionMirrors: [],
          subToken: `tok_c${i}`,
          sniRegion: 'IR',
          state: 'active',
          updatedAt: Date.now(),
        });
      }
    });
    await t.mutation(internal.memberCountry.cleanStoredCountries, {});
    await t.finishAllScheduledFunctions(vi.runAllTimers);
    const holding = await t.run(
      async (ctx) =>
        (
          await ctx.db
            .query('subscriptions')
            .withIndex('by_sni_region', (q) => q.gt('sniRegion', ''))
            .collect()
        ).length,
    );
    expect(holding).toBe(0);
  });
});

describe('re-issued keys', () => {
  const issue = (
    t: T,
    userId: Id<'users'>,
    placement: string,
    carry: { carrySubTokenFromId?: Id<'subscriptions'>; carryCountryFromId?: Id<'subscriptions'> },
  ) =>
    t.mutation(internal.subscriptions.insertSubscription, {
      userId,
      backend: 'remnawave',
      backendUserId: `u-${Math.random()}`,
      backendShortId: `s-${Math.random()}`,
      subscriptionUrl: 'https://panel.example/sub/x',
      subscriptionMirrors: [],
      placement,
      ...carry,
    });

  test('a switch within the freedom family carries the choice and the guess; regenerate the choice only; nothing into privacy', async () => {
    const { t, subId, userId } = await world();
    await t.run((ctx) =>
      ctx.db.patch(subId, {
        sniRegion: 'RU',
        regionSeenCountry: 'IR',
        regionSeenAt: Date.now(),
        regionSeenFirstAt: Date.now(),
      }),
    );
    const switched = await row(
      t,
      await issue(t, userId, FREEDOM_SQUAD, { carrySubTokenFromId: subId }),
    );
    expect([switched.sniRegion, switched.regionSeenCountry]).toEqual(['RU', 'IR']);
    const regenerated = await row(
      t,
      await issue(t, userId, FREEDOM_SQUAD, { carryCountryFromId: switched._id }),
    );
    expect([regenerated.sniRegion, regenerated.regionSeenCountry]).toEqual(['RU', undefined]);
    const privacy = await row(
      t,
      await issue(t, userId, PRIVACY_SQUAD, { carrySubTokenFromId: regenerated._id }),
    );
    expect(countriesOn(privacy)).toEqual([]);
  });
});

describe('the account view and the admin view', () => {
  test("a reading on the account view sets the guess on the member's freedom keys", async () => {
    const { t, subId, userId } = await world();
    expect(
      await t.mutation(internal.memberCountry.noteSeenCountryForUser, {
        userId,
        country: 'TR',
        ownExit: false,
      }),
    ).toEqual({ effective: 'TR', source: 'guess' });
    // A stored "Somewhere else" comes back as an answer, not as "nothing stored".
    await t.mutation(internal.memberCountry.setChoice, { userId, region: 'ZZ' });
    expect(
      await t.mutation(internal.memberCountry.noteSeenCountryForUser, {
        userId,
        country: 'IR',
        ownExit: false,
      }),
    ).toEqual({ effective: null, source: 'choice' });
    await t.mutation(internal.memberCountry.setChoice, { userId, region: null });
    await t.mutation(internal.memberCountry.noteSeenCountryForUser, {
      userId,
      country: 'TR',
      ownExit: false,
    });
    expect((await row(t, subId)).regionSeenCountry).toBe('TR');
    const member = await t.query(internal.memberCountry.memberView, { userId });
    expect(member).toMatchObject({
      applies: true,
      choice: null,
      effective: 'TR',
      source: 'guess',
      detect: true,
      stickyDays: 30,
      options: ['IR', 'RU', 'TR'],
    });
    const admin = await t.query(internal.memberCountry.adminView, { userId });
    expect(admin?.keys).toEqual([
      expect.objectContaining({
        current: true,
        family: 'freedom',
        effective: 'TR',
        source: 'guess',
        delivered: null,
      }),
    ]);
    expect(await t.query(internal.memberCountry.adminView, { userId: 'not-an-id' })).toBeNull();
  });
});
