/// <reference types="vite/client" />
/**
 * Keys by country (lib/countryKeyCounts.ts, convex/countryKeyCounts.ts): the
 * counter moves in the write that changes a key's answer or guess, the daily
 * recount rebuilds it exactly (and is the only writer of "neither"), and what
 * the Countries pages read is numbers only.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { CENSORED_COUNTRIES_KEY } from './lib/censoredCountries';
import {
  COUNTRY_KEY_COUNTS_KEY,
  COUNTRY_KEY_COUNTER,
  countryBucket,
  countryKeysView,
  readCountryKeys,
} from './lib/countryKeyCounts';
import { readCounter } from './lib/statusCounters';

const modules = import.meta.glob('./**/*.*s');
type T = ReturnType<typeof convexTest>;

const FREEDOM_SQUAD = '11111111-2222-3333-4444-000000000001';
const PRIVACY_SQUAD = '11111111-2222-3333-4444-000000000002';
const LISTED = ['IR', 'RU', 'TR'];
const DAY = 86_400_000;

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});
afterEach(() => {
  vi.unstubAllEnvs();
});

let seq = 0;
/** One member with one active key in a freedom-family (default) or privacy-family mode. */
async function member(t: T, o: { privacy?: boolean; fields?: Record<string, unknown> } = {}) {
  const n = ++seq;
  return t.run(async (ctx) => {
    const tier = await ctx.db.query('tiers').first();
    const userId = await ctx.db.insert('users', {
      tierId: tier!._id,
      status: 'active',
      connectionModeId: o.privacy ? 'privacy-reality' : 'freedom-ws',
      updatedAt: Date.now(),
    });
    const subId = await ctx.db.insert('subscriptions', {
      userId,
      backend: 'remnawave',
      backendUserId: `uuid-${n}`,
      backendShortId: `short-${n}`,
      backendPlacement: o.privacy ? PRIVACY_SQUAD : FREEDOM_SQUAD,
      subscriptionUrl: `https://panel.example/sub/short-${n}`,
      subscriptionMirrors: [],
      subToken: `tok_${n}`,
      state: 'active',
      updatedAt: Date.now(),
      ...o.fields,
    });
    await ctx.db.patch(userId, { currentSubscriptionId: subId });
    return { userId, subId };
  });
}

async function world(o: { limits?: boolean; settings?: Record<string, unknown> } = {}) {
  const t = convexTest({ schema, modules, transactionLimits: o.limits ?? false });
  await t.run(async (ctx) => {
    await ctx.db.insert('tiers', {
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
    await upsertSettingRow(
      ctx,
      CENSORED_COUNTRIES_KEY,
      JSON.stringify(LISTED.map((code) => ({ code, checkEdges: true, checkNamesInside: false }))),
    );
    await upsertSettingRow(ctx, 'delivery.country.detect', 'true');
    for (const [k, v] of Object.entries(o.settings ?? {}))
      await upsertSettingRow(ctx, k, JSON.stringify(v));
  });
  return t;
}

const recount = (t: T) => t.action(internal.countryKeyCounts.reconcile, {});
const view = (t: T) => t.run((ctx) => readCountryKeys(ctx.db, LISTED));
/** The numbers of one country, the opt-out and "neither", in one line. */
async function numbers(t: T) {
  const v = await view(t);
  return {
    IR: v.byCountry.IR,
    RU: v.byCountry.RU,
    optOut: v.optOut,
    neither: v.neither,
    other: v.otherGuessed,
  };
}
const NONE = { answered: 0, guessed: 0 };
const setChoice = (t: T, userId: Id<'users'>, region: string | null) =>
  t.mutation(internal.memberCountry.setChoice, { userId, region });
const reading = async (t: T, subId: Id<'subscriptions'>, country: string) =>
  t.mutation(internal.memberCountry.noteSeenCountry, {
    subscriptionId: subId,
    countryRev: (await t.run((ctx) => ctx.db.get(subId)))!.countryRev ?? 0,
    country,
    ownExit: false,
  });

describe('where a key is counted', () => {
  test('by its answer, else its guess, and only while it is active', () => {
    const row = (o: Record<string, unknown>) => ({ state: 'active' as const, ...o });
    expect(countryBucket(row({ sniRegion: 'IR', regionSeenCountry: 'RU' }))).toBe('c:IR');
    expect(countryBucket(row({ sniRegion: 'ZZ' }))).toBe('c:ZZ');
    expect(countryBucket(row({ regionSeenCountry: 'RU' }))).toBe('g:RU');
    expect(countryBucket(row({}))).toBeNull();
    expect(countryBucket({ state: 'disabled', sniRegion: 'IR' })).toBeNull();
    expect(countryBucket({ state: 'deleted', regionSeenCountry: 'IR' })).toBeNull();
    // Anything that is not a two-letter code counts nowhere.
    expect(countryBucket(row({ sniRegion: 'ir' }))).toBeNull();
    expect(countryBucket(row({ sniRegion: 'c:IR' }))).toBeNull();
  });
});

describe('the counter moves with the key', () => {
  test('before the first count nothing is known, and nothing is counted', async () => {
    const t = await world();
    const { userId } = await member(t);
    await setChoice(t, userId, 'IR');
    expect(await view(t)).toMatchObject({ counted: false, countedAt: null });
    // No counter row yet: the first recount builds it, an answer before it adds nothing.
    expect(
      await t.run((ctx) =>
        ctx.db
          .query('appState')
          .withIndex('by_key', (q) => q.eq('key', COUNTRY_KEY_COUNTS_KEY))
          .unique(),
      ),
    ).toBeNull();
    await recount(t);
    const v = await view(t);
    expect(v.counted).toBe(true);
    expect(v.countedAt).toBeGreaterThan(Date.now() - 60_000);
    expect(v.byCountry.IR).toEqual({ answered: 1, guessed: 0 });
  });

  test('an answer, a change of answer, the opt-out and a clear', async () => {
    const t = await world();
    const { userId } = await member(t);
    await recount(t);
    expect(await numbers(t)).toEqual({ IR: NONE, RU: NONE, optOut: 0, neither: 1, other: 0 });

    await setChoice(t, userId, 'IR');
    expect(await numbers(t)).toMatchObject({ IR: { answered: 1, guessed: 0 }, RU: NONE });
    // The same answer again moves nothing.
    await setChoice(t, userId, 'IR');
    expect((await numbers(t)).IR).toEqual({ answered: 1, guessed: 0 });

    await setChoice(t, userId, 'RU');
    expect(await numbers(t)).toMatchObject({ IR: NONE, RU: { answered: 1, guessed: 0 } });

    await setChoice(t, userId, 'ZZ');
    expect(await numbers(t)).toMatchObject({ IR: NONE, RU: NONE, optOut: 1 });

    await setChoice(t, userId, null);
    expect(await numbers(t)).toMatchObject({ IR: NONE, RU: NONE, optOut: 0 });
  });

  test('a guess written, moved, replaced by an answer, and forgotten', async () => {
    const t = await world();
    const { userId, subId } = await member(t);
    await recount(t);

    await reading(t, subId, 'IR');
    expect((await numbers(t)).IR).toEqual({ answered: 0, guessed: 1 });
    // Seen there again: the guess is refreshed, the count does not move.
    await t.run((ctx) => ctx.db.patch(subId, { regionSeenAt: Date.now() - DAY }));
    await reading(t, subId, 'IR');
    expect((await numbers(t)).IR).toEqual({ answered: 0, guessed: 1 });

    await reading(t, subId, 'RU');
    expect(await numbers(t)).toMatchObject({ IR: NONE, RU: { answered: 0, guessed: 1 } });

    // The member's own answer replaces the guess: counted once, as an answer.
    await setChoice(t, userId, 'IR');
    expect(await numbers(t)).toMatchObject({ IR: { answered: 1, guessed: 0 }, RU: NONE });

    await setChoice(t, userId, null);
    await reading(t, subId, 'IR');
    expect((await numbers(t)).IR).toEqual({ answered: 0, guessed: 1 });
    // Past the sticky window the daily sweep forgets it.
    await t.run((ctx) => ctx.db.patch(subId, { regionSeenAt: Date.now() - 31 * DAY }));
    await t.mutation(internal.memberCountry.sweepGuesses, {});
    expect((await numbers(t)).IR).toEqual(NONE);
  });

  test('a key deleted, a key replaced, and a key issued with a carried answer', async () => {
    const t = await world();
    const a = await member(t);
    const b = await member(t);
    await recount(t);
    await setChoice(t, a.userId, 'IR');
    await setChoice(t, b.userId, 'IR');
    expect((await numbers(t)).IR).toEqual({ answered: 2, guessed: 0 });

    // Deleted: the country goes with the key, and so does its count.
    await t.mutation(internal.subscriptions.markSubscriptionDeleted, { subscriptionId: a.subId });
    expect((await numbers(t)).IR).toEqual({ answered: 1, guessed: 0 });
    // Deleting it again moves nothing.
    await t.mutation(internal.subscriptions.markSubscriptionDeleted, { subscriptionId: a.subId });
    expect((await numbers(t)).IR).toEqual({ answered: 1, guessed: 0 });

    // Regenerated: the new key carries the answer and is counted; the old one
    // keeps its fields through the grace and is no longer counted.
    const next = await t.mutation(internal.subscriptions.insertSubscription, {
      userId: b.userId,
      backend: 'remnawave',
      backendUserId: 'uuid-next',
      backendShortId: 'short-next',
      subscriptionUrl: 'https://panel.example/sub/next',
      subscriptionMirrors: [],
      placement: FREEDOM_SQUAD,
      carryCountryFromId: b.subId,
    });
    expect((await numbers(t)).IR).toEqual({ answered: 2, guessed: 0 });
    const old = (await t.run((ctx) => ctx.db.get(b.subId)))!;
    await t.mutation(internal.subscriptions.tombstoneWithGrace, {
      backendUserId: old.backendUserId,
      graceMs: DAY,
    });
    expect((await t.run((ctx) => ctx.db.get(b.subId)))!.sniRegion).toBe('IR');
    expect((await numbers(t)).IR).toEqual({ answered: 1, guessed: 0 });
    // The grace ends: the old key was not counted, so nothing moves.
    await t.mutation(internal.subscriptions.markSubscriptionDeleted, { subscriptionId: b.subId });
    expect((await numbers(t)).IR).toEqual({ answered: 1, guessed: 0 });
    // A key issued into a privacy mode carries nothing and counts nowhere.
    await t.mutation(internal.subscriptions.insertSubscription, {
      userId: b.userId,
      backend: 'remnawave',
      backendUserId: 'uuid-priv',
      backendShortId: 'short-priv',
      subscriptionUrl: 'https://panel.example/sub/priv',
      subscriptionMirrors: [],
      placement: PRIVACY_SQUAD,
      carrySubTokenFromId: next,
    });
    expect((await numbers(t)).IR).toEqual({ answered: 1, guessed: 0 });
  });

  test('an in-place switch into a privacy mode takes the key out of its country', async () => {
    const t = await world();
    const { userId, subId } = await member(t);
    await recount(t);
    await setChoice(t, userId, 'IR');
    await t.mutation(internal.subscriptions.setPlacementAndClearCache, {
      subscriptionId: subId,
      placement: PRIVACY_SQUAD,
    });
    expect((await numbers(t)).IR).toEqual(NONE);
  });

  test('a guess of a country off the list is counted apart (any-country guesses)', async () => {
    const t = await world({
      settings: { 'delivery.country.steer': true, 'delivery.country.latency': true },
    });
    const { subId } = await member(t);
    await recount(t);
    await reading(t, subId, 'DE');
    expect(await numbers(t)).toMatchObject({ IR: NONE, RU: NONE, other: 1 });
  });
});

describe('the daily recount', () => {
  test('counts every key once: answers, guesses, the opt-out, and freedom keys with neither', async () => {
    const t = await world();
    await member(t, { fields: { sniRegion: 'IR' } });
    await member(t, { fields: { sniRegion: 'IR' } });
    await member(t, { fields: { sniRegion: 'ZZ' } });
    await member(t, { fields: { regionSeenCountry: 'RU', regionSeenAt: Date.now() } });
    // Neither: counted only when the key is of a freedom mode.
    await member(t);
    await member(t);
    await member(t, { privacy: true });
    // Not active: a replaced key in its grace, a deleted one.
    await member(t, { fields: { sniRegion: 'IR', state: 'disabled', deletedAt: Date.now() } });
    await member(t, { fields: { state: 'deleted', deletedAt: Date.now() } });
    expect(await recount(t)).toEqual({ applied: true, rows: 9 });
    expect(await numbers(t)).toEqual({
      IR: { answered: 2, guessed: 0 },
      RU: { answered: 0, guessed: 1 },
      optOut: 1,
      neither: 2,
      other: 0,
    });
    // Idempotent.
    await recount(t);
    expect((await numbers(t)).IR).toEqual({ answered: 2, guessed: 0 });
  });

  test('a key that is no longer of a freedom mode is in no number, though it still holds a country', async () => {
    const t = await world();
    const stays = await member(t, { fields: { sniRegion: 'IR' } });
    const moved = await member(t, { fields: { sniRegion: 'IR' } });
    const guessed = await member(t, {
      fields: { regionSeenCountry: 'RU', regionSeenAt: Date.now() },
    });
    // Their mode left the freedom family with no write to their keys (an admin
    // change to the mode): the rows keep the country until the clean-up.
    await t.run(async (ctx) => {
      for (const m of [moved, guessed]) {
        await ctx.db.patch(m.userId, { connectionModeId: 'privacy-reality' });
        await ctx.db.patch(m.subId, { backendPlacement: PRIVACY_SQUAD });
      }
    });
    await recount(t);
    expect(await numbers(t)).toEqual({
      IR: { answered: 1, guessed: 0 },
      RU: NONE,
      optOut: 0,
      neither: 0,
      other: 0,
    });
    expect((await t.run((ctx) => ctx.db.get(moved.subId)))!.sniRegion).toBe('IR');
    // The clean-up then clears them; nothing goes below zero, and the key that stayed stays counted.
    await t.mutation(internal.memberCountry.cleanStoredCountries, {});
    await t.finishInProgressScheduledFunctions();
    expect((await t.run((ctx) => ctx.db.get(moved.subId)))!.sniRegion).toBeUndefined();
    await recount(t);
    expect((await numbers(t)).IR).toEqual({ answered: 1, guessed: 0 });
    expect((await t.run((ctx) => ctx.db.get(stays.subId)))!.sniRegion).toBe('IR');
  });

  test('repairs drift: a number that went wrong, and a write that bumped nothing', async () => {
    const t = await world();
    const a = await member(t, { fields: { sniRegion: 'IR' } });
    await member(t);
    await recount(t);
    // The counter row drifted, and a row changed without its bump.
    await t.run(async (ctx) => {
      const row = (await ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', COUNTRY_KEY_COUNTS_KEY))
        .unique())!;
      const state = JSON.parse(row.value) as Record<string, unknown>;
      await ctx.db.patch(row._id, {
        value: JSON.stringify({ ...state, 'c:IR': 41, 'c:TR': 3, none: 0 }),
      });
      await ctx.db.patch(a.subId, { sniRegion: 'RU' });
    });
    expect((await numbers(t)).IR).toEqual({ answered: 41, guessed: 0 });
    await recount(t);
    expect(await numbers(t)).toEqual({
      IR: NONE,
      RU: { answered: 1, guessed: 0 },
      optOut: 0,
      neither: 1,
      other: 0,
    });
    // A country nothing counts under any more leaves the counter, not kept at zero.
    const { counts } = await t.run((ctx) => readCounter(ctx.db, COUNTRY_KEY_COUNTER));
    expect(Object.keys(counts).sort()).toEqual(['c:RU', 'none']);
  });

  test('an answer given while a recount runs is counted exactly once', async () => {
    const t = await world();
    const early = await member(t);
    const late = await member(t);
    await recount(t);
    const token = await t.mutation(internal.countryKeyCounts.beginReconcile, {});
    // The scan has passed the first key and not reached the second.
    await t.mutation(internal.countryKeyCounts.scanPage, { pageSize: 1 });
    await setChoice(t, early.userId, 'IR');
    await setChoice(t, late.userId, 'IR');
    for (let i = 0; i < 5; i++)
      if ((await t.mutation(internal.countryKeyCounts.scanPage, { pageSize: 1 })).done) break;
    expect(await t.mutation(internal.countryKeyCounts.finishReconcile, { token })).toBe(true);
    expect((await numbers(t)).IR).toEqual({ answered: 2, guessed: 0 });
  });

  test("a full page of keys with neither stays within one execution's limits", async () => {
    const t = await world({ limits: true });
    for (let i = 0; i < 40; i++)
      await t.run(async (ctx) => {
        const tier = await ctx.db.query('tiers').first();
        for (let j = 0; j < 10; j++) {
          const userId = await ctx.db.insert('users', {
            tierId: tier!._id,
            status: 'active',
            updatedAt: Date.now(),
          });
          await ctx.db.insert('subscriptions', {
            userId,
            backend: 'remnawave',
            backendUserId: `bulk-${i}-${j}`,
            backendShortId: `bulk-${i}-${j}`,
            backendPlacement: FREEDOM_SQUAD,
            subscriptionUrl: 'https://panel.example/sub/bulk',
            subscriptionMirrors: [],
            state: 'active',
            updatedAt: Date.now(),
          });
        }
      });
    await t.mutation(internal.countryKeyCounts.beginReconcile, {});
    const page = await t.mutation(internal.countryKeyCounts.scanPage, {});
    expect(page).toEqual({ done: true, rows: 400 });
  });
});

describe('what the Countries pages read', () => {
  test('numbers only: nothing about a key, a member or a node', async () => {
    const t = await world();
    const a = await member(t, { fields: { sniRegion: 'IR' } });
    await member(t, { fields: { regionSeenCountry: 'IR', regionSeenAt: Date.now() } });
    await member(t, { fields: { sniRegion: 'ZZ' } });
    await recount(t);

    const head = await t.query(internal.edgeCountryView.summaryHead, {});
    expect(head.keys).toEqual({
      counted: true,
      countedAt: expect.any(Number),
      byCountry: {
        IR: { answered: 1, guessed: 1 },
        RU: { answered: 0, guessed: 0 },
        TR: { answered: 0, guessed: 0 },
      },
      optOut: 1,
      neither: 0,
      otherGuessed: 0,
    });
    // A country off the list has no count of its own, whatever is guessed there.
    await t.run(async (ctx) => {
      const row = (await ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', COUNTRY_KEY_COUNTS_KEY))
        .unique())!;
      const state = JSON.parse(row.value) as Record<string, unknown>;
      await ctx.db.patch(row._id, { value: JSON.stringify({ ...state, 'g:DE': 5 }) });
    });
    expect((await t.query(internal.edgeCountryView.country, { country: 'DE' })).keys).toEqual({
      counted: true,
      countedAt: expect.any(Number),
      answered: 0,
      guessed: 0,
    });
    expect((await t.query(internal.edgeCountryView.summaryHead, {})).keys.otherGuessed).toBe(5);
    await recount(t);
    const page = await t.query(internal.edgeCountryView.country, { country: 'IR' });
    expect(page.keys).toEqual({
      counted: true,
      countedAt: expect.any(Number),
      answered: 1,
      guessed: 1,
    });
    // Every leaf is a number or the one flag, and no id of a key or a member is in it.
    const leaves = (v: unknown): unknown[] =>
      v && typeof v === 'object' ? Object.values(v).flatMap(leaves) : [v];
    for (const keys of [head.keys, page.keys, await t.query(internal.countryKeyCounts.view, {})]) {
      for (const leaf of leaves(keys)) expect(['number', 'boolean']).toContain(typeof leaf);
      const text = JSON.stringify(keys);
      expect(text).not.toContain(a.subId);
      expect(text).not.toContain(a.userId);
      expect(text).not.toContain('tok_');
    }
    // The counter itself holds numbers per country and nothing else.
    const { counts } = await t.run((ctx) => readCounter(ctx.db, COUNTRY_KEY_COUNTER));
    expect(counts).toEqual({ 'c:IR': 1, 'g:IR': 1, 'c:ZZ': 1, none: 0 });
  });

  test('a country that is not on the list reads its guesses only as "another country"', () => {
    const v = countryKeysView({ 'c:IR': 2, 'g:DE': 5, 'g:IR': 1, none: 9 }, true, 1, ['IR']);
    expect(v).toEqual({
      counted: true,
      countedAt: 1,
      byCountry: { IR: { answered: 2, guessed: 1 } },
      optOut: 0,
      neither: 9,
      otherGuessed: 5,
    });
    // Nothing is known before the first count, whatever a bump left behind.
    expect(countryKeysView({ 'c:IR': 2 }, false, 1, ['IR'])).toMatchObject({
      counted: false,
      countedAt: null,
    });
  });
});
