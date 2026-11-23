/// <reference types="vite/client" />
/**
 * The fronted route's per-UA body cache in its own table
 * (lib/subscriptionBodies.ts): bounded per key, written without touching the
 * subscription row, dropped with the key, and the move off the old
 * `subscriptions.subCache` blob (read while it is there, moved by the first
 * write or by `migrateLegacy`).
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { SUB_CACHE_MAX, entriesForUa, keepBodiesFor } from './lib/subscriptionBodies';
import { cacheBlob, setCacheBlob } from './lib/subscriptionBodies.testing';
import { LEGACY_MOVED_KEY } from './subscriptionBodies';

const modules = import.meta.glob('./**/*.*s');

beforeEach(() => {
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
});
afterEach(() => {
  vi.unstubAllEnvs();
});

type T = ReturnType<typeof convexTest>;

/** What the route writes for a new account (open lane, no stored country). */
const entry = (ua: string, at: number, extra: Record<string, unknown> = {}) => ({
  v: 2,
  content: `body for ${ua}`,
  contentType: 'text/plain',
  ua,
  at,
  lane: 'open',
  validUntil: null,
  ...extra,
});

async function seed(t: T, opts: { subCache?: unknown[]; state?: 'active' | 'deleted' } = {}) {
  return t.run(async (ctx) => {
    const tierId = await ctx.db.insert('tiers', {
      slug: 'free',
      name: 'Tier',
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
      updatedAt: Date.now(),
    });
    const userId = await ctx.db.insert('users', {
      tierId,
      status: 'active',
      updatedAt: Date.now(),
    });
    const subscriptionId = await ctx.db.insert('subscriptions', {
      userId,
      backend: 'remnawave',
      backendUserId: `bu-${userId}`,
      backendShortId: `s-${userId}`,
      subscriptionUrl: `https://sub.example/${userId}`,
      subscriptionMirrors: [],
      subToken: 'tok_bodies',
      state: opts.state ?? 'active',
      ...(opts.subCache ? { subCache: JSON.stringify(opts.subCache) } : {}),
      updatedAt: Date.now(),
    });
    return { userId, subscriptionId };
  });
}

const write = (t: T, subscriptionId: Id<'subscriptions'>, e: Record<string, unknown>) =>
  t.mutation(internal.subscriptions.writeContentCache, {
    subscriptionId,
    entry: JSON.stringify(e),
  });
const uasOf = async (t: T, id: Id<'subscriptions'>) => {
  const blob = await t.run((ctx) => cacheBlob(ctx.db, id));
  return blob ? (JSON.parse(blob) as { ua: string }[]).map((e) => e.ua) : [];
};
const forUa = (t: T, subscriptionId: Id<'subscriptions'>, ua: string) =>
  t.run((ctx) => entriesForUa(ctx.db, subscriptionId, ua));

describe('the per-UA body table', () => {
  test('one row per UA, the newest SUB_CACHE_MAX kept, a UA replaces its own slot', async () => {
    const t = convexTest(schema, modules);
    const { subscriptionId } = await seed(t);
    for (let i = 0; i < SUB_CACHE_MAX + 2; i++) await write(t, subscriptionId, entry(`ua${i}`, i));
    expect(await uasOf(t, subscriptionId)).toEqual(['ua5', 'ua4', 'ua3', 'ua2']);
    // The same UA again: its slot is rewritten, nothing else moves.
    await write(t, subscriptionId, entry('ua3', 10, { content: 'newer' }));
    expect(await uasOf(t, subscriptionId)).toEqual(['ua3', 'ua5', 'ua4', 'ua2']);
    const [one] = await forUa(t, subscriptionId, 'ua3');
    expect(JSON.parse(one!)).toMatchObject({ content: 'newer', at: 10 });
    // A lookup loads this UA's body only, and none for a UA never fetched.
    expect(await forUa(t, subscriptionId, 'ua0')).toEqual([]);
    const rows = await t.run((ctx) => ctx.db.query('subscriptionBodies').collect());
    expect(rows).toHaveLength(SUB_CACHE_MAX);
  });

  test('a body write leaves the subscription row untouched', async () => {
    const t = convexTest(schema, modules);
    const { subscriptionId } = await seed(t);
    const before = await t.run((ctx) => ctx.db.get(subscriptionId));
    await write(t, subscriptionId, entry('a', 1));
    await write(t, subscriptionId, entry('b', 2));
    expect(await t.run((ctx) => ctx.db.get(subscriptionId))).toEqual(before);
  });

  test('dropped with the key and on an in-place move', async () => {
    const t = convexTest(schema, modules);
    const { subscriptionId } = await seed(t);
    await write(t, subscriptionId, entry('a', 1));
    await t.mutation(internal.subscriptions.setPlacementAndClearCache, {
      subscriptionId,
      placement: 'squad-b',
    });
    expect(await uasOf(t, subscriptionId)).toEqual([]);
    await write(t, subscriptionId, entry('a', 2));
    await t.mutation(internal.subscriptions.markSubscriptionDeleted, { subscriptionId });
    expect(await uasOf(t, subscriptionId)).toEqual([]);
    // And a deleted key takes no new body.
    await write(t, subscriptionId, entry('a', 3));
    expect(await uasOf(t, subscriptionId)).toEqual([]);
  });
});

describe('a country change', () => {
  test('keeps the bodies shaped for no country or for the stored one, drops the rest', async () => {
    const t = convexTest(schema, modules);
    const { subscriptionId } = await seed(t);
    await t.run((ctx) =>
      setCacheBlob(
        ctx.db,
        subscriptionId,
        JSON.stringify([
          entry('ir', 4, { region: 'IR' }),
          entry('none', 3),
          entry('ru', 2, { region: 'RU' }),
          entry('null', 1, { region: null }),
        ]),
      ),
    );
    await t.run((ctx) => keepBodiesFor(ctx, subscriptionId, 'RU'));
    expect(await uasOf(t, subscriptionId)).toEqual(['none', 'ru', 'null']);
    await t.run((ctx) => keepBodiesFor(ctx, subscriptionId, null));
    expect(await uasOf(t, subscriptionId)).toEqual(['none', 'null']);
  });
});

describe('the move off the old blob', () => {
  const legacy = [entry('a', 3), entry('b', 2), entry('c', 1)];

  test('a key not moved yet is still answered from its blob, per UA', async () => {
    const t = convexTest(schema, modules);
    const { subscriptionId } = await seed(t, { subCache: legacy });
    expect((await forUa(t, subscriptionId, 'b')).map((s) => JSON.parse(s))).toEqual([legacy[1]]);
    expect(await forUa(t, subscriptionId, 'z')).toEqual([]);
  });

  test('the first body written moves the rest of the blob across and clears it', async () => {
    const t = convexTest(schema, modules);
    const { subscriptionId } = await seed(t, { subCache: legacy });
    await write(t, subscriptionId, entry('b', 5, { content: 'fresh' }));
    expect(await uasOf(t, subscriptionId)).toEqual(['b', 'a', 'c']);
    expect((await t.run((ctx) => ctx.db.get(subscriptionId)))!.subCache).toBeUndefined();
    const [b] = await forUa(t, subscriptionId, 'b');
    expect(JSON.parse(b!)).toMatchObject({ content: 'fresh' });
    expect(JSON.parse((await forUa(t, subscriptionId, 'c'))[0]!)).toEqual(legacy[2]);
  });

  test('migrateLegacy moves every blob once, drops a deleted key’s, then is a no-op', async () => {
    const t = convexTest(schema, modules);
    const live = await seed(t, { subCache: legacy });
    const gone = await t.run(async (ctx) => {
      const row = (await ctx.db.get(live.subscriptionId))!;
      const { _id, _creationTime, ...copy } = row;
      void _id;
      void _creationTime;
      return ctx.db.insert('subscriptions', {
        ...copy,
        subToken: undefined,
        state: 'deleted',
        backendUserId: 'bu-gone',
      });
    });
    const none = await seed(t);
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    await t.mutation(internal.subscriptionBodies.migrateLegacy, {});
    await t.finishAllScheduledFunctions(vi.runAllTimers);
    vi.useRealTimers();
    expect(await uasOf(t, live.subscriptionId)).toEqual(['a', 'b', 'c']);
    expect(await uasOf(t, gone)).toEqual([]);
    expect(await uasOf(t, none.subscriptionId)).toEqual([]);
    const rows = await t.run((ctx) => ctx.db.query('subscriptions').collect());
    expect(rows.every((r) => r.subCache === undefined)).toBe(true);
    const flag = await t.run((ctx) =>
      ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', LEGACY_MOVED_KEY))
        .unique(),
    );
    expect(flag).not.toBeNull();
    // Once done, a later deploy's call reads nothing.
    await t.run((ctx) =>
      ctx.db.patch(none.subscriptionId, { subCache: JSON.stringify([entry('x', 1)]) }),
    );
    expect(await t.mutation(internal.subscriptionBodies.migrateLegacy, {})).toEqual({ moved: 0 });
  });

  test('clearForRollback pauses writes, empties the table, and the move runs again after resume', async () => {
    const t = convexTest(schema, modules);
    const { subscriptionId } = await seed(t, { subCache: legacy });
    await t.mutation(internal.subscriptionBodies.migrateLegacy, {});
    expect(await uasOf(t, subscriptionId)).toEqual(['a', 'b', 'c']);
    const status = () => t.query(internal.subscriptionBodies.rollbackStatus, {});
    expect(await status()).toEqual({ paused: false, empty: false });
    expect(await t.mutation(internal.subscriptionBodies.clearForRollback, {})).toEqual({
      deleted: 3,
    });
    expect(await status()).toEqual({ paused: true, empty: true });
    // A fetch while the drain runs writes no body behind it, and no move runs.
    await write(t, subscriptionId, entry('late', 9));
    expect(await uasOf(t, subscriptionId)).toEqual([]);
    // The older build wrote a blob again.
    await t.run((ctx) =>
      ctx.db.patch(subscriptionId, { subCache: JSON.stringify([entry('x', 1)]) }),
    );
    expect(await t.mutation(internal.subscriptionBodies.migrateLegacy, {})).toEqual({ moved: 0 });
    expect(await status()).toEqual({ paused: true, empty: true });
    // This build deployed again: the pause is lifted and the move picks the blob up.
    expect(await t.mutation(internal.subscriptionBodies.resume, {})).toEqual({ resumed: true });
    expect(await t.mutation(internal.subscriptionBodies.migrateLegacy, {})).toEqual({ moved: 1 });
    expect(await uasOf(t, subscriptionId)).toEqual(['x']);
    await write(t, subscriptionId, entry('late', 9));
    expect(await uasOf(t, subscriptionId)).toEqual(['late', 'x']);
  });
});
