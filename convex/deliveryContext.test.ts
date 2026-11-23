/// <reference types="vite/client" />
/**
 * The fronted subscription route's cache-hit path (GET /api/v1/sub/<token>):
 * one `deliveryContext.forToken` read, and the delivery stamp called only when
 * something is due (lib/deliveryStamp.ts). Every Convex function the route
 * calls is counted, so the per-poll cost is pinned here.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { DELIVERY_STAMP_THROTTLE_MS, planDelivery } from './lib/deliveryStamp';

const glob = import.meta.glob('./**/*.*s');

/** Function calls by `module:name`, as convex-test resolves them. */
let calls: string[] = [];
const modules: typeof glob = Object.fromEntries(
  Object.entries(glob).map(([path, load]) => [
    path,
    async () => {
      const mod = (await load()) as Record<string, unknown>;
      const name = path.replace(/^\.\//, '').replace(/\.[jt]s$/, '');
      return Object.fromEntries(
        Object.entries(mod).map(([key, fn]) => {
          const f = fn as { _handler?: (...a: unknown[]) => unknown };
          if (typeof fn !== 'function' || typeof f._handler !== 'function') return [key, fn];
          const handler = f._handler;
          return [
            key,
            Object.assign(Object.create(null), fn, {
              _handler: (...a: unknown[]) => {
                calls.push(`${name}:${key}`);
                return handler(...a);
              },
            }),
          ];
        }),
      );
    },
  ]),
);

type T = ReturnType<typeof convexTest>;

async function seedSub(t: T): Promise<{ subId: Id<'subscriptions'> }> {
  return t.run(async (ctx) => {
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
      updatedAt: Date.now(),
    });
    const serverId = await ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'RW',
      slug: 'rw-1',
      config: { type: 'remnawave', baseUrl: 'https://panel.internal', apiToken: 'tok' },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: Date.now(),
    });
    const subId = await ctx.db.insert('subscriptions', {
      userId,
      backend: 'remnawave',
      backendUserId: 'uuid-1',
      backendShortId: 'short-1',
      backendServerId: serverId,
      subscriptionUrl: 'https://panel.internal/sub/short-1',
      subscriptionMirrors: [],
      subToken: 'tok_abc',
      state: 'active',
      updatedAt: Date.now(),
    });
    await ctx.db.patch(userId, { currentSubscriptionId: subId });
    return { subId };
  });
}

let fetches = 0;
beforeEach(() => {
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('TRUSTED_PROXY', 'true');
  fetches = 0;
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => {
      fetches += 1;
      return new Response('RAW-CONFIG', { status: 200, headers: { 'content-type': 'text/yaml' } });
    }),
  );
  calls = [];
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

const poll = (t: T, headers: Record<string, string> = {}) =>
  t.fetch('/api/v1/sub/tok_abc', {
    headers: { 'user-agent': 'Clash/1', 'x-forwarded-for': '192.0.2.7', ...headers },
  });

describe('a poll answered from the cache', () => {
  test('one context read and the two rate limits; no stamp while none is due', async () => {
    const t = convexTest(schema, modules);
    const { subId } = await seedSub(t);
    const first = await poll(t);
    expect(first.status).toBe(200);
    expect(fetches).toBe(1);
    // The miss stamps the delivery and caches the body.
    expect(calls).toContain('subscriptions:markDelivered');
    expect(calls).toContain('subscriptions:writeContentCache');
    const stamped = (await t.run((ctx) => ctx.db.get(subId)))!;
    expect(stamped.lastDeliveredAt).toBeTypeOf('number');

    calls = [];
    const hit = await poll(t);
    expect(hit.status).toBe(200);
    expect(await hit.text()).toBe('RAW-CONFIG');
    expect(fetches).toBe(1);
    expect(calls).toEqual(['rateLimits:enforce', 'deliveryContext:forToken', 'rateLimits:enforce']);
    // Nothing was due, and nothing changed.
    expect(await t.run((ctx) => ctx.db.get(subId))).toEqual(stamped);

    // A conditional poll answered 304 from the cache costs the same.
    calls = [];
    const tag = hit.headers.get('etag')!;
    const revalidated = await poll(t, { 'if-none-match': tag });
    expect(revalidated.status).toBe(304);
    expect(calls).toEqual(['rateLimits:enforce', 'deliveryContext:forToken', 'rateLimits:enforce']);
  });

  test('once the stamp is due, the hit records it as before', async () => {
    const t = convexTest(schema, modules);
    const { subId } = await seedSub(t);
    await poll(t);
    const old = Date.now() - DELIVERY_STAMP_THROTTLE_MS - 1_000;
    await t.run((ctx) => ctx.db.patch(subId, { lastDeliveredAt: old }));
    calls = [];
    await poll(t);
    expect(calls).toEqual([
      'rateLimits:enforce',
      'deliveryContext:forToken',
      'rateLimits:enforce',
      'subscriptions:markDelivered',
    ]);
    expect((await t.run((ctx) => ctx.db.get(subId)))!.lastDeliveredAt).toBeGreaterThan(old);
  });

  test('an unknown token is one read and a 404', async () => {
    const t = convexTest(schema, modules);
    await seedSub(t);
    const res = await t.fetch('/api/v1/sub/nope', {
      headers: { 'user-agent': 'Clash/1', 'x-forwarded-for': '192.0.2.7' },
    });
    expect(res.status).toBe(404);
    expect(calls).toEqual(['rateLimits:enforce', 'deliveryContext:forToken']);
  });

  test('a device-bound request reads no cached body and is never served one', async () => {
    const t = convexTest(schema, modules);
    await seedSub(t);
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'devices.enforcementEnabled',
        value: 'true',
        updatedAt: Date.now(),
      }),
    );
    await poll(t);
    expect(fetches).toBe(1);
    const ctxRead = await t.query(internal.deliveryContext.forToken, {
      subToken: 'tok_abc',
      ua: 'Clash/1',
      hwidHeader: true,
    });
    expect(ctxRead).toMatchObject({ hwidEnabled: true, entries: [] });
    const res = await poll(t, { 'x-hwid': 'device-1' });
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('private, no-store');
    expect(fetches).toBe(2);
  });
});

describe('the delivery plan', () => {
  // The route skips the mutation exactly when this plan, on the row it read,
  // writes nothing; the mutation applies the same plan to the row it reads.
  const base = {
    _id: 'sub' as Id<'subscriptions'>,
    _creationTime: 0,
    state: 'active',
    deliveryRev: 2,
    lastDeliveredAt: 1_000_000,
    lastDeliveredContentAt: 900_000,
    lastRenderedEpoch: 7,
    lastRenderedAt: 1_000_000,
    lastRender: { epoch: 7, family: 'clash', listenerKeys: ['a'], at: 1 },
  } as unknown as Doc<'subscriptions'>;
  const render = { epoch: 7, family: 'clash', listenerKeys: ['a'] };
  const facts = {
    contentAt: 900_000,
    renderedEpoch: 7,
    render,
    deliveryRev: 2,
    lane: 'open' as const,
  };
  const at = 1_000_000 + DELIVERY_STAMP_THROTTLE_MS - 1;
  const live = { laneNow: 'open' as const };

  test('the same body, within the throttle: nothing', () => {
    expect(planDelivery(base, facts, at, live)).toEqual({ noteExposures: false, patch: null });
  });
  test('each fact that is due writes', () => {
    expect(planDelivery(base, facts, at + 1, live).patch).toMatchObject({
      lastDeliveredAt: at + 1,
    });
    expect(planDelivery(base, { ...facts, contentAt: 950_000 }, at, live).patch).toMatchObject({
      lastDeliveredContentAt: 950_000,
    });
    expect(planDelivery(base, { ...facts, renderedEpoch: 8 }, at, live).patch).toMatchObject({
      lastRenderedEpoch: 8,
    });
    const moved = planDelivery(
      base,
      { ...facts, render: { ...render, listenerKeys: ['b'] } },
      at,
      live,
    );
    expect(moved.noteExposures).toBe(true);
    expect(moved.patch?.lastRender).toMatchObject({ listenerKeys: ['b'], at });
  });
  test('the fence: a moved key or lane only stamps when stale', () => {
    expect(
      planDelivery(base, { ...facts, deliveryRev: 1, contentAt: 2e6 }, at, live).patch,
    ).toBeNull();
    expect(
      planDelivery(base, { ...facts, contentAt: 2e6 }, at, { laneNow: 'trusted' }).patch,
    ).toBeNull();
    expect(planDelivery(base, { ...facts, deliveryRev: 1 }, at + 1, live).patch).toEqual({
      lastDeliveredAt: at + 1,
    });
  });
  test('a snapshot naming a country the row no longer stores keeps only its plain facts', () => {
    const withCountry = { ...base, lastRender: { ...base.lastRender!, country: 'IR' } };
    const given = { ...facts, render: { ...render, country: 'IR' } };
    expect(planDelivery(withCountry, given, at, { ...live, storedCountry: 'IR' }).patch).toBeNull();
    const stripped = planDelivery(withCountry, given, at, { ...live, storedCountry: null });
    expect(stripped.patch?.lastRender).toEqual({ ...render, at });
  });
});
