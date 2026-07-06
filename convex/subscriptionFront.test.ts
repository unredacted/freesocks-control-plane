/// <reference types="vite/client" />
/**
 * FCP-fronted subscription route (GET /api/v1/sub/<token>): the public,
 * unauthenticated, small-TTL-cached content proxy that fronts the backend
 * subscription URL for the member's proxy app. Covers token minting/resolution,
 * the cache hit/miss + User-Agent keying, header passthrough, 404, and the
 * account-view URL (fronted vs. fallback).
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';

const modules = import.meta.glob('./**/*.*s');

const FREE_TIER = {
  slug: 'free',
  name: 'Free',
  backend: 'remnawave' as const,
  monthlyTrafficGb: 50,
  deviceLimit: 1,
  hwidLimit: 1,
  hwidEnabled: true,
  trafficStrategy: 'MONTH' as const,
  isDefaultFree: true,
  isActive: true,
  priority: 0,
  expirationDaysAfterMembershipLapse: 0,
};

async function seedSub(
  t: ReturnType<typeof convexTest>,
  subOver: Record<string, unknown> = {},
): Promise<{ userId: Id<'users'>; subId: Id<'subscriptions'> }> {
  return t.run(async (ctx) => {
    const tierId = await ctx.db.insert('tiers', { ...FREE_TIER, updatedAt: Date.now() });
    const userId = await ctx.db.insert('users', {
      tierId,
      status: 'active',
      supportId: 'SUP-1',
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
      ...subOver,
    });
    await ctx.db.patch(userId, { currentSubscriptionId: subId });
    return { userId, subId };
  });
}

// A mutable content + header source for the fronted-fetch mock, plus a call count.
let mockBody = 'RAW-CONFIG-1';
let mockHeaders: Record<string, string> = { 'content-type': 'text/yaml' };
let fetchCalls = 0;
function stubFrontFetch(): void {
  fetchCalls = 0;
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => {
      fetchCalls += 1;
      return new Response(mockBody, { status: 200, headers: mockHeaders });
    }),
  );
}

describe('subscription token minting + resolution', () => {
  test('insertSubscription mints a 32-hex token; bySubToken resolves it', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedSub(t); // seeds one with the fixed 'tok_abc'
    const id = await t.mutation(internal.subscriptions.insertSubscription, {
      userId,
      backend: 'remnawave',
      backendUserId: 'uuid-2',
      backendShortId: 'short-2',
      subscriptionUrl: 'https://panel.internal/sub/short-2',
      subscriptionMirrors: [],
    });
    const row = await t.run((ctx) => ctx.db.get(id));
    expect(row?.subToken).toMatch(/^[0-9a-f]{32}$/);
    const resolved = await t.query(internal.subscriptions.bySubToken, {
      subToken: row!.subToken!,
    });
    expect(resolved?._id).toBe(id);
  });
});

describe('GET /api/v1/sub/<token>', () => {
  beforeEach(() => {
    vi.stubEnv('IP_HASH_SALT', 'test-salt');
    mockBody = 'RAW-CONFIG-1';
    mockHeaders = {
      'content-type': 'text/yaml',
      'subscription-userinfo': 'upload=0; download=10; total=100; expire=0',
    };
    stubFrontFetch();
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  test('404 for an unknown token (no backend fetch)', async () => {
    const t = convexTest(schema, modules);
    await seedSub(t);
    const res = await t.fetch('/api/v1/sub/does-not-exist');
    expect(res.status).toBe(404);
    expect(fetchCalls).toBe(0);
  });

  test('cache miss: raw content + backend content-type + cache-control + passthrough headers', async () => {
    const t = convexTest(schema, modules);
    await seedSub(t);
    const res = await t.fetch('/api/v1/sub/tok_abc', { headers: { 'user-agent': 'Clash/1' } });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('RAW-CONFIG-1');
    expect(res.headers.get('content-type')).toBe('text/yaml');
    expect(res.headers.get('cache-control')).toContain('max-age=');
    expect(res.headers.get('subscription-userinfo')).toBe(
      'upload=0; download=10; total=100; expire=0',
    );
    expect(fetchCalls).toBe(1);
  });

  test('same-UA re-poll within TTL is served from cache (no second backend fetch)', async () => {
    const t = convexTest(schema, modules);
    await seedSub(t);
    await t.fetch('/api/v1/sub/tok_abc', { headers: { 'user-agent': 'Clash/1' } });
    expect(fetchCalls).toBe(1);
    mockBody = 'RAW-CONFIG-2'; // would surface if it refetched
    const res2 = await t.fetch('/api/v1/sub/tok_abc', { headers: { 'user-agent': 'Clash/1' } });
    expect(await res2.text()).toBe('RAW-CONFIG-1'); // cached
    expect(fetchCalls).toBe(1);
  });

  test('different UA bypasses the cache and refetches (format correctness)', async () => {
    const t = convexTest(schema, modules);
    await seedSub(t);
    await t.fetch('/api/v1/sub/tok_abc', { headers: { 'user-agent': 'Clash/1' } });
    mockBody = 'RAW-CONFIG-SINGBOX';
    const res2 = await t.fetch('/api/v1/sub/tok_abc', { headers: { 'user-agent': 'sing-box/1' } });
    expect(await res2.text()).toBe('RAW-CONFIG-SINGBOX');
    expect(fetchCalls).toBe(2);
  });
});

describe('getAccountView subscription URL', () => {
  beforeEach(() => {
    // Mock backend so getAccountView's live getUser doesn't hit the network.
    vi.stubEnv('DEV_MOCK_BACKEND', 'true');
    vi.stubEnv('ENVIRONMENT', 'development');
    vi.stubEnv('IP_HASH_SALT', 'test-salt');
  });
  afterEach(() => vi.unstubAllEnvs());

  test('exposes the raw backend url + the opaque subToken (SPA builds the fronted URL)', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedSub(t);
    const view = await t.action(internal.account.getAccountView, { userId });
    // The server returns the RAW backend URL; the SPA fronts it from subToken +
    // its own origin (subscriptionDisplayUrl), so there's no PUBLIC_BASE_URL dep.
    expect(view?.subscription?.url).toBe('https://panel.internal/sub/short-1');
    expect(view?.subscription?.subToken).toBe('tok_abc');
  });

  test('subToken is null for a legacy subscription issued before the token existed', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedSub(t, { subToken: undefined });
    const view = await t.action(internal.account.getAccountView, { userId });
    expect(view?.subscription?.subToken).toBeNull();
  });
});
