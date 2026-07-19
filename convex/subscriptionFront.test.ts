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
let mockStatus = 200;
let fetchCalls = 0;
// Request headers seen by the LAST stubbed panel fetch (to assert forwarding).
let lastReqHeaders: Record<string, string> = {};
function stubFrontFetch(): void {
  fetchCalls = 0;
  lastReqHeaders = {};
  vi.stubGlobal(
    'fetch',
    vi.fn(async (_url: string, init?: { headers?: Record<string, string> }) => {
      fetchCalls += 1;
      lastReqHeaders = { ...(init?.headers ?? {}) };
      return new Response(mockBody, { status: mockStatus, headers: mockHeaders });
    }),
  );
}

// HWID forwarding is gated on the device-enforcement master toggle (Review
// B-F1) — turn it on for the device-specific tests.
async function enableDeviceEnforcement(t: ReturnType<typeof convexTest>): Promise<void> {
  await t.run(async (ctx) => {
    await ctx.db.insert('appSettings', {
      key: 'devices.enforcementEnabled',
      value: 'true',
      updatedAt: Date.now(),
    });
  });
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
    mockStatus = 200;
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
    // A shared cache MUST vary on UA (the body is UA-formatted). (WS4 / M1.)
    expect(res.headers.get('vary')).toBe('User-Agent');
    expect(res.headers.get('subscription-userinfo')).toBe(
      'upload=0; download=10; total=100; expire=0',
    );
    expect(fetchCalls).toBe(1);
  });

  test('an x-hwid (device-specific) request is private/no-store and never shared-cached (WS4)', async () => {
    const t = convexTest(schema, modules);
    await seedSub(t);
    await enableDeviceEnforcement(t);
    const res = await t.fetch('/api/v1/sub/tok_abc', {
      headers: { 'user-agent': 'Karing/1', 'x-hwid': 'device-aaa' },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('private, no-store');
    expect(res.headers.get('vary')).toBeNull(); // device-specific → no shared caching at all
    expect(fetchCalls).toBe(1);
    // A different device (same UA) must reach the panel too — no cross-serve.
    await t.fetch('/api/v1/sub/tok_abc', {
      headers: { 'user-agent': 'Karing/1', 'x-hwid': 'device-bbb' },
    });
    expect(fetchCalls).toBe(2);
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

  // Review #11: the bounded per-UA cache retains multiple clients' formats, so two
  // apps on one subscription don't evict each other into a refetch-per-request
  // thrash (the old single-slot cache dropped UA1's entry when UA2 wrote).
  test('two UAs are cached independently (no thrash on alternating polls)', async () => {
    const t = convexTest(schema, modules);
    await seedSub(t);
    await t.fetch('/api/v1/sub/tok_abc', { headers: { 'user-agent': 'Clash/1' } }); // fetch #1
    mockBody = 'RAW-CONFIG-SINGBOX';
    await t.fetch('/api/v1/sub/tok_abc', { headers: { 'user-agent': 'sing-box/1' } }); // fetch #2
    expect(fetchCalls).toBe(2);
    // Re-poll UA1: still cached (would have refetched under the old single slot).
    mockBody = 'RAW-CONFIG-WOULD-REFETCH';
    const c1 = await t.fetch('/api/v1/sub/tok_abc', { headers: { 'user-agent': 'Clash/1' } });
    expect(await c1.text()).toBe('RAW-CONFIG-1');
    // Re-poll UA2: still cached with ITS format.
    const c2 = await t.fetch('/api/v1/sub/tok_abc', { headers: { 'user-agent': 'sing-box/1' } });
    expect(await c2.text()).toBe('RAW-CONFIG-SINGBOX');
    expect(fetchCalls).toBe(2); // neither re-poll hit the backend
  });

  test('forwards the client HWID headers to the panel fetch', async () => {
    const t = convexTest(schema, modules);
    await seedSub(t);
    await enableDeviceEnforcement(t);
    await t.fetch('/api/v1/sub/tok_abc', {
      headers: {
        'user-agent': 'Karing/1',
        'x-hwid': 'device-abc-123',
        'x-device-os': 'iOS',
        'x-ver-os': '17.0',
        'x-device-model': 'iPhone15,2',
      },
    });
    expect(lastReqHeaders['x-hwid']).toBe('device-abc-123');
    expect(lastReqHeaders['x-device-os']).toBe('iOS');
    expect(lastReqHeaders['x-ver-os']).toBe('17.0');
    expect(lastReqHeaders['x-device-model']).toBe('iPhone15,2');
    expect(lastReqHeaders['user-agent']).toBe('Karing/1');
  });

  test('an hwid request BYPASSES the cache (each device reaches the panel to register)', async () => {
    const t = convexTest(schema, modules);
    await seedSub(t);
    await enableDeviceEnforcement(t);
    // Two devices, same UA, different hwid → two panel fetches (no cache collision).
    await t.fetch('/api/v1/sub/tok_abc', {
      headers: { 'user-agent': 'Karing/1', 'x-hwid': 'device-A' },
    });
    await t.fetch('/api/v1/sub/tok_abc', {
      headers: { 'user-agent': 'Karing/1', 'x-hwid': 'device-B' },
    });
    expect(fetchCalls).toBe(2);
    expect(lastReqHeaders['x-hwid']).toBe('device-B');
    // And an hwid response is not written to the cache: a subsequent no-hwid poll
    // still hits the backend (nothing cached for this UA).
    const noHwid = await t.fetch('/api/v1/sub/tok_abc', { headers: { 'user-agent': 'Karing/1' } });
    expect(noHwid.status).toBe(200);
    expect(fetchCalls).toBe(3);
  });

  test('panel 404 (HWID rejection) passes through as 404, not a 502 or a stale body', async () => {
    const t = convexTest(schema, modules);
    await seedSub(t);
    await enableDeviceEnforcement(t);
    // Prime a cached body for this UA (no hwid) so we can prove 404 doesn't serve it.
    await t.fetch('/api/v1/sub/tok_abc', { headers: { 'user-agent': 'Karing/1' } });
    expect(fetchCalls).toBe(1);
    // Now the panel rejects the device-limited fetch with 404.
    mockStatus = 404;
    mockBody = 'not found';
    const res = await t.fetch('/api/v1/sub/tok_abc', {
      headers: { 'user-agent': 'Karing/1', 'x-hwid': 'unregistered-device' },
    });
    expect(res.status).toBe(404);
    // Not the stale cached body.
    expect(await res.text()).not.toBe('RAW-CONFIG-1');
  });

  // Review #11: on a backend outage the stale fallback must match the requester's
  // UA — never serve another client's format. A UA with nothing cached gets 502.
  test('with device enforcement OFF, x-hwid is NOT forwarded (and the request uses the cache path)', async () => {
    const t = convexTest(schema, modules);
    await seedSub(t); // no enableDeviceEnforcement — the toggle defaults off
    // Review B-F1: an x-hwid on an enforcement-off deploy has zero panel effect
    // (FCP never sends a hwidDeviceLimit), so forwarding would only REGISTER
    // arbitrary devices (the stuffing vector). It must be dropped.
    const res = await t.fetch('/api/v1/sub/tok_abc', {
      headers: { 'user-agent': 'Karing/1', 'x-hwid': 'device-aaa' },
    });
    expect(res.status).toBe(200);
    expect(lastReqHeaders['x-hwid']).toBeUndefined();
    // Not device-specific → the public cache path applies (Vary + shared TTL).
    expect(res.headers.get('vary')).toBe('User-Agent');
    // A second "different device" poll hits the SAME cache entry (no bypass).
    await t.fetch('/api/v1/sub/tok_abc', {
      headers: { 'user-agent': 'Karing/1', 'x-hwid': 'device-bbb' },
    });
    expect(fetchCalls).toBe(1);
  });

  test('the per-token rate limit 429s a UA-rotating burst past the cap (Review B-F1)', async () => {
    const t = convexTest(schema, modules);
    await seedSub(t);
    // 60/min per token; rotate the UA so every request is a live panel fetch.
    let last: Response | null = null;
    for (let i = 0; i < 61; i++) {
      last = await t.fetch('/api/v1/sub/tok_abc', { headers: { 'user-agent': `Rot/${i}` } });
    }
    expect(last!.status).toBe(429);
    // The cap is per TOKEN, not per IP: an unknown token is a plain 404 (no bucket).
    const res = await t.fetch('/api/v1/sub/does-not-exist');
    expect(res.status).toBe(404);
  });

  test('a deleted subscription resolves as not found (Review D-#12)', async () => {
    const t = convexTest(schema, modules);
    await seedSub(t, { state: 'deleted' });
    const res = await t.fetch('/api/v1/sub/tok_abc');
    expect(res.status).toBe(404);
    expect(fetchCalls).toBe(0);
    // A tombstoned (grace) row still resolves — the 24h grace URL must work.
    const t2 = convexTest(schema, modules);
    await seedSub(t2, { state: 'disabled' });
    const res2 = await t2.fetch('/api/v1/sub/tok_abc', { headers: { 'user-agent': 'Clash/1' } });
    expect(res2.status).toBe(200);
  });

  test('the panel landing page is sandboxed + nosniff (same-origin XSS guard)', async () => {
    const t = convexTest(schema, modules);
    await seedSub(t);
    const res = await t.fetch('/api/v1/sub/tok_abc', { headers: { 'user-agent': 'Mozilla/5' } });
    expect(res.headers.get('content-security-policy')).toContain('sandbox');
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
  });

  test('backend-down stale fallback never serves another UA’s format', async () => {
    const t = convexTest(schema, modules);
    await seedSub(t);
    await t.fetch('/api/v1/sub/tok_abc', { headers: { 'user-agent': 'Clash/1' } }); // prime UA1
    expect(fetchCalls).toBe(1);
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('backend down');
      }),
    );
    // A different UA has nothing cached → 502, NOT UA1's cached content.
    const other = await t.fetch('/api/v1/sub/tok_abc', {
      headers: { 'user-agent': 'sing-box/1' },
    });
    expect(other.status).toBe(502);
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
