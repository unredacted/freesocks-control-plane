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
import YAML from 'yaml';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { addressRemark } from './lib/backend/hostRemark';
import { decodeBase64Loose, encodeBase64 } from './lib/edges/render/base64';
import { signValue } from './lib/cookies';

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
// Request headers seen by the LAST stubbed backend fetch (to assert forwarding).
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
    // A different device (same UA) must reach the backend too — no cross-serve.
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

  test('forwards the client HWID headers to the backend fetch', async () => {
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

  test('an hwid request BYPASSES the cache (each device reaches the backend to register)', async () => {
    const t = convexTest(schema, modules);
    await seedSub(t);
    await enableDeviceEnforcement(t);
    // Two devices, same UA, different hwid → two backend fetches (no cache collision).
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

  test('backend 404 (HWID rejection) passes through as 404, not a 502 or a stale body', async () => {
    const t = convexTest(schema, modules);
    await seedSub(t);
    await enableDeviceEnforcement(t);
    // Prime a cached body for this UA (no hwid) so we can prove 404 doesn't serve it.
    await t.fetch('/api/v1/sub/tok_abc', { headers: { 'user-agent': 'Karing/1' } });
    expect(fetchCalls).toBe(1);
    // Now the backend rejects the device-limited fetch with 404.
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
    // Review B-F1: an x-hwid on an enforcement-off deploy has zero backend effect
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
    // 60/min per token; rotate the UA so every request is a live backend fetch.
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

  test('the backend landing page is sandboxed + nosniff (same-origin XSS guard)', async () => {
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

describe('GET /api/v1/sub/<token>: member-facing entry names', () => {
  // Two direct nodes serving the same mode, two server names each: what the
  // backend serves a key whose mode group holds both (example names).
  const NODES = [
    { node: 'quiet-amber-falcon', address: '192.0.2.10' },
    { node: 'brisk-cobalt-otter', address: '198.51.100.20' },
  ];
  const SERVER_NAMES = ['www.decoy-a.example', 'cdn.decoy-b.example'];
  const LINKS = NODES.flatMap(({ node, address }) =>
    SERVER_NAMES.map(
      (sni) =>
        `vless://11111111-2222-3333-4444-555555555555@${address}:443?security=reality&type=tcp&sni=${sni}&pbk=PUBKEY&sid=ab#${encodeURIComponent(addressRemark(node, sni))}`,
    ),
  );

  beforeEach(() => {
    vi.stubEnv('IP_HASH_SALT', 'test-salt');
    mockBody = encodeBase64(LINKS.join('\n'));
    mockStatus = 200;
    mockHeaders = { 'content-type': 'text/plain' };
    stubFrontFetch();
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  async function seedWithLocation(t: ReturnType<typeof convexTest>) {
    const seeded = await seedSub(t);
    await t.run(async (ctx) => {
      const sub = (await ctx.db.get(seeded.subId))!;
      await ctx.db.patch(sub.backendServerId!, {
        location: 'EXC',
        locationLabel: 'Example City, EX',
      });
    });
    return seeded;
  }

  async function served(t: ReturnType<typeof convexTest>): Promise<string[]> {
    const res = await t.fetch('/api/v1/sub/tok_abc', { headers: { 'user-agent': 'Hiddify/2.0' } });
    expect(res.status).toBe(200);
    return decodeBase64Loose(await res.text())!.split('\n');
  }

  test('the member gets one node, pinned, under neutral names; no node or server name in a name', async () => {
    const t = convexTest(schema, modules);
    const { subId } = await seedWithLocation(t);
    const lines = await served(t);
    const pinned = (await t.run((ctx) => ctx.db.get(subId)))!.pinnedNode;
    const node = NODES.find((n) => n.node === pinned)!;
    expect(node).toBeTruthy();
    expect(lines).toHaveLength(SERVER_NAMES.length);
    expect(lines.every((l) => new URL(l).hostname === node.address)).toBe(true);
    const names = lines.map((l) => decodeURIComponent(l.slice(l.indexOf('#') + 1)));
    expect(new Set(names).size).toBe(names.length);
    for (const name of names) {
      expect(name).toMatch(/^FreeSocks · Example City · [A-Z2-9]{4}$/);
      for (const sni of SERVER_NAMES) expect(name).not.toContain(sni);
    }
    for (const n of NODES) expect(lines.join('\n')).not.toContain(n.node);
    // A refresh (cache cleared) gives the same names.
    await t.run((ctx) => ctx.db.patch(subId, { subCache: undefined }));
    expect(await served(t)).toEqual(lines);
  });

  test('the service name comes from subscription.siteName; turned off, the backend names pass', async () => {
    const t = convexTest(schema, modules);
    const { subId } = await seedWithLocation(t);
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'subscription.siteName',
        value: JSON.stringify('Example VPN'),
        updatedAt: Date.now(),
      }),
    );
    const named = await served(t);
    expect(
      named.every((l) => decodeURIComponent(l.split('#')[1]).startsWith('Example VPN · ')),
    ).toBe(true);
    await t.run(async (ctx) => {
      await ctx.db.insert('appSettings', {
        key: 'subscription.entryNames',
        value: 'false',
        updatedAt: Date.now(),
      });
      await ctx.db.patch(subId, { subCache: undefined });
    });
    const raw = await served(t);
    const pinned = (await t.run((ctx) => ctx.db.get(subId)))!.pinnedNode!;
    expect(raw.every((l) => decodeURIComponent(l.split('#')[1]).startsWith(`${pinned} | `))).toBe(
      true,
    );
  });
});

/**
 * The subscription title: the backend sent its own (`profile-title`), so apps
 * named the subscription after the backend product. FCP names it itself, from
 * the service name (`subscription.siteName`), on every path a body can take.
 */
describe('profile-title is the service name on every subscription response', () => {
  const b64 = (name: string) =>
    `base64:${btoa(String.fromCharCode(...new TextEncoder().encode(name)))}`;
  beforeEach(() => {
    vi.stubEnv('IP_HASH_SALT', 'test-salt');
    mockBody = 'RAW-CONFIG-1';
    mockStatus = 200;
    mockHeaders = { 'content-type': 'text/yaml', 'profile-title': 'base64:UmVtbmF3YXZl' };
    stubFrontFetch();
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });
  const get = (t: ReturnType<typeof convexTest>, ua = 'Clash/1') =>
    t.fetch('/api/v1/sub/tok_abc', { headers: { 'user-agent': ua } });

  test('the backend title never reaches the app: the default name, then the admin-set one (cache hit too)', async () => {
    const t = convexTest(schema, modules);
    await seedSub(t);
    const first = await get(t);
    expect(first.headers.get('profile-title')).toBe(b64('FreeSocks'));
    expect(b64('FreeSocks')).toBe('base64:RnJlZVNvY2tz');

    // A name with non-ASCII letters survives the header (that is what base64 is for).
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'subscription.siteName',
        value: JSON.stringify('  Свобода VPN\n'),
        updatedAt: Date.now(),
      }),
    );
    const cached = await get(t);
    expect(fetchCalls).toBe(1); // a cache hit, still titled now
    expect(cached.headers.get('profile-title')).toBe(b64('Свобода VPN'));
  });

  test('a stale body served while the backend is down carries it', async () => {
    const t = convexTest(schema, modules);
    const { subId } = await seedSub(t);
    await get(t);
    // Age the cached body past its TTL, then take the backend down.
    await t.run(async (ctx) => {
      const sub = (await ctx.db.get(subId))!;
      const entries = JSON.parse(sub.subCache!) as Array<{ at: number }>;
      for (const e of entries) e.at -= 24 * 3600_000;
      await ctx.db.patch(subId, { subCache: JSON.stringify(entries) });
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('backend down');
      }),
    );
    const res = await get(t);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('RAW-CONFIG-1');
    expect(res.headers.get('profile-title')).toBe(b64('FreeSocks'));
  });

  test('an Outline key (no headers of its own) is titled too', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      const tierId = await ctx.db.insert('tiers', {
        ...FREE_TIER,
        backend: 'outline',
        updatedAt: Date.now(),
      });
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        supportId: 'SUP-2',
        updatedAt: Date.now(),
      });
      const serverId = await ctx.db.insert('backendServers', {
        backend: 'outline',
        name: 'OL',
        slug: 'ol-1',
        config: {
          type: 'outline',
          apiUrl: 'https://outline.test/secret/',
          websocketEnabled: false,
        },
        isActive: true,
        priority: 0,
        keyCount: 0,
        updatedAt: Date.now(),
      });
      await ctx.db.insert('subscriptions', {
        userId,
        backend: 'outline',
        backendUserId: '7',
        backendShortId: '7',
        backendServerId: serverId,
        subscriptionUrl: 'ss://key',
        subscriptionMirrors: [],
        subToken: 'tok_abc',
        state: 'active',
        updatedAt: Date.now(),
      });
    });
    mockHeaders = { 'content-type': 'application/json' };
    mockBody = JSON.stringify({ id: '7', accessUrl: 'ss://key@192.0.2.9:443' });
    const res = await get(t);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('ss://key@192.0.2.9:443\n');
    expect(res.headers.get('profile-title')).toBe(b64('FreeSocks'));
  });
});

/**
 * The backend's page URL (`profile-web-page-url`) is the key's own backend
 * subscription URL: the backend's public address plus the key's capability,
 * whose body names the backend's nodes. It never reaches the app, whichever
 * path the body took, including a body cached before the header stopped
 * passing.
 */
describe('the backend’s page URL never reaches the app', () => {
  const PAGE_URL = 'https://panel.example.org/api/sub/short-1';
  const USERINFO = 'upload=0; download=10; total=100; expire=0';
  beforeEach(() => {
    vi.stubEnv('IP_HASH_SALT', 'test-salt');
    mockBody = 'RAW-CONFIG-1';
    mockStatus = 200;
    mockHeaders = {
      'content-type': 'text/yaml',
      'subscription-userinfo': USERINFO,
      'profile-update-interval': '12',
      'profile-web-page-url': PAGE_URL,
    };
    stubFrontFetch();
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });
  const get = (t: ReturnType<typeof convexTest>) =>
    t.fetch('/api/v1/sub/tok_abc', { headers: { 'user-agent': 'Clash/1' } });
  const expectNoPageUrl = (res: Response) => {
    expect(res.status).toBe(200);
    expect(res.headers.get('profile-web-page-url')).toBeNull();
    expect(res.headers.get('subscription-userinfo')).toBe(USERINFO);
    expect(res.headers.get('profile-update-interval')).toBe('12');
  };

  test('fresh, then from a body cached with the header, then stale', async () => {
    const t = convexTest(schema, modules);
    const { subId } = await seedSub(t);
    expectNoPageUrl(await get(t));
    expect(fetchCalls).toBe(1);
    // A body cached while the header still passed (before this change).
    const patchCache = (edit: (e: { at: number; headers?: Record<string, string> }) => void) =>
      t.run(async (ctx) => {
        const sub = (await ctx.db.get(subId))!;
        const entries = JSON.parse(sub.subCache!) as Array<{
          at: number;
          headers?: Record<string, string>;
        }>;
        for (const e of entries) edit(e);
        await ctx.db.patch(subId, { subCache: JSON.stringify(entries) });
      });
    await patchCache((e) => {
      e.headers = { ...e.headers, 'profile-web-page-url': PAGE_URL };
    });
    expectNoPageUrl(await get(t));
    expect(fetchCalls).toBe(1); // a cache hit
    // The same body, aged past its TTL, served while the backend is down.
    await patchCache((e) => {
      e.at -= 24 * 3600_000;
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('backend down');
      }),
    );
    const stale = await get(t);
    expectNoPageUrl(stale);
    expect(await stale.text()).toBe('RAW-CONFIG-1');
  });
});

/**
 * The backend's subscription templates name their selector group after the
 * backend product; apps show it like a connection. Members get the service's
 * own name for it instead, unless the operator turned member names off.
 */
describe('GET /api/v1/sub/<token>: the backend’s group', () => {
  const NODE = 'quiet-amber-falcon';
  const SERVER_NAMES = ['www.decoy-a.example', 'cdn.decoy-b.example'];
  const PROXIES = SERVER_NAMES.map((sni) => ({
    name: addressRemark(NODE, sni),
    type: 'vless',
    server: '192.0.2.10',
    port: 443,
    uuid: '11111111-2222-3333-4444-555555555555',
    servername: sni,
    'reality-opts': { 'public-key': 'PUBKEY', 'short-id': 'ab' },
  }));
  // What the backend makes of its Clash template for this key.
  const BODY = YAML.stringify({
    'mixed-port': 7890,
    mode: 'global',
    proxies: PROXIES,
    'proxy-groups': [{ name: '→ Remnawave', type: 'select', proxies: PROXIES.map((p) => p.name) }],
    rules: ['MATCH,→ Remnawave'],
  });

  beforeEach(() => {
    vi.stubEnv('IP_HASH_SALT', 'test-salt');
    mockBody = BODY;
    mockStatus = 200;
    mockHeaders = { 'content-type': 'text/yaml' };
    stubFrontFetch();
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  async function served(t: ReturnType<typeof convexTest>) {
    const res = await t.fetch('/api/v1/sub/tok_abc', { headers: { 'user-agent': 'mihomo/1.19' } });
    expect(res.status).toBe(200);
    const text = await res.text();
    const doc = YAML.parse(text) as {
      proxies: Array<{ name: string }>;
      'proxy-groups': Array<{ name: string; proxies: string[] }>;
      rules: string[];
    };
    return { text, doc };
  }

  test('the group is "<site> Select" and every reference follows; off, it is the backend’s', async () => {
    const t = convexTest(schema, modules);
    const { subId } = await seedSub(t);
    const { text, doc } = await served(t);
    expect(text).not.toMatch(/remnawave/i);
    expect(text).not.toContain(NODE);
    expect(doc['proxy-groups'].map((g) => g.name)).toEqual(['FreeSocks Select']);
    expect(doc['proxy-groups'][0].proxies).toEqual(doc.proxies.map((p) => p.name));
    expect(doc.rules).toEqual(['MATCH,FreeSocks Select']);

    await t.run(async (ctx) => {
      await ctx.db.insert('appSettings', {
        key: 'subscription.siteName',
        value: JSON.stringify('Example VPN'),
        updatedAt: Date.now(),
      });
      await ctx.db.patch(subId, { subCache: undefined });
    });
    expect((await served(t)).doc.rules).toEqual(['MATCH,Example VPN Select']);

    await t.run(async (ctx) => {
      await ctx.db.insert('appSettings', {
        key: 'subscription.entryNames',
        value: 'false',
        updatedAt: Date.now(),
      });
      await ctx.db.patch(subId, { subCache: undefined });
    });
    const off = await served(t);
    expect(off.doc['proxy-groups'].map((g) => g.name)).toEqual(['→ Remnawave']);
    expect(off.doc.rules).toEqual(['MATCH,→ Remnawave']);
  });

  test('a body cached before the rename is renamed on a cache hit and when served stale', async () => {
    const t = convexTest(schema, modules);
    const { subId } = await seedSub(t);
    await served(t);
    // What a body cached before this change holds: the backend's group name.
    const patchCache = (edit: (e: { at: number; content: string }) => void) =>
      t.run(async (ctx) => {
        const sub = (await ctx.db.get(subId))!;
        const entries = JSON.parse(sub.subCache!) as Array<{ at: number; content: string }>;
        for (const e of entries) edit(e);
        await ctx.db.patch(subId, { subCache: JSON.stringify(entries) });
      });
    await patchCache((e) => {
      e.content = e.content.replaceAll('FreeSocks Select', '→ Remnawave');
    });
    const hit = await served(t);
    expect(fetchCalls).toBe(1); // a cache hit
    expect(hit.text).not.toMatch(/remnawave/i);
    expect(hit.doc.rules).toEqual(['MATCH,FreeSocks Select']);
    // The same body, aged past its TTL, served while the backend is down.
    await patchCache((e) => {
      e.at -= 24 * 3600_000;
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('backend down');
      }),
    );
    const stale = await served(t);
    expect(stale.text).not.toMatch(/remnawave/i);
    expect(stale.doc['proxy-groups'].map((g) => g.name)).toEqual(['FreeSocks Select']);
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

/**
 * Asking whether a configuration changed (docs/edges.md): every answer carries
 * a weak tag over what the app applies; `If-None-Match` naming it gets a 304.
 * Here on a place no origin covers (the backend body passes through); the
 * edge-rendered cases live in edgeRender.test.ts.
 */
describe('GET /api/v1/sub/<token>: conditional requests', () => {
  const UA = { 'user-agent': 'Clash/1' };
  beforeEach(() => {
    vi.stubEnv('IP_HASH_SALT', 'test-salt');
    mockBody = 'RAW-CONFIG-1';
    mockStatus = 200;
    mockHeaders = {
      'content-type': 'text/yaml',
      'subscription-userinfo': 'upload=0; download=10; total=100; expire=0',
      'profile-update-interval': '12',
    };
    stubFrontFetch();
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });
  const get = (t: ReturnType<typeof convexTest>, extra: Record<string, string> = {}) =>
    t.fetch('/api/v1/sub/tok_abc', { headers: { ...UA, ...extra } });
  const ageCache = (t: ReturnType<typeof convexTest>, subId: Id<'subscriptions'>, ms: number) =>
    t.run(async (ctx) => {
      const sub = (await ctx.db.get(subId))!;
      const entries = JSON.parse(sub.subCache!) as Array<Record<string, unknown> & { at: number }>;
      for (const e of entries) e.at -= ms;
      await ctx.db.patch(subId, { subCache: JSON.stringify(entries) });
    });

  test('a weak tag on the miss, the same on a hit; a matching If-None-Match is a 304', async () => {
    const t = convexTest(schema, modules);
    await seedSub(t);
    const first = await get(t);
    const tag = first.headers.get('etag')!;
    expect(tag).toMatch(/^W\/"fs1-[A-Za-z0-9_-]{22}"$/);
    // An unbound place keeps the backend's own refresh interval.
    expect(first.headers.get('profile-update-interval')).toBe('12');
    expect((await get(t)).headers.get('etag')).toBe(tag); // cache hit, same bytes
    const again = await get(t, { 'if-none-match': tag });
    expect(again.status).toBe(304);
    expect(await again.text()).toBe('');
    expect(again.headers.get('etag')).toBe(tag);
    expect(again.headers.get('cache-control')).toBe('public, max-age=30');
    expect(again.headers.get('vary')).toBe('User-Agent');
    expect(again.headers.get('subscription-userinfo')).toBe(
      'upload=0; download=10; total=100; expire=0',
    );
    expect(again.headers.get('profile-title')).toBeTruthy();
    expect(again.headers.get('profile-update-interval')).toBe('12');
    expect(again.headers.get('content-type')).toBeNull();
    // The strong spelling, a list and the wildcard match too (weak comparison).
    expect((await get(t, { 'if-none-match': tag.slice(2) })).status).toBe(304);
    expect((await get(t, { 'if-none-match': `"x", ${tag}` })).status).toBe(304);
    expect((await get(t, { 'if-none-match': '*' })).status).toBe(304);
    expect(fetchCalls).toBe(1);
  });

  test('a different, suffixed or malformed validator gets the full body', async () => {
    const t = convexTest(schema, modules);
    await seedSub(t);
    const tag = (await get(t)).headers.get('etag')!;
    for (const header of [
      'W/"fs1-BBBBBBBBBBBBBBBBBBBBBB"',
      `${tag}-gzip`,
      tag.replace(/"$/, '-zstd"'),
      tag.replace(/"/g, ''),
      `${tag}, garbage`,
    ]) {
      const res = await get(t, { 'if-none-match': header });
      expect(res.status, header).toBe(200);
      expect(await res.text()).toBe('RAW-CONFIG-1');
    }
  });

  test('the tag follows what the app applies: a new body or a new service name changes it', async () => {
    const t = convexTest(schema, modules);
    const { subId } = await seedSub(t);
    const tag = (await get(t)).headers.get('etag')!;
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'subscription.siteName',
        value: JSON.stringify('Ours'),
        updatedAt: Date.now(),
      }),
    );
    const renamed = await get(t, { 'if-none-match': tag });
    expect(renamed.status).toBe(200); // a cache hit, but the title moved
    const tag2 = renamed.headers.get('etag')!;
    expect(tag2).not.toBe(tag);
    // The backend body changes once the cache ages out.
    await ageCache(t, subId, 120_000 + 11 * 60_000);
    mockBody = 'RAW-CONFIG-2';
    const changed = await get(t, { 'if-none-match': tag2 });
    expect(changed.status).toBe(200);
    expect(await changed.text()).toBe('RAW-CONFIG-2');
    expect(changed.headers.get('etag')).not.toBe(tag2);
  });

  test('revalidation: past the 30 s cache a matching validator is answered from the entry, unconditional polls refetch', async () => {
    const t = convexTest(schema, modules);
    const { subId } = await seedSub(t);
    const tag = (await get(t)).headers.get('etag')!;
    await ageCache(t, subId, 5 * 60_000);
    mockBody = 'RAW-CONFIG-2'; // would surface if the conditional request refetched
    const kept = await get(t, { 'if-none-match': tag });
    expect(kept.status).toBe(304);
    expect(fetchCalls).toBe(1);
    // Past the revalidation window the backend is asked again.
    await ageCache(t, subId, 6 * 60_000);
    const asked = await get(t, { 'if-none-match': tag });
    expect(asked.status).toBe(200);
    expect(await asked.text()).toBe('RAW-CONFIG-2');
    expect(fetchCalls).toBe(2);
    // An unconditional poll keeps the 30 s cache: aged 1 min, it refetches.
    await ageCache(t, subId, 60_000);
    await get(t);
    expect(fetchCalls).toBe(3);
  });

  test('a stale body served while the backend is down carries the tag and can be a 304', async () => {
    const t = convexTest(schema, modules);
    const { subId } = await seedSub(t);
    const tag = (await get(t)).headers.get('etag')!;
    await ageCache(t, subId, 24 * 3600_000);
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('backend down');
      }),
    );
    const stale = await get(t);
    expect(stale.status).toBe(200);
    expect(stale.headers.get('etag')).toBe(tag);
    expect((await get(t, { 'if-none-match': tag })).status).toBe(304);
  });

  test('a cache entry from before the format change is never served, fresh or stale', async () => {
    const t = convexTest(schema, modules);
    const { subId } = await seedSub(t);
    await get(t);
    const legacy = async () =>
      t.run(async (ctx) => {
        const sub = (await ctx.db.get(subId))!;
        const entries = JSON.parse(sub.subCache!) as Array<Record<string, unknown>>;
        for (const e of entries) {
          delete e.v;
          delete e.validUntil;
        }
        await ctx.db.patch(subId, { subCache: JSON.stringify(entries) });
      });
    await legacy();
    await get(t); // within the TTL, yet the backend is asked
    expect(fetchCalls).toBe(2);
    const fresh = (await t.run((ctx) => ctx.db.get(subId)))!;
    expect(JSON.parse(fresh.subCache!)[0]).toMatchObject({ v: 2, validUntil: null });
    await legacy();
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('backend down');
      }),
    );
    expect((await get(t)).status).toBe(502);
  });

  test('no tag and no 304 on a refusal: unknown token, throttled, backend down, device rejected', async () => {
    const t = convexTest(schema, modules);
    await seedSub(t);
    const tag = (await get(t)).headers.get('etag')!;
    const unknown = await t.fetch('/api/v1/sub/nope', { headers: { 'if-none-match': '*' } });
    expect(unknown.status).toBe(404);
    expect(unknown.headers.get('etag')).toBeNull();
    // Backend down with nothing cached for this UA.
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('backend down');
      }),
    );
    const down = await t.fetch('/api/v1/sub/tok_abc', {
      headers: { 'user-agent': 'sing-box/1', 'if-none-match': '*' },
    });
    expect(down.status).toBe(502);
    expect(down.headers.get('etag')).toBeNull();
    // A device rejection.
    stubFrontFetch();
    await enableDeviceEnforcement(t);
    mockStatus = 404;
    mockBody = 'not found';
    const rejected = await get(t, { 'x-hwid': 'unregistered', 'if-none-match': tag });
    expect(rejected.status).toBe(404);
    expect(rejected.headers.get('etag')).toBeNull();
    // Throttled (the per-token cap, UA-rotating so every request is live).
    mockStatus = 200;
    let last: Response | null = null;
    for (let i = 0; i < 61; i++)
      last = await t.fetch('/api/v1/sub/tok_abc', {
        headers: { 'user-agent': `Rot/${i}`, 'if-none-match': '*' },
      });
    expect(last!.status).toBe(429);
    expect(last!.headers.get('etag')).toBeNull();
  });

  test('a device-specific request still reaches the backend every time, and may be a 304', async () => {
    const t = convexTest(schema, modules);
    await seedSub(t);
    await enableDeviceEnforcement(t);
    const first = await get(t, { 'x-hwid': 'device-a' });
    const tag = first.headers.get('etag')!;
    expect(first.headers.get('cache-control')).toBe('private, no-store');
    const second = await get(t, { 'x-hwid': 'device-a', 'if-none-match': tag });
    expect(second.status).toBe(304);
    expect(second.headers.get('vary')).toBeNull();
    expect(second.headers.get('cache-control')).toBe('private, no-store');
    expect(fetchCalls).toBe(2); // the device registered with the backend both times
    expect(lastReqHeaders['x-hwid']).toBe('device-a');
  });
});

/** A place no origin covers: the raw-config view hands out the backend body as `/sub` does. */
describe('GET /api/v1/subscription/content on an unbound place', () => {
  beforeEach(() => {
    vi.stubEnv('IP_HASH_SALT', 'test-salt');
    vi.stubEnv('SESSION_SIGNING_KEY', 'raw-sign');
    mockBody = 'vless://u@192.0.2.40:443?security=reality#direct';
    mockStatus = 200;
    mockHeaders = { 'content-type': 'text/plain' };
    stubFrontFetch();
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  test('the panel body passes through (relabelled), fetched with no client User-Agent', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedSub(t);
    const sid = `sid-raw-${Math.random().toString(36).slice(2)}`;
    await t.mutation(internal.sessions.create, { sid, kind: 'member', userId, ttlMs: 3_600_000 });
    const res = await t.fetch('/api/v1/subscription/content', {
      headers: {
        cookie: `fs_session=${await signValue(sid, 'raw-sign')}`,
        'user-agent': 'Mozilla/5',
      },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { content: string; contentType: string };
    expect(body.content).toContain('192.0.2.40:443');
    expect(body.contentType).toBe('text/plain');
    // The browser's User-Agent never reaches the panel (it could fetch the HTML page).
    expect(lastReqHeaders['user-agent']).not.toBe('Mozilla/5');
  });
});
