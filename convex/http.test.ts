/// <reference types="vite/client" />
/**
 * Route-layer tests (pass 2): the first coverage of convex/http.ts itself —
 * scope enforcement as wired into routes, the webhook config-vs-HMAC split,
 * the request-body caps, the login throttle ordering (429 BEFORE the captcha
 * verify), cookie auth resolution, and the cache-control defaults. Everything
 * below goes through `t.fetch`, i.e. the real httpRouter.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { signValue } from './lib/cookies';
import { hmacSha256Hex, hmacSha512Hex, sha256Hex } from './lib/crypto';
import { resolveCountry } from './lib/http';
import { bytesToB64Url } from '../src/shared/crypto/envelope';

const modules = import.meta.glob('./**/*.*s');

const SIGN_KEY = 'test-sign';
const ADMIN_SIGN_KEY = 'test-admin-sign';

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', SIGN_KEY);
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', ADMIN_SIGN_KEY);
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
  vi.stubEnv('TRUSTED_PROXY', 'true');
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

async function seedTierAndUser(
  t: ReturnType<typeof convexTest>,
): Promise<{ tierId: Id<'tiers'>; userId: Id<'users'> }> {
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
    return { tierId, userId };
  });
}

/** Mint a member session row + the signed fs_session cookie header value. */
async function memberCookie(t: ReturnType<typeof convexTest>, userId: Id<'users'>) {
  const sid = `sid-${Math.random().toString(36).slice(2)}`;
  await t.mutation(internal.sessions.create, { sid, kind: 'member', userId, ttlMs: 3_600_000 });
  return `fs_session=${await signValue(sid, SIGN_KEY)}`;
}

/** Mint an admin session row + the signed fs_admin_session cookie header value. */
async function adminCookie(t: ReturnType<typeof convexTest>) {
  const adminUserId = await t.run((ctx) =>
    ctx.db.insert('adminUsers', {
      username: 'op',
      displayName: 'Op',
      isActive: true,
      updatedAt: Date.now(),
    }),
  );
  const sid = `asid-${Math.random().toString(36).slice(2)}`;
  await t.mutation(internal.sessions.create, { sid, kind: 'admin', adminUserId, ttlMs: 3_600_000 });
  return `fs_admin_session=${await signValue(sid, ADMIN_SIGN_KEY)}`;
}

/** Insert an fsv1_ token row directly (same approach as scopes.test.ts). */
async function insertToken(
  t: ReturnType<typeof convexTest>,
  opts: { scopes: string[]; subjectType: 'service' | 'user'; subjectUserId?: Id<'users'> },
): Promise<string> {
  const plaintext = `fsv1_${opts.scopes.join('.')}-${opts.subjectType}-${Math.random().toString(36).slice(2)}`;
  const tokenHash = await sha256Hex(plaintext);
  await t.run(async (ctx) => {
    const admin = await ctx.db.insert('adminUsers', {
      username: `tok-${plaintext.slice(-8)}`,
      displayName: 'T',
      isActive: true,
      updatedAt: Date.now(),
    });
    await ctx.db.insert('apiTokens', {
      name: 'test',
      tokenHash,
      tokenPrefix: plaintext.slice(0, 12),
      createdByAdminId: admin,
      scopes: opts.scopes,
      subjectType: opts.subjectType,
      subjectUserId: opts.subjectUserId,
      updatedAt: Date.now(),
    });
  });
  return plaintext;
}

describe('billing webhook config vs HMAC', () => {
  const body = JSON.stringify({
    eventId: 'evt-1',
    accountId: '1'.repeat(32),
    tierSlug: 'member',
  });

  test('unset secret answers a distinct 503 webhook.not_configured', async () => {
    vi.stubEnv('WEBHOOK_SIGNING_SECRET', '');
    const t = convexTest(schema, modules);
    const res = await t.fetch('/api/webhooks/billing', { method: 'POST', body });
    expect(res.status).toBe(503);
    const json = (await res.json()) as { error: { code: string } };
    expect(json.error.code).toBe('webhook.not_configured');
  });

  test('bad HMAC is the generic 400 rejection', async () => {
    vi.stubEnv('WEBHOOK_SIGNING_SECRET', 'whsec');
    const t = convexTest(schema, modules);
    const res = await t.fetch('/api/webhooks/billing', {
      method: 'POST',
      body,
      headers: { 'x-signature': 'deadbeef' },
    });
    expect(res.status).toBe(400);
    const json = (await res.json()) as { error: { code: string } };
    expect(json.error.code).toBe('webhook.rejected');
  });

  test('good HMAC is accepted (unknown user ACKed, not retried)', async () => {
    vi.stubEnv('WEBHOOK_SIGNING_SECRET', 'whsec');
    const t = convexTest(schema, modules);
    const sig = await hmacSha256Hex('whsec', body);
    const res = await t.fetch('/api/webhooks/billing', {
      method: 'POST',
      body,
      headers: { 'x-signature': sig },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ ok: true, applied: false });
  });
});

describe('request-body caps (413)', () => {
  test('sealed route: oversized wire body is rejected before any work', async () => {
    const t = convexTest(schema, modules);
    // '/api/v1/account' has a reveal policy, so sealed() reads (and caps) the
    // wire body before the handler — no auth needed to observe the cap.
    const res = await t.fetch('/api/v1/account', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ pad: 'x'.repeat(70 * 1024) }),
    });
    expect(res.status).toBe(413);
    const json = (await res.json()) as { error: { code: string } };
    expect(json.error.code).toBe('request.too_large');
  });

  test('guarded admin route: a spoofed oversized content-length is rejected', async () => {
    const t = convexTest(schema, modules);
    const token = await insertToken(t, { scopes: ['admin:tiers:write'], subjectType: 'service' });
    const res = await t.fetch('/api/v1/admin/tiers', {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
        'content-length': String(10 * 1024 * 1024),
      },
      body: '{}',
    });
    expect(res.status).toBe(413);
  });
});

describe('account-login throttle runs BEFORE the captcha verify', () => {
  test('11th attempt from one IP is a 429 even while captcha always fails', async () => {
    // Captcha CONFIGURED but always failing (siteverify → {success:false}) → the
    // action answers 403 captcha. The per-IP gate (default 10/h) must trip FIRST on
    // attempt 11 — proving login floods can't drive Cap siteverify QPS. (An
    // UNconfigured Cap would answer 503 config instead — see Review #12.)
    vi.stubEnv('CAP_API_ENDPOINT', 'http://cap:3000');
    vi.stubEnv('CAP_SITE_KEY', 'sk');
    vi.stubEnv('CAP_SECRET', 'secret');
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify({ success: false }), { status: 200 })),
    );
    const t = convexTest(schema, modules);
    const attempt = () =>
      t.fetch('/api/v1/auth/account-login', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-forwarded-for': '203.0.113.50',
        },
        body: JSON.stringify({ accountId: '1'.repeat(32), captchaToken: 'tok' }),
      });
    for (let i = 0; i < 10; i++) {
      const res = await attempt();
      expect(res.status).toBe(403);
      const json = (await res.json()) as { error: { code: string } };
      expect(json.error.code).toBe('auth.captcha_failed');
    }
    const blocked = await attempt();
    expect(blocked.status).toBe(429);
    const json = (await blocked.json()) as { error: { code: string } };
    expect(json.error.code).toBe('rate_limit.exceeded');
  });
});

describe('route-level scope enforcement', () => {
  test('admin GET /tiers: right scope 200, wrong scope 401, no auth 401', async () => {
    const t = convexTest(schema, modules);
    const right = await insertToken(t, { scopes: ['admin:tiers:read'], subjectType: 'service' });
    const wrong = await insertToken(t, { scopes: ['admin:users:read'], subjectType: 'service' });

    const ok = await t.fetch('/api/v1/admin/tiers', {
      headers: { authorization: `Bearer ${right}` },
    });
    expect(ok.status).toBe(200);

    const denied = await t.fetch('/api/v1/admin/tiers', {
      headers: { authorization: `Bearer ${wrong}` },
    });
    expect(denied.status).toBe(401);

    const anon = await t.fetch('/api/v1/admin/tiers');
    expect(anon.status).toBe(401);
  });

  test('admin cookie session is full-privilege (no scope gate)', async () => {
    const t = convexTest(schema, modules);
    const cookie = await adminCookie(t);
    const res = await t.fetch('/api/v1/admin/tiers', { headers: { cookie } });
    expect(res.status).toBe(200);
  });

  test('member GET /account: user token needs account:read', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedTierAndUser(t);
    const lacking = await insertToken(t, {
      scopes: ['subscription:write'],
      subjectType: 'user',
      subjectUserId: userId,
    });
    const carrying = await insertToken(t, {
      scopes: ['account:read'],
      subjectType: 'user',
      subjectUserId: userId,
    });

    const denied = await t.fetch('/api/v1/account', {
      headers: { authorization: `Bearer ${lacking}` },
    });
    expect(denied.status).toBe(401);

    const ok = await t.fetch('/api/v1/account', {
      headers: { authorization: `Bearer ${carrying}` },
    });
    expect(ok.status).toBe(200);
    const view = (await ok.json()) as { user: { status: string }; subscription: unknown };
    expect(view.user.status).toBe('active');
    expect(view.subscription).toBeNull();
  });

  test('remnawave placement routes enforce the servers scope (moved off settings:write)', async () => {
    const t = convexTest(schema, modules);
    // The pool bind moved from admin:settings:write (the old /connection-profiles
    // route) to admin:servers:write — the Ansible panel-bootstrap token that mints
    // per-node squads must now carry servers:write to bind them.
    const serversW = await insertToken(t, {
      scopes: ['admin:servers:write'],
      subjectType: 'service',
    });
    const settingsW = await insertToken(t, {
      scopes: ['admin:settings:write'],
      subjectType: 'service',
    });
    const serversR = await insertToken(t, {
      scopes: ['admin:servers:read'],
      subjectType: 'service',
    });
    const body = JSON.stringify({
      modes: { evade: { squadUuids: ['e5c4de00-1111-4111-8111-cccccccccccc'] } },
    });

    const bound = await t.fetch('/api/v1/admin/remnawave/mode-placements', {
      method: 'PATCH',
      headers: { authorization: `Bearer ${serversW}`, 'content-type': 'application/json' },
      body,
    });
    expect(bound.status).toBe(200);

    // The OLD scope (settings:write) is now rejected on the pool bind.
    const wrongScope = await t.fetch('/api/v1/admin/remnawave/mode-placements', {
      method: 'PATCH',
      headers: { authorization: `Bearer ${settingsW}`, 'content-type': 'application/json' },
      body,
    });
    expect(wrongScope.status).toBe(401);

    // node-stats is servers:read; settings:write cannot read it.
    const statsOk = await t.fetch('/api/v1/admin/remnawave/node-stats', {
      headers: { authorization: `Bearer ${serversR}` },
    });
    expect(statsOk.status).toBe(200);
    const statsDenied = await t.fetch('/api/v1/admin/remnawave/node-stats', {
      headers: { authorization: `Bearer ${settingsW}` },
    });
    expect(statsDenied.status).toBe(401);
  });

  test('PATCH /api/v1/admin/site: needs settings:write, sanitizes, round-trips via /config', async () => {
    const t = convexTest(schema, modules);
    const settingsW = await insertToken(t, {
      scopes: ['admin:settings:write'],
      subjectType: 'service',
    });
    const wrong = await insertToken(t, { scopes: ['admin:tiers:read'], subjectType: 'service' });
    const body = JSON.stringify({
      bannerEnabled: true,
      bannerText: '  Service maintenance 03:00 UTC  ',
      repoEnabled: true,
      repoUrl: 'http://insecure.example', // non-https → must sanitize to ''
      transparencyUrl: 'https://example.org/transparency',
      socialXUrl: 'https://x.com/freesocks',
      socialMastodonUrl: 'javascript:alert(1)', // unsafe scheme → must sanitize to ''
      socialBlueskyUrl: 'https://bsky.app/profile/freesocks.example',
    });

    const wrongScope = await t.fetch('/api/v1/admin/site', {
      method: 'PATCH',
      headers: { authorization: `Bearer ${wrong}`, 'content-type': 'application/json' },
      body,
    });
    expect(wrongScope.status).toBe(401);

    const ok = await t.fetch('/api/v1/admin/site', {
      method: 'PATCH',
      headers: { authorization: `Bearer ${settingsW}`, 'content-type': 'application/json' },
      body,
    });
    expect(ok.status).toBe(200);
    const clean = (await ok.json()) as {
      bannerText: string;
      repoUrl: string;
      bannerEnabled: boolean;
      transparencyUrl: string;
      socialXUrl: string;
      socialMastodonUrl: string;
      socialBlueskyUrl: string;
    };
    expect(clean.bannerText).toBe('Service maintenance 03:00 UTC'); // trimmed
    expect(clean.repoUrl).toBe(''); // unsafe scheme dropped
    expect(clean.bannerEnabled).toBe(true);
    expect(clean.transparencyUrl).toBe('https://example.org/transparency');
    expect(clean.socialXUrl).toBe('https://x.com/freesocks');
    expect(clean.socialMastodonUrl).toBe(''); // unsafe scheme dropped
    expect(clean.socialBlueskyUrl).toBe('https://bsky.app/profile/freesocks.example');

    // The saved config is surfaced (non-secret) through the one public route.
    const cfg = await t.fetch('/api/v1/config');
    expect(cfg.status).toBe(200);
    const pub = (await cfg.json()) as {
      site?: {
        bannerEnabled: boolean;
        bannerText: string;
        repoUrl: string;
        transparencyUrl: string;
        socialXUrl: string;
        socialMastodonUrl: string;
        socialBlueskyUrl: string;
      };
    };
    expect(pub.site?.bannerEnabled).toBe(true);
    expect(pub.site?.bannerText).toBe('Service maintenance 03:00 UTC');
    expect(pub.site?.repoUrl).toBe('');
    expect(pub.site?.transparencyUrl).toBe('https://example.org/transparency');
    expect(pub.site?.socialXUrl).toBe('https://x.com/freesocks');
    expect(pub.site?.socialMastodonUrl).toBe('');
    expect(pub.site?.socialBlueskyUrl).toBe('https://bsky.app/profile/freesocks.example');
  });
});

describe('account-id rotate throttle (policy account.rotate, max 5)', () => {
  test('the 6th rotate in the window is a 429 rate_limit.exceeded', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedTierAndUser(t);
    const cookie = await memberCookie(t, userId);
    const rotate = () =>
      t.fetch('/api/v1/account/account-id/rotate', {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/json' },
        body: '{}',
      });
    // The first 5 pass the gate (they may 200 or surface a downstream error, but
    // must NOT be a 429); the 6th trips the per-user policy.
    for (let i = 0; i < 5; i++) {
      const r = await rotate();
      expect(r.status).not.toBe(429);
    }
    const blocked = await rotate();
    expect(blocked.status).toBe(429);
    const json = (await blocked.json()) as { error: { code: string } };
    expect(json.error.code).toBe('rate_limit.exceeded');
  });
});

describe('public GET throttles (WS5)', () => {
  test('/api/v1/config is per-IP rate limited past its policy', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.rateLimits.setPolicy, {
      policyKey: 'config.fetch',
      max: 1,
      windowMs: 60_000,
      enabled: true,
    });
    const headers = { 'x-forwarded-for': '203.0.113.77' };
    expect((await t.fetch('/api/v1/config', { headers })).status).toBe(200);
    const blocked = await t.fetch('/api/v1/config', { headers });
    expect(blocked.status).toBe(429);
    expect(((await blocked.json()) as { error: { code: string } }).error.code).toBe(
      'rate_limit.exceeded',
    );
  });

  test('/api/v1/e2ee/keys is per-IP rate limited past its policy', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.rateLimits.setPolicy, {
      policyKey: 'e2ee.keys.fetch',
      max: 1,
      windowMs: 60_000,
      enabled: true,
    });
    const headers = { 'x-forwarded-for': '203.0.113.78' };
    expect((await t.fetch('/api/v1/e2ee/keys', { headers })).status).toBe(200);
    expect((await t.fetch('/api/v1/e2ee/keys', { headers })).status).toBe(429);
  });
});

describe('/api/v1/me cookie resolution', () => {
  test('a valid member cookie authenticates; garbage does not', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedTierAndUser(t);
    const cookie = await memberCookie(t, userId);

    const ok = await t.fetch('/api/v1/me', { headers: { cookie } });
    expect(ok.status).toBe(200);
    expect(await ok.json()).toMatchObject({ authenticated: true });

    const anon = await t.fetch('/api/v1/me', {
      headers: { cookie: 'fs_session=not-a-real.signature' },
    });
    expect(await anon.json()).toMatchObject({ authenticated: false });
  });
});

describe('cache-control defaults', () => {
  test('json() responses default to no-store', async () => {
    const t = convexTest(schema, modules);
    const res = await t.fetch('/healthz');
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('no-store');
  });

  test('the e2ee keys route keeps its public, max-age=60 override', async () => {
    const t = convexTest(schema, modules);
    const res = await t.fetch('/api/v1/e2ee/keys');
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('public, max-age=60');
  });
});

// --- billing (self-service membership) --------------------------------------

async function seedMemberTierUser(
  t: ReturnType<typeof convexTest>,
): Promise<{ userId: Id<'users'>; memberTierId: Id<'tiers'> }> {
  return t.run(async (ctx) => {
    const freeTierId = await ctx.db.insert('tiers', {
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
    const memberTierId = await ctx.db.insert('tiers', {
      slug: 'member',
      name: 'FreeSocks Membership',
      backend: 'remnawave',
      monthlyTrafficGb: 0,
      deviceLimit: 0,
      hwidLimit: 0,
      hwidEnabled: false,
      trafficStrategy: 'NO_RESET',
      isDefaultFree: false,
      isActive: true,
      priority: 10,
      expirationDaysAfterMembershipLapse: 7,
      updatedAt: Date.now(),
    });
    const userId = await ctx.db.insert('users', {
      tierId: freeTierId,
      status: 'active',
      updatedAt: Date.now(),
    });
    return { userId, memberTierId };
  });
}

async function enableBillingSettings(t: ReturnType<typeof convexTest>) {
  await t.run(async (ctx) => {
    const put = (key: string, value: unknown) =>
      ctx.db.insert('appSettings', { key, value: JSON.stringify(value), updatedAt: Date.now() });
    await put('billing.enabled', true);
    await put('billing.nowpayments.enabled', true);
    await put('billing.membership.durations', [{ months: 3, amountCents: 1400 }]);
  });
}

function stubInvoiceFetch() {
  vi.stubGlobal(
    'fetch',
    vi.fn(
      async () =>
        new Response(JSON.stringify({ id: 'inv_x', invoice_url: 'https://pay.example/i/inv_x' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    ),
  );
}

describe('billing checkout route', () => {
  beforeEach(() => {
    vi.stubEnv('NOWPAYMENTS_API_KEY', 'np-key');
    vi.stubEnv('PUBLIC_BASE_URL', 'https://beta.example');
  });

  test('401 without authentication', async () => {
    const t = convexTest(schema, modules);
    const res = await t.fetch('/api/v1/billing/checkout', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ processor: 'nowpayments', months: 3 }),
    });
    expect(res.status).toBe(401);
  });

  test('200 returns a redirect URL for a signed-in member', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedMemberTierUser(t);
    await enableBillingSettings(t);
    stubInvoiceFetch();
    const cookie = await memberCookie(t, userId);
    const res = await t.fetch('/api/v1/billing/checkout', {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ processor: 'nowpayments', months: 3 }),
    });
    expect(res.status).toBe(200);
    const json = (await res.json()) as { redirectUrl: string; orderRef: string };
    expect(json.redirectUrl).toBe('https://pay.example/i/inv_x');
    expect(json.orderRef).toMatch(/^[0-9a-f]{32}$/);
  });

  test('the 11th checkout in the window is throttled (429)', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedMemberTierUser(t);
    await enableBillingSettings(t);
    stubInvoiceFetch();
    const cookie = await memberCookie(t, userId);
    const body = JSON.stringify({ processor: 'nowpayments', months: 3 });
    const headers = { cookie, 'content-type': 'application/json' };
    for (let i = 0; i < 10; i++) {
      const r = await t.fetch('/api/v1/billing/checkout', { method: 'POST', headers, body });
      expect(r.status).toBe(200);
    }
    const r11 = await t.fetch('/api/v1/billing/checkout', { method: 'POST', headers, body });
    expect(r11.status).toBe(429);
  });
});

describe('nowpayments webhook route', () => {
  // Signed the way nowpayments.verifyAndParse expects (flat sorted-key JSON, HMAC-SHA512).
  const signIpn = (payload: Record<string, unknown>, secret: string) =>
    hmacSha512Hex(secret, JSON.stringify(payload, Object.keys(payload).sort()));

  test('unset IPN secret answers a distinct 503', async () => {
    const t = convexTest(schema, modules); // global beforeEach leaves the secret unset
    const res = await t.fetch('/api/webhooks/nowpayments', { method: 'POST', body: '{}' });
    expect(res.status).toBe(503);
    const json = (await res.json()) as { error: { code: string } };
    expect(json.error.code).toBe('billing.not_configured');
  });

  test('bad signature is the generic 400 rejection', async () => {
    vi.stubEnv('NOWPAYMENTS_IPN_SECRET', 'ipn');
    const t = convexTest(schema, modules);
    const res = await t.fetch('/api/webhooks/nowpayments', {
      method: 'POST',
      headers: { 'x-nowpayments-sig': 'deadbeef' },
      body: JSON.stringify({ payment_status: 'finished', order_id: 'x' }),
    });
    expect(res.status).toBe(400);
    const json = (await res.json()) as { error: { code: string } };
    expect(json.error.code).toBe('webhook.rejected');
  });

  test('a valid finished IPN extends the bound member’s membership', async () => {
    vi.stubEnv('NOWPAYMENTS_IPN_SECRET', 'ipn');
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedMemberTierUser(t);
    await t.run((ctx) =>
      ctx.db.insert('billingOrders', {
        processor: 'nowpayments',
        opaqueRef: 'route-ref',
        userId,
        tierId: memberTierId,
        durationDays: 91,
        amountCents: 1400,
        currency: 'USD',
        status: 'pending',
        updatedAt: Date.now(),
      }),
    );
    const payload = { payment_status: 'finished', payment_id: 1, order_id: 'route-ref' };
    const res = await t.fetch('/api/webhooks/nowpayments', {
      method: 'POST',
      headers: { 'x-nowpayments-sig': await signIpn(payload, 'ipn') },
      body: JSON.stringify(payload),
    });
    expect(res.status).toBe(200);
    await t.run(async (ctx) => {
      const user = await ctx.db.get(userId);
      expect(user?.tierId).toBe(memberTierId);
      expect(user?.membershipExpiresAt).toBeGreaterThan(Date.now());
    });
  });

  test('an oversized body is rejected with 413', async () => {
    vi.stubEnv('NOWPAYMENTS_IPN_SECRET', 'ipn');
    const t = convexTest(schema, modules);
    const res = await t.fetch('/api/webhooks/nowpayments', {
      method: 'POST',
      headers: { 'x-nowpayments-sig': 'x' },
      body: JSON.stringify({ pad: 'x'.repeat(70 * 1024) }),
    });
    expect(res.status).toBe(413);
  });
});

describe('stripe webhook route', () => {
  const signStripe = async (rawBody: string, secret: string): Promise<string> => {
    const ts = Math.floor(Date.now() / 1000);
    return `t=${ts},v1=${await hmacSha256Hex(secret, `${ts}.${rawBody}`)}`;
  };

  test('unset webhook secret answers a distinct 503', async () => {
    const t = convexTest(schema, modules);
    const res = await t.fetch('/api/webhooks/stripe', { method: 'POST', body: '{}' });
    expect(res.status).toBe(503);
    const json = (await res.json()) as { error: { code: string } };
    expect(json.error.code).toBe('billing.not_configured');
  });

  test('a valid completed session extends the bound member’s membership', async () => {
    vi.stubEnv('STRIPE_WEBHOOK_SECRET', 'whsec');
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedMemberTierUser(t);
    await t.run((ctx) =>
      ctx.db.insert('billingOrders', {
        processor: 'stripe',
        opaqueRef: 'stripe-route-ref',
        userId,
        tierId: memberTierId,
        durationDays: 91,
        amountCents: 1400,
        currency: 'USD',
        status: 'pending',
        updatedAt: Date.now(),
      }),
    );
    const rawBody = JSON.stringify({
      id: 'evt_route',
      type: 'checkout.session.completed',
      data: {
        object: { id: 'cs_route', client_reference_id: 'stripe-route-ref', payment_status: 'paid' },
      },
    });
    const res = await t.fetch('/api/webhooks/stripe', {
      method: 'POST',
      headers: { 'stripe-signature': await signStripe(rawBody, 'whsec') },
      body: rawBody,
    });
    expect(res.status).toBe(200);
    await t.run(async (ctx) => {
      const user = await ctx.db.get(userId);
      expect(user?.tierId).toBe(memberTierId);
      expect(user?.membershipExpiresAt).toBeGreaterThan(Date.now());
    });
  });
});

describe('btcpay webhook route', () => {
  const signBtcpay = async (rawBody: string, secret: string): Promise<string> =>
    `sha256=${await hmacSha256Hex(secret, rawBody)}`;

  test('unset webhook secret answers a distinct 503', async () => {
    const t = convexTest(schema, modules);
    const res = await t.fetch('/api/webhooks/btcpay', { method: 'POST', body: '{}' });
    expect(res.status).toBe(503);
    const json = (await res.json()) as { error: { code: string } };
    expect(json.error.code).toBe('billing.not_configured');
  });

  test('bad signature is the generic 400 rejection', async () => {
    vi.stubEnv('BTCPAY_WEBHOOK_SECRET', 'whsec-bp');
    const t = convexTest(schema, modules);
    const res = await t.fetch('/api/webhooks/btcpay', {
      method: 'POST',
      headers: { 'btcpay-sig': 'sha256=deadbeef' },
      body: JSON.stringify({ type: 'InvoiceSettled', invoiceId: 'x' }),
    });
    expect(res.status).toBe(400);
    const json = (await res.json()) as { error: { code: string } };
    expect(json.error.code).toBe('webhook.rejected');
  });

  test('a valid settled invoice extends the bound member’s membership', async () => {
    vi.stubEnv('BTCPAY_WEBHOOK_SECRET', 'whsec-bp');
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedMemberTierUser(t);
    await t.run((ctx) =>
      ctx.db.insert('billingOrders', {
        processor: 'btcpay',
        opaqueRef: 'btcpay-route-ref',
        userId,
        tierId: memberTierId,
        durationDays: 91,
        amountCents: 1400,
        currency: 'USD',
        status: 'pending',
        updatedAt: Date.now(),
      }),
    );
    const rawBody = JSON.stringify({
      type: 'InvoiceSettled',
      invoiceId: 'inv_route',
      metadata: { orderId: 'btcpay-route-ref' },
    });
    const res = await t.fetch('/api/webhooks/btcpay', {
      method: 'POST',
      headers: { 'btcpay-sig': await signBtcpay(rawBody, 'whsec-bp') },
      body: rawBody,
    });
    expect(res.status).toBe(200);
    await t.run(async (ctx) => {
      const user = await ctx.db.get(userId);
      expect(user?.tierId).toBe(memberTierId);
      expect(user?.membershipExpiresAt).toBeGreaterThan(Date.now());
    });
  });

  test('an oversized body is rejected with 413', async () => {
    vi.stubEnv('BTCPAY_WEBHOOK_SECRET', 'whsec-bp');
    const t = convexTest(schema, modules);
    const res = await t.fetch('/api/webhooks/btcpay', {
      method: 'POST',
      headers: { 'btcpay-sig': 'sha256=x' },
      body: JSON.stringify({ pad: 'x'.repeat(70 * 1024) }),
    });
    expect(res.status).toBe(413);
  });
});

describe('billing order poll route', () => {
  test('404 for an unknown ref', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedMemberTierUser(t);
    const cookie = await memberCookie(t, userId);
    const res = await t.fetch('/api/v1/billing/order/no-such-ref', { headers: { cookie } });
    expect(res.status).toBe(404);
  });

  test('200 for the member’s own order', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedMemberTierUser(t);
    await t.run((ctx) =>
      ctx.db.insert('billingOrders', {
        processor: 'nowpayments',
        opaqueRef: 'poll-ref',
        userId,
        tierId: memberTierId,
        durationDays: 91,
        amountCents: 1400,
        currency: 'USD',
        status: 'confirming',
        updatedAt: Date.now(),
      }),
    );
    const cookie = await memberCookie(t, userId);
    const res = await t.fetch('/api/v1/billing/order/poll-ref', { headers: { cookie } });
    expect(res.status).toBe(200);
    const json = (await res.json()) as { status: string };
    expect(json.status).toBe('confirming');
  });
});

describe('GET /api/admin/auth/status — cookie-only signed-in detection', () => {
  test('a PoP-bound admin session reports signedIn WITHOUT a PoP signature', async () => {
    const t = convexTest(schema, modules);
    const adminUserId = await t.run((ctx) =>
      ctx.db.insert('adminUsers', {
        username: 'op',
        displayName: 'Op',
        isActive: true,
        updatedAt: Date.now(),
      }),
    );
    const sid = `asid-${Math.random().toString(36).slice(2)}`;
    // popPublicKey set => the session is PoP-bound. A bound session sending no
    // x-fs-pop-* signature fails resolveAdmin's sessionPopOk; the status probe
    // must succeed anyway (detection, not authorization) — this is the /admin
    // re-prompt regression. A real 65-byte P-256 point (sessions.create validates
    // the length against popAlg before binding).
    const kp = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;
    const popPublicKey = bytesToB64Url(
      new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey)),
    );
    await t.mutation(internal.sessions.create, {
      sid,
      kind: 'admin',
      adminUserId,
      ttlMs: 3_600_000,
      popPublicKey,
    });
    const cookie = `fs_admin_session=${await signValue(sid, ADMIN_SIGN_KEY)}`;
    const res = await t.fetch('/api/admin/auth/status', {
      method: 'GET',
      headers: { cookie }, // deliberately NO x-fs-pop-* headers
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { signedIn: boolean };
    expect(body.signedIn).toBe(true);
  });

  test('no cookie reports signedIn:false', async () => {
    const t = convexTest(schema, modules);
    const res = await t.fetch('/api/admin/auth/status', { method: 'GET' });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { signedIn: boolean };
    expect(body.signedIn).toBe(false);
  });
});

describe('resolveCountry (CF-IPCountry, CF_FRONTED-gated)', () => {
  const reqWith = (cc: string) => new Request('https://x/', { headers: { 'cf-ipcountry': cc } });

  test('null unless CF_FRONTED is set (header is spoofable otherwise)', () => {
    expect(resolveCountry(reqWith('IR'))).toBeNull();
    vi.stubEnv('CF_FRONTED', 'true');
    expect(resolveCountry(reqWith('IR'))).toBe('IR');
  });

  test('uppercases a code, rejects anonymizer/unknown/malformed values', () => {
    vi.stubEnv('CF_FRONTED', 'true');
    expect(resolveCountry(reqWith('ru'))).toBe('RU');
    for (const cc of ['XX', 'T1', 'T2', '', 'USA', '1']) {
      expect(resolveCountry(reqWith(cc))).toBeNull();
    }
  });
});

describe('opt-in mirror routes require a member session', () => {
  test('POST /api/v1/mirror/request → 401 without auth', async () => {
    const t = convexTest(schema, modules);
    const res = await t.fetch('/api/v1/mirror/request', {
      method: 'POST',
      body: JSON.stringify({ countryCode: 'IR' }),
    });
    expect(res.status).toBe(401);
  });

  test('DELETE /api/v1/mirror → 401 without auth', async () => {
    const t = convexTest(schema, modules);
    const res = await t.fetch('/api/v1/mirror', { method: 'DELETE' });
    expect(res.status).toBe(401);
  });

  test('GET /api/v1/subscription/content → 401 without auth', async () => {
    const t = convexTest(schema, modules);
    const res = await t.fetch('/api/v1/subscription/content', { method: 'GET' });
    expect(res.status).toBe(401);
  });
});

describe('test-connection tolerates an upsert-shaped body (strict-validator guard)', () => {
  test('backend-servers/test-connection with extra name/slug/… fields → 200, not 500', async () => {
    const t = convexTest(schema, modules);
    const token = await insertToken(t, { scopes: ['admin:servers:read'], subjectType: 'service' });
    // The full upsert body carries name/slug/isActive/priority — none declared by
    // testBackendConnection. The route must forward ONLY the connection fields;
    // otherwise Convex's strict arg validator throws and this 500s (the exact
    // trap the Ansible role hit reusing its upsert body). apiUrl points at a
    // refused port so the provider returns a clean {ok:false}, never a throw.
    const res = await t.fetch('/api/v1/admin/backend-servers/test-connection', {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        backend: 'outline',
        name: 'srv',
        slug: 'srv',
        isActive: true,
        priority: 0,
        apiUrl: 'https://127.0.0.1:1/proxy/secret',
        websocketEnabled: false,
      }),
    });
    expect(res.status).toBe(200); // NOT 500 — the undeclared fields were filtered out
    const body = (await res.json()) as { ok: boolean };
    expect(body.ok).toBe(false); // unreachable origin → clean verdict, not a validation throw
  });
});

describe('/api/v1/status public route', () => {
  test('per-IP rate limited past its policy; serves a public-safe shape', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.rateLimits.setPolicy, {
      policyKey: 'status.fetch',
      max: 1,
      windowMs: 60_000,
      enabled: true,
    });
    const headers = { 'x-forwarded-for': '203.0.113.90' };
    const ok = await t.fetch('/api/v1/status', { headers });
    expect(ok.status).toBe(200);
    const body = (await ok.json()) as {
      generatedAt: string;
      locations: unknown[];
      censorship: { modes: unknown[]; rows: unknown[] };
      incidents: unknown[];
    };
    expect(body.generatedAt).toBeTruthy();
    expect(Array.isArray(body.locations)).toBe(true);
    expect(Array.isArray(body.incidents)).toBe(true);
    expect((await t.fetch('/api/v1/status', { headers })).status).toBe(429);
  });
});

describe('referral routes', () => {
  test('account creation binds a valid referral code and reports referralApplied', async () => {
    vi.stubEnv('CAP_API_ENDPOINT', 'http://cap:3000');
    vi.stubEnv('CAP_SITE_KEY', 'sk');
    vi.stubEnv('CAP_SECRET', 'secret');
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify({ success: true }), { status: 200 })),
    );
    const t = convexTest(schema, modules);
    const { tierId } = await seedTierAndUser(t);
    const referrerId = await t.run((ctx) =>
      ctx.db.insert('users', {
        tierId,
        status: 'active',
        referralCode: 'FSR-AAAA-BBBB',
        updatedAt: Date.now(),
      }),
    );
    const res = await t.fetch('/api/v1/account', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.91' },
      body: JSON.stringify({ captchaToken: 'tok', referralCode: 'fsr-aaaa-bbbb' }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { accountId: string; referralApplied?: boolean };
    expect(body.referralApplied).toBe(true);
    // The new account is bound to the referrer (pending until a paid conversion).
    const rows = await t.run((ctx) => ctx.db.query('referrals').collect());
    expect(rows).toHaveLength(1);
    expect(rows[0]!.referrerUserId).toBe(referrerId);
    expect(rows[0]!.status).toBe('pending');
    // And the referrer's own code + the referee's code were both minted.
    const referee = await t.run((ctx) => ctx.db.get(rows[0]!.refereeUserId));
    expect(referee?.referralCode).toMatch(/^FSR-/);
  });

  test('a bad referral code never blocks creation (referralApplied false)', async () => {
    vi.stubEnv('CAP_API_ENDPOINT', 'http://cap:3000');
    vi.stubEnv('CAP_SITE_KEY', 'sk');
    vi.stubEnv('CAP_SECRET', 'secret');
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify({ success: true }), { status: 200 })),
    );
    const t = convexTest(schema, modules);
    await seedTierAndUser(t);
    const res = await t.fetch('/api/v1/account', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.92' },
      body: JSON.stringify({ captchaToken: 'tok', referralCode: 'FSR-NOPE-0000' }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { referralApplied?: boolean };
    expect(body.referralApplied).toBe(false);
    expect(await t.run((ctx) => ctx.db.query('referrals').collect())).toHaveLength(0);
  });

  test('GET /api/v1/account/referrals: 401 anonymous; mints + stats for a member', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedTierAndUser(t);
    expect((await t.fetch('/api/v1/account/referrals')).status).toBe(401);
    const cookie = await memberCookie(t, userId);
    const res = await t.fetch('/api/v1/account/referrals', { headers: { cookie } });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      enabled: boolean;
      code: string | null;
      stats: { invited: number; converted: number; pending: number; bonusDaysEarned: number };
    };
    expect(body.enabled).toBe(true);
    expect(body.code).toMatch(/^FSR-/);
    expect(body.stats).toEqual({ invited: 0, converted: 0, pending: 0, bonusDaysEarned: 0 });
    // Disabled program hides the surface.
    await t.mutation(internal.referrals.setConfig, { enabled: false });
    const off = await t.fetch('/api/v1/account/referrals', { headers: { cookie } });
    expect(((await off.json()) as { enabled: boolean }).enabled).toBe(false);
  });
});
