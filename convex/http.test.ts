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

  test('login fails closed (503) when no trustworthy client IP exists', async () => {
    // No proxy trust configured → the per-IP throttle can't run and the
    // per-(prefix,IP) backstop would degrade to a deployment-wide bucket, so
    // the route answers 503 rather than weaken login throttling (mirrors
    // account-create's freetier.ip_unresolved).
    vi.stubEnv('TRUSTED_PROXY', '');
    const t = convexTest(schema, modules);
    const res = await t.fetch('/api/v1/auth/account-login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ accountId: '1'.repeat(32), captchaToken: 'tok' }),
    });
    expect(res.status).toBe(503);
    const json = (await res.json()) as { error: { code: string } };
    expect(json.error.code).toBe('auth.ip_unresolved');
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

  test('an admin-disabled member loses API access immediately (cookie AND token)', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedTierAndUser(t);
    const cookie = await memberCookie(t, userId);
    const token = await insertToken(t, {
      scopes: ['account:read'],
      subjectType: 'user',
      subjectUserId: userId,
    });

    // Sanity: both authenticate while the account is active.
    expect((await t.fetch('/api/v1/account', { headers: { cookie } })).status).toBe(200);
    expect(
      (await t.fetch('/api/v1/account', { headers: { authorization: `Bearer ${token}` } })).status,
    ).toBe(200);

    // The ban takes effect on the NEXT request — not after the 30-day TTL.
    await t.run((ctx) =>
      ctx.db.patch(userId, { status: 'disabled', disabledReason: 'admin_action' }),
    );
    expect((await t.fetch('/api/v1/account', { headers: { cookie } })).status).toBe(401);
    expect(
      (await t.fetch('/api/v1/account', { headers: { authorization: `Bearer ${token}` } })).status,
    ).toBe(401);
  });

  test('deleted loses access; lapsed + inactive members KEEP it (renewal/reactivation flows)', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedTierAndUser(t);
    const cookie = await memberCookie(t, userId);
    const get = () => t.fetch('/api/v1/account', { headers: { cookie } });

    await t.run((ctx) =>
      ctx.db.patch(userId, { status: 'disabled', disabledReason: 'membership_lapsed' }),
    );
    expect((await get()).status).toBe(200);

    await t.run((ctx) => ctx.db.patch(userId, { status: 'inactive', disabledReason: undefined }));
    expect((await get()).status).toBe(200);

    await t.run((ctx) => ctx.db.patch(userId, { status: 'deleted' }));
    expect((await get()).status).toBe(401);
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
      modes: { 'freedom-ws': { squadUuids: ['e5c4de00-1111-4111-8111-cccccccccccc'] } },
    });

    const bound = await t.fetch('/api/v1/admin/backends/remnawave/mode-placements', {
      method: 'PATCH',
      headers: { authorization: `Bearer ${serversW}`, 'content-type': 'application/json' },
      body,
    });
    expect(bound.status).toBe(200);

    // The OLD scope (settings:write) is rejected on the pool bind.
    const wrongScope = await t.fetch('/api/v1/admin/backends/remnawave/mode-placements', {
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
      bannerLinkUrl: 'https://example.org/blog/launch',
      bannerLinkLabel: '  Read the launch post  ',
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
      bannerLinkUrl: string;
      bannerLinkLabel: string;
      repoUrl: string;
      bannerEnabled: boolean;
      transparencyUrl: string;
      socialXUrl: string;
      socialMastodonUrl: string;
      socialBlueskyUrl: string;
    };
    expect(clean.bannerText).toBe('Service maintenance 03:00 UTC'); // trimmed
    expect(clean.bannerLinkUrl).toBe('https://example.org/blog/launch');
    expect(clean.bannerLinkLabel).toBe('Read the launch post'); // trimmed
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
        bannerLinkUrl: string;
        bannerLinkLabel: string;
        repoUrl: string;
        transparencyUrl: string;
        socialXUrl: string;
        socialMastodonUrl: string;
        socialBlueskyUrl: string;
      };
    };
    expect(pub.site?.bannerEnabled).toBe(true);
    expect(pub.site?.bannerText).toBe('Service maintenance 03:00 UTC');
    expect(pub.site?.bannerLinkUrl).toBe('https://example.org/blog/launch');
    expect(pub.site?.bannerLinkLabel).toBe('Read the launch post');
    expect(pub.site?.repoUrl).toBe('');

    // An unsafe banner-link scheme sanitizes to '' (no link rendered) while the
    // banner text itself is preserved.
    const unsafe = await t.fetch('/api/v1/admin/site', {
      method: 'PATCH',
      headers: { authorization: `Bearer ${settingsW}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        bannerEnabled: true,
        bannerText: 'Launch!',
        bannerLinkUrl: 'javascript:alert(1)',
        bannerLinkLabel: 'click',
      }),
    });
    expect(unsafe.status).toBe(200);
    const unsafeClean = (await unsafe.json()) as { bannerLinkUrl: string; bannerText: string };
    expect(unsafeClean.bannerLinkUrl).toBe('');
    expect(unsafeClean.bannerText).toBe('Launch!');
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

  // A cache that outlives the epoch it holds hands clients an EXPIRED key, which
  // the client cannot distinguish from a tampered one (it fired the loud
  // "couldn't verify the encryption key" banner), so max-age is clamped to the
  // remaining validity and a rotation gap is never cached.
  test('the e2ee keys route caps max-age at the epoch validity', async () => {
    const t = convexTest(schema, modules);
    const now = Date.now();
    await t.run(async (ctx) => {
      await ctx.db.insert('keyEpochs', {
        kid: 'kid-cache-cap',
        publicKey: 'pk',
        seed: 'seed',
        manifestSig: 'sig',
        notBefore: now - 1_000,
        notAfter: now + 20_000, // 20s left: shorter than the 60s ceiling
      });
    });
    const res = await t.fetch('/api/v1/e2ee/keys');
    expect(res.status).toBe(200);
    const maxAge = Number(/max-age=(\d+)/.exec(res.headers.get('cache-control') ?? '')?.[1]);
    expect(maxAge).toBeGreaterThan(0);
    expect(maxAge).toBeLessThanOrEqual(20);
  });

  test('the e2ee keys route keeps public, max-age=60 for a long-lived epoch', async () => {
    const t = convexTest(schema, modules);
    const now = Date.now();
    await t.run(async (ctx) => {
      await ctx.db.insert('keyEpochs', {
        kid: 'kid-cache-full',
        publicKey: 'pk',
        seed: 'seed',
        manifestSig: 'sig',
        notBefore: now - 1_000,
        notAfter: now + 30 * 60_000,
      });
    });
    const res = await t.fetch('/api/v1/e2ee/keys');
    expect(res.headers.get('cache-control')).toBe('public, max-age=60');
  });

  test('a rotation gap (no live epoch) is not cached at all', async () => {
    const t = convexTest(schema, modules);
    const res = await t.fetch('/api/v1/e2ee/keys');
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ epoch: null });
    expect(res.headers.get('cache-control')).toBe('no-store');
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
    const payload = {
      payment_status: 'finished',
      payment_id: 1,
      order_id: 'route-ref',
      // Real finished IPNs carry the amounts; the settle-tolerance guard
      // downgrades a finished that lacks them (fail-safe).
      actually_paid: 1,
      pay_amount: 1,
    };
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

describe('rate-limit coverage (pre-launch review)', () => {
  test('unauthenticated passkey options routes fail closed (503) when the client IP is unresolvable', async () => {
    // TRUSTED_PROXY is set but no x-forwarded-for arrives (proxy misconfig) →
    // resolveClientIp is null; the throttles must not fail OPEN.
    const t = convexTest(schema, modules);
    for (const path of [
      '/api/v1/auth/passkey/authenticate/options',
      '/api/admin/auth/authenticate/options',
      '/api/admin/auth/register/options',
      '/api/admin/auth/register-bootstrap/options',
    ]) {
      const res = await t.fetch(path, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ invite: 'x', username: 'x' }),
      });
      expect(res.status, path).toBe(503);
      expect(((await res.json()) as { error: { code: string } }).error.code, path).toBe(
        'auth.ip_unresolved',
      );
    }
  });

  test('the bootstrap options route is per-IP throttled (no unlimited secret-oracle guesses)', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.rateLimits.setPolicy, {
      policyKey: 'admin.register.ip',
      max: 2,
      windowMs: 60_000,
      enabled: true,
      actorAdminId: undefined,
    });
    const call = () =>
      t.fetch('/api/admin/auth/register-bootstrap/options', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.95' },
        body: JSON.stringify({ username: 'x' }),
      });
    await call();
    await call();
    const third = await call();
    expect(third.status).toBe(429);
  });

  test('/readyz is per-IP throttled', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.rateLimits.setPolicy, {
      policyKey: 'readyz.fetch',
      max: 1,
      windowMs: 60_000,
      enabled: true,
      actorAdminId: undefined,
    });
    const headers = { 'x-forwarded-for': '203.0.113.96' };
    expect((await t.fetch('/readyz', { headers })).status).toBe(200);
    expect((await t.fetch('/readyz', { headers })).status).toBe(429);
  });

  test('GET /account/usage is per-user throttled', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedTierAndUser(t);
    const cookie = await memberCookie(t, userId);
    await t.mutation(internal.rateLimits.setPolicy, {
      policyKey: 'account.usage',
      max: 1,
      windowMs: 60_000,
      enabled: true,
      actorAdminId: undefined,
    });
    // First call passes the throttle (usage itself degrades to null — no sub).
    expect((await t.fetch('/api/v1/account/usage', { headers: { cookie } })).status).toBe(200);
    expect((await t.fetch('/api/v1/account/usage', { headers: { cookie } })).status).toBe(429);
  });
});

/**
 * suggestedModeId respects the LIVE catalog (flipped characterization from the
 * mode overhaul): a censorship-recommended mode is suggested only when it is
 * enabled AND available on the member's backend; otherwise the resolved
 * default. The old compiled-array pick suggested the dark freedom-reality.
 */
describe('suggestedModeId respects enabled + availability', () => {
  test('privacy-country caller falls back to the default while freedom-reality is dark/unbound', async () => {
    vi.stubEnv('CF_FRONTED', 'true');
    const t = convexTest(schema, modules);
    const { userId } = await seedTierAndUser(t);
    const cookie = await memberCookie(t, userId);
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'delivery.privacyCountries',
        value: JSON.stringify(['IR']),
        updatedAt: Date.now(),
      }),
    );

    const res = await t.fetch('/api/v1/account', {
      headers: { cookie, 'cf-ipcountry': 'IR' },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { suggestedModeId: string; geoCountry: string | null };
    expect(body.geoCountry).toBe('IR');
    // freedom-reality ships dark (disabled) and unbound → never suggested.
    expect(body.suggestedModeId).toBe('freedom-ws');
  });

  test('privacy-country caller gets the censorship-recommended mode once enabled + bound', async () => {
    vi.stubEnv('CF_FRONTED', 'true');
    const t = convexTest(schema, modules);
    const { userId } = await seedTierAndUser(t);
    const cookie = await memberCookie(t, userId);
    await t.run(async (ctx) => {
      await ctx.db.insert('appSettings', {
        key: 'delivery.privacyCountries',
        value: JSON.stringify(['IR']),
        updatedAt: Date.now(),
      });
      // Materialize the catalog with freedom-reality enabled + bound.
      await ctx.db.insert('connectionModeFamilies', {
        slug: 'freedom',
        iconId: 'zap',
        enabled: true,
        order: 0,
        updatedAt: Date.now(),
      });
      await ctx.db.insert('connectionModes', {
        slug: 'freedom-ws',
        familySlug: 'freedom',
        deliveryStyle: 'url',
        enabled: true,
        isFamilyDefault: true,
        backends: ['remnawave'],
        order: 0,
        updatedAt: Date.now(),
      });
      await ctx.db.insert('connectionModes', {
        slug: 'freedom-reality',
        familySlug: 'freedom',
        deliveryStyle: 'rawConfig',
        enabled: true,
        isFamilyDefault: false,
        isCensorshipRecommended: true,
        backends: ['remnawave'],
        order: 1,
        updatedAt: Date.now(),
      });
      await ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-reality',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: ['11111111-2222-3333-4444-555555555555'] }),
        updatedAt: Date.now(),
      });
    });

    const res = await t.fetch('/api/v1/account', {
      headers: { cookie, 'cf-ipcountry': 'IR' },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { suggestedModeId: string };
    expect(body.suggestedModeId).toBe('freedom-reality');
  });

  test('a non-listed country gets the compiled default', async () => {
    vi.stubEnv('CF_FRONTED', 'true');
    const t = convexTest(schema, modules);
    const { userId } = await seedTierAndUser(t);
    const cookie = await memberCookie(t, userId);
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'delivery.privacyCountries',
        value: JSON.stringify(['IR']),
        updatedAt: Date.now(),
      }),
    );

    const res = await t.fetch('/api/v1/account', {
      headers: { cookie, 'cf-ipcountry': 'DE' },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { suggestedModeId: string };
    expect(body.suggestedModeId).toBe('freedom-ws');
  });
});

/**
 * The connection-mode admin surface: per-entity CRUD routes and the generic
 * per-backend placement route (the Ansible role's bind path; its legacy
 * /admin/remnawave/mode-placements alias was removed 2026-07-30 after the
 * role converged — pinned below as a 404).
 */
describe('connection-mode admin routes', () => {
  const SQUAD = '11111111-2222-3333-4444-555555555555';

  test('CRUD round-trip: create family + mode, patch, delete; scopes enforced', async () => {
    const t = convexTest(schema, modules);
    const write = await insertToken(t, {
      scopes: ['admin:settings:write'],
      subjectType: 'service',
    });
    const read = await insertToken(t, { scopes: ['admin:settings:read'], subjectType: 'service' });

    // Wrong scope refused.
    expect(
      (
        await t.fetch('/api/v1/admin/connection-modes', {
          method: 'POST',
          headers: { authorization: `Bearer ${read}`, 'content-type': 'application/json' },
          body: JSON.stringify({ slug: 'x', label: 'X', family: 'freedom' }),
        })
      ).status,
    ).toBe(401);

    const famRes = await t.fetch('/api/v1/admin/connection-mode-families', {
      method: 'POST',
      headers: { authorization: `Bearer ${write}`, 'content-type': 'application/json' },
      body: JSON.stringify({ slug: 'stealth', label: 'Stealth', iconId: 'eye-off' }),
    });
    expect(famRes.status).toBe(200);

    const modeRes = await t.fetch('/api/v1/admin/connection-modes', {
      method: 'POST',
      headers: { authorization: `Bearer ${write}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        slug: 'stealth-x',
        label: 'Stealth X',
        family: 'stealth',
        deliveryStyle: 'rawConfig',
        backends: ['remnawave'],
        // A stray field must be filtered, not 500 the strict validator.
        bogusField: true,
      }),
    });
    expect(modeRes.status).toBe(200);

    const patch = await t.fetch('/api/v1/admin/connection-modes/stealth-x', {
      method: 'PATCH',
      headers: { authorization: `Bearer ${write}`, 'content-type': 'application/json' },
      body: JSON.stringify({ description: 'For hostile networks', order: 3 }),
    });
    expect(patch.status).toBe(200);

    const view = await t.fetch('/api/v1/admin/connection-modes', {
      headers: { authorization: `Bearer ${read}` },
    });
    const body = (await view.json()) as {
      modes: Array<{ id: string; description: string | null; order: number }>;
      families: Array<{ id: string }>;
    };
    expect(body.families.map((f) => f.id)).toContain('stealth');
    const x = body.modes.find((m) => m.id === 'stealth-x')!;
    expect(x).toMatchObject({ description: 'For hostile networks', order: 3 });

    // Delete mode then family (order matters: family refuses while occupied).
    expect(
      (
        await t.fetch('/api/v1/admin/connection-mode-families/stealth', {
          method: 'DELETE',
          headers: { authorization: `Bearer ${write}` },
        })
      ).status,
    ).toBe(409);
    expect(
      (
        await t.fetch('/api/v1/admin/connection-modes/stealth-x', {
          method: 'DELETE',
          headers: { authorization: `Bearer ${write}` },
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await t.fetch('/api/v1/admin/connection-mode-families/stealth', {
          method: 'DELETE',
          headers: { authorization: `Bearer ${write}` },
        })
      ).status,
    ).toBe(200);
  });

  test('the legacy remnawave placement alias is GONE (removed 2026-07-30, role converged)', async () => {
    // The byte-compatible alias (with its evade/privacy id mapping) existed
    // for ansible-role-freesocks; both stacks now converge through the
    // generic route, so a request here must 404 — never silently rebind.
    const t = convexTest(schema, modules);
    const token = await insertToken(t, {
      scopes: ['admin:servers:write'],
      subjectType: 'service',
    });
    const res = await t.fetch('/api/v1/admin/remnawave/mode-placements', {
      method: 'PATCH',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ modes: { evade: { addSquadUuids: [SQUAD] } } }),
    });
    expect(res.status).toBe(404);
    expect(await t.run(async (ctx) => ctx.db.query('modePlacements').collect())).toHaveLength(0);
  });

  test('generic per-backend placement route: PATCH + GET summaries; placement-less backend 400s', async () => {
    const t = convexTest(schema, modules);
    const write = await insertToken(t, { scopes: ['admin:servers:write'], subjectType: 'service' });
    const read = await insertToken(t, { scopes: ['admin:servers:read'], subjectType: 'service' });

    const patch = await t.fetch('/api/v1/admin/backends/remnawave/mode-placements', {
      method: 'PATCH',
      headers: { authorization: `Bearer ${write}`, 'content-type': 'application/json' },
      body: JSON.stringify({ modes: { 'privacy-reality': { squadUuids: [SQUAD] } } }),
    });
    expect(patch.status).toBe(200);

    const get = await t.fetch('/api/v1/admin/backends/remnawave/mode-placements', {
      headers: { authorization: `Bearer ${read}` },
    });
    expect(get.status).toBe(200);
    const body = (await get.json()) as {
      backend: string;
      placements: Array<{ modeId: string; bound: boolean; boundCount: number }>;
    };
    expect(body.backend).toBe('remnawave');
    expect(body.placements.find((p) => p.modeId === 'privacy-reality')).toMatchObject({
      bound: true,
      boundCount: 1,
    });
    // No config contents anywhere in the response.
    expect(JSON.stringify(body)).not.toContain(SQUAD);

    const outline = await t.fetch('/api/v1/admin/backends/outline/mode-placements', {
      method: 'PATCH',
      headers: { authorization: `Bearer ${write}`, 'content-type': 'application/json' },
      body: JSON.stringify({ modes: { 'freedom-ws': { squadUuids: [SQUAD] } } }),
    });
    expect(outline.status).toBe(400);

    const bogus = await t.fetch('/api/v1/admin/backends/wireguard/mode-placements', {
      method: 'PATCH',
      headers: { authorization: `Bearer ${write}`, 'content-type': 'application/json' },
      body: JSON.stringify({ modes: {} }),
    });
    expect(bogus.status).toBe(404);
  });
});

describe('analytics relay (POST /api/v1/telemetry + admin config)', () => {
  const A_UUID = 'b1f0a2c4-1234-4abc-9def-0123456789ab';

  /** Store an analytics config directly (bypassing the admin PATCH). */
  async function seedAnalytics(
    t: ReturnType<typeof convexTest>,
    cfg: {
      enabled: boolean;
      umamiUrl: string;
      websiteId: string;
      forwardIp?: boolean;
      ipHeader?: string;
      geoMode?: string;
    },
  ) {
    await t.run(async (ctx) => {
      const rows: Array<[string, unknown]> = [
        ['analytics.enabled', cfg.enabled],
        ['analytics.umamiUrl', cfg.umamiUrl],
        ['analytics.websiteId', cfg.websiteId],
        ['analytics.forwardIp', cfg.forwardIp === true],
        ['analytics.ipHeader', cfg.ipHeader ?? ''],
        ['analytics.geoMode', cfg.geoMode ?? 'full'],
      ];
      for (const [key, value] of rows) {
        await ctx.db.insert('appSettings', {
          key,
          value: JSON.stringify(value),
          updatedAt: Date.now(),
        });
      }
    });
  }

  const beacon = (body: unknown, headers: Record<string, string> = {}) => ({
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });

  test('analytics off (default): 202 and NO outbound call', async () => {
    const t = convexTest(schema, modules);
    const spy = vi.fn();
    vi.stubGlobal('fetch', spy);
    const res = await t.fetch('/api/v1/telemetry', beacon({ route: '/' }));
    expect(res.status).toBe(202);
    expect(spy).not.toHaveBeenCalled();
  });

  test('enabled + configured: 202 and exactly one sanitized outbound call', async () => {
    const t = convexTest(schema, modules);
    await seedAnalytics(t, { enabled: true, umamiUrl: 'https://umami.example', websiteId: A_UUID });
    const spy = vi.fn().mockResolvedValue(new Response('ok'));
    vi.stubGlobal('fetch', spy);
    const res = await t.fetch(
      '/api/v1/telemetry',
      beacon(
        { route: '/account', referrer: 'https://ref.example/private?x=1', language: 'fa' },
        { 'user-agent': 'TestUA/1.0', host: 'freesocks.org' },
      ),
    );
    expect(res.status).toBe(202);
    expect(spy).toHaveBeenCalledTimes(1);
    const [url, init] = spy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://umami.example/api/send');
    expect(JSON.parse(init.body as string)).toMatchObject({
      type: 'event',
      payload: {
        website: A_UUID,
        url: '/account',
        title: 'Account',
        referrer: 'https://ref.example',
      },
    });
  });

  test('Umami failure (reject / 500): still 202', async () => {
    const t = convexTest(schema, modules);
    await seedAnalytics(t, { enabled: true, umamiUrl: 'https://umami.example', websiteId: A_UUID });
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('down')));
    expect((await t.fetch('/api/v1/telemetry', beacon({ route: '/' }))).status).toBe(202);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('err', { status: 500 })));
    expect((await t.fetch('/api/v1/telemetry', beacon({ route: '/' }))).status).toBe(202);
  });

  test('malformed body → 202 (bucketed to /other); oversized body → 413', async () => {
    const t = convexTest(schema, modules);
    await seedAnalytics(t, { enabled: true, umamiUrl: 'https://umami.example', websiteId: A_UUID });
    const spy = vi.fn().mockResolvedValue(new Response('ok'));
    vi.stubGlobal('fetch', spy);

    const garbage = await t.fetch('/api/v1/telemetry', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: 'not json at all',
    });
    expect(garbage.status).toBe(202);
    expect(
      (
        JSON.parse((spy.mock.calls[0] as [string, RequestInit])[1].body as string) as {
          payload: { url: string };
        }
      ).payload.url,
    ).toBe('/other');

    const oversized = await t.fetch(
      '/api/v1/telemetry',
      beacon({ route: '/', junk: 'x'.repeat(10_000) }),
    );
    expect(oversized.status).toBe(413);
  });

  test('a signed-in member beacon leaks nothing session-derived outbound', async () => {
    const t = convexTest(schema, modules);
    await seedAnalytics(t, { enabled: true, umamiUrl: 'https://umami.example', websiteId: A_UUID });
    const { userId } = await seedTierAndUser(t);
    const cookie = await memberCookie(t, userId);
    const spy = vi.fn().mockResolvedValue(new Response('ok'));
    vi.stubGlobal('fetch', spy);
    const res = await t.fetch(
      '/api/v1/telemetry',
      beacon({ route: '/account' }, { cookie, 'user-agent': 'UA' }),
    );
    expect(res.status).toBe(202);
    const [, init] = spy.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers['cookie']).toBeUndefined();
    expect(JSON.stringify(init.body)).not.toContain('fs_session');
    expect(JSON.stringify(init.body)).not.toContain(String(userId));
  });

  test('forwardIp OFF omits payload.ip; ON embeds it (v2.17+ per-request shape)', async () => {
    const t = convexTest(schema, modules);
    await seedAnalytics(t, { enabled: true, umamiUrl: 'https://umami.example', websiteId: A_UUID });
    const spy = vi.fn().mockResolvedValue(new Response('ok'));
    vi.stubGlobal('fetch', spy);
    await t.fetch(
      '/api/v1/telemetry',
      beacon({ route: '/' }, { 'x-forwarded-for': '203.0.113.9' }),
    );
    const offBody = JSON.parse((spy.mock.calls[0] as [string, RequestInit])[1].body as string) as {
      payload: Record<string, string>;
    };
    expect(offBody.payload).not.toHaveProperty('ip');

    await t.run(async (ctx) => {
      const row = await ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.eq('key', 'analytics.forwardIp'))
        .unique();
      if (row) await ctx.db.patch(row._id, { value: JSON.stringify(true) });
    });
    await t.fetch(
      '/api/v1/telemetry',
      beacon({ route: '/' }, { 'x-forwarded-for': '203.0.113.9' }),
    );
    const [, onInit] = spy.mock.calls[1] as [string, RequestInit];
    const onBody = JSON.parse(onInit.body as string) as { payload: Record<string, string> };
    expect(onBody.payload.ip).toBe('203.0.113.9');
    // Never via headers: CLIENT_IP_HEADER is instance-global on Umami and
    // unusable on a shared multi-site instance.
    const headers = onInit.headers as Record<string, string>;
    expect(Object.keys(headers).sort()).toEqual(['content-type', 'user-agent']);
  });

  test('ipHeader source: payload.ip comes from the chosen CDN header, not XFF', async () => {
    const t = convexTest(schema, modules);
    await seedAnalytics(t, {
      enabled: true,
      umamiUrl: 'https://umami.example',
      websiteId: A_UUID,
      forwardIp: true,
      ipHeader: 'cf-connecting-ip',
    });
    const spy = vi.fn().mockResolvedValue(new Response('ok'));
    vi.stubGlobal('fetch', spy);

    // The CDN header wins; the XFF chain (which resolveClientIp would read,
    // and which here carries the fronting tunnel's private hop) is ignored.
    await t.fetch(
      '/api/v1/telemetry',
      beacon(
        { route: '/' },
        { 'cf-connecting-ip': '203.0.113.50', 'x-forwarded-for': '172.16.0.9' },
      ),
    );
    const withHeader = JSON.parse(
      (spy.mock.calls[0] as [string, RequestInit])[1].body as string,
    ) as { payload: Record<string, string> };
    expect(withHeader.payload.ip).toBe('203.0.113.50');

    // Header absent → the field is simply omitted (no silent XFF fallback:
    // the operator chose header trust, so resolveClientIp is not consulted).
    await t.fetch(
      '/api/v1/telemetry',
      beacon({ route: '/' }, { 'x-forwarded-for': '203.0.113.51' }),
    );
    const withoutHeader = JSON.parse(
      (spy.mock.calls[1] as [string, RequestInit])[1].body as string,
    ) as { payload: Record<string, string> };
    expect(withoutHeader.payload).not.toHaveProperty('ip');
  });

  test('coarse geoMode: geo headers out, no payload.ip, city never sent', async () => {
    const t = convexTest(schema, modules);
    await seedAnalytics(t, {
      enabled: true,
      umamiUrl: 'https://umami.example',
      websiteId: A_UUID,
      forwardIp: true,
      geoMode: 'coarse',
    });
    const spy = vi.fn().mockResolvedValue(new Response('ok'));
    vi.stubGlobal('fetch', spy);
    await t.fetch(
      '/api/v1/telemetry',
      beacon(
        { route: '/status' },
        {
          'cf-ipcountry': 'IR',
          'cf-region-code': 'THR',
          'cf-ipcity': 'Tehran', // inbound city must NOT be forwarded
          'x-forwarded-for': '203.0.113.60',
        },
      ),
    );
    const [, init] = spy.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers['cf-ipcountry']).toBe('IR');
    expect(headers['cf-region-code']).toBe('THR');
    expect(headers['cf-ipcity']).toBeUndefined();
    const body = JSON.parse(init.body as string) as { payload: Record<string, string> };
    expect(body.payload).not.toHaveProperty('ip');
    expect(JSON.stringify(init.body)).not.toContain('203.0.113.60');
  });

  test('per-IP throttle: second POST past the policy is 429 with no outbound', async () => {
    const t = convexTest(schema, modules);
    await seedAnalytics(t, { enabled: true, umamiUrl: 'https://umami.example', websiteId: A_UUID });
    await t.mutation(internal.rateLimits.setPolicy, {
      policyKey: 'telemetry.send',
      max: 1,
      windowMs: 60_000,
      enabled: true,
    });
    const spy = vi.fn().mockResolvedValue(new Response('ok'));
    vi.stubGlobal('fetch', spy);
    const headers = { 'x-forwarded-for': '203.0.113.80' };
    expect((await t.fetch('/api/v1/telemetry', beacon({ route: '/' }, headers))).status).toBe(202);
    const blocked = await t.fetch('/api/v1/telemetry', beacon({ route: '/' }, headers));
    expect(blocked.status).toBe(429);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  test('admin GET requires admin:settings:read; PATCH requires write', async () => {
    const t = convexTest(schema, modules);
    const wrongScope = await insertToken(t, {
      scopes: ['admin:tiers:read'],
      subjectType: 'service',
    });
    const read = await insertToken(t, { scopes: ['admin:settings:read'], subjectType: 'service' });
    const write = await insertToken(t, {
      scopes: ['admin:settings:write'],
      subjectType: 'service',
    });

    expect(
      (
        await t.fetch('/api/v1/admin/analytics', {
          headers: { authorization: `Bearer ${wrongScope}` },
        })
      ).status,
    ).toBe(401);
    const ok = await t.fetch('/api/v1/admin/analytics', {
      headers: { authorization: `Bearer ${read}` },
    });
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({
      enabled: false,
      umamiUrl: '',
      websiteId: '',
      forwardIp: false,
      ipHeader: '',
      geoMode: 'full',
    });

    expect(
      (
        await t.fetch('/api/v1/admin/analytics', {
          method: 'PATCH',
          headers: { authorization: `Bearer ${read}`, 'content-type': 'application/json' },
          body: JSON.stringify({ enabled: true }),
        })
      ).status,
    ).toBe(401);
    expect(
      (
        await t.fetch('/api/v1/admin/analytics', {
          method: 'PATCH',
          headers: { authorization: `Bearer ${write}`, 'content-type': 'application/json' },
          body: JSON.stringify({
            enabled: true,
            umamiUrl: 'https://umami.example',
            websiteId: A_UUID,
          }),
        })
      ).status,
    ).toBe(200);
  });

  test('PATCH sanitizes: http url → "", junk id → "", missing booleans → off', async () => {
    const t = convexTest(schema, modules);
    const write = await insertToken(t, {
      scopes: ['admin:settings:write'],
      subjectType: 'service',
    });
    const res = await t.fetch('/api/v1/admin/analytics', {
      method: 'PATCH',
      headers: { authorization: `Bearer ${write}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        umamiUrl: 'http://insecure.example',
        websiteId: 'not-a-uuid',
        ipHeader: 'x-forwarded-for', // multi-hop list header → rejected to ''
      }),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      enabled: false,
      umamiUrl: '',
      websiteId: '',
      forwardIp: false,
      ipHeader: '',
      geoMode: 'full',
    });
  });

  test('LEAK GUARD: /api/v1/config carries only the enabled bit', async () => {
    const t = convexTest(schema, modules);
    await seedAnalytics(t, { enabled: true, umamiUrl: 'https://umami.example', websiteId: A_UUID });
    const res = await t.fetch('/api/v1/config');
    expect(res.status).toBe(200);
    const text = JSON.stringify(await res.json());
    expect(text).toContain('"analytics":{"enabled":true}');
    expect(text).not.toContain('umami.example');
    expect(text).not.toContain(A_UUID);
  });

  test('LEAK GUARD: the generic settings surface never sees analytics.*', async () => {
    const t = convexTest(schema, modules);
    await seedAnalytics(t, { enabled: true, umamiUrl: 'https://umami.example', websiteId: A_UUID });
    const cookie = await adminCookie(t);

    const settings = await t.fetch('/api/v1/admin/settings', { headers: { cookie } });
    expect(settings.status).toBe(200);
    const text = JSON.stringify(await settings.json());
    expect(text).not.toContain('umami.example');
    expect(text).not.toContain(A_UUID);

    const patch = await t.fetch('/api/v1/admin/settings', {
      method: 'PATCH',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ 'analytics.enabled': true }),
    });
    expect(patch.status).toBe(400);
  });
});
