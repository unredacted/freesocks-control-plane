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
import { hmacSha256Hex, sha256Hex } from './lib/crypto';

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
    // CAP_* unset → verifyCaptcha fails closed; the action would answer 403
    // captcha. The per-IP gate (default 10/h) must trip FIRST on attempt 11 —
    // proving login floods can't drive Cap siteverify QPS.
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
