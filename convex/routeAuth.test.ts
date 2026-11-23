// @vitest-environment node
/// <reference types="vite/client" />
/**
 * Every HTTP route authenticates, or says why it doesn't.
 *
 * Convex function visibility keeps the raw surface closed (publicSurface.test.ts),
 * so the HTTP router IS the perimeter: each route resolves its caller itself
 * through `resolveMember` / `resolveAdmin` (convex/lib/http.ts). A route that
 * forgets the resolver, or calls `resolveAdmin` without a scope (which then
 * accepts ANY admin token), would expose internal functions. This file makes
 * either a failing build:
 *
 *   1. every `http.route` in http.ts calls a resolver, or is in PUBLIC_ROUTES
 *      with the reason it needs none; the list is exact (no stale entries, no
 *      entry that does call a resolver);
 *   2. every `resolveAdmin` call passes a scope, and `resolveMember` without a
 *      scope (any member token passes) is limited to MEMBER_ANY_TOKEN;
 *   3. the edges and servers sections register only through their `wrap`,
 *      which resolves the admin with the per-verb scope;
 *   4. at runtime, an anonymous request to every non-public route is refused.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import http from './http';

const modules = import.meta.glob('./**/*.*s');
const read = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');

/**
 * Routes with no member/admin resolver call. Key `"METHOD /path"`, or
 * `"METHOD /prefix/*"` for a pathPrefix route. The value says what gates it.
 */
const PUBLIC_ROUTES: Record<string, string> = {
  'GET /healthz': 'liveness probe, no data',
  'GET /readyz': 'readiness probe, no data',
  'GET /api/v1/config': 'the public bootstrap (publicConfig.get), per-IP rate limited',
  'GET /api/v1/status': 'the public status page, per-IP rate limited',
  'GET /api/v1/site/home-image': 'the public home page image',
  'GET /api/v1/billing/coins': 'the public direct-checkout coin list (prices only, no user data)',
  'POST /api/v1/telemetry': 'anonymous pageview relay, allowlisted routes, per-IP rate limited',
  'GET /api/v1/hpke/keys': 'public HPKE keys',
  'GET /api/v1/e2ee/keys': 'public HPKE keys (alias)',
  'POST /api/v1/auth/account-login': 'the account number is the credential',
  'POST /api/v1/auth/logout': 'only deletes the session its own cookie names',
  'POST /api/v1/auth/passkey/authenticate/options':
    'member passkey ceremony (the passkey is the credential)',
  'POST /api/v1/auth/passkey/authenticate/verify':
    'member passkey ceremony (the passkey is the credential)',
  'GET /api/v1/sub/*': 'the subscription token in the path is the credential',
  'GET /api/admin/auth/status': 'booleans only (adminSessionProbe), no privileged action',
  'POST /api/admin/auth/register-bootstrap/options':
    'gated by ADMIN_BOOTSTRAP_SECRET, locks once an admin exists',
  'POST /api/admin/auth/register-bootstrap/verify':
    'gated by ADMIN_BOOTSTRAP_SECRET, locks once an admin exists',
  'POST /api/admin/auth/authenticate/options':
    'admin passkey ceremony (the passkey is the credential)',
  'POST /api/admin/auth/authenticate/verify':
    'admin passkey ceremony (the passkey is the credential)',
  'POST /api/admin/auth/logout': 'only deletes the session its own cookie names',
  'POST /api/admin/auth/register/options': 'gated by a single-use admin invite',
  'POST /api/admin/auth/register/verify': 'gated by a single-use admin invite',
  'POST /api/webhooks/billing': 'HMAC-signed processor webhook',
  'POST /api/webhooks/nowpayments': 'HMAC-signed processor webhook',
  'POST /api/webhooks/btcpay': 'HMAC-signed processor webhook',
  'POST /api/webhooks/stripe': 'signed processor webhook',
  'POST /api/webhooks/telegram': 'Telegram webhook, secret-token header',
  'POST /api/webhooks/paypal': 'signed processor webhook (verified with PayPal)',
};

/** Routes that call `resolveMember` with no scope: any user token passes. */
const MEMBER_ANY_TOKEN: Record<string, string> = {
  'POST /api/v1/account': 'account creation: only checks whether the caller is already signed in',
  'GET /api/v1/me': 'minimal identity read',
};

/** Non-public routes that answer an anonymous caller 200, with the body they must give. */
const ANONYMOUS_ANSWERS: Record<string, (body: unknown) => boolean> = {
  // The SPA's "who am I" probe: says signed out, carries nothing else.
  'GET /api/v1/me': (body) => JSON.stringify(body) === JSON.stringify({ authenticated: false }),
};

interface RouteBlock {
  key: string;
  src: string;
}

function routeBlocks(src: string): RouteBlock[] {
  return src
    .split(/\n(?=http\.route\(\{)/)
    .slice(1)
    .map((block) => {
      const m = /^http\.route\(\{\s*(path|pathPrefix):\s*'([^']+)',\s*method:\s*'(\w+)'/.exec(
        block,
      );
      if (!m) throw new Error(`unparsed route: ${block.slice(0, 80)}`);
      const prefix = m[1] === 'pathPrefix';
      return { key: `${m[3]} ${m[2]}${prefix ? '*' : ''}`, src: block };
    });
}

const RESOLVER = /\b(resolveMember|resolveAdmin|resolveAdminCookie)\(/;
const ADMIN_CALLS = /\bresolveAdmin\(\s*ctx\s*,\s*req\s*(?:,\s*([^)]*))?\)/g;
const MEMBER_CALLS = /\bresolveMember\(\s*ctx\s*,\s*req\s*(?:,\s*([^)]*))?\)/g;

describe('http.ts route auth', () => {
  const blocks = routeBlocks(read('./http.ts'));

  test('the route parser sees every route', () => {
    const count = (read('./http.ts').match(/^http\.route\(\{/gm) ?? []).length;
    expect(blocks.length).toBe(count);
    expect(blocks.length).toBeGreaterThan(100);
  });

  test('every route calls a resolver or is a listed public route', () => {
    const missing = blocks
      .filter((b) => !RESOLVER.test(b.src) && !(b.key in PUBLIC_ROUTES))
      .map((b) => b.key);
    expect(missing).toEqual([]);
  });

  test('the public list is exact', () => {
    const keys = new Set(blocks.map((b) => b.key));
    const stale = Object.keys(PUBLIC_ROUTES).filter((k) => !keys.has(k));
    expect(stale).toEqual([]);
    const resolving = blocks
      .filter((b) => b.key in PUBLIC_ROUTES && RESOLVER.test(b.src))
      .map((b) => b.key);
    expect(resolving).toEqual([]);
  });

  test('every resolveAdmin call passes a scope', () => {
    const unscoped: string[] = [];
    for (const b of blocks) {
      for (const m of b.src.matchAll(ADMIN_CALLS)) {
        if (!m[1]?.trim()) unscoped.push(b.key);
      }
    }
    expect(unscoped).toEqual([]);
  });

  test('resolveMember without a scope is limited to MEMBER_ANY_TOKEN', () => {
    const unscoped = new Set<string>();
    for (const b of blocks) {
      for (const m of b.src.matchAll(MEMBER_CALLS)) {
        if (!m[1]?.trim()) unscoped.add(b.key);
      }
    }
    expect([...unscoped].sort()).toEqual(Object.keys(MEMBER_ANY_TOKEN).sort());
  });
});

describe('edges and servers sections', () => {
  for (const file of ['./httpEdges.ts', './httpServers.ts']) {
    test(`${file} registers only through wrap, which resolves a per-verb scope`, () => {
      const src = read(file);
      const routes = src.match(/http\.route\(\{[^}]*\}\)/g) ?? [];
      expect(routes.length).toBeGreaterThan(0);
      for (const r of routes) expect(r).toMatch(/handler:\s*wrap\(/);
      expect(src).toMatch(/resolveAdmin\(ctx,\s*req,\s*scopeFor\(parts,\s*method\)\)/);
    });
  }
});

describe('anonymous requests', () => {
  afterEach(() => vi.unstubAllEnvs());

  test('every non-public route refuses a request with no credentials', async () => {
    // A resolvable client IP, so routes that fail closed on an unknown IP get
    // past that gate and reach their auth check.
    vi.stubEnv('TRUSTED_PROXY', 'true');
    vi.stubEnv('IP_HASH_SALT', 'route-auth-test-salt');
    const t = convexTest(schema, modules);
    const publicKeys = new Set(Object.keys(PUBLIC_ROUTES));
    const accepted: string[] = [];
    let checked = 0;
    for (const [path, method] of http.getRoutes()) {
      const isPrefix = path.endsWith('/');
      const key = `${method} ${path}${isPrefix ? '*' : ''}`;
      if (publicKeys.has(key)) continue;
      const url = isPrefix ? `${path}probe` : path;
      const hasBody = method !== 'GET';
      const res = await t.fetch(url, {
        method,
        headers: {
          'x-forwarded-for': '203.0.113.7',
          ...(hasBody ? { 'content-type': 'application/json' } : {}),
        },
        body: hasBody ? '{}' : undefined,
      });
      checked++;
      const expectAnswer = ANONYMOUS_ANSWERS[key];
      if (expectAnswer) {
        if (res.status !== 200 || !expectAnswer(await res.json()))
          accepted.push(`${key} -> ${res.status}`);
        continue;
      }
      // Refused = a 4xx. A 2xx (or 3xx) means the route served an anonymous caller.
      if (res.status < 400 || res.status >= 500) accepted.push(`${key} -> ${res.status}`);
    }
    expect(checked).toBeGreaterThan(100);
    expect(accepted).toEqual([]);
  }, 120_000);
});
