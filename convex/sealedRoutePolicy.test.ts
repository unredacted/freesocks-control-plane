// @vitest-environment node
/**
 * Keeps the `sealed()` wrappers in convex/http.ts (+ httpEdges.ts) and the
 * sealing policy table in src/shared/crypto/envelope.ts from drifting apart.
 *
 * The wrapper does nothing on its own: `sealedInner` looks the route up in
 * `routePolicy` and passes plaintext straight through when there is no entry,
 * and the SPA keys off the same table. So a route can be wrapped, commented as
 * "sealed", and still travel plaintext-over-TLS through the CDN — which is
 * exactly what happened to /subscription/content, /redeem-code and
 * /mirror/request (2026-09). This test makes that a failing build:
 *
 *   1. every `sealed()`-wrapped route has a policy entry, or is on the explicit
 *      INTENTIONALLY_UNSEALED list below with a reason;
 *   2. that list is exact: each entry is a real wrapped route and has NO policy
 *      (so the list never masks a live entry or keeps a stale name);
 *   3. the reverse: every policy entry maps to a wrapped route, otherwise the
 *      SPA would seal a request the server never opens.
 *
 * Sealing is passive-CDN confidentiality of crown-jewel secrets (account
 * numbers, proxy config / URLs, bearer codes, infra credentials). A route whose
 * bodies carry none of those may stay wrapped (uniform error handling, and a
 * later entry takes effect with no route change) but must say so here.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'vitest';
import { routePolicy, SEALED_PREFIXES, SEALED_ROUTES } from '../src/shared/crypto/envelope';

const read = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');

/**
 * `sealed()`-wrapped routes that deliberately have NO policy entry. Key is
 * `"METHOD /path"`, or `"METHOD /prefix/*"` for a `pathPrefix` route. The value
 * is the reason a passive CDN gains nothing from the plaintext.
 */
const INTENTIONALLY_UNSEALED: Record<string, string> = {
  // Member plane. Same class as the passkey LOGIN ceremony, which the threat
  // model leaves unsealed on purpose: single-use, origin-bound, non-replayable.
  'POST /api/v1/account/devices/revoke':
    'hwid only: a device identifier the proxy client already reports to the backend over its own TLS; not a credential, config or code',
  'POST /api/v1/account/passkey/register/options':
    'WebAuthn creation options: a single-use, origin-bound challenge',
  'POST /api/v1/account/passkey/register/verify': 'WebAuthn attestation: the credential PUBLIC key',
  'GET /api/v1/account/passkeys': 'credential ids + labels',
  'POST /api/v1/account/passkey/revoke': 'a credential id',
  // Admin plane. The credential-bearing admin bodies are all in the table; these
  // carry names and flags only.
  'POST /api/v1/admin/billing/test-connection':
    'processor NAME only; the processor keys are read server-side from stored config',
  'PATCH /api/v1/admin/backends/*':
    'mode-placement patch (mode ids -> bound flags), no credentials',
  'POST /api/v1/admin/remnawave/harden-logging':
    'empty body; the response is a per-profile changed/unchanged report, no config content',
};

interface RegisteredRoute {
  method: string;
  path: string;
  isPrefix: boolean;
  sealed: boolean;
  source: string;
}

const key = (r: RegisteredRoute) => `${r.method} ${r.path}${r.isPrefix ? '*' : ''}`;

/** Handler wrappers in http.ts that never seal (a new wrapper must be classified here). */
const PLAIN_WRAPPERS = new Set(['httpAction', 'guard', 'processorWebhook']);

/** Parse the literal `http.route({ path|pathPrefix, method, handler: X( })` blocks. */
function parseHttpRoutes(): RegisteredRoute[] {
  const src = read('./http.ts');
  const re =
    /http\.route\(\{\s*(path|pathPrefix):\s*'([^']+)',\s*method:\s*'([A-Z]+)',\s*handler:\s*([A-Za-z_$][\w$]*)\(/g;
  const out: RegisteredRoute[] = [];
  for (const m of src.matchAll(re)) {
    const [, kind, path, method, wrapper] = m;
    expect(
      wrapper === 'sealed' || PLAIN_WRAPPERS.has(wrapper),
      `unknown handler wrapper ${wrapper}( on ${method} ${path}: classify it as sealed or plain`,
    ).toBe(true);
    out.push({
      method,
      path,
      isPrefix: kind === 'pathPrefix',
      sealed: wrapper === 'sealed',
      source: 'http.ts',
    });
  }
  // Parser sanity: a formatting change must fail loudly, not silently skip routes.
  const declared = (src.match(/http\.route\(/g) ?? []).length;
  expect(out.length, 'every http.route({...}) in http.ts must be parsed').toBe(declared);
  return out;
}

/**
 * A prefix-dispatcher surface (edges, servers) registers one prefix route per
 * verb via `wrap(handler, sealed)`.
 */
function parsePrefixRoutes(file: string): RegisteredRoute[] {
  const src = read(`./${file}`);
  const prefix = /^const PREFIX = '([^']+)';/m.exec(src)?.[1];
  expect(prefix, `${file} PREFIX const`).toBeTruthy();
  const re =
    /http\.route\(\{\s*pathPrefix:\s*PREFIX,\s*method:\s*'([A-Z]+)',\s*handler:\s*wrap\(\w+,\s*(true|false)\)/g;
  const out: RegisteredRoute[] = [];
  for (const m of src.matchAll(re)) {
    out.push({
      method: m[1],
      path: prefix!,
      isPrefix: true,
      sealed: m[2] === 'true',
      source: file,
    });
  }
  const declared = (src.match(/http\.route\(/g) ?? []).length;
  expect(out.length, `every http.route({...}) in ${file} must be parsed`).toBe(declared);
  return out;
}

const routes = [
  ...parseHttpRoutes(),
  ...parsePrefixRoutes('httpEdges.ts'),
  ...parsePrefixRoutes('httpServers.ts'),
];
const sealedRoutes = routes.filter((r) => r.sealed);

/** The policy a registered route resolves to (a prefix route is probed with a dummy tail). */
const policyOf = (r: RegisteredRoute) =>
  routePolicy(r.isPrefix ? `${r.path}probe` : r.path, r.method);

describe('sealed() wrappers vs the envelope.ts policy table', () => {
  test('the parser saw the routes this repo is known to register', () => {
    expect(sealedRoutes.length).toBeGreaterThan(20);
    expect(routes.some((r) => key(r) === 'POST /api/v1/auth/account-login' && r.sealed)).toBe(true);
    expect(routes.some((r) => key(r) === 'GET /api/v1/admin/edges/*' && r.sealed)).toBe(true);
    expect(routes.some((r) => key(r) === 'GET /api/v1/admin/servers/*' && r.sealed)).toBe(true);
  });

  test('every sealed()-wrapped route has a policy entry or is explicitly listed as intentionally unsealed', () => {
    const drifted = sealedRoutes
      .filter((r) => !policyOf(r) && !(key(r) in INTENTIONALLY_UNSEALED))
      .map((r) => `${key(r)} (${r.source})`);
    expect(
      drifted,
      'wrapped in sealed() but plaintext on the wire: add a SEALED_ROUTES / SEALED_PREFIXES entry, or list it in INTENTIONALLY_UNSEALED with a reason',
    ).toEqual([]);
  });

  test('the intentionally-unsealed list is exact: real wrapped routes, none with a policy', () => {
    const wrapped = new Set(sealedRoutes.map(key));
    for (const [k, reason] of Object.entries(INTENTIONALLY_UNSEALED)) {
      expect(reason.length, `${k} needs a reason`).toBeGreaterThan(10);
      expect(
        wrapped.has(k),
        `${k} is listed but is not a sealed()-wrapped route (stale entry?)`,
      ).toBe(true);
      const [method, path] = k.split(' ');
      const probe = path.endsWith('*') ? `${path.slice(0, -1)}probe` : path;
      expect(
        routePolicy(probe, method),
        `${k} is listed as unsealed but HAS a policy entry`,
      ).toBeUndefined();
    }
  });

  test('every SEALED_ROUTES entry maps to a sealed()-wrapped exact route', () => {
    const wrapped = new Set(sealedRoutes.filter((r) => !r.isPrefix).map(key));
    const orphans = Object.keys(SEALED_ROUTES).filter((k) => !wrapped.has(k));
    expect(orphans, 'policy entries the SPA would seal but no sealed() handler opens').toEqual([]);
  });

  test('every SEALED_PREFIXES entry maps to a sealed()-wrapped pathPrefix route', () => {
    const prefixRoutes = sealedRoutes.filter((r) => r.isPrefix);
    const orphans = SEALED_PREFIXES.filter(
      (p) => !prefixRoutes.some((r) => r.method === p.method && p.prefix.startsWith(r.path)),
    ).map((p) => `${p.method} ${p.prefix}*`);
    expect(orphans, 'prefix policies with no sealed() prefix handler under them').toEqual([]);
  });

  test('the three routes that drifted in 2026-09 are sealed with the right leg', () => {
    expect(routePolicy('/api/v1/subscription/content', 'GET')).toEqual({
      request: 'plain',
      response: 'reveal',
    });
    expect(routePolicy('/api/v1/account/redeem-code', 'POST')).toEqual({
      request: 'seal',
      response: 'plain',
    });
    expect(routePolicy('/api/v1/mirror/request', 'POST')).toEqual({
      request: 'plain',
      response: 'reveal',
    });
  });
});
