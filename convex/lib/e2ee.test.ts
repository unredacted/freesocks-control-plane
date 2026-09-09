/// <reference types="vite/client" />
/**
 * The sealing wrapper's REQUIRED posture for admin routes: with
 * FS_E2EE_ADMIN_REQUIRED=true a cookie-session (passkey CMS) caller must seal,
 * while an `fsv1_` bearer caller (IaC, cannot seal) keeps plaintext. The member
 * knob (FS_E2EE_REQUIRED) never touches admin routes. Exercised through the
 * edges prefix (GET reveal / POST seal-both / PATCH seal-request).
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from '../schema';
import { internal } from '../_generated/api';
import { signValue } from './cookies';
import { sha256Hex } from './crypto';
import { bearerHeaderPresent } from './e2ee';
import {
  bytesToB64Url,
  isSealedWire,
  kidFromPublicKey,
  routePolicy,
} from '../../src/shared/crypto/envelope';
import { serializePublicKey, serverKeyPairFromSeed } from '../../src/shared/crypto/hpke';
import { clientOpenResponse, clientPrepareRequest } from '../../src/shared/crypto/channel';

// convex-test resolves `ctx.runAction(internal.lib.e2eeCrypto…)` as
// `<root>lib/e2eeCrypto` where <root> comes from the `_generated` key (`../`).
// Vite rewrites this directory's own matches to `./x.ts`, which that lookup
// never finds, so re-root them under `../lib/`.
const modules = Object.fromEntries(
  Object.entries(import.meta.glob('../**/*.*s')).map(([k, v]) => [
    k.startsWith('./') ? `../lib/${k.slice(2)}` : k,
    v,
  ]),
);
const ADMIN_SIGN_KEY = 'test-admin-sign';
const SERVER_SEED = new Uint8Array(32).fill(7);

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', ADMIN_SIGN_KEY);
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
  vi.stubEnv('FS_SERVER_HPKE_SK', bytesToB64Url(SERVER_SEED));
});
afterEach(() => {
  vi.unstubAllEnvs();
});

async function setup() {
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
  await t.mutation(internal.sessions.create, { sid, kind: 'admin', adminUserId, ttlMs: 3_600_000 });
  const cookie = `fs_admin_session=${await signValue(sid, ADMIN_SIGN_KEY)}`;
  const plaintext = `fsv1_${Math.random().toString(36).slice(2)}${Math.random().toString(36).slice(2)}`;
  await t.run(async (ctx) => {
    await ctx.db.insert('apiTokens', {
      name: 'iac',
      tokenHash: await sha256Hex(plaintext),
      tokenPrefix: plaintext.slice(0, 12),
      createdByAdminId: adminUserId,
      scopes: ['admin:servers:read', 'admin:servers:write', 'admin:settings:write'],
      subjectType: 'service',
      updatedAt: Date.now(),
    });
  });
  const kp = await serverKeyPairFromSeed(SERVER_SEED);
  const kid = await kidFromPublicKey(await serializePublicKey(kp.publicKey));
  return { t, cookie, bearer: `Bearer ${plaintext}`, kp, kid };
}

const SUMMARY = '/api/v1/admin/edges/summary';
const PREVIEW = '/api/v1/admin/edges/render/preview';
const CONFIG = '/api/v1/admin/edges/config';

describe('e2ee: FS_E2EE_ADMIN_REQUIRED', () => {
  test('bearerHeaderPresent: only a well-formed Authorization: Bearer header counts', () => {
    const mk = (h: Record<string, string>) => new Request('https://x/', { headers: h });
    expect(bearerHeaderPresent(mk({ authorization: 'Bearer fsv1_abc' }))).toBe(true);
    expect(bearerHeaderPresent(mk({ Authorization: 'bearer fsv1_abc' }))).toBe(true);
    expect(bearerHeaderPresent(mk({ authorization: 'Bearer' }))).toBe(false);
    expect(bearerHeaderPresent(mk({ authorization: 'Basic abc' }))).toBe(false);
    expect(bearerHeaderPresent(mk({ cookie: 'fs_admin_session=x' }))).toBe(false);
    expect(bearerHeaderPresent(mk({}))).toBe(false);
  });

  test('knob off (default): cookie plaintext passes through on every verb class', async () => {
    const { t, cookie } = await setup();
    expect((await t.fetch(SUMMARY, { headers: { cookie } })).status).toBe(200);
    const preview = await t.fetch(PREVIEW, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ relayId: 'nope', family: 'other' }),
    });
    // Reached the handler (a validation-class failure, NOT the sealing gate).
    expect(preview.status).not.toBe(401);
    expect((await preview.json()).error?.code).not.toBe('e2ee.sealed_required');
    const patch = await t.fetch(CONFIG, {
      method: 'PATCH',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ render: { enabled: false } }),
    });
    expect(patch.status).toBe(200);
  });

  test('FS_E2EE_REQUIRED alone (member knob) never gates admin routes', async () => {
    vi.stubEnv('FS_E2EE_REQUIRED', 'true');
    const { t, cookie } = await setup();
    expect((await t.fetch(SUMMARY, { headers: { cookie } })).status).toBe(200);
    const patch = await t.fetch(CONFIG, {
      method: 'PATCH',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ render: { enabled: false } }),
    });
    expect(patch.status).toBe(200);
  });

  test('knob on: a cookie caller is refused in plaintext (GET reveal, POST seal-both, PATCH seal-request) with e2ee.sealed_required', async () => {
    vi.stubEnv('FS_E2EE_ADMIN_REQUIRED', 'true');
    const { t, cookie } = await setup();
    const get = await t.fetch(SUMMARY, { headers: { cookie } });
    expect(get.status).toBe(400);
    expect(await get.json()).toMatchObject({ error: { code: 'e2ee.sealed_required' } });
    const post = await t.fetch(PREVIEW, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ relayId: 'nope', family: 'other' }),
    });
    expect(post.status).toBe(400);
    expect(await post.json()).toMatchObject({ error: { code: 'e2ee.sealed_required' } });
    const patch = await t.fetch(CONFIG, {
      method: 'PATCH',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ render: { enabled: true } }),
    });
    expect(patch.status).toBe(400);
    expect(await patch.json()).toMatchObject({ error: { code: 'e2ee.sealed_required' } });
    // Nothing was written by the refused PATCH.
    const rows = await t.run((ctx) => ctx.db.query('appSettings').collect());
    expect(rows.find((r) => r.key === 'edge.render.enabled')).toBeUndefined();
    // Anonymous plaintext is refused the same way (no bearer → sealing is required first).
    expect((await t.fetch(SUMMARY)).status).toBe(400);
    // A cookie session that ADDS a bogus bearer header is still a cookie caller:
    // the handler would authenticate the cookie and never check the bearer, so
    // the header must not buy a plaintext downgrade.
    const downgrade = await t.fetch(SUMMARY, {
      headers: { cookie, authorization: 'Bearer fsv1_bogus' },
    });
    expect(downgrade.status).toBe(400);
    expect(await downgrade.json()).toMatchObject({ error: { code: 'e2ee.sealed_required' } });
  });

  test('knob on: an fsv1_ bearer caller keeps plaintext on every verb class', async () => {
    vi.stubEnv('FS_E2EE_ADMIN_REQUIRED', 'true');
    const { t, bearer } = await setup();
    expect((await t.fetch(SUMMARY, { headers: { authorization: bearer } })).status).toBe(200);
    // A stale / malformed / expired browser cookie riding along must not refuse
    // a VALID token: resolveAdmin falls through to the bearer when the cookie
    // fails, so the class follows the credential that authenticates.
    for (const stale of ['fs_admin_session=garbage', 'fs_admin_session=', 'fs_admin_session=a.b']) {
      const r = await t.fetch(SUMMARY, { headers: { authorization: bearer, cookie: stale } });
      expect(r.status).toBe(200);
    }
    const patch = await t.fetch(CONFIG, {
      method: 'PATCH',
      headers: { authorization: bearer, 'content-type': 'application/json' },
      body: JSON.stringify({ render: { enabled: true } }),
    });
    expect(patch.status).toBe(200);
    expect(await patch.json()).toEqual({ changedKeys: ['render.enabled'] });
    // A bogus bearer is still a "token caller" for the gate, but then fails auth (401, not 400).
    const bogus = await t.fetch(SUMMARY, { headers: { authorization: 'Bearer fsv1_nope' } });
    expect(bogus.status).toBe(401);
  });

  test('knob on: a SEALED cookie request is opened and the response sealed to the request ephemeral', async () => {
    vi.stubEnv('FS_E2EE_ADMIN_REQUIRED', 'true');
    const { t, cookie, kp, kid } = await setup();
    // GET reveal with a response ephemeral header.
    const prepGet = await clientPrepareRequest({
      serverPub: kp.publicKey,
      serverKid: kid,
      method: 'GET',
      path: SUMMARY,
      policy: routePolicy(SUMMARY, 'GET')!,
      bodyObj: undefined,
    });
    const get = await t.fetch(SUMMARY, {
      headers: { cookie, 'x-fs-resp-eph': prepGet.respEphPubB64! },
    });
    expect(get.status).toBe(200);
    expect(get.headers.get('x-fs-sealed')).toBe('1');
    const wire = await get.json();
    expect(isSealedWire(wire)).toBe(true);
    const opened = (await clientOpenResponse({
      serverKid: kid,
      method: 'GET',
      path: SUMMARY,
      respEphPriv: prepGet.respEphPriv!,
      wire,
    })) as { counts: { relays: number } };
    expect(opened.counts.relays).toBe(0);
    // PATCH seal-request.
    const prepPatch = await clientPrepareRequest({
      serverPub: kp.publicKey,
      serverKid: kid,
      method: 'PATCH',
      path: CONFIG,
      policy: routePolicy(CONFIG, 'PATCH')!,
      bodyObj: { render: { enabled: true } },
    });
    expect(isSealedWire(prepPatch.body)).toBe(true);
    const patch = await t.fetch(CONFIG, {
      method: 'PATCH',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify(prepPatch.body),
    });
    expect(patch.status).toBe(200);
    expect(await patch.json()).toEqual({ changedKeys: ['render.enabled'] });
  });
});
