/// <reference types="vite/client" />
/**
 * The country question (docs/privacy.md "Where a member connects from",
 * docs/mirrors.md "Asking"): the member's answer given with the first key
 * (regenerate `region`) and with a mirror (mirror request `region`), the
 * pre-key view for the mode picked at sign-up, the public on/off bit, and the
 * rule that a member's country never crosses the CDN in the clear.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { api, internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { CENSORED_COUNTRIES_KEY } from './lib/censoredCountries';
import { signValue } from './lib/cookies';
import { sha256Hex } from './lib/crypto';
import {
  bytesToB64Url,
  isSealedWire,
  kidFromPublicKey,
  routePolicy,
} from '../src/shared/crypto/envelope';
import { serializePublicKey, serverKeyPairFromSeed } from '../src/shared/crypto/hpke';
import { clientOpenResponse, clientPrepareRequest } from '../src/shared/crypto/channel';

const modules = import.meta.glob('./**/*.*s');
type T = ReturnType<typeof convexTest>;

const FREEDOM_SQUAD = '11111111-2222-3333-4444-000000000001';
const PRIVACY_SQUAD = '11111111-2222-3333-4444-000000000002';
const SERVER_SEED = new Uint8Array(32).fill(9);
const JSON_HDR = { 'content-type': 'application/json' };
const REGEN = '/api/v1/account/regenerate';
const MIRROR = '/api/v1/mirror/request';
const REGION = '/api/v1/account/connection-region';

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
  vi.stubEnv('FS_SERVER_HPKE_SK', bytesToB64Url(SERVER_SEED));
  // Issuance short-circuits with no HTTP (account.test.ts).
  vi.stubEnv('DEV_MOCK_BACKEND', 'true');
  vi.stubEnv('ENVIRONMENT', 'development');
});
afterEach(() => {
  vi.unstubAllEnvs();
});

async function world(o: { mode?: string; listed?: string[]; ask?: boolean } = {}) {
  const t = convexTest(schema, modules);
  const ids = await t.run(async (ctx) => {
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
      ...(o.mode ? { connectionModeId: o.mode } : {}),
      updatedAt: Date.now(),
    });
    for (const [modeSlug, squad] of [
      ['freedom-ws', FREEDOM_SQUAD],
      ['privacy-reality', PRIVACY_SQUAD],
    ] as const)
      await ctx.db.insert('modePlacements', {
        modeSlug,
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: [squad] }),
        updatedAt: Date.now(),
      });
    await upsertSettingRow(
      ctx,
      CENSORED_COUNTRIES_KEY,
      JSON.stringify(
        (o.listed ?? ['IR', 'RU']).map((code) => ({
          code,
          checkEdges: true,
          checkNamesInside: false,
        })),
      ),
    );
    if (o.ask !== undefined)
      await upsertSettingRow(ctx, 'delivery.country.ask', JSON.stringify(o.ask));
    return { userId };
  });
  const sid = `sid-${Math.random().toString(36).slice(2)}`;
  await t.mutation(internal.sessions.create, {
    sid,
    kind: 'member',
    userId: ids.userId,
    ttlMs: 3_600_000,
  });
  const cookie = `fs_session=${await signValue(sid, 'test-sign')}`;
  const kp = await serverKeyPairFromSeed(SERVER_SEED);
  const kid = await kidFromPublicKey(await serializePublicKey(kp.publicKey));
  return { t, cookie, kp, kid, ...ids };
}

type World = Awaited<ReturnType<typeof world>>;

/** A sealed POST to a seal-both route; returns the status and the opened body. */
async function sealedPost(w: World, path: string, bodyObj: Record<string, unknown>) {
  const prep = await clientPrepareRequest({
    serverPub: w.kp.publicKey,
    serverKid: w.kid,
    method: 'POST',
    path,
    policy: routePolicy(path, 'POST')!,
    bodyObj,
  });
  expect(isSealedWire(prep.body)).toBe(true);
  const res = await w.t.fetch(path, {
    method: 'POST',
    headers: { cookie: w.cookie, ...JSON_HDR },
    body: JSON.stringify(prep.body),
  });
  if (!res.ok) return { status: res.status, body: await res.json() };
  const wire = await res.json();
  return {
    status: res.status,
    body: await clientOpenResponse({
      serverKid: w.kid,
      method: 'POST',
      path,
      respEphPriv: prep.respEphPriv!,
      wire,
    }),
  };
}

async function sealedGet(w: World, path: string) {
  const bare = path.split('?')[0]!;
  const prep = await clientPrepareRequest({
    serverPub: w.kp.publicKey,
    serverKid: w.kid,
    method: 'GET',
    path: bare,
    policy: routePolicy(bare, 'GET')!,
  });
  const res = await w.t.fetch(path, {
    headers: { cookie: w.cookie, 'x-fs-resp-eph': prep.respEphPubB64! },
  });
  expect(res.status).toBe(200);
  return clientOpenResponse({
    serverKid: w.kid,
    method: 'GET',
    path: bare,
    respEphPriv: prep.respEphPriv!,
    wire: await res.json(),
  }) as Promise<{ applies: boolean; choice: string | null; options: string[] }>;
}

const currentChoice = (t: T, userId: Id<'users'>) =>
  t.run(async (ctx) => {
    const user = await ctx.db.get(userId);
    const sub = user?.currentSubscriptionId ? await ctx.db.get(user.currentSubscriptionId) : null;
    return sub?.sniRegion ?? null;
  });

const dayCount = (t: T, userId: Id<'users'>) =>
  t.run(async (ctx) => {
    const rows = await ctx.db.query('rateLimits').collect();
    return rows
      .filter((r) => r.bucket === `account.country.day:${userId}`)
      .reduce((n, r) => n + r.count, 0);
  });

describe('publicConfig.countryQuestion', () => {
  test('off by default, on only with the switch AND a non-empty list', async () => {
    expect((await (await world()).t.query(api.publicConfig.get, {})).countryQuestion).toBe(false);
    expect(
      (await (await world({ ask: true })).t.query(api.publicConfig.get, {})).countryQuestion,
    ).toBe(true);
    expect(
      (await (await world({ ask: true, listed: [] })).t.query(api.publicConfig.get, {}))
        .countryQuestion,
    ).toBe(false);
  });
});

describe('the pre-key view (sign-up)', () => {
  test('?mode= judges the question for the picked mode until a key exists', async () => {
    const w = await world({ mode: 'freedom-ws' });
    // No key and no mode: unchanged (the account card stays hidden).
    expect(await sealedGet(w, REGION)).toMatchObject({ applies: false, options: [] });
    expect(await sealedGet(w, `${REGION}?mode=freedom-ws`)).toMatchObject({
      applies: true,
      choice: null,
      options: ['IR', 'RU'],
    });
    expect(await sealedGet(w, `${REGION}?mode=privacy-reality`)).toMatchObject({
      applies: false,
      options: [],
    });
    expect(await sealedGet(w, `${REGION}?mode=no-such-mode`)).toMatchObject({ applies: false });
  });
});

describe('the first key carries the answer (regenerate region)', () => {
  test('a plaintext region is refused before anything is issued', async () => {
    const w = await world({ mode: 'freedom-ws' });
    const res = await w.t.fetch(REGEN, {
      method: 'POST',
      headers: { cookie: w.cookie, ...JSON_HDR },
      body: JSON.stringify({ confirm: true, region: 'IR' }),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: { code: 'hpke.sealed_required' } });
    expect(await w.t.run((ctx) => ctx.db.query('subscriptions').collect())).toHaveLength(0);
  });

  test('a plaintext regenerate without a region still works (old clients)', async () => {
    const w = await world({ mode: 'freedom-ws' });
    const res = await w.t.fetch(REGEN, {
      method: 'POST',
      headers: { cookie: w.cookie, ...JSON_HDR },
      body: JSON.stringify({ confirm: true }),
    });
    expect(res.status).toBe(200);
    expect(await currentChoice(w.t, w.userId)).toBeNull();
  });

  test('sealed: a listed country is born on the key and uses one of the day changes', async () => {
    const w = await world({ mode: 'freedom-ws' });
    const out = await sealedPost(w, REGEN, { confirm: true, region: 'ir' });
    expect(out.status).toBe(200);
    // The response shape is unchanged: no answer, no applied bit.
    expect(out.body).not.toHaveProperty('regionApplied');
    expect(JSON.stringify(out.body)).not.toMatch(/"IR"/);
    expect(await currentChoice(w.t, w.userId)).toBe('IR');
    expect(await dayCount(w.t, w.userId)).toBe(1);
  });

  test('sealed: the opt-out is stored and free', async () => {
    const w = await world({ mode: 'freedom-ws' });
    expect((await sealedPost(w, REGEN, { confirm: true, region: 'ZZ' })).status).toBe(200);
    expect(await currentChoice(w.t, w.userId)).toBe('ZZ');
    expect(await dayCount(w.t, w.userId)).toBe(0);
  });

  test('sealed: a country off the list is refused, nothing issued', async () => {
    const w = await world({ mode: 'freedom-ws' });
    const out = await sealedPost(w, REGEN, { confirm: true, region: 'DE' });
    expect(out.status).toBe(400);
    expect(out.body).toMatchObject({ error: { code: 'validation' } });
    expect(await w.t.run((ctx) => ctx.db.query('subscriptions').collect())).toHaveLength(0);
  });

  test('sealed: a privacy-family key stores nothing and the day change is given back', async () => {
    const w = await world({ mode: 'privacy-reality' });
    expect((await sealedPost(w, REGEN, { confirm: true, region: 'IR' })).status).toBe(200);
    expect(await currentChoice(w.t, w.userId)).toBeNull();
    expect(await dayCount(w.t, w.userId)).toBe(0);
  });

  test('an answer given now wins over the one regenerate would carry', async () => {
    const w = await world({ mode: 'freedom-ws' });
    await sealedPost(w, REGEN, { confirm: true, region: 'IR' });
    await sealedPost(w, REGEN, { confirm: true, region: 'RU' });
    expect(await currentChoice(w.t, w.userId)).toBe('RU');
    // Without one, regenerate carries the answer (unchanged).
    await sealedPost(w, REGEN, { confirm: true });
    expect(await currentChoice(w.t, w.userId)).toBe('RU');
  });

  test('the day limit holds: a fourth new country in a day is refused, nothing issued', async () => {
    const w = await world({ mode: 'freedom-ws', listed: ['IR', 'RU', 'TR', 'CN'] });
    for (const c of ['IR', 'RU', 'TR'])
      expect((await sealedPost(w, REGEN, { confirm: true, region: c })).status).toBe(200);
    const before = await w.t.run((ctx) => ctx.db.query('subscriptions').collect());
    const out = await sealedPost(w, REGEN, { confirm: true, region: 'CN' });
    expect(out.status).toBe(429);
    expect(out.body).toMatchObject({ error: { code: 'rate_limit.country_day' } });
    expect(await w.t.run((ctx) => ctx.db.query('subscriptions').collect())).toHaveLength(
      before.length,
    );
  });
});

describe('a mirror carries the answer (mirror request region)', () => {
  test('a plaintext host hint or answer is refused; plaintext null still works', async () => {
    const w = await world({ mode: 'freedom-ws' });
    await sealedPost(w, REGEN, { confirm: true });
    for (const body of [{ countryCode: 'IR' }, { region: 'IR' }]) {
      const res = await w.t.fetch(MIRROR, {
        method: 'POST',
        headers: { cookie: w.cookie, ...JSON_HDR },
        body: JSON.stringify(body),
      });
      expect(res.status, JSON.stringify(body)).toBe(400);
      expect(await res.json()).toMatchObject({ error: { code: 'hpke.sealed_required' } });
    }
    const ok = await w.t.fetch(MIRROR, {
      method: 'POST',
      headers: { cookie: w.cookie, ...JSON_HDR },
      body: JSON.stringify({ countryCode: null }),
    });
    expect(ok.status).not.toBe(400);
    expect(await currentChoice(w.t, w.userId)).toBeNull();
  });

  test('sealed: the answer is saved to the key before the mirror is made', async () => {
    const w = await world({ mode: 'freedom-ws' });
    await sealedPost(w, REGEN, { confirm: true });
    const provision = vi.spyOn(console, 'error').mockImplementation(() => {});
    const out = await sealedPost(w, MIRROR, { region: 'IR' });
    provision.mockRestore();
    // No provider is configured here: the request answers, the answer stands.
    expect(out.status).toBeLessThan(500);
    expect(await currentChoice(w.t, w.userId)).toBe('IR');
    expect(await dayCount(w.t, w.userId)).toBe(1);
  });

  test('sealed: an answer on a key with no country is refused and the day change given back', async () => {
    const w = await world({ mode: 'privacy-reality' });
    await sealedPost(w, REGEN, { confirm: true });
    const out = await sealedPost(w, MIRROR, { region: 'IR' });
    expect(out.status).toBe(400);
    expect(out.body).toMatchObject({ error: { code: 'validation' } });
    expect(await dayCount(w.t, w.userId)).toBe(0);
  });
});

describe('the answer stays out of the audit log', () => {
  test('no audit row written on these paths names the country', async () => {
    const w = await world({ mode: 'freedom-ws' });
    await sealedPost(w, REGEN, { confirm: true, region: 'IR' });
    await sealedPost(w, MIRROR, { region: 'RU' });
    const rows = await w.t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(rows.length).toBeGreaterThan(0);
    for (const r of rows) {
      const text = JSON.stringify(r);
      expect(text, r.action).not.toMatch(/"(IR|RU)"/);
      expect(text, r.action).not.toContain('sniRegion');
    }
  });
});

describe('sealing posture (FS_HPKE_REQUIRED) on the routes that may carry a country', () => {
  test('a sealed request with no response ephemeral is refused: its answer would go back in plaintext', async () => {
    vi.stubEnv('FS_HPKE_REQUIRED', 'true');
    const w = await world({ mode: 'freedom-ws' });
    // Sealed, but prepared as if the response were plain: no fsRespEph inside.
    const prep = await clientPrepareRequest({
      serverPub: w.kp.publicKey,
      serverKid: w.kid,
      method: 'POST',
      path: REGEN,
      policy: { request: 'seal', response: 'plain' },
      bodyObj: { confirm: true },
    });
    const res = await w.t.fetch(REGEN, {
      method: 'POST',
      headers: { cookie: w.cookie, ...JSON_HDR },
      body: JSON.stringify(prep.body),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: { code: 'hpke.sealed_required' } });
    expect(await w.t.run((ctx) => ctx.db.query('subscriptions').collect())).toHaveLength(0);
  });

  test("an older client's reveal-only shape still works; a country in it is still refused", async () => {
    vi.stubEnv('FS_HPKE_REQUIRED', 'true');
    const w = await world({ mode: 'freedom-ws' });
    const older = async (path: string, bodyObj: Record<string, unknown>) => {
      const prep = await clientPrepareRequest({
        serverPub: w.kp.publicKey,
        serverKid: w.kid,
        method: 'POST',
        path,
        policy: { request: 'plain', response: 'reveal' },
        bodyObj,
      });
      return {
        prep,
        res: await w.t.fetch(path, {
          method: 'POST',
          headers: { cookie: w.cookie, ...JSON_HDR },
          body: typeof prep.body === 'string' ? prep.body : JSON.stringify(prep.body),
        }),
      };
    };
    const ok = await older(REGEN, { confirm: true });
    expect(ok.res.status).toBe(200);
    expect(ok.res.headers.get('x-fs-sealed')).toBe('1');
    const opened = (await clientOpenResponse({
      serverKid: w.kid,
      method: 'POST',
      path: REGEN,
      respEphPriv: ok.prep.respEphPriv!,
      wire: await ok.res.json(),
    })) as { subscriptionUrl: string };
    expect(opened.subscriptionUrl).toBeTruthy();
    for (const [path, body] of [
      [REGEN, { confirm: true, region: 'IR' }],
      [MIRROR, { countryCode: 'IR' }],
    ] as const) {
      const { res } = await older(path, body);
      expect(res.status, path).toBe(400);
      expect(await res.json()).toMatchObject({ error: { code: 'hpke.sealed_required' } });
    }
    // Plaintext with no response ephemeral: refused as before.
    const bare = await w.t.fetch(REGEN, {
      method: 'POST',
      headers: { cookie: w.cookie, ...JSON_HDR },
      body: JSON.stringify({ confirm: true }),
    });
    expect(bare.status).toBe(400);
  });
});

describe('scopes', () => {
  test('a token without subscription:write cannot save an answer through a mirror request', async () => {
    const w = await world({ mode: 'freedom-ws' });
    await sealedPost(w, REGEN, { confirm: true });
    const plaintext = `fsv1_${Math.random().toString(36).slice(2)}${Math.random().toString(36).slice(2)}`;
    await w.t.run(async (ctx) => {
      const adminId = await ctx.db.insert('adminUsers', {
        username: 'op',
        displayName: 'Op',
        isActive: true,
        updatedAt: Date.now(),
      });
      await ctx.db.insert('apiTokens', {
        name: 'member-token',
        tokenHash: await sha256Hex(plaintext),
        tokenPrefix: plaintext.slice(0, 12),
        createdByAdminId: adminId,
        scopes: ['account:write'],
        subjectType: 'user',
        subjectUserId: w.userId,
        updatedAt: Date.now(),
      });
    });
    const prep = await clientPrepareRequest({
      serverPub: w.kp.publicKey,
      serverKid: w.kid,
      method: 'POST',
      path: MIRROR,
      policy: routePolicy(MIRROR, 'POST')!,
      bodyObj: { region: 'IR' },
    });
    const res = await w.t.fetch(MIRROR, {
      method: 'POST',
      headers: { authorization: `Bearer ${plaintext}`, ...JSON_HDR },
      body: JSON.stringify(prep.body),
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: { code: 'auth.forbidden' } });
    expect(await currentChoice(w.t, w.userId)).toBeNull();
    expect(await dayCount(w.t, w.userId)).toBe(0);
  });
});
