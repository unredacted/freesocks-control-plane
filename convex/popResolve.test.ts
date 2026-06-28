/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import type { Id } from './_generated/dataModel';
import { resolveMember } from './lib/http';
import { signValue } from './lib/cookies';
import { bytesToB64Url } from '../src/shared/crypto/envelope';
import {
  buildPopMessage,
  digestB64Url,
  POP_NONCE_HEADER,
  POP_SIG_HEADER,
  POP_TS_HEADER,
  POP_VERSION,
  POP_VERSION_HEADER,
  signP1363,
} from '../src/shared/crypto/pop';

const modules = import.meta.glob('./**/*.*s');
const SIGN_KEY = 'test-session-signing-key';
const PATH = '/api/v1/me';

async function seedUser(t: ReturnType<typeof convexTest>): Promise<Id<'users'>> {
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
    return ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() });
  });
}

async function makeKey() {
  const kp = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const pubB64 = bytesToB64Url(new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey)));
  return { priv: kp.privateKey, pubB64 };
}

async function seedSession(
  t: ReturnType<typeof convexTest>,
  userId: Id<'users'>,
  popPublicKey?: string,
): Promise<string> {
  const sid = `sid-${Math.random().toString(16).slice(2)}`;
  await t.run(async (ctx) => {
    await ctx.db.insert('sessions', {
      sid,
      kind: 'member',
      userId,
      expiresAt: Date.now() + 3_600_000,
      ...(popPublicKey ? { popPublicKey, popAlg: 'ES256', popBoundAt: Date.now() } : {}),
    });
  });
  return sid;
}

async function buildReq(opts: {
  sid: string;
  priv?: CryptoKey;
  nonceByte?: number;
  ts?: number;
}): Promise<Request> {
  const cookie = `fs_session=${await signValue(opts.sid, SIGN_KEY)}`;
  const headers = new Headers({ cookie });
  if (opts.priv) {
    const ts = opts.ts ?? Date.now();
    const nonceB64 = bytesToB64Url(new Uint8Array(16).fill(opts.nonceByte ?? 3));
    const bodyHashB64 = await digestB64Url(new TextEncoder().encode(''));
    const msg = buildPopMessage({ method: 'GET', path: PATH, bodyHashB64, ts, nonceB64 });
    headers.set(POP_SIG_HEADER, bytesToB64Url(await signP1363(opts.priv, msg)));
    headers.set(POP_TS_HEADER, String(ts));
    headers.set(POP_NONCE_HEADER, nonceB64);
    headers.set(POP_VERSION_HEADER, POP_VERSION);
  }
  return new Request(`http://localhost${PATH}`, { headers });
}

describe('resolveMember + PoP (Phase 2 verify path)', () => {
  beforeEach(() => vi.stubEnv('SESSION_SIGNING_KEY', SIGN_KEY));
  afterEach(() => vi.unstubAllEnvs());

  test('a bound session with a valid signature authenticates', async () => {
    const t = convexTest(schema, modules);
    const userId = await seedUser(t);
    const { priv, pubB64 } = await makeKey();
    const sid = await seedSession(t, userId, pubB64);
    const req = await buildReq({ sid, priv });

    const auth = await t.action(async (ctx) => resolveMember(ctx, req));
    expect(auth?.userId).toBe(userId);
    expect(auth?.source).toBe('cookie');
  });

  test('a replayed request (same nonce) is rejected on the second use', async () => {
    const t = convexTest(schema, modules);
    const userId = await seedUser(t);
    const { priv, pubB64 } = await makeKey();
    const sid = await seedSession(t, userId, pubB64);
    const req = await buildReq({ sid, priv, nonceByte: 9 });

    expect((await t.action(async (ctx) => resolveMember(ctx, req)))?.userId).toBe(userId);
    // Same signed request again: the nonce is now spent.
    expect(await t.action(async (ctx) => resolveMember(ctx, req))).toBeNull();
  });

  test('a bound session with NO signature is rejected (re-bind rule, no silent accept)', async () => {
    const t = convexTest(schema, modules);
    const userId = await seedUser(t);
    const { pubB64 } = await makeKey();
    const sid = await seedSession(t, userId, pubB64);
    const req = await buildReq({ sid }); // cookie only, no PoP headers

    expect(await t.action(async (ctx) => resolveMember(ctx, req))).toBeNull();
  });

  test('a bound session with a signature from the wrong key is rejected', async () => {
    const t = convexTest(schema, modules);
    const userId = await seedUser(t);
    const { pubB64 } = await makeKey();
    const stranger = await makeKey();
    const sid = await seedSession(t, userId, pubB64);
    const req = await buildReq({ sid, priv: stranger.priv });

    expect(await t.action(async (ctx) => resolveMember(ctx, req))).toBeNull();
  });

  test('a legacy (unbound) session authenticates by cookie alone while POP_REQUIRED is off', async () => {
    const t = convexTest(schema, modules);
    const userId = await seedUser(t);
    const sid = await seedSession(t, userId); // no popPublicKey
    const req = await buildReq({ sid }); // cookie only

    const auth = await t.action(async (ctx) => resolveMember(ctx, req));
    expect(auth?.userId).toBe(userId);
  });

  test('a legacy session is rejected once POP_REQUIRED is enabled', async () => {
    vi.stubEnv('POP_REQUIRED', 'true');
    const t = convexTest(schema, modules);
    const userId = await seedUser(t);
    const sid = await seedSession(t, userId); // no popPublicKey
    const req = await buildReq({ sid });

    expect(await t.action(async (ctx) => resolveMember(ctx, req))).toBeNull();
  });
});
