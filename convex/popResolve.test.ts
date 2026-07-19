/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { resolveMember, resolveAdmin } from './lib/http';
import { signValue } from './lib/cookies';
import { sha256Hex } from './lib/crypto';
import { bytesToB64Url } from '../src/shared/crypto/envelope';
import {
  buildPopMessage,
  digestB64Url,
  POP_NONCE_HEADER,
  POP_SIG_HEADER,
  POP_TS_HEADER,
  POP_VERSION,
  POP_VERSION_HEADER,
  signPop,
} from '../src/shared/crypto/pop';

const modules = import.meta.glob('./**/*.*s');
const SIGN_KEY = 'test-session-signing-key';
const PATH = '/api/v1/me';
const PST = 'pst-test'; // the public per-session token, bound into the signature

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

/** A WebCrypto Ed25519 session keypair, or null if this runtime lacks it. */
async function makeEd25519Key() {
  try {
    const kp = (await crypto.subtle.generateKey({ name: 'Ed25519' }, false, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;
    const pubB64 = bytesToB64Url(
      new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey)),
    );
    return { priv: kp.privateKey, pubB64 };
  } catch {
    return null;
  }
}

async function seedSession(
  t: ReturnType<typeof convexTest>,
  userId: Id<'users'>,
  popPublicKey?: string,
  popSessionToken?: string,
  popAlg = 'ES256',
): Promise<string> {
  const sid = `sid-${Math.random().toString(16).slice(2)}`;
  await t.run(async (ctx) => {
    await ctx.db.insert('sessions', {
      sid,
      kind: 'member',
      userId,
      expiresAt: Date.now() + 3_600_000,
      ...(popPublicKey ? { popPublicKey, popAlg, popSessionToken } : {}),
    });
  });
  return sid;
}

async function buildReq(opts: {
  sid: string;
  priv?: CryptoKey;
  sessionToken?: string;
  nonceByte?: number;
  ts?: number;
}): Promise<Request> {
  const cookie = `fs_session=${await signValue(opts.sid, SIGN_KEY)}`;
  const headers = new Headers({ cookie });
  if (opts.priv) {
    const ts = opts.ts ?? Date.now();
    const nonceB64 = bytesToB64Url(new Uint8Array(16).fill(opts.nonceByte ?? 3));
    const bodyHashB64 = await digestB64Url(new TextEncoder().encode(''));
    const msg = buildPopMessage({
      method: 'GET',
      path: PATH,
      sessionToken: opts.sessionToken ?? '',
      bodyHashB64,
      ts,
      nonceB64,
    });
    headers.set(POP_SIG_HEADER, bytesToB64Url(await signPop(opts.priv, msg)));
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
    const sid = await seedSession(t, userId, pubB64, PST);
    const req = await buildReq({ sid, priv, sessionToken: PST });

    const auth = await t.action(async (ctx) => resolveMember(ctx, req));
    expect(auth?.userId).toBe(userId);
    expect(auth?.source).toBe('cookie');
  });

  test('an Ed25519-bound session (popAlg EdDSA) authenticates with a valid signature', async () => {
    const t = convexTest(schema, modules);
    const userId = await seedUser(t);
    const k = await makeEd25519Key();
    if (!k) return; // runtime without WebCrypto Ed25519 (P-256 path is fully covered)
    const sid = await seedSession(t, userId, k.pubB64, PST, 'EdDSA');
    const req = await buildReq({ sid, priv: k.priv, sessionToken: PST });

    const auth = await t.action(async (ctx) => resolveMember(ctx, req));
    expect(auth?.userId).toBe(userId);
    expect(auth?.source).toBe('cookie');
  });

  test('a replayed request (same nonce) is rejected on the second use', async () => {
    const t = convexTest(schema, modules);
    const userId = await seedUser(t);
    const { priv, pubB64 } = await makeKey();
    const sid = await seedSession(t, userId, pubB64, PST);
    const req = await buildReq({ sid, priv, sessionToken: PST, nonceByte: 9 });

    expect((await t.action(async (ctx) => resolveMember(ctx, req)))?.userId).toBe(userId);
    // Same signed request again: the nonce is now spent.
    expect(await t.action(async (ctx) => resolveMember(ctx, req))).toBeNull();
  });

  test('a bound session with NO signature is rejected (re-bind rule, no silent accept)', async () => {
    const t = convexTest(schema, modules);
    const userId = await seedUser(t);
    const { pubB64 } = await makeKey();
    const sid = await seedSession(t, userId, pubB64, PST);
    const req = await buildReq({ sid }); // cookie only, no PoP headers

    expect(await t.action(async (ctx) => resolveMember(ctx, req))).toBeNull();
  });

  test('a bound session with a signature from the wrong key is rejected', async () => {
    const t = convexTest(schema, modules);
    const userId = await seedUser(t);
    const { pubB64 } = await makeKey();
    const stranger = await makeKey();
    const sid = await seedSession(t, userId, pubB64, PST);
    const req = await buildReq({ sid, priv: stranger.priv, sessionToken: PST });

    expect(await t.action(async (ctx) => resolveMember(ctx, req))).toBeNull();
  });

  test('a bound session whose signed token does not match the stored pst is rejected', async () => {
    const t = convexTest(schema, modules);
    const userId = await seedUser(t);
    const { priv, pubB64 } = await makeKey();
    // The session stores pst-A; the client signs pst-B (e.g. a signature lifted
    // from another session that reuses this key) → reconstruction mismatch.
    const sid = await seedSession(t, userId, pubB64, 'pst-A');
    const req = await buildReq({ sid, priv, sessionToken: 'pst-B' });

    expect(await t.action(async (ctx) => resolveMember(ctx, req))).toBeNull();
  });

  test('a bound session with NO stored token (pre-upgrade) is rejected → re-auth', async () => {
    const t = convexTest(schema, modules);
    const userId = await seedUser(t);
    const { priv, pubB64 } = await makeKey();
    const sid = await seedSession(t, userId, pubB64); // bound but no popSessionToken
    const req = await buildReq({ sid, priv, sessionToken: PST });

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

// --- token scope enforcement (P1-1) at the resolve* layer -------------------

/** Insert an fsv1_ token row directly and return its plaintext. */
async function insertToken(
  t: ReturnType<typeof convexTest>,
  opts: { scopes: string[]; subjectType: 'service' | 'user'; subjectUserId?: Id<'users'> },
): Promise<string> {
  const plaintext = `fsv1_${Math.random().toString(36).slice(2)}${Math.random().toString(36).slice(2)}`;
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

const tokenReq = (plaintext: string) =>
  new Request(`http://localhost${PATH}`, {
    headers: { authorization: `Bearer ${plaintext}` },
  });

describe('token scope enforcement (resolveMember / resolveAdmin)', () => {
  test('a user token lacking the required scope resolves to null; carrying it succeeds', async () => {
    const t = convexTest(schema, modules);
    const userId = await seedUser(t);
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

    expect(
      await t.action(async (ctx) => resolveMember(ctx, tokenReq(lacking), 'account:read')),
    ).toBeNull();
    const ok = await t.action(async (ctx) =>
      resolveMember(ctx, tokenReq(carrying), 'account:read'),
    );
    expect(ok?.userId).toBe(userId);
    expect(ok?.source).toBe('token');
  });

  test('an admin token with only a read scope is rejected on a write-scoped route', async () => {
    const t = convexTest(schema, modules);
    const readOnly = await insertToken(t, {
      scopes: ['admin:tiers:read'],
      subjectType: 'service',
    });
    const writer = await insertToken(t, {
      scopes: ['admin:tiers:write'],
      subjectType: 'service',
    });

    expect(
      await t.action(async (ctx) => resolveAdmin(ctx, tokenReq(readOnly), 'admin:tiers:write')),
    ).toBeNull();
    const ok = await t.action(async (ctx) =>
      resolveAdmin(ctx, tokenReq(writer), 'admin:tiers:write'),
    );
    expect(ok?.tokenScopes).toEqual(['admin:tiers:write']);
  });
});

// --- account.rotate rate-limit policy (max: 5 / window) ---------------------

describe("rateLimits.enforce policy 'account.rotate'", () => {
  test('5 calls in the window are allowed, the 6th is refused with a retryAfterMs', async () => {
    const t = convexTest(schema, modules);
    const userId = await seedUser(t);
    const call = () =>
      t.mutation(internal.rateLimits.enforce, {
        policyKey: 'account.rotate',
        subject: userId,
      });

    for (let i = 0; i < 5; i++) {
      const r = await call();
      expect(r.allowed).toBe(true);
    }
    const sixth = await call();
    expect(sixth.allowed).toBe(false);
    expect(sixth.retryAfterMs).toBeGreaterThan(0);
  });
});
