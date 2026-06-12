// @vitest-environment node
/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { hmacSha256Hex } from './lib/crypto';

const modules = import.meta.glob('./**/*.*s');

// These tests cover the GATING + SECURITY branches of the passkey ceremonies
// (bootstrap lock, anti-enumeration, throttle, replay/challenge handling) which
// are reachable without a real authenticator. The cryptographic happy-path
// (verifyRegistrationResponse / verifyAuthenticationResponse succeeding on a
// genuine attestation/assertion) needs a hardware/virtual authenticator and is
// left to an end-to-end browser test (see the test.todo at the bottom).

const IP_SALT = 'test-ip-salt';

beforeEach(() => {
  vi.stubEnv('WEBAUTHN_RP_ID', 'localhost');
  vi.stubEnv('WEBAUTHN_ORIGIN', 'http://localhost:5173');
  vi.stubEnv('ADMIN_BOOTSTRAP_SECRET', 'correct-secret');
  vi.stubEnv('IP_HASH_SALT', IP_SALT);
});
afterEach(() => vi.unstubAllEnvs());

type T = ReturnType<typeof convexTest>;

/** Seed an active admin plus one registered passkey (so hasActiveAdmin is true). */
async function seedAdminWithCredential(
  t: T,
  username = 'admin',
  credentialId = 'cred-1',
): Promise<{ adminId: Id<'adminUsers'>; credentialId: string }> {
  const adminId = await t.run(async (ctx) => {
    const id = await ctx.db.insert('adminUsers', {
      username,
      displayName: username,
      isActive: true,
      updatedAt: Date.now(),
    });
    await ctx.db.insert('passkeyCredentials', {
      adminUserId: id,
      credentialId,
      publicKey: 'cHVibGljLWtleQ==',
      counter: 0,
    });
    return id;
  });
  return { adminId, credentialId };
}

describe('registerBootstrapOptions', () => {
  test('rejects a wrong bootstrap secret', async () => {
    const t = convexTest(schema, modules);
    await expect(
      t.action(internal.webauthn.registerBootstrapOptions, {
        bootstrapSecret: 'wrong',
        username: 'admin',
      }),
    ).rejects.toThrow(/Bootstrap secret required/);
  });

  test('rejects when no bootstrap secret is configured', async () => {
    vi.stubEnv('ADMIN_BOOTSTRAP_SECRET', '');
    const t = convexTest(schema, modules);
    await expect(
      t.action(internal.webauthn.registerBootstrapOptions, {
        bootstrapSecret: 'anything',
        username: 'admin',
      }),
    ).rejects.toThrow(/Bootstrap secret required/);
  });

  test('is closed once an admin credential exists', async () => {
    const t = convexTest(schema, modules);
    await seedAdminWithCredential(t);
    await expect(
      t.action(internal.webauthn.registerBootstrapOptions, {
        bootstrapSecret: 'correct-secret',
        username: 'admin2',
      }),
    ).rejects.toThrow(/Bootstrap closed/);
  });

  test('requires a username', async () => {
    const t = convexTest(schema, modules);
    await expect(
      t.action(internal.webauthn.registerBootstrapOptions, {
        bootstrapSecret: 'correct-secret',
        username: '',
      }),
    ).rejects.toThrow(/username required/);
  });

  test('returns options + adminId and stores a registration challenge on the happy path', async () => {
    const t = convexTest(schema, modules);
    const res = await t.action(internal.webauthn.registerBootstrapOptions, {
      bootstrapSecret: 'correct-secret',
      username: 'admin',
    });
    expect(typeof res.options.challenge).toBe('string');
    expect(res.adminId).toBeTruthy();
    const { admins, challenges } = await t.run(async (ctx) => ({
      admins: await ctx.db.query('adminUsers').collect(),
      challenges: await ctx.db.query('webauthnRegistrationChallenges').collect(),
    }));
    expect(admins.map((a) => a.username)).toContain('admin');
    expect(challenges).toHaveLength(1);
    expect(challenges[0]!.adminUserId).toBe(res.adminId);
  });
});

describe('registerBootstrapVerify', () => {
  test('re-checks the bootstrap lock (TOCTOU) and rejects when an admin exists', async () => {
    const t = convexTest(schema, modules);
    const { adminId } = await seedAdminWithCredential(t);
    await expect(
      t.action(internal.webauthn.registerBootstrapVerify, {
        adminId,
        response: { id: 'x', rawId: 'x', response: {}, type: 'public-key' },
      }),
    ).rejects.toThrow(/Bootstrap closed/);
  });

  test('rejects when there is no valid registration challenge', async () => {
    const t = convexTest(schema, modules);
    // An admin row with no credential (abandoned bootstrap): lock is still open,
    // but there is no pending challenge to consume.
    const adminId = await t.run((ctx) =>
      ctx.db.insert('adminUsers', {
        username: 'admin',
        displayName: 'admin',
        isActive: true,
        updatedAt: Date.now(),
      }),
    );
    await expect(
      t.action(internal.webauthn.registerBootstrapVerify, {
        adminId,
        response: { id: 'x', rawId: 'x', response: {}, type: 'public-key' },
      }),
    ).rejects.toThrow(/No valid challenge/);
  });
});

describe('authenticateOptions (M4 anti-enumeration + throttle)', () => {
  test('an unknown username yields well-formed options with no credentials', async () => {
    const t = convexTest(schema, modules);
    const res = await t.action(internal.webauthn.authenticateOptions, { username: 'ghost' });
    expect(typeof res.options.challenge).toBe('string');
    expect(typeof res.challengeId).toBe('string');
    expect(res.options.allowCredentials ?? []).toHaveLength(0);
    // The stored challenge is not tied to any admin (no existence leak).
    const row = await t.run(async (ctx) =>
      (await ctx.db.query('webauthnAuthChallenges').collect()).find(
        (r) => r.challengeId === res.challengeId,
      ),
    );
    expect(row?.adminUserId).toBeUndefined();
  });

  test('usernameless: no username yields discoverable options (no allowCredentials), admin-blind challenge', async () => {
    const t = convexTest(schema, modules);
    await seedAdminWithCredential(t, 'admin', 'cred-1');
    // The default sign-in flow: omit the username entirely. The authenticator
    // picks from its resident passkeys, so the server sends no allowCredentials
    // hint and the challenge is not tied to any admin (verify resolves the admin
    // from the chosen credential).
    const res = await t.action(internal.webauthn.authenticateOptions, {});
    expect(typeof res.options.challenge).toBe('string');
    expect(typeof res.challengeId).toBe('string');
    expect(res.options.allowCredentials ?? []).toHaveLength(0);
    const row = await t.run(async (ctx) =>
      (await ctx.db.query('webauthnAuthChallenges').collect()).find(
        (r) => r.challengeId === res.challengeId,
      ),
    );
    expect(row?.adminUserId).toBeUndefined();
  });

  test('a known admin (username fallback) yields the same shape but with its credentials listed', async () => {
    const t = convexTest(schema, modules);
    await seedAdminWithCredential(t, 'admin', 'cred-1');
    const res = await t.action(internal.webauthn.authenticateOptions, { username: 'admin' });
    // Same response shape as the unknown case (options + challengeId)...
    expect(typeof res.options.challenge).toBe('string');
    expect(typeof res.challengeId).toBe('string');
    // ...but allowCredentials now lists the admin's credential.
    expect(res.options.allowCredentials?.map((c) => c.id)).toContain('cred-1');
  });

  test('throttles per IP once the window cap is reached', async () => {
    const t = convexTest(schema, modules);
    const ipHash = await hmacSha256Hex(IP_SALT, '203.0.113.9');
    await t.run((ctx) =>
      ctx.db.insert('rateLimits', {
        bucket: `admin-auth:ip:${ipHash}`,
        count: 20, // at the cap (max 20)
        expiresAt: Date.now() + 3_600_000,
      }),
    );
    await expect(
      t.action(internal.webauthn.authenticateOptions, { username: 'admin', ip: '203.0.113.9' }),
    ).rejects.toThrow(/Too many sign-in attempts/);
  });
});

describe('authenticateVerify', () => {
  test('rejects an invalid or expired challenge id', async () => {
    const t = convexTest(schema, modules);
    await expect(
      t.action(internal.webauthn.authenticateVerify, {
        challengeId: 'does-not-exist',
        response: { id: 'cred-1', rawId: 'cred-1', response: {}, type: 'public-key' },
      }),
    ).rejects.toThrow(/Invalid or expired challenge/);
  });

  test('rejects an unknown credential after consuming a valid challenge', async () => {
    const t = convexTest(schema, modules);
    await t.run((ctx) =>
      ctx.db.insert('webauthnAuthChallenges', {
        challengeId: 'ch-1',
        challenge: 'a-fake-challenge',
        expiresAt: Date.now() + 60_000,
      }),
    );
    await expect(
      t.action(internal.webauthn.authenticateVerify, {
        challengeId: 'ch-1',
        response: { id: 'unregistered-cred', rawId: 'x', response: {}, type: 'public-key' },
      }),
    ).rejects.toThrow(/Unknown credential/);
    // The challenge is single-use: it was consumed before the credential lookup.
    const row = await t.run(async (ctx) =>
      (await ctx.db.query('webauthnAuthChallenges').collect()).find(
        (r) => r.challengeId === 'ch-1',
      ),
    );
    expect(row?.consumedAt).toBeTypeOf('number');
  });
});

// The cryptographic happy-path (a genuine attestation/assertion passing
// @simplewebauthn verification, the counter bump, the session mint + signed
// cookie) requires a real or virtual authenticator and belongs in an e2e
// browser test, not convex-test.
test.todo('e2e: full passkey registration + authentication happy-path with a real authenticator');
