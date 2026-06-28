// @vitest-environment node
/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { hmacSha256Hex, sha256Hex } from './lib/crypto';
import { verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server';

// Mock ONLY the two cryptographic verifiers, so the post-verify happy-path
// (counter bump, credential insert, session mint + signed cookie) is reachable in
// convex-test without a real/virtual authenticator. generate*Options stay REAL
// (the options tests rely on them). Every existing *Verify test bails BEFORE these
// are reached (bad/expired challenge, unknown credential, bootstrap lock), so they
// are unaffected. The full ceremony with a genuine authenticator is the e2e todo.
vi.mock('@simplewebauthn/server', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@simplewebauthn/server')>();
  return {
    ...actual,
    verifyRegistrationResponse: vi.fn(),
    verifyAuthenticationResponse: vi.fn(),
  };
});

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

  test('happy path: a verified attestation inserts the credential (post-verify logic)', async () => {
    const t = convexTest(schema, modules);
    // Lock open (admin row, no credential yet) + a pending registration challenge.
    const adminId = await t.run(async (ctx) => {
      const id = await ctx.db.insert('adminUsers', {
        username: 'first',
        displayName: 'First',
        isActive: true,
        updatedAt: Date.now(),
      });
      await ctx.db.insert('webauthnRegistrationChallenges', {
        adminUserId: id,
        challenge: 'stored-challenge',
        expiresAt: Date.now() + 60_000,
      });
      return id;
    });
    vi.mocked(verifyRegistrationResponse).mockResolvedValue({
      verified: true,
      registrationInfo: {
        credential: {
          id: 'new-cred-id',
          publicKey: new Uint8Array([1, 2, 3, 4]),
          counter: 0,
          transports: [],
        },
        aaguid: 'aaguid-test',
      },
    } as unknown as Awaited<ReturnType<typeof verifyRegistrationResponse>>);

    const res = await t.action(internal.webauthn.registerBootstrapVerify, {
      adminId,
      response: { id: 'new-cred-id', rawId: 'new-cred-id', response: {}, type: 'public-key' },
      deviceLabel: 'My Key',
    });
    expect(res.ok).toBe(true);
    const creds = await t.run(async (ctx) =>
      (await ctx.db.query('passkeyCredentials').collect()).filter((c) => c.adminUserId === adminId),
    );
    expect(creds).toHaveLength(1);
    expect(creds[0]!.credentialId).toBe('new-cred-id');
    expect(creds[0]!.counter).toBe(0);
    expect(creds[0]!.deviceLabel).toBe('My Key');
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

  test('happy path: a verified assertion bumps the counter and mints an admin session', async () => {
    vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', 'test-admin-signing-key');
    const t = convexTest(schema, modules);
    const { adminId } = await seedAdminWithCredential(t, 'admin', 'cred-1');
    await t.run((ctx) =>
      ctx.db.insert('webauthnAuthChallenges', {
        challengeId: 'ch-auth',
        challenge: 'stored-challenge',
        expiresAt: Date.now() + 60_000,
      }),
    );
    vi.mocked(verifyAuthenticationResponse).mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 7 },
    } as unknown as Awaited<ReturnType<typeof verifyAuthenticationResponse>>);

    const res = await t.action(internal.webauthn.authenticateVerify, {
      challengeId: 'ch-auth',
      response: { id: 'cred-1', rawId: 'cred-1', response: {}, type: 'public-key' },
    });
    expect(res.ok).toBe(true);
    expect(res.username).toBe('admin');
    expect(typeof res.signedCookieValue).toBe('string');
    // The counter advanced to the verifier's value + an admin session row minted.
    const cred = await t.run(async (ctx) =>
      (await ctx.db.query('passkeyCredentials').collect()).find((c) => c.credentialId === 'cred-1'),
    );
    expect(cred?.counter).toBe(7);
    const sessions = await t.run(async (ctx) =>
      (await ctx.db.query('sessions').collect()).filter(
        (s) => s.kind === 'admin' && s.adminUserId === adminId,
      ),
    );
    expect(sessions).toHaveLength(1);
  });
});

describe('createInvite (multi-admin onboarding)', () => {
  async function seedCreator(t: T): Promise<Id<'adminUsers'>> {
    return t.run((ctx) =>
      ctx.db.insert('adminUsers', {
        username: 'root',
        displayName: 'Root',
        isActive: true,
        updatedAt: Date.now(),
      }),
    );
  }

  test('mints an invite for a new admin and returns a one-time token (stored hashed)', async () => {
    const t = convexTest(schema, modules);
    const creator = await seedCreator(t);
    const res = await t.action(internal.webauthn.createInvite, {
      username: 'alex',
      createdByAdminId: creator,
    });
    expect(res.inviteToken).toMatch(/^[0-9a-f]{64}$/);
    expect(res.username).toBe('alex');
    const { admins, invites } = await t.run(async (ctx) => ({
      admins: await ctx.db.query('adminUsers').collect(),
      invites: await ctx.db.query('adminInvites').collect(),
    }));
    expect(admins.map((a) => a.username)).toContain('alex');
    expect(invites).toHaveLength(1);
    // Only the hash is persisted — never the raw token.
    expect(invites[0]!.tokenHash).toBe(await sha256Hex(res.inviteToken));
    expect(invites[0]!.tokenHash).not.toBe(res.inviteToken);
  });

  test('rejects a username that already has a registered passkey', async () => {
    const t = convexTest(schema, modules);
    const creator = await seedCreator(t);
    await seedAdminWithCredential(t, 'taken', 'cred-x');
    await expect(
      t.action(internal.webauthn.createInvite, { username: 'taken', createdByAdminId: creator }),
    ).rejects.toThrow(/already has a registered admin/);
  });
});

describe('registerInviteOptions / registerInviteVerify (invite gating)', () => {
  async function seedInvite(
    t: T,
    opts: { token?: string; expired?: boolean; consumed?: boolean } = {},
  ): Promise<{ adminUserId: Id<'adminUsers'>; token: string }> {
    const token = opts.token ?? 'a'.repeat(64);
    const adminUserId = await t.run((ctx) =>
      ctx.db.insert('adminUsers', {
        username: 'alex',
        displayName: 'Alex',
        isActive: true,
        updatedAt: Date.now(),
      }),
    );
    const tokenHash = await sha256Hex(token);
    await t.run((ctx) =>
      ctx.db.insert('adminInvites', {
        adminUserId,
        tokenHash,
        tokenPrefix: token.slice(0, 8),
        createdByAdminId: adminUserId,
        expiresAt: opts.expired ? Date.now() - 1000 : Date.now() + 3_600_000,
        consumedAt: opts.consumed ? Date.now() : undefined,
        updatedAt: Date.now(),
      }),
    );
    return { adminUserId, token };
  }

  test('options: an invalid invite is rejected', async () => {
    const t = convexTest(schema, modules);
    await expect(
      t.action(internal.webauthn.registerInviteOptions, { invite: 'not-a-real-token' }),
    ).rejects.toThrow(/Invalid or expired invite/);
  });

  test('options: a valid invite returns registration options + stores a challenge', async () => {
    const t = convexTest(schema, modules);
    const { adminUserId, token } = await seedInvite(t);
    const res = await t.action(internal.webauthn.registerInviteOptions, { invite: token });
    expect(typeof res.options.challenge).toBe('string');
    const challenges = await t.run((ctx) =>
      ctx.db
        .query('webauthnRegistrationChallenges')
        .withIndex('by_admin_expires', (q) => q.eq('adminUserId', adminUserId))
        .collect(),
    );
    expect(challenges).toHaveLength(1);
  });

  test('options: an expired invite is rejected', async () => {
    const t = convexTest(schema, modules);
    const { token } = await seedInvite(t, { expired: true });
    await expect(
      t.action(internal.webauthn.registerInviteOptions, { invite: token }),
    ).rejects.toThrow(/Invalid or expired invite/);
  });

  test('options: a consumed invite is rejected', async () => {
    const t = convexTest(schema, modules);
    const { token } = await seedInvite(t, { consumed: true });
    await expect(
      t.action(internal.webauthn.registerInviteOptions, { invite: token }),
    ).rejects.toThrow(/Invalid or expired invite/);
  });

  test('verify: an invalid invite is rejected', async () => {
    const t = convexTest(schema, modules);
    await expect(
      t.action(internal.webauthn.registerInviteVerify, { invite: 'nope', response: {} }),
    ).rejects.toThrow(/Invalid or expired invite/);
  });

  test('verify: a valid invite with no pending challenge fails before any crypto', async () => {
    const t = convexTest(schema, modules);
    const { token } = await seedInvite(t);
    await expect(
      t.action(internal.webauthn.registerInviteVerify, {
        invite: token,
        response: { id: 'x', rawId: 'x', response: {}, type: 'public-key' },
      }),
    ).rejects.toThrow(/No valid challenge/);
  });
});

// The cryptographic happy-path (a genuine attestation/assertion passing
// @simplewebauthn verification, the counter bump, the session mint + signed
// cookie) requires a real or virtual authenticator and belongs in an e2e
// browser test, not convex-test.
test.todo('e2e: full passkey registration + authentication happy-path with a real authenticator');
