// @vitest-environment node
/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { hmacSha256Hex } from './lib/crypto';
import { verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server';

// Mock ONLY the two cryptographic verifiers (mirrors webauthn.test.ts), so the
// post-verify happy path (counter bump, credential insert, member session mint) is
// reachable without a real authenticator. generate*Options stay REAL. The full
// ceremony with a genuine authenticator is an e2e todo.
vi.mock('@simplewebauthn/server', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@simplewebauthn/server')>();
  return {
    ...actual,
    verifyRegistrationResponse: vi.fn(),
    verifyAuthenticationResponse: vi.fn(),
  };
});

const modules = import.meta.glob('./**/*.*s');
const IP_SALT = 'test-ip-salt';

beforeEach(() => {
  vi.stubEnv('WEBAUTHN_RP_ID', 'localhost');
  vi.stubEnv('WEBAUTHN_ORIGIN', 'http://localhost:5173');
  vi.stubEnv('IP_HASH_SALT', IP_SALT);
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-member-signing-key');
});
afterEach(() => vi.unstubAllEnvs());

type T = ReturnType<typeof convexTest>;
type Status = 'active' | 'grace' | 'inactive' | 'disabled' | 'deleted';

/** Seed a tier + a member user, optionally with one member passkey credential. */
async function seedMember(
  t: T,
  opts: { status?: Status; disabledReason?: string; credentialId?: string } = {},
): Promise<{ userId: Id<'users'>; credentialId?: string }> {
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
      status: opts.status ?? 'active',
      disabledReason: opts.disabledReason,
      updatedAt: Date.now(),
    });
    if (opts.credentialId) {
      await ctx.db.insert('memberPasskeyCredentials', {
        userId,
        credentialId: opts.credentialId,
        publicKey: 'cHVibGljLWtleQ==',
        counter: 0,
        deviceLabel: 'Test device',
      });
    }
    return { userId, credentialId: opts.credentialId };
  });
}

describe('registerOptions (add a passkey)', () => {
  test('returns options + stores a member registration challenge keyed to the user', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedMember(t);
    const res = await t.action(internal.memberWebauthn.registerOptions, { userId });
    expect(typeof res.options.challenge).toBe('string');
    const challenges = await t.run((ctx) =>
      ctx.db
        .query('memberWebauthnRegistrationChallenges')
        .withIndex('by_user_expires', (q) => q.eq('userId', userId))
        .collect(),
    );
    expect(challenges).toHaveLength(1);
  });

  test('excludeCredentials lists the member existing passkeys (no double-register)', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedMember(t, { credentialId: 'existing-cred' });
    const res = await t.action(internal.memberWebauthn.registerOptions, { userId });
    expect(res.options.excludeCredentials?.map((c) => c.id)).toContain('existing-cred');
  });

  test('per-member enroll limit holds even with NO request IP', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedMember(t);
    // The bucket is keyed by userId (not IP), so the limit must apply even when
    // the request IP is unresolvable (a previous `if (ip)` guard disabled it).
    for (let i = 0; i < 20; i++) {
      await t.action(internal.memberWebauthn.registerOptions, { userId });
    }
    await expect(t.action(internal.memberWebauthn.registerOptions, { userId })).rejects.toThrow(
      /Too many attempts/,
    );
  });
});

describe('registerVerify', () => {
  test('rejects when there is no valid challenge', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedMember(t);
    await expect(
      t.action(internal.memberWebauthn.registerVerify, {
        userId,
        response: { id: 'x', rawId: 'x', response: {}, type: 'public-key' },
      }),
    ).rejects.toThrow(/No valid challenge/);
  });

  test('happy path: a verified attestation inserts the member credential + audits', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedMember(t);
    await t.run((ctx) =>
      ctx.db.insert('memberWebauthnRegistrationChallenges', {
        userId,
        challenge: 'stored-challenge',
        expiresAt: Date.now() + 60_000,
      }),
    );
    vi.mocked(verifyRegistrationResponse).mockResolvedValue({
      verified: true,
      registrationInfo: {
        credential: { id: 'new-member-cred', publicKey: new Uint8Array([1, 2, 3]), counter: 0 },
        aaguid: 'aaguid-test',
      },
    } as unknown as Awaited<ReturnType<typeof verifyRegistrationResponse>>);

    const res = await t.action(internal.memberWebauthn.registerVerify, {
      userId,
      response: { id: 'new-member-cred', rawId: 'x', response: {}, type: 'public-key' },
      deviceLabel: 'My phone',
    });
    expect(res.ok).toBe(true);
    const { creds, audit } = await t.run(async (ctx) => ({
      creds: (await ctx.db.query('memberPasskeyCredentials').collect()).filter(
        (c) => c.userId === userId,
      ),
      audit: (await ctx.db.query('auditLog').collect()).filter(
        (a) => a.action === 'account.passkey.register',
      ),
    }));
    expect(creds).toHaveLength(1);
    expect(creds[0]!.credentialId).toBe('new-member-cred');
    expect(creds[0]!.deviceLabel).toBe('My phone');
    expect(audit).toHaveLength(1);
  });
});

describe('authenticateOptions (usernameless, no-oracle, throttle)', () => {
  test('returns discoverable options (no allowCredentials) + an admin/member-blind challenge', async () => {
    const t = convexTest(schema, modules);
    await seedMember(t, { credentialId: 'cred-1' });
    const res = await t.action(internal.memberWebauthn.authenticateOptions, {});
    expect(typeof res.options.challenge).toBe('string');
    expect(typeof res.challengeId).toBe('string');
    expect(res.options.allowCredentials ?? []).toHaveLength(0);
    // The stored challenge is not tied to any user (no existence oracle).
    const row = await t.run(async (ctx) =>
      (await ctx.db.query('memberWebauthnAuthChallenges').collect()).find(
        (r) => r.challengeId === res.challengeId,
      ),
    );
    expect(row?.userId).toBeUndefined();
  });

  test('throttles per IP once the window cap is reached', async () => {
    const t = convexTest(schema, modules);
    const ipHash = await hmacSha256Hex(IP_SALT, '203.0.113.9');
    await t.run((ctx) =>
      ctx.db.insert('rateLimits', {
        bucket: `passkey.authenticate:${ipHash}`,
        count: 30, // at the cap (default max 30)
        expiresAt: Date.now() + 3_600_000,
      }),
    );
    await expect(
      t.action(internal.memberWebauthn.authenticateOptions, { ip: '203.0.113.9' }),
    ).rejects.toThrow(/Too many sign-in attempts/);
  });
});

describe('authenticateVerify', () => {
  test('rejects an invalid or expired challenge', async () => {
    const t = convexTest(schema, modules);
    await expect(
      t.action(internal.memberWebauthn.authenticateVerify, {
        challengeId: 'nope',
        response: { id: 'cred-1', rawId: 'x', response: {}, type: 'public-key' },
      }),
    ).rejects.toThrow(/Invalid or expired challenge/);
  });

  test('cross-realm isolation: an ADMIN credential id is NOT accepted by member verify', async () => {
    const t = convexTest(schema, modules);
    // Seed an admin passkey (different table) + a valid member auth challenge.
    await t.run(async (ctx) => {
      const adminId = await ctx.db.insert('adminUsers', {
        username: 'admin',
        displayName: 'admin',
        isActive: true,
        updatedAt: Date.now(),
      });
      await ctx.db.insert('passkeyCredentials', {
        adminUserId: adminId,
        credentialId: 'admin-cred',
        publicKey: 'cHVibGljLWtleQ==',
        counter: 0,
      });
      await ctx.db.insert('memberWebauthnAuthChallenges', {
        challengeId: 'ch-x',
        challenge: 'c',
        expiresAt: Date.now() + 60_000,
      });
    });
    // Picking the admin passkey at the member login fails: member verify only
    // looks in memberPasskeyCredentials, so the admin credential is "unknown".
    await expect(
      t.action(internal.memberWebauthn.authenticateVerify, {
        challengeId: 'ch-x',
        response: { id: 'admin-cred', rawId: 'x', response: {}, type: 'public-key' },
      }),
    ).rejects.toThrow(/Unknown credential/);
    // The challenge was consumed before the credential lookup (single-use).
    const row = await t.run(async (ctx) =>
      (await ctx.db.query('memberWebauthnAuthChallenges').collect()).find(
        (r) => r.challengeId === 'ch-x',
      ),
    );
    expect(row?.consumedAt).toBeTypeOf('number');
  });

  test('happy path: a verified assertion bumps the counter and mints a MEMBER session', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedMember(t, { status: 'active', credentialId: 'cred-1' });
    await t.run((ctx) =>
      ctx.db.insert('memberWebauthnAuthChallenges', {
        challengeId: 'ch-auth',
        challenge: 'stored-challenge',
        expiresAt: Date.now() + 60_000,
      }),
    );
    vi.mocked(verifyAuthenticationResponse).mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 5 },
    } as unknown as Awaited<ReturnType<typeof verifyAuthenticationResponse>>);

    const res = await t.action(internal.memberWebauthn.authenticateVerify, {
      challengeId: 'ch-auth',
      response: { id: 'cred-1', rawId: 'cred-1', response: {}, type: 'public-key' },
    });
    expect(res.ok).toBe(true);
    expect(typeof res.signedCookieValue).toBe('string');
    const { cred, sessions } = await t.run(async (ctx) => ({
      cred: (await ctx.db.query('memberPasskeyCredentials').collect()).find(
        (c) => c.credentialId === 'cred-1',
      ),
      sessions: (await ctx.db.query('sessions').collect()).filter(
        (s) => s.kind === 'member' && s.userId === userId,
      ),
    }));
    expect(cred?.counter).toBe(5);
    expect(sessions).toHaveLength(1);
  });

  test('rejects a deleted / non-lapsed-disabled account even with a valid assertion', async () => {
    const t = convexTest(schema, modules);
    await seedMember(t, { status: 'deleted', credentialId: 'cred-del' });
    await t.run((ctx) =>
      ctx.db.insert('memberWebauthnAuthChallenges', {
        challengeId: 'ch-del',
        challenge: 'c',
        expiresAt: Date.now() + 60_000,
      }),
    );
    vi.mocked(verifyAuthenticationResponse).mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 1 },
    } as unknown as Awaited<ReturnType<typeof verifyAuthenticationResponse>>);
    await expect(
      t.action(internal.memberWebauthn.authenticateVerify, {
        challengeId: 'ch-del',
        response: { id: 'cred-del', rawId: 'x', response: {}, type: 'public-key' },
      }),
    ).rejects.toThrow(/not available/);
  });
});

describe('revokeCredential (member-owned, no last-credential guard)', () => {
  test('deletes the caller own passkey + audits', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedMember(t, { credentialId: 'cred-mine' });
    const credId = await t.run(async (ctx) => {
      const row = (await ctx.db.query('memberPasskeyCredentials').collect())[0]!;
      return row._id as string;
    });
    const res = await t.mutation(internal.memberPasskeys.revokeCredential, {
      credentialId: credId,
      userId,
    });
    expect(res).toEqual({ ok: true, revoked: true });
    const remaining = await t.run((ctx) => ctx.db.query('memberPasskeyCredentials').collect());
    expect(remaining).toHaveLength(0);
  });

  test('refuses to revoke a passkey that belongs to a DIFFERENT member (no-op, no delete)', async () => {
    const t = convexTest(schema, modules);
    const { userId: owner } = await seedMember(t, { credentialId: 'cred-a' });
    const { userId: other } = await seedMember(t);
    const credId = await t.run(async (ctx) => {
      const row = (await ctx.db.query('memberPasskeyCredentials').collect()).find(
        (c) => c.userId === owner,
      )!;
      return row._id as string;
    });
    const res = await t.mutation(internal.memberPasskeys.revokeCredential, {
      credentialId: credId,
      userId: other,
    });
    expect(res).toEqual({ ok: true, revoked: false });
    // The owner credential is untouched.
    const remaining = await t.run((ctx) => ctx.db.query('memberPasskeyCredentials').collect());
    expect(remaining).toHaveLength(1);
  });
});

describe('listCredentials (masked)', () => {
  test('never returns publicKey or counter — only display fields', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedMember(t, { credentialId: 'cred-1' });
    const list = await t.query(internal.memberPasskeys.listCredentials, { userId });
    expect(list).toHaveLength(1);
    expect(list[0]).toHaveProperty('deviceLabel');
    expect(list[0]).not.toHaveProperty('publicKey');
    expect(list[0]).not.toHaveProperty('counter');
  });
});
