/// <reference types="vite/client" />
/**
 * Coverage for the previously-untested support modules: the remnawaveNodes
 * stats writer + stampede guard, the keyRevocations store, and the member
 * passkey management module (memberPasskeys.ts — the ceremonies live in
 * memberWebauthn.test.ts).
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';

const modules = import.meta.glob('./**/*.*s');

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

async function seedServer(t: ReturnType<typeof convexTest>): Promise<Id<'backendServers'>> {
  return t.run((ctx) =>
    ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'n1',
      slug: 'n1',
      config: { type: 'remnawave', baseUrl: 'https://panel.test', apiToken: 'tok' },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: Date.now(),
    }),
  );
}

describe('remnawaveNodes.markNodeStats', () => {
  test('inserts then upserts by placement (latest snapshot wins)', async () => {
    const t = convexTest(schema, modules);
    const serverId = await seedServer(t);
    const node = {
      placement: 'sq-1',
      label: 'Node A',
      usersOnline: 5,
      online: true,
      nodeCount: 1,
    };
    await t.mutation(internal.remnawaveNodes.markNodeStats, {
      backendServerId: serverId,
      nodes: [node],
    });
    await t.mutation(internal.remnawaveNodes.markNodeStats, {
      backendServerId: serverId,
      nodes: [{ ...node, usersOnline: 42 }],
    });
    const rows = await t.run((ctx) => ctx.db.query('remnawaveNodeStats').collect());
    expect(rows).toHaveLength(1);
    expect(rows[0]!.usersOnline).toBe(42);
    expect(rows[0]!.backendServerId).toBe(serverId);
    expect(rows[0]!.lastStatsAt).toBeGreaterThan(0);
    // And the per-placement read the member node-status path uses resolves.
    const one = await t.query(internal.remnawaveNodes.getPlacementStats, { placement: 'sq-1' });
    expect(one?.usersOnline).toBe(42);
  });
});

describe('remnawaveNodes.claimStatsRefresh (stampede guard)', () => {
  test('only the FIRST claim inside the window wins; a later window re-allows', async () => {
    const t = convexTest(schema, modules);
    const serverId = await seedServer(t);
    const freshMs = 60_000;
    expect(
      await t.mutation(internal.remnawaveNodes.claimStatsRefresh, {
        backendServerId: serverId,
        freshMs,
      }),
    ).toBe(true);
    // Held: concurrent pollers in the same window lose (≤1 panel sweep per window).
    expect(
      await t.mutation(internal.remnawaveNodes.claimStatsRefresh, {
        backendServerId: serverId,
        freshMs,
      }),
    ).toBe(false);
    expect(
      await t.mutation(internal.remnawaveNodes.claimStatsRefresh, {
        backendServerId: serverId,
        freshMs,
      }),
    ).toBe(false);
    // A zero-width window means the claim is already stale → re-allowed.
    expect(
      await t.mutation(internal.remnawaveNodes.claimStatsRefresh, {
        backendServerId: serverId,
        freshMs: 0,
      }),
    ).toBe(true);
  });
});

describe('keyRevocations', () => {
  test('current is the highest version (never an older, kid-omitting list)', async () => {
    const t = convexTest(schema, modules);
    const insert = (version: number, kids: string[]) =>
      t.mutation(internal.keyRevocations.insert, {
        version,
        revokedKids: kids,
        notAfter: Date.now() + 86_400_000,
        manifestSig: `sig-${version}`,
      });
    await insert(3, ['kid-c']);
    await insert(1, ['kid-a']);
    await insert(2, ['kid-b']);
    const current = await t.query(internal.keyRevocations.current, {});
    expect(current?.version).toBe(3);
    expect(current?.revokedKids).toEqual(['kid-c']);
  });

  test('empty store reads null (no revocation in force)', async () => {
    const t = convexTest(schema, modules);
    expect(await t.query(internal.keyRevocations.current, {})).toBeNull();
  });
});

describe('memberPasskeys management', () => {
  test('insert is uniqueness-checked (a dup credentialId throws)', async () => {
    const t = convexTest(schema, modules);
    const userId = await seedUser(t);
    const base = { userId, credentialId: 'cred-1', publicKey: 'pk', counter: 0 };
    await t.mutation(internal.memberPasskeys.insertCredential, base);
    await expect(t.mutation(internal.memberPasskeys.insertCredential, base)).rejects.toThrow(
      /collision/,
    );
  });

  test('listCredentials masks secrets; credentialIdsByUser + counter bump work', async () => {
    const t = convexTest(schema, modules);
    const userId = await seedUser(t);
    await t.mutation(internal.memberPasskeys.insertCredential, {
      userId,
      credentialId: 'cred-2',
      publicKey: 'pk-secret',
      counter: 3,
      deviceLabel: 'Phone',
    });
    const list = await t.query(internal.memberPasskeys.listCredentials, { userId });
    expect(list).toHaveLength(1);
    expect(list[0]!.deviceLabel).toBe('Phone');
    expect(JSON.stringify(list)).not.toContain('pk-secret');
    expect(await t.query(internal.memberPasskeys.credentialIdsByUser, { userId })).toEqual([
      'cred-2',
    ]);
    await t.mutation(internal.memberPasskeys.bumpCredentialCounter, {
      credentialId: 'cred-2',
      newCounter: 4,
    });
    const cred = await t.query(internal.memberPasskeys.credentialByCredentialId, {
      credentialId: 'cred-2',
    });
    expect(cred?.counter).toBe(4);
    expect(cred?.lastUsedAt).toBeTypeOf('number');
  });

  test("revoke deletes only the caller's own credential (foreign is a silent no-op) and audits", async () => {
    const t = convexTest(schema, modules);
    const userId = await seedUser(t);
    const otherId = await seedUser(t);
    await t.mutation(internal.memberPasskeys.insertCredential, {
      userId,
      credentialId: 'cred-3',
      publicKey: 'pk',
      counter: 0,
      deviceLabel: 'Laptop',
    });
    const cred = (await t.query(internal.memberPasskeys.listCredentials, { userId }))[0]!.id;
    // A FOREIGN member can't revoke it (no existence oracle).
    expect(
      await t.mutation(internal.memberPasskeys.revokeCredential, {
        credentialId: cred,
        userId: otherId,
      }),
    ).toEqual({ ok: true, revoked: false });
    expect(await t.query(internal.memberPasskeys.credentialIdsByUser, { userId })).toHaveLength(1);
    // The owner can — once (idempotent).
    expect(
      await t.mutation(internal.memberPasskeys.revokeCredential, {
        credentialId: cred,
        userId,
      }),
    ).toEqual({ ok: true, revoked: true });
    expect(await t.query(internal.memberPasskeys.credentialIdsByUser, { userId })).toHaveLength(0);
    expect(
      await t.mutation(internal.memberPasskeys.revokeCredential, {
        credentialId: cred,
        userId,
      }),
    ).toEqual({ ok: true, revoked: false });
    await t.run(async (ctx) => {
      const audits = await ctx.db.query('auditLog').collect();
      const revoke = audits.find((a) => a.action === 'account.passkey.revoke');
      expect(revoke?.actorId).toBe(userId);
    });
  });

  test('auth challenges are single-use and expire', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.memberPasskeys.insertAuthChallenge, {
      challengeId: 'ch-1',
      challenge: 'c',
      ttlMs: 60_000,
    });
    expect(
      await t.mutation(internal.memberPasskeys.consumeAuthChallenge, { challengeId: 'ch-1' }),
    ).toEqual({ challenge: 'c' });
    // Consumed → gone for good.
    expect(
      await t.mutation(internal.memberPasskeys.consumeAuthChallenge, { challengeId: 'ch-1' }),
    ).toBeNull();
    // Already-expired → null.
    await t.mutation(internal.memberPasskeys.insertAuthChallenge, {
      challengeId: 'ch-2',
      challenge: 'c2',
      ttlMs: -1,
    });
    expect(
      await t.mutation(internal.memberPasskeys.consumeAuthChallenge, { challengeId: 'ch-2' }),
    ).toBeNull();
  });
});
