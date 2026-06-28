/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';

const modules = import.meta.glob('./**/*.*s');

type TestCtx = ReturnType<typeof convexTest>;

/** Seed an admin row with `passkeys` credentials; returns its id. */
async function seedAdmin(
  t: TestCtx,
  opts: { username: string; isActive?: boolean; passkeys?: number },
): Promise<Id<'adminUsers'>> {
  const { username, isActive = true, passkeys = 1 } = opts;
  return await t.run(async (ctx) => {
    const adminId = await ctx.db.insert('adminUsers', {
      username,
      displayName: username,
      isActive,
      updatedAt: 0,
    });
    for (let i = 0; i < passkeys; i++) {
      await ctx.db.insert('passkeyCredentials', {
        adminUserId: adminId,
        credentialId: `${username}-cred-${i}`,
        publicKey: 'pk',
        counter: 0,
        deviceLabel: `dev-${i}`,
      });
    }
    return adminId;
  });
}

const firstCredOf = (t: TestCtx, adminId: Id<'adminUsers'>) =>
  t.run(async (ctx) => {
    // withIndex isn't typed inside t.run's generic ctx; the table is tiny.
    const all = await ctx.db.query('passkeyCredentials').collect();
    return all.find((r) => r.adminUserId === adminId)!._id;
  });

describe('admins.setAdminActive (last-admin guard)', () => {
  test('the last admin who can sign in cannot be deactivated', async () => {
    const t = convexTest(schema, modules);
    const only = await seedAdmin(t, { username: 'solo', passkeys: 1 });
    await expect(
      t.mutation(internal.admins.setAdminActive, {
        adminUserId: only,
        isActive: false,
        actorAdminId: only,
      }),
    ).rejects.toThrow(/last admin/i);
    expect((await t.run((ctx) => ctx.db.get(only)))!.isActive).toBe(true);
  });

  test('with two effective admins, one can be deactivated (audited)', async () => {
    const t = convexTest(schema, modules);
    const a = await seedAdmin(t, { username: 'a' });
    const b = await seedAdmin(t, { username: 'b' });
    const res = await t.mutation(internal.admins.setAdminActive, {
      adminUserId: b,
      isActive: false,
      actorAdminId: a,
    });
    expect(res.isActive).toBe(false);
    expect((await t.run((ctx) => ctx.db.get(b)))!.isActive).toBe(false);
    const audits = await t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .filter((q) => q.eq(q.field('action'), 'admin.admin.deactivate'))
        .collect(),
    );
    expect(audits).toHaveLength(1);
    expect((audits[0]!.payload as Record<string, unknown>).username).toBe('b');
  });

  test('reactivation is unguarded; deactivating the now-last is blocked', async () => {
    const t = convexTest(schema, modules);
    const a = await seedAdmin(t, { username: 'a' });
    const b = await seedAdmin(t, { username: 'b' });
    await t.mutation(internal.admins.setAdminActive, {
      adminUserId: b,
      isActive: false,
      actorAdminId: a,
    });
    // a is now the last effective admin → cannot be deactivated.
    await expect(
      t.mutation(internal.admins.setAdminActive, {
        adminUserId: a,
        isActive: false,
        actorAdminId: a,
      }),
    ).rejects.toThrow(/last admin/i);
    // b can always be reactivated.
    const res = await t.mutation(internal.admins.setAdminActive, {
      adminUserId: b,
      isActive: true,
      actorAdminId: a,
    });
    expect(res.isActive).toBe(true);
  });

  test('no-op when unchanged writes no audit', async () => {
    const t = convexTest(schema, modules);
    const a = await seedAdmin(t, { username: 'a' });
    await seedAdmin(t, { username: 'b' });
    await t.mutation(internal.admins.setAdminActive, {
      adminUserId: a,
      isActive: true,
      actorAdminId: a,
    });
    expect(await t.run((ctx) => ctx.db.query('auditLog').collect())).toHaveLength(0);
  });

  test('an INACTIVE admin (even with a passkey) is not "effective"', async () => {
    const t = convexTest(schema, modules);
    const active = await seedAdmin(t, { username: 'active', passkeys: 1 });
    await seedAdmin(t, { username: 'inactive', isActive: false, passkeys: 1 });
    await expect(
      t.mutation(internal.admins.setAdminActive, {
        adminUserId: active,
        isActive: false,
        actorAdminId: active,
      }),
    ).rejects.toThrow(/last admin/i);
  });

  test('an active admin with NO passkey is not "effective"', async () => {
    const t = convexTest(schema, modules);
    const withKey = await seedAdmin(t, { username: 'withkey', passkeys: 1 });
    await seedAdmin(t, { username: 'nokey', passkeys: 0 });
    await expect(
      t.mutation(internal.admins.setAdminActive, {
        adminUserId: withKey,
        isActive: false,
        actorAdminId: withKey,
      }),
    ).rejects.toThrow(/last admin/i);
  });
});

describe('admins.revokeCredential (last-admin guard)', () => {
  test('the last passkey of the last admin cannot be revoked', async () => {
    const t = convexTest(schema, modules);
    const only = await seedAdmin(t, { username: 'solo', passkeys: 1 });
    const cred = await firstCredOf(t, only);
    await expect(
      t.mutation(internal.admins.revokeCredential, { credentialId: cred, actorAdminId: only }),
    ).rejects.toThrow(/last passkey/i);
    expect(await t.run((ctx) => ctx.db.query('passkeyCredentials').collect())).toHaveLength(1);
  });

  test('ok when the owner has a second passkey (audited)', async () => {
    const t = convexTest(schema, modules);
    const a = await seedAdmin(t, { username: 'a', passkeys: 2 });
    const cred = await firstCredOf(t, a);
    const res = await t.mutation(internal.admins.revokeCredential, {
      credentialId: cred,
      actorAdminId: a,
    });
    expect(res.revoked).toBe(true);
    expect(await t.run((ctx) => ctx.db.query('passkeyCredentials').collect())).toHaveLength(1);
    const audits = await t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .filter((q) => q.eq(q.field('action'), 'admin.passkey.revoke'))
        .collect(),
    );
    expect(audits).toHaveLength(1);
  });

  test('ok when another effective admin exists; re-revoke is a no-op', async () => {
    const t = convexTest(schema, modules);
    const a = await seedAdmin(t, { username: 'a', passkeys: 1 });
    await seedAdmin(t, { username: 'b', passkeys: 1 });
    const credA = await firstCredOf(t, a);
    const res = await t.mutation(internal.admins.revokeCredential, {
      credentialId: credA,
      actorAdminId: a,
    });
    expect(res.revoked).toBe(true);
    const res2 = await t.mutation(internal.admins.revokeCredential, {
      credentialId: credA,
      actorAdminId: a,
    });
    expect(res2.revoked).toBe(false); // already gone → no-op, not an error
  });
});

describe('admins.listCredentials', () => {
  test('returns only masked display fields (never publicKey/counter)', async () => {
    const t = convexTest(schema, modules);
    const a = await seedAdmin(t, { username: 'a', passkeys: 1 });
    const list = await t.query(internal.admins.listCredentials, { adminUserId: a });
    expect(list).toHaveLength(1);
    expect(list[0]).toHaveProperty('deviceLabel', 'dev-0');
    expect(list[0]).not.toHaveProperty('publicKey');
    expect(list[0]).not.toHaveProperty('counter');
  });
});
