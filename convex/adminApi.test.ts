/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { maskApiUrl } from './adminApi';
import { resolveTheme } from './lib/themeConfig';
import { resolveModeSquadPool } from './lib/remnawavePlacement';
import { UserAdmin, AdminStatusSummary } from '../src/shared/contracts/admin';

const modules = import.meta.glob('./**/*.*s');

/** Full TierUpsert payload (description is required-nullable). */
function tierUpsert(overrides: Record<string, unknown> = {}) {
  return {
    slug: 'pro',
    name: 'Pro',
    description: null,
    backend: 'remnawave' as const,
    monthlyTrafficGb: 100,
    deviceLimit: 2,
    hwidLimit: 2,
    hwidEnabled: false,
    trafficStrategy: 'MONTH' as const,
    isDefaultFree: false,
    isActive: true,
    priority: 5,
    expirationDaysAfterMembershipLapse: 7,
    ...overrides,
  };
}

describe('adminApi tiers', () => {
  test('createTier then tiersList contains it (mapped shape)', async () => {
    const t = convexTest(schema, modules);
    const created = await t.mutation(internal.adminApi.createTier, tierUpsert());
    expect(created.slug).toBe('pro');
    expect(created.id).toBeTruthy();
    expect(created.createdAt).toMatch(/^\d{4}-\d{2}-\d{2}T/); // ISO timestamp
    expect(created.description).toBeNull();

    const { tiers } = await t.query(internal.adminApi.tiersList, {});
    expect(tiers.map((x) => x.slug)).toContain('pro');
  });

  test('duplicate slug throws', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.adminApi.createTier, tierUpsert({ slug: 'dup' }));
    await expect(
      t.mutation(internal.adminApi.createTier, tierUpsert({ slug: 'dup', name: 'Other' })),
    ).rejects.toThrow(/already exists/);
  });

  test('updateTier patches selected fields', async () => {
    const t = convexTest(schema, modules);
    const created = await t.mutation(internal.adminApi.createTier, tierUpsert({ slug: 'patchme' }));
    const updated = await t.mutation(internal.adminApi.updateTier, {
      id: created.id as never,
      name: 'Renamed',
      monthlyTrafficGb: 999,
    });
    expect(updated.name).toBe('Renamed');
    expect(updated.monthlyTrafficGb).toBe(999);
    expect(updated.slug).toBe('patchme'); // unchanged
  });

  test('updateTier can null out description', async () => {
    const t = convexTest(schema, modules);
    const created = await t.mutation(
      internal.adminApi.createTier,
      tierUpsert({ slug: 'desc', description: 'has one' }),
    );
    expect(created.description).toBe('has one');
    const updated = await t.mutation(internal.adminApi.updateTier, {
      id: created.id as never,
      description: null,
    });
    expect(updated.description).toBeNull();
  });

  test('deleteTier removes the row', async () => {
    const t = convexTest(schema, modules);
    const created = await t.mutation(internal.adminApi.createTier, tierUpsert({ slug: 'gone' }));
    await t.mutation(internal.adminApi.deleteTier, { id: created.id as never });
    const { tiers } = await t.query(internal.adminApi.tiersList, {});
    expect(tiers.map((x) => x.slug)).not.toContain('gone');
  });
});

describe('adminApi upsertTierBySlug', () => {
  test('minimal {slug} creates with safe defaults; re-run patches (idempotent)', async () => {
    const t = convexTest(schema, modules);
    const created = await t.mutation(internal.adminApi.upsertTierBySlug, { slug: 'premium' });
    expect(created.created).toBe(true);
    expect(created.name).toBe('premium'); // name defaults to slug
    expect(created.backend).toBe('remnawave'); // default backend
    expect(created.isDefaultFree).toBe(false); // never silently steal the default
    expect(created.isActive).toBe(true);

    // Re-run patches one field → not created, exactly one row (idempotent).
    const updated = await t.mutation(internal.adminApi.upsertTierBySlug, {
      slug: 'premium',
      name: 'Premium',
      priority: 9,
    });
    expect(updated.created).toBe(false);
    expect(updated.name).toBe('Premium');
    expect(updated.priority).toBe(9);
    const rows = await t.run((ctx) => ctx.db.query('tiers').collect());
    expect(rows.filter((r) => r.slug === 'premium')).toHaveLength(1);
  });

  test('isDefaultFree:true via upsert clears the peer default on the same backend', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(
      internal.adminApi.createTier,
      tierUpsert({ slug: 'free-a', backend: 'remnawave', isDefaultFree: true }),
    );
    // Upsert a second remnawave tier as the default → the first must be cleared.
    await t.mutation(internal.adminApi.upsertTierBySlug, {
      slug: 'free-b',
      backend: 'remnawave',
      isDefaultFree: true,
    });
    const rows = await t.run((ctx) => ctx.db.query('tiers').collect());
    const defaults = rows.filter((r) => r.backend === 'remnawave' && r.isDefaultFree);
    expect(defaults).toHaveLength(1);
    expect(defaults[0]!.slug).toBe('free-b');
  });
});

describe('mirrorProviders upsertByName', () => {
  const provider = (overrides: Record<string, unknown> = {}) => ({
    name: 'r2-eu',
    endpoint: 'https://r2.example.com',
    bucket: 'subs',
    publicUrl: 'https://cdn.example.com',
    accessKeyId: 'AKIA-public',
    secretAccessKey: 'super-secret',
    ...overrides,
  });

  test('creates on first call, then keeps the secret on a blank re-run (idempotent)', async () => {
    const t = convexTest(schema, modules);
    const created = await t.mutation(internal.mirrorProviders.upsertByName, provider());
    expect(created.created).toBe(true);
    expect(created.secretAccessKeySet).toBe(true);

    const updated = await t.mutation(internal.mirrorProviders.upsertByName, {
      name: 'r2-eu',
      publicUrl: 'https://cdn2.example.com',
      // no secret → keep the stored one
    });
    expect(updated.created).toBe(false);
    expect(updated.publicUrl).toBe('https://cdn2.example.com');

    const rows = await t.run((ctx) => ctx.db.query('mirrorProviders').collect());
    expect(rows).toHaveLength(1);
    expect(rows[0]!.secretAccessKey).toBe('super-secret'); // survived the blank re-run
  });

  test('refuses to create a new provider without full credentials', async () => {
    const t = convexTest(schema, modules);
    await expect(
      t.mutation(internal.mirrorProviders.upsertByName, { name: 'incomplete', bucket: 'x' }),
    ).rejects.toThrow(/needs endpoint|required/i);
  });
});

describe('adminApi usersSearch', () => {
  test('returns seeded users in the UserAdmin shape', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
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
      await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      await ctx.db.insert('users', { tierId, status: 'disabled', updatedAt: Date.now() });
    });

    const all = await t.query(internal.adminApi.usersSearch, {});
    expect(all.users.length).toBe(2);
    const row = all.users[0]!;
    // Contract shape: id, status, tierSlug, createdAt, backend, etc.
    expect(row).toHaveProperty('id');
    expect(row).toHaveProperty('status');
    expect(row.tierSlug).toBe('free');
    expect(row).toHaveProperty('createdAt');
    expect(row.backend).toBeNull(); // no subscription yet
  });

  test('status filter narrows the result set', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
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
      await ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() });
      await ctx.db.insert('users', { tierId, status: 'disabled', updatedAt: Date.now() });
    });
    const disabled = await t.query(internal.adminApi.usersSearch, { status: 'disabled' });
    expect(disabled.users).toHaveLength(1);
    expect(disabled.users[0]!.status).toBe('disabled');
  });

  // Review #4: a sparse post-filter must not truncate. With limit=2 (scan window
  // = 8), the only matching rows sit PAST the first window; the continuation loop
  // must still find them, not return an empty page with a null cursor (the old
  // single over-fetch did exactly that).
  test('a sparse filter with matches beyond the first scan window is not truncated', async () => {
    const t = convexTest(schema, modules);
    const drifted = await t.run(async (ctx) => {
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
      // Two drifted users FIRST (oldest _creationTime, so desc-order puts them last)…
      const d1 = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        backendPushFailedAt: Date.now(),
        updatedAt: Date.now(),
      });
      const d2 = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        backendPushFailedAt: Date.now(),
        updatedAt: Date.now(),
      });
      // …then 10 non-drift users (newer), so the drift rows fall past the first
      // window of 8 (= limit*4).
      for (let i = 0; i < 10; i++) {
        await ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() });
      }
      return [d1, d2];
    });

    const res = await t.query(internal.adminApi.usersSearch, { drift: true, limit: 2 });
    expect(res.users).toHaveLength(2);
    expect(new Set(res.users.map((u) => u.id))).toEqual(new Set(drifted));
  });

  test('drift filter + statusSummary count track the backend push-drift flag', async () => {
    const t = convexTest(schema, modules);
    const drifted = await t.run(async (ctx) => {
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
      const id = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        backendPushFailedAt: Date.now(),
        updatedAt: Date.now(),
      });
      await ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() });
      return id;
    });
    // Rows seeded directly (no transition bumps) → reconcile builds the counter
    // statusSummary reads. Mirrors the deploy flow (backfill → reconcile).
    await t.action(internal.userStats.reconcileUserCounts, {});

    // Only the flagged user matches drift=true, and the row carries the stamp.
    const drift = await t.query(internal.adminApi.usersSearch, { drift: true });
    expect(drift.users).toHaveLength(1);
    expect(drift.users[0]!.id).toBe(drifted);
    expect(drift.users[0]!.backendPushFailedAt).not.toBeNull();
    expect((await t.query(internal.adminApi.statusSummary, {})).backendDrift).toBe(1);

    // Clearing the flag drops it from both surfaces (and is idempotent).
    await t.mutation(internal.lifecycle.setBackendDrift, { userId: drifted, failed: false });
    expect((await t.query(internal.adminApi.usersSearch, { drift: true })).users).toHaveLength(0);
    expect((await t.query(internal.adminApi.statusSummary, {})).backendDrift).toBe(0);
  });
});

// Ties the SERVER output to the CLIENT zod contract, in CI. The admin pages
// zod-validate every response and hard-error ("Something went wrong") on any
// mismatch, so a mapUser/statusSummary field that drifts from the contract
// (a required field the server omits, or a shape the client rejects) is a
// user-visible outage the matched-version unit tests otherwise miss.
describe('adminApi ↔ client contract agreement', () => {
  test('usersSearch rows + statusSummary parse against the client contract', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
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
      // One drifted (backendPushFailedAt set) + one clean, so both branches of
      // the optional field are exercised against the contract.
      await ctx.db.insert('users', {
        tierId,
        status: 'active',
        membershipExpiresAt: Date.now() + 86_400_000,
        backendPushFailedAt: Date.now(),
        updatedAt: Date.now(),
      });
      await ctx.db.insert('users', { tierId, status: 'grace', updatedAt: Date.now() });
    });

    const { users } = await t.query(internal.adminApi.usersSearch, {});
    expect(users).toHaveLength(2);
    // Throws (failing the test) if any row violates the client's UserAdmin shape.
    for (const u of users) UserAdmin.parse(u);

    const summary = await t.query(internal.adminApi.statusSummary, {});
    AdminStatusSummary.parse(summary);
  });
});

describe('adminApi reEnableUser', () => {
  const freeTier = {
    slug: 'free',
    name: 'Free',
    backend: 'remnawave' as const,
    monthlyTrafficGb: 50,
    deviceLimit: 1,
    hwidLimit: 1,
    hwidEnabled: true,
    trafficStrategy: 'MONTH' as const,
    isDefaultFree: true,
    isActive: true,
    priority: 0,
    expirationDaysAfterMembershipLapse: 0,
  };

  test('flips a disabled user back to active and clears the suspension fields', async () => {
    const t = convexTest(schema, modules);
    const userId = await t.run(async (ctx) => {
      const tierId = await ctx.db.insert('tiers', { ...freeTier, updatedAt: Date.now() });
      return ctx.db.insert('users', {
        tierId,
        status: 'disabled',
        disabledReason: 'admin_action',
        suspendedAt: Date.now(),
        updatedAt: Date.now(),
      });
    });

    await t.mutation(internal.adminApi.reEnableUser, { userId });

    const user = await t.run((ctx) => ctx.db.get(userId));
    expect(user?.status).toBe('active');
    expect(user?.disabledReason).toBeUndefined();
    expect(user?.suspendedAt).toBeUndefined();
  });

  test('is a no-op for a user who is not disabled', async () => {
    const t = convexTest(schema, modules);
    const userId = await t.run(async (ctx) => {
      const tierId = await ctx.db.insert('tiers', { ...freeTier, updatedAt: Date.now() });
      return ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() });
    });

    await t.mutation(internal.adminApi.reEnableUser, { userId });

    const user = await t.run((ctx) => ctx.db.get(userId));
    expect(user?.status).toBe('active');
  });
});

describe('adminApi mintAutomationToken', () => {
  test('mints a service token attributed to a credential-less automation admin', async () => {
    const t = convexTest(schema, modules);
    const res = await t.action(internal.adminApi.mintAutomationToken, {
      scopes: ['admin:servers:read', 'admin:servers:write'],
    });
    expect(res.plaintext.startsWith('fsv1_')).toBe(true);
    expect(res.prefix.startsWith('fsv1_')).toBe(true);
    expect(res.scopes).toEqual(['admin:servers:read', 'admin:servers:write']);

    const tok = await t.run((ctx) => ctx.db.get(res.id));
    expect(tok?.subjectType).toBe('service');
    expect(tok?.createdByAdminId).toBe(res.adminUserId);
    expect(tok?.scopes).toEqual(['admin:servers:read', 'admin:servers:write']);

    // The synthetic admin exists but has NO passkey — it can never log in.
    const admin = await t.run((ctx) => ctx.db.get(res.adminUserId));
    expect(admin?.username).toBe('automation');
    const creds = await t.run((ctx) =>
      ctx.db
        .query('passkeyCredentials')
        .withIndex('by_admin', (q) => q.eq('adminUserId', res.adminUserId))
        .collect(),
    );
    expect(creds).toHaveLength(0);

    // The mint is audited (no secret — name + scope count only).
    const audit = await t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .withIndex('by_action', (q) => q.eq('action', 'admin.automation_token.mint'))
        .collect(),
    );
    expect(audit).toHaveLength(1);
    expect(audit[0]!.payload).toMatchObject({ scopeCount: 2 });
  });

  test('reuses the same automation admin across calls (idempotent)', async () => {
    const t = convexTest(schema, modules);
    const a = await t.action(internal.adminApi.mintAutomationToken, {
      scopes: ['admin:servers:write'],
    });
    const b = await t.action(internal.adminApi.mintAutomationToken, {
      scopes: ['admin:users:read'],
    });
    expect(a.adminUserId).toBe(b.adminUserId);
    const admins = await t.run((ctx) =>
      ctx.db
        .query('adminUsers')
        .withIndex('by_username', (q) => q.eq('username', 'automation'))
        .collect(),
    );
    expect(admins).toHaveLength(1);
  });

  test('rejects member scopes, unknown scopes, and an empty list', async () => {
    const t = convexTest(schema, modules);
    await expect(
      t.action(internal.adminApi.mintAutomationToken, { scopes: ['account:read'] }),
    ).rejects.toThrow(/non-admin|invalid/i);
    await expect(
      t.action(internal.adminApi.mintAutomationToken, { scopes: ['admin:bogus:read'] }),
    ).rejects.toThrow(/invalid|non-admin/i);
    await expect(t.action(internal.adminApi.mintAutomationToken, { scopes: [] })).rejects.toThrow(
      /at least one scope/i,
    );
  });
});

describe('adminApi upsertBackendServerBySlug', () => {
  test('creates on first call, updates on re-run keeping the secret on blank', async () => {
    const t = convexTest(schema, modules);

    const created = await t.mutation(internal.adminApi.upsertBackendServerBySlug, {
      slug: 'node-a',
      backend: 'remnawave',
      name: 'Node A',
      baseUrl: 'https://panel.example',
      apiToken: 'secret-token-1',
    });
    expect(created.created).toBe(true);
    expect(created.slug).toBe('node-a');

    // Re-run with a new name and NO apiToken (blank) → updates, keeps the secret.
    const updated = await t.mutation(internal.adminApi.upsertBackendServerBySlug, {
      slug: 'node-a',
      backend: 'remnawave',
      name: 'Node A (renamed)',
      baseUrl: 'https://panel.example',
    });
    expect(updated.created).toBe(false);
    expect(updated.name).toBe('Node A (renamed)');

    // Exactly one row (idempotent); the stored apiToken survived the blank re-run.
    const rows = await t.run((ctx) => ctx.db.query('backendServers').collect());
    expect(rows).toHaveLength(1);
    const cfg = rows[0]!.config;
    expect(cfg.type).toBe('remnawave');
    if (cfg.type === 'remnawave') expect(cfg.apiToken).toBe('secret-token-1');
  });

  test('rejects changing the backend type of an existing slug', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.adminApi.upsertBackendServerBySlug, {
      slug: 'node-b',
      backend: 'remnawave',
      baseUrl: 'https://panel.example',
      apiToken: 'tok',
    });
    await expect(
      t.mutation(internal.adminApi.upsertBackendServerBySlug, {
        slug: 'node-b',
        backend: 'outline',
        apiUrl: 'https://outline.example/secret',
      }),
    ).rejects.toThrow(/cannot change it to|exists as type/i);
  });

  test('deleteBackendServerBySlug removes by slug; idempotent no-op when absent', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.adminApi.upsertBackendServerBySlug, {
      slug: 'node-d',
      backend: 'remnawave',
      baseUrl: 'https://panel.example',
      apiToken: 'tok',
    });
    const del1 = await t.mutation(internal.adminApi.deleteBackendServerBySlug, { slug: 'node-d' });
    expect(del1.deleted).toBe(true);
    expect(await t.run((ctx) => ctx.db.query('backendServers').collect())).toHaveLength(0);
    const del2 = await t.mutation(internal.adminApi.deleteBackendServerBySlug, { slug: 'node-d' });
    expect(del2.deleted).toBe(false); // re-run = no-op, not an error
  });
});

describe('adminApi grantMembership', () => {
  const memberTierRow = {
    slug: 'member',
    name: 'Member',
    backend: 'remnawave' as const,
    monthlyTrafficGb: 0,
    deviceLimit: 0,
    hwidLimit: 0,
    hwidEnabled: false,
    trafficStrategy: 'MONTH' as const,
    isDefaultFree: false,
    isActive: true,
    priority: 10,
    expirationDaysAfterMembershipLapse: 7,
  };

  test('grants a tier, extends expiry, re-activates a disabled user, and audits', async () => {
    const t = convexTest(schema, modules);
    const { memberTier, userId } = await t.run(async (ctx) => {
      const free = await ctx.db.insert('tiers', {
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
      const member = await ctx.db.insert('tiers', { ...memberTierRow, updatedAt: Date.now() });
      const u = await ctx.db.insert('users', {
        tierId: free,
        status: 'disabled',
        disabledReason: 'admin_action',
        updatedAt: Date.now(),
      });
      return { memberTier: member, userId: u };
    });

    const before = Date.now();
    const res = await t.mutation(internal.adminApi.grantMembership, {
      userId,
      tierId: memberTier,
      durationDays: 30,
    });
    expect(res.ok).toBe(true);

    const user = await t.run((ctx) => ctx.db.get(userId));
    expect(user?.tierId).toBe(memberTier);
    expect(user?.status).toBe('active'); // lapsed → re-activated
    expect(user!.membershipExpiresAt!).toBeGreaterThanOrEqual(before + 30 * 86_400_000);

    const audit = await t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .withIndex('by_action', (q) => q.eq('action', 'admin.user.grant_membership'))
        .collect(),
    );
    expect(audit).toHaveLength(1);
    expect(audit[0]!.payload).toMatchObject({ durationDays: 30 });
  });

  test('rejects an out-of-range durationDays', async () => {
    const t = convexTest(schema, modules);
    const { memberTier, userId } = await t.run(async (ctx) => {
      const member = await ctx.db.insert('tiers', { ...memberTierRow, updatedAt: Date.now() });
      const u = await ctx.db.insert('users', {
        tierId: member,
        status: 'active',
        updatedAt: Date.now(),
      });
      return { memberTier: member, userId: u };
    });
    await expect(
      t.mutation(internal.adminApi.grantMembership, {
        userId,
        tierId: memberTier,
        durationDays: 0,
      }),
    ).rejects.toThrow(/durationDays/);
    await expect(
      t.mutation(internal.adminApi.grantMembership, {
        userId,
        tierId: memberTier,
        durationDays: 99999,
      }),
    ).rejects.toThrow(/durationDays/);
  });
});

describe('adminApi statusSummary', () => {
  test('tallies users by status and summarizes backend health (no secrets)', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
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
      await ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() });
      await ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() });
      await ctx.db.insert('users', { tierId, status: 'disabled', updatedAt: Date.now() });
      await ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'Primary',
        slug: 'p1',
        config: { type: 'remnawave', baseUrl: 'https://panel', apiToken: 'secret' },
        isActive: true,
        priority: 0,
        keyCount: 5,
        lastHealthOkAt: Date.now(),
        lastHealthRttMs: 12,
        updatedAt: Date.now(),
      });
    });

    await t.action(internal.userStats.reconcileUserCounts, {});
    const s = await t.query(internal.adminApi.statusSummary, {});
    expect(s.users.active).toBe(2);
    expect(s.users.disabled).toBe(1);
    expect(s.totals.backends).toBe(1);
    expect(s.totals.activeBackends).toBe(1);
    expect(s.totals.healthyBackends).toBe(1);
    expect(s.totals.keys).toBe(5);
    expect(s.backends[0]!.slug).toBe('p1');
    expect(s.backends[0]!.healthy).toBe(true);
    // The secret config must never appear in the status payload.
    expect(JSON.stringify(s)).not.toContain('secret');
    expect(s.healthcheck.ok).toBe(true);
    expect(typeof s.generatedAt).toBe('string');
  });

  test('pop readiness counts bound vs cookie-only active sessions (excludes expired)', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
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
        updatedAt: Date.now(),
      });
      const future = Date.now() + 3_600_000;
      // 1 bound member, 1 cookie-only member, 1 cookie-only admin, 1 expired (ignored).
      await ctx.db.insert('sessions', {
        sid: 's-bound',
        kind: 'member',
        userId,
        expiresAt: future,
        popPublicKey: 'AAAA',
        popAlg: 'EdDSA',
      });
      await ctx.db.insert('sessions', {
        sid: 's-unbound-m',
        kind: 'member',
        userId,
        expiresAt: future,
      });
      await ctx.db.insert('sessions', { sid: 's-unbound-a', kind: 'admin', expiresAt: future });
      await ctx.db.insert('sessions', {
        sid: 's-expired',
        kind: 'member',
        userId,
        expiresAt: Date.now() - 1_000,
      });
    });

    const s = await t.query(internal.adminApi.statusSummary, {});
    expect(s.pop.activeSessions).toBe(3); // the expired row is not counted
    expect(s.pop.bound).toBe(1);
    expect(s.pop.unbound).toBe(2);
    expect(s.pop.unboundMember).toBe(1);
    expect(s.pop.unboundAdmin).toBe(1);
    expect(s.pop.readyToEnable).toBe(false); // cookie-only sessions would be locked out
    expect(s.pop.required).toBe(false); // POP_REQUIRED unset in tests
  });

  test('pop readiness: readyToEnable once every active session is key-bound', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
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
        updatedAt: Date.now(),
      });
      const future = Date.now() + 3_600_000;
      await ctx.db.insert('sessions', {
        sid: 'b1',
        kind: 'member',
        userId,
        expiresAt: future,
        popPublicKey: 'AAAA',
        popAlg: 'EdDSA',
      });
      await ctx.db.insert('sessions', {
        sid: 'b2',
        kind: 'admin',
        expiresAt: future,
        popPublicKey: 'BBBB',
        popAlg: 'EdDSA',
      });
    });

    const s = await t.query(internal.adminApi.statusSummary, {});
    expect(s.pop.unbound).toBe(0);
    expect(s.pop.bound).toBe(2);
    expect(s.pop.readyToEnable).toBe(true);
  });
});

describe('adminApi auditList filtering', () => {
  test('filters by action, actorType, and since', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      await ctx.db.insert('auditLog', { actorType: 'admin', action: 'admin.user.disable' });
      await ctx.db.insert('auditLog', { actorType: 'admin', action: 'admin.user.disable' });
      await ctx.db.insert('auditLog', { actorType: 'system', action: 'membership.tier_change' });
      await ctx.db.insert('auditLog', { actorType: 'webhook', action: 'billing.order.paid' });
    });

    const all = await t.query(internal.adminApi.auditList, {});
    expect(all.entries.length).toBe(4);

    const byAction = await t.query(internal.adminApi.auditList, { action: 'admin.user.disable' });
    expect(byAction.entries).toHaveLength(2);
    expect(byAction.entries.every((e) => e.action === 'admin.user.disable')).toBe(true);

    const byActor = await t.query(internal.adminApi.auditList, { actorType: 'webhook' });
    expect(byActor.entries).toHaveLength(1);
    expect(byActor.entries[0]!.actorType).toBe('webhook');

    // A future lower bound excludes everything (nothing was created ahead of now).
    const future = await t.query(internal.adminApi.auditList, { since: Date.now() + 3_600_000 });
    expect(future.entries).toHaveLength(0);
  });
});

describe('adminApi setTheme + resolveTheme', () => {
  test('defaults to emerald / no hue when unset', async () => {
    const t = convexTest(schema, modules);
    const cfg = await t.run((ctx) => resolveTheme(ctx.db));
    expect(cfg.preset).toBe('emerald');
    expect(cfg.hue).toBeNull();
  });

  test('persists a preset + hue, readable by resolveTheme, and audits', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.adminApi.setTheme, { preset: 'teal', hue: 200 });
    const cfg = await t.run((ctx) => resolveTheme(ctx.db));
    expect(cfg.preset).toBe('teal');
    expect(cfg.hue).toBe(200);

    const audit = await t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .withIndex('by_action', (q) => q.eq('action', 'admin.theme.change'))
        .collect(),
    );
    expect(audit).toHaveLength(1);
    expect(audit[0]!.payload).toMatchObject({ preset: 'teal', hue: 200 });
  });

  test('rejects an unknown preset and drops an out-of-range hue', async () => {
    const t = convexTest(schema, modules);
    await expect(
      t.mutation(internal.adminApi.setTheme, { preset: 'bogus', hue: null }),
    ).rejects.toThrow(/unknown theme preset/i);

    await t.mutation(internal.adminApi.setTheme, { preset: 'emerald', hue: 999 });
    const cfg = await t.run((ctx) => resolveTheme(ctx.db));
    expect(cfg.preset).toBe('emerald');
    expect(cfg.hue).toBeNull(); // 999 is out of [0,360] → no override
  });
});

describe('adminApi connection modes + remnawave placements', () => {
  test('splits generic catalog (label/default) from the Remnawave placement pool; view is BOUND, never the uuid', async () => {
    const t = convexTest(schema, modules);
    // Remnawave-namespaced pool bind: squad UUIDs are write-only + return only
    // which modes are now bound.
    const placed = await t.mutation(internal.remnawaveNodes.setModePlacements, {
      patch: {
        modes: {
          evade: { squadUuids: ['fronted-squad-uuid'] },
          privacy: { squadUuids: ['reality-squad-uuid'] },
        },
      },
    });
    expect([...placed.bound].sort()).toEqual(['evade', 'privacy']);
    expect(JSON.stringify(placed)).not.toContain('reality-squad-uuid');
    expect(JSON.stringify(placed)).not.toContain('fronted-squad-uuid');

    // Generic catalog copy + default live behind the settings scope — no squads here.
    const out = await t.mutation(internal.adminApi.setConnectionModes, {
      patch: {
        default: 'privacy',
        modes: {
          privacy: { label: 'Max privacy', description: 'Direct Reality, no CDN in the path.' },
        },
      },
    });
    const priv = out.modes.find((m) => m.id === 'privacy')!;
    expect(priv.bound).toBe(true); // pool bound above
    expect(priv.label).toBe('Max privacy');
    expect(priv.description).toBe('Direct Reality, no CDN in the path.');
    expect(priv.deliveryStyle).toBe('rawConfig');
    expect(priv.isDefault).toBe(true);
    const evade = out.modes.find((m) => m.id === 'evade')!;
    expect(evade.bound).toBe(true);
    // No custom copy set on evade → nulls (never the compiled English default,
    // which would round-trip through the admin form and pin English over i18n).
    expect(evade.label).toBeNull();
    expect(evade.description).toBeNull();
    // Neither the catalog view nor the pool return ever carries a squad UUID.
    expect(JSON.stringify(out)).not.toContain('reality-squad-uuid');
    expect(JSON.stringify(out)).not.toContain('fronted-squad-uuid');

    // Server-only resolver reads the bound pools back (the issuance path).
    const priv2 = await t.run((ctx) => resolveModeSquadPool(ctx.db, 'privacy'));
    expect(priv2).toEqual(['reality-squad-uuid']);
    const evade2 = await t.run((ctx) => resolveModeSquadPool(ctx.db, 'evade'));
    expect(evade2).toEqual(['fronted-squad-uuid']);
  });

  test('audits a pool bind as a boolean, never the uuid', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.remnawaveNodes.setModePlacements, {
      patch: { modes: { privacy: { squadUuids: ['super-secret-squad'] } } },
    });
    const audit = await t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .withIndex('by_action', (q) => q.eq('action', 'admin.remnawave.mode_placement.update'))
        .collect(),
    );
    expect(audit).toHaveLength(1);
    expect(audit[0]!.payload).toMatchObject({
      key: 'remnawave.modePlacement.privacy.squads',
      poolBound: true,
    });
    expect(JSON.stringify(audit[0]!.payload)).not.toContain('super-secret-squad');
  });

  test('rejects a bad default id and an empty patch', async () => {
    const t = convexTest(schema, modules);
    await expect(
      t.mutation(internal.adminApi.setConnectionModes, { patch: { default: 'nope' } }),
    ).rejects.toThrow(/invalid default mode id/i);
    await expect(
      t.mutation(internal.adminApi.setConnectionModes, { patch: { modes: {} } }),
    ).rejects.toThrow(/no recognized connection-mode fields/i);
  });
});

describe('adminApi.maskApiUrl', () => {
  test('keeps scheme+host and redacts the secret path', () => {
    expect(maskApiUrl('https://outline.example.com:8443/SeCrEtPaTh/abc')).toBe(
      'https://outline.example.com:8443/***',
    );
  });

  test('falls back to a bare sentinel for an unparseable value', () => {
    expect(maskApiUrl('not a url')).toBe('***');
  });
});

describe('adminApi default-free auto-clear (pass 2)', () => {
  test('creating a second default-free tier on a backend clears the first (audited)', async () => {
    const t = convexTest(schema, modules);
    const a = await t.mutation(
      internal.adminApi.createTier,
      tierUpsert({ slug: 'free-a', isDefaultFree: true }),
    );
    const b = await t.mutation(
      internal.adminApi.createTier,
      tierUpsert({ slug: 'free-b', isDefaultFree: true }),
    );
    expect(b.isDefaultFree).toBe(true);
    const { tiers } = await t.query(internal.adminApi.tiersList, {});
    expect(tiers.find((x) => x.id === a.id)!.isDefaultFree).toBe(false);
    await t.run(async (ctx) => {
      const audits = await ctx.db.query('auditLog').collect();
      expect(audits.some((e) => e.action === 'admin.tier.default_free_cleared')).toBe(true);
    });
  });

  test('flipping the flag on via updateTier clears the previous holder', async () => {
    const t = convexTest(schema, modules);
    const a = await t.mutation(
      internal.adminApi.createTier,
      tierUpsert({ slug: 'free-a2', isDefaultFree: true }),
    );
    const b = await t.mutation(
      internal.adminApi.createTier,
      tierUpsert({ slug: 'free-b2', isDefaultFree: false }),
    );
    await t.mutation(internal.adminApi.updateTier, {
      id: b.id as never,
      isDefaultFree: true,
    });
    const { tiers } = await t.query(internal.adminApi.tiersList, {});
    expect(tiers.find((x) => x.id === a.id)!.isDefaultFree).toBe(false);
    expect(tiers.find((x) => x.id === b.id)!.isDefaultFree).toBe(true);
  });

  test('defaults on DIFFERENT backends coexist', async () => {
    const t = convexTest(schema, modules);
    const rw = await t.mutation(
      internal.adminApi.createTier,
      tierUpsert({ slug: 'free-rw', backend: 'remnawave', isDefaultFree: true }),
    );
    const ol = await t.mutation(
      internal.adminApi.createTier,
      tierUpsert({ slug: 'free-ol', backend: 'outline', isDefaultFree: true }),
    );
    const { tiers } = await t.query(internal.adminApi.tiersList, {});
    expect(tiers.find((x) => x.id === rw.id)!.isDefaultFree).toBe(true);
    expect(tiers.find((x) => x.id === ol.id)!.isDefaultFree).toBe(true);
  });

  test("moving a default tier to another backend clears that backend's holder", async () => {
    const t = convexTest(schema, modules);
    const rw = await t.mutation(
      internal.adminApi.createTier,
      tierUpsert({ slug: 'free-rw3', backend: 'remnawave', isDefaultFree: true }),
    );
    const ol = await t.mutation(
      internal.adminApi.createTier,
      tierUpsert({ slug: 'free-ol3', backend: 'outline', isDefaultFree: true }),
    );
    // Move the remnawave default onto outline: the outline holder must clear.
    await t.mutation(internal.adminApi.updateTier, {
      id: rw.id as never,
      backend: 'outline',
    });
    const { tiers } = await t.query(internal.adminApi.tiersList, {});
    expect(tiers.find((x) => x.id === rw.id)!.isDefaultFree).toBe(true);
    expect(tiers.find((x) => x.id === ol.id)!.isDefaultFree).toBe(false);
  });
});
