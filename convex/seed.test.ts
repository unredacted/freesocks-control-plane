/// <reference types="vite/client" />
/**
 * Phase-5 cutover migration tests (seed:migrateConnectionModes). Confirms the
 * deprecated connection-profile / Remnawave-squad shape is copied into the new
 * generic fields and then CLEARED on every row — the precondition for the
 * follow-up deploy dropping those fields from the schema. Live keys must keep
 * their placement (set-once), and a second run must be a no-op (idempotent).
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';

const modules = import.meta.glob('./**/*.*s');

async function seedTier(t: ReturnType<typeof convexTest>): Promise<Id<'tiers'>> {
  return t.run((ctx) =>
    ctx.db.insert('tiers', {
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
    }),
  );
}

describe('seed:migrateConnectionModes cutover', () => {
  test('subscriptions: squad handle → backendPlacement (set-once), old field cleared', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() }),
    );
    const mkSub = (buid: string, extra: Record<string, unknown>) =>
      t.run((ctx) =>
        ctx.db.insert('subscriptions', {
          userId,
          backend: 'remnawave',
          backendUserId: buid,
          backendShortId: `${buid}-s`,
          subscriptionUrl: 'https://panel/sub',
          subscriptionMirrors: [],
          state: 'active',
          updatedAt: Date.now(),
          ...extra,
        }),
      );
    // (a) legacy squad only → copied. (b) already has backendPlacement → NOT
    // clobbered but old field still cleared. (c) no legacy field → untouched.
    const aId = await mkSub('a', { remnawaveSquadUuid: 'SQUAD_A' });
    const bId = await mkSub('b', { remnawaveSquadUuid: 'OLD_B', backendPlacement: 'NEW_B' });
    const cId = await mkSub('c', {});

    const out = await t.action(internal.seed.migrateConnectionModes, {});
    expect(out.subscriptionsMigrated).toBe(2); // a + b (c had nothing)

    await t.run(async (ctx) => {
      const a = await ctx.db.get(aId);
      expect(a!.backendPlacement).toBe('SQUAD_A');
      expect(a!.remnawaveSquadUuid).toBeUndefined();
      const b = await ctx.db.get(bId);
      expect(b!.backendPlacement).toBe('NEW_B'); // set-once: not clobbered
      expect(b!.remnawaveSquadUuid).toBeUndefined();
      const c = await ctx.db.get(cId);
      expect(c!.backendPlacement).toBeUndefined();
    });

    // Idempotent: a second run migrates nothing.
    const again = await t.action(internal.seed.migrateConnectionModes, {});
    expect(again.subscriptionsMigrated).toBe(0);
  });

  test('users: connectionProfileId → connectionModeId, old field cleared', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const uId = await t.run((ctx) =>
      ctx.db.insert('users', {
        tierId,
        status: 'active',
        connectionProfileId: 'privacy',
        updatedAt: Date.now(),
      }),
    );

    const out = await t.action(internal.seed.migrateConnectionModes, {});
    expect(out.usersMigrated).toBe(1);
    await t.run(async (ctx) => {
      const u = await ctx.db.get(uId);
      expect(u!.connectionModeId).toBe('privacy');
      expect(u!.connectionProfileId).toBeUndefined();
    });
  });

  test('appSettings: connectionProfile.* → connectionMode.* + pool merged into remnawave.modePlacement.*', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      const now = Date.now();
      const put = (key: string, value: unknown) =>
        ctx.db.insert('appSettings', { key, value: JSON.stringify(value), updatedAt: now });
      await put('connectionProfile.default', 'privacy');
      await put('connectionProfile.privacy.label', 'Max privacy');
      await put('connectionProfile.privacy.description', 'Direct Reality.');
      await put('connectionProfile.privacy.squadUuids', ['sq-1', 'sq-2']);
      await put('connectionProfile.evade.squadUuid', 'sq-evade'); // legacy singular
    });

    const out = await t.action(internal.seed.migrateConnectionModes, {});
    expect(out.settings.renamed).toBe(3); // default + label + description
    expect(out.settings.poolsWritten).toBe(2); // privacy + evade

    await t.run(async (ctx) => {
      const read = async (key: string) =>
        (
          await ctx.db
            .query('appSettings')
            .withIndex('by_key', (q) => q.eq('key', key))
            .unique()
        )?.value;
      // Renamed catalog keys.
      expect(await read('connectionMode.default')).toBe(JSON.stringify('privacy'));
      expect(await read('connectionMode.privacy.label')).toBe(JSON.stringify('Max privacy'));
      expect(await read('connectionMode.privacy.description')).toBe(
        JSON.stringify('Direct Reality.'),
      );
      // Pools moved to the Remnawave namespace (singular folded into a 1-elem pool).
      expect(await read('remnawave.modePlacement.privacy.squads')).toBe(
        JSON.stringify(['sq-1', 'sq-2']),
      );
      expect(await read('remnawave.modePlacement.evade.squads')).toBe(JSON.stringify(['sq-evade']));
      // No legacy connectionProfile.* rows survive.
      const leftover = await ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) =>
          q.gte('key', 'connectionProfile.').lt('key', 'connectionProfile/'),
        )
        .collect();
      expect(leftover).toHaveLength(0);
    });
  });

  test('clears the deprecated remnawaveSquadStats table', async () => {
    const t = convexTest(schema, modules);
    const serverId = await t.run((ctx) =>
      ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'rw',
        slug: 'rw',
        config: { type: 'remnawave', baseUrl: 'https://rw', apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 0,
        updatedAt: Date.now(),
      }),
    );
    await t.run(async (ctx) => {
      const now = Date.now();
      for (const sq of ['s1', 's2', 's3']) {
        await ctx.db.insert('remnawaveSquadStats', {
          backendServerId: serverId,
          squadUuid: sq,
          membersCount: 5,
          lastStatsAt: now,
          updatedAt: now,
        });
      }
    });

    const out = await t.action(internal.seed.migrateConnectionModes, {});
    expect(out.squadStatsRemoved).toBe(3);
    await t.run(async (ctx) => {
      expect(await ctx.db.query('remnawaveSquadStats').collect()).toHaveLength(0);
    });
  });
});
