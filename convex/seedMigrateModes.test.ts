/// <reference types="vite/client" />
/**
 * seed:migrateConnectionModeIds — the one-time rename of the connection-mode ids
 * to the family/transport scheme. Operator-run against LIVE data, so the two
 * properties that matter most are covered here: it moves every surface, and it
 * is safe to run twice (or to resume after a partial page).
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { resolveConnectionModes, resolveDefaultModeId } from './lib/connectionModes';
import { resolveModeSquadPool } from './lib/remnawavePlacement';

const modules = import.meta.glob('./**/*.*s');

async function seedTier(t: ReturnType<typeof convexTest>): Promise<Id<'tiers'>> {
  return t.run((ctx) =>
    ctx.db.insert('tiers', {
      slug: 'free',
      name: 'Free',
      backend: 'remnawave',
      monthlyTrafficGb: 50,
      deviceLimit: 3,
      hwidLimit: 3,
      hwidEnabled: false,
      trafficStrategy: 'MONTH',
      isDefaultFree: true,
      isActive: true,
      priority: 0,
      expirationDaysAfterMembershipLapse: 0,
      updatedAt: Date.now(),
    }),
  );
}

async function seedUser(
  t: ReturnType<typeof convexTest>,
  tierId: Id<'tiers'>,
  connectionModeId?: string,
): Promise<Id<'users'>> {
  return t.run((ctx) =>
    ctx.db.insert('users', {
      tierId,
      status: 'active',
      ...(connectionModeId ? { connectionModeId } : {}),
      updatedAt: Date.now(),
    }),
  );
}

async function setSetting(t: ReturnType<typeof convexTest>, key: string, value: unknown) {
  await t.run((ctx) =>
    ctx.db.insert('appSettings', { key, value: JSON.stringify(value), updatedAt: Date.now() }),
  );
}

/** The stored value, or null when the row is absent. (Convex serializes an
 *  `undefined` return as null, so the absent case is spelled null throughout.) */
async function readSetting(t: ReturnType<typeof convexTest>, key: string): Promise<unknown> {
  return t.run(async (ctx) => {
    const row = await ctx.db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', key))
      .unique();
    return row ? JSON.parse(row.value) : null;
  });
}

describe('seed:migrateConnectionModeIds', () => {
  test('renames users, mode copy, placement pools, and the default', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const onEvade = await seedUser(t, tierId, 'evade');
    const onPrivacy = await seedUser(t, tierId, 'privacy');
    const untouched = await seedUser(t, tierId); // never chose a mode

    await setSetting(t, 'connectionMode.evade.label', 'Beat censorship');
    await setSetting(t, 'connectionMode.privacy.description', 'Direct Reality');
    await setSetting(t, 'connectionMode.default', 'privacy');
    await setSetting(t, 'remnawave.modePlacement.evade.squads', ['sq-ws']);
    await setSetting(t, 'remnawave.modePlacement.privacy.squads', ['sq-priv']);

    const res = await t.mutation(internal.seed.migrateConnectionModeIds, {});
    expect(res.usersUpdated).toBe(2);
    expect(res.nextCursor).toBeNull();

    await t.run(async (ctx) => {
      expect((await ctx.db.get(onEvade))!.connectionModeId).toBe('freedom-ws');
      expect((await ctx.db.get(onPrivacy))!.connectionModeId).toBe('privacy-reality');
      expect((await ctx.db.get(untouched))!.connectionModeId).toBeUndefined();
    });

    expect(await readSetting(t, 'connectionMode.freedom-ws.label')).toBe('Beat censorship');
    expect(await readSetting(t, 'connectionMode.evade.label')).toBeNull();
    expect(await readSetting(t, 'connectionMode.privacy-reality.description')).toBe(
      'Direct Reality',
    );
    expect(await readSetting(t, 'connectionMode.default')).toBe('privacy-reality');
    expect(await readSetting(t, 'remnawave.modePlacement.freedom-ws.squads')).toEqual(['sq-ws']);
    expect(await readSetting(t, 'remnawave.modePlacement.evade.squads')).toBeNull();

    // The renamed pools resolve through the new ids.
    expect(await t.run((ctx) => resolveModeSquadPool(ctx.db, 'privacy-reality'))).toEqual([
      'sq-priv',
    ]);
    expect(await t.run((ctx) => resolveDefaultModeId(ctx.db))).toBe('privacy-reality');
  });

  test('seeds the enable toggles without overwriting an operator choice', async () => {
    const t = convexTest(schema, modules);
    // The operator turned freedom-reality ON before running the migration.
    await setSetting(t, 'connectionMode.freedom-reality.enabled', true);

    const res = await t.mutation(internal.seed.migrateConnectionModeIds, {});
    expect(res.enabledSeeded).toBeGreaterThan(0);

    expect(await readSetting(t, 'connectionMode.freedom-reality.enabled')).toBe(true); // preserved
    expect(await readSetting(t, 'connectionMode.freedom-ws.enabled')).toBe(true);
    expect(await readSetting(t, 'connectionModeFamily.freedom.enabled')).toBe(true);
    expect(await readSetting(t, 'connectionModeFamily.privacy.enabled')).toBe(true);
    // Deprecated aliases never get a toggle row.
    expect(await readSetting(t, 'connectionMode.evade.enabled')).toBeNull();

    const modes = await t.run((ctx) => resolveConnectionModes(ctx.db));
    expect(modes.find((m) => m.id === 'freedom-reality')!.enabled).toBe(true);
  });

  test('is idempotent: a second run changes nothing', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    await seedUser(t, tierId, 'evade');
    await setSetting(t, 'connectionMode.evade.label', 'Beat censorship');
    await setSetting(t, 'remnawave.modePlacement.evade.squads', ['sq-ws']);

    await t.mutation(internal.seed.migrateConnectionModeIds, {});
    const second = await t.mutation(internal.seed.migrateConnectionModeIds, {});
    expect(second).toMatchObject({
      usersUpdated: 0,
      settingsRenamed: 0,
      defaultUpdated: 0,
      enabledSeeded: 0,
    });
    expect(await readSetting(t, 'connectionMode.freedom-ws.label')).toBe('Beat censorship');
  });

  test('a destination that already exists wins; the legacy row is dropped', async () => {
    // An admin who edited the NEW key before the migration ran must not have
    // their edit clobbered by the stale legacy value.
    const t = convexTest(schema, modules);
    await setSetting(t, 'connectionMode.evade.label', 'old');
    await setSetting(t, 'connectionMode.freedom-ws.label', 'new');

    await t.mutation(internal.seed.migrateConnectionModeIds, {});
    expect(await readSetting(t, 'connectionMode.freedom-ws.label')).toBe('new');
    expect(await readSetting(t, 'connectionMode.evade.label')).toBeNull();
  });

  test('pages the user scan and reports a resumable cursor', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    for (let i = 0; i < 3; i++) await seedUser(t, tierId, 'evade');

    const first = await t.mutation(internal.seed.migrateConnectionModeIds, { limit: 2 });
    expect(first.usersUpdated).toBe(2);
    expect(first.nextCursor).not.toBeNull();

    const second = await t.mutation(internal.seed.migrateConnectionModeIds, {
      limit: 2,
      cursor: first.nextCursor ?? undefined,
    });
    expect(second.usersUpdated).toBe(1);
    expect(second.nextCursor).toBeNull();

    await t.run(async (ctx) => {
      const users = await ctx.db.query('users').collect();
      expect(users.every((u) => u.connectionModeId === 'freedom-ws')).toBe(true);
    });
  });
});

describe('lazy self-heal (users.canonicalizeConnectionMode)', () => {
  test('rewrites a pre-rename id so no legacy value reaches the picker', async () => {
    // The reported bug: a member still on `evade` got an id publicConfig no
    // longer lists, which the picker rendered as a raw "evade" chip.
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await seedUser(t, tierId, 'evade');

    const out = await t.mutation(internal.users.canonicalizeConnectionMode, { userId });
    expect(out).toBe('freedom-ws');
    await t.run(async (ctx) => {
      expect((await ctx.db.get(userId))!.connectionModeId).toBe('freedom-ws');
    });
  });

  test('maps privacy to privacy-reality, never to the catalog default', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await seedUser(t, tierId, 'privacy');
    expect(await t.mutation(internal.users.canonicalizeConnectionMode, { userId })).toBe(
      'privacy-reality',
    );
  });

  test('is a no-op for a current id (the account view refetches every 60s)', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await seedUser(t, tierId, 'privacy-reality');
    const before = await t.run(async (ctx) => (await ctx.db.get(userId))!.updatedAt);

    expect(await t.mutation(internal.users.canonicalizeConnectionMode, { userId })).toBe(
      'privacy-reality',
    );
    await t.run(async (ctx) => {
      // updatedAt untouched proves no write fired.
      expect((await ctx.db.get(userId))!.updatedAt).toBe(before);
    });
  });

  test('leaves an unset mode alone (the member follows the catalog default)', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await seedUser(t, tierId);
    expect(await t.mutation(internal.users.canonicalizeConnectionMode, { userId })).toBeNull();
    await t.run(async (ctx) => {
      expect((await ctx.db.get(userId))!.connectionModeId).toBeUndefined();
    });
  });
});
