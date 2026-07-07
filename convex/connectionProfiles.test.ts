/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import {
  resolveConnectionProfiles,
  resolveProfileSquad,
  resolveProfilePool,
  pickSquadFromPool,
  publicProjection,
  connectionProfileWrites,
  CONNECTION_PROFILE_KEYS,
  DEFAULT_CONNECTION_PROFILE,
} from './lib/connectionProfiles';

const modules = import.meta.glob('./**/*.*s');

describe('connectionProfiles lib', () => {
  test('resolves defaults with no rows: both ids, evade default, no squads bound', async () => {
    const t = convexTest(schema, modules);
    const profiles = await t.run((ctx) => resolveConnectionProfiles(ctx.db));
    expect(profiles.map((p) => p.id).sort()).toEqual(['evade', 'privacy']);
    expect(profiles.find((p) => p.id === 'evade')!.isDefault).toBe(true);
    expect(profiles.every((p) => p.squadUuid === null)).toBe(true);
    expect(DEFAULT_CONNECTION_PROFILE).toBe('evade');
  });

  test('resolves a bound squad + custom default + label from appSettings', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      const now = Date.now();
      await ctx.db.insert('appSettings', {
        key: CONNECTION_PROFILE_KEYS.squad('privacy'),
        value: JSON.stringify('squad-reality'),
        updatedAt: now,
      });
      await ctx.db.insert('appSettings', {
        key: CONNECTION_PROFILE_KEYS.label('privacy'),
        value: JSON.stringify('Max privacy'),
        updatedAt: now,
      });
      await ctx.db.insert('appSettings', {
        key: CONNECTION_PROFILE_KEYS.defaultId,
        value: JSON.stringify('privacy'),
        updatedAt: now,
      });
    });
    const profiles = await t.run((ctx) => resolveConnectionProfiles(ctx.db));
    const priv = profiles.find((p) => p.id === 'privacy')!;
    expect(priv.squadUuid).toBe('squad-reality');
    expect(priv.label).toBe('Max privacy');
    expect(priv.isDefault).toBe(true);
    expect(profiles.find((p) => p.id === 'evade')!.isDefault).toBe(false);
    expect(await t.run((ctx) => resolveProfileSquad(ctx.db, 'privacy'))).toBe('squad-reality');
    expect(await t.run((ctx) => resolveProfileSquad(ctx.db, 'evade'))).toBeNull(); // unbound → null
    // No explicit choice → the DEFAULT profile's squad (here default=privacy).
    expect(await t.run((ctx) => resolveProfileSquad(ctx.db, null))).toBe('squad-reality');
  });

  test('no explicit choice resolves the DEFAULT profile squad (new-member issuance)', async () => {
    // Regression: a never-chosen member (connectionProfileId null) must issue into
    // the default profile's squad, not NO squad (which yields Remnawave "No hosts
    // found"). Default is evade (unset default), bound to the fronted squad.
    const t = convexTest(schema, modules);
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: CONNECTION_PROFILE_KEYS.squad('evade'),
        value: JSON.stringify('squad-fronted'),
        updatedAt: Date.now(),
      }),
    );
    expect(await t.run((ctx) => resolveProfileSquad(ctx.db, null))).toBe('squad-fronted');
    expect(await t.run((ctx) => resolveProfileSquad(ctx.db, undefined))).toBe('squad-fronted');
    expect(await t.run((ctx) => resolveProfileSquad(ctx.db, 'evade'))).toBe('squad-fronted');
  });

  test('fail-safe: corrupt JSON / invalid default never throws', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      const now = Date.now();
      await ctx.db.insert('appSettings', {
        key: CONNECTION_PROFILE_KEYS.squad('evade'),
        value: 'not json{',
        updatedAt: now,
      });
      await ctx.db.insert('appSettings', {
        key: CONNECTION_PROFILE_KEYS.defaultId,
        value: JSON.stringify('nonsense'),
        updatedAt: now,
      });
    });
    const profiles = await t.run((ctx) => resolveConnectionProfiles(ctx.db));
    expect(profiles.find((p) => p.id === 'evade')!.squadUuid).toBeNull(); // corrupt → null
    expect(profiles.find((p) => p.id === 'evade')!.isDefault).toBe(true); // invalid default → evade
  });

  test('publicProjection strips squadUuid + sets available + nulls non-custom copy', () => {
    const pub = publicProjection([
      {
        id: 'evade',
        label: 'Stay connected',
        labelCustom: false,
        description: null,
        squadUuid: 'sq-front',
        squadUuids: ['sq-front'],
        isDefault: true,
      },
      {
        id: 'privacy',
        label: 'Custom privacy title',
        labelCustom: true,
        description: 'Custom body',
        squadUuid: null,
        squadUuids: [],
        isDefault: false,
      },
    ]);
    expect(pub).toEqual([
      // Non-custom label ships as null so the SPA's i18n stays authoritative.
      { id: 'evade', label: null, description: null, isDefault: true, available: true },
      {
        id: 'privacy',
        label: 'Custom privacy title',
        description: 'Custom body',
        isDefault: false,
        available: false,
      },
    ]);
    expect(JSON.stringify(pub)).not.toContain('sq-front'); // squad uuid never leaks
  });

  test('description: stored value resolves, blank/whitespace clears to null', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      const now = Date.now();
      await ctx.db.insert('appSettings', {
        key: CONNECTION_PROFILE_KEYS.description('evade'),
        value: JSON.stringify('Fastest, works behind heavy filtering.'),
        updatedAt: now,
      });
      await ctx.db.insert('appSettings', {
        key: CONNECTION_PROFILE_KEYS.description('privacy'),
        value: JSON.stringify('   '), // whitespace-only = cleared
        updatedAt: now,
      });
    });
    const profiles = await t.run((ctx) => resolveConnectionProfiles(ctx.db));
    expect(profiles.find((p) => p.id === 'evade')!.description).toBe(
      'Fastest, works behind heavy filtering.',
    );
    expect(profiles.find((p) => p.id === 'privacy')!.description).toBeNull();
  });

  test('labelCustom tracks stored-vs-default labels', async () => {
    const t = convexTest(schema, modules);
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: CONNECTION_PROFILE_KEYS.label('privacy'),
        value: JSON.stringify('Max privacy'),
        updatedAt: Date.now(),
      }),
    );
    const profiles = await t.run((ctx) => resolveConnectionProfiles(ctx.db));
    const evade = profiles.find((p) => p.id === 'evade')!;
    const priv = profiles.find((p) => p.id === 'privacy')!;
    expect(evade.labelCustom).toBe(false);
    expect(evade.label).toBe('Stay connected'); // compiled default, admin-side only
    expect(priv.labelCustom).toBe(true);
    expect(priv.label).toBe('Max privacy');
    const pub = publicProjection(profiles);
    expect(pub.find((p) => p.id === 'evade')!.label).toBeNull();
    expect(pub.find((p) => p.id === 'privacy')!.label).toBe('Max privacy');
  });

  test('squad pools: squadUuids overrides legacy squadUuid; legacy resolves as a one-element pool', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      const now = Date.now();
      // evade: legacy single squad only (backward compat).
      await ctx.db.insert('appSettings', {
        key: CONNECTION_PROFILE_KEYS.squad('evade'),
        value: JSON.stringify('sq-legacy'),
        updatedAt: now,
      });
      // privacy: a pool (and a stale legacy key the pool must shadow).
      await ctx.db.insert('appSettings', {
        key: CONNECTION_PROFILE_KEYS.squad('privacy'),
        value: JSON.stringify('sq-old'),
        updatedAt: now,
      });
      await ctx.db.insert('appSettings', {
        key: CONNECTION_PROFILE_KEYS.squads('privacy'),
        value: JSON.stringify(['sq-a', 'sq-b', 'sq-a']), // dupe dropped
        updatedAt: now,
      });
    });
    expect(await t.run((ctx) => resolveProfilePool(ctx.db, 'evade'))).toEqual(['sq-legacy']);
    expect(await t.run((ctx) => resolveProfilePool(ctx.db, 'privacy'))).toEqual(['sq-a', 'sq-b']);
    // The deterministic single-squad view = the pool's first element.
    expect(await t.run((ctx) => resolveProfileSquad(ctx.db, 'privacy'))).toBe('sq-a');
    const profiles = await t.run((ctx) => resolveConnectionProfiles(ctx.db));
    expect(profiles.find((p) => p.id === 'privacy')!.squadUuids).toEqual(['sq-a', 'sq-b']);
    // Corrupt pool JSON falls back to the legacy single squad, never throws.
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: CONNECTION_PROFILE_KEYS.squads('evade'),
        value: 'not json{',
        updatedAt: Date.now(),
      }),
    );
    expect(await t.run((ctx) => resolveProfilePool(ctx.db, 'evade'))).toEqual(['sq-legacy']);
  });

  test('pickSquadFromPool: least-loaded fresh squad wins; stale/unknown deprioritized; deterministic fallback', async () => {
    const t = convexTest(schema, modules);
    // Fast paths need no stats rows.
    expect(await t.run((ctx) => pickSquadFromPool(ctx.db, []))).toBeNull();
    expect(await t.run((ctx) => pickSquadFromPool(ctx.db, ['only']))).toBe('only');
    // All-unknown → declaration order (deterministic).
    expect(await t.run((ctx) => pickSquadFromPool(ctx.db, ['first', 'second']))).toBe('first');

    const serverId = await t.run((ctx) =>
      ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'rw',
        slug: 'rw',
        config: { type: 'remnawave', baseUrl: 'https://rw.example', apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 0,
        updatedAt: Date.now(),
      }),
    );
    const now = Date.now();
    await t.run(async (ctx) => {
      await ctx.db.insert('remnawaveSquadStats', {
        backendServerId: serverId,
        squadUuid: 'sq-busy',
        name: 'busy',
        membersCount: 50,
        lastStatsAt: now,
        updatedAt: now,
      });
      await ctx.db.insert('remnawaveSquadStats', {
        backendServerId: serverId,
        squadUuid: 'sq-idle',
        name: 'idle',
        membersCount: 3,
        lastStatsAt: now,
        updatedAt: now,
      });
      await ctx.db.insert('remnawaveSquadStats', {
        backendServerId: serverId,
        squadUuid: 'sq-stale',
        name: 'stale',
        membersCount: 0, // lowest count, but STALE → must not win over fresh
        lastStatsAt: now - 45 * 60_000,
        updatedAt: now - 45 * 60_000,
      });
    });
    // Least-loaded fresh squad wins regardless of declaration order.
    expect(await t.run((ctx) => pickSquadFromPool(ctx.db, ['sq-busy', 'sq-idle']))).toBe('sq-idle');
    // A stale zero-count squad loses to any fresh one...
    expect(await t.run((ctx) => pickSquadFromPool(ctx.db, ['sq-stale', 'sq-busy']))).toBe(
      'sq-busy',
    );
    // ...and a never-observed squad also loses to a fresh one.
    expect(await t.run((ctx) => pickSquadFromPool(ctx.db, ['sq-new', 'sq-idle']))).toBe('sq-idle');
  });

  test('connectionProfileWrites validates ids + maps to appSettings keys', () => {
    const writes = connectionProfileWrites({
      default: 'privacy',
      profiles: {
        evade: { squadUuid: 'sq-front', description: 'Own copy' },
        privacy: { label: 'P', description: '' },
      },
    });
    const byKey = Object.fromEntries(writes.map((w) => [w.key, JSON.parse(w.value)]));
    expect(byKey[CONNECTION_PROFILE_KEYS.defaultId]).toBe('privacy');
    expect(byKey[CONNECTION_PROFILE_KEYS.squad('evade')]).toBe('sq-front');
    expect(byKey[CONNECTION_PROFILE_KEYS.label('privacy')]).toBe('P');
    expect(byKey[CONNECTION_PROFILE_KEYS.description('evade')]).toBe('Own copy');
    // An explicit empty string is a valid clear-write (resolves back to null).
    expect(byKey[CONNECTION_PROFILE_KEYS.description('privacy')]).toBe('');
    // Squad pools: valid array maps (deduped); bad shapes throw; [] is a clear-write.
    const poolWrites = connectionProfileWrites({
      profiles: { evade: { squadUuids: ['sq-1', 'sq-2', 'sq-1'] }, privacy: { squadUuids: [] } },
    });
    const poolByKey = Object.fromEntries(poolWrites.map((w) => [w.key, JSON.parse(w.value)]));
    expect(poolByKey[CONNECTION_PROFILE_KEYS.squads('evade')]).toEqual(['sq-1', 'sq-2']);
    expect(poolByKey[CONNECTION_PROFILE_KEYS.squads('privacy')]).toEqual([]);
    expect(() =>
      connectionProfileWrites({ profiles: { evade: { squadUuids: 'not-an-array' } } }),
    ).toThrow(/squadUuids/);
    expect(() =>
      connectionProfileWrites({ profiles: { evade: { squadUuids: ['ok', ''] } } }),
    ).toThrow(/squadUuids/);
    expect(() => connectionProfileWrites({ default: 'nope' })).toThrow();
    expect(() => connectionProfileWrites('x')).toThrow();
    // Unknown profile ids are ignored, not an error.
    expect(connectionProfileWrites({ profiles: { bogus: { squadUuid: 'x' } } })).toEqual([]);
  });
});
