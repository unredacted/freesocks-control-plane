/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import {
  resolveConnectionProfiles,
  resolveProfileSquad,
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
    expect(await t.run((ctx) => resolveProfileSquad(ctx.db, null))).toBeNull();
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

  test('publicProjection strips squadUuid + sets available', () => {
    const pub = publicProjection([
      { id: 'evade', label: 'Stay connected', squadUuid: 'sq-front', isDefault: true },
      { id: 'privacy', label: 'Maximize privacy', squadUuid: null, isDefault: false },
    ]);
    expect(pub).toEqual([
      { id: 'evade', label: 'Stay connected', isDefault: true, available: true },
      { id: 'privacy', label: 'Maximize privacy', isDefault: false, available: false },
    ]);
    expect(JSON.stringify(pub)).not.toContain('sq-front'); // squad uuid never leaks
  });

  test('connectionProfileWrites validates ids + maps to appSettings keys', () => {
    const writes = connectionProfileWrites({
      default: 'privacy',
      profiles: { evade: { squadUuid: 'sq-front' }, privacy: { label: 'P' } },
    });
    const byKey = Object.fromEntries(writes.map((w) => [w.key, JSON.parse(w.value)]));
    expect(byKey[CONNECTION_PROFILE_KEYS.defaultId]).toBe('privacy');
    expect(byKey[CONNECTION_PROFILE_KEYS.squad('evade')]).toBe('sq-front');
    expect(byKey[CONNECTION_PROFILE_KEYS.label('privacy')]).toBe('P');
    expect(() => connectionProfileWrites({ default: 'nope' })).toThrow();
    expect(() => connectionProfileWrites('x')).toThrow();
    // Unknown profile ids are ignored, not an error.
    expect(connectionProfileWrites({ profiles: { bogus: { squadUuid: 'x' } } })).toEqual([]);
  });
});
