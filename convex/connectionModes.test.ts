/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import {
  resolveConnectionModes,
  resolveDefaultModeId,
  publicProjection,
  connectionModeWrites,
  CONNECTION_MODE_KEYS,
  DEFAULT_CONNECTION_MODE,
  type ConnectionMode,
} from './lib/connectionModes';
import {
  resolveModeSquadPool,
  resolvePlacementPool,
  resolveModePlacementStable,
  resolveBoundModeIds,
  modePlacementWrites,
} from './lib/remnawavePlacement';

const modules = import.meta.glob('./**/*.*s');

describe('connectionModes catalog', () => {
  test('resolves defaults with no rows: both modes, evade default, deliveryStyle set', async () => {
    const t = convexTest(schema, modules);
    const modes = await t.run((ctx) => resolveConnectionModes(ctx.db));
    expect(modes.map((m) => m.id).sort()).toEqual(['evade', 'privacy']);
    expect(modes.find((m) => m.id === 'evade')!.isDefault).toBe(true);
    expect(modes.find((m) => m.id === 'evade')!.deliveryStyle).toBe('url');
    expect(modes.find((m) => m.id === 'privacy')!.deliveryStyle).toBe('rawConfig');
    expect(modes.every((m) => m.label === null && m.description === null)).toBe(true);
    expect(DEFAULT_CONNECTION_MODE).toBe('evade');
    expect(await t.run((ctx) => resolveDefaultModeId(ctx.db))).toBe('evade');
  });

  test('resolves admin label/description + custom default from appSettings', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      const now = Date.now();
      await ctx.db.insert('appSettings', {
        key: CONNECTION_MODE_KEYS.label('privacy'),
        value: JSON.stringify('Max privacy'),
        updatedAt: now,
      });
      await ctx.db.insert('appSettings', {
        key: CONNECTION_MODE_KEYS.description('privacy'),
        value: JSON.stringify('Direct Reality, no CDN.'),
        updatedAt: now,
      });
      await ctx.db.insert('appSettings', {
        key: CONNECTION_MODE_KEYS.defaultId,
        value: JSON.stringify('privacy'),
        updatedAt: now,
      });
    });
    const modes = await t.run((ctx) => resolveConnectionModes(ctx.db));
    const priv = modes.find((m) => m.id === 'privacy')!;
    expect(priv.label).toBe('Max privacy');
    expect(priv.description).toBe('Direct Reality, no CDN.');
    expect(priv.isDefault).toBe(true);
    expect(modes.find((m) => m.id === 'evade')!.isDefault).toBe(false);
    expect(await t.run((ctx) => resolveDefaultModeId(ctx.db))).toBe('privacy');
  });

  test('blank/whitespace label + description clear to null; corrupt/invalid default never throws', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      const now = Date.now();
      await ctx.db.insert('appSettings', {
        key: CONNECTION_MODE_KEYS.label('evade'),
        value: JSON.stringify('   '),
        updatedAt: now,
      });
      await ctx.db.insert('appSettings', {
        key: CONNECTION_MODE_KEYS.description('evade'),
        value: 'not json{',
        updatedAt: now,
      });
      await ctx.db.insert('appSettings', {
        key: CONNECTION_MODE_KEYS.defaultId,
        value: JSON.stringify('nonsense'),
        updatedAt: now,
      });
    });
    const modes = await t.run((ctx) => resolveConnectionModes(ctx.db));
    expect(modes.find((m) => m.id === 'evade')!.label).toBeNull();
    expect(modes.find((m) => m.id === 'evade')!.description).toBeNull();
    expect(modes.find((m) => m.id === 'evade')!.isDefault).toBe(true); // invalid default → evade
  });

  test('publicProjection ships deliveryStyle + admin copy + available; sorts by order; leaks no UUID', () => {
    const modes: ConnectionMode[] = [
      {
        id: 'privacy',
        deliveryStyle: 'rawConfig',
        label: 'Custom privacy',
        description: 'Body',
        isDefault: false,
        order: 1,
      },
      {
        id: 'evade',
        deliveryStyle: 'url',
        label: null,
        description: null,
        isDefault: true,
        order: 0,
      },
    ];
    const pub = publicProjection(modes, new Set(['evade']));
    expect(pub.map((m) => m.id)).toEqual(['evade', 'privacy']); // sorted by order
    expect(pub[0]).toEqual({
      id: 'evade',
      deliveryStyle: 'url',
      label: null,
      description: null,
      isDefault: true,
      available: true,
    });
    expect(pub[1]).toMatchObject({
      id: 'privacy',
      deliveryStyle: 'rawConfig',
      label: 'Custom privacy',
      available: false, // not in the bound set
    });
  });

  test('connectionModeWrites: label/description/default only, empty string clears, unknown ids ignored', () => {
    const writes = connectionModeWrites({
      default: 'privacy',
      modes: { evade: { description: 'Own copy' }, privacy: { label: 'P', description: '' } },
    });
    const byKey = Object.fromEntries(writes.map((w) => [w.key, JSON.parse(w.value)]));
    expect(byKey[CONNECTION_MODE_KEYS.defaultId]).toBe('privacy');
    expect(byKey[CONNECTION_MODE_KEYS.description('evade')]).toBe('Own copy');
    expect(byKey[CONNECTION_MODE_KEYS.label('privacy')]).toBe('P');
    expect(byKey[CONNECTION_MODE_KEYS.description('privacy')]).toBe(''); // explicit clear-write
    // It never writes squad/pool keys (those go through modePlacementWrites).
    expect(writes.every((w) => !w.key.endsWith('.squadUuids'))).toBe(true);
    expect(() => connectionModeWrites({ default: 'nope' })).toThrow(/default/);
    expect(() => connectionModeWrites('x')).toThrow();
    expect(connectionModeWrites({ modes: { bogus: { label: 'x' } } })).toEqual([]);
  });
});

describe('remnawave mode placement pools', () => {
  test('resolveModeSquadPool: dedupes; default-mode fallback; corrupt → []', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      const now = Date.now();
      await ctx.db.insert('appSettings', {
        key: 'remnawave.modePlacement.evade.squads',
        value: JSON.stringify(['sq-a', 'sq-b', 'sq-a']), // dupe dropped
        updatedAt: now,
      });
      await ctx.db.insert('appSettings', {
        key: 'connectionMode.default',
        value: JSON.stringify('evade'),
        updatedAt: now,
      });
    });
    expect(await t.run((ctx) => resolveModeSquadPool(ctx.db, 'evade'))).toEqual(['sq-a', 'sq-b']);
    // No explicit mode → the default mode's pool.
    expect(await t.run((ctx) => resolveModeSquadPool(ctx.db, null))).toEqual(['sq-a', 'sq-b']);
    // Unbound mode → [].
    expect(await t.run((ctx) => resolveModeSquadPool(ctx.db, 'privacy'))).toEqual([]);
    // Deterministic first-of-pool.
    expect(await t.run((ctx) => resolveModePlacementStable(ctx.db, 'evade'))).toBe('sq-a');
    // Corrupt JSON → [] (never throws).
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'remnawave.modePlacement.privacy.squads',
        value: 'not json{',
        updatedAt: Date.now(),
      }),
    );
    expect(await t.run((ctx) => resolveModeSquadPool(ctx.db, 'privacy'))).toEqual([]);
  });

  test('resolveBoundModeIds: only modes with a non-empty pool are bound', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      const now = Date.now();
      await ctx.db.insert('appSettings', {
        key: 'remnawave.modePlacement.evade.squads',
        value: JSON.stringify(['sq-a']),
        updatedAt: now,
      });
      await ctx.db.insert('appSettings', {
        key: 'remnawave.modePlacement.privacy.squads',
        value: JSON.stringify([]), // empty → not bound
        updatedAt: now,
      });
    });
    const bound = await t.run(async (ctx) => [...(await resolveBoundModeIds(ctx.db))]);
    expect(bound).toEqual(['evade']);
  });

  test('modePlacementWrites: maps pools (deduped), [] is a clear-write, bad shapes throw', () => {
    const writes = modePlacementWrites({
      modes: { evade: { squadUuids: ['sq-1', 'sq-2', 'sq-1'] }, privacy: { squadUuids: [] } },
    });
    const byKey = Object.fromEntries(writes.map((w) => [w.key, JSON.parse(w.value)]));
    expect(byKey['remnawave.modePlacement.evade.squads']).toEqual(['sq-1', 'sq-2']);
    expect(byKey['remnawave.modePlacement.privacy.squads']).toEqual([]);
    expect(() => modePlacementWrites({ modes: { evade: { squadUuids: 'nope' } } })).toThrow(
      /squadUuids/,
    );
    expect(() => modePlacementWrites({ modes: { evade: { squadUuids: ['ok', ''] } } })).toThrow(
      /squadUuids/,
    );
    // Unknown mode ids ignored.
    expect(modePlacementWrites({ modes: { bogus: { squadUuids: ['x'] } } })).toEqual([]);
  });
});

describe('resolvePlacementPool — anti-squad-less fallback (WS1)', () => {
  const bind = (t: ReturnType<typeof convexTest>, id: string, squads: string[]) =>
    t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: `remnawave.modePlacement.${id}.squads`,
        value: JSON.stringify(squads),
        updatedAt: Date.now(),
      }),
    );

  test('a bound mode resolves its OWN pool', async () => {
    const t = convexTest(schema, modules);
    await bind(t, 'privacy', ['P']);
    expect(await t.run((ctx) => resolvePlacementPool(ctx.db, 'privacy'))).toEqual(['P']);
  });

  test('an UNBOUND mode falls back to the DEFAULT mode pool', async () => {
    const t = convexTest(schema, modules);
    await bind(t, 'evade', ['E']); // evade is the catalog default
    // privacy has no pool → falls back to evade (default).
    expect(await t.run((ctx) => resolvePlacementPool(ctx.db, 'privacy'))).toEqual(['E']);
  });

  test('requested + default both unbound → ANY bound pool (catalog order)', async () => {
    const t = convexTest(schema, modules);
    await bind(t, 'privacy', ['P']); // only privacy bound; evade (requested+default) unbound
    expect(await t.run((ctx) => resolvePlacementPool(ctx.db, 'evade'))).toEqual(['P']);
  });

  test('nothing bound anywhere → [] (caller issues squad-less + audits)', async () => {
    const t = convexTest(schema, modules);
    expect(await t.run((ctx) => resolvePlacementPool(ctx.db, 'privacy'))).toEqual([]);
  });

  test('resolveModePlacementStable inherits the fallback (never clears a live squad)', async () => {
    const t = convexTest(schema, modules);
    await bind(t, 'evade', ['E']);
    // A key whose mode (privacy) lost its pool still resolves a real squad on push.
    expect(await t.run((ctx) => resolveModePlacementStable(ctx.db, 'privacy'))).toBe('E');
    // Truly-unbound deploy → null (nothing to preserve).
    const t2 = convexTest(schema, modules);
    expect(await t2.run((ctx) => resolveModePlacementStable(ctx.db, 'privacy'))).toBeNull();
  });
});
