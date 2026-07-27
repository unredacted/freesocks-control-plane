/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import {
  resolveConnectionModes,
  resolveConnectionModeFamilies,
  resolveDefaultModeId,
  publicProjection,
  publicFamilyProjection,
  connectionModeWrites,
  canonicalModeId,
  CONNECTION_MODE_KEYS,
  CONNECTION_MODE_FAMILY_KEYS,
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

/** A resolved-leaf fixture with the boilerplate filled in. */
function mode(over: Partial<ConnectionMode> & Pick<ConnectionMode, 'id'>): ConnectionMode {
  return {
    family: 'freedom',
    deliveryStyle: 'url',
    label: null,
    description: null,
    isDefault: false,
    isFamilyDefault: false,
    enabled: true,
    order: 0,
    deprecated: false,
    ...over,
  };
}

describe('connectionModes catalog', () => {
  test('resolves defaults with no rows: freedom-ws default, deliveryStyle + family set', async () => {
    const t = convexTest(schema, modules);
    const modes = await t.run((ctx) => resolveConnectionModes(ctx.db));
    const live = modes.filter((m) => !m.deprecated).map((m) => m.id);
    expect(live.sort()).toEqual(['freedom-reality', 'freedom-ws', 'privacy-reality']);
    const ws = modes.find((m) => m.id === 'freedom-ws')!;
    expect(ws.isDefault).toBe(true);
    expect(ws.deliveryStyle).toBe('url');
    expect(ws.family).toBe('freedom');
    expect(ws.isFamilyDefault).toBe(true);
    expect(modes.find((m) => m.id === 'privacy-reality')!.deliveryStyle).toBe('rawConfig');
    expect(modes.find((m) => m.id === 'privacy-reality')!.family).toBe('privacy');
    expect(modes.every((m) => m.label === null && m.description === null)).toBe(true);
    expect(DEFAULT_CONNECTION_MODE).toBe('freedom-ws');
    expect(await t.run((ctx) => resolveDefaultModeId(ctx.db))).toBe('freedom-ws');
  });

  test('freedom-reality ships DARK: enabled only once an admin turns it on', async () => {
    const t = convexTest(schema, modules);
    let modes = await t.run((ctx) => resolveConnectionModes(ctx.db));
    expect(modes.find((m) => m.id === 'freedom-reality')!.enabled).toBe(false);
    expect(modes.find((m) => m.id === 'freedom-ws')!.enabled).toBe(true);

    await t.run(async (ctx) => {
      await ctx.db.insert('appSettings', {
        key: CONNECTION_MODE_KEYS.enabled('freedom-reality'),
        value: JSON.stringify(true),
        updatedAt: Date.now(),
      });
    });
    modes = await t.run((ctx) => resolveConnectionModes(ctx.db));
    expect(modes.find((m) => m.id === 'freedom-reality')!.enabled).toBe(true);
  });

  test('disabling a FAMILY disables its whole subtree', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      await ctx.db.insert('appSettings', {
        key: CONNECTION_MODE_FAMILY_KEYS.enabled('freedom'),
        value: JSON.stringify(false),
        updatedAt: Date.now(),
      });
    });
    const modes = await t.run((ctx) => resolveConnectionModes(ctx.db));
    expect(modes.find((m) => m.id === 'freedom-ws')!.enabled).toBe(false);
    expect(modes.find((m) => m.id === 'freedom-reality')!.enabled).toBe(false);
    expect(modes.find((m) => m.id === 'privacy-reality')!.enabled).toBe(true);
  });

  test('the default never resolves to a DISABLED mode', async () => {
    const t = convexTest(schema, modules);
    // Disable the whole freedom family, which owns the compiled default.
    await t.run(async (ctx) => {
      await ctx.db.insert('appSettings', {
        key: CONNECTION_MODE_FAMILY_KEYS.enabled('freedom'),
        value: JSON.stringify(false),
        updatedAt: Date.now(),
      });
    });
    // Falls through to the only remaining enabled mode rather than a dead id.
    expect(await t.run((ctx) => resolveDefaultModeId(ctx.db))).toBe('privacy-reality');
    const modes = await t.run((ctx) => resolveConnectionModes(ctx.db));
    expect(modes.find((m) => m.isDefault)!.id).toBe('privacy-reality');
  });

  test('a stored default naming a DISABLED mode is ignored', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      const now = Date.now();
      // freedom-reality is dark by default; pointing the default at it must not stick.
      await ctx.db.insert('appSettings', {
        key: CONNECTION_MODE_KEYS.defaultId,
        value: JSON.stringify('freedom-reality'),
        updatedAt: now,
      });
    });
    expect(await t.run((ctx) => resolveDefaultModeId(ctx.db))).toBe('freedom-ws');
  });

  test('a stored default naming a LEGACY id resolves to its successor', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      await ctx.db.insert('appSettings', {
        key: CONNECTION_MODE_KEYS.defaultId,
        value: JSON.stringify('privacy'),
        updatedAt: Date.now(),
      });
    });
    expect(await t.run((ctx) => resolveDefaultModeId(ctx.db))).toBe('privacy-reality');
    expect(canonicalModeId('evade')).toBe('freedom-ws');
    expect(canonicalModeId('freedom-ws')).toBe('freedom-ws');
  });

  test('resolves admin label/description + custom default from appSettings', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      const now = Date.now();
      await ctx.db.insert('appSettings', {
        key: CONNECTION_MODE_KEYS.label('privacy-reality'),
        value: JSON.stringify('Max privacy'),
        updatedAt: now,
      });
      await ctx.db.insert('appSettings', {
        key: CONNECTION_MODE_KEYS.description('privacy-reality'),
        value: JSON.stringify('Direct Reality, no CDN.'),
        updatedAt: now,
      });
      await ctx.db.insert('appSettings', {
        key: CONNECTION_MODE_KEYS.defaultId,
        value: JSON.stringify('privacy-reality'),
        updatedAt: now,
      });
    });
    const modes = await t.run((ctx) => resolveConnectionModes(ctx.db));
    const priv = modes.find((m) => m.id === 'privacy-reality')!;
    expect(priv.label).toBe('Max privacy');
    expect(priv.description).toBe('Direct Reality, no CDN.');
    expect(priv.isDefault).toBe(true);
    expect(modes.find((m) => m.id === 'freedom-ws')!.isDefault).toBe(false);
    expect(await t.run((ctx) => resolveDefaultModeId(ctx.db))).toBe('privacy-reality');
  });

  test('family label/description resolve, and blank clears to null', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      const now = Date.now();
      await ctx.db.insert('appSettings', {
        key: CONNECTION_MODE_FAMILY_KEYS.label('freedom'),
        value: JSON.stringify('Freedom'),
        updatedAt: now,
      });
      await ctx.db.insert('appSettings', {
        key: CONNECTION_MODE_FAMILY_KEYS.description('privacy'),
        value: JSON.stringify('   '),
        updatedAt: now,
      });
    });
    const families = await t.run((ctx) => resolveConnectionModeFamilies(ctx.db));
    expect(families.find((f) => f.id === 'freedom')!.label).toBe('Freedom');
    expect(families.find((f) => f.id === 'privacy')!.description).toBeNull();
    expect(families.every((f) => f.enabled)).toBe(true);
  });

  test('blank/whitespace label + description clear to null; corrupt/invalid default never throws', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      const now = Date.now();
      await ctx.db.insert('appSettings', {
        key: CONNECTION_MODE_KEYS.label('freedom-ws'),
        value: JSON.stringify('   '),
        updatedAt: now,
      });
      await ctx.db.insert('appSettings', {
        key: CONNECTION_MODE_KEYS.description('freedom-ws'),
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
    expect(modes.find((m) => m.id === 'freedom-ws')!.label).toBeNull();
    expect(modes.find((m) => m.id === 'freedom-ws')!.description).toBeNull();
    expect(modes.find((m) => m.id === 'freedom-ws')!.isDefault).toBe(true); // invalid → compiled
  });

  test('publicProjection: omits disabled + deprecated, ships family, sorts by order, no UUID', () => {
    const modes: ConnectionMode[] = [
      mode({
        id: 'privacy-reality',
        family: 'privacy',
        deliveryStyle: 'rawConfig',
        label: 'Custom privacy',
        description: 'Body',
        isFamilyDefault: true,
        order: 1,
      }),
      mode({ id: 'freedom-ws', isDefault: true, isFamilyDefault: true, order: 0 }),
      // Admin-disabled and legacy entries must not reach members.
      mode({ id: 'freedom-reality', deliveryStyle: 'rawConfig', enabled: false, order: 2 }),
      mode({ id: 'evade', family: undefined, enabled: false, deprecated: true, order: 90 }),
    ];
    const pub = publicProjection(modes, new Set(['freedom-ws']));
    expect(pub.map((m) => m.id)).toEqual(['freedom-ws', 'privacy-reality']); // sorted by order
    expect(pub[0]).toEqual({
      id: 'freedom-ws',
      family: 'freedom',
      deliveryStyle: 'url',
      label: null,
      description: null,
      isDefault: true,
      isFamilyDefault: true,
      available: true,
    });
    expect(pub[1]).toMatchObject({
      id: 'privacy-reality',
      family: 'privacy',
      deliveryStyle: 'rawConfig',
      label: 'Custom privacy',
      available: false, // not in the bound set
    });
  });

  test('publicProjection: an enabled-but-UNBOUND mode ships as available:false, not hidden', () => {
    const pub = publicProjection([mode({ id: 'freedom-ws', isDefault: true })], new Set());
    expect(pub).toHaveLength(1);
    expect(pub[0]!.available).toBe(false);
  });

  test('publicFamilyProjection drops families with no visible child', () => {
    const families = [
      { id: 'freedom', label: null, description: null, enabled: true, order: 0 },
      { id: 'privacy', label: 'P', description: null, enabled: true, order: 1 },
    ];
    const visible = publicProjection([mode({ id: 'freedom-ws' })], new Set(['freedom-ws']));
    expect(publicFamilyProjection(families, visible).map((f) => f.id)).toEqual(['freedom']);
  });

  test('connectionModeWrites: families + enabled toggles, empty string clears, unknown ids ignored', () => {
    const writes = connectionModeWrites({
      default: 'privacy-reality',
      families: { privacy: { label: 'Privacy Mode', enabled: true } },
      modes: {
        'freedom-ws': { description: 'Own copy' },
        'privacy-reality': { label: 'P', description: '', enabled: true },
        'freedom-reality': { enabled: true },
      },
    });
    const byKey = Object.fromEntries(writes.map((w) => [w.key, JSON.parse(w.value)]));
    expect(byKey[CONNECTION_MODE_KEYS.defaultId]).toBe('privacy-reality');
    expect(byKey[CONNECTION_MODE_KEYS.description('freedom-ws')]).toBe('Own copy');
    expect(byKey[CONNECTION_MODE_KEYS.label('privacy-reality')]).toBe('P');
    expect(byKey[CONNECTION_MODE_KEYS.description('privacy-reality')]).toBe(''); // explicit clear
    expect(byKey[CONNECTION_MODE_KEYS.enabled('freedom-reality')]).toBe(true);
    expect(byKey[CONNECTION_MODE_FAMILY_KEYS.label('privacy')]).toBe('Privacy Mode');
    expect(byKey[CONNECTION_MODE_FAMILY_KEYS.enabled('privacy')]).toBe(true);
    // It never writes squad/pool keys (those go through modePlacementWrites).
    expect(writes.every((w) => !w.key.endsWith('.squadUuids'))).toBe(true);
    expect(() => connectionModeWrites({ default: 'nope' })).toThrow(/default/);
    expect(() => connectionModeWrites('x')).toThrow();
    expect(connectionModeWrites({ modes: { bogus: { label: 'x' } } })).toEqual([]);
    // Legacy aliases are read-only: they resolve but can never be edited.
    expect(connectionModeWrites({ modes: { evade: { label: 'x' } } })).toEqual([]);
  });

  test('connectionModeWrites refuses to make a mode default and disable it in one save', () => {
    expect(() =>
      connectionModeWrites({
        default: 'privacy-reality',
        modes: { 'privacy-reality': { enabled: false } },
      }),
    ).toThrow(/disabled/);
    expect(() =>
      connectionModeWrites({
        default: 'privacy-reality',
        families: { privacy: { enabled: false } },
      }),
    ).toThrow(/disabled/);
    // A deprecated alias can never be the default.
    expect(() => connectionModeWrites({ default: 'evade' })).toThrow(/default/);
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
        key: 'remnawave.modePlacement.freedom-ws.squads',
        value: JSON.stringify(['sq-a']),
        updatedAt: now,
      });
      await ctx.db.insert('appSettings', {
        key: 'remnawave.modePlacement.privacy-reality.squads',
        value: JSON.stringify([]), // empty → not bound
        updatedAt: now,
      });
    });
    const bound = await t.run(async (ctx) => [...(await resolveBoundModeIds(ctx.db))]);
    expect(bound).toEqual(['freedom-ws']);
  });

  test('resolveBoundModeIds: a pre-migration pool also marks its SUCCESSOR bound', async () => {
    // Dual-accept window: the pool is still stored under the legacy key, but the
    // public `available` flag is computed against the new id, so both must resolve.
    const t = convexTest(schema, modules);
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'remnawave.modePlacement.evade.squads',
        value: JSON.stringify(['sq-a']),
        updatedAt: Date.now(),
      }),
    );
    const bound = await t.run(async (ctx) => [...(await resolveBoundModeIds(ctx.db))]);
    expect(bound.sort()).toEqual(['evade', 'freedom-ws']);
    // …and the pool itself resolves through the new id.
    expect(await t.run((ctx) => resolveModeSquadPool(ctx.db, 'freedom-ws'))).toEqual(['sq-a']);
  });

  // Real-shaped squad UUIDs — replace/add entries are UUID-validated server-side.
  const SQ1 = '11111111-1111-4111-8111-111111111111';
  const SQ2 = '22222222-2222-4222-8222-222222222222';
  const SQ3 = '33333333-3333-4333-8333-333333333333';
  const bindPool = (t: ReturnType<typeof convexTest>, id: string, squads: string[]) =>
    t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: `remnawave.modePlacement.${id}.squads`,
        value: JSON.stringify(squads),
        updatedAt: Date.now(),
      }),
    );

  test('modePlacementWrites: maps pools (deduped), [] is a clear-write, bad shapes throw', async () => {
    const t = convexTest(schema, modules);
    const writes = await t.run((ctx) =>
      modePlacementWrites(ctx.db, {
        modes: { evade: { squadUuids: [SQ1, SQ2, SQ1] }, privacy: { squadUuids: [] } },
      }),
    );
    const byKey = Object.fromEntries(writes.map((w) => [w.key, JSON.parse(w.value)]));
    expect(byKey['remnawave.modePlacement.evade.squads']).toEqual([SQ1, SQ2]);
    expect(byKey['remnawave.modePlacement.privacy.squads']).toEqual([]);
    await expect(
      t.run((ctx) => modePlacementWrites(ctx.db, { modes: { evade: { squadUuids: 'nope' } } })),
    ).rejects.toThrow(/squadUuids/);
    await expect(
      t.run((ctx) => modePlacementWrites(ctx.db, { modes: { evade: { squadUuids: [SQ1, ''] } } })),
    ).rejects.toThrow(/squadUuids/);
    // Non-UUID entries are rejected server-side (headless callers have no UI guard).
    await expect(
      t.run((ctx) =>
        modePlacementWrites(ctx.db, { modes: { evade: { squadUuids: ['not-a-uuid'] } } }),
      ),
    ).rejects.toThrow(/not a squad UUID: not-a-uuid/);
    // Unknown mode ids ignored.
    expect(
      await t.run((ctx) =>
        modePlacementWrites(ctx.db, { modes: { bogus: { squadUuids: [SQ1] } } }),
      ),
    ).toEqual([]);
  });

  test('modePlacementWrites: addSquadUuids appends to the stored pool (deduped)', async () => {
    const t = convexTest(schema, modules);
    await bindPool(t, 'evade', [SQ1]);
    const writes = await t.run((ctx) =>
      modePlacementWrites(ctx.db, { modes: { evade: { addSquadUuids: [SQ2, SQ1] } } }),
    );
    expect(JSON.parse(writes[0]!.value)).toEqual([SQ1, SQ2]);
    // add against an unbound mode starts a fresh pool.
    const fresh = await t.run((ctx) =>
      modePlacementWrites(ctx.db, { modes: { privacy: { addSquadUuids: [SQ3] } } }),
    );
    expect(JSON.parse(fresh[0]!.value)).toEqual([SQ3]);
    // add entries are UUID-validated too.
    await expect(
      t.run((ctx) =>
        modePlacementWrites(ctx.db, { modes: { evade: { addSquadUuids: ['garbage'] } } }),
      ),
    ).rejects.toThrow(/not a squad UUID/);
  });

  test('modePlacementWrites: removeSquadUuids drops from the stored pool (any string ok)', async () => {
    const t = convexTest(schema, modules);
    await bindPool(t, 'evade', [SQ1, SQ2, 'legacy-garbage']);
    const writes = await t.run((ctx) =>
      modePlacementWrites(ctx.db, {
        modes: { evade: { removeSquadUuids: [SQ2, 'legacy-garbage', SQ3] } },
      }),
    );
    // SQ3 wasn't in the pool — removing an absent entry is a no-op, and the
    // non-UUID 'legacy-garbage' is removable (purge path for pre-validation rows).
    expect(JSON.parse(writes[0]!.value)).toEqual([SQ1]);
  });

  test('modePlacementWrites: replace + add + remove compose in that order', async () => {
    const t = convexTest(schema, modules);
    await bindPool(t, 'evade', ['ignored-by-replace']);
    const writes = await t.run((ctx) =>
      modePlacementWrites(ctx.db, {
        modes: {
          evade: { squadUuids: [SQ1, SQ2], addSquadUuids: [SQ3], removeSquadUuids: [SQ1] },
        },
      }),
    );
    expect(JSON.parse(writes[0]!.value)).toEqual([SQ2, SQ3]);
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
