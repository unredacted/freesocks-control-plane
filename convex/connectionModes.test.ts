/// <reference types="vite/client" />
/**
 * The DB-driven connection-mode catalog: table-backed resolution with the
 * compiled-defaults fallback, enabled AND-gating, the default ladder,
 * per-backend availability, the public projections, and the admin CRUD
 * (create/edit/delete with the strand-nobody guards).
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import {
  DEFAULT_CONNECTION_MODE,
  publicFamilyProjection,
  publicProjection,
  resolveDefaultModeId,
  resolveModeCatalog,
} from './lib/connectionModes';
import { resolveCatalogWithAvailability, resolvePublicModes } from './lib/placement';

const modules = import.meta.glob('./**/*.*s');

const SQUAD = '11111111-2222-3333-4444-555555555555';

async function bindPool(t: ReturnType<typeof convexTest>, slug: string, squads: string[]) {
  await t.run((ctx) =>
    ctx.db.insert('modePlacements', {
      modeSlug: slug,
      backend: 'remnawave',
      config: JSON.stringify({ squadUuids: squads }),
      updatedAt: Date.now(),
    }),
  );
}

describe('resolveModeCatalog', () => {
  test('empty tables → the compiled defaults (never a blank picker)', async () => {
    const t = convexTest(schema, modules);
    const { families, modes } = await t.run((ctx) => resolveModeCatalog(ctx.db));
    expect(families.map((f) => f.id)).toEqual(['freedom', 'privacy']);
    expect(families.map((f) => f.iconId)).toEqual(['zap', 'shield-check']);
    expect(modes.map((m) => m.id)).toEqual(['freedom-ws', 'freedom-reality', 'privacy-reality']);
    // freedom-reality ships dark; the other two are enabled.
    expect(modes.find((m) => m.id === 'freedom-reality')!.enabled).toBe(false);
    expect(modes.find((m) => m.id === 'freedom-ws')!.enabled).toBe(true);
    expect(modes.find((m) => m.id === 'freedom-ws')!.isDefault).toBe(true);
    expect(modes.every((m) => m.builtIn)).toBe(true);
  });

  test('DB rows replace the defaults entirely once seeded', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      await ctx.db.insert('connectionModeFamilies', {
        slug: 'custom',
        label: 'Custom Family',
        iconId: 'globe',
        enabled: true,
        order: 0,
        updatedAt: Date.now(),
      });
      await ctx.db.insert('connectionModes', {
        slug: 'custom-ws',
        familySlug: 'custom',
        deliveryStyle: 'url',
        label: 'Custom WS',
        enabled: true,
        isFamilyDefault: true,
        backends: ['remnawave'],
        order: 0,
        updatedAt: Date.now(),
      });
    });
    const { families, modes } = await t.run((ctx) => resolveModeCatalog(ctx.db));
    // No compiled entries bleed through — the tables are the catalog now.
    expect(families.map((f) => f.id)).toEqual(['custom']);
    expect(modes.map((m) => m.id)).toEqual(['custom-ws']);
    expect(modes[0]!.builtIn).toBe(false);
    expect(modes[0]!.isDefault).toBe(true); // first enabled — compiled default absent
  });

  test('enabled = own toggle AND the family toggle; a missing family is fail-safe disabled + orphaned', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      await ctx.db.insert('connectionModeFamilies', {
        slug: 'fam',
        label: 'Fam',
        iconId: 'zap',
        enabled: false, // family off ⇒ whole subtree off
        order: 0,
        updatedAt: Date.now(),
      });
      await ctx.db.insert('connectionModes', {
        slug: 'fam-a',
        familySlug: 'fam',
        deliveryStyle: 'url',
        label: 'A',
        enabled: true,
        isFamilyDefault: true,
        backends: ['remnawave'],
        order: 0,
        updatedAt: Date.now(),
      });
      await ctx.db.insert('connectionModes', {
        slug: 'lost',
        familySlug: 'gone', // no such family row
        deliveryStyle: 'url',
        label: 'Lost',
        enabled: true,
        isFamilyDefault: false,
        backends: ['remnawave'],
        order: 0,
        updatedAt: Date.now(),
      });
    });
    const { modes } = await t.run((ctx) => resolveModeCatalog(ctx.db));
    const a = modes.find((m) => m.id === 'fam-a')!;
    expect(a.ownEnabled).toBe(true);
    expect(a.enabled).toBe(false);
    const lost = modes.find((m) => m.id === 'lost')!;
    expect(lost.enabled).toBe(false);
    expect(lost.orphaned).toBe(true);
  });

  test('default ladder: stored pointer → compiled default → legacy pointer canonicalizes', async () => {
    const t = convexTest(schema, modules);
    // Stored pointer respected while its mode is enabled.
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'connectionMode.default',
        value: JSON.stringify('privacy-reality'),
        updatedAt: Date.now(),
      }),
    );
    expect(await t.run((ctx) => resolveDefaultModeId(ctx.db))).toBe('privacy-reality');

    // Pointer at a DISABLED mode → falls to the compiled default.
    await t.run(async (ctx) => {
      const row = await ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.eq('key', 'connectionMode.default'))
        .unique();
      await ctx.db.patch(row!._id, { value: JSON.stringify('freedom-reality') }); // ships dark
    });
    expect(await t.run((ctx) => resolveDefaultModeId(ctx.db))).toBe(DEFAULT_CONNECTION_MODE);

    // A legacy-id pointer canonicalizes.
    await t.run(async (ctx) => {
      const row = await ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.eq('key', 'connectionMode.default'))
        .unique();
      await ctx.db.patch(row!._id, { value: JSON.stringify('privacy') });
    });
    expect(await t.run((ctx) => resolveDefaultModeId(ctx.db))).toBe('privacy-reality');
  });
});

describe('per-backend availability', () => {
  test('placement-capable backend requires a bound pool; placement-less is trivially available', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      await ctx.db.insert('connectionModeFamilies', {
        slug: 'fam',
        label: 'Fam',
        iconId: 'zap',
        enabled: true,
        order: 0,
        updatedAt: Date.now(),
      });
      for (const [slug, backends] of [
        ['both-mode', ['remnawave', 'outline']],
        ['rw-only', ['remnawave']],
        ['ol-only', ['outline']],
      ] as const) {
        await ctx.db.insert('connectionModes', {
          slug,
          familySlug: 'fam',
          deliveryStyle: 'url',
          label: slug,
          enabled: true,
          isFamilyDefault: slug === 'both-mode',
          backends: [...backends],
          order: 0,
          updatedAt: Date.now(),
        });
      }
    });
    // Nothing bound yet: remnawave needs a pool, outline never does.
    let { modes } = await t.run(async (ctx) => {
      const { modes } = await resolveCatalogWithAvailability(ctx.db);
      return { modes };
    });
    expect(modes.find((m) => m.id === 'both-mode')!.availableBackends).toEqual(['outline']);
    expect(modes.find((m) => m.id === 'rw-only')!.availableBackends).toEqual([]);
    expect(modes.find((m) => m.id === 'ol-only')!.availableBackends).toEqual(['outline']);

    await bindPool(t, 'both-mode', [SQUAD]);
    ({ modes } = await t.run(async (ctx) => {
      const { modes } = await resolveCatalogWithAvailability(ctx.db);
      return { modes };
    }));
    expect(modes.find((m) => m.id === 'both-mode')!.availableBackends).toEqual([
      'remnawave',
      'outline',
    ]);
  });

  test('a disabled mode is available nowhere, bound or not', async () => {
    const t = convexTest(schema, modules);
    await bindPool(t, 'freedom-reality', [SQUAD]); // ships dark
    const { modes } = await t.run(async (ctx) => {
      const { modes } = await resolveCatalogWithAvailability(ctx.db);
      return { modes };
    });
    expect(modes.find((m) => m.id === 'freedom-reality')!.availableBackends).toEqual([]);
  });
});

describe('public projections', () => {
  test('disabled modes are OMITTED; availability + copy/icon ride along', async () => {
    const t = convexTest(schema, modules);
    await bindPool(t, 'freedom-ws', [SQUAD]);
    const { modes: pub, catalog } = await t.run(async (ctx) => {
      const { modes, catalog } = await resolvePublicModes(ctx.db);
      return { modes, catalog: { families: catalog.families } };
    });
    // freedom-reality (disabled) is not even present.
    expect(pub.map((m) => m.id)).toEqual(['freedom-ws', 'privacy-reality']);
    const ws = pub.find((m) => m.id === 'freedom-ws')!;
    expect(ws.available).toBe(true);
    expect(ws.availableBackends).toEqual(['remnawave']);
    const priv = pub.find((m) => m.id === 'privacy-reality')!;
    expect(priv.available).toBe(false); // enabled but unbound

    const fams = publicFamilyProjection(catalog.families, pub);
    expect(fams.map((f) => f.id)).toEqual(['freedom', 'privacy']);
    expect(fams[0]!.iconId).toBe('zap');
    // Built-ins with no admin copy ship null → the SPA renders i18n.
    expect(fams[0]!.label).toBeNull();
    expect(fams[0]!.audience).toBeNull();
  });

  test('a family whose every child is disabled disappears from the projection', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.connectionModes.updateMode, {
      slug: 'privacy-reality',
      enabled: false,
    });
    const { modes: pub, catalog } = await t.run(async (ctx) => {
      const { modes, catalog } = await resolvePublicModes(ctx.db);
      return { modes, catalog: { families: catalog.families } };
    });
    expect(publicFamilyProjection(catalog.families, pub).map((f) => f.id)).toEqual(['freedom']);
  });

  test('publicProjection never leaks admin-only fields', async () => {
    const t = convexTest(schema, modules);
    const { modes } = await t.run(async (ctx) => {
      const { modes } = await resolveCatalogWithAvailability(ctx.db);
      return { modes };
    });
    const pub = publicProjection(modes);
    for (const m of pub) {
      expect(m).not.toHaveProperty('ownEnabled');
      expect(m).not.toHaveProperty('orphaned');
      expect(m).not.toHaveProperty('builtIn');
      expect(m).not.toHaveProperty('isCensorshipRecommended');
    }
  });
});

describe('memberMode', () => {
  test('projects the member’s mode even when DISABLED (deliveryStyle + family survive)', async () => {
    const t = convexTest(schema, modules);
    // freedom-reality ships dark; a member left on it must still resolve it.
    const out = await t.query(internal.connectionModes.memberMode, {
      modeId: 'freedom-reality',
      backend: 'remnawave',
    });
    expect(out).toMatchObject({
      id: 'freedom-reality',
      deliveryStyle: 'rawConfig',
      family: { id: 'freedom', label: null },
      available: false,
    });
  });

  test('canonicalizes a legacy id and falls back to the default for null', async () => {
    const t = convexTest(schema, modules);
    const legacy = await t.query(internal.connectionModes.memberMode, {
      modeId: 'privacy',
      backend: 'remnawave',
    });
    expect(legacy!.id).toBe('privacy-reality');
    const none = await t.query(internal.connectionModes.memberMode, {
      modeId: null,
      backend: 'remnawave',
    });
    expect(none!.id).toBe(DEFAULT_CONNECTION_MODE);
  });

  test('availability is judged against the MEMBER’s backend', async () => {
    const t = convexTest(schema, modules);
    await bindPool(t, 'freedom-ws', [SQUAD]);
    const onRw = await t.query(internal.connectionModes.memberMode, {
      modeId: 'freedom-ws',
      backend: 'remnawave',
    });
    expect(onRw!.available).toBe(true);
    const onOl = await t.query(internal.connectionModes.memberMode, {
      modeId: 'freedom-ws',
      backend: 'outline',
    });
    // freedom-ws declares remnawave only → not available on outline.
    expect(onOl!.available).toBe(false);
  });
});

describe('admin CRUD', () => {
  test('first edit MATERIALIZES the compiled defaults, then applies (no stranded defaults)', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.connectionModes.updateMode, {
      slug: 'freedom-reality',
      enabled: true,
    });
    const rows = await t.run((ctx) => ctx.db.query('connectionModes').collect());
    expect(rows.map((r) => r.slug).sort()).toEqual([
      'freedom-reality',
      'freedom-ws',
      'privacy-reality',
    ]);
    expect(rows.find((r) => r.slug === 'freedom-reality')!.enabled).toBe(true);
    // The other defaults kept their compiled state.
    expect(rows.find((r) => r.slug === 'freedom-ws')!.enabled).toBe(true);
  });

  test('createMode: validation (slug shape, dup, unknown family, empty backends, label required)', async () => {
    const t = convexTest(schema, modules);
    const base = {
      label: 'Turbo',
      family: 'freedom',
      deliveryStyle: 'url' as const,
      backends: ['remnawave' as const],
    };
    await expect(
      t.mutation(internal.connectionModes.createMode, { ...base, slug: 'Bad Slug!' }),
    ).rejects.toThrow(/slug must be/i);
    await expect(
      t.mutation(internal.connectionModes.createMode, { ...base, slug: 'freedom-ws' }),
    ).rejects.toThrow(/already exists/i);
    await expect(
      t.mutation(internal.connectionModes.createMode, { ...base, slug: 'turbo', family: 'nope' }),
    ).rejects.toThrow(/unknown family/i);
    await expect(
      t.mutation(internal.connectionModes.createMode, { ...base, slug: 'turbo', backends: [] }),
    ).rejects.toThrow(/at least one backend/i);
    await expect(
      t.mutation(internal.connectionModes.createMode, { ...base, slug: 'turbo', label: '  ' }),
    ).rejects.toThrow(/label is required/i);

    const created = await t.mutation(internal.connectionModes.createMode, {
      ...base,
      slug: 'turbo',
      isFamilyDefault: true,
    });
    expect(created.slug).toBe('turbo');
    const { modes } = await t.run((ctx) => resolveModeCatalog(ctx.db));
    const turbo = modes.find((m) => m.id === 'turbo')!;
    expect(turbo.label).toBe('Turbo');
    expect(turbo.isFamilyDefault).toBe(true);
    // The flag moved off the family's previous default leaf.
    expect(modes.find((m) => m.id === 'freedom-ws')!.isFamilyDefault).toBe(false);
  });

  test('createFamily + a mode in it composes availability end to end', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.connectionModes.createFamily, {
      slug: 'stealth',
      label: 'Stealth',
      audience: 'For the most hostile networks',
      iconId: 'eye-off',
      order: 5,
    });
    await t.mutation(internal.connectionModes.createMode, {
      slug: 'stealth-x',
      label: 'Stealth X',
      family: 'stealth',
      deliveryStyle: 'rawConfig',
      backends: ['remnawave'],
    });
    await bindPool(t, 'stealth-x', [SQUAD]);
    const { modes: pub, catalog } = await t.run(async (ctx) => {
      const { modes, catalog } = await resolvePublicModes(ctx.db);
      return { modes, catalog: { families: catalog.families } };
    });
    const x = pub.find((m) => m.id === 'stealth-x')!;
    expect(x.available).toBe(true);
    const fam = publicFamilyProjection(catalog.families, pub).find((f) => f.id === 'stealth')!;
    expect(fam).toMatchObject({
      label: 'Stealth',
      audience: 'For the most hostile networks',
      iconId: 'eye-off',
    });
  });

  test('removeFamily refuses while modes reference it', async () => {
    const t = convexTest(schema, modules);
    await expect(
      t.mutation(internal.connectionModes.removeFamily, { slug: 'freedom' }),
    ).rejects.toThrow(/still has modes/i);
  });

  test('removeMode: occupied guard (indexed existence check → conflict)', async () => {
    const t = convexTest(schema, modules);
    const tierId: Id<'tiers'> = await t.run((ctx) =>
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
    await t.run((ctx) =>
      ctx.db.insert('users', {
        tierId,
        status: 'active',
        connectionModeId: 'privacy-reality',
        updatedAt: Date.now(),
      }),
    );
    await expect(
      t.mutation(internal.connectionModes.removeMode, { slug: 'privacy-reality' }),
    ).rejects.toThrow(/members are currently on this mode/i);
  });

  test('removeMode: the resolved default cannot be deleted while another mode is enabled', async () => {
    const t = convexTest(schema, modules);
    await expect(
      t.mutation(internal.connectionModes.removeMode, { slug: 'freedom-ws' }),
    ).rejects.toThrow(/set another default/i);
  });

  test('removeMode cascades its placement bindings', async () => {
    const t = convexTest(schema, modules);
    await bindPool(t, 'privacy-reality', [SQUAD]);
    await t.mutation(internal.connectionModes.removeMode, { slug: 'privacy-reality' });
    const placements = await t.run((ctx) => ctx.db.query('modePlacements').collect());
    expect(placements.filter((p) => p.modeSlug === 'privacy-reality')).toHaveLength(0);
    const { modes } = await t.run((ctx) => resolveModeCatalog(ctx.db));
    expect(modes.map((m) => m.id)).not.toContain('privacy-reality');
  });

  test('updateFamily: label null clears a built-in back to i18n; non-built-in must keep one', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.connectionModes.updateFamily, {
      slug: 'freedom',
      label: 'Liberty Mode',
    });
    let { families } = await t.run((ctx) => resolveModeCatalog(ctx.db));
    expect(families.find((f) => f.id === 'freedom')!.label).toBe('Liberty Mode');
    await t.mutation(internal.connectionModes.updateFamily, { slug: 'freedom', label: null });
    ({ families } = await t.run((ctx) => resolveModeCatalog(ctx.db)));
    expect(families.find((f) => f.id === 'freedom')!.label).toBeNull();

    await t.mutation(internal.connectionModes.createFamily, {
      slug: 'custom',
      label: 'Custom',
    });
    await expect(
      t.mutation(internal.connectionModes.updateFamily, { slug: 'custom', label: null }),
    ).rejects.toThrow(/label is required/i);
  });

  test('makeDefault writes the pointer; family disable takes the default’s subtree down', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.connectionModes.updateMode, {
      slug: 'privacy-reality',
      makeDefault: true,
    });
    expect(await t.run((ctx) => resolveDefaultModeId(ctx.db))).toBe('privacy-reality');
    // Disabling the privacy family kills privacy-reality → the ladder falls back.
    await t.mutation(internal.connectionModes.updateFamily, { slug: 'privacy', enabled: false });
    expect(await t.run((ctx) => resolveDefaultModeId(ctx.db))).toBe(DEFAULT_CONNECTION_MODE);
  });
});

describe('internal list (validation surface)', () => {
  test('ships availability + legacy bound; disabled modes stay listed (admin/status need them)', async () => {
    const t = convexTest(schema, modules);
    await bindPool(t, 'freedom-ws', [SQUAD]);
    const modes = await t.query(internal.connectionModes.list, {});
    expect(modes.map((m) => m.id)).toEqual(['freedom-ws', 'freedom-reality', 'privacy-reality']);
    const ws = modes.find((m) => m.id === 'freedom-ws')!;
    expect(ws.bound).toBe(true);
    expect(ws.availableBackends).toEqual(['remnawave']);
    const reality = modes.find((m) => m.id === 'freedom-reality')!;
    expect(reality.enabled).toBe(false);
    expect(reality.bound).toBe(false);
  });
});
