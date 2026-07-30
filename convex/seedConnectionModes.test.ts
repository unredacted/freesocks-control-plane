/// <reference types="vite/client" />
/**
 * The connection-mode seed + migration centerpiece: fresh-deploy seeding,
 * absorption of the pre-refactor appSettings state (current AND legacy keys,
 * current-beats-legacy), the placement-pool move (existing-row-wins), the paged
 * legacy user-id rewrite, and the idempotency guarantees (double-run = zero
 * writes; admin edits survive every later deploy).
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';

const modules = import.meta.glob('./**/*.*s');

async function putSetting(t: ReturnType<typeof convexTest>, key: string, value: unknown) {
  await t.run((ctx) =>
    ctx.db.insert('appSettings', { key, value: JSON.stringify(value), updatedAt: Date.now() }),
  );
}

async function seedUserWithMode(
  t: ReturnType<typeof convexTest>,
  modeId: string | undefined,
): Promise<Id<'users'>> {
  const tierId: Id<'tiers'> = await t.run(async (ctx) => {
    // (collect+find, not withIndex: t.run's ctx typing loses table indexes here)
    const existing = (await ctx.db.query('tiers').collect()).find((x) => x.slug === 'free');
    if (existing) return existing._id;
    return ctx.db.insert('tiers', {
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
  });
  return t.run((ctx) =>
    ctx.db.insert('users', {
      tierId,
      status: 'active',
      connectionModeId: modeId,
      updatedAt: Date.now(),
    }),
  );
}

describe('seedConnectionModes: fresh deploy', () => {
  test('inserts the compiled defaults into empty tables', async () => {
    const t = convexTest(schema, modules);
    const out = await t.mutation(internal.seed.seedConnectionModes, {});
    expect(out).toMatchObject({ familiesInserted: 2, modesInserted: 3, poolsMoved: 0 });
    const fams = await t.run((ctx) => ctx.db.query('connectionModeFamilies').collect());
    const modes = await t.run((ctx) => ctx.db.query('connectionModes').collect());
    expect(fams.map((f) => f.slug).sort()).toEqual(['freedom', 'privacy']);
    expect(modes.map((m) => m.slug).sort()).toEqual([
      'freedom-reality',
      'freedom-ws',
      'privacy-reality',
    ]);
    // Fresh rows carry NO admin copy (null → the SPA's i18n).
    expect(fams.every((f) => f.label === undefined)).toBe(true);
    expect(modes.find((m) => m.slug === 'freedom-reality')!.enabled).toBe(false); // ships dark
    expect(modes.find((m) => m.slug === 'freedom-reality')!.isCensorshipRecommended).toBe(true);
  });

  test('double-run produces byte-identical state (zero new writes)', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.seed.seedConnectionModes, {});
    const snapshot = await t.run(async (ctx) => ({
      fams: await ctx.db.query('connectionModeFamilies').collect(),
      modes: await ctx.db.query('connectionModes').collect(),
      pools: await ctx.db.query('modePlacements').collect(),
    }));
    const out2 = await t.mutation(internal.seed.seedConnectionModes, {});
    expect(out2).toMatchObject({ familiesInserted: 0, modesInserted: 0, poolsMoved: 0 });
    const snapshot2 = await t.run(async (ctx) => ({
      fams: await ctx.db.query('connectionModeFamilies').collect(),
      modes: await ctx.db.query('connectionModes').collect(),
      pools: await ctx.db.query('modePlacements').collect(),
    }));
    expect(snapshot2).toEqual(snapshot);
  });

  test('admin edits (and deliberate deletes) survive a re-deploy seed', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.seed.seedConnectionModes, {});
    await t.mutation(internal.connectionModes.updateMode, {
      slug: 'freedom-ws',
      label: 'Tunnel Mode',
      enabled: false,
    });
    // The admin deletes a built-in outright (guards allow it: not default, unoccupied).
    await t.mutation(internal.connectionModes.removeMode, { slug: 'freedom-reality' });
    await t.mutation(internal.seed.seedConnectionModes, {});
    const modes = await t.run((ctx) => ctx.db.query('connectionModes').collect());
    // Not resurrected, not clobbered.
    expect(modes.map((m) => m.slug).sort()).toEqual(['freedom-ws', 'privacy-reality']);
    expect(modes.find((m) => m.slug === 'freedom-ws')!.label).toBe('Tunnel Mode');
    expect(modes.find((m) => m.slug === 'freedom-ws')!.enabled).toBe(false);
  });
});

describe('seedConnectionModes: absorbing pre-refactor appSettings', () => {
  test('label/description/enabled fold in from current keys', async () => {
    const t = convexTest(schema, modules);
    await putSetting(t, 'connectionMode.privacy-reality.label', 'Max privacy');
    await putSetting(t, 'connectionMode.privacy-reality.description', 'No CDN in the path.');
    await putSetting(t, 'connectionMode.freedom-reality.enabled', true); // operator lit it up
    await putSetting(t, 'connectionModeFamily.freedom.label', 'Internet Freedom');
    await t.mutation(internal.seed.seedConnectionModes, {});
    const modes = await t.run((ctx) => ctx.db.query('connectionModes').collect());
    const fams = await t.run((ctx) => ctx.db.query('connectionModeFamilies').collect());
    expect(modes.find((m) => m.slug === 'privacy-reality')).toMatchObject({
      label: 'Max privacy',
      description: 'No CDN in the path.',
    });
    expect(modes.find((m) => m.slug === 'freedom-reality')!.enabled).toBe(true);
    expect(fams.find((f) => f.slug === 'freedom')!.label).toBe('Internet Freedom');
    // Absorbed source rows are LEFT IN PLACE (deploy-1 rollback safety).
    const leftover = await t.run((ctx) =>
      ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.eq('key', 'connectionMode.privacy-reality.label'))
        .unique(),
    );
    expect(leftover).not.toBeNull();
  });

  test('legacy-keyed copy folds onto the successor; a current key wins over it', async () => {
    const t = convexTest(schema, modules);
    await putSetting(t, 'connectionMode.evade.label', 'Old Evade Label');
    await putSetting(t, 'connectionMode.privacy.label', 'Old Privacy Label');
    await putSetting(t, 'connectionMode.privacy-reality.label', 'New Privacy Label'); // wins
    await t.mutation(internal.seed.seedConnectionModes, {});
    const modes = await t.run((ctx) => ctx.db.query('connectionModes').collect());
    expect(modes.find((m) => m.slug === 'freedom-ws')!.label).toBe('Old Evade Label');
    expect(modes.find((m) => m.slug === 'privacy-reality')!.label).toBe('New Privacy Label');
  });

  test('the default pointer is canonicalized in place', async () => {
    const t = convexTest(schema, modules);
    await putSetting(t, 'connectionMode.default', 'privacy'); // legacy id
    await t.mutation(internal.seed.seedConnectionModes, {});
    const row = await t.run((ctx) =>
      ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.eq('key', 'connectionMode.default'))
        .unique(),
    );
    expect(JSON.parse(row!.value)).toBe('privacy-reality');
  });

  test('placement pools move to modePlacements rows (canonical slug, legacy key folds, existing row wins)', async () => {
    const t = convexTest(schema, modules);
    await putSetting(t, 'remnawave.modePlacement.evade.squads', ['sq-legacy-ws']);
    await putSetting(t, 'remnawave.modePlacement.privacy-reality.squads', ['sq-priv']);
    // The admin already wrote the new store for privacy-reality → the seed must not clobber it.
    await t.run((ctx) =>
      ctx.db.insert('modePlacements', {
        modeSlug: 'privacy-reality',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: ['sq-priv-new-store'] }),
        updatedAt: Date.now(),
      }),
    );
    const out = await t.mutation(internal.seed.seedConnectionModes, {});
    expect(out.poolsMoved).toBe(1); // only the evade pool moved
    const pools = await t.run((ctx) => ctx.db.query('modePlacements').collect());
    const ws = pools.find((p) => p.modeSlug === 'freedom-ws')!;
    expect(JSON.parse(ws.config)).toEqual({ squadUuids: ['sq-legacy-ws'] });
    const priv = pools.find((p) => p.modeSlug === 'privacy-reality')!;
    expect(JSON.parse(priv.config)).toEqual({ squadUuids: ['sq-priv-new-store'] });
  });

  test('canonical-key pool wins over a legacy-key pool for the same mode', async () => {
    const t = convexTest(schema, modules);
    await putSetting(t, 'remnawave.modePlacement.evade.squads', ['sq-old']);
    await putSetting(t, 'remnawave.modePlacement.freedom-ws.squads', ['sq-new']);
    await t.mutation(internal.seed.seedConnectionModes, {});
    const pools = await t.run((ctx) => ctx.db.query('modePlacements').collect());
    expect(pools).toHaveLength(1);
    expect(JSON.parse(pools[0]!.config)).toEqual({ squadUuids: ['sq-new'] });
  });

  test('censorship-matrix cells re-key from legacy mode ids (canonical cell wins; labels survive)', async () => {
    const t = convexTest(schema, modules);
    await putSetting(t, 'status.censorship', {
      rows: [
        // Pure-legacy cells re-key onto the successors.
        { countryCode: 'CN', label: 'China', cells: { evade: 'partial', privacy: 'blocked' } },
        // A row that already has the canonical cell keeps it (legacy copy dropped).
        { countryCode: 'IR', cells: { evade: 'blocked', 'freedom-ws': 'available' } },
      ],
    });
    await t.mutation(internal.seed.seedConnectionModes, {});
    const row = await t.run((ctx) =>
      ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.eq('key', 'status.censorship'))
        .unique(),
    );
    const parsed = JSON.parse(row!.value) as {
      rows: Array<{ countryCode: string; label?: string; cells: Record<string, string> }>;
    };
    const cn = parsed.rows.find((r) => r.countryCode === 'CN')!;
    expect(cn.cells).toEqual({ 'freedom-ws': 'partial', 'privacy-reality': 'blocked' });
    expect(cn.label).toBe('China');
    const ir = parsed.rows.find((r) => r.countryCode === 'IR')!;
    expect(ir.cells).toEqual({ 'freedom-ws': 'available' });

    // Idempotent: a second seed run leaves the value byte-identical.
    const before = row!.value;
    await t.mutation(internal.seed.seedConnectionModes, {});
    const again = await t.run((ctx) =>
      ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.eq('key', 'status.censorship'))
        .unique(),
    );
    expect(again!.value).toBe(before);
  });

  test('a legacy spelling that IS a live catalog slug is never re-keyed', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.seed.seedConnectionModes, {});
    // An admin later creates a mode literally slugged 'evade' and curates a cell.
    await t.run((ctx) =>
      ctx.db.insert('connectionModes', {
        slug: 'evade',
        familySlug: 'freedom',
        deliveryStyle: 'url',
        label: 'Evade (new)',
        enabled: true,
        isFamilyDefault: false,
        backends: ['remnawave'],
        order: 9,
        updatedAt: Date.now(),
      }),
    );
    await putSetting(t, 'status.censorship', {
      rows: [{ countryCode: 'RU', cells: { evade: 'available' } }],
    });
    await t.mutation(internal.seed.seedConnectionModes, {});
    const row = await t.run((ctx) =>
      ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.eq('key', 'status.censorship'))
        .unique(),
    );
    const parsed = JSON.parse(row!.value) as { rows: Array<{ cells: Record<string, string> }> };
    expect(parsed.rows[0]!.cells).toEqual({ evade: 'available' });
  });
});

describe('migrateLegacyModeUserIds', () => {
  test('rewrites legacy ids, leaves everything else alone, pages to completion', async () => {
    const t = convexTest(schema, modules);
    const legacy1 = await seedUserWithMode(t, 'evade');
    const legacy2 = await seedUserWithMode(t, 'privacy');
    const current = await seedUserWithMode(t, 'freedom-ws');
    const unset = await seedUserWithMode(t, undefined);

    // Page size 1 exercises the cursor loop.
    let cursor: number | null = null;
    let total = 0;
    do {
      const page: { usersUpdated: number; nextCursor: number | null } = await t.mutation(
        internal.seed.migrateLegacyModeUserIds,
        cursor != null ? { cursor, limit: 1 } : { limit: 1 },
      );
      total += page.usersUpdated;
      cursor = page.nextCursor;
    } while (cursor != null);
    expect(total).toBe(2);

    await t.run(async (ctx) => {
      expect((await ctx.db.get(legacy1))!.connectionModeId).toBe('freedom-ws');
      expect((await ctx.db.get(legacy2))!.connectionModeId).toBe('privacy-reality');
      expect((await ctx.db.get(current))!.connectionModeId).toBe('freedom-ws');
      expect((await ctx.db.get(unset))!.connectionModeId).toBeUndefined();
    });

    // Converged: a re-run finds nothing.
    const again = await t.mutation(internal.seed.migrateLegacyModeUserIds, {});
    expect(again).toEqual({ usersUpdated: 0, nextCursor: null });
  });
});

describe('seedPeerGroups', () => {
  test('groups legacy pairwise links symmetrically; idempotent; never touches an existing group', async () => {
    const t = convexTest(schema, modules);
    const mk = (slug: string, backend: 'remnawave' | 'outline') =>
      t.run((ctx) =>
        ctx.db.insert('tiers', {
          slug,
          name: slug,
          backend,
          monthlyTrafficGb: 0,
          deviceLimit: 0,
          hwidLimit: 0,
          hwidEnabled: false,
          trafficStrategy: 'NO_RESET',
          isDefaultFree: false,
          isActive: true,
          priority: 10,
          expirationDaysAfterMembershipLapse: 7,
          updatedAt: Date.now(),
        }),
      );
    const a = await mk('member', 'remnawave');
    const b = await mk('member-outline', 'outline');
    const c = await mk('vip', 'remnawave');
    await t.run(async (ctx) => {
      await ctx.db.patch(a, { peerTierId: b }); // one-directional legacy link
      await ctx.db.patch(c, { peerGroup: 'vip-group' }); // pre-set group: untouched
    });

    const out = await t.mutation(internal.seed.seedPeerGroups, {});
    expect(out.grouped).toBe(2);
    await t.run(async (ctx) => {
      const ta = (await ctx.db.get(a))!;
      const tb = (await ctx.db.get(b))!;
      expect(ta.peerGroup).toBeTruthy();
      expect(ta.peerGroup).toBe(tb.peerGroup);
      expect((await ctx.db.get(c))!.peerGroup).toBe('vip-group');
    });

    // Re-run converges: nothing left to group.
    expect((await t.mutation(internal.seed.seedPeerGroups, {})).grouped).toBe(0);
  });
});

describe('seedCutover integration', () => {
  test('one call seeds the catalog AND runs the user rewrite to completion', async () => {
    const t = convexTest(schema, modules);
    const legacy = await seedUserWithMode(t, 'evade');
    const out = await t.action(internal.seed.seedCutover, {});
    expect(out.modesInserted).toBe(3);
    expect(out.modeUsersUpdated).toBe(1);
    await t.run(async (ctx) => {
      expect((await ctx.db.get(legacy))!.connectionModeId).toBe('freedom-ws');
    });
    // Second deploy: fully converged, zero work.
    const out2 = await t.action(internal.seed.seedCutover, {});
    expect(out2.modesInserted).toBe(0);
    expect(out2.modeUsersUpdated).toBe(0);
  });
});
