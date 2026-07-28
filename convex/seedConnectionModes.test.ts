/// <reference types="vite/client" />
/**
 * The connection-mode seed (post-migration, deploy-2 shape): fresh-deploy
 * seeding, the idempotency guarantees (double-run = zero writes; admin edits
 * survive every later deploy), peer-group conversion, and the guarded one-shot
 * `cleanupLegacyModeSettings` that deletes the dead appSettings rows the
 * 2026-07-28 migration absorbed.
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
    expect(out).toMatchObject({ familiesInserted: 2, modesInserted: 3 });
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
    expect(out2).toMatchObject({ familiesInserted: 0, modesInserted: 0 });
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

describe('cleanupLegacyModeSettings', () => {
  test('deletes the absorbed namespaces, keeps the default pointer + unrelated keys; idempotent', async () => {
    const t = convexTest(schema, modules);
    await putSetting(t, 'connectionMode.privacy-reality.label', 'Max privacy');
    await putSetting(t, 'connectionMode.evade.label', 'Old Evade Label');
    await putSetting(t, 'connectionMode.freedom-reality.enabled', true);
    await putSetting(t, 'connectionModeFamily.freedom.label', 'Internet Freedom');
    await putSetting(t, 'remnawave.modePlacement.evade.squads', ['sq-legacy-ws']);
    await putSetting(t, 'remnawave.modePlacement.freedom-ws.squads', ['sq-ws']);
    // Survivors: the live default pointer + neighbors outside the namespaces.
    await putSetting(t, 'connectionMode.default', 'freedom-ws');
    await putSetting(t, 'remnawave.nodePlacement.usersOnline_weight', 1);
    await putSetting(t, 'site.bannerEnabled', false);

    const out = await t.mutation(internal.seed.cleanupLegacyModeSettings, {});
    expect(out.deleted).toBe(6);

    const keys = await t.run(async (ctx) =>
      (await ctx.db.query('appSettings').collect()).map((r) => r.key).sort(),
    );
    expect(keys).toEqual([
      'connectionMode.default',
      'remnawave.nodePlacement.usersOnline_weight',
      'site.bannerEnabled',
    ]);

    // Idempotent: a re-run deletes nothing.
    expect((await t.mutation(internal.seed.cleanupLegacyModeSettings, {})).deleted).toBe(0);
  });

  test('refuses while any user still holds a pre-rename mode id', async () => {
    const t = convexTest(schema, modules);
    await putSetting(t, 'connectionMode.evade.label', 'Old Evade Label');
    const legacy = await seedUserWithMode(t, 'evade');
    await expect(t.mutation(internal.seed.cleanupLegacyModeSettings, {})).rejects.toThrow(
      /pre-rename mode id "evade"/,
    );
    // Nothing was deleted on the refused run.
    const rows = await t.run((ctx) => ctx.db.query('appSettings').collect());
    expect(rows).toHaveLength(1);
    // Once the user is off the legacy id, the cleanup proceeds.
    await t.run((ctx) => ctx.db.patch(legacy, { connectionModeId: 'freedom-ws' }));
    expect((await t.mutation(internal.seed.cleanupLegacyModeSettings, {})).deleted).toBe(1);
  });

  test('a current-id or unset user does not trip the guard', async () => {
    const t = convexTest(schema, modules);
    await seedUserWithMode(t, 'freedom-ws');
    await seedUserWithMode(t, undefined);
    expect((await t.mutation(internal.seed.cleanupLegacyModeSettings, {})).deleted).toBe(0);
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
  test('one call seeds the catalog; a second deploy is zero work', async () => {
    const t = convexTest(schema, modules);
    const out = await t.action(internal.seed.seedCutover, {});
    expect(out.modesInserted).toBe(3);
    expect(out.modeFamiliesInserted).toBe(2);
    // Second deploy: fully converged, zero work.
    const out2 = await t.action(internal.seed.seedCutover, {});
    expect(out2.modesInserted).toBe(0);
    expect(out2.modeFamiliesInserted).toBe(0);
  });
});
