/// <reference types="vite/client" />
/**
 * Protocol profiles: retiring a server name invalidates renders twice — at
 * once (new selections stop) and again at `drainUntil` (the node stops
 * ACCEPTING it, so every cached body / mirror that could still carry it must
 * be invalidated the moment it actually dies).
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';

const modules = import.meta.glob('./**/*.*s');

async function seed() {
  const t = convexTest(schema, modules);
  await t.run((ctx) =>
    ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'panel-a',
      slug: 'panel-a',
      config: { type: 'remnawave', baseUrl: 'https://panel.example', apiToken: 'tok' },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: Date.now(),
    }),
  );
  const { id: profileId } = await t.mutation(internal.protocolProfiles.create, {
    slug: 'prof-a',
    name: 'Profile A',
    targetAddress: 'target.example',
    serverNames: ['a.example', 'b.example', 'c.example'],
  });
  const { id: relayId } = await t.mutation(internal.relays.upsertBySlug, {
    slug: 'node-one',
    backendServerSlug: 'panel-a',
    nodeHostname: 'node-one',
    originAddress: '203.0.113.10',
  });
  await t.mutation(internal.relaySlots.upsert, {
    relayId,
    slotKey: 'a',
    profileSlug: 'prof-a',
    inboundTag: 'VLESS_RELAY_A',
    configProfileUuid: '11111111-1111-4111-8111-111111111111',
    configProfileInboundUuid: '22222222-2222-4222-8222-222222222222',
    originPort: 443,
  });
  return { t, profileId, relayId };
}

const scheduled = (t: ReturnType<typeof convexTest>) =>
  t.run(async (ctx) => {
    const rows = await ctx.db.system.query('_scheduled_functions').collect();
    return {
      refreshes: rows.filter((r) => r.name === 'storage:refreshActiveMirrors').length,
      drains: rows
        .filter((r) => r.name === 'protocolProfiles:onSniDrainElapsed')
        .map((r) => ({ at: r.scheduledTime, args: r.args[0] as { snis: string[] } })),
    };
  });

const epochOf = (t: ReturnType<typeof convexTest>, relayId: Id<'relays'>) =>
  t.run(async (ctx) => (await ctx.db.get(relayId))!.publicationEpoch);

describe('protocolProfiles: server-name retirement invalidation', () => {
  test('retireSni bumps now, refreshes mirrors, and schedules the drain-elapsed bump at drainUntil', async () => {
    const { t, profileId, relayId } = await seed();
    const before = await epochOf(t, relayId);
    const s0 = await scheduled(t);
    await t.mutation(internal.protocolProfiles.retireSni, { id: profileId, snis: ['a.example'] });
    expect(await epochOf(t, relayId)).toBe(before + 1);
    const s1 = await scheduled(t);
    expect(s1.refreshes).toBe(s0.refreshes + 1);
    expect(s1.drains).toHaveLength(1);
    expect(s1.drains[0].args.snis).toEqual(['a.example']);
    const row = (await t.run((ctx) => ctx.db.get(profileId)))!;
    const retired = row.serverNames.find((s) => s.sni === 'a.example')!;
    expect(retired.status).toBe('retired');
    expect(s1.drains[0].at).toBe(retired.drainUntil);
    expect(retired.drainUntil!).toBeGreaterThan(Date.now());
  });

  test('update(serverNames) retiring a name schedules the drain-elapsed bump too', async () => {
    const { t, profileId } = await seed();
    await t.mutation(internal.protocolProfiles.update, {
      id: profileId,
      serverNames: ['a.example', 'c.example'], // b retires
    });
    const s = await scheduled(t);
    expect(s.drains).toHaveLength(1);
    expect(s.drains[0].args.snis).toEqual(['b.example']);
    // Re-adding an active name retires nothing → no extra job.
    await t.mutation(internal.protocolProfiles.update, {
      id: profileId,
      serverNames: ['a.example', 'c.example', 'd.example'],
    });
    expect((await scheduled(t)).drains).toHaveLength(1);
  });

  test('onSniDrainElapsed: bumps + refreshes once the drain elapsed, no-op while draining or after reactivation', async () => {
    const { t, profileId, relayId } = await seed();
    await t.mutation(internal.protocolProfiles.retireSni, { id: profileId, snis: ['a.example'] });
    const epoch = await epochOf(t, relayId);
    const refreshes = (await scheduled(t)).refreshes;
    // Still inside the drain → nothing.
    await t.mutation(internal.protocolProfiles.onSniDrainElapsed, {
      id: profileId,
      snis: ['a.example'],
    });
    expect(await epochOf(t, relayId)).toBe(epoch);
    // Drain elapsed → bump + mirror refresh.
    await t.run(async (ctx) => {
      const p = (await ctx.db.get(profileId))!;
      await ctx.db.patch(profileId, {
        serverNames: p.serverNames.map((s) =>
          s.sni === 'a.example' ? { ...s, drainUntil: Date.now() - 1 } : s,
        ),
      });
    });
    await t.mutation(internal.protocolProfiles.onSniDrainElapsed, {
      id: profileId,
      snis: ['a.example'],
    });
    expect(await epochOf(t, relayId)).toBe(epoch + 1);
    expect((await scheduled(t)).refreshes).toBe(refreshes + 1);
    // Reactivated in the meantime → the stale job is a no-op.
    await t.mutation(internal.protocolProfiles.reactivateSni, {
      id: profileId,
      snis: ['a.example'],
    });
    const afterReactivate = await epochOf(t, relayId);
    await t.mutation(internal.protocolProfiles.onSniDrainElapsed, {
      id: profileId,
      snis: ['a.example'],
    });
    expect(await epochOf(t, relayId)).toBe(afterReactivate);
  });
});
