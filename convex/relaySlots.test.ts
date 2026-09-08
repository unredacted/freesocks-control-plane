/// <reference types="vite/client" />
/**
 * Relay slots: every change that alters what an origin renders (upsert,
 * retire) bumps its publication epoch AND refreshes stored mirrors, so a
 * mirror-only member is not left holding a retired slot's template entry.
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';

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
  await t.mutation(internal.protocolProfiles.create, {
    slug: 'prof-a',
    name: 'Profile A',
    targetAddress: 'target.example',
    serverNames: ['a.example', 'b.example'],
  });
  const { id: relayId } = await t.mutation(internal.relays.upsertBySlug, {
    slug: 'node-one',
    backendServerSlug: 'panel-a',
    nodeHostname: 'node-one',
    originAddress: '203.0.113.10',
  });
  return { t, relayId };
}

const slotArgs = {
  slotKey: 'a',
  profileSlug: 'prof-a',
  inboundTag: 'VLESS_RELAY_A',
  configProfileUuid: '11111111-1111-4111-8111-111111111111',
  configProfileInboundUuid: '22222222-2222-4222-8222-222222222222',
  originPort: 443,
};

const scheduledRefreshes = (t: ReturnType<typeof convexTest>) =>
  t.run(async (ctx) => {
    const rows = await ctx.db.system.query('_scheduled_functions').collect();
    return rows.filter((r) => r.name === 'storage:refreshActiveMirrors').length;
  });

describe('relaySlots: epoch bumps refresh mirrors', () => {
  test('upsert bumps the epoch and schedules a mirror refresh', async () => {
    const { t, relayId } = await seed();
    const before = (await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch;
    await t.mutation(internal.relaySlots.upsert, { relayId, ...slotArgs });
    expect((await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch).toBe(before + 1);
    expect(await scheduledRefreshes(t)).toBe(1);
  });

  test('retire bumps the epoch and schedules a mirror refresh', async () => {
    const { t, relayId } = await seed();
    await t.mutation(internal.relaySlots.upsert, { relayId, ...slotArgs });
    const before = (await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch;
    await t.mutation(internal.relaySlots.retire, { relayId, slotKey: 'a' });
    expect((await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch).toBe(before + 1);
    expect(await scheduledRefreshes(t)).toBe(2);
    // Retiring an unknown slot is a no-op: no bump, no refresh.
    await t.mutation(internal.relaySlots.retire, { relayId, slotKey: 'zz' });
    expect((await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch).toBe(before + 1);
    expect(await scheduledRefreshes(t)).toBe(2);
  });
});
