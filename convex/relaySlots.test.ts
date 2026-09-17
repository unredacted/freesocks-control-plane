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

describe('relaySlots: origin transport + revision', () => {
  const transport = {
    scheme: 'https' as const,
    certPublic: true,
    certNames: ['origin.example', '*.origin.example'],
    acceptsHostHeader: 'any' as const,
  };

  test('the declared origin transport is stored, normalised and surfaced with the slot layers', async () => {
    const { t, relayId } = await seed();
    await t.mutation(internal.relaySlots.upsert, {
      relayId,
      ...slotArgs,
      // The profile's own names (a.example / b.example) are what a member
      // presents, so the ORIGIN certificate has to cover them for L4.
      originTransport: { ...transport, certNames: ['A.example.', 'a.example', 'b.example'] },
    });
    const [slot] = await t.query(internal.relaySlots.listByRelay, { relayId });
    expect(slot.originTransport).toEqual({
      scheme: 'https',
      certPublic: true,
      // Lower-cased, trailing dot dropped, duplicates collapsed.
      certNames: ['a.example', 'b.example'],
      acceptsHostHeader: 'any',
    });
    // A `reality` profile over a publicly trusted, name-covered origin can sit
    // behind an L4 forwarder; it is not an HTTP transport, so not behind an L7 front.
    expect(slot.layers).toEqual(['l4']);
  });

  test('a certificate that does not cover the profile names leaves NO usable layer', async () => {
    const { t, relayId } = await seed();
    await t.mutation(internal.relaySlots.upsert, {
      relayId,
      ...slotArgs,
      originTransport: { ...transport, certNames: ['origin.example'] },
    });
    // L4 is out (a member's TLS session to the node would fail the name check)
    // and L7 is out (REALITY is not an HTTP transport): nothing can front it.
    expect((await t.query(internal.relaySlots.listByRelay, { relayId }))[0].layers).toEqual([]);
  });

  test('certificate names must be hostnames or a single leftmost wildcard', async () => {
    const { t, relayId } = await seed();
    for (const bad of ['1.2.3.4', 'f*.example', '*.*.example', 'localhost']) {
      await expect(
        t.mutation(internal.relaySlots.upsert, {
          relayId,
          ...slotArgs,
          originTransport: { ...transport, certNames: [bad] },
        }),
      ).rejects.toThrow(/invalid certificate name/);
    }
  });

  test('a publicly trusted https origin must name its certificate', async () => {
    const { t, relayId } = await seed();
    await expect(
      t.mutation(internal.relaySlots.upsert, {
        relayId,
        ...slotArgs,
        originTransport: { ...transport, certNames: [] },
      }),
    ).rejects.toThrow(/name its certificate/);
  });

  test('every write bumps the revision, so a front qualification bound to it expires', async () => {
    const { t, relayId } = await seed();
    await t.mutation(internal.relaySlots.upsert, { relayId, ...slotArgs });
    const first = (await t.query(internal.relaySlots.listByRelay, { relayId }))[0];
    expect(first.revision).toBe(1);
    await t.mutation(internal.relaySlots.upsert, { relayId, ...slotArgs });
    expect((await t.query(internal.relaySlots.listByRelay, { relayId }))[0].revision).toBe(2);
    await t.mutation(internal.relaySlots.retire, { relayId, slotKey: 'a' });
    expect((await t.query(internal.relaySlots.listByRelay, { relayId }))[0].revision).toBe(3);
  });

  test('an absent originTransport on a re-upsert keeps the stored one; null clears it', async () => {
    const { t, relayId } = await seed();
    await t.mutation(internal.relaySlots.upsert, {
      relayId,
      ...slotArgs,
      originTransport: transport,
    });
    await t.mutation(internal.relaySlots.upsert, { relayId, ...slotArgs });
    expect(
      (await t.query(internal.relaySlots.listByRelay, { relayId }))[0].originTransport,
    ).toEqual(transport);
    await t.mutation(internal.relaySlots.upsert, { relayId, ...slotArgs, originTransport: null });
    expect(
      (await t.query(internal.relaySlots.listByRelay, { relayId }))[0].originTransport,
    ).toBeNull();
  });
});
