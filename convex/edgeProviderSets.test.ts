/**
 * A node's provider set as the admin reads and edits it, and what the
 * requirement counts as published. Fixtures only (RFC 5737, `*.example`).
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import {
  adoptL4Edge,
  createAccount,
  seedEdgeFixture,
  setFrontsTraffic,
  wsListener,
} from './lib/edges/testing/fixtures';
import { setPicksOf, setStateOf } from './lib/edges/setState';

const modules = import.meta.glob('./**/*.*s');

describe('provider set view and state', () => {
  test('without a recorded set the picks are the ones its published edges imply, and are not offered again', async () => {
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t, { qualified: true, provider: 'upcloud' });
    await t.mutation(internal.edgeProviderAccounts.recordTest, { id: fx.accountId, ok: true });
    await adoptL4Edge(t, fx.relayId, fx.listenerId, {
      ipv4: '198.51.100.21',
      publish: true,
      accountId: fx.accountId,
    });
    const view = await t.query(internal.edgeProviderSets.view, { relayId: fx.relayId });
    expect(view!.hasSet).toBe(false);
    expect(view!.picks).toHaveLength(1);
    expect(view!.available.some((a) => a.locationId === view!.picks[0]!.locationId)).toBe(false);
  });

  test('a DNS account is a usable pick, or one to add, only while DNS accounts may front', async () => {
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t, {
      qualified: true,
      provider: 'upcloud',
      listeners: [wsListener()],
    });
    await t.mutation(internal.edgeProviderAccounts.recordTest, { id: fx.accountId, ok: true });
    const dns = await createAccount(t, { provider: 'cloudflare', name: 'acct-dns' });
    await t.mutation(internal.edgeProviderAccounts.recordTest, { id: dns, ok: true });
    const locationOf = (accountId: Id<'edgeProviderAccounts'>) =>
      t.run(
        async (c) =>
          (await c.db.query('edgeLocations').collect()).find((l) => l.accountId === accountId)!,
      );
    const dnsLocation = await locationOf(dns);
    // The zone's facts, as its location's check observed them.
    await t.mutation(internal.edgeLocations.recordCheck, {
      id: dnsLocation._id,
      ok: true,
      observed: { zoneSslMode: 'full', websockets: 'on' },
    });
    const l4Location = await locationOf(fx.accountId);
    // A set picked while the DNS account was set to DNS and fronting.
    await t.run((c) =>
      c.db.patch(fx.relayId, {
        providerSet: [
          { locationId: l4Location._id, addedAt: Date.now() },
          { locationId: dnsLocation._id, addedAt: Date.now() },
        ],
      }),
    );
    const usable = () =>
      t.run(async (c) =>
        ((await setPicksOf(c.db, (await c.db.get(fx.relayId))!)) ?? []).map((p) => [
          p.account.provider,
          p.usable,
        ]),
      );
    // DNS only (the default): the DNS pick carries nothing and is never offered.
    expect(await usable()).toEqual([
      ['upcloud', true],
      ['cloudflare', false],
    ]);
    await t.run((c) => c.db.patch(fx.relayId, { providerSet: undefined }));
    const view = await t.query(internal.edgeProviderSets.view, { relayId: fx.relayId });
    expect(view!.available.some((a) => a.accountId === dns)).toBe(false);
    // DNS and fronting: both are usable again.
    await setFrontsTraffic(t, dns, true);
    const viewOn = await t.query(internal.edgeProviderSets.view, { relayId: fx.relayId });
    expect(viewOn!.available.some((a) => a.accountId === dns)).toBe(true);
    await t.run((c) =>
      c.db.patch(fx.relayId, {
        providerSet: [
          { locationId: l4Location._id, addedAt: Date.now() },
          { locationId: dnsLocation._id, addedAt: Date.now() },
        ],
      }),
    );
    expect(await usable()).toEqual([
      ['upcloud', true],
      ['cloudflare', true],
    ]);
  });

  test('an edge of a disabled transport neither covers it nor holds a pick', async () => {
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t, { qualified: true, provider: 'upcloud' });
    const e = await adoptL4Edge(t, fx.relayId, fx.listenerId, {
      ipv4: '198.51.100.22',
      publish: true,
      accountId: fx.accountId,
    });
    const publishedIds = () =>
      t.run(async (c) =>
        (await setStateOf(c.db, (await c.db.get(fx.relayId))!)).published.map((p) => p.edgeId),
      );
    expect(await publishedIds()).toEqual([e.edgeId as Id<'edges'>]);
    await t.run((c) => c.db.patch(fx.listenerId, { enabled: false }));
    expect(await publishedIds()).toEqual([]);
  });
});
