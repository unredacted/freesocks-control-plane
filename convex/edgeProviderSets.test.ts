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

describe('the pool against the set: what a free slot is held for', () => {
  /**
   * The walk's shape: the node wants 2 addresses in use and has 1, at location
   * A; location B of its set has nothing in use, so the one free slot is held
   * for an address there (reserved allocation).
   */
  async function heldForB() {
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t, { qualified: true, provider: 'upcloud' });
    const other = await createAccount(t, { provider: 'gcore', name: 'acct-b', qualified: true });
    for (const id of [fx.accountId, other])
      await t.mutation(internal.edgeProviderAccounts.recordTest, { id, ok: true });
    const locationOf = (accountId: Id<'edgeProviderAccounts'>) =>
      t.run(
        async (c) =>
          (await c.db.query('edgeLocations').collect()).find((l) => l.accountId === accountId)!,
      );
    const a = await locationOf(fx.accountId);
    const b = await locationOf(other);
    await t.run((c) =>
      c.db.patch(fx.relayId, {
        desiredPublished: 2,
        providerSet: [
          { locationId: a._id, addedAt: Date.now() },
          { locationId: b._id, addedAt: Date.now() },
        ],
      }),
    );
    await adoptL4Edge(t, fx.relayId, fx.listenerId, {
      ipv4: '198.51.100.21',
      publish: true,
      accountId: fx.accountId,
    });
    // A tested spare at A, where the node already has its address in use.
    const spareA = await adoptL4Edge(t, fx.relayId, fx.listenerId, {
      ipv4: '198.51.100.22',
      accountId: fx.accountId,
    });
    return { t, fx, a, b, other, spareA: spareA.edgeId as Id<'edges'> };
  }

  test('the view names the location the slot is held for, and which spare would stay a spare', async () => {
    const { t, fx, b, other, spareA } = await heldForB();
    const spareB = await adoptL4Edge(t, fx.relayId, fx.listenerId, {
      ipv4: '198.51.100.23',
      accountId: other,
    });
    const view = (await t.query(internal.edgeProviderSets.view, { relayId: fx.relayId }))!;
    expect(view.deficit).toBe(1);
    expect(view.missing).toEqual([
      { listenerKey: 'a', locationId: b._id, label: b.label, accountName: 'acct-b' },
    ]);
    expect(view.pool).toEqual({ wanted: 2, inUse: 1, free: 1, held: 1 });
    expect(view.spares).toEqual(
      expect.arrayContaining([
        { edgeId: spareA, takesSlot: false },
        { edgeId: spareB.edgeId, takesSlot: true },
      ]),
    );
    // "Put it in use" is offered for the spare that fills the held slot.
    const { items } = await t.query(internal.edgeOperator.attention, {});
    expect(items.find((i) => i.kind === 'pool_below_desired')).toMatchObject({
      edgeId: spareB.edgeId,
      action: 'publish',
      code: null,
    });
  });

  test('with only a spare that would stay a spare, attention names it as held instead of offering a publish', async () => {
    const { t, spareA } = await heldForB();
    const { items } = await t.query(internal.edgeOperator.attention, {});
    expect(items.find((i) => i.kind === 'pool_below_desired')).toMatchObject({
      edgeId: spareA,
      action: 'open_relay',
      code: 'pool_reserved',
      facts: { published: 1, desired: 2, standbys: 1 },
    });
  });

  test('the dry run of a new spare says whether, once tested, it would get the slot', async () => {
    const { t, fx, a, b } = await heldForB();
    const dry = (locationId: Id<'edgeLocations'>) =>
      t.query(internal.edgeOperator.preflight, {
        relayId: fx.relayId,
        kind: 'provision',
        listenerKey: 'a',
        locationId,
        publish: false,
      });
    const atA = await dry(a._id);
    expect(atA.wouldSelect).toMatchObject({ locationId: a._id, takesSlot: false });
    const atB = await dry(b._id);
    expect(atB.wouldSelect).toMatchObject({ locationId: b._id, takesSlot: true });
    // Only a provision asks: a replace takes the slot of what it replaces.
    const published = (await t.query(internal.relays.get, { id: fx.relayId }))!
      .publishedEdgeIds[0]!;
    const replace = await t.query(internal.edgeOperator.preflight, {
      relayId: fx.relayId,
      kind: 'replace',
      edgeId: published,
    });
    expect(replace.wouldSelect?.takesSlot ?? null).toBeNull();
  });

  test('the dry run of a publish the pool would refuse warns that it stays a standby', async () => {
    const { t, fx, other, spareA } = await heldForB();
    const publish = (edgeId: Id<'edges'>) =>
      t.query(internal.edgeOperator.preflight, { relayId: fx.relayId, kind: 'publish', edgeId });
    expect((await publish(spareA)).warnings.map((w) => w.code)).toContain('pool_reserved');
    const spareB = await adoptL4Edge(t, fx.relayId, fx.listenerId, {
      ipv4: '198.51.100.23',
      accountId: other,
    });
    const atB = await publish(spareB.edgeId as Id<'edges'>);
    expect(atB.warnings.map((w) => w.code)).not.toContain('pool_reserved');
    expect(atB.warnings.map((w) => w.code)).not.toContain('pool_full');
  });
});
