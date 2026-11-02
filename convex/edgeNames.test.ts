/**
 * Names for load balancer addresses (edgeNames.ts + edgeNameOps.ts) against an
 * in-memory zone behind the DNS seam: made, spread, re-pointed, moved on a
 * replace (once per window), moved back on a rollback, removed before the
 * address is destroyed, renewed, and handed to the renderer only while the
 * switch is on. Every value is RFC 5737 / RFC 3849 / `*.example`.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { seedEdgeFixture } from './lib/edges/testing/fixtures';
import { fakeDnsZone, type FakeDnsZone } from './lib/edges/testing/fakeCloudFront';
import { jsonRes, mockFetch } from './lib/edges/testing/mockFetch';
import { __setAddressNameDnsFactory } from './edgeNameOps';
import { moveNameBack, moveNameOnReplace } from './edgeNames';
import { publishedEdgesOf } from './edgeRender';
import { addressNameMarker, mintAddressName } from './lib/edges/addressNames';

const modules = import.meta.glob('./**/*.*s');
const DAY = 86_400_000;
type T = TestConvex<typeof schema>;

let zones: Map<string, FakeDnsZone>;

beforeEach(() => {
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  zones = new Map();
  __setAddressNameDnsFactory((provider, zone) => {
    if (provider !== 'cloudflare') return null;
    let z = zones.get(zone.zoneId);
    if (!z) {
      z = fakeDnsZone(zone);
      zones.set(zone.zoneId, z);
    }
    return z;
  });
});
afterEach(() => {
  __setAddressNameDnsFactory(null);
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.useRealTimers();
});

/** A DNS account with one zone (a location); returns the zone's location id. */
async function dnsZone(t: T, zoneName: string, zoneId: string): Promise<Id<'edgeLocations'>> {
  return t.run(async (ctx) => {
    const now = Date.now();
    const accountId = await ctx.db.insert('edgeProviderAccounts', {
      provider: 'cloudflare',
      name: `dns-${zoneName}`,
      credentials: { type: 'cloudflare', apiToken: 'tok' } as never,
      settings: { type: 'cloudflare', accountId: 'b'.repeat(32) } as never,
      enabled: true,
      priority: 0,
      dailyAllocationBudget: 10,
      allocationsToday: 0,
      maxLiveEdges: 6,
      updatedAt: now,
    });
    const placement = { type: 'cloudflare', zoneId, zoneName };
    return await ctx.db.insert('edgeLocations', {
      accountId,
      provider: 'cloudflare',
      placeKey: zoneId,
      placement: placement as never,
      placementHash: `h-${zoneId}`,
      label: zoneName,
      enabled: true,
      qualified: true,
      createdAt: now,
      updatedAt: now,
    });
  });
}

async function setNames(
  t: T,
  names: { enabled?: boolean; zones?: string[]; moveQuietDays?: number },
) {
  await t.mutation(internal.edgeAdmin.patchConfig, { patch: { names } });
}

/** An address FCP made with the switch on (or off), active, at `v4` (and `v6`). */
async function address(
  t: T,
  f: { relayId: Id<'relays'>; listenerId: Id<'relayListeners'> },
  v4: string,
  opts: { v6?: string; published?: boolean; nameWanted?: boolean; lane?: 'trusted' } = {},
): Promise<Id<'edges'>> {
  return t.run(async (ctx) => {
    const now = Date.now();
    const id = await ctx.db.insert('edges', {
      relayId: f.relayId,
      listenerId: f.listenerId,
      provider: 'gcore',
      managed: true,
      name: `fcp-node-one-${v4.split('.').pop()}`,
      steps: [],
      resources: [],
      listeners: [{ edgePort: 443, originAddress: '203.0.113.10', originPort: 443 }],
      addresses: { v4, ...(opts.v6 ? { v6: opts.v6 } : {}) },
      layer: 'l4',
      publication: opts.published ? 'published' : 'unpublished',
      ...(opts.published ? { poolIndex: 0, publishedAt: now } : {}),
      status: 'active',
      statusChangedAt: now,
      health: 'online',
      destroyAttempts: 0,
      ...(opts.nameWanted === false ? {} : { nameWanted: true }),
      ...(opts.lane ? { lane: opts.lane } : {}),
      updatedAt: now,
    });
    if (opts.published) await ctx.db.patch(f.relayId, { publishedEdgeIds: [id] });
    return id;
  });
}

const nameRows = (t: T) => t.run((ctx) => ctx.db.query('edgeNames').collect());
const nameOf = async (t: T, edgeId: Id<'edges'>) =>
  (await nameRows(t)).find((r) => r.edgeId === edgeId && r.state !== 'gone');

async function seed(t: T, zoneCount = 1) {
  const f = await seedEdgeFixture(t);
  const zoneIds: Id<'edgeLocations'>[] = [];
  for (let i = 0; i < zoneCount; i++)
    zoneIds.push(await dnsZone(t, `z${i}.names.example`, `${i}`.repeat(32)));
  await setNames(t, { enabled: true, zones: zoneIds });
  return { ...f, zoneIds };
}

describe('names for addresses', () => {
  test('an address that wants a name gets one: A and AAAA, unproxied, short TTL, marked', async () => {
    const t = convexTest(schema, modules);
    const f = await seed(t);
    const edgeId = await address(t, f, '198.51.100.11', { v6: '2001:db8::11', published: true });
    const epoch0 = (await t.run((ctx) => ctx.db.get(f.relayId)))!.publicationEpoch;
    expect(await t.action(internal.edgeNameOps.work, { edgeId })).toBe('done');
    const row = (await nameOf(t, edgeId))!;
    expect(row).toMatchObject({ state: 'live', zoneLocationId: f.zoneIds[0], moves: 0 });
    expect(row.fqdn).toMatch(/^[a-z]+-[a-z]+\.z0\.names\.example$/);
    const zone = zones.get('0'.repeat(32))!;
    // The fake keeps what was sent, the TTL included.
    const sent = zone.rows as Array<(typeof zone.rows)[number] & { ttl?: number }>;
    expect(sent.map((r) => [r.type, r.name, r.content, r.proxied, r.ttl, r.comment])).toEqual([
      ['A', row.fqdn, '198.51.100.11', false, 60, addressNameMarker(row._id)],
      ['AAAA', row.fqdn, '2001:db8::11', false, 60, addressNameMarker(row._id)],
    ]);
    // Its members move to the name at their next fetch.
    expect((await t.run((ctx) => ctx.db.get(f.relayId)))!.publicationEpoch).toBe(epoch0 + 1);
    // A second pass changes nothing.
    expect(await t.action(internal.edgeNameOps.work, { nameId: row._id })).toBe('done');
    expect(zone.rows).toHaveLength(2);
  });

  test('off, or an address made before: no name, nothing written', async () => {
    const t = convexTest(schema, modules);
    const f = await seed(t);
    const before = await address(t, f, '198.51.100.12', { nameWanted: false });
    expect(await t.action(internal.edgeNameOps.work, { edgeId: before })).toBe('none');
    await setNames(t, { enabled: false });
    const wanted = await address(t, f, '198.51.100.13');
    expect(await t.action(internal.edgeNameOps.work, { edgeId: wanted })).toBe('none');
    expect(await nameRows(t)).toEqual([]);
    expect(zones.size).toBe(0);
  });

  test("a node's addresses are spread over the eligible zones", async () => {
    const t = convexTest(schema, modules);
    const f = await seed(t, 2);
    const a = await address(t, f, '198.51.100.21');
    const b = await address(t, f, '198.51.100.22');
    await t.action(internal.edgeNameOps.work, { edgeId: a });
    await t.action(internal.edgeNameOps.work, { edgeId: b });
    const za = (await nameOf(t, a))!.zoneLocationId;
    const zb = (await nameOf(t, b))!.zoneLocationId;
    expect(new Set([za, zb])).toEqual(new Set(f.zoneIds));
  });

  test('a name somebody else uses moves to the next word pair; theirs is never touched', async () => {
    const t = convexTest(schema, modules);
    const f = await seed(t);
    const edgeId = await address(t, f, '198.51.100.31');
    const taken = mintAddressName('fcp-node-one-31', 'z0.names.example', 0);
    const zone = fakeDnsZone(
      { apiToken: 'x', zoneId: '0'.repeat(32), zoneName: 'z0', accountId: 'a' },
      [
        {
          id: 'theirs',
          type: 'A',
          name: taken,
          content: '192.0.2.99',
          proxied: false,
          comment: 'mine',
        },
      ],
    );
    zones.set('0'.repeat(32), zone);
    expect(await t.action(internal.edgeNameOps.work, { edgeId })).toBe('conflict');
    expect(await t.action(internal.edgeNameOps.work, { edgeId })).toBe('done');
    const row = (await nameOf(t, edgeId))!;
    expect(row).toMatchObject({ state: 'live', generation: 1 });
    expect(row.fqdn).not.toBe(taken);
    expect(zone.rows.find((r) => r.id === 'theirs')).toMatchObject({ content: '192.0.2.99' });
  });

  test('a re-addressed address: the record changes in place', async () => {
    const t = convexTest(schema, modules);
    const f = await seed(t);
    const edgeId = await address(t, f, '198.51.100.41');
    await t.action(internal.edgeNameOps.work, { edgeId });
    const zone = zones.get('0'.repeat(32))!;
    const id = zone.rows[0]!.id;
    await t.run((ctx) => ctx.db.patch(edgeId, { addresses: { v4: '198.51.100.42' } }));
    const plan = await t.query(internal.edgeNames.upkeepPlan, { candidates: [], limit: 10 });
    const row = (await nameOf(t, edgeId))!;
    expect(plan.nameIds).toEqual([row._id]);
    await t.action(internal.edgeNameOps.work, { nameId: row._id });
    expect(zone.rows).toEqual([expect.objectContaining({ id, content: '198.51.100.42' })]);
    expect(zone.deleted).toEqual([]);
  });

  test('a replacement takes the name once; within the window the next one keeps its own', async () => {
    const t = convexTest(schema, modules);
    const f = await seed(t);
    const a = await address(t, f, '198.51.100.51', { published: true });
    const b = await address(t, f, '198.51.100.52');
    await t.action(internal.edgeNameOps.work, { edgeId: a });
    await t.action(internal.edgeNameOps.work, { edgeId: b });
    const nameA = (await nameOf(t, a))!;
    const ownB = (await nameOf(t, b))!;
    const verdict = await t.run(async (ctx) =>
      moveNameOnReplace(ctx, {
        from: (await ctx.db.get(a))!,
        to: (await ctx.db.get(b))!,
        toLane: 'open',
        now: Date.now(),
      }),
    );
    expect(verdict).toEqual({ move: true });
    const moving = (await t.run((ctx) => ctx.db.get(nameA._id)))!;
    expect(moving).toMatchObject({ state: 'moving', edgeId: b, leavingEdgeId: a, moves: 1 });
    expect(moving.served.map((s) => [s.edgeId, s.why])).toEqual([
      [a, 'moved'],
      [b, undefined],
    ]);
    // While the record still points at the drained address, a's walk waits for it.
    expect(await t.query(internal.edgeNames.pendingForDestroy, { edgeId: a })).toBe(1);
    await t.action(internal.edgeNameOps.work, { nameId: nameA._id });
    await t.action(internal.edgeNameOps.work, { nameId: ownB._id });
    const zone = zones.get('0'.repeat(32))!;
    expect(zone.rows.map((r) => [r.name, r.content])).toEqual([[nameA.fqdn, '198.51.100.52']]);
    expect((await t.run((ctx) => ctx.db.get(ownB._id)))!.state).toBe('gone');
    expect(await t.query(internal.edgeNames.pendingForDestroy, { edgeId: a })).toBe(0);

    // b is replaced within 30 days: the name stays with b, c keeps its own.
    const c = await address(t, f, '198.51.100.53');
    const again = await t.run(async (ctx) =>
      moveNameOnReplace(ctx, {
        from: (await ctx.db.get(b))!,
        to: (await ctx.db.get(c))!,
        toLane: 'open',
        now: Date.now() + 3 * DAY,
      }),
    );
    expect(again).toEqual({ move: false, reason: 'moved_recently' });
  });

  test('never into the other lane', async () => {
    const t = convexTest(schema, modules);
    const f = await seed(t);
    const a = await address(t, f, '198.51.100.61', { published: true });
    const b = await address(t, f, '198.51.100.62');
    await t.action(internal.edgeNameOps.work, { edgeId: a });
    const verdict = await t.run(async (ctx) =>
      moveNameOnReplace(ctx, {
        from: (await ctx.db.get(a))!,
        to: (await ctx.db.get(b))!,
        toLane: 'trusted',
        now: Date.now(),
      }),
    );
    expect(verdict).toEqual({ move: false, reason: 'other_lane' });
  });

  test('a rolled-back replace takes the name back', async () => {
    const t = convexTest(schema, modules);
    const f = await seed(t);
    const a = await address(t, f, '198.51.100.71', { published: true });
    const b = await address(t, f, '198.51.100.72', { nameWanted: false });
    await t.action(internal.edgeNameOps.work, { edgeId: a });
    const row = (await nameOf(t, a))!;
    await t.run(async (ctx) =>
      moveNameOnReplace(ctx, {
        from: (await ctx.db.get(a))!,
        to: (await ctx.db.get(b))!,
        toLane: 'open',
        now: Date.now(),
      }),
    );
    await t.action(internal.edgeNameOps.work, { nameId: row._id });
    expect(
      await t.run((ctx) => moveNameBack(ctx, { current: b, previous: a, now: Date.now() })),
    ).toBe(true);
    await t.action(internal.edgeNameOps.work, { nameId: row._id });
    expect((await t.run((ctx) => ctx.db.get(row._id)))!).toMatchObject({
      state: 'live',
      edgeId: a,
    });
    expect(zones.get('0'.repeat(32))!.rows.map((r) => r.content)).toEqual(['198.51.100.71']);
  });

  test('an address being destroyed loses its names first', async () => {
    const t = convexTest(schema, modules);
    const f = await seed(t);
    const a = await address(t, f, '198.51.100.81', { v6: '2001:db8::81' });
    await t.action(internal.edgeNameOps.work, { edgeId: a });
    await t.run((ctx) => ctx.db.patch(a, { status: 'destroying' }));
    const pending = await t.mutation(internal.edgeNames.retireForDestroy, { edgeId: a });
    expect(pending).toHaveLength(1);
    expect(await t.query(internal.edgeNames.pendingForDestroy, { edgeId: a })).toBe(1);
    expect(await t.action(internal.edgeNameOps.work, { nameId: pending[0]! })).toBe('removed');
    expect(await t.query(internal.edgeNames.pendingForDestroy, { edgeId: a })).toBe(0);
    expect(zones.get('0'.repeat(32))!.rows).toEqual([]);
    const row = (await nameRows(t))[0]!;
    expect(row).toMatchObject({ state: 'gone' });
    expect(row.served.at(-1)?.why).toBe('destroyed');
  });

  test('a zone holding names cannot be deleted; renew moves the name to another zone', async () => {
    const t = convexTest(schema, modules);
    const f = await seed(t, 2);
    const a = await address(t, f, '198.51.100.91', { published: true });
    await t.action(internal.edgeNameOps.work, { edgeId: a });
    const first = (await nameOf(t, a))!;
    await expect(
      t.mutation(internal.edgeLocations.remove, { id: first.zoneLocationId }),
    ).rejects.toThrow(/names_in_zone|Names for addresses/);
    await t.mutation(internal.edgeNames.renew, { edgeId: a });
    await t.action(internal.edgeNameOps.work, { nameId: first._id });
    await t.action(internal.edgeNameOps.work, { edgeId: a });
    const next = (await nameOf(t, a))!;
    expect(next._id).not.toBe(first._id);
    expect(next.zoneLocationId).not.toBe(first.zoneLocationId);
    expect(next.fqdn).not.toBe(first.fqdn);
    expect((await t.run((ctx) => ctx.db.get(first._id)))!.state).toBe('gone');
  });

  test('the renderer gets the name only while the switch is on', async () => {
    const t = convexTest(schema, modules);
    const f = await seed(t);
    const a = await address(t, f, '198.51.100.101', { published: true });
    await t.action(internal.edgeNameOps.work, { edgeId: a });
    const fqdn = (await nameOf(t, a))!.fqdn;
    const read = () =>
      t.run(async (ctx) => {
        const origin = (await ctx.db.get(f.relayId))!;
        const { published } = await publishedEdgesOf(
          ctx,
          origin,
          { kind: 'member' },
          {
            includeIneligible: true,
          },
        );
        return published.find((p) => p.edgeId === a);
      });
    expect((await read())?.addressName).toBe(fqdn);
    const epoch = (await t.run((ctx) => ctx.db.get(f.relayId)))!.publicationEpoch;
    await setNames(t, { enabled: false });
    expect((await read())?.addressName).toBeUndefined();
    // Turning it off changes every member's body: the epoch moved.
    expect((await t.run((ctx) => ctx.db.get(f.relayId)))!.publicationEpoch).toBe(epoch + 1);
  });

  test('the reconcile pass makes names, and removes them before the walk ends an address', async () => {
    const t = convexTest(schema, modules);
    // The rest of the pass (Hosts, plans) reads other services: nothing to say.
    mockFetch(() => jsonRes({}, 404));
    const f = await seed(t);
    const a = await address(t, f, '198.51.100.121');
    await t.action(internal.edgeReconcile.run, {});
    const row = (await nameOf(t, a))!;
    expect(row.state).toBe('live');
    const zone = zones.get('0'.repeat(32))!;
    expect(zone.rows).toHaveLength(1);
    await t.run((ctx) => ctx.db.patch(a, { status: 'destroying' }));
    await t.action(internal.edgeReconcile.run, {});
    expect(zone.rows).toEqual([]);
    expect((await t.run((ctx) => ctx.db.get(row._id)))!.state).toBe('gone');
    expect((await t.run((ctx) => ctx.db.get(a)))!.status).toBe('destroyed');
  });

  test('upkeep: an address that wants a name and has none is listed once', async () => {
    const t = convexTest(schema, modules);
    const f = await seed(t);
    const a = await address(t, f, '198.51.100.111');
    const b = await address(t, f, '198.51.100.112', { nameWanted: false });
    let plan = await t.query(internal.edgeNames.upkeepPlan, { candidates: [a, b], limit: 10 });
    expect(plan.edgeIds).toEqual([a]);
    await t.action(internal.edgeNameOps.work, { edgeId: a });
    plan = await t.query(internal.edgeNames.upkeepPlan, { candidates: [a, b], limit: 10 });
    expect(plan).toEqual({ nameIds: [], edgeIds: [] });
  });
});
