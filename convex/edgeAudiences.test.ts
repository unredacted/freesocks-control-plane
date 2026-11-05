/// <reference types="vite/client" />
/**
 * Addresses only for some countries end to end (docs/edges.md "Addresses only
 * for some countries"): switching a location to only (and its guards), what a
 * first publication does there (contained, tainted, never the first address),
 * who is handed a contained address (fail closed), the guards that keep the
 * rendezvous walk, switching back to everyone, and the rollback helpers.
 * Adopted RFC 5737 edges, made clean by hand where a test needs one created
 * after the switch; no provider call is made.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { CENSORED_COUNTRIES_KEY } from './lib/censoredCountries';
import {
  adoptL4Edge,
  createAccount,
  insertPanelServer,
  realityListener,
  registerRelay,
} from './lib/edges/testing/fixtures';
import { refuseNetwork } from './lib/edges/testing/mockFetch';

const modules = import.meta.glob('./**/*.*s');

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
  refuseNetwork();
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

/**
 * A node with locations A (meant for Iran) and B, an address in use at B (the
 * transport's template). Steering on, the rendezvous walk.
 */
async function world(opts: { steer?: boolean; legacy?: boolean; onlyA?: boolean } = {}) {
  const t = convexTest(schema, modules);
  await insertPanelServer(t);
  await t.run(async (ctx) => {
    await upsertSettingRow(ctx, 'edge.enabled', 'true');
    await upsertSettingRow(ctx, 'edge.render.enabled', 'true');
    if (opts.steer !== false) await upsertSettingRow(ctx, 'delivery.country.steer', 'true');
    await upsertSettingRow(
      ctx,
      CENSORED_COUNTRIES_KEY,
      JSON.stringify(
        ['IR', 'RU'].map((code) => ({ code, checkEdges: true, checkNamesInside: false })),
      ),
    );
  });
  const accountA = await createAccount(t, { name: 'acct-a', qualified: true });
  const accountB = await createAccount(t, { provider: 'upcloud', name: 'acct-b', qualified: true });
  for (const id of [accountA, accountB])
    await t.mutation(internal.edgeProviderAccounts.recordTest, { id, ok: true });
  const locationOf = (accountId: Id<'edgeProviderAccounts'>) =>
    t.run(async (c) =>
      (await c.db.query('edgeLocations').collect()).find((l) => l.accountId === accountId)!,
    );
  const a = await locationOf(accountA);
  const b = await locationOf(accountB);
  const { relayId, listenerId } = await registerRelay(t, {
    listeners: [realityListener({ listenerKey: 'u', tlsNames: ['a.example', 'b.example'] })],
  });
  await t.run(async (c) => {
    await c.db.patch(relayId, {
      desiredPublished: 4,
      ...(opts.legacy ? { edgePick: undefined } : { edgePick: 'hrw1' }),
      providerSet: [
        { locationId: a._id, addedAt: 1 },
        { locationId: b._id, addedAt: 1 },
      ],
    });
    await c.db.patch(a._id, { forCountries: { codes: ['IR'], updatedAt: 1 } });
  });
  const everyone = (
    await adoptL4Edge(t, relayId, listenerId, {
      ipv4: '198.51.100.20',
      publish: true,
      accountId: accountB,
    })
  ).edgeId as Id<'edges'>;
  if (opts.onlyA) await t.mutation(internal.edgeAudiences.setOnly, { id: a._id, only: true });
  return { t, relayId, listenerId, a, b, accountA, accountB, everyone };
}
type World = Awaited<ReturnType<typeof world>>;

/** A spare at A as if FCP had just made it (not adopted), created after the switch. */
async function freshSpareAtA(w: World, ip: string): Promise<Id<'edges'>> {
  const { edgeId } = await adoptL4Edge(w.t, w.relayId, w.listenerId, {
    ipv4: ip,
    publish: false,
    accountId: w.accountA,
  });
  // What FCP's own create leaves on the row: a resource it made.
  await w.t.run((c) =>
    c.db.patch(edgeId as Id<'edges'>, {
      resources: [
        {
          stepId: 'create_lb',
          kind: 'gcore.loadbalancer',
          resourceId: `lb-${ip}`,
          ownership: 'created',
          deleteState: 'present',
        },
      ],
    }),
  );
  return edgeId as Id<'edges'>;
}

const edgeOf = (w: World, id: Id<'edges'>) =>
  w.t.run(async (c) => (await c.db.get(id))!) as Promise<Doc<'edges'>>;
const publish = (w: World, edgeId: Id<'edges'>) =>
  w.t.mutation(internal.relays.publishEdge, { relayId: w.relayId, edgeId });

describe('switching a location to only', () => {
  test('needs ordering by country, the rendezvous walk, and another carrier for everyone', async () => {
    const off = await world({ steer: false });
    await expect(
      off.t.mutation(internal.edgeAudiences.setOnly, { id: off.a._id, only: true }),
    ).rejects.toThrow(/ordering by country/);
    const legacy = await world({ legacy: true });
    await expect(
      legacy.t.mutation(internal.edgeAudiences.setOnly, { id: legacy.a._id, only: true }),
    ).rejects.toThrow(/old pool walk/);
    const alone = await world();
    await alone.t.run((c) =>
      c.db.patch(alone.relayId, { providerSet: [{ locationId: alone.a._id, addedAt: 1 }] }),
    );
    await expect(
      alone.t.mutation(internal.edgeAudiences.setOnly, { id: alone.a._id, only: true }),
    ).rejects.toThrow(/no other location carrying/);
    const w = await world();
    expect(
      await w.t.mutation(internal.edgeAudiences.setOnly, { id: w.a._id, only: true }),
    ).toMatchObject({
      changed: true,
    });
    const loc = await w.t.run(async (c) => (await c.db.get(w.a._id))!);
    expect(loc.forCountries?.only?.since).toBeGreaterThan(0);
    // Editing its countries keeps the switch; emptying them is refused while it is on.
    await w.t.mutation(internal.edgeLocations.setForCountries, {
      id: w.a._id,
      codes: ['IR', 'RU'],
    });
    expect(
      (await w.t.run(async (c) => (await c.db.get(w.a._id))!)).forCountries?.only,
    ).toBeTruthy();
    await expect(
      w.t.mutation(internal.edgeLocations.setForCountries, { id: w.a._id, codes: [] }),
    ).rejects.toThrow(/switch that off first/);
  });
});

describe('first publication at an only location', () => {
  test('a clean address takes its countries; it never becomes the template', async () => {
    const w = await world({ onlyA: true });
    const spare = await freshSpareAtA(w, '198.51.100.21');
    await publish(w, spare);
    const e = await edgeOf(w, spare);
    expect(e.publication).toBe('published');
    expect(e.audience).toEqual(['IR']);
    const listener = await w.t.run(async (c) => (await c.db.get(w.listenerId))!);
    expect(listener.templateEdgeId).toBe(w.everyone);
  });

  test('an adopted address, or one made before the switch, is never put in use there', async () => {
    const w = await world();
    const before = await freshSpareAtA(w, '198.51.100.22');
    // The switch comes strictly later than the spare was made.
    await new Promise((r) => setTimeout(r, 5));
    await w.t.mutation(internal.edgeAudiences.setOnly, { id: w.a._id, only: true });
    const be = await edgeOf(w, before);
    const loc = await w.t.run(async (c) => (await c.db.get(w.a._id))!);
    void be;
    void loc;
    await expect(publish(w, before)).rejects.toThrow(/cannot be/);
    const adopted = await adoptL4Edge(w.t, w.relayId, w.listenerId, {
      ipv4: '198.51.100.23',
      publish: true,
      accountId: w.accountA,
    }).catch((e: Error) => e);
    const rows = await w.t.run((c) => c.db.query('edges').collect());
    const row = rows.find((e) => e.addresses.v4 === '198.51.100.23');
    expect({
      err: adopted instanceof Error,
      pub: row?.publication ?? null,
      loc: row?.locationId === w.a._id,
    }).toEqual({ err: true, pub: null, loc: false });
  });

  test('upkeep never publishes a contained spare as a transport first address', async () => {
    const w = await world({ onlyA: true });
    // The only address for everyone leaves the pool: the transport has no template.
    await w.t.mutation(internal.relays.unpublishEdge, { relayId: w.relayId, edgeId: w.everyone });
    const spare = await freshSpareAtA(w, '198.51.100.24');
    await w.t.mutation(internal.edgeReconcileMutations.publishStandby, {
      relayId: w.relayId,
      candidates: [spare],
    });
    expect((await edgeOf(w, spare)).publication).toBe('unpublished');
  });
});

describe('who is handed a contained address', () => {
  test('a member in its countries only: not another country, not no country (the opt-out too)', async () => {
    const w = await world({ onlyA: true });
    const spare = await freshSpareAtA(w, '198.51.100.25');
    await publish(w, spare);
    const holds = async (country?: string) => {
      for (let i = 0; i < 30; i++) {
        const p = await w.t.query(internal.edgeAdmin.renderPreview, {
          relayId: w.relayId,
          family: 'xray-links',
          sampleKey: `${i.toString(16).padStart(8, '0')}${'ab'.repeat(28)}`,
          ...(country ? { country } : {}),
        });
        if (p.body.includes('198.51.100.25')) return true;
      }
      return false;
    };
    expect(await holds('IR')).toBe(true);
    expect(await holds('RU')).toBe(false);
    expect(await holds()).toBe(false);
  });
});

describe('keeping the rendezvous walk', () => {
  test('a node with a contained address, or an only pick, may not go back to the legacy walk', async () => {
    const w = await world({ onlyA: true });
    await expect(
      w.t.mutation(internal.edgeAdmin.setEdgePick, { relayId: w.relayId, version: null }),
    ).rejects.toThrow(/rendezvous walk/);
    await expect(w.t.mutation(internal.edgeAdmin.clearSeatsForRollback, {})).rejects.toThrow(
      /rendezvous walk/,
    );
  });
});

describe('back to everyone', () => {
  test('every address there becomes everyone’s for good; the node moves its epoch', async () => {
    const w = await world({ onlyA: true });
    const spare = await freshSpareAtA(w, '198.51.100.26');
    await publish(w, spare);
    const epoch = (await w.t.run(async (c) => (await c.db.get(w.relayId))!)).publicationEpoch;
    expect(
      await w.t.mutation(internal.edgeAudiences.setOnly, { id: w.a._id, only: false }),
    ).toMatchObject({
      changed: true,
      widened: 1,
      nodes: 1,
    });
    expect((await edgeOf(w, spare)).audience).toBeUndefined();
    expect((await w.t.run(async (c) => (await c.db.get(w.relayId))!)).publicationEpoch).toBe(
      epoch + 1,
    );
  });
});

describe('rollback', () => {
  test('contained addresses in use drain; the clear step waits until they are destroyed', async () => {
    const w = await world({ onlyA: true });
    const spare = await freshSpareAtA(w, '198.51.100.27');
    await publish(w, spare);
    await expect(
      w.t.mutation(internal.edgeLocations.clearCountriesForRollback, {}),
    ).rejects.toThrow(/retireAudiencesForRollback/);
    expect(await w.t.mutation(internal.edgeAudiences.retireAudiencesForRollback, {})).toMatchObject(
      {
        drained: 1,
      },
    );
    const e = await edgeOf(w, spare);
    expect(e.publication).toBe('draining');
    // Kept as a spare it would be handed to everyone by a build without audiences.
    await expect(
      w.t.mutation(internal.edgeAdmin.resolveOperator, { edgeId: spare, action: 'reactivate' }),
    ).rejects.toThrow();
    await expect(
      w.t.mutation(internal.edgeAudiences.clearAudiencesForRollback, {}),
    ).rejects.toThrow(/not destroyed yet/);
    await w.t.run((c) => c.db.patch(spare, { status: 'destroyed', publication: 'unpublished' }));
    expect(await w.t.mutation(internal.edgeAudiences.clearAudiencesForRollback, {})).toMatchObject({
      cleared: 1,
    });
    expect((await edgeOf(w, spare)).audience).toBeUndefined();
    // The location is no longer only: the countries' own rollback may run.
    await w.t.mutation(internal.edgeLocations.clearCountriesForRollback, {});
  });
});

describe('review fixes', () => {
  test('a contained address published again stays contained: never a first address', async () => {
    const w = await world({ onlyA: true });
    const spare = await freshSpareAtA(w, '198.51.100.30');
    await publish(w, spare);
    // Back to a spare, and the address for everyone leaves too: none is in use.
    await w.t.mutation(internal.relays.unpublishEdge, {
      relayId: w.relayId,
      edgeId: spare,
      keepActive: true,
    });
    await w.t.mutation(internal.relays.unpublishEdge, { relayId: w.relayId, edgeId: w.everyone });
    await expect(publish(w, spare)).rejects.toThrow(/first one/);
    expect((await edgeOf(w, spare)).audience).toEqual(['IR']);
  });

  test('a node on the legacy walk never gets a contained address', async () => {
    const w = await world({ onlyA: true });
    await w.t.run((c) => c.db.patch(w.relayId, { edgePick: undefined }));
    const spare = await freshSpareAtA(w, '198.51.100.31');
    await expect(publish(w, spare)).rejects.toThrow();
    expect((await edgeOf(w, spare)).publication).toBe('unpublished');
  });

  test("a spare made before the switch does not hold back a count's purchase", async () => {
    const w = await world();
    await freshSpareAtA(w, '198.51.100.32');
    await new Promise((r) => setTimeout(r, 5));
    await w.t.mutation(internal.edgeAudiences.setOnly, { id: w.a._id, only: true });
    await w.t.run((c) =>
      c.db.patch(w.relayId, {
        providerSet: [
          { locationId: w.a._id, addedAt: 1, want: 1 },
          { locationId: w.b._id, addedAt: 1 },
        ],
      }),
    );
    expect(
      await w.t.query(internal.edgePickWants.nextCountGap, { relayId: w.relayId }),
    ).toMatchObject({
      spares: [],
      mayProvision: true,
    });
  });
});

describe('part 2', () => {
  const renew = (w: World, publish = true) =>
    w.t.mutation(internal.edgeReconcileMutations.renewOutOfDate, { relayId: w.relayId, publish });
  const relayOf = (w: World) => w.t.run(async (c) => (await c.db.get(w.relayId))!);
  /** An address for Iran in use at A, then A made for Iran and Russia: it is out of date. */
  async function outOfDate(w: World): Promise<Id<'edges'>> {
    const old = await freshSpareAtA(w, '198.51.100.40');
    await publish(w, old);
    await w.t.mutation(internal.edgeLocations.setForCountries, {
      id: w.a._id,
      codes: ['IR', 'RU'],
    });
    return old;
  }

  test('an out-of-date address is renewed in its own slot: the pool keeps its size', async () => {
    const w = await world({ onlyA: true });
    const old = await outOfDate(w);
    const slot = (await edgeOf(w, old)).poolIndex;
    // Nothing there to take its place: upkeep is asked for one spare there.
    expect(await renew(w)).toEqual({
      kind: 'needs_spare',
      listenerId: w.listenerId,
      locationId: w.a._id,
    });
    const spare = await freshSpareAtA(w, '198.51.100.41');
    const before = await relayOf(w);
    // Spares going in use by hand: it only waits.
    expect(await renew(w, false)).toEqual({ kind: 'waiting' });
    expect((await edgeOf(w, old)).publication).toBe('published');
    expect(await renew(w)).toEqual({ kind: 'renewed', edgeId: old, by: spare });
    const after = await relayOf(w);
    expect((await edgeOf(w, old)).publication).toBe('draining');
    const taken = await edgeOf(w, spare);
    expect(taken).toMatchObject({ publication: 'published', poolIndex: slot });
    expect(taken.audience).toEqual(['IR', 'RU']);
    expect(after.desiredPublished).toBe(before.desiredPublished);
    expect(after.publishedEdgeIds.filter(Boolean).length).toBe(
      before.publishedEdgeIds.filter(Boolean).length,
    );
    expect(after.standbyEdgeIds).not.toContain(spare);
    expect(await renew(w)).toEqual({ kind: 'none' });
  });

  test('with more current addresses there than the count, the out-of-date one just leaves', async () => {
    const w = await world({ onlyA: true });
    const old = await outOfDate(w);
    const current = await freshSpareAtA(w, '198.51.100.41');
    await publish(w, current);
    expect((await edgeOf(w, current)).audience).toEqual(['IR', 'RU']);
    expect(await renew(w)).toEqual({ kind: 'retired', edgeId: old });
    expect((await edgeOf(w, old)).publication).toBe('draining');
    expect((await edgeOf(w, current)).publication).toBe('published');
  });

  test('the pool never grows for a renewal: the out-of-date address holds its count', async () => {
    const w = await world({ onlyA: true });
    await outOfDate(w);
    await w.t.run(async (c) => {
      const r = (await c.db.get(w.relayId))!;
      await c.db.patch(w.relayId, {
        desiredPublished: r.publishedEdgeIds.filter(Boolean).length,
        providerSet: [
          { locationId: w.a._id, addedAt: 1, want: 1 },
          { locationId: w.b._id, addedAt: 1 },
        ],
      });
    });
    const full = (await relayOf(w)).desiredPublished;
    const capacity = await w.t.mutation(internal.relays.ensureCapacity, { relayId: w.relayId });
    expect(capacity?.to).toBe(full);
    expect(await w.t.query(internal.edgePickWants.nextCountGap, { relayId: w.relayId })).toBeNull();
  });

  test('nothing is renewed while the node is held (guided setup, restore)', async () => {
    const w = await world({ onlyA: true });
    const old = await outOfDate(w);
    await freshSpareAtA(w, '198.51.100.41');
    await w.t.run((c) => c.db.patch(w.relayId, { setupOwned: true }));
    expect(await renew(w)).toEqual({ kind: 'none' });
    const now = Date.now();
    await w.t.run((c) =>
      c.db.patch(w.relayId, {
        setupOwned: undefined,
        restore: {
          purpose: 'cancel_setup',
          phase: 'freeze',
          startedAt: now,
          updatedAt: now,
          attempt: 0,
        } as never,
      }),
    );
    expect(await renew(w)).toEqual({ kind: 'none' });
    expect((await edgeOf(w, old)).publication).toBe('published');
  });

  test("a contained address's probe round is planned and charged for its countries only", async () => {
    const w = await world({ onlyA: true });
    const spare = await freshSpareAtA(w, '198.51.100.43');
    await publish(w, spare);
    const testsOf = async (edgeId: Id<'edges'>) => {
      await w.t.mutation(internal.probes.requestProbes, {
        target: { kind: 'edge', ref: edgeId },
        trigger: 'manual',
        sources: ['globalping'],
      });
      const runs = await w.t.run((c) => c.db.query('probeRuns').collect());
      const mine = runs.filter((r) => r.targetRef === edgeId && r.source === 'globalping');
      return mine.map((r) => r.tests);
    };
    const contained = await testsOf(spare);
    const everyone = await testsOf(w.everyone);
    // Iran only against Iran and Russia: half the vantages (no controls here).
    expect(contained.length).toBe(1);
    expect(contained[0]).toBeGreaterThan(0);
    expect(everyone).toEqual([contained[0]! * 2]);
  });

  test('a contained address is probed only from its countries (the controls stay)', async () => {
    const w = await world({ onlyA: true });
    const spare = await freshSpareAtA(w, '198.51.100.42');
    await publish(w, spare);
    const runId = await w.t.run((c) =>
      c.db.insert('probeRuns', {
        targetKind: 'edge',
        targetRef: spare,
        source: 'globalping',
        target: '198.51.100.42:443',
        status: 'requested',
        trigger: 'cron',
        requestedAt: Date.now(),
        results: [],
      }),
    );
    const ctx = await w.t.query(internal.probes.runContext, { runId });
    expect(ctx?.countries).toEqual(['IR']);
    const everyoneRun = await w.t.run((c) =>
      c.db.insert('probeRuns', {
        targetKind: 'edge',
        targetRef: w.everyone,
        source: 'globalping',
        target: '198.51.100.20:443',
        status: 'requested',
        trigger: 'cron',
        requestedAt: Date.now(),
        results: [],
      }),
    );
    expect(
      (await w.t.query(internal.probes.runContext, { runId: everyoneRun }))?.countries,
    ).toEqual(['IR', 'RU']);
  });
});
