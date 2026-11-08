/// <reference types="vite/client" />
/**
 * Countries with their own addresses end to end (docs/edges.md "Countries with
 * their own addresses"): a node's pick keeping addresses for some countries
 * (saving it and its guards), the count over every pick holding them (step 5W:
 * a spare made for them first, else a provision made for them, at the second
 * place when the first is held), what a first publication does to an address
 * made for them, the fills of everyone's addresses never taking one, a pick
 * serving its countries only, selection, and the rollback. Adopted RFC 5737
 * edges, made clean by hand where a test needs one FCP made; no provider call.
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
 * A node picking locations A and B (two accounts), an address everyone is
 * handed in use at B (the transport's template). Steering on, the rendezvous
 * walk, upkeep provisioning on.
 */
async function world(opts: { steer?: boolean; legacy?: boolean } = {}) {
  const t = convexTest(schema, modules);
  await insertPanelServer(t);
  await t.run(async (ctx) => {
    await upsertSettingRow(ctx, 'edge.enabled', 'true');
    await upsertSettingRow(ctx, 'edge.render.enabled', 'true');
    await upsertSettingRow(ctx, 'edge.autoProvisionToDesired', 'true');
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
  });
  const everyone = (
    await adoptL4Edge(t, relayId, listenerId, {
      ipv4: '198.51.100.20',
      publish: true,
      accountId: accountB,
    })
  ).edgeId as Id<'edges'>;
  // Location A holds an address everyone is handed too (the set's coverage).
  await adoptL4Edge(t, relayId, listenerId, {
    ipv4: '198.51.100.19',
    publish: true,
    accountId: accountA,
  });
  return { t, relayId, listenerId, a, b, accountA, accountB, everyone };
}
type World = Awaited<ReturnType<typeof world>>;

const relayOf = (w: World) => w.t.run(async (c) => (await c.db.get(w.relayId))!);
const edgeOf = (w: World, id: Id<'edges'>) =>
  w.t.run(async (c) => (await c.db.get(id))!) as Promise<Doc<'edges'>>;
const reconcile = (w: World) => w.t.action(internal.edgeReconcile.run, {});
const rotations = (w: World) =>
  w.t.run(async (c) =>
    (await c.db.query('edgeRotations').collect()).filter((r) => r.relayId === w.relayId),
  );
const setAudience = (
  w: World,
  codes: string[],
  want: number | null,
  at: Id<'edgeLocations'> = w.a._id,
  remove?: boolean,
) =>
  w.t.mutation(internal.edgeAudiences.setPickAudience, {
    relayId: w.relayId,
    locationId: at,
    codes,
    want,
    ...(remove ? { remove } : {}),
  });

/** A spare as if FCP had just made it (a resource of its own), optionally for some countries. */
async function freshSpare(
  w: World,
  ip: string,
  accountId: Id<'edgeProviderAccounts'>,
  intent?: string[],
): Promise<Id<'edges'>> {
  const { edgeId } = await adoptL4Edge(w.t, w.relayId, w.listenerId, {
    ipv4: ip,
    publish: false,
    accountId,
  });
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
      ...(intent ? { audienceIntent: intent } : {}),
    }),
  );
  return edgeId as Id<'edges'>;
}

describe('saving countries on a pick', () => {
  test('needs ordering by country and the rendezvous walk; listed countries, picked locations', async () => {
    const off = await world({ steer: false });
    await expect(setAudience(off, ['IR'], 1)).rejects.toThrow(/ordering by country/);
    const legacy = await world({ legacy: true });
    await expect(setAudience(legacy, ['IR'], 1)).rejects.toThrow(/rendezvous walk/);
    const w = await world();
    await expect(setAudience(w, ['CN'], 1)).rejects.toThrow(/not on the censored-country list/);
    await expect(setAudience(w, [], 1)).rejects.toThrow(/Name 1 to/);
    await expect(setAudience(w, ['IR'], 9)).rejects.toThrow(/1 to 8/);
    const accountC = await createAccount(w.t, { name: 'acct-c', qualified: true });
    const other = await w.t.run(
      async (c) =>
        (await c.db.query('edgeLocations').collect()).find((l) => l.accountId === accountC)!._id,
    );
    await expect(setAudience(w, ['IR'], 1, other)).rejects.toThrow(/not picked/);
  });

  test('saved, audited; the same again changes nothing; one country per pick once; removable', async () => {
    const w = await world();
    expect(await setAudience(w, ['ir'], 1)).toMatchObject({ changed: true });
    expect(await setAudience(w, ['IR'], 1)).toMatchObject({ changed: false });
    const pick = (await relayOf(w)).providerSet!.find((p) => p.locationId === w.a._id)!;
    expect(pick.audiences).toEqual([{ codes: ['IR'], want: 1, addedAt: expect.any(Number) }]);
    await expect(setAudience(w, ['IR', 'RU'], 1)).rejects.toThrow(/already keeps addresses for IR/);
    // Another count for the same countries replaces it; a place with none is fine too.
    expect(await setAudience(w, ['IR'], null)).toMatchObject({ changed: true });
    expect(
      (await relayOf(w)).providerSet!.find((p) => p.locationId === w.a._id)!.audiences,
    ).toEqual([{ codes: ['IR'], addedAt: expect.any(Number) }]);
    const audit = await w.t.run((c) =>
      c.db
        .query('auditLog')
        .filter((q) => q.eq(q.field('action'), 'edge.relay.pick_audience'))
        .collect(),
    );
    expect(audit.map((x) => x.payload)).toMatchObject([
      { countries: 'IR', want: 1 },
      { countries: 'IR', want: 0 },
    ]);
    expect(await setAudience(w, ['IR'], null, w.a._id, true)).toMatchObject({ changed: true });
    expect(
      (await relayOf(w)).providerSet!.find((p) => p.locationId === w.a._id)!.audiences,
    ).toBeUndefined();
  });

  test('never at a location only for some countries, and such a location never takes a pick of them', async () => {
    const w = await world();
    await w.t.run((c) => c.db.patch(w.a._id, { forCountries: { codes: ['IR'], updatedAt: 1 } }));
    await setAudience(w, ['RU'], 1);
    await expect(
      w.t.mutation(internal.edgeAudiences.setOnly, { id: w.a._id, only: true }),
    ).rejects.toThrow(/keeps addresses for some countries here/);
    await setAudience(w, ['RU'], null, w.a._id, true);
    await w.t.mutation(internal.edgeAudiences.setOnly, { id: w.a._id, only: true });
    await expect(setAudience(w, ['IR'], 1)).rejects.toThrow(/only for some countries already/);
  });

  test('a node keeping addresses for some countries keeps the rendezvous walk', async () => {
    const w = await world();
    await setAudience(w, ['IR'], 1);
    const { holdsContainment } = await import('./edgeAudiences');
    expect(await w.t.run(async (c) => holdsContainment(c.db, (await c.db.get(w.relayId))!))).toBe(
      true,
    );
  });
});

describe('a pick serving its countries only', () => {
  test('needs countries, no count of everyone’s, and another carrier for everyone', async () => {
    const w = await world();
    const only = (on: boolean, at = w.a._id) =>
      w.t.mutation(internal.edgeAudiences.setPickAudienceOnly, {
        relayId: w.relayId,
        locationId: at,
        only: on,
      });
    await expect(only(true)).rejects.toThrow(/Name the countries/);
    await setAudience(w, ['IR'], 1);
    await w.t.mutation(internal.edgePickWants.setPickWant, {
      relayId: w.relayId,
      locationId: w.a._id,
      want: 1,
    });
    await expect(only(true)).rejects.toThrow(/Clear the count/);
    await w.t.mutation(internal.edgePickWants.setPickWant, {
      relayId: w.relayId,
      locationId: w.a._id,
      want: null,
    });
    expect(await only(true)).toMatchObject({ changed: true });
    expect((await relayOf(w)).providerSet!.find((p) => p.locationId === w.a._id)).toMatchObject({
      audienceOnly: true,
    });
    // B alone carries the transport for everyone now: B may not be kept for countries.
    await setAudience(w, ['RU'], 1, w.b._id);
    await expect(only(true, w.b._id)).rejects.toThrow(/no other location carrying/);
    // Its last countries removed: it serves everyone again.
    await setAudience(w, ['IR'], null, w.a._id, true);
    const pick = (await relayOf(w)).providerSet!.find((p) => p.locationId === w.a._id)!;
    expect(pick.audienceOnly).toBeUndefined();
  });
});

describe('upkeep keeps their count (step 5W)', () => {
  test('without a spare, a provision made for them at the first place', async () => {
    const w = await world();
    await setAudience(w, ['IR'], 1);
    await reconcile(w);
    const rs = await rotations(w);
    expect(rs).toHaveLength(1);
    expect(rs[0]).toMatchObject({
      kind: 'provision',
      onlyLocationId: w.a._id,
      audience: ['IR'],
      listenerId: w.listenerId,
      publishOnDone: true,
    });
  });

  test('the second place when the first is held (a refused create)', async () => {
    const w = await world();
    await setAudience(w, ['IR'], 1);
    await setAudience(w, ['IR'], null, w.b._id);
    await w.t.run((c) =>
      c.db.patch(w.relayId, {
        refusedLocations: [
          { locationId: w.a._id, code: 'create_refused', at: 1, until: Date.now() + 3_600_000 },
        ],
      }),
    );
    await reconcile(w);
    const rs = await rotations(w);
    expect(rs).toHaveLength(1);
    expect(rs[0]).toMatchObject({ onlyLocationId: w.b._id, audience: ['IR'] });
  });

  test('a fill of everyone’s never takes a spare made for some countries', async () => {
    const w = await world();
    const theirs = await freshSpare(w, '198.51.100.30', w.accountB, ['IR']);
    // A count of everyone's at B is short: it buys one rather than take the IR spare.
    await w.t.mutation(internal.edgePickWants.setPickWant, {
      relayId: w.relayId,
      locationId: w.b._id,
      want: 2,
    });
    await reconcile(w);
    expect((await edgeOf(w, theirs)).publication).toBe('unpublished');
    expect((await rotations(w)).map((r) => [r.kind, r.onlyLocationId, r.audience])).toEqual([
      ['provision', w.b._id, undefined],
    ]);
  });

  test('a spare made for them goes in use first, contained to them', async () => {
    const w = await world();
    const theirs = await freshSpare(w, '198.51.100.30', w.accountA, ['IR']);
    await setAudience(w, ['IR'], 1);
    await reconcile(w);
    const e = await edgeOf(w, theirs);
    expect(e.publication).toBe('published');
    expect(e.audience).toEqual(['IR']);
    // The count is met: nothing more is made for them.
    const forThem = (await rotations(w)).filter((r) => r.audience?.length);
    expect(forThem).toEqual([]);
  });

  test('a count met by an address of theirs anywhere asks for nothing; everyone’s never counts', async () => {
    const w = await world();
    await setAudience(w, ['IR'], 1, w.b._id);
    const theirs = await freshSpare(w, '198.51.100.31', w.accountA, ['IR']);
    await w.t.mutation(internal.relays.publishEdge, { relayId: w.relayId, edgeId: theirs });
    expect((await edgeOf(w, theirs)).audience).toEqual(['IR']);
    const gaps = await w.t.run(async (c) => {
      const { countGapsOf } = await import('./edgePickWants');
      return countGapsOf(c.db, (await c.db.get(w.relayId))!, Date.now());
    });
    expect(gaps).toEqual([]);
  });
});

describe('with address lanes on', () => {
  test('the pool keeps the lanes, the addresses of theirs in use, and what their count still asks', async () => {
    const w = await world();
    const theirs = await freshSpare(w, '198.51.100.36', w.accountA, ['IR']);
    await w.t.mutation(internal.relays.publishEdge, { relayId: w.relayId, edgeId: theirs });
    await w.t.mutation(internal.edgeLanes.setLanes, {
      relayId: w.relayId,
      lanes: { open: 1, trusted: 1 },
    });
    // The lanes: two open addresses of everyone's in use and a trusted one
    // wanted (three), and Iran's one in use (four).
    await w.t.mutation(internal.edgeLanes.reconcileLanes, { relayId: w.relayId });
    expect((await relayOf(w)).desiredPublished).toBe(4);
    // Iran's count asks for one more: a fifth slot.
    await setAudience(w, ['IR'], 2);
    await w.t.mutation(internal.edgeLanes.reconcileLanes, { relayId: w.relayId });
    expect((await relayOf(w)).desiredPublished).toBe(5);
  });
});

describe('an address made for some countries', () => {
  test('takes them at its first publication wherever it is; adopted or published before, never', async () => {
    const w = await world();
    const clean = await freshSpare(w, '198.51.100.32', w.accountB, ['IR']);
    await w.t.mutation(internal.relays.publishEdge, { relayId: w.relayId, edgeId: clean });
    expect(await edgeOf(w, clean)).toMatchObject({ audience: ['IR'], contained: true });
    // Never the template: the backend's Host stays on everyone's address.
    const listener = await w.t.run(async (c) => (await c.db.get(w.listenerId))!);
    expect(listener.templateEdgeId).toBe(w.everyone);
    const adopted = (
      await adoptL4Edge(w.t, w.relayId, w.listenerId, {
        ipv4: '198.51.100.33',
        publish: false,
        accountId: w.accountB,
      })
    ).edgeId as Id<'edges'>;
    await w.t.run((c) => c.db.patch(adopted, { audienceIntent: ['IR'] }));
    await expect(
      w.t.mutation(internal.relays.publishEdge, { relayId: w.relayId, edgeId: adopted }),
    ).rejects.toThrow(/cannot be/);
  });
});

describe('selection', () => {
  const select = async (w: World, req: { audience?: string[]; only?: Id<'edgeLocations'> } = {}) =>
    w.t.run(async (ctx) => {
      const { selectionContext } = await import('./edgeRotations');
      const { resolveEdgeConfig } = await import('./lib/edgeConfig');
      const sel = await selectionContext(
        ctx,
        {
          kind: 'provision',
          trigger: 'reconcile',
          publishOnDone: false,
          listenerId: w.listenerId,
          ...(req.only ? { onlyLocationId: req.only } : {}),
          ...(req.audience ? { audience: req.audience } : {}),
        },
        (await ctx.db.get(w.relayId))!,
        null,
        await resolveEdgeConfig(ctx.db),
      );
      return { location: sel.account?.locationId ?? null, failure: sel.accountFailure ?? null };
    });

  test('a fill for some countries only where a pick holds exactly them', async () => {
    const w = await world();
    await setAudience(w, ['IR'], 1, w.b._id);
    expect((await select(w, { audience: ['IR'] })).location).toBe(w.b._id);
    expect((await select(w, { audience: ['RU'] })).location).toBeNull();
  });

  test('a pick serving its countries only never takes an address for everyone', async () => {
    const w = await world();
    await setAudience(w, ['IR'], 1);
    await w.t.mutation(internal.edgeAudiences.setPickAudienceOnly, {
      relayId: w.relayId,
      locationId: w.a._id,
      only: true,
    });
    expect((await select(w, { only: w.a._id })).location).toBeNull();
    expect((await select(w, { only: w.b._id })).location).toBe(w.b._id);
    expect((await select(w, { audience: ['IR'], only: w.a._id })).location).toBe(w.a._id);
  });

  test('a provision for countries no pick holds is refused at start', async () => {
    const w = await world();
    await expect(
      w.t.mutation(internal.edgeRotations.start, {
        relayId: w.relayId,
        kind: 'provision',
        trigger: 'manual',
        audience: ['IR'],
      }),
    ).rejects.toThrow(/keeps addresses for those countries/);
  });
});

describe('rollback', () => {
  test('every pick forgets its countries, every row what it was made for; contained stay contained', async () => {
    vi.useFakeTimers();
    const w = await world();
    await setAudience(w, ['IR'], 1);
    const published = await freshSpare(w, '198.51.100.34', w.accountA, ['IR']);
    await w.t.mutation(internal.relays.publishEdge, { relayId: w.relayId, edgeId: published });
    const spare = await freshSpare(w, '198.51.100.35', w.accountA, ['IR']);
    await w.t.mutation(internal.edgeAudiences.clearAudiencePicksForRollback, {});
    await w.t.finishAllScheduledFunctions(vi.runAllTimers);
    const pick = (await relayOf(w)).providerSet!.find((p) => p.locationId === w.a._id)!;
    expect(pick.audiences).toBeUndefined();
    expect((await edgeOf(w, spare)).audienceIntent).toBeUndefined();
    const e = await edgeOf(w, published);
    expect(e.audienceIntent).toBeUndefined();
    expect(e.audience).toEqual(['IR']);
  });
});
