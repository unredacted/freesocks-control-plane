/// <reference types="vite/client" />
/**
 * A country on its own addresses end to end (docs/edges.md "A country on its
 * own addresses"): a cutover and what it needs first, stopping it, a cutover
 * on every node, the rehearsal, a replacement of the country's own address on
 * its own budget (counted, outside the node's cap and cooldown; an operator's
 * never refused), the attention, the hourly count of keys still on an older
 * body, and the rollback. Adopted RFC 5737 edges, made clean by hand where a
 * test needs one FCP made; no provider call.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { CENSORED_COUNTRIES_KEY } from './lib/censoredCountries';
import {
  adoptL4Edge,
  createAccount,
  FIXTURE_NODE,
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
 * A node picking locations A and B, an address everyone is handed in use at
 * each; Iran keeps one address of its own at A, in use and contained. Steering
 * and the country question on, the rendezvous walk.
 */
async function world(opts: { ask?: boolean; ready?: boolean } = {}) {
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
  await t.run(async (ctx) => {
    await upsertSettingRow(ctx, 'edge.enabled', 'true');
    await upsertSettingRow(ctx, 'edge.render.enabled', 'true');
    await upsertSettingRow(ctx, 'delivery.country.steer', 'true');
    if (opts.ask !== false) await upsertSettingRow(ctx, 'delivery.country.ask', 'true');
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
  await t.run((c) =>
    c.db.patch(relayId, {
      desiredPublished: 4,
      edgePick: 'hrw1',
      providerSet: [
        { locationId: a._id, addedAt: 1 },
        { locationId: b._id, addedAt: 1 },
      ],
    }),
  );
  for (const [ip, accountId] of [
    ['198.51.100.19', accountA],
    ['198.51.100.20', accountB],
  ] as const)
    await adoptL4Edge(t, relayId, listenerId, { ipv4: ip, publish: true, accountId });
  const w = { t, serverId, relayId, listenerId, a, b, accountA, accountB };
  if (opts.ready !== false) {
    const own = await freshSpare(w, '198.51.100.30', accountA, ['IR']);
    await t.mutation(internal.edgeAudiences.setPickAudience, {
      relayId,
      locationId: a._id,
      codes: ['IR'],
      want: 1,
    });
    await t.action(internal.edgeReconcile.run, {});
    return { ...w, own };
  }
  return { ...w, own: null as Id<'edges'> | null };
}
type World = Awaited<ReturnType<typeof world>>;

/** A spare as if FCP had just made it (a resource of its own), optionally for some countries. */
async function freshSpare(
  w: Pick<World, 't' | 'relayId' | 'listenerId'>,
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

const relayOf = (w: World) => w.t.run(async (c) => (await c.db.get(w.relayId))!);
const cutover = (w: World, code: string, own = true) =>
  w.t.mutation(internal.edgeOwnPools.setOwnPool, { relayId: w.relayId, code, own });
const audit = (w: World, action: string) =>
  w.t.run((c) =>
    c.db
      .query('auditLog')
      .filter((q) => q.eq(q.field('action'), action))
      .collect(),
  );

describe('cutting a country over', () => {
  test('its own addresses in use, contained, before anything else', async () => {
    const w = await world();
    const e = await w.t.run(async (c) => (await c.db.get(w.own!))!);
    expect(e.publication).toBe('published');
    expect(e.audience).toEqual(['IR']);
  });

  test('needs the country question, a pool of its own at its count, none of it blocked there', async () => {
    const noAsk = await world({ ask: false });
    await expect(cutover(noAsk, 'IR')).rejects.toThrow(/country question/);
    const w = await world();
    await expect(cutover(w, 'CN')).rejects.toThrow(/not on the censored-country list/);
    await expect(cutover(w, 'RU')).rejects.toThrow(
      /No location of this node keeps addresses for RU/,
    );
    // A count of two: one short.
    await w.t.mutation(internal.edgeAudiences.setPickAudience, {
      relayId: w.relayId,
      locationId: w.a._id,
      codes: ['IR'],
      want: 2,
    });
    await expect(cutover(w, 'IR')).rejects.toThrow(/fewer than their count/);
    await w.t.mutation(internal.edgeAudiences.setPickAudience, {
      relayId: w.relayId,
      locationId: w.a._id,
      codes: ['IR'],
      want: 1,
    });
    await w.t.mutation(internal.edgeCountry.setMark, {
      scope: 'edge',
      ref: w.own!,
      country: 'IR',
      state: 'blocked',
    });
    await expect(cutover(w, 'IR')).rejects.toThrow(/blocked there/);
    // Ordering by country off: refused too.
    await w.t.mutation(internal.edgeCountry.setMark, {
      scope: 'edge',
      ref: w.own!,
      country: 'IR',
      state: null,
    });
    await w.t.run((c) => upsertSettingRow(c, 'delivery.country.steer', 'false'));
    await expect(cutover(w, 'IR')).rejects.toThrow(/ordering by country/);
  });

  test('cut over: stored, the epoch moves, audited; again nothing; stopping is never refused', async () => {
    const w = await world();
    const before = (await relayOf(w)).publicationEpoch;
    expect(await cutover(w, 'ir')).toMatchObject({ changed: true });
    const r = await relayOf(w);
    expect(r.ownPools).toEqual([{ code: 'IR', since: expect.any(Number) }]);
    expect(r.publicationEpoch).toBe(before + 1);
    expect(await cutover(w, 'IR')).toMatchObject({ changed: false });
    // Blocked after the cutover: stopping is still allowed.
    await w.t.mutation(internal.edgeCountry.setMark, {
      scope: 'edge',
      ref: w.own!,
      country: 'IR',
      state: 'blocked',
    });
    expect(await cutover(w, 'IR', false)).toMatchObject({ changed: true });
    const after = await relayOf(w);
    expect(after.ownPools).toBeUndefined();
    expect(after.publicationEpoch).toBe(before + 2);
    expect((await audit(w, 'edge.relay.own_pool')).map((x) => x.payload)).toMatchObject([
      { country: 'IR', own: true },
      { country: 'IR', own: false },
    ]);
  });

  test('on every node where it may be: one result per node keeping addresses for it', async () => {
    const w = await world();
    const out = await w.t.mutation(internal.edgeOwnPools.setOwnPoolEverywhere, {
      code: 'IR',
      own: true,
    });
    expect(out.results).toEqual([{ relaySlug: expect.any(String), changed: true, refusal: null }]);
    const ru = await w.t.mutation(internal.edgeOwnPools.setOwnPoolEverywhere, {
      code: 'RU',
      own: true,
    });
    expect(ru.results).toEqual([]);
  });

  test('the rehearsal: who moves, and the refusal', async () => {
    const w = await world();
    const p = await w.t.query(internal.edgeOwnPools.cutoverPreview, {
      relayId: w.relayId,
      code: 'IR',
    });
    expect(p.refusal).toBeNull();
    expect(p.own).toBe(false);
    // One address of its own: it first, a shared one as the backup, both today and after.
    expect(p.rehearsal.sampled).toBeGreaterThan(0);
    expect(p.rehearsal.sharedAfter).toBe(p.rehearsal.sampled);
    const ru = await w.t.query(internal.edgeOwnPools.cutoverPreview, {
      relayId: w.relayId,
      code: 'RU',
    });
    expect(ru.refusal?.code).toBe('edge.audience_no_pool');
  });
});

describe("its own address's replacement", () => {
  test('on its own budget: counted there, not on the node, no cooldown; then refused until tomorrow', async () => {
    const w = await world();
    await cutover(w, 'IR');
    const spare = await freshSpare(w, '198.51.100.31', w.accountB, ['IR']);
    await w.t.mutation(internal.edgeRotations.start, {
      relayId: w.relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: w.own!,
      toEdgeId: spare,
    });
    const r = await relayOf(w);
    expect(r.audienceReplaces).toEqual([
      { key: `IR|${w.listenerId}`, day: expect.any(String), count: 1 },
    ]);
    expect(r.rotationsToday ?? 0).toBe(0);
    const rotation = await w.t.run(async (c) => (await c.db.get(r.activeRotationId!))!);
    expect(rotation.ownPool).toBe(true);
    // Today's one is used: an automatic start is refused, an operator's is not.
    const blockers = async (trigger: 'api' | 'manual') =>
      (
        await w.t.query(internal.edgeOperator.preflight, {
          relayId: w.relayId,
          kind: 'replace',
          edgeId: w.own!,
          trigger,
        })
      ).blockers.map((b) => b.code);
    expect(await blockers('api')).toContain('audience_budget');
    expect(await blockers('manual')).not.toContain('audience_budget');
    // A node's budget of 2 lets one more through.
    await w.t.mutation(internal.edgeOwnPools.setOwnBudget, { relayId: w.relayId, perDay: 2 });
    expect(await blockers('api')).not.toContain('audience_budget');
    await expect(
      w.t.mutation(internal.edgeOwnPools.setOwnBudget, { relayId: w.relayId, perDay: 11 }),
    ).rejects.toThrow(/0 to 10/);
  });
});

describe('attention and the count of keys on an older body', () => {
  test('its own addresses all blocked there: its members are on shared ones', async () => {
    const w = await world();
    await cutover(w, 'IR');
    const kinds = async () =>
      (await w.t.query(internal.edgeOperator.attention, {})).items
        .filter((i: { kind: string }) => i.kind.startsWith('audience_'))
        .map((i: { kind: string; facts?: unknown }) => [i.kind, i.facts]);
    expect(await kinds()).toEqual([]);
    await w.t.mutation(internal.edgeCountry.setMark, {
      scope: 'edge',
      ref: w.own!,
      country: 'IR',
      state: 'blocked',
    });
    expect(await kinds()).toEqual([['audience_pool_down', { country: 'IR', inUse: 1 }]]);
  });

  test('keys of the country whose last body predates the cutover are counted, once an hour', async () => {
    const w = await world();
    await cutover(w, 'IR');
    const since = (await relayOf(w)).ownPools![0]!.since;
    const userId = await w.t.run(async (ctx) => {
      const tierId = await ctx.db.insert('tiers', {
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
        updatedAt: since,
      });
      return ctx.db.insert('users', { tierId, status: 'active', updatedAt: since });
    });
    const key = (country: string, at: number) =>
      w.t.run((ctx) =>
        ctx.db.insert('subscriptions', {
          userId,
          backend: 'remnawave',
          backendUserId: `u-${Math.random()}`,
          backendShortId: 'short',
          subscriptionUrl: 'https://panel.example/sub/x',
          subscriptionMirrors: [],
          backendServerId: w.serverId,
          pinnedNode: FIXTURE_NODE,
          state: 'active',
          lastRender: { at, epoch: 1, family: 'singbox', listenerKeys: ['u'], country },
          updatedAt: at,
        }),
      );
    await key('IR', since - 1);
    await key('IR', since - 2);
    await key('IR', since + 1);
    await key('RU', since - 1);
    expect(await w.t.action(internal.edgeOwnPools.countStale, { relayId: w.relayId })).toEqual({
      counts: [2],
    });
    const r = await relayOf(w);
    expect(r.ownPools![0]!.stale).toEqual({ at: expect.any(Number), keys: 2 });
    const items = (await w.t.query(internal.edgeOperator.attention, {})).items.filter(
      (i: { kind: string }) => i.kind === 'audience_stale_keys',
    );
    expect(items).toHaveLength(1);
  });
});

describe('the rollback', () => {
  test('every cutover, budget and count goes; the epoch moves; rotations forget theirs', async () => {
    vi.useFakeTimers();
    const w = await world();
    await cutover(w, 'IR');
    await w.t.mutation(internal.edgeOwnPools.setOwnBudget, { relayId: w.relayId, perDay: 3 });
    const spare = await freshSpare(w, '198.51.100.31', w.accountB, ['IR']);
    await w.t.mutation(internal.edgeRotations.start, {
      relayId: w.relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: w.own!,
      toEdgeId: spare,
    });
    // Refused while a replacement of its own is running.
    await expect(w.t.mutation(internal.edgeOwnPools.clearOwnPoolsForRollback, {})).rejects.toThrow(
      /let it finish/,
    );
    const rid = (await relayOf(w)).activeRotationId!;
    await w.t.run((c) => c.db.patch(rid, { phase: 'done' }));
    const before = (await relayOf(w)).publicationEpoch;
    await w.t.mutation(internal.edgeOwnPools.clearOwnPoolsForRollback, {});
    await w.t.finishAllScheduledFunctions(vi.runAllTimers);
    const r = await relayOf(w);
    expect(r.ownPools).toBeUndefined();
    expect(r.audienceReplaces).toBeUndefined();
    expect(r.audienceReplacesPerDay).toBeUndefined();
    expect(r.publicationEpoch).toBeGreaterThan(before);
    expect((await w.t.run(async (c) => (await c.db.get(rid))!)).ownPool).toBeUndefined();
  });
});
