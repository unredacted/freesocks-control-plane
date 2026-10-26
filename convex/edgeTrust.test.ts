/// <reference types="vite/client" />
/**
 * Suspicion, the Convex half (docs/edges.md "Address enumeration"): first
 * exposures on the delivery stamp, strikes on the first judgement of a
 * trusted address, the cutoff, the claim once per address, demotion into the
 * open lane and its mirror pass, retention, account deletion, and that no
 * account, mark or address reaches a log line or an audit row.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { adoptL4Edge, seedEdgeFixture, verifyL4Edge } from './lib/edges/testing/fixtures';
import { markOf } from './edgeTrust';

const modules = import.meta.glob('./**/*.*s');
const DAY = 86_400_000;
const T0 = Date.UTC(2026, 9, 1);

beforeEach(() => {
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.useFakeTimers({ now: T0 });
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.useRealTimers();
});

type T = TestConvex<typeof schema>;
const later = (ms: number) => vi.setSystemTime(Date.now() + ms);

/** A node with lanes on, suspicion recording, and `n` trusted addresses in use. */
async function seedNode(t: T, n: number, opts: { firstWave?: 'default' } = {}) {
  const f = await seedEdgeFixture(t);
  await t.run((ctx) => ctx.db.patch(f.relayId, { desiredPublished: 2 + n }));
  await adoptL4Edge(t, f.relayId, f.listenerId, { ipv4: '198.51.100.1', publish: true });
  await t.mutation(internal.edgeTrust.ensureSince, {});
  // The tests below hand addresses out right after they go into use; the first
  // wave has its own test, at the shipped default.
  if (opts.firstWave !== 'default')
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'edge.trust.firstWaveHours',
        value: '0',
        updatedAt: Date.now(),
      }),
    );
  later(1000);
  await t.mutation(internal.edgeLanes.setLanes, {
    relayId: f.relayId,
    lanes: { open: 1, trusted: n },
  });
  later(1000);
  const trusted: Id<'edges'>[] = [];
  for (let i = 0; i < n; i++) {
    const id = await t.run((ctx) =>
      ctx.db.insert('edges', {
        relayId: f.relayId,
        listenerId: f.listenerId,
        provider: 'gcore',
        managed: true,
        name: `t${i}`,
        steps: [],
        resources: [],
        listeners: [{ edgePort: 443, originAddress: '203.0.113.10', originPort: 443 }],
        addresses: { v4: `198.51.100.${40 + i}` },
        layer: 'l4',
        publication: 'unpublished',
        status: 'active',
        statusChangedAt: Date.now(),
        health: 'online',
        destroyAttempts: 0,
        updatedAt: Date.now(),
      }),
    );
    await verifyL4Edge(t, id);
    await t.mutation(internal.relays.publishEdge, { relayId: f.relayId, edgeId: id });
    trusted.push(id);
  }
  for (const id of trusted) expect((await t.run((c) => c.db.get(id)))!.lane).toBe('trusted');
  return { ...f, trusted };
}

async function seedUser(t: T, paid = false) {
  return t.run(async (ctx) => {
    const tierId = await ctx.db.insert('tiers', {
      slug: paid ? 'paid' : 'free',
      name: 'Tier',
      backend: 'remnawave',
      monthlyTrafficGb: 50,
      deviceLimit: 1,
      hwidLimit: 1,
      hwidEnabled: false,
      trafficStrategy: 'MONTH',
      isDefaultFree: !paid,
      isActive: true,
      priority: 0,
      expirationDaysAfterMembershipLapse: 0,
      updatedAt: Date.now(),
    });
    const userId = await ctx.db.insert('users', {
      tierId,
      status: 'active',
      updatedAt: Date.now(),
    });
    const subscriptionId = await ctx.db.insert('subscriptions', {
      userId,
      backend: 'remnawave',
      backendUserId: `bu-${userId}`,
      backendShortId: `s-${userId}`,
      subscriptionUrl: `https://sub.example/${userId}`,
      subscriptionMirrors: [],
      state: 'active',
      updatedAt: Date.now(),
    });
    return { userId, subscriptionId };
  });
}

/** The account's app fetched a body handing out these addresses (the /sub delivery stamp). */
const hand = (
  t: T,
  subscriptionId: Id<'subscriptions'>,
  primary: Id<'edges'>,
  backup?: Id<'edges'>,
) =>
  t.mutation(internal.subscriptions.markDelivered, {
    subscriptionId,
    contentAt: Date.now(),
    renderedEpoch: 1,
    render: {
      epoch: 1,
      family: 'other',
      listenerKeys: ['a'],
      primaryEdgeId: primary,
      ...(backup ? { backupEdgeId: backup } : {}),
    },
  });

const strikesOf = (t: T, userId: Id<'users'>) =>
  t.run(async (ctx) => {
    const row = await ctx.db
      .query('edgeTrust')
      .withIndex('by_mark', (q) => q.eq('mark', markOf(userId)!))
      .first();
    return row?.strikes.length ?? 0;
  });

const blocked = (t: T, edgeId: Id<'edges'>) =>
  t.mutation(internal.edgeTrust.noteBlocked, { edgeId, evidenceAt: Date.now() });

describe('who gets a strike', () => {
  test('a long-time holder never; a fresh one does; the claim is once per address', async () => {
    const t = convexTest(schema, modules);
    const { trusted } = await seedNode(t, 1);
    const x = trusted[0]!;
    const longTime = await seedUser(t);
    const fresh = await seedUser(t);
    await hand(t, longTime.subscriptionId, x);
    later(9 * DAY);
    // The daily sweep keeps a live trusted address's rows, so a long-time
    // holder's first exposure is still the old one.
    await t.mutation(internal.edgeTrust.sweep, {});
    await hand(t, fresh.subscriptionId, x);
    // A long-time holder's later fetches write nothing new.
    await hand(t, longTime.subscriptionId, x, trusted[0]);
    later(DAY);
    expect(await blocked(t, x)).toMatchObject({ claimed: true, fresh: 1, struck: 1 });
    expect(await strikesOf(t, longTime.userId)).toBe(0);
    expect(await strikesOf(t, fresh.userId)).toBe(1);
    // Repeated detector passes, a manual mark, a country round: claimed already.
    later(2 * DAY);
    expect((await blocked(t, x)).claimed).toBe(false);
    expect((await blocked(t, x)).claimed).toBe(false);
    expect(await strikesOf(t, fresh.userId)).toBe(1);
  });

  test("an address's first wave is never fresh; an account that moved onto it later is", async () => {
    const t = convexTest(schema, modules);
    const { trusted } = await seedNode(t, 1, { firstWave: 'default' });
    const x = trusted[0]!;
    const firstWave = await seedUser(t);
    const mover = await seedUser(t);
    later(60_000);
    await hand(t, firstWave.subscriptionId, x);
    later(2 * DAY);
    await hand(t, mover.subscriptionId, x);
    later(DAY);
    expect(await blocked(t, x)).toMatchObject({ claimed: true, fresh: 1, struck: 1 });
    expect(await strikesOf(t, firstWave.userId)).toBe(0);
    expect(await strikesOf(t, mover.userId)).toBe(1);
  });

  test('an account handed it after the block began is not fresh', async () => {
    const t = convexTest(schema, modules);
    const { trusted } = await seedNode(t, 1);
    const u = await seedUser(t);
    const evidenceAt = Date.now();
    later(60_000);
    await hand(t, u.subscriptionId, trusted[0]!);
    expect(
      await t.mutation(internal.edgeTrust.noteBlocked, { edgeId: trusted[0]!, evidenceAt }),
    ).toMatchObject({ claimed: true, fresh: 0, struck: 0 });
  });

  test('too many fresh holders: not attributable, nobody gets one', async () => {
    const t = convexTest(schema, modules);
    const { trusted } = await seedNode(t, 1);
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'edge.trust.maxFreshHolders',
        value: '2',
        updatedAt: Date.now(),
      }),
    );
    const users = [await seedUser(t), await seedUser(t), await seedUser(t)];
    for (const u of users) await hand(t, u.subscriptionId, trusted[0]!);
    later(DAY);
    expect(await blocked(t, trusted[0]!)).toMatchObject({ claimed: true, fresh: 3, struck: 0 });
    for (const u of users) expect(await strikesOf(t, u.userId)).toBe(0);
  });

  test('an open address and one published before recording began strike nobody', async () => {
    const t = convexTest(schema, modules);
    const f = await seedNode(t, 1);
    // The imported first address is open.
    const relay = (await t.query(internal.relays.get, { id: f.relayId }))!;
    const openId = relay.publishedEdgeIds.find((id) => id && !f.trusted.includes(id))!;
    const u = await seedUser(t);
    await hand(t, u.subscriptionId, openId as Id<'edges'>);
    later(DAY);
    expect((await blocked(t, openId as Id<'edges'>)).claimed).toBe(false);
    // Recording "began" after this trusted address went into use.
    await t.run(async (ctx) => {
      const row = await ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', 'edge:trustSince'))
        .first();
      await ctx.db.patch(row!._id, { value: JSON.stringify({ at: Date.now() }) });
    });
    await hand(t, u.subscriptionId, f.trusted[0]!);
    expect(await blocked(t, f.trusted[0]!)).toMatchObject({ claimed: true, fresh: 0, struck: 0 });
  });
});

describe('suspected accounts', () => {
  test('three strikes a day apart move even a paid account to the open lane, and every mirror is rendered again', async () => {
    const t = convexTest(schema, modules);
    const { trusted } = await seedNode(t, 3);
    const u = await seedUser(t, true);
    const lane = () => t.query(internal.edgeLanes.laneOf, { subscriptionId: u.subscriptionId });
    expect(await lane()).toBe('trusted');
    for (const x of trusted) {
      await hand(t, u.subscriptionId, x);
      later(DAY);
      await blocked(t, x);
    }
    expect(await strikesOf(t, u.userId)).toBe(3);
    expect(await lane()).toBe('open');
    const scheduled = await t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect());
    expect(scheduled.some((s) => s.name.includes('drainMirrors'))).toBe(true);
    // A body rendered for its old lane is neither kept nor stamped (the fence).
    await t.mutation(internal.subscriptions.markDelivered, {
      subscriptionId: u.subscriptionId,
      contentAt: Date.now(),
      renderedEpoch: 2,
      render: { epoch: 2, family: 'other', listenerKeys: ['a'], primaryEdgeId: trusted[0]! },
      lane: 'trusted',
    });
    expect((await t.run((c) => c.db.get(u.subscriptionId)))!.lastRender?.epoch).not.toBe(2);
    const summary = await t.query(internal.edgeTrust.summary, {});
    expect(summary).toMatchObject({ suspected: 1, withStrikes: 1, demotionsToday: 1 });
    // Strikes stop counting after 30 days, and the sweep removes the row.
    later(31 * DAY);
    expect(await lane()).toBe('trusted');
    await t.mutation(internal.edgeTrust.sweep, {});
    expect(await t.run((c) => c.db.query('edgeTrust').collect())).toEqual([]);
  });
});

describe('retention and deletion', () => {
  test('first exposures go with their address; an account deleted takes its rows', async () => {
    const t = convexTest(schema, modules);
    const { trusted } = await seedNode(t, 2);
    const a = await seedUser(t);
    await hand(t, a.subscriptionId, trusted[0]!, trusted[1]!);
    expect(await t.run((c) => c.db.query('edgeExposures').collect())).toHaveLength(2);
    await t.run((ctx) => ctx.db.patch(trusted[0]!, { status: 'destroyed' }));
    await t.mutation(internal.edgeTrust.sweep, {});
    expect(
      (await t.run((c) => c.db.query('edgeExposures').collect())).map((r) => r.edgeId),
    ).toEqual([trusted[1]]);
    later(DAY);
    await blocked(t, trusted[1]!);
    expect(await strikesOf(t, a.userId)).toBe(1);
    await t.mutation(internal.freeTier.deleteFreeUser, { userId: a.userId });
    expect(await t.run((c) => c.db.query('edgeExposures').collect())).toEqual([]);
    expect(await t.run((c) => c.db.query('edgeTrust').collect())).toEqual([]);
  });
});

describe('privacy', () => {
  test('no account, mark or address reaches a log line or an audit row', async () => {
    const t = convexTest(schema, modules);
    const lines: string[] = [];
    for (const m of ['log', 'info', 'warn', 'error', 'debug'] as const)
      vi.spyOn(console, m).mockImplementation((...args: unknown[]) => {
        lines.push(args.map(String).join(' '));
      });
    const { trusted } = await seedNode(t, 3);
    const u = await seedUser(t, true);
    for (const x of trusted) {
      await hand(t, u.subscriptionId, x);
      later(DAY);
      await blocked(t, x);
    }
    expect(await strikesOf(t, u.userId)).toBe(3);
    const mark = markOf(u.userId)!;
    const audit = JSON.stringify(await t.run((c) => c.db.query('auditLog').collect()));
    for (const secret of [mark, u.userId as string, u.subscriptionId as string]) {
      expect(audit).not.toContain(secret);
      for (const l of lines) expect(l).not.toContain(secret);
    }
    expect(audit).not.toMatch(/edgeTrust|edgeExposures|strike/i);
    vi.restoreAllMocks();
  });
});

describe('rolling back', () => {
  test('clearForRollback leaves no exposure, strike, claim or state key', async () => {
    const t = convexTest(schema, modules);
    const { trusted } = await seedNode(t, 1);
    const u = await seedUser(t);
    await hand(t, u.subscriptionId, trusted[0]!);
    later(DAY);
    await blocked(t, trusted[0]!);
    expect(await strikesOf(t, u.userId)).toBe(1);
    await t.mutation(internal.edgeTrust.clearForRollback, {});
    await t.finishAllScheduledFunctions(vi.runAllTimers);
    expect(await t.run((c) => c.db.query('edgeExposures').collect())).toEqual([]);
    expect(await t.run((c) => c.db.query('edgeTrust').collect())).toEqual([]);
    expect((await t.run((c) => c.db.get(trusted[0]!)))!.blockClaim).toBeUndefined();
    const keys = (await t.run((c) => c.db.query('appState').collect())).map((r) => r.key);
    expect(keys).not.toContain('edge:trustSince');
    expect(keys).not.toContain('edge:trustDaily');
  });
});
