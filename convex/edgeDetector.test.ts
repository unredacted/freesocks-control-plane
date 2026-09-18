/// <reference types="vite/client" />
/**
 * Relay attribution on member reports (through the real route) and the block
 * detector's evaluation → suspicion → gated automatic rotation.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { signValue } from './lib/cookies';
import { upsertSettingRow } from './appSettings';
import { resolveEdgeAttribution } from './edgeAttribution';
import { publishedEdgesOf } from './edgeRender';
import { assignEndpoints } from './lib/edges/assignment';
import {
  adoptL4Edge,
  FIXTURE_CONFIG_PROFILE,
  insertPanelServer,
  realityListener,
  registerRelay,
} from './lib/edges/testing/fixtures';

const modules = import.meta.glob('./**/*.*s');
const SIGN_KEY = 'test-sign';

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', SIGN_KEY);
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('EDGE_MARK_PEPPER', 'test-mark-pepper');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.useRealTimers();
});

const ORIGIN = '203.0.113.10';
const EDGE_A = '198.51.100.1';
const EDGE_B = '198.51.100.2';

/** The REALITY listener `u`, scoped to the UpCloud network (the old "profile U"). */
const listenerU = () =>
  realityListener({
    listenerKey: 'u',
    tlsNames: ['a.example'],
    providerScope: { provider: 'upcloud' },
    panelBinding: {
      inboundTag: 'VLESS_RELAY_U',
      configProfileUuid: FIXTURE_CONFIG_PROFILE,
      configProfileInboundUuid: '22222222-2222-4222-8222-222222222222',
    },
  });

async function seed() {
  const t = convexTest(schema, modules);
  const tierId = await t.run((ctx) =>
    ctx.db.insert('tiers', {
      slug: 'free',
      name: 'Free',
      backend: 'remnawave',
      monthlyTrafficGb: 50,
      deviceLimit: 1,
      hwidLimit: 1,
      hwidEnabled: false,
      trafficStrategy: 'MONTH',
      isDefaultFree: true,
      isActive: true,
      priority: 0,
      expirationDaysAfterMembershipLapse: 0,
      updatedAt: Date.now(),
    }),
  );
  const serverId = await insertPanelServer(t);
  await t.run((ctx) => upsertSettingRow(ctx, 'edge.render.enabled', 'true'));
  const { relayId, listenerId } = await registerRelay(t, { listeners: [listenerU()] });
  const a = await adoptL4Edge(t, relayId, listenerId, { ipv4: EDGE_A, publish: true });
  const b = await adoptL4Edge(t, relayId, listenerId, { ipv4: EDGE_B, publish: true });
  return {
    t,
    tierId,
    serverId,
    relayId,
    listenerId,
    edgeA: a.edgeId as Id<'edges'>,
    edgeB: b.edgeId as Id<'edges'>,
  };
}

/** A member with an active key pinned to node-one, plus a signed session cookie. */
async function member(
  t: ReturnType<typeof convexTest>,
  tierId: Id<'tiers'>,
  serverId: Id<'backendServers'>,
  n: number,
) {
  const { userId, subId } = await t.run(async (ctx) => {
    const userId = await ctx.db.insert('users', {
      tierId,
      status: 'active',
      supportId: `SUP-${n}`,
      updatedAt: Date.now(),
    });
    const subId = await ctx.db.insert('subscriptions', {
      userId,
      backend: 'remnawave',
      backendUserId: `uuid-${n}`,
      backendShortId: `short-${n}`,
      backendServerId: serverId,
      subscriptionUrl: `https://panel.example/sub/short-${n}`,
      subscriptionMirrors: [],
      subToken: `tok_${n}`,
      state: 'active',
      pinnedNode: 'node-one',
      renderKey: `${n}`.padStart(64, 'a'),
      updatedAt: Date.now(),
    });
    await ctx.db.patch(userId, { currentSubscriptionId: subId });
    return { userId, subId };
  });
  const sid = `sid-${n}-${Math.random().toString(36).slice(2)}`;
  await t.mutation(internal.sessions.create, { sid, kind: 'member', userId, ttlMs: 3_600_000 });
  const cookie = `fs_session=${await signValue(sid, SIGN_KEY)}`;
  return { userId, subId, cookie };
}

async function report(
  t: ReturnType<typeof convexTest>,
  cookie: string,
  body: Record<string, unknown>,
) {
  return t.fetch('/api/v1/account/report-issue', {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/json', 'x-forwarded-for': '192.0.2.1' },
    body: JSON.stringify(body),
  });
}

/** Record what the renderer handed this subscriber (attribution reads ONLY this snapshot). */
async function handed(
  t: ReturnType<typeof convexTest>,
  subId: Id<'subscriptions'>,
  relayId: Id<'relays'>,
  primaryEdgeId: Id<'edges'>,
  backupEdgeId?: Id<'edges'>,
) {
  await t.run(async (ctx) => {
    const epoch = (await ctx.db.get(relayId))!.publicationEpoch;
    await ctx.db.patch(subId, {
      lastRenderedEpoch: epoch,
      lastRender: {
        at: Date.now(),
        epoch,
        family: 'mihomo',
        listenerKeys: ['a'],
        primaryEdgeId,
        backupEdgeId,
      },
    });
  });
}

describe('relay attribution on member reports', () => {
  test('a report carries the origin slug; the edge only for an explicit choice; the first report per window weighs 1', async () => {
    const s = await seed();
    const m = await member(s.t, s.tierId, s.serverId, 1);
    await handed(s.t, m.subId, s.relayId, s.edgeA, s.edgeB);
    const r1 = await report(s.t, m.cookie, { reason: 'cant-connect', connection: 'primary' });
    expect(r1.status).toBe(200);
    const r2 = await report(s.t, m.cookie, { reason: 'cant-connect', connection: 'unsure' });
    expect(r2.status).toBe(200);
    const rows = await s.t.run((ctx) => ctx.db.query('issueReports').collect());
    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({
      relaySlug: 'node-one',
      connectionChoice: 'primary',
      detectorWeight: 1,
      refreshNotObserved: false,
    });
    expect(rows[0].relayEdgeId).toBe(s.edgeA);
    // Second report by the same member inside the window: no edge (unsure), weight 0.
    expect(rows[1]).toMatchObject({
      relaySlug: 'node-one',
      connectionChoice: 'unsure',
      detectorWeight: 0,
    });
    expect(rows[1].relayEdgeId).toBeUndefined();
    // The mark row never carries the member id.
    const marks = await s.t.run((ctx) => ctx.db.query('relayReportMarks').collect());
    expect(marks).toHaveLength(1);
    expect(marks[0].key).not.toContain(m.userId);
    expect(marks[0].key).toMatch(/^[0-9a-f]{64}$/);
    // Primary vs backup resolve to DIFFERENT edges for the same member.
    const m2 = await member(s.t, s.tierId, s.serverId, 2);
    await handed(s.t, m2.subId, s.relayId, s.edgeB, s.edgeA);
    await report(s.t, m2.cookie, { reason: 'cant-connect', connection: 'primary' });
    await report(s.t, m2.cookie, { reason: 'cant-connect', connection: 'backup' });
    const rows2 = (await s.t.run((ctx) => ctx.db.query('issueReports').collect())).slice(2);
    expect(rows2[0].relayEdgeId).toBeDefined();
    expect(rows2[1].relayEdgeId).toBeDefined();
    expect(rows2[0].relayEdgeId).not.toBe(rows2[1].relayEdgeId);
    // The audit trail stays reason-only.
    const audit = await s.t.run((ctx) => ctx.db.query('auditLog').collect());
    const issue = audit.filter((a) => a.action === 'subscription.issue_reported');
    expect(issue).toHaveLength(4);
    expect(JSON.stringify(issue)).not.toContain('node-one');
  });

  test('a member never rendered gets NO edge attribution: nothing is recomputed from the pool', async () => {
    const s = await seed();
    const m = await member(s.t, s.tierId, s.serverId, 40);
    await report(s.t, m.cookie, { reason: 'cant-connect', connection: 'primary' });
    const row = (await s.t.run((ctx) => ctx.db.query('issueReports').collect()))[0];
    expect(row).toMatchObject({ relaySlug: 'node-one', connectionChoice: 'primary' });
    expect(row.relayEdgeId).toBeUndefined();
  });

  test('refreshNotObserved when the key has not fetched content since the origin last rotated', async () => {
    const s = await seed();
    await s.t.run((ctx) => ctx.db.patch(s.relayId, { lastRotatedAt: Date.now() }));
    const m = await member(s.t, s.tierId, s.serverId, 3);
    await report(s.t, m.cookie, { reason: 'cant-connect' });
    const row = (await s.t.run((ctx) => ctx.db.query('issueReports').collect()))[0];
    expect(row.refreshNotObserved).toBe(true);
    expect(row.relayEdgeId).toBeUndefined();
    expect(row.connectionChoice).toBeUndefined();
  });

  test('refreshNotObserved prefers the rendered publication epoch (any pool change), falling back to the rotation timestamp', async () => {
    const s = await seed();
    const m = await member(s.t, s.tierId, s.serverId, 30);
    const now = Date.now();
    await s.t.run(async (ctx) => {
      const origin = (await ctx.db.get(s.relayId))!;
      // A non-rotation pool change bumped the epoch; no rotation ever happened.
      await ctx.db.patch(s.relayId, { publicationEpoch: origin.publicationEpoch + 1 });
      const sub = (await ctx.db.get(m.subId))!;
      const epoch = (await ctx.db.get(s.relayId))!.publicationEpoch;
      const withEpoch = (lastRenderedEpoch: number) =>
        ({
          ...sub,
          lastRenderedEpoch,
          lastRender: {
            at: now,
            epoch: lastRenderedEpoch,
            family: 'mihomo',
            listenerKeys: ['a'],
            primaryEdgeId: s.edgeA,
          },
        }) as typeof sub;
      // Rendered against an older epoch → still on the old pool → no edge attribution.
      const behind = await resolveEdgeAttribution(ctx.db, withEpoch(epoch - 1), 'primary', now);
      expect(behind).toMatchObject({ relaySlug: 'node-one', refreshNotObserved: true });
      expect(behind!.relayEdgeId).toBeNull();
      // Rendered against the current epoch → attributable, even though
      // lastDeliveredContentAt is unset.
      const current = await resolveEdgeAttribution(ctx.db, withEpoch(epoch), 'primary', now);
      expect(current!.refreshNotObserved).toBe(false);
      expect(current!.relayEdgeId).not.toBeNull();
      // No epoch on the sub (never rendered since the field exists): the old
      // comparison against lastRotatedAt decides.
      const legacy = await resolveEdgeAttribution(ctx.db, sub, 'primary', now);
      expect(legacy!.refreshNotObserved).toBe(false);
      await ctx.db.patch(s.relayId, { lastRotatedAt: now });
      const legacyRotated = await resolveEdgeAttribution(ctx.db, sub, 'primary', now);
      expect(legacyRotated!.refreshNotObserved).toBe(true);
      // An epoch-bearing sub ignores lastRotatedAt entirely.
      const epochWins = await resolveEdgeAttribution(ctx.db, withEpoch(epoch), 'primary', now);
      expect(epochWins!.refreshNotObserved).toBe(false);
    });
  });

  test('the dedupe mark is a sliding window from the first report: two reports 1s apart across an aligned bucket edge weigh 1 then 0', async () => {
    const windowMs = 30 * 60_000; // detect.windowMinutes default
    // One second before a clock-aligned boundary of the old bucket scheme.
    const boundary = Math.ceil(1_800_000_000_000 / windowMs) * windowMs;
    vi.useFakeTimers({ now: boundary - 1000 });
    const s = await seed();
    const m = await member(s.t, s.tierId, s.serverId, 40);
    expect((await report(s.t, m.cookie, { reason: 'cant-connect' })).status).toBe(200);
    vi.setSystemTime(boundary + 1000);
    expect((await report(s.t, m.cookie, { reason: 'cant-connect' })).status).toBe(200);
    const rows = await s.t.run((ctx) => ctx.db.query('issueReports').collect());
    expect(rows.map((r) => r.detectorWeight)).toEqual([1, 0]);
    const marks = await s.t.run((ctx) => ctx.db.query('relayReportMarks').collect());
    expect(marks).toHaveLength(1);
    expect(marks[0].expiresAt).toBe(boundary - 1000 + windowMs);
    // Once the member's own window has elapsed, a new report counts again.
    vi.setSystemTime(boundary - 1000 + windowMs + 1);
    expect((await report(s.t, m.cookie, { reason: 'cant-connect' })).status).toBe(200);
    const rows2 = await s.t.run((ctx) => ctx.db.query('issueReports').collect());
    expect(rows2.map((r) => r.detectorWeight)).toEqual([1, 0, 1]);
  });

  test('no mark pepper configured → fail CLOSED: the report is stored with weight 0 and no edge attribution', async () => {
    vi.stubEnv('EDGE_MARK_PEPPER', '');
    vi.stubEnv('IP_HASH_SALT', '');
    const s = await seed();
    const m = await member(s.t, s.tierId, s.serverId, 50);
    const r = await report(s.t, m.cookie, { reason: 'cant-connect', connection: 'primary' });
    expect(r.status).toBe(200);
    const rows = await s.t.run((ctx) => ctx.db.query('issueReports').collect());
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ relaySlug: 'node-one', detectorWeight: 0 });
    expect(rows[0].relayEdgeId).toBeUndefined();
    expect(await s.t.run((ctx) => ctx.db.query('relayReportMarks').collect())).toEqual([]);
    // The detector sees no reporter from it.
    const w = (await s.t.query(internal.edgeDetector.relayWindow, {
      relayId: s.relayId,
      now: Date.now(),
    }))!;
    expect(w.window.reports).toBe(1);
    expect(w.window.distinctReporters).toBe(0);
  });
});

describe('relay block detector', () => {
  const NOW = 1_800_000_000_000;

  test('edge evidence counts deduplicated reporters: repeats by one member (weight 0) add nothing', async () => {
    vi.useFakeTimers({ now: NOW });
    const s = await seed();
    await s.t.run(async (ctx) => {
      for (let i = 0; i < 5; i++) {
        await ctx.db.insert('issueReports', {
          kind: 'report',
          reason: 'cant-connect',
          backend: 'remnawave',
          relaySlug: 'node-one',
          relayEdgeId: s.edgeA,
          connectionChoice: 'primary',
          country: 'IR',
          detectorWeight: i === 0 ? 1 : 0,
        });
      }
    });
    const w = (await s.t.query(internal.edgeDetector.relayWindow, {
      relayId: s.relayId,
      now: NOW,
    }))!;
    expect(w.window.reports).toBe(5);
    expect(w.window.distinctReporters).toBe(1);
    expect(w.window.byEdge[s.edgeA]).toEqual({ count: 1, countries: { IR: 1 } });
  });

  /**
   * Report rows on the origin: `zeroWeight` deduplicated repeats and `weighted`
   * distinct reporters. `weightedFirst` puts the real reporters at the head of
   * the index instead of behind the repeats.
   */
  async function bulkReports(
    t: ReturnType<typeof convexTest>,
    opts: {
      zeroWeight: number;
      weighted: number;
      edgeId?: Id<'edges'>;
      weightedFirst?: boolean;
      relaySlug?: string;
    },
  ) {
    const insert = (
      ctx: { db: { insert: (table: 'issueReports', doc: object) => unknown } },
      weight: 0 | 1,
    ) =>
      ctx.db.insert('issueReports', {
        kind: 'report',
        reason: 'cant-connect',
        backend: 'remnawave',
        relaySlug: opts.relaySlug ?? 'node-one',
        country: 'IR',
        detectorWeight: weight,
        ...(weight === 1 && opts.edgeId
          ? { connectionChoice: 'primary' as const, relayEdgeId: opts.edgeId }
          : {}),
      });
    await t.run(async (ctx) => {
      const rounds: Array<0 | 1> = opts.weightedFirst ? [1, 0] : [0, 1];
      for (const weight of rounds) {
        const n = weight === 1 ? opts.weighted : opts.zeroWeight;
        for (let i = 0; i < n; i++) await insert(ctx, weight);
      }
    });
  }

  test('the window is paginated, not collected: zero-weight duplicates ahead of the real reporters never hide them', async () => {
    vi.useFakeTimers({ now: NOW });
    const s = await seed();
    // 300 deduplicated repeats are written FIRST, so any `.take(N)` with N ≤ 300
    // would read nothing but zero-weight rows and see no reporter at all.
    await bulkReports(s.t, { zeroWeight: 300, weighted: 8 });
    const w = (await s.t.query(internal.edgeDetector.relayWindow, {
      relayId: s.relayId,
      now: NOW,
    }))!;
    expect(w.window.reports).toBe(308);
    expect(w.window.distinctReporters).toBe(8);
    expect(w.window.incomplete ?? false).toBe(false);
  });

  test('a window past detect.maxReportRowsPerEval is INCOMPLETE: suspicion still shows, but the veto is evidence_incomplete and nothing rotates', async () => {
    vi.useFakeTimers({ now: NOW });
    const s = await seed();
    await warmBaseline(s.t, s.relayId, 100);
    await nodeLoad(s.t, s.serverId, 0);
    await s.t.run(async (ctx) => {
      await upsertSettingRow(ctx, 'edge.enabled', 'true');
      await upsertSettingRow(ctx, 'edge.autoRotate', 'true');
      // A cap below the row count (100 is the configurable floor): the same
      // evidence that rotates under the cap must not rotate over it.
      await upsertSettingRow(ctx, 'edge.detect.maxReportRowsPerEval', '100');
      await ctx.db.patch(s.relayId, { autoRotate: true });
    });
    // Enough edge-attributed reporters to rotate, behind enough duplicates to
    // push the window over the cap.
    await bulkReports(s.t, {
      zeroWeight: 200,
      weighted: 8,
      edgeId: s.edgeA,
      weightedFirst: true,
    });
    const capped = (await s.t.query(internal.edgeDetector.relayWindow, {
      relayId: s.relayId,
      now: NOW,
    }))!;
    expect(capped.window.incomplete).toBe(true);
    expect(capped.window.reports).toBe(100);
    const r = await s.t.action(internal.edgeDetector.run, {});
    expect(r.rotated).toBe(0);
    const o = (await s.t.query(internal.relays.get, { id: s.relayId }))!;
    expect(o.suspicion!.veto).toBe('evidence_incomplete');
    expect(o.activeRotationId).toBeUndefined();
    // A truncated window never teaches the baseline either.
    const samples = await s.t.run((ctx) => ctx.db.query('relaySamples').collect());
    expect(samples.some((x) => x.at === NOW)).toBe(false);
    // Raise the cap over the row count and the very same rows rotate.
    await s.t.run((ctx) => upsertSettingRow(ctx, 'edge.detect.maxReportRowsPerEval', '2000'));
    const whole = (await s.t.query(internal.edgeDetector.relayWindow, {
      relayId: s.relayId,
      now: NOW,
    }))!;
    expect(whole.window.incomplete ?? false).toBe(false);
    expect(whole.window.reports).toBe(208);
    expect(whole.window.distinctReporters).toBe(8);
    expect((await s.t.action(internal.edgeDetector.run, {})).rotated).toBe(1);
  });

  test('a baseline sample is written ONCE from the window, and never while the node stats are stale', async () => {
    vi.useFakeTimers({ now: NOW });
    const s = await seed();
    await warmBaseline(s.t, s.relayId, 100);
    // Stats older than the staleness ceiling: no live user count to compare
    // against, so the sample would poison the baseline it feeds.
    await s.t.run((ctx) =>
      ctx.db.insert('backendNodeInventory', {
        backendServerId: s.serverId,
        nodeUuid: 'n1',
        name: 'node-one',
        usersOnline: 100,
        online: true,
        lastStatsAt: NOW - 60 * 60_000,
      }),
    );
    await bulkReports(s.t, { zeroWeight: 3, weighted: 2 });
    await s.t.action(internal.edgeDetector.run, {});
    expect(
      (await s.t.run((ctx) => ctx.db.query('relaySamples').collect())).some((x) => x.at === NOW),
    ).toBe(false);
    // Fresh stats: one sample, carrying the WINDOW's own counts (rows and
    // deduplicated reporters), written by a single mutation.
    await s.t.run(async (ctx) => {
      for (const inv of await ctx.db.query('backendNodeInventory').collect())
        await ctx.db.patch(inv._id, { lastStatsAt: NOW - 60_000 });
    });
    const later = NOW + 60_000;
    vi.setSystemTime(later);
    await s.t.action(internal.edgeDetector.run, {});
    const written = (await s.t.run((ctx) => ctx.db.query('relaySamples').collect())).filter(
      (x) => x.at === later,
    );
    expect(written).toHaveLength(1);
    expect(written[0]).toMatchObject({ reports: 5, distinctReporters: 2, usersOnline: 100 });
  });

  async function warmBaseline(
    t: ReturnType<typeof convexTest>,
    relayId: Id<'relays'>,
    usersOnline: number,
  ) {
    // A week of samples every two hours: warm (≥72) and with the same clock
    // hour on every previous day for the time-of-day baseline.
    await t.run(async (ctx) => {
      for (let i = 1; i <= 84; i++) {
        await ctx.db.insert('relaySamples', {
          relayId,
          at: NOW - i * 2 * 60 * 60_000,
          reports: 0,
          distinctReporters: 0,
          usersOnline,
        });
      }
    });
  }

  /** The edge has been reachable from these countries before (the transition marker). */
  async function reachableHistory(
    t: ReturnType<typeof convexTest>,
    edgeId: Id<'edges'>,
    countries: string[],
  ) {
    await t.run(async (ctx) => {
      for (const country of countries) {
        await ctx.db.insert('probeReachability', {
          targetKind: 'edge',
          targetRef: edgeId,
          country,
          source: 'globalping',
          ipVersion: 4,
          okCount: 0,
          failCount: 4,
          lastReachableAt: NOW - 3 * 60 * 60_000,
          failNetworks: ['AS1', 'AS2'],
          verdict: 'unreachable',
          updatedAt: NOW - 60_000,
        });
      }
    });
  }

  async function nodeLoad(
    t: ReturnType<typeof convexTest>,
    serverId: Id<'backendServers'>,
    usersOnline: number,
    online = true,
  ) {
    await t.run((ctx) =>
      ctx.db.insert('backendNodeInventory', {
        backendServerId: serverId,
        nodeUuid: 'n1',
        name: 'node-one',
        usersOnline,
        online,
        lastStatsAt: NOW - 60_000,
      }),
    );
  }

  /** Six edge-attributed IR reporters against `edgeId` (enough to rotate on their own). */
  async function edgeReports(t: ReturnType<typeof convexTest>, edgeId: Id<'edges'>, n = 6) {
    await t.run(async (ctx) => {
      for (let i = 0; i < n; i++) {
        await ctx.db.insert('issueReports', {
          kind: 'report',
          reason: 'cant-connect',
          backend: 'remnawave',
          relaySlug: 'node-one',
          country: 'IR',
          detectorWeight: 1,
          connectionChoice: 'primary',
          relayEdgeId: edgeId,
        });
      }
    });
  }

  test('an OFFLINE node is an outage: suspected, but the veto is node_offline and no sample joins the baseline', async () => {
    vi.useFakeTimers({ now: NOW });
    const s = await seed();
    await warmBaseline(s.t, s.relayId, 100);
    await nodeLoad(s.t, s.serverId, 0, false);
    await s.t.run(async (ctx) => {
      await upsertSettingRow(ctx, 'edge.enabled', 'true');
      await upsertSettingRow(ctx, 'edge.autoRotate', 'true');
      await ctx.db.patch(s.relayId, { autoRotate: true });
    });
    await edgeReports(s.t, s.edgeA);
    const r = await s.t.action(internal.edgeDetector.run, {});
    expect(r).toMatchObject({ suspected: 1, rotated: 0 });
    const o = (await s.t.query(internal.relays.get, { id: s.relayId }))!;
    expect(o.suspicion).toMatchObject({ state: 'suspected', veto: 'node_offline' });
    expect(o.suspicion!.hint).toMatch(/Node offline/);
    expect(o.activeRotationId).toBeUndefined();
    const samples = await s.t.run((ctx) => ctx.db.query('relaySamples').collect());
    expect(samples.some((x) => x.at === NOW)).toBe(false);
  });

  test('quiet origin: evaluated, clear, a sample recorded', async () => {
    vi.useFakeTimers({ now: NOW });
    const s = await seed();
    await warmBaseline(s.t, s.relayId, 100);
    await nodeLoad(s.t, s.serverId, 100);
    const r = await s.t.action(internal.edgeDetector.run, {});
    expect(r).toMatchObject({ evaluated: 1, suspected: 0, rotated: 0 });
    const o = (await s.t.query(internal.relays.get, { id: s.relayId }))!;
    // The global switch is the first gate, so it names the veto while off.
    expect(o.suspicion).toMatchObject({
      state: 'clear',
      hintLevel: 'none',
      baselineWarm: true,
      veto: 'edge_disabled',
    });
    const samples = await s.t.run((ctx) => ctx.db.query('relaySamples').collect());
    expect(samples.some((x) => x.at === NOW)).toBe(true);
  });

  test('reports-only suspicion asks the probes for evidence with CUMULATIVE stagger offsets: no two runs of one external source share a slot', async () => {
    vi.useFakeTimers({ now: NOW });
    const s = await seed();
    await warmBaseline(s.t, s.relayId, 100);
    await nodeLoad(s.t, s.serverId, 10);
    await s.t.run(async (ctx) => {
      await upsertSettingRow(ctx, 'edge.enabled', 'true');
      await upsertSettingRow(ctx, 'edge.probe.enabled', 'true');
      await upsertSettingRow(ctx, 'edge.probe.sourceSpacingMs', '1500');
    });
    await bulkReports(s.t, { zeroWeight: 0, weighted: 10 });
    const r = await s.t.action(internal.edgeDetector.run, {});
    expect(r.suspected).toBe(1);
    expect(r.probesRequested).toBeGreaterThan(0);
    const runs = await s.t.run((ctx) => ctx.db.query('probeRuns').collect());
    expect(runs.length).toBe(r.probesRequested);
    // Both published edges were asked; per external source every run has its
    // own slot (offsets accumulate across targets instead of restarting at 0).
    expect(new Set(runs.map((x) => x.targetRef)).size).toBe(2);
    const external = [...new Set(runs.map((x) => x.source))].filter((src) => src !== 'internal');
    expect(external.length).toBeGreaterThan(0);
    for (const src of external) {
      const at = runs.filter((x) => x.source === src).map((x) => x.scheduledAt ?? x.requestedAt);
      expect(new Set(at).size).toBe(at.length);
      const sorted = [...at].sort((a, b) => a - b);
      for (let i = 1; i < sorted.length; i++) expect(sorted[i]! - sorted[i - 1]!).toBe(1500);
    }
  });

  test('reports + load drop suspect the origin (hint), but without edge evidence nothing rotates', async () => {
    vi.useFakeTimers({ now: NOW });
    const s = await seed();
    await warmBaseline(s.t, s.relayId, 100);
    await nodeLoad(s.t, s.serverId, 10);
    await s.t.run(async (ctx) => {
      await upsertSettingRow(ctx, 'edge.enabled', 'true');
      await upsertSettingRow(ctx, 'edge.autoRotate', 'true');
      await ctx.db.patch(s.relayId, { autoRotate: true });
    });
    await bulkReports(s.t, { zeroWeight: 0, weighted: 10 });
    const r = await s.t.action(internal.edgeDetector.run, {});
    expect(r).toMatchObject({ evaluated: 1, suspected: 1, rotated: 0 });
    const o = (await s.t.query(internal.relays.get, { id: s.relayId }))!;
    expect(o.suspicion).toMatchObject({
      state: 'suspected',
      hintLevel: 'reports',
      scope: 'regional',
      veto: 'no_edge_evidence',
    });
    expect(o.suspicion!.loadScore).toBeGreaterThan(0);
    expect(o.suspicion!.countries[0]).toEqual({ code: 'IR', count: 10 });
    expect(o.suspicion!.hint).toMatch(/Possible block \(mostly IR\)/);
    expect(o.activeRotationId).toBeUndefined();
    const audit = await s.t.run((ctx) => ctx.db.query('auditLog').collect());
    const sus = audit.find((a) => a.action === 'edge.block_suspected');
    expect(sus?.payload).toMatchObject({
      relaySlug: 'node-one',
      hintLevel: 'reports',
      topCountry: 'IR',
      autoRotate: true,
    });
  });

  test('a backend-server origin has NO load / online signal: the window carries none and the load score is 0', async () => {
    vi.useFakeTimers({ now: NOW });
    const t = convexTest(schema, modules);
    const serverB = await insertPanelServer(t, { slug: 'panel-b' });
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.render.enabled', 'true'));
    // A whole-server origin: the listener has no panel binding, so the fixture
    // strips it and the relay derives hostMode `none`.
    const { relayId, listenerId } = await registerRelay(t, {
      slug: 'server-b',
      kind: 'backend-server',
      backendSlug: 'panel-b',
      originAddress: '203.0.113.20',
      listeners: [listenerU()],
    });
    expect((await t.query(internal.relays.get, { id: relayId }))!.hostMode).toBe('none');
    await adoptL4Edge(t, relayId, listenerId, { ipv4: EDGE_A, publish: true });
    await warmBaseline(t, relayId, 100);
    // Node inventory rows exist on the server, yet a server-wide origin is not
    // one node: none of them is ITS load.
    await t.run((ctx) =>
      ctx.db.insert('backendNodeInventory', {
        backendServerId: serverB,
        nodeUuid: 'n1',
        name: 'some-node',
        usersOnline: 0,
        online: false,
        lastStatsAt: NOW - 60_000,
      }),
    );
    const w = (await t.query(internal.edgeDetector.relayWindow, { relayId, now: NOW }))!;
    expect(w.usersOnline).toBeNull();
    expect(w.nodeOnline).toBeNull();
    expect(w.loadStale).toBe(true);
    await t.run(async (ctx) => {
      await upsertSettingRow(ctx, 'edge.enabled', 'true');
      await upsertSettingRow(ctx, 'edge.autoRotate', 'true');
      await ctx.db.patch(relayId, { autoRotate: true });
    });
    await bulkReports(t, { zeroWeight: 0, weighted: 10, relaySlug: 'server-b' });
    // Default `detect.requireLoadCorroboration`: reports alone cannot be
    // corroborated by a load signal that does not exist, so the origin stays
    // CLEAR (score capped at half) with the reports visible in the score parts.
    const r = await t.action(internal.edgeDetector.run, {});
    expect(r).toMatchObject({ evaluated: 1, suspected: 0, rotated: 0 });
    let o = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(o.suspicion).toMatchObject({ state: 'clear', loadScore: 0 });
    expect(o.suspicion!.reportScore).toBeGreaterThan(0);
    // The offline bit of an unrelated node is never this origin's veto.
    expect(o.suspicion!.veto).not.toBe('node_offline');
    // Nor does an absent load signal ever produce a baseline sample.
    const samples = await t.run((ctx) => ctx.db.query('relaySamples').collect());
    expect(samples.some((x) => x.at === NOW)).toBe(false);
    // Without the corroboration requirement, the same reports suspect it.
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.detect.requireLoadCorroboration', 'false'));
    const r2 = await t.action(internal.edgeDetector.run, {});
    expect(r2).toMatchObject({ evaluated: 1, suspected: 1, rotated: 0 });
    o = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(o.suspicion).toMatchObject({ state: 'suspected', hintLevel: 'reports', loadScore: 0 });
    expect(o.suspicion!.hint).not.toMatch(/Node offline/);
  });

  test('edge evidence from probes + every gate open → a detector burn rotation of that edge; gates closed → veto recorded', async () => {
    vi.useFakeTimers({ now: NOW });
    const s = await seed();
    await warmBaseline(s.t, s.relayId, 100);
    await nodeLoad(s.t, s.serverId, 5);
    const unreachable = (edgeId: Id<'edges'>) =>
      s.t.run((ctx) =>
        ctx.db.patch(edgeId, {
          reachability: {
            byCountry: [
              {
                country: 'IR',
                verdict: 'unreachable',
                okVantages: 0,
                failVantages: 4,
                lastAt: NOW - 60_000,
              },
              {
                country: 'RU',
                verdict: 'unreachable',
                okVantages: 0,
                failVantages: 4,
                lastAt: NOW - 60_000,
              },
              {
                country: 'XX',
                verdict: 'reachable',
                okVantages: 1,
                failVantages: 0,
                lastAt: NOW - 60_000,
              },
            ],
            updatedAt: NOW - 60_000,
          },
          health: 'online',
        }),
      );
    await unreachable(s.edgeB);
    await reachableHistory(s.t, s.edgeB, ['IR', 'RU']);
    // Probe evidence counts only while probes are enabled (stale/legacy summaries never do).
    await s.t.run((ctx) => upsertSettingRow(ctx, 'edge.probe.enabled', 'true'));
    await bulkReports(s.t, { zeroWeight: 0, weighted: 10 });
    // Gates closed (global switch off): suspected with a veto, no rotation.
    const r1 = await s.t.action(internal.edgeDetector.run, {});
    expect(r1).toMatchObject({ suspected: 1, rotated: 0 });
    let o = (await s.t.query(internal.relays.get, { id: s.relayId }))!;
    expect(o.suspicion).toMatchObject({
      state: 'suspected',
      hintLevel: 'corroborated',
      veto: 'edge_disabled',
    });
    expect(o.suspicion!.edgeEvidence).toEqual([
      { edgeId: s.edgeB, source: 'probes', countries: ['IR', 'RU'] },
    ]);
    // Open the gates: global + per-origin opt-in.
    await s.t.run(async (ctx) => {
      await upsertSettingRow(ctx, 'edge.enabled', 'true');
      await upsertSettingRow(ctx, 'edge.autoRotate', 'true');
      await ctx.db.patch(s.relayId, { autoRotate: true });
    });
    const r2 = await s.t.action(internal.edgeDetector.run, {});
    expect(r2).toMatchObject({ suspected: 1, rotated: 1 });
    o = (await s.t.query(internal.relays.get, { id: s.relayId }))!;
    expect(o.activeRotationId).toBeDefined();
    expect(o.suspicion!.veto).toBeNull();
    // Samples taken while suspected never join the baseline ring.
    const samples = await s.t.run((ctx) => ctx.db.query('relaySamples').collect());
    expect(samples.some((x) => x.at === NOW)).toBe(false);
    const rot = (await s.t.query(internal.edgeRotations.get, { id: o.activeRotationId! }))!;
    expect(rot).toMatchObject({
      kind: 'replace',
      trigger: 'detector',
      burn: true,
      targetEdgeId: s.edgeB,
      listenerId: s.listenerId,
      reason: 'detector:probes',
    });
    // Next tick: the running rotation is itself a veto.
    const r3 = await s.t.action(internal.edgeDetector.run, {});
    expect(r3.rotated).toBe(0);
    o = (await s.t.query(internal.relays.get, { id: s.relayId }))!;
    expect(o.suspicion!.veto).toBe('rotation_active');
  });

  test('an edge that is down for everyone is an outage: no rotation, veto edge_outage', async () => {
    vi.useFakeTimers({ now: NOW });
    const s = await seed();
    await warmBaseline(s.t, s.relayId, 100);
    await nodeLoad(s.t, s.serverId, 0);
    await s.t.run(async (ctx) => {
      await upsertSettingRow(ctx, 'edge.enabled', 'true');
      await upsertSettingRow(ctx, 'edge.autoRotate', 'true');
      await ctx.db.patch(s.relayId, { autoRotate: true });
      await ctx.db.patch(s.edgeA, {
        reachability: {
          byCountry: [
            { country: 'IR', verdict: 'unreachable', okVantages: 0, failVantages: 4, lastAt: NOW },
            { country: 'XX', verdict: 'unreachable', okVantages: 0, failVantages: 1, lastAt: NOW },
          ],
          updatedAt: NOW,
        },
      });
      for (let i = 0; i < 10; i++) {
        await ctx.db.insert('issueReports', {
          kind: 'report',
          reason: 'cant-connect',
          backend: 'remnawave',
          relaySlug: 'node-one',
          detectorWeight: 1,
        });
      }
    });
    const r = await s.t.action(internal.edgeDetector.run, {});
    expect(r.rotated).toBe(0);
    const o = (await s.t.query(internal.relays.get, { id: s.relayId }))!;
    expect(o.suspicion!.state).toBe('suspected');
    expect(o.suspicion!.edgeEvidence).toEqual([]);
    expect(o.suspicion!.veto).toBe('no_edge_evidence');
  });

  test('member "which connection" evidence alone can rotate; the marks sweep drops expired rows', async () => {
    vi.useFakeTimers({ now: NOW });
    const s = await seed();
    await warmBaseline(s.t, s.relayId, 100);
    await nodeLoad(s.t, s.serverId, 0);
    await s.t.run(async (ctx) => {
      await upsertSettingRow(ctx, 'edge.enabled', 'true');
      await upsertSettingRow(ctx, 'edge.autoRotate', 'true');
      await ctx.db.patch(s.relayId, { autoRotate: true });
      await ctx.db.insert('relayReportMarks', {
        key: 'k-old',
        firstAt: NOW - 3_600_000,
        expiresAt: NOW - 1,
      });
      await ctx.db.insert('relayReportMarks', {
        key: 'k-live',
        firstAt: NOW,
        expiresAt: NOW + 3_600_000,
      });
    });
    await edgeReports(s.t, s.edgeA);
    const r = await s.t.action(internal.edgeDetector.run, {});
    expect(r.rotated).toBe(1);
    const o = (await s.t.query(internal.relays.get, { id: s.relayId }))!;
    expect(o.suspicion!.edgeEvidence).toEqual([
      { edgeId: s.edgeA, source: 'reports', countries: ['IR'] },
    ]);
    const rot = (await s.t.query(internal.edgeRotations.get, { id: o.activeRotationId! }))!;
    expect(rot.targetEdgeId).toBe(s.edgeA);
    expect(rot.reason).toBe('detector:reports');
    const marks = await s.t.run((ctx) => ctx.db.query('relayReportMarks').collect());
    expect(marks.map((m) => m.key)).toEqual(['k-live']);
  });

  test('the Host veto is ONLY for operator-managed Hosts: hostMode operator holds a template-edge rotation, fcp and none do not', async () => {
    vi.useFakeTimers({ now: NOW });
    const s = await seed();
    await warmBaseline(s.t, s.relayId, 100);
    await nodeLoad(s.t, s.serverId, 0);
    await s.t.run(async (ctx) => {
      await upsertSettingRow(ctx, 'edge.enabled', 'true');
      await upsertSettingRow(ctx, 'edge.autoRotate', 'true');
      await ctx.db.patch(s.relayId, { autoRotate: true });
    });
    // edgeA sits at index 0 and is the listener's template edge.
    expect((await s.t.run((ctx) => ctx.db.get(s.listenerId)))!.templateEdgeId).toBe(s.edgeA);
    await edgeReports(s.t, s.edgeA);
    // The operator owns the panel Hosts: the detector may not move the template
    // edge (its Host would keep pointing at the burned address).
    await s.t.mutation(internal.relays.update, { id: s.relayId, hostMode: 'operator' });
    const held = await s.t.action(internal.edgeDetector.run, {});
    expect(held.rotated).toBe(0);
    let o = (await s.t.query(internal.relays.get, { id: s.relayId }))!;
    expect(o.suspicion).toMatchObject({ state: 'suspected', veto: 'hosts_unmanaged' });
    expect(o.suspicion!.hint).toMatch(/hosts_unmanaged/);
    expect(o.activeRotationId).toBeUndefined();
    // Back to FCP-owned Hosts: the same evidence rotates (the machine flips the Host).
    await s.t.run((ctx) => ctx.db.patch(s.relayId, { hostMode: 'fcp' }));
    const rotated = await s.t.action(internal.edgeDetector.run, {});
    expect(rotated.rotated).toBe(1);
    o = (await s.t.query(internal.relays.get, { id: s.relayId }))!;
    expect(o.suspicion!.veto).toBeNull();
    expect(o.activeRotationId).toBeDefined();
    expect(
      (await s.t.query(internal.edgeRotations.get, { id: o.activeRotationId! }))!.targetEdgeId,
    ).toBe(s.edgeA);
  });

  test('maintenance: while frozen the detector evaluates nothing (a tick may start a rotation)', async () => {
    vi.useFakeTimers({ now: NOW });
    const s = await seed();
    await warmBaseline(s.t, s.relayId, 100);
    await nodeLoad(s.t, s.serverId, 0);
    await s.t.run(async (ctx) => {
      await upsertSettingRow(ctx, 'edge.enabled', 'true');
      await upsertSettingRow(ctx, 'edge.autoRotate', 'true');
      await ctx.db.patch(s.relayId, { autoRotate: true });
    });
    await edgeReports(s.t, s.edgeA);
    await s.t.mutation(internal.edgeMaintenance.freeze, { reason: 'test' });
    const frozen = await s.t.action(internal.edgeDetector.run, {});
    expect(frozen).toMatchObject({ evaluated: 0, suspected: 0, rotated: 0 });
    expect((await s.t.query(internal.relays.get, { id: s.relayId }))!.suspicion).toBeUndefined();
    await s.t.mutation(internal.edgeMaintenance.thaw, {});
    const thawed = await s.t.action(internal.edgeDetector.run, {});
    expect(thawed).toMatchObject({ evaluated: 1, suspected: 1, rotated: 1 });
  });
});
