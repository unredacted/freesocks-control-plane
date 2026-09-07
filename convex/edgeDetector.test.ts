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

async function seed() {
  const t = convexTest(schema, modules);
  const base = await t.run(async (ctx) => {
    const tierId = await ctx.db.insert('tiers', {
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
    });
    const serverId = await ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'panel-a',
      slug: 'panel-a',
      config: { type: 'remnawave', baseUrl: 'https://panel.example', apiToken: 'tok' },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: Date.now(),
    });
    await upsertSettingRow(ctx, 'edge.render.enabled', 'true');
    return { tierId, serverId };
  });
  await t.mutation(internal.protocolProfiles.create, {
    slug: 'prof-u',
    name: 'P',
    provider: 'upcloud',
    targetAddress: 'target.example',
    serverNames: ['a.example'],
  });
  const { id: relayId } = await t.mutation(internal.relays.upsertBySlug, {
    slug: 'node-one',
    backendServerSlug: 'panel-a',
    nodeHostname: 'node-one',
    originAddress: ORIGIN,
  });
  const { id: slotId } = await t.mutation(internal.relaySlots.upsert, {
    relayId,
    slotKey: 'u',
    profileSlug: 'prof-u',
    inboundTag: 'VLESS_RELAY_U',
    configProfileUuid: '11111111-1111-4111-8111-111111111111',
    configProfileInboundUuid: '22222222-2222-4222-8222-222222222222',
    originPort: 443,
  });
  const a = await t.mutation(internal.relays.adoptEdge, {
    relayId,
    slotId,
    ipv4: EDGE_A,
    publish: true,
  });
  const b = await t.mutation(internal.relays.adoptEdge, {
    relayId,
    slotId,
    ipv4: EDGE_B,
    publish: true,
  });
  return {
    t,
    ...base,
    relayId,
    slotId,
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

describe('relay attribution on member reports', () => {
  test('a report carries the origin slug; the edge only for an explicit choice; the first report per window weighs 1', async () => {
    const s = await seed();
    const m = await member(s.t, s.tierId, s.serverId, 1);
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
    expect([s.edgeA, s.edgeB]).toContain(rows[0].relayEdgeId);
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

  async function warmBaseline(
    t: ReturnType<typeof convexTest>,
    relayId: Id<'relays'>,
    usersOnline: number,
  ) {
    await t.run(async (ctx) => {
      for (let i = 1; i <= 80; i++) {
        await ctx.db.insert('relaySamples', {
          relayId,
          at: NOW - i * 5 * 60_000,
          reports: 0,
          distinctReporters: 0,
          usersOnline,
        });
      }
    });
  }

  async function nodeLoad(
    t: ReturnType<typeof convexTest>,
    serverId: Id<'backendServers'>,
    usersOnline: number,
  ) {
    await t.run((ctx) =>
      ctx.db.insert('backendNodeInventory', {
        backendServerId: serverId,
        nodeUuid: 'n1',
        name: 'node-one',
        usersOnline,
        online: true,
        lastStatsAt: NOW - 60_000,
      }),
    );
  }

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

  test('reports + load drop suspect the origin (hint), but without edge evidence nothing rotates', async () => {
    vi.useFakeTimers({ now: NOW });
    const s = await seed();
    await warmBaseline(s.t, s.relayId, 100);
    await nodeLoad(s.t, s.serverId, 10);
    await s.t.run(async (ctx) => {
      await upsertSettingRow(ctx, 'edge.enabled', 'true');
      await upsertSettingRow(ctx, 'edge.autoRotate', 'true');
      await ctx.db.patch(s.relayId, { autoRotate: true });
      for (let i = 0; i < 10; i++) {
        await ctx.db.insert('issueReports', {
          kind: 'report',
          reason: 'cant-connect',
          backend: 'remnawave',
          relaySlug: 'node-one',
          country: 'IR',
          detectorWeight: 1,
        });
      }
    });
    const r = await s.t.action(internal.edgeDetector.run, {});
    expect(r).toMatchObject({ evaluated: 1, suspected: 1, rotated: 0 });
    const o = (await s.t.query(internal.relays.get, { id: s.relayId }))!;
    expect(o.suspicion).toMatchObject({
      state: 'suspected',
      hintLevel: 'reports',
      scope: 'regional',
      veto: 'no_edge_evidence',
    });
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
    await s.t.run(async (ctx) => {
      for (let i = 0; i < 10; i++) {
        await ctx.db.insert('issueReports', {
          kind: 'report',
          reason: 'cant-connect',
          backend: 'remnawave',
          relaySlug: 'node-one',
          country: 'IR',
          detectorWeight: 1,
        });
      }
    });
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
    const rot = (await s.t.query(internal.edgeRotations.get, { id: o.activeRotationId! }))!;
    expect(rot).toMatchObject({
      kind: 'replace',
      trigger: 'detector',
      burn: true,
      targetEdgeId: s.edgeB,
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
      for (let i = 0; i < 6; i++) {
        await ctx.db.insert('issueReports', {
          kind: 'report',
          reason: 'cant-connect',
          backend: 'remnawave',
          relaySlug: 'node-one',
          country: 'IR',
          detectorWeight: 1,
          connectionChoice: 'primary',
          relayEdgeId: s.edgeA,
        });
      }
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
});
