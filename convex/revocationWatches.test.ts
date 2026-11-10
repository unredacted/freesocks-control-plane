/// <reference types="vite/client" />
/**
 * The revocation watch (revocationWatches.ts) against a fetch-faked panel:
 *
 *  - off by default: nothing is watched and a tombstoned Hysteria key is
 *    deleted at once, as before;
 *  - on: only Hysteria-placed keys are watched (a REALITY key is not);
 *  - a disabled key that keeps moving bytes past the settle time asks for a
 *    restart of its node, sent through the operations ledger as a forced
 *    restart; a key that moved nothing never restarts anything;
 *  - one restart per node per interval, however many keys leaked;
 *  - a tombstoned Hysteria key is disabled first and deleted after the drain;
 *  - an admin disable cuts at once when the key was online recently.
 *
 * Fixtures use RFC 5737 addresses and `*.example` names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { insertPanelServer, markBackendSetUp } from './lib/edges/testing/fixtures';
import { SETTLE_MS } from './lib/revocationWatch';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;
const MIN = 60_000;

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', 'test-admin-sign');
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(new Date('2026-11-10T12:00:00Z'));
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

interface Panel {
  users: Map<string, { status: 'ACTIVE' | 'DISABLED'; used: number; onlineAt: string | null }>;
  restarts: string[];
  deletes: string[];
  failRestart: boolean;
  lastStatusChange: string;
}

const HY_SQUAD = 'sq-hy';
// Backend user ids (2.x uuid form).
const HY1 = '00000000-0000-4000-8000-000000000001';
const HY2 = '00000000-0000-4000-8000-000000000002';
const R1 = '00000000-0000-4000-8000-000000000003';
const REALITY_SQUAD = 'sq-r';

function installPanel(): Panel {
  const panel: Panel = {
    users: new Map(),
    restarts: [],
    deletes: [],
    failRestart: false,
    lastStatusChange: 't0',
  };
  const json = (o: unknown, status = 200) =>
    new Response(JSON.stringify({ response: o }), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  const node = () => ({
    uuid: 'n-1',
    name: 'node-one',
    address: '192.0.2.10',
    port: 2222,
    countryCode: 'NL',
    isDisabled: false,
    isConnected: true,
    lastStatusChange: panel.lastStatusChange,
    configProfile: {
      activeConfigProfileUuid: 'p-1',
      activeInbounds: [{ uuid: 'i-1', tag: 'in-1' }],
    },
  });
  const profile = {
    uuid: 'p-1',
    name: 'Default',
    config: {
      inbounds: [
        {
          tag: 'in-1',
          port: 443,
          protocol: 'vless',
          streamSettings: { network: 'tcp', security: 'none' },
        },
      ],
    },
    inbounds: [{ uuid: 'i-1', tag: 'in-1' }],
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL, init: RequestInit = {}) => {
      const path = new URL(typeof input === 'string' ? input : input.toString()).pathname;
      const method = (init.method ?? 'GET').toUpperCase();
      const userId = path.match(/^\/api\/users\/([^/]+)$/)?.[1];
      if (userId && method === 'GET') {
        const u = panel.users.get(userId);
        if (!u) return new Response('{"message":"not found"}', { status: 404 });
        return new Response(
          JSON.stringify({
            response: {
              uuid: userId,
              shortUuid: `s-${userId}`,
              username: `u-${userId}`,
              status: u.status,
              trafficLimitBytes: 0,
              trafficLimitStrategy: 'NO_RESET',
              usedTrafficBytes: u.used,
              hwidDeviceLimit: 0,
              subscriptionUrl: `https://panel.example/sub/s-${userId}`,
              expireAt: '2099-01-01T00:00:00.000Z',
              userTraffic: { usedTrafficBytes: u.used, onlineAt: u.onlineAt },
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      if (userId && method === 'DELETE') {
        panel.deletes.push(userId);
        panel.users.delete(userId);
        return json({ isDeleted: true });
      }
      const action = path.match(/^\/api\/users\/([^/]+)\/actions\/(enable|disable)$/);
      if (action) {
        const u = panel.users.get(action[1]!);
        if (u) u.status = action[2] === 'disable' ? 'DISABLED' : 'ACTIVE';
        return json({});
      }
      if (path.startsWith('/api/hwid/devices/')) return new Response('nf', { status: 404 });
      if (path === `/api/internal-squads/${HY_SQUAD}/accessible-nodes`)
        return json({ accessibleNodes: [{ uuid: 'n-1' }] });
      if (path === `/api/internal-squads/${REALITY_SQUAD}/accessible-nodes`)
        return json({ accessibleNodes: [{ uuid: 'n-1' }] });
      if (path === '/api/nodes/n-1/actions/restart' && method === 'POST' && panel.failRestart)
        return new Response('{"message":"no"}', { status: 403 });
      if (path === '/api/nodes/n-1/actions/restart' && method === 'POST') {
        panel.restarts.push(String(init.body));
        return json({}, 202);
      }
      if (path === '/api/nodes') return json([node()]);
      if (path === '/api/hosts') return json([]);
      if (path === '/api/internal-squads') return json({ internalSquads: [] });
      if (path === '/api/config-profiles') return json({ configProfiles: [profile] });
      if (path === '/api/config-profiles/p-1') return json(profile);
      return json({});
    }),
  );
  return panel;
}

async function setWatch(t: T, on: boolean, extra: Record<string, unknown> = {}) {
  await t.mutation(internal.appSettings.setMany, {
    entries: Object.entries({ 'revocation.watch': on, ...extra }).map(([key, value]) => ({
      key,
      value: JSON.stringify(value),
    })),
  });
}

async function seed() {
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
  const panel = installPanel();
  await t.action(internal.backendObserve.refresh, { backendServerId: serverId });
  await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': true } });
  await markBackendSetUp(t, serverId);
  const tierId = await t.run(async (ctx) => {
    await ctx.db.insert('modePlacements', {
      modeSlug: 'privacy-hysteria',
      backend: 'remnawave',
      config: JSON.stringify({ squadUuids: [HY_SQUAD] }),
      updatedAt: Date.now(),
    });
    return ctx.db.insert('tiers', {
      slug: 'member',
      name: 'Member',
      backend: 'remnawave',
      monthlyTrafficGb: 0,
      deviceLimit: 3,
      hwidLimit: 3,
      hwidEnabled: false,
      trafficStrategy: 'MONTH',
      isDefaultFree: false,
      isActive: true,
      priority: 10,
      expirationDaysAfterMembershipLapse: 7,
      updatedAt: Date.now(),
    });
  });
  const key = async (
    backendUserId: string,
    placement: string,
    state: 'active' | 'disabled' = 'active',
  ): Promise<Id<'subscriptions'>> => {
    panel.users.set(backendUserId, { status: 'ACTIVE', used: 1000, onlineAt: null });
    return t.run(async (ctx) => {
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      return ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId,
        backendShortId: `s-${backendUserId}`,
        backendServerId: serverId,
        backendPlacement: placement,
        ...(placement === HY_SQUAD ? { backendExtraPlacements: [REALITY_SQUAD] } : {}),
        subscriptionUrl: 'https://panel.example/sub/x',
        subscriptionMirrors: [],
        state,
        ...(state === 'disabled' ? { deletedAt: Date.now() - 1000 } : {}),
        updatedAt: Date.now(),
      });
    });
  };
  const watches = () => t.run((ctx) => ctx.db.query('revocationWatches').collect());
  const later = (ms: number) => vi.setSystemTime(new Date(Date.now() + ms));
  return { t, serverId, panel, key, watches, later };
}

describe('revocation watch', () => {
  test('off by default: nothing is watched', async () => {
    const { t, key, watches } = await seed();
    await key(HY1, HY_SQUAD);
    expect(
      await t.mutation(internal.revocationWatches.start, { backendUserId: HY1, reason: 'lapsed' }),
    ).toBeNull();
    expect(await watches()).toHaveLength(0);
  });

  test('on: a Hysteria key is watched, a REALITY key is not', async () => {
    const { t, key, watches } = await seed();
    await setWatch(t, true);
    await key(HY1, HY_SQUAD);
    await key(R1, REALITY_SQUAD);
    expect(
      await t.mutation(internal.revocationWatches.start, { backendUserId: R1, reason: 'lapsed' }),
    ).toBeNull();
    const id = await t.mutation(internal.revocationWatches.start, {
      backendUserId: HY1,
      reason: 'lapsed',
    });
    expect(id).not.toBeNull();
    // Idempotent.
    expect(
      await t.mutation(internal.revocationWatches.start, { backendUserId: HY1, reason: 'admin' }),
    ).toBe(id);
    const [w] = await watches();
    expect(w).toMatchObject({ state: 'watching', placements: [HY_SQUAD, REALITY_SQUAD], cuts: 0 });
  });

  test('a disabled key that keeps moving bytes restarts its node, once, through the ledger', async () => {
    const { t, panel, key, watches, later } = await seed();
    await setWatch(t, true);
    await key(HY1, HY_SQUAD);
    await key(HY2, HY_SQUAD);
    panel.users.get(HY1)!.status = 'DISABLED';
    panel.users.get(HY2)!.status = 'DISABLED';
    await t.mutation(internal.revocationWatches.start, { backendUserId: HY1, reason: 'lapsed' });
    await t.mutation(internal.revocationWatches.start, { backendUserId: HY2, reason: 'lapsed' });

    // Before the settle time nothing is read as a baseline.
    await t.action(internal.revocationWatches.sweep, {});
    expect((await watches()).every((w) => w.baselineBytes === undefined)).toBe(true);

    later(SETTLE_MS + 1);
    await t.action(internal.revocationWatches.sweep, {});
    expect((await watches()).map((w) => w.baselineBytes)).toEqual([1000, 1000]);

    // Both open connections keep moving data.
    panel.users.get(HY1)!.used += 10 * 1024 * 1024;
    panel.users.get(HY2)!.used += 10 * 1024 * 1024;
    later(6 * MIN);
    const out = await t.action(internal.revocationWatches.sweep, {});
    expect(out).toMatchObject({ leaked: 2, cuts: 1 });
    expect(panel.restarts).toEqual([JSON.stringify({ forceRestart: true })]);
    // Both watches start over after the cut, with one cut counted.
    expect((await watches()).map((w) => [w.state, w.cuts])).toEqual([
      ['watching', 1],
      ['watching', 1],
    ]);
    const ops = await t.run((ctx) => ctx.db.query('panelOps').collect());
    expect(ops.filter((o) => o.verb === 'restart')).toHaveLength(1);
  });

  test('a key that moves nothing never restarts anything', async () => {
    const { t, panel, key, watches, later } = await seed();
    await setWatch(t, true);
    await key(HY1, HY_SQUAD);
    panel.users.get(HY1)!.status = 'DISABLED';
    await t.mutation(internal.revocationWatches.start, { backendUserId: HY1, reason: 'lapsed' });
    for (let i = 0; i < 4; i++) {
      later(6 * MIN);
      await t.action(internal.revocationWatches.sweep, {});
    }
    expect(panel.restarts).toHaveLength(0);
    expect((await watches())[0]).toMatchObject({ state: 'watching', baselineBytes: 1000 });
  });

  test('a key enabled again ends its watch', async () => {
    const { t, panel, key, watches, later } = await seed();
    await setWatch(t, true);
    await key(HY1, HY_SQUAD);
    await t.mutation(internal.revocationWatches.start, { backendUserId: HY1, reason: 'lapsed' });
    panel.users.get(HY1)!.status = 'ACTIVE';
    later(SETTLE_MS + 1);
    await t.action(internal.revocationWatches.sweep, {});
    expect(await watches()).toHaveLength(0);
  });

  test('a second leak within the interval waits for it', async () => {
    const { t, panel, key, later } = await seed();
    await setWatch(t, true, { 'revocation.cutMinIntervalMinutes': 30 });
    for (const id of [HY1, HY2]) {
      await key(id, HY_SQUAD);
      panel.users.get(id)!.status = 'DISABLED';
    }
    await t.mutation(internal.revocationWatches.start, { backendUserId: HY1, reason: 'lapsed' });
    later(SETTLE_MS + 1);
    await t.action(internal.revocationWatches.sweep, {});
    panel.users.get(HY1)!.used += 10 * 1024 * 1024;
    later(6 * MIN);
    await t.action(internal.revocationWatches.sweep, {});
    expect(panel.restarts).toHaveLength(1);

    // The ledger settles the restart once the node's clock moves.
    panel.lastStatusChange = 't1';
    const [op] = await t.run((ctx) => ctx.db.query('panelOps').collect());
    await t.action(internal.backendWrites.observe, { opId: op!._id });

    await t.mutation(internal.revocationWatches.start, { backendUserId: HY2, reason: 'lapsed' });
    later(SETTLE_MS + 1);
    await t.action(internal.revocationWatches.sweep, {});
    panel.users.get(HY2)!.used += 10 * 1024 * 1024;
    later(6 * MIN);
    await t.action(internal.revocationWatches.sweep, {});
    expect(panel.restarts).toHaveLength(1); // still inside the 30 minutes
    later(30 * MIN);
    await t.action(internal.revocationWatches.sweep, {});
    expect(panel.restarts).toHaveLength(2);
  });

  test('a failed restart is retried after a while, not every round', async () => {
    const { t, panel, key, later } = await seed();
    await setWatch(t, true);
    await key(HY1, HY_SQUAD);
    panel.users.get(HY1)!.status = 'DISABLED';
    await t.mutation(internal.revocationWatches.start, { backendUserId: HY1, reason: 'lapsed' });
    later(SETTLE_MS + 1);
    await t.action(internal.revocationWatches.sweep, {});
    panel.users.get(HY1)!.used += 10 * 1024 * 1024;
    panel.failRestart = true;
    later(6 * MIN);
    expect((await t.action(internal.revocationWatches.sweep, {})).cuts).toBe(0);
    const [cut] = await t.run((ctx) => ctx.db.query('nodeSessionCuts').collect());
    expect(cut).toMatchObject({ lastError: 'restart_failed' });
    expect(cut!.retryAfter).toBeGreaterThan(Date.now());
    panel.failRestart = false;
    later(5 * MIN);
    expect((await t.action(internal.revocationWatches.sweep, {})).cuts).toBe(0); // still waiting
    later(11 * MIN);
    expect((await t.action(internal.revocationWatches.sweep, {})).cuts).toBe(1);
  });

  test('off: a tombstoned Hysteria key is deleted at once', async () => {
    const { t, panel, key } = await seed();
    await key(HY1, HY_SQUAD, 'disabled');
    await t.action(internal.lifecycle.sweepTombstones, {});
    expect(panel.deletes).toEqual([HY1]);
  });

  test('on: a tombstoned Hysteria key is disabled first and deleted after the drain', async () => {
    const { t, panel, key, watches, later } = await seed();
    await setWatch(t, true, { 'revocation.drainMinutes': 60 });
    const subId = await key(HY1, HY_SQUAD, 'disabled');
    await key(R1, REALITY_SQUAD, 'disabled');
    await t.action(internal.lifecycle.sweepTombstones, {});
    // The REALITY key goes at once; the Hysteria key is only turned off.
    expect(panel.deletes).toEqual([R1]);
    expect(panel.users.get(HY1)!.status).toBe('DISABLED');
    expect(await watches()).toMatchObject([{ backendUserId: HY1, reason: 'teardown' }]);
    const row = await t.run((ctx) => ctx.db.get(subId));
    expect(row!.state).toBe('disabled');
    expect(row!.tombstoneAttempts).toBeUndefined(); // a drain is not a failed attempt
    expect(Math.abs(row!.revokeDrainUntil! - (Date.now() + 60 * MIN))).toBeLessThan(1000);

    later(30 * MIN);
    await t.action(internal.lifecycle.sweepTombstones, {});
    expect(panel.deletes).toEqual([R1]);

    later(31 * MIN);
    await t.action(internal.lifecycle.sweepTombstones, {});
    expect(panel.deletes).toEqual([R1, HY1]);
    expect((await t.run((ctx) => ctx.db.get(subId)))!.state).toBe('deleted');
    // The watch ends at its next read (the key is gone).
    later(6 * MIN);
    await t.action(internal.revocationWatches.sweep, {});
    expect(await watches()).toHaveLength(0);
  });

  test('an admin disable cuts at once when the key was online recently', async () => {
    const { t, panel, key } = await seed();
    await setWatch(t, true);
    await key(HY1, HY_SQUAD);
    await key(HY2, HY_SQUAD);
    panel.users.get(HY1)!.onlineAt = new Date(Date.now() - 2 * MIN).toISOString();
    panel.users.get(HY2)!.onlineAt = new Date(Date.now() - 3 * 3_600_000).toISOString();
    expect(
      await t.action(internal.revocationWatches.afterAdminDisable, { backendUserId: HY2 }),
    ).toEqual({ watched: true, cut: false });
    expect(panel.restarts).toHaveLength(0);
    expect(
      await t.action(internal.revocationWatches.afterAdminDisable, { backendUserId: HY1 }),
    ).toEqual({ watched: true, cut: true });
    expect(panel.restarts).toHaveLength(1);
  });

  test('an admin disable does not cut when that setting is off', async () => {
    const { t, panel, key } = await seed();
    await setWatch(t, true, { 'revocation.adminDisableCutsNow': false });
    await key(HY1, HY_SQUAD);
    panel.users.get(HY1)!.onlineAt = new Date(Date.now() - MIN).toISOString();
    expect(
      await t.action(internal.revocationWatches.afterAdminDisable, { backendUserId: HY1 }),
    ).toEqual({ watched: true, cut: false });
    expect(panel.restarts).toHaveLength(0);
  });
});
