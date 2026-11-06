/// <reference types="vite/client" />
/**
 * A key in two groups (lib/placementSet.ts): a Hysteria key is placed in its
 * own mode's group AND its backup mode's (REALITY), so its subscription carries
 * both entries. Every writer sends the whole set:
 *
 *  - issue target resolution names the backup group on the SAME backend, and
 *    says so when it is not bound there (the key never issues without it);
 *  - an in-place switch into the mode moves both groups at once, a switch away
 *    leaves only the target's own; the row stores both halves together;
 *  - a tier push re-sends the stored set (a renewal never drops the backup);
 *  - a backup mode is validated (same family and backends, never itself, no
 *    chains, never deleted while used);
 *  - the mode is available only while a node serves it beside its backup.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { placementGroups, placementSetOf } from './lib/placementSet';
import { groupHasOtherNode } from './lib/switchServer';

const modules = import.meta.glob('./**/*.*s');

const SQ_REALITY = '11111111-0000-4000-8000-00000000000a';
const SQ_HY = '11111111-0000-4000-8000-00000000000b';

beforeEach(() => {
  vi.stubEnv('DEV_MOCK_BACKEND', '');
  vi.stubEnv('ENVIRONMENT', 'production');
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe('placementSetOf', () => {
  test('a legacy row has no extras; extras never outlive a cleared primary', () => {
    expect(placementSetOf({ backendPlacement: 'a' })).toEqual({ primary: 'a', extras: [] });
    expect(placementSetOf({ backendPlacement: 'a', backendExtraPlacements: ['b'] })).toEqual({
      primary: 'a',
      extras: ['b'],
    });
    expect(placementSetOf({ backendExtraPlacements: ['b'] })).toEqual({
      primary: null,
      extras: [],
    });
    expect(placementGroups({ primary: 'a', extras: ['b', 'a'] })).toEqual(['a', 'b']);
    expect(placementGroups({ primary: null, extras: ['b'] })).toEqual([]);
  });
});

/** A backend with REALITY and Hysteria groups bound, a member on REALITY, and a node serving both. */
async function seed(opts: { bindHysteria?: boolean; serving?: boolean } = {}) {
  const t = convexTest(schema, modules);
  await t.mutation(internal.seed.seedConnectionModes, {});
  const ids = await t.run(async (ctx) => {
    // The built-in ships dark: turned on here.
    const hysteria = (await ctx.db
      .query('connectionModes')
      .withIndex('by_slug', (q) => q.eq('slug', 'privacy-hysteria'))
      .unique())!;
    await ctx.db.patch(hysteria._id, { enabled: true });
    const serverId = await ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'test',
      slug: 'test',
      config: { type: 'remnawave', baseUrl: 'https://panel.test', apiToken: 'tok' },
      isActive: true,
      priority: 0,
      keyCount: 1,
      updatedAt: Date.now(),
    });
    for (const [slug, squad] of [
      ['privacy-reality', SQ_REALITY],
      ...(opts.bindHysteria === false ? [] : [['privacy-hysteria', SQ_HY]]),
    ] as const) {
      await ctx.db.insert('modePlacements', {
        modeSlug: slug,
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: [squad] }),
        updatedAt: Date.now(),
      });
      await ctx.db.insert('remnawaveNodeStats', {
        backendServerId: serverId,
        placement: squad,
        label: 'Node A',
        usersOnline: 1,
        online: true,
        nodeCount: 1,
        lastStatsAt: Date.now(),
        updatedAt: Date.now(),
      });
    }
    // A node serving Hysteria beside its REALITY (nodeExtraModes.ts).
    await ctx.db.insert('panelNodeIntents', nodeIntent(serverId, opts.serving !== false));
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
    const userId = await ctx.db.insert('users', {
      tierId,
      status: 'active',
      connectionModeId: 'privacy-reality',
      updatedAt: Date.now(),
    });
    const subId = await ctx.db.insert('subscriptions', {
      userId,
      backend: 'remnawave',
      backendUserId: '550e8400-e29b-41d4-a716-446655440000',
      backendShortId: 'shortA',
      backendServerId: serverId,
      subscriptionUrl: 'https://panel.test/sub/shortA',
      subToken: 'tok-abc',
      subscriptionMirrors: [],
      backendPlacement: SQ_REALITY,
      state: 'active',
      updatedAt: Date.now(),
    });
    await ctx.db.patch(userId, { currentSubscriptionId: subId });
    return { serverId, userId, subId };
  });
  return { t, ...ids };
}

function nodeIntent(serverId: Id<'backendServers'>, serving: boolean | null, name = 'node-a') {
  const now = Date.now();
  return {
    backendServerId: serverId,
    name,
    label: name,
    mode: 'privacy-reality',
    contractVersion: 2,
    generation: 1,
    desiredHash: 'h',
    state: 'ready' as const,
    observed: {
      management: { address: '192.0.2.10', port: 2222 },
      publicIps: { v4: '203.0.113.10' },
      capabilities: { caddy: false, ipv6: false },
      at: now,
    },
    settings: { originHostnameSource: 'none' as const, publishV6: false, nodePort: 2222 },
    machineRevision: 1,
    activation: { stage: 'live' as const, evidence: [] },
    delivery: {
      disposition: 'live' as const,
      acceptingAssignments: true,
      exposure: {
        everLive: true,
        hosts: [],
        mirrors: 0,
        testCredentials: 0,
        dns: 0,
      },
    },
    origin: { dns: 'none' as const },
    extraModes:
      serving === null
        ? []
        : [
            {
              slug: 'privacy-hysteria',
              state: serving ? ('serving' as const) : ('activating' as const),
              firewall: { port: 443, protocol: 'udp' as const, confirmedBy: 'role' as const },
              since: now,
              updatedAt: now,
            },
          ],
    registeredAt: now,
    updatedAt: now,
  };
}

function panel() {
  return vi.fn(
    async (_input: string | URL, _init?: RequestInit) =>
      new Response(
        JSON.stringify({
          response: {
            uuid: '550e8400-e29b-41d4-a716-446655440000',
            shortUuid: 'shortA',
            username: 'u',
            status: 'ACTIVE',
            trafficLimitBytes: null,
            trafficLimitStrategy: 'MONTH',
            userTraffic: { usedTrafficBytes: 0 },
            expireAt: new Date(Date.now() + 30 * 86_400_000).toISOString(),
            hwidDeviceLimit: null,
            subscriptionUrl: 'https://panel.test/sub/shortA',
          },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
  );
}
const patches = (f: ReturnType<typeof panel>) =>
  f.mock.calls
    .filter(([u, i]) => String(u).includes('/api/users') && i?.method === 'PATCH')
    .map(([, i]) => JSON.parse(String(i!.body)) as { activeInternalSquads?: string[] });

describe('issue target resolution', () => {
  test('names the backup group on the same backend', async () => {
    const { t, serverId } = await seed();
    const r = await t.query(internal.connectionModes.resolveIssueTarget, {
      backend: 'remnawave',
      modeId: 'privacy-hysteria',
      onlyServerId: serverId,
    });
    expect(r).toMatchObject({
      placement: SQ_HY,
      extraPlacements: [SQ_REALITY],
      fallbackUnresolved: false,
    });
    // A mode with no backup has none.
    expect(
      await t.query(internal.connectionModes.resolveIssueTarget, {
        backend: 'remnawave',
        modeId: 'privacy-reality',
        onlyServerId: serverId,
      }),
    ).toMatchObject({ placement: SQ_REALITY, extraPlacements: [], fallbackUnresolved: false });
    // No choice made: the key issues into the default mode, with its backup.
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'connectionMode.default',
        value: JSON.stringify('privacy-hysteria'),
        updatedAt: Date.now(),
      }),
    );
    expect(
      await t.query(internal.connectionModes.resolveIssueTarget, {
        backend: 'remnawave',
        modeId: null,
        onlyServerId: serverId,
      }),
    ).toMatchObject({ placement: SQ_HY, extraPlacements: [SQ_REALITY], fallbackUnresolved: false });
  });

  test('says when the backup is not bound there', async () => {
    const { t, serverId } = await seed();
    await t.run(async (ctx) => {
      const row = (await ctx.db.query('modePlacements').collect()).find(
        (r) => r.modeSlug === 'privacy-reality',
      )!;
      await ctx.db.delete(row._id);
    });
    const r = await t.query(internal.connectionModes.resolveIssueTarget, {
      backend: 'remnawave',
      modeId: 'privacy-hysteria',
      onlyServerId: serverId,
    });
    expect(r).toMatchObject({ placement: SQ_HY, extraPlacements: [], fallbackUnresolved: true });
  });
});

describe('every writer sends the whole set', () => {
  test('switching in moves both groups, a push keeps them, switching away leaves one', async () => {
    const { t, userId, subId } = await seed();
    const f = panel();
    vi.stubGlobal('fetch', f);

    const into = await t.action(internal.account.switchMode, {
      userId,
      target: 'privacy-hysteria',
    });
    expect(into).toMatchObject({ ok: true });
    expect(patches(f).at(-1)!.activeInternalSquads).toEqual([SQ_HY, SQ_REALITY]);
    const sub = await t.run((ctx) => ctx.db.get(subId));
    expect(placementSetOf(sub!)).toEqual({ primary: SQ_HY, extras: [SQ_REALITY] });

    // A tier push (a renewal) re-sends exactly that.
    const st = await t.query(internal.lifecycle.activeSubAndTier, { userId });
    expect(st?.placementSet).toEqual({ primary: SQ_HY, extras: [SQ_REALITY] });

    const away = await t.action(internal.account.switchMode, {
      userId,
      target: 'privacy-reality',
    });
    expect(away).toMatchObject({ ok: true });
    expect(patches(f).at(-1)!.activeInternalSquads).toEqual([SQ_REALITY]);
    expect(placementSetOf((await t.run((ctx) => ctx.db.get(subId)))!)).toEqual({
      primary: SQ_REALITY,
      extras: [],
    });
  });
});

describe('the pin', () => {
  test('a key in two groups is pinned among the nodes serving its mode beside the backup', async () => {
    const { t, serverId, subId } = await seed();
    const rules = () =>
      t.query(internal.freedomDelivery.pinRules, {
        backendServerId: serverId,
        backendShortId: 'shortA',
      });
    // A REALITY key: nothing narrows its pick.
    expect((await rules()).servable).toBeNull();
    await t.run((ctx) =>
      ctx.db.patch(subId, { backendPlacement: SQ_HY, backendExtraPlacements: [SQ_REALITY] }),
    );
    // A second REALITY node that does not serve Hysteria.
    await t.run((ctx) => ctx.db.insert('panelNodeIntents', nodeIntent(serverId, null, 'node-b')));
    expect((await rules()).servable).toEqual(['node-a']);
    // "Switch server" counts only that tier: pinned to node-a, nowhere to go.
    await t.run((ctx) => ctx.db.patch(subId, { pinnedNode: 'node-a' }));
    expect(
      await t.query(internal.subscriptions.otherPinTargets, { subscriptionId: subId }),
    ).toEqual([]);
    const degraded = () =>
      t.query(internal.subscriptions.extraModeDegraded, { subscriptionId: subId });
    expect(await degraded()).toBe(false);
    // A pin still under the node's former name (a rename not drained yet) is
    // that node's: still served, and still nowhere else to switch to.
    await t.run(async (ctx) => {
      const now = Date.now();
      const renameId = await ctx.db.insert('panelNodeRenames', {
        backendServerId: serverId,
        nodeUuid: 'n-a',
        from: 'old-node-a',
        to: 'node-a',
        relayIds: [],
        state: 'running',
        step: 'subscriptions',
        createdAt: now,
        updatedAt: now,
      });
      await ctx.db.insert('panelNodeAliases', {
        backendServerId: serverId,
        formerName: 'old-node-a',
        name: 'node-a',
        nodeUuid: 'n-a',
        renameId,
        at: now,
      });
      await ctx.db.patch(subId, { pinnedNode: 'old-node-a' });
    });
    expect(await degraded()).toBe(false);
    expect(
      await t.query(internal.subscriptions.otherPinTargets, { subscriptionId: subId }),
    ).toEqual([]);
    await t.run(async (ctx) => {
      for (const a of await ctx.db.query('panelNodeAliases').collect()) await ctx.db.delete(a._id);
      await ctx.db.patch(subId, { pinnedNode: 'node-a' });
    });
    // While no node serves it (its address closed for a re-check), it pins
    // among its backup mode's nodes: the member keeps the backup entry.
    await t.run(async (ctx) => {
      const i = (await ctx.db.query('panelNodeIntents').collect()).find(
        (r) => r.name === 'node-a',
      )!;
      await ctx.db.patch(i._id, {
        extraModes: i.extraModes!.map((m) => ({ ...m, state: 'activating' as const })),
      });
    });
    expect((await rules()).servable).toEqual(['node-a', 'node-b']);
    // The account view says the UDP connection is unavailable right now.
    expect(await degraded()).toBe(true);
    expect(
      await t.query(internal.subscriptions.otherPinTargets, { subscriptionId: subId }),
    ).toEqual(['node-b']);
    // A node whose delivery gate is closed is never a candidate.
    await t.run(async (ctx) => {
      const i = (await ctx.db.query('panelNodeIntents').collect()).find(
        (r) => r.name === 'node-b',
      )!;
      await ctx.db.patch(i._id, { maintenance: { id: 'm1', since: Date.now(), reason: 'test' } });
    });
    expect((await rules()).servable).toEqual(['node-a']);
  });

  test('switch server needs another node in the tier, not just in the group', () => {
    const now = Date.now();
    const stats = { nodeCount: 3, lastStatsAt: now };
    expect(groupHasOtherNode(stats, now)).toBe(true);
    expect(groupHasOtherNode(stats, now, [])).toBe(false);
    expect(groupHasOtherNode(stats, now, ['node-b'])).toBe(true);
    expect(groupHasOtherNode({ nodeCount: 1, lastStatsAt: now }, now, ['node-b'])).toBe(false);
  });
});

describe('the backup mode', () => {
  test('is validated: same family, never itself, no chains, never deleted while used', async () => {
    const { t } = await seed();
    const update = (slug: string, fallbackModeSlug: string | null) =>
      t.mutation(internal.connectionModes.updateMode, { slug, fallbackModeSlug });
    await expect(update('privacy-hysteria', 'privacy-hysteria')).rejects.toThrow(/its own backup/);
    await expect(update('privacy-hysteria', 'freedom-ws')).rejects.toThrow(/same family/);
    await expect(update('privacy-hysteria', 'nonsense')).rejects.toThrow(/unknown backup/);
    // REALITY is a backup already: it cannot take one of its own (no chains).
    await expect(update('privacy-reality', 'privacy-hysteria')).rejects.toThrow(
      /backup of its own|uses this one/,
    );
    await expect(
      t.mutation(internal.connectionModes.removeMode, { slug: 'privacy-reality' }),
    ).rejects.toThrow(/uses this mode as its backup/);
    // Nor leave the family of the mode it backs.
    await expect(
      t.mutation(internal.connectionModes.updateMode, {
        slug: 'privacy-reality',
        family: 'freedom',
      }),
    ).rejects.toThrow(/uses this mode as its backup/);
    await update('privacy-hysteria', null);
    const list = await t.query(internal.connectionModes.list, {});
    expect(list.find((m) => m.id === 'privacy-hysteria')!.fallbackModeSlug).toBeNull();
  });

  test('the mode is available only while a node serves it beside its backup', async () => {
    const served = await seed();
    const avail = async (t: typeof served.t) =>
      (await t.query(internal.connectionModes.list, {})).find((m) => m.id === 'privacy-hysteria')!
        .availableBackends;
    expect(await avail(served.t)).toEqual(['remnawave']);
    const notYet = await seed({ serving: false });
    expect(await avail(notYet.t)).toEqual([]);
    const unbound = await seed({ bindHysteria: false });
    expect(await avail(unbound.t)).toEqual([]);
  });
});
