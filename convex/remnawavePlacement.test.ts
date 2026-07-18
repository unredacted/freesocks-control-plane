/// <reference types="vite/client" />
/**
 * Issuance-time node placement: the least-loaded-node picker
 * (lib/remnawavePlacement.pickByNodeLoad) over the cron-fed remnawaveNodeStats
 * cache, plus the remnawaveGetNodeStats provider aggregation (squad → nodes →
 * per-node load).
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import type { Id } from './_generated/dataModel';
import {
  pickByNodeLoad,
  resolveBoundModeCounts,
  resolvePlacementTarget,
} from './lib/remnawavePlacement';
import { remnawaveGetNodeStats } from './lib/backends/remnawave';

const modules = import.meta.glob('./**/*.*s');

async function seedServer(t: ReturnType<typeof convexTest>): Promise<Id<'backendServers'>> {
  return t.run((ctx) =>
    ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'rw',
      slug: 'rw',
      config: { type: 'remnawave', baseUrl: 'https://rw.example', apiToken: 'tok' },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: Date.now(),
    }),
  );
}

function seedNode(
  t: ReturnType<typeof convexTest>,
  backendServerId: Id<'backendServers'>,
  o: {
    placement: string;
    usersOnline: number;
    online?: boolean;
    nodeCount?: number;
    ageMs?: number;
  },
) {
  const now = Date.now();
  const at = now - (o.ageMs ?? 0);
  return t.run((ctx) =>
    ctx.db.insert('remnawaveNodeStats', {
      backendServerId,
      placement: o.placement,
      label: o.placement,
      usersOnline: o.usersOnline,
      online: o.online ?? true,
      nodeCount: o.nodeCount ?? 1,
      lastStatsAt: at,
      updatedAt: at,
    }),
  );
}

describe('pickByNodeLoad', () => {
  test('fast paths: empty → null, single → that element, all-unknown → declaration order', async () => {
    const t = convexTest(schema, modules);
    expect(await t.run((ctx) => pickByNodeLoad(ctx.db, []))).toBeNull();
    expect(await t.run((ctx) => pickByNodeLoad(ctx.db, ['only']))).toBe('only');
    // No stats rows for either → all-unknown → declaration order (deterministic).
    expect(await t.run((ctx) => pickByNodeLoad(ctx.db, ['first', 'second']))).toBe('first');
  });

  test('least-loaded fresh+online node wins regardless of declaration order', async () => {
    const t = convexTest(schema, modules);
    const server = await seedServer(t);
    await seedNode(t, server, { placement: 'busy', usersOnline: 50 });
    await seedNode(t, server, { placement: 'idle', usersOnline: 3 });
    // With ≥2 usable candidates the pick is uniform over the top-3 (anti-herding);
    // random → 0 pins the least-loaded slot.
    const spy = vi.spyOn(Math, 'random').mockReturnValue(0);
    try {
      expect(await t.run((ctx) => pickByNodeLoad(ctx.db, ['busy', 'idle']))).toBe('idle');
    } finally {
      spy.mockRestore();
    }
  });

  test('anti-herding (L5): the pick spreads across the top-3 usable, not always top-1', async () => {
    const t = convexTest(schema, modules);
    const server = await seedServer(t);
    await seedNode(t, server, { placement: 'n1', usersOnline: 1 });
    await seedNode(t, server, { placement: 'n2', usersOnline: 2 });
    await seedNode(t, server, { placement: 'n3', usersOnline: 3 });
    await seedNode(t, server, { placement: 'n4', usersOnline: 4 }); // outside the top-3
    // random → top-end picks the LAST of the top-3 (n3); n4 is never eligible.
    const spy = vi.spyOn(Math, 'random').mockReturnValue(0.999);
    try {
      expect(await t.run((ctx) => pickByNodeLoad(ctx.db, ['n1', 'n2', 'n3', 'n4']))).toBe('n3');
    } finally {
      spy.mockRestore();
    }
  });

  test('stale / offline / unroutable / never-observed nodes lose to a fresh+online one', async () => {
    const t = convexTest(schema, modules);
    const server = await seedServer(t);
    // Lowest count but STALE (>30 min) → must not win.
    await seedNode(t, server, { placement: 'stale', usersOnline: 0, ageMs: 45 * 60_000 });
    // Offline (no connected node) → must not win despite a low count.
    await seedNode(t, server, { placement: 'offline', usersOnline: 0, online: false });
    // Unroutable (maps to zero nodes) → must not win.
    await seedNode(t, server, { placement: 'unrouted', usersOnline: 0, nodeCount: 0 });
    // The one fresh+online node.
    await seedNode(t, server, { placement: 'live', usersOnline: 9 });
    expect(
      await t.run((ctx) => pickByNodeLoad(ctx.db, ['stale', 'offline', 'unrouted', 'live'])),
    ).toBe('live');
    // A never-observed placement also loses to the fresh one.
    expect(await t.run((ctx) => pickByNodeLoad(ctx.db, ['never-seen', 'live']))).toBe('live');
  });

  test('a bound-but-all-degraded pool still returns a placement (declaration order), never null', async () => {
    const t = convexTest(schema, modules);
    const server = await seedServer(t);
    await seedNode(t, server, { placement: 'a', usersOnline: 0, online: false });
    await seedNode(t, server, { placement: 'b', usersOnline: 0, nodeCount: 0 });
    // Neither is usable → falls back to declaration order (a), so a key still issues.
    expect(await t.run((ctx) => pickByNodeLoad(ctx.db, ['a', 'b']))).toBe('a');
  });
});

describe('remnawaveGetNodeStats (provider aggregation)', () => {
  const cfg = { baseUrl: 'https://panel.test', apiToken: 'tok' };

  afterEach(() => vi.unstubAllGlobals());

  // Route the panel's endpoints to canned JSON.
  function stubPanel(handlers: Record<string, unknown>): void {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        const path = new URL(url).pathname;
        // accessible-nodes is /api/internal-squads/{uuid}/accessible-nodes
        const key = path.includes('/accessible-nodes') ? `accessible:${path.split('/')[3]}` : path;
        const body = handlers[key];
        if (body === undefined) return new Response('null', { status: 404 });
        return new Response(JSON.stringify({ response: body }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }),
    );
  }

  test('aggregates per-squad load over its accessible nodes (1:1 and 1:many)', async () => {
    stubPanel({
      '/api/internal-squads': {
        internalSquads: [
          { uuid: 'sq-a', name: 'A' },
          { uuid: 'sq-b', name: 'B' },
        ],
      },
      '/api/nodes': [
        { uuid: 'n1', isConnected: true, isDisabled: false, usersOnline: 4, trafficUsedBytes: 10 },
        { uuid: 'n2', isConnected: true, isDisabled: false, usersOnline: 6, trafficUsedBytes: 20 },
        { uuid: 'n3', isConnected: false, isDisabled: false, usersOnline: 0, trafficUsedBytes: 0 },
      ],
      'accessible:sq-a': { accessibleNodes: [{ uuid: 'n1' }] }, // 1:1
      'accessible:sq-b': { accessibleNodes: [{ uuid: 'n2' }, { uuid: 'n3' }] }, // 1:many
      '/api/bandwidth-stats/nodes/realtime': [],
    });
    const stats = await remnawaveGetNodeStats(cfg);
    const a = stats.find((s) => s.placement === 'sq-a')!;
    const b = stats.find((s) => s.placement === 'sq-b')!;
    expect(a).toMatchObject({ usersOnline: 4, online: true, nodeCount: 1, label: 'A' });
    // sq-b aggregates n2 (6) + n3 (0); online because n2 is connected.
    expect(b).toMatchObject({ usersOnline: 6, online: true, nodeCount: 2 });
  });

  test('a squad mapping to zero known nodes is emitted as unroutable (nodeCount 0, offline)', async () => {
    stubPanel({
      '/api/internal-squads': { internalSquads: [{ uuid: 'sq-x', name: 'X' }] },
      '/api/nodes': [
        { uuid: 'n1', isConnected: true, isDisabled: false, usersOnline: 1, trafficUsedBytes: 0 },
      ],
      'accessible:sq-x': { accessibleNodes: [] },
      '/api/bandwidth-stats/nodes/realtime': [],
    });
    const stats = await remnawaveGetNodeStats(cfg);
    expect(stats).toEqual([
      expect.objectContaining({ placement: 'sq-x', usersOnline: 0, online: false, nodeCount: 0 }),
    ]);
  });

  test('a disabled node does not count as online', async () => {
    stubPanel({
      '/api/internal-squads': { internalSquads: [{ uuid: 'sq-a', name: 'A' }] },
      '/api/nodes': [
        { uuid: 'n1', isConnected: true, isDisabled: true, usersOnline: 5, trafficUsedBytes: 0 },
      ],
      'accessible:sq-a': { accessibleNodes: [{ uuid: 'n1' }] },
      '/api/bandwidth-stats/nodes/realtime': [],
    });
    const [a] = await remnawaveGetNodeStats(cfg);
    expect(a).toMatchObject({ usersOnline: 5, online: false, nodeCount: 1 });
  });
});

describe('resolveBoundModeCounts', () => {
  test('returns per-mode pool sizes (never UUIDs); unbound = 0', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      await ctx.db.insert('appSettings', {
        key: 'remnawave.modePlacement.evade.squads',
        value: JSON.stringify(['sq-1', 'sq-2', 'sq-3']),
        updatedAt: Date.now(),
      });
    });
    const counts = await t.run((ctx) => resolveBoundModeCounts(ctx.db));
    expect(counts).toEqual({ evade: 3, privacy: 0 });
  });
});

// --- resolvePlacementTarget (multi-panel: placement + panel picked together) --

async function seedLocatedServer(
  t: ReturnType<typeof convexTest>,
  o: {
    slug: string;
    location?: string;
    locationLabel?: string;
    isActive?: boolean;
    keyCount?: number;
    maxKeys?: number;
  },
): Promise<Id<'backendServers'>> {
  return t.run((ctx) =>
    ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: o.slug,
      slug: o.slug,
      location: o.location,
      locationLabel: o.locationLabel,
      config: { type: 'remnawave', baseUrl: `https://${o.slug}.example`, apiToken: 'tok' },
      isActive: o.isActive ?? true,
      priority: 0,
      keyCount: o.keyCount ?? 0,
      maxKeys: o.maxKeys,
      updatedAt: Date.now(),
    }),
  );
}

async function bindPool(t: ReturnType<typeof convexTest>, modeId: string, squads: string[]) {
  await t.run((ctx) =>
    ctx.db.insert('appSettings', {
      key: `remnawave.modePlacement.${modeId}.squads`,
      value: JSON.stringify(squads),
      updatedAt: Date.now(),
    }),
  );
}

describe('resolvePlacementTarget', () => {
  test('pairs the placement with its own panel (least-loaded across panels)', async () => {
    const t = convexTest(schema, modules);
    const mci = await seedLocatedServer(t, { slug: 'mci', location: 'MCI' });
    const ams = await seedLocatedServer(t, { slug: 'ams', location: 'AMS' });
    await bindPool(t, 'evade', ['sq-mci', 'sq-ams']);
    await seedNode(t, mci, { placement: 'sq-mci', usersOnline: 50 });
    await seedNode(t, ams, { placement: 'sq-ams', usersOnline: 1 });
    // random → 0 pins the least-loaded of the top-3 (anti-herding spread).
    const spy = vi.spyOn(Math, 'random').mockReturnValue(0);
    try {
      const target = await t.run((ctx) => resolvePlacementTarget(ctx.db, 'evade'));
      expect(target).toEqual({ placement: 'sq-ams', serverId: ams });
    } finally {
      spy.mockRestore();
    }
  });

  test('a location pick narrows to that panel even when another is less loaded', async () => {
    const t = convexTest(schema, modules);
    const mci = await seedLocatedServer(t, { slug: 'mci', location: 'MCI' });
    const ams = await seedLocatedServer(t, { slug: 'ams', location: 'AMS' });
    await bindPool(t, 'evade', ['sq-mci', 'sq-ams']);
    await seedNode(t, mci, { placement: 'sq-mci', usersOnline: 50 });
    await seedNode(t, ams, { placement: 'sq-ams', usersOnline: 1 });
    const target = await t.run((ctx) =>
      resolvePlacementTarget(ctx.db, 'evade', { location: 'MCI' }),
    );
    expect(target).toEqual({ placement: 'sq-mci', serverId: mci });
  });

  test('an unknown/stale location code fails soft to any panel, never blocks issuance', async () => {
    const t = convexTest(schema, modules);
    const ams = await seedLocatedServer(t, { slug: 'ams', location: 'AMS' });
    await bindPool(t, 'evade', ['sq-ams']);
    await seedNode(t, ams, { placement: 'sq-ams', usersOnline: 1 });
    const target = await t.run((ctx) =>
      resolvePlacementTarget(ctx.db, 'evade', { location: 'GONE' }),
    );
    expect(target).toEqual({ placement: 'sq-ams', serverId: ams });
  });

  test('an at-capacity panel is excluded for NEW keys (location pick falls elsewhere)', async () => {
    const t = convexTest(schema, modules);
    const mci = await seedLocatedServer(t, {
      slug: 'mci',
      location: 'MCI',
      keyCount: 10,
      maxKeys: 10,
    });
    const ams = await seedLocatedServer(t, { slug: 'ams', location: 'AMS' });
    await bindPool(t, 'evade', ['sq-mci', 'sq-ams']);
    await seedNode(t, mci, { placement: 'sq-mci', usersOnline: 1 });
    await seedNode(t, ams, { placement: 'sq-ams', usersOnline: 50 });
    const target = await t.run((ctx) =>
      resolvePlacementTarget(ctx.db, 'evade', { location: 'MCI' }),
    );
    expect(target).toEqual({ placement: 'sq-ams', serverId: ams });
  });

  test('onlyServerId pins to that panel; a mode with no squad there resolves null', async () => {
    const t = convexTest(schema, modules);
    const mci = await seedLocatedServer(t, { slug: 'mci', location: 'MCI' });
    const ams = await seedLocatedServer(t, { slug: 'ams', location: 'AMS' });
    await bindPool(t, 'evade', ['sq-mci', 'sq-ams']);
    await bindPool(t, 'privacy', ['sq-ams-priv']);
    await seedNode(t, mci, { placement: 'sq-mci', usersOnline: 5 });
    await seedNode(t, ams, { placement: 'sq-ams', usersOnline: 1 });
    await seedNode(t, ams, { placement: 'sq-ams-priv', usersOnline: 1 });
    // Pinned to MCI: the evade squad on MCI wins despite AMS being idler.
    expect(
      await t.run((ctx) =>
        resolvePlacementTarget(ctx.db, 'evade', { onlyServerId: mci as string }),
      ),
    ).toEqual({ placement: 'sq-mci', serverId: mci });
    // Privacy has no squad on MCI (its only squad is attributed to AMS) → null,
    // the caller falls back to a re-issue that may move panels.
    expect(
      await t.run((ctx) =>
        resolvePlacementTarget(ctx.db, 'privacy', { onlyServerId: mci as string }),
      ),
    ).toEqual({ placement: null, serverId: null });
  });

  test('onlyServerId keeps UNATTRIBUTED squads eligible (bring-up / single panel)', async () => {
    const t = convexTest(schema, modules);
    const mci = await seedLocatedServer(t, { slug: 'mci', location: 'MCI' });
    await bindPool(t, 'privacy', ['sq-unobserved']);
    // No stats row for sq-unobserved: can't be proven foreign → still usable.
    expect(
      await t.run((ctx) =>
        resolvePlacementTarget(ctx.db, 'privacy', { onlyServerId: mci as string }),
      ),
    ).toEqual({ placement: 'sq-unobserved', serverId: mci });
  });

  test('bring-up (no stats rows at all): global pick, no panel pin', async () => {
    const t = convexTest(schema, modules);
    await seedLocatedServer(t, { slug: 'mci', location: 'MCI' });
    await bindPool(t, 'evade', ['sq-a', 'sq-b']);
    const target = await t.run((ctx) => resolvePlacementTarget(ctx.db, 'evade'));
    expect(target).toEqual({ placement: 'sq-a', serverId: null });
  });

  test('MULTI-panel with zero attributable squads signals fail-loud (no dead keys)', async () => {
    const t = convexTest(schema, modules);
    await seedLocatedServer(t, { slug: 'mci', location: 'MCI' });
    await seedLocatedServer(t, { slug: 'ams', location: 'AMS' });
    await bindPool(t, 'evade', ['sq-a', 'sq-b']);
    // No stats rows: the (squad, panel) pair can't be resolved, and an unpinned
    // pick could mint a squad onto the wrong panel — a dead key. The caller
    // (account.resolveIssueTarget) turns this flag into a 503 instead.
    const target = await t.run((ctx) => resolvePlacementTarget(ctx.db, 'evade'));
    expect(target).toEqual({ placement: null, serverId: null, unattributedMultiPanel: true });
  });

  test('multi-panel WITH attribution still pairs normally', async () => {
    const t = convexTest(schema, modules);
    const mci = await seedLocatedServer(t, { slug: 'mci', location: 'MCI' });
    await seedLocatedServer(t, { slug: 'ams', location: 'AMS' });
    await bindPool(t, 'evade', ['sq-a']);
    await seedNode(t, mci, { placement: 'sq-a', usersOnline: 3 });
    const target = await t.run((ctx) => resolvePlacementTarget(ctx.db, 'evade'));
    expect(target).toEqual({ placement: 'sq-a', serverId: mci });
  });

  test('no pool bound anywhere: null placement (caller audits the squad-less key)', async () => {
    const t = convexTest(schema, modules);
    await seedLocatedServer(t, { slug: 'mci', location: 'MCI' });
    expect(await t.run((ctx) => resolvePlacementTarget(ctx.db, 'evade'))).toEqual({
      placement: null,
      serverId: null,
    });
  });
});
