/// <reference types="vite/client" />
/**
 * Public network-status projection (lib/statusPage.ts): the location grouping
 * + load bands, the censorship-matrix sanitizer, the incident window, and the
 * admin input validator. Everything public ships bands only — never raw user
 * counts — so the tests pin the band boundaries.
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import {
  resolvePublicStatusPage,
  resolveStatusLocations,
  sanitizeCensorshipRows,
  validateIncidentInput,
  STATUS_KEYS,
} from './lib/statusPage';
import {
  bandFromUsersPerNode,
  bandFromUtilization,
  LOAD_THRESHOLD_DEFAULTS,
} from './lib/loadBands';

const modules = import.meta.glob('./**/*.*s');

async function seedServer(
  t: ReturnType<typeof convexTest>,
  o: {
    slug: string;
    location?: string;
    locationLabel?: string;
    isActive?: boolean;
    healthAgeMs?: number | null;
    keyCount?: number;
    maxKeys?: number;
    fleetStats?: { nodesOnline: number; nodesTotal: number };
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
      lastHealthOkAt: o.healthAgeMs === null ? undefined : Date.now() - (o.healthAgeMs ?? 0),
      fleetStats: o.fleetStats
        ? {
            ...o.fleetStats,
            onlineNow: 0,
            distinctCountries: 0,
            monthTrafficBytes: 0,
            lifetimeTrafficBytes: 0,
            panelVersion: 'test',
          }
        : undefined,
      fleetStatsAt: o.fleetStats ? Date.now() : undefined,
      updatedAt: Date.now(),
    }),
  );
}

async function seedNodeStats(
  t: ReturnType<typeof convexTest>,
  backendServerId: Id<'backendServers'>,
  o: { usersOnline: number; online?: boolean; nodeCount?: number; ageMs?: number },
): Promise<void> {
  await t.run((ctx) =>
    ctx.db.insert('remnawaveNodeStats', {
      backendServerId,
      placement: crypto.randomUUID(),
      usersOnline: o.usersOnline,
      online: o.online ?? true,
      nodeCount: o.nodeCount ?? 1,
      lastStatsAt: Date.now() - (o.ageMs ?? 0),
      updatedAt: Date.now(),
    }),
  );
}

describe('load band math', () => {
  test('users-per-node bands against thresholds', () => {
    const th = LOAD_THRESHOLD_DEFAULTS; // 50/150
    expect(bandFromUsersPerNode(0, th)).toBe('quiet');
    expect(bandFromUsersPerNode(49.9, th)).toBe('quiet');
    expect(bandFromUsersPerNode(50, th)).toBe('busy');
    expect(bandFromUsersPerNode(149.9, th)).toBe('busy');
    expect(bandFromUsersPerNode(150, th)).toBe('crowded');
  });

  test('utilization bands at 0.6/0.85', () => {
    expect(bandFromUtilization(0)).toBe('quiet');
    expect(bandFromUtilization(0.59)).toBe('quiet');
    expect(bandFromUtilization(0.6)).toBe('busy');
    expect(bandFromUtilization(0.84)).toBe('busy');
    expect(bandFromUtilization(0.85)).toBe('crowded');
  });
});

describe('resolveStatusLocations', () => {
  test('groups by code; skips inactive/unlocated; online = any-fresh; fleetStats freshest', async () => {
    const t = convexTest(schema, modules);
    await seedServer(t, {
      slug: 'mci-1',
      location: 'MCI',
      fleetStats: { nodesOnline: 2, nodesTotal: 3 },
    });
    await seedServer(t, { slug: 'mci-2', location: 'MCI', healthAgeMs: 45 * 60_000 }); // stale
    await seedServer(t, { slug: 'ams', location: 'AMS', locationLabel: 'Amsterdam' });
    await seedServer(t, { slug: 'off', location: 'OFF', isActive: false });
    await seedServer(t, { slug: 'plain' }); // no location
    const locations = await t.run((ctx) => resolveStatusLocations(ctx.db));
    expect(locations.map((l) => l.code)).toEqual(['AMS', 'MCI']);
    const mci = locations.find((l) => l.code === 'MCI')!;
    expect(mci.online).toBe(true);
    expect(mci.label).toBe('MCI'); // no label anywhere → code
    const ams = locations.find((l) => l.code === 'AMS')!;
    expect(ams.label).toBe('Amsterdam');
    // Exact node counts never ship publicly (bands-only posture): the shape
    // carries no count fields at all.
    expect('nodesOnline' in mci).toBe(false);
    expect('nodesTotal' in mci).toBe(false);
  });

  test('load: key-capacity utilization wins when every instance is capped', async () => {
    const t = convexTest(schema, modules);
    // 80/100 = 0.8 → busy, even though the (stale) stats row would say quiet.
    await seedServer(t, { slug: 'mci', location: 'MCI', keyCount: 80, maxKeys: 100 });
    const locations = await t.run((ctx) => resolveStatusLocations(ctx.db));
    expect(locations[0]!.load).toBe('busy');
  });

  test('load: users-per-node fallback aggregates fresh stats across instances', async () => {
    const t = convexTest(schema, modules);
    const a = await seedServer(t, { slug: 'mci-1', location: 'MCI' });
    const b = await seedServer(t, { slug: 'mci-2', location: 'MCI' });
    // (100 users / 2 nodes) + (200 / 2) = 300 users over 4 nodes = 75/node → busy (>= 50).
    await seedNodeStats(t, a, { usersOnline: 100, nodeCount: 2 });
    await seedNodeStats(t, b, { usersOnline: 200, nodeCount: 2 });
    const locations = await t.run((ctx) => resolveStatusLocations(ctx.db));
    expect(locations[0]!.load).toBe('busy');
  });

  test('load: stale or all-offline stats read unknown, never quiet', async () => {
    const t = convexTest(schema, modules);
    const a = await seedServer(t, { slug: 'mci', location: 'MCI' });
    await seedNodeStats(t, a, { usersOnline: 1, nodeCount: 1, ageMs: 60 * 60_000 }); // stale
    await seedNodeStats(t, a, { usersOnline: 1, nodeCount: 1, online: false }); // offline
    const locations = await t.run((ctx) => resolveStatusLocations(ctx.db));
    expect(locations[0]!.load).toBe('unknown');
  });

  test('load thresholds are admin-tunable via status.*', async () => {
    const t = convexTest(schema, modules);
    const a = await seedServer(t, { slug: 'mci', location: 'MCI' });
    await seedNodeStats(t, a, { usersOnline: 60, nodeCount: 1 }); // 60/node
    await t.run((ctx) =>
      ctx.db.insert('appSettings', { key: STATUS_KEYS.loadBusyAt, value: '100', updatedAt: 0 }),
    );
    const locations = await t.run((ctx) => resolveStatusLocations(ctx.db));
    expect(locations[0]!.load).toBe('quiet'); // 60 < 100 with the raised bar
  });
});

describe('setPageConfig threshold validation', () => {
  test('rejects crowdedAt <= busyAt against the EFFECTIVE pair', async () => {
    const t = convexTest(schema, modules);
    // Defaults are 50/150; a write that collapses the gap is refused.
    await expect(t.mutation(internal.statusPage.setPageConfig, { busyAt: 200 })).rejects.toThrow(
      /crowdedAt must be greater than busyAt/,
    );
    await expect(
      t.mutation(internal.statusPage.setPageConfig, { busyAt: 150, crowdedAt: 150 }),
    ).rejects.toThrow(/crowdedAt must be greater than busyAt/);
    // A valid pair persists (and audits).
    const out = await t.mutation(internal.statusPage.setPageConfig, {
      busyAt: 80,
      crowdedAt: 200,
    });
    expect(out.busyAt).toBe(80);
    expect(out.crowdedAt).toBe(200);
    // And a single-sided write validates against the STORED other side.
    await expect(t.mutation(internal.statusPage.setPageConfig, { crowdedAt: 80 })).rejects.toThrow(
      /crowdedAt must be greater than busyAt/,
    );
    const out2 = await t.mutation(internal.statusPage.setPageConfig, { crowdedAt: 120 });
    expect(out2.crowdedAt).toBe(120);
  });
});

describe('sanitizeCensorshipRows', () => {
  test('keeps valid rows/cells, drops junk, dedupes + sorts + normalizes case', () => {
    const rows = sanitizeCensorshipRows({
      rows: [
        { countryCode: 'ir', label: ' Iran ', cells: { evade: 'available', privacy: 'partial' } },
        { countryCode: 'IR', cells: { evade: 'blocked' } }, // dup → last wins
        { countryCode: 'XX1', cells: { evade: 'available' } }, // bad code
        { countryCode: 'CN', cells: { evade: 'maybe', privacy: 'available', bogus: 'blocked' } },
        'garbage',
      ],
    });
    expect(rows).toEqual([
      { countryCode: 'CN', label: null, cells: { privacy: 'available' } },
      { countryCode: 'IR', label: null, cells: { evade: 'blocked' } },
    ]);
  });

  test('non-object input resolves to empty', () => {
    expect(sanitizeCensorshipRows(undefined)).toEqual([]);
    expect(sanitizeCensorshipRows('nope')).toEqual([]);
    expect(sanitizeCensorshipRows({ rows: 'nope' })).toEqual([]);
  });
});

describe('incidents', () => {
  test('public projection: unresolved any age + resolved within 30d, newest-first', async () => {
    const t = convexTest(schema, modules);
    const now = Date.now();
    const insert = (o: { title: string; startedAt: number; resolvedAt?: number }) =>
      t.run((ctx) =>
        ctx.db.insert('statusIncidents', {
          title: o.title,
          severity: 'outage' as const,
          locationCodes: [],
          startedAt: o.startedAt,
          resolvedAt: o.resolvedAt,
          updatedAt: now,
        }),
      );
    await insert({ title: 'old-unresolved', startedAt: now - 90 * 86_400_000 });
    await insert({
      title: 'recent-resolved',
      startedAt: now - 10 * 86_400_000,
      resolvedAt: now - 5 * 86_400_000,
    });
    await insert({
      title: 'ancient-resolved',
      startedAt: now - 120 * 86_400_000,
      resolvedAt: now - 100 * 86_400_000,
    });
    const page = await t.run((ctx) => resolvePublicStatusPage(ctx.db));
    expect(page.incidents.map((i) => i.title)).toEqual(['recent-resolved', 'old-unresolved']);
    expect(page.incidents[0]!.resolvedAt).not.toBeNull();
    expect(page.incidents[1]!.resolvedAt).toBeNull();
  });
});

describe('validateIncidentInput', () => {
  test('accepts a full valid payload', () => {
    const out = validateIncidentInput({
      title: ' MCI degraded ',
      body: ' upstream fiber cut ',
      severity: 'degraded',
      locationCodes: ['MCI', 'MCI', 'AMS'],
      startedAt: Date.now(),
    });
    expect(out.title).toBe('MCI degraded');
    expect(out.body).toBe('upstream fiber cut');
    expect(out.locationCodes).toEqual(['MCI', 'AMS']);
  });

  test('rejects missing title / bad severity / future startedAt / junk locations', () => {
    expect(() => validateIncidentInput({ severity: 'outage', startedAt: 1 })).toThrow(/title/);
    expect(() => validateIncidentInput({ title: 'x', severity: 'meh', startedAt: 1 })).toThrow(
      /severity/,
    );
    expect(() =>
      validateIncidentInput({
        title: 'x',
        severity: 'outage',
        startedAt: Date.now() + 2 * 86_400_000,
      }),
    ).toThrow(/startedAt/);
    expect(() =>
      validateIncidentInput({ title: 'x', severity: 'outage', locationCodes: [42], startedAt: 1 }),
    ).toThrow(/strings/);
  });
});
