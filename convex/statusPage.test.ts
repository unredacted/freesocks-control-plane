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
} from './lib/statusPage';
import { bandFromCpu } from './lib/loadBands';

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

async function seedNode(
  t: ReturnType<typeof convexTest>,
  backendServerId: Id<'backendServers'>,
  o: { cpuLoad5?: number; cpuCores?: number; online?: boolean; ageMs?: number },
): Promise<void> {
  await t.run((ctx) =>
    ctx.db.insert('backendNodeInventory', {
      backendServerId,
      nodeUuid: crypto.randomUUID(),
      name: 'node',
      usersOnline: 0,
      online: o.online ?? true,
      lastStatsAt: Date.now() - (o.ageMs ?? 0),
      cpuLoad5: o.cpuLoad5,
      cpuCores: o.cpuCores,
    }),
  );
}

describe('load band math', () => {
  test('CPU bands at 70% / 90%', () => {
    expect(bandFromCpu(0)).toBe('quiet');
    expect(bandFromCpu(0.69)).toBe('quiet');
    expect(bandFromCpu(0.7)).toBe('busy');
    expect(bandFromCpu(0.89)).toBe('busy');
    expect(bandFromCpu(0.9)).toBe('crowded');
    expect(bandFromCpu(1.4)).toBe('crowded'); // load above the core count
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

  test('load: CPU load over cores, summed across the nodes of every instance', async () => {
    const t = convexTest(schema, modules);
    const a = await seedServer(t, { slug: 'mci-1', location: 'MCI' });
    const b = await seedServer(t, { slug: 'mci-2', location: 'MCI' });
    // (3.6 + 0.4 + 2.0) load over (4 + 4 + 2) cores = 0.6 → quiet, though one
    // node alone is at 90%.
    await seedNode(t, a, { cpuLoad5: 3.6, cpuCores: 4 });
    await seedNode(t, a, { cpuLoad5: 0.4, cpuCores: 4 });
    await seedNode(t, b, { cpuLoad5: 2.0, cpuCores: 2 });
    let locations = await t.run((ctx) => resolveStatusLocations(ctx.db));
    expect(locations[0]!.load).toBe('quiet');
    // One more busy node tips the whole location over 70%: 9.6 / 12 = 0.8.
    await seedNode(t, b, { cpuLoad5: 3.6, cpuCores: 2 });
    locations = await t.run((ctx) => resolveStatusLocations(ctx.db));
    expect(locations[0]!.load).toBe('busy');
  });

  test('load: crowded from 90%, and a key cap is not load', async () => {
    const t = convexTest(schema, modules);
    // A full key cap used to read crowded; only the CPU decides now.
    const a = await seedServer(t, { slug: 'mci', location: 'MCI', keyCount: 99, maxKeys: 100 });
    await seedNode(t, a, { cpuLoad5: 1, cpuCores: 4 });
    let locations = await t.run((ctx) => resolveStatusLocations(ctx.db));
    expect(locations[0]!.load).toBe('quiet');
    await seedNode(t, a, { cpuLoad5: 6.6, cpuCores: 4 }); // 7.6 / 8 = 0.95
    locations = await t.run((ctx) => resolveStatusLocations(ctx.db));
    expect(locations[0]!.load).toBe('crowded');
  });

  test('load: stale, offline or unreported nodes read unknown, never quiet', async () => {
    const t = convexTest(schema, modules);
    const a = await seedServer(t, { slug: 'mci', location: 'MCI' });
    await seedNode(t, a, { cpuLoad5: 0.1, cpuCores: 4, ageMs: 60 * 60_000 }); // stale
    await seedNode(t, a, { cpuLoad5: 0.1, cpuCores: 4, online: false }); // offline
    await seedNode(t, a, {}); // connected, no CPU report
    const locations = await t.run((ctx) => resolveStatusLocations(ctx.db));
    expect(locations[0]!.load).toBe('unknown');
  });

  test('load: the retired users-per-node threshold rows are ignored', async () => {
    const t = convexTest(schema, modules);
    const a = await seedServer(t, { slug: 'mci', location: 'MCI' });
    await seedNode(t, a, { cpuLoad5: 0.2, cpuCores: 4 });
    await t.run((ctx) =>
      ctx.db.insert('appSettings', { key: 'status.loadBusyAt', value: '1', updatedAt: 0 }),
    );
    const locations = await t.run((ctx) => resolveStatusLocations(ctx.db));
    expect(locations[0]!.load).toBe('quiet');
  });
});

describe('setPageConfig', () => {
  test('refuses an empty write and no longer takes thresholds', async () => {
    const t = convexTest(schema, modules);
    await expect(t.mutation(internal.statusPage.setPageConfig, {})).rejects.toThrow(
      /no recognized status-page fields/,
    );
    const out = await t.mutation(internal.statusPage.setPageConfig, { rows: [] });
    expect(out).toEqual({ rows: [], countries: expect.any(Array) });
  });
});

describe('sanitizeCensorshipRows', () => {
  const VALID = new Set(['freedom-ws', 'freedom-reality', 'privacy-reality']);

  test('keeps valid rows/cells, drops junk, dedupes + sorts + normalizes case', () => {
    const rows = sanitizeCensorshipRows(
      {
        rows: [
          {
            countryCode: 'ir',
            label: ' Iran ',
            cells: { 'freedom-ws': 'available', 'privacy-reality': 'partial' },
          },
          { countryCode: 'IR', cells: { 'freedom-ws': 'blocked' } }, // dup → last wins
          { countryCode: 'XX1', cells: { 'freedom-ws': 'available' } }, // bad code
          {
            countryCode: 'CN',
            cells: { 'freedom-ws': 'maybe', 'privacy-reality': 'available', bogus: 'blocked' },
          },
          'garbage',
        ],
      },
      VALID,
    );
    expect(rows).toEqual([
      { countryCode: 'CN', label: null, cells: { 'privacy-reality': 'available' } },
      { countryCode: 'IR', label: null, cells: { 'freedom-ws': 'blocked' } },
    ]);
  });

  test('cells for a DISABLED-but-known mode are PRESERVED (validity ≠ enablement)', () => {
    // freedom-reality ships dark; its stored cells must survive a save so
    // re-enabling the mode restores the column with its data.
    const rows = sanitizeCensorshipRows(
      { rows: [{ countryCode: 'CN', cells: { 'freedom-reality': 'blocked' } }] },
      VALID,
    );
    expect(rows).toEqual([
      { countryCode: 'CN', label: null, cells: { 'freedom-reality': 'blocked' } },
    ]);
  });

  test('non-object input resolves to empty', () => {
    expect(sanitizeCensorshipRows(undefined, VALID)).toEqual([]);
    expect(sanitizeCensorshipRows('nope', VALID)).toEqual([]);
    expect(sanitizeCensorshipRows({ rows: 'nope' }, VALID)).toEqual([]);
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
