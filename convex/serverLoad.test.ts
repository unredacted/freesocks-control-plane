/// <reference types="vite/client" />
/**
 * Hot fields kept off the rows cached queries read (lib/serverLoad.ts,
 * stats:publicImpact). Convex caches a query result until a write lands in
 * its read set, so `publicConfig.get` (GET /api/v1/config) stays cached only
 * while issuance and sign-up writes stay out of what it reads. These tests run
 * the real handler against a recording `db`, snapshot every document it read,
 * then make those writes and check that none of the snapshot changed.
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { api, internal } from './_generated/api';
import type { FunctionReturnType } from 'convex/server';
import type { DatabaseReader } from './_generated/server';
import type { Id } from './_generated/dataModel';
import { get as publicConfigGet } from './publicConfig';
import { applyCountsDelta, PUBLIC_IMPACT_KEY, USER_COUNTS_KEY } from './lib/statusCounters';
import { readHealth, readKeyCount } from './lib/serverLoad';

const modules = import.meta.glob('./**/*.*s');

type T = ReturnType<typeof convexTest>;

/** A `db` that records the tables queried and every document handed back. */
function recordingDb(db: DatabaseReader) {
  const tables = new Set<string>();
  const docs = new Map<string, unknown>();
  const note = (v: unknown): void => {
    if (Array.isArray(v)) v.forEach(note);
    else if (v && typeof v === 'object') {
      if ('_id' in v) docs.set(String((v as { _id: unknown })._id), v);
      else if ('page' in v) note((v as { page: unknown }).page);
      else if ('value' in v && 'done' in v) note((v as { value: unknown }).value);
    }
  };
  const wrap = <O extends object>(obj: O): O =>
    new Proxy(obj, {
      get(target, prop) {
        const val = Reflect.get(target, prop) as unknown;
        if (typeof val !== 'function') return val;
        return (...args: unknown[]) => {
          const out = (val as (...a: unknown[]) => unknown).apply(target, args);
          if (out && typeof (out as Promise<unknown>).then === 'function')
            return (out as Promise<unknown>).then((r) => (note(r), r));
          if (out && typeof out === 'object') return wrap(out);
          return out;
        };
      },
    });
  const proxy = {
    get: async (...args: unknown[]) => {
      const d = await (db.get as (...a: unknown[]) => Promise<unknown>)(...args);
      note(d);
      return d;
    },
    query: (table: string) => {
      tables.add(table);
      return wrap(db.query(table as never));
    },
    normalizeId: db.normalizeId.bind(db),
    system: db.system,
  } as unknown as DatabaseReader;
  return { db: proxy, tables, docs };
}

type PublicConfig = FunctionReturnType<typeof api.publicConfig.get>;

/** Run publicConfig.get once; return its result and its read set. */
async function readPublicConfig(t: T) {
  return t.run(async (ctx) => {
    const rec = recordingDb(ctx.db);
    const handler = (publicConfigGet as unknown as { _handler: (c: unknown, a: object) => unknown })
      ._handler;
    const result = (await handler({ ...ctx, db: rec.db }, {})) as PublicConfig;
    return { result, tables: [...rec.tables], ids: [...rec.docs.keys()] };
  });
}

/** The current content of the given documents. */
async function snapshot(t: T, ids: string[]) {
  return t.run(async (ctx) => {
    const out: Record<string, unknown> = {};
    for (const id of ids) out[id] = await ctx.db.get(id as Id<'backendServers'>);
    return out;
  });
}

async function seedServer(t: T, legacy: { keyCount?: number; lastHealthOkAt?: number } = {}) {
  return t.run((ctx) =>
    ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'mci',
      slug: 'mci',
      location: 'MCI',
      locationLabel: 'Kansas City, MO',
      config: { type: 'remnawave', baseUrl: 'https://mci.example', apiToken: 'tok' },
      isActive: true,
      priority: 0,
      ...legacy,
      updatedAt: Date.now(),
    }),
  );
}

async function seedFreeTier(t: T) {
  await t.run((ctx) =>
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
}

describe("publicConfig.get's read set", () => {
  test('issuance and sign-up writes land outside it; the rounded figure moving lands inside', async () => {
    const t = convexTest(schema, modules);
    await seedFreeTier(t);
    const serverId = await seedServer(t);
    await t.mutation(internal.backendServers.markHealthy, {
      id: serverId,
      keyCount: null,
      rttMs: 40,
    });
    await t.mutation(internal.backendServers.bumpKeyCount, { id: serverId });
    await t.mutation(internal.userStats.setFreeActive, { freeActive: 123 });

    const before = await readPublicConfig(t);
    expect(before.result.billing.donation.freeUsersHelped).toBe(120);
    expect(before.result.locations).toEqual([
      expect.objectContaining({ code: 'MCI', online: true }),
    ]);
    // Neither the key counts nor the live user counter is read at all.
    expect(before.tables).not.toContain('backendServerLoad');
    const userCountsRow = await t.run((ctx) =>
      ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', USER_COUNTS_KEY))
        .unique(),
    );
    expect(before.ids).not.toContain(String(userCountsRow!._id));
    expect(before.ids).toContain(String(serverId));
    const snap = await snapshot(t, before.ids);

    // A burst of issuances and teardowns, sign-ups and status changes, and a
    // free-user recount that does not move the rounded figure.
    for (let i = 0; i < 3; i++)
      await t.mutation(internal.backendServers.bumpKeyCount, { id: serverId });
    await t.mutation(internal.backendServers.bumpKeyCount, { id: serverId, delta: -1 });
    await t.run(async (ctx) => {
      await applyCountsDelta(ctx, { statusTo: 'active', creationTime: Date.now() });
      await applyCountsDelta(ctx, {
        statusFrom: 'active',
        statusTo: 'grace',
        creationTime: Date.now(),
      });
    });
    await t.mutation(internal.userStats.setFreeActive, { freeActive: 129 });

    expect(await snapshot(t, before.ids)).toEqual(snap);
    expect(await t.run(async (ctx) => readKeyCount(ctx.db, (await ctx.db.get(serverId))!))).toBe(3);

    // The figure the page shows moving is a write inside the read set.
    await t.mutation(internal.userStats.setFreeActive, { freeActive: 131 });
    expect(await snapshot(t, before.ids)).not.toEqual(snap);
    expect((await readPublicConfig(t)).result.billing.donation.freeUsersHelped).toBe(130);
  });

  test('before stats:publicImpact exists the figure falls back to the counter', async () => {
    const t = convexTest(schema, modules);
    await seedFreeTier(t);
    await t.run(async (ctx) => {
      await ctx.db.insert('appState', {
        key: USER_COUNTS_KEY,
        value: JSON.stringify({ freeActive: 57, initialized: true, runSeq: 1 }),
        updatedAt: Date.now(),
      });
    });
    expect((await readPublicConfig(t)).result.billing.donation.freeUsersHelped).toBe(50);
    const impact = await t.run((ctx) =>
      ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', PUBLIC_IMPACT_KEY))
        .unique(),
    );
    expect(impact).toBeNull();
  });
});

describe('backend server load and health live in side tables', () => {
  test('the healthcheck writes the health row; an exact key count (Outline) the load row', async () => {
    const t = convexTest(schema, modules);
    const serverId = await seedServer(t);
    const row0 = await t.run((ctx) => ctx.db.get(serverId));
    await t.mutation(internal.backendServers.markHealthy, {
      id: serverId,
      keyCount: 12,
      rttMs: 30,
    });
    await t.mutation(internal.backendServers.markFleetStats, {
      id: serverId,
      fleetStats: {
        onlineNow: 1,
        nodesOnline: 1,
        nodesTotal: 1,
        distinctCountries: 1,
        monthTrafficBytes: 0,
        lifetimeTrafficBytes: 0,
        panelVersion: '2.3.0',
      },
    });
    await t.run(async (ctx) => {
      const server = (await ctx.db.get(serverId))!;
      // The server row itself is untouched.
      expect(server).toEqual(row0);
      expect(await readKeyCount(ctx.db, server)).toBe(12);
      const h = await readHealth(ctx.db, server);
      expect(h.lastHealthRttMs).toBe(30);
      expect(h.lastHealthOkAt).toBeGreaterThan(0);
      expect(h.fleetStats?.panelVersion).toBe('2.3.0');
    });
  });

  test('legacy fields read until the migration moves them; the migration is idempotent', async () => {
    const t = convexTest(schema, modules);
    const okAt = Date.now() - 60_000;
    const serverId = await seedServer(t, { keyCount: 7, lastHealthOkAt: okAt });

    // Before the migration: the legacy fields are read in place.
    expect((await readPublicConfig(t)).result.locations).toEqual([
      expect.objectContaining({ code: 'MCI', online: true }),
    ]);
    // A bump before the migration starts from the legacy count.
    await t.mutation(internal.backendServers.bumpKeyCount, { id: serverId });

    expect(await t.mutation(internal.seed.migrateServerLoad, {})).toEqual({ moved: 1 });
    await t.run(async (ctx) => {
      const server = (await ctx.db.get(serverId))!;
      expect(server.keyCount).toBeUndefined();
      expect(server.lastHealthOkAt).toBeUndefined();
      // The load row written by the bump is newer than the legacy field: kept.
      expect(await readKeyCount(ctx.db, server)).toBe(8);
      expect((await readHealth(ctx.db, server)).lastHealthOkAt).toBe(okAt);
    });
    expect(await t.mutation(internal.seed.migrateServerLoad, {})).toEqual({ moved: 0 });
    expect((await readPublicConfig(t)).result.locations).toEqual([
      expect.objectContaining({ code: 'MCI', online: true }),
    ]);
  });

  test('removing a backend server drops its side rows', async () => {
    const t = convexTest(schema, modules);
    const serverId = await seedServer(t);
    await t.mutation(internal.backendServers.markHealthy, { id: serverId, keyCount: 0, rttMs: 30 });
    await t.mutation(internal.adminApi.deleteBackendServer, { id: serverId });
    await t.run(async (ctx) => {
      expect(await ctx.db.query('backendServerLoad').collect()).toEqual([]);
      expect(await ctx.db.query('backendServerHealth').collect()).toEqual([]);
    });
  });
});
