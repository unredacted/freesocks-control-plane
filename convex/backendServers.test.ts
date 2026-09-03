/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';

const modules = import.meta.glob('./**/*.*s');
type T = ReturnType<typeof convexTest>;

const UUID = '550e8400-e29b-41d4-a716-446655440000';

/** A schema-valid Remnawave user JSON for stubbed issue/get responses. */
function remnaUser(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    uuid: UUID,
    shortUuid: 'short1',
    username: 'u',
    status: 'ACTIVE',
    trafficLimitBytes: null,
    trafficLimitStrategy: 'MONTH',
    usedTrafficBytes: 0,
    expireAt: null,
    hwidDeviceLimit: null,
    subscriptionUrl: 'https://panel.test/sub/short1',
    ...over,
  };
}
function jsonRes(obj: unknown): Response {
  return new Response(JSON.stringify(obj), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

async function seedInstance(
  t: T,
  o: {
    backend?: 'remnawave' | 'outline';
    slug: string;
    keyCount?: number;
    priority?: number;
    isActive?: boolean;
    lastHealthOkAt?: number;
    lastHealthRttMs?: number;
    maxKeys?: number;
  },
): Promise<Id<'backendServers'>> {
  const backend = o.backend ?? 'remnawave';
  return t.run((ctx) =>
    ctx.db.insert('backendServers', {
      backend,
      name: o.slug,
      slug: o.slug,
      config:
        backend === 'remnawave'
          ? { type: 'remnawave', baseUrl: 'https://panel.test', apiToken: 'tok' }
          : { type: 'outline', apiUrl: 'https://outline.test/secret/', websocketEnabled: false },
      isActive: o.isActive ?? true,
      priority: o.priority ?? 0,
      keyCount: o.keyCount ?? 0,
      ...(o.maxKeys != null ? { maxKeys: o.maxKeys } : {}),
      ...(o.lastHealthOkAt != null ? { lastHealthOkAt: o.lastHealthOkAt } : {}),
      ...(o.lastHealthRttMs != null ? { lastHealthRttMs: o.lastHealthRttMs } : {}),
      updatedAt: Date.now(),
    }),
  );
}

afterEach(() => vi.unstubAllGlobals());

describe('pickCandidatesForIssue', () => {
  test('returns only active instances of the requested type, lowest load first', async () => {
    const t = convexTest(schema, modules);
    await seedInstance(t, { backend: 'remnawave', slug: 'rw-busy', keyCount: 5 });
    await seedInstance(t, { backend: 'remnawave', slug: 'rw-idle', keyCount: 1 });
    await seedInstance(t, { backend: 'remnawave', slug: 'rw-off', isActive: false });
    await seedInstance(t, { backend: 'outline', slug: 'ol-a' });

    const picks = await t.query(internal.backendServers.pickCandidatesForIssue, {
      backend: 'remnawave',
    });
    expect(picks.map((p) => p.slug)).toEqual(['rw-idle', 'rw-busy']);
    expect(picks.every((p) => p.backend === 'remnawave' && p.isActive)).toBe(true);
  });

  test('returns [] when no instance of the type exists', async () => {
    const t = convexTest(schema, modules);
    await seedInstance(t, { backend: 'remnawave', slug: 'rw-only' });
    expect(
      await t.query(internal.backendServers.pickCandidatesForIssue, { backend: 'outline' }),
    ).toEqual([]);
  });

  test('a probed-but-stale instance is preferred over a never-probed one (fallback)', async () => {
    const t = convexTest(schema, modules);
    const now = Date.now();
    // Neither is "fresh" (one probed >30min ago, one never probed), so the
    // no-fresh-instances fallback ranks them. The never-probed instance must NOT
    // win on a phantom rtt of 0 despite its lower key count — probed-ness sorts
    // first (regression guard for the `?? 0` scoring bug).
    await seedInstance(t, {
      slug: 'rw-probed-stale',
      keyCount: 9,
      lastHealthOkAt: now - 40 * 60_000,
      lastHealthRttMs: 40,
    });
    await seedInstance(t, { slug: 'rw-never-probed', keyCount: 0 });
    const picks = await t.query(internal.backendServers.pickCandidatesForIssue, {
      backend: 'remnawave',
    });
    expect(picks.map((p) => p.slug)).toEqual(['rw-probed-stale', 'rw-never-probed']);
  });

  test('maxKeys: an at-capacity instance is skipped; all-at-capacity returns []', async () => {
    const t = convexTest(schema, modules);
    await seedInstance(t, { slug: 'rw-full', keyCount: 10, maxKeys: 10 });
    await seedInstance(t, { slug: 'rw-room', keyCount: 999, maxKeys: 1000 });
    await seedInstance(t, { slug: 'rw-uncapped', keyCount: 5000 }); // no cap → always eligible
    const picks = await t.query(internal.backendServers.pickCandidatesForIssue, {
      backend: 'remnawave',
    });
    expect(picks.map((p) => p.slug).sort()).toEqual(['rw-room', 'rw-uncapped']);

    // Saturate everything → empty (the dispatch maps this to backend.unavailable).
    const t2 = convexTest(schema, modules);
    await seedInstance(t2, { slug: 'rw-a', keyCount: 3, maxKeys: 3 });
    await seedInstance(t2, { slug: 'rw-b', keyCount: 7, maxKeys: 5 }); // over-cap counts as full
    expect(
      await t2.query(internal.backendServers.pickCandidatesForIssue, { backend: 'remnawave' }),
    ).toEqual([]);
  });

  test('maxKeys: a full-but-fresh instance cannot win via the fresh window', async () => {
    const t = convexTest(schema, modules);
    const now = Date.now();
    // The only FRESH instance is full; the stale one has room. The capacity
    // filter runs before the fresh/fallback split, so the stale-with-room
    // instance must be picked rather than the fresh-but-full one.
    await seedInstance(t, {
      slug: 'rw-fresh-full',
      keyCount: 10,
      maxKeys: 10,
      lastHealthOkAt: now - 60_000,
      lastHealthRttMs: 20,
    });
    await seedInstance(t, {
      slug: 'rw-stale-room',
      keyCount: 2,
      lastHealthOkAt: now - 40 * 60_000,
      lastHealthRttMs: 30,
    });
    const picks = await t.query(internal.backendServers.pickCandidatesForIssue, {
      backend: 'remnawave',
    });
    expect(picks.map((p) => p.slug)).toEqual(['rw-stale-room']);
  });

  test('among fresh instances, lower measured rtt wins at equal load', async () => {
    const t = convexTest(schema, modules);
    const now = Date.now();
    await seedInstance(t, {
      slug: 'rw-fast',
      keyCount: 2,
      lastHealthOkAt: now - 60_000,
      lastHealthRttMs: 20,
    });
    await seedInstance(t, {
      slug: 'rw-slow',
      keyCount: 2,
      lastHealthOkAt: now - 60_000,
      lastHealthRttMs: 300,
    });
    const picks = await t.query(internal.backendServers.pickCandidatesForIssue, {
      backend: 'remnawave',
    });
    expect(picks.map((p) => p.slug)).toEqual(['rw-fast', 'rw-slow']);
  });
});

describe('admin CRUD (createBackendServer / updateBackendServer)', () => {
  test('creates a Remnawave instance and never echoes the token', async () => {
    const t = convexTest(schema, modules);
    const res = await t.mutation(internal.adminApi.createBackendServer, {
      backend: 'remnawave',
      name: 'RW',
      slug: 'rw-1',
      baseUrl: 'https://panel.test',
      apiToken: 'SUPER_SECRET',
    });
    expect(res.backend).toBe('remnawave');
    expect(res.config).toEqual({
      type: 'remnawave',
      baseUrl: 'https://panel.test',
      apiTokenSet: true,
    });
    expect(JSON.stringify(res)).not.toContain('SUPER_SECRET');
    const row = await t.run((ctx) => ctx.db.query('backendServers').first());
    expect(row!.config).toMatchObject({ type: 'remnawave', apiToken: 'SUPER_SECRET' });
  });

  test('creates an Outline instance and masks the secret apiUrl', async () => {
    const t = convexTest(schema, modules);
    const res = await t.mutation(internal.adminApi.createBackendServer, {
      backend: 'outline',
      name: 'OL',
      slug: 'ol-1',
      apiUrl: 'https://host:8443/secretpath',
    });
    expect(res.config).toMatchObject({ type: 'outline', apiUrlMasked: 'https://host:8443/***' });
    expect(JSON.stringify(res)).not.toContain('secretpath');
  });

  test('rejects a create missing the per-type required secret', async () => {
    const t = convexTest(schema, modules);
    await expect(
      t.mutation(internal.adminApi.createBackendServer, {
        backend: 'remnawave',
        name: 'x',
        slug: 'x1',
      }),
    ).rejects.toThrow(/base URL and an API token/);
    await expect(
      t.mutation(internal.adminApi.createBackendServer, {
        backend: 'outline',
        name: 'y',
        slug: 'y1',
      }),
    ).rejects.toThrow(/apiUrl/);
  });

  test('enforces slug uniqueness across backend types', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.adminApi.createBackendServer, {
      backend: 'remnawave',
      name: 'A',
      slug: 'dup',
      baseUrl: 'https://a',
      apiToken: 't',
    });
    await expect(
      t.mutation(internal.adminApi.createBackendServer, {
        backend: 'outline',
        name: 'B',
        slug: 'dup',
        apiUrl: 'https://b/secret',
      }),
    ).rejects.toThrow(/already exists/);
  });

  test('an edit keeps the stored secret when the field is blank, and rotates it when set', async () => {
    const t = convexTest(schema, modules);
    const created = await t.mutation(internal.adminApi.createBackendServer, {
      backend: 'remnawave',
      name: 'RW',
      slug: 'rw-u',
      baseUrl: 'https://a',
      apiToken: 'OLD',
    });
    const id = created.id as Id<'backendServers'>;
    // Edit a non-secret field only: token must be preserved.
    await t.mutation(internal.adminApi.updateBackendServer, { id, name: 'RW2' });
    let row = await t.run((ctx) => ctx.db.get(id));
    expect(row!.name).toBe('RW2');
    expect((row!.config as { apiToken: string }).apiToken).toBe('OLD');
    // Retyping the token rotates it.
    await t.mutation(internal.adminApi.updateBackendServer, { id, apiToken: 'NEW' });
    row = await t.run((ctx) => ctx.db.get(id));
    expect((row!.config as { apiToken: string }).apiToken).toBe('NEW');
  });
});

describe('generic dispatch (convex/backends.ts via the provider registry)', () => {
  test('issueUser picks an active instance, issues, returns + bumps its key count', async () => {
    const t = convexTest(schema, modules);
    const instanceId = await seedInstance(t, {
      backend: 'remnawave',
      slug: 'rw-issue',
      keyCount: 0,
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonRes(remnaUser())),
    );
    const issued = await t.action(internal.backends.issueUser, {
      backend: 'remnawave',
      spec: { username: 'u', trafficLimitBytes: null, expireAt: null, tag: 'free' },
    });
    expect(issued.backendUserId).toBe(UUID);
    expect(issued.backendServerId).toBe(instanceId);
    const row = await t.run((ctx) => ctx.db.get(instanceId));
    expect(row!.keyCount).toBe(1);
  });

  test('issueUser throws when no active instance of the type exists', async () => {
    const t = convexTest(schema, modules);
    await seedInstance(t, { backend: 'remnawave', slug: 'rw-x' });
    await expect(
      t.action(internal.backends.issueUser, {
        backend: 'outline',
        spec: { username: 'u', trafficLimitBytes: null, expireAt: null, tag: 'free' },
      }),
    ).rejects.toThrow(/backend\.unavailable/);
  });

  test('getUser resolves the instance from the subscription row by key', async () => {
    const t = convexTest(schema, modules);
    const instanceId = await seedInstance(t, { backend: 'remnawave', slug: 'rw-get' });
    await t.run(async (ctx) => {
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
        updatedAt: Date.now(),
      });
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: UUID,
        backendShortId: 'short1',
        backendServerId: instanceId,
        subscriptionUrl: 'https://panel.test/sub/short1',
        subscriptionMirrors: [],
        state: 'active',
        updatedAt: Date.now(),
      });
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL) => {
        const u = typeof input === 'string' ? input : input.toString();
        if (u.includes('/api/hwid/devices'))
          return jsonRes({ response: { total: 0, devices: [] } });
        return jsonRes(remnaUser({ status: 'LIMITED' }));
      }),
    );
    const state = await t.action(internal.backends.getUser, {
      backend: 'remnawave',
      backendUserId: UUID,
    });
    expect(state.status).toBe('limited');
  });
});

describe('migrateRemnawaveUserIds (2.x uuid → instance-scoped 3.x id)', () => {
  async function seedSubs(t: T, instanceId: Id<'backendServers'>) {
    return t.run(async (ctx) => {
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
      const mk = async (
        backendUserId: string,
        backendShortId: string,
        state: 'active' | 'deleted',
      ) => {
        const userId = await ctx.db.insert('users', {
          tierId,
          status: 'active',
          updatedAt: Date.now(),
        });
        return ctx.db.insert('subscriptions', {
          userId,
          backend: 'remnawave',
          backendUserId,
          backendShortId,
          backendServerId: instanceId,
          subscriptionUrl: `https://panel.test/sub/${backendShortId}`,
          subscriptionMirrors: [],
          state,
          updatedAt: Date.now(),
        });
      };
      return {
        legacy: await mk(UUID, 'sA', 'active'),
        scoped: await mk(`${instanceId}:9`, 'sB', 'active'),
        gone: await mk('550e8400-e29b-41d4-a716-446655440001', 'sGone', 'active'),
        deleted: await mk('550e8400-e29b-41d4-a716-446655440002', 'sDel', 'deleted'),
      };
    });
  }

  /** A panel stub: reports `version`, answers by-short-uuid from `byShort`. */
  function stubPanel(version: string, byShort: Record<string, number>) {
    const seen: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL) => {
        const path = new URL(String(input)).pathname;
        seen.push(path);
        if (path === '/api/system/stats')
          return jsonRes({
            response: {
              onlineStats: { onlineNow: 0 },
              nodes: { totalOnline: 0, totalBytesLifetime: '0' },
            },
          });
        if (path === '/api/system/stats/recap')
          return jsonRes({
            response: {
              thisMonth: { traffic: '0' },
              total: { nodes: 0, traffic: '0', distinctCountries: 0 },
              version,
            },
          });
        const m = /^\/api\/users\/by-short-uuid\/(.+)$/.exec(path);
        if (m && byShort[m[1]!] != null) {
          const { uuid: _u, ...rest } = remnaUser({ shortUuid: m[1] });
          void _u;
          return jsonRes({ response: { ...rest, id: byShort[m[1]!] } });
        }
        return new Response(null, { status: 404 });
      }),
    );
    return seen;
  }

  test('remaps legacy uuid keys on a 3.x panel, skips scoped/deleted rows, counts the missing', async () => {
    const t = convexTest(schema, modules);
    const instanceId = await seedInstance(t, { slug: 'rw-3x' });
    const subs = await seedSubs(t, instanceId);
    stubPanel('3.4.2', { sA: 5 });

    // Dry run: full report, nothing written.
    const dry = await t.action(internal.backendServers.migrateRemnawaveUserIds, { dryRun: true });
    expect(dry.dryRun).toBe(true);
    expect(dry.servers).toHaveLength(1);
    expect(dry.servers[0]).toMatchObject({
      panelVersion: '3.4.2',
      scanned: 4,
      legacy: 2, // uuid + gone (the deleted row and the scoped row are skipped)
      remapped: 1,
      missing: 1,
      failed: 0,
      complete: true,
    });
    await t.run(async (ctx) => {
      expect((await ctx.db.get(subs.legacy))!.backendUserId).toBe(UUID);
    });

    // Real run: the legacy key is re-keyed to the instance-scoped numeric id.
    const real = await t.action(internal.backendServers.migrateRemnawaveUserIds, {});
    expect(real.servers[0]).toMatchObject({ remapped: 1, missing: 1, conflicts: 0 });
    await t.run(async (ctx) => {
      expect((await ctx.db.get(subs.legacy))!.backendUserId).toBe(`${instanceId}:5`);
      expect((await ctx.db.get(subs.scoped))!.backendUserId).toBe(`${instanceId}:9`);
      // The panel-unknown key is left for the operator, untouched.
      expect((await ctx.db.get(subs.gone))!.backendUserId).toBe(
        '550e8400-e29b-41d4-a716-446655440001',
      );
      const audit = await ctx.db.query('auditLog').collect();
      const row = audit.find((a) => a.action === 'admin.remnawave.user_ids_migrated');
      expect(row).toBeTruthy();
      expect(row!.payload).toMatchObject({ remapped: 1, missing: 1 });
    });

    // Rerun is a no-op for the migrated row (only the missing one is still legacy).
    const again = await t.action(internal.backendServers.migrateRemnawaveUserIds, {});
    expect(again.servers[0]).toMatchObject({ legacy: 1, remapped: 0, missing: 1 });
  });

  test('a panel still on 2.x is skipped: its uuids are correct as they are', async () => {
    const t = convexTest(schema, modules);
    const instanceId = await seedInstance(t, { slug: 'rw-2x' });
    const subs = await seedSubs(t, instanceId);
    const seen = stubPanel('2.8.1', { sA: 5 });
    const res = await t.action(internal.backendServers.migrateRemnawaveUserIds, {});
    expect(res.servers[0]!.skipped).toMatch(/not 3\.x/);
    expect(seen.some((p) => p.includes('by-short-uuid'))).toBe(false);
    await t.run(async (ctx) => {
      expect((await ctx.db.get(subs.legacy))!.backendUserId).toBe(UUID);
    });
  });

  test('refuses to remap onto an id another row already holds (index stays unique)', async () => {
    const t = convexTest(schema, modules);
    const instanceId = await seedInstance(t, { slug: 'rw-dup' });
    const subs = await seedSubs(t, instanceId);
    // The panel claims the legacy key is user 9 — but `${instanceId}:9` is already
    // held by another row. Never clobber: report a conflict.
    stubPanel('3.4.2', { sA: 9 });
    const res = await t.action(internal.backendServers.migrateRemnawaveUserIds, {});
    expect(res.servers[0]).toMatchObject({ remapped: 0, conflicts: 1 });
    await t.run(async (ctx) => {
      expect((await ctx.db.get(subs.legacy))!.backendUserId).toBe(UUID);
    });
  });
});
