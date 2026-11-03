/// <reference types="vite/client" />
/**
 * Edge addresses against watched allowlists (docs/edges.md "Edge addresses
 * against allowlists", convex/countryListEdges.ts):
 *
 *  - a mark checked against an older version reads "not checked yet";
 *  - listed, then not listed, raises `list_address_left`, which stays across
 *    hourly rechecks; never listed raises nothing;
 *  - "Seen it" hides it until the address is listed again and leaves again;
 *  - a new address starts the mark over;
 *  - a stale or unwatched list raises nothing;
 *  - retention keeps a version a mark was checked against, and a removed
 *    list or a gone edge takes its marks along.
 *
 * Fixtures use example names and documentation ranges only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { signValue } from './lib/cookies';
import { seedEdgeFixture } from './lib/edges/testing/fixtures';
import { splitUploadParts } from '../src/shared/contracts/countryLists';

const modules = import.meta.glob('./**/*.*s');
const ADMIN_SIGN_KEY = 'test-admin-sign';
const MIN = 60_000;
const DAY = 24 * 60 * MIN;
type T = TestConvex<typeof schema>;
type ListId = Id<'countryLists'>;

beforeEach(() => {
  vi.useFakeTimers({
    toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'],
  });
  vi.setSystemTime(Date.UTC(2026, 10, 3, 12));
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', ADMIN_SIGN_KEY);
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
});

const later = (ms = MIN) => vi.setSystemTime(Date.now() + ms);

async function setting(t: T, key: string, value: unknown) {
  await t.run(async (ctx) => {
    const row = await ctx.db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', key))
      .unique();
    if (row) await ctx.db.patch(row._id, { value: JSON.stringify(value) });
    else
      await ctx.db.insert('appSettings', {
        key,
        value: JSON.stringify(value),
        updatedAt: Date.now(),
      });
  });
}

const IN = '192.0.2.0/24\nalpha.example.com\n';
const OUT = '198.51.100.0/24\nalpha.example.com\n';

async function seed() {
  const t = convexTest(schema, modules);
  await setting(t, 'edge.lists.enabled', true);
  const f = await seedEdgeFixture(t);
  const edgeId = await t.run((ctx) =>
    ctx.db.insert('edges', {
      relayId: f.relayId,
      listenerId: f.listenerId,
      provider: 'gcore',
      managed: true,
      name: 'e1',
      steps: [],
      resources: [],
      listeners: [{ edgePort: 443, originAddress: '203.0.113.10', originPort: 443 }],
      addresses: { v4: '192.0.2.10', v6: '2001:db8::10' },
      layer: 'l4',
      publication: 'published',
      status: 'active',
      statusChangedAt: Date.now(),
      health: 'online',
      destroyAttempts: 0,
      updatedAt: Date.now(),
    }),
  );
  const adminUserId = await t.run((ctx) =>
    ctx.db.insert('adminUsers', {
      username: 'op',
      displayName: 'Op',
      isActive: true,
      updatedAt: Date.now(),
    }),
  );
  const sid = `asid-${Math.random().toString(36).slice(2)}`;
  await t.mutation(internal.sessions.create, { sid, kind: 'admin', adminUserId, ttlMs: 900 * DAY });
  const cookie = `fs_admin_session=${await signValue(sid, ADMIN_SIGN_KEY)}`;
  const call = async (method: string, path: string, body?: unknown) => {
    const res = await t.fetch(`/api/v1/admin/edges/${path}`, {
      method,
      headers: { cookie, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: res.status, body: (await res.json()) as Record<string, unknown> };
  };
  const create = async (watchEdges = true) =>
    (
      await call('POST', 'lists', {
        label: 'Works',
        country: 'RU',
        regime: 'allowlist',
        source: { kind: 'paste' },
        watchEdges,
      })
    ).body.id as ListId;
  const list = (listId: ListId) => t.run((ctx) => ctx.db.get(listId));
  /** Paste a version, use it (every version here waits: the first, or a wholesale change), and publish. */
  const publish = async (listId: ListId, text: string) => {
    const { body } = await call('POST', `lists/${listId}/uploads`, {});
    const uploadId = body.uploadId as Id<'countryListUploads'>;
    for (const [index, part] of splitUploadParts(text).entries())
      await call('POST', `lists/${listId}/uploads/${uploadId}/parts`, { index, text: part });
    await call('POST', `lists/${listId}/uploads/${uploadId}/finish`, {});
    await t.action(internal.countryListOps.ingest, { listId, uploadId });
    const held = (await list(listId))!.heldVersionId;
    if (held) await call('POST', `lists/${listId}/versions/${held}/approve`, {});
    await t.mutation(internal.countryLists.afterPublish, {
      versionId: (await list(listId))!.activeVersionId!,
    });
  };
  /** One recheck as the chain runs it (the fixture's edges fit one page). */
  const recheck = async () => {
    await t.mutation(internal.countryListEdges.recheck, { phase: 'edges' });
    await t.mutation(internal.countryListEdges.recheck, { phase: 'marks' });
  };
  const marks = async () => {
    const r = await call('GET', `lists/marks?edge=${edgeId}`);
    return r.body as {
      lists: Array<{
        listId: string;
        checked: boolean;
        addresses: Array<{
          family: string;
          state: string;
          markId: string | null;
          needsLook: boolean;
        }>;
      }>;
    };
  };
  const stateOf = async (family: 'v4' | 'v6') =>
    (await marks()).lists[0]?.addresses.find((a) => a.family === family)?.state;
  const leftItems = async () =>
    (await t.query(internal.edgeOperator.attention, {})).items.filter(
      (i) => i.kind === 'list_address_left',
    );
  return { t, f, edgeId, call, create, list, publish, recheck, marks, stateOf, leftItems };
}

describe('marks', () => {
  test('listed, then gone: the item stays across rechecks; never listed raises nothing', async () => {
    const s = await seed();
    const id = await s.create();
    await s.publish(id, IN);
    await s.recheck();
    expect(await s.stateOf('v4')).toBe('listed');
    expect(await s.stateOf('v6')).toBe('not_listed');
    expect(await s.leftItems()).toEqual([]);

    later();
    await s.publish(id, OUT);
    // Checked against the version before: not checked yet.
    expect(await s.stateOf('v4')).toBe('checking');
    await s.recheck();
    expect(await s.stateOf('v4')).toBe('left');
    expect(await s.stateOf('v6')).toBe('not_listed');
    const items = await s.leftItems();
    expect(items.map((i) => i.id)).toEqual([`list_address_left:${s.edgeId}:${id}:v4`]);
    expect(items[0]).toMatchObject({
      severity: 'warning',
      action: 'open_edge',
      edgeId: s.edgeId,
      facts: { list: 'Works', country: 'RU', addressFamily: 'v4' },
    });

    // The hourly pass looks again: nothing changed, the item stays.
    later(60 * MIN);
    await s.t.mutation(internal.countryListEdges.kick, {});
    await s.recheck();
    expect((await s.leftItems()).length).toBe(1);
    expect((await s.call('GET', `lists/${id}`)).body.edges).toEqual({
      listed: 0,
      not_listed: 1,
      left: 1,
      checking: 0,
    });
  });

  test('Seen it hides the item until the address is listed again and leaves again', async () => {
    const s = await seed();
    const id = await s.create();
    await s.publish(id, IN);
    await s.recheck();
    later();
    await s.publish(id, OUT);
    await s.recheck();
    const v4 = (await s.marks()).lists[0]!.addresses.find((a) => a.family === 'v4')!;
    expect(v4.needsLook).toBe(true);
    // Only an address that left can be seen.
    const v6 = (await s.marks()).lists[0]!.addresses.find((a) => a.family === 'v6')!;
    expect((await s.call('POST', `lists/${id}/marks/${v6.markId}/seen`, {})).status).toBe(409);
    later();
    expect((await s.call('POST', `lists/${id}/marks/${v4.markId}/seen`, {})).status).toBe(200);
    expect(await s.leftItems()).toEqual([]);
    later(60 * MIN);
    await s.recheck();
    expect(await s.leftItems()).toEqual([]);

    later();
    await s.publish(id, IN);
    await s.recheck();
    expect(await s.stateOf('v4')).toBe('listed');
    later();
    await s.publish(id, OUT);
    await s.recheck();
    expect((await s.leftItems()).length).toBe(1);
  });

  test('a new address starts the mark over', async () => {
    const s = await seed();
    const id = await s.create();
    await s.publish(id, IN);
    await s.recheck();
    later();
    await s.publish(id, OUT);
    await s.recheck();
    expect((await s.leftItems()).length).toBe(1);
    later();
    await s.t.run((ctx) => ctx.db.patch(s.edgeId, { addresses: { v4: '198.51.100.5' } }));
    // Not checked under the new address yet, and the old address's item is gone.
    expect(await s.stateOf('v4')).toBe('checking');
    expect(await s.leftItems()).toEqual([]);
    await s.recheck();
    expect(await s.stateOf('v4')).toBe('listed');
    const rows = await s.t.run((ctx) =>
      ctx.db
        .query('countryListEdgeMarks')
        .withIndex('by_edge', (q) => q.eq('edgeId', s.edgeId))
        .collect(),
    );
    // The address lost its IPv6: that mark went.
    expect(rows.map((r) => [r.family, r.address, r.leftAt ?? null, r.firstListedAt])).toEqual([
      ['v4', '198.51.100.5', null, Date.now()],
    ]);
  });

  test('a stale, unwatched or switched-off list raises nothing', async () => {
    const s = await seed();
    const id = await s.create();
    await s.publish(id, IN);
    await s.recheck();
    later();
    await s.publish(id, OUT);
    await s.recheck();
    expect((await s.leftItems()).length).toBe(1);

    await setting(s.t, 'edge.lists.enabled', false);
    expect(await s.leftItems()).toEqual([]);
    expect((await s.marks()).lists[0]!.checked).toBe(false);
    await setting(s.t, 'edge.lists.enabled', true);

    expect((await s.call('PATCH', `lists/${id}`, { watchEdges: false })).status).toBe(200);
    expect(await s.leftItems()).toEqual([]);
    expect((await s.marks()).lists).toEqual([]);
    await s.call('PATCH', `lists/${id}`, { watchEdges: true });
    expect((await s.leftItems()).length).toBe(1);

    // Past the stale window without a word from the source.
    later(31 * DAY);
    expect(await s.leftItems()).toEqual([]);
  });

  test('only an allowlist watches edge addresses', async () => {
    const s = await seed();
    const r = await s.call('POST', 'lists', {
      label: 'Blocked',
      country: 'RU',
      regime: 'blocklist',
      source: { kind: 'paste' },
      watchEdges: true,
    });
    expect(r.status).toBe(409);
    expect((r.body.error as { code: string }).code).toBe('edge.list.watch_allowlist_only');
    const id = await s.create();
    await s.call('PATCH', `lists/${id}`, { regime: 'blocklist' });
    expect((await s.list(id))!.watchEdges).toBe(false);
  });

  test('the chain runs to the end from a kick', async () => {
    const s = await seed();
    const id = await s.create();
    await s.publish(id, IN);
    await s.t.finishAllScheduledFunctions(vi.runAllTimers);
    expect(await s.stateOf('v4')).toBe('listed');
  });
});

describe('cleanup and retention', () => {
  test('a gone edge, a removed list: their marks go', async () => {
    const s = await seed();
    const id = await s.create();
    await s.publish(id, IN);
    await s.recheck();
    const count = () =>
      s.t.run(async (ctx) => (await ctx.db.query('countryListEdgeMarks').collect()).length);
    expect(await count()).toBe(2);
    await s.t.run((ctx) => ctx.db.patch(s.edgeId, { status: 'destroyed' }));
    await s.recheck();
    expect(await count()).toBe(0);

    await s.t.run((ctx) => ctx.db.patch(s.edgeId, { status: 'active' }));
    await s.recheck();
    expect(await count()).toBe(2);
    await s.call('DELETE', `lists/${id}`);
    await s.t.mutation(internal.countryLists.purgeList, { listId: id });
    expect(await count()).toBe(0);
  });

  test('a version a mark was checked against is kept past the retention window', async () => {
    const s = await seed();
    const id = await s.create();
    await s.publish(id, IN);
    await s.recheck();
    const first = (await s.list(id))!.activeVersionId!;
    // No longer watched: its marks stay, checked against the first version.
    await s.call('PATCH', `lists/${id}`, { watchEdges: false });
    later();
    await s.publish(id, OUT);
    later(11 * MIN);
    await s.t.mutation(internal.countryLists.dropVersion, { versionId: first });
    expect((await s.t.run((ctx) => ctx.db.get(first)))?.cleanedAt).toBeDefined();
    later(181 * DAY);
    await s.t.mutation(internal.countryLists.sweep, {});
    expect(await s.t.run((ctx) => ctx.db.get(first))).not.toBeNull();
    // Once no mark names it, it goes.
    await s.t.run(async (ctx) => {
      for (const m of await ctx.db.query('countryListEdgeMarks').collect())
        await ctx.db.delete(m._id);
    });
    await s.t.mutation(internal.countryLists.sweep, {});
    expect(await s.t.run((ctx) => ctx.db.get(first))).toBeNull();
  });
});
