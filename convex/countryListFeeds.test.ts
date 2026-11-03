/// <reference types="vite/client" />
/**
 * Country lists into finding names (docs/edges.md "Names into finding names",
 * convex/countryListFeeds.ts, countryListFacts.ts):
 *
 *  - a feed added after a version is in use takes that version (the backfill);
 *  - a run behind the list's version stops, and the new version runs again;
 *  - a capped feed is tried again once its scope has room;
 *  - list facts are stored on candidates and family names and follow every
 *    change (a version, a list switched off, the switch off);
 *  - a family name only a block list holds gets a suggestion the page shows
 *    and Apply records as the operator's mark.
 *
 * Fixtures use example names and documentation ranges only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { signValue } from './lib/cookies';
import { splitUploadParts } from '../src/shared/contracts/countryLists';

const modules = import.meta.glob('./**/*.*s');
const ADMIN_SIGN_KEY = 'test-admin-sign';
const DAY = 24 * 60 * 60_000;
type T = TestConvex<typeof schema>;
type ListId = Id<'countryLists'>;

beforeEach(() => {
  vi.useFakeTimers({
    toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'],
  });
  vi.setSystemTime(Date.UTC(2026, 10, 2, 12));
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', ADMIN_SIGN_KEY);
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
});

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

async function seed() {
  const t = convexTest(schema, modules);
  await setting(t, 'edge.lists.enabled', true);
  const networkId = await t.run((ctx) =>
    ctx.db.insert('edgeNetworks', {
      slug: 'net-a',
      label: 'Net A',
      asns: [64500],
      announced: { v4: [], v6: [] },
      manualPrefixes: ['192.0.2.0/24'],
      prefixes: { v4: ['192.0.2.0/24'], v6: [] },
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
  await t.mutation(internal.sessions.create, { sid, kind: 'admin', adminUserId, ttlMs: 400 * DAY });
  const cookie = `fs_admin_session=${await signValue(sid, ADMIN_SIGN_KEY)}`;
  const call = async (method: string, path: string, body?: unknown) => {
    const res = await t.fetch(`/api/v1/admin/edges/${path}`, {
      method,
      headers: { cookie, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: res.status, body: (await res.json()) as Record<string, unknown> };
  };
  const create = async (regime: 'allowlist' | 'blocklist' = 'allowlist') =>
    (
      await call('POST', 'lists', {
        label: regime === 'allowlist' ? 'Works' : 'Blocked',
        country: 'RU',
        regime,
        source: { kind: 'paste' },
      })
    ).body.id as ListId;
  /** Paste, read, and run what a publication schedules (history, facts, feeds). */
  const paste = async (listId: ListId, text: string) => {
    const { body } = await call('POST', `lists/${listId}/uploads`, {});
    const uploadId = body.uploadId as Id<'countryListUploads'>;
    for (const [index, part] of splitUploadParts(text).entries())
      await call('POST', `lists/${listId}/uploads/${uploadId}/parts`, { index, text: part });
    await call('POST', `lists/${listId}/uploads/${uploadId}/finish`, {});
    return t.action(internal.countryListOps.ingest, { listId, uploadId });
  };
  const list = (listId: ListId) => t.run((ctx) => ctx.db.get(listId));
  const approve = async (listId: ListId) => {
    const l = (await list(listId))!;
    await call('POST', `lists/${listId}/versions/${l.heldVersionId}/approve`, {});
    await t.mutation(internal.countryLists.afterPublish, {
      versionId: (await list(listId))!.activeVersionId!,
    });
  };
  const runs = (listId: ListId) =>
    t.run((ctx) =>
      ctx.db
        .query('countryListFeedRuns')
        .withIndex('by_list_feed', (q) => q.eq('listId', listId))
        .collect(),
    );
  /** Step every running run until none is left. */
  const feed = async (listId: ListId) => {
    for (let i = 0; i < 20; i++) {
      const running = (await runs(listId)).filter((r) => r.state === 'running');
      if (running.length === 0) return;
      for (const r of running)
        await t.mutation(internal.countryListFeeds.feedStep, { runId: r._id, gen: r.gen });
    }
  };
  const candidates = () =>
    t.run((ctx) =>
      ctx.db
        .query('sniCandidates')
        .withIndex('by_scope_base', (q) => q.eq('networkId', networkId).eq('familyId', undefined))
        .collect(),
    );
  const refresh = async () => {
    for (let i = 0; i < 10; i++) {
      const a = await t.mutation(internal.countryListFacts.refresh, { table: 'sniCandidates' });
      const b = await t.mutation(internal.countryListFacts.refresh, { table: 'sniNames' });
      if (a.rows === 0 && b.rows === 0) return;
    }
  };
  return { t, call, create, paste, approve, runs, feed, candidates, refresh, list, networkId };
}

const NAMES = 'alpha.example.com\nbeta.example.com\n*.example.org\n192.0.2.0/24\n';

describe('feeds', () => {
  test('a feed added after a version is in use takes that version', async () => {
    const { call, create, paste, approve, feed, candidates, runs } = await seed();
    const id = await create();
    await paste(id, NAMES);
    await approve(id);
    expect(await runs(id)).toEqual([]);
    const r = await call('POST', `lists/${id}/feeds`, { feeds: [{ network: 'net-a' }] });
    expect(r.body).toEqual({ ok: true, started: 1 });
    await feed(id);
    const rows = await candidates();
    expect(rows.map((c) => [c.name, c.sources]).sort()).toEqual([
      ['alpha.example.com', ['list']],
      ['beta.example.com', ['list']],
    ]);
    const [run] = await runs(id);
    expect(run).toMatchObject({ state: 'done', counts: { added: 2, wildcards: 1, capped: 0 } });
    const view = (await call('GET', `lists/${id}`)).body as {
      list: { feeds: Array<{ slug: string; run: { counts: { added: number } } }> };
    };
    expect(view.list.feeds[0]).toMatchObject({ slug: 'net-a', run: { counts: { added: 2 } } });
  });

  test('a run behind the list stops; the new version runs again', async () => {
    const { t, call, create, paste, approve, feed, candidates, runs, list } = await seed();
    const id = await create();
    await paste(id, NAMES);
    await approve(id);
    await call('POST', `lists/${id}/feeds`, { feeds: [{ network: 'net-a' }] });
    const [first] = await runs(id);
    // A new version goes into use before the run stepped.
    expect(await paste(id, `${NAMES}gamma.example.com\n`)).toBe('published');
    await t.mutation(internal.countryListFeeds.feedStep, { runId: first!._id, gen: first!.gen });
    expect((await runs(id)).find((r) => r._id === first!._id)).toMatchObject({
      state: 'stopped',
      stopped: 'superseded',
    });
    await t.mutation(internal.countryLists.afterPublish, {
      versionId: (await list(id))!.activeVersionId!,
    });
    await feed(id);
    expect((await candidates()).map((c) => c.name).sort()).toEqual([
      'alpha.example.com',
      'beta.example.com',
      'gamma.example.com',
    ]);
  });

  test('a capped feed is tried again once its scope has room', async () => {
    const { t, call, create, paste, approve, feed, runs, networkId } = await seed();
    const scopeId = await t.run((ctx) =>
      ctx.db.insert('sniHuntScopes', {
        networkId,
        kind: 'network',
        total: 2000,
        ready: 0,
        updatedAt: Date.now(),
      }),
    );
    const id = await create();
    await paste(id, NAMES);
    await approve(id);
    await call('POST', `lists/${id}/feeds`, { feeds: [{ network: 'net-a' }] });
    await feed(id);
    expect((await runs(id))[0]).toMatchObject({ state: 'done', counts: { added: 0, capped: 2 } });
    // Still full: nothing is tried again.
    await t.mutation(internal.countryLists.sweep, {});
    expect((await runs(id)).filter((r) => r.state === 'running')).toEqual([]);
    await t.run((ctx) => ctx.db.patch(scopeId, { total: 10 }));
    await t.mutation(internal.countryLists.sweep, {});
    expect((await runs(id)).filter((r) => r.state === 'running')).toHaveLength(1);
    await feed(id);
    expect((await runs(id)).at(-1)).toMatchObject({ state: 'done', counts: { added: 2 } });
  });

  test('removing a feed stops its run; candidates stay', async () => {
    const { call, create, paste, approve, runs, feed, candidates } = await seed();
    const id = await create();
    await paste(id, NAMES);
    await approve(id);
    await call('POST', `lists/${id}/feeds`, { feeds: [{ network: 'net-a' }] });
    await call('POST', `lists/${id}/feeds`, { feeds: [] });
    expect((await runs(id))[0]).toMatchObject({ state: 'stopped', stopped: 'feed_removed' });
    await feed(id);
    expect(await candidates()).toEqual([]);
    expect((await call('POST', `lists/${id}/feeds/again`, {})).body).toMatchObject({
      error: { code: 'edge.list.no_feeds' },
    });
  });
});

describe('stored facts', () => {
  test('follow a version, a list switched off, and the switch', async () => {
    const { t, call, create, paste, approve, feed, candidates, refresh } = await seed();
    const id = await create();
    await paste(id, NAMES);
    await approve(id);
    await call('POST', `lists/${id}/feeds`, { feeds: [{ network: 'net-a' }] });
    await feed(id);
    await refresh();
    const factsOf = async () =>
      Object.fromEntries((await candidates()).map((c) => [c.name, c.onLists ?? null]));
    expect(await factsOf()).toEqual({
      'alpha.example.com': [{ listId: id, cc: 'RU', regime: 'allowlist' }],
      'beta.example.com': [{ listId: id, cc: 'RU', regime: 'allowlist' }],
    });
    // The score reads them: 0.75 for RU among the curated countries.
    const scope = await t.run((ctx) => ctx.db.query('sniHuntScopes').first());
    expect(scope?.dirty).toBe(true);
    await call('PATCH', `lists/${id}`, { enabled: false });
    await refresh();
    expect(await factsOf()).toEqual({ 'alpha.example.com': null, 'beta.example.com': null });
    await call('PATCH', `lists/${id}`, { enabled: true });
    await refresh();
    expect((await factsOf())['alpha.example.com']).toHaveLength(1);
    await t.mutation(internal.edgeAdmin.patchConfig, { patch: { 'lists.enabled': false } });
    await refresh();
    expect((await factsOf())['alpha.example.com']).toBeNull();
  });

  test('a list turning stale moves them at the daily sweep', async () => {
    const { t, call, create, paste, approve, feed, candidates, refresh } = await seed();
    const id = await create();
    await paste(id, NAMES);
    await approve(id);
    await call('POST', `lists/${id}/feeds`, { feeds: [{ network: 'net-a' }] });
    await feed(id);
    await t.mutation(internal.countryLists.sweep, {});
    await refresh();
    expect((await candidates())[0]!.onLists).toHaveLength(1);
    vi.setSystemTime(Date.now() + 31 * DAY);
    await t.mutation(internal.countryLists.sweep, {});
    await refresh();
    expect((await candidates())[0]!.onLists).toBeUndefined();
  });
});

describe('a block list on a family name', () => {
  test('the page suggests blocked, and Apply records it as the operator’s mark', async () => {
    const { t, create, paste, approve, refresh } = await seed();
    await t.mutation(internal.sniFamilies.create, {
      slug: 'fam-a',
      label: 'Family A',
      targetAddress: 'target.example.com',
      targetPort: 443,
    });
    await t.mutation(internal.sniFamilies.importNames, {
      slug: 'fam-a',
      lines: ['x.example.com', 'y.example.com'],
    });
    const id = await create('blocklist');
    await paste(id, 'x.example.com\n');
    await approve(id);
    await refresh();
    const detail = await t.query(internal.sniFamilies.detail, { slug: 'fam-a' });
    const x = detail.names.find((n) => n.name === 'x.example.com')!;
    expect(x.onLists).toEqual([{ cc: 'RU', regime: 'blocklist', label: 'Blocked' }]);
    expect(x.vantage).toEqual([
      expect.objectContaining({
        country: 'RU',
        latest: 'none',
        suggestion: 'blocked',
        provenance: 'list',
        decision: 'suggest',
      }),
    ]);
    expect(detail.names.find((n) => n.name === 'y.example.com')!.vantage).toEqual([]);
    const r = await t.mutation(internal.sniVantage.applySuggestions, {
      slug: 'fam-a',
      names: ['x.example.com', 'y.example.com'],
      country: 'RU',
    });
    expect(r).toEqual({ proven: 0, blocked: 1, skipped: 1 });
    const marks = await t.run((ctx) => ctx.db.query('sniNameCountry').collect());
    expect(marks.map((m) => [m.name, m.country, m.state, m.source])).toEqual([
      ['x.example.com', 'RU', 'blocked', 'operator'],
    ]);
  });
});
