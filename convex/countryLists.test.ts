/// <reference types="vite/client" />
/**
 * Country lists (docs/edges.md "Country lists", convex/countryLists.ts,
 * countryListOps.ts):
 *
 *  - a paste goes up in parts small enough for one sealed request each, and
 *    a fetch is stubbed here (pinnedFetch.test.ts covers the real one);
 *  - a version is staged under its own id and published by one pointer move:
 *    a reader never sees names of a version still being written;
 *  - a version that looks wrong waits for a person; a decision on a version
 *    whose base moved on is refused;
 *  - old versions go after a grace, crashed staging is failed by the sweep,
 *    and retention never deletes a version a list still points at;
 *  - evidence reads only enabled, fresh lists, and nothing while switched off.
 *
 * Fixtures use example names, documentation ranges and private ASNs only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { signValue } from './lib/cookies';
import { MAX_BODY_BYTES } from './lib/http';
import { __setListFetchForTests } from './countryListOps';
import { scopeFor, throttlePolicyFor } from './httpEdges';
import { CLEANUP_GRACE_MS } from './countryLists';
import { listFactsFor } from './lib/edges/lists/facts';
import type { PinnedFetchResult } from './lib/edges/lists/pinnedFetch';
import {
  CountryListDetail,
  CountryListLookup,
  CountryListsResponse,
  splitUploadParts,
  UPLOAD_PART_BYTES,
} from '../src/shared/contracts/countryLists';
import { bytesToB64Url, kidFromPublicKey, routePolicy } from '../src/shared/crypto/envelope';
import { serializePublicKey, serverKeyPairFromSeed } from '../src/shared/crypto/hpke';
import { clientPrepareRequest } from '../src/shared/crypto/channel';

const modules = import.meta.glob('./**/*.*s');
const ADMIN_SIGN_KEY = 'test-admin-sign';
const MIN = 60_000;
const DAY = 24 * 60 * MIN;
type T = TestConvex<typeof schema>;
type ListId = Id<'countryLists'>;

beforeEach(() => {
  // Scheduled follow-ups never run on their own here; the tests run them.
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
  __setListFetchForTests(null);
  vi.useRealTimers();
  vi.unstubAllEnvs();
});

const advance = (ms: number) => vi.setSystemTime(Date.now() + ms);

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
  const adminUserId = await t.run((ctx) =>
    ctx.db.insert('adminUsers', {
      username: 'op',
      displayName: 'Op',
      isActive: true,
      updatedAt: Date.now(),
    }),
  );
  const sid = `asid-${Math.random().toString(36).slice(2)}`;
  // The tests move the clock by months.
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
  const create = async (over: Record<string, unknown> = {}) => {
    const r = await call('POST', 'lists', {
      label: 'Mobile',
      country: 'ru',
      regime: 'allowlist',
      source: { kind: 'paste' },
      ...over,
    });
    expect(r.status).toBe(200);
    return r.body.id as ListId;
  };
  /** Paste text through the routes, then run the ingest the finish scheduled. */
  const paste = async (listId: ListId, text: string, partBytes?: number) => {
    const started = await call('POST', `lists/${listId}/uploads`, {});
    expect(started.status).toBe(200);
    const uploadId = started.body.uploadId as Id<'countryListUploads'>;
    const parts = splitUploadParts(text, partBytes);
    for (const [index, part] of parts.entries()) {
      const r = await call('POST', `lists/${listId}/uploads/${uploadId}/parts`, {
        index,
        text: part,
      });
      expect(r.status).toBe(200);
    }
    expect((await call('POST', `lists/${listId}/uploads/${uploadId}/finish`, {})).status).toBe(200);
    return t.action(internal.countryListOps.ingest, { listId, uploadId });
  };
  const detail = async (listId: ListId) => {
    const r = await call('GET', `lists/${listId}`);
    if (r.status !== 200)
      throw new Error(`GET lists/${listId}: ${r.status} ${JSON.stringify(r.body)}`);
    return CountryListDetail.parse(r.body);
  };
  const lookup = async (entries: string[]) =>
    CountryListLookup.parse((await call('POST', 'lists/lookup', { entries })).body).results;
  const approve = (listId: ListId, versionId: string) =>
    call('POST', `lists/${listId}/versions/${versionId}/approve`, {});
  return { t, call, cookie, create, paste, detail, lookup, approve };
}

const V1 = ['example.com', '*.example.org', '192.0.2.0/24', '2001:db8::/48'].join('\n');

describe('sources', () => {
  test('an address must be https on 443 with no user and no private address', async () => {
    const { call, create } = await seed();
    for (const url of [
      'http://example.com/list.txt',
      'https://10.0.0.1/list.txt',
      'https://user:pw@example.com/list.txt',
      'https://example.com:8443/list.txt',
    ]) {
      const r = await call('POST', 'lists', {
        label: 'A',
        country: 'RU',
        regime: 'allowlist',
        source: { kind: 'url', url },
      });
      expect(r.status).toBe(400);
      expect(r.body).toMatchObject({ error: { code: 'edge.list.bad_url' } });
    }
    const bad = await call('POST', 'lists', {
      label: 'A',
      country: 'RU',
      regime: 'maybe',
      source: { kind: 'paste' },
    });
    expect(bad.status).toBe(400);
    const id = await create({ source: { kind: 'url', url: 'https://example.com/list.txt#x' } });
    const lists = CountryListsResponse.parse((await call('GET', 'lists')).body);
    expect(lists.lists).toHaveLength(1);
    expect(lists.lists[0]).toMatchObject({
      id,
      country: 'RU',
      source: { kind: 'url', url: 'https://example.com/list.txt' },
      fetchEveryHours: 24,
      active: null,
    });
  });
});

describe('a paste, from parts to a version', () => {
  test('the first version waits; once used, lookups answer from it', async () => {
    const { t, create, paste, detail, lookup, approve } = await seed();
    const id = await create();
    // Tiny parts: the paste goes up in many.
    expect(await paste(id, V1, 24)).toBe('held');
    const held = (await detail(id)).list.held!;
    expect(held.heldReasons).toEqual(['first_version']);
    expect(held.counts).toMatchObject({
      names: 1,
      wildcards: 1,
      v4Ranges: 1,
      v6Ranges: 1,
      v4: 256,
    });
    // Nothing is active: nothing is held by any list yet.
    expect((await lookup(['example.com'])).every((r) => r.lists.length === 0)).toBe(true);
    expect((await approve(id, held.id)).status).toBe(200);
    const results = await lookup([
      'example.com',
      'a.example.org',
      'example.org',
      '192.0.2.7',
      '198.51.100.1',
      '2001:db8::5',
      'not a name!',
    ]);
    expect(results.map((r) => [r.entry, r.kind, r.lists.map((l) => l.how)])).toEqual([
      ['example.com', 'name', ['exact']],
      ['a.example.org', 'name', ['wildcard']],
      // A wildcard never holds its apex.
      ['example.org', 'name', []],
      ['192.0.2.7', 'address', ['range']],
      ['198.51.100.1', 'address', []],
      ['2001:db8::5', 'address', ['range']],
      ['not a name!', 'invalid', []],
    ]);
    const view = await detail(id);
    expect(view.list.active?.id).toBe(held.id);
    expect(view.list.fresh).toBe(true);
    // The history of names fills in after publication.
    await t.mutation(internal.countryLists.afterPublish, {
      versionId: held.id as Id<'countryListVersions'>,
    });
    const history = await t.run((ctx) => ctx.db.query('countryListNameHistory').collect());
    expect(history.map((h) => [h.name, h.wildcard])).toEqual(
      expect.arrayContaining([
        ['example.com', false],
        ['example.org', true],
      ]),
    );
  });

  test('parts go in order; a repeat is harmless; an oversize part is refused', async () => {
    const { call, create } = await seed();
    const id = await create();
    const { body } = await call('POST', `lists/${id}/uploads`, {});
    const path = `lists/${id}/uploads/${body.uploadId}/parts`;
    expect((await call('POST', path, { index: 1, text: 'a' })).body).toMatchObject({
      error: { code: 'edge.list.part_order' },
    });
    expect((await call('POST', path, { index: 0, text: 'example.com\n' })).status).toBe(200);
    expect((await call('POST', path, { index: 0, text: 'example.com\n' })).body).toEqual({
      parts: 1,
      bytes: 12,
    });
    const big = await call('POST', path, { index: 1, text: 'x'.repeat(UPLOAD_PART_BYTES) });
    expect(big.status).toBe(413);
    // A URL list takes no paste.
    const fetched = await create({ source: { kind: 'url', url: 'https://example.com/a.txt' } });
    expect((await call('POST', `lists/${fetched}/uploads`, {})).body).toMatchObject({
      error: { code: 'edge.list.not_paste' },
    });
  });

  test('a full part, sealed, fits one request', async () => {
    const SEED = new Uint8Array(32).fill(7);
    vi.stubEnv('FS_SERVER_HPKE_SK', bytesToB64Url(SEED));
    const kp = await serverKeyPairFromSeed(SEED);
    const kid = await kidFromPublicKey(await serializePublicKey(kp.publicKey));
    const { t, cookie, call, create } = await seed();
    const id = await create();
    const { body } = await call('POST', `lists/${id}/uploads`, {});
    // Names in Unicode take two bytes a character: the worst ordinary case.
    const text = 'пример.рф\n'.repeat(20_000);
    const [part] = splitUploadParts(text);
    expect(new TextEncoder().encode(JSON.stringify(part)).length).toBeLessThanOrEqual(
      UPLOAD_PART_BYTES,
    );
    const path = `/api/v1/admin/edges/lists/${id}/uploads/${body.uploadId}/parts`;
    const prep = await clientPrepareRequest({
      serverPub: kp.publicKey,
      serverKid: kid,
      method: 'POST',
      path,
      policy: routePolicy(path, 'POST')!,
      bodyObj: { index: 0, text: part },
    });
    const wire = JSON.stringify(prep.body);
    expect(wire.length).toBeLessThanOrEqual(MAX_BODY_BYTES);
    const res = await t.fetch(path, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: wire,
    });
    expect(res.status).toBe(200);
  });
});

describe('publication', () => {
  test('a small change is used at once; the old version goes after the grace', async () => {
    const { t, create, paste, detail, approve } = await seed();
    const id = await create();
    await paste(id, V1);
    const first = (await detail(id)).list.held!.id as Id<'countryListVersions'>;
    await approve(id, first);
    expect(await paste(id, `${V1}\nexample.net\n198.51.100.0/24`)).toBe('published');
    const view = await detail(id);
    expect(view.list.active?.id).not.toBe(first);
    expect(view.list.active?.diff?.names).toEqual({ added: 1, removed: 0, common: 2 });
    expect(view.list.active?.diff?.v4).toEqual({ added: 256, removed: 0, common: 256 });
    expect(view.versions.find((v) => v.id === first)?.status).toBe('superseded');
    const rowsOf = (versionId: Id<'countryListVersions'>) =>
      t.run(async (ctx) => ({
        members: (
          await ctx.db
            .query('countryListMembers')
            .withIndex('by_version_name', (q) => q.eq('versionId', versionId))
            .collect()
        ).length,
        chunks: (
          await ctx.db
            .query('countryListChunks')
            .withIndex('by_version_family_lo', (q) => q.eq('versionId', versionId))
            .collect()
        ).length,
      }));
    // Inside the grace, a pinned reader still finds its rows.
    await t.mutation(internal.countryLists.dropVersion, { versionId: first });
    expect(await rowsOf(first)).toEqual({ members: 2, chunks: 2 });
    advance(CLEANUP_GRACE_MS + MIN);
    await t.mutation(internal.countryLists.dropVersion, { versionId: first });
    expect(await rowsOf(first)).toEqual({ members: 0, chunks: 0 });
    expect((await t.run((ctx) => ctx.db.get(first)))?.cleanedAt).toBeDefined();
    expect(await rowsOf(view.list.active!.id as Id<'countryListVersions'>)).toEqual({
      members: 3,
      chunks: 2,
    });
  });

  test('names of a version still being written are never read', async () => {
    const { t, create, paste, detail, lookup, approve } = await seed();
    const id = await create();
    await paste(id, V1);
    await approve(id, (await detail(id)).list.held!.id);
    const counts = {
      entries: 3,
      names: 2,
      wildcards: 1,
      v4Ranges: 1,
      v6Ranges: 1,
      v4: 256,
      v6: 65_536,
      invalid: 0,
      nonPublic: 0,
      tooBroad: 0,
      capped: 0,
    };
    const begun = (await t.mutation(internal.countryLists.stageBegin, {
      listId: id,
      sha256: 'next',
      source: 'upload',
      counts,
      samples: [],
    }))!;
    await t.mutation(internal.countryLists.stageNames, {
      versionId: begun.versionId,
      names: [
        { name: 'example.com', wildcard: false },
        { name: 'staged.example.com', wildcard: false },
        { name: 'example.org', wildcard: true },
      ],
    });
    expect((await lookup(['staged.example.com']))[0]!.lists).toEqual([]);
    // Without its chunks the ranges are gone in that version; the old one still answers.
    expect((await lookup(['192.0.2.1']))[0]!.lists).toHaveLength(1);
    await t.mutation(internal.countryLists.stageFinish, {
      versionId: begun.versionId,
      diff: {
        names: { added: 1, removed: 0, common: 2 },
        v4: { added: 0, removed: 0, common: 256 },
        v6: { added: 0, removed: 0, common: 65_536 },
      },
    });
    expect((await lookup(['staged.example.com']))[0]!.lists).toHaveLength(1);
  });

  test('a jump, a same-size replacement and an IPv6-only change wait', async () => {
    const { create, paste, detail, approve } = await seed();
    const id = await create();
    await paste(id, V1);
    await approve(id, (await detail(id)).list.held!.id);
    const wide = Array.from({ length: 20 }, (_, i) => `198.51.${100 + i}.0/24`).join('\n');
    expect(await paste(id, `example.com\n*.example.org\n2001:db8::/48\n${wide}`)).toBe('held');
    expect((await detail(id)).list.held?.heldReasons).toEqual(['jump', 'replaced']);
    // Same size, nothing in common.
    expect(await paste(id, 'example.com\n*.example.org\n203.0.113.0/24\n2001:db8::/48')).toBe(
      'held',
    );
    expect((await detail(id)).list.held?.heldReasons).toEqual(['replaced']);
    // Only the IPv6 range moved.
    expect(await paste(id, 'example.com\n*.example.org\n192.0.2.0/24\n2001:db8:9::/48')).toBe(
      'held',
    );
    const view = await detail(id);
    expect(view.list.held?.heldReasons).toEqual(['replaced']);
    // Each newer hold replaced the one before it.
    expect(view.versions.filter((v) => v.status === 'held')).toHaveLength(1);
    expect(view.versions.filter((v) => v.status === 'rejected')).toHaveLength(2);
  });

  test('a held version whose base moved on is refused', async () => {
    const { create, paste, detail, approve } = await seed();
    const id = await create();
    await paste(id, V1);
    await approve(id, (await detail(id)).list.held!.id);
    await paste(id, 'example.com\n*.example.org\n203.0.113.0/24\n2001:db8::/48');
    const stale = (await detail(id)).list.held!.id;
    // A small change from the active version goes through on its own.
    expect(await paste(id, `${V1}\nexample.net`)).toBe('published');
    const r = await approve(id, stale);
    expect(r.status).toBe(409);
    expect(r.body).toMatchObject({ error: { code: 'edge.list.version_stale' } });
  });
});

describe('fetching', () => {
  test('validators, unchanged answers and failures', async () => {
    const { t, call, create, detail, approve } = await seed();
    const id = await create({ source: { kind: 'url', url: 'https://example.com/list.txt' } });
    const asked: Array<{ etag?: string | null }> = [];
    const answers: PinnedFetchResult[] = [];
    __setListFetchForTests(async (_url, opts) => {
      asked.push({ etag: opts.etag });
      return answers.shift()!;
    });
    const fetchNow = () => t.action(internal.countryListOps.ingest, { listId: id });

    // The route marks the list busy and schedules the fetch; a second ask waits.
    expect((await call('POST', `lists/${id}/fetch`, {})).status).toBe(200);
    expect((await call('POST', `lists/${id}/fetch`, {})).body).toMatchObject({
      error: { code: 'edge.list.busy' },
    });
    answers.push({ ok: true, status: 200, text: V1, etag: '"a"' });
    expect(await fetchNow()).toBe('held');
    await approve(id, (await detail(id)).list.held!.id);
    const confirmedAt = () => detail(id).then((d) => d.list.confirmedAt);
    const first = await confirmedAt();

    // Its validators go out again; a 304 confirms the active version.
    advance(DAY);
    answers.push({ ok: true, status: 304 });
    expect(await fetchNow()).toBe('not_modified');
    expect(asked.at(-1)).toEqual({ etag: '"a"' });
    expect(await confirmedAt()).not.toBe(first);

    // The same content again (no validators this time) confirms it too, with no new version.
    advance(DAY);
    const before = await confirmedAt();
    answers.push({ ok: true, status: 200, text: `# moved\n${V1}` });
    expect(await fetchNow()).toBe('unchanged');
    expect(await confirmedAt()).not.toBe(before);
    expect((await detail(id)).versions).toHaveLength(1);

    // A failure keeps what was there and is audited.
    advance(DAY);
    const kept = await confirmedAt();
    answers.push({ ok: false, error: 'timeout' });
    expect(await fetchNow()).toBe('timeout');
    expect((await detail(id)).list.lastFetch?.outcome).toBe('timeout');
    expect(await confirmedAt()).toBe(kept);
    const audits = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audits.filter((a) => a.action === 'edge.list.failed').map((a) => a.payload)).toEqual([
      { listId: id, outcome: 'timeout' },
    ]);
  });

  test('a 304 on a waiting version confirms nothing', async () => {
    const { t, create, detail, approve } = await seed();
    const id = await create({ source: { kind: 'url', url: 'https://example.com/list.txt' } });
    const answers: PinnedFetchResult[] = [
      { ok: true, status: 200, text: V1 },
      { ok: true, status: 200, text: 'example.com\n203.0.113.0/24\n2001:db8::/48', etag: '"b"' },
      { ok: true, status: 304 },
    ];
    __setListFetchForTests(async () => answers.shift()!);
    const fetchNow = () => t.action(internal.countryListOps.ingest, { listId: id });
    await fetchNow();
    await approve(id, (await detail(id)).list.held!.id);
    const confirmed = (await detail(id)).list.confirmedAt;
    advance(DAY);
    expect(await fetchNow()).toBe('held');
    expect(await fetchNow()).toBe('held_same');
    expect((await detail(id)).list.confirmedAt).toBe(confirmed);
  });
});

describe('the sweep', () => {
  test('fails crashed staging and frees the list for the next run', async () => {
    const { t, create } = await seed();
    const id = await create();
    const begun = (await t.mutation(internal.countryLists.stageBegin, {
      listId: id,
      sha256: 'x',
      source: 'upload',
      counts: {
        entries: 0,
        names: 0,
        wildcards: 0,
        v4Ranges: 0,
        v6Ranges: 0,
        v4: 0,
        v6: 0,
        invalid: 0,
        nonPublic: 0,
        tooBroad: 0,
        capped: 0,
      },
      samples: [],
    }))!;
    await t.mutation(internal.countryLists.stageNames, {
      versionId: begun.versionId,
      names: [{ name: 'example.com', wildcard: false }],
    });
    advance(61 * MIN);
    expect((await t.mutation(internal.countryLists.sweep, {})).failed).toBe(1);
    expect((await t.run((ctx) => ctx.db.get(id)))?.stagingVersionId).toBeUndefined();
    advance(CLEANUP_GRACE_MS + MIN);
    await t.mutation(internal.countryLists.dropVersion, { versionId: begun.versionId });
    expect(await t.run((ctx) => ctx.db.query('countryListMembers').collect())).toEqual([]);
  });

  test('never deletes a version a list points at, however old', async () => {
    const { t, create, paste, detail, approve } = await seed();
    const id = await create();
    await paste(id, V1);
    const active = (await detail(id)).list.held!.id;
    await approve(id, active);
    await paste(id, 'example.com\n203.0.113.0/24\n2001:db8::/48');
    const held = (await detail(id)).list.held!.id;
    advance(200 * DAY);
    await t.mutation(internal.countryLists.sweep, {});
    const view = await detail(id);
    expect(view.list.active?.id).toBe(active);
    // A version nobody decided on expires; it is not deleted in the same pass.
    expect(view.list.held).toBeNull();
    expect(view.versions.find((v) => v.id === held)?.status).toBe('rejected');
  });
});

describe('what evidence reads', () => {
  test('only enabled, fresh lists, and none while switched off', async () => {
    const { t, call, create, paste, detail, approve } = await seed();
    const id = await create();
    await paste(id, V1);
    await approve(id, (await detail(id)).list.held!.id);
    const facts = () =>
      t.run(async (ctx) =>
        [
          ...(
            await listFactsFor(ctx.db, {
              names: ['example.com'],
              addresses: ['192.0.2.9'],
              now: Date.now(),
            })
          ).entries(),
        ].map(([k, f]) => [k, f.map((x) => `${x.country}:${x.regime}:${x.how}`)]),
      );
    expect(await facts()).toEqual([
      ['example.com', ['RU:allowlist:exact']],
      ['192.0.2.9', ['RU:allowlist:range']],
    ]);
    await setting(t, 'edge.lists.enabled', false);
    expect(await facts()).toEqual([]);
    await setting(t, 'edge.lists.enabled', true);
    await call('PATCH', `lists/${id}`, { enabled: false });
    expect(await facts()).toEqual([]);
    await call('PATCH', `lists/${id}`, { enabled: true });
    advance(31 * DAY);
    expect(await facts()).toEqual([]);
    expect((await detail(id)).list.fresh).toBe(false);
  });
});

describe('removal', () => {
  test('a removed list is gone at once; its rows follow', async () => {
    const { t, call, create, paste, detail, approve } = await seed();
    const id = await create();
    await paste(id, V1);
    await approve(id, (await detail(id)).list.held!.id);
    expect((await call('DELETE', `lists/${id}`)).status).toBe(200);
    expect((await call('GET', `lists/${id}`)).status).toBe(404);
    expect(
      await t.run(
        async (ctx) =>
          (await listFactsFor(ctx.db, { names: ['example.com'], now: Date.now() })).size,
      ),
    ).toBe(0);
    await t.mutation(internal.countryLists.purgeList, { listId: id });
    advance(CLEANUP_GRACE_MS + MIN);
    const [version] = await t.run((ctx) => ctx.db.query('countryListVersions').collect());
    await t.mutation(internal.countryLists.dropVersion, { versionId: version!._id });
    await t.mutation(internal.countryLists.purgeList, { listId: id });
    expect(await t.run((ctx) => ctx.db.query('countryListVersions').collect())).toEqual([]);
    expect(await t.run((ctx) => ctx.db.query('countryListMembers').collect())).toEqual([]);
    expect(await t.run((ctx) => ctx.db.query('countryListNameHistory').collect())).toEqual([]);
  });
});

describe('routes', () => {
  test('scopes and throttles', () => {
    expect(scopeFor(['lists'], 'GET')).toBe('admin:servers:read');
    expect(scopeFor(['lists', 'lookup'], 'POST')).toBe('admin:servers:read');
    expect(scopeFor(['lists'], 'POST')).toBe('admin:servers:manage');
    expect(scopeFor(['lists', 'x', 'uploads', 'u', 'parts'], 'POST')).toBe('admin:servers:manage');
    expect(throttlePolicyFor(['lists', 'x', 'fetch'])).toBe('admin.edges.provider-call');
    expect(throttlePolicyFor(['lists', 'x', 'uploads', 'u', 'finish'])).toBe(
      'admin.edges.provider-call',
    );
    expect(throttlePolicyFor(['lists', 'x', 'uploads', 'u', 'parts'])).toBe(
      'admin.edges.list-upload',
    );
    expect(throttlePolicyFor(['lists', 'lookup'])).toBeNull();
  });
});
