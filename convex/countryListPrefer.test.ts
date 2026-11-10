/// <reference types="vite/client" />
/**
 * Names on a country's allowlist (docs/edges.md "Names on a country's
 * allowlist", convex/countryListFacts.ts `applyPreference`):
 *
 *  - both switches are needed, and off nothing is written;
 *  - the preference is copied onto the listeners that carry the name, moves a
 *    listener onto `hrw1` once, and moves its origin once;
 *  - a version that touches no name in use changes nothing; one that drops
 *    the name takes the preference away;
 *  - a block list for the same country, a stale list, a list switched off and
 *    either switch off all take it away;
 *  - only an allowlist can prefer its names;
 *  - the rollback step leaves no row an older schema refuses.
 *
 * Fixtures use example names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { signValue } from './lib/cookies';
import { splitUploadParts } from '../src/shared/contracts/countryLists';
import { insertPanelServer, registerRelay, realityListener } from './lib/edges/testing/fixtures';

const modules = import.meta.glob('./**/*.*s');
const ADMIN_SIGN_KEY = 'test-admin-sign';
const DAY = 24 * 60 * 60_000;
type T = TestConvex<typeof schema>;
type ListId = Id<'countryLists'>;

beforeEach(() => {
  vi.useFakeTimers({
    toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'],
  });
  vi.setSystemTime(Date.UTC(2026, 10, 10, 12));
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', ADMIN_SIGN_KEY);
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
});

const V1 = 'x.example.com\nk1.example.com\nk2.example.com\nk3.example.com\n';

async function seed() {
  const t: T = convexTest(schema, modules);
  await insertPanelServer(t);
  await t.mutation(internal.edgeAdmin.patchConfig, { patch: { 'lists.enabled': true } });
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
  const create = async (regime: 'allowlist' | 'blocklist' = 'allowlist', country = 'RU') =>
    (
      await call('POST', 'lists', {
        label: regime === 'allowlist' ? 'Works' : 'Blocked',
        country,
        regime,
        source: { kind: 'paste' },
      })
    ).body.id as ListId;
  const paste = async (listId: ListId, text: string) => {
    const { body } = await call('POST', `lists/${listId}/uploads`, {});
    const uploadId = body.uploadId as Id<'countryListUploads'>;
    for (const [index, part] of splitUploadParts(text).entries())
      await call('POST', `lists/${listId}/uploads/${uploadId}/parts`, { index, text: part });
    await call('POST', `lists/${listId}/uploads/${uploadId}/finish`, {});
    const outcome = await t.action(internal.countryListOps.ingest, { listId, uploadId });
    if (outcome === 'published') await published(listId);
    return outcome;
  };
  /** What a publication schedules: the list-facts generation moves. */
  const published = async (listId: ListId) =>
    t.mutation(internal.countryLists.afterPublish, {
      versionId: (await t.run((ctx) => ctx.db.get(listId)))!.activeVersionId!,
    });
  const approve = async (listId: ListId) => {
    const l = (await t.run((ctx) => ctx.db.get(listId)))!;
    await call('POST', `lists/${listId}/versions/${l.heldVersionId}/approve`, {});
    await published(listId);
  };
  /** The facts of the family names, then what a finished refresh schedules. */
  const settle = async () => {
    for (let i = 0; i < 10; i++)
      if ((await t.mutation(internal.countryListFacts.refresh, { table: 'sniNames' })).rows === 0)
        break;
    return t.mutation(internal.countryListFacts.applyPreference, {});
  };

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
  const { relayId, listenerIds } = await registerRelay(t, {
    listeners: [realityListener({ tlsNames: ['x.example.com', 'y.example.com'] })],
  });
  const names = async () => (await t.run((ctx) => ctx.db.get(listenerIds.a)))!.tlsNames!;
  const pick = async () => (await t.run((ctx) => ctx.db.get(listenerIds.a)))!.sniPick;
  const epoch = async () => (await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch;
  const preferOn = () =>
    t.mutation(internal.edgeAdmin.patchConfig, { patch: { 'lists.preferNames': true } });
  return { t, call, create, paste, approve, settle, names, pick, epoch, preferOn, listenerIds };
}

const PLAIN = [
  { name: 'x.example.com', status: 'active' },
  { name: 'y.example.com', status: 'active' },
];
const LISTED = [
  { name: 'x.example.com', status: 'active', listedIn: ['RU'] },
  { name: 'y.example.com', status: 'active' },
];

describe('an allowlist that prefers its names', () => {
  test('needs both switches; then the listener carries it, on hrw1, and its origin moves once', async () => {
    const { t, call, create, paste, approve, settle, names, pick, epoch, preferOn } = await seed();
    const id = await create();
    await paste(id, V1);
    await approve(id);
    const epoch0 = await epoch();
    // Neither switch: nothing is written.
    expect(await settle()).toEqual({ changed: 0, switched: 0, origins: 0 });
    // The deployment's switch alone: no list prefers its names yet.
    await preferOn();
    expect(await settle()).toEqual({ changed: 0, switched: 0, origins: 0 });
    expect(await names()).toEqual(PLAIN);
    expect(await pick()).toBeUndefined();
    expect(await epoch()).toBe(epoch0);

    expect((await call('PATCH', `lists/${id}`, { preferNames: true })).status).toBe(200);
    expect(await settle()).toEqual({ changed: 1, switched: 1, origins: 1 });
    expect(await names()).toEqual(LISTED);
    // The legacy pick ignores the member's country: the listener moved, once.
    expect(await pick()).toBe('hrw1');
    expect(await epoch()).toBe(epoch0 + 1);
    const audit = await t.run(async (ctx) =>
      (await ctx.db.query('auditLog').collect()).filter(
        (r) => r.action === 'edge.list.prefer.applied',
      ),
    );
    expect(audit.map((r) => r.payload)).toEqual([{ listeners: 1, origins: 1, switched: 1 }]);
    const view = (await call('GET', `lists/${id}`)).body as { list: { preferNames: boolean } };
    expect(view.list.preferNames).toBe(true);

    // Settled: another pass moves nobody.
    expect(await settle()).toEqual({ changed: 0, switched: 0, origins: 0 });
    expect(await epoch()).toBe(epoch0 + 1);
    // The legacy pick is refused while a name is preferred somewhere.
    await expect(
      t.mutation(internal.relayListeners.setSniPick, {
        id: (await t.run((ctx) => ctx.db.query('relayListeners').first()))!._id,
        version: null,
      }),
    ).rejects.toThrow(/judged per country/);
  });

  test('a version that touches no name in use changes nothing; one without the name takes it away', async () => {
    const { create, paste, approve, settle, names, epoch, preferOn, call } = await seed();
    const id = await create();
    await paste(id, V1);
    await approve(id);
    await preferOn();
    await call('PATCH', `lists/${id}`, { preferNames: true });
    await settle();
    const e = await epoch();
    expect(await paste(id, `${V1}k4.example.com\n`)).toBe('published');
    expect(await settle()).toEqual({ changed: 0, switched: 0, origins: 0 });
    expect(await epoch()).toBe(e);
    expect(
      await paste(id, 'k1.example.com\nk2.example.com\nk3.example.com\nk4.example.com\n'),
    ).toBe('published');
    expect(await settle()).toEqual({ changed: 1, switched: 0, origins: 1 });
    expect(await names()).toEqual(PLAIN);
    expect(await epoch()).toBe(e + 1);
  });

  test('a mark still decides: the copy sits beside it, and a new name gets it when it arrives', async () => {
    const { t, create, paste, approve, settle, names, preferOn, call, listenerIds } = await seed();
    const id = await create();
    await paste(id, V1);
    await approve(id);
    await preferOn();
    await call('PATCH', `lists/${id}`, { preferNames: true });
    await settle();
    await t.mutation(internal.sniFamilies.setCountry, {
      slug: 'fam-a',
      names: ['x.example.com'],
      country: 'RU',
      state: 'blocked',
    });
    expect((await names())[0]).toEqual({
      name: 'x.example.com',
      status: 'active',
      blockedIn: ['RU'],
      listedIn: ['RU'],
    });
    // Retired and brought back: the writer copies the preference with the marks.
    await t.mutation(internal.relayListeners.retireName, {
      id: listenerIds.a,
      names: ['x.example.com'],
    });
    await t.mutation(internal.relayListeners.reactivateName, {
      id: listenerIds.a,
      names: ['x.example.com'],
    });
    expect((await names())[0]).toMatchObject({ blockedIn: ['RU'], listedIn: ['RU'] });
  });

  test('a block list for the same country, a stale list, a list off and either switch off take it away', async () => {
    const { t, create, paste, approve, settle, names, preferOn, call } = await seed();
    const id = await create();
    await paste(id, V1);
    await approve(id);
    await preferOn();
    await call('PATCH', `lists/${id}`, { preferNames: true });
    await settle();
    expect(await names()).toEqual(LISTED);

    // Lists that disagree prefer nothing.
    const block = await create('blocklist');
    await paste(block, 'x.example.com\n');
    await approve(block);
    await settle();
    expect(await names()).toEqual(PLAIN);
    await call('DELETE', `lists/${block}`);
    await settle();
    expect(await names()).toEqual(LISTED);

    // The list's own switch.
    await call('PATCH', `lists/${id}`, { preferNames: false });
    await settle();
    expect(await names()).toEqual(PLAIN);
    await call('PATCH', `lists/${id}`, { preferNames: true });
    await settle();
    expect(await names()).toEqual(LISTED);

    // The list switched off.
    await call('PATCH', `lists/${id}`, { enabled: false });
    await settle();
    expect(await names()).toEqual(PLAIN);
    await call('PATCH', `lists/${id}`, { enabled: true });
    await settle();
    expect(await names()).toEqual(LISTED);

    // The deployment's switch.
    await t.mutation(internal.edgeAdmin.patchConfig, { patch: { 'lists.preferNames': false } });
    await settle();
    expect(await names()).toEqual(PLAIN);
    await preferOn();
    await settle();
    expect(await names()).toEqual(LISTED);

    // Stale: nothing reads the list any more.
    await t.mutation(internal.countryLists.sweep, {});
    vi.setSystemTime(Date.now() + 31 * DAY);
    await t.mutation(internal.countryLists.sweep, {});
    await settle();
    expect(await names()).toEqual(PLAIN);
  });

  test('only a list of what works can prefer its names, and one that becomes a block list stops', async () => {
    const { t, call, create } = await seed();
    const block = await create('blocklist');
    const r = await call('PATCH', `lists/${block}`, { preferNames: true });
    expect(r.status).toBe(409);
    expect((r.body.error as { code: string }).code).toBe('edge.list.prefer_allowlist_only');
    const allow = await create();
    await call('PATCH', `lists/${allow}`, { preferNames: true });
    await call('PATCH', `lists/${allow}`, { regime: 'blocklist' });
    expect((await t.run((ctx) => ctx.db.get(allow)))!.preferNames).toBe(false);
  });

  test('a list for a country that is not curated prefers nothing', async () => {
    const { create, paste, approve, settle, names, preferOn, call } = await seed();
    const id = await create('allowlist', 'NZ');
    await paste(id, V1);
    await approve(id);
    await preferOn();
    await call('PATCH', `lists/${id}`, { preferNames: true });
    expect(await settle()).toEqual({ changed: 0, switched: 0, origins: 0 });
    expect(await names()).toEqual(PLAIN);
  });

  test('the rollback step turns it off and leaves nothing an older schema refuses', async () => {
    const { t, create, paste, approve, settle, names, epoch, preferOn, call } = await seed();
    const id = await create();
    await paste(id, V1);
    await approve(id);
    await preferOn();
    await call('PATCH', `lists/${id}`, { preferNames: true });
    await settle();
    const e = await epoch();
    expect(await t.mutation(internal.countryListFacts.clearForRollback, {})).toEqual({
      lists: 1,
      listeners: 1,
      origins: 1,
    });
    expect(await names()).toEqual(PLAIN);
    expect(await epoch()).toBe(e + 1);
    expect((await t.run((ctx) => ctx.db.get(id)))!.preferNames).toBeUndefined();
    // Off now, so a pass writes nothing back.
    expect(await settle()).toEqual({ changed: 0, switched: 0, origins: 0 });
    expect(await t.mutation(internal.countryListFacts.clearForRollback, {})).toEqual({
      lists: 0,
      listeners: 0,
      origins: 0,
    });
  });
});
