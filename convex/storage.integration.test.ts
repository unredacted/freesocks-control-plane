// @vitest-environment node
/// <reference types="vite/client" />
/**
 * The S3 mirror path against a REAL S3-compatible store (a throwaway SeaweedFS
 * from docker-compose.s3-test.yml; `bun run test:integration:s3` stands it up,
 * points FCP_S3_TEST_ENDPOINT at it and tears it down). Nothing is stubbed on
 * the storage side: the AWS SDK writes and deletes the objects, and the
 * member-facing URL is read over plain HTTP with no credentials, exactly as a
 * member's app would. Only the proxy backend's body is canned.
 *
 * It walks one member's mirror through its whole life (request, refresh,
 * read-back, an object deleted and one overwritten behind FCP's back, removal),
 * a provider's withdrawal, and the admin connection test.
 */
import { afterAll, afterEach, beforeAll, describe, expect, test, vi } from 'vitest';
import { convexTest, type TestConvex } from 'convex-test';
import {
  CreateBucketCommand,
  DeleteObjectCommand,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { sha256Hex } from './lib/crypto';

const modules = import.meta.glob('./**/*.*s');
const ENDPOINT = process.env.FCP_S3_TEST_ENDPOINT ?? '';
const ACCESS = 'fcp-test-access';
const SECRET = 'fcp-test-secret-not-a-real-one';
const BUCKETS = ['fcp-mirrors-a', 'fcp-mirrors-b'] as const;

const s3 = new S3Client({
  region: 'us-east-1',
  endpoint: ENDPOINT || 'http://127.0.0.1:1',
  forcePathStyle: true,
  credentials: { accessKeyId: ACCESS, secretAccessKey: SECRET },
});
const realFetch = globalThis.fetch;
/** What the (canned) proxy backend serves, by short id. */
const backend = new Map<string, string>();
const body = (key: string) => `vless://${key}@1.1.1.1:443?type=ws#xray1-ws`;

/** A plain, credential-less GET, as a member's app makes it. */
async function memberGet(url: string) {
  const res = await realFetch(url, { headers: { 'cache-control': 'no-cache' } });
  return {
    status: res.status,
    cacheControl: res.headers.get('cache-control'),
    text: await res.text(),
  };
}

type T = TestConvex<typeof schema>;

async function world(): Promise<T> {
  vi.stubEnv('DEV_MOCK_BACKEND', '');
  vi.stubEnv('ENVIRONMENT', 'production');
  // Only the proxy backend is canned; every other request (the member-facing
  // reads) goes to the real store.
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: unknown, init?: RequestInit) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url.startsWith('https://panel.test/')) {
        for (const [short, b] of backend) if (url.includes(short)) return new Response(b);
        return new Response('not found', { status: 404 });
      }
      return realFetch(input as RequestInfo, init);
    }),
  );
  const t = convexTest(schema, modules);
  await t.run(async (ctx) => {
    for (const [i, bucket] of BUCKETS.entries())
      await ctx.db.insert('mirrorProviders', {
        name: `p${i + 1}`,
        endpoint: ENDPOINT,
        bucket,
        publicUrl: `${ENDPOINT}/${bucket}`,
        region: 'us-east-1',
        accessKeyId: ACCESS,
        secretAccessKey: SECRET,
        isActive: i === 0,
        priority: i,
        updatedAt: Date.now(),
      });
  });
  await t.mutation(internal.mirrorCopies.markSeeded, {});
  return t;
}

async function member(t: T, short: string) {
  backend.set(short, body(`key-${short}`));
  return t.run(async (ctx) => {
    const tierId = await ctx.db.insert('tiers', {
      slug: `free-${short}`,
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
    const serverId = await ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: `n-${short}`,
      slug: `n-${short}`,
      config: { type: 'remnawave', baseUrl: 'https://panel.test', apiToken: 'tok' },
      isActive: true,
      priority: 0,
      keyCount: 1,
      updatedAt: Date.now(),
    });
    const subId = await ctx.db.insert('subscriptions', {
      userId,
      backend: 'remnawave',
      backendUserId: `u-${short}`,
      backendShortId: short,
      backendServerId: serverId,
      subscriptionUrl: `https://panel.test/sub/${short}`,
      subscriptionMirrors: [],
      state: 'active',
      updatedAt: Date.now(),
    });
    await ctx.db.patch(userId, { currentSubscriptionId: subId });
    return { userId, subId };
  });
}

const copy = async (t: T, subId: Id<'subscriptions'>) =>
  (await t.run((ctx) => ctx.db.query('mirrorCopies').collect())).find(
    (c) => c.subscriptionId === subId,
  );
/** Every copy due a read of its public URL again (as if hours had passed). */
const readAgainSoon = (t: T) =>
  t.run(async (ctx) => {
    for (const c of await ctx.db.query('mirrorCopies').collect())
      await ctx.db.patch(c._id, { verifiedAt: Date.now() - 7 * 3_600_000 });
  });

describe.skipIf(!ENDPOINT)('S3 mirrors against a real store', () => {
  beforeAll(async () => {
    for (const Bucket of BUCKETS)
      await s3.send(new CreateBucketCommand({ Bucket })).catch((err: Error) => {
        if (!/BucketAlready/.test(err.name)) throw err;
      });
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });
  afterAll(() => s3.destroy());

  test("a member's mirror lives in the bucket, follows FCP, and is put back when the bucket loses it", async () => {
    const t = await world();
    const { userId, subId } = await member(t, 'walkA');

    // 1. The member asks for a mirror: the object is in the bucket and the
    //    URL they are handed serves it, with no-cache.
    const res = await t.action(internal.storage.provisionMirror, { userId, countryCode: null });
    expect(res.status).toBe('ok');
    const url = res.publicUrl!;
    let got = await memberGet(url);
    expect(got.status).toBe(200);
    expect(got.text).toContain('key-walkA');
    expect(got.cacheControl).toBe('no-cache');
    let c = await copy(t, subId);
    expect(c).toMatchObject({ state: 'in_sync', objectHash: await sha256Hex(got.text) });

    // 2. What the member is served changes: the sweep rewrites the object.
    backend.set('walkA', body('key-walkA-v2'));
    const sweep = await t.action(internal.storage.refreshActiveMirrors, {});
    expect(sweep).toMatchObject({ scanned: 1, refreshed: 1 });
    got = await memberGet(url);
    expect(got.text).toContain('key-walkA-v2');
    expect((await copy(t, subId))!.objectHash).toBe(await sha256Hex(got.text));

    // 3. Nothing changed: the next sweep confirms and writes nothing.
    expect(await t.action(internal.storage.refreshActiveMirrors, {})).toMatchObject({
      scanned: 1,
      refreshed: 0,
    });

    // 4. The read-back through the member's URL matches.
    expect(await t.action(internal.storage.verifyMirrorCopies, {})).toMatchObject({
      read: 1,
      match: 1,
    });

    // 5. The object is deleted behind FCP's back: the read sees it, the copy
    //    is rewritten, and the URL serves again.
    const key = new URL(url).pathname.split('/').slice(2).join('/');
    await s3.send(new DeleteObjectCommand({ Bucket: BUCKETS[0], Key: key }));
    expect((await memberGet(url)).status).toBe(404);
    await readAgainSoon(t);
    expect(await t.action(internal.storage.verifyMirrorCopies, {})).toMatchObject({ missing: 1 });
    expect(await copy(t, subId)).toMatchObject({ state: 'never', reason: 'missing' });
    await t.action(internal.storage.refreshMirrorsForSubscription, {
      subscriptionId: subId,
      forceProviders: ['p1'],
    });
    got = await memberGet(url);
    expect(got.status).toBe(200);
    expect(got.text).toContain('key-walkA-v2');
    expect((await copy(t, subId))!.state).toBe('in_sync');
    // The read that found the problem is repeated soon after the rewrite: it matches.
    await t.run(async (ctx) => {
      for (const r of await ctx.db.query('mirrorCopies').collect())
        await ctx.db.patch(r._id, { recheckAt: Date.now() - 1 });
    });
    expect(await t.action(internal.storage.verifyMirrorCopies, {})).toMatchObject({ match: 1 });

    // 6. Overwritten behind FCP's back: seen and put right.
    await s3.send(
      new PutObjectCommand({
        Bucket: BUCKETS[0],
        Key: key,
        Body: 'tampered',
        ContentType: 'text/plain',
      }),
    );
    await readAgainSoon(t);
    expect(await t.action(internal.storage.verifyMirrorCopies, {})).toMatchObject({ mismatch: 1 });
    expect(await copy(t, subId)).toMatchObject({ state: 'stale', reason: 'object_mismatch' });
    await t.action(internal.storage.refreshMirrorsForSubscription, {
      subscriptionId: subId,
      forceProviders: ['p1'],
    });
    expect((await memberGet(url)).text).toContain('key-walkA-v2');
    c = await copy(t, subId);
    expect(c!.state).toBe('in_sync');

    // 7. The member removes their mirrors: the object is gone from the bucket.
    expect(await t.action(internal.storage.clearMirrorsForUser, { userId })).toEqual({
      removed: 1,
    });
    expect((await memberGet(url)).status).toBe(404);
    expect(await copy(t, subId)).toBeUndefined();
  });

  test("removing a provider deletes its members' objects from the bucket, then the row", async () => {
    const t = await world();
    const { userId, subId } = await member(t, 'walkB');
    const res = await t.action(internal.storage.provisionMirror, { userId, countryCode: null });
    expect(res.status).toBe('ok');
    expect((await memberGet(res.publicUrl!)).status).toBe(200);
    const p1 = (await t.run((ctx) => ctx.db.query('mirrorProviders').collect())).find(
      (p) => p.name === 'p1',
    )!;
    expect(await t.mutation(internal.mirrorProviders.remove, { id: p1._id })).toEqual({
      ok: true,
      removing: true,
    });
    expect(
      await t.action(internal.storage.withdrawProviderMirrors, { providerId: p1._id }),
    ).toEqual({ withdrawn: 1, done: true });
    expect((await memberGet(res.publicUrl!)).status).toBe(404);
    expect((await t.run((ctx) => ctx.db.get(subId)))!.subscriptionMirrors).toEqual([]);
    expect(await t.run((ctx) => ctx.db.get(p1._id))).toBeNull();
  });

  test('a store that refuses writes is recorded as failing, and the copy recovers with it', async () => {
    const t = await world();
    const { userId, subId } = await member(t, 'walkC');
    await t.action(internal.storage.provisionMirror, { userId, countryCode: null });
    // The provider's secret stops working (rotated at the provider, say).
    await t.run(async (ctx) => {
      const p1 = (await ctx.db.query('mirrorProviders').collect()).find((p) => p.name === 'p1')!;
      await ctx.db.patch(p1._id, { secretAccessKey: 'wrong' });
    });
    backend.set('walkC', body('key-walkC-v2'));
    await t.action(internal.storage.refreshMirrorsForSubscription, { subscriptionId: subId });
    expect(await copy(t, subId)).toMatchObject({
      state: 'failing',
      reason: 'upload_failed',
      failures: 1,
    });
    await t.run(async (ctx) => {
      const p1 = (await ctx.db.query('mirrorProviders').collect()).find((p) => p.name === 'p1')!;
      await ctx.db.patch(p1._id, { secretAccessKey: SECRET });
    });
    await t.action(internal.storage.refreshMirrorsForSubscription, { subscriptionId: subId });
    expect(await copy(t, subId)).toMatchObject({ state: 'in_sync', failures: 0 });
  });

  test('the admin connection test writes, reads back through the public URL, and finds listing off', async () => {
    const t = await world();
    const base = {
      endpoint: ENDPOINT,
      bucket: BUCKETS[1],
      region: 'us-east-1',
      accessKeyId: ACCESS,
      secretAccessKey: SECRET,
    };
    expect(
      await t.action(internal.storage.testProviderConnection, {
        ...base,
        publicUrl: `${ENDPOINT}/${BUCKETS[1]}`,
      }),
    ).toEqual({ ok: true, publicRead: 'ok', publicList: 'private' });
    expect(
      await t.action(internal.storage.testProviderConnection, {
        ...base,
        publicUrl: `${ENDPOINT}/not-the-bucket`,
      }),
    ).toMatchObject({ ok: true, publicRead: 'unreadable' });
    expect(
      await t.action(internal.storage.testProviderConnection, {
        ...base,
        secretAccessKey: 'wrong',
      }),
    ).toMatchObject({ ok: false });
  });
});
