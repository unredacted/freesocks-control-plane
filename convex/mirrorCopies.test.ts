// @vitest-environment node
/// <reference types="vite/client" />
/**
 * The mirror sync ledger and the mirror fixes it carries (docs/mirrors.md):
 * every copy of a member's mirror is tracked against
 * what FCP would serve now, and every path that writes, moves or drops a copy
 * keeps the ledger, the counter and the bucket in step.
 *
 * S3 is a map behind the injected send (`__setS3SendForTests`), and the
 * member-facing URL is read from the same map (`__setMirrorFetchForTests`), so
 * an object that is deleted or overwritten "in the bucket" is seen by the read.
 * The real SDK against a real store is storage.integration.test.ts.
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { convexTest, type TestConvex } from 'convex-test';
import schema from './schema';
import { api, internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { __setMirrorFetchForTests, __setS3SendForTests, type S3Op } from './storage';
import { repairBackoffMs, REPAIR_GRACE_MS } from './mirrorUploads';
import { invalidateDelivery } from './subscriptions';
import { setStoredCountry } from './memberCountry';
import { readMirrorCopyCounts } from './lib/statusCounters';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;

/** One-line bodies (the node pin keeps the single entry), told apart by their key. */
const body = (key: string) => `vless://${key}@1.1.1.1:443?type=ws#xray1-ws`;

interface World {
  t: T;
  /** What each backend URL serves now (by short id). */
  backend: Map<string, string>;
  /** The "buckets": `${provider}:${key}` → body. */
  objects: Map<string, string>;
  calls: { provider: string; op: S3Op }[];
  /** Fail an S3 op when this says so. */
  fail: { fn: (provider: string, op: S3Op) => boolean };
  /** Make every public-URL read answer this instead of the bucket. */
  urlOverride: { status: number | null };
  /** Run during a put (after it is recorded, before it resolves). */
  duringPut: { fn: (() => Promise<void>) | null };
}

const PROVIDERS = {
  p1: 'https://cdn-1.example',
  p2: 'https://cdn-2.example',
} as const;

async function world(): Promise<World> {
  vi.stubEnv('DEV_MOCK_BACKEND', '');
  vi.stubEnv('ENVIRONMENT', 'production');
  const t = convexTest(schema, modules);
  const w: World = {
    t,
    backend: new Map(),
    objects: new Map(),
    calls: [],
    fail: { fn: () => false },
    urlOverride: { status: null },
    duringPut: { fn: null },
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: unknown) => {
      const url = String(input instanceof Request ? input.url : input);
      for (const [short, b] of w.backend) if (url.includes(short)) return new Response(b);
      return new Response('not found', { status: 404 });
    }),
  );
  __setS3SendForTests(async (p, op) => {
    w.calls.push({ provider: p.name, op });
    if (w.fail.fn(p.name, op)) throw new Error(`${p.name} down`);
    if (op.kind === 'put') {
      const during = w.duringPut.fn;
      w.duringPut.fn = null;
      if (during) await during();
      w.objects.set(`${p.name}:${op.key}`, op.body);
    } else w.objects.delete(`${p.name}:${op.key}`);
  });
  __setMirrorFetchForTests(async (url) => {
    if (w.urlOverride.status !== null) return { status: w.urlOverride.status, body: null };
    for (const [name, base] of Object.entries(PROVIDERS)) {
      if (!url.startsWith(`${base}/`)) continue;
      const b = w.objects.get(`${name}:${url.slice(base.length + 1)}`);
      return b === undefined ? { status: 404, body: null } : { status: 200, body: b };
    }
    return { status: 404, body: null };
  });
  await t.run(async (ctx) => {
    for (const [name, publicUrl] of Object.entries(PROVIDERS))
      await ctx.db.insert('mirrorProviders', {
        name,
        endpoint: `https://s3.${name}.example`,
        bucket: `b-${name}`,
        publicUrl,
        region: 'auto',
        accessKeyId: 'ak',
        secretAccessKey: 'sk',
        isActive: name === 'p1',
        priority: name === 'p1' ? 0 : 1,
        updatedAt: Date.now(),
      });
  });
  await t.mutation(internal.mirrorCopies.markSeeded, {});
  return w;
}

/** A member with one active key on a backend instance (its body served by `w.backend`). */
async function member(w: World, short = 'shortA') {
  w.backend.set(short, body(`key-${short}`));
  return w.t.run(async (ctx) => {
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
    return { userId, subId, serverId };
  });
}

const copies = (t: T, subId?: Id<'subscriptions'>) =>
  t.run(async (ctx) =>
    (await ctx.db.query('mirrorCopies').collect()).filter(
      (c) => !subId || c.subscriptionId === subId,
    ),
  );
const counts = (t: T) => t.run(async (ctx) => (await readMirrorCopyCounts(ctx.db)).counts);
const sub = (t: T, id: Id<'subscriptions'>) => t.run((ctx) => ctx.db.get(id));
/** Every scheduled call of `name` so far (whatever ran since). */
const scheduled = (t: T, name: string) =>
  t.run(async (ctx) =>
    (await ctx.db.system.query('_scheduled_functions').collect()).filter((f) =>
      f.name.includes(name),
    ),
  );
const puts = (w: World) => w.calls.filter((c) => c.op.kind === 'put');
const deletes = (w: World) => w.calls.filter((c) => c.op.kind === 'delete');
const openUploads = (t: T) =>
  t.run((ctx) =>
    ctx.db
      .query('mirrorUploads')
      .withIndex('by_state', (q) => q.eq('state', 'open'))
      .collect(),
  );
/** Make every open obligation due now (past the in-flight grace and any backoff). */
const makeDue = (t: T) =>
  t.run(async (ctx) => {
    for (const r of await ctx.db.query('mirrorUploads').collect())
      await ctx.db.patch(r._id, {
        updatedAt: Date.now() - REPAIR_GRACE_MS - 1_000,
        ...(r.dueAt !== undefined ? { dueAt: Date.now() - 1 } : {}),
      });
  });

/** Give a key a mirror on these providers, its object holding `held` (FCP's ledger knows it). */
async function mirrored(
  w: World,
  subId: Id<'subscriptions'>,
  providers: (keyof typeof PROVIDERS)[],
  held: Record<string, string>,
  path = 'mirrors/m1',
) {
  await w.t.run(async (ctx) => {
    await ctx.db.patch(subId, {
      subscriptionMirrors: providers.map((p) => ({
        provider: p,
        publicUrl: `${PROVIDERS[p]}/${path}`,
        objectPath: path,
        status: 'ok' as const,
      })),
    });
  });
  for (const p of providers) w.objects.set(`${p}:${path}`, held[p]!);
  // The ledger learns the copies the way a legacy mirror does, then their
  // hashes are set to what the "bucket" holds.
  await w.t.mutation(internal.mirrorCopies.recordCheck, {
    subscriptionId: subId,
    deliveryRev: 0,
    countryRev: 0,
    at: Date.now(),
    served: null,
    outcomes: [],
  });
  const { sha256Hex } = await import('./lib/crypto');
  await w.t.run(async (ctx) => {
    for (const c of await ctx.db.query('mirrorCopies').collect())
      if (c.subscriptionId === subId)
        await ctx.db.patch(c._id, { objectHash: await sha256Hex(held[c.provider]!) });
  });
}

beforeEach(() => {
  vi.useRealTimers();
});
afterEach(() => {
  __setS3SendForTests(null);
  __setMirrorFetchForTests(null);
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe('a requested mirror is tracked', () => {
  test('provisioning records the copy in sync, counted, written with no-cache', async () => {
    const w = await world();
    const { userId, subId } = await member(w);
    const res = await w.t.action(internal.storage.provisionMirror, { userId, countryCode: null });
    expect(res.status).toBe('ok');
    const [c] = await copies(w.t, subId);
    expect(c).toMatchObject({ provider: 'p1', state: 'in_sync', failures: 0 });
    expect(c!.objectHash).toBe(c!.servedHash);
    expect(await counts(w.t)).toEqual({ in_sync: 1, stale: 0, failing: 0, never: 0 });
    expect(puts(w).at(-1)!.op).toMatchObject({ cacheControl: 'no-cache' });
    const summary = await w.t.query(internal.mirrorCopies.summary, {});
    expect(summary).toMatchObject({ attention: false, counts: { inSync: 1, total: 1 } });
  });

  test('the per-mirror feed names no member and no key (it is read with the settings scope)', async () => {
    const w = await world();
    const { userId, subId } = await member(w);
    await w.t.action(internal.storage.provisionMirror, { userId, countryCode: null });
    const { page } = await w.t.query(internal.mirrorCopies.listForAdmin, {
      cursor: null,
      numItems: 10,
    });
    expect(page).toHaveLength(1);
    const json = JSON.stringify(page);
    expect(json).not.toContain(userId);
    expect(json).not.toContain(subId);
    expect(json).not.toContain('mirrors/');
    expect(Object.keys(page[0]!)).not.toEqual(expect.arrayContaining(['userId']));
  });

  test('a refresh rewrites only the copies whose object differs', async () => {
    const w = await world();
    const { subId } = await member(w);
    await mirrored(w, subId, ['p1', 'p2'], { p1: 'old', p2: 'old' });
    await w.t.action(internal.storage.refreshMirrorsForSubscription, { subscriptionId: subId });
    expect(
      puts(w)
        .map((c) => c.provider)
        .sort(),
    ).toEqual(['p1', 'p2']);
    // Now p2's object is overwritten in the bucket and the ledger knows it.
    w.calls.length = 0;
    await w.t.run(async (ctx) => {
      const c = (await ctx.db.query('mirrorCopies').collect()).find((r) => r.provider === 'p2')!;
      await ctx.db.patch(c._id, { objectHash: 'something-else' });
    });
    await w.t.action(internal.storage.refreshMirrorsForSubscription, { subscriptionId: subId });
    expect(puts(w).map((c) => c.provider)).toEqual(['p2']);
    expect((await copies(w.t, subId)).map((c) => c.state)).toEqual(['in_sync', 'in_sync']);
  });

  test('a second mirror brings the older copy to the body it holds (no subscription-wide skip)', async () => {
    const w = await world();
    const { userId, subId } = await member(w);
    await w.t.action(internal.storage.provisionMirror, { userId, countryCode: null });
    // The backend body changes before the sweep comes round; the member asks
    // for a second mirror (p2 is made active for it).
    w.backend.set('shortA', body('key-shortA-v2'));
    await w.t.run(async (ctx) => {
      const p2 = (await ctx.db.query('mirrorProviders').collect()).find((p) => p.name === 'p2')!;
      await ctx.db.patch(p2._id, { isActive: true });
    });
    const res = await w.t.action(internal.storage.provisionMirror, { userId, countryCode: null });
    expect(res).toMatchObject({ status: 'ok', provider: 'p2' });
    const before = Object.fromEntries((await copies(w.t, subId)).map((c) => [c.provider, c.state]));
    expect(before).toEqual({ p1: 'stale', p2: 'in_sync' });
    // The hash only advances when every copy holds the body.
    expect((await sub(w.t, subId))!.rawContentHash).toBeUndefined();
    expect(await scheduled(w.t, 'refreshMirrorsForSubscription')).toHaveLength(1);
    await w.t.action(internal.storage.refreshMirrorsForSubscription, { subscriptionId: subId });
    expect(
      w.objects.get('p1:' + (await sub(w.t, subId))!.subscriptionMirrors[0]!.objectPath),
    ).toContain('key-shortA-v2');
    expect((await copies(w.t, subId)).every((c) => c.state === 'in_sync')).toBe(true);
  });

  test("a deactivated provider's mirrors keep being refreshed", async () => {
    const w = await world();
    const { subId } = await member(w);
    await mirrored(w, subId, ['p2'], { p2: 'old' }); // p2 is inactive
    const res = await w.t.action(internal.storage.refreshActiveMirrors, {});
    expect(res.refreshed).toBe(1);
    expect(w.objects.get('p2:mirrors/m1')).toContain('key-shortA');
  });
});

describe('the post-deploy seed', () => {
  test('gives a mirror without ledger rows its rows even when the ledger says it was seeded', async () => {
    // A rollback to code without the ledger can add mirrors after the first seed.
    const w = await world();
    const { subId } = await member(w);
    await w.t.run((ctx) =>
      ctx.db.patch(subId, {
        subscriptionMirrors: [
          { provider: 'p1', publicUrl: `${PROVIDERS.p1}/mirrors/r1`, objectPath: 'mirrors/r1' },
        ],
      }),
    );
    expect(await copies(w.t, subId)).toEqual([]);
    expect(await w.t.action(internal.storage.seedMirrorLedger, {})).toEqual({
      keys: 1,
      done: true,
    });
    expect((await copies(w.t, subId))[0]).toMatchObject({ state: 'stale', reason: 'unchecked' });
    expect(puts(w)).toEqual([]);
    // The next pass reaches it through the ledger.
    expect(await w.t.action(internal.storage.refreshActiveMirrors, {})).toMatchObject({
      scanned: 1,
    });
  });
});

describe('a change to what the member is served reaches the ledger', () => {
  test('an in-place move marks the copies stale and schedules their refresh', async () => {
    const w = await world();
    const { subId } = await member(w);
    await mirrored(w, subId, ['p1'], { p1: 'old' });
    await w.t.action(internal.storage.refreshMirrorsForSubscription, { subscriptionId: subId });
    await w.t.run(async (ctx) =>
      invalidateDelivery(ctx, (await ctx.db.get(subId))!, { refreshMirrors: true }),
    );
    expect((await copies(w.t, subId))[0]).toMatchObject({ state: 'stale', reason: 'invalidated' });
    expect(await counts(w.t)).toMatchObject({ stale: 1, in_sync: 0 });
  });

  test("the member's country changing re-renders their mirror now", async () => {
    const w = await world();
    const { subId } = await member(w);
    await mirrored(w, subId, ['p1'], { p1: 'old' });
    await w.t.run(async (ctx) => {
      await setStoredCountry(ctx, (await ctx.db.get(subId))!, { choice: 'ZZ' });
    });
    expect((await copies(w.t, subId))[0]).toMatchObject({
      state: 'stale',
      reason: 'country_changed',
    });
    expect(await scheduled(w.t, 'refreshMirrorsForSubscription')).toHaveLength(1);
  });

  test('a re-issue carries the copies, stale, and a superseded key drops its own', async () => {
    const w = await world();
    const { userId, subId } = await member(w);
    await mirrored(w, subId, ['p1'], { p1: 'old' });
    await w.t.action(internal.storage.refreshMirrorsForSubscription, { subscriptionId: subId });
    const old = (await sub(w.t, subId))!;
    w.backend.set('shortB', body('key-shortB'));
    const newSub = await w.t.mutation(internal.subscriptions.insertSubscription, {
      userId,
      backend: 'remnawave',
      backendUserId: 'u-shortB',
      backendShortId: 'shortB',
      backendServerId: old.backendServerId,
      subscriptionUrl: 'https://panel.test/sub/shortB',
      subscriptionMirrors: [],
      carrySubTokenFromId: subId,
    });
    expect(await copies(w.t, subId)).toEqual([]);
    expect((await copies(w.t, newSub))[0]).toMatchObject({ state: 'stale', reason: 'reissued' });
    await w.t.action(internal.storage.refreshMirrorsForSubscription, { subscriptionId: newSub });
    expect(w.objects.get('p1:mirrors/m1')).toContain('key-shortB');
    expect((await copies(w.t, newSub))[0]!.state).toBe('in_sync');
    // A regenerate-style tombstone of a mirrored key: its copies leave the ledger.
    await w.t.mutation(internal.subscriptions.tombstoneWithGrace, {
      backendUserId: 'u-shortB',
      graceMs: 86_400_000,
    });
    expect(await copies(w.t)).toEqual([]);
    expect(await counts(w.t)).toEqual({ in_sync: 0, stale: 0, failing: 0, never: 0 });
  });
});

describe('a carried object is never left with, or deleted under, the old key', () => {
  async function carried(w: World) {
    const { userId, subId } = await member(w);
    await mirrored(w, subId, ['p1'], { p1: 'old' });
    const old = (await sub(w.t, subId))!;
    w.backend.set('shortB', body('key-shortB'));
    const carry = () =>
      w.t.mutation(internal.subscriptions.insertSubscription, {
        userId,
        backend: 'remnawave',
        backendUserId: 'u-shortB',
        backendShortId: 'shortB',
        backendServerId: old.backendServerId,
        subscriptionUrl: 'https://panel.test/sub/shortB',
        subscriptionMirrors: [],
        carrySubTokenFromId: subId,
      });
    return { userId, subId, carry };
  }

  test("an old row's refresh that lands after the carry hands the object back to the live row", async () => {
    const w = await world();
    const { subId, carry } = await carried(w);
    let newSub: Id<'subscriptions'> | null = null;
    // The old row's refresh read the key, then the re-issue carried the
    // mirror away while its upload was in flight.
    w.duringPut.fn = async () => {
      newSub = await carry();
    };
    await w.t.action(internal.storage.refreshMirrorsForSubscription, { subscriptionId: subId });
    expect(w.objects.get('p1:mirrors/m1')).toContain('key-shortA'); // the stale write landed
    expect((await copies(w.t, newSub!))[0]).toMatchObject({
      state: 'stale',
      reason: 'overwritten',
    });
    const queued = await scheduled(w.t, 'refreshMirrorsForSubscription');
    expect(queued.map((f) => f.args[0])).toContainEqual({ subscriptionId: newSub });
    await w.t.action(internal.storage.refreshMirrorsForSubscription, { subscriptionId: newSub! });
    expect(w.objects.get('p1:mirrors/m1')).toContain('key-shortB');
    expect((await copies(w.t, newSub!))[0]!.state).toBe('in_sync');
    expect(deletes(w)).toEqual([]);
  });

  test('a record left on the old row repairs the object the new row serves, never withdraws it', async () => {
    const w = await world();
    const { subId, carry } = await carried(w);
    const newSub = await carry();
    // An obligation opened on the old row after the carry (an upload of it
    // that a policy move overtook), then the old key is tombstoned.
    await w.t.mutation(internal.mirrorUploads.open, {
      subscriptionId: subId,
      objectPath: 'mirrors/m1',
      providers: ['p1'],
      tokenBefore: null,
      kind: 'refresh',
    });
    await w.t.mutation(internal.subscriptions.tombstoneWithGrace, {
      backendUserId: 'u-shortA',
      graceMs: 86_400_000,
    });
    await makeDue(w.t);
    await w.t.action(internal.storage.repairMirrorUploads, {});
    expect(deletes(w)).toEqual([]);
    expect(w.objects.get('p1:mirrors/m1')).toContain('key-shortB');
    expect(await openUploads(w.t)).toEqual([]);
    expect((await copies(w.t, newSub))[0]!.state).toBe('in_sync');
  });
});

describe('a superseded key keeps its mirror through the grace', () => {
  test('a refresh that lands after a regenerate tombstoned the key settles, deleting nothing early', async () => {
    const w = await world();
    const { subId } = await member(w);
    await mirrored(w, subId, ['p1'], { p1: 'old' });
    w.duringPut.fn = async () => {
      await w.t.mutation(internal.subscriptions.tombstoneWithGrace, {
        backendUserId: 'u-shortA',
        graceMs: 86_400_000,
      });
    };
    await w.t.action(internal.storage.refreshMirrorsForSubscription, { subscriptionId: subId });
    expect(await openUploads(w.t)).toEqual([]);
    await makeDue(w.t);
    await w.t.action(internal.storage.repairMirrorUploads, {});
    expect(deletes(w)).toEqual([]);
    expect(w.objects.has('p1:mirrors/m1')).toBe(true);
  });
});

describe('copies nothing should serve are deleted until they are gone', () => {
  test("a member's cleared mirror whose delete failed is retried by the repair pass", async () => {
    const w = await world();
    const { userId, subId } = await member(w);
    await w.t.action(internal.storage.provisionMirror, { userId, countryCode: null });
    const path = (await sub(w.t, subId))!.subscriptionMirrors[0]!.objectPath!;
    w.fail.fn = (_p, op) => op.kind === 'delete';
    expect(await w.t.action(internal.storage.clearMirrorsForUser, { userId })).toEqual({
      removed: 1,
    });
    expect(w.objects.has(`p1:${path}`)).toBe(true);
    expect(await copies(w.t)).toEqual([]);
    const open = await openUploads(w.t);
    expect(open.map((o) => [o.kind, o.providers])).toEqual([['withdraw', ['p1']]]);
    // Still failing: the record stays.
    await w.t.action(internal.storage.repairMirrorUploads, {});
    expect(await openUploads(w.t)).toHaveLength(1);
    w.fail.fn = () => false;
    await makeDue(w.t);
    await w.t.action(internal.storage.repairMirrorUploads, {});
    expect(w.objects.has(`p1:${path}`)).toBe(false);
    expect(await openUploads(w.t)).toEqual([]);
  });

  test('a provider that keeps failing is retried with a growing backoff, not every five minutes', async () => {
    expect([1, 2, 3, 4, 5, 20].map(repairBackoffMs)).toEqual([
      REPAIR_GRACE_MS,
      REPAIR_GRACE_MS,
      2 * REPAIR_GRACE_MS,
      4 * REPAIR_GRACE_MS,
      8 * REPAIR_GRACE_MS,
      6 * 3_600_000,
    ]);
    const w = await world();
    const { subId } = await member(w);
    await mirrored(w, subId, ['p1'], { p1: 'old' });
    w.fail.fn = (_p, op) => op.kind === 'put';
    await w.t.mutation(internal.mirrorUploads.open, {
      subscriptionId: subId,
      objectPath: 'mirrors/m1',
      providers: ['p1'],
      tokenBefore: null,
      kind: 'refresh',
    });
    for (let i = 0; i < 3; i++) {
      await makeDue(w.t);
      await w.t.action(internal.storage.repairMirrorUploads, {});
    }
    const [o] = await openUploads(w.t);
    expect(o!.attempts).toBeGreaterThanOrEqual(1);
    // Not due again before its backoff ran out.
    expect(await w.t.query(internal.mirrorUploads.listDue, { now: Date.now() })).toEqual([]);
    expect((await copies(w.t, subId))[0]).toMatchObject({
      state: 'failing',
      reason: 'upload_failed',
    });
  });
});

describe('removing or renaming a provider', () => {
  test('removing one that holds mirrors withdraws them first, then the row goes', async () => {
    const w = await world();
    const { subId } = await member(w);
    await mirrored(w, subId, ['p1', 'p2'], { p1: 'x', p2: 'x' });
    const p1 = (await w.t.run((ctx) => ctx.db.query('mirrorProviders').collect())).find(
      (p) => p.name === 'p1',
    )!;
    w.fail.fn = (p, op) => p === 'p1' && op.kind === 'delete';
    const res = await w.t.mutation(internal.mirrorProviders.remove, { id: p1._id });
    expect(res).toEqual({ ok: true, removing: true });
    const listed = (await w.t.query(internal.mirrorProviders.listForAdmin, {})).providers;
    expect(listed.find((p) => p.name === 'p1')).toMatchObject({
      removing: true,
      isActive: false,
      mirrors: 1,
    });
    // New mirrors never go to a provider being removed.
    expect(
      await w.t.query(internal.mirrorProviders.selectNextProvider, {
        countryCode: null,
        tried: [],
      }),
    ).toBeNull();
    // A delete that fails keeps the copy (the provider holds the only credential).
    expect(
      await w.t.action(internal.storage.withdrawProviderMirrors, { providerId: p1._id }),
    ).toEqual({ withdrawn: 0, done: false });
    expect((await sub(w.t, subId))!.subscriptionMirrors.map((m) => m.provider)).toEqual([
      'p1',
      'p2',
    ]);
    w.fail.fn = () => false;
    expect(
      await w.t.action(internal.storage.withdrawProviderMirrors, { providerId: p1._id }),
    ).toEqual({ withdrawn: 1, done: true });
    expect(w.objects.has('p1:mirrors/m1')).toBe(false);
    expect(w.objects.has('p2:mirrors/m1')).toBe(true);
    expect((await sub(w.t, subId))!.subscriptionMirrors.map((m) => m.provider)).toEqual(['p2']);
    expect((await copies(w.t, subId)).map((c) => c.provider)).toEqual(['p2']);
    expect(await w.t.run((ctx) => ctx.db.get(p1._id))).toBeNull();
  });

  test('a provider holding mirrors cannot be renamed', async () => {
    const w = await world();
    const { subId } = await member(w);
    await mirrored(w, subId, ['p1'], { p1: 'x' });
    const p1 = (await w.t.run((ctx) => ctx.db.query('mirrorProviders').collect())).find(
      (p) => p.name === 'p1',
    )!;
    await expect(
      w.t.mutation(internal.mirrorProviders.update, { id: p1._id, name: 'renamed' }),
    ).rejects.toThrow(/name cannot change/);
    // Other edits still work.
    await w.t.mutation(internal.mirrorProviders.update, { id: p1._id, priority: 5 });
  });
});

describe('the member-facing URL is read back', () => {
  test('a deleted object is rewritten once; a URL that never serves it is then failing', async () => {
    const w = await world();
    const { userId, subId } = await member(w);
    await w.t.action(internal.storage.provisionMirror, { userId, countryCode: null });
    const path = (await sub(w.t, subId))!.subscriptionMirrors[0]!.objectPath!;
    let out = await w.t.action(internal.storage.verifyMirrorCopies, {});
    expect(out).toMatchObject({ read: 1, match: 1 });
    // Deleted out of band (a lifecycle rule, a hand clean-up).
    w.objects.delete(`p1:${path}`);
    await w.t.run(async (ctx) => {
      for (const c of await ctx.db.query('mirrorCopies').collect())
        await ctx.db.patch(c._id, { verifiedAt: Date.now() - 7 * 3_600_000 });
    });
    out = await w.t.action(internal.storage.verifyMirrorCopies, {});
    expect(out).toMatchObject({ missing: 1 });
    expect((await copies(w.t, subId))[0]).toMatchObject({ state: 'never', reason: 'missing' });
    const queued = await scheduled(w.t, 'refreshMirrorsForSubscription');
    expect(queued.map((f) => f.args[0])).toEqual([
      { subscriptionId: subId, forceProviders: ['p1'], verifyAfter: true },
    ]);
    await w.t.action(internal.storage.refreshMirrorsForSubscription, {
      subscriptionId: subId,
      forceProviders: ['p1'],
    });
    expect(w.objects.has(`p1:${path}`)).toBe(true);
    expect((await copies(w.t, subId))[0]!.state).toBe('in_sync');
    // The URL itself now serves nothing (the bucket stopped being public).
    w.urlOverride.status = 403;
    await w.t.run(async (ctx) => {
      for (const c of await ctx.db.query('mirrorCopies').collect())
        await ctx.db.patch(c._id, { recheckAt: Date.now() - 1 });
    });
    out = await w.t.action(internal.storage.verifyMirrorCopies, {});
    expect(out).toMatchObject({ missing: 1 });
    expect((await copies(w.t, subId))[0]).toMatchObject({
      state: 'failing',
      reason: 'url_unreadable',
    });
    // No upload loop: nothing new was scheduled for it.
    expect(await scheduled(w.t, 'refreshMirrorsForSubscription')).toHaveLength(1);
  });

  test('an admin re-check rewrites a deleted object and reads it back, so a later overwrite is repaired too', async () => {
    // Found on the beta walk: without the read after the rewrite, the next
    // problem (an unrelated overwrite) looked like "the rewrite did not help".
    const w = await world();
    const { userId, subId } = await member(w);
    await w.t.action(internal.storage.provisionMirror, { userId, countryCode: null });
    const path = (await sub(w.t, subId))!.subscriptionMirrors[0]!.objectPath!;
    const [c] = await copies(w.t, subId);
    w.objects.delete(`p1:${path}`);
    expect(await w.t.action(internal.storage.recheckCopy, { id: c!._id })).toEqual({ ok: true });
    expect(w.objects.has(`p1:${path}`)).toBe(true);
    expect((await copies(w.t, subId))[0]).toMatchObject({ state: 'in_sync', verify: 'match' });
    w.objects.set(`p1:${path}`, 'tampered');
    await w.t.action(internal.storage.recheckCopy, { id: c!._id });
    expect(w.objects.get(`p1:${path}`)).toContain('key-shortA');
    expect((await copies(w.t, subId))[0]).toMatchObject({ state: 'in_sync', verify: 'match' });
    // A URL that really serves nothing, even right after the rewrite: failing.
    w.urlOverride.status = 404;
    await w.t.action(internal.storage.recheckCopy, { id: c!._id });
    expect((await copies(w.t, subId))[0]).toMatchObject({
      state: 'failing',
      reason: 'url_unreadable',
    });
    // A refresh does not clear it; a read that matches does.
    await w.t.action(internal.storage.refreshMirrorsForSubscription, { subscriptionId: subId });
    expect((await copies(w.t, subId))[0]!.state).toBe('failing');
    w.urlOverride.status = null;
    await w.t.action(internal.storage.recheckCopy, { id: c!._id });
    expect((await copies(w.t, subId))[0]).toMatchObject({ state: 'in_sync', verify: 'match' });
  });

  test('an overwritten object is seen and rewritten', async () => {
    const w = await world();
    const { userId, subId } = await member(w);
    await w.t.action(internal.storage.provisionMirror, { userId, countryCode: null });
    const path = (await sub(w.t, subId))!.subscriptionMirrors[0]!.objectPath!;
    w.objects.set(`p1:${path}`, 'someone else');
    const out = await w.t.action(internal.storage.verifyMirrorCopies, {});
    expect(out).toMatchObject({ mismatch: 1 });
    expect((await copies(w.t, subId))[0]).toMatchObject({
      state: 'stale',
      reason: 'object_mismatch',
    });
    await w.t.action(internal.storage.refreshMirrorsForSubscription, {
      subscriptionId: subId,
      forceProviders: ['p1'],
    });
    expect(w.objects.get(`p1:${path}`)).toContain('key-shortA');
    expect((await copies(w.t, subId))[0]!.state).toBe('in_sync');
  });
});

describe('review fixes', () => {
  test('copies whose URL keeps failing never crowd the read-back queue', async () => {
    const w = await world();
    const { userId, subId } = await member(w);
    await w.t.action(internal.storage.provisionMirror, { userId, countryCode: null });
    // Three copies elsewhere whose URL keeps failing, read 20 minutes ago.
    await w.t.run(async (ctx) => {
      for (let i = 0; i < 3; i++) {
        const other = await ctx.db.insert('subscriptions', {
          userId,
          backend: 'remnawave',
          backendUserId: `u-x${i}`,
          backendShortId: `x${i}`,
          subscriptionUrl: `https://panel.test/sub/x${i}`,
          subscriptionMirrors: [],
          state: 'active',
          updatedAt: Date.now(),
        });
        await ctx.db.insert('mirrorCopies', {
          subscriptionId: other,
          provider: 'p1',
          objectPath: `mirrors/x${i}`,
          state: 'failing',
          reason: 'url_unreadable',
          since: Date.now() - 3_600_000,
          failures: 3,
          verify: 'missing',
          verifiedAt: Date.now() - 20 * 60_000,
          updatedAt: Date.now(),
        });
      }
    });
    // The new copy (never read) is still read first.
    const due = await w.t.query(internal.mirrorCopies.dueForVerify, { now: Date.now(), limit: 1 });
    expect(due.rows.map((r) => r.subscriptionId)).toEqual([subId]);
  });

  test('an open withdrawal record naming a provider keeps it until the repair pass has deleted the object', async () => {
    const w = await world();
    const { userId, subId } = await member(w);
    await w.t.action(internal.storage.provisionMirror, { userId, countryCode: null });
    const path = (await sub(w.t, subId))!.subscriptionMirrors[0]!.objectPath!;
    w.fail.fn = (_p, op) => op.kind === 'delete';
    await w.t.action(internal.storage.clearMirrorsForUser, { userId });
    const p1 = (await w.t.run((ctx) => ctx.db.query('mirrorProviders').collect())).find(
      (p) => p.name === 'p1',
    )!;
    // No copy is left on p1, but the failed delete still needs its credentials.
    expect(await w.t.mutation(internal.mirrorProviders.remove, { id: p1._id })).toEqual({
      ok: true,
      removing: true,
    });
    await expect(
      w.t.mutation(internal.mirrorProviders.update, { id: p1._id, name: 'x' }),
    ).rejects.toThrow();
    expect(
      await w.t.action(internal.storage.withdrawProviderMirrors, { providerId: p1._id }),
    ).toEqual({ withdrawn: 0, done: false });
    expect(await w.t.run((ctx) => ctx.db.get(p1._id))).not.toBeNull();
    w.fail.fn = () => false;
    await makeDue(w.t);
    await w.t.action(internal.storage.repairMirrorUploads, {});
    expect(w.objects.has(`p1:${path}`)).toBe(false);
    expect(
      await w.t.action(internal.storage.withdrawProviderMirrors, { providerId: p1._id }),
    ).toEqual({ withdrawn: 0, done: true });
    expect(await w.t.run((ctx) => ctx.db.get(p1._id))).toBeNull();
  });

  test('the withdrawal count is carried across runs into the audit', async () => {
    const w = await world();
    const a = await member(w, 'shortA');
    const b = await member(w, 'shortB');
    await mirrored(w, a.subId, ['p1'], { p1: 'x' }, 'mirrors/a');
    await mirrored(w, b.subId, ['p1'], { p1: 'x' }, 'mirrors/b');
    const p1 = (await w.t.run((ctx) => ctx.db.query('mirrorProviders').collect())).find(
      (p) => p.name === 'p1',
    )!;
    await w.t.mutation(internal.mirrorProviders.remove, { id: p1._id });
    // One earlier run already withdrew 5 (another key, gone before this run).
    expect(
      await w.t.action(internal.storage.withdrawProviderMirrors, {
        providerId: p1._id,
        withdrawn: 5,
      }),
    ).toEqual({ withdrawn: 7, done: true });
    const audit = await w.t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.find((r) => r.action === 'mirror_provider.withdrawn')!.payload).toMatchObject({
      mirrors: 7,
    });
  });

  test('a removal resumes its ledger seed from where it stopped', async () => {
    const w = await world();
    const { subId } = await member(w);
    await w.t.run(async (ctx) => {
      const seeded = await ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', 'mirror-copies:seeded'))
        .unique();
      await ctx.db.delete(seeded!._id);
      await ctx.db.patch(subId, {
        subscriptionMirrors: [
          { provider: 'p1', publicUrl: `${PROVIDERS.p1}/mirrors/l1`, objectPath: 'mirrors/l1' },
        ],
      });
    });
    w.objects.set('p1:mirrors/l1', 'legacy');
    const p1 = (await w.t.run((ctx) => ctx.db.query('mirrorProviders').collect())).find(
      (p) => p.name === 'p1',
    )!;
    expect(await w.t.mutation(internal.mirrorProviders.remove, { id: p1._id })).toMatchObject({
      removing: true,
    });
    expect(
      await w.t.action(internal.storage.withdrawProviderMirrors, { providerId: p1._id }),
    ).toEqual({ withdrawn: 1, done: true });
    expect(w.objects.has('p1:mirrors/l1')).toBe(false);
    expect(await w.t.query(internal.mirrorCopies.isSeeded, {})).toBe(true);
  });
});

describe('counts, attention and the reconcile', () => {
  test('a copy failing past the bound is attention; the reconcile rebuilds the counter', async () => {
    const w = await world();
    const { subId } = await member(w);
    await mirrored(w, subId, ['p1'], { p1: 'old' });
    w.fail.fn = (_p, op) => op.kind === 'put';
    await w.t.action(internal.storage.refreshMirrorsForSubscription, { subscriptionId: subId });
    expect(await counts(w.t)).toMatchObject({ failing: 1 });
    let summary = await w.t.query(internal.mirrorCopies.summary, {});
    expect(summary.attention).toBe(false); // not past the bound yet
    await w.t.run(async (ctx) => {
      for (const c of await ctx.db.query('mirrorCopies').collect())
        await ctx.db.patch(c._id, { since: Date.now() - 2 * 3_600_000 });
    });
    summary = await w.t.query(internal.mirrorCopies.summary, {});
    expect(summary).toMatchObject({ attention: true, overdue: { failing: { count: 1 } } });
    // A drifted counter and an orphaned row are healed by the daily reconcile.
    await w.t.run(async (ctx) => {
      const row = await ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', 'stats:mirrorCopies'))
        .unique();
      await ctx.db.patch(row!._id, { value: JSON.stringify({ in_sync: 9, failing: 0 }) });
      await ctx.db.insert('mirrorCopies', {
        subscriptionId: subId,
        provider: 'ghost',
        objectPath: 'mirrors/m1',
        state: 'stale',
        since: Date.now(),
        failures: 0,
        updatedAt: Date.now(),
      });
    });
    const res = await w.t.action(internal.mirrorCopies.reconcile, {});
    expect(res.dropped).toBe(1);
    expect(res.counts).toEqual({ in_sync: 0, stale: 0, failing: 1, never: 0 });
  });

  test('the status summary carries the figures, and the member gate follows the cap', async () => {
    const w = await world();
    const { userId } = await member(w);
    await w.t.action(internal.storage.provisionMirror, { userId, countryCode: null });
    const status = await w.t.query(internal.adminApi.statusSummary, {});
    expect(status.mirrors).toMatchObject({ counts: { inSync: 1, total: 1 }, attention: false });
    expect((await w.t.query(api.publicConfig.get, {})).mirrorsEnabled).toBe(true);
    await w.t.run((ctx) =>
      ctx.db.insert('appSettings', { key: 'mirror.maxPerUser', value: '0', updatedAt: Date.now() }),
    );
    expect((await w.t.query(api.publicConfig.get, {})).mirrorsEnabled).toBe(false);
  });
});
