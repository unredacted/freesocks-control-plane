// @vitest-environment node
/// <reference types="vite/client" />
import { afterEach, describe, expect, test, vi } from 'vitest';
import { convexTest } from 'convex-test';
import schema from './schema';
import { internal } from './_generated/api';
import { pinSubscriptionToNode } from './lib/nodePinning';
import { relabelMemberEntries } from './lib/memberEntryNames';
import { sha256Hex } from './lib/crypto';
import { scheduleMirrorRefresh } from './lib/edges/relayGuards';
import {
  deleteFromProviders,
  realFetch,
  uploadToProviders,
  verifyCopy,
  type S3Op,
  type S3Provider,
  type S3Send,
} from './storage';

function provider(i: number, over: Partial<S3Provider> = {}): S3Provider {
  return {
    name: `p${i}`,
    endpoint: `https://s3-${i}.example.com`,
    bucket: `bucket-${i}`,
    // p1 has a trailing slash, others do not: covers the publicUrl join both ways.
    publicUrl: i === 1 ? 'https://cdn-1.example.com/' : `https://cdn-${i}.example.com`,
    region: 'us-east-1',
    accessKeyId: `ak${i}`,
    secretAccessKey: `sk${i}`,
    ...over,
  };
}

/** A deterministic injected S3 send that records calls and can fail per-provider. */
function recorder(fail?: (p: S3Provider) => boolean): {
  send: S3Send;
  calls: { bucket: string; op: S3Op }[];
} {
  const calls: { bucket: string; op: S3Op }[] = [];
  const send: S3Send = async (p, op) => {
    calls.push({ bucket: p.bucket, op });
    if (fail?.(p)) throw new Error(`send failed for ${p.bucket}`);
  };
  return { send, calls };
}

afterEach(() => vi.unstubAllEnvs());

describe('uploadToProviders', () => {
  test('returns [] and sends nothing when there are no providers', async () => {
    const { send, calls } = recorder();
    const out = await uploadToProviders([], { objectPath: 'subs/abc', content: 'x' }, send);
    expect(out).toEqual([]);
    expect(calls).toHaveLength(0);
  });

  test('uploads to every provider and builds the public URL (slash-normalized)', async () => {
    const { send, calls } = recorder();
    const out = await uploadToProviders(
      [provider(1), provider(2)],
      { objectPath: 'subs/abc', content: 'hello', contentType: 'text/yaml' },
      send,
    );
    expect(calls).toHaveLength(2);
    expect(out).toEqual(
      expect.arrayContaining([
        {
          provider: 'p1',
          publicUrl: 'https://cdn-1.example.com/subs/abc',
          objectPath: 'subs/abc',
          status: 'ok',
        },
        {
          provider: 'p2',
          publicUrl: 'https://cdn-2.example.com/subs/abc',
          objectPath: 'subs/abc',
          status: 'ok',
        },
      ]),
    );
    // The object key + content-type are forwarded on the put op.
    expect(
      calls.every(
        (c) => c.op.kind === 'put' && c.op.key === 'subs/abc' && c.op.contentType === 'text/yaml',
      ),
    ).toBe(true);
  });

  test('defaults the content-type to text/plain', async () => {
    const { send, calls } = recorder();
    await uploadToProviders([provider(1)], { objectPath: 'subs/abc', content: 'hi' }, send);
    expect(calls[0]!.op).toMatchObject({ kind: 'put', contentType: 'text/plain' });
  });

  test('returns only the successful mirrors when one provider fails', async () => {
    const { send } = recorder((p) => p.bucket === 'bucket-2');
    const out = await uploadToProviders(
      [provider(1), provider(2)],
      { objectPath: 'subs/abc', content: 'hello' },
      send,
    );
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ provider: 'p1', status: 'ok' });
  });

  test('throws when every provider upload fails', async () => {
    const { send } = recorder(() => true);
    await expect(
      uploadToProviders(
        [provider(1), provider(2)],
        { objectPath: 'subs/abc', content: 'hello' },
        send,
      ),
    ).rejects.toThrow(/All S3 mirror uploads failed/);
  });
});

describe('reading a copy back (realFetch + verifyCopy)', () => {
  afterEach(() => vi.unstubAllGlobals());
  const big = 5 * 1024 * 1024;

  test('a declared length past the bound is refused unread, as another body', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('x', { headers: { 'content-length': String(big) } })),
    );
    expect(await realFetch('https://cdn.example/m')).toEqual({
      status: 200,
      body: null,
      oversize: true,
    });
    expect(await verifyCopy(realFetch, 'https://cdn.example/m', 'h')).toEqual({
      kind: 'mismatch',
      observedHash: 'oversize',
    });
  });

  test('an undeclared body is cut at the bound while streaming', async () => {
    let sent = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(c) {
        if (sent > 2 * big) return c.close();
        sent += 1024 * 1024;
        c.enqueue(new Uint8Array(1024 * 1024));
      },
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(stream)),
    );
    expect(await realFetch('https://cdn.example/m')).toMatchObject({ oversize: true });
    expect(sent).toBeLessThan(2 * big);
  });

  test('a normal body is read and hashed', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('hello')),
    );
    expect(await verifyCopy(realFetch, 'https://cdn.example/m', await sha256Hex('hello'))).toEqual({
      kind: 'match',
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('gone', { status: 404 })),
    );
    expect(await verifyCopy(realFetch, 'https://cdn.example/m', 'h')).toEqual({ kind: 'missing' });
  });
});

describe('deleteFromProviders', () => {
  test('deletes known providers and skips unknown ones without throwing', async () => {
    const { send, calls } = recorder();
    await expect(
      deleteFromProviders(
        [provider(1)],
        [
          { provider: 'p1', objectPath: 'subs/abc' },
          { provider: 'ghost', objectPath: 'subs/xyz' },
        ],
        send,
      ),
    ).resolves.toEqual({ failed: [] });
    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual({ bucket: 'bucket-1', op: { kind: 'delete', key: 'subs/abc' } });
  });

  test('never throws on a delete failure, and names the provider it failed on', async () => {
    const { send } = recorder(() => true);
    await expect(
      deleteFromProviders([provider(1)], [{ provider: 'p1', objectPath: 'subs/abc' }], send),
    ).resolves.toEqual({ failed: ['p1'] });
  });
});

const modules = import.meta.glob('./**/*.*s');

/** Two nodes' links, so the pin has a real choice to make. */
const RAW = [
  'vless://a@1.1.1.1:443?type=ws#xray1-ws',
  'vless://b@2.2.2.2:443?type=ws#xray2-ws',
].join('\n');

/** What a mirror holds for a pinned body: the member-facing names (no location set here). */
const memberBody = (pinned: string) =>
  relabelMemberEntries(pinned, { siteName: 'FreeSocks', place: null }).content;

describe('mirror refresh records the pinned node', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  /** A mirrored sub whose stored hash may or may not match what the backend serves. */
  async function seedMirroredSub(t: ReturnType<typeof convexTest>, rawContentHash: string) {
    return t.run(async (ctx) => {
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
      const instanceId = await ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'n1',
        slug: 'n1',
        config: { type: 'remnawave', baseUrl: 'https://panel.test', apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 1,
        updatedAt: Date.now(),
      });
      await ctx.db.insert('mirrorProviders', {
        name: 'p1',
        endpoint: 'https://s3.invalid',
        bucket: 'b',
        publicUrl: 'https://cdn.test',
        region: 'auto',
        accessKeyId: 'ak',
        secretAccessKey: 'sk',
        isActive: true,
        priority: 0,
        updatedAt: Date.now(),
      });
      return ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'k1',
        backendShortId: 'short1',
        backendServerId: instanceId,
        subscriptionUrl: 'https://panel.test/sub/short1',
        subscriptionMirrors: [{ provider: 'p1', publicUrl: 'https://cdn.test/x', objectPath: 'x' }],
        rawContentHash,
        state: 'active',
        updatedAt: Date.now(),
      });
    });
  }

  test('does NOT record the pin when every mirror upload fails', async () => {
    // The mirror still serves the OLD node, so recording the new one would make
    // the member's next switch exclude a node they are not actually on.
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const t = convexTest(schema, modules);
    // A hash that cannot match → the refresh attempts an upload, which fails
    // against the unroutable endpoint above.
    const subId = await seedMirroredSub(t, 'stale-hash');
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(RAW, { status: 200 })),
    );

    await t.action(internal.storage.refreshActiveMirrors, {});

    await t.run(async (ctx) => {
      expect((await ctx.db.get(subId))!.pinnedNode).toBeUndefined();
    });
  }, 20_000);

  test('persists the node even when the content hash is unchanged', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const t = convexTest(schema, modules);
    // What the refresh sees AFTER pinning — stored as rawContentHash so the
    // upload short-circuits and the only observable effect is the recorded pin.
    const pinned = pinSubscriptionToNode(RAW, 'short1');
    expect(pinned.node).toBeTruthy();
    const subId = await seedMirroredSub(t, await sha256Hex(memberBody(pinned.content)));
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(RAW, { status: 200 })),
    );

    await t.action(internal.storage.refreshActiveMirrors, {});

    await t.run(async (ctx) => {
      expect((await ctx.db.get(subId))!.pinnedNode).toBe(pinned.node);
    });
  });

  test('a mirror holds the member-facing names, never the backend’s node names', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const t = convexTest(schema, modules);
    const pinned = pinSubscriptionToNode(RAW, 'short1');
    expect(memberBody(pinned.content)).not.toContain(pinned.node!);
    // The stored hash of the body WITH the node names does not describe what
    // the refresh would upload: it tries to re-upload (and fails against the
    // unroutable endpoint), so the pin stays unrecorded.
    const subId = await seedMirroredSub(t, await sha256Hex(pinned.content));
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(RAW, { status: 200 })),
    );
    await t.action(internal.storage.refreshActiveMirrors, {});
    await t.run(async (ctx) => {
      expect((await ctx.db.get(subId))!.pinnedNode).toBeUndefined();
    });
  }, 20_000);

  test('stamps lastDeliveredContentAt once the mirror provably holds the current content (mirror-only members are not "never refreshed")', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const t = convexTest(schema, modules);
    const pinned = pinSubscriptionToNode(RAW, 'short1');
    const subId = await seedMirroredSub(t, await sha256Hex(memberBody(pinned.content)));
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(RAW, { status: 200 })),
    );
    const before = Date.now();
    await t.action(internal.storage.refreshActiveMirrors, {});
    await t.run(async (ctx) => {
      const sub = (await ctx.db.get(subId))!;
      expect(sub.lastDeliveredContentAt).toBeGreaterThanOrEqual(before);
      // No fronted delivery happened, and no origin origin renders this node.
      expect(sub.lastDeliveredAt).toBeUndefined();
      expect(sub.lastRenderedEpoch).toBeUndefined();
    });
  });

  test('a failed upload round stamps nothing (the mirror still serves the old content)', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const t = convexTest(schema, modules);
    const subId = await seedMirroredSub(t, 'stale-hash');
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(RAW, { status: 200 })),
    );
    await t.action(internal.storage.refreshActiveMirrors, {});
    await t.run(async (ctx) => {
      expect((await ctx.db.get(subId))!.lastDeliveredContentAt).toBeUndefined();
    });
  }, 20_000);
});

describe('provisionMirror honours the pending node switch', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  test('excludes the node the member left, and records the one it landed on', async () => {
    // A member who switches servers and then provisions their FIRST mirror
    // before ever fetching /sub. Without the exclusion the deterministic picker
    // uploads the node they just left; without the pin write their next switch
    // finds nothing to rotate.
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const t = convexTest(schema, modules);
    const left = pinSubscriptionToNode(RAW, 'short1').node!;
    const expected = pinSubscriptionToNode(RAW, 'short1', left).node!;
    expect(expected).not.toBe(left); // the fixture really does offer a choice

    const { userId, subId } = await t.run(async (ctx) => {
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
      const instanceId = await ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'n1',
        slug: 'n1',
        config: { type: 'remnawave', baseUrl: 'https://panel.test', apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 1,
        updatedAt: Date.now(),
      });
      await ctx.db.insert('mirrorProviders', {
        name: 'p1',
        endpoint: 'https://s3.invalid',
        bucket: 'b',
        publicUrl: 'https://cdn.test',
        region: 'auto',
        accessKeyId: 'ak',
        secretAccessKey: 'sk',
        isActive: true,
        priority: 0,
        updatedAt: Date.now(),
      });
      const subId = await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'k1',
        backendShortId: 'short1',
        backendServerId: instanceId,
        subscriptionUrl: 'https://panel.test/sub/short1',
        subscriptionMirrors: [],
        // Mid-switch: the pin was rotated away and no fetch has happened yet.
        excludeNode: left,
        state: 'active',
        updatedAt: Date.now(),
      });
      await ctx.db.patch(userId, { currentSubscriptionId: subId });
      return { userId, subId };
    });

    const uploaded: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL) => {
        // The S3 PUT goes through the AWS SDK, not fetch; only the backend read
        // lands here.
        uploaded.push(String(input));
        return new Response(RAW, { status: 200 });
      }),
    );

    const res = await t.action(internal.storage.provisionMirror, { userId, countryCode: null });

    // The backend read happened (so the fetch leg ran with the exclusion applied)
    // and the upload then failed against the unroutable S3 endpoint.
    expect(uploaded.some((u) => u.includes('/sub/short1'))).toBe(true);
    expect(res.status).toBe('error');
    await t.run(async (ctx) => {
      // A failed upload must NOT record the pin — same rule as the refresh path.
      expect((await ctx.db.get(subId))!.pinnedNode).toBeUndefined();
      // ...and no mirror entry was appended for an object that isn't there.
      expect((await ctx.db.get(subId))!.subscriptionMirrors).toEqual([]);
    });
  }, 20_000);
});

describe('a change members must see reaches every mirror in one pass', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  test('a triggered refresh renders a mirrored key far past the sweep window', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    vi.useFakeTimers();
    const t = convexTest(schema, modules);
    const pinned = pinSubscriptionToNode(RAW, 'short-last');
    const hash = await sha256Hex(memberBody(pinned.content));
    const subId = await t.run(async (ctx) => {
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
      const backendServerId = await ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'n1',
        slug: 'n1',
        config: { type: 'remnawave', baseUrl: 'https://panel.test', apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 1,
        updatedAt: Date.now(),
      });
      await ctx.db.insert('mirrorProviders', {
        name: 'p1',
        endpoint: 'https://s3.invalid',
        bucket: 'b',
        publicUrl: 'https://cdn.test',
        region: 'auto',
        accessKeyId: 'ak',
        secretAccessKey: 'sk',
        isActive: true,
        priority: 0,
        updatedAt: Date.now(),
      });
      const key = (i: number) => ({
        userId,
        backend: 'remnawave' as const,
        backendUserId: `k${i}`,
        backendShortId: `short${i}`,
        backendServerId,
        subscriptionUrl: `https://panel.test/sub/short${i}`,
        subscriptionMirrors: [],
        state: 'active' as const,
        updatedAt: Date.now(),
      });
      // More active keys than one sweep run reads, and the one mirrored key last.
      for (let i = 0; i < 2600; i++) await ctx.db.insert('subscriptions', key(i));
      return ctx.db.insert('subscriptions', {
        ...key(2600),
        backendShortId: 'short-last',
        subscriptionMirrors: [{ provider: 'p1', publicUrl: 'https://cdn.test/x', objectPath: 'x' }],
        rawContentHash: hash,
      });
    });
    const fetches = vi.fn(async () => new Response(RAW, { status: 200 }));
    vi.stubGlobal('fetch', fetches);
    await t.run((ctx) => scheduleMirrorRefresh(ctx));
    await t.finishAllScheduledFunctions(vi.runAllTimers);
    expect(fetches).toHaveBeenCalledTimes(1);
    expect((await t.run((ctx) => ctx.db.get(subId)))!.lastDeliveredContentAt).toBeDefined();
  }, 60_000);

  test('a pass that ends because no mirror provider is left frees the pass for the next request', async () => {
    vi.useFakeTimers();
    const t = convexTest(schema, modules);
    const claim = () => t.mutation(internal.mirrorProviders.claimMirrorPass, {});
    expect(await claim()).toBe(true);
    // A request while it runs: it is to go round once more.
    expect(await claim()).toBe(false);
    // The last provider is gone when the pass continues.
    await t.action(internal.storage.drainMirrors, { cursor: null, pass: 'continue' });
    await t.finishAllScheduledFunctions(vi.runAllTimers);
    // Nothing runs any more: the next request starts a pass of its own.
    expect(await claim()).toBe(true);
  });

  test('requests while a pass runs make it go round once more, not once each', async () => {
    const t = convexTest(schema, modules);
    const claim = () => t.mutation(internal.mirrorProviders.claimMirrorPass, {});
    const progress = (done: boolean) =>
      t.mutation(internal.mirrorProviders.noteMirrorPass, { done });
    expect(await claim()).toBe(true);
    expect(await claim()).toBe(false);
    expect(await claim()).toBe(false);
    expect(await progress(false)).toBe(false);
    // The end of the pass: one more round for the two requests it absorbed...
    expect(await progress(true)).toBe(true);
    // ...and then it is over: the next request starts a pass of its own.
    expect(await progress(true)).toBe(false);
    expect(await claim()).toBe(true);
  });
});
