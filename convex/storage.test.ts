// @vitest-environment node
/// <reference types="vite/client" />
import { afterEach, describe, expect, test, vi } from 'vitest';
import { convexTest } from 'convex-test';
import schema from './schema';
import { internal } from './_generated/api';
import { pinSubscriptionToNode } from './lib/nodePinning';
import { sha256Hex } from './lib/crypto';
import {
  deleteFromProviders,
  uploadToProviders,
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
    ).resolves.toBeUndefined();
    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual({ bucket: 'bucket-1', op: { kind: 'delete', key: 'subs/abc' } });
  });

  test('swallows a delete failure (best-effort)', async () => {
    const { send } = recorder(() => true);
    await expect(
      deleteFromProviders([provider(1)], [{ provider: 'p1', objectPath: 'subs/abc' }], send),
    ).resolves.toBeUndefined();
  });
});

const modules = import.meta.glob('./**/*.*s');

/** Two nodes' links, so the pin has a real choice to make. */
const RAW = [
  'vless://a@1.1.1.1:443?type=ws#xray1-ws',
  'vless://b@2.2.2.2:443?type=ws#xray2-ws',
].join('\n');

describe('mirror refresh records the pinned node', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  /** A mirrored sub whose stored hash may or may not match what the panel serves. */
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
    const subId = await seedMirroredSub(t, await sha256Hex(pinned.content));
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(RAW, { status: 200 })),
    );

    await t.action(internal.storage.refreshActiveMirrors, {});

    await t.run(async (ctx) => {
      expect((await ctx.db.get(subId))!.pinnedNode).toBe(pinned.node);
    });
  });
});
