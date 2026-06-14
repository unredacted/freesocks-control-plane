// @vitest-environment node
import { afterEach, describe, expect, test, vi } from 'vitest';
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
