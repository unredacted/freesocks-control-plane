import { describe, expect, it } from 'vitest';
import {
  FastlyKvStore,
  type FastlyKVEntry,
  type FastlyKVNamespace,
} from '../../../src/server/kv/fastly';

/**
 * Fastly KV has no native TTL. `FastlyKvStore` simulates it by wrapping every
 * value in a `{ __exp, v }` envelope and checking the expiry on read.
 *
 * These tests pin down:
 *   - The envelope format (so future refactors don't accidentally break it).
 *   - Expired entries return null even though the underlying KV row still
 *     exists.
 *   - Non-envelope strings (written by an older version of this code, or by
 *     a different tool altogether) pass through unchanged. Backwards-compat
 *     matters because we can't atomically rewrite every entry on upgrade.
 *   - `list()` throws — surfacing a Fastly-specific limitation loudly rather
 *     than returning empty.
 */

/** In-memory `FastlyKVNamespace` for tests. */
function makeNamespace(): FastlyKVNamespace & { _store: Map<string, string> } {
  const store = new Map<string, string>();
  return {
    _store: store,
    async get(key) {
      const v = store.get(key);
      if (v === undefined) return null;
      const entry: FastlyKVEntry = {
        text: async () => v,
        arrayBuffer: async () => new TextEncoder().encode(v).buffer as ArrayBuffer,
      };
      return entry;
    },
    async put(key, value) {
      // Tests only pass strings (the production code does too — the union
      // type is for type compatibility with Fastly's broader signature).
      store.set(key, value as string);
    },
    async delete(key) {
      store.delete(key);
    },
  };
}

describe('FastlyKvStore', () => {
  it('writes a JSON envelope so the format is recoverable across deploys', async () => {
    const ns = makeNamespace();
    const kv = new FastlyKvStore(ns);
    await kv.put('hello', 'world');
    const raw = ns._store.get('hello')!;
    const parsed = JSON.parse(raw);
    expect(parsed).toMatchObject({ v: 'world' });
    expect(parsed.__exp).toBeNull(); // no TTL = no expiry
  });

  it('roundtrips a value without TTL', async () => {
    const ns = makeNamespace();
    const kv = new FastlyKvStore(ns);
    await kv.put('hello', 'world');
    expect(await kv.get('hello')).toBe('world');
  });

  it('applies expirationTtl as a relative window from now()', async () => {
    const ns = makeNamespace();
    const kv = new FastlyKvStore(ns);
    await kv.put('hot', 'v', { expirationTtl: 60 });
    const env = JSON.parse(ns._store.get('hot')!);
    // Should land within a couple seconds of "now + 60s".
    const delta = env.__exp - Date.now();
    expect(delta).toBeGreaterThan(55_000);
    expect(delta).toBeLessThan(65_000);
  });

  it('returns null for an entry past its expiry', async () => {
    const ns = makeNamespace();
    const kv = new FastlyKvStore(ns);
    // Write an entry that expired 1ms ago. We write the envelope directly to
    // avoid depending on real time.
    ns._store.set('stale', JSON.stringify({ __exp: Date.now() - 1, v: 'should-be-gone' }));
    expect(await kv.get('stale')).toBeNull();
  });

  it('returns the value for an entry not yet expired', async () => {
    const ns = makeNamespace();
    const kv = new FastlyKvStore(ns);
    ns._store.set('fresh', JSON.stringify({ __exp: Date.now() + 60_000, v: 'still-good' }));
    expect(await kv.get('fresh')).toBe('still-good');
  });

  it('falls through non-envelope strings unchanged (backwards-compat with raw writes)', async () => {
    const ns = makeNamespace();
    const kv = new FastlyKvStore(ns);
    // A value written by a previous version of this code, or by an external
    // tool, won't have the envelope. The store should pass it through rather
    // than return null.
    ns._store.set('legacy', 'plain-string');
    expect(await kv.get('legacy')).toBe('plain-string');
  });

  it('falls through envelope-shaped but malformed JSON (no `v` field)', async () => {
    const ns = makeNamespace();
    const kv = new FastlyKvStore(ns);
    // Looks like JSON, but doesn't match our envelope shape — treat as raw.
    ns._store.set('malformed', JSON.stringify({ unrelated: true }));
    expect(await kv.get('malformed')).toBe(JSON.stringify({ unrelated: true }));
  });

  it('getJson handles wrapped JSON values', async () => {
    const ns = makeNamespace();
    const kv = new FastlyKvStore(ns);
    await kv.putJson('obj', { a: 1, b: 'two' });
    expect(await kv.getJson<{ a: number; b: string }>('obj')).toEqual({ a: 1, b: 'two' });
  });

  it('delete removes the entry', async () => {
    const ns = makeNamespace();
    const kv = new FastlyKvStore(ns);
    await kv.put('gone', 'soon');
    await kv.delete('gone');
    expect(await kv.get('gone')).toBeNull();
  });

  it('list() throws to surface the Fastly limitation', async () => {
    const ns = makeNamespace();
    const kv = new FastlyKvStore(ns);
    await expect(kv.list()).rejects.toThrow(/not implemented/);
  });
});
