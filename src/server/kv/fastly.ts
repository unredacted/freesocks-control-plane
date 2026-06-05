import type { KvListResult, KvPutOptions, KvStore } from './interface';

/**
 * Subset of the Fastly Compute KVStore API surface we depend on. We don't
 * import the real `fastly:kv-store` types here because they only resolve under
 * the Fastly build toolchain — typing the namespace structurally keeps
 * `tsc -b` happy on Workers and Node builds where the binding doesn't exist.
 *
 * @see https://js-compute-reference-docs.edgecompute.app/docs/fastly:kv-store/
 */
export interface FastlyKVEntry {
  text(): Promise<string>;
  arrayBuffer(): Promise<ArrayBuffer>;
}

export interface FastlyKVNamespace {
  get(key: string): Promise<FastlyKVEntry | null>;
  put(key: string, value: string | ArrayBuffer | ReadableStream): Promise<void>;
  delete(key: string): Promise<void>;
}

/**
 * KvStore implementation backed by Fastly Compute's KV Store
 * (`fastly:kv-store`).
 *
 * Fastly KV does NOT support a native per-item TTL. To preserve the contract
 * that callers expect from Workers KV — "this entry disappears after N
 * seconds" — every value we write is wrapped in an envelope:
 *
 *     { "__exp": <ms epoch>|null, "v": "<original-string>" }
 *
 * On read, we check `__exp` and return `null` if it's in the past. Expired
 * envelopes stick around in the store until either (a) the key is overwritten
 * or (b) the periodic cleanup job sweeps them — Fastly itself never collects
 * them.
 *
 * Reasoning for the envelope approach over a separate "sweeper" cron:
 *   - Fastly Compute has no native cron. A reaper would require an external
 *     trigger anyway.
 *   - Stale-but-fenced entries are correct from the application's
 *     perspective; storage cost on Fastly KV is negligible for our key sets
 *     (sessions, hot caches, rate-limit windows that turn over hourly).
 *   - Envelope reads are O(1) and the JSON.parse cost is trivial for the
 *     short strings we store.
 *
 * Limitations vs. Workers KV:
 *   - `list()` is not exposed by Fastly KV's JS SDK. Callers that need to
 *     enumerate keys are not supported on Fastly today; this implementation
 *     throws to surface the limitation loudly. (None of our hot paths use
 *     `list` — it's only used by the admin "show me everything in cache"
 *     diagnostic, which we leave Workers-only.)
 *   - `metadata` is not preserved; we drop it. Callers that rely on metadata
 *     for indexing won't work on Fastly.
 */
export class FastlyKvStore implements KvStore {
  constructor(private readonly ns: FastlyKVNamespace) {}

  async get(key: string): Promise<string | null> {
    const entry = await this.ns.get(key);
    if (!entry) return null;
    const raw = await entry.text();
    return unwrap(raw);
  }

  async getJson<T>(key: string): Promise<T | null> {
    const raw = await this.get(key);
    if (raw === null) return null;
    try {
      return JSON.parse(raw) as T;
    } catch {
      return null;
    }
  }

  async put(key: string, value: string, opts?: KvPutOptions): Promise<void> {
    const expEpoch =
      opts?.expiration !== undefined
        ? opts.expiration * 1000
        : opts?.expirationTtl !== undefined
          ? Date.now() + opts.expirationTtl * 1000
          : null;
    const envelope = JSON.stringify({ __exp: expEpoch, v: value });
    await this.ns.put(key, envelope);
  }

  async putJson(key: string, value: unknown, opts?: KvPutOptions): Promise<void> {
    await this.put(key, JSON.stringify(value), opts);
  }

  async delete(key: string): Promise<void> {
    await this.ns.delete(key);
  }

  async list<TMetadata = unknown>(): Promise<KvListResult<TMetadata>> {
    throw new Error(
      'FastlyKvStore.list() is not implemented — Fastly KV does not expose ' +
        'enumeration. If you hit this, gate the caller on the platform and ' +
        'use D1 (or libsql on Fastly) for the data instead.',
    );
  }
}

interface KvEnvelope {
  __exp: number | null;
  v: string;
}

function unwrap(raw: string): string | null {
  let env: KvEnvelope;
  try {
    env = JSON.parse(raw) as KvEnvelope;
  } catch {
    // Backwards-compat: a value written before this code shipped, or a value
    // written by a different tool, won't have the envelope. Treat as
    // never-expiring and pass through.
    return raw;
  }
  if (typeof env !== 'object' || env === null || typeof env.v !== 'string') {
    // Shape mismatch — same fallback.
    return raw;
  }
  if (env.__exp !== null && env.__exp <= Date.now()) {
    return null;
  }
  return env.v;
}
