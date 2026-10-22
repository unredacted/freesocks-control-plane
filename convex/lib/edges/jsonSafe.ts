/**
 * Provider answers made safe to cross a Convex function boundary and to store
 * as JSON. An SDK hands back class-shaped objects (`Date`s above all: the
 * Scaleway SDK turns every timestamp into one), which Convex refuses as a
 * return value ("Date is not a supported Convex type"), so a live view of such
 * an adapter failed outright. `jsonSafe` is applied once, in edgeProviderOps, to
 * every adapter's `inspect` and `describe` answer.
 */

/** Longest object key Convex accepts. */
const MAX_FIELD_NAME_CHARS = 1024;

/** A key Convex accepts in an object: non-empty printable ASCII, not starting with `$`. */
function acceptedKey(k: string): boolean {
  if (k.length === 0 || k.length > MAX_FIELD_NAME_CHARS || k.startsWith('$')) return false;
  for (let i = 0; i < k.length; i++) {
    const c = k.charCodeAt(i);
    if (c < 32 || c >= 127) return false;
  }
  return true;
}

/**
 * A deep copy holding only what JSON and Convex both carry: a `Date` becomes
 * its ISO string (an invalid one, null), a bigint its decimal string, a
 * non-finite number null; `undefined`, functions and symbols are dropped from
 * objects (null in arrays, as `JSON.stringify` does); a key Convex refuses is
 * dropped; a Map becomes an object, a Set or typed array a list; a cycle is cut
 * (`[circular]`). Plain data comes back equal.
 */
export function jsonSafe(value: unknown): unknown {
  const seen = new WeakSet<object>();
  const walk = (v: unknown): unknown => {
    if (v === null) return null;
    switch (typeof v) {
      case 'string':
      case 'boolean':
        return v;
      case 'number':
        return Number.isFinite(v) ? v : null;
      case 'bigint':
        return v.toString();
      case 'undefined':
      case 'function':
      case 'symbol':
        return undefined;
    }
    if (v instanceof Date) return Number.isNaN(v.getTime()) ? null : v.toISOString();
    const o = v as object;
    if (seen.has(o)) return '[circular]';
    seen.add(o);
    try {
      if (Array.isArray(o)) return o.map((x) => walk(x) ?? null);
      if (ArrayBuffer.isView(o)) return Array.from(o as unknown as ArrayLike<number>);
      if (o instanceof Set) return [...o].map((x) => walk(x) ?? null);
      const entries = o instanceof Map ? [...o.entries()] : Object.entries(o);
      const out: Record<string, unknown> = {};
      for (const [k, x] of entries) {
        const key = String(k);
        if (!acceptedKey(key)) continue;
        const w = walk(x);
        if (w !== undefined) out[key] = w;
      }
      return out;
    } finally {
      seen.delete(o);
    }
  };
  return walk(value) ?? null;
}
