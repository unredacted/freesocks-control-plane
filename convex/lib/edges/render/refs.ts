/**
 * Reference pruning for rendered proxy configs (sing-box JSON / Clash YAML
 * object trees). When template outbounds/proxies are removed from a body, every
 * other mention of their tag must go with them or the config is invalid:
 * group membership lists, `route.final` / a group `default`, rule targets
 * (`route.rules[].outbound`, Clash `rules: [ "MATCH,<name>" ]`), DNS/outbound
 * `detour`s. These helpers walk the tree structurally (never a substring scan):
 *
 *  - a string VALUE equal to a removed name → the fallback (or the key is
 *    dropped when there is no fallback);
 *  - a removed name as an ARRAY ITEM (a membership list) → the item is removed;
 *  - a comma-joined rule string whose segment equals a removed name → the
 *    segment becomes the fallback (or the rule is dropped without one).
 */

type Json = unknown;

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Rewrite one string: exact match or a comma-joined rule segment. Returns
 *  undefined when the string should be dropped (a reference with no fallback). */
function rewriteString(
  s: string,
  removed: ReadonlySet<string>,
  fallback: string | null,
): string | undefined {
  if (removed.has(s)) return fallback ?? undefined;
  if (!s.includes(',')) return s;
  const parts = s.split(',');
  let hit = false;
  const next = parts.map((p) => {
    if (removed.has(p.trim())) {
      hit = true;
      return fallback;
    }
    return p;
  });
  if (!hit) return s;
  if (next.some((p) => p === null)) return undefined;
  return next.join(',');
}

/**
 * Deep-copy `value` with every reference to a removed name rewritten. `skip`
 * lets the caller leave a top-level subtree alone (the outbound/proxy list it
 * already rebuilt). Returns undefined when the value itself must be dropped.
 */
export function pruneRefs(
  value: Json,
  removed: ReadonlySet<string>,
  fallback: string | null,
  skip?: (key: string) => boolean,
): Json {
  if (typeof value === 'string') return rewriteString(value, removed, fallback);
  if (Array.isArray(value)) {
    const out: Json[] = [];
    for (const item of value) {
      if (typeof item === 'string') {
        // Membership lists: a removed member is REMOVED, never replaced (the
        // fallback is usually already in the list). Rule strings keep the
        // segment logic.
        if (removed.has(item)) continue;
        const next = rewriteString(item, removed, fallback);
        if (next !== undefined) out.push(next);
        continue;
      }
      const next = pruneRefs(item, removed, fallback);
      if (next !== undefined) out.push(next);
    }
    return out;
  }
  if (isObj(value)) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      if (skip?.(k)) {
        out[k] = v;
        continue;
      }
      const next = pruneRefs(v, removed, fallback);
      if (next !== undefined) out[k] = next;
    }
    return out;
  }
  return value;
}

/** Whether any string in the tree references one of the names (structural, token-exact). */
export function mentionsAny(value: Json, names: ReadonlySet<string>): boolean {
  if (typeof value === 'string') {
    if (names.has(value)) return true;
    return value.includes(',') && value.split(',').some((p) => names.has(p.trim()));
  }
  if (Array.isArray(value)) return value.some((v) => mentionsAny(v, names));
  if (isObj(value)) return Object.values(value).some((v) => mentionsAny(v, names));
  return false;
}

/** A name not already taken: `base`, else `base (2)`, `base (3)`, … */
export function uniqueName(base: string, taken: ReadonlySet<string>): string {
  if (!taken.has(base)) return base;
  for (let i = 2; ; i++) {
    const candidate = `${base} (${i})`;
    if (!taken.has(candidate)) return candidate;
  }
}

/** JSON round-trip clone (the Convex isolate is not guaranteed a `structuredClone`). */
export function cloneJson<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}
