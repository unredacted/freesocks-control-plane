/**
 * Flat view of the edge config and the diff the settings page saves (pure;
 * unit-tested). The flattening mirrors the server's: scalars and arrays live at
 * dotted paths (`detect.windowMinutes`), per-family render rules stay objects
 * under `render.clients.<family>` (the server stores one row per family and
 * sanitises the whole rule, so a rule is always sent complete).
 *
 * Exports:
 *   flattenConfig(config)                     -> Record<path, value>
 *   canonical(value)                          stable JSON (key order independent)
 *   sameValue(a, b)
 *   diffConfig(base, edits, paths?)           -> ConfigChange[] (only real changes)
 *   buildPatch(changes)                       -> flat patch for PATCH config
 *   adjustedValues(sent, fresh)               -> what the server stored differently
 *   formatConfigValue(value)                  words for the diff list
 *   pathCovers(path, key)                     key === path or a sub-key of it
 */
export type FlatConfig = Record<string, unknown>;

const CLIENTS = 'render.clients';

export function flattenConfig(config: unknown): FlatConfig {
  const out: FlatConfig = {};
  const walk = (obj: Record<string, unknown>, prefix: string) => {
    for (const [k, val] of Object.entries(obj)) {
      const path = prefix ? `${prefix}.${k}` : k;
      if (path === CLIENTS && val && typeof val === 'object') {
        for (const [fam, rule] of Object.entries(val as Record<string, unknown>)) {
          out[`${CLIENTS}.${fam}`] = rule;
        }
        continue;
      }
      if (val && typeof val === 'object' && !Array.isArray(val)) {
        walk(val as Record<string, unknown>, path);
      } else {
        out[path] = val;
      }
    }
  };
  if (config && typeof config === 'object') walk(config as Record<string, unknown>, '');
  return out;
}

export function canonical(value: unknown): string {
  if (value === undefined) return 'undefined';
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const o = value as Record<string, unknown>;
  return `{${Object.keys(o)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`)
    .join(',')}}`;
}
export const sameValue = (a: unknown, b: unknown): boolean => canonical(a) === canonical(b);

export const pathCovers = (path: string, key: string): boolean =>
  key === path || key.startsWith(`${path}.`);

export interface ConfigChange {
  /** The flat path that is sent (`render.clients.singbox` for a rule). */
  path: string;
  /** What the operator reads: the path, or `path.field` for one field of a rule. */
  display: string;
  from: unknown;
  to: unknown;
  /** The complete value to send for `path`. */
  send: unknown;
}

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === 'object' && !Array.isArray(v);

export function diffConfig(
  base: FlatConfig,
  edits: FlatConfig,
  paths?: readonly string[],
): ConfigChange[] {
  const out: ConfigChange[] = [];
  const keys = Object.keys(edits)
    .filter((k) => !paths || paths.includes(k))
    .sort();
  for (const path of keys) {
    const to = edits[path];
    const from = base[path];
    if (to === undefined || sameValue(from, to)) continue;
    if (isPlainObject(to) && isPlainObject(from)) {
      // One row per changed field of a rule, but the whole rule is what is sent.
      for (const field of Object.keys(to).sort()) {
        if (!sameValue(from[field], to[field])) {
          out.push({
            path,
            display: `${path}.${field}`,
            from: from[field],
            to: to[field],
            send: to,
          });
        }
      }
      continue;
    }
    out.push({ path, display: path, from, to, send: to });
  }
  return out;
}

export function buildPatch(changes: readonly ConfigChange[]): FlatConfig {
  const patch: FlatConfig = {};
  for (const c of changes) patch[c.path] = c.send;
  return patch;
}

export interface AdjustedValue {
  display: string;
  sent: unknown;
  stored: unknown;
}
/** After a save: the values the server clamped or replaced (sent vs what it now reports). */
export function adjustedValues(sent: FlatConfig, fresh: FlatConfig): AdjustedValue[] {
  const out: AdjustedValue[] = [];
  for (const path of Object.keys(sent).sort()) {
    const s = sent[path];
    const f = fresh[path];
    if (sameValue(s, f)) continue;
    if (isPlainObject(s) && isPlainObject(f)) {
      for (const field of Object.keys(s).sort()) {
        if (!sameValue(s[field], f[field])) {
          out.push({ display: `${path}.${field}`, sent: s[field], stored: f[field] });
        }
      }
      continue;
    }
    out.push({ display: path, sent: s, stored: f });
  }
  return out;
}

export function formatConfigValue(value: unknown): string {
  if (value === undefined || value === null) return 'not set';
  if (typeof value === 'boolean') return value ? 'on' : 'off';
  if (typeof value === 'string') return value === '' ? 'empty' : `"${value}"`;
  if (typeof value === 'number') return String(value);
  if (Array.isArray(value)) return value.length === 0 ? 'none' : value.join(', ');
  return canonical(value);
}
