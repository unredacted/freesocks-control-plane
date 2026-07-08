/**
 * Connection modes: the member-facing transport choice. "Evade" (a CDN-fronted
 * WebSocket path) and "Privacy" (a non-fronted VLESS-Reality path) ship by
 * default, but the set is DATA-DRIVEN — ids are plain strings validated against
 * this catalog, so more modes can be added without touching a union in a dozen
 * files. A mode is ORTHOGONAL to the entitlement tier (the tier sets limits).
 *
 * A mode carries a `deliveryStyle` CAPABILITY FLAG that drives member-UI
 * behavior as DATA rather than a hardcoded `=== 'privacy'` branch:
 *   - 'url'       → the auto-updating subscription URL is the star.
 *   - 'rawConfig' → the raw config is the deliverable; the URL is hidden and
 *                   S3 mirrors are suppressed (the privacy posture).
 *
 * Generic + squad-free. WHICH backend placement (Remnawave squad pool) a mode
 * issues into is Remnawave-specific and lives in convex/lib/remnawavePlacement.ts
 * — this module never names a squad. Admin label/description overrides + the
 * default live in the `appSettings` `connectionMode.*` namespace (deliberately
 * NOT in SETTINGS_DEFAULTS), resolved fail-safe; publicConfig ships
 * id/label/description/deliveryStyle/isDefault/available (never a squad UUID).
 */
import type { DatabaseReader } from '../_generated/server';

export type DeliveryStyle = 'url' | 'rawConfig';

/** The compiled catalog of known modes. Adding a mode: add an entry here (and,
 *  for member-facing copy, either an i18n key pair or rely on the admin-set DB
 *  label/description). `labelKey`/`bodyKey` are the built-in i18n keys for the
 *  two shipped modes; a novel mode with no key falls back to the admin DB copy,
 *  then the id. */
export interface ConnectionModeDef {
  id: string;
  deliveryStyle: DeliveryStyle;
  labelKey: string;
  bodyKey: string;
  iconId: 'zap' | 'shield-check';
  order: number;
}

export const CONNECTION_MODES: readonly ConnectionModeDef[] = [
  {
    id: 'evade',
    deliveryStyle: 'url',
    labelKey: 'delivery.evadeTitle',
    bodyKey: 'delivery.evadeBody',
    iconId: 'zap',
    order: 0,
  },
  {
    id: 'privacy',
    deliveryStyle: 'rawConfig',
    labelKey: 'delivery.privacyTitle',
    bodyKey: 'delivery.privacyBody',
    iconId: 'shield-check',
    order: 1,
  },
] as const;

export const CONNECTION_MODE_IDS: readonly string[] = CONNECTION_MODES.map((m) => m.id);
export const DEFAULT_CONNECTION_MODE = 'evade';

export function isConnectionModeId(v: unknown): v is string {
  return typeof v === 'string' && CONNECTION_MODE_IDS.includes(v);
}

/** Server-side resolved mode: catalog def + admin overrides + default flag. */
export interface ConnectionMode {
  id: string;
  deliveryStyle: DeliveryStyle;
  /** Admin-set label; null = the SPA renders its own i18n copy for the mode. */
  label: string | null;
  /** Admin-set member-facing description; null = the SPA's i18n body. */
  description: string | null;
  isDefault: boolean;
  order: number;
}

/** Public-safe projection publicConfig ships. `available` = the mode has a
 *  backend placement pool bound (else picking it would fall back to the tier
 *  squad); the caller supplies the bound-mode set (Remnawave-owned). */
export interface PublicConnectionMode {
  id: string;
  deliveryStyle: DeliveryStyle;
  label: string | null;
  description: string | null;
  isDefault: boolean;
  available: boolean;
}

/** appSettings keys — `connectionMode.<id>.<field>` + the default. No squad keys
 *  (placement pools live in the Remnawave namespace). */
export const CONNECTION_MODE_KEYS = {
  label: (id: string) => `connectionMode.${id}.label`,
  description: (id: string) => `connectionMode.${id}.description`,
  defaultId: 'connectionMode.default',
} as const;

async function readModeNamespace(db: DatabaseReader): Promise<Map<string, unknown>> {
  const rows = await db
    .query('appSettings')
    // ['connectionMode.', 'connectionMode/') — '/' is the next byte after '.',
    // so this range captures exactly the connectionMode.* keys.
    .withIndex('by_key', (q) => q.gte('key', 'connectionMode.').lt('key', 'connectionMode/'))
    .collect();
  const map = new Map<string, unknown>();
  for (const r of rows) {
    try {
      map.set(r.key, JSON.parse(r.value));
    } catch {
      /* skip malformed */
    }
  }
  return map;
}

/** Resolve the full mode catalog, fail-safe. Always returns every known mode. */
export async function resolveConnectionModes(db: DatabaseReader): Promise<ConnectionMode[]> {
  const ns = await readModeNamespace(db);
  const rawDefault = ns.get(CONNECTION_MODE_KEYS.defaultId);
  const defaultId = isConnectionModeId(rawDefault) ? rawDefault : DEFAULT_CONNECTION_MODE;
  return CONNECTION_MODES.map((def) => {
    const label = ns.get(CONNECTION_MODE_KEYS.label(def.id));
    const description = ns.get(CONNECTION_MODE_KEYS.description(def.id));
    return {
      id: def.id,
      deliveryStyle: def.deliveryStyle,
      label: typeof label === 'string' && label.trim() ? label : null,
      description: typeof description === 'string' && description.trim() ? description : null,
      isDefault: def.id === defaultId,
      order: def.order,
    };
  });
}

/** The resolved default mode id (for AccountView when a member hasn't chosen). */
export async function resolveDefaultModeId(db: DatabaseReader): Promise<string> {
  const row = await db
    .query('appSettings')
    .withIndex('by_key', (q) => q.eq('key', CONNECTION_MODE_KEYS.defaultId))
    .unique();
  let rawDefault: unknown;
  if (row) {
    try {
      rawDefault = JSON.parse(row.value);
    } catch {
      /* fall through to the compiled default */
    }
  }
  return isConnectionModeId(rawDefault) ? rawDefault : DEFAULT_CONNECTION_MODE;
}

export function publicProjection(
  modes: ConnectionMode[],
  boundModeIds: Set<string>,
): PublicConnectionMode[] {
  return modes
    .slice()
    .sort((a, b) => a.order - b.order)
    .map((m) => ({
      id: m.id,
      deliveryStyle: m.deliveryStyle,
      // Only an admin-set label/description overrides the SPA's i18n copy.
      label: m.label,
      description: m.description,
      isDefault: m.isDefault,
      available: boundModeIds.has(m.id),
    }));
}

/**
 * Admin PATCH → appSettings writes for the GENERIC mode catalog (label /
 * description / default only — NO squad/placement writes; those go through the
 * Remnawave-namespaced endpoint). An empty string clears a label/description
 * back to the i18n fallback. Throws on a malformed patch or bad default id.
 */
export function connectionModeWrites(patch: unknown): Array<{ key: string; value: string }> {
  if (!patch || typeof patch !== 'object') {
    throw new Error('connection-mode patch must be an object');
  }
  const p = patch as Record<string, unknown>;
  const writes: Array<{ key: string; value: string }> = [];
  if ('default' in p) {
    if (!isConnectionModeId(p.default)) throw new Error('invalid default mode id');
    writes.push({ key: CONNECTION_MODE_KEYS.defaultId, value: JSON.stringify(p.default) });
  }
  const modes = (p.modes ?? {}) as Record<string, unknown>;
  for (const id of Object.keys(modes)) {
    if (!isConnectionModeId(id)) continue; // ignore unknown ids (never an error)
    const entry = modes[id];
    if (!entry || typeof entry !== 'object') continue;
    const e = entry as Record<string, unknown>;
    if (typeof e.label === 'string') {
      writes.push({ key: CONNECTION_MODE_KEYS.label(id), value: JSON.stringify(e.label) });
    }
    if (typeof e.description === 'string') {
      writes.push({
        key: CONNECTION_MODE_KEYS.description(id),
        value: JSON.stringify(e.description),
      });
    }
  }
  return writes;
}
