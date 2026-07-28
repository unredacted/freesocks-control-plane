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

/**
 * FAMILIES are the parent modes a member picks first ("Freedom Mode", "Privacy
 * Mode"); the entries in CONNECTION_MODES are their transport sub-choices. The
 * hierarchy is PRESENTATIONAL + ADMINISTRATIVE ONLY — what is stored on the user
 * and sent to a backend is always a flat LEAF id, so issuance/placement never
 * sees a family. A family with one enabled child renders as a plain card.
 */
export interface ConnectionModeFamilyDef {
  id: string;
  labelKey: string;
  bodyKey: string;
  iconId: 'zap' | 'shield-check';
  order: number;
  /** Compiled fallback when the admin hasn't set `connectionModeFamily.<id>.enabled`. */
  defaultEnabled: boolean;
}

export const CONNECTION_MODE_FAMILIES: readonly ConnectionModeFamilyDef[] = [
  {
    id: 'freedom',
    labelKey: 'delivery.freedomTitle',
    bodyKey: 'delivery.freedomBody',
    iconId: 'zap',
    order: 0,
    defaultEnabled: true,
  },
  {
    id: 'privacy',
    labelKey: 'delivery.privacyTitle',
    bodyKey: 'delivery.privacyBody',
    iconId: 'shield-check',
    order: 1,
    defaultEnabled: true,
  },
] as const;

/**
 * The compiled catalog of known LEAF modes (transport sub-choices).
 *
 * ADDING A TRANSPORT to an existing family (the expected way this grows — e.g. a
 * second Privacy Mode method alongside REALITY) is additive and needs no new
 * plumbing:
 *   1. an entry here with the family's id and the next `order`. Do NOT set
 *      `isFamilyDefault` unless you intend to change what clicking the parent
 *      card selects; exactly one leaf per family should carry it.
 *   2. `delivery.<id>Title` / `delivery.<id>Body` in `messages/en.json`, then
 *      `bun run i18n:keys`, plus a `MODE_COPY` entry in
 *      `src/client/lib/connectionModeCopy.ts` (without it the picker falls back
 *      to the admin-set label, then the raw id).
 *   3. bind its placement pool in Admin → Remnawave, then enable it in
 *      Admin → Settings. It ships unselectable until BOTH are done.
 * Everything else — the picker (a one-transport family's static chip becomes a
 * radiogroup automatically), the admin editors, placement resolution, the status
 * matrix — is data-driven off this array.
 *
 * `deprecated` entries are legacy ids retained only so pre-migration rows still
 * validate; they carry no family and are never projected to members.
 */
export interface ConnectionModeDef {
  id: string;
  /** Parent family id; absent ONLY for deprecated legacy ids. */
  family?: string;
  deliveryStyle: DeliveryStyle;
  labelKey: string;
  bodyKey: string;
  order: number;
  /** Compiled fallback when the admin hasn't set `connectionMode.<id>.enabled`. */
  defaultEnabled: boolean;
  /** The leaf selected when a member picks this family without choosing a transport. */
  isFamilyDefault?: boolean;
  /** Legacy id kept for migration compatibility; never shown, never selectable. */
  deprecated?: boolean;
}

export const CONNECTION_MODES: readonly ConnectionModeDef[] = [
  {
    id: 'freedom-ws',
    family: 'freedom',
    deliveryStyle: 'url',
    labelKey: 'delivery.freedomWsTitle',
    bodyKey: 'delivery.freedomWsBody',
    order: 0,
    defaultEnabled: true,
    isFamilyDefault: true,
  },
  {
    id: 'freedom-reality',
    family: 'freedom',
    deliveryStyle: 'rawConfig',
    labelKey: 'delivery.freedomRealityTitle',
    bodyKey: 'delivery.freedomRealityBody',
    order: 1,
    // Ships dark: stays off until relay squads are bound and it has been tested.
    // The operator turns it on in Admin -> Settings.
    defaultEnabled: false,
  },
  {
    id: 'privacy-reality',
    family: 'privacy',
    deliveryStyle: 'rawConfig',
    labelKey: 'delivery.privacyRealityTitle',
    bodyKey: 'delivery.privacyRealityBody',
    order: 0,
    defaultEnabled: true,
    isFamilyDefault: true,
  },
  // --- deprecated aliases (drop once seed:migrateConnectionModeIds has run) ---
  {
    id: 'evade',
    deliveryStyle: 'url',
    labelKey: 'delivery.freedomWsTitle',
    bodyKey: 'delivery.freedomWsBody',
    order: 90,
    defaultEnabled: false,
    deprecated: true,
  },
  {
    id: 'privacy',
    deliveryStyle: 'rawConfig',
    labelKey: 'delivery.privacyRealityTitle',
    bodyKey: 'delivery.privacyRealityBody',
    order: 91,
    defaultEnabled: false,
    deprecated: true,
  },
] as const;

export const CONNECTION_MODE_IDS: readonly string[] = CONNECTION_MODES.map((m) => m.id);
export const CONNECTION_MODE_FAMILY_IDS: readonly string[] = CONNECTION_MODE_FAMILIES.map(
  (f) => f.id,
);
export const DEFAULT_CONNECTION_MODE = 'freedom-ws';

/** The family whose modes are built for censored networks. Privacy Mode is
 *  deliberately NOT in it — it is a traffic-mixing/traditional-VPN posture whose
 *  decoy is SNI-blocked in China, so it must never be suggested there. */
export const CENSORSHIP_MODE_FAMILY = 'freedom';

/** Legacy id -> current id. Consumed by seed:migrateConnectionModeIds and by the
 *  read paths, so a pre-migration row resolves to its successor rather than to
 *  the catalog default (which would silently move a Privacy member to Freedom). */
export const LEGACY_MODE_ID_MAP: Readonly<Record<string, string>> = {
  evade: 'freedom-ws',
  privacy: 'privacy-reality',
} as const;

export function isConnectionModeId(v: unknown): v is string {
  return typeof v === 'string' && CONNECTION_MODE_IDS.includes(v);
}

export function isConnectionModeFamilyId(v: unknown): v is string {
  return typeof v === 'string' && CONNECTION_MODE_FAMILY_IDS.includes(v);
}

/** Map a possibly-legacy id onto its current spelling (identity for current ids). */
export function canonicalModeId(v: string): string {
  return LEGACY_MODE_ID_MAP[v] ?? v;
}

/** Server-side resolved mode: catalog def + admin overrides + default flag. */
export interface ConnectionMode {
  id: string;
  family?: string;
  deliveryStyle: DeliveryStyle;
  /** Admin-set label; null = the SPA renders its own i18n copy for the mode. */
  label: string | null;
  /** Admin-set member-facing description; null = the SPA's i18n body. */
  description: string | null;
  isDefault: boolean;
  isFamilyDefault: boolean;
  /** Admin toggle (`connectionMode.<id>.enabled`), AND-ed with the family's. */
  enabled: boolean;
  order: number;
  deprecated: boolean;
}

/** Server-side resolved family: catalog def + admin overrides + enabled flag. */
export interface ConnectionModeFamily {
  id: string;
  label: string | null;
  description: string | null;
  enabled: boolean;
  order: number;
}

/** Public-safe projection publicConfig ships. `available` = the mode is enabled
 *  (family AND sub-mode) AND has a backend placement pool bound; an unbound mode
 *  is disabled in the picker and rejected server-side (issuing into it would mint
 *  a squad-less key). The caller supplies the bound-mode set (Remnawave-owned).
 *  Admin-disabled modes are OMITTED entirely rather than shipped with a flag —
 *  except `keepId` (the member's current mode), so a member the admin just
 *  disabled still sees their own selection instead of a blank picker. */
export interface PublicConnectionMode {
  id: string;
  family?: string;
  deliveryStyle: DeliveryStyle;
  label: string | null;
  description: string | null;
  isDefault: boolean;
  isFamilyDefault: boolean;
  available: boolean;
}

export interface PublicConnectionModeFamily {
  id: string;
  label: string | null;
  description: string | null;
}

/** appSettings keys — `connectionMode.<id>.<field>` + the default. No squad keys
 *  (placement pools live in the Remnawave namespace). Family keys sit in their own
 *  `connectionModeFamily.` namespace, which falls OUTSIDE the leaf range scan
 *  ['connectionMode.', 'connectionMode/') because 'F' > '/' — so the two readers
 *  below can't see each other's rows. */
export const CONNECTION_MODE_KEYS = {
  label: (id: string) => `connectionMode.${id}.label`,
  description: (id: string) => `connectionMode.${id}.description`,
  enabled: (id: string) => `connectionMode.${id}.enabled`,
  defaultId: 'connectionMode.default',
} as const;

export const CONNECTION_MODE_FAMILY_KEYS = {
  label: (id: string) => `connectionModeFamily.${id}.label`,
  description: (id: string) => `connectionModeFamily.${id}.description`,
  enabled: (id: string) => `connectionModeFamily.${id}.enabled`,
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

async function readFamilyNamespace(db: DatabaseReader): Promise<Map<string, unknown>> {
  const rows = await db
    .query('appSettings')
    .withIndex('by_key', (q) =>
      q.gte('key', 'connectionModeFamily.').lt('key', 'connectionModeFamily/'),
    )
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

/** A stored `enabled` override, or the compiled fallback when unset/malformed. */
function readEnabled(ns: Map<string, unknown>, key: string, fallback: boolean): boolean {
  const v = ns.get(key);
  return typeof v === 'boolean' ? v : fallback;
}

function trimmedOrNull(v: unknown): string | null {
  return typeof v === 'string' && v.trim() ? v : null;
}

/** Resolve the family catalog, fail-safe. Always returns every known family. */
export async function resolveConnectionModeFamilies(
  db: DatabaseReader,
): Promise<ConnectionModeFamily[]> {
  const ns = await readFamilyNamespace(db);
  return CONNECTION_MODE_FAMILIES.map((def) => ({
    id: def.id,
    label: trimmedOrNull(ns.get(CONNECTION_MODE_FAMILY_KEYS.label(def.id))),
    description: trimmedOrNull(ns.get(CONNECTION_MODE_FAMILY_KEYS.description(def.id))),
    enabled: readEnabled(ns, CONNECTION_MODE_FAMILY_KEYS.enabled(def.id), def.defaultEnabled),
    order: def.order,
  }));
}

/** Resolve the full LEAF catalog, fail-safe. Always returns every known mode
 *  (deprecated aliases included — callers filter). `enabled` is the AND of the
 *  mode's own toggle and its family's, so a disabled family disables its whole
 *  subtree with one switch. A deprecated alias is never enabled. */
export async function resolveConnectionModes(db: DatabaseReader): Promise<ConnectionMode[]> {
  const ns = await readModeNamespace(db);
  const families = await resolveConnectionModeFamilies(db);
  const familyEnabled = new Map(families.map((f) => [f.id, f.enabled]));
  const rawDefault = ns.get(CONNECTION_MODE_KEYS.defaultId);
  const storedDefault = isConnectionModeId(rawDefault) ? canonicalModeId(rawDefault) : null;

  const resolved = CONNECTION_MODES.map((def) => {
    const own = readEnabled(ns, CONNECTION_MODE_KEYS.enabled(def.id), def.defaultEnabled);
    const enabled =
      !def.deprecated && own && (def.family ? (familyEnabled.get(def.family) ?? false) : false);
    return {
      id: def.id,
      family: def.family,
      deliveryStyle: def.deliveryStyle,
      label: trimmedOrNull(ns.get(CONNECTION_MODE_KEYS.label(def.id))),
      description: trimmedOrNull(ns.get(CONNECTION_MODE_KEYS.description(def.id))),
      isDefault: false,
      isFamilyDefault: def.isFamilyDefault === true,
      enabled,
      order: def.order,
      deprecated: def.deprecated === true,
    };
  });

  // The default must be a mode a member can actually be placed on: an admin who
  // disables the current default must not leave every new account pointing at a
  // dead id. Fall back to the compiled default, then to any enabled mode.
  const usable = (id: string | null) =>
    id != null && resolved.some((m) => m.id === id && m.enabled);
  const defaultId =
    (usable(storedDefault) ? storedDefault : null) ??
    (usable(DEFAULT_CONNECTION_MODE) ? DEFAULT_CONNECTION_MODE : null) ??
    resolved.find((m) => m.enabled)?.id ??
    DEFAULT_CONNECTION_MODE;
  for (const m of resolved) m.isDefault = m.id === defaultId;
  return resolved;
}

/** The resolved default mode id (for AccountView when a member hasn't chosen).
 *  Never returns a disabled mode — see resolveConnectionModes. */
export async function resolveDefaultModeId(db: DatabaseReader): Promise<string> {
  const modes = await resolveConnectionModes(db);
  return modes.find((m) => m.isDefault)?.id ?? DEFAULT_CONNECTION_MODE;
}

/**
 * The member-facing mode list. Disabled and deprecated modes are OMITTED, not
 * flagged, so publicConfig never advertises what an operator turned off.
 *
 * publicConfig is member-agnostic (it is the ONLY public Convex function and is
 * shared by every visitor), so it cannot special-case "the caller's own mode".
 * A member sitting on a mode the admin just disabled is handled CLIENT-side:
 * DeliveryPreference synthesizes an entry for `selected` when it is absent from
 * this list, so the member still sees their selection and can switch away
 * instead of facing an empty picker.
 */
export function publicProjection(
  modes: ConnectionMode[],
  boundModeIds: Set<string>,
): PublicConnectionMode[] {
  return modes
    .filter((m) => m.enabled && !m.deprecated)
    .slice()
    .sort((a, b) => a.order - b.order)
    .map((m) => ({
      id: m.id,
      family: m.family,
      deliveryStyle: m.deliveryStyle,
      // Only an admin-set label/description overrides the SPA's i18n copy.
      label: m.label,
      description: m.description,
      isDefault: m.isDefault,
      isFamilyDefault: m.isFamilyDefault,
      // Selectable only when enabled AND its placement pool is bound — an
      // enabled-but-unbound mode would mint a squad-less key.
      available: m.enabled && boundModeIds.has(m.id),
    }));
}

/** Families that still have at least one visible child, in display order. */
export function publicFamilyProjection(
  families: ConnectionModeFamily[],
  visibleModes: PublicConnectionMode[],
): PublicConnectionModeFamily[] {
  const withChildren = new Set(visibleModes.map((m) => m.family).filter(Boolean));
  return families
    .filter((f) => f.enabled && withChildren.has(f.id))
    .slice()
    .sort((a, b) => a.order - b.order)
    .map((f) => ({ id: f.id, label: f.label, description: f.description }));
}

/**
 * Admin PATCH → appSettings writes for the GENERIC mode catalog (label /
 * description / enabled / default only — NO squad/placement writes; those go
 * through the Remnawave-namespaced endpoint). An empty string clears a
 * label/description back to the i18n fallback. Unknown ids are ignored (never an
 * error, so a stale admin tab can't 400); a bad default id throws.
 *
 * The default must name an id that is not being disabled in the SAME patch —
 * otherwise a single save could point every new account at a dead mode.
 */
export function connectionModeWrites(patch: unknown): Array<{ key: string; value: string }> {
  if (!patch || typeof patch !== 'object') {
    throw new Error('connection-mode patch must be an object');
  }
  const p = patch as Record<string, unknown>;
  const writes: Array<{ key: string; value: string }> = [];
  const modes = (p.modes ?? {}) as Record<string, unknown>;
  const families = (p.families ?? {}) as Record<string, unknown>;

  if ('default' in p) {
    if (!isConnectionModeId(p.default)) throw new Error('invalid default mode id');
    const def = CONNECTION_MODES.find((m) => m.id === p.default);
    if (def?.deprecated) throw new Error('invalid default mode id');
    const modePatch = modes[p.default as string] as Record<string, unknown> | undefined;
    if (modePatch && modePatch.enabled === false) {
      throw new Error('cannot set a disabled mode as the default');
    }
    const familyPatch = def?.family
      ? (families[def.family] as Record<string, unknown> | undefined)
      : undefined;
    if (familyPatch && familyPatch.enabled === false) {
      throw new Error('cannot set a mode in a disabled family as the default');
    }
    writes.push({ key: CONNECTION_MODE_KEYS.defaultId, value: JSON.stringify(p.default) });
  }

  for (const id of Object.keys(families)) {
    if (!isConnectionModeFamilyId(id)) continue;
    const entry = families[id];
    if (!entry || typeof entry !== 'object') continue;
    const e = entry as Record<string, unknown>;
    if (typeof e.label === 'string') {
      writes.push({ key: CONNECTION_MODE_FAMILY_KEYS.label(id), value: JSON.stringify(e.label) });
    }
    if (typeof e.description === 'string') {
      writes.push({
        key: CONNECTION_MODE_FAMILY_KEYS.description(id),
        value: JSON.stringify(e.description),
      });
    }
    if (typeof e.enabled === 'boolean') {
      writes.push({
        key: CONNECTION_MODE_FAMILY_KEYS.enabled(id),
        value: JSON.stringify(e.enabled),
      });
    }
  }

  for (const id of Object.keys(modes)) {
    if (!isConnectionModeId(id)) continue; // ignore unknown ids (never an error)
    if (CONNECTION_MODES.find((m) => m.id === id)?.deprecated) continue; // legacy alias: read-only
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
    if (typeof e.enabled === 'boolean') {
      writes.push({ key: CONNECTION_MODE_KEYS.enabled(id), value: JSON.stringify(e.enabled) });
    }
  }
  return writes;
}
