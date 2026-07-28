/**
 * Connection modes: the member-facing transport choice, DB-DRIVEN — families
 * ("Freedom Mode", "Privacy Mode") and their transport leaves (WebSocket,
 * REALITY, ...) are rows in `connectionModeFamilies` / `connectionModes`,
 * fully admin-managed (create/edit/delete in the CMS, no code change to add
 * one). A mode is ORTHOGONAL to the entitlement tier (the tier sets limits).
 *
 * The compiled DEFAULT_* rows below serve two jobs:
 *   1. the SEED a fresh deploy inserts (seed:seedConnectionModes), and
 *   2. the READ FALLBACK while both tables are empty (the clients-catalog
 *      pattern), so the picker is never blank pre-seed or on a wiped stack.
 *
 * A mode carries a `deliveryStyle` CAPABILITY FLAG (closed code enum — the
 * admin picks one, the set itself never comes from data):
 *   - 'url'       → the auto-updating subscription URL is the star.
 *   - 'rawConfig' → the raw config is the deliverable; the URL is hidden and
 *                   S3 mirrors are suppressed (the privacy posture).
 *
 * Modes declare backend APPLICABILITY (`backends`, the clients.backends
 * pattern); per-backend AVAILABILITY additionally requires a bound placement
 * on placement-capable backends and is composed in lib/placement.ts — this
 * module never reads a placement store. Admin label/description override the
 * SPA's compiled i18n (null → i18n for built-in slugs, humanized slug
 * otherwise); publicConfig ships copy + availability, never a placement.
 *
 * LEGACY (drop in deploy 2): `LEGACY_MODE_ID_MAP` + `canonicalModeId` map the
 * pre-rename ids (evade/privacy) onto their successors at the read points,
 * covering the window until seed:migrateLegacyModeUserIds has rewritten every
 * user row.
 */
import type { DatabaseReader } from '../_generated/server';
import type { Doc } from '../_generated/dataModel';
import type { BackendId } from './backendIds';

export type DeliveryStyle = 'url' | 'rawConfig';

/** Row-shaped compiled defaults (seed source + empty-table read fallback). */
export interface DefaultFamilyRow {
  slug: string;
  iconId: string;
  audienceKeyed: boolean; // built-in: the SPA has i18n copy for this slug
  enabled: boolean;
  order: number;
}

export interface DefaultModeRow {
  slug: string;
  familySlug: string;
  deliveryStyle: DeliveryStyle;
  enabled: boolean;
  isFamilyDefault: boolean;
  isCensorshipRecommended?: boolean;
  backends: BackendId[];
  order: number;
}

export const DEFAULT_CONNECTION_MODE_FAMILIES: readonly DefaultFamilyRow[] = [
  { slug: 'freedom', iconId: 'zap', audienceKeyed: true, enabled: true, order: 0 },
  { slug: 'privacy', iconId: 'shield-check', audienceKeyed: true, enabled: true, order: 1 },
] as const;

export const DEFAULT_CONNECTION_MODES: readonly DefaultModeRow[] = [
  {
    slug: 'freedom-ws',
    familySlug: 'freedom',
    deliveryStyle: 'url',
    enabled: true,
    isFamilyDefault: true,
    backends: ['remnawave'],
    order: 0,
  },
  {
    // Ships dark: stays off until relay squads are bound and it has been
    // tested. The operator turns it on in the admin CMS.
    slug: 'freedom-reality',
    familySlug: 'freedom',
    deliveryStyle: 'rawConfig',
    enabled: false,
    isFamilyDefault: false,
    // The geo suggestion for censored regions targets this leaf (Privacy Mode
    // is deliberately NOT censorship-recommended — its decoy is SNI-blocked in
    // China by design).
    isCensorshipRecommended: true,
    backends: ['remnawave'],
    order: 1,
  },
  {
    slug: 'privacy-reality',
    familySlug: 'privacy',
    deliveryStyle: 'rawConfig',
    enabled: true,
    isFamilyDefault: true,
    backends: ['remnawave'],
    order: 0,
  },
] as const;

export const DEFAULT_CONNECTION_MODE = 'freedom-ws';

/** Built-in slugs: rows the SPA has compiled i18n copy for (label may stay
 *  null) and the seed manages. Everything else is admin-created. */
export const BUILT_IN_FAMILY_SLUGS: ReadonlySet<string> = new Set(
  DEFAULT_CONNECTION_MODE_FAMILIES.map((f) => f.slug),
);
export const BUILT_IN_MODE_SLUGS: ReadonlySet<string> = new Set(
  DEFAULT_CONNECTION_MODES.map((m) => m.slug),
);

/** Legacy id -> current id (pre-2026-07 catalog). Read-point shim ONLY —
 *  deleted in deploy 2 once seed:migrateLegacyModeUserIds has run live. */
export const LEGACY_MODE_ID_MAP: Readonly<Record<string, string>> = {
  evade: 'freedom-ws',
  privacy: 'privacy-reality',
} as const;

/** Map a possibly-legacy id onto its current spelling (identity otherwise). */
export function canonicalModeId(v: string): string {
  return LEGACY_MODE_ID_MAP[v] ?? v;
}

/** The wire id everywhere (users.connectionModeId, matrix cells, audits). */
export const MODE_SLUG_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;

// The default-mode pointer stays a single appSettings key (a per-row isDefault
// column would need exactly-one-true bookkeeping in every mutation).
export const CONNECTION_MODE_DEFAULT_KEY = 'connectionMode.default';

// --- resolution --------------------------------------------------------------

/** Server-side resolved family. */
export interface ConnectionModeFamily {
  id: string; // the slug
  label: string | null;
  description: string | null;
  audience: string | null;
  iconId: string;
  enabled: boolean;
  order: number;
  builtIn: boolean;
}

/** Server-side resolved mode. `enabled` = own toggle AND the family's (a
 *  missing/deleted family row resolves DISABLED, fail-safe, and is flagged
 *  `orphaned` for the admin view). */
export interface ConnectionMode {
  id: string; // the slug
  family: string;
  deliveryStyle: DeliveryStyle;
  label: string | null;
  description: string | null;
  enabled: boolean;
  ownEnabled: boolean;
  orphaned: boolean;
  isDefault: boolean;
  isFamilyDefault: boolean;
  isCensorshipRecommended: boolean;
  backends: BackendId[];
  order: number;
  builtIn: boolean;
}

export interface ModeCatalog {
  families: ConnectionModeFamily[];
  modes: ConnectionMode[];
}

function trimmedOrNull(v: string | undefined): string | null {
  return typeof v === 'string' && v.trim() ? v : null;
}

async function readDefaultPointer(db: DatabaseReader): Promise<string | null> {
  const row = await db
    .query('appSettings')
    .withIndex('by_key', (q) => q.eq('key', CONNECTION_MODE_DEFAULT_KEY))
    .unique();
  if (!row) return null;
  try {
    const parsed: unknown = JSON.parse(row.value);
    return typeof parsed === 'string' ? canonicalModeId(parsed) : null;
  } catch {
    return null;
  }
}

type FamilySource = Pick<
  Doc<'connectionModeFamilies'>,
  'slug' | 'label' | 'description' | 'audience' | 'iconId' | 'enabled' | 'order'
>;
type ModeSource = Pick<
  Doc<'connectionModes'>,
  | 'slug'
  | 'familySlug'
  | 'deliveryStyle'
  | 'label'
  | 'description'
  | 'enabled'
  | 'isFamilyDefault'
  | 'isCensorshipRecommended'
  | 'backends'
  | 'order'
>;

function defaultFamilySources(): FamilySource[] {
  return DEFAULT_CONNECTION_MODE_FAMILIES.map((f) => ({
    slug: f.slug,
    iconId: f.iconId,
    enabled: f.enabled,
    order: f.order,
  }));
}

function defaultModeSources(): ModeSource[] {
  return DEFAULT_CONNECTION_MODES.map((m) => ({
    slug: m.slug,
    familySlug: m.familySlug,
    deliveryStyle: m.deliveryStyle,
    enabled: m.enabled,
    isFamilyDefault: m.isFamilyDefault,
    isCensorshipRecommended: m.isCensorshipRecommended,
    backends: [...m.backends],
    order: m.order,
  }));
}

export function byFamilyThenOrder(
  familyOrder: Map<string, number>,
): (a: ConnectionMode, b: ConnectionMode) => number {
  return (a, b) =>
    (familyOrder.get(a.family) ?? Number.MAX_SAFE_INTEGER) -
      (familyOrder.get(b.family) ?? Number.MAX_SAFE_INTEGER) ||
    a.order - b.order ||
    a.id.localeCompare(b.id);
}

/**
 * The resolved catalog, fail-safe: DB rows, or the compiled defaults while
 * BOTH tables are empty (fresh deploy / pre-seed window). Modes are sorted
 * (family order, mode order); exactly one carries `isDefault` via the ladder
 * stored pointer (if enabled) → compiled default (if enabled) → first enabled
 * → compiled default. Never throws on row content.
 */
export async function resolveModeCatalog(db: DatabaseReader): Promise<ModeCatalog> {
  const [familyRows, modeRows] = await Promise.all([
    db.query('connectionModeFamilies').collect(),
    db.query('connectionModes').collect(),
  ]);
  const seeded = familyRows.length > 0 || modeRows.length > 0;
  const familySources: FamilySource[] = seeded ? familyRows : defaultFamilySources();
  const modeSources: ModeSource[] = seeded ? modeRows : defaultModeSources();

  const families: ConnectionModeFamily[] = familySources
    .map((f) => ({
      id: f.slug,
      label: trimmedOrNull(f.label),
      description: trimmedOrNull(f.description),
      audience: trimmedOrNull(f.audience),
      iconId: f.iconId,
      enabled: f.enabled,
      order: f.order,
      builtIn: BUILT_IN_FAMILY_SLUGS.has(f.slug),
    }))
    .sort((a, b) => a.order - b.order || a.id.localeCompare(b.id));

  const familyEnabled = new Map(families.map((f) => [f.id, f.enabled]));
  const familyOrder = new Map(families.map((f) => [f.id, f.order]));

  const modes: ConnectionMode[] = modeSources
    .map((m) => {
      const orphaned = !familyEnabled.has(m.familySlug);
      return {
        id: m.slug,
        family: m.familySlug,
        deliveryStyle: m.deliveryStyle,
        label: trimmedOrNull(m.label),
        description: trimmedOrNull(m.description),
        ownEnabled: m.enabled,
        // Fail-safe: a mode whose family row is missing resolves disabled.
        enabled: m.enabled && (familyEnabled.get(m.familySlug) ?? false),
        orphaned,
        isDefault: false,
        isFamilyDefault: m.isFamilyDefault,
        isCensorshipRecommended: m.isCensorshipRecommended === true,
        backends: [...m.backends],
        order: m.order,
        builtIn: BUILT_IN_MODE_SLUGS.has(m.slug),
      };
    })
    .sort(byFamilyThenOrder(familyOrder));

  // The default must be a mode a member can actually land on: an admin who
  // disables the current default must not leave every new account pointing at
  // a dead id.
  const stored = await readDefaultPointer(db);
  const usable = (id: string | null) => id != null && modes.some((m) => m.id === id && m.enabled);
  const defaultId =
    (usable(stored) ? stored : null) ??
    (usable(DEFAULT_CONNECTION_MODE) ? DEFAULT_CONNECTION_MODE : null) ??
    modes.find((m) => m.enabled)?.id ??
    DEFAULT_CONNECTION_MODE;
  for (const m of modes) m.isDefault = m.id === defaultId;
  return { families, modes };
}

/** The resolved default mode id (AccountView when a member hasn't chosen).
 *  Never a disabled mode while any mode is enabled — see resolveModeCatalog. */
export async function resolveDefaultModeId(db: DatabaseReader): Promise<string> {
  const { modes } = await resolveModeCatalog(db);
  return modes.find((m) => m.isDefault)?.id ?? DEFAULT_CONNECTION_MODE;
}

// --- public projection --------------------------------------------------------

/** Public-safe mode projection. Disabled modes are OMITTED, not flagged, so
 *  publicConfig never advertises what an operator turned off; a member sitting
 *  on a disabled mode is served their own mode via the account view's
 *  `currentMode` projection instead. `availableBackends` = the backends the
 *  mode is actually selectable on (enabled AND applicable AND bound where the
 *  backend has a placement concept — composed by lib/placement.ts). */
export interface PublicConnectionMode {
  id: string;
  family: string;
  deliveryStyle: DeliveryStyle;
  label: string | null;
  description: string | null;
  isDefault: boolean;
  isFamilyDefault: boolean;
  availableBackends: BackendId[];
  available: boolean;
}

export interface PublicConnectionModeFamily {
  id: string;
  label: string | null;
  description: string | null;
  audience: string | null;
  iconId: string;
}

export type ModeWithAvailability = ConnectionMode & { availableBackends: BackendId[] };

export function publicProjection(modes: ModeWithAvailability[]): PublicConnectionMode[] {
  return modes
    .filter((m) => m.enabled)
    .map((m) => ({
      id: m.id,
      family: m.family,
      deliveryStyle: m.deliveryStyle,
      // Only an admin-set label/description overrides the SPA's i18n copy.
      label: m.label,
      description: m.description,
      isDefault: m.isDefault,
      isFamilyDefault: m.isFamilyDefault,
      availableBackends: m.availableBackends,
      available: m.availableBackends.length > 0,
    }));
}

/** Families that still have at least one visible child, in display order. */
export function publicFamilyProjection(
  families: ConnectionModeFamily[],
  visibleModes: PublicConnectionMode[],
): PublicConnectionModeFamily[] {
  const withChildren = new Set(visibleModes.map((m) => m.family));
  return families
    .filter((f) => f.enabled && withChildren.has(f.id))
    .map((f) => ({
      id: f.id,
      label: f.label,
      description: f.description,
      audience: f.audience,
      iconId: f.iconId,
    }));
}
