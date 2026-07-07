/**
 * Connection profiles (2026-07-03): the member-facing transport choice —
 * "Stay connected" (evade) = a CDN-fronted WebSocket Remnawave squad, and
 * "Maximize privacy" (privacy) = a non-fronted VLESS-Reality squad. A profile is
 * ORTHOGONAL to the entitlement tier: the tier sets limits, the chosen profile
 * sets which Remnawave squad the key is issued into (activeInternalSquads).
 *
 * Stored in the `appSettings` `connectionProfile.*` namespace (like theme.* /
 * billing.*: deliberately NOT in SETTINGS_DEFAULTS, so squad UUIDs never leak
 * through the generic settings allowlist / `appSettings.resolved`), resolved
 * fail-safe. The squad UUID is infra detail: it lives ONLY in this resolver + the
 * admin write path. publicConfig ships id/label/isDefault/available (NEVER the
 * UUID); the audit log records a `squadBound` boolean, never the value. The
 * Ansible panel-bootstrap binds each profile's squad via the admin
 * connection-profiles endpoint after it creates the squads on the panel.
 */
import type { DatabaseReader } from '../_generated/server';

export const CONNECTION_PROFILE_IDS = ['evade', 'privacy'] as const;
export type ConnectionProfileId = (typeof CONNECTION_PROFILE_IDS)[number];
export const DEFAULT_CONNECTION_PROFILE: ConnectionProfileId = 'evade';

/** Server-side profile: id + admin label/description + the squad it issues into. */
export interface ConnectionProfile {
  id: ConnectionProfileId;
  label: string;
  /** True when the label came from a stored admin value (vs the compiled
   *  DEFAULT_LABELS fallback) — the public projection only ships a label the
   *  admin actually set, so the SPA's i18n stays authoritative otherwise. */
  labelCustom: boolean;
  /** Admin-set member-facing description; null = the SPA renders its i18n copy. */
  description: string | null;
  squadUuid: string | null; // null until bound; issuance then falls back to the tier squad
  isDefault: boolean;
}

/** Public-safe projection — the exact shape publicConfig ships (NO squadUuid).
 *  `label`/`description` are null unless the admin set them: a non-null value
 *  overrides the SPA's translated copy verbatim (all locales), by design. */
export interface PublicConnectionProfile {
  id: ConnectionProfileId;
  label: string | null;
  description: string | null;
  isDefault: boolean;
  available: boolean; // squad bound → selectable (else it would fall back to the tier squad)
}

/** appSettings keys — `connectionProfile.<id>.<field>` (parallels the theme and billing namespaces). */
export const CONNECTION_PROFILE_KEYS = {
  label: (id: ConnectionProfileId) => `connectionProfile.${id}.label`,
  description: (id: ConnectionProfileId) => `connectionProfile.${id}.description`,
  squad: (id: ConnectionProfileId) => `connectionProfile.${id}.squadUuid`,
  defaultId: 'connectionProfile.default',
} as const;

/** Compiled default labels — an English fallback; the SPA renders its own i18n
 *  keyed by profile id, so these only surface in the admin CMS / a dark locale. */
const DEFAULT_LABELS: Record<ConnectionProfileId, string> = {
  evade: 'Stay connected',
  privacy: 'Maximize privacy',
};

export function isConnectionProfileId(v: unknown): v is ConnectionProfileId {
  return typeof v === 'string' && (CONNECTION_PROFILE_IDS as readonly string[]).includes(v);
}

async function readSetting(db: DatabaseReader, key: string): Promise<unknown> {
  const row = await db
    .query('appSettings')
    .withIndex('by_key', (q) => q.eq('key', key))
    .unique();
  if (!row) return undefined;
  try {
    return JSON.parse(row.value);
  } catch {
    return undefined;
  }
}

/** Read the whole connectionProfile.* namespace in ONE indexed range scan → a
 *  key→parsedValue map. resolveConnectionProfiles needs all keys, so one range
 *  read beats the five sequential point reads it used to do. (Review P2.) */
async function readProfileNamespace(db: DatabaseReader): Promise<Map<string, unknown>> {
  const rows = await db
    .query('appSettings')
    // ['connectionProfile.', 'connectionProfile/') — '/' is the next byte after '.'
    // so this range captures exactly the connectionProfile.* keys.
    .withIndex('by_key', (q) => q.gte('key', 'connectionProfile.').lt('key', 'connectionProfile/'))
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

/** Resolve the full catalog, fail-safe. Always returns every known id. */
export async function resolveConnectionProfiles(db: DatabaseReader): Promise<ConnectionProfile[]> {
  const ns = await readProfileNamespace(db);
  const rawDefault = ns.get(CONNECTION_PROFILE_KEYS.defaultId);
  const defaultId = isConnectionProfileId(rawDefault) ? rawDefault : DEFAULT_CONNECTION_PROFILE;
  const out: ConnectionProfile[] = [];
  for (const id of CONNECTION_PROFILE_IDS) {
    const label = ns.get(CONNECTION_PROFILE_KEYS.label(id));
    const description = ns.get(CONNECTION_PROFILE_KEYS.description(id));
    const squad = ns.get(CONNECTION_PROFILE_KEYS.squad(id));
    const labelCustom = typeof label === 'string' && label.trim().length > 0;
    out.push({
      id,
      label: labelCustom ? (label as string) : DEFAULT_LABELS[id],
      labelCustom,
      description:
        typeof description === 'string' && description.trim() ? (description as string) : null,
      squadUuid: typeof squad === 'string' && squad.trim() ? squad : null,
      isDefault: id === defaultId,
    });
  }
  return out;
}

/** The squad a profile issues into (issuance path). When the member has made no
 *  explicit choice (id null/invalid), this resolves the DEFAULT profile's squad —
 *  a new member follows the catalog default (bound to the fronted squad). Without
 *  that fallback a never-chosen member would issue into NO squad (empty
 *  activeInternalSquads) and Remnawave returns a "No hosts found" placeholder.
 *  Returns null only when the resolved profile has no squad bound, in which case
 *  callers fall back to the tier's own squad. */
export async function resolveProfileSquad(
  db: DatabaseReader,
  id: ConnectionProfileId | null | undefined,
): Promise<string | null> {
  let profileId: ConnectionProfileId;
  if (isConnectionProfileId(id)) {
    profileId = id;
  } else {
    const rawDefault = await readSetting(db, CONNECTION_PROFILE_KEYS.defaultId);
    profileId = isConnectionProfileId(rawDefault) ? rawDefault : DEFAULT_CONNECTION_PROFILE;
  }
  const squad = await readSetting(db, CONNECTION_PROFILE_KEYS.squad(profileId));
  return typeof squad === 'string' && squad.trim() ? squad : null;
}

export function publicProjection(profiles: ConnectionProfile[]): PublicConnectionProfile[] {
  return profiles.map((p) => ({
    id: p.id,
    // Only an admin-set label/description overrides the SPA's i18n copy; the
    // compiled English defaults must NOT ship (they'd pin English on every locale).
    label: p.labelCustom ? p.label : null,
    description: p.description,
    isDefault: p.isDefault,
    available: p.squadUuid !== null,
  }));
}

/**
 * Admin PATCH → appSettings writes. Validates ids; `label`/`description`/
 * `squadUuid` optional per id (an empty string clears back to the i18n/compiled
 * fallback); `default` optional. Returns the key/value pairs the mutation
 * persists (mirrors `billingConfigWrites`). Throws on a malformed patch.
 */
export function connectionProfileWrites(patch: unknown): Array<{ key: string; value: string }> {
  if (!patch || typeof patch !== 'object') {
    throw new Error('connection-profile patch must be an object');
  }
  const p = patch as Record<string, unknown>;
  const writes: Array<{ key: string; value: string }> = [];
  if ('default' in p) {
    if (!isConnectionProfileId(p.default)) throw new Error('invalid default profile id');
    writes.push({ key: CONNECTION_PROFILE_KEYS.defaultId, value: JSON.stringify(p.default) });
  }
  const profiles = (p.profiles ?? {}) as Record<string, unknown>;
  for (const id of CONNECTION_PROFILE_IDS) {
    const entry = profiles[id];
    if (!entry || typeof entry !== 'object') continue;
    const e = entry as Record<string, unknown>;
    if (typeof e.label === 'string') {
      writes.push({ key: CONNECTION_PROFILE_KEYS.label(id), value: JSON.stringify(e.label) });
    }
    if (typeof e.description === 'string') {
      writes.push({
        key: CONNECTION_PROFILE_KEYS.description(id),
        value: JSON.stringify(e.description),
      });
    }
    if (typeof e.squadUuid === 'string') {
      writes.push({ key: CONNECTION_PROFILE_KEYS.squad(id), value: JSON.stringify(e.squadUuid) });
    }
  }
  return writes;
}
