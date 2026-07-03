/**
 * Connection profiles (2026-07-03): the member-facing transport choice —
 * "Stay connected" (evade) = a CDN-fronted WS+XHTTP Remnawave squad, and
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

/** Server-side profile: id + admin label + the squad it issues into. */
export interface ConnectionProfile {
  id: ConnectionProfileId;
  label: string;
  squadUuid: string | null; // null until bound; issuance then falls back to the tier squad
  isDefault: boolean;
}

/** Public-safe projection — the exact shape publicConfig ships (NO squadUuid). */
export interface PublicConnectionProfile {
  id: ConnectionProfileId;
  label: string;
  isDefault: boolean;
  available: boolean; // squad bound → selectable (else it would fall back to the tier squad)
}

/** appSettings keys — `connectionProfile.<id>.<field>` (parallels the theme and billing namespaces). */
export const CONNECTION_PROFILE_KEYS = {
  label: (id: ConnectionProfileId) => `connectionProfile.${id}.label`,
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

/** Resolve the full catalog, fail-safe. Always returns every known id. */
export async function resolveConnectionProfiles(db: DatabaseReader): Promise<ConnectionProfile[]> {
  const rawDefault = await readSetting(db, CONNECTION_PROFILE_KEYS.defaultId);
  const defaultId = isConnectionProfileId(rawDefault) ? rawDefault : DEFAULT_CONNECTION_PROFILE;
  const out: ConnectionProfile[] = [];
  for (const id of CONNECTION_PROFILE_IDS) {
    const label = await readSetting(db, CONNECTION_PROFILE_KEYS.label(id));
    const squad = await readSetting(db, CONNECTION_PROFILE_KEYS.squad(id));
    out.push({
      id,
      label: typeof label === 'string' && label.trim() ? label : DEFAULT_LABELS[id],
      squadUuid: typeof squad === 'string' && squad.trim() ? squad : null,
      isDefault: id === defaultId,
    });
  }
  return out;
}

/** The squad a profile issues into (issuance path). null when unknown/unbound —
 *  callers fall back to the tier's own squad, so behavior is unchanged until a
 *  profile is actually bound. */
export async function resolveProfileSquad(
  db: DatabaseReader,
  id: ConnectionProfileId | null | undefined,
): Promise<string | null> {
  if (!isConnectionProfileId(id)) return null;
  const squad = await readSetting(db, CONNECTION_PROFILE_KEYS.squad(id));
  return typeof squad === 'string' && squad.trim() ? squad : null;
}

export function publicProjection(profiles: ConnectionProfile[]): PublicConnectionProfile[] {
  return profiles.map((p) => ({
    id: p.id,
    label: p.label,
    isDefault: p.isDefault,
    available: p.squadUuid !== null,
  }));
}

/**
 * Admin PATCH → appSettings writes. Validates ids; `label`/`squadUuid` optional
 * per id; `default` optional. Returns the key/value pairs the mutation persists
 * (mirrors `billingConfigWrites`). Throws on a malformed patch.
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
    if (typeof e.squadUuid === 'string') {
      writes.push({ key: CONNECTION_PROFILE_KEYS.squad(id), value: JSON.stringify(e.squadUuid) });
    }
  }
  return writes;
}
