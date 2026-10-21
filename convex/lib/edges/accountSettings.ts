/**
 * Pure validation + masking for origin provider ACCOUNTS: the non-secret
 * `settings` variant per provider (zod), the secret `credentials` field list,
 * the admin-safe mask (per-field set/not-set booleans) and the keep-on-blank
 * merge. Isolate-safe (no SDK imports).
 *
 * An account is the WHOLE provider account: its credentials and what they can
 * reach. Where an edge's resources live is never the account's: it is a
 * LOCATION's placement (region / project / network for a load balancer, the
 * DNS zone (and the DNS account writing it) for a CDN front), chosen when a
 * node is protected and frozen on each edge. `settings` holds three kinds of
 * non-secret fields, told apart by name lists:
 *  - LOCATING settings decide where every one of the account's resources
 *    lives: locked by the account update mutation while edges exist. Only the
 *    API endpoint an OVH key was issued for is one.
 *  - credential IDENTIFIERS (the public half of a key pair: Scaleway access
 *    key, OVH application key; the Cloudflare account an account-owned token
 *    belongs to). They rotate with the secret and locate nothing, so they stay
 *    editable while edges exist.
 *  - INTENT DEFAULTS: values frozen into each edge's `provisionIntent` when
 *    the edge is planned, so a change only affects NEW edges. None is left:
 *    the TLS configuration of a front is its location's.
 * The certificate authority and the certificate scope used to be intent
 * defaults too; they are provider OPTIONS now (`providers/templates.ts`),
 * defaulted in the account's `optionDefaults`. A payload or a stored row that
 * still carries them under `settings` is translated (`legacyOptionDefaults`)
 * and never counts as a settings change.
 * `accountSettings.test.ts` pins that the three lists cover every schema key.
 */
import { z } from 'zod';
import type { EdgeProviderId } from '../edgeProviderIds';
import { canonicalJson } from './providers/template';

/** Account-level settings per provider: identifiers and intent defaults (never a place). */
export const EDGE_SETTINGS_SCHEMAS = {
  gcore: z.object({ type: z.literal('gcore') }),
  upcloud: z.object({ type: z.literal('upcloud') }),
  scaleway: z.object({
    type: z.literal('scaleway'),
    accessKey: z.string().regex(/^SCW[A-Z0-9]{17}$/, 'access key like SCWXXXXXXXXXXXXXXXXX'),
  }),
  ovh: z.object({
    type: z.literal('ovh'),
    applicationKey: z.string().min(1).max(128),
    // The API endpoint the application key was issued for: part of the
    // credential's identity, never a location.
    endpoint: z.enum(['ovh-eu', 'ovh-ca', 'ovh-us']),
  }),
  // L7: the token alone. `accountId` is the Cloudflare account an
  // account-owned token belongs to (its verify endpoint needs it when no zone
  // has been read yet); the zones the token reaches are locations.
  cloudflare: z.object({
    type: z.literal('cloudflare'),
    accountId: z
      .string()
      .regex(/^[0-9a-f]{32}$/)
      .optional(),
  }),
  // L7: Fastly services. The DNS account and zone a front's records live in,
  // and its TLS configuration, are its location's; certificates are
  // Fastly-managed TLS subscriptions.
  fastly: z.object({
    type: z.literal('fastly'),
    // How a new front's hostname is attached to its service: its own
    // (versionless, Domain Management) domain, or a domain on the service
    // version (classic; Fastly offers it only to accounts from before
    // 2025-09-16). Absent = versionless for a new edge (EDGE_INTENT_FACTS).
    // An account property, not a node's choice: it stays a setting.
    domainModel: z.enum(['versionless', 'classic']).optional(),
  }),
} as const;

/** A DNS zone id as the zone's provider issues it (Cloudflare: 32 hex characters). */
const ZONE_ID = z.string().regex(/^[0-9a-f]{32}$/, 'zone id is 32 hex characters');
/** A DNS zone name, lower case, at least two labels. */
const ZONE_NAME = z
  .string()
  .min(1)
  .max(253)
  .regex(
    /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/,
    'zone name like example.org',
  );

/**
 * Where an edge's resources live, per provider: what a LOCATION holds and each
 * edge freezes. For a CDN front that is the DNS zone its hostname lives in
 * (Cloudflare: one of the zones the account's token reaches; Fastly: a zone of
 * the DNS account it writes its records through, and the TLS configuration
 * that decides which addresses members reach). A CDN's place key is still
 * `anycast`: every zone of one CDN shares its address ranges.
 */
export const EDGE_PLACEMENT_SCHEMAS = {
  gcore: z.object({
    type: z.literal('gcore'),
    projectId: z.number().int().positive(),
    regionId: z.number().int().positive(),
    // Private VIP + floating-IP mode needs a network/subnet; public-VIP mode does not.
    networkId: z.string().min(1).max(128).optional(),
    subnetId: z.string().min(1).max(128).optional(),
  }),
  upcloud: z.object({
    type: z.literal('upcloud'),
    zone: z.string().regex(/^[a-z]{2}-[a-z]{3}\d$/, 'zone like de-fra1'),
  }),
  scaleway: z.object({
    type: z.literal('scaleway'),
    // Optional: the API key's default project is used when absent.
    projectId: z.string().uuid().optional(),
    zone: z.string().regex(/^[a-z]{2}-[a-z]{3}-\d$/, 'zone like fr-par-1'),
  }),
  ovh: z.object({
    type: z.literal('ovh'),
    serviceName: z.string().min(1).max(128),
    regionName: z.string().min(1).max(64),
    networkId: z.string().min(1).max(128),
    subnetId: z.string().min(1).max(128),
    gatewayId: z.string().min(1).max(128).optional(),
  }),
  cloudflare: z.object({ type: z.literal('cloudflare'), zoneId: ZONE_ID, zoneName: ZONE_NAME }),
  fastly: z.object({
    type: z.literal('fastly'),
    // An edgeProviderAccounts id of a DNS provider (Cloudflare today).
    dnsAccountId: z.string().min(1).max(64),
    zoneId: ZONE_ID,
    zoneName: ZONE_NAME,
    // Absent = the Fastly account's default TLS configuration.
    tlsConfigurationId: z.string().min(1).max(64).optional(),
  }),
} as const;

export type EdgePlacementFor<P extends EdgeProviderId> = z.infer<
  (typeof EDGE_PLACEMENT_SCHEMAS)[P]
>;
export type EdgePlacement = EdgePlacementFor<EdgeProviderId>;

export type EdgeSettingsFor<P extends EdgeProviderId> = z.infer<(typeof EDGE_SETTINGS_SCHEMAS)[P]>;
export type EdgeSettings = EdgeSettingsFor<EdgeProviderId>;

/** Secret credential field names per provider (everything else on the row is non-secret). */
export const EDGE_CREDENTIAL_FIELDS: Record<EdgeProviderId, readonly string[]> = {
  gcore: ['apiKey'],
  upcloud: ['token'],
  scaleway: ['secretKey'],
  ovh: ['applicationSecret', 'consumerKey'],
  cloudflare: ['apiToken'],
  fastly: ['apiToken'],
};

/** Placement fields per provider: on a LOCATION (and frozen on each edge), never on the account. */
export const EDGE_PLACEMENT_SETTINGS: Record<EdgeProviderId, readonly string[]> = {
  gcore: ['projectId', 'regionId', 'networkId', 'subnetId'],
  upcloud: ['zone'],
  scaleway: ['projectId', 'zone'],
  ovh: ['serviceName', 'regionName', 'networkId', 'subnetId', 'gatewayId'],
  cloudflare: ['zoneId', 'zoneName'],
  fastly: ['dnsAccountId', 'zoneId', 'zoneName', 'tlsConfigurationId'],
};

/** Account settings that still LOCATE every edge of the account: locked while any non-destroyed edge references it. */
export const EDGE_LOCATING_SETTINGS: Record<EdgeProviderId, readonly string[]> = {
  gcore: [],
  upcloud: [],
  scaleway: [],
  // The application key was issued for one API endpoint: another endpoint is
  // another API, where none of the account's resources exist.
  ovh: ['endpoint'],
  cloudflare: [],
  fastly: [],
};

/** Defaults frozen into each new edge's provisionIntent (L7); a change never moves an existing edge. */
export const EDGE_INTENT_DEFAULT_SETTINGS: Record<EdgeProviderId, readonly string[]> = {
  gcore: [],
  upcloud: [],
  scaleway: [],
  ovh: [],
  cloudflare: [],
  fastly: ['domainModel'],
};

/**
 * Settings whose change makes the account's last credential test answer for
 * something else: changing one marks the account untested (`retest_required`)
 * until a new test runs. None is left: the zone, its DNS account and the TLS
 * configuration are a location's placement (never edited: another one is
 * another location), and the authority and the scope are provider options,
 * whose account defaults do the same when they change
 * (`edgeProviderAccounts.update`).
 */
export const EDGE_RETEST_SETTINGS: Record<EdgeProviderId, readonly string[]> = {
  gcore: [],
  upcloud: [],
  scaleway: [],
  ovh: [],
  cloudflare: [],
  fastly: [],
};

/**
 * Settings a NEW account gets when its payload leaves them out, where the
 * schema itself must not default them (an existing account without the key
 * keeps its older behaviour until it is switched). Options a new account
 * starts from are `EDGE_NEW_ACCOUNT_OPTION_DEFAULTS` (providers/templates.ts).
 */
export const EDGE_NEW_ACCOUNT_SETTINGS: Partial<Record<EdgeProviderId, Record<string, unknown>>> = {
  fastly: { domainModel: 'versionless' },
};

/**
 * How the provider is driven, frozen into every NEW edge's intent: `planned`
 * unless the account's setting of the same name says otherwise (an intent
 * default the operator may set, `domainModel`), while an intent without the
 * key predates it and keeps `legacy`. `edgeProviderOps.loadAdapter` gives the
 * adapter the account's choice (else `planned`) when it plans, and the edge's
 * own value (else `legacy`) afterwards.
 */
export const EDGE_INTENT_FACTS: Record<
  EdgeProviderId,
  Readonly<Record<string, { planned: string; legacy: string }>>
> = {
  gcore: {},
  upcloud: {},
  scaleway: {},
  ovh: {},
  cloudflare: {},
  // A versionless (Domain Management) domain instead of a version's domain.
  fastly: { domainModel: { planned: 'versionless', legacy: 'classic' } },
};

/**
 * Settings keys that are provider OPTIONS now (account `optionDefaults`): a
 * stored row may still hold them until `migrateOptionDefaults` has run, and an
 * older client may still send them.
 */
export const EDGE_LEGACY_OPTION_SETTINGS: Record<EdgeProviderId, readonly string[]> = {
  gcore: [],
  upcloud: [],
  scaleway: [],
  ovh: [],
  cloudflare: [],
  fastly: ['certificateAuthority', 'certificateScope'],
};

/** The option defaults a settings payload (or a stored row) still carries the old way. */
export function legacyOptionDefaults(
  provider: EdgeProviderId,
  raw: Record<string, unknown> | undefined,
): Record<string, unknown> {
  return raw ? pick(raw, EDGE_LEGACY_OPTION_SETTINGS[provider]) : {};
}

/** Non-secret credential identifiers kept in `settings`: rotate with the secret, locate nothing. */
export const EDGE_CREDENTIAL_IDENTIFIER_FIELDS: Record<EdgeProviderId, readonly string[]> = {
  gcore: [],
  upcloud: [],
  scaleway: ['accessKey'],
  ovh: ['applicationKey'],
  cloudflare: ['accountId'],
  fastly: [],
};

/**
 * The settings keys of the shape before L7 locations (a CDN account's zone, a
 * Fastly account's DNS account and TLS configuration): moved onto the
 * account's location by the L7 locations migration and read only as its
 * fallback. An edit keeps whatever of them a row still has (stripping them
 * before the migration ran would lose the place), and the cleanup drops them.
 */
export const EDGE_LEGACY_SETTINGS: Record<EdgeProviderId, readonly string[]> = {
  gcore: [],
  upcloud: [],
  scaleway: [],
  ovh: [],
  cloudflare: ['zoneId', 'zoneName'],
  fastly: ['dnsAccountId', 'tlsConfigurationId'],
};

/** The legacy keys a stored settings object still carries (usually none). */
export function legacySettingsOf(
  provider: EdgeProviderId,
  stored: Record<string, unknown>,
): Record<string, unknown> {
  return pick(stored, EDGE_LEGACY_SETTINGS[provider]);
}

export type EdgeCredentials = { type: EdgeProviderId } & Record<string, string>;

export function validateSettings(
  provider: EdgeProviderId,
  raw: unknown,
): { ok: true; settings: EdgeSettings } | { ok: false; issues: string[] } {
  const res = EDGE_SETTINGS_SCHEMAS[provider].safeParse({
    ...((raw ?? {}) as Record<string, unknown>),
    type: provider,
  });
  if (res.success) return { ok: true, settings: res.data as EdgeSettings };
  return {
    ok: false,
    issues: res.error.issues
      .slice(0, 10)
      .map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`),
  };
}

export function validatePlacement(
  provider: EdgeProviderId,
  raw: unknown,
): { ok: true; placement: EdgePlacement } | { ok: false; issues: string[] } {
  const res = EDGE_PLACEMENT_SCHEMAS[provider].safeParse({
    ...((raw ?? {}) as Record<string, unknown>),
    type: provider,
  });
  if (res.success) return { ok: true, placement: res.data as EdgePlacement };
  return {
    ok: false,
    issues: res.error.issues
      .slice(0, 10)
      .map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`),
  };
}

/**
 * The placement keys an admin payload carries (null when it carries none):
 * what an account created with the single-location shape says about where its
 * first location is.
 */
export function placementKeysOf(
  provider: EdgeProviderId,
  raw: Record<string, unknown> | undefined,
): Record<string, unknown> | null {
  const keys = EDGE_PLACEMENT_SETTINGS[provider];
  if (keys.length === 0 || !raw) return null;
  const out = pick(raw, keys);
  return Object.keys(out).length > 0 ? out : null;
}

/**
 * The settings with every placement key (a location's) and every key that is
 * an option now (`EDGE_LEGACY_OPTION_SETTINGS`) removed: what the account's
 * settings themselves keep.
 */
export function withoutPlacementKeys(
  provider: EdgeProviderId,
  raw: Record<string, unknown>,
): Record<string, unknown> {
  const drop = new Set([
    ...EDGE_PLACEMENT_SETTINGS[provider],
    ...EDGE_LEGACY_OPTION_SETTINGS[provider],
  ]);
  return Object.fromEntries(Object.entries(raw).filter(([k]) => !drop.has(k)));
}

/** Key-order-insensitive, recursive equality (stored rows may reorder keys). */
export function settingsEqual(a: unknown, b: unknown): boolean {
  return canonicalJson(a) === canonicalJson(b);
}

function pick(obj: Record<string, unknown>, keys: readonly string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of keys) if (obj[k] !== undefined) out[k] = obj[k];
  return out;
}

/** True when any LOCATING setting differs between two settings objects (order-insensitive). */
export function locatingSettingsChanged(
  provider: EdgeProviderId,
  next: Record<string, unknown>,
  prev: Record<string, unknown>,
): boolean {
  const keys = EDGE_LOCATING_SETTINGS[provider];
  return !settingsEqual(pick(next, keys), pick(prev, keys));
}

/** Only the credential-identifier fields of an admin payload (unknown keys dropped). */
export function pickCredentialIdentifiers(
  provider: EdgeProviderId,
  incoming: Record<string, unknown> | undefined,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of EDGE_CREDENTIAL_IDENTIFIER_FIELDS[provider]) {
    const v = incoming?.[k];
    if (typeof v === 'string' && v.trim().length > 0) out[k] = v.trim();
  }
  return out;
}

/** Admin-safe view: `{ apiKey: true }` style booleans, never a value. */
export function maskCredentials(creds: Record<string, unknown>): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  for (const [k, v] of Object.entries(creds)) {
    if (k === 'type') continue;
    out[k] = typeof v === 'string' && v.length > 0;
  }
  return out;
}

/**
 * Build credentials for a provider from an admin payload. On CREATE every field
 * is required; on UPDATE (`existing` given) a blank/absent field keeps the
 * stored value (the UI never round-trips secrets). Unknown fields are dropped.
 */
export function buildCredentials(
  provider: EdgeProviderId,
  incoming: Record<string, unknown> | undefined,
  existing?: Record<string, unknown>,
): { ok: true; credentials: EdgeCredentials } | { ok: false; missing: string[] } {
  const out: Record<string, string> = {};
  const missing: string[] = [];
  for (const field of EDGE_CREDENTIAL_FIELDS[provider]) {
    const raw = incoming?.[field];
    const val = typeof raw === 'string' ? raw.trim() : '';
    if (val.length > 0) out[field] = val;
    else if (
      existing &&
      typeof existing[field] === 'string' &&
      (existing[field] as string).length > 0
    )
      out[field] = existing[field] as string;
    else missing.push(field);
  }
  if (missing.length > 0) return { ok: false, missing };
  return { ok: true, credentials: { type: provider, ...out } };
}

/** Deterministic provider-side name for a new edge (the discovery key). */
export function edgeResourceName(relaySlug: string, nonceHex8: string): string {
  const slug = relaySlug
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '-')
    .slice(0, 24);
  return `fcp-relay-${slug}-${nonceHex8}`;
}
