/**
 * Pure validation + masking for relay provider ACCOUNTS: the non-secret
 * `settings` variant per provider (zod), the secret `credentials` field list,
 * the admin-safe mask (per-field set/not-set booleans) and the keep-on-blank
 * merge. Isolate-safe (no SDK imports).
 *
 * `settings` holds two kinds of non-secret fields, told apart by name lists:
 *  - LOCATING settings (project / region / zone / network / gateway) decide
 *    where the account's resources live. Edges store only resource ids, so a
 *    locating change while edges exist would make them invisible to
 *    reconciliation and undeletable: locked by the account update mutation.
 *  - credential IDENTIFIERS (the public half of a key pair: Scaleway access
 *    key, OVH application key). They rotate with the secret and locate nothing,
 *    so they stay editable while edges exist.
 * `accountSettings.test.ts` pins that the two lists cover every schema key.
 */
import { z } from 'zod';
import type { EdgeProviderId } from '../edgeProviderIds';
import { canonicalJson } from './providers/template';

export const EDGE_SETTINGS_SCHEMAS = {
  gcore: z.object({
    type: z.literal('gcore'),
    projectId: z.number().int().positive(),
    regionId: z.number().int().positive(),
    networkId: z.string().min(1).max(128).optional(),
    subnetId: z.string().min(1).max(128).optional(),
  }),
  upcloud: z.object({
    type: z.literal('upcloud'),
    zone: z.string().regex(/^[a-z]{2}-[a-z]{3}\d$/, 'zone like de-fra1'),
  }),
  scaleway: z.object({
    type: z.literal('scaleway'),
    accessKey: z.string().regex(/^SCW[A-Z0-9]{17}$/, 'access key like SCWXXXXXXXXXXXXXXXXX'),
    // Optional: the API key's default project is used when absent.
    projectId: z.string().uuid().optional(),
    zone: z.string().regex(/^[a-z]{2}-[a-z]{3}-\d$/, 'zone like fr-par-1'),
  }),
  ovh: z.object({
    type: z.literal('ovh'),
    applicationKey: z.string().min(1).max(128),
    endpoint: z.enum(['ovh-eu', 'ovh-ca', 'ovh-us']),
    serviceName: z.string().min(1).max(128),
    regionName: z.string().min(1).max(64),
    networkId: z.string().min(1).max(128),
    subnetId: z.string().min(1).max(128),
    gatewayId: z.string().min(1).max(128).optional(),
  }),
} as const;

export type EdgeSettingsFor<P extends EdgeProviderId> = z.infer<(typeof EDGE_SETTINGS_SCHEMAS)[P]>;
export type EdgeSettings = EdgeSettingsFor<EdgeProviderId>;

/** Secret credential field names per provider (everything else on the row is non-secret). */
export const EDGE_CREDENTIAL_FIELDS: Record<EdgeProviderId, readonly string[]> = {
  gcore: ['apiKey'],
  upcloud: ['token'],
  scaleway: ['secretKey'],
  ovh: ['applicationSecret', 'consumerKey'],
};

/** Settings that LOCATE resources: locked while any non-destroyed edge references the account. */
export const EDGE_LOCATING_SETTINGS: Record<EdgeProviderId, readonly string[]> = {
  gcore: ['projectId', 'regionId', 'networkId', 'subnetId'],
  upcloud: ['zone'],
  scaleway: ['projectId', 'zone'],
  ovh: ['endpoint', 'serviceName', 'regionName', 'networkId', 'subnetId', 'gatewayId'],
};

/** Non-secret credential identifiers kept in `settings`: rotate with the secret, locate nothing. */
export const EDGE_CREDENTIAL_IDENTIFIER_FIELDS: Record<EdgeProviderId, readonly string[]> = {
  gcore: [],
  upcloud: [],
  scaleway: ['accessKey'],
  ovh: ['applicationKey'],
};

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
