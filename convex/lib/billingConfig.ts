/**
 * Billing catalog + rail toggles (the self-service membership purchase config).
 * Stored in `appSettings` under the `billing.*` namespace as JSON, exactly like
 * the W2 `ratelimit.*` policies: every consumer resolves a typed config and
 * FALLS BACK to the compiled defaults here when a row is missing or invalid
 * (fail-safe). This lets an operator edit prices / durations / which rails are
 * live WITHOUT a deploy, via the dedicated admin billing endpoint — never the
 * generic settings PATCH (these keys are intentionally NOT in SETTINGS_DEFAULTS,
 * so they don't leak through that allowlist and get structured validation here).
 *
 * Pure helpers (no Convex wrappers) so the resolver, the public config query,
 * the checkout action, and the admin write path share one source of truth.
 */
import type { DatabaseReader } from '../_generated/server';

export type BillingProcessor = 'nowpayments' | 'stripe' | 'paypal';
export const BILLING_PROCESSORS: readonly BillingProcessor[] = ['nowpayments', 'stripe', 'paypal'];

export interface BillingDuration {
  months: number;
  amountCents: number;
}

export interface BillingConfig {
  /** Master switch. When false the checkout route refuses and the SPA hides the upgrade UI. */
  enabled: boolean;
  /** Per-rail toggles. A rail also needs its processor secrets set (else its webhook 503s). */
  rails: Record<BillingProcessor, boolean>;
  /** Tier slug the membership maps to (resolved to a tierId at checkout). */
  tierSlug: string;
  /** ISO 4217 currency the prices are denominated in (display + processor invoice). */
  currency: string;
  /** Purchasable fixed terms, ascending by months. */
  durations: BillingDuration[];
}

/** Compiled defaults. PLACEHOLDER prices — set real ones in Admin → Billing pre-launch. */
export const BILLING_DEFAULTS: BillingConfig = {
  enabled: false,
  rails: { nowpayments: false, stripe: false, paypal: false },
  tierSlug: 'member',
  currency: 'USD',
  durations: [
    { months: 1, amountCents: 500 },
    { months: 3, amountCents: 1400 },
    { months: 6, amountCents: 2700 },
    { months: 12, amountCents: 5000 },
  ],
};

/** The `appSettings` keys this config is persisted across (the `billing.` namespace). */
export const BILLING_KEYS = {
  enabled: 'billing.enabled',
  rail_nowpayments: 'billing.nowpayments.enabled',
  rail_stripe: 'billing.stripe.enabled',
  rail_paypal: 'billing.paypal.enabled',
  tierSlug: 'billing.membership.tierSlug',
  currency: 'billing.membership.currency',
  durations: 'billing.membership.durations',
} as const;

const MAX_MONTHS = 120; // 10 years — a sane upper bound on a single fixed term.
const MAX_AMOUNT_CENTS = 10_000_00; // $10,000 — guards a fat-fingered admin edit.

/** Coerce a single duration entry; returns null if unusable (dropped by the caller). */
function sanitizeDuration(raw: unknown): BillingDuration | null {
  if (!raw || typeof raw !== 'object') return null;
  const o = raw as Record<string, unknown>;
  const months = o.months;
  const amountCents = o.amountCents;
  const okMonths =
    typeof months === 'number' && Number.isInteger(months) && months >= 1 && months <= MAX_MONTHS;
  const okAmount =
    typeof amountCents === 'number' &&
    Number.isInteger(amountCents) &&
    amountCents >= 0 &&
    amountCents <= MAX_AMOUNT_CENTS;
  if (!okMonths || !okAmount) return null;
  return { months: months as number, amountCents: amountCents as number };
}

/**
 * Coerce a durations list: drop malformed entries, dedupe by `months` (last
 * wins), sort ascending. An empty/all-invalid result falls back to the defaults
 * so the catalog is never empty when billing is on.
 */
export function sanitizeDurations(raw: unknown): BillingDuration[] {
  if (!Array.isArray(raw)) return [...BILLING_DEFAULTS.durations];
  const byMonths = new Map<number, BillingDuration>();
  for (const entry of raw) {
    const d = sanitizeDuration(entry);
    if (d) byMonths.set(d.months, d);
  }
  const list = [...byMonths.values()].sort((a, b) => a.months - b.months);
  return list.length > 0 ? list : [...BILLING_DEFAULTS.durations];
}

function asBool(raw: unknown, fallback: boolean): boolean {
  return typeof raw === 'boolean' ? raw : fallback;
}

function asNonEmptyString(raw: unknown, fallback: string): string {
  return typeof raw === 'string' && raw.trim().length > 0 ? raw : fallback;
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

/** Resolve the full billing config from stored `billing.*` rows, fail-safe to defaults. */
export async function resolveBillingConfig(db: DatabaseReader): Promise<BillingConfig> {
  const [enabled, np, st, pp, tierSlug, currency, durations] = await Promise.all([
    readSetting(db, BILLING_KEYS.enabled),
    readSetting(db, BILLING_KEYS.rail_nowpayments),
    readSetting(db, BILLING_KEYS.rail_stripe),
    readSetting(db, BILLING_KEYS.rail_paypal),
    readSetting(db, BILLING_KEYS.tierSlug),
    readSetting(db, BILLING_KEYS.currency),
    readSetting(db, BILLING_KEYS.durations),
  ]);
  return {
    enabled: asBool(enabled, BILLING_DEFAULTS.enabled),
    rails: {
      nowpayments: asBool(np, BILLING_DEFAULTS.rails.nowpayments),
      stripe: asBool(st, BILLING_DEFAULTS.rails.stripe),
      paypal: asBool(pp, BILLING_DEFAULTS.rails.paypal),
    },
    tierSlug: asNonEmptyString(tierSlug, BILLING_DEFAULTS.tierSlug),
    currency: asNonEmptyString(currency, BILLING_DEFAULTS.currency).toUpperCase(),
    durations: sanitizeDurations(durations),
  };
}

/** Look up a duration by months in a resolved config. */
export function findDuration(cfg: BillingConfig, months: number): BillingDuration | undefined {
  return cfg.durations.find((d) => d.months === months);
}

/**
 * Validate + normalize an admin billing-config PATCH into the exact
 * `appSettings` rows to write (key → JSON-encoded value). Only fields present in
 * `patch` are written (partial update); each is sanitized so an invalid edit
 * can't persist a value the resolver would just discard. Throws on a structurally
 * bad patch shape.
 */
export function billingConfigWrites(patch: unknown): Array<{ key: string; value: string }> {
  if (!patch || typeof patch !== 'object') {
    throw new Error('billing config patch must be an object');
  }
  const p = patch as Record<string, unknown>;
  const writes: Array<{ key: string; value: string }> = [];
  const put = (key: string, value: unknown) => writes.push({ key, value: JSON.stringify(value) });

  if ('enabled' in p) put(BILLING_KEYS.enabled, asBool(p.enabled, BILLING_DEFAULTS.enabled));
  if (p.rails && typeof p.rails === 'object') {
    const r = p.rails as Record<string, unknown>;
    if ('nowpayments' in r) put(BILLING_KEYS.rail_nowpayments, asBool(r.nowpayments, false));
    if ('stripe' in r) put(BILLING_KEYS.rail_stripe, asBool(r.stripe, false));
    if ('paypal' in r) put(BILLING_KEYS.rail_paypal, asBool(r.paypal, false));
  }
  if ('tierSlug' in p) {
    put(BILLING_KEYS.tierSlug, asNonEmptyString(p.tierSlug, BILLING_DEFAULTS.tierSlug));
  }
  if ('currency' in p) {
    put(
      BILLING_KEYS.currency,
      asNonEmptyString(p.currency, BILLING_DEFAULTS.currency).toUpperCase(),
    );
  }
  if ('durations' in p) put(BILLING_KEYS.durations, sanitizeDurations(p.durations));

  return writes;
}

// --- processor secrets (DB-stored, env-fallback) ----------------------------
//
// Secrets live in the same `appSettings` table as the proxy-backend secrets
// (backendServers.config), NOT in SETTINGS_DEFAULTS — so they're never returned
// by appSettings.resolved or publicConfig. They are resolved ONLY by the billing
// actions (internal) and surfaced to the admin UI as set/not-set booleans, never
// as values. DB takes precedence; an env var is the fallback (so an existing
// env-configured deploy keeps working until secrets are moved into the DB).

export interface ProcessorSecrets {
  publicBaseUrl: string;
  nowpayments: { apiKey: string; ipnSecret: string; apiUrl: string };
  stripe: { apiKey: string; webhookSecret: string };
  paypal: { clientId: string; secret: string; webhookId: string; apiBase: string };
}

const NOWPAYMENTS_DEFAULT_API = 'https://api.nowpayments.io';
const PAYPAL_DEFAULT_API = 'https://api-m.paypal.com';

/** Keys that hold credentials (`secret`) or non-secret processor config. */
export const BILLING_SECRET_KEYS = {
  publicBaseUrl: 'billing.publicBaseUrl',
  np_apiKey: 'billing.secret.nowpayments.apiKey',
  np_ipnSecret: 'billing.secret.nowpayments.ipnSecret',
  np_apiUrl: 'billing.nowpayments.apiUrl',
  stripe_apiKey: 'billing.secret.stripe.apiKey',
  stripe_webhookSecret: 'billing.secret.stripe.webhookSecret',
  pp_clientId: 'billing.secret.paypal.clientId',
  pp_secret: 'billing.secret.paypal.secret',
  pp_webhookId: 'billing.secret.paypal.webhookId',
  pp_apiBase: 'billing.paypal.apiBase',
} as const;

const asStr = (raw: unknown): string => (typeof raw === 'string' ? raw : '');

/** DB value (a non-blank string) else the env fallback else `fallback`. */
function dbOrEnv(dbVal: unknown, envName: string, fallback = ''): string {
  const s = asStr(dbVal).trim();
  if (s.length > 0) return s;
  const e = process.env[envName];
  return e && e.trim().length > 0 ? e : fallback;
}

/** Resolve all processor credentials (DB rows, env fallback). Internal use only. */
export async function resolveProcessorSecrets(db: DatabaseReader): Promise<ProcessorSecrets> {
  const [pub, npKey, npIpn, npUrl, stKey, stWh, ppCid, ppSec, ppWh, ppBase] = await Promise.all([
    readSetting(db, BILLING_SECRET_KEYS.publicBaseUrl),
    readSetting(db, BILLING_SECRET_KEYS.np_apiKey),
    readSetting(db, BILLING_SECRET_KEYS.np_ipnSecret),
    readSetting(db, BILLING_SECRET_KEYS.np_apiUrl),
    readSetting(db, BILLING_SECRET_KEYS.stripe_apiKey),
    readSetting(db, BILLING_SECRET_KEYS.stripe_webhookSecret),
    readSetting(db, BILLING_SECRET_KEYS.pp_clientId),
    readSetting(db, BILLING_SECRET_KEYS.pp_secret),
    readSetting(db, BILLING_SECRET_KEYS.pp_webhookId),
    readSetting(db, BILLING_SECRET_KEYS.pp_apiBase),
  ]);
  return {
    publicBaseUrl: dbOrEnv(pub, 'PUBLIC_BASE_URL'),
    nowpayments: {
      apiKey: dbOrEnv(npKey, 'NOWPAYMENTS_API_KEY'),
      ipnSecret: dbOrEnv(npIpn, 'NOWPAYMENTS_IPN_SECRET'),
      apiUrl: dbOrEnv(npUrl, 'NOWPAYMENTS_API_URL', NOWPAYMENTS_DEFAULT_API),
    },
    stripe: {
      apiKey: dbOrEnv(stKey, 'STRIPE_API_KEY'),
      webhookSecret: dbOrEnv(stWh, 'STRIPE_WEBHOOK_SECRET'),
    },
    paypal: {
      clientId: dbOrEnv(ppCid, 'PAYPAL_CLIENT_ID'),
      secret: dbOrEnv(ppSec, 'PAYPAL_SECRET'),
      webhookId: dbOrEnv(ppWh, 'PAYPAL_WEBHOOK_ID'),
      apiBase: dbOrEnv(ppBase, 'PAYPAL_API_BASE', PAYPAL_DEFAULT_API),
    },
  };
}

/** Admin-safe view: which credentials are set (booleans), plus the non-secret URLs. */
export interface ProcessorSecretStatus {
  publicBaseUrl: string;
  nowpayments: { apiKey: boolean; ipnSecret: boolean; apiUrl: string };
  stripe: { apiKey: boolean; webhookSecret: boolean };
  paypal: { clientId: boolean; secret: boolean; webhookId: boolean; apiBase: string };
}
export function processorSecretStatus(s: ProcessorSecrets): ProcessorSecretStatus {
  const set = (v: string) => v.trim().length > 0;
  return {
    publicBaseUrl: s.publicBaseUrl,
    nowpayments: {
      apiKey: set(s.nowpayments.apiKey),
      ipnSecret: set(s.nowpayments.ipnSecret),
      apiUrl: s.nowpayments.apiUrl,
    },
    stripe: { apiKey: set(s.stripe.apiKey), webhookSecret: set(s.stripe.webhookSecret) },
    paypal: {
      clientId: set(s.paypal.clientId),
      secret: set(s.paypal.secret),
      webhookId: set(s.paypal.webhookId),
      apiBase: s.paypal.apiBase,
    },
  };
}

/**
 * Admin secret-patch → `appSettings` writes. WRITE-ONLY: a blank field is left
 * unchanged (the UI never round-trips secret values, so a submit with empty
 * boxes must not wipe set credentials). Accepts `{ publicBaseUrl?, secrets?: {
 * nowpayments?, stripe?, paypal? } }`.
 */
export function billingSecretWrites(patch: unknown): Array<{ key: string; value: string }> {
  if (!patch || typeof patch !== 'object') return [];
  const p = patch as Record<string, unknown>;
  const writes: Array<{ key: string; value: string }> = [];
  const putStr = (key: string, raw: unknown) => {
    const s = asStr(raw).trim();
    if (s.length > 0) writes.push({ key, value: JSON.stringify(s) });
  };
  if ('publicBaseUrl' in p) putStr(BILLING_SECRET_KEYS.publicBaseUrl, p.publicBaseUrl);
  if (p.secrets && typeof p.secrets === 'object') {
    const s = p.secrets as Record<string, unknown>;
    const np = (s.nowpayments ?? {}) as Record<string, unknown>;
    putStr(BILLING_SECRET_KEYS.np_apiKey, np.apiKey);
    putStr(BILLING_SECRET_KEYS.np_ipnSecret, np.ipnSecret);
    putStr(BILLING_SECRET_KEYS.np_apiUrl, np.apiUrl);
    const st = (s.stripe ?? {}) as Record<string, unknown>;
    putStr(BILLING_SECRET_KEYS.stripe_apiKey, st.apiKey);
    putStr(BILLING_SECRET_KEYS.stripe_webhookSecret, st.webhookSecret);
    const pp = (s.paypal ?? {}) as Record<string, unknown>;
    putStr(BILLING_SECRET_KEYS.pp_clientId, pp.clientId);
    putStr(BILLING_SECRET_KEYS.pp_secret, pp.secret);
    putStr(BILLING_SECRET_KEYS.pp_webhookId, pp.webhookId);
    putStr(BILLING_SECRET_KEYS.pp_apiBase, pp.apiBase);
  }
  return writes;
}
