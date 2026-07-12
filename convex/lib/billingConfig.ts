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

export type BillingProcessor = 'nowpayments' | 'btcpay' | 'stripe' | 'paypal';

export interface BillingDuration {
  months: number;
  amountCents: number;
}

/**
 * Optional donations. A supporter can add a donation on top of a membership
 * checkout or give standalone. Donations in a calendar month accumulate into a
 * shared pool that raises every free user's monthly bandwidth cap by
 * `min(monthlyBonusCapGb, monthDonatedUSD * bonusGbPerUsd)` (see
 * lib/donationBonus.ts). All fields are non-secret and shipped in publicConfig so
 * the picker + the "adds N GB" copy can render.
 */
export interface DonationConfig {
  /** Master switch for the donation UI (also gated by the billing `enabled` flag). */
  enabled: boolean;
  /** Preset amount chips shown in the picker (minor units / cents), ascending. */
  suggestedAmountsCents: number[];
  /** Floor for a standalone donation-only checkout (cents). */
  minAmountCents: number;
  /** GB added to the shared monthly pool per 1 unit of currency donated. */
  bonusGbPerUsd: number;
  /** Ceiling on the shared monthly bonus (GB) regardless of how much is donated. */
  monthlyBonusCapGb: number;
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
  /**
   * Minimum term (months) purchasable with the crypto rail (NOWPayments). Each
   * coin has a per-payment minimum that floats with fees — XMR's is high — and
   * the payer picks the coin on the hosted page, so we can't pre-check it. This
   * floor keeps the cheapest offered crypto term above that minimum; shorter
   * terms stay card/PayPal-only. Card/PayPal have no such floor (min 1).
   */
  cryptoMinMonths: number;
  /**
   * Minimum term (months) purchasable with the BTCPay rail. Defaults to 1:
   * Lightning has no meaningful per-payment minimum, and the operator's own
   * BTCPay policy (not a third party's coin list) governs on-chain floors.
   */
  btcpayMinMonths: number;
  /** Optional-donation config (add-on + standalone → free-user bandwidth pool). */
  donation: DonationConfig;
}

/** Compiled defaults. PLACEHOLDER prices — set real ones in Admin → Billing pre-launch. */
export const BILLING_DEFAULTS: BillingConfig = {
  enabled: false,
  rails: { nowpayments: false, btcpay: false, stripe: false, paypal: false },
  tierSlug: 'member',
  currency: 'USD',
  durations: [
    { months: 1, amountCents: 500 },
    { months: 3, amountCents: 1400 },
    { months: 6, amountCents: 2700 },
    { months: 12, amountCents: 5000 },
  ],
  cryptoMinMonths: 3,
  btcpayMinMonths: 1,
  donation: {
    enabled: true,
    suggestedAmountsCents: [300, 500, 1000, 2500],
    minAmountCents: 200,
    bonusGbPerUsd: 1,
    monthlyBonusCapGb: 100,
  },
};

/** The `appSettings` keys this config is persisted across (the `billing.` namespace). */
export const BILLING_KEYS = {
  enabled: 'billing.enabled',
  rail_nowpayments: 'billing.nowpayments.enabled',
  rail_btcpay: 'billing.btcpay.enabled',
  rail_stripe: 'billing.stripe.enabled',
  rail_paypal: 'billing.paypal.enabled',
  tierSlug: 'billing.membership.tierSlug',
  currency: 'billing.membership.currency',
  durations: 'billing.membership.durations',
  cryptoMinMonths: 'billing.nowpayments.minMonths',
  btcpayMinMonths: 'billing.btcpay.minMonths',
  donation_enabled: 'billing.donation.enabled',
  donation_suggestedAmounts: 'billing.donation.suggestedAmounts',
  donation_minAmountCents: 'billing.donation.minAmountCents',
  donation_bonusGbPerUsd: 'billing.donation.bonusGbPerUsd',
  donation_monthlyBonusCapGb: 'billing.donation.monthlyBonusCapGb',
} as const;

const MAX_MONTHS = 120; // 10 years — a sane upper bound on a single fixed term.
const MAX_AMOUNT_CENTS = 10_000_00; // $10,000 — guards a fat-fingered admin edit.
const MAX_SUGGESTED_AMOUNTS = 8; // cap the preset-chip list length.
const MAX_BONUS_GB_PER_USD = 1000; // sanity ceiling on the donation→bandwidth rate.
const MAX_MONTHLY_CAP_GB = 100_000; // sanity ceiling on the shared monthly bonus.

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

/** Clamp a minimum-term value to an integer in [1, MAX_MONTHS]; else the fallback. */
function asMinMonths(raw: unknown, fallback: number): number {
  return typeof raw === 'number' && Number.isInteger(raw) && raw >= 1 && raw <= MAX_MONTHS
    ? raw
    : fallback;
}

/** A positive integer amount of cents in [1, MAX_AMOUNT_CENTS]; else the fallback. */
function asAmountCents(raw: unknown, fallback: number): number {
  return typeof raw === 'number' && Number.isInteger(raw) && raw >= 1 && raw <= MAX_AMOUNT_CENTS
    ? raw
    : fallback;
}

/** A finite non-negative number clamped to [0, max]; else the fallback. */
function asNonNegNumber(raw: unknown, fallback: number, max: number): number {
  return typeof raw === 'number' && Number.isFinite(raw) && raw >= 0 && raw <= max ? raw : fallback;
}

/**
 * Coerce the suggested-donation-amounts list: keep positive integer cents, dedupe,
 * sort ascending, cap the count. Empty/all-invalid falls back to the defaults.
 */
export function sanitizeAmountsList(raw: unknown): number[] {
  if (!Array.isArray(raw)) return [...BILLING_DEFAULTS.donation.suggestedAmountsCents];
  const set = new Set<number>();
  for (const v of raw) {
    if (typeof v === 'number' && Number.isInteger(v) && v >= 1 && v <= MAX_AMOUNT_CENTS) set.add(v);
  }
  const list = [...set].sort((a, b) => a - b).slice(0, MAX_SUGGESTED_AMOUNTS);
  return list.length > 0 ? list : [...BILLING_DEFAULTS.donation.suggestedAmountsCents];
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
  const [
    enabled,
    np,
    bp,
    st,
    pp,
    tierSlug,
    currency,
    durations,
    cryptoMin,
    btcpayMin,
    dEnabled,
    dAmounts,
    dMin,
    dRate,
    dCap,
  ] = await Promise.all([
    readSetting(db, BILLING_KEYS.enabled),
    readSetting(db, BILLING_KEYS.rail_nowpayments),
    readSetting(db, BILLING_KEYS.rail_btcpay),
    readSetting(db, BILLING_KEYS.rail_stripe),
    readSetting(db, BILLING_KEYS.rail_paypal),
    readSetting(db, BILLING_KEYS.tierSlug),
    readSetting(db, BILLING_KEYS.currency),
    readSetting(db, BILLING_KEYS.durations),
    readSetting(db, BILLING_KEYS.cryptoMinMonths),
    readSetting(db, BILLING_KEYS.btcpayMinMonths),
    readSetting(db, BILLING_KEYS.donation_enabled),
    readSetting(db, BILLING_KEYS.donation_suggestedAmounts),
    readSetting(db, BILLING_KEYS.donation_minAmountCents),
    readSetting(db, BILLING_KEYS.donation_bonusGbPerUsd),
    readSetting(db, BILLING_KEYS.donation_monthlyBonusCapGb),
  ]);
  const d = BILLING_DEFAULTS.donation;
  return {
    enabled: asBool(enabled, BILLING_DEFAULTS.enabled),
    rails: {
      nowpayments: asBool(np, BILLING_DEFAULTS.rails.nowpayments),
      btcpay: asBool(bp, BILLING_DEFAULTS.rails.btcpay),
      stripe: asBool(st, BILLING_DEFAULTS.rails.stripe),
      paypal: asBool(pp, BILLING_DEFAULTS.rails.paypal),
    },
    tierSlug: asNonEmptyString(tierSlug, BILLING_DEFAULTS.tierSlug),
    currency: asNonEmptyString(currency, BILLING_DEFAULTS.currency).toUpperCase(),
    durations: sanitizeDurations(durations),
    cryptoMinMonths: asMinMonths(cryptoMin, BILLING_DEFAULTS.cryptoMinMonths),
    btcpayMinMonths: asMinMonths(btcpayMin, BILLING_DEFAULTS.btcpayMinMonths),
    donation: {
      enabled: asBool(dEnabled, d.enabled),
      suggestedAmountsCents: sanitizeAmountsList(dAmounts),
      minAmountCents: asAmountCents(dMin, d.minAmountCents),
      bonusGbPerUsd: asNonNegNumber(dRate, d.bonusGbPerUsd, MAX_BONUS_GB_PER_USD),
      monthlyBonusCapGb: asNonNegNumber(dCap, d.monthlyBonusCapGb, MAX_MONTHLY_CAP_GB),
    },
  };
}

/** Look up a duration by months in a resolved config. */
export function findDuration(cfg: BillingConfig, months: number): BillingDuration | undefined {
  return cfg.durations.find((d) => d.months === months);
}

/**
 * Minimum purchasable term (months) for a rail. Crypto (NOWPayments) carries the
 * per-coin-minimum floor; card/PayPal have none. The SPA mirrors this to gate the
 * duration picker; the checkout action enforces it server-side.
 */
export function minMonthsForProcessor(cfg: BillingConfig, processor: BillingProcessor): number {
  if (processor === 'nowpayments') return cfg.cryptoMinMonths;
  if (processor === 'btcpay') return cfg.btcpayMinMonths;
  return 1;
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
    if ('btcpay' in r) put(BILLING_KEYS.rail_btcpay, asBool(r.btcpay, false));
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
  if ('cryptoMinMonths' in p) {
    put(
      BILLING_KEYS.cryptoMinMonths,
      asMinMonths(p.cryptoMinMonths, BILLING_DEFAULTS.cryptoMinMonths),
    );
  }
  if ('btcpayMinMonths' in p) {
    put(
      BILLING_KEYS.btcpayMinMonths,
      asMinMonths(p.btcpayMinMonths, BILLING_DEFAULTS.btcpayMinMonths),
    );
  }
  if (p.donation && typeof p.donation === 'object') {
    const dd = p.donation as Record<string, unknown>;
    const def = BILLING_DEFAULTS.donation;
    if ('enabled' in dd) put(BILLING_KEYS.donation_enabled, asBool(dd.enabled, def.enabled));
    if ('suggestedAmountsCents' in dd) {
      put(BILLING_KEYS.donation_suggestedAmounts, sanitizeAmountsList(dd.suggestedAmountsCents));
    }
    if ('minAmountCents' in dd) {
      put(
        BILLING_KEYS.donation_minAmountCents,
        asAmountCents(dd.minAmountCents, def.minAmountCents),
      );
    }
    if ('bonusGbPerUsd' in dd) {
      put(
        BILLING_KEYS.donation_bonusGbPerUsd,
        asNonNegNumber(dd.bonusGbPerUsd, def.bonusGbPerUsd, MAX_BONUS_GB_PER_USD),
      );
    }
    if ('monthlyBonusCapGb' in dd) {
      put(
        BILLING_KEYS.donation_monthlyBonusCapGb,
        asNonNegNumber(dd.monthlyBonusCapGb, def.monthlyBonusCapGb, MAX_MONTHLY_CAP_GB),
      );
    }
  }

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
  btcpay: { apiKey: string; webhookSecret: string; apiUrl: string; storeId: string };
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
  bp_apiKey: 'billing.secret.btcpay.apiKey',
  bp_webhookSecret: 'billing.secret.btcpay.webhookSecret',
  bp_apiUrl: 'billing.btcpay.apiUrl',
  bp_storeId: 'billing.btcpay.storeId',
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
  const [
    pub,
    npKey,
    npIpn,
    npUrl,
    bpKey,
    bpWh,
    bpUrl,
    bpStore,
    stKey,
    stWh,
    ppCid,
    ppSec,
    ppWh,
    ppBase,
  ] = await Promise.all([
    readSetting(db, BILLING_SECRET_KEYS.publicBaseUrl),
    readSetting(db, BILLING_SECRET_KEYS.np_apiKey),
    readSetting(db, BILLING_SECRET_KEYS.np_ipnSecret),
    readSetting(db, BILLING_SECRET_KEYS.np_apiUrl),
    readSetting(db, BILLING_SECRET_KEYS.bp_apiKey),
    readSetting(db, BILLING_SECRET_KEYS.bp_webhookSecret),
    readSetting(db, BILLING_SECRET_KEYS.bp_apiUrl),
    readSetting(db, BILLING_SECRET_KEYS.bp_storeId),
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
    // BTCPay is self-hosted: the API URL is the operator's own server, so there
    // is deliberately NO default (unset = rail not configured).
    btcpay: {
      apiKey: dbOrEnv(bpKey, 'BTCPAY_API_KEY'),
      webhookSecret: dbOrEnv(bpWh, 'BTCPAY_WEBHOOK_SECRET'),
      apiUrl: dbOrEnv(bpUrl, 'BTCPAY_API_URL'),
      storeId: dbOrEnv(bpStore, 'BTCPAY_STORE_ID'),
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
  btcpay: { apiKey: boolean; webhookSecret: boolean; apiUrl: string; storeId: string };
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
    btcpay: {
      apiKey: set(s.btcpay.apiKey),
      webhookSecret: set(s.btcpay.webhookSecret),
      apiUrl: s.btcpay.apiUrl,
      storeId: s.btcpay.storeId,
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
    const bp = (s.btcpay ?? {}) as Record<string, unknown>;
    putStr(BILLING_SECRET_KEYS.bp_apiKey, bp.apiKey);
    putStr(BILLING_SECRET_KEYS.bp_webhookSecret, bp.webhookSecret);
    putStr(BILLING_SECRET_KEYS.bp_apiUrl, bp.apiUrl);
    putStr(BILLING_SECRET_KEYS.bp_storeId, bp.storeId);
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
