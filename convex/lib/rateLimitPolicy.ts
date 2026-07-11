/**
 * W2 (launch): rate-limit policies are admin-tunable knobs stored in
 * `appSettings` under the `ratelimit.<key>` namespace as JSON
 * `{max, windowMs, enabled}`. Every limited endpoint resolves its policy by key
 * and FALLS BACK to the compiled default here when the row is missing or
 * invalid — fail-safe, never fail-open. This lets an operator retune limits live
 * (e.g. under attack, or to loosen the free-tier cap for a CGNAT region) without
 * a deploy, since limits are read per request.
 *
 * The pure helpers live here (no Convex wrappers) so both the `enforce` mutation
 * and the `getPolicy` query in convex/rateLimits.ts share one source of truth.
 */
import type { DatabaseReader } from '../_generated/server';

export interface RateLimitPolicy {
  max: number;
  windowMs: number;
  enabled: boolean;
}

const DAY = 86_400_000;
const HOUR = 3_600_000;
const MINUTE = 60_000;

/**
 * Compiled defaults. Every key a call site enforces MUST appear here — it's the
 * allowlist (admin edits to unknown keys are rejected) and the fallback.
 */
export const RATE_LIMIT_DEFAULTS = {
  // Anonymous free-account creation — the per-(IP,day) cap. This IS the hard cap:
  // freeTier.createFreeAccount RESERVES a slot here (increment) before creating the
  // account, so NO durable IP is stored — the hashed IP lives only in this
  // auto-expiring bucket. `max` = accounts per IP per `windowMs` (raised 1 -> 3 for
  // carrier-grade-NAT regions); the counter is serializable, so it closes the H1
  // over-issuance race the old freeGrants slot-claim used to. `enabled:false` => no cap.
  'freetier.create': { max: 3, windowMs: DAY, enabled: true },
  // Per-IP throttle on the account-create route, in front of the captcha verify.
  'account.create.ip': { max: 12, windowMs: HOUR, enabled: true },
  // Member account-number login.
  'account-login.ip': { max: 10, windowMs: HOUR, enabled: true },
  'account-login.prefix': { max: 30, windowMs: DAY, enabled: true },
  // Authenticated member issuance actions (each mints/replaces a backend key).
  'account.regenerate': { max: 10, windowMs: HOUR, enabled: true },
  'account.switch-backend': { max: 10, windowMs: HOUR, enabled: true },
  'account.switch-mode': { max: 10, windowMs: HOUR, enabled: true },
  'account.refresh-membership': { max: 1, windowMs: 30_000, enabled: true },
  // Account-number rotation mints a fresh credential; throttle hard vs. churn.
  'account.rotate': { max: 5, windowMs: HOUR, enabled: true },
  // Member device (HWID) revocation: cheap backend call, but cap the churn.
  'account.device-revoke': { max: 10, windowMs: HOUR, enabled: true },
  // Membership code redemption (W4): throttle hard against code guessing.
  'code.redeem': { max: 5, windowMs: HOUR, enabled: true },
  // Member passkey LOGIN options (per IP): each call writes an assertion challenge
  // row, so bound challenge-flooding. The assertion itself is cryptographic (not
  // guessable), so no captcha gates it — this is the only throttle on that path.
  'passkey.authenticate': { max: 30, windowMs: HOUR, enabled: true },
  // Member passkey ENROLLMENT options (per member): cap churn on the add-a-passkey
  // flow (already session-gated, so this is hygiene, not access control).
  'account.passkey-register': { max: 20, windowMs: HOUR, enabled: true },
  // Per-IP throttle on the billing webhook (generous; a legit portal calls it).
  'webhook.billing.ip': { max: 60, windowMs: MINUTE, enabled: true },
  // Self-service membership checkout (per member): each call creates a hosted
  // invoice + a pending order, so cap the churn without blocking real retries.
  'billing.checkout': { max: 10, windowMs: HOUR, enabled: true },
  // Per-IP throttle on the crypto IPN (a single payment fires several status
  // callbacks: waiting → confirming → finished — so this is generous).
  'webhook.nowpayments.ip': { max: 120, windowMs: MINUTE, enabled: true },
  // Per-IP throttle on the BTCPay store webhook (same shape: several invoice
  // events per payment — created → processing → settled).
  'webhook.btcpay.ip': { max: 120, windowMs: MINUTE, enabled: true },
  // Per-IP throttle on the Stripe + PayPal webhooks (generous; legit senders).
  'webhook.stripe.ip': { max: 120, windowMs: MINUTE, enabled: true },
  'webhook.paypal.ip': { max: 120, windowMs: MINUTE, enabled: true },
  // Opt-in mirror provisioning (per member): generous — this is a troubleshooting
  // flow a stuck user taps repeatedly, but the per-user cap is the real bound.
  'mirror.request': { max: 20, windowMs: HOUR, enabled: true },
  // FCP-fronted subscription URL fetch (per IP). Proxy apps re-poll periodically
  // and the short-TTL cache absorbs bursts, so this is generous — it's DoS
  // hygiene, not access control (the token is a 128-bit unguessable capability).
  'subscription.fetch': { max: 120, windowMs: MINUTE, enabled: true },
  // Unauthenticated public GETs (per IP) — DoS-amplification hygiene, not access
  // control. Generous: the SPA polls /config on load and /e2ee/keys before a
  // sealed login, and both are briefly cacheable.
  'config.fetch': { max: 120, windowMs: MINUTE, enabled: true },
  'e2ee.keys.fetch': { max: 120, windowMs: MINUTE, enabled: true },
} as const satisfies Record<string, RateLimitPolicy>;

export type RateLimitPolicyKey = keyof typeof RATE_LIMIT_DEFAULTS;

export const RATE_LIMIT_KEYS = Object.keys(RATE_LIMIT_DEFAULTS) as RateLimitPolicyKey[];

export function isRateLimitPolicyKey(key: string): key is RateLimitPolicyKey {
  return key in RATE_LIMIT_DEFAULTS;
}

const SETTINGS_PREFIX = 'ratelimit.';
export const policySettingKey = (key: RateLimitPolicyKey): string => SETTINGS_PREFIX + key;

/**
 * Coerce an admin-supplied (or stored) policy to a safe value, falling back to
 * `fallback` for any field that fails validation. Bounds: max in [1, 1e6],
 * windowMs in [1s, 7d]. Rejects non-integers, NaN, Infinity. This is also the
 * validator the admin write path uses (an invalid edit can't persist a value the
 * resolver would just discard).
 */
export function sanitizePolicy(raw: unknown, fallback: RateLimitPolicy): RateLimitPolicy {
  if (!raw || typeof raw !== 'object') return fallback;
  const o = raw as Record<string, unknown>;
  const okMax =
    typeof o.max === 'number' && Number.isInteger(o.max) && o.max >= 1 && o.max <= 1_000_000;
  const okWin =
    typeof o.windowMs === 'number' &&
    Number.isInteger(o.windowMs) &&
    o.windowMs >= 1000 &&
    o.windowMs <= 7 * DAY;
  return {
    max: okMax ? (o.max as number) : fallback.max,
    windowMs: okWin ? (o.windowMs as number) : fallback.windowMs,
    enabled: typeof o.enabled === 'boolean' ? o.enabled : fallback.enabled,
  };
}

/** Resolve a policy: stored override (validated) or the compiled default. */
export async function resolvePolicy(
  db: DatabaseReader,
  key: RateLimitPolicyKey,
): Promise<RateLimitPolicy> {
  const fallback = RATE_LIMIT_DEFAULTS[key];
  const row = await db
    .query('appSettings')
    .withIndex('by_key', (q) => q.eq('key', policySettingKey(key)))
    .unique();
  if (!row) return fallback;
  try {
    return sanitizePolicy(JSON.parse(row.value), fallback);
  } catch {
    return fallback;
  }
}
