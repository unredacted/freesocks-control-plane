/**
 * Audit-log payload allowlist (M3). The audit table's `payload` is `v.any()`, so
 * a careless future caller could persist a raw request body, and admins with
 * `admin:audit:read` would then be able to read it (free-text, account numbers,
 * future PII). To make that impossible by construction rather than by review,
 * every audit write goes through `writeAuditLog`, which projects the payload
 * down to an explicit per-action key allowlist.
 *
 * Fail-closed: an action with no allowlist entry stores NO payload at all (a
 * one-time console.warn names the action so the author registers it here). The
 * action name is never secret, so logging it is safe. Curated, no-payload
 * actions (admin.login, transitions, etc.) are simply absent from the map; they
 * never pass a payload, so they never warn.
 *
 * Pure helpers live here so both write paths share them: the `audit.record`
 * mutation (called from actions) and the in-mutation direct inserts (lifecycle /
 * freeTier / adminApi, which cannot `ctx.runMutation` another mutation).
 */
import type { MutationCtx } from '../_generated/server';

export type AuditActorType = 'system' | 'admin' | 'member' | 'anonymous' | 'webhook';

export interface AuditEntry {
  actorType: AuditActorType;
  action: string;
  actorId?: string;
  targetType?: string;
  targetId?: string;
  payload?: unknown;
  requestId?: string;
}

/**
 * The only payloads any audit write is allowed to persist, keyed by action.
 * Add an entry (with the exact, curated key set) when a new action needs to
 * record structured context. Keys absent here are dropped before insert; an
 * action absent here drops its payload entirely. Keep these to non-secret,
 * scalar context: never an account number, token, secret, or apiUrl.
 */
export const AUDIT_PAYLOAD_ALLOWLIST: Readonly<Record<string, readonly string[]>> = {
  'subscription.switch_backend': ['fromBackend', 'toBackend', 'fromTier', 'toTier'],
  // Member switches connection mode (transport) within a backend. `inPlace` marks
  // an in-place squad re-point (existing key kept) vs a re-issue fallback.
  'subscription.switch_mode': ['fromMode', 'toMode', 'inPlace'],
  // Member revokes one HWID device (truncated identifier only, never the full hwid).
  'subscription.device_revoke': ['hwidPrefix'],
  // A key was issued with no placement (no Remnawave pool bound anywhere) — a
  // bring-up misconfiguration signal. `requestedMode` is a non-secret mode id.
  'subscription.issued_without_placement': ['requestedMode'],
  // Issuance-saga compensation couldn't delete the freshly-minted backend user
  // (bounded retries exhausted): an ORPHAN proxy account exists panel-side with
  // no local row. The operator's manual cleanup queue. backendUserId is the
  // panel-side account id (non-secret; needed to find + delete the orphan).
  'subscription.compensation_failed': ['backend', 'backendUserId'],
  // The post-issuance tombstone of a superseded key failed past the bounded
  // retry — TWO live keys exist until an operator deletes the old one.
  'subscription.tombstone_failed': ['backendUserId'],
  // A tombstoned sub exhausted its sweep backoff (permanently-dead backend):
  // the local row was marked deleted so the sweep moves on, but the backend
  // key may still exist — the operator's manual cleanup queue.
  'subscription.tombstone_abandoned': ['backend', 'backendUserId', 'attempts'],
  // The donation fleet re-cap finished INCOMPLETE (a panel was down mid-run or
  // the page cap hit): the applied marker was deliberately NOT set, so the next
  // hourly run re-pushes. Surfaced because the start-of-run heartbeat alone
  // would make the cron look healthy.
  'donation.bonus_partial': ['effective', 'failedChunks', 'exhausted'],
  'membership.tier_change': ['fromTierId', 'toTierId', 'reason'],
  'user.create.free': ['ipCountry', 'asn'],
  // W2: admin retunes a rate-limit policy.
  'settings.ratelimit_change': ['policyKey', 'max', 'windowMs', 'enabled'],
  // E2EE verification channels (non-secret URLs + the show/hide toggle).
  'admin.verification.change': [
    'showPanel',
    'releaseUrl',
    'onionAddress',
    'sourceUrl',
    'extensionUrl',
  ],
  // Site chrome: the announcement banner (toggle + text) + footer repo link
  // (toggle + https URL). All non-secret, operator-typed presentation values.
  'admin.site.change': [
    'bannerEnabled',
    'bannerText',
    'repoEnabled',
    'repoUrl',
    'tosUrl',
    'privacyUrl',
    'supportEmail',
    'heroTitle',
    'heroSubtitle',
    'heroTitles',
  ],
  // Member opt-in passkeys: enroll / revoke (device label is a non-secret display
  // string; the credential id / public key are never logged). Login is audited as
  // `account.login.passkey` with NO payload (like `account.login.account_id`).
  'account.passkey.register': ['deviceLabel'],
  'account.passkey.revoke': ['deviceLabel'],
  // W4: admin mints / revokes membership codes (never the code/hash itself).
  'membership_code.mint': ['count', 'tierId', 'durationDays'],
  'membership_code.revoke': ['codeId'],
  'membership_code.redeem': ['tierId', 'durationDays'],
  // Billing: self-service membership purchases + donations (never payer PII).
  'billing.checkout.created': ['processor', 'months', 'kind', 'quantity', 'donationCents'],
  'billing.order.paid': [
    'processor',
    'tierSlug',
    'durationDays',
    'amountCents',
    'kind',
    'quantity',
    'donationCents',
  ],
  'billing.config.update': ['key'],
  // Grant refused by the defense-in-depth cross-checks (amount/ref mismatch) —
  // amounts + verdicts only, never payer data.
  'billing.grant_refused': [
    'processor',
    'reason',
    'expectedMinor',
    'reportedMinor',
    'reportedCurrency',
    'refMatched',
  ],
  // Refund/reversal-class event seen for an ALREADY-PAID order: the operator's
  // chargeback action queue (membership is not auto-revoked).
  'billing.refund_seen': ['processor', 'amountCents', 'reportedMinor'],
  // A second paid event with a different payment id for an already-paid order:
  // the buyer paid twice on one invoice. The operator's refund-review queue.
  'billing.overpayment_seen': ['processor', 'amountCents', 'reportedMinor'],
  // A paid-class webhook for an INCOMPLETELY-paid invoice (merchant settle-
  // tolerance): the grant was refused by downgrade, so this is the operator's
  // follow-up queue (refund or request a top-up).
  'billing.underpayment_seen': ['processor', 'expectedMinor', 'reportedMinor'],
  // A webhook claim whose grant threw (retryable only until the sender gives
  // up) — surfaced on the admin billing page as money-at-risk.
  'billing.webhook.grant_failed': ['source'],
  // Multi-admin onboarding: invite minted / redeemed (username is a non-secret
  // admin label, never the invite token).
  'admin.invite.created': ['username'],
  'admin.invite.redeemed': ['username'],
  // Automation-token mint (bootstrap via `convex run`); never the token/secret.
  'admin.automation_token.mint': ['name', 'scopeCount'],
  // Human-admin API-token mint / revoke from the CMS; never the token/secret.
  'admin.token.mint': ['name', 'scopeCount', 'subjectType'],
  'admin.token.revoke': ['name'],
  // Admin tier lifecycle from the CMS (the by-slug IaC path audits separately).
  'admin.tier.create': ['slug', 'backend'],
  'admin.tier.update': ['slug'],
  'admin.tier.delete': ['slug'],
  // PATCH /admin/settings flipped a key (e.g. devices.enforcementEnabled) —
  // the key NAME only, never the value (some values are secret-adjacent).
  'admin.settings.change': ['key'],
  // By-id backend-server CRUD from the CMS (the by-slug IaC path audits
  // separately); never the config secret / apiUrl.
  'admin.backend_server.create': ['slug', 'backend'],
  'admin.backend_server.update': ['slug'],
  // Mirror-provider CRUD (repointing endpoint/bucket/publicUrl silently
  // redirects member subscription mirrors — must be traceable). Name only.
  'admin.mirror_provider.create': ['name'],
  'admin.mirror_provider.update': ['name'],
  'admin.mirror_provider.delete': ['name'],
  'admin.mirror_provider.upsert': ['name', 'created'],
  // Idempotent backend-server upsert by slug (Ansible / IaC); never the config secret.
  'admin.backend_server.upsert': ['slug', 'backend', 'created'],
  // Slug-addressed backend-server delete (migrate / IaC).
  'admin.backend_server.delete': ['slug'],
  // Admin grant/extend of a membership from the Users page.
  'admin.user.grant_membership': ['tierId', 'durationDays'],
  // Idempotent tier upsert by slug (Ansible / IaC). Node placement is bound
  // separately per connection mode (admin.remnawave.mode_placement.update).
  'admin.tier.upsert': ['slug', 'backend', 'created'],
  // Admin/IaC edits a connection-mode label/description/default (generic).
  'admin.connection_mode.update': ['key'],
  // Admin/IaC binds a mode's Remnawave placement pool. `poolBound` is a boolean —
  // the squad UUIDs are NEVER logged (only which mode's pool + whether it's set).
  'admin.remnawave.mode_placement.update': ['key', 'poolBound'],
  // Admin enforced the no-client-IP-logging posture on the Remnawave config
  // profiles (Xray log/policy). Counts only — no config content is logged.
  'admin.remnawave.logging_hardened': ['instances', 'profilesChanged', 'profilesTotal'],
  // Admin changes the brand theme (preset + optional hue override).
  'admin.theme.change': ['preset', 'hue'],
  // W3-8: admin lifecycle — deactivate/reactivate an admin, revoke a passkey
  // (username + device label are non-secret display strings).
  'admin.admin.deactivate': ['username'],
  'admin.admin.reactivate': ['username'],
  'admin.passkey.revoke': ['deviceLabel'],
};

/**
 * Project an audit payload to its action's allowlisted keys. Returns `undefined`
 * (store nothing) when there is no payload, the payload is not a plain object,
 * or the action is unregistered. Shallow by design: allowlisted values are
 * curated scalars, so there is no nested structure to recurse into.
 */
export function sanitizeAuditPayload(
  action: string,
  payload: unknown,
): Record<string, unknown> | undefined {
  if (payload === undefined || payload === null) return undefined;
  if (typeof payload !== 'object' || Array.isArray(payload)) {
    console.warn(`[audit] dropping non-object payload for action "${action}"`);
    return undefined;
  }
  const allow = AUDIT_PAYLOAD_ALLOWLIST[action];
  if (!allow) {
    console.warn(`[audit] dropping payload for unregistered action "${action}"`);
    return undefined;
  }
  const src = payload as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of allow) {
    if (key in src && src[key] !== undefined) out[key] = src[key];
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

/**
 * The single blessed way to write the audit log: sanitizes the payload, then
 * inserts. Never `ctx.db.insert('auditLog', ...)` directly, or the allowlist is
 * bypassed.
 */
export async function writeAuditLog(ctx: MutationCtx, entry: AuditEntry): Promise<void> {
  const { payload, ...rest } = entry;
  await ctx.db.insert('auditLog', {
    ...rest,
    payload: sanitizeAuditPayload(entry.action, payload),
  });
}
