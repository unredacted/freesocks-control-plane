import { sql } from 'drizzle-orm';
import { blob, index, integer, sqliteTable, text, uniqueIndex } from 'drizzle-orm/sqlite-core';

const timestamps = {
  createdAt: integer('created_at')
    .notNull()
    .default(sql`(unixepoch() * 1000)`),
  updatedAt: integer('updated_at')
    .notNull()
    .default(sql`(unixepoch() * 1000)`),
};

export const tiers = sqliteTable(
  'tiers',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    slug: text('slug').notNull().unique(),
    name: text('name').notNull(),
    description: text('description'),
    monthlyTrafficGb: integer('monthly_traffic_gb').notNull().default(0),
    deviceLimit: integer('device_limit').notNull().default(1),
    hwidLimit: integer('hwid_limit').notNull().default(1),
    hwidEnabled: integer('hwid_enabled', { mode: 'boolean' }).notNull().default(true),
    trafficStrategy: text('traffic_strategy', {
      enum: ['NO_RESET', 'DAY', 'WEEK', 'MONTH'],
    })
      .notNull()
      .default('MONTH'),
    /** Backend a key issued from this tier lives in. */
    backend: text('backend', { enum: ['remnawave', 'outline'] })
      .notNull()
      .default('remnawave'),
    remnawaveSquadUuid: text('remnawave_squad_uuid'),
    isDefaultFree: integer('is_default_free', { mode: 'boolean' }).notNull().default(false),
    isActive: integer('is_active', { mode: 'boolean' }).notNull().default(true),
    priority: integer('priority').notNull().default(0),
    expirationDaysAfterMembershipLapse: integer('expiration_days_after_membership_lapse')
      .notNull()
      .default(7),
    ...timestamps,
  },
  (t) => ({
    activeIdx: index('idx_tiers_active').on(t.isActive),
  }),
);

export const users = sqliteTable(
  'users',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    authentikSubject: text('authentik_subject').unique(),
    email: text('email'),
    emailVerifiedAt: integer('email_verified_at'),
    tierId: integer('tier_id')
      .notNull()
      .references(() => tiers.id),
    currentSubscriptionId: integer('current_subscription_id'),
    status: text('status', { enum: ['active', 'grace', 'disabled', 'deleted'] })
      .notNull()
      .default('active'),
    disabledReason: text('disabled_reason'),
    membershipExpiresAt: integer('membership_expires_at'),
    suspendedAt: integer('suspended_at'),
    /**
     * Self-service account-number auth (see docs/account-number-design.md). We
     * store only a SHA-256 hash of the canonical 16-digit number plus a 4-digit
     * plaintext prefix (for admin search); the plaintext is shown exactly once
     * at issuance and never persisted. Nullable: existing/JWT-provisioned rows
     * may not have one. `rotatedAt` is set when a number is reminted.
     */
    accountIdHash: text('account_id_hash'),
    accountIdPrefix: text('account_id_prefix'),
    accountIdCreatedAt: integer('account_id_created_at'),
    accountIdRotatedAt: integer('account_id_rotated_at'),
    ...timestamps,
  },
  (t) => ({
    statusIdx: index('idx_users_status').on(t.status),
    tierIdx: index('idx_users_tier').on(t.tierId),
    expiresIdx: index('idx_users_membership_expires')
      .on(t.membershipExpiresAt)
      .where(sql`status IN ('active', 'grace')`),
    accountIdHashIdx: uniqueIndex('idx_users_account_id_hash')
      .on(t.accountIdHash)
      .where(sql`account_id_hash IS NOT NULL`),
    accountIdPrefixIdx: index('idx_users_account_id_prefix')
      .on(t.accountIdPrefix)
      .where(sql`account_id_prefix IS NOT NULL`),
  }),
);

export const subscriptions = sqliteTable(
  'subscriptions',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    userId: integer('user_id')
      .notNull()
      .references(() => users.id),
    /**
     * Which backend this subscription lives in. Drives BackendRegistry
     * dispatch for getUser/updateUser/deleteUser and the
     * fetch-subscription-content call.
     */
    backend: text('backend', { enum: ['remnawave', 'outline'] })
      .notNull()
      .default('remnawave'),
    /**
     * Backend's primary user identifier. For Remnawave this is the user
     * UUID; for Outline this is the numeric access-key id. The column was
     * renamed from `remnawave_user_uuid` in migration 0004; existing rows
     * keep their values.
     */
    backendUserId: text('backend_user_id').notNull().unique(),
    /**
     * Backend's short identifier used for subscription content lookup. For
     * Remnawave this is the shortUuid; for Outline this is reused as the
     * access-key id (Outline has no separate "short" form).
     */
    backendShortId: text('backend_short_id').notNull().unique(),
    /**
     * Outline server this subscription's key lives on. NULL for
     * Remnawave-backed rows. References `outline_servers.id`.
     */
    outlineServerId: integer('outline_server_id'),
    subscriptionUrl: text('subscription_url').notNull(),
    subscriptionMirrors: text('subscription_mirrors').notNull().default('[]'),
    rawContentHash: text('raw_content_hash'),
    state: text('state', { enum: ['active', 'disabled', 'deleted'] })
      .notNull()
      .default('active'),
    ...timestamps,
    deletedAt: integer('deleted_at'),
  },
  (t) => ({
    userIdx: index('idx_subscriptions_user').on(t.userId),
    stateIdx: index('idx_subscriptions_state').on(t.state),
  }),
);

export const tierHistory = sqliteTable(
  'tier_history',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    userId: integer('user_id')
      .notNull()
      .references(() => users.id),
    fromTierId: integer('from_tier_id').references(() => tiers.id),
    toTierId: integer('to_tier_id')
      .notNull()
      .references(() => tiers.id),
    reason: text('reason').notNull(),
    triggeredBy: text('triggered_by').notNull(),
    changedAt: integer('changed_at')
      .notNull()
      .default(sql`(unixepoch() * 1000)`),
  },
  (t) => ({
    userTimeIdx: index('idx_tier_history_user').on(t.userId, t.changedAt),
  }),
);

export const freeGrants = sqliteTable(
  'free_grants',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    userId: integer('user_id')
      .notNull()
      .references(() => users.id),
    ipHash: text('ip_hash').notNull(),
    ipCountry: text('ip_country'),
    asn: integer('asn'),
    tlsFingerprint: text('tls_fingerprint'),
    turnstileAction: text('turnstile_action'),
    turnstileCdata: text('turnstile_cdata'),
    userAgentHash: text('user_agent_hash'),
    grantedAt: integer('granted_at')
      .notNull()
      .default(sql`(unixepoch() * 1000)`),
    grantedDayBucket: integer('granted_day_bucket').notNull(),
    /**
     * Per-(ipHash, dayBucket) slot index, 0-based. Combined with the unique
     * index below this makes free-tier issuance an ATOMIC cap: a new grant
     * inserts with `slot = COUNT(existing grants for this ip+day)`, so two
     * racing requests compute the same slot and collide on the unique index —
     * exactly one wins. Closes the prior check-then-insert TOCTOU where
     * concurrent callers could each pass the count check and over-issue.
     */
    slot: integer('slot').notNull().default(0),
  },
  (t) => ({
    ipDayIdx: index('idx_free_grants_ip_day').on(t.ipHash, t.grantedDayBucket),
    grantedAtIdx: index('idx_free_grants_granted_at').on(t.grantedAt),
    ipDaySlotUnique: uniqueIndex('idx_free_grants_ip_day_slot').on(
      t.ipHash,
      t.grantedDayBucket,
      t.slot,
    ),
  }),
);

export const auditLog = sqliteTable(
  'audit_log',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    actorType: text('actor_type', {
      enum: ['system', 'admin', 'member', 'anonymous', 'webhook'],
    }).notNull(),
    actorId: text('actor_id'),
    action: text('action').notNull(),
    targetType: text('target_type'),
    targetId: text('target_id'),
    payload: text('payload'),
    requestId: text('request_id'),
    ipHash: text('ip_hash'),
    createdAt: integer('created_at')
      .notNull()
      .default(sql`(unixepoch() * 1000)`),
  },
  (t) => ({
    targetIdx: index('idx_audit_target').on(t.targetType, t.targetId, t.createdAt),
    actorIdx: index('idx_audit_actor').on(t.actorType, t.actorId, t.createdAt),
    actionIdx: index('idx_audit_action').on(t.action, t.createdAt),
  }),
);

export const adminUsers = sqliteTable('admin_users', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  username: text('username').notNull().unique(),
  displayName: text('display_name').notNull(),
  email: text('email'),
  isActive: integer('is_active', { mode: 'boolean' }).notNull().default(true),
  ...timestamps,
  lastLoginAt: integer('last_login_at'),
});

export const passkeyCredentials = sqliteTable(
  'passkey_credentials',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    adminUserId: integer('admin_user_id')
      .notNull()
      .references(() => adminUsers.id),
    credentialId: text('credential_id').notNull().unique(),
    publicKey: text('public_key').notNull(),
    counter: integer('counter').notNull().default(0),
    transports: text('transports'),
    deviceLabel: text('device_label'),
    aaguid: text('aaguid'),
    createdAt: integer('created_at')
      .notNull()
      .default(sql`(unixepoch() * 1000)`),
    lastUsedAt: integer('last_used_at'),
  },
  (t) => ({
    adminIdx: index('idx_passkey_admin').on(t.adminUserId),
  }),
);

export const webauthnRegistrationChallenges = sqliteTable(
  'webauthn_registration_challenges',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    adminUserId: integer('admin_user_id')
      .notNull()
      .references(() => adminUsers.id),
    challenge: text('challenge').notNull(),
    expiresAt: integer('expires_at').notNull(),
    consumedAt: integer('consumed_at'),
  },
  (t) => ({
    adminIdx: index('idx_webauthn_reg_admin').on(t.adminUserId, t.expiresAt),
  }),
);

export const emailLog = sqliteTable(
  'email_log',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    toEmail: text('to_email').notNull(),
    subject: text('subject').notNull(),
    templateKey: text('template_key').notNull(),
    params: text('params').notNull(),
    status: text('status', { enum: ['sent', 'failed', 'suppressed'] }).notNull(),
    providerMessageId: text('provider_message_id'),
    error: text('error'),
    dedupeKey: text('dedupe_key'),
    attemptedAt: integer('attempted_at')
      .notNull()
      .default(sql`(unixepoch() * 1000)`),
    sentAt: integer('sent_at'),
  },
  (t) => ({
    dedupeUnique: uniqueIndex('idx_email_dedupe')
      .on(t.dedupeKey)
      .where(sql`dedupe_key IS NOT NULL`),
    toEmailIdx: index('idx_email_to').on(t.toEmail, t.attemptedAt),
  }),
);

export const appState = sqliteTable('app_state', {
  key: text('key').primaryKey(),
  value: text('value').notNull(),
  updatedAt: integer('updated_at')
    .notNull()
    .default(sql`(unixepoch() * 1000)`),
});

export const webhookEvents = sqliteTable(
  'webhook_events',
  {
    id: text('id').primaryKey(),
    source: text('source').notNull(),
    receivedAt: integer('received_at')
      .notNull()
      .default(sql`(unixepoch() * 1000)`),
    processedAt: integer('processed_at'),
    payload: text('payload').notNull(),
  },
  (t) => ({
    sourceIdx: index('idx_webhook_events_source').on(t.source, t.receivedAt),
  }),
);

export const apiTokens = sqliteTable(
  'api_tokens',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    name: text('name').notNull(),
    tokenHash: text('token_hash').notNull().unique(),
    tokenPrefix: text('token_prefix').notNull(),
    createdByAdminId: integer('created_by_admin_id')
      .notNull()
      .references(() => adminUsers.id),
    scopes: text('scopes').notNull().default('[]'),
    subjectType: text('subject_type', { enum: ['service', 'user'] })
      .notNull()
      .default('service'),
    subjectUserId: integer('subject_user_id').references(() => users.id),
    expiresAt: integer('expires_at'),
    lastUsedAt: integer('last_used_at'),
    revokedAt: integer('revoked_at'),
    ...timestamps,
  },
  (t) => ({
    // Note: the column already has `.unique()`, which Drizzle materializes as
    // an automatically-generated `api_tokens_token_hash_unique` index. We do
    // NOT add a second `uniqueIndex('idx_api_tokens_hash')` here because that
    // duplicates the same constraint and forces SQLite to maintain two
    // identical b-trees for every insert.
    creatorIdx: index('idx_api_tokens_creator').on(t.createdByAdminId),
    activeIdx: index('idx_api_tokens_active').on(t.revokedAt, t.expiresAt),
  }),
);

/**
 * Outline Manager API endpoint registry. One row per Outline server the
 * system can issue keys against. `api_url` includes the secret path segment
 * from the Outline Manager API and is therefore sensitive — never log it,
 * redact it in audit payloads.
 */
export const outlineServers = sqliteTable(
  'outline_servers',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    name: text('name').notNull(),
    slug: text('slug').notNull().unique(),
    apiUrl: text('api_url').notNull(),
    websocketEnabled: integer('websocket_enabled', { mode: 'boolean' }).notNull().default(false),
    websocketDomain: text('websocket_domain'),
    prometheusUrl: text('prometheus_url'),
    isActive: integer('is_active', { mode: 'boolean' }).notNull().default(true),
    priority: integer('priority').notNull().default(0),
    lastHealthOkAt: integer('last_health_ok_at'),
    accessKeyCount: integer('access_key_count').notNull().default(0),
    ...timestamps,
  },
  (t) => ({
    activeIdx: index('idx_outline_servers_active').on(t.isActive, t.priority),
  }),
);

/**
 * Typed admin-editable global settings. Schema enforced by AppSettingsService
 * — see `services/app-settings.ts` for the Zod registry of supported keys.
 */
export const appSettings = sqliteTable('app_settings', {
  key: text('key').primaryKey(),
  value: text('value').notNull(),
  updatedAt: integer('updated_at')
    .notNull()
    .default(sql`(unixepoch() * 1000)`),
  updatedByAdminId: integer('updated_by_admin_id').references(() => adminUsers.id),
});

// SQLite-backed KV substitute for Node/Bun runtimes (ignored on Workers).
export const kvTable = sqliteTable(
  'kv_table',
  {
    namespace: text('namespace').notNull(),
    key: text('key').notNull(),
    value: blob('value', { mode: 'buffer' }),
    metadata: text('metadata'),
    expiresAt: integer('expires_at'),
    updatedAt: integer('updated_at')
      .notNull()
      .default(sql`(unixepoch() * 1000)`),
  },
  (t) => ({
    pk: uniqueIndex('idx_kv_table_pk').on(t.namespace, t.key),
    expiresIdx: index('idx_kv_table_expires').on(t.expiresAt),
  }),
);
