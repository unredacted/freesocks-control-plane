import { defineSchema, defineTable } from 'convex/server';
import { v } from 'convex/values';

/**
 * Convex schema for FreeSocks Control Plane: the migration target
 * (`.claude/plans/...`, phase P2). Ported from `src/server/db/schema.ts` with
 * Convex idioms:
 *
 *  - Integer PKs/FKs become `_id` / `v.id("table")`. No referential enforcement
 *    (Convex has none); code keeps the existing best-effort delete semantics.
 *  - `created_at` columns are dropped in favour of the built-in `_creationTime`;
 *    explicit timestamps are kept ONLY where they're indexed or mutated
 *    (updatedAt, membershipExpiresAt, grantedAt, expiresAt, …).
 *  - There are NO UNIQUE constraints in Convex. Uniqueness (slug, tokenHash,
 *    accountIdHash, backendUserId, …) is enforced inside transactional mutations
 *    via a by-field index read-check (serializable OCC makes it race-free).
 *  - Partial indexes don't exist; the predicate moves into the query filter.
 *  - JSON-as-TEXT columns become nested validators (subscriptionMirrors, scopes).
 *  - Identity is the account-number system ONLY: no `authentik_subject` /
 *    `civicrm_contact_id`. `kv_table` is gone (KV → Convex tables); `sessions`
 *    and `rateLimits` replace the former KvStore namespaces.
 */

// Reusable enum validators (Drizzle text-enums → unions of literals).
const backendId = v.union(v.literal('remnawave'), v.literal('outline'));
const trafficStrategy = v.union(
  v.literal('NO_RESET'),
  v.literal('DAY'),
  v.literal('WEEK'),
  v.literal('MONTH'),
);
const userStatus = v.union(
  v.literal('active'),
  v.literal('grace'),
  v.literal('disabled'),
  v.literal('deleted'),
);
const subscriptionState = v.union(v.literal('active'), v.literal('disabled'), v.literal('deleted'));
const actorType = v.union(
  v.literal('system'),
  v.literal('admin'),
  v.literal('member'),
  v.literal('anonymous'),
  v.literal('webhook'),
);

// On-disk subscription-mirror entry (see src/server/lib/mirrors.ts).
const subscriptionMirror = v.object({
  provider: v.string(),
  publicUrl: v.string(),
  objectPath: v.optional(v.string()),
  status: v.optional(v.union(v.literal('ok'), v.literal('failed'))),
});

export default defineSchema({
  tiers: defineTable({
    slug: v.string(),
    name: v.string(),
    description: v.optional(v.string()),
    backend: backendId,
    monthlyTrafficGb: v.number(),
    deviceLimit: v.number(),
    hwidLimit: v.number(),
    hwidEnabled: v.boolean(),
    trafficStrategy,
    remnawaveSquadUuid: v.optional(v.string()),
    isDefaultFree: v.boolean(),
    isActive: v.boolean(),
    priority: v.number(),
    expirationDaysAfterMembershipLapse: v.number(),
    updatedAt: v.number(),
  })
    .index('by_slug', ['slug']) // uniqueness enforced in mutations
    .index('by_active', ['isActive']),

  users: defineTable({
    tierId: v.id('tiers'),
    currentSubscriptionId: v.optional(v.id('subscriptions')),
    status: userStatus,
    disabledReason: v.optional(v.string()),
    membershipExpiresAt: v.optional(v.number()),
    suspendedAt: v.optional(v.number()),
    // Account-number auth: store only a peppered keyed hash
    // (HMAC-SHA256(ACCOUNT_ID_PEPPER, number)) + a 4-digit plaintext prefix
    // (admin search). Uniqueness of the hash is enforced in mutations.
    accountIdHash: v.optional(v.string()),
    accountIdPrefix: v.optional(v.string()),
    accountIdCreatedAt: v.optional(v.number()),
    accountIdRotatedAt: v.optional(v.number()),
    updatedAt: v.number(),
  })
    .index('by_account_id_hash', ['accountIdHash'])
    .index('by_account_id_prefix', ['accountIdPrefix'])
    .index('by_status_expires', ['status', 'membershipExpiresAt'])
    .index('by_tier', ['tierId']),

  subscriptions: defineTable({
    userId: v.id('users'),
    backend: backendId,
    backendUserId: v.string(),
    backendShortId: v.string(),
    outlineServerId: v.optional(v.id('outlineServers')),
    subscriptionUrl: v.string(),
    subscriptionMirrors: v.array(subscriptionMirror),
    rawContentHash: v.optional(v.string()),
    state: subscriptionState,
    updatedAt: v.number(),
    deletedAt: v.optional(v.number()),
  })
    .index('by_user', ['userId'])
    .index('by_state', ['state'])
    .index('by_backend_user_id', ['backendUserId'])
    .index('by_backend_short_id', ['backendShortId']),

  tierHistory: defineTable({
    userId: v.id('users'),
    fromTierId: v.optional(v.id('tiers')),
    toTierId: v.id('tiers'),
    reason: v.string(),
    triggeredBy: v.string(),
  }).index('by_user', ['userId']),

  freeGrants: defineTable({
    userId: v.id('users'),
    ipHash: v.string(),
    ipCountry: v.optional(v.string()),
    asn: v.optional(v.number()),
    tlsFingerprint: v.optional(v.string()),
    turnstileAction: v.optional(v.string()),
    turnstileCdata: v.optional(v.string()),
    userAgentHash: v.optional(v.string()),
    grantedAt: v.number(),
    grantedDayBucket: v.number(),
    // NOTE: the old `slot` column + composite UNIQUE index are intentionally
    // gone. The free-tier cap is now enforced by a serializable mutation
    // (read count over by_ip_day, then insert); see migration plan §2.
  })
    .index('by_ip_day', ['ipHash', 'grantedDayBucket'])
    .index('by_granted_at', ['grantedAt']),

  auditLog: defineTable({
    actorType,
    actorId: v.optional(v.string()),
    action: v.string(),
    targetType: v.optional(v.string()),
    targetId: v.optional(v.string()),
    payload: v.optional(v.any()),
    requestId: v.optional(v.string()),
    ipHash: v.optional(v.string()),
  })
    .index('by_target', ['targetType', 'targetId'])
    .index('by_actor', ['actorType', 'actorId'])
    .index('by_action', ['action']),

  adminUsers: defineTable({
    username: v.string(),
    displayName: v.string(),
    isActive: v.boolean(),
    updatedAt: v.number(),
    lastLoginAt: v.optional(v.number()),
  }).index('by_username', ['username']),

  passkeyCredentials: defineTable({
    adminUserId: v.id('adminUsers'),
    credentialId: v.string(),
    publicKey: v.string(),
    counter: v.number(),
    transports: v.optional(v.string()),
    deviceLabel: v.optional(v.string()),
    aaguid: v.optional(v.string()),
    lastUsedAt: v.optional(v.number()),
  })
    .index('by_admin', ['adminUserId'])
    .index('by_credential_id', ['credentialId']),

  webauthnRegistrationChallenges: defineTable({
    adminUserId: v.id('adminUsers'),
    challenge: v.string(),
    expiresAt: v.number(),
    consumedAt: v.optional(v.number()),
  }).index('by_admin_expires', ['adminUserId', 'expiresAt']),

  // Short-lived passkey ASSERTION challenges (was the `webauthn:assert:<id>` KV
  // entry). Keyed by an opaque challengeId; `adminUserId` is absent for the
  // unknown/inactive-user sentinel so verify fails like any wrong passkey
  // without revealing whether the username existed. Daily-swept by expiresAt.
  webauthnAuthChallenges: defineTable({
    challengeId: v.string(),
    challenge: v.string(),
    adminUserId: v.optional(v.id('adminUsers')),
    expiresAt: v.number(),
    consumedAt: v.optional(v.number()),
  })
    .index('by_challenge_id', ['challengeId'])
    .index('by_expires', ['expiresAt']),

  // Accounts are anonymous by design: no contact details are ever collected,
  // and the control plane sends no notifications.

  // Generic singleton key/value state (e.g. tier-propagation cursors).
  appState: defineTable({
    key: v.string(),
    value: v.string(),
    updatedAt: v.number(),
  }).index('by_key', ['key']),

  webhookEvents: defineTable({
    // `eventId` is the dedupe hash (was the string PK in SQLite). Convex PKs
    // are opaque `_id`s, so dedupe is via this indexed field.
    eventId: v.string(),
    source: v.string(),
    payload: v.string(),
    processedAt: v.optional(v.number()),
  })
    .index('by_event_id', ['eventId'])
    .index('by_source', ['source']),

  apiTokens: defineTable({
    name: v.string(),
    tokenHash: v.string(),
    tokenPrefix: v.string(),
    createdByAdminId: v.id('adminUsers'),
    scopes: v.array(v.string()),
    subjectType: v.union(v.literal('service'), v.literal('user')),
    subjectUserId: v.optional(v.id('users')),
    expiresAt: v.optional(v.number()),
    lastUsedAt: v.optional(v.number()),
    revokedAt: v.optional(v.number()),
    updatedAt: v.number(),
  })
    .index('by_token_hash', ['tokenHash'])
    .index('by_creator', ['createdByAdminId'])
    .index('by_active', ['revokedAt', 'expiresAt']),

  outlineServers: defineTable({
    name: v.string(),
    slug: v.string(),
    apiUrl: v.string(),
    websocketEnabled: v.boolean(),
    websocketDomain: v.optional(v.string()),
    prometheusUrl: v.optional(v.string()),
    isActive: v.boolean(),
    priority: v.number(),
    lastHealthOkAt: v.optional(v.number()),
    accessKeyCount: v.number(),
    updatedAt: v.number(),
  })
    .index('by_slug', ['slug'])
    .index('by_active_priority', ['isActive', 'priority']),

  appSettings: defineTable({
    key: v.string(),
    value: v.string(),
    updatedByAdminId: v.optional(v.id('adminUsers')),
    updatedAt: v.number(),
  }).index('by_key', ['key']),

  // --- new tables replacing the former KvStore namespaces ---

  // Member + admin sessions (was the `sessions` KV namespace + signed cookie).
  //
  // Proof-of-possession (CDN-blinding Phase 2): a session MAY be bound to an
  // asymmetric PoP key minted client-side at login. `popPublicKey` is the raw
  // uncompressed P-256 point (65 bytes, base64url) the client posted; the
  // private half is a non-extractable CryptoKey the browser holds and the CDN
  // never sees. Once a session carries `popPublicKey`, the signed cookie alone
  // is NOT sufficient: each request must also carry a fresh signature over its
  // canonical form (see convex/lib/pop.ts + the re-bind rule in lib/http.ts).
  // Sessions minted before Phase 2 leave these unset and authenticate by cookie
  // only until POP_REQUIRED is enabled.
  sessions: defineTable({
    sid: v.string(),
    kind: v.union(v.literal('member'), v.literal('admin')),
    userId: v.optional(v.id('users')),
    adminUserId: v.optional(v.id('adminUsers')),
    expiresAt: v.number(),
    popPublicKey: v.optional(v.string()),
    popAlg: v.optional(v.string()),
    popBoundAt: v.optional(v.number()),
  })
    .index('by_sid', ['sid'])
    .index('by_expires', ['expiresAt']),

  // Short-lived HPKE epoch KEM keys (CDN-blinding Phase 3). The login request
  // seals to the CURRENT epoch key instead of the multi-day static key, so the
  // request-direction retroactive-exposure window shrinks from days to the epoch
  // validity (tens of minutes). `seed` is the random 32-byte X-Wing seed (a
  // SECRET); it is generated fresh per epoch and DESTROYED by the sweep once the
  // epoch expires, which is what gives forward secrecy (a later key compromise
  // cannot recover a swept epoch's logins). NEVER log `seed`. `manifestSig` is
  // the Ed25519 manifest signature over the epoch statement, so the client can
  // verify the epoch public key it is handed via the CDN-fronted /config.
  keyEpochs: defineTable({
    kid: v.string(),
    publicKey: v.string(),
    seed: v.string(),
    manifestSig: v.string(),
    // Phase 4: the ML-DSA-65 half of the hybrid manifest signature (Ed25519 is
    // `manifestSig`). Optional so a deployment without FS_MANIFEST_SK_PQ still
    // mints epoch keys (Ed25519-only).
    manifestSigPq: v.optional(v.string()),
    notBefore: v.number(),
    notAfter: v.number(),
  })
    .index('by_kid', ['kid'])
    .index('by_not_before', ['notBefore'])
    .index('by_expires', ['notAfter']),

  // Manifest-signed revoked-kid list (CDN-blinding Phase 3c). A break-glass
  // mechanism: an operator runs e2eeCrypto.signRevocation to publish a new
  // version listing compromised kids (static or epoch). `version` is monotonic;
  // the client persists the last-seen version and REJECTS an older one (a CDN
  // cannot roll back to un-revoke a kid). Each row is a full snapshot at its
  // version; the current row is the max version.
  keyRevocations: defineTable({
    version: v.number(),
    revokedKids: v.array(v.string()),
    notAfter: v.number(),
    manifestSig: v.string(),
    manifestSigPq: v.optional(v.string()),
  }).index('by_version', ['version']),

  // Single-use PoP request nonces (CDN-blinding Phase 2). Each authenticated,
  // PoP-signed request carries a 16-byte nonce; `consumeNonce` inserts
  // (sid, nonceHash) exactly once via a serializable mutation, so a passive CDN
  // that captured a request cannot replay it inside its freshness window. Rows
  // are keyed by the per-session sid + a SHA-256 hash of the nonce (the raw
  // nonce is never stored) and swept daily by `expiresAt`. Kept separate from
  // the rateLimits table (different lifetime, different access pattern).
  replayGuard: defineTable({
    sid: v.string(),
    nonceHash: v.string(),
    expiresAt: v.number(),
  })
    .index('by_sid_nonce', ['sid', 'nonceHash'])
    .index('by_expires', ['expiresAt']),

  // Anti-abuse counters (was the `rateLimit` KV namespace). The `bucket` key
  // encodes the subject + window (e.g. "account-login:ip:<hash>:<hour>"); a
  // daily cron sweeps rows past `expiresAt`. The strict free-tier cap lives in
  // the issuance mutation, not here.
  rateLimits: defineTable({
    bucket: v.string(),
    count: v.number(),
    expiresAt: v.number(),
  })
    .index('by_bucket', ['bucket'])
    .index('by_expires', ['expiresAt']),
});
