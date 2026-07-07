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

// The set of proxy-backend TYPES. Keep these literals in sync with BACKEND_IDS
// in src/shared/contracts/backends.ts (the client-side source of truth): adding
// a backend type means a literal here + a config variant in backendServerConfig.
const backendId = v.union(v.literal('remnawave'), v.literal('outline'));

// Per-instance backend config: the secret-bearing connection details for one
// deployed server. A discriminated union keyed by backend type (`type` matches
// the row's `backend`). NEVER returned to the SPA (admin responses mask it).
const backendServerConfig = v.union(
  v.object({
    type: v.literal('remnawave'),
    baseUrl: v.string(),
    apiToken: v.string(),
  }),
  v.object({
    type: v.literal('outline'),
    // The Outline Manager URL embeds a secret path segment.
    apiUrl: v.string(),
    websocketEnabled: v.boolean(),
    websocketDomain: v.optional(v.string()),
    prometheusUrl: v.optional(v.string()),
  }),
);
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

// Self-service membership payment processors (hosted-redirect rails). Keep in
// sync with the PaymentProcessor adapters in convex/lib/processors/.
const billingProcessor = v.union(
  v.literal('nowpayments'),
  v.literal('stripe'),
  v.literal('paypal'),
);
// Order lifecycle. `confirming` is the crypto mempool/confirmation wait (a
// non-terminal state the SPA keeps polling). Only `paid` grants membership.
const billingOrderStatus = v.union(
  v.literal('pending'),
  v.literal('confirming'),
  v.literal('paid'),
  v.literal('failed'),
  v.literal('expired'),
);

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
    // Cross-backend peer (D-1): the equivalent tier on the OTHER backend, so a
    // member on this tier can switch backends (account.switchBackend). Optional;
    // free tiers auto-resolve their peer via the per-backend default-free row and
    // need no explicit link. Resolved (incl. a reverse lookup) in convex/tiers.ts
    // getPeerTier; set by an admin in the tier editor.
    peerTierId: v.optional(v.id('tiers')),
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
    // W3: a non-secret `FS-XXXX-XXXX` support handle (NOT a credential). Minted
    // at account creation, lazily backfilled for pre-W3 users. Unique (enforced
    // in the mutation). See convex/lib/supportId.ts.
    supportId: v.optional(v.string()),
    // Set when a backend push (tier propagation, or an enable/disable) fails and
    // hasn't since succeeded; cleared on the next successful push. Surfaced as the
    // admin "backend drift" signal so otherwise-silent entitlement drift (a paid
    // upgrade that never reached the panel, a disable the key ignored) is visible.
    backendPushFailedAt: v.optional(v.number()),
    // Member-chosen connection profile (transport → Remnawave squad), orthogonal
    // to the entitlement tier: the tier sets limits, this selects which squad the
    // key issues into. Unset → the catalog default (see lib/connectionProfiles.ts).
    // Additive/optional; legacy rows + new free signups default cleanly.
    connectionProfileId: v.optional(v.union(v.literal('evade'), v.literal('privacy'))),
    updatedAt: v.number(),
  })
    .index('by_account_id_hash', ['accountIdHash'])
    .index('by_account_id_prefix', ['accountIdPrefix'])
    .index('by_support_id', ['supportId'])
    .index('by_status_expires', ['status', 'membershipExpiresAt'])
    .index('by_tier', ['tierId']),

  subscriptions: defineTable({
    userId: v.id('users'),
    backend: backendId,
    backendUserId: v.string(),
    backendShortId: v.string(),
    backendServerId: v.optional(v.id('backendServers')),
    subscriptionUrl: v.string(),
    subscriptionMirrors: v.array(subscriptionMirror),
    rawContentHash: v.optional(v.string()),
    // Opaque per-subscription capability token for the FCP-fronted subscription
    // URL (GET /api/v1/sub/<subToken>): the member's proxy app fetches its config
    // from THIS origin instead of the backend panel. Rotates per key by
    // construction (a new sub row = a new token). Minted in insertSubscription.
    subToken: v.optional(v.string()),
    // Small in-front content cache for the fronted route — a JSON blob holding a
    // BOUNDED per-UA list of {content, contentType, headers?, ua, at} entries (see
    // convex/http.ts + subscriptions.writeContentCache). Bounded (no growth),
    // dropped with the row, keyed by UA so multiple clients (phone + desktop)
    // don't thrash and we never serve one client's format to another — on both the
    // fresh-hit and stale-fallback paths. Never logged.
    subCache: v.optional(v.string()),
    state: subscriptionState,
    updatedAt: v.number(),
    deletedAt: v.optional(v.number()),
  })
    .index('by_user', ['userId'])
    // (userId, state): the active-subscription resolvers hit this directly
    // instead of collecting every historical row for the user (tombstones
    // accrue with each regenerate/switch and, for paid users, otherwise
    // accumulate forever — see retention.sweepDeletedSubscriptions).
    .index('by_user_state', ['userId', 'state'])
    // (state, deletedAt): the tombstone sweep prefix-queries state; the
    // deleted-row retention sweep range-queries deletedAt under it.
    .index('by_state', ['state', 'deletedAt'])
    .index('by_backend_user_id', ['backendUserId'])
    .index('by_backend_short_id', ['backendShortId'])
    // The FCP-fronted subscription route resolves the sub by its opaque token.
    .index('by_sub_token', ['subToken']),

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
  })
    .index('by_admin_expires', ['adminUserId', 'expiresAt'])
    .index('by_expires', ['expiresAt']),

  // Single-use, short-lived admin INVITE tokens (multi-admin onboarding). An
  // existing admin mints one for a pre-created (credential-less) adminUsers row;
  // the invitee opens the link on their own device and registers a passkey,
  // which consumes the invite. Stored HASHED (never the raw token), like
  // apiTokens; `tokenPrefix` is the non-secret first chars for display/audit.
  adminInvites: defineTable({
    adminUserId: v.id('adminUsers'),
    tokenHash: v.string(),
    tokenPrefix: v.string(),
    createdByAdminId: v.id('adminUsers'),
    expiresAt: v.number(),
    consumedAt: v.optional(v.number()),
    updatedAt: v.number(),
  })
    .index('by_token_hash', ['tokenHash'])
    .index('by_admin', ['adminUserId'])
    .index('by_expires', ['expiresAt']),

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

  // Per-cron liveness heartbeats (one row per scheduled job, keyed by cron name).
  // Every target in convex/crons.ts stamps this at the START of its run, so
  // freshness reflects that the SCHEDULER is firing the job — deliberately
  // decoupled from whether the job's work succeeds (backend health / drift are
  // surfaced separately). statusSummary joins these against the known cadences
  // (cronHeartbeat.CRON_META) to flag any job that has gone stale. Fixed
  // cardinality (~one row per cron), upserted in place, so it never grows.
  cronHeartbeats: defineTable({
    name: v.string(),
    lastRunAt: v.number(),
    runCount: v.number(),
  }).index('by_name', ['name']),

  webhookEvents: defineTable({
    // `eventId` is the dedupe hash (was the string PK in SQLite). Convex PKs
    // are opaque `_id`s, so dedupe is via this indexed field.
    eventId: v.string(),
    source: v.string(),
    payload: v.string(),
    processedAt: v.optional(v.number()),
    // Dedupe-claim lifecycle: 'pending' = claimed, grant not yet confirmed;
    // 'processed' = grant applied exactly once (terminal — replays no-op);
    // 'failed' = grant threw, safe to re-apply on the sender's retry. Absent
    // (legacy rows) is treated as terminal so historical events never re-grant.
    status: v.optional(v.union(v.literal('pending'), v.literal('processed'), v.literal('failed'))),
  })
    .index('by_event_id', ['eventId'])
    .index('by_source', ['source']),

  // Self-service membership purchases: one row per checkout. The member's
  // `userId` is bound HERE, server-side — it is NEVER sent to the processor as
  // identity; the processor only ever sees the unguessable `opaqueRef` (used as
  // its `order_id` and in the return URL). A confirmed-payment webhook flips
  // status→paid EXACTLY ONCE (billing.markOrderPaidAndGrant) and extends
  // membership. NO payer PII is stored (no email/name/address) — only the ref,
  // amount, tier, duration, and status. `by_status` (Convex appends
  // `_creationTime`) drives the stale-pending sweep.
  billingOrders: defineTable({
    processor: billingProcessor,
    opaqueRef: v.string(),
    processorRef: v.optional(v.string()),
    userId: v.id('users'),
    tierId: v.id('tiers'),
    durationDays: v.number(),
    amountCents: v.number(),
    currency: v.string(),
    status: billingOrderStatus,
    paidAt: v.optional(v.number()),
    // Gift purchases: a 'gift' order mints `quantity` shareable codes (bound to
    // the buyer via redemptionCodes.purchasedByOrderId) instead of extending the
    // buyer's own membership. Absent ⇒ legacy self-upgrade. `giftReveal` is the
    // TRANSIENT plaintext buffer returned to the buyer ONCE on the return poll,
    // then cleared on ack (or by the gift-reveal sweep) — the codes live
    // hash-only in redemptionCodes; durable storage is never plaintext.
    kind: v.optional(v.union(v.literal('self'), v.literal('gift'))),
    quantity: v.optional(v.number()),
    giftReveal: v.optional(v.array(v.string())),
    giftRevealAck: v.optional(v.boolean()),
    // True while a paid gift order still holds an unacked plaintext reveal; unset
    // on ack or by the gift-reveal sweep. A dedicated flag + index so the sweep
    // scans ONLY pending reveals (oldest-first via the appended _creationTime),
    // never the whole paid-orders table — which starved it once paid self-orders
    // outnumbered the page window. (Review #5.)
    giftRevealPending: v.optional(v.boolean()),
    updatedAt: v.number(),
  })
    .index('by_opaque_ref', ['opaqueRef'])
    .index('by_processor_ref', ['processor', 'processorRef'])
    .index('by_user', ['userId'])
    .index('by_status', ['status'])
    .index('by_gift_reveal_pending', ['giftRevealPending']),

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

  // Backend instances: one row per deployed proxy server of any backend type
  // (Remnawave, Outline, ...). Generalizes the former `outlineServers` table so
  // adding a backend type needs no new table. `config` holds the per-type
  // connection secret (never returned to the SPA). `keyCount` + `lastHealthRttMs`
  // feed pool selection at issuance; `lastHealthOkAt` is stamped by the
  // healthcheck cron. Uniqueness of `slug` is enforced in the mutation.
  backendServers: defineTable({
    backend: backendId,
    name: v.string(),
    slug: v.string(),
    config: backendServerConfig,
    isActive: v.boolean(),
    priority: v.number(),
    lastHealthOkAt: v.optional(v.number()),
    lastHealthRttMs: v.optional(v.number()),
    keyCount: v.number(),
    // Read-only fleet observability, cached by the backend-healthcheck cron so the
    // admin dashboard never makes a live panel call. Best-effort: absent until the
    // first successful fetch, and left as-is (not cleared) on a later failure.
    fleetStats: v.optional(
      v.object({
        onlineNow: v.number(),
        nodesOnline: v.number(),
        nodesTotal: v.number(),
        distinctCountries: v.number(),
        monthTrafficBytes: v.number(),
        lifetimeTrafficBytes: v.number(),
        panelVersion: v.string(),
      }),
    ),
    fleetStatsAt: v.optional(v.number()),
    updatedAt: v.number(),
  })
    .index('by_slug', ['slug'])
    .index('by_backend_active', ['backend', 'isActive', 'priority']),

  // S3 subscription-mirror providers (the censorship-resistance hedge): a
  // variable-length POOL of S3-compatible buckets the subscription content is
  // copied to, so a client can still fetch its key if the control plane is
  // blocked. Structurally a sibling of `backendServers` — each row carries a
  // credential (`secretAccessKey`) that is NEVER returned to the admin UI (shown
  // as a set/not-set boolean) and NEVER logged. `accessKeyId` is the public half
  // of the keypair (shown). Mirroring is ACTIVE iff ≥1 row is `isActive` — there
  // is no separate enable flag. `name` is the stable identifier echoed into
  // `subscriptions.subscriptionMirrors[].provider` (the delete-match key), so it
  // is unique (enforced in the create/update mutation via the by_name index).
  // Fully DB-driven + CMS-managed; replaced the S3_MIRRORS_ENABLED / S3_PROVIDER_*
  // env scheme.
  mirrorProviders: defineTable({
    name: v.string(),
    endpoint: v.string(),
    bucket: v.string(),
    publicUrl: v.string(),
    region: v.string(),
    accessKeyId: v.string(),
    secretAccessKey: v.string(),
    // Country tiering: ISO-3166-1 alpha-2 codes (uppercase) this provider is
    // PREFERRED for. Empty/absent = a global fallback usable for any country.
    // Selection prefers a country match, then global, by priority. Operator
    // knowledge — "which S3 host is least likely to be blocked in country X".
    countryCodes: v.optional(v.array(v.string())),
    isActive: v.boolean(),
    priority: v.number(),
    updatedAt: v.number(),
  })
    .index('by_name', ['name'])
    .index('by_active', ['isActive', 'priority']),

  // Recommended VPN client apps shown to members ("set up your app"). Fully
  // DB-driven + CMS-managed: add / remove / enable / reorder with no deploy. The
  // fussy per-app import URL SCHEME stays a tested code builder in
  // src/client/lib/appLinks.ts, referenced here by `schemeId` (absent = manual /
  // QR import only, e.g. Streisand, Outline). `name` is unique (enforced in the
  // mutation via by_name). No secrets — safe to project publicly.
  clients: defineTable({
    name: v.string(),
    platforms: v.array(v.string()), // 'android' | 'ios' | 'windows' | 'desktop'
    backends: v.array(backendId), // which proxy backend(s) this app is for
    homepageUrl: v.string(),
    schemeId: v.optional(v.string()), // an appLinks builder id; absent = manual / QR only
    hwid: v.boolean(), // supports Remnawave device-id (so the device limit is honored)
    enabled: v.boolean(),
    priority: v.number(),
    updatedAt: v.number(),
  })
    .index('by_name', ['name'])
    .index('by_enabled', ['enabled', 'priority']),

  appSettings: defineTable({
    key: v.string(),
    value: v.string(),
    updatedByAdminId: v.optional(v.id('adminUsers')),
    updatedAt: v.number(),
  }).index('by_key', ['key']),

  // Membership redemption codes (W4): admin-minted bearer codes a member redeems
  // to grant/extend a paid tier — no billing portal required. Codes are SECRETS:
  // only the SHA-256 `codeHash` is stored (never plaintext), plus a short
  // `codePrefix` for the admin list. Single-use: a serializable consume flips
  // status active→redeemed. Uniqueness of `codeHash` is enforced in the mutation.
  redemptionCodes: defineTable({
    codeHash: v.string(),
    codePrefix: v.string(),
    tierId: v.id('tiers'),
    durationDays: v.number(),
    status: v.union(v.literal('active'), v.literal('redeemed'), v.literal('revoked')),
    note: v.optional(v.string()),
    batchId: v.optional(v.string()),
    // Origin is EITHER an admin mint (mintedByAdminId) OR a member purchase
    // (purchasedByUserId + purchasedByOrderId). Both optional so a purchased code
    // carries no admin. `by_purchaser` drives the buyer's "codes I bought" list;
    // `purchasedByOrderId` makes gift-minting idempotent against a replayed webhook.
    mintedByAdminId: v.optional(v.id('adminUsers')),
    purchasedByUserId: v.optional(v.id('users')),
    purchasedByOrderId: v.optional(v.id('billingOrders')),
    redeemedByUserId: v.optional(v.id('users')),
    redeemedAt: v.optional(v.number()),
    updatedAt: v.number(),
  })
    .index('by_code_hash', ['codeHash'])
    .index('by_status', ['status'])
    .index('by_batch', ['batchId'])
    .index('by_purchaser', ['purchasedByUserId']),

  // --- new tables replacing the former KvStore namespaces ---

  // Member + admin sessions (was the `sessions` KV namespace + signed cookie).
  //
  // Proof-of-possession (CDN-blinding Phase 2): a session MAY be bound to an
  // asymmetric PoP key minted client-side at login. `popPublicKey` is the raw
  // public key the client posted (base64url): an Ed25519 32-byte key (preferred)
  // OR an uncompressed P-256 point (65 bytes, the fallback for browsers without
  // WebCrypto Ed25519). `popAlg` ('EdDSA' | 'ES256') records which, so the
  // verifier dispatches on it (convex/lib/pop.ts `verifyPop`). The private half is
  // a non-extractable CryptoKey the browser holds and the CDN never sees. Once a
  // session carries `popPublicKey`, the signed cookie alone is NOT sufficient:
  // each request must also carry a fresh signature over its canonical form (see
  // convex/lib/pop.ts + the re-bind rule in lib/http.ts). Sessions minted before
  // Phase 2 leave these unset and authenticate by cookie only until POP_REQUIRED
  // is enabled.
  sessions: defineTable({
    sid: v.string(),
    kind: v.union(v.literal('member'), v.literal('admin')),
    userId: v.optional(v.id('users')),
    adminUserId: v.optional(v.id('adminUsers')),
    expiresAt: v.number(),
    popPublicKey: v.optional(v.string()),
    popAlg: v.optional(v.string()),
    popBoundAt: v.optional(v.number()),
    // The public per-session token (PoP sid-binding). A non-secret value minted at
    // login, returned in the login response body, and signed into every PoP
    // message so a signature is bound to exactly ONE session — it cannot be lifted
    // onto another session that reuses the same persisted key. Set only when the
    // session is PoP-bound; read back by lib/http.ts (sessionPopOk) on every
    // request and folded into the canonical message (convex/lib/pop.ts). Optional
    // because legacy/unbound sessions have none.
    popSessionToken: v.optional(v.string()),
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
