import { defineSchema, defineTable } from 'convex/server';
import { v } from 'convex/values';
import { backendIdValidator } from './lib/backendIds';
import { edgeProviderIdValidator } from './lib/edgeProviderIds';
import { listenerProtoFields } from './lib/edgeProtocolIds';

/**
 * Convex schema for FreeSocks Control Plane: the migration target. Ported from
 * the previous Drizzle schema (`src/server/db/schema.ts`, since removed) with
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

// The set of proxy-backend TYPES, derived from BACKEND_IDS (the single source
// of truth in src/shared/contracts/backendIds.ts): adding a backend type means
// an id there + a config variant in backendServerConfig below.
const backendId = backendIdValidator;

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
  // Idle free user: key reclaimed, row RETAINED on the free tier, and
  // login-reactivatable (unlike 'deleted', which kills the account number).
  // Set by the deactivate-idle-free sweep; cleared back to 'active' on return.
  v.literal('inactive'),
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
  // What the object holds under the edge-required policy: the binding policy
  // version + origin epoch the render passed under and the edges it carries;
  // `stub` = an unavailable stub was written because nothing could render.
  // Absent = raw / pre-policy content (to be replaced when an origin claims the node).
  validated: v.optional(
    v.object({
      policyVersion: v.number(),
      epoch: v.number(),
      edgeIds: v.array(v.string()),
      at: v.number(),
      stub: v.optional(v.boolean()),
    }),
  ),
});

// Self-service membership payment processors (hosted-redirect rails). Keep in
// sync with the PaymentProcessor adapters in convex/lib/processors/.
const billingProcessor = v.union(
  v.literal('nowpayments'),
  v.literal('btcpay'),
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

// Edges (provider-managed L4 load balancers in front of origin nodes):
// shared validators for the origin* tables below. Credentials and settings are
// discriminated by provider `type` so EDGE_PROVIDER_IDS drift is a test failure.
const relayProviderId = edgeProviderIdValidator;
const relayProviderCredentials = v.union(
  v.object({ type: v.literal('gcore'), apiKey: v.string() }),
  v.object({ type: v.literal('upcloud'), token: v.string() }),
  v.object({ type: v.literal('scaleway'), secretKey: v.string() }),
  v.object({ type: v.literal('ovh'), applicationSecret: v.string(), consumerKey: v.string() }),
  v.object({ type: v.literal('cloudflare'), apiToken: v.string() }),
  v.object({ type: v.literal('fastly'), apiToken: v.string() }),
  v.object({ type: v.literal('cloudfront'), secretAccessKey: v.string() }),
);
// Account settings: credential identifiers and intent defaults. WHERE an
// account's edges live is never here: it is a location
// (`edgeLocations.placement`, frozen on each edge), including a CDN front's DNS
// zone. The zone / DNS account / TLS configuration keys below are the legacy
// shape the L7 locations migration (`edgeL7Locations.ts`) moves onto the
// account's location; they are read only as its fallback and dropped by the
// follow-up cleanup.
const relayProviderSettings = v.union(
  v.object({ type: v.literal('gcore') }),
  v.object({ type: v.literal('upcloud') }),
  v.object({
    type: v.literal('scaleway'),
    accessKey: v.string(), // public key id (the SDK pairs it with the secret); not a secret
  }),
  v.object({
    type: v.literal('ovh'),
    applicationKey: v.string(), // public app identifier, not a secret
    endpoint: v.union(v.literal('ovh-eu'), v.literal('ovh-ca'), v.literal('ovh-us')),
  }),
  // L7 (CDN front): the token's Cloudflare account (account-owned tokens).
  v.object({
    type: v.literal('cloudflare'),
    accountId: v.optional(v.string()),
    zoneId: v.optional(v.string()), // legacy (migrated onto the location)
    zoneName: v.optional(v.string()), // legacy (migrated onto the location)
  }),
  // L7: nothing of its own. `certificateAuthority` / `certificateScope` are the
  // pre-options copies of the account's certificate options, moved into
  // `optionDefaults` on deploy (edgeProviderAccounts.migrateOptionDefaults);
  // `dnsAccountId` / `tlsConfigurationId` the pre-location copies of where its
  // fronts live, moved onto its location (edgeL7Locations.migrate). Kept
  // readable until a cleanup drops them.
  v.object({
    type: v.literal('fastly'),
    certificateAuthority: v.optional(
      v.union(v.literal('certainly'), v.literal('lets-encrypt'), v.literal('globalsign')),
    ),
    // One wildcard certificate per account and zone, or one per front (absent).
    certificateScope: v.optional(v.union(v.literal('per_host'), v.literal('wildcard'))),
    dnsAccountId: v.optional(v.string()), // legacy (migrated onto the location)
    tlsConfigurationId: v.optional(v.string()), // legacy (migrated onto the location)
    // A new front's domain: versionless (Domain Management, absent) or classic.
    domainModel: v.optional(v.union(v.literal('versionless'), v.literal('classic'))),
  }),
  v.object({
    type: v.literal('cloudfront'),
    accessKeyId: v.string(), // the IAM access key's public id; not a secret
  }),
);
// Where an edge's resources live (`lib/edges/accountSettings.ts`
// EDGE_PLACEMENT_SCHEMAS validates every new one). A CDN front's keys are
// optional here only because edges planned before L7 locations froze `{type}`
// alone (their provisionIntent holds the zone) and a location the migration
// could not complete keeps it.
const relayEdgePlacement = v.union(
  v.object({
    type: v.literal('gcore'),
    projectId: v.number(),
    regionId: v.number(),
    // Private VIP + floating-IP mode needs a network/subnet; public-VIP mode does not.
    networkId: v.optional(v.string()),
    subnetId: v.optional(v.string()),
  }),
  v.object({ type: v.literal('upcloud'), zone: v.string() }),
  v.object({
    type: v.literal('scaleway'),
    projectId: v.optional(v.string()), // absent = the key's default project
    zone: v.string(),
  }),
  v.object({
    type: v.literal('ovh'),
    serviceName: v.string(),
    regionName: v.string(),
    networkId: v.string(),
    subnetId: v.string(),
    gatewayId: v.optional(v.string()),
  }),
  v.object({
    type: v.literal('cloudflare'),
    zoneId: v.optional(v.string()),
    zoneName: v.optional(v.string()),
  }),
  v.object({
    type: v.literal('fastly'),
    dnsAccountId: v.optional(v.string()),
    zoneId: v.optional(v.string()),
    zoneName: v.optional(v.string()),
    tlsConfigurationId: v.optional(v.string()),
  }),
  v.object({
    type: v.literal('cloudfront'),
    dnsAccountId: v.optional(v.string()),
    zoneId: v.optional(v.string()),
    zoneName: v.optional(v.string()),
  }),
);
// Layers an edge can be: an L4 forwarder (address = IP literal) or an L7 CDN
// front (address = hostname). Absent on rows written before L7 = l4.
const relayEdgeLayer = v.union(v.literal('l4'), v.literal('l7'));

// What a load balancer plan's traffic costs (lib/edges/pricing.ts): `unlimited`
// = no traffic charge, `included` = that many GB a month then `perGb`, `per_gb`
// = every GB, `unknown` = the source does not say.
const edgePlanTraffic = v.object({
  kind: v.union(
    v.literal('unlimited'),
    v.literal('included'),
    v.literal('per_gb'),
    v.literal('unknown'),
  ),
  includedGb: v.optional(v.number()),
  perGb: v.optional(v.number()),
});
// What a listener speaks (`listenerProtoFields`, spread into the tables below):
// three orthogonal fields with a validity matrix
// (src/shared/contracts/edgeProtocolIds.ts). Client-facing security here is
// separate from how a front dials the node (`originTransport` below).
// One server name a listener presents (REALITY SNI or certificate name).
// Retired names stay accepted by the node until `drainUntil`; `retiredBy`
// says whether the node role may reactivate it (only its own retirements).
const listenerName = v.object({
  // `family` = activated by a server-name rollout after a node proved it
  // accepts the name. Absent = came from a registration body or an admin edit.
  origin: v.optional(v.literal('family')),
  // Curated countries where the name is known blocked / proven to work. A copy
  // of `sniNameCountry`, kept ON the name so a render needs no extra reads.
  blockedIn: v.optional(v.array(v.string())),
  provenIn: v.optional(v.array(v.string())),
  name: v.string(),
  status: v.union(v.literal('active'), v.literal('retired')),
  retiredAt: v.optional(v.number()),
  drainUntil: v.optional(v.number()),
  retiredBy: v.optional(v.union(v.literal('admin'), v.literal('role'))),
});
// How the renderer finds a listener's entry in a subscription body.
const listenerMatchRule = v.union(
  v.object({ kind: v.literal('remark'), remark: v.string() }),
  v.object({ kind: v.literal('address') }),
  v.object({ kind: v.literal('whole-body') }),
);
// The backend Host a listener owns (hostMode `fcp`), as a persisted state
// machine: an uncertain create/delete is `unresolved` until discovery settles
// it against the INTENDED binding (remark + transport + address:port), never
// remark alone; `ambiguous` parks it for an operator (lib/edges/hostOps.ts).
const listenerHostState = v.union(
  v.literal('absent'),
  v.literal('creating'),
  v.literal('present'),
  v.literal('deleting'),
  v.literal('unresolved'),
  v.literal('ambiguous'),
);
const listenerHost = v.object({
  state: listenerHostState,
  uuid: v.optional(v.string()),
  ownership: v.optional(v.union(v.literal('fcp'), v.literal('adopted'))),
  intended: v.optional(
    v.object({
      remark: v.string(),
      address: v.string(),
      port: v.number(),
      sni: v.union(v.string(), v.null()),
      host: v.union(v.string(), v.null()),
      inboundUuid: v.string(),
    }),
  ),
  op: v.optional(
    v.object({
      kind: v.union(v.literal('create'), v.literal('delete')),
      opId: v.string(),
      claimedAt: v.number(),
      expiresAt: v.number(),
      attempts: v.number(),
      lastLookAt: v.optional(v.number()),
    }),
  ),
});
// Where an origin's origin is: a backend node (FCP can own its Hosts and pin
// subscriptions to it), a whole backend server (an Outline instance), or an
// address the operator described by hand (provision / probe / rotate only).
const relayOrigin = v.union(
  v.object({
    kind: v.literal('panel-node'),
    backendServerId: v.id('backendServers'),
    nodeName: v.string(),
    nodeUuid: v.optional(v.string()),
  }),
  v.object({ kind: v.literal('backend-server'), backendServerId: v.id('backendServers') }),
  v.object({ kind: v.literal('manual') }),
);
// Who writes the client-facing backend Hosts: FCP, the operator, or nobody
// (there is no Host at all: Outline, manual).
const relayHostMode = v.union(v.literal('fcp'), v.literal('operator'), v.literal('none'));
// What the node speaks to whoever dials it behind an L7 front (declared by the
// node role on the slot): scheme, whether its certificate is publicly trusted,
// the names that certificate carries (wildcards allowed) and which Host header
// values it accepts. Absent = a legacy L4-only slot (raw TCP to the transport).
const relaySlotOriginTransport = v.object({
  scheme: v.union(v.literal('http'), v.literal('https')),
  certPublic: v.boolean(),
  certNames: v.array(v.string()),
  acceptsHostHeader: v.union(v.literal('any'), v.literal('names')),
});
const relayReadinessState = v.union(
  v.literal('ready'),
  v.literal('pending'),
  v.literal('failed'),
  v.literal('unknown'),
);
const relayStepState = v.union(
  v.literal('pending'),
  v.literal('requested'),
  v.literal('done'),
  v.literal('unresolved'),
  v.literal('ambiguous'),
  v.literal('needs_operator'),
);
const relayDeleteState = v.union(
  v.literal('present'),
  v.literal('delete_requested'),
  v.literal('confirmed_gone'),
);
const relayEdgeStatus = v.union(
  v.literal('planning'),
  v.literal('provisioning'),
  v.literal('verifying'),
  v.literal('active'),
  v.literal('draining'),
  v.literal('destroying'),
  v.literal('destroyed'),
  v.literal('failed'),
  v.literal('cancelled'),
  v.literal('quarantined'),
  v.literal('needs_operator'),
);
const relayPublication = v.union(
  v.literal('unpublished'),
  v.literal('published'),
  v.literal('draining'),
);
const relayHealth = v.union(
  v.literal('online'),
  v.literal('offline'),
  v.literal('degraded'),
  v.literal('unknown'),
);
const relayReachVerdict = v.union(
  v.literal('reachable'),
  v.literal('unreachable'),
  v.literal('mixed'),
  v.literal('unknown'),
);
/** Cross-source reachability summary kept on a probed target (edge, origin node, custom). */
const probeReachabilitySummary = v.object({
  byCountry: v.array(
    v.object({
      country: v.string(),
      // The IPv4 path (what every member receives); IPv6 rows only when no v4 row exists.
      verdict: relayReachVerdict,
      // The IPv6 path, when the target has one and it was probed.
      v6Verdict: v.optional(relayReachVerdict),
      // The BY-NAME path, when the target was also probed by hostname (an L7
      // front has no family of its own; for such a target the name path IS
      // `verdict` and this stays absent).
      nameVerdict: v.optional(relayReachVerdict),
      okVantages: v.number(),
      failVantages: v.number(),
      lastAt: v.number(),
      // Transition marker, evaluated PER PORT before the ports roll up: some
      // listener port that is now unreachable from this country was reachable
      // from it before. A port that has never been reached is not evidence,
      // however long another port's reachable history is.
      wasReachable: v.optional(v.boolean()),
    }),
  ),
  updatedAt: v.number(),
});
// What one round of checks says about an edge from one country (lib/edges/country/verdict.ts).
const countryRoundResult = v.union(
  v.literal('proven'),
  v.literal('blocked'),
  v.literal('down'),
  v.literal('unknown'),
);
const countryDecided = v.union(v.literal('proven'), v.literal('blocked'));
/**
 * The EFFECTIVE result per checked country, copied onto the edge (like name
 * marks onto listeners) so a render needs no extra read. Decided entries only;
 * one past its `until` is unknown at read (a mark has none).
 */
const edgeCountryStateV = v.object({
  byCountry: v.array(
    v.object({
      country: v.string(),
      state: countryDecided,
      until: v.optional(v.number()),
      from: v.union(v.literal('edge'), v.literal('group'), v.literal('mark')),
    }),
  ),
  updatedAt: v.number(),
});
const probeTargetKind = v.union(v.literal('edge'), v.literal('relay'), v.literal('custom'));
// What a probe speaks (lib/edges/probes/types.ts `ProbeProtocol`). `tls-sni` is
// the internal protocol-shape check of an L4 edge in front of a REALITY / TLS
// listener: a handshake with SNI = one of the listener's active names, chain
// verified for that name. Shape evidence only (a forwarder aimed at the
// camouflage site passes it); never authentication.
const probeProtocolV = v.union(
  v.literal('tcp'),
  v.literal('tls'),
  v.literal('https'),
  v.literal('tls-sni'),
);
// Configuration-bound endpoint verification of an L4 edge (lib/edges/verification.ts).
// `verified` is set ONLY by an operator's confirmation against the exact
// binding they were shown; `partial` is the probe ceiling, written by the
// system (`method: 'probe'`, lib/edges/verifyRung.ts) from probe evidence and
// never satisfying the publication gate. The record proves nothing by itself:
// `verificationCurrent` compares revision + configHash.
const relayEdgeVerification = v.object({
  rung: v.union(v.literal('partial'), v.literal('verified')),
  by: v.union(v.literal('admin'), v.literal('system')),
  at: v.number(),
  endpoint: v.string(), // "host:port" (or the hostname) the operator connected to
  listenerKey: v.string(),
  listenerRevision: v.number(),
  configHash: v.string(),
  method: v.union(
    v.literal('test_link'),
    v.literal('named_connection'),
    v.literal('l7_proof'),
    v.literal('probe'),
  ),
  // An enrolled node's REALITY auth revision the record was taken under (it is
  // folded into `configHash` too): only read to SAY why a record went stale
  // (the key moved). Database only; never in a binding a client sees.
  authRevision: v.optional(v.string()),
});
// Provider-account trust evidence (lib/edges/autoQualify.ts): who trusted the
// account and, when it came from an endpoint, the exact configuration that was
// proven. Ids and hashes only: never an address.
const relayAccountQualification = v.object({
  by: v.union(v.literal('admin'), v.literal('auto')),
  at: v.number(),
  evidence: v.optional(
    v.object({
      edgeId: v.id('edges'),
      endpoint: v.string(),
      accountTestedAt: v.number(),
      templateHash: v.string(),
      listenerId: v.id('relayListeners'),
      listenerRevision: v.number(),
      proofCheckedAt: v.optional(v.number()),
    }),
  ),
});

const relayProbeSource = v.union(
  v.literal('globalping'),
  v.literal('checkhost'),
  v.literal('ripeatlas'),
  v.literal('internal'),
);
// An in-flight external operation claim (one at a time per edge / per rotation).
const relayEdgeOp = v.object({
  opId: v.string(),
  kind: v.union(
    v.literal('provision_step'),
    v.literal('poll_step'),
    v.literal('discover'),
    v.literal('destroy_step'),
  ),
  target: v.string(), // stepId / resourceId
  attempt: v.number(),
  claimedAt: v.number(),
  expiresAt: v.number(),
});
const relayHostOp = v.object({
  opId: v.string(),
  kind: v.union(v.literal('host_write'), v.literal('host_observe')),
  hostUuid: v.string(),
  direction: v.union(v.literal('forward'), v.literal('rollback')),
  attempt: v.number(),
  claimedAt: v.number(),
  expiresAt: v.number(),
});
const relayRotationPhase = v.union(
  v.literal('select'),
  v.literal('provisioning'),
  v.literal('verifying'),
  v.literal('publishing'),
  v.literal('host_flipping'),
  v.literal('confirming'),
  v.literal('finalizing'),
  v.literal('rolling_back'),
  v.literal('done'),
  v.literal('failed'),
  v.literal('rolled_back'),
  v.literal('quarantined'),
  v.literal('cancelled'),
);
// Guided setup ("Autopilot") run stages and states (convex/edgeSetupRuns.ts;
// the vocabularies are pinned in src/shared/contracts/edgeCodes.ts).
const setupRunStage = v.union(
  v.literal('prepare'),
  v.literal('credential'),
  v.literal('provision'),
  v.literal('verify'),
  v.literal('try_it'),
  v.literal('publish'),
  v.literal('hide_direct_hosts'),
  v.literal('rehearse'),
  v.literal('go_live'),
  v.literal('done'),
);
const setupRunState = v.union(
  v.literal('running'),
  v.literal('waiting'),
  v.literal('needs_you'),
  v.literal('done'),
  v.literal('done_unbound'),
  v.literal('failed'),
  v.literal('cancelled'),
);
const setupRunVerify = v.union(
  v.literal('pending'),
  v.literal('partial'),
  v.literal('verified'),
  v.literal('unreachable'),
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
    // Cross-backend peer GROUP: tiers sharing this key are "the same tier" on
    // their respective backends, so a member can switch backends between them
    // (account.switchBackend). Symmetric and N-ary by construction (the old
    // pairwise peerTierId link could not express 3+ backends). Optional; free
    // tiers auto-resolve their peer via the per-backend default-free row and
    // need no group. Resolved in convex/tiers.ts getPeerTier; set by an admin
    // in the tier editor.
    peerGroup: v.optional(v.string()),
    // DEPRECATED (read-fallback only; superseded by peerGroup — the seed
    // assigns a group to existing pairs; schema drop is a later two-deploy).
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
    // The membership expiry counting only PAID-VALUE grants (billing, code
    // redemption, admin grant) — never referral-reward extensions. The referral
    // vest check keys off this so a self-referral can't satisfy the holding
    // period with its own instant referee bonus (the M4 farming hole): the
    // referrer's reward vests only while the referee is a PAYING member.
    // Unset on pre-existing rows → the vest check falls back to
    // membershipExpiresAt.
    membershipPaidThroughAt: v.optional(v.number()),
    suspendedAt: v.optional(v.number()),
    // Account-number auth: store only a peppered keyed hash
    // (HMAC-SHA256(ACCOUNT_ID_PEPPER, number)) + a 4-digit plaintext prefix
    // (admin search). Uniqueness of the hash is enforced in mutations.
    accountIdHash: v.optional(v.string()),
    accountIdPrefix: v.optional(v.string()),
    // Legacy fields kept (optional) so pre-removal documents still pass
    // deploy-time schema validation (dropped as dead in bcc663e; can be
    // dropped permanently once no document carries them).
    accountIdCreatedAt: v.optional(v.number()),
    accountIdRotatedAt: v.optional(v.number()),
    // W3: a non-secret `FS-XXXX-XXXX` support handle (NOT a credential). Minted
    // at account creation, lazily backfilled for pre-W3 users. Unique (enforced
    // in the mutation). See convex/lib/supportId.ts.
    supportId: v.optional(v.string()),
    // Set when a backend push (tier propagation, or an enable/disable) fails and
    // hasn't since succeeded; cleared on the next successful push. Surfaced as the
    // admin "backend drift" signal so otherwise-silent entitlement drift (a paid
    // upgrade that never reached the backend, a disable the key ignored) is visible.
    backendPushFailedAt: v.optional(v.number()),
    // Member-chosen connection mode (transport), orthogonal to the entitlement
    // tier: the tier sets limits, this selects which backend placement the key
    // issues into. A plain string validated against the mode catalog (see
    // lib/connectionModes.ts), unset → the catalog default. Additive/optional.
    connectionModeId: v.optional(v.string()),
    // Member-chosen node location (a backendServers.location code, e.g. "MCI"),
    // orthogonal to the connection mode: the mode picks the transport, this
    // narrows WHICH instance's nodes the key issues onto. Unset = automatic
    // (least-loaded across all locations). Fail-soft: a stale code that no
    // longer matches an active instance never blocks issuance.
    preferredLocation: v.optional(v.string()),
    // Free-tier idle marker: the issued key's backend `expireAt` (ms). Stamped at
    // free-account creation + re-stamped on every free key issuance / reactivation,
    // so it advances only when the member acts — the "still using the service"
    // signal the deactivate-idle-free sweep keys off (an ACTIVE free user whose
    // key has expired and wasn't refreshed is deactivated). Unset for paid users.
    freeKeyExpiresAt: v.optional(v.number()),
    // Durable donor marker: the ms timestamp of the member's FIRST settled
    // donation (set once, never cleared). Backs the persistent account donor
    // badge so the read path needs no billing-order scan. Unset ⇒ not a donor.
    firstDonatedAt: v.optional(v.number()),
    // The member's referral code (`FSR-XXXX-XXXX`, Crockford base32 like the
    // support ID, distinct prefix): NON-SECRET, shareable freely — it credits
    // the referrer, it grants nothing to the holder. Minted at account
    // creation, lazily backfilled on first referral-stats read for older
    // accounts. Unique (enforced in the mint mutation).
    referralCode: v.optional(v.string()),
    // Lifetime settled-donation aggregates (the impact backend). Maintained at
    // grant time (billing.fundDonation) so billing-order retention pruning
    // (365d) never shrinks a donor's totals.
    donatedCentsTotal: v.optional(v.number()),
    donationCount: v.optional(v.number()),
    updatedAt: v.number(),
  })
    .index('by_account_id_hash', ['accountIdHash'])
    .index('by_account_id_prefix', ['accountIdPrefix'])
    .index('by_support_id', ['supportId'])
    .index('by_referral_code', ['referralCode'])
    .index('by_status_expires', ['status', 'membershipExpiresAt'])
    // Idle-free sweep: (tierId, status, freeKeyExpiresAt) — scan ONLY active free
    // users due for deactivation; `inactive` rows fall outside the range, so the
    // sweep never re-scans its own output (no accretion).
    .index('by_tier_status_freekey', ['tierId', 'status', 'freeKeyExpiresAt'])
    .index('by_tier', ['tierId'])
    // Mode-catalog delete/disable guards: cheap "is any member on this mode?"
    // existence checks (never full counts on the hot path).
    .index('by_connection_mode', ['connectionModeId']),

  // === DB-driven connection-mode catalog (families + leaf modes) =============
  // The member-facing transport choice, fully admin-managed (create/edit/delete
  // in the CMS). Compiled defaults in lib/connectionModes.ts seed a fresh deploy
  // and serve as the read fallback while both tables are empty, so the picker is
  // never blank. The string `slug` is the wire id everywhere (users.
  // connectionModeId, censorship-matrix cells, audit payloads) and is IMMUTABLE
  // after create — a rename is create+migrate+delete, never an alias layer.
  connectionModeFamilies: defineTable({
    slug: v.string(), // unique (read-check in the create mutation)
    // Admin-set copy; absent → the SPA renders its compiled i18n for built-in
    // slugs (and a humanized slug otherwise, which create() prevents by
    // requiring a label for non-built-ins).
    label: v.optional(v.string()),
    description: v.optional(v.string()),
    // The "who is this for" picker chip; absent → built-in i18n or no chip.
    audience: v.optional(v.string()),
    // OPEN icon id resolved by the client icon registry; unknown → fallback.
    iconId: v.string(),
    enabled: v.boolean(),
    order: v.number(),
    updatedAt: v.number(),
  }).index('by_slug', ['slug']),

  connectionModes: defineTable({
    slug: v.string(), // unique (read-check in the create mutation)
    familySlug: v.string(),
    // Closed CODE enum — drives member delivery UI (URL-first vs raw-config).
    deliveryStyle: v.union(v.literal('url'), v.literal('rawConfig')),
    label: v.optional(v.string()),
    description: v.optional(v.string()),
    enabled: v.boolean(),
    // The leaf selected when a member picks the family without a transport.
    isFamilyDefault: v.boolean(),
    // The geo-based suggestion for censored-region members targets this mode
    // (replaces the compiled CENSORSHIP_MODE_FAMILY constant).
    isCensorshipRecommended: v.optional(v.boolean()),
    // Backend APPLICABILITY (the clients.backends pattern): which backend types
    // this mode is offered on. Availability additionally requires a bound
    // placement on placement-capable backends.
    backends: v.array(backendId),
    order: v.number(),
    updatedAt: v.number(),
  }).index('by_slug', ['slug']),

  // Per-(mode, backend) placement binding. `config` is a backend-defined JSON
  // string (Remnawave: {"squadUuids":[...]}) parsed fail-safe by that backend's
  // placement resolver — malformed config reads as unbound, never a throw.
  // WRITE-ONLY over HTTP: admin reads get {bound, boundCount} summaries, never
  // the config; audits carry poolBound + counts only. Scope admin:servers:write
  // (the Ansible role's token), deliberately separate from the catalog tables'
  // admin:settings:write.
  modePlacements: defineTable({
    modeSlug: v.string(),
    backend: backendId,
    config: v.string(),
    updatedAt: v.number(),
  })
    .index('by_mode_backend', ['modeSlug', 'backend'])
    .index('by_backend', ['backend']),

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
    // from THIS origin instead of the backend backend. Rotates per key by
    // construction (a new sub row = a new token). Minted in insertSubscription.
    subToken: v.optional(v.string()),
    // Small in-front content cache for the fronted route — a JSON blob holding a
    // BOUNDED per-UA list of {content, contentType, headers?, ua, at} entries (see
    // convex/http.ts + subscriptions.writeContentCache). Bounded (no growth),
    // dropped with the row, keyed by UA so multiple clients (phone + desktop)
    // don't thrash and we never serve one client's format to another — on both the
    // fresh-hit and stale-fallback paths. Never logged.
    subCache: v.optional(v.string()),
    // Opaque backend placement handle this key was issued into (Remnawave: the
    // internal-mode group UUID chosen by node-load placement). Persisted so tier
    // pushes re-send the SAME placement instead of re-picking — a re-pick would
    // thrash live keys across nodes on every renewal. Absent on non-Remnawave
    // subs; the push then falls back to the mode's placement resolution.
    backendPlacement: v.optional(v.string()),
    // Opaque CSPRNG key for origin-edge assignment + SNI selection (never the
    // subToken, so a URL rotation does not reshuffle a member's endpoints).
    renderKey: v.optional(v.string()),
    // The member's OWN answer to "where are you connecting from?": a country on
    // the censored-country list, or `ZZ` ("Somewhere else"). Set on the account
    // page and clearable (Automatic). Freedom-family keys only (lib/memberCountry.ts).
    sniRegion: v.optional(v.string()),
    // On Automatic with `delivery.country.detect` on: the country the CDN
    // reported, stored only when it is on the censored-country list (a GUESS,
    // shown to the member), first and last seen. Forgotten `stickyDays` after it
    // was last seen; cleared with the key, on a switch to a privacy-family mode
    // and when its country leaves the list. Never in logs, audit or analytics.
    regionSeenCountry: v.optional(v.string()),
    regionSeenFirstAt: v.optional(v.number()),
    regionSeenAt: v.optional(v.number()),
    // Bumped by every change of the stored country (choice or guess); a request
    // that read an older revision cannot write a country back
    // (subscriptions.ts `setStoredCountry`).
    countryRev: v.optional(v.number()),
    // Fronted-route delivery observations: last successful 200 (cache hit or
    // miss, HWID or not) and when the served body was generated by the backend.
    lastDeliveredAt: v.optional(v.number()),
    lastDeliveredContentAt: v.optional(v.number()),
    lastRenderedEpoch: v.optional(v.number()),
    // The eligibility snapshot of the last render (what this subscriber was
    // handed): member connection labels and report attribution read it and
    // never reconstruct an assignment without the body.
    lastRender: v.optional(
      v.object({
        at: v.number(),
        epoch: v.number(),
        family: v.string(),
        listenerKeys: v.array(v.string()),
        primaryEdgeId: v.optional(v.id('edges')),
        backupEdgeId: v.optional(v.id('edges')),
        // The member's STORED country the body was shaped for (never a
        // transient reading), and, when their edges were ordered by it, the
        // tier each endpoint came from there (0 proven, 1 not known, 2 blocked).
        // Cleared with every other copy of the country (memberCountry.ts).
        country: v.optional(v.string()),
        primaryTier: v.optional(v.number()),
        backupTier: v.optional(v.number()),
      }),
    ),
    // The node this key's subscription content is currently pinned to
    // (Remnawave node pinning), recorded at serve time.
    pinnedNode: v.optional(v.string()),
    // The assignment version of `pinnedNode` and who wrote it: a node
    // migration moves a member only when the version it snapshotted is still
    // current, and restores only what it wrote itself (docs/servers.md).
    pinVersion: v.optional(v.number()),
    pinOwner: v.optional(v.string()),
    // The node this key was pinned to BEFORE issuance (copied from the old
    // subscription at regenerate) — excluded from the pin pick when others
    // exist, so a regenerated key lands on a different node.
    excludeNode: v.optional(v.string()),
    // Bumped whenever what this key should carry moves IN PLACE (a mode or
    // server switch that keeps the row, a pin rotation): the cached bodies, the
    // pin, the render snapshot and the mirror hash go with it, and a request
    // that read an older revision writes none of them back
    // (subscriptions.ts `invalidateDelivery`).
    deliveryRev: v.optional(v.number()),
    state: subscriptionState,
    updatedAt: v.number(),
    deletedAt: v.optional(v.number()),
    // Tombstone-sweep retry state: a row whose backend delete keeps failing
    // (dead backend) is deferred by an exponential backoff so it can't occupy the
    // sweep page forever and starve newer tombstones (head-of-line blocking).
    // After TOMBSTONE_MAX_ATTEMPTS the row is abandoned (marked deleted + audit).
    tombstoneRetryAfter: v.optional(v.number()),
    tombstoneAttempts: v.optional(v.number()),
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
    // (state, tombstoneRetryAfter): the tombstone sweep's due-row selection —
    // undefined sorts below numbers, so never-retried rows are picked first
    // and backoff-deferred rows (retryAfter >= now) fall outside the range.
    .index('by_state_tombstone_retry', ['state', 'tombstoneRetryAfter', 'deletedAt'])
    .index('by_backend_user_id', ['backendUserId'])
    .index('by_backend_short_id', ['backendShortId'])
    // The member-country sweeps: a country leaving the censored-country list
    // (both indexes) and a guess expiring (`by_region_seen_at`).
    .index('by_sni_region', ['sniRegion'])
    .index('by_region_seen_country', ['regionSeenCountry'])
    .index('by_region_seen_at', ['regionSeenAt'])
    // Instance→subs reference check before a backend-server delete (refuse
    // while keys still point at it).
    .index('by_backend_server', ['backendServerId'])
    // Bounded "any live key on this backend?" probe for the instance-delete guard;
    // with the placement, the whole-server origin's COHORT walk (below).
    .index('by_backend_server_state', ['backendServerId', 'state', 'backendPlacement'])
    // (backendServerId, pinnedNode, state, backendPlacement): the origin layer's
    // COHORTS (one representative per placement among the keys pinned to a
    // node), found by an indexed walk over the DISTINCT placements (one read per
    // placement, driven from an action; convex/lib/edges/cohorts.ts), never by
    // reading every key.
    .index('by_backend_server_pinned', [
      'backendServerId',
      'pinnedNode',
      'state',
      'backendPlacement',
    ])
    // The FCP-fronted subscription route resolves the sub by its opaque token.
    .index('by_sub_token', ['subToken']),

  // The mirror barrier (docs/servers.md "Node lifecycle"): one row per mirror
  // upload, opened BEFORE the object is written with the delivery token the
  // body was rendered under. Settled only when the token read AFTER a
  // successful upload is still that token (then dropped); an upload that raced a policy move
  // (maintenance, a delivery binding, a candidate set) stays open, and the
  // repair pass re-renders and re-uploads under the current policy, or
  // withdraws the object. Holds no content and no address.
  mirrorUploads: defineTable({
    subscriptionId: v.id('subscriptions'),
    objectPath: v.string(),
    providers: v.array(v.string()),
    // The delivery token (edgeRender.epochFor) the body was rendered under; null = no place token.
    tokenBefore: v.union(v.string(), v.null()),
    // `initial`: the first upload of a new mirror (the row may not reference it yet).
    kind: v.union(v.literal('initial'), v.literal('refresh'), v.literal('repair')),
    // A settled obligation is deleted: every row is an open one.
    state: v.literal('open'),
    attempts: v.number(),
    startedAt: v.number(),
    updatedAt: v.number(),
  })
    .index('by_state', ['state', 'updatedAt'])
    .index('by_subscription', ['subscriptionId', 'state']),

  tierHistory: defineTable({
    userId: v.id('users'),
    fromTierId: v.optional(v.id('tiers')),
    toTierId: v.id('tiers'),
    reason: v.string(),
    triggeredBy: v.string(),
  }).index('by_user', ['userId']),

  auditLog: defineTable({
    actorType,
    actorId: v.optional(v.string()),
    action: v.string(),
    targetType: v.optional(v.string()),
    targetId: v.optional(v.string()),
    payload: v.optional(v.any()),
    requestId: v.optional(v.string()),
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

  // --- member passkeys (optional alternative login for MEMBERS) --------------
  // Parallel to the admin passkey tables above, but keyed to `users` (members),
  // NOT `adminUsers`. Kept as separate tables (rather than generalizing the admin
  // ones) so the admin last-admin invariants stay isolated and member verify can
  // ONLY match a member credential — cross-realm isolation: an admin passkey can
  // never assert a member session, and vice-versa (same RP id, different table).
  // A member passkey is an OPT-IN convenience credential; the account number
  // stays valid as the portable recovery secret.
  memberPasskeyCredentials: defineTable({
    userId: v.id('users'),
    credentialId: v.string(),
    publicKey: v.string(),
    counter: v.number(),
    transports: v.optional(v.string()),
    deviceLabel: v.optional(v.string()),
    aaguid: v.optional(v.string()),
    lastUsedAt: v.optional(v.number()),
  })
    .index('by_user', ['userId'])
    .index('by_credential_id', ['credentialId']),

  memberWebauthnRegistrationChallenges: defineTable({
    userId: v.id('users'),
    challenge: v.string(),
    expiresAt: v.number(),
    consumedAt: v.optional(v.number()),
  })
    .index('by_user_expires', ['userId', 'expiresAt'])
    .index('by_expires', ['expiresAt']),

  // Passkey ASSERTION challenges for member login. `userId` is absent (the
  // usernameless discoverable flow), so there is no existence oracle. Swept daily.
  memberWebauthnAuthChallenges: defineTable({
    challengeId: v.string(),
    challenge: v.string(),
    userId: v.optional(v.id('users')),
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
    // Outcome tracking (separate from the start-stamp): an action-context cron
    // commits its start-stamp independently, so a job that THROWS every run
    // still shows a fresh lastRunAt. `lastOkAt` stamps successful completion
    // and `lastError` the latest failure message, so the dashboard can tell a
    // firing-but-wedged job apart from a healthy one.
    lastOkAt: v.optional(v.number()),
    lastError: v.optional(v.string()),
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
    .index('by_source', ['source'])
    // Failed-claim surface for the admin billing page (a stuck 'failed' claim
    // past the sender's retry window = a paid-but-ungranted order).
    .index('by_status', ['status']),

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
    // Absent = an ANONYMOUS donation order (kind 'donation' only): no account
    // involved, the opaque ref is the payer's only handle. Memberships and
    // gifts are always user-bound.
    userId: v.optional(v.id('users')),
    // Optional: a donation-only order (kind 'donation') carries no tier.
    tierId: v.optional(v.id('tiers')),
    durationDays: v.number(),
    amountCents: v.number(),
    // The donation portion of amountCents (0/absent for a pure membership order).
    // On a membership+donation order amountCents = price + donationCents; on a
    // donation-only order amountCents === donationCents. Recorded on the order so
    // the grant path + admin billing log can report how much was donated.
    donationCents: v.optional(v.number()),
    currency: v.string(),
    status: billingOrderStatus,
    paidAt: v.optional(v.number()),
    // Gift purchases: a 'gift' order mints `quantity` shareable codes (bound to
    // the buyer via redemptionCodes.purchasedByOrderId) instead of extending the
    // buyer's own membership. Absent ⇒ legacy self-upgrade. A 'donation' order
    // grants nothing (records the donation + funds the free-bandwidth pool).
    // `giftReveal` is the TRANSIENT plaintext buffer returned to the buyer ONCE on
    // the return poll, then cleared on ack (or by the gift-reveal sweep) — the
    // codes live hash-only in redemptionCodes; durable storage is never plaintext.
    kind: v.optional(v.union(v.literal('self'), v.literal('gift'), v.literal('donation'))),
    quantity: v.optional(v.number()),
    giftReveal: v.optional(v.array(v.string())),
    giftRevealAck: v.optional(v.boolean()),
    // True while a paid gift order still holds an unacked plaintext reveal; unset
    // on ack or by the gift-reveal sweep. A dedicated flag + index so the sweep
    // scans ONLY pending reveals (oldest-first via the appended _creationTime),
    // never the whole paid-orders table — which starved it once paid self-orders
    // outnumbered the page window. (Review #5.)
    giftRevealPending: v.optional(v.boolean()),
    // Set when a refund-class event unwound this order's donation from the
    // shared pool (+ the donor aggregates). Guards the unwind to ONCE per order:
    // Stripe emits one charge.refunded per (partial) refund — each a distinct
    // dedupe id — so without the flag every event re-subtracted the FULL
    // donation, over-correcting the pool by an arbitrary multiple. (Review C-F2.)
    donationUnwoundAt: v.optional(v.number()),
    // Expiry of the pool bucket this order's donation landed in. A UTC day can
    // hold SEVERAL buckets once an admin retunes `donation.bonusWindowDays`
    // (same-day gifts keep their own windows), so the day alone no longer
    // identifies the funding — without this a refund could drain a neighbouring
    // gift's bucket and leave the refunded money live. Absent on orders granted
    // before this field existed; the unwind then falls back to the day.
    donationBucketExpiresAt: v.optional(v.number()),
    updatedAt: v.number(),
  })
    .index('by_opaque_ref', ['opaqueRef'])
    .index('by_processor_ref', ['processor', 'processorRef'])
    .index('by_user', ['userId'])
    .index('by_status', ['status'])
    // Revenue chart: a range scan aligned with the settle time, so the scan
    // cap bounds the SELECTED range instead of silently dropping old ranges
    // once the newest N paid orders no longer reach back that far.
    .index('by_status_paidAt', ['status', 'paidAt'])
    .index('by_gift_reveal_pending', ['giftRevealPending']),

  apiTokens: defineTable({
    name: v.string(),
    tokenHash: v.string(),
    tokenPrefix: v.string(),
    createdByAdminId: v.id('adminUsers'),
    scopes: v.array(v.string()),
    subjectType: v.union(v.literal('service'), v.literal('user')),
    subjectUserId: v.optional(v.id('users')),
    // Registration boundary for `admin:edges:register` (and `admin:servers:manage`)
    // tokens: the backend servers (and optionally node names) the token may act
    // for on the Servers by-name node routes (lib/adminHttp.ts registrationBoundaryOf).
    edgeRegistration: v.optional(
      v.object({
        backendServerIds: v.array(v.id('backendServers')),
        nodeNames: v.optional(v.array(v.string())),
      }),
    ),
    expiresAt: v.optional(v.number()),
    lastUsedAt: v.optional(v.number()),
    revokedAt: v.optional(v.number()),
    updatedAt: v.number(),
  })
    .index('by_token_hash', ['tokenHash'])
    .index('by_creator', ['createdByAdminId'])
    // Purge cascade (lifecycle.deleteInactiveUser) drops a user's subject tokens.
    .index('by_subject_user', ['subjectUserId']),

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
    // Physical location of the nodes this instance manages (one backend per
    // location by convention): a short operator code (`location`, e.g. "MCI")
    // plus a member-facing display label (`locationLabel`, e.g. "Kansas City,
    // MO"). Both optional — an instance without one simply isn't part of the
    // member location picker. Non-secret (projected publicly by code+label).
    location: v.optional(v.string()),
    locationLabel: v.optional(v.string()),
    // Coarse map coordinates for the location (city-level; the label already
    // names the city publicly, so nothing new leaks). Set/cleared together;
    // absent = the location gets no dot on the member map. Validated in the
    // admin mutations (lat -90..90, lng -180..180).
    locationLat: v.optional(v.number()),
    locationLng: v.optional(v.number()),
    isActive: v.boolean(),
    priority: v.number(),
    lastHealthOkAt: v.optional(v.number()),
    lastHealthRttMs: v.optional(v.number()),
    keyCount: v.number(),
    // Optional hard capacity cap: at keyCount >= maxKeys the instance is skipped
    // by pickCandidatesForIssue (all-at-capacity → backend.unavailable). Absent
    // (or null-cleared) = uncapped.
    maxKeys: v.optional(v.number()),
    // Read-only fleet observability, cached by the backend-healthcheck cron so the
    // admin dashboard never makes a live backend call. Best-effort: absent until the
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

  // Per-placement node-load cache for issuance-time node placement. One row per
  // internal mode group (the placement handle), refreshed by the backend-healthcheck
  // cron: `usersOnline` (+ optional realtime bandwidth) aggregated from the
  // mode group's accessible nodes via GET /api/nodes. The least-loaded placement is
  // chosen at issuance. Stats-only, no secrets; pool MEMBERSHIP (which mode groups a
  // mode may use) lives in the appSettings namespace, never here.
  remnawaveNodeStats: defineTable({
    backendServerId: v.id('backendServers'),
    placement: v.string(), // the internal-mode group uuid
    label: v.optional(v.string()),
    usersOnline: v.number(),
    trafficBytesRealtime: v.optional(v.number()),
    online: v.boolean(),
    nodeCount: v.number(),
    // The group's node membership has never been read successfully: nodeCount
    // is a placeholder and mode availability treats the group as unknown.
    nodeCountUnknown: v.optional(v.boolean()),
    lastStatsAt: v.number(),
    updatedAt: v.number(),
  })
    .index('by_placement', ['placement'])
    .index('by_server', ['backendServerId']),

  // ===========================================================================
  // Edges: provider-managed L4 load balancers published in front of
  // REALITY nodes. Design notes: docs/edges.md. Everything below is additive.
  // Secrets live ONLY in relayProviderAccounts.credentials (masked to per-field
  // booleans for the admin) and are never logged or audited.
  // ===========================================================================

  // One cloud or CDN account FCP may provision edges in: a provider plus
  // credentials. WHERE its edges live is a location (`edgeLocations`).
  edgeProviderAccounts: defineTable({
    provider: relayProviderId,
    name: v.string(), // unique (read-check in the create mutation); the IaC key
    credentials: relayProviderCredentials,
    settings: relayProviderSettings,
    defaultTemplateId: v.optional(v.id('edgeTemplates')),
    // The location pickers preselect (the migrated one for an account that
    // had a single fixed location, else the first one added).
    defaultLocationId: v.optional(v.id('edgeLocations')),
    enabled: v.boolean(),
    // A DNS provider's account (capability role `dns`): true = DNS and
    // fronting (it may front member traffic too), false = DNS only. Read only
    // for that role (an edge provider's account always fronts). Absent on a row
    // `migrateDnsFronting` has not reached yet, which reads as DNS only.
    frontsTraffic: v.optional(v.boolean()),
    // When the credentials or locating settings last changed (an edit, not a
    // keep-qualification rotation): auto-trust needs a test AFTER this.
    credentialsChangedAt: v.optional(v.number()),
    // When an account this one depends on (its DNS account) last changed its
    // credentials or settings: a proof or test taken before this was taken
    // through the OLD dependency, so auto-trust needs both AFTER it.
    dependencyChangedAt: v.optional(v.number()),
    priority: v.number(),
    // Allocation limits: provider calls that create billable resources per UTC
    // day (0 = unlimited) and the number of not-yet-destroyed edges.
    dailyAllocationBudget: v.number(),
    allocationsDayKey: v.optional(v.string()),
    allocationsToday: v.number(),
    maxLiveEdges: v.number(),
    lastTestOkAt: v.optional(v.number()),
    lastTestError: v.optional(v.string()), // short code, never a body
    // Redacted, capped excerpt of what the provider answered on the failing test
    // (lib/edges/providers/http.ts redactErrorDetail). Admin display only.
    lastTestErrorDetail: v.optional(v.string()),
    // Facts the credential test OBSERVED at the provider that planning needs but
    // the operator never enters (e.g. a zone's encryption mode). JSON, string
    // values only; frozen per edge into its provisionIntent.
    observedSettings: v.optional(v.string()),
    observedAt: v.optional(v.number()),
    // The account's defaults for its provider's CERTIFICATE options (JSON,
    // lib/edges/providers/options.ts): copied into a node's pick when it is
    // protected, and used live by picks recorded before options existed.
    optionDefaults: v.optional(v.string()),
    // Provider API health (edgeProviderOps `tracked`): consecutive calls that
    // failed for a reason on the provider's side (timeout, network, 5xx,
    // 401/403/429, an answer the adapter cannot read), reset by the first
    // call that succeeds. Attention `account_api_failing` past a few in a row.
    // `lastApiError` is a short code, never a body.
    apiFailures: v.optional(v.number()),
    apiFailingSince: v.optional(v.number()),
    lastApiError: v.optional(v.string()),
    // Legacy: the shared wildcard certificate as it was recorded per account,
    // before an account fronted in several zones. The L7 locations migration
    // moves it onto the location of its zone (`edgeLocations.sharedCertificate`,
    // where `state` is the provider's, or `absent` / `ambiguous`, and `code` a
    // fixed one); a cleanup drops it.
    // Shared provider objects an edge of this account CREATED (`<kind>:<id>`,
    // most recent last, capped): proof that FCP ordered a zone's wildcard, so
    // it alone may be removed from the account page.
    orderedSharedResources: v.optional(v.array(v.string())),
    sharedCertificate: v.optional(
      v.object({
        name: v.string(),
        subscriptionId: v.optional(v.string()),
        state: v.string(),
        code: v.optional(v.string()),
        notAfter: v.optional(v.string()),
        checkedAt: v.number(),
      }),
    ),
    // What the operator says this account costs (docs/edges.md § "Plans and
    // prices"): `paid` = `list` (the provider's list price, a load balancer
    // account only), `free` (free or credits) or `amount` (`perEdgeMonthly` in
    // `currency`, per edge a month). Absent: a load balancer account pays the
    // list price, a CDN account has no price set (never priced on its own).
    // `monthlyCap` (in `currency`): new edges stop once the account's monthly
    // estimate would pass it; absent = no cap (the default).
    cost: v.optional(
      v.object({
        paid: v.union(v.literal('list'), v.literal('free'), v.literal('amount')),
        perEdgeMonthly: v.optional(v.number()),
        currency: v.optional(v.string()),
        note: v.optional(v.string()),
        monthlyCap: v.optional(v.number()),
      }),
    ),
    updatedAt: v.number(),
  })
    .index('by_name', ['name'])
    .index('by_provider_enabled', ['provider', 'enabled', 'priority']),

  // One account's place to create edges in (docs/edges.md § "Provider
  // accounts and locations"): the frozen placement, the provider's own id for
  // the region (`placeKey`, account-agnostic: what per-country grades key on,
  // as `<provider>:<placeKey>`), and the trust taken there. An L7 account has
  // exactly one (`anycast`, an empty placement), created with it.
  edgeLocations: defineTable({
    accountId: v.id('edgeProviderAccounts'),
    provider: relayProviderId,
    placeKey: v.string(),
    placement: relayEdgePlacement,
    // Canonical identity of the placement: creating it again returns this row.
    placementHash: v.string(),
    // The region's name as the provider lists it (admin display only).
    label: v.string(),
    enabled: v.boolean(),
    // Trust (lib/edges/autoQualify.ts, edgeVerification): automatic selection
    // uses trusted locations only. Taken by an operator (the trust override or
    // the first confirmed L4 endpoint here) or by the L7 auto-trust rule,
    // bound to the effective template it was taken with.
    qualified: v.boolean(),
    qualifiedTemplateHash: v.optional(v.string()),
    qualification: v.optional(relayAccountQualification),
    // A manual untrust holds the automatic rules off until an operator
    // trusts again or the account's credentials change.
    autoQualifyHold: v.optional(v.boolean()),
    // The template this location provisions with (else the account's), and
    // its own values of the template's regional fields (JSON, e.g. a flavor).
    defaultTemplateId: v.optional(v.id('edgeTemplates')),
    regionalParams: v.optional(v.string()),
    // The provider's quota in this region (optional; the account cap applies too).
    maxLiveEdges: v.optional(v.number()),
    // Operator text shown next to the location when it is picked (a price).
    costNote: v.optional(v.string()),
    // Last provider inventory pull here (LBs / IPs / flavors), JSON, admin-only.
    inventorySnapshot: v.optional(v.string()),
    inventoryAt: v.optional(v.number()),
    // When this place's plans and prices were last read (`edgePlans`), when a
    // read was last tried, and why the last one failed (a short code; the
    // stored plans stay).
    plansAt: v.optional(v.number()),
    plansTriedAt: v.optional(v.number()),
    plansError: v.optional(v.string()),
    // What the provider said about this place when it was last checked (a
    // CDN zone: its encryption mode, WebSockets, status). JSON, string values
    // only; the encryption mode is frozen into each new edge's intent.
    observed: v.optional(v.string()),
    observedAt: v.optional(v.number()),
    // The last check refused the place (a paused zone, a zone the token can no
    // longer read): no new edge is planned here until a check passes. A short
    // code, plus the provider's redacted answer for the admin.
    checkError: v.optional(v.string()),
    checkErrorDetail: v.optional(v.string()),
    // The wildcard certificate (`*.<zone>`) the account's fronts in this zone
    // share, as the provider last showed it (a front provider that orders one
    // per account and zone). Read by the credential test and the reconcile cron.
    sharedCertificate: v.optional(
      v.object({
        name: v.string(),
        subscriptionId: v.optional(v.string()),
        state: v.string(),
        code: v.optional(v.string()),
        notAfter: v.optional(v.string()),
        checkedAt: v.number(),
      }),
    ),
    createdAt: v.number(),
    updatedAt: v.number(),
  })
    .index('by_account', ['accountId', 'enabled'])
    .index('by_place', ['provider', 'placeKey'])
    .index('by_account_placement', ['accountId', 'placementHash']),

  // What one account's credentials reach at its provider, as last listed
  // (`edgeProviderCatalog.ts`): the zones, regions, projects or TLS
  // configurations the pickers offer. A hint only: every write that takes one
  // asks the provider again. One row per (account, kind); `items` is JSON
  // `[{id, label, facts?}]`, admin-only.
  edgeProviderCatalog: defineTable({
    accountId: v.id('edgeProviderAccounts'),
    kind: v.union(
      v.literal('zones'),
      v.literal('regions'),
      v.literal('projects'),
      v.literal('tlsConfigurations'),
    ),
    items: v.string(),
    // The listing stopped at its cap (more exist than are listed).
    truncated: v.optional(v.boolean()),
    refreshedAt: v.number(),
    // A failed listing keeps the previous items and says why.
    error: v.optional(v.string()),
    errorDetail: v.optional(v.string()),
    errorAt: v.optional(v.number()),
  }).index('by_account_kind', ['accountId', 'kind']),

  // One load balancer plan (size) at one location, as last read
  // (`edgePlans.ts`, docs/edges.md § "Plans and prices"): its list price, its
  // traffic terms and bandwidth, whether it takes a node outside the provider.
  // `source` = `api` (the provider's own price list) or `catalog` (FCP's dated
  // table, `catalogAsOf`). Rows are replaced whole per location on each read;
  // a location has a handful (operator-scale). A CDN account has none.
  edgePlans: defineTable({
    accountId: v.id('edgeProviderAccounts'),
    locationId: v.id('edgeLocations'),
    provider: relayProviderId,
    // The template value (a flavor, plan or type) and its lower-cased key.
    size: v.string(),
    sizeKey: v.string(),
    label: v.string(),
    perHour: v.optional(v.number()),
    perMonth: v.optional(v.number()),
    currency: v.optional(v.string()),
    traffic: edgePlanTraffic,
    bandwidthMbps: v.optional(v.number()),
    // Takes a backend server outside the provider's own cloud (absent = the
    // provider does not say, which every provider but Scaleway means yes).
    acceptsOutsideNode: v.optional(v.boolean()),
    source: v.union(v.literal('api'), v.literal('catalog')),
    catalogAsOf: v.optional(v.string()),
    pricedAt: v.number(),
  })
    .index('by_location_size', ['locationId', 'sizeKey'])
    .index('by_account', ['accountId']),

  // Provisioning parameters for one provider (flavor/plan/type, health monitor,
  // timeouts, allowed CIDRs, tags, IP-family options). `params` is JSON validated
  // by the adapter's templateSchema; placeholders {{name}} {{originAddress}}
  // {{originPort}} {{edgePort}} are substituted at provision time.
  edgeTemplates: defineTable({
    provider: relayProviderId,
    accountId: v.optional(v.id('edgeProviderAccounts')),
    name: v.string(),
    params: v.string(),
    paramsHash: v.string(),
    isDefault: v.boolean(),
    updatedAt: v.number(),
  })
    .index('by_provider', ['provider'])
    .index('by_account', ['accountId']),

  // One origin: an ORIGIN members reach only through edges. `origin` says what
  // kind it is; `backendServerId` / `nodeName` are denormalised copies of the
  // origin's fields for indexing (written only by origins.ts). `originAddress`
  // is what edges dial and is never published.
  relays: defineTable({
    slug: v.string(), // unique; the IaC key
    label: v.optional(v.string()),
    origin: relayOrigin,
    backendServerId: v.optional(v.id('backendServers')),
    nodeName: v.optional(v.string()),
    originAddress: v.string(),
    // Names among the node's Hosts found to resolve to the node, with their
    // answers (its other family): the node too, for the direct-Host hide and
    // every leak check. Kept once found (nodeIntents.nodeAddressesOf).
    nodeAddresses: v.optional(v.array(v.string())),
    locationCode: v.optional(v.string()),
    hostMode: relayHostMode,
    // The only delivery policy today: a subscription pinned to this origin is
    // served a rendered body or an unavailable response, never the origin body.
    delivery: v.literal('edge-required'),
    enabled: v.boolean(),
    autoRotate: v.boolean(),
    providerPreference: v.optional(relayProviderId),
    // The node's provider set: the (account, location) picks its addresses come
    // from. Absent = any trusted location (origins that are not a backend node).
    // Each pick may carry the provider OPTIONS chosen for this node there (JSON:
    // tuning values laid over the location's template, certificate values;
    // lib/edges/providers/options.ts). Absent = a pick from before options:
    // the template and the account's defaults.
    providerSet: v.optional(
      v.array(
        v.object({
          locationId: v.id('edgeLocations'),
          addedAt: v.number(),
          options: v.optional(v.string()),
        }),
      ),
    ),
    // Picks whose address the detector just burned here: no automatic work
    // allocates, provisions or publishes into them until `until`.
    cooling: v.optional(
      v.array(v.object({ locationId: v.id('edgeLocations'), until: v.number() })),
    ),
    // The published-pool size (state: setup runs and re-protect widen it), seeded
    // from `edge.desiredPublishedDefault`.
    desiredPublished: v.number(),
    // Per-origin OVERRIDES of the fleet knobs, one rule for all five
    // (`originPolicy` in lib/edgeConfig.ts): absent = follow `edge.*`.
    standbyPerRelay: v.optional(v.number()),
    // Verified standbys kept per coverage listener.
    standbyPerListener: v.optional(v.number()),
    cooldownMs: v.optional(v.number()),
    maxRotationsPerDay: v.optional(v.number()),
    drainMs: v.optional(v.number()),
    // Bumps on every published-pool / profile / rule change; part of the
    // subscription render cache key.
    publicationEpoch: v.number(),
    // Published edges by pool index (a gap is a null); assignments hash into it.
    publishedEdgeIds: v.array(v.union(v.id('edges'), v.null())),
    standbyEdgeIds: v.array(v.id('edges')),
    activeRotationId: v.optional(v.id('edgeRotations')),
    cooldownUntil: v.optional(v.number()),
    rotationsDayKey: v.optional(v.string()),
    rotationsToday: v.number(),
    // L7 replacements that went to the SAME provider today. Minting another CDN
    // hostname does not guarantee a different frontend IP, so repeated
    // same-provider replacements are bounded (edge.l7.maxSameProviderReplacementsPerDay).
    l7ReplacementsDayKey: v.optional(v.string()),
    l7ReplacementsToday: v.optional(v.number()),
    lastRotatedAt: v.optional(v.number()),
    // A rotation whose rollback could not converge parks the origin here; nothing
    // bypasses it (resolveQuarantine is the only exit).
    quarantine: v.optional(
      v.object({ rotationId: v.id('edgeRotations'), since: v.number(), reason: v.string() }),
    ),
    deleting: v.optional(v.boolean()),
    // Guided setup: the delivery binding is claimed at go-live, not at insert
    // (`claimDeliveryBinding`); until then the origin serves its raw body.
    bindingDeferred: v.optional(v.boolean()),
    // A setup run owns this origin: reconcile upkeep and the detector's automatic
    // replacement skip it until the run clears the flag (independent of the run's state).
    setupOwned: v.optional(v.boolean()),
    // A node rename is moving this origin's node name and Host remarks
    // (backendNodeRenames.ts): every pool, edge and listener write waits
    // (`edge.panel_op_running`, the same guard as a server change's claim).
    renaming: v.optional(v.object({ renameId: v.id('panelNodeRenames'), since: v.number() })),
    // Member cohorts the operator knowingly left without protected delivery
    // (their whole body went with the consented hides): stamped at go-live, or
    // from the run's rehearsal when a restore cancels a setup. The ONE copy the
    // restore workflow's raw-body checks read; without it the origin could
    // never release its binding or be removed.
    darkCohortKeys: v.optional(v.array(v.string())),
    // The stage the setup run recorded last (informational; the run machine is a later release).
    setupStage: v.optional(v.string()),
    // The persisted RESTORE workflow (convex/edgeRestore.ts): hides settled,
    // the binding released with the origin enabled, direct Hosts re-enabled,
    // then the purpose's finish. Present = in progress; a second workflow and
    // every new direct-Host hide are refused (`edge.restore_in_progress`).
    restore: v.optional(
      v.object({
        purpose: v.union(
          v.literal('cancel_setup'),
          v.literal('release_requirement'),
          v.literal('delete_relay'),
        ),
        phase: v.union(
          v.literal('freeze'),
          v.literal('settle'),
          v.literal('verify_fcp_raw'),
          v.literal('release_binding'),
          v.literal('restore'),
          v.literal('verify_direct'),
          v.literal('finish'),
        ),
        startedAt: v.number(),
        updatedAt: v.number(),
        // Passes of the current phase that could not advance it (bounded per phase).
        attempt: v.number(),
        lastError: v.optional(v.string()),
        // `delete_relay`: what the deletion body runs with once phase 7 is reached.
        force: v.optional(v.boolean()),
        actorAdminId: v.optional(v.id('adminUsers')),
      }),
    ),
    // Direct Hosts (enabled, dialling the origin itself) the reconcile pass saw on
    // a BOUND guided origin and could neither cover nor re-hide: attention
    // `direct_host_reappeared`. Cleared when a pass sees none.
    directHostAlert: v.optional(
      v.object({
        at: v.number(),
        hosts: v.array(
          v.object({
            uuid: v.string(),
            remark: v.string(),
            inboundUuid: v.union(v.string(), v.null()),
          }),
        ),
      }),
    ),
    // Block-detector state (convex/edgeDetector.ts).
    suspicion: v.optional(
      v.object({
        state: v.union(v.literal('clear'), v.literal('suspected')),
        hintLevel: v.union(
          v.literal('none'),
          v.literal('reports'),
          v.literal('probes'),
          v.literal('corroborated'),
        ),
        score: v.number(),
        reportScore: v.number(),
        loadScore: v.number(),
        probeScore: v.number(),
        scope: v.union(v.literal('global'), v.literal('regional'), v.null()),
        countries: v.array(v.object({ code: v.string(), count: v.number() })),
        edgeEvidence: v.array(
          v.object({
            edgeId: v.id('edges'),
            source: v.union(v.literal('reports'), v.literal('probes')),
            countries: v.array(v.string()),
          }),
        ),
        firstSeenAt: v.union(v.number(), v.null()),
        lastEvalAt: v.number(),
        quietEvals: v.number(),
        baselineWarm: v.boolean(),
        veto: v.union(v.string(), v.null()),
        hint: v.optional(v.string()),
        lastRotateError: v.optional(v.string()),
        // Test block evidence (convex/edgeSimulations.ts) took part in this
        // evaluation: a simulated block on a test deployment, never a real one.
        simulated: v.optional(v.boolean()),
      }),
    ),
    driftHash: v.optional(v.string()),
    // Probe the node's own address too (a direct block signal, operator evidence only).
    probeNode: v.optional(v.boolean()),
    reachability: v.optional(probeReachabilitySummary),
    // The backend account the L7 front qualification authenticates with (minted
    // by FCP through the backend provider on the origin's placement; a member-
    // shaped credential so the proof travels a member's path).
    qualificationUserId: v.optional(v.string()),
    // The same credential's Trojan password (a Trojan transport's L7 proof
    // authenticates with it). Never returned by any admin read, like the id.
    qualificationTrojanPassword: v.optional(v.string()),
    // The backend user behind that credential (the stored backendUserId form), so
    // it can be deactivated when the origin goes or the credential is re-minted.
    qualificationBackendUserId: v.optional(v.string()),
    // Backend users whose deactivation failed transiently (a replaced or revoked
    // credential): retried on the next mint/revoke and on origin delete, so a
    // capped account is never silently orphaned.
    qualificationRemovalPending: v.optional(v.array(v.string())),
    // The connection mode the L7 qualification credential was minted on.
    qualificationModeSlug: v.optional(v.string()),
    // The qualification credential as a PERSISTED OPERATION
    // (relayQualification.ensure): written BEFORE any backend call with the
    // deterministic username the backend user is re-found by, and the binding
    // {backendServerId, placement, modeSlug} the credential covers once stored.
    // A credential is reused only when the requested binding equals this one.
    qualificationMint: v.optional(
      v.object({
        opId: v.string(),
        username: v.string(),
        backendServerId: v.id('backendServers'),
        placement: v.union(v.string(), v.null()),
        modeSlug: v.union(v.string(), v.null()),
        state: v.union(
          v.literal('intended'),
          v.literal('issued'),
          v.literal('stored'),
          v.literal('unresolved'),
        ),
        claimedAt: v.number(),
        // Quiet by-username looks since the claim (the settle rule before a re-issue).
        looks: v.optional(v.number()),
      }),
    ),
    // The credential's own subscription (short id + backend URL): what the test
    // link and the empty-node rehearsal fetch. Never the credential itself.
    qualificationSubscription: v.optional(
      v.object({ backendShortId: v.string(), subscriptionUrl: v.string() }),
    ),
    // Stamped by every by-slug registration, changed or not (the role heartbeat).
    lastRegisteredAt: v.optional(v.number()),
    updatedAt: v.number(),
  })
    .index('by_slug', ['slug'])
    .index('by_backend_server', ['backendServerId'])
    .index('by_node', ['backendServerId', 'nodeName'])
    .index('by_enabled', ['enabled']),

  // Temporary test credentials (docs/edges.md § "Publication", the test link):
  // a durable obligation to remove a backend user FCP minted for a test. The
  // row is written BEFORE `issueUser` (`backendUserId` absent until issuance is
  // observed) and settled by the reconcile sweep independently of any setup
  // run: expired or released rows go through `deleteUser` with bounded
  // retries; a delete that keeps failing is surfaced as attention
  // `test_key_cleanup`. Remnawave tests reuse the origin's qualification user
  // and write no row here; Outline has no name lookup, so its temporary keys
  // live here.
  edgeTestCredentials: defineTable({
    // The owner: an origin (the test link and rehearsal of a fronted origin) or
    // a node intent (the isolated direct link of a node being activated,
    // docs/servers.md "Node lifecycle"). Exactly one is set.
    relayId: v.optional(v.id('relays')),
    nodeIntentId: v.optional(v.id('panelNodeIntents')),
    backendServerId: v.id('backendServers'),
    backend: backendId,
    username: v.string(),
    backendUserId: v.optional(v.string()),
    backendShortId: v.optional(v.string()),
    subscriptionUrl: v.optional(v.string()),
    purpose: v.union(v.literal('rehearsal'), v.literal('test_link')),
    expiresAt: v.number(),
    removal: v.union(v.literal('pending'), v.literal('done'), v.literal('failed')),
    attempts: v.number(),
    // Set when a delete attempt failed: the sweep waits for the backoff.
    retryAfter: v.optional(v.number()),
    updatedAt: v.number(),
  })
    .index('by_relay', ['relayId'])
    .index('by_intent', ['nodeIntentId'])
    .index('by_removal_expires', ['removal', 'expiresAt']),

  // One LISTENER on an origin: a port the origin answers on, what it speaks,
  // the names / REALITY target the renderer needs, how the renderer finds its
  // entry in a subscription body, and (backend origins) the transport it maps to
  // plus the backend Host FCP owns for it. Edges bind to one listener; their
  // provider listener forwards edgePort -> originPort.
  relayListeners: defineTable({
    relayId: v.id('relays'),
    listenerKey: v.string(), // [a-z0-9]{1,16}; the role's key
    ...listenerProtoFields,
    // Copied from the catalogue at write time (indexable; probes skip udp).
    transport: v.union(v.literal('tcp'), v.literal('udp')),
    originPort: v.number(),
    // Server names (REALITY SNIs / certificate names). APPEND-ONLY order: a
    // stored name keeps its index and new names are appended, never re-sorted
    // (the legacy SNI selection is index-based).
    tlsNames: v.optional(v.array(listenerName)),
    // How one name is chosen per subscriber. Absent = the legacy modulus PRF
    // (stable under retirement, reshuffles on growth); `hrw1` = rendezvous
    // hashing, stable under growth too. Set explicitly per listener.
    sniPick: v.optional(v.literal('hrw1')),
    // Bumped by a name change that does NOT invalidate what an operator's
    // endpoint test proved (today: retiring a REALITY name). Every other
    // name change is a `revision` bump. See lib/edges/verification.ts.
    namesRevision: v.optional(v.number()),
    realityTarget: v.optional(v.object({ address: v.string(), port: v.number() })),
    // HTTP-transport parameters as deployed (path + upgrade token for
    // ws/httpupgrade, service name for grpc, path + mode for xhttp): what the
    // front qualification must send. A qualification binds to their hash.
    transportParams: v.optional(
      v.object({
        path: v.optional(v.string()),
        host: v.optional(v.string()),
        serviceName: v.optional(v.string()),
        upgradeToken: v.optional(v.string()),
        mode: v.optional(v.string()),
      }),
    ),
    // How the transport is reached behind an L7 front (lib/edges/layers.ts).
    originTransport: v.optional(relaySlotOriginTransport),
    // Only edges of this provider (account) may front the listener.
    providerScope: v.optional(
      v.object({ provider: relayProviderId, accountId: v.optional(v.id('edgeProviderAccounts')) }),
    ),
    matchRule: listenerMatchRule,
    // Backend origins: the transport this listener is (the node role deploys it).
    panelBinding: v.optional(
      v.object({
        inboundTag: v.string(),
        configProfileUuid: v.string(),
        configProfileInboundUuid: v.string(),
      }),
    ),
    host: v.optional(listenerHost),
    // Remarks this listener's Host carried before its node was renamed: the
    // renderer keeps matching them, so a body fetched before the Host changed
    // (or a cached one) still resolves.
    formerRemarks: v.optional(v.array(v.string())),
    // Legacy Hosts adopted from a manual deployment (never deleted by FCP).
    legacyHosts: v.optional(
      v.array(v.object({ uuid: v.string(), remark: v.string(), sni: v.optional(v.string()) })),
    ),
    // The published edge this listener's Host / plans point at (lowest pool
    // index among the edges bound to it); absent = listener unavailable.
    templateEdgeId: v.optional(v.id('edges')),
    // Who owns the row: the node role (pruned by its registration) or an admin.
    source: v.union(v.literal('role'), v.literal('admin')),
    // Canonical configuration hash (registration idempotency).
    configHash: v.string(),
    enabled: v.boolean(),
    deployed: v.boolean(),
    deployedAt: v.optional(v.number()),
    retired: v.boolean(),
    // Bumped on every MATERIAL write; a front qualification binds to it.
    revision: v.number(),
    updatedAt: v.number(),
  })
    .index('by_relay', ['relayId'])
    .index('by_relay_key', ['relayId', 'listenerKey']),

  // One provider load balancer. `steps` is the provisioning plan; `resources` the
  // ledger of EVERY child resource a step created (compound steps record all of
  // them, partial results included). An edge is discoverable (the reconcile cron
  // must settle it) whenever it has an open currentOp or a step still
  // requested/unresolved, whatever its status.
  edges: defineTable({
    relayId: v.id('relays'),
    listenerId: v.id('relayListeners'),
    accountId: v.optional(v.id('edgeProviderAccounts')),
    // The location the edge was created in, FROZEN at plan time with a copy of
    // its placement: every step, describe, discovery and destroy acts in the
    // edge's own region, whatever the location row or the account say later.
    // `placeKey` is denormalised for the per-place reads (`<provider>:<placeKey>`).
    locationId: v.optional(v.id('edgeLocations')),
    placeKey: v.optional(v.string()),
    placement: v.optional(relayEdgePlacement),
    templateId: v.optional(v.id('edgeTemplates')),
    // The hash of what the edge was built with: the location's effective
    // template, with the node's tuning choices laid over it when it had any.
    templateHash: v.optional(v.string()),
    // With choices: the location's own effective template hash at plan time
    // (what a template edit is detected against, and what trust evidence
    // compares), and the node's choices themselves (JSON), frozen.
    baseTemplateHash: v.optional(v.string()),
    choices: v.optional(v.string()),
    // The load balancer size it was built with (the effective template's
    // flavor, plan or type), frozen: what its monthly cost is read for
    // (`edgePlans`). Absent on an edge from before, or a CDN front.
    planSize: v.optional(v.string()),
    // An address family a describe reported after the endpoint was confirmed:
    // held here, not served and not in the confirmation's hash, until a test
    // of that address promotes it into `addresses` (edgeVerification.confirm).
    learnedAddresses: v.optional(
      v.object({ v4: v.optional(v.string()), v6: v.optional(v.string()) }),
    ),
    provider: v.optional(relayProviderId),
    managed: v.boolean(), // false = adopted, observe-only, never destroyed
    name: v.string(), // provider-side resource name; the discovery key
    steps: v.array(
      v.object({
        stepId: v.string(),
        kind: v.string(),
        resourceName: v.string(),
        // How the adapter can re-find this resource after an unknown outcome.
        discoverability: v.optional(
          v.union(v.literal('by_name'), v.literal('by_tag'), v.literal('none')),
        ),
        state: relayStepState,
        opRef: v.optional(v.string()),
        attempt: v.number(),
        // Consecutive `unresolved` discovery passes for this step (adapters
        // need ≥2 quiet looks before `confirmed_absent`); reset when settled.
        discoverAttempts: v.optional(v.number()),
        startedAt: v.optional(v.number()),
        finishedAt: v.optional(v.number()),
      }),
    ),
    resources: v.array(
      v.object({
        stepId: v.string(),
        kind: v.string(),
        resourceId: v.string(),
        ownership: v.union(v.literal('created'), v.literal('adopted')),
        deleteState: relayDeleteState,
        meta: v.optional(v.string()),
      }),
    ),
    currentOp: v.optional(relayEdgeOp),
    listeners: v.array(
      v.object({
        edgePort: v.number(),
        originAddress: v.string(),
        originPort: v.number(),
        // Absent = tcp (every adapter forwards TCP; udp is reserved for future protocols).
        transport: v.optional(v.union(v.literal('tcp'), v.literal('udp'))),
      }),
    ),
    // L4: IP literals. L7: the fronted hostname (what members connect to).
    addresses: v.object({
      v4: v.optional(v.string()),
      v6: v.optional(v.string()),
      hostname: v.optional(v.string()),
    }),
    layer: v.optional(relayEdgeLayer),
    // L7: everything a step, discovery, describe or destroy needs, FROZEN when
    // the edge is planned (JSON, lib/edges/intent.ts). Account settings and
    // templates may change afterwards without moving this edge.
    provisionIntent: v.optional(v.string()),
    // L7 readiness dimensions (DNS record, certificate, the front end to end).
    readiness: v.optional(
      v.object({
        dns: relayReadinessState,
        certificate: relayReadinessState,
        front: relayReadinessState,
        checkedAt: v.number(),
      }),
    ),
    // L7: the authenticated end-to-end test session through the front, bound to
    // the exact configuration it proved (lib/edges/frontCheck). Publication
    // re-derives the binding and refuses on mismatch or expiry.
    frontQualification: v.optional(
      v.object({
        ok: v.boolean(),
        code: v.optional(v.string()),
        checkedAt: v.number(),
        expiresAt: v.number(),
        binding: v.object({
          hostname: v.string(),
          listenerId: v.id('relayListeners'),
          listenerRevision: v.number(),
          ...listenerProtoFields,
          transportParamsHash: v.string(),
          intentHash: v.string(),
        }),
        affectedCountries: v.optional(
          v.array(v.object({ country: v.string(), verdict: relayReachVerdict, at: v.number() })),
        ),
      }),
    ),
    // L4: the operator's per-endpoint confirmation, bound to the listener
    // revision + configuration hash it was taken against. The publication gate
    // (origins.checkPublishable) refuses an L4 edge without a CURRENT one.
    verification: v.optional(relayEdgeVerification),
    // Fastly shared-service teardown (an adopted domain on a service FCP does
    // not own): the persisted version workflow, serialized per service.
    sharedTeardown: v.optional(
      v.object({
        // The adapter's own workflow phase (Fastly: clone → remove_domain →
        // validate → activate → confirm), plus the terminal `done` /
        // `needs_operator`. A string, not a union: the phase vocabulary belongs
        // to the driver, and reconcile only ever compares the terminal two.
        phase: v.string(),
        serviceId: v.string(),
        fromVersion: v.number(),
        workVersion: v.optional(v.number()),
        opId: v.optional(v.string()),
        attempts: v.number(),
      }),
    ),
    // The driver's own extra fields for that workflow (adapter-shaped: a code,
    // a marker, whatever the next phase needs), JSON, so the persisted state can
    // carry more than the columns above without a schema change per adapter.
    sharedTeardownState: v.optional(v.string()),
    publication: relayPublication,
    poolIndex: v.optional(v.number()),
    publishedAt: v.optional(v.number()),
    status: relayEdgeStatus,
    statusChangedAt: v.number(),
    health: relayHealth,
    lastHealthAt: v.optional(v.number()),
    liveSnapshot: v.optional(v.string()), // JSON from the adapter's inspect(); cleared on destroy
    liveAt: v.optional(v.number()),
    reachability: v.optional(probeReachabilitySummary),
    // Per-country checks (edgeCountry.ts): the effective state per checked country.
    countryState: v.optional(edgeCountryStateV),
    destroyAttempts: v.number(),
    // Consecutive `gone` describes (reset by any other state). The pool drop +
    // status transition need TWO so an auth-shaped 404 or one blip cannot act.
    goneObservations: v.optional(v.number()),
    // Consecutive `active` describes that OMITTED a previously known address.
    // Dropping an address stops rendering it, so it needs the same two
    // observations a `gone` transition does (one truncated answer is not proof).
    addressLossObservations: v.optional(v.number()),
    // Consecutive `unresolved` confirmDestroyed passes for the resource the
    // destroy walk is currently on; past the cap the idempotent delete is re-issued.
    destroyConfirm: v.optional(v.object({ resourceId: v.string(), attempts: v.number() })),
    // Why the edge stopped. `detail`: the provider's own words on the refusal,
    // redacted and scrubbed of the edge's names (edgeProviderOps toOpsFailure);
    // admin display only, never a log line or an audit row.
    failure: v.optional(
      v.object({
        step: v.string(),
        code: v.optional(v.string()),
        status: v.optional(v.number()),
        detail: v.optional(v.string()),
      }),
    ),
    // What a requested step is held up by while it waits, when the provider
    // says (L7: a CAA record, the validation record; `L7_CERTIFICATE_CODES`),
    // since when. Cleared when the step settles any other way.
    waiting: v.optional(v.object({ step: v.string(), code: v.string(), since: v.number() })),
    burnedAt: v.optional(v.number()),
    drainUntil: v.optional(v.number()),
    destroyedAt: v.optional(v.number()),
    updatedAt: v.number(),
  })
    .index('by_relay_status', ['relayId', 'status'])
    .index('by_relay_publication', ['relayId', 'publication'])
    .index('by_status', ['status', 'statusChangedAt'])
    .index('by_account_status', ['accountId', 'status'])
    .index('by_location_status', ['locationId', 'status'])
    .index('by_name', ['name']),

  // The rotation ledger + saga state. Advanced ONLY through edgeRotations.advance
  // (step version) and the claimOp/settleOp pair (external writes). Control flow
  // reads the explicit row fields below, never the bounded `events[]` log
  // (display-only); rows created before those fields existed fall back to the
  // event inference in edgeRotations.ts.
  edgeRotations: defineTable({
    relayId: v.id('relays'),
    kind: v.union(v.literal('provision'), v.literal('publish'), v.literal('replace')),
    trigger: v.union(
      v.literal('manual'),
      v.literal('detector'),
      v.literal('api'),
      v.literal('reconcile'),
    ),
    burn: v.boolean(),
    force: v.boolean(),
    // An operator waived the affected-country evidence gate for this run (and
    // ONLY that gate: the transport proof, TLS chain, ownership, layer and
    // configuration-binding checks all still apply). Audited at the request.
    forceGeoEvidence: v.optional(v.boolean()),
    // provision kind: publish the new edge when it verifies (bootstrap / pool fill).
    publishOnDone: v.optional(v.boolean()),
    targetEdgeId: v.optional(v.id('edges')), // the edge being replaced
    toEdgeId: v.optional(v.id('edges')),
    phase: relayRotationPhase,
    stepVersion: v.number(),
    cancelRequested: v.boolean(),
    currentOp: v.optional(relayHostOp),
    outcome: v.optional(v.string()),
    reason: v.optional(v.string()),
    // The listener the operator asked for (provision) / the target's listener
    // (replace, publish). A retired or missing listener FAILS the run.
    listenerId: v.optional(v.id('relayListeners')),
    // The explicit bootstrap provision (`test-provision`): the account and
    // template the operator named, and whether an UNQUALIFIED account is
    // admitted (only this path may say yes; the result is never published).
    requestedAccountId: v.optional(v.id('edgeProviderAccounts')),
    requestedTemplateId: v.optional(v.id('edgeTemplates')),
    allowUnqualified: v.optional(v.boolean()),
    // The location an explicit provision asks for (its account is
    // `requestedAccountId`); a setup run's terminal hook matches its target on it.
    requestedLocationId: v.optional(v.id('edgeLocations')),
    // A replace's explicit spare (the operator named it).
    requestedSpareEdgeId: v.optional(v.id('edges')),
    // Options for the one edge this run builds (JSON), instead of its pick's:
    // an operator's "options for this address" on a spare or a replacement.
    requestedOptions: v.optional(v.string()),
    // A DETECTOR start: the countries its evidence named for the target, taken
    // from the evaluation that started it. The L7 replacement gate and the
    // confirming re-check prove the new front against these, never against the
    // origin's live suspicion (which later passes rewrite). Absent on a row
    // written before the snapshot existed (the gate then reads the suspicion).
    affectedCountries: v.optional(v.array(v.string())),
    // The test block (edgeBlockSimulations) this detector start answered, consumed
    // in the same transaction that created the row.
    simulationId: v.optional(v.id('edgeBlockSimulations')),
    // The guided setup run that started this rotation, with the run GENERATION
    // it was started under: the terminal hook reports this stored generation,
    // never the run's current one, so a retried run ignores the old rotation.
    setupRun: v.optional(v.object({ runId: v.id('edgeSetupRuns'), generation: v.number() })),
    // Selection outcome: the new edge came from an existing standby (true) or was
    // provisioned by this run (`createdEdgeId`, the only edge a failure may mark).
    viaStandby: v.optional(v.boolean()),
    createdEdgeId: v.optional(v.id('edges')),
    // The Host plan was captured from the live list (an empty plan is then final).
    hostPlanCaptured: v.optional(v.boolean()),
    // A forward Host PATCH was CLAIMED (set in the same mutation as the claim): the
    // backend may hold the new address even without a settle, so the rollback must
    // re-observe instead of taking the "nothing written" shortcut.
    forwardWriteAttempted: v.optional(v.boolean()),
    // Unexpected throws in the step action (bounded; past the cap the run fails).
    stepErrors: v.optional(v.number()),
    // When the current step's action began (stale detection: scheduled-not-started
    // vs started-too-long-ago).
    stepStartedAt: v.optional(v.number()),
    // Every audit row this run produced (bounded), so the trail is complete.
    auditIds: v.optional(v.array(v.id('auditLog'))),
    // Per LISTENER: only the listeners whose template edge is the one being
    // replaced are planned, flipped and rolled back.
    hostPlan: v.array(
      v.object({
        listenerKey: v.optional(v.string()),
        uuid: v.string(),
        oldAddress: v.string(),
        oldPort: v.number(),
        inboundUuid: v.optional(v.string()),
        // Snapshot version 2 also captured the Host's SNI and Host header, so
        // the flip/rollback write the FULL tuple. Absent = a legacy plan whose
        // historical SNI/Host are UNKNOWN (not null): rollback restores
        // address/port only and never clears operator configuration.
        snapshotVersion: v.optional(v.number()),
        oldSni: v.optional(v.union(v.string(), v.null())),
        oldHost: v.optional(v.union(v.string(), v.null())),
      }),
    ),
    // The complete binding before a replace, for a complete rollback.
    previousBinding: v.optional(
      v.object({
        edgeId: v.id('edges'),
        listenerId: v.id('relayListeners'),
        poolIndex: v.number(),
      }),
    ),
    flipAttempts: v.number(),
    rollbackAttempts: v.number(),
    pollAttempts: v.number(),
    nextStepAt: v.optional(v.number()),
    // Bounded live log for the admin progress view.
    events: v.array(
      v.object({
        at: v.number(),
        level: v.union(v.literal('info'), v.literal('warn'), v.literal('error')),
        code: v.string(),
        detail: v.optional(v.string()),
      }),
    ),
    actorAdminId: v.optional(v.id('adminUsers')),
    startedAt: v.number(),
    provisionedAt: v.optional(v.number()),
    flippedAt: v.optional(v.number()),
    finishedAt: v.optional(v.number()),
    updatedAt: v.number(),
  })
    .index('by_relay', ['relayId', 'startedAt'])
    .index('by_phase', ['phase', 'nextStepAt'])
    // Retention: terminal rows by finish time.
    .index('by_phase_finished', ['phase', 'finishedAt']),

  // One guided setup ("Autopilot") run: protect a backend node with edges by
  // walking the stage machine in convex/edgeSetupRuns.ts (docs/edges.md
  // § "Guided setup runs"). One non-terminal run per origin; the origin it
  // creates stays `setupOwned` until go-live. Control flow reads the row
  // fields (`stage`, `state`, `expect`, `listeners[]`), never `events[]`.
  edgeSetupRuns: defineTable({
    relayId: v.optional(v.id('relays')),
    relaySlug: v.string(),
    backendServerId: v.id('backendServers'),
    nodeName: v.string(),
    nodeUuid: v.string(),
    // The (account, location) picks the run creates addresses in.
    picks: v.optional(
      v.array(
        v.object({
          locationId: v.id('edgeLocations'),
          accountId: v.id('edgeProviderAccounts'),
          // The options chosen for this pick (JSON), recorded on the set at go-live.
          options: v.optional(v.string()),
        }),
      ),
    ),
    // The plan snapshot (JSON, edgeSetupPlan.ts) + its hash and the consent revision.
    plan: v.string(),
    planHash: v.string(),
    planRevision: v.number(),
    // The EXACT uncovered direct-Host uuids the operator approved for hiding.
    approvedHideUuids: v.array(v.string()),
    // "Keep those members on the direct address": finish unbound after publish.
    keepDirect: v.optional(v.boolean()),
    // Absent = a first protection. `reprotect`: a live, bound node protected
    // again; members keep the committed delivery, a cancel drops only the
    // run's own candidates, a failure leaves the node live (docs/edges.md).
    kind: v.optional(v.literal('reprotect')),
    stage: setupRunStage,
    state: setupRunState,
    // `providerAnswer`: the provider's redacted words on the refused create that
    // ended the run (from the edge's `failure.detail`), admin display only.
    need: v.optional(
      v.object({
        code: v.string(),
        detail: v.optional(v.string()),
        providerAnswer: v.optional(v.string()),
      }),
    ),
    // Bumped by retry / continue: the terminal hook of a rotation started under
    // an older generation is a no-op.
    generation: v.number(),
    // Fences the step action (bumped on every transition and re-kick).
    stepVersion: v.number(),
    // The rotation whose terminal outcome the run is waiting for.
    expect: v.optional(v.object({ rotationId: v.id('edgeRotations'), generation: v.number() })),
    // The enrolled node's activation run this run publishes for, set by the
    // node's approval and never changed by a retry or a resume (ownership; the
    // generation above is only the attempt fence). docs/servers.md "Node lifecycle".
    activationRunId: v.optional(v.id('panelActivationRuns')),
    listeners: v.array(
      v.object({
        listenerKey: v.string(),
        // The pick this entry's address is created in (absent = the run's one pick).
        locationId: v.optional(v.id('edgeLocations')),
        layer: v.union(v.literal('l4'), v.literal('l7')),
        edgeId: v.optional(v.id('edges')),
        verify: setupRunVerify,
        published: v.boolean(),
        probeRequestedAt: v.optional(v.number()),
        proofRequestedAt: v.optional(v.number()),
        // A fresh outside check ("Check again", or after `reappliedEdgeId`):
        // only evidence from this time on counts for the address.
        recheckSince: v.optional(v.number()),
        // The address whose configuration stage 4 saved again, once, when its
        // outside check found it unreachable (EdgeProvider.reapply).
        reappliedEdgeId: v.optional(v.id('edges')),
        // Families of the address no outside source could test when stage 4
        // passed it (the run card's "not checked from outside over IPv6").
        notChecked: v.optional(v.array(v.union(v.literal(4), v.literal(6)))),
      }),
    ),
    // The isolated test links shown for the `try_it` card (one per L4 endpoint).
    testLinks: v.optional(
      v.array(
        v.object({
          edgeId: v.id('edges'),
          listenerKey: v.string(),
          link: v.string(),
          format: v.string(),
          method: v.union(v.literal('test_link'), v.literal('named_connection')),
          binding: v.object({
            endpoint: v.string(),
            listenerRevision: v.number(),
            configHash: v.string(),
            issuedAt: v.number(),
          }),
        }),
      ),
    ),
    testedEndpoints: v.optional(
      v.array(
        v.object({
          edgeId: v.id('edges'),
          listenerKey: v.string(),
          endpoint: v.string(),
          at: v.number(),
        }),
      ),
    ),
    // Uncovered direct Hosts found at stage 6 that the consent did not name.
    reviewDelta: v.optional(v.array(v.object({ uuid: v.string(), remark: v.string() }))),
    // Stage 7's result: the version vector + the final Host observation stage 8 compares.
    rehearsal: v.optional(
      v.object({
        at: v.number(),
        attempts: v.number(),
        vector: v.object({
          listenerRevisions: v.record(v.string(), v.number()),
          renderConfigHash: v.string(),
          publicationEpoch: v.number(),
          qualificationEvidenceIds: v.array(v.string()),
          // The activation candidate the rehearsal rendered (an enrolled node):
          // a later approval is a new candidate an old rehearsal cannot satisfy.
          activation: v.optional(
            v.union(
              v.null(),
              v.object({
                runId: v.string(),
                machineRevision: v.number(),
                configRevision: v.string(),
                authRevision: v.union(v.string(), v.null()),
                deliveryRevision: v.string(),
              }),
            ),
          ),
        }),
        hostsObservation: v.object({ at: v.number(), version: v.number(), hash: v.string() }),
        darkCohortKeys: v.array(v.string()),
      }),
    ),
    stageEnteredAt: v.number(),
    stepStartedAt: v.optional(v.number()),
    nextStepAt: v.optional(v.number()),
    // When the current attempt began (a retry starts a new one); absent = the
    // first attempt, which began at `startedAt`.
    attemptStartedAt: v.optional(v.number()),
    // Bounded live log for the progress view (display only).
    events: v.array(
      v.object({
        at: v.number(),
        level: v.union(v.literal('info'), v.literal('warn'), v.literal('error')),
        code: v.string(),
        detail: v.optional(v.string()),
      }),
    ),
    actorAdminId: v.optional(v.id('adminUsers')),
    startedAt: v.number(),
    finishedAt: v.optional(v.number()),
    updatedAt: v.number(),
  })
    .index('by_state', ['state', 'updatedAt'])
    .index('by_relay', ['relayId'])
    .index('by_origin', ['backendServerId', 'nodeName']),

  // Claims on EXTERNAL resources shared by several edges (a Cloudflare zone's
  // ruleset, a Fastly service's version chain). `claimOp` locks one edge; this
  // locks the shared thing. An expired, unsettled lock blocks further writes
  // until the holder re-observes the outcome (same rule as `currentOp`).
  externalLocks: defineTable({
    key: v.string(), // e.g. "cloudflare-zone:<zoneId>", "fastly-service:<serviceId>"
    // An edge's step holds it, or an account-level action (removing an
    // account's shared certificate) does: exactly one of the two.
    holderEdgeId: v.optional(v.id('edges')),
    holderAccountId: v.optional(v.id('edgeProviderAccounts')),
    opId: v.string(),
    claimedAt: v.number(),
    expiresAt: v.number(),
  }).index('by_key', ['key']),

  // The DELIVERY policy an origin imposes on the subscriptions of its node /
  // backend server, kept apart from the origin row so deleting the origin never
  // silently restores raw delivery: a final delete must carry a disposition
  // (`restore-direct` releases the binding, `keep-dark` keeps members at 503
  // until another origin claims the node). `policyVersion` is part of the sub
  // cache key. Absent `nodeName` = the whole backend server.
  edgeDeliveryBindings: defineTable({
    backendServerId: v.id('backendServers'),
    nodeName: v.optional(v.string()),
    policy: v.literal('edge-required'),
    policyVersion: v.number(),
    relaySlug: v.string(),
    state: v.union(v.literal('active'), v.literal('released')),
    updatedAt: v.number(),
  })
    .index('by_server_node', ['backendServerId', 'nodeName'])
    .index('by_server', ['backendServerId']),

  // The direct-Host hide LEDGER (docs/edges.md § "Direct-Host hides and the
  // restore workflow"): one row per backend Host FCP disables (intent `disable`)
  // or re-enables (intent `restore`) on a guided origin's node, written BEFORE
  // the backend call with the tuple that was observed. A row that holds an
  // `opId` is possibly written and is settled only by observation: disabled =
  // `confirmed`, gone = `released`, still enabled = `unresolved` until the
  // settle floor and two quiet looks have passed since the lease expired. A
  // lease expiry alone never releases or reverses anything.
  edgeHostHides: defineTable({
    relayId: v.id('relays'),
    // The setup run that asked for the hide (its id as a string; absent for a
    // reconcile re-hide).
    runId: v.optional(v.string()),
    backendServerId: v.id('backendServers'),
    hostUuid: v.string(),
    observed: v.object({
      remark: v.string(),
      address: v.string(),
      port: v.number(),
      sni: v.union(v.string(), v.null()),
      host: v.union(v.string(), v.null()),
      inboundUuid: v.union(v.string(), v.null()),
      isDisabled: v.boolean(),
    }),
    intent: v.union(v.literal('disable'), v.literal('restore')),
    state: v.union(
      v.literal('intended'),
      v.literal('written'),
      v.literal('confirmed'),
      v.literal('unresolved'),
      v.literal('released'),
    ),
    opId: v.optional(v.string()),
    attempt: v.number(),
    claimedAt: v.optional(v.number()),
    expiresAt: v.optional(v.number()),
    confirmedAt: v.optional(v.number()),
    // Quiet looks (the Host still enabled) taken since the lease expired.
    quietLooks: v.optional(v.number()),
    // The read-back found the uuid disabled but at a DIFFERENT tuple than the
    // one observed before the write (an administrator repointed it meanwhile):
    // never confirmed, surfaced as failed, and still re-enabled by a restore.
    tupleDrifted: v.optional(v.boolean()),
    lastLookAt: v.optional(v.number()),
    // Why a row was released: `gone`, `changed`, `restored`, `never_written`, `settled`.
    releasedReason: v.optional(v.string()),
    updatedAt: v.number(),
  })
    .index('by_relay', ['relayId'])
    .index('by_run', ['runId'])
    .index('by_host', ['hostUuid'])
    .index('by_state_updated', ['state', 'updatedAt']),

  // External / internal reachability probe requests against one edge.
  // Operator-entered probe targets (any host:port), alongside the derived ones
  // (edge addresses, origin nodes). Operator evidence only: never fed to the detector.
  probeTargets: defineTable({
    label: v.string(),
    address: v.string(), // IP literal or hostname
    port: v.number(),
    // What the probe speaks. Default `tcp` (a bare connect): a hostname does
    // not imply HTTPS, and a REALITY or plaintext decoy would fail a handshake
    // probe while serving perfectly well. `tls` / `https` are opt-in per target.
    probeProtocol: v.optional(probeProtocolV),
    enabled: v.boolean(),
    notes: v.optional(v.string()),
    reachability: v.optional(probeReachabilitySummary),
    updatedAt: v.number(),
  }).index('by_enabled', ['enabled']),

  probeRuns: defineTable({
    // What was probed: an edge (its address), an origin node (its origin address)
    // or a custom target. `targetRef` is the row id of that kind.
    targetKind: probeTargetKind,
    targetRef: v.string(),
    source: relayProbeSource,
    target: v.string(), // "ip:port" as probed
    // The listener port probed (also inside `target`; absent on rows written
    // before per-port rollups, which parse it out of `target`).
    port: v.optional(v.number()),
    // Observed address family; absent = probed by NAME (the resolver decided).
    ipVersion: v.optional(v.union(v.literal(4), v.literal(6))),
    // Independent of the family: what kind of address was probed, what the
    // probe spoke, and which family was requested (`any` for a name).
    addressKind: v.optional(v.union(v.literal('ip'), v.literal('name'))),
    probeProtocol: v.optional(probeProtocolV),
    requestedFamily: v.optional(v.union(v.literal(4), v.literal(6), v.literal('any'))),
    externalId: v.optional(v.string()),
    status: v.union(
      v.literal('requested'),
      v.literal('running'),
      v.literal('finished'),
      v.literal('failed'),
      v.literal('timeout'),
    ),
    trigger: v.union(
      v.literal('cron'),
      v.literal('manual'),
      v.literal('detector'),
      v.literal('qualification'),
    ),
    requestedAt: v.number(),
    // When the executor was scheduled to start (requestedAt + the batch
    // stagger delay); absent = requestedAt. The stuck-run timeout counts from
    // here, never from the request, so a staggered run is not timed out
    // before its executor fires.
    scheduledAt: v.optional(v.number()),
    // When the executor actually started the measurement (`running`).
    startedAt: v.optional(v.number()),
    finishedAt: v.optional(v.number()),
    // The ROUND this run belongs to: the runs one request inserted for one
    // target together (edgeCountry.ts settles a round once every run of it has).
    roundId: v.optional(v.string()),
    // What the run costs at Globalping (probes asked for), for the tests budget.
    tests: v.optional(v.number()),
    // Control countries asked in the same measurement (one vantage each); their
    // results carry `control` and never reach `probeReachability`.
    controls: v.optional(v.array(v.string())),
    // A short failure class when the run could not measure (never service text).
    error: v.optional(v.string()),
    results: v.array(
      v.object({
        country: v.string(),
        asn: v.optional(v.string()),
        network: v.optional(v.string()),
        vantageClass: v.union(v.literal('eyeball'), v.literal('datacenter'), v.literal('unknown')),
        ok: v.boolean(),
        rttMs: v.optional(v.number()),
        error: v.optional(v.string()),
        control: v.optional(v.boolean()),
      }),
    ),
  })
    .index('by_target_requested', ['targetKind', 'targetRef', 'requestedAt'])
    .index('by_target_source_requested', ['targetKind', 'targetRef', 'source', 'requestedAt'])
    .index('by_source_requested', ['source', 'requestedAt'])
    .index('by_round', ['roundId'])
    .index('by_status', ['status'])
    .index('by_status_requested', ['status', 'requestedAt']),

  // Rolled-up per-target, per-country, per-source, per address family, PER
  // LISTENER PORT reachability counts (one row per such key; the index prefix
  // covers a target, the rest is matched in memory — bounded per target).
  probeReachability: defineTable({
    targetKind: probeTargetKind,
    targetRef: v.string(),
    country: v.string(),
    source: relayProbeSource,
    // Address family probed; absent = 4 (rows written before dual-stack rollups)
    // unless `addressKind` is `name` (probed by name: no family).
    ipVersion: v.optional(v.union(v.literal(4), v.literal(6))),
    addressKind: v.optional(v.union(v.literal('ip'), v.literal('name'))),
    probeProtocol: v.optional(probeProtocolV),
    // Listener port probed; absent = the legacy single-port row, adopted (and
    // stamped) by the first per-port run that lands on its path.
    port: v.optional(v.number()),
    okCount: v.number(),
    failCount: v.number(),
    lastOkAt: v.optional(v.number()),
    lastFailAt: v.optional(v.number()),
    // The last time THIS source's verdict was `reachable`: a later `unreachable`
    // is a transition (block evidence); a country that was never reachable from
    // this target is not.
    lastReachableAt: v.optional(v.number()),
    // Distinct failing networks (ASN / network name) behind the last verdict,
    // bounded (≤16). The cross-source agreement rule counts these for real.
    failNetworks: v.optional(v.array(v.string())),
    verdict: relayReachVerdict,
    updatedAt: v.number(),
  }).index('by_target_country', ['targetKind', 'targetRef', 'country']),

  // Per-country checks of edges (edgeCountry.ts, docs/edges.md "Countries:
  // checks and delivery"). One row per (edge, country): the ADDRESS track
  // (rounds with controls) and the HANDSHAKE track (#126 name batches paired
  // with a working TCP reading), never merged. Infrastructure only: an
  // operator-owned edge and third-party vantages. Rows outlive the edge for
  // `edge.country.windowDays` (a burned address is evidence about its range).
  edgeCountryEvidence: defineTable({
    edgeId: v.id('edges'),
    relayId: v.id('relays'),
    groupKey: v.string(),
    country: v.string(),
    address: v.object({
      state: v.union(v.literal('proven'), v.literal('blocked'), v.literal('unknown')),
      reason: v.optional(v.string()),
      // The last round that decided (or re-confirmed) the state; absent = never decided.
      decidedAt: v.optional(v.number()),
      until: v.optional(v.number()),
      // Blocked rounds counted towards `blockedRounds` (at least 30 min apart).
      blockedRounds: v.number(),
      lastBlockedAt: v.optional(v.number()),
      // A repeat round is due (the probe planner takes it first).
      repeatAt: v.optional(v.number()),
    }),
    lastRound: v.optional(
      v.object({
        roundId: v.string(),
        at: v.number(),
        result: countryRoundResult,
        reason: v.optional(v.string()),
        ok: v.number(),
        fail: v.number(),
        networks: v.number(),
        controlsOk: v.number(),
        v6Result: v.optional(countryRoundResult),
      }),
    ),
    // The newest TCP reading per path (family x port): what a name batch pairs with.
    paths: v.optional(
      v.array(
        v.object({
          family: v.union(v.literal(4), v.literal(6), v.literal('name')),
          port: v.number(),
          address: v.string(),
          tcp: v.union(
            v.literal('works'),
            v.literal('fails'),
            v.literal('thin'),
            v.literal('mixed'),
          ),
          at: v.number(),
        }),
      ),
    ),
    handshake: v.object({
      state: v.union(v.literal('blocked'), v.literal('none')),
      reason: v.optional(v.string()),
      decidedAt: v.optional(v.number()),
      until: v.optional(v.number()),
      // When the paired `path` batches counted towards a block happened (bounded).
      pathBatches: v.array(v.number()),
      lastBatchAt: v.optional(v.number()),
    }),
    combined: v.union(v.literal('proven'), v.literal('blocked'), v.literal('unknown')),
    // How long `combined` itself holds (a block: its latest blocking track; a
    // proof: the address proof): what every copy of the state carries.
    stateUntil: v.optional(v.number()),
    // The earliest `until` of the decided tracks (the expiry worker's clock).
    until: v.optional(v.number()),
    lastRoundAt: v.optional(v.number()),
    updatedAt: v.number(),
  })
    .index('by_edge_country', ['edgeId', 'country'])
    .index('by_group_country', ['groupKey', 'country'])
    .index('by_country_round', ['country', 'lastRoundAt'])
    .index('by_repeat', ['address.repeatAt'])
    .index('by_until', ['until'])
    .index('by_updated', ['updatedAt']),

  // What the edges of one (provider, location) say from one country, rolled up.
  countryGroupGrades: defineTable({
    groupKey: v.string(),
    country: v.string(),
    state: v.union(
      v.literal('proven'),
      v.literal('blocked'),
      v.literal('mixed'),
      v.literal('unknown'),
    ),
    counts: v.object({ edges: v.number(), proven: v.number(), blocked: v.number() }),
    // When the grade must be looked at again (its earliest contributing expiry).
    until: v.optional(v.number()),
    updatedAt: v.number(),
  })
    .index('by_group_country', ['groupKey', 'country'])
    .index('by_country', ['country'])
    .index('by_until', ['until']),

  // An operator's word about an edge or a whole group in one country. Checks
  // never override it (a disagreeing check shows as a conflict); it never expires.
  countryMarks: defineTable({
    scope: v.union(v.literal('edge'), v.literal('group')),
    edgeId: v.optional(v.id('edges')),
    groupKey: v.optional(v.string()),
    country: v.string(),
    state: countryDecided,
    at: v.number(),
    by: v.optional(v.id('adminUsers')),
  })
    .index('by_edge_country', ['edgeId', 'country'])
    .index('by_group_country', ['groupKey', 'country']),

  // Detector ring buffer: one row per origin per evaluation (7-day retention).
  relaySamples: defineTable({
    relayId: v.id('relays'),
    at: v.number(),
    reports: v.number(),
    distinctReporters: v.number(),
    usersOnline: v.union(v.number(), v.null()),
  }).index('by_relay_at', ['relayId', 'at']),

  // Per-NODE stats from the backend (the origin mode group is shared, so per-mode group
  // remnawaveNodeStats cannot isolate one node). Refreshed by the healthcheck cron.
  backendNodeInventory: defineTable({
    backendServerId: v.id('backendServers'),
    nodeUuid: v.string(),
    name: v.string(),
    usersOnline: v.number(),
    online: v.boolean(),
    lastStatsAt: v.number(),
    // As the backend reports them (the origin picker pre-fills from these).
    address: v.optional(v.string()),
    port: v.optional(v.number()),
    countryCode: v.optional(v.string()),
  })
    .index('by_server_name', ['backendServerId', 'name'])
    .index('by_server', ['backendServerId']),

  // --- Server-name families (REALITY) ------------------------------------------
  // A REALITY transport accepts an exact allowlist of server names, and forwards
  // every other handshake to ONE target. A name is only safe to hand out if that
  // target genuinely serves it (TLS 1.3, a certificate valid for the name):
  // otherwise an active probe presenting the name sees a mismatch and the node
  // stands out. A FAMILY is therefore a target plus the names it serves, each
  // checked against that target before it may be used.
  sniFamilies: defineTable({
    slug: v.string(),
    label: v.string(),
    // `static` = one fixed site. `sni-router` (a target on the node that follows
    // the presented name) is reserved so adding it needs no migration.
    target: v.object({
      kind: v.union(v.literal('static'), v.literal('sni-router')),
      address: v.string(),
      port: v.number(),
    }),
    enabled: v.boolean(),
    // Require HTTP/2 from the target for a name to qualify (preferred, not default).
    requireH2: v.boolean(),
    // Monotonic per family and never reused: the order names are taken in.
    nextSeq: v.number(),
    updatedAt: v.number(),
  }).index('by_slug', ['slug']),

  sniNames: defineTable({
    familyId: v.id('sniFamilies'),
    // Lowercase, no trailing dot. Fleet-unique: a name belongs to ONE family.
    name: v.string(),
    seq: v.number(),
    // active    may be used once it qualifies
    // suspended stopped qualifying (the target no longer serves it); recovers by itself
    // retired   an operator took it out of use
    // burned    known blocked; removed everywhere and never offered again
    status: v.union(
      v.literal('active'),
      v.literal('suspended'),
      v.literal('retired'),
      v.literal('burned'),
    ),
    qualification: v.object({
      state: v.union(v.literal('pending'), v.literal('ok'), v.literal('failed')),
      tlsVersion: v.optional(v.string()),
      alpn: v.optional(v.string()),
      // A code word (`q_cert`, `q_tls12`, ...), never a handshake error string.
      code: v.optional(v.string()),
      consecutiveFails: v.number(),
    }),
    // 0 = never checked; the qualify cron takes the oldest first.
    checkedAt: v.number(),
    updatedAt: v.number(),
  })
    .index('by_family_seq', ['familyId', 'seq'])
    .index('by_name', ['name'])
    .index('by_checked', ['checkedAt']),

  // A family bound to ONE backend transport: the single authoritative allowlist for
  // it. Every origin listener whose `panelBinding` is that transport inherits it;
  // what each NODE has been proven to accept is tracked per listener.
  sniInboundBindings: defineTable({
    backendServerId: v.id('backendServers'),
    profileUuid: v.string(),
    inboundTag: v.string(),
    inboundUuid: v.string(),
    familyId: v.id('sniFamilies'),
    // Bumped by every rollout that changes the backend allowlist.
    generation: v.number(),
    // The generation the PANEL was last seen to hold (a read-back, not a node).
    panelConfirmedGeneration: v.number(),
    updatedAt: v.number(),
  })
    .index('by_server_inbound', ['backendServerId', 'inboundUuid'])
    .index('by_family', ['familyId']),

  // Every name a transport has EVER listed, keyed by the transport and the name and
  // independent of any family binding (it survives unbind / rebind and is never
  // reset). A name absent from here has never been accepted by any earlier
  // config of that transport, which is what makes it a WITNESS: a node that
  // authenticates it must be running the generation that introduced it.
  sniInboundNameHistory: defineTable({
    backendServerId: v.id('backendServers'),
    inboundUuid: v.string(),
    name: v.string(),
    // 0 = already there when FCP first looked (history before that is unknown).
    firstSeenGeneration: v.number(),
  }).index('by_inbound_name', ['backendServerId', 'inboundUuid', 'name']),

  // Whether a server name works in a curated country. A name that is fine
  // elsewhere can be blocked in one place (a big site that is itself censored
  // there), so "usable" is per country. Absent = nobody has judged it there.
  sniNameCountry: defineTable({
    name: v.string(),
    country: v.string(),
    state: v.union(v.literal('proven'), v.literal('blocked')),
    source: v.union(v.literal('operator'), v.literal('probe')),
    updatedAt: v.number(),
  })
    .index('by_name', ['name'])
    .index('by_name_country', ['name', 'country']),

  // One push of a family's allowlist to its transport. `names` is the COMPLETE list
  // written (family names + names an origin still hands out + names still
  // draining). The backend write runs through the operations ledger (`opId`);
  // what members get is decided afterwards, per node, by receipts.
  sniRollouts: defineTable({
    bindingId: v.id('sniInboundBindings'),
    backendServerId: v.id('backendServers'),
    generation: v.number(),
    names: v.array(v.string()),
    added: v.array(v.string()),
    removed: v.array(v.string()),
    // An added name this transport has NEVER listed before. A node that
    // authenticates it must be running this generation, so one test of it
    // proves the whole generation on that node. Absent = every added name was
    // listed at some point: each is then proven on its own.
    witness: v.optional(v.string()),
    // The token the profile must have once the write has landed.
    expectedToken: v.string(),
    opId: v.optional(v.id('panelOps')),
    phase: v.union(
      v.literal('writing'),
      v.literal('panel_confirmed'),
      v.literal('failed'),
      v.literal('superseded'),
    ),
    errorCode: v.optional(v.string()),
    startedAt: v.number(),
    updatedAt: v.number(),
  })
    .index('by_binding', ['bindingId'])
    .index('by_op', ['opId'])
    .index('by_phase_updated', ['phase', 'updatedAt']),

  // The proof that ONE node accepts a name: an authenticated REALITY session,
  // made by an operator with an isolated test link through one of that node's
  // verified edges. Bound to everything it proves; a change to any of it, an
  // expiry, or a newer generation voids it. A TLS probe never creates one.
  sniAcceptanceReceipts: defineTable({
    rolloutId: v.id('sniRollouts'),
    generation: v.number(),
    relayId: v.id('relays'),
    listenerId: v.id('relayListeners'),
    edgeId: v.id('edges'),
    sni: v.string(),
    isWitness: v.boolean(),
    expectedToken: v.string(),
    // The endpoint confirmation the edge held when the link was issued.
    endpoint: v.string(),
    listenerRevision: v.number(),
    configHash: v.string(),
    evidenceKind: v.union(
      v.literal('operator_test_link'),
      v.literal('auth_probe'),
      v.literal('adopted'),
    ),
    state: v.union(
      v.literal('issued'),
      v.literal('confirmed'),
      v.literal('expired'),
      v.literal('superseded'),
    ),
    issuedAt: v.number(),
    expiresAt: v.number(),
    confirmedAt: v.optional(v.number()),
    actorAdminId: v.optional(v.id('adminUsers')),
  })
    .index('by_rollout', ['rolloutId'])
    .index('by_listener', ['listenerId']),

  // --- Backend observation (server management) ---------------------------------
  // What an operator sees of a backend BEFORE any write: its nodes, config
  // profiles, Hosts and mode groups, as last read by `backendObserve`. Read caches
  // with ONE writer each (the observe mutation); a row the backend no longer
  // lists is deleted. NOTHING here is secret by construction: a transport is the
  // allowlist projection discovery uses, and a profile is that plus digests
  // (lib/backend/digest.ts) that say "this changed" without carrying what did.
  // Kept apart from `backendNodeInventory` so neither writer clobbers the other.
  panelNodes: defineTable({
    backendServerId: v.id('backendServers'),
    nodeUuid: v.string(),
    name: v.string(),
    address: v.optional(v.string()),
    port: v.optional(v.number()),
    countryCode: v.optional(v.string()),
    online: v.boolean(),
    isDisabled: v.boolean(),
    usersOnline: v.number(),
    configProfileUuid: v.optional(v.string()),
    activeInboundUuids: v.array(v.string()),
    tags: v.array(v.string()),
    observedAt: v.number(),
  })
    .index('by_server', ['backendServerId'])
    .index('by_server_uuid', ['backendServerId', 'nodeUuid']),

  panelProfiles: defineTable({
    backendServerId: v.id('backendServers'),
    profileUuid: v.string(),
    name: v.string(),
    // SHA-256 over the REDACTED config: storable, drives diffs.
    shapeHash: v.string(),
    // Keyed digest over the COMPLETE config (moves on a key rotation too), and
    // the id of the key it was made with: a different key re-baselines, it
    // never reads as a change.
    changeToken: v.string(),
    digestKeyId: v.string(),
    // When the token last moved under the SAME key. Who moved it is the ops
    // ledger's question, not this cache's.
    tokenChangedAt: v.optional(v.number()),
    // The token moved to something NO change made from FCP expected: the backend
    // UI, the node role, another tool. Stays until an operator acknowledges it,
    // because what FCP believes about this profile may no longer hold.
    foreignEditAt: v.optional(v.number()),
    inbounds: v.array(
      v.object({
        tag: v.string(),
        inboundUuid: v.string(),
        protocol: v.string(),
        port: v.union(v.number(), v.null()),
        listen: v.optional(v.string()),
        network: v.string(),
        security: v.string(),
        reality: v.optional(
          v.object({ target: v.union(v.string(), v.null()), serverNames: v.array(v.string()) }),
        ),
        tlsServerName: v.optional(v.union(v.string(), v.null())),
        path: v.optional(v.union(v.string(), v.null())),
        serviceName: v.optional(v.union(v.string(), v.null())),
        // REALITY authentication identity: a keyed, value-free digest plus the
        // PUBLIC key derived from the private one.
        realityAuth: v.optional(
          v.object({
            digest: v.union(v.string(), v.null()),
            publicKey: v.union(v.string(), v.null()),
            publicKeyMismatch: v.boolean(),
          }),
        ),
      }),
    ),
    observedAt: v.number(),
  })
    .index('by_server', ['backendServerId'])
    .index('by_server_uuid', ['backendServerId', 'profileUuid']),

  panelHosts: defineTable({
    backendServerId: v.id('backendServers'),
    hostUuid: v.string(),
    remark: v.string(),
    address: v.string(),
    port: v.number(),
    sni: v.optional(v.string()),
    host: v.optional(v.string()),
    path: v.optional(v.string()),
    alpn: v.optional(v.string()),
    fingerprint: v.optional(v.string()),
    securityLayer: v.optional(v.string()),
    isDisabled: v.boolean(),
    isHidden: v.boolean(),
    tag: v.optional(v.string()),
    viewPosition: v.optional(v.number()),
    configProfileUuid: v.optional(v.string()),
    configProfileInboundUuid: v.optional(v.string()),
    nodeUuids: v.array(v.string()),
    observedAt: v.number(),
  })
    .index('by_server', ['backendServerId'])
    .index('by_server_uuid', ['backendServerId', 'hostUuid']),

  panelSquads: defineTable({
    backendServerId: v.id('backendServers'),
    squadUuid: v.string(),
    name: v.string(),
    inboundUuids: v.array(v.string()),
    membersCount: v.optional(v.number()),
    observedAt: v.number(),
  })
    .index('by_server', ['backendServerId'])
    .index('by_server_uuid', ['backendServerId', 'squadUuid']),

  // One row per instance: when it was last observed and whether that worked.
  // `errorCode` is a code word, never the provider's message.
  panelObserveState: defineTable({
    backendServerId: v.id('backendServers'),
    attemptedAt: v.number(),
    observedAt: v.optional(v.number()),
    ok: v.boolean(),
    errorCode: v.optional(v.string()),
    counts: v.optional(
      v.object({
        nodes: v.number(),
        profiles: v.number(),
        hosts: v.number(),
        squads: v.number(),
      }),
    ),
  }).index('by_server', ['backendServerId']),

  // --- Backend writes (server management) ---------------------------------------
  // The operations ledger. One row per management write, inserted BEFORE the
  // backend is called, together with its claims, in one mutation. Three facts are
  // recorded SEPARATELY and never collapsed into one "known" flag:
  //   request      what happened to the HTTP exchange;
  //   panelState   whether the non-secret postcondition was SEEN on a later read;
  //   asyncEffect  whether work the backend queued behind the write has finished.
  // Claims are released only when the request was provably rejected before any
  // change, or the postcondition was observed AND the queued work is done. There
  // is NO timed release, NO re-assert and NO administrative abandonment: an
  // attempt whose outcome is unknown stays fenced until a recorded recovery
  // (`recovery`) establishes that it can no longer change anything.
  panelOps: defineTable({
    backendServerId: v.id('backendServers'),
    kind: v.union(v.literal('host'), v.literal('squad'), v.literal('profile'), v.literal('node')),
    verb: v.union(
      v.literal('create'),
      v.literal('update'),
      v.literal('delete'),
      v.literal('reorder'),
      v.literal('patch'),
      v.literal('enable'),
      v.literal('disable'),
      v.literal('restart'),
    ),
    // Fences every mutation made on the op's behalf.
    generation: v.number(),
    claimKeys: v.array(v.string()),
    // Names for display and audit (remark, mode group name); never a secret.
    label: v.string(),
    // The backend uuid being changed; absent for a create until it is known.
    objectUuid: v.optional(v.string()),
    // A create's reserved identity: what discovery looks for after a lost response.
    identity: v.optional(v.string()),
    // JSON of the intended call, and of what a later read must show. Non-secret.
    intent: v.string(),
    postcondition: v.string(),
    request: v.union(
      v.literal('pending'),
      v.literal('rejected_pre_mutation'),
      v.literal('acknowledged'),
      v.literal('uncertain'),
    ),
    panelState: v.union(v.literal('observed'), v.literal('unobserved')),
    asyncEffect: v.union(
      v.literal('none'),
      v.literal('pending'),
      v.literal('complete'),
      v.literal('unresolved'),
    ),
    // Nodes whose application work the backend queued behind this write, with
    // the backend's `lastStatusChange` for each as read BEFORE the call.
    asyncNodes: v.optional(
      v.array(v.object({ nodeUuid: v.string(), before: v.union(v.string(), v.null()) })),
    ),
    // True while the op holds its claims (indexable "needs settling").
    open: v.boolean(),
    // At most one outstanding attempt, ever: a create is never sent twice.
    attemptId: v.optional(v.string()),
    sentAt: v.optional(v.number()),
    lastLookAt: v.optional(v.number()),
    quietLooks: v.number(),
    settledAt: v.optional(v.number()),
    // A code word, never the backend's text.
    errorCode: v.optional(v.string()),
    // The recorded recovery of an attempt whose outcome could not be observed:
    // an operator's attestation to EACH condition, by name.
    recovery: v.optional(
      v.object({
        credentialsRevoked: v.boolean(),
        noInFlightExecutor: v.boolean(),
        queueDrained: v.boolean(),
        freshReadAt: v.number(),
        note: v.optional(v.string()),
        byAdminId: v.optional(v.id('adminUsers')),
        at: v.number(),
      }),
    ),
    actorAdminId: v.optional(v.id('adminUsers')),
    // No admin asked: the FCP run that made the write (`<kind>:<id>`), for the audit.
    actorRun: v.optional(v.string()),
    createdAt: v.number(),
    updatedAt: v.number(),
  })
    .index('by_server', ['backendServerId'])
    .index('by_open', ['open', 'backendServerId'])
    // The newest ops of one kind (foreign-edit detection reads profile ops only).
    .index('by_server_kind', ['backendServerId', 'kind'])
    // Retention: settled ops past the window (retention.sweepPanelOps).
    .index('by_open_updated', ['open', 'updatedAt']),

  // One row per claimed resource (`host:<uuid>`, `hostid:<identity>`,
  // `mode group:<uuid>`, `profile:<uuid>`, `node:<uuid>`), scoped by instance.
  // Written with the op, in the same mutation; a second op touching a claimed
  // key is refused. Other workflows reject a claim in the reverse direction.
  panelClaims: defineTable({
    backendServerId: v.id('backendServers'),
    key: v.string(),
    opId: v.id('panelOps'),
    generation: v.number(),
    claimedAt: v.number(),
  })
    .index('by_server_key', ['backendServerId', 'key'])
    .index('by_op', ['opId']),

  // What FCP owns on a backend, what is reserved for creation, and what was
  // DELIBERATELY removed. Durable: independent of any switch and of FCP being
  // reachable. `lookup` keeps every identity the object ever had (name,
  // composite), so a tombstone rejects recreation by name after a rename, not
  // only by the former uuid.
  panelOwnership: defineTable({
    backendServerId: v.id('backendServers'),
    kind: v.union(
      v.literal('node'),
      v.literal('host'),
      v.literal('inbound'),
      v.literal('squad'),
      v.literal('profile'),
    ),
    identity: v.string(),
    lookup: v.array(v.string()),
    panelUuid: v.optional(v.string()),
    state: v.union(v.literal('owned'), v.literal('tombstoned')),
    since: v.number(),
    updatedAt: v.number(),
  })
    .index('by_server_kind_identity', ['backendServerId', 'kind', 'identity'])
    .index('by_server_uuid', ['backendServerId', 'panelUuid']),

  // Member reports attributed to the server names the reporter held, as
  // AGGREGATE fractional weights per (name, country, day). No member, no
  // subscription, no address: a row cannot be traced to who reported. `country`
  // is the reporter's curated country (their saved choice, else what they
  // consented to share) or `ZZ`. Swept after `edge.sni.reportRetentionDays`.
  sniReportCounts: defineTable({
    name: v.string(),
    country: v.string(),
    day: v.string(), // YYYY-MM-DD, UTC
    weight: v.number(),
    updatedAt: v.number(),
  })
    .index('by_name_country_day', ['name', 'country', 'day'])
    .index('by_day', ['day'])
    // One country's counts, bounded per country (checks from inside a country).
    .index('by_country_day', ['country', 'day']),

  // Checks of server names from vantages inside curated countries
  // (docs/edges.md "Checks from inside a country"). One row per MEASUREMENT:
  // one name presented to one of FCP's own member-facing addresses, from one
  // source, in one country. A BATCH is the names of one address measured from
  // the same vantages (the controls of each other). No member data anywhere:
  // the address is an operator-owned edge or opted-in origin, the vantages are
  // third-party probes. Deleted after `edge.sni.vantage.windowDays`.
  sniVantageProbes: defineTable({
    name: v.string(),
    familyId: v.id('sniFamilies'),
    country: v.string(),
    source: v.union(v.literal('globalping'), v.literal('ripeatlas')),
    batch: v.string(),
    targetKind: v.union(v.literal('edge'), v.literal('relay')),
    targetRef: v.string(),
    // What was dialled, so a run whose target moved under it is not misread.
    address: v.string(),
    port: v.number(),
    trigger: v.union(v.literal('cron'), v.literal('manual')),
    status: v.union(
      v.literal('requested'),
      v.literal('running'),
      v.literal('finished'),
      v.literal('failed'),
      v.literal('timeout'),
    ),
    externalId: v.optional(v.string()),
    // A short code when the measurement could not run (never service text).
    error: v.optional(v.string()),
    requestedAt: v.number(),
    scheduledAt: v.number(),
    startedAt: v.optional(v.number()),
    finishedAt: v.optional(v.number()),
    results: v.array(
      v.object({
        asn: v.optional(v.string()),
        network: v.optional(v.string()),
        vantageClass: v.union(v.literal('eyeball'), v.literal('datacenter'), v.literal('unknown')),
        outcome: v.union(
          v.literal('ok'),
          v.literal('answered'),
          v.literal('cert_mismatch'),
          v.literal('reset'),
          v.literal('timeout'),
          v.literal('refused'),
          v.literal('error'),
        ),
        rttMs: v.optional(v.number()),
        error: v.optional(v.string()),
      }),
    ),
  })
    .index('by_batch_source', ['batch', 'source'])
    .index('by_name_country_requested', ['name', 'country', 'requestedAt'])
    .index('by_requested', ['requestedAt'])
    .index('by_status_requested', ['status', 'requestedAt']),

  // What the checks say about one name in one country (lib/edges/sni/vantage.ts
  // `aggregateEvidence`), refreshed whenever one of its batches settles. The
  // suggestion itself is derived at read time (it also depends on member
  // reports and on the thresholds, which move independently).
  sniVantageEvidence: defineTable({
    familyId: v.id('sniFamilies'),
    name: v.string(),
    country: v.string(),
    // When this pair was last put into a batch (the planner's "due" clock).
    lastRequestedAt: v.number(),
    measurements: v.number(),
    okVantages: v.number(),
    okNetworks: v.number(),
    lastOkAt: v.optional(v.number()),
    // The newest working check EVER (kept past the window: the transition marker).
    everOkAt: v.optional(v.number()),
    lastFailAt: v.optional(v.number()),
    lastAt: v.optional(v.number()),
    // The oldest measurement the aggregate rests on (requestedAt): once it leaves
    // the window the sweep aggregates again. Absent = nothing in the window.
    oldestAt: v.optional(v.number()),
    latest: v.union(v.literal('ok'), v.literal('failing'), v.literal('mixed'), v.literal('none')),
    streak: v.optional(
      v.object({
        nameFailures: v.number(),
        networks: v.number(),
        singled: v.number(),
        pathFailures: v.number(),
        batches: v.number(),
        startedAt: v.number(),
        transition: v.boolean(),
      }),
    ),
    updatedAt: v.number(),
  })
    .index('by_name_country', ['name', 'country'])
    .index('by_family', ['familyId'])
    .index('by_oldest', ['oldestAt']),

  // --- Bootstrap contract v2 (docs/servers.md "Setting up a backend", "Node lifecycle") ---
  //
  // FCP owns the backend; the node role bootstraps the MACHINE and reports.
  // The rows below are durable workflows: each carries what it wants
  // (`desired`), a generation that fences every scheduled action made on its
  // behalf, and a lease (`claim`) so an interrupted run resumes from the
  // sweep. External side effects are `backendObligations`, persisted BEFORE the
  // call.

  // One per backend server: the profile, one transport per mode, each mode's
  // group and family, the subscription templates, the origin-DNS account and
  // the delivery gate version.
  panelSetups: defineTable({
    backendServerId: v.id('backendServers'),
    desired: v.string(), // JSON BackendSetupInput (non-secret: names, targets, ports)
    desiredHash: v.string(),
    generation: v.number(),
    claim: v.optional(v.object({ attemptId: v.string(), expiresAt: v.number() })),
    state: v.union(v.literal('pending'), v.literal('ready'), v.literal('failed')),
    step: v.optional(v.string()),
    code: v.optional(v.string()),
    profileName: v.string(),
    profileUuid: v.optional(v.string()),
    // One entry per mode the backend serves: the connection mode it feeds,
    // its group, its shape, its family, and the EFFECTIVE transport (from
    // the adopted or created profile, never the defaults).
    modes: v.array(
      v.object({
        slug: v.string(),
        name: v.string(),
        shape: v.object({
          transport: v.union(v.literal('reality'), v.literal('xhttp-reality'), v.literal('ws')),
          fronting: v.union(v.literal('direct'), v.literal('edge-l4'), v.literal('edge-l7')),
        }),
        familySlug: v.optional(v.string()),
        acceptProxyProtocol: v.boolean(),
        ws: v.optional(v.object({ path: v.string(), port: v.number() })),
        // The transport tag: the group name's, or the tag an adopted profile
        // already carried (a backend keys transports by tag; never renamed).
        tag: v.string(),
        groupUuid: v.optional(v.string()),
        // The name the group was found under when it was renamed in place.
        renamedFrom: v.optional(v.string()),
        placement: v.union(v.literal('pending'), v.literal('bound'), v.literal('skipped')),
        transport: v.optional(
          v.object({
            uuid: v.string(),
            listen: v.optional(v.string()),
            port: v.number(),
            path: v.optional(v.string()),
            serverNames: v.optional(v.array(v.string())),
            target: v.optional(v.object({ address: v.string(), port: v.number() })),
            publicKey: v.optional(v.string()),
          }),
        ),
        family: v.union(
          v.literal('none'),
          v.literal('bound'),
          v.literal('unbound'),
          v.literal('target_mismatch'),
          // Bound to a DIFFERENT family: that family's rollouts own the names.
          v.literal('bound_elsewhere'),
        ),
      }),
    ),
    templates: v.array(
      v.object({
        family: v.string(),
        hash: v.string(),
        state: v.union(v.literal('matched'), v.literal('drifted'), v.literal('refused')),
      }),
    ),
    // When the live templates were last looked at (setup or the sweep's re-sync);
    // absent on rows from before the re-sync, which are due at once.
    templatesCheckedAt: v.optional(v.number()),
    // The privacy posture of the adopted profile, from the harden preview.
    privacy: v.optional(v.union(v.literal('ok'), v.literal('drifted'))),
    originDns: v.optional(
      v.union(
        v.object({
          accountId: v.id('edgeProviderAccounts'),
          zoneId: v.string(),
          zoneName: v.string(),
        }),
        v.null(),
      ),
    ),
    // Taken over with existing nodes or addresses (the operator's typed adopt).
    adopted: v.boolean(),
    // When the setup first reached ready: from then on FCP is the backend's
    // writer, and a new request is a change of its setup. Absent on a row that
    // is ready but older than the field (its state says the same).
    readyAt: v.optional(v.number()),
    // The delivery gate version of this backend: bumped on every disposition
    // or resource-set change of any of its nodes; part of every render's token.
    gateVersion: v.number(),
    createdAt: v.number(),
    updatedAt: v.number(),
  }).index('by_server', ['backendServerId']),

  // One per enrolled node: what the role enrolled and observes, what FCP owns
  // of the machine configuration, the revisions, the activation ladder, the
  // committed (approved) configuration and the delivery disposition.
  panelNodeIntents: defineTable({
    backendServerId: v.id('backendServers'),
    name: v.string(),
    label: v.string(),
    // The machine's own name as the node role reports it (its inventory host
    // name), so an operator can tell nodes apart. OPERATOR-ONLY: the node name
    // stays the member-facing one (address remarks, subscription bodies); this
    // never leaves the admin surface. Absent for adopted and hand-added nodes.
    machineName: v.optional(v.string()),
    // The connection mode this node serves (one per node); the machine shape
    // follows from the backend setup's entry for it.
    mode: v.string(),
    contractVersion: v.number(),
    generation: v.number(),
    desiredHash: v.string(),
    claim: v.optional(v.object({ attemptId: v.string(), expiresAt: v.number() })),
    state: v.union(
      v.literal('pending'),
      v.literal('ready'),
      v.literal('blocked'),
      v.literal('retiring'),
      v.literal('retired'),
    ),
    code: v.optional(v.string()),
    // Observations the role reports on every run (never FCP-owned settings).
    observed: v.object({
      management: v.object({ address: v.string(), port: v.number() }),
      publicIps: v.object({ v4: v.optional(v.string()), v6: v.optional(v.string()) }),
      capabilities: v.object({ caddy: v.boolean(), ipv6: v.boolean() }),
      at: v.number(),
    }),
    // FCP-owned machine settings; changed only by an admin (bumps machineRevision).
    settings: v.object({
      ingress: v.optional(
        v.object({
          externalPort: v.number(),
          hostHeader: v.union(v.literal('any'), v.literal('hostname')),
          internal: v.array(
            v.object({
              inboundTag: v.string(),
              listen: v.string(),
              port: v.number(),
              path: v.string(),
              upstream: v.optional(v.literal('h2c')),
            }),
          ),
        }),
      ),
      originHostnameSource: v.union(v.literal('managed'), v.literal('explicit'), v.literal('none')),
      explicitHostname: v.optional(v.string()),
      originAddressOverride: v.optional(v.string()),
      publishV6: v.boolean(),
      nodePort: v.number(),
      countryCode: v.optional(v.string()),
    }),
    machineRevision: v.number(),
    appliedRevision: v.optional(v.number()),
    appliedAt: v.optional(v.number()),
    appliedReport: v.optional(
      v.object({ certificateReady: v.optional(v.boolean()), nodeStarted: v.boolean() }),
    ),
    // The profile token and transport uuid this node runs, and the REALITY
    // authentication digest of its transport, as last derived.
    configRevision: v.optional(v.string()),
    authRevision: v.optional(v.string()),
    deliveryRevision: v.optional(v.string()),
    activation: v.object({
      stage: v.union(
        v.literal('registered'),
        v.literal('bootstrap_available'),
        v.literal('machine_applied'),
        v.literal('machine_ready'),
        v.literal('candidates_verified'),
        v.literal('awaiting_approval'),
        v.literal('activating'),
        v.literal('live'),
      ),
      // Evidence rows, each bound to the revisions it was taken for.
      evidence: v.array(
        v.object({
          kind: v.string(),
          machineRevision: v.number(),
          configRevision: v.optional(v.string()),
          authRevision: v.optional(v.string()),
          deliveryRevision: v.optional(v.string()),
          at: v.number(),
          detail: v.optional(v.string()),
        }),
      ),
      currentRunId: v.optional(v.id('panelActivationRuns')),
      reviewHash: v.optional(v.string()),
    }),
    // The COMMITTED configuration: what members are served. Moves only when a
    // delivery commit promotes an activation run's candidate snapshot.
    approved: v.optional(
      v.object({
        machineRevision: v.number(),
        configRevision: v.string(),
        authRevision: v.optional(v.string()),
        deliveryRevision: v.string(),
        reviewHash: v.string(),
        approvedAt: v.number(),
        byAdminId: v.optional(v.id('adminUsers')),
        committed: v.object({ hostUuids: v.array(v.string()), edgeIds: v.array(v.string()) }),
      }),
    ),
    delivery: v.object({
      disposition: v.union(
        v.literal('staged'),
        v.literal('activating'),
        v.literal('live'),
        v.literal('unavailable'),
        v.literal('retiring'),
      ),
      acceptingAssignments: v.boolean(),
      lastLiveAt: v.optional(v.number()),
      exposure: v.object({
        everLive: v.boolean(),
        hosts: v.array(v.string()),
        relayId: v.optional(v.id('relays')),
        mirrors: v.number(),
        testCredentials: v.number(),
        dns: v.number(),
      }),
    }),
    origin: v.object({
      hostname: v.optional(v.string()),
      address: v.optional(v.string()),
      dns: v.union(
        v.literal('none'),
        v.literal('pending'),
        v.literal('created'),
        v.literal('resolves'),
        v.literal('conflict'),
      ),
    }),
    // A maintenance transition that closed this node (with the ids of every
    // node it closed, so none reopens on another's checks).
    maintenance: v.optional(
      v.object({
        id: v.string(),
        reason: v.string(),
        since: v.number(),
        byAdminId: v.optional(v.id('adminUsers')),
      }),
    ),
    nodeUuid: v.optional(v.string()),
    // Every name the node had before a rename, oldest first (backendNodeRenames.ts).
    // The first is the name its origin DNS record's marker was written with.
    formerNames: v.optional(v.array(v.string())),
    // A direct node's own addresses on the backend: one per family name.
    addressUuids: v.optional(v.array(v.string())),
    // Taken over as it was (already serving members): live at once, with its
    // current addresses committed. `externallyFronted`: a fronted node whose
    // edge FCP does not run yet (an earlier tool made it); Edges takes over later.
    adopted: v.optional(v.object({ at: v.number(), externallyFronted: v.boolean() })),
    retirementId: v.optional(v.id('panelRetirements')),
    tokenId: v.optional(v.id('apiTokens')),
    registeredAt: v.number(),
    updatedAt: v.number(),
  })
    .index('by_server', ['backendServerId'])
    .index('by_server_name', ['backendServerId', 'name'])
    .index('by_state', ['state']),

  // A maintenance transition over a shared change (a profile edit): the nodes
  // it closed. Managed nodes carry the transition on their own row; unmanaged
  // nodes (no intent) are held closed by name here until an admin releases the
  // hold, since nothing re-verifies them.
  panelMaintenanceHolds: defineTable({
    backendServerId: v.id('backendServers'),
    transitionId: v.string(),
    reason: v.string(),
    // Unmanaged node names held closed; managed nodes are listed for the record.
    heldNodeNames: v.array(v.string()),
    closedIntentIds: v.array(v.id('panelNodeIntents')),
    released: v.boolean(),
    since: v.number(),
    byAdminId: v.optional(v.id('adminUsers')),
    updatedAt: v.number(),
  })
    .index('by_server', ['backendServerId'])
    // The open holds of a backend (read on every member fetch of an unmanaged node).
    .index('by_server_released', ['backendServerId', 'released'])
    .index('by_released_updated', ['released', 'updatedAt']),

  // A node rename (docs/servers.md "Renaming a node"): a resumable workflow
  // that renames the backend row through the ledger, every FCP row keyed by
  // the name in the transaction that SEES the new name, then the Host
  // remarks FCP wrote (each through the ledger) and the subscriptions'
  // pins (a paginated drain). `step` says what is next; `opId` is the
  // ledger op the current step waits on.
  panelNodeRenames: defineTable({
    backendServerId: v.id('backendServers'),
    nodeUuid: v.string(),
    from: v.string(),
    to: v.string(),
    intentId: v.optional(v.id('panelNodeIntents')),
    relayIds: v.array(v.id('relays')),
    state: v.union(v.literal('running'), v.literal('done'), v.literal('failed')),
    step: v.union(
      v.literal('backend'),
      v.literal('hosts'),
      v.literal('subscriptions'),
      v.literal('done'),
    ),
    opId: v.optional(v.id('panelOps')),
    // The subscriptions drain's page cursor.
    cursor: v.optional(v.string()),
    // Hosts whose remark write the backend refused before any change: never
    // sent again on their own; the rename waits for an operator's retry.
    refusedHosts: v.optional(
      v.array(v.object({ hostUuid: v.string(), remark: v.string(), code: v.string() })),
    ),
    code: v.optional(v.string()),
    claim: v.optional(v.object({ attemptId: v.string(), expiresAt: v.number() })),
    actorAdminId: v.optional(v.id('adminUsers')),
    createdAt: v.number(),
    updatedAt: v.number(),
  })
    .index('by_server', ['backendServerId'])
    .index('by_state', ['state'])
    .index('by_op', ['opId']),

  // A name a node had before a rename, and the name it has now. Lookups by a
  // name that is not current (a subscription pinned before its drain, a body
  // whose Hosts still carry the old remark, the node role calling by its old
  // name) resolve through here. A former name stays reserved.
  panelNodeAliases: defineTable({
    backendServerId: v.id('backendServers'),
    formerName: v.string(),
    name: v.string(),
    nodeUuid: v.string(),
    renameId: v.id('panelNodeRenames'),
    at: v.number(),
  })
    .index('by_server_former', ['backendServerId', 'formerName'])
    .index('by_server', ['backendServerId']),

  // A profile edit that opens a port (docs/servers.md "Firewall
  // acknowledgement"): staged, NOT claimed, until every node that will listen
  // there confirmed its firewall lets the port in. Then the edit is claimed
  // through the ledger like any other (`opId`) and its state follows that op.
  // `ops` is the non-secret JSON of the typed edit and the tokens the operator
  // previewed; nothing here is key material.
  panelPortChanges: defineTable({
    backendServerId: v.id('backendServers'),
    profileUuid: v.string(),
    profileName: v.string(),
    inboundTag: v.string(),
    inboundUuid: v.string(),
    fromPort: v.optional(v.number()),
    toPort: v.number(),
    ops: v.string(),
    baseToken: v.string(),
    expectedToken: v.string(),
    inboundUuids: v.record(v.string(), v.string()),
    unmanaged: v.optional(v.union(v.literal('hold'), v.literal('acknowledge'))),
    // waiting: for confirmations (or for a busy profile); applying: claimed as
    // `opId`, its outcome is the op's; refused: the claim was refused (`code`).
    state: v.union(
      v.literal('waiting'),
      v.literal('applying'),
      v.literal('refused'),
      v.literal('cancelled'),
    ),
    code: v.optional(v.string()),
    opId: v.optional(v.id('panelOps')),
    actorAdminId: v.optional(v.id('adminUsers')),
    createdAt: v.number(),
    updatedAt: v.number(),
  })
    .index('by_server', ['backendServerId'])
    .index('by_state', ['state'])
    .index('by_state_updated', ['state', 'updatedAt'])
    .index('by_op', ['opId']),

  // One node that must let a staged change's port in. `role`: an enrolled node
  // the node role runs, confirmed by its applied report; `operator`: a node FCP
  // does not run the role for (unmanaged, or adopted), confirmed by an admin.
  panelPortRequirements: defineTable({
    backendServerId: v.id('backendServers'),
    changeId: v.id('panelPortChanges'),
    nodeName: v.string(),
    intentId: v.optional(v.id('panelNodeIntents')),
    port: v.number(),
    confirmedBy: v.union(v.literal('role'), v.literal('operator')),
    state: v.union(v.literal('waiting'), v.literal('confirmed'), v.literal('cancelled')),
    confirmedAt: v.optional(v.number()),
    byAdminId: v.optional(v.id('adminUsers')),
    createdAt: v.number(),
    updatedAt: v.number(),
  })
    .index('by_change', ['changeId'])
    .index('by_server_node', ['backendServerId', 'nodeName']),

  // One activation attempt: an immutable candidate snapshot with its own
  // approval, the candidate resources it enables or publishes, and the
  // rehearsal it recorded. The delivery commit promotes exactly this snapshot.
  panelActivationRuns: defineTable({
    backendServerId: v.id('backendServers'),
    intentId: v.id('panelNodeIntents'),
    // A fronted node's guided setup run that publishes this candidate: set at
    // approval, immutable (ownership, never an attempt fence).
    setupRunId: v.optional(v.id('edgeSetupRuns')),
    generation: v.number(),
    stepVersion: v.number(),
    state: v.union(
      v.literal('review'),
      v.literal('running'),
      v.literal('blocked'),
      v.literal('committed'),
      v.literal('superseded'),
      v.literal('failed'),
    ),
    stage: v.union(
      v.literal('hosts'),
      v.literal('publish'),
      v.literal('rehearse'),
      v.literal('commit'),
      v.literal('done'),
    ),
    candidate: v.object({
      machineRevision: v.number(),
      configRevision: v.string(),
      authRevision: v.optional(v.string()),
      deliveryRevision: v.string(),
      reviewHash: v.string(),
      // The review card, non-secret (what the approval named).
      review: v.string(),
      approval: v.optional(v.object({ byAdminId: v.optional(v.id('adminUsers')), at: v.number() })),
    }),
    resources: v.object({ hostUuids: v.array(v.string()), edgeIds: v.array(v.string()) }),
    // The reviewed delivery snapshot: the committed edges this activation keeps
    // plus its candidates. The rehearsal renders it and the commit promotes
    // exactly it; `resources` stays what the run OWNS (the gate's candidates,
    // what a cancel removes).
    delivery: v.optional(v.object({ edgeIds: v.array(v.string()) })),
    rehearsal: v.optional(
      v.object({
        at: v.number(),
        ok: v.boolean(),
        families: v.array(v.string()),
        detail: v.optional(v.string()),
      }),
    ),
    code: v.optional(v.string()),
    events: v.array(v.object({ at: v.number(), code: v.string() })),
    createdAt: v.number(),
    updatedAt: v.number(),
  })
    .index('by_intent', ['intentId'])
    .index('by_state', ['state'])
    .index('by_state_updated', ['state', 'updatedAt']),

  // The retirement ladder of one node (docs/servers.md "Retirement").
  panelRetirements: defineTable({
    backendServerId: v.id('backendServers'),
    intentId: v.id('panelNodeIntents'),
    stage: v.union(
      v.literal('requested'),
      v.literal('needs_admin'),
      v.literal('draining'),
      v.literal('panel_removed'),
      v.literal('ready_to_wipe'),
      v.literal('retired'),
    ),
    // Moving members to another node is not offered; a retired node's members
    // get the edge-required unavailable behaviour.
    disposition: v.optional(v.literal('keep-dark')),
    requestedBy: v.union(v.literal('role'), v.literal('admin')),
    code: v.optional(v.string()),
    // Where `draining` stopped last (the admin page words the ladder from it).
    step: v.optional(
      v.union(
        v.literal('origin'),
        v.literal('credentials'),
        v.literal('addresses'),
        v.literal('dns'),
        v.literal('panel_row'),
      ),
    ),
    events: v.array(v.object({ at: v.number(), code: v.string() })),
    createdAt: v.number(),
    updatedAt: v.number(),
  }).index('by_intent', ['intentId']),

  // External side effects of the workflows above, persisted BEFORE the call.
  // A superseded owner generation never releases an unresolved one; on
  // settlement the result is reconciled against current desired state
  // (reuse / retain / delete) rather than cleaned up by rule.
  backendObligations: defineTable({
    backendServerId: v.id('backendServers'),
    ownerKind: v.union(
      v.literal('setup'),
      v.literal('intent'),
      v.literal('activation'),
      v.literal('retirement'),
    ),
    ownerId: v.string(),
    ownerGeneration: v.number(),
    attemptId: v.string(),
    kind: v.union(
      v.literal('profile.create'),
      v.literal('dns.record'),
      v.literal('host'),
      v.literal('node'),
      v.literal('test_credential'),
      v.literal('edge_publication'),
      v.literal('mirror.withdraw'),
      v.literal('mirror.replace'),
      v.literal('machine_cleanup'),
    ),
    identity: v.string(),
    verb: v.union(v.literal('create'), v.literal('update'), v.literal('delete')),
    ownership: v.union(v.literal('created'), v.literal('adopted'), v.literal('shared')),
    state: v.union(
      v.literal('pending'),
      v.literal('sent'),
      v.literal('unresolved'),
      v.literal('confirmed'),
      v.literal('failed'),
    ),
    intent: v.string(), // JSON, non-secret (a DNS record's name and content, a Host tuple)
    resourceRef: v.optional(v.string()),
    // Where a DNS record lives: cleanup uses this, never the setup's current account.
    dns: v.optional(
      v.object({
        accountId: v.id('edgeProviderAccounts'),
        zoneId: v.string(),
        zoneName: v.string(),
        recordId: v.optional(v.string()),
        marker: v.string(),
      }),
    ),
    code: v.optional(v.string()),
    sentAt: v.optional(v.number()),
    settledAt: v.optional(v.number()),
    createdAt: v.number(),
    updatedAt: v.number(),
  })
    .index('by_owner', ['ownerKind', 'ownerId'])
    .index('by_server_kind_identity', ['backendServerId', 'kind', 'identity'])
    .index('by_state', ['state'])
    .index('by_state_updated', ['state', 'updatedAt']),

  // Detector dedupe marks: one contribution per member per detector window,
  // ACROSS origins: the key is a peppered HMAC of the member alone (see
  // `http.ts`: `origin-mark:<userId>`), with no origin in it, so a member who
  // reports about two origins inside one window is counted once. `key` is
  // computed in the HTTP action; the issueReports row itself carries only the
  // resulting 0/1 weight.
  relayReportMarks: defineTable({
    key: v.string(),
    firstAt: v.number(),
    expiresAt: v.number(),
  })
    .index('by_key', ['key'])
    .index('by_expiresAt', ['expiresAt']),

  // Test block evidence on a test deployment (convex/edgeSimulations.ts,
  // docs/edges.md "Simulating a block on a test deployment"): while live, the
  // block detector reads its edge as blocked in its country. Only accepted
  // where EDGE_SIMULATOR_ALLOW opts in (or local development). One live per
  // edge; a detector start that answers it consumes it atomically.
  edgeBlockSimulations: defineTable({
    relayId: v.id('relays'),
    edgeId: v.id('edges'),
    country: v.string(),
    reporters: v.number(),
    startedAt: v.number(),
    expiresAt: v.number(),
    startedBy: v.optional(v.id('adminUsers')),
    endedAt: v.optional(v.number()),
    endReason: v.optional(
      v.union(
        v.literal('ended'),
        v.literal('expired'),
        v.literal('consumed'),
        v.literal('disabled'),
      ),
    ),
    rotationId: v.optional(v.id('edgeRotations')),
  })
    // Open rows (`endedAt` absent) ordered by expiry: a live one is
    // `endedAt == undefined && expiresAt > now`, read as a RANGE, so expired
    // rows a stalled sweep left open never crowd a bounded read of live ones.
    .index('by_relay_live', ['relayId', 'endedAt', 'expiresAt'])
    .index('by_edge_live', ['edgeId', 'endedAt', 'expiresAt'])
    .index('by_live', ['endedAt', 'expiresAt']),

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
    // Open-source signal: OSS apps get a badge + rank ahead of proprietary ones.
    // Optional so an admin-created row without the metadata still validates.
    openSource: v.optional(v.boolean()),
    license: v.optional(v.string()), // short label: 'GPL-3.0', 'Apache-2.0', 'Proprietary'
    sourceUrl: v.optional(v.string()), // public source repo (OSS only)
    // Admin-set member-facing blurb ("why choose this app"). Shown verbatim in
    // every locale; absent = the SPA falls back to its built-in translated copy
    // for known default apps (the connection-mode label/description pattern).
    description: v.optional(v.string()),
    // Ease-of-use rating: within each open-source group, easier apps rank first
    // (missing = treated as 'moderate'). 'easy'/'advanced' also get a badge.
    easeOfUse: v.optional(v.union(v.literal('easy'), v.literal('moderate'), v.literal('advanced'))),
    // Verified IPv6-through-tunnel behavior: true works / false IPv4-only /
    // absent untested (tri-state; see lib/clientCatalog.ts).
    ipv6: v.optional(v.boolean()),
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

  // Operator-published network-status incidents (the public /status page).
  // Deliberately NOT auto-derived from healthcheck flapping: a human writes and
  // resolves each entry, so the page stays trustworthy. `locationCodes` scopes
  // an incident to fleet locations (empty = global). Unresolved rows show at any
  // age; resolved rows show for 30 days, then only in the admin list.
  statusIncidents: defineTable({
    title: v.string(),
    body: v.optional(v.string()),
    severity: v.union(v.literal('maintenance'), v.literal('degraded'), v.literal('outage')),
    locationCodes: v.array(v.string()),
    startedAt: v.number(),
    resolvedAt: v.optional(v.number()),
    updatedAt: v.number(),
  }).index('by_startedAt', ['startedAt']),

  // Member issue telemetry (Admin → Telemetry): one row per switch-server /
  // report-issue event. DELIBERATELY UNLINKED — no userId, no subscriptionId,
  // never an IP (docs/privacy.md): the table answers "what is failing, where,
  // on which networks", not "who". Geo fields are member-consented AND
  // member-editable (a report sent through the VPN would otherwise carry the
  // exit node's geo); `detected*` is what the CDN edge claimed at submit time,
  // kept so edited values can be told apart from as-detected ones. Window scans
  // + the retention sweep use the built-in by_creation_time index. Config +
  // sanitizers: convex/lib/issueTelemetry.ts.
  issueReports: defineTable({
    kind: v.union(v.literal('switch'), v.literal('report')),
    reason: v.string(),
    // DEPRECATED (2026-09-15): the report dialog's free-text box was removed;
    // members are pointed at `site.supportEmail` instead. Nothing writes this
    // field any more. Kept only so rows written before then still validate;
    // the `issue-telemetry-retention` sweep (default 90d) drains them — drop
    // the field once no row carries it.
    detail: v.optional(v.string()),
    backend: v.string(),
    // Where the key lived when the event fired (server-resolved, not client-claimed).
    locationCode: v.optional(v.string()),
    nodeLabel: v.optional(v.string()),
    connectionModeId: v.optional(v.string()),
    // Consented, member-editable network context (null field = not shared).
    country: v.optional(v.string()),
    city: v.optional(v.string()),
    asn: v.optional(v.number()),
    detectedCountry: v.optional(v.string()),
    detectedCity: v.optional(v.string()),
    detectedAsn: v.optional(v.number()),
    // Origin attribution (server-resolved from the key's pinned node; operator
    // infrastructure labels only, still no member/subscription/IP linkage).
    relaySlug: v.optional(v.string()),
    // Which connection the member said they were using; the edge id is set ONLY
    // when that choice resolves to one edge (never inferred from the primary).
    connectionChoice: v.optional(v.string()),
    relayEdgeId: v.optional(v.string()),
    // FCP has not observed a fronted delivery of content generated after the
    // origin's last rotation for this key (an approximation, see docs/edges.md).
    refreshNotObserved: v.optional(v.boolean()),
    // 1 = this member's first eligible report for this origin inside the detector
    // window, else 0 (a deduplicated contribution, not a distinct-member count).
    detectorWeight: v.optional(v.number()),
  }).index('by_relay', ['relaySlug']),

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
    // (purchasedByUserId). Both optional so a purchased code carries no admin.
    // `by_purchaser` drives the buyer's "codes I bought" list.
    mintedByAdminId: v.optional(v.id('adminUsers')),
    purchasedByUserId: v.optional(v.id('users')),
    // Legacy field kept (optional) so pre-removal documents still pass
    // deploy-time schema validation (dropped as dead in bcc663e).
    purchasedByOrderId: v.optional(v.id('billingOrders')),
    redeemedByUserId: v.optional(v.id('users')),
    redeemedAt: v.optional(v.number()),
    updatedAt: v.number(),
  })
    .index('by_code_hash', ['codeHash'])
    .index('by_status', ['status'])
    .index('by_batch', ['batchId'])
    .index('by_purchaser', ['purchasedByUserId'])
    // Tier-delete reference check (adminApi.deleteTier) — an O(table) collect in
    // a mutation trips the read limit as code history grows.
    .index('by_tier', ['tierId']),

  // Referrals (word-of-mouth growth): ONE row per referee (uniqueness enforced
  // in the bind mutation), linking the new account to the member whose
  // referral code they used. Lifecycle: 'pending' (signed up) → 'converted'
  // (referee's FIRST paid-tier grant — the referee's bonus days applied
  // immediately, the referrer's reward vesting) → 'rewarded' (vested and
  // granted) | 'void' (referee lapsed before vesting / referrer gone / monthly
  // cap reached). Rewards only ever fire on a PAID conversion, so farming free
  // accounts is worthless by construction.
  referrals: defineTable({
    referrerUserId: v.id('users'),
    refereeUserId: v.id('users'),
    status: v.union(
      v.literal('pending'),
      v.literal('converted'),
      v.literal('rewarded'),
      v.literal('void'),
    ),
    voidReason: v.optional(v.string()),
    refereeBonusDaysGranted: v.optional(v.number()),
    referrerBonusDaysGranted: v.optional(v.number()),
    // The referrer bonus PINNED at conversion: vesting grants exactly what was
    // promised at conversion time, even if the admin edits referral.* mid-vest.
    // Absent on pre-pin rows → the vest path falls back to live config.
    referrerBonusDaysPlanned: v.optional(v.number()),
    convertedAt: v.optional(v.number()),
    rewardedAt: v.optional(v.number()),
    updatedAt: v.number(),
  })
    .index('by_referee', ['refereeUserId'])
    .index('by_referrer', ['referrerUserId'])
    // Monthly reward-cap counting: eq referrer + range rewardedAt >= month start.
    .index('by_referrer_rewarded', ['referrerUserId', 'rewardedAt']),

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
    // Legacy field kept (optional) so pre-removal session documents still pass
    // deploy-time schema validation; they age out via expiresAt and can be
    // dropped permanently once the fleet is clean (removed in bcc663e).
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
    .index('by_expires', ['expiresAt'])
    // Hard-delete cascades (lifecycle.deleteInactiveUser) drop a user's sessions
    // by userId; the daily expiry sweep can't key off identity.
    .index('by_user', ['userId']),

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
  // mechanism: an operator runs hpkeCrypto.signRevocation to publish a new
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
