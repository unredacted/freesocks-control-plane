/**
 * Relay-edge contracts (admin surface `/api/v1/admin/edges/*`): the zod shapes
 * the SPA parses. The provider id enum derives from EDGE_PROVIDER_IDS so it can
 * never drift from the Convex validator. Every route under the prefix is
 * HPKE-sealed by verb class (src/shared/crypto/envelope.ts).
 */
import { z } from 'zod';
import { AuditEntry } from './admin';
import {
  ATTENTION_ACTIONS,
  ATTENTION_KINDS,
  ATTENTION_SEVERITIES,
  INBOUND_UNSUPPORTED_CODES,
  PREFLIGHT_KINDS,
  RESTORE_PHASES,
  RESTORE_PURPOSES,
  SETUP_RUN_STAGES,
  SETUP_RUN_STATES,
  SETUP_STEP_IDS,
  SETUP_STEP_STATUSES,
} from './edgeCodes';
import { EDGE_PROVIDER_IDS } from './edgeProviderIds';
import {
  LISTENER_PROTOCOL_IDS,
  LISTENER_SECURITY_IDS,
  LISTENER_STREAM_TRANSPORT_IDS,
} from './edgeProtocolIds';

export { EDGE_PROVIDER_IDS, isRelayProviderId } from './edgeProviderIds';
export type EdgeProviderId = import('./edgeProviderIds').EdgeProviderId;
export const EdgeProviderId = z.enum(EDGE_PROVIDER_IDS);

const iso = z.string();
const isoN = z.string().nullable();

// --- provider accounts ------------------------------------------------------------

export const EdgeProviderAccountAdmin = z.object({
  id: z.string(),
  provider: EdgeProviderId,
  name: z.string(),
  settings: z.record(z.string(), z.unknown()),
  credentialsSet: z.record(z.string(), z.boolean()),
  defaultTemplateId: z.string().nullable(),
  enabled: z.boolean(),
  qualified: z.boolean(),
  qualifiedTemplateHash: z.string().nullable(),
  /** Who trusted the account and, when it came from an endpoint, which edge (ids and dates only). */
  qualification: z
    .object({
      by: z.enum(['admin', 'auto']),
      at: iso,
      edgeId: z.string().nullable().default(null),
      proofCheckedAt: isoN.default(null),
    })
    .nullable()
    .default(null),
  /** A manual untrust holds the automatic trust rules off until an operator trusts again. */
  autoQualifyHold: z.boolean().default(false),
  priority: z.number(),
  dailyAllocationBudget: z.number(),
  allocationsToday: z.number(),
  maxLiveEdges: z.number(),
  lastTestOkAt: isoN,
  lastTestError: z.string().nullable(),
  /** What the last credential test OBSERVED at the provider (e.g. `zoneSslMode`). */
  observedSettings: z.record(z.string(), z.string()).nullable().default(null),
  observedAt: isoN.default(null),
  inventoryAt: isoN,
  /** Dev only: the adapter behind this account is the in-memory fake (never true outside development). */
  fake: z.boolean().default(false),
  createdAt: iso,
  updatedAt: iso,
});
export type EdgeProviderAccountAdmin = z.infer<typeof EdgeProviderAccountAdmin>;
export const EdgeProviderAccountList = z.array(EdgeProviderAccountAdmin);

export const EdgeCredentialFields = z.record(z.string(), z.array(z.string()));
export const EdgeProviderAccountsResponse = z.object({
  accounts: EdgeProviderAccountList,
  credentialFields: EdgeCredentialFields,
});
export type EdgeProviderAccountsResponse = z.infer<typeof EdgeProviderAccountsResponse>;

export const EdgeTestCredentialsResponse = z.object({
  ok: z.boolean(),
  code: z.string().nullable(),
  regions: z.array(z.object({ id: z.string(), label: z.string() })),
});
export type EdgeTestCredentialsResponse = z.infer<typeof EdgeTestCredentialsResponse>;

/**
 * POST …/providers/{id}/rotate-credentials: the new secret is tested first and
 * applied only on a pass (qualification kept). Booleans only, never a value.
 */
export const EdgeRotateCredentialsResponse = z.union([
  z.object({
    ok: z.literal(true),
    qualified: z.boolean(),
    credentialsChanged: z.boolean(),
    identifiersChanged: z.boolean(),
  }),
  z.object({ ok: z.literal(false), code: z.string() }),
]);
export type EdgeRotateCredentialsResponse = z.infer<typeof EdgeRotateCredentialsResponse>;

const DiscoverOption = z.object({ id: z.string(), label: z.string() });
/** POST …/providers/discover: choice lists for the account form given credentials + partial settings. */
export const EdgeDiscoverResponse = z.object({
  projects: z.array(DiscoverOption).optional(),
  regions: z.array(DiscoverOption).optional(),
  networks: z.array(DiscoverOption.extend({ subnets: z.array(DiscoverOption) })).optional(),
  /** L7: DNS zones (Cloudflare) and TLS configurations (Fastly). */
  zones: z.array(DiscoverOption).optional(),
  tlsConfigurations: z.array(DiscoverOption).optional(),
  errors: z.record(z.string(), z.string()).optional(),
});
export type EdgeDiscoverResponse = z.infer<typeof EdgeDiscoverResponse>;

export const EdgeInventory = z.object({
  loadBalancers: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      status: z.string().optional(),
      addresses: z.object({
        v4: z.string().optional(),
        v6: z.string().optional(),
        hostname: z.string().optional(),
      }),
      createdAt: z.string().optional(),
      /** True when no edge ledger references this resource (an unowned LB). */
      unowned: z.boolean().optional(),
      /** L7 import: what the front dials (must equal the relay's origin to be owned). */
      content: z.string().optional(),
      /** L7 import: every hostname the resource serves (ownership boundary). */
      hostnames: z.array(z.string()).optional(),
    }),
  ),
  ips: z.array(
    z.object({ id: z.string(), address: z.string(), attachedTo: z.string().nullable().optional() }),
  ),
  flavors: z.array(z.object({ id: z.string(), label: z.string() })),
});
export const EdgeInventoryResponse = z.object({
  inventory: EdgeInventory.nullable(),
  inventoryAt: isoN,
});
export type EdgeInventoryResponse = z.infer<typeof EdgeInventoryResponse>;

// --- templates --------------------------------------------------------------------------

export const EdgeTemplateField = z.object({
  key: z.string(),
  label: z.string(),
  type: z.enum(['string', 'number', 'boolean', 'select', 'string-list']),
  help: z.string().optional(),
  options: z.array(z.object({ value: z.string(), label: z.string() })).optional(),
  required: z.boolean().optional(),
});
export type EdgeTemplateField = z.infer<typeof EdgeTemplateField>;

export const EdgeTemplateAdmin = z.object({
  id: z.string(),
  provider: EdgeProviderId,
  accountId: z.string().nullable(),
  name: z.string(),
  params: z.unknown(),
  paramsHash: z.string(),
  isDefault: z.boolean(),
  updatedAt: iso,
});
export type EdgeTemplateAdmin = z.infer<typeof EdgeTemplateAdmin>;

export const EdgeTemplatesResponse = z.object({
  templates: z.array(EdgeTemplateAdmin),
  schemas: z.record(
    z.string(),
    z.object({ fields: z.array(EdgeTemplateField), defaults: z.record(z.string(), z.unknown()) }),
  ),
});
export type EdgeTemplatesResponse = z.infer<typeof EdgeTemplatesResponse>;

export const EdgeTemplateValidateResponse = z.union([
  z.object({ ok: z.literal(true), params: z.unknown(), paramsHash: z.string() }),
  z.object({ ok: z.literal(false), issues: z.array(z.string()) }),
]);
export type EdgeTemplateValidateResponse = z.infer<typeof EdgeTemplateValidateResponse>;

// --- listener catalogue -------------------------------------------------------------------------

export const ListenerProtocolId = z.enum(LISTENER_PROTOCOL_IDS);
export const ListenerStreamTransport = z.enum(LISTENER_STREAM_TRANSPORT_IDS);
export const ListenerSecurity = z.enum(LISTENER_SECURITY_IDS);
export type ListenerProtocolId = z.infer<typeof ListenerProtocolId>;
export type ListenerStreamTransport = z.infer<typeof ListenerStreamTransport>;
export type ListenerSecurity = z.infer<typeof ListenerSecurity>;

// --- relays / listeners / edges / rotations ----------------------------------------------------

/** The restore workflow (docs/edges.md § "Direct-Host hides and the restore workflow") in progress on a relay. */
export const RelayRestore = z.object({
  purpose: z.enum(RESTORE_PURPOSES),
  phase: z.enum(RESTORE_PHASES),
  startedAt: z.string(),
  attempt: z.number(),
  lastError: z.string().nullable().default(null),
});
export type RelayRestore = z.infer<typeof RelayRestore>;

export const RelaySuspicion = z.object({
  state: z.enum(['clear', 'suspected']),
  hintLevel: z.enum(['none', 'reports', 'probes', 'corroborated']),
  score: z.number(),
  reportScore: z.number(),
  loadScore: z.number(),
  probeScore: z.number(),
  scope: z.enum(['global', 'regional']).nullable(),
  countries: z.array(z.object({ code: z.string(), count: z.number() })),
  edgeEvidence: z.array(
    z.object({
      edgeId: z.string(),
      source: z.enum(['reports', 'probes']),
      countries: z.array(z.string()),
    }),
  ),
  firstSeenAt: isoN,
  lastEvalAt: iso,
  quietEvals: z.number(),
  baselineWarm: z.boolean(),
  veto: z.string().nullable(),
  hint: z.string().optional(),
  lastRotateError: z.string().optional(),
});

/** Where a relay's origin is (lib/edges/origin.ts). */
export const RelayOrigin = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('panel-node'),
    backendServerId: z.string(),
    nodeName: z.string(),
    nodeUuid: z.string().nullable(),
  }),
  z.object({ kind: z.literal('backend-server'), backendServerId: z.string() }),
  z.object({ kind: z.literal('manual') }),
]);
export type RelayOrigin = z.infer<typeof RelayOrigin>;
export const HOST_MODE_IDS = ['fcp', 'operator', 'none'] as const;
export const HostMode = z.enum(HOST_MODE_IDS);
export type HostMode = z.infer<typeof HostMode>;

export const RelayAdmin = z.object({
  id: z.string(),
  slug: z.string(),
  label: z.string().nullable().default(null),
  origin: RelayOrigin,
  originAddress: z.string(),
  locationCode: z.string().nullable(),
  /** Who writes the client-facing panel Hosts: FCP, the operator, or nobody (no Host). */
  hostMode: HostMode,
  delivery: z.literal('edge-required'),
  enabled: z.boolean(),
  autoRotate: z.boolean(),
  probeNode: z.boolean().default(false),
  /** An L7 front-qualification credential is minted for this relay. */
  qualificationCredential: z.boolean().default(false),
  qualificationModeSlug: z.string().nullable().default(null),
  reachability: z
    .object({ byCountry: z.array(z.unknown()), updatedAt: isoN })
    .nullable()
    .default(null),
  providerPreference: EdgeProviderId.nullable(),
  desiredPublished: z.number(),
  standbyPerRelay: z.number(),
  /** Verified standbys kept per coverage listener (null = the config default). */
  standbyPerListener: z.number().nullable().default(null),
  /** The delivery binding is deferred to go-live (a guided relay): members still get the raw body. */
  bindingDeferred: z.boolean().default(false),
  /** A guided setup owns the relay: upkeep and automatic replacement skip it. */
  setupOwned: z.boolean().default(false),
  cooldownMinutes: z.number(),
  maxRotationsPerDay: z.number(),
  drainMinutes: z.number(),
  publicationEpoch: z.number(),
  publishedEdgeIds: z.array(z.string().nullable()),
  publishedCount: z.number(),
  standbyEdgeIds: z.array(z.string()),
  activeRotationId: z.string().nullable(),
  cooldownUntil: isoN,
  rotationsToday: z.number(),
  lastRotatedAt: isoN,
  lastRegisteredAt: isoN.default(null),
  quarantine: z.object({ rotationId: z.string(), since: iso, reason: z.string() }).nullable(),
  deleting: z.boolean(),
  /** The persisted restore workflow in progress (hides settled, binding released, direct Hosts back), if any. */
  restore: RelayRestore.nullable().default(null),
  suspicion: RelaySuspicion.nullable(),
  updatedAt: iso,
});
export type RelayAdmin = z.infer<typeof RelayAdmin>;

export const EDGE_LAYER_IDS = ['l4', 'l7'] as const;
export const EdgeLayer = z.enum(EDGE_LAYER_IDS);
export type EdgeLayer = z.infer<typeof EdgeLayer>;
/** How a listener's inbound is reached behind an L7 front (declared by the node role). */
export const ListenerOriginTransport = z.object({
  scheme: z.enum(['http', 'https']),
  certPublic: z.boolean(),
  certNames: z.array(z.string()),
  acceptsHostHeader: z.enum(['any', 'names']),
});
export type ListenerOriginTransport = z.infer<typeof ListenerOriginTransport>;
export const ListenerMatchRule = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('remark'), remark: z.string() }),
  z.object({ kind: z.literal('address') }),
  z.object({ kind: z.literal('whole-body') }),
]);
export type ListenerMatchRule = z.infer<typeof ListenerMatchRule>;
export const ListenerName = z.object({
  name: z.string(),
  status: z.enum(['active', 'retired']),
  retiredAt: isoN,
  drainUntil: isoN,
  retiredBy: z.enum(['admin', 'role']).nullable().default(null),
});
export const LISTENER_HOST_STATES = [
  'absent',
  'creating',
  'present',
  'deleting',
  'unresolved',
  'ambiguous',
] as const;
export const ListenerHostState = z.enum(LISTENER_HOST_STATES);

/** One listener as the CMS sees it. */
export const RelayListenerAdmin = z.object({
  id: z.string(),
  relayId: z.string(),
  listenerKey: z.string(),
  protocol: ListenerProtocolId,
  streamTransport: ListenerStreamTransport,
  security: ListenerSecurity,
  label: z.string().optional(),
  transport: z.enum(['tcp', 'udp']),
  originPort: z.number(),
  tlsNames: z.array(ListenerName),
  realityTarget: z.object({ address: z.string(), port: z.number() }).nullable(),
  transportParams: z
    .object({
      path: z.string().optional(),
      host: z.string().optional(),
      serviceName: z.string().optional(),
      upgradeToken: z.string().optional(),
    })
    .nullable(),
  originTransport: ListenerOriginTransport.nullable(),
  providerScope: z
    .object({ provider: EdgeProviderId, accountId: z.string().nullable() })
    .nullable(),
  matchRule: ListenerMatchRule,
  panelBinding: z
    .object({
      inboundTag: z.string(),
      configProfileUuid: z.string(),
      configProfileInboundUuid: z.string(),
    })
    .nullable(),
  host: z
    .object({
      state: ListenerHostState,
      uuid: z.string().nullable(),
      ownership: z.enum(['fcp', 'adopted']).nullable(),
      pendingOp: z.object({ kind: z.enum(['create', 'delete']), attempts: z.number() }).nullable(),
    })
    .nullable(),
  legacyHosts: z.array(z.object({ uuid: z.string(), remark: z.string() })).default([]),
  templateEdgeId: z.string().nullable(),
  templateHostRemark: z.string().nullable(),
  source: z.enum(['role', 'admin']),
  /** Layers that can front this listener given its complete chain, and why the others cannot. */
  layers: z.array(EdgeLayer),
  excluded: z.record(z.string(), z.string()).default({}),
  enabled: z.boolean(),
  deployed: z.boolean(),
  deployedAt: isoN,
  retired: z.boolean(),
  revision: z.number(),
  updatedAt: iso,
});
export type RelayListenerAdmin = z.infer<typeof RelayListenerAdmin>;

/** One listener as a registration body (the node role's PUT, the admin form) carries it. */
export const ListenerSpec = z.object({
  listenerKey: z.string(),
  protocol: ListenerProtocolId,
  streamTransport: ListenerStreamTransport,
  security: ListenerSecurity,
  originPort: z.number().int(),
  tlsNames: z.array(z.string()).nullish(),
  realityTarget: z.object({ address: z.string(), port: z.number().int() }).nullish(),
  transportParams: z
    .object({
      path: z.string().optional(),
      host: z.string().optional(),
      serviceName: z.string().optional(),
      upgradeToken: z.string().optional(),
    })
    .nullish(),
  originTransport: ListenerOriginTransport.nullish(),
  panelBinding: z
    .object({
      inboundTag: z.string(),
      configProfileUuid: z.string(),
      configProfileInboundUuid: z.string(),
    })
    .nullish(),
  matchRule: ListenerMatchRule.nullish(),
  providerScope: z.object({ provider: EdgeProviderId, accountId: z.string().optional() }).nullish(),
  deployed: z.boolean().optional(),
});
export type ListenerSpec = z.infer<typeof ListenerSpec>;

/** The wire origin of a registration body: the backend by SLUG (the role never knows ids). */
export const RelayWireOrigin = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('panel-node'),
    backendSlug: z.string(),
    nodeName: z.string(),
    nodeUuid: z.string().nullish(),
  }),
  z.object({ kind: z.literal('backend-server'), backendSlug: z.string() }),
  z.object({ kind: z.literal('manual') }),
]);
/** `PUT /api/v1/admin/edges/relays/by-slug/{slug}`: one idempotent body (docs/edges.md). */
export const RelayRegisterBody = z.object({
  origin: RelayWireOrigin,
  originAddress: z.string(),
  locationCode: z.string().nullish(),
  label: z.string().nullish(),
  listeners: z.array(ListenerSpec),
  pruneListeners: z.boolean().optional(),
  hostModeRequest: z.literal('operator').optional(),
});
export type RelayRegisterBody = z.infer<typeof RelayRegisterBody>;

/** Edge addresses: IP literals for an L4 edge, the fronted hostname for an L7 edge. */
export const EdgeAddresses = z.object({
  v4: z.string().nullable(),
  v6: z.string().nullable(),
  hostname: z.string().nullable().default(null),
});
export type EdgeAddresses = z.infer<typeof EdgeAddresses>;

export const EdgeStep = z.object({
  stepId: z.string(),
  kind: z.string(),
  state: z.string(),
  attempt: z.number().optional(),
  startedAt: isoN,
  finishedAt: isoN,
});
export const ProbeReachabilityCountry = z.object({
  country: z.string(),
  /** The IPv4 path's verdict (IPv6 only when the edge was probed over v6 alone). */
  verdict: z.enum(['reachable', 'unreachable', 'mixed', 'unknown']),
  /** The IPv6 path, when the edge has one and it was probed. */
  v6Verdict: z.enum(['reachable', 'unreachable', 'mixed', 'unknown']).optional(),
  /**
   * The by-name path, when the target was also probed by hostname. A hostname
   * (L7) target has no family of its own: there the name path IS `verdict` and
   * this stays absent.
   */
  nameVerdict: z.enum(['reachable', 'unreachable', 'mixed', 'unknown']).optional(),
  okVantages: z.number(),
  failVantages: z.number(),
  lastAt: iso,
});
/** The L4 endpoint-verification view an admin edge carries (see `EdgeAdmin.verification`). */
export const EdgeVerificationView = z.object({
  required: z.boolean(),
  /** Null when the listener could not be read (the view was built without it). */
  current: z.boolean().nullable(),
  stale: z.boolean().nullable(),
  record: z
    .object({
      rung: z.enum(['partial', 'verified']),
      by: z.enum(['admin', 'system']),
      at: iso,
      /** `probe` = the system's `partial` rung from probe evidence (never satisfies the gate). */
      method: z.enum(['test_link', 'named_connection', 'l7_proof', 'probe']),
      listenerKey: z.string(),
      listenerRevision: z.number(),
    })
    .nullable(),
});
export type EdgeVerificationView = z.infer<typeof EdgeVerificationView>;

/**
 * `GET edges/{id}/verification-binding`: what the operator is about to test.
 * `POST edges/{id}/verify` must echo `endpoint`, `listenerRevision` and
 * `configHash` exactly; the server recomputes them and refuses a mismatch.
 */
export const EdgeVerificationBinding = z.object({
  edgeId: z.string(),
  layer: EdgeLayer,
  endpoint: z.string(),
  listenerKey: z.string(),
  listenerRevision: z.number(),
  configHash: z.string(),
  verification: EdgeVerificationView,
  /** The gate would pass once this endpoint is confirmed (nothing else blocks it). */
  publishableAfter: z.boolean(),
  /** The other blocker, when one exists (a `checkPublishable` code). */
  blocker: z.string().nullable(),
});
export type EdgeVerificationBinding = z.infer<typeof EdgeVerificationBinding>;

/**
 * `GET edges/{id}/test-link`: the isolated test link for an L4 candidate (the
 * candidate connection only, rendered from the test credential's own body)
 * plus the binding `POST edges/{id}/verify` must echo (the same one
 * `verification-binding` derives).
 */
export const EdgeTestLinkResponse = z.object({
  link: z.string(),
  format: z.literal('links'),
  binding: z.object({
    edgeId: z.string(),
    endpoint: z.string(),
    listenerKey: z.string(),
    listenerRevision: z.number(),
    configHash: z.string(),
    issuedAt: iso,
  }),
  /** The temporary credential behind the link (Outline), released when the sheet closes. */
  credentialId: z.string().nullable(),
});
export type EdgeTestLinkResponse = z.infer<typeof EdgeTestLinkResponse>;

export const EdgeVerifyRequest = z.object({
  endpoint: z.string(),
  listenerRevision: z.number(),
  configHash: z.string(),
  method: z.enum(['test_link', 'named_connection']).default('test_link'),
});
export type EdgeVerifyRequest = z.infer<typeof EdgeVerifyRequest>;

export const EdgeVerifyResponse = z.object({
  ok: z.literal(true),
  edgeId: z.string(),
  verifiedAt: iso,
  /** The first confirmed endpoint of an untrusted account also trusted the account. */
  accountTrusted: z.boolean(),
  /**
   * Why the account was NOT trusted by this tick (null when it was, or when
   * the edge has no account): `already_qualified`, `hold`, `account_untested`,
   * `tested_before_credential_change`, `template_mismatch`, `account_not_found`.
   */
  accountTrustReason: z.string().nullable().default(null),
});
export type EdgeVerifyResponse = z.infer<typeof EdgeVerifyResponse>;

export const EdgeAdmin = z.object({
  id: z.string(),
  relayId: z.string(),
  listenerId: z.string(),
  accountId: z.string().nullable(),
  templateId: z.string().nullable(),
  templateHash: z.string().nullable(),
  provider: EdgeProviderId.nullable(),
  managed: z.boolean(),
  name: z.string(),
  steps: z.array(EdgeStep),
  resources: z.array(
    z.object({
      stepId: z.string(),
      kind: z.string(),
      resourceId: z.string(),
      ownership: z.enum(['created', 'adopted']),
      deleteState: z.enum(['present', 'delete_requested', 'confirmed_gone']),
    }),
  ),
  currentOp: z
    .object({
      opId: z.string(),
      kind: z.string(),
      target: z.string(),
      attempt: z.number(),
      claimedAt: iso,
      expiresAt: iso,
    })
    .nullable(),
  listeners: z.array(
    z.object({ edgePort: z.number(), originAddress: z.string(), originPort: z.number() }),
  ),
  addresses: EdgeAddresses,
  layer: EdgeLayer.default('l4'),
  readiness: z
    .object({
      dns: z.enum(['ready', 'pending', 'failed', 'unknown']),
      certificate: z.enum(['ready', 'pending', 'failed', 'unknown']),
      front: z.enum(['ready', 'pending', 'failed', 'unknown']),
      checkedAt: iso,
    })
    .nullable()
    .default(null),
  frontQualification: z
    .object({
      ok: z.boolean(),
      code: z.string().nullable(),
      checkedAt: iso,
      expiresAt: iso,
      /** True when the binding still matches the current listener/intent and has not expired. */
      current: z.boolean(),
    })
    .nullable()
    .default(null),
  /**
   * L4 endpoint verification (the operator's per-endpoint confirmation, bound
   * to the listener revision + configuration hash). `required` is false for an
   * L7 edge (verified by its proof); `current` is what the publication gate
   * reads; `stale` = a record exists but no longer describes the live
   * configuration (a retest is due).
   */
  verification: EdgeVerificationView.default({
    required: true,
    current: null,
    stale: null,
    record: null,
  }),
  publication: z.enum(['unpublished', 'published', 'draining']),
  poolIndex: z.number().nullable(),
  publishedAt: isoN,
  status: z.string(),
  statusChangedAt: iso,
  health: z.enum(['online', 'offline', 'degraded', 'unknown']),
  lastHealthAt: isoN,
  liveAt: isoN,
  reachability: z
    .object({ byCountry: z.array(ProbeReachabilityCountry), updatedAt: iso })
    .nullable(),
  destroyAttempts: z.number(),
  failure: z
    .object({ step: z.string(), code: z.string().optional(), status: z.number().optional() })
    .nullable(),
  burnedAt: isoN,
  drainUntil: isoN,
  destroyedAt: isoN,
  progress: z.object({ done: z.number(), total: z.number(), percent: z.number() }),
  createdAt: iso,
  updatedAt: iso,
});
export type EdgeAdmin = z.infer<typeof EdgeAdmin>;

export const EdgeLive = z.object({
  summary: z
    .object({
      status: z.string().optional(),
      operatingStatus: z.string().optional(),
      flavor: z.string().optional(),
      region: z.string().optional(),
      createdAt: z.string().optional(),
      addresses: z.object({
        v4: z.string().optional(),
        v6: z.string().optional(),
        hostname: z.string().optional(),
      }),
      members: z.array(
        z.object({ address: z.string(), port: z.number(), health: z.string().optional() }),
      ),
      listeners: z.array(z.object({ port: z.number(), protocol: z.string().optional() })),
      stats: z
        .object({
          connections: z.number().optional(),
          bytesIn: z.number().optional(),
          bytesOut: z.number().optional(),
        })
        .optional(),
    })
    .passthrough(),
  /**
   * The provider's own describe() payload as recorded by the last live pull.
   * Operator-only diagnostics: the CMS never renders it by default (the summary
   * is the view); it sits behind an explicit "show raw" toggle. The server is
   * expected to prune it to a curated key set before storing — treat it as
   * potentially containing provider-internal identifiers, never credentials.
   */
  raw: z.unknown(),
  liveAt: iso,
});
export type EdgeLive = z.infer<typeof EdgeLive>;
/** The last probe runs against one edge, as the detail view lists them. */
export const EdgeDetailProbe = z.object({
  id: z.string(),
  source: z.string(),
  status: z.string(),
  requestedAt: iso,
  okVantages: z.number().int(),
  failVantages: z.number().int(),
});
export const EdgeDetail = z.object({
  edge: EdgeAdmin,
  live: EdgeLive.nullable(),
  probes: z.array(EdgeDetailProbe),
});
export type EdgeDetail = z.infer<typeof EdgeDetail>;
export const EdgeLiveResponse = z.object({ live: EdgeLive.nullable() });

export const EdgeRotationAdmin = z.object({
  id: z.string(),
  relayId: z.string(),
  kind: z.enum(['provision', 'publish', 'replace']),
  trigger: z.enum(['manual', 'detector', 'api', 'reconcile']),
  burn: z.boolean(),
  force: z.boolean(),
  targetEdgeId: z.string().nullable(),
  toEdgeId: z.string().nullable(),
  phase: z.string(),
  terminal: z.boolean(),
  stepVersion: z.number(),
  cancelRequested: z.boolean(),
  /** Whether a cancel would be accepted right now (the server's own rule). */
  cancellable: z.boolean().default(false),
  /** The listener the run is for; null when it names none. */
  listenerKey: z.string().nullable().default(null),
  outcome: z.string().nullable(),
  reason: z.string().nullable(),
  steps: z.array(EdgeStep),
  progress: z.object({ done: z.number(), total: z.number(), percent: z.number() }),
  events: z.array(
    z.object({
      at: iso,
      level: z.enum(['info', 'warn', 'error']),
      code: z.string(),
      detail: z.string().nullable(),
    }),
  ),
  edge: z
    .object({
      id: z.string(),
      provider: EdgeProviderId.nullable(),
      addresses: EdgeAddresses,
      health: z.string(),
      status: z.string(),
    })
    .nullable(),
  hostPlanSize: z.number(),
  flipAttempts: z.number(),
  rollbackAttempts: z.number(),
  startedAt: iso,
  provisionedAt: isoN,
  flippedAt: isoN,
  finishedAt: isoN,
  updatedAt: iso,
});
export type EdgeRotationAdmin = z.infer<typeof EdgeRotationAdmin>;
/** One rotation with its merged audit trail (rotation-, relay- and edge-targeted rows). */
export const EdgeRotationDetail = EdgeRotationAdmin.extend({
  audit: z.array(AuditEntry).default([]),
});
export type EdgeRotationDetail = z.infer<typeof EdgeRotationDetail>;

// --- probes -------------------------------------------------------------------------------------

export const PROBE_TARGET_KINDS = ['edge', 'relay', 'custom'] as const;
export const ProbeTargetKind = z.enum(PROBE_TARGET_KINDS);
export type ProbeTargetKind = z.infer<typeof ProbeTargetKind>;
export const ProbeTargetRef = z.object({ kind: ProbeTargetKind, ref: z.string(), key: z.string() });

export const ProbeReachabilitySummary = z.object({
  byCountry: z.array(ProbeReachabilityCountry),
  updatedAt: isoN,
});
export type ProbeReachabilitySummary = z.infer<typeof ProbeReachabilitySummary>;

export const ProbeRunAdmin = z.object({
  id: z.string(),
  target: ProbeTargetRef,
  source: z.enum(['globalping', 'checkhost', 'ripeatlas', 'internal']),
  /** Observed address family; null when probed by name. */
  ipVersion: z
    .union([z.literal(4), z.literal(6)])
    .nullable()
    .default(null),
  addressKind: z.enum(['ip', 'name']).default('ip'),
  probeProtocol: z.enum(['tcp', 'tls', 'https', 'tls-sni']).default('tcp'),
  /** The family FCP asked for; `any` for a name (the vantage's resolver picks). */
  requestedFamily: z.union([z.literal(4), z.literal(6), z.literal('any')]).default(4),
  /** The listener port this run probed (a multi-port edge gets one run per port). */
  port: z.number().int().nullable().optional(),
  status: z.enum(['requested', 'running', 'finished', 'failed', 'timeout']),
  trigger: z.enum(['cron', 'manual', 'detector', 'qualification']),
  requestedAt: iso,
  finishedAt: isoN,
  okVantages: z.number(),
  failVantages: z.number(),
  results: z.array(
    z.object({
      country: z.string(),
      asn: z.string().nullable(),
      network: z.string().nullable(),
      vantageClass: z.enum(['eyeball', 'datacenter', 'unknown']),
      ok: z.boolean(),
      rttMs: z.number().nullable(),
      error: z.string().nullable(),
    }),
  ),
});
export type ProbeRunAdmin = z.infer<typeof ProbeRunAdmin>;

export const ProbeMatrixTarget = z.object({
  key: z.string(),
  kind: ProbeTargetKind,
  ref: z.string(),
  label: z.string(),
  detail: z.string(),
  /** Scheduled by the cron (published edge, opted-in relay node, enabled custom target). */
  enabled: z.boolean(),
  reachability: ProbeReachabilitySummary,
});
export type ProbeMatrixTarget = z.infer<typeof ProbeMatrixTarget>;
export const ProbeReachabilityMatrix = z.object({
  countries: z.array(z.string()),
  targets: z.array(ProbeMatrixTarget),
});
export type ProbeReachabilityMatrix = z.infer<typeof ProbeReachabilityMatrix>;

export const ProbeRunsResponse = z.object({ runs: z.array(ProbeRunAdmin) });

/** GET …/probes/summary?window=<ms> (or ?from=&to=): the Telemetry → Probes chart data. */
const okFail = z.object({ ok: z.number().int(), fail: z.number().int() });
export const ProbeSummary = z.object({
  sinceMs: z.number(),
  untilMs: z.number(),
  bucketMs: z.number(),
  buckets: z.array(
    z.object({
      start: z.number(),
      ok: z.number().int(),
      fail: z.number().int(),
      runs: z.number().int(),
      byCountry: z.record(z.string(), okFail),
    }),
  ),
  totals: z.object({ runs: z.number().int(), ok: z.number().int(), fail: z.number().int() }),
  byCountry: z.array(okFail.extend({ country: z.string() })),
  bySource: z.array(okFail.extend({ source: z.string(), runs: z.number().int() })),
  truncated: z.boolean(),
});
export type ProbeSummary = z.infer<typeof ProbeSummary>;
export type ProbeRunsResponse = z.infer<typeof ProbeRunsResponse>;

export const ProbeTargetAdmin = z.object({
  id: z.string(),
  key: z.string(),
  label: z.string(),
  address: z.string(),
  port: z.number(),
  /** What the probe speaks against this target; `tcp` (a bare connect) by default. (`tls-sni` is derived for edges only, never a custom-target choice.) */
  probeProtocol: z.enum(['tcp', 'tls', 'https']).default('tcp'),
  display: z.string(),
  enabled: z.boolean(),
  notes: z.string().nullable(),
  reachability: ProbeReachabilitySummary,
  updatedAt: iso,
});
export type ProbeTargetAdmin = z.infer<typeof ProbeTargetAdmin>;
export const ProbeTargetsResponse = z.object({ targets: z.array(ProbeTargetAdmin) });
export type ProbeTargetsResponse = z.infer<typeof ProbeTargetsResponse>;
export const ProbeTargetCreatedResponse = z.object({ id: z.string(), key: z.string() });

export const ProbeAuditResponse = z.object({ entries: z.array(AuditEntry) });
export type ProbeAuditResponse = z.infer<typeof ProbeAuditResponse>;

export const ProbeManyRequestedResponse = z.object({
  runIds: z.array(z.string()),
  skipped: z.array(z.string()),
});
export type ProbeManyRequestedResponse = z.infer<typeof ProbeManyRequestedResponse>;

// --- summary / endpoints / preview / config -------------------------------------------------------

export const RelayPoolEntry = z.object({
  poolIndex: z.number(),
  edgeId: z.string(),
  provider: EdgeProviderId.nullable(),
  managed: z.boolean(),
  addresses: EdgeAddresses,
  layer: EdgeLayer.default('l4'),
  listenerId: z.string().optional(),
  health: z.string(),
  status: z.string(),
  unreachableIn: z.array(z.string()),
  mixedIn: z.array(z.string()),
});
export const RelayPoolSummary = z.object({
  relay: RelayAdmin,
  pool: z.array(RelayPoolEntry),
  standbys: z.number(),
  draining: z.number(),
  needsOperator: z.number(),
  rotation: z
    .object({ id: z.string(), kind: z.string(), phase: z.string(), percent: z.number() })
    .nullable(),
});
export const EdgeSummary = z.object({
  counts: z.object({
    relays: z.number(),
    published: z.number(),
    suspected: z.number(),
    rotating: z.number(),
    quarantined: z.number(),
    unreachableEdges: z.number(),
    needsOperator: z.number(),
  }),
  relays: z.array(RelayPoolSummary),
  generatedAt: iso,
});
export type EdgeSummary = z.infer<typeof EdgeSummary>;

export const RelayPublishedEndpoint = z.object({
  poolIndex: z.number(),
  edgeId: z.string(),
  provider: z.string(),
  listenerKey: z.string(),
  templateHostRemark: z.string().nullable().default(null),
  protocol: ListenerProtocolId,
  streamTransport: ListenerStreamTransport,
  security: ListenerSecurity,
  port: z.number(),
  addresses: EdgeAddresses,
  layer: EdgeLayer.default('l4'),
  /** L7: the fronted hostname (address, SNI and Host header alike). */
  hostname: z.string().nullable().default(null),
  /** What the template Host must present: the SNI and the HTTP Host header (null = none / clear). */
  sni: z.string().nullable().default(null),
  hostHeader: z.string().nullable().default(null),
  /** Empty for a listener that presents no name; for an L7 edge the hostname is the only name. */
  activeNames: z.array(z.string()),
});
export type RelayPublishedEndpoint = z.infer<typeof RelayPublishedEndpoint>;
export const RelayEndpointsResponse = z.object({
  relaySlug: z.string(),
  epoch: z.number(),
  published: z.array(RelayPublishedEndpoint),
  /** An anonymous sample assignment (a fixed sample key), so the operator sees one rendering. */
  sample: z.object({
    primary: z.object({ edgeId: z.string(), sni: z.string().nullable() }).nullable(),
    backup: z.object({ edgeId: z.string(), sni: z.string().nullable() }).nullable(),
  }),
});
export type RelayEndpointsResponse = z.infer<typeof RelayEndpointsResponse>;

/** What a client must dial per listener (every origin kind; a manual origin lives off this). */
export const RelayConnectionPlanEntry = z.object({
  listenerKey: z.string(),
  address: z.string(),
  port: z.number(),
  sni: z.string().nullable(),
  host: z.string().nullable(),
});
/** The Hosts the OPERATOR must create/keep when hostMode is `operator`. */
export const RelayHostsPlan = z.object({
  mode: HostMode,
  hosts: z.array(
    RelayConnectionPlanEntry.extend({
      remark: z.string(),
      inbound: z.object({ configProfileUuid: z.string(), configProfileInboundUuid: z.string() }),
    }),
  ),
});
/** The CMS view of a relay's listeners + what is published for them. */
export const RelayListenersResponse = z.object({
  listeners: z.array(RelayListenerAdmin),
  publishedEndpoints: z.array(RelayPublishedEndpoint),
  connectionPlan: z.array(RelayConnectionPlanEntry),
  hostsPlan: RelayHostsPlan,
});
export type RelayListenersResponse = z.infer<typeof RelayListenersResponse>;

/** Panel nodes the relay picker offers (inventory cache), with any relay already bound. */
export const RelayNodeCandidate = z.object({
  nodeUuid: z.string(),
  name: z.string(),
  address: z.string().nullable(),
  port: z.number().nullable(),
  countryCode: z.string().nullable(),
  online: z.boolean(),
  usersOnline: z.number(),
  relaySlug: z.string().nullable(),
});
export type RelayNodeCandidate = z.infer<typeof RelayNodeCandidate>;
export const RelayNodeCandidatesResponse = z.object({
  fetchedAt: isoN,
  nodes: z.array(RelayNodeCandidate),
});
export type RelayNodeCandidatesResponse = z.infer<typeof RelayNodeCandidatesResponse>;

/**
 * `GET relays/inbound-candidates?backendServerId=&nodeUuid=`: the node's
 * inbounds mapped to listener candidates (docs/edges.md § "Listener
 * catalogue", discovery), with `originTransport` filled where the origin probe
 * succeeded and `layers` recomputed from it. Nothing is registered by this call.
 */
export const InboundCandidate = z.object({
  listenerSpec: ListenerSpec,
  /** The layers that can front the candidate, and why the others cannot (`LAYER_EXCLUSION_CODES`). */
  layers: z.object({
    layers: z.array(EdgeLayer),
    excluded: z.record(z.string(), z.string()).default({}),
  }),
  formats: z.object({ links: z.boolean(), singbox: z.boolean(), clash: z.boolean() }),
  needsName: z.boolean(),
  sourceTag: z.string(),
  originTransport: ListenerOriginTransport.nullable(),
  /** The origin probe's verdict (HTTP-transport candidates only); `reason` is a short code, never an address. */
  probe: z.object({ ok: z.boolean(), reason: z.string().nullable() }).nullable(),
});
export type InboundCandidate = z.infer<typeof InboundCandidate>;
export const InboundCandidatesResponse = z.object({
  node: z.object({ nodeUuid: z.string(), name: z.string(), address: z.string().nullable() }),
  originAddress: z.string(),
  /** The relay already registered on this node, when one exists. */
  relaySlug: z.string().nullable(),
  candidates: z.array(InboundCandidate),
  unsupported: z.array(
    z.object({
      tag: z.string(),
      reason: z.enum(INBOUND_UNSUPPORTED_CODES),
      detail: z.string().optional(),
    }),
  ),
  probedAt: iso,
});
export type InboundCandidatesResponse = z.infer<typeof InboundCandidatesResponse>;

/**
 * The node role's view of `GET/PUT …/relays/by-slug/{slug}` (docs/edges.md § "Node
 * role contract"): the MINIMAL projection. No detector state, no rotation
 * limits, no pool-wide provider names, so a leaked register token learns none.
 */
export const RelayBySlugResponse = z.object({
  relay: z.object({
    id: z.string(),
    slug: z.string(),
    hostMode: HostMode,
    delivery: z.literal('edge-required'),
    enabled: z.boolean(),
    deleting: z.boolean(),
    publicationEpoch: z.number(),
    originAddress: z.string(),
    lastRegisteredAt: isoN,
  }),
  listeners: z.array(
    z.object({
      listenerKey: z.string(),
      protocol: ListenerProtocolId,
      streamTransport: ListenerStreamTransport,
      security: ListenerSecurity,
      transport: z.enum(['tcp', 'udp']),
      originPort: z.number(),
      layers: z.array(EdgeLayer),
      excluded: z.record(z.string(), z.string()).default({}),
      deployed: z.boolean(),
      retired: z.boolean(),
      templateHostRemark: z.string().nullable(),
    }),
  ),
  publishedEndpoints: z.array(
    z.object({
      listenerKey: z.string(),
      poolIndex: z.number(),
      layer: EdgeLayer.default('l4'),
      port: z.number(),
      addresses: EdgeAddresses,
      sni: z.string().nullable().default(null),
      hostHeader: z.string().nullable().default(null),
    }),
  ),
  connectionPlan: z.array(RelayConnectionPlanEntry),
  hostsPlan: RelayHostsPlan,
  /** Present on a PUT: what the registration changed. */
  registration: z
    .object({
      id: z.string(),
      created: z.boolean(),
      changed: z.boolean(),
      listeners: z.object({
        created: z.array(z.string()),
        updated: z.array(z.string()),
        unchanged: z.array(z.string()),
        retired: z.array(z.string()),
        owned: z.array(z.string()),
        blockedNames: z.array(z.string()),
        changed: z.boolean(),
      }),
      /** Notices (`edge.<code>`), e.g. `edge.pool_raised` when the pool grew to cover every listener. */
      warnings: z.array(z.string()).default([]),
    })
    .passthrough()
    .optional(),
});
export type RelayBySlugResponse = z.infer<typeof RelayBySlugResponse>;
/** @deprecated alias: the by-slug response IS the minimal projection now. */
export const RelayBySlugMinimalResponse = RelayBySlugResponse;
export type RelayBySlugMinimalResponse = RelayBySlugResponse;

export const RENDER_CLIENT_FAMILY_IDS = [
  'singbox',
  'mihomo',
  'xray-links',
  'happ',
  'hiddify',
  'streisand',
  'v2rayng',
  'other',
] as const;
export const RenderClientFamily = z.enum(RENDER_CLIENT_FAMILY_IDS);
export type RenderClientFamily = z.infer<typeof RenderClientFamily>;

export const EdgeRenderPreviewResponse = z.object({
  family: RenderClientFamily,
  format: z.enum(['links', 'singbox-json', 'clash-yaml']),
  input: z.string(),
  body: z.string(),
  applied: z.boolean(),
  reason: z.string().nullable(),
  emitted: z.number(),
  /** The edge-required verdict this render would get on the fronted route. */
  delivery: z
    .discriminatedUnion('kind', [
      z.object({ kind: z.literal('serve') }),
      z.object({ kind: z.literal('unavailable'), reason: z.string() }),
    ])
    .optional(),
  /** Per listener, whether its template entry resolved in the preview body. */
  listeners: z
    .array(
      z.object({ listenerKey: z.string(), matched: z.boolean(), reason: z.string().optional() }),
    )
    .default([]),
});
export type EdgeRenderPreviewResponse = z.infer<typeof EdgeRenderPreviewResponse>;

export const ClientRenderRule = z
  .object({
    enabled: z.boolean(),
    autoGroup: z.boolean(),
    autoGroupName: z.string(),
    includeBackup: z.boolean(),
    ipv6Mode: z.enum(['inherit', 'off', 'auto-group-only', 'both']),
    primaryLabel: z.string(),
    backupLabel: z.string(),
    order: z.enum(['primary-first', 'backup-first']),
    maxEntries: z.number(),
    dropTemplateEntries: z.boolean(),
  })
  .passthrough();
export type ClientRenderRule = z.infer<typeof ClientRenderRule>;

/** The relay config namespace as the admin sees it (server-sanitized; nested passthrough
 *  so a newer backend can add knobs without breaking an older SPA). */
export const EdgeConfigView = z.object({
  config: z
    .object({
      enabled: z.boolean(),
      autoRotate: z.boolean(),
      providerAffinity: z.enum(['rotate', 'sticky']),
      desiredPublishedDefault: z.number(),
      standbyPerRelay: z.number(),
      standbyPerListener: z.number().default(0),
      drainMinutes: z.number(),
      burnedDrainMinutes: z.number(),
      sniDrainMinutes: z.number(),
      cooldownMinutes: z.number(),
      maxRotationsPerRelayPerDay: z.number(),
      maxConcurrentRotations: z.number(),
      autoPublishStandby: z.boolean(),
      autoProvisionToDesired: z.boolean(),
      requireProviderHealth: z.boolean(),
      refreshMirrorsAfterFlip: z.boolean(),
      detect: z.record(z.string(), z.unknown()),
      render: z
        .object({
          enabled: z.boolean(),
          autoGroupName: z.string(),
          primaryLabel: z.string(),
          backupLabel: z.string(),
          ipv6Label: z.string(),
          ipv6Mode: z.enum(['off', 'auto-group-only', 'both']),
          preferDistinctProviders: z.boolean(),
          clients: z.record(z.string(), ClientRenderRule),
        })
        .passthrough(),
      probe: z
        .object({
          enabled: z.boolean(),
          sources: z.object({
            globalping: z.boolean(),
            checkhost: z.boolean(),
            ripeatlas: z.boolean(),
            internal: z.boolean(),
          }),
          countries: z.array(z.string()),
          intervalMinutes: z.number(),
          suspectedIntervalMinutes: z.number(),
          perCountryLimit: z.number(),
          hourlyBudget: z.number(),
          agreementVantages: z.number(),
          preferEyeball: z.boolean(),
        })
        .passthrough(),
    })
    .passthrough(),
  secrets: z.object({ globalpingToken: z.boolean(), ripeAtlasKey: z.boolean() }),
  families: z.array(z.string()),
  /** Per integer / ratio knob (flat path, e.g. `detect.windowMinutes`): the bounds the server clamps to. */
  bounds: z.record(z.string(), z.object({ min: z.number(), max: z.number() })).default({}),
  /** The compiled defaults (same flat paths), for the reset-to-default affordance. */
  defaults: z.record(z.string(), z.unknown()).default({}),
});
export type EdgeConfigView = z.infer<typeof EdgeConfigView>;

export const EdgeConfigPatchResponse = z.object({ changedKeys: z.array(z.string()) });

// --- small responses -------------------------------------------------------------------------------

/**
 * `{ ok }` plus whatever the mutation adds. `ok:false` with a 200 is a refusal
 * the mutation chose not to throw (e.g. retry-destroy on a published edge, which
 * adds `code`); the CMS must read `ok` and surface `code`, never assume success.
 */
export const EdgeOkResponse = z
  .object({ ok: z.boolean(), code: z.string().optional() })
  .passthrough();
/** Seed the compiled adapter defaults as template rows (`POST templates/ensure-defaults`). */
export const EdgeTemplatesSeedResponse = z.object({ created: z.number().int() });
export const EdgeIdResponse = z.object({ id: z.string() }).passthrough();
export const EdgeRotationStartedResponse = z.object({ rotationId: z.string() });
export const EdgeAdoptResponse = z.object({
  edgeId: z.string(),
  poolIndex: z.number().nullable(),
  /**
   * Why the import was NOT published (an L7 front is never published without a
   * current end-to-end proof: `front_unqualified`). The edge exists either way.
   */
  code: z.string().nullable().default(null),
});
export const ProbeRequestedResponse = z.object({ runIds: z.array(z.string()) });
export const RelayListenerUpsertResponse = z.object({
  id: z.string(),
  created: z.boolean(),
  changed: z.boolean(),
  templateHostRemark: z.string().nullable(),
});

// --- operator endpoints (guided setup, preflight, attention, quarantine, timeline, usage) ------------

export const SetupStepId = z.enum(SETUP_STEP_IDS);
export type SetupStepId = z.infer<typeof SetupStepId>;
export const SetupStepStatus = z.enum(SETUP_STEP_STATUSES);
export type SetupStepStatus = z.infer<typeof SetupStepStatus>;

/** One reason a step is not done. `subject` names the thing (slug, account name, listener key); `detail` is a short server hint. */
export const SetupBlocker = z.object({
  code: z.string(),
  subject: z.string().nullable().default(null),
  detail: z.string().nullable().default(null),
});
export type SetupBlocker = z.infer<typeof SetupBlocker>;

export const SetupStep = z.object({
  id: SetupStepId,
  status: SetupStepStatus,
  blockers: z.array(SetupBlocker),
  warnings: z.array(SetupBlocker).default([]),
  /** Small facts the step body renders (counts, names, flags). Never secrets, never addresses of a deployment. */
  facts: z.record(z.string(), z.unknown()).default({}),
});
export type SetupStep = z.infer<typeof SetupStep>;

/** What the wizard has selected so far (server-derived: the relay's own rows, or the best candidate). */
export const SetupContext = z.object({
  relaySlug: z.string().nullable(),
  relayId: z.string().nullable(),
  originKind: z.enum(['panel-node', 'backend-server', 'manual']).nullable(),
  backendServerId: z.string().nullable(),
  accountId: z.string().nullable(),
  templateId: z.string().nullable(),
  listenerKey: z.string().nullable(),
  edgeId: z.string().nullable(),
});
export type SetupContext = z.infer<typeof SetupContext>;

/** A relay the wizard could resume (fleet scope). */
export const SetupResumeEntry = z.object({
  relaySlug: z.string(),
  relayId: z.string(),
  currentStep: SetupStepId.nullable(),
  complete: z.boolean(),
});

/**
 * `GET setup-status[?relay=<slug>]` / `POST setup-status { draft }`: the guided
 * setup judged for ONE relay (or a draft before the relay exists). Without a
 * relay it is the fleet aggregation: the overview checklist plus relays with an
 * incomplete setup to resume.
 */
export const SetupStatusResponse = z.object({
  scope: z.enum(['relay', 'draft', 'fleet']),
  steps: z.array(SetupStep),
  /** The first step that is not done or skipped (null = complete). */
  currentStep: SetupStepId.nullable(),
  complete: z.boolean(),
  context: SetupContext,
  /** Public values the node role needs (slug, listener keys, the by-slug URL path); never a token or an address. */
  roleVars: z.record(z.string(), z.string()).nullable().default(null),
  resume: z.array(SetupResumeEntry).default([]),
  generatedAt: iso,
});
export type SetupStatusResponse = z.infer<typeof SetupStatusResponse>;

/** The draft the wizard posts before the relay row exists (steps 1 to 3 judge layer compatibility against it). */
export const SetupDraft = z.object({
  origin: RelayWireOrigin.nullable(),
  listeners: z
    .array(
      z.object({
        protocol: ListenerProtocolId,
        streamTransport: ListenerStreamTransport,
        security: ListenerSecurity,
        originPort: z.number().int().optional(),
        originTransport: ListenerOriginTransport.optional(),
        tlsNames: z.array(z.string()).optional(),
      }),
    )
    .default([]),
});
export type SetupDraft = z.infer<typeof SetupDraft>;

export const PreflightKind = z.enum(PREFLIGHT_KINDS);
export type PreflightKind = z.infer<typeof PreflightKind>;

/** `POST relays/{id}/preflight`: a dry run of the operation it names (writes nothing). */
export const PreflightRequest = z.object({
  kind: PreflightKind,
  edgeId: z.string().optional(),
  listenerKey: z.string().optional(),
  accountId: z.string().optional(),
  templateId: z.string().optional(),
  trigger: z.enum(['manual', 'detector', 'api', 'reconcile']).optional(),
});
export type PreflightRequest = z.infer<typeof PreflightRequest>;

export const PreflightIssue = z.object({
  code: z.string(),
  detail: z.string().nullable().default(null),
});
export const PreflightResponse = z.object({
  ok: z.boolean(),
  blockers: z.array(PreflightIssue),
  warnings: z.array(PreflightIssue),
  /** What the machine would pick (null when blocked before selection, or when the kind needs no pick). */
  wouldSelect: z
    .object({
      listenerKey: z.string().nullable(),
      standbyEdgeId: z.string().nullable(),
      accountId: z.string().nullable(),
      accountName: z.string().nullable(),
      provider: EdgeProviderId.nullable(),
      layer: EdgeLayer.nullable(),
      templateId: z.string().nullable(),
    })
    .nullable(),
});
export type PreflightResponse = z.infer<typeof PreflightResponse>;

/** `POST relays/{id}/test-provision`: the explicit bootstrap provision (a tested but unqualified account is allowed). */
export const TestProvisionRequest = z.object({
  accountId: z.string(),
  listenerKey: z.string(),
  templateId: z.string().optional(),
});
export type TestProvisionRequest = z.infer<typeof TestProvisionRequest>;

/** `POST automation {on}`: the keys the switch wrote (`edge.*` appSettings keys). */
export const EdgeAutomationResponse = z.object({
  on: z.boolean(),
  changedKeys: z.array(z.string()),
});
export type EdgeAutomationResponse = z.infer<typeof EdgeAutomationResponse>;

/** `POST relays/{id}/rebalance`: the duplicate that went back to standby. */
export const RelayRebalanceResponse = z.object({
  ok: z.literal(true),
  edgeId: z.string(),
  poolIndex: z.number().nullable(),
  epoch: z.number(),
});
export type RelayRebalanceResponse = z.infer<typeof RelayRebalanceResponse>;

export const AttentionKind = z.enum(ATTENTION_KINDS);
export const AttentionSeverity = z.enum(ATTENTION_SEVERITIES);
export const AttentionAction = z.enum(ATTENTION_ACTIONS);
export const AttentionItem = z.object({
  /** Stable per item: `<kind>:<subject id>`, for dismiss-free rendering keys. */
  id: z.string(),
  kind: AttentionKind,
  severity: AttentionSeverity,
  relaySlug: z.string().nullable(),
  relayId: z.string().nullable(),
  edgeId: z.string().nullable().default(null),
  listenerKey: z.string().nullable().default(null),
  accountId: z.string().nullable().default(null),
  rotationId: z.string().nullable().default(null),
  /** A short code the CMS maps to words (a veto, a failure code, a Host state); never free text from a provider. */
  code: z.string().nullable().default(null),
  /**
   * Small facts for the row. Keys per kind (all optional; the CMS renders only these):
   * `pool_below_desired` published, desired, standbys · `members_dark` published ·
   * `host_unresolved` op (create|delete|null), attempts · `rotation_failed` kind, phase ·
   * `block_suspected` score, hintLevel, countries[] · `edge_unreachable` countries[] ·
   * `needs_operator` provider, layer · `account_untested` / `account_unqualified` name, provider.
   */
  facts: z.record(z.string(), z.unknown()).default({}),
  action: AttentionAction,
  since: isoN.default(null),
});
export type AttentionItem = z.infer<typeof AttentionItem>;
export const AttentionResponse = z.object({
  items: z.array(AttentionItem),
  generatedAt: iso,
});
export type AttentionResponse = z.infer<typeof AttentionResponse>;

/** A client-facing Host as a tuple (what the panel serves for a listener). */
export const HostTuple = z.object({
  address: z.string(),
  port: z.number(),
  sni: z.string().nullable(),
  host: z.string().nullable(),
});
export type HostTuple = z.infer<typeof HostTuple>;

/**
 * `GET relays/{id}/quarantine` (+ `POST …/quarantine/inspect` for the live
 * column): both recorded bindings as Host tuples and, per listener, the Host
 * the panel serves right now and which binding it matches.
 */
export const QuarantineView = z.object({
  quarantine: z.object({ rotationId: z.string(), since: iso, reason: z.string() }).nullable(),
  rotation: EdgeRotationAdmin.nullable(),
  listeners: z.array(
    z.object({
      listenerKey: z.string(),
      remark: z.string().nullable(),
      /** The binding the rotation replaced (rollback target). */
      previous: HostTuple.extend({ edgeId: z.string().nullable() }).nullable(),
      /** The binding the rotation wrote (or meant to write). */
      current: HostTuple.extend({ edgeId: z.string().nullable() }).nullable(),
      /** What the panel serves for this listener's remark; null until inspected or when absent. */
      live: HostTuple.extend({ uuid: z.string() }).nullable(),
      match: z.enum(['previous', 'current', 'neither', 'absent', 'unknown']),
    }),
  ),
  /** Hosts the panel serves under this relay's remarks that no listener claims (duplicates, legacy variants). */
  extraHosts: z.array(HostTuple.extend({ uuid: z.string(), remark: z.string() })).default([]),
  inspectedAt: isoN.default(null),
});
export type QuarantineView = z.infer<typeof QuarantineView>;

/** `GET relays/{id}/timeline`: merged audit rows (relay, non-destroyed edges, rotations, probe verdicts), newest first. */
export const TimelineResponse = z.object({
  entries: z.array(
    AuditEntry.extend({
      /** Which row the entry came from (for the icon and the link). */
      subject: z.enum(['relay', 'edge', 'rotation', 'probe', 'listener', 'other']),
    }),
  ),
  /** More rows exist beyond the cap. */
  truncated: z.boolean().default(false),
});
export type TimelineResponse = z.infer<typeof TimelineResponse>;

/** `GET providers/usage`: capacity and budget per account, desired vs published per relay. */
export const ProvidersUsageResponse = z.object({
  accounts: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      provider: EdgeProviderId,
      layer: EdgeLayer,
      enabled: z.boolean(),
      qualified: z.boolean(),
      tested: z.boolean(),
      fake: z.boolean().default(false),
      liveEdges: z.number(),
      maxLiveEdges: z.number(),
      allocationsToday: z.number(),
      dailyAllocationBudget: z.number(),
      published: z.number(),
      standby: z.number(),
      draining: z.number(),
    }),
  ),
  relays: z.array(
    z.object({
      id: z.string(),
      slug: z.string(),
      desiredPublished: z.number(),
      published: z.number(),
      standby: z.number(),
      draining: z.number(),
      /** Edges the reconcile cron would provision if `autoProvisionToDesired` were on. */
      plannedIfAutoProvision: z.number(),
    }),
  ),
  totals: z.object({
    liveEdges: z.number(),
    published: z.number(),
    standby: z.number(),
    draining: z.number(),
    plannedIfAutoProvision: z.number(),
  }),
  generatedAt: iso,
});
export type ProvidersUsageResponse = z.infer<typeof ProvidersUsageResponse>;

/** `POST relays/{id}/listeners/{key}/adopt-host { hostUuid }`: take over an operator-created Host. */
export const AdoptHostRequest = z.object({ hostUuid: z.string() });
export const AdoptHostResponse = z.object({
  ok: z.boolean(),
  listenerKey: z.string(),
  host: z.object({ uuid: z.string(), ownership: z.literal('adopted') }),
});
export type AdoptHostResponse = z.infer<typeof AdoptHostResponse>;

/** `POST relays/{id}/resolve-quarantine { keep, reason? }` (the reason is audited, never free-form provider text). */
export const ResolveQuarantineRequest = z.object({
  keep: z.enum(['current', 'previous']),
  reason: z.string().max(200).optional(),
});

/** `GET edges/delivery-bindings`: bindings without a live relay (a `keep-dark` left behind, to release). */
export const DeliveryBindingAdmin = z.object({
  id: z.string(),
  backendServerId: z.string(),
  nodeName: z.string().nullable(),
  relaySlug: z.string(),
  /** True when a relay row still claims this binding. */
  relayPresent: z.boolean(),
  policyVersion: z.number(),
  state: z.enum(['active', 'released']),
  updatedAt: iso,
});
export const DeliveryBindingsResponse = z.object({ bindings: z.array(DeliveryBindingAdmin) });
export type DeliveryBindingAdmin = z.infer<typeof DeliveryBindingAdmin>;

// --- guided setup runs (Autopilot) ------------------------------------------------------------------

export const SetupRunStage = z.enum(SETUP_RUN_STAGES);
export const SetupRunState = z.enum(SETUP_RUN_STATES);
export type SetupRunStage = z.infer<typeof SetupRunStage>;
export type SetupRunState = z.infer<typeof SetupRunState>;

/** One discovered inbound in the plan: frontable ones become the required listeners. */
export const SetupPlanInbound = z.object({
  listenerKey: z.string(),
  sourceTag: z.string(),
  listenerSpec: z.unknown().nullable(),
  layers: z.array(EdgeLayer),
  frontable: z.boolean(),
  formats: z.object({ links: z.boolean(), singbox: z.boolean(), clash: z.boolean() }),
  needsName: z.boolean(),
  /** An `INBOUND_UNSUPPORTED_CODES` reason, `needs_names`, or a layer exclusion. */
  reason: z.string().optional(),
  detail: z.string().optional(),
});
export const SetupPlanDirectHost = z.object({
  uuid: z.string(),
  remark: z.string(),
  inboundUuid: z.string(),
  /** Its inbound is frontable in every format (hidden without consent); else the operator consents by uuid. */
  covered: z.boolean(),
});
export const SetupPlanAccount = z.object({
  id: z.string(),
  name: z.string(),
  provider: EdgeProviderId,
  layer: EdgeLayer,
  compatible: z.boolean(),
  /** `SETUP_ACCOUNT_REASONS` codes. */
  reasons: z.array(z.string()),
});

/** `POST setup-runs/plan {backendServerId, nodeUuid}`: the read-only snapshot + its hash. */
export const SetupPlanResponse = z.object({
  backendServerId: z.string(),
  backend: z.string(),
  nodeUuid: z.string(),
  nodeName: z.string(),
  originAddress: z.string(),
  relaySlug: z.string(),
  inbounds: z.array(SetupPlanInbound),
  requiredListeners: z.array(z.string()),
  tooManyInbounds: z.boolean(),
  directHosts: z.array(SetupPlanDirectHost),
  accounts: z.array(SetupPlanAccount),
  renderGlobal: z.object({ willEnable: z.boolean(), affectedRelays: z.array(z.string()) }),
  familiesDisabled: z.array(z.string()),
  emptyNode: z.boolean(),
  existingRelay: z
    .object({ id: z.string(), slug: z.string(), setupStage: z.string().nullable() })
    .nullable(),
  activeRunId: z.string().nullable(),
  planHash: z.string(),
  generatedAt: iso,
});
export type SetupPlanResponse = z.infer<typeof SetupPlanResponse>;

/** `POST setup-runs`: the consent the run persists (the exact uncovered Host uuids, or keep them). */
export const SetupRunCreateRequest = z.object({
  backendServerId: z.string(),
  nodeUuid: z.string(),
  accountId: z.string(),
  planHash: z.string(),
  approvedHideUuids: z.array(z.string()).default([]),
  keepDirect: z.boolean().optional(),
});
export type SetupRunCreateRequest = z.infer<typeof SetupRunCreateRequest>;
export const SetupRunCreatedResponse = z.object({ runId: z.string(), stage: SetupRunStage });
export type SetupRunCreatedResponse = z.infer<typeof SetupRunCreatedResponse>;

/** The binding a `try_it` tick echoes back (what the card showed). */
export const SetupRunTestLink = z.object({
  edgeId: z.string(),
  listenerKey: z.string(),
  /** Empty for a `named_connection` retest of an already published address. */
  link: z.string(),
  format: z.string(),
  method: z.enum(['test_link', 'named_connection']),
  binding: z.object({
    endpoint: z.string(),
    listenerRevision: z.number(),
    configHash: z.string(),
    issuedAt: iso,
  }),
});
export type SetupRunTestLink = z.infer<typeof SetupRunTestLink>;

/** `GET setup-runs/{id}`: the run as the progress view polls it. */
export const SetupRunAdmin = z.object({
  id: z.string(),
  relayId: z.string().nullable(),
  relaySlug: z.string(),
  backendServerId: z.string(),
  nodeName: z.string(),
  nodeUuid: z.string(),
  accountId: z.string(),
  stage: SetupRunStage,
  state: SetupRunState,
  /** The interruption (`SETUP_RUN_NEEDS`) when `state === 'needs_you'`. */
  need: z.object({ code: z.string(), detail: z.string().nullable() }).nullable(),
  generation: z.number(),
  planRevision: z.number(),
  keepDirect: z.boolean(),
  listeners: z.array(
    z.object({
      listenerKey: z.string(),
      layer: EdgeLayer,
      edgeId: z.string().nullable(),
      verify: z.enum(['pending', 'partial', 'verified', 'unreachable']),
      published: z.boolean(),
    }),
  ),
  testLinks: z.array(SetupRunTestLink).default([]),
  testedEndpoints: z
    .array(z.object({ edgeId: z.string(), listenerKey: z.string(), endpoint: z.string(), at: iso }))
    .default([]),
  /** Uncovered direct Hosts found at stage 6 that the consent did not name (`review_changed`). */
  reviewDelta: z.array(z.object({ uuid: z.string(), remark: z.string() })).default([]),
  rehearsal: z
    .object({
      at: iso,
      attempts: z.number(),
      hostsObservationAt: iso,
      darkCohortKeys: z.array(z.string()),
    })
    .nullable(),
  plan: z.object({
    requiredListeners: z.array(z.string()),
    directHosts: z.array(SetupPlanDirectHost),
    renderGlobal: z.object({ willEnable: z.boolean(), affectedRelays: z.array(z.string()) }),
    familiesDisabled: z.array(z.string()),
    emptyNode: z.boolean(),
  }),
  approvedHideUuids: z.array(z.string()),
  events: z.array(
    z.object({
      at: iso,
      level: z.enum(['info', 'warn', 'error']),
      code: z.string(),
      detail: z.string().nullable(),
    }),
  ),
  startedAt: iso,
  updatedAt: iso,
  finishedAt: isoN,
});
export type SetupRunAdmin = z.infer<typeof SetupRunAdmin>;
export const SetupRunsResponse = z.object({ runs: z.array(SetupRunAdmin), generatedAt: iso });
export type SetupRunsResponse = z.infer<typeof SetupRunsResponse>;

/** `POST setup-runs/{id}/retry`: the card's secondary buttons. */
export const SetupRunRetryRequest = z.object({
  tryAnotherAddress: z.boolean().optional(),
  acceptPartial: z.boolean().optional(),
  accountId: z.string().optional(),
});
export type SetupRunRetryRequest = z.infer<typeof SetupRunRetryRequest>;
export const SetupRunRetryResponse = z.object({
  ok: z.literal(true),
  generation: z.number(),
  stage: SetupRunStage,
});

/** `POST setup-runs/{id}/continue`: ticks, a replaced consent, or keep-direct. */
export const SetupRunContinueRequest = z.object({
  confirmations: z
    .array(
      z.object({
        edgeId: z.string(),
        endpoint: z.string(),
        listenerRevision: z.number(),
        configHash: z.string(),
      }),
    )
    .optional(),
  approvedHideUuids: z.array(z.string()).optional(),
  keepDirect: z.boolean().optional(),
});
export type SetupRunContinueRequest = z.infer<typeof SetupRunContinueRequest>;
export const SetupRunContinueResponse = z.object({
  ok: z.literal(true),
  state: z.enum(['running', 'done_unbound']),
  accountTrusted: z.boolean(),
});

/** `POST setup-runs/{id}/cancel`. */
export const SetupRunCancelResponse = z.object({
  ok: z.literal(true),
  disposition: z.enum(['deleted', 'restore', 'none']),
});

/** `POST relays/{id}/require-edges`: pending endpoints instead of a binding when an L4 edge is untested. */
export const RequireEdgesResponse = z.object({
  runId: z.string(),
  stage: SetupRunStage,
  state: SetupRunState,
  pending: z.array(
    z.object({
      edgeId: z.string(),
      listenerKey: z.string(),
      endpoint: z.string(),
      listenerRevision: z.number(),
      configHash: z.string(),
    }),
  ),
});
export type RequireEdgesResponse = z.infer<typeof RequireEdgesResponse>;

/** `GET maintenance` / `POST maintenance/{freeze|thaw}`: the "pause new edge work" switch (docs/edges.md). */
export const EdgeMaintenanceView = z.object({
  frozen: z.boolean(),
  reason: z.string().nullable().default(null),
  since: isoN.default(null),
});
export type EdgeMaintenanceView = z.infer<typeof EdgeMaintenanceView>;
