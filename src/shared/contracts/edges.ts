/**
 * Relay-edge contracts (admin surface `/api/v1/admin/edges/*`): the zod shapes
 * the SPA parses. The provider id enum derives from EDGE_PROVIDER_IDS so it can
 * never drift from the Convex validator. Every route under the prefix is
 * HPKE-sealed by verb class (src/shared/crypto/envelope.ts).
 */
import { z } from 'zod';
import { AuditEntry } from './admin';
import { EDGE_PROVIDER_IDS } from './edgeProviderIds';

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
  priority: z.number(),
  dailyAllocationBudget: z.number(),
  allocationsToday: z.number(),
  maxLiveEdges: z.number(),
  lastTestOkAt: isoN,
  lastTestError: z.string().nullable(),
  inventoryAt: isoN,
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

const DiscoverOption = z.object({ id: z.string(), label: z.string() });
/** POST …/providers/discover: choice lists for the account form given credentials + partial settings. */
export const EdgeDiscoverResponse = z.object({
  projects: z.array(DiscoverOption).optional(),
  regions: z.array(DiscoverOption).optional(),
  networks: z.array(DiscoverOption.extend({ subnets: z.array(DiscoverOption) })).optional(),
  errors: z.record(z.string(), z.string()).optional(),
});
export type EdgeDiscoverResponse = z.infer<typeof EdgeDiscoverResponse>;

export const EdgeInventory = z.object({
  loadBalancers: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      status: z.string().optional(),
      addresses: z.object({ v4: z.string().optional(), v6: z.string().optional() }),
      createdAt: z.string().optional(),
      /** True when no edge ledger references this resource (an unowned LB). */
      unowned: z.boolean().optional(),
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

// --- camouflage profiles ------------------------------------------------------------------

export const ProfileServerName = z.object({
  sni: z.string(),
  status: z.enum(['active', 'retired']),
  retiredAt: isoN,
  drainUntil: isoN,
});
export const ProtocolProfileAdmin = z.object({
  id: z.string(),
  slug: z.string(),
  name: z.string(),
  /** What the inbound speaks; decides whether server names / a target apply. */
  protocol: z.enum(['reality', 'tls', 'plain']),
  /** null = usable behind any provider. */
  provider: EdgeProviderId.nullable(),
  accountId: z.string().nullable(),
  /** REALITY only. */
  targetAddress: z.string().nullable(),
  targetPort: z.number().nullable(),
  serverNames: z.array(ProfileServerName),
  enabled: z.boolean(),
  qualification: z
    .object({
      checkedAt: iso,
      edgeAsn: z.string().nullable(),
      targetAsn: z.string().nullable(),
      sameAsn: z.boolean().nullable(),
      tlsOk: z.boolean(),
      authOk: z.boolean(),
    })
    .nullable(),
  notes: z.string().nullable(),
  updatedAt: iso,
});
export type ProtocolProfileAdmin = z.infer<typeof ProtocolProfileAdmin>;
export const ProtocolProfileList = z.array(ProtocolProfileAdmin);

// --- origins / slots / edges / rotations -----------------------------------------------------

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

export const RelayAdmin = z.object({
  id: z.string(),
  slug: z.string(),
  backendServerId: z.string(),
  nodeHostname: z.string(),
  nodeUuid: z.string().nullable(),
  originAddress: z.string(),
  locationCode: z.string().nullable(),
  modeSlugs: z.array(z.string()),
  enabled: z.boolean(),
  autoRotate: z.boolean(),
  hostManaged: z.boolean(),
  probeNode: z.boolean().default(false),
  reachability: z
    .object({ byCountry: z.array(z.unknown()), updatedAt: isoN })
    .nullable()
    .default(null),
  providerAffinity: z.enum(['rotate', 'sticky']),
  providerPreference: EdgeProviderId.nullable(),
  desiredPublished: z.number(),
  standbyPerRelay: z.number(),
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
  quarantine: z.object({ rotationId: z.string(), since: iso, reason: z.string() }).nullable(),
  deleting: z.boolean(),
  suspicion: RelaySuspicion.nullable(),
  updatedAt: iso,
});
export type RelayAdmin = z.infer<typeof RelayAdmin>;

export const SLOT_PROTOCOL_IDS = ['reality', 'tls', 'plain'] as const;
export const SlotProtocol = z.enum(SLOT_PROTOCOL_IDS);
export type SlotProtocol = z.infer<typeof SlotProtocol>;

export const RelaySlotAdmin = z.object({
  id: z.string(),
  relayId: z.string(),
  slotKey: z.string(),
  protocol: SlotProtocol,
  profileId: z.string(),
  profileSlug: z.string().nullable(),
  provider: EdgeProviderId.nullable(),
  inboundTag: z.string(),
  configProfileUuid: z.string(),
  configProfileInboundUuid: z.string(),
  originPort: z.number(),
  templateHostUuid: z.string().nullable(),
  templateHostRemark: z.string(),
  deployed: z.boolean(),
  deployedAt: isoN,
  retired: z.boolean(),
  updatedAt: iso,
});
export type RelaySlotAdmin = z.infer<typeof RelaySlotAdmin>;

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
  okVantages: z.number(),
  failVantages: z.number(),
  lastAt: iso,
});
export const EdgeAdmin = z.object({
  id: z.string(),
  relayId: z.string(),
  slotId: z.string(),
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
  addresses: z.object({ v4: z.string().nullable(), v6: z.string().nullable() }),
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
      addresses: z.object({ v4: z.string().optional(), v6: z.string().optional() }),
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
  raw: z.unknown(),
  liveAt: iso,
});
export const EdgeDetail = z.object({
  edge: EdgeAdmin,
  live: EdgeLive.nullable(),
  probes: z.array(z.unknown()),
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
      addresses: z.object({ v4: z.string().nullable(), v6: z.string().nullable() }),
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
  ipVersion: z.union([z.literal(4), z.literal(6)]),
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
  addresses: z.object({ v4: z.string().nullable(), v6: z.string().nullable() }),
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
  slotKey: z.string(),
  slotRemark: z.string(),
  protocol: SlotProtocol,
  port: z.number(),
  addresses: z.object({ v4: z.string().nullable(), v6: z.string().nullable() }),
  /** Empty for a non-REALITY slot. */
  activeServerNames: z.array(z.string()),
});
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

/** The IaC (Ansible) view of a relay: relay + slots + what is published. */
export const RelayBySlugResponse = z.object({
  relay: RelayAdmin,
  slots: z.array(RelaySlotAdmin),
  publishedEndpoints: z.array(RelayPublishedEndpoint),
});
export type RelayBySlugResponse = z.infer<typeof RelayBySlugResponse>;

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
});
export type EdgeConfigView = z.infer<typeof EdgeConfigView>;

export const EdgeConfigPatchResponse = z.object({ changedKeys: z.array(z.string()) });

// --- small responses -------------------------------------------------------------------------------

export const EdgeOkResponse = z.object({ ok: z.boolean() }).passthrough();
export const EdgeIdResponse = z.object({ id: z.string() }).passthrough();
export const EdgeRotationStartedResponse = z.object({ rotationId: z.string() });
export const EdgeAdoptResponse = z.object({
  edgeId: z.string(),
  poolIndex: z.number().nullable(),
});
export const ProbeRequestedResponse = z.object({ runIds: z.array(z.string()) });
export const RelaySlotUpsertResponse = z.object({
  id: z.string(),
  created: z.boolean(),
  templateHostRemark: z.string(),
});
