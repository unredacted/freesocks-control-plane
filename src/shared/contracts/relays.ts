/**
 * Relay-edge contracts (admin surface `/api/v1/admin/relays/*`): the zod shapes
 * the SPA parses. The provider id enum derives from RELAY_PROVIDER_IDS so it can
 * never drift from the Convex validator. Every route under the prefix is
 * HPKE-sealed by verb class (src/shared/crypto/envelope.ts).
 */
import { z } from 'zod';
import { RELAY_PROVIDER_IDS } from './relayProviderIds';

export { RELAY_PROVIDER_IDS, isRelayProviderId } from './relayProviderIds';
export type RelayProviderId = import('./relayProviderIds').RelayProviderId;
export const RelayProviderId = z.enum(RELAY_PROVIDER_IDS);

const iso = z.string();
const isoN = z.string().nullable();

// --- provider accounts ------------------------------------------------------------

export const RelayAccountAdmin = z.object({
  id: z.string(),
  provider: RelayProviderId,
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
export type RelayAccountAdmin = z.infer<typeof RelayAccountAdmin>;
export const RelayAccountList = z.array(RelayAccountAdmin);

export const RelayCredentialFields = z.record(z.string(), z.array(z.string()));
export const RelayAccountsResponse = z.object({
  accounts: RelayAccountList,
  credentialFields: RelayCredentialFields,
});
export type RelayAccountsResponse = z.infer<typeof RelayAccountsResponse>;

export const RelayTestCredentialsResponse = z.object({
  ok: z.boolean(),
  code: z.string().nullable(),
  regions: z.array(z.object({ id: z.string(), label: z.string() })),
});
export type RelayTestCredentialsResponse = z.infer<typeof RelayTestCredentialsResponse>;

export const RelayInventory = z.object({
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
export const RelayInventoryResponse = z.object({
  inventory: RelayInventory.nullable(),
  inventoryAt: isoN,
});
export type RelayInventoryResponse = z.infer<typeof RelayInventoryResponse>;

// --- templates --------------------------------------------------------------------------

export const RelayTemplateField = z.object({
  key: z.string(),
  label: z.string(),
  type: z.enum(['string', 'number', 'boolean', 'select', 'string-list']),
  help: z.string().optional(),
  options: z.array(z.object({ value: z.string(), label: z.string() })).optional(),
  required: z.boolean().optional(),
});
export type RelayTemplateField = z.infer<typeof RelayTemplateField>;

export const RelayTemplateAdmin = z.object({
  id: z.string(),
  provider: RelayProviderId,
  accountId: z.string().nullable(),
  name: z.string(),
  params: z.unknown(),
  paramsHash: z.string(),
  isDefault: z.boolean(),
  updatedAt: iso,
});
export type RelayTemplateAdmin = z.infer<typeof RelayTemplateAdmin>;

export const RelayTemplatesResponse = z.object({
  templates: z.array(RelayTemplateAdmin),
  schemas: z.record(
    z.string(),
    z.object({ fields: z.array(RelayTemplateField), defaults: z.record(z.string(), z.unknown()) }),
  ),
});
export type RelayTemplatesResponse = z.infer<typeof RelayTemplatesResponse>;

export const RelayTemplateValidateResponse = z.union([
  z.object({ ok: z.literal(true), params: z.unknown(), paramsHash: z.string() }),
  z.object({ ok: z.literal(false), issues: z.array(z.string()) }),
]);
export type RelayTemplateValidateResponse = z.infer<typeof RelayTemplateValidateResponse>;

// --- camouflage profiles ------------------------------------------------------------------

export const RelayServerName = z.object({
  sni: z.string(),
  status: z.enum(['active', 'retired']),
  retiredAt: isoN,
  drainUntil: isoN,
});
export const RelayProfileAdmin = z.object({
  id: z.string(),
  slug: z.string(),
  name: z.string(),
  provider: RelayProviderId,
  accountId: z.string().nullable(),
  targetAddress: z.string(),
  targetPort: z.number(),
  serverNames: z.array(RelayServerName),
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
export type RelayProfileAdmin = z.infer<typeof RelayProfileAdmin>;
export const RelayProfileList = z.array(RelayProfileAdmin);

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

export const RelayOriginAdmin = z.object({
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
  providerAffinity: z.enum(['rotate', 'sticky']),
  providerPreference: RelayProviderId.nullable(),
  desiredPublished: z.number(),
  standbyPerOrigin: z.number(),
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
export type RelayOriginAdmin = z.infer<typeof RelayOriginAdmin>;

export const RelaySlotAdmin = z.object({
  id: z.string(),
  originId: z.string(),
  slotKey: z.string(),
  profileId: z.string(),
  profileSlug: z.string().nullable(),
  provider: RelayProviderId.nullable(),
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

export const RelayEdgeStep = z.object({
  stepId: z.string(),
  kind: z.string(),
  state: z.string(),
  attempt: z.number().optional(),
  startedAt: isoN,
  finishedAt: isoN,
});
export const RelayReachabilityCountry = z.object({
  country: z.string(),
  /** The IPv4 path's verdict (IPv6 only when the edge was probed over v6 alone). */
  verdict: z.enum(['reachable', 'unreachable', 'mixed', 'unknown']),
  /** The IPv6 path, when the edge has one and it was probed. */
  v6Verdict: z.enum(['reachable', 'unreachable', 'mixed', 'unknown']).optional(),
  okVantages: z.number(),
  failVantages: z.number(),
  lastAt: iso,
});
export const RelayEdgeAdmin = z.object({
  id: z.string(),
  originId: z.string(),
  slotId: z.string(),
  accountId: z.string().nullable(),
  templateId: z.string().nullable(),
  templateHash: z.string().nullable(),
  provider: RelayProviderId.nullable(),
  managed: z.boolean(),
  name: z.string(),
  steps: z.array(RelayEdgeStep),
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
    .object({ byCountry: z.array(RelayReachabilityCountry), updatedAt: iso })
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
export type RelayEdgeAdmin = z.infer<typeof RelayEdgeAdmin>;

export const RelayEdgeLive = z.object({
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
export const RelayEdgeDetail = z.object({
  edge: RelayEdgeAdmin,
  live: RelayEdgeLive.nullable(),
  probes: z.array(z.unknown()),
});
export type RelayEdgeDetail = z.infer<typeof RelayEdgeDetail>;
export const RelayEdgeLiveResponse = z.object({ live: RelayEdgeLive.nullable() });

export const RelayRotationAdmin = z.object({
  id: z.string(),
  originId: z.string(),
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
  steps: z.array(RelayEdgeStep),
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
      provider: RelayProviderId.nullable(),
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
export type RelayRotationAdmin = z.infer<typeof RelayRotationAdmin>;

// --- probes -------------------------------------------------------------------------------------

export const RelayProbeRunAdmin = z.object({
  id: z.string(),
  edgeId: z.string(),
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
export type RelayProbeRunAdmin = z.infer<typeof RelayProbeRunAdmin>;

export const RelayReachabilityMatrix = z.object({
  countries: z.array(z.string()),
  edges: z.array(
    z.object({
      edgeId: z.string(),
      publication: z.string(),
      poolIndex: z.number().nullable(),
      provider: RelayProviderId.nullable(),
      byCountry: z.array(RelayReachabilityCountry),
      updatedAt: isoN,
    }),
  ),
});
export type RelayReachabilityMatrix = z.infer<typeof RelayReachabilityMatrix>;

// --- summary / endpoints / preview / config -------------------------------------------------------

export const RelayPoolEntry = z.object({
  poolIndex: z.number(),
  edgeId: z.string(),
  provider: RelayProviderId.nullable(),
  managed: z.boolean(),
  addresses: z.object({ v4: z.string().nullable(), v6: z.string().nullable() }),
  health: z.string(),
  status: z.string(),
  unreachableIn: z.array(z.string()),
  mixedIn: z.array(z.string()),
});
export const RelayOriginSummary = z.object({
  origin: RelayOriginAdmin,
  pool: z.array(RelayPoolEntry),
  standbys: z.number(),
  draining: z.number(),
  needsOperator: z.number(),
  rotation: z
    .object({ id: z.string(), kind: z.string(), phase: z.string(), percent: z.number() })
    .nullable(),
});
export const RelaySummary = z.object({
  counts: z.object({
    origins: z.number(),
    published: z.number(),
    suspected: z.number(),
    rotating: z.number(),
    quarantined: z.number(),
    unreachableEdges: z.number(),
    needsOperator: z.number(),
  }),
  origins: z.array(RelayOriginSummary),
  generatedAt: iso,
});
export type RelaySummary = z.infer<typeof RelaySummary>;

export const RelayPublishedEndpoint = z.object({
  poolIndex: z.number(),
  edgeId: z.string(),
  provider: z.string(),
  slotKey: z.string(),
  slotRemark: z.string(),
  port: z.number(),
  addresses: z.object({ v4: z.string().nullable(), v6: z.string().nullable() }),
  activeServerNames: z.array(z.string()),
});
export const RelayEndpointsResponse = z.object({
  originSlug: z.string(),
  epoch: z.number(),
  published: z.array(RelayPublishedEndpoint),
  /** An anonymous sample assignment (a fixed sample key), so the operator sees one rendering. */
  sample: z.object({
    primary: z.object({ edgeId: z.string(), sni: z.string() }).nullable(),
    backup: z.object({ edgeId: z.string(), sni: z.string() }).nullable(),
  }),
});
export type RelayEndpointsResponse = z.infer<typeof RelayEndpointsResponse>;

/** The IaC (Ansible) view of an origin: origin + slots + what is published. */
export const RelayOriginBySlugResponse = z.object({
  origin: RelayOriginAdmin,
  slots: z.array(RelaySlotAdmin),
  publishedEndpoints: z.array(RelayPublishedEndpoint),
});
export type RelayOriginBySlugResponse = z.infer<typeof RelayOriginBySlugResponse>;

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

export const RelayRenderPreviewResponse = z.object({
  family: RenderClientFamily,
  format: z.enum(['links', 'singbox-json', 'clash-yaml']),
  input: z.string(),
  body: z.string(),
  applied: z.boolean(),
  reason: z.string().nullable(),
  emitted: z.number(),
});
export type RelayRenderPreviewResponse = z.infer<typeof RelayRenderPreviewResponse>;

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
export const RelayConfigView = z.object({
  config: z
    .object({
      enabled: z.boolean(),
      autoRotate: z.boolean(),
      providerAffinity: z.enum(['rotate', 'sticky']),
      desiredPublishedDefault: z.number(),
      standbyPerOrigin: z.number(),
      drainMinutes: z.number(),
      burnedDrainMinutes: z.number(),
      sniDrainMinutes: z.number(),
      cooldownMinutes: z.number(),
      maxRotationsPerOriginPerDay: z.number(),
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
export type RelayConfigView = z.infer<typeof RelayConfigView>;

export const RelayConfigPatchResponse = z.object({ changedKeys: z.array(z.string()) });

// --- small responses -------------------------------------------------------------------------------

export const RelayOkResponse = z.object({ ok: z.boolean() }).passthrough();
export const RelayIdResponse = z.object({ id: z.string() }).passthrough();
export const RelayRotationStartedResponse = z.object({ rotationId: z.string() });
export const RelayAdoptResponse = z.object({
  edgeId: z.string(),
  poolIndex: z.number().nullable(),
});
export const RelayProbeRequestedResponse = z.object({ runIds: z.array(z.string()) });
export const RelaySlotUpsertResponse = z.object({
  id: z.string(),
  created: z.boolean(),
  templateHostRemark: z.string(),
});
