/**
 * Admin -> Edges data layer: the ONLY place edge API paths are built.
 *
 * Three layers, all exported:
 *   1. `fetch*` / verb functions: one typed function per server route under
 *      `/api/v1/admin/edges/`, each parsing with the contract in
 *      `src/shared/contracts/edges.ts` through `apiClient` (which seals by the
 *      shared route policy; nothing to do here).
 *   2. `edgeKeys`: the TanStack query-key tree. Everything sits under
 *      `['admin', 'edges']` (the admin 401 handler keys off `'admin'`); per-relay
 *      subtrees are keyed by SLUG (`['admin','edges','relay', slug, …]`) because the
 *      pages route by slug, per-edge by id (`['admin','edges','edge', edgeId, …]`),
 *      providers under `['admin','edges','providers', …]`, config under
 *      `['admin','edges','config']`.
 *   3. `*Query()` wrappers around `createQuery` in the accessor-function style of
 *      `queries.ts` (`(relaySlug: () => string | null)`), with the cadences the
 *      section relies on: summary 30 s (3 s while `counts.rotating > 0`),
 *      attention 15 s, setup-status 30 s (5 s while a step is `ready`), relay
 *      10 s while a rotation runs, rotation detail 2 s until terminal, probe
 *      matrix 30 s.
 *   Plus `invalidateOverview / invalidateRelay / invalidateEdge /
 *   invalidateProviders / invalidateConfig / invalidateAllEdges(qc, …)`.
 *
 * Request-body types not in the contracts are declared here (`CreateProviderBody`,
 * `RelayPatch`, …); the coordinator may lift them into the contracts later.
 */
import { createQuery, type QueryClient } from '@tanstack/svelte-query';
import { z } from 'zod';
import { apiClient } from './api';
import {
  AdoptHostRequest,
  AdoptHostResponse,
  AttentionResponse,
  DeliveryBindingsResponse,
  EdgeAdmin,
  EdgeAdoptResponse,
  EdgeConfigPatchResponse,
  EdgeConfigView,
  EdgeDetail,
  EdgeDiscoverResponse,
  EdgeIdResponse,
  EdgeInventoryResponse,
  EdgeLiveResponse,
  EdgeMaintenanceView,
  EdgeOkResponse,
  EdgeProviderAccountAdmin,
  EdgeProviderAccountsResponse,
  EdgeRenderPreviewResponse,
  EdgeRotateCredentialsResponse,
  EdgeRotationAdmin,
  EdgeRotationDetail,
  EdgeRotationStartedResponse,
  EdgeSummary,
  EdgeTemplateValidateResponse,
  EdgeTemplatesResponse,
  EdgeTemplatesSeedResponse,
  EdgeTestCredentialsResponse,
  EdgeVerificationBinding,
  EdgeVerifyRequest,
  EdgeVerifyResponse,
  ListenerSpec,
  PreflightRequest,
  PreflightResponse,
  ProbeAuditResponse,
  ProbeManyRequestedResponse,
  ProbeReachabilityMatrix,
  ProbeRequestedResponse,
  ProbeRunsResponse,
  ProbeSummary,
  ProbeTargetCreatedResponse,
  ProbeTargetsResponse,
  ProvidersUsageResponse,
  QuarantineView,
  RelayAdmin,
  RelayBySlugResponse,
  RelayEndpointsResponse,
  RelayListenerUpsertResponse,
  RelayListenersResponse,
  RelayNodeCandidatesResponse,
  InboundCandidatesResponse,
  EdgeTestLinkResponse,
  ResolveQuarantineRequest,
  SetupDraft,
  SetupStatusResponse,
  TestProvisionRequest,
  TimelineResponse,
  type EdgeProviderId,
  type HostMode,
  type RenderClientFamily,
  EdgeAutomationResponse,
  RelayRebalanceResponse,
  RequireEdgesResponse,
  SetupPlanResponse,
  SetupRunAdmin,
  SetupRunCancelResponse,
  SetupRunContinueRequest,
  SetupRunContinueResponse,
  SetupRunCreateRequest,
  SetupRunCreatedResponse,
  SetupRunRetryRequest,
  SetupRunRetryResponse,
  SetupRunsResponse,
} from '../../shared/contracts/edges';

const BASE = '/api/v1/admin/edges';
const enc = encodeURIComponent;

// --- request bodies (not in the contracts yet) ---------------------------------------------------

export type SetupDraftBody = z.infer<typeof SetupDraft>;
export type PreflightBody = z.infer<typeof PreflightRequest>;
export type TestProvisionBody = z.infer<typeof TestProvisionRequest>;
export type ResolveQuarantineBody = z.infer<typeof ResolveQuarantineRequest>;
export type AdoptHostBody = z.infer<typeof AdoptHostRequest>;
export type ListenerSpecBody = z.infer<typeof ListenerSpec>;

/** Any `edge.*` config change: flat paths (`{ 'detect.windowMinutes': 15 }`), nested objects, or `{ secrets: {…} }`. */
export type EdgeConfigPatch = Record<string, unknown>;

export interface CreateProviderBody {
  provider: EdgeProviderId;
  name: string;
  settings: Record<string, unknown>;
  credentials: Record<string, string>;
  maxLiveEdges?: number;
  dailyAllocationBudget?: number;
  priority?: number;
  defaultTemplateId?: string | null;
}
export interface ProviderPatch {
  name?: string;
  settings?: Record<string, unknown>;
  enabled?: boolean;
  priority?: number;
  dailyAllocationBudget?: number;
  maxLiveEdges?: number;
  defaultTemplateId?: string | null;
}
export interface DiscoverProviderBody {
  provider: EdgeProviderId;
  credentials: Record<string, string>;
  settings: Record<string, unknown>;
  accountId?: string;
}
export interface RotateCredentialsBody {
  credentials: Record<string, string>;
  identifiers?: Record<string, string>;
}
export interface CreateTemplateBody {
  provider: EdgeProviderId;
  name: string;
  params: unknown;
  isDefault?: boolean;
  accountId?: string | null;
}
export interface TemplatePatch {
  name?: string;
  params?: unknown;
  isDefault?: boolean;
  accountId?: string | null;
}
export interface ValidateTemplateBody {
  provider: EdgeProviderId;
  params: unknown;
}

/** The admin create shape: the backend by ID (the node role's PUT uses the slug). */
export type CreateRelayOrigin =
  | { kind: 'panel-node'; backendServerId: string; nodeName: string; nodeUuid?: string | null }
  | { kind: 'backend-server'; backendServerId: string }
  | { kind: 'manual' };
export interface CreateRelayBody {
  slug: string;
  origin: CreateRelayOrigin;
  originAddress: string;
  label?: string | null;
  locationCode?: string | null;
  listeners?: ListenerSpecBody[];
}
export interface RelayPatch {
  enabled?: boolean;
  autoRotate?: boolean;
  hostMode?: HostMode;
  label?: string | null;
  locationCode?: string | null;
  originAddress?: string;
  desiredPublished?: number;
  standbyPerRelay?: number;
  providerPreference?: EdgeProviderId | null;
  cooldownMinutes?: number;
  maxRotationsPerDay?: number;
  drainMinutes?: number;
  probeNode?: boolean;
  /** The connection mode whose placement the L7 qualification user is minted on; null = default. */
  qualificationModeSlug?: string | null;
}
export type RelayDeleteDisposition = 'restore-direct' | 'keep-dark';
export interface ProvisionBody {
  listenerId?: string;
  publish?: boolean;
}
export interface PublishRelayEdgeBody {
  edgeId: string;
  forceGeoEvidence?: boolean;
}
export interface RotateBody {
  edgeId: string;
  force?: boolean;
  forceGeoEvidence?: boolean;
}
export interface AdoptEdgeBody {
  accountId?: string;
  resourceId?: string;
  hostname?: string;
  ipv4?: string;
  port?: number;
  listenerId: string;
  publish?: boolean;
}
export interface PublishEdgeBody {
  direct?: boolean;
  poolIndex?: number;
  forceGeoEvidence?: boolean;
}
export type ResolveOperatorAction = 'destroy' | 'forget' | 'reactivate';
export interface ProbeTargetBody {
  label: string;
  address: string;
  port: number;
  probeProtocol: 'tcp' | 'tls' | 'https';
  enabled: boolean;
  notes: string;
}
export interface RenderPreviewBody {
  relayId: string;
  family: RenderClientFamily;
  sampleKey?: string;
}

/** Either a trailing window ending now, or an explicit custom date range (mirrors queries.ts). */
export type ProbeRange =
  | { kind: 'window'; windowMs: number }
  | { kind: 'range'; fromMs: number; toMs: number };
export const probeRangeQs = (r: ProbeRange): string =>
  r.kind === 'window' ? `window=${r.windowMs}` : `from=${r.fromMs}&to=${r.toMs}`;

// --- response shapes the contracts leave open --------------------------------------------------

/** `POST {edgeId}/publish`: a rotation when the flip needs the machine, a plain ok otherwise. */
export const EdgePublishResponse = z.union([EdgeRotationStartedResponse, EdgeOkResponse]);
export type EdgePublishResponse = z.infer<typeof EdgePublishResponse>;
/** `POST {edgeId}/qualify`: the front-qualification run result. */
export const EdgeQualifyResponse = z
  .object({ ok: z.boolean(), code: z.string().nullable().optional() })
  .passthrough();
export type EdgeQualifyResponse = z.infer<typeof EdgeQualifyResponse>;
const RelayList = z.array(RelayAdmin);
const EdgeList = z.array(EdgeAdmin);
const RotationList = z.array(EdgeRotationAdmin);
const NodeCandidatesLoose = RelayNodeCandidatesResponse.passthrough();

// --- fleet ---------------------------------------------------------------------------------------

export const fetchEdgeSummary = () => apiClient.get(`${BASE}/summary`, EdgeSummary);
export const fetchAttention = () => apiClient.get(`${BASE}/attention`, AttentionResponse);
export const fetchSetupStatus = (relaySlug?: string | null) =>
  apiClient.get(
    relaySlug ? `${BASE}/setup-status?relay=${enc(relaySlug)}` : `${BASE}/setup-status`,
    SetupStatusResponse,
  );
export const postSetupDraftStatus = (draft: SetupDraftBody) =>
  apiClient.post(`${BASE}/setup-status`, { draft }, SetupStatusResponse);

export const fetchEdgeConfig = () => apiClient.get(`${BASE}/config`, EdgeConfigView);
export const patchEdgeConfig = (patch: EdgeConfigPatch) =>
  apiClient.patch(`${BASE}/config`, patch, EdgeConfigPatchResponse);

export const fetchMaintenance = () => apiClient.get(`${BASE}/maintenance`, EdgeMaintenanceView);
export const freezeMaintenance = (reason?: string) =>
  apiClient.post(`${BASE}/maintenance/freeze`, reason ? { reason } : {}, EdgeMaintenanceView);
export const thawMaintenance = (reason?: string) =>
  apiClient.post(`${BASE}/maintenance/thaw`, reason ? { reason } : {}, EdgeMaintenanceView);
/** The one automation switch: `edge.enabled` + `autoRotate` + `probe.enabled` + `autoProvisionToDesired` (+ one spare per listener when on). */
export const setEdgeAutomation = (on: boolean) =>
  apiClient.post(`${BASE}/automation`, { on }, EdgeAutomationResponse);

// --- guided setup runs (Autopilot) ------------------------------------------------------------------

export type SetupRunCreateBody = z.infer<typeof SetupRunCreateRequest>;
export type SetupRunRetryBody = z.infer<typeof SetupRunRetryRequest>;
export type SetupRunContinueBody = z.infer<typeof SetupRunContinueRequest>;

/** The read-only plan for one panel node (throttled: it lists the node's inbounds and Hosts). */
export const planSetupRun = (backendServerId: string, nodeUuid: string) =>
  apiClient.post(`${BASE}/setup-runs/plan`, { backendServerId, nodeUuid }, SetupPlanResponse);
export const createSetupRun = (body: SetupRunCreateBody) =>
  apiClient.post(`${BASE}/setup-runs`, body, SetupRunCreatedResponse);
export const fetchSetupRuns = () => apiClient.get(`${BASE}/setup-runs`, SetupRunsResponse);
export const fetchSetupRun = (runId: string) =>
  apiClient.get(`${BASE}/setup-runs/${enc(runId)}`, SetupRunAdmin);
export const cancelSetupRun = (runId: string) =>
  apiClient.post(`${BASE}/setup-runs/${enc(runId)}/cancel`, {}, SetupRunCancelResponse);
export const retrySetupRun = (runId: string, body: SetupRunRetryBody = {}) =>
  apiClient.post(`${BASE}/setup-runs/${enc(runId)}/retry`, body, SetupRunRetryResponse);
export const continueSetupRun = (runId: string, body: SetupRunContinueBody = {}) =>
  apiClient.post(`${BASE}/setup-runs/${enc(runId)}/continue`, body, SetupRunContinueResponse);
/** The activation policy on a deferred relay: pending untested L4 endpoints come back instead of a binding. */
export const requireRelayEdges = (relayId: string, accountId?: string) =>
  apiClient.post(
    `${BASE}/relays/${enc(relayId)}/require-edges`,
    accountId ? { accountId } : {},
    RequireEdgesResponse,
  );

// --- providers ------------------------------------------------------------------------------------

export const fetchProviders = () =>
  apiClient.get(`${BASE}/providers`, EdgeProviderAccountsResponse);
export const fetchProvidersUsage = () =>
  apiClient.get(`${BASE}/providers/usage`, ProvidersUsageResponse);
export const fetchProvider = (id: string) =>
  apiClient.get(`${BASE}/providers/${enc(id)}`, EdgeProviderAccountAdmin);
export const fetchProviderInventory = (id: string) =>
  apiClient.get(`${BASE}/providers/${enc(id)}/inventory`, EdgeInventoryResponse);
export const createProvider = (body: CreateProviderBody) =>
  apiClient.post(`${BASE}/providers`, body, EdgeIdResponse);
export const discoverProviderOptions = (body: DiscoverProviderBody) =>
  apiClient.post(`${BASE}/providers/discover`, body, EdgeDiscoverResponse);
export const testProviderCredentials = (accountId: string) =>
  apiClient.post(`${BASE}/providers/test-credentials`, { accountId }, EdgeTestCredentialsResponse);
export const refreshProviderInventory = (id: string) =>
  apiClient.post(`${BASE}/providers/${enc(id)}/inventory/refresh`, {}, EdgeInventoryResponse);
export const qualifyProvider = (id: string, qualified: boolean) =>
  apiClient.post(`${BASE}/providers/${enc(id)}/qualify`, { qualified }, EdgeOkResponse);
export const rotateProviderCredentials = (id: string, body: RotateCredentialsBody) =>
  apiClient.post(
    `${BASE}/providers/${enc(id)}/rotate-credentials`,
    body,
    EdgeRotateCredentialsResponse,
  );
export const updateProvider = (id: string, patch: ProviderPatch) =>
  apiClient.patch(`${BASE}/providers/${enc(id)}`, patch, EdgeOkResponse);
export const deleteProvider = (id: string) =>
  apiClient.delete(`${BASE}/providers/${enc(id)}`, EdgeOkResponse);

// --- templates -----------------------------------------------------------------------------------

export const fetchTemplates = () => apiClient.get(`${BASE}/templates`, EdgeTemplatesResponse);
export const createTemplate = (body: CreateTemplateBody) =>
  apiClient.post(`${BASE}/templates`, body, EdgeIdResponse);
export const validateTemplate = (body: ValidateTemplateBody) =>
  apiClient.post(`${BASE}/templates/validate`, body, EdgeTemplateValidateResponse);
export const ensureDefaultTemplates = () =>
  apiClient.post(`${BASE}/templates/ensure-defaults`, {}, EdgeTemplatesSeedResponse);
export const updateTemplate = (id: string, patch: TemplatePatch) =>
  apiClient.patch(`${BASE}/templates/${enc(id)}`, patch, EdgeOkResponse);
export const deleteTemplate = (id: string) =>
  apiClient.delete(`${BASE}/templates/${enc(id)}`, EdgeOkResponse);

// --- relays ----------------------------------------------------------------------------------------

export const fetchRelays = () => apiClient.get(`${BASE}/relays`, RelayList);
/** 404 (an ApiCallError with status 404) when the slug is unknown. */
export const lookupRelay = (slug: string) =>
  apiClient.get(`${BASE}/relays/lookup?slug=${enc(slug)}`, RelayAdmin);
export const fetchNodeCandidates = (backendServerId: string) =>
  apiClient.get(
    `${BASE}/relays/node-candidates?backendServerId=${enc(backendServerId)}`,
    RelayNodeCandidatesResponse,
  );
/** Discovery with the origin probe applied (throttled: reaches the panel and opens sockets). */
export const fetchInboundCandidates = (backendServerId: string, nodeUuid: string) =>
  apiClient.get(
    `${BASE}/relays/inbound-candidates?backendServerId=${enc(backendServerId)}&nodeUuid=${enc(nodeUuid)}`,
    InboundCandidatesResponse,
  );
/** The isolated test link for an L4 candidate (throttled: fetches the credential body). */
// A POST: building the link may mint the test credential (a panel user or a
// temporary key), so it needs the write scope a GET would not carry.
export const fetchTestLink = (edgeId: string) =>
  apiClient.post(`${BASE}/edges/${enc(edgeId)}/test-link`, {}, EdgeTestLinkResponse);
/** What the operator is about to test, exactly as `verifyEdge` must echo it. */
export const fetchVerificationBinding = (edgeId: string) =>
  apiClient.get(`${BASE}/edges/${enc(edgeId)}/verification-binding`, EdgeVerificationBinding);
/** The per-endpoint confirmation of an L4 address; `edge.verification_stale` when the binding moved. */
export const verifyEdge = (edgeId: string, body: z.infer<typeof EdgeVerifyRequest>) =>
  apiClient.post(`${BASE}/edges/${enc(edgeId)}/verify`, body, EdgeVerifyResponse);
export const refreshNodeCandidates = (backendServerId: string) =>
  apiClient.post(
    `${BASE}/relays/node-candidates/refresh`,
    { backendServerId },
    NodeCandidatesLoose,
  );
export const fetchRelayBySlug = (slug: string) =>
  apiClient.get(`${BASE}/relays/by-slug/${enc(slug)}`, RelayBySlugResponse);
export const createRelay = (body: CreateRelayBody) =>
  apiClient.post(`${BASE}/relays`, body, EdgeIdResponse);
export const updateRelay = (relayId: string, patch: RelayPatch) =>
  apiClient.patch(`${BASE}/relays/${enc(relayId)}`, patch, EdgeOkResponse);
export const deleteRelay = (relayId: string, disposition: RelayDeleteDisposition, force = false) =>
  apiClient.delete(
    `${BASE}/relays/${enc(relayId)}?disposition=${disposition}${force ? '&force=true' : ''}`,
    EdgeOkResponse,
  );
export const fetchRelayListeners = (relayId: string) =>
  apiClient.get(`${BASE}/relays/${enc(relayId)}/listeners`, RelayListenersResponse);
export const fetchRelayEndpoints = (relayId: string) =>
  apiClient.get(`${BASE}/relays/${enc(relayId)}/endpoints`, RelayEndpointsResponse);
export const fetchRelayRotations = (relayId: string) =>
  apiClient.get(`${BASE}/relays/${enc(relayId)}/rotations`, RotationList);
export const fetchRelayTimeline = (relayId: string) =>
  apiClient.get(`${BASE}/relays/${enc(relayId)}/timeline`, TimelineResponse);
export const fetchRelayQuarantine = (relayId: string) =>
  apiClient.get(`${BASE}/relays/${enc(relayId)}/quarantine`, QuarantineView);
export const inspectRelayQuarantine = (relayId: string) =>
  apiClient.post(`${BASE}/relays/${enc(relayId)}/quarantine/inspect`, {}, QuarantineView);
export const preflightRelay = (relayId: string, body: PreflightBody) =>
  apiClient.post(`${BASE}/relays/${enc(relayId)}/preflight`, body, PreflightResponse);
export const testProvisionRelay = (relayId: string, body: TestProvisionBody) =>
  apiClient.post(
    `${BASE}/relays/${enc(relayId)}/test-provision`,
    body,
    EdgeRotationStartedResponse,
  );
export const provisionRelay = (relayId: string, body: ProvisionBody = {}) =>
  apiClient.post(`${BASE}/relays/${enc(relayId)}/provision`, body, EdgeRotationStartedResponse);
export const publishRelayEdge = (relayId: string, body: PublishRelayEdgeBody) =>
  apiClient.post(`${BASE}/relays/${enc(relayId)}/publish`, body, EdgeRotationStartedResponse);
export const rotateRelayEdge = (relayId: string, body: RotateBody) =>
  apiClient.post(`${BASE}/relays/${enc(relayId)}/rotate`, body, EdgeRotationStartedResponse);
export const burnRelayEdge = (relayId: string, body: RotateBody) =>
  apiClient.post(`${BASE}/relays/${enc(relayId)}/burn`, body, EdgeRotationStartedResponse);
export const cancelRelayRotation = (relayId: string) =>
  apiClient.post(`${BASE}/relays/${enc(relayId)}/cancel`, {}, EdgeOkResponse);
export const resolveRelayQuarantine = (relayId: string, body: ResolveQuarantineBody) =>
  apiClient.post(`${BASE}/relays/${enc(relayId)}/resolve-quarantine`, body, EdgeOkResponse);
/** Coverage at the cap: send ONE duplicate edge back to standby so an uncovered listener can be published. */
export const rebalanceRelay = (relayId: string) =>
  apiClient.post(`${BASE}/relays/${enc(relayId)}/rebalance`, {}, RelayRebalanceResponse);
export const probeRelay = (relayId: string) =>
  apiClient.post(`${BASE}/relays/${enc(relayId)}/probe`, {}, ProbeManyRequestedResponse);
export const adoptRelayEdge = (relayId: string, body: AdoptEdgeBody) =>
  apiClient.post(`${BASE}/relays/${enc(relayId)}/adopt`, body, EdgeAdoptResponse);
export const upsertRelayListener = (relayId: string, spec: ListenerSpecBody) =>
  apiClient.post(`${BASE}/relays/${enc(relayId)}/listeners`, spec, RelayListenerUpsertResponse);
export const deleteRelayListener = (relayId: string, listenerKey: string) =>
  apiClient.delete(`${BASE}/relays/${enc(relayId)}/listeners/${enc(listenerKey)}`, EdgeOkResponse);
export const adoptListenerHost = (relayId: string, listenerKey: string, body: AdoptHostBody) =>
  apiClient.post(
    `${BASE}/relays/${enc(relayId)}/listeners/${enc(listenerKey)}/adopt-host`,
    body,
    AdoptHostResponse,
  );
export const mintQualificationCredential = (relayId: string) =>
  apiClient.post(`${BASE}/relays/${enc(relayId)}/qualification-credential`, {}, EdgeOkResponse);
export const removeQualificationCredential = (relayId: string) =>
  apiClient.delete(`${BASE}/relays/${enc(relayId)}/qualification-credential`, EdgeOkResponse);

// --- edges -----------------------------------------------------------------------------------------

export const fetchRelayEdges = (relayId: string) =>
  apiClient.get(`${BASE}/list?relayId=${enc(relayId)}`, EdgeList);
export const fetchEdgeDetail = (edgeId: string) =>
  apiClient.get(`${BASE}/${enc(edgeId)}`, EdgeDetail);
export const fetchEdgeLive = (edgeId: string) =>
  apiClient.get(`${BASE}/${enc(edgeId)}/live`, EdgeLiveResponse);
export const publishEdge = (edgeId: string, body: PublishEdgeBody = {}) =>
  apiClient.post(`${BASE}/${enc(edgeId)}/publish`, body, EdgePublishResponse);
export const unpublishEdge = (edgeId: string, keepActive?: boolean) =>
  apiClient.post(
    `${BASE}/${enc(edgeId)}/unpublish`,
    keepActive === undefined ? {} : { keepActive },
    EdgeOkResponse,
  );
export const qualifyEdge = (edgeId: string) =>
  apiClient.post(`${BASE}/${enc(edgeId)}/qualify`, {}, EdgeQualifyResponse);
export const retryDestroyEdge = (edgeId: string) =>
  apiClient.post(`${BASE}/${enc(edgeId)}/retry-destroy`, {}, EdgeOkResponse);
export const resolveEdgeOperator = (edgeId: string, action: ResolveOperatorAction) =>
  apiClient.post(`${BASE}/${enc(edgeId)}/resolve-operator`, { action }, EdgeOkResponse);
export const probeEdge = (edgeId: string) =>
  apiClient.post(`${BASE}/${enc(edgeId)}/probe`, {}, ProbeRequestedResponse);
export const refreshEdgeLive = (edgeId: string) =>
  apiClient.post(`${BASE}/${enc(edgeId)}/live/refresh`, {}, EdgeLiveResponse);
export const deleteEdge = (edgeId: string) =>
  apiClient.delete(`${BASE}/${enc(edgeId)}`, EdgeOkResponse);

// --- rotations / listeners -----------------------------------------------------------------------

export const fetchRotation = (rotationId: string) =>
  apiClient.get(`${BASE}/rotations/${enc(rotationId)}`, EdgeRotationDetail);
/** Retire one server name everywhere it appears (fleet-wide). */
export const retireListenerNameEverywhere = (name: string) =>
  apiClient.post(`${BASE}/listeners/retire-name`, { name }, EdgeOkResponse);
export const retireListenerNames = (listenerId: string, snis: string[]) =>
  apiClient.post(`${BASE}/listeners/${enc(listenerId)}/retire-name`, { snis }, EdgeOkResponse);
export const reactivateListenerNames = (listenerId: string, snis: string[]) =>
  apiClient.post(`${BASE}/listeners/${enc(listenerId)}/reactivate-name`, { snis }, EdgeOkResponse);
export const enableListener = (listenerId: string) =>
  apiClient.post(`${BASE}/listeners/${enc(listenerId)}/enable`, {}, EdgeOkResponse);
export const disableListener = (listenerId: string) =>
  apiClient.post(`${BASE}/listeners/${enc(listenerId)}/disable`, {}, EdgeOkResponse);

// --- probes ----------------------------------------------------------------------------------------

export const fetchProbeRuns = (targetKey: string, take = 50) =>
  apiClient.get(`${BASE}/probes?target=${enc(targetKey)}&take=${take}`, ProbeRunsResponse);
export const fetchProbeMatrix = () =>
  apiClient.get(`${BASE}/probes/matrix`, ProbeReachabilityMatrix);
export const fetchProbeSummary = (range: ProbeRange) =>
  apiClient.get(`${BASE}/probes/summary?${probeRangeQs(range)}`, ProbeSummary);
export const fetchProbeTargets = () =>
  apiClient.get(`${BASE}/probes/targets`, ProbeTargetsResponse);
export const fetchProbeAudit = (take = 100) =>
  apiClient.get(`${BASE}/probes/audit?take=${take}`, ProbeAuditResponse);
export const requestProbes = (targets: string[], sources?: string[]) =>
  apiClient.post(
    `${BASE}/probes`,
    sources ? { targets, sources } : { targets },
    ProbeManyRequestedResponse,
  );
export const createProbeTarget = (body: ProbeTargetBody) =>
  apiClient.post(`${BASE}/probes/targets`, body, ProbeTargetCreatedResponse);
export const updateProbeTarget = (id: string, body: Partial<ProbeTargetBody>) =>
  apiClient.patch(`${BASE}/probes/targets/${enc(id)}`, body, EdgeOkResponse);
export const deleteProbeTarget = (id: string) =>
  apiClient.delete(`${BASE}/probes/targets/${enc(id)}`, EdgeOkResponse);

// --- render / delivery bindings --------------------------------------------------------------------

export const previewRender = (body: RenderPreviewBody) =>
  apiClient.post(`${BASE}/render/preview`, body, EdgeRenderPreviewResponse);
export const fetchDeliveryBindings = () =>
  apiClient.get(`${BASE}/delivery-bindings`, DeliveryBindingsResponse);
export const releaseDeliveryBinding = (id: string) =>
  apiClient.post(`${BASE}/delivery-bindings/${enc(id)}/release`, {}, EdgeOkResponse);

// --- query keys ------------------------------------------------------------------------------------

const ROOT = ['admin', 'edges'] as const;
export const edgeKeys = {
  all: ROOT,
  summary: [...ROOT, 'summary'] as const,
  attention: [...ROOT, 'attention'] as const,
  setupStatusAll: [...ROOT, 'setup-status'] as const,
  setupStatus: (relaySlug: string | null) => [...ROOT, 'setup-status', relaySlug ?? ''] as const,
  setupDraft: (draftKey: string) => [...ROOT, 'setup-status', 'draft', draftKey] as const,
  config: [...ROOT, 'config'] as const,
  maintenance: [...ROOT, 'maintenance'] as const,
  setupRuns: [...ROOT, 'setup-runs'] as const,
  setupRun: (runId: string) => [...ROOT, 'setup-runs', 'run', runId] as const,
  testLinks: (edgeIds: readonly string[]) => [...ROOT, 'test-links', edgeIds.join(',')] as const,
  providers: [...ROOT, 'providers'] as const,
  providersList: [...ROOT, 'providers', 'list'] as const,
  providersUsage: [...ROOT, 'providers', 'usage'] as const,
  provider: (id: string) => [...ROOT, 'providers', 'account', id] as const,
  providerInventory: (id: string) => [...ROOT, 'providers', 'account', id, 'inventory'] as const,
  templates: [...ROOT, 'templates'] as const,
  relays: [...ROOT, 'relays'] as const,
  relayLookup: (slug: string) => [...ROOT, 'relay', slug, 'lookup'] as const,
  relay: (slug: string) => [...ROOT, 'relay', slug] as const,
  relayBySlug: (slug: string) => [...ROOT, 'relay', slug, 'by-slug'] as const,
  relayListeners: (slug: string) => [...ROOT, 'relay', slug, 'listeners'] as const,
  relayEndpoints: (slug: string) => [...ROOT, 'relay', slug, 'endpoints'] as const,
  relayRotations: (slug: string) => [...ROOT, 'relay', slug, 'rotations'] as const,
  relayTimeline: (slug: string) => [...ROOT, 'relay', slug, 'timeline'] as const,
  relayQuarantine: (slug: string) => [...ROOT, 'relay', slug, 'quarantine'] as const,
  relayEdges: (slug: string) => [...ROOT, 'relay', slug, 'edges'] as const,
  nodeCandidates: (backendServerId: string) =>
    [...ROOT, 'node-candidates', backendServerId] as const,
  edge: (edgeId: string) => [...ROOT, 'edge', edgeId] as const,
  edgeDetail: (edgeId: string) => [...ROOT, 'edge', edgeId, 'detail'] as const,
  edgeLive: (edgeId: string) => [...ROOT, 'edge', edgeId, 'live'] as const,
  rotation: (rotationId: string) => [...ROOT, 'rotation', rotationId] as const,
  probes: [...ROOT, 'probes'] as const,
  probeMatrix: [...ROOT, 'probes', 'matrix'] as const,
  probeTargets: [...ROOT, 'probes', 'targets'] as const,
  probeRuns: (targetKey: string) => [...ROOT, 'probes', 'runs', targetKey] as const,
  probeSummary: (qs: string) => [...ROOT, 'probes', 'summary', qs] as const,
  probeAudit: [...ROOT, 'probes', 'audit'] as const,
  deliveryBindings: [...ROOT, 'delivery-bindings'] as const,
};

// --- invalidation ---------------------------------------------------------------------------------

/** Summary + attention + setup-status (every scope) + the guided runs. */
export function invalidateOverview(qc: QueryClient): void {
  void qc.invalidateQueries({ queryKey: edgeKeys.summary });
  void qc.invalidateQueries({ queryKey: edgeKeys.attention });
  void qc.invalidateQueries({ queryKey: edgeKeys.setupStatusAll });
  void qc.invalidateQueries({ queryKey: edgeKeys.setupRuns });
}
/** Everything keyed under one relay slug, the relay list, and the overview. */
export function invalidateRelay(qc: QueryClient, slug: string): void {
  void qc.invalidateQueries({ queryKey: edgeKeys.relay(slug) });
  void qc.invalidateQueries({ queryKey: edgeKeys.relays });
  void qc.invalidateQueries({ queryKey: edgeKeys.probeMatrix });
  invalidateOverview(qc);
}
export function invalidateEdge(qc: QueryClient, edgeId: string): void {
  void qc.invalidateQueries({ queryKey: edgeKeys.edge(edgeId) });
}
/** Accounts, usage, inventories, plus the setup steps that judge them. */
export function invalidateProviders(qc: QueryClient): void {
  void qc.invalidateQueries({ queryKey: edgeKeys.providers });
  void qc.invalidateQueries({ queryKey: edgeKeys.templates });
  void qc.invalidateQueries({ queryKey: edgeKeys.setupStatusAll });
  void qc.invalidateQueries({ queryKey: edgeKeys.attention });
}
/** Config + maintenance, plus the automation / rendering setup steps. */
export function invalidateConfig(qc: QueryClient): void {
  void qc.invalidateQueries({ queryKey: edgeKeys.config });
  void qc.invalidateQueries({ queryKey: edgeKeys.maintenance });
  void qc.invalidateQueries({ queryKey: edgeKeys.setupStatusAll });
  void qc.invalidateQueries({ queryKey: edgeKeys.attention });
}
export function invalidateProbes(qc: QueryClient): void {
  void qc.invalidateQueries({ queryKey: edgeKeys.probes });
}
/** The whole section (after a mutation whose blast radius is unclear). */
export function invalidateAllEdges(qc: QueryClient): void {
  void qc.invalidateQueries({ queryKey: edgeKeys.all });
}

// --- query wrappers ------------------------------------------------------------------------------

/** Fleet summary: 30 s, 3 s while any rotation runs. */
export const edgeSummaryQuery = () =>
  createQuery(() => ({
    queryKey: edgeKeys.summary,
    queryFn: fetchEdgeSummary,
    staleTime: 10_000,
    refetchInterval: (q) => ((q.state.data?.counts.rotating ?? 0) > 0 ? 3_000 : 30_000),
  }));

/** Ranked attention items: 15 s. */
export const attentionQuery = () =>
  createQuery(() => ({
    queryKey: edgeKeys.attention,
    queryFn: fetchAttention,
    staleTime: 10_000,
    refetchInterval: 15_000,
  }));

/**
 * Guided-setup status for one relay (slug) or the fleet (null): 30 s, 5 s while
 * a step is `ready` (the operator is acting on it right now).
 */
export const setupStatusQuery = (relaySlug: () => string | null) =>
  createQuery(() => ({
    queryKey: edgeKeys.setupStatus(relaySlug()),
    queryFn: () => fetchSetupStatus(relaySlug()),
    staleTime: 5_000,
    refetchInterval: (q) =>
      q.state.data?.steps.some((s) => s.status === 'ready') ? 5_000 : 30_000,
  }));

/** Setup status judged against a draft (before the relay row exists); null = off. */
export const setupDraftStatusQuery = (draft: () => SetupDraftBody | null) =>
  createQuery(() => {
    const d = draft();
    return {
      queryKey: edgeKeys.setupDraft(d ? JSON.stringify(d) : ''),
      queryFn: () => postSetupDraftStatus(d!),
      enabled: d !== null,
      staleTime: 10_000,
    };
  });

export const edgeConfigQuery = () =>
  createQuery(() => ({
    queryKey: edgeKeys.config,
    queryFn: fetchEdgeConfig,
    staleTime: 60_000,
  }));

const RUN_TERMINAL = new Set(['done', 'done_unbound', 'failed', 'cancelled']);
/** Every guided setup run: 15 s, 3 s while one is live. */
export const setupRunsQuery = () =>
  createQuery(() => ({
    queryKey: edgeKeys.setupRuns,
    queryFn: fetchSetupRuns,
    staleTime: 2_000,
    refetchInterval: (q) =>
      q.state.data?.runs.some((r) => !RUN_TERMINAL.has(r.state)) ? 3_000 : 15_000,
  }));

/** One run as the progress view polls it: every 3 s until it is terminal. */
export const setupRunQuery = (runId: () => string | null) =>
  createQuery(() => ({
    queryKey: edgeKeys.setupRun(runId() ?? ''),
    queryFn: () => fetchSetupRun(runId()!),
    enabled: runId() !== null,
    staleTime: 1_000,
    refetchInterval: (q) => (q.state.data && !RUN_TERMINAL.has(q.state.data.state) ? 3_000 : false),
  }));

/** The isolated test links of several addresses at once (each fetch is throttled server-side). */
export const testLinksQuery = (edgeIds: () => readonly string[]) =>
  createQuery(() => ({
    queryKey: edgeKeys.testLinks(edgeIds()),
    queryFn: () => Promise.all(edgeIds().map((id) => fetchTestLink(id))),
    enabled: edgeIds().length > 0,
    // The fetch is a POST that may mint the test credential and always reaches
    // the panel: built once per card, never re-issued on a window focus.
    staleTime: 5 * 60_000,
    refetchOnWindowFocus: false,
    retry: false,
  }));

export const maintenanceQuery = () =>
  createQuery(() => ({
    queryKey: edgeKeys.maintenance,
    queryFn: fetchMaintenance,
    staleTime: 15_000,
    refetchInterval: 30_000,
  }));

export const providersQuery = () =>
  createQuery(() => ({
    queryKey: edgeKeys.providersList,
    queryFn: fetchProviders,
    staleTime: 30_000,
  }));

export const providersUsageQuery = () =>
  createQuery(() => ({
    queryKey: edgeKeys.providersUsage,
    queryFn: fetchProvidersUsage,
    staleTime: 15_000,
    refetchInterval: 30_000,
  }));

export const providerQuery = (accountId: () => string | null) =>
  createQuery(() => ({
    queryKey: edgeKeys.provider(accountId() ?? ''),
    queryFn: () => fetchProvider(accountId()!),
    enabled: accountId() !== null,
    staleTime: 15_000,
  }));

export const providerInventoryQuery = (accountId: () => string | null) =>
  createQuery(() => ({
    queryKey: edgeKeys.providerInventory(accountId() ?? ''),
    queryFn: () => fetchProviderInventory(accountId()!),
    enabled: accountId() !== null,
    staleTime: 15_000,
  }));

export const templatesQuery = () =>
  createQuery(() => ({
    queryKey: edgeKeys.templates,
    queryFn: fetchTemplates,
    staleTime: 60_000,
  }));

export const relaysQuery = () =>
  createQuery(() => ({
    queryKey: edgeKeys.relays,
    queryFn: fetchRelays,
    staleTime: 10_000,
    refetchInterval: 30_000,
  }));

/** One relay by slug: 10 s while a rotation runs on it, 30 s otherwise. 404 = unknown slug. */
export const relayLookupQuery = (relaySlug: () => string | null) =>
  createQuery(() => ({
    queryKey: edgeKeys.relayLookup(relaySlug() ?? ''),
    queryFn: () => lookupRelay(relaySlug()!),
    enabled: relaySlug() !== null,
    staleTime: 5_000,
    refetchInterval: (q) => (q.state.data?.activeRotationId ? 10_000 : 30_000),
  }));

export const relayBySlugQuery = (relaySlug: () => string | null) =>
  createQuery(() => ({
    queryKey: edgeKeys.relayBySlug(relaySlug() ?? ''),
    queryFn: () => fetchRelayBySlug(relaySlug()!),
    enabled: relaySlug() !== null,
    staleTime: 10_000,
  }));

export const nodeCandidatesQuery = (backendServerId: () => string | null) =>
  createQuery(() => ({
    queryKey: edgeKeys.nodeCandidates(backendServerId() ?? ''),
    queryFn: () => fetchNodeCandidates(backendServerId()!),
    enabled: !!backendServerId(),
    staleTime: 30_000,
  }));

/**
 * Per-relay sub-resources. Keyed by SLUG (the page's route param) but fetched
 * by ID (the server's path param): pass both accessors; the query waits until
 * the id is known (from `relayLookupQuery`). `rotating` (optional) speeds the
 * poll to 10 s while a rotation runs.
 */
type RelayRef = { slug: () => string | null; id: () => string | null; rotating?: () => boolean };
const relayEnabled = (r: RelayRef) => r.slug() !== null && r.id() !== null;
const relayInterval = (r: RelayRef) => (r.rotating?.() ? 10_000 : false);

export const relayListenersQuery = (r: RelayRef) =>
  createQuery(() => ({
    queryKey: edgeKeys.relayListeners(r.slug() ?? ''),
    queryFn: () => fetchRelayListeners(r.id()!),
    enabled: relayEnabled(r),
    staleTime: 10_000,
    refetchInterval: relayInterval(r),
  }));

export const relayEndpointsQuery = (r: RelayRef) =>
  createQuery(() => ({
    queryKey: edgeKeys.relayEndpoints(r.slug() ?? ''),
    queryFn: () => fetchRelayEndpoints(r.id()!),
    enabled: relayEnabled(r),
    staleTime: 10_000,
    refetchInterval: relayInterval(r),
  }));

export const relayRotationsQuery = (r: RelayRef) =>
  createQuery(() => ({
    queryKey: edgeKeys.relayRotations(r.slug() ?? ''),
    queryFn: () => fetchRelayRotations(r.id()!),
    enabled: relayEnabled(r),
    staleTime: 5_000,
    refetchInterval: relayInterval(r),
  }));

export const relayTimelineQuery = (r: RelayRef) =>
  createQuery(() => ({
    queryKey: edgeKeys.relayTimeline(r.slug() ?? ''),
    queryFn: () => fetchRelayTimeline(r.id()!),
    enabled: relayEnabled(r),
    staleTime: 15_000,
    refetchInterval: relayInterval(r),
  }));

export const relayQuarantineQuery = (r: RelayRef) =>
  createQuery(() => ({
    queryKey: edgeKeys.relayQuarantine(r.slug() ?? ''),
    queryFn: () => fetchRelayQuarantine(r.id()!),
    enabled: relayEnabled(r),
    staleTime: 5_000,
  }));

export const relayEdgesQuery = (r: RelayRef) =>
  createQuery(() => ({
    queryKey: edgeKeys.relayEdges(r.slug() ?? ''),
    queryFn: () => fetchRelayEdges(r.id()!),
    enabled: relayEnabled(r),
    staleTime: 5_000,
    refetchInterval: relayInterval(r),
  }));

export const edgeDetailQuery = (edgeId: () => string | null) =>
  createQuery(() => ({
    queryKey: edgeKeys.edgeDetail(edgeId() ?? ''),
    queryFn: () => fetchEdgeDetail(edgeId()!),
    enabled: edgeId() !== null,
    staleTime: 5_000,
  }));

export const edgeLiveQuery = (edgeId: () => string | null) =>
  createQuery(() => ({
    queryKey: edgeKeys.edgeLive(edgeId() ?? ''),
    queryFn: () => fetchEdgeLive(edgeId()!),
    enabled: edgeId() !== null,
    staleTime: 15_000,
  }));

/** One rotation, polled every 2 s until it reaches a terminal phase. */
export const rotationQuery = (rotationId: () => string | null) =>
  createQuery(() => ({
    queryKey: edgeKeys.rotation(rotationId() ?? ''),
    queryFn: () => fetchRotation(rotationId()!),
    enabled: rotationId() !== null,
    staleTime: 1_000,
    refetchInterval: (q) => (q.state.data && !q.state.data.terminal ? 2_000 : false),
  }));

export const probeMatrixQuery = () =>
  createQuery(() => ({
    queryKey: edgeKeys.probeMatrix,
    queryFn: fetchProbeMatrix,
    staleTime: 15_000,
    refetchInterval: 30_000,
  }));

export const probeTargetsQuery = () =>
  createQuery(() => ({
    queryKey: edgeKeys.probeTargets,
    queryFn: fetchProbeTargets,
    staleTime: 30_000,
  }));

export const probeRunsQuery = (targetKey: () => string | null) =>
  createQuery(() => ({
    queryKey: edgeKeys.probeRuns(targetKey() ?? ''),
    queryFn: () => fetchProbeRuns(targetKey()!),
    enabled: !!targetKey(),
    staleTime: 10_000,
    refetchInterval: 15_000,
  }));

export const probeSummaryQuery = (range: () => ProbeRange) =>
  createQuery(() => {
    const qs = probeRangeQs(range());
    return {
      queryKey: edgeKeys.probeSummary(qs),
      queryFn: () => fetchProbeSummary(range()),
      staleTime: 30_000,
    };
  });

export const probeAuditQuery = () =>
  createQuery(() => ({
    queryKey: edgeKeys.probeAudit,
    queryFn: () => fetchProbeAudit(),
    staleTime: 15_000,
    refetchInterval: 30_000,
  }));

export const deliveryBindingsQuery = () =>
  createQuery(() => ({
    queryKey: edgeKeys.deliveryBindings,
    queryFn: fetchDeliveryBindings,
    staleTime: 30_000,
  }));

/**
 * Live validation of template params (the editor debounces the body it passes;
 * null = off). Keyed under `templates` by provider + the params JSON.
 */
export const templateValidateQuery = (body: () => ValidateTemplateBody | null) =>
  createQuery(() => {
    const b = body();
    return {
      queryKey: [
        ...edgeKeys.templates,
        'validate',
        b?.provider ?? '',
        b ? JSON.stringify(b.params) : '',
      ] as const,
      queryFn: () => validateTemplate(b!),
      enabled: b !== null,
      staleTime: 60_000,
      retry: false,
    };
  });
