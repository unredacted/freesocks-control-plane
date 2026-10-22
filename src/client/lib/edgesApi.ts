/**
 * Admin -> Edges data layer: the ONLY place edge API paths are built.
 *
 * Three layers, all exported:
 *   1. `fetch*` / verb functions: one typed function per server route under
 *      `/api/v1/admin/edges/`, each parsing with the contract in
 *      `src/shared/contracts/edges.ts` through `apiClient` (which seals by the
 *      shared route policy; nothing to do here).
 *   2. `edgeKeys`: the TanStack query-key tree. Everything sits under
 *      `['admin', 'edges']` (the admin 401 handler keys off `'admin'`); per-origin
 *      subtrees are keyed by SLUG (`['admin','edges','origin', slug, …]`) because the
 *      pages route by slug, per-edge by id (`['admin','edges','edge', edgeId, …]`),
 *      providers under `['admin','edges','providers', …]`, config under
 *      `['admin','edges','config']`.
 *   3. `*Query()` wrappers around `createQuery` in the accessor-function style of
 *      `queries.ts` (`(relaySlug: () => string | null)`), with the cadences the
 *      section relies on: summary 30 s (3 s while `counts.rotating > 0`),
 *      attention 15 s, setup-status 30 s (5 s while a step is `ready`), the
 *      origin and its lists 30 s (4 s while something runs on it; never off,
 *      lib/livePoll.ts), rotation detail 2 s until terminal, probe matrix 30 s,
 *      the checks from each country and the probe sources 30 s (4 s while a
 *      check the page asked for is out), a target's runs 30 s (4 s while one runs).
 *      The origin lookup, the summary and attention also note each origin's
 *      stamp; a stamp that moved invalidates that origin's lists
 *      (lib/edgesLive.ts `noteOrigins`), so a rotation shorter than one poll
 *      still shows within one summary read.
 *   Plus `invalidateOverview / invalidateRelay / invalidateEdge /
 *   invalidateProviders / invalidateConfig (qc, …)`.
 *
 * Request-body types not in the contracts are declared here (`CreateProviderBody`,
 * `RelayPatch`, …); the coordinator may lift them into the contracts later.
 */
import { createQuery, type QueryClient } from '@tanstack/svelte-query';
import { z } from 'zod';
import { apiClient } from './api';
import { noteOrigins } from './edgesLive';
import { edgeInFlight, liveInterval, originBusy, originStamp, originStatusStamp } from './livePoll';
import {
  AdoptHostRequest,
  AdoptHostResponse,
  AttentionResponse,
  CountryMarkResponse,
  type CountryMarkRequest,
  DeliveryBindingsResponse,
  EdgeAdmin,
  EdgeAdoptResponse,
  EdgeConfigPatchResponse,
  EdgeConfigView,
  EdgeCountriesResponse,
  EdgeDetail,
  EdgeDiscoverResponse,
  EdgeIdResponse,
  EdgeInventoryResponse,
  EdgeLiveResponse,
  EdgeAccountCostRequest,
  EdgeCatalogRefreshResponse,
  EdgeCatalogView,
  EdgePlansRefreshResponse,
  EdgeLocationCheckResponse,
  EdgeLocationCreateResponse,
  EdgeLocationList,
  EdgeMaintenanceView,
  FreedomDeliveryView,
  FreedomPreview,
  type EdgeLocationCreateRequest,
  type EdgeLocationUpdateRequest,
  EdgeOkResponse,
  EdgeSimulationEndedResponse,
  EdgeSimulationStartedResponse,
  EdgeSimulationsView,
  EdgeProviderAccountAdmin,
  EdgeProviderAccountsResponse,
  EdgeRenderPreviewResponse,
  EdgeRotateCredentialsResponse,
  EdgeSharedCertificateRemoveResponse,
  EdgeRotationAdmin,
  EdgeRotationDetail,
  EdgeRotationStartedResponse,
  EdgeSummary,
  EdgeTemplateValidateResponse,
  EdgeTemplatesResponse,
  EdgeTemplatesSeedResponse,
  EdgeTestCredentialsResponse,
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
  ProbeSourcesResponse,
  ProbeSummary,
  ProbeTargetCreatedResponse,
  ProbeTargetsResponse,
  ProvidersUsageResponse,
  QuarantineView,
  OriginAdmin,
  RelayListenerUpsertResponse,
  RelayListenersResponse,
  RelayNodeCandidatesResponse,
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
  ProviderSetView,
  ProviderSetChangeResponse,
  SetupRunAdmin,
  SetupRunCancelResponse,
  SetupRunContinueRequest,
  SetupRunContinueResponse,
  SetupRunCreateRequest,
  SetupRunCreatedResponse,
  SetupRunRetryRequest,
  SetupRunRetryResponse,
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
  /** The account's own settings, plus the first location's keys (split off by the server). */
  settings: Record<string, unknown>;
  /** The provider's name for that first location's region. */
  locationLabel?: string;
  credentials: Record<string, string>;
  maxLiveEdges?: number;
  dailyAllocationBudget?: number;
  priority?: number;
  defaultTemplateId?: string | null;
  /** Defaults for the provider's certificate options. */
  optionDefaults?: Record<string, unknown>;
  /** A DNS provider's account: DNS and fronting (true) or DNS only (false, the default). */
  frontsTraffic?: boolean;
}
export interface ProviderPatch {
  name?: string;
  settings?: Record<string, unknown>;
  /** The account's certificate option defaults, whole. */
  optionDefaults?: Record<string, unknown>;
  enabled?: boolean;
  /** A DNS provider's account: DNS and fronting (true) or DNS only (false). */
  frontsTraffic?: boolean;
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

/** The admin create shape: the backend by ID (the setup draft names it by slug). */
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
  /** The per-origin overrides: a number sets one, null follows the fleet setting again. */
  standbyPerRelay?: number | null;
  providerPreference?: EdgeProviderId | null;
  cooldownMinutes?: number | null;
  maxRotationsPerDay?: number | null;
  drainMinutes?: number | null;
  probeNode?: boolean;
  /** The connection mode whose placement the L7 qualification user is minted on; null = default. */
  qualificationModeSlug?: string | null;
}
export type RelayDeleteDisposition = 'restore-direct' | 'keep-dark';
export interface ProvisionBody {
  listenerId?: string;
  publish?: boolean;
  /** An explicit location (needs `listenerId`); an untrusted one only with `publish: false`. */
  locationId?: string;
  /**
   * Provider options for this one address instead of its pick's (needs `locationId`).
   * Automatic work never takes such an address afterwards: it was not built for its pick.
   */
  options?: Record<string, unknown>;
}
export interface PublishRelayEdgeBody {
  edgeId: string;
  forceGeoEvidence?: boolean;
}
export interface RotateBody {
  edgeId: string;
  force?: boolean;
  forceGeoEvidence?: boolean;
  /** An explicit spare (that one or nothing); Automatic otherwise. */
  spareEdgeId?: string;
  /** An explicit location for a new CDN front; Automatic otherwise. */
  locationId?: string;
  /** Provider options for the new address instead of its pick's (needs `locationId`). */
  options?: Record<string, unknown>;
}
export interface AdoptEdgeBody {
  accountId?: string;
  /** The account's location the resource lives in (its default when absent). */
  locationId?: string;
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
  /** "As a member in <country>" (a listed country). */
  country?: string;
}

/** Either a trailing window ending now, or an explicit custom date range (mirrors queries.ts). */
export type ProbeRange =
  | { kind: 'window'; windowMs: number }
  | { kind: 'range'; fromMs: number; toMs: number };
export const probeRangeQs = (r: ProbeRange): string =>
  r.kind === 'window' ? `window=${r.windowMs}` : `from=${r.fromMs}&to=${r.toMs}`;

// --- response shapes the contracts leave open --------------------------------------------------

/** `POST {edgeId}/qualify`: the front-qualification run result. */
export const EdgeQualifyResponse = z
  .object({ ok: z.boolean(), code: z.string().nullable().optional() })
  .passthrough();
export type EdgeQualifyResponse = z.infer<typeof EdgeQualifyResponse>;
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

export const fetchEdgeConfig = () => apiClient.get(`${BASE}/config`, EdgeConfigView);
export const patchEdgeConfig = (patch: EdgeConfigPatch) =>
  apiClient.patch(`${BASE}/config`, patch, EdgeConfigPatchResponse);

export const fetchMaintenance = () => apiClient.get(`${BASE}/maintenance`, EdgeMaintenanceView);
export const freezeMaintenance = (reason?: string) =>
  apiClient.post(`${BASE}/maintenance/freeze`, reason ? { reason } : {}, EdgeMaintenanceView);
export const thawMaintenance = (reason?: string) =>
  apiClient.post(`${BASE}/maintenance/thaw`, reason ? { reason } : {}, EdgeMaintenanceView);
/** Freedom modes only through edges: the switch, what turning it on would close, and the switch itself. */
export const fetchFreedomDelivery = () => apiClient.get(`${BASE}/freedom`, FreedomDeliveryView);
export const fetchFreedomPreview = () => apiClient.get(`${BASE}/freedom/preview`, FreedomPreview);
export const setFreedomEdgesOnly = (on: boolean, confirm = false) =>
  apiClient.post(`${BASE}/freedom`, { on, confirm }, FreedomDeliveryView);
/** The one automation switch: `edge.enabled` + `autoRotate` + `probe.enabled` + `autoProvisionToDesired` (+ one spare per listener when on). */
export const setEdgeAutomation = (on: boolean) =>
  apiClient.post(`${BASE}/automation`, { on }, EdgeAutomationResponse);

// --- guided setup runs (Autopilot) ------------------------------------------------------------------

export type SetupRunCreateBody = z.infer<typeof SetupRunCreateRequest>;
export type SetupRunRetryBody = z.infer<typeof SetupRunRetryRequest>;
export type SetupRunContinueBody = z.infer<typeof SetupRunContinueRequest>;

/**
 * The read-only plan for one backend node (throttled: it lists the node's transports and Hosts).
 * `listenerKeys` names the transports to protect on a node with more than one run takes.
 */
export const planSetupRun = (
  backendServerId: string,
  nodeUuid: string,
  listenerKeys?: string[],
  picks?: string[],
  pickOptions?: Record<string, Record<string, unknown>>,
) =>
  apiClient.post(
    `${BASE}/setup-runs/plan`,
    {
      backendServerId,
      nodeUuid,
      ...(listenerKeys ? { listenerKeys } : {}),
      ...(picks && picks.length > 0 ? { picks } : {}),
      ...(pickOptions && Object.keys(pickOptions).length > 0 ? { pickOptions } : {}),
    },
    SetupPlanResponse,
  );
export const createSetupRun = (body: SetupRunCreateBody) =>
  apiClient.post(`${BASE}/setup-runs`, body, SetupRunCreatedResponse);
export const fetchSetupRun = (runId: string) =>
  apiClient.get(`${BASE}/setup-runs/${enc(runId)}`, SetupRunAdmin);
export const cancelSetupRun = (runId: string) =>
  apiClient.post(`${BASE}/setup-runs/${enc(runId)}/cancel`, {}, SetupRunCancelResponse);
export const retrySetupRun = (runId: string, body: SetupRunRetryBody = {}) =>
  apiClient.post(`${BASE}/setup-runs/${enc(runId)}/retry`, body, SetupRunRetryResponse);
export const continueSetupRun = (runId: string, body: SetupRunContinueBody = {}) =>
  apiClient.post(`${BASE}/setup-runs/${enc(runId)}/continue`, body, SetupRunContinueResponse);
/**
 * "Serve this node directly again": the restore workflow that releases
 * edge-required delivery first, then puts the node's direct Hosts back
 * (edges and listeners stay; the node can be protected again later).
 */
export const serveRelayDirect = (relayId: string) =>
  apiClient.post(`${BASE}/relays/${enc(relayId)}/serve-direct`, {}, EdgeOkResponse);
/**
 * "Protect again": a re-protect run on a live, bound enrolled node (new
 * candidate addresses, Try it, the approval when one is needed). Members keep
 * what they have until it goes live; cancelling drops only its candidates.
 */
export const reprotectRelay = (
  relayId: string,
  mode?: 'replace_all' | 'add',
  pickOptions?: Record<string, Record<string, unknown>>,
) =>
  apiClient.post(
    `${BASE}/relays/${enc(relayId)}/reprotect`,
    { ...(mode ? { mode } : {}), ...(pickOptions ? { pickOptions } : {}) },
    SetupRunCreatedResponse,
  );
/** The node's provider set: its picks, what they hold, what could be added. */
export const fetchProviderSet = (relayId: string) =>
  apiClient.get(`${BASE}/relays/${enc(relayId)}/providers`, ProviderSetView);
/** Add or remove picks (an add on a live enrolled node starts a run). */
export const changeProviderSet = (relayId: string, body: { add?: string[]; remove?: string[] }) =>
  apiClient.post(`${BASE}/relays/${enc(relayId)}/providers`, body, ProviderSetChangeResponse);
/** The activation policy on a deferred origin: pending untested L4 endpoints come back instead of a binding. */
export const requireRelayEdges = (relayId: string, accountId?: string, locationId?: string) =>
  apiClient.post(
    `${BASE}/relays/${enc(relayId)}/require-edges`,
    { ...(accountId ? { accountId } : {}), ...(locationId ? { locationId } : {}) },
    RequireEdgesResponse,
  );

// --- providers ------------------------------------------------------------------------------------

export const fetchProviders = () =>
  apiClient.get(`${BASE}/providers`, EdgeProviderAccountsResponse);
export const fetchProvidersUsage = () =>
  apiClient.get(`${BASE}/providers/usage`, ProvidersUsageResponse);
export const fetchProvider = (id: string) =>
  apiClient.get(`${BASE}/providers/${enc(id)}`, EdgeProviderAccountAdmin);
export const fetchProviderInventory = (id: string, locationId?: string | null) =>
  apiClient.get(
    `${BASE}/providers/${enc(id)}/inventory${locationId ? `?location=${enc(locationId)}` : ''}`,
    EdgeInventoryResponse,
  );
export const createProvider = (body: CreateProviderBody) =>
  apiClient.post(`${BASE}/providers`, body, EdgeIdResponse);
export const discoverProviderOptions = (body: DiscoverProviderBody) =>
  apiClient.post(`${BASE}/providers/discover`, body, EdgeDiscoverResponse);
export const testProviderCredentials = (accountId: string) =>
  apiClient.post(`${BASE}/providers/test-credentials`, { accountId }, EdgeTestCredentialsResponse);
export const refreshProviderInventory = (id: string, locationId?: string | null) =>
  apiClient.post(
    `${BASE}/providers/${enc(id)}/inventory/refresh`,
    locationId ? { locationId } : {},
    EdgeInventoryResponse,
  );
export const qualifyProvider = (id: string, qualified: boolean) =>
  apiClient.post(`${BASE}/providers/${enc(id)}/qualify`, { qualified }, EdgeOkResponse);

// --- an account's locations (where its edges live) --------------------------------------------------

export const fetchProviderLocations = (accountId: string) =>
  apiClient.get(`${BASE}/providers/${enc(accountId)}/locations`, EdgeLocationList);
/**
 * The location form's choices for a stored account: regions, then networks and flavors of the
 * chosen one. `defaults`: a picked region's placement completed (`defaults`, `missing`).
 */
export const locationOptions = (
  accountId: string,
  placement: Record<string, unknown> = {},
  opts: { defaults?: boolean } = {},
) =>
  apiClient.post(
    `${BASE}/providers/${enc(accountId)}/locations/options`,
    { placement, ...(opts.defaults ? { defaults: true } : {}) },
    EdgeDiscoverResponse,
  );
/** Add a location (the provider must offer the region to this key); the same place twice is one location. */
export const createProviderLocation = (accountId: string, body: EdgeLocationCreateRequest) =>
  apiClient.post(`${BASE}/providers/${enc(accountId)}/locations`, body, EdgeLocationCreateResponse);
export const updateProviderLocation = (
  accountId: string,
  locationId: string,
  patch: EdgeLocationUpdateRequest,
) =>
  apiClient.patch(
    `${BASE}/providers/${enc(accountId)}/locations/${enc(locationId)}`,
    patch,
    EdgeOkResponse,
  );
export const deleteProviderLocation = (accountId: string, locationId: string) =>
  apiClient.delete(
    `${BASE}/providers/${enc(accountId)}/locations/${enc(locationId)}`,
    EdgeOkResponse,
  );
/** Ask the provider about one place again (a CDN zone's encryption mode, a refused check). */
export const checkProviderLocation = (accountId: string, locationId: string) =>
  apiClient.post(
    `${BASE}/providers/${enc(accountId)}/locations/${enc(locationId)}/check`,
    {},
    EdgeLocationCheckResponse,
  );
/** What the account's credentials reach (zones, regions, projects, TLS configurations), as last listed. */
export const fetchProviderCatalog = (accountId: string) =>
  apiClient.get(`${BASE}/providers/${enc(accountId)}/catalog`, EdgeCatalogView);
/** List what the account reaches again (a no-op answer `{refreshed: false}` right after another). */
export const refreshProviderCatalog = (accountId: string) =>
  apiClient.post(
    `${BASE}/providers/${enc(accountId)}/catalog/refresh`,
    {},
    EdgeCatalogRefreshResponse,
  );
/** The trust override for one location (an untrust holds the automatic rules off). */
export const qualifyProviderLocation = (
  accountId: string,
  locationId: string,
  qualified: boolean,
) =>
  apiClient.post(
    `${BASE}/providers/${enc(accountId)}/locations/${enc(locationId)}/qualify`,
    { qualified },
    EdgeOkResponse,
  );
export const rotateProviderCredentials = (id: string, body: RotateCredentialsBody) =>
  apiClient.post(
    `${BASE}/providers/${enc(id)}/rotate-credentials`,
    body,
    EdgeRotateCredentialsResponse,
  );
export const removeSharedCertificate = (id: string, locationId: string) =>
  apiClient.post(
    `${BASE}/providers/${enc(id)}/locations/${enc(locationId)}/shared-certificate/remove`,
    {},
    EdgeSharedCertificateRemoveResponse,
  );
export const updateProvider = (id: string, patch: ProviderPatch) =>
  apiClient.patch(`${BASE}/providers/${enc(id)}`, patch, EdgeOkResponse);
/** What the account costs (`cost: null` = the default) and its monthly cap. */
export const setProviderCost = (id: string, body: EdgeAccountCostRequest) =>
  apiClient.post(`${BASE}/providers/${enc(id)}/cost`, body, EdgeOkResponse);
/** Read one location's plans and prices again at the provider. */
export const refreshLocationPlans = (accountId: string, locationId: string) =>
  apiClient.post(
    `${BASE}/providers/${enc(accountId)}/locations/${enc(locationId)}/plans/refresh`,
    {},
    EdgePlansRefreshResponse,
  );
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

// --- origins ----------------------------------------------------------------------------------------

/** 404 (an ApiCallError with status 404) when the slug is unknown. */
export const lookupRelay = (slug: string) =>
  apiClient.get(`${BASE}/relays/lookup?slug=${enc(slug)}`, OriginAdmin);
export const fetchNodeCandidates = (backendServerId: string) =>
  apiClient.get(
    `${BASE}/relays/node-candidates?backendServerId=${enc(backendServerId)}`,
    RelayNodeCandidatesResponse,
  );
/** The isolated test link for an L4 candidate (throttled: fetches the credential body). */
// A POST: building the link may mint the test credential (a backend user or a
// temporary key), so it needs the write scope a GET would not carry.
export const fetchTestLink = (edgeId: string) =>
  apiClient.post(`${BASE}/edges/${enc(edgeId)}/test-link`, {}, EdgeTestLinkResponse);
/** The card closed or finished: the temporary credential behind its link expires now. */
export const releaseTestLink = (edgeId: string, credentialId: string) =>
  apiClient.post(
    `${BASE}/edges/${enc(edgeId)}/test-link/release`,
    { credentialId },
    EdgeOkResponse,
  );
/** The per-endpoint confirmation of an L4 address; `edge.verification_stale` when the binding moved. */
export const verifyEdge = (edgeId: string, body: z.infer<typeof EdgeVerifyRequest>) =>
  apiClient.post(`${BASE}/edges/${enc(edgeId)}/verify`, body, EdgeVerifyResponse);
export const refreshNodeCandidates = (backendServerId: string) =>
  apiClient.post(
    `${BASE}/relays/node-candidates/refresh`,
    { backendServerId },
    NodeCandidatesLoose,
  );
export const createRelay = (body: CreateRelayBody) =>
  apiClient.post(`${BASE}/relays`, body, EdgeIdResponse);
export const updateRelay = (relayId: string, patch: RelayPatch) =>
  apiClient.patch(`${BASE}/relays/${enc(relayId)}`, patch, EdgeOkResponse);
export const deleteRelay = (relayId: string, disposition: RelayDeleteDisposition, force = false) =>
  apiClient.delete(
    `${BASE}/relays/${enc(relayId)}?disposition=${disposition}${force ? '&force=true' : ''}`,
    EdgeOkResponse,
  );
/** Test block evidence on an origin (accepted here at all, live, recent). */
export const fetchRelaySimulations = (relayId: string) =>
  apiClient.get(`${BASE}/relays/${enc(relayId)}/simulations`, EdgeSimulationsView);
/** Start test block evidence on a published edge (a test deployment only). */
export const simulateBlock = (
  edgeId: string,
  body: { country: string; reporters?: number; minutes?: number },
) =>
  apiClient.post(
    `${BASE}/edges/${enc(edgeId)}/simulate-block`,
    body,
    EdgeSimulationStartedResponse,
  );
/** End every live test block on an edge. */
export const endSimulatedBlock = (edgeId: string) =>
  apiClient.post(
    `${BASE}/edges/${enc(edgeId)}/simulate-block/end`,
    {},
    EdgeSimulationEndedResponse,
  );
export const fetchRelayListeners = (relayId: string) =>
  apiClient.get(`${BASE}/relays/${enc(relayId)}/listeners`, RelayListenersResponse);
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
/** Whether each enabled source is bringing back evidence. */
export const fetchProbeSources = () =>
  apiClient.get(`${BASE}/probes/sources`, ProbeSourcesResponse);

// --- checks from each country --------------------------------------------------------------------

/** Grades per location, every edge's state per checked country, marks, sources. */
export const fetchEdgeCountries = () => apiClient.get(`${BASE}/countries`, EdgeCountriesResponse);
/** An operator's mark on an edge or a location in one country (`state: null` removes it). */
export const setCountryMark = (body: CountryMarkRequest) =>
  apiClient.post(`${BASE}/countries/marks`, body, CountryMarkResponse);
/** One round of one edge from every checked country now (throttled like a probe request). */
export const requestCountryCheck = (edgeId: string) =>
  apiClient.post(`${BASE}/countries/check`, { edgeId }, ProbeRequestedResponse);

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
  freedom: [...ROOT, 'freedom'] as const,
  freedomPreview: [...ROOT, 'freedom', 'preview'] as const,
  setupRuns: [...ROOT, 'setup-runs'] as const,
  setupRun: (runId: string) => [...ROOT, 'setup-runs', 'run', runId] as const,
  testLinks: (edgeIds: readonly string[]) => [...ROOT, 'test-links', edgeIds.join(',')] as const,
  providers: [...ROOT, 'providers'] as const,
  providersList: [...ROOT, 'providers', 'list'] as const,
  providersUsage: [...ROOT, 'providers', 'usage'] as const,
  provider: (id: string) => [...ROOT, 'providers', 'account', id] as const,
  providerInventory: (id: string) => [...ROOT, 'providers', 'account', id, 'inventory'] as const,
  providerCatalog: (id: string) => [...ROOT, 'providers', 'account', id, 'catalog'] as const,
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
  relayProviders: (slug: string) => [...ROOT, 'relay', slug, 'providers'] as const,
  relaySimulations: (slug: string) => [...ROOT, 'relay', slug, 'simulations'] as const,
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
  probeSources: [...ROOT, 'probes', 'sources'] as const,
  countries: [...ROOT, 'countries'] as const,
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
/** Everything keyed under one origin slug, the origin list, and the overview. */
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
/** The checks from each country, the probes (a check is a round of runs) and attention. */
export function invalidateCountries(qc: QueryClient): void {
  void qc.invalidateQueries({ queryKey: edgeKeys.countries });
  void qc.invalidateQueries({ queryKey: edgeKeys.probes });
  void qc.invalidateQueries({ queryKey: edgeKeys.attention });
}

// --- query wrappers ------------------------------------------------------------------------------

/** Fleet summary: 30 s, 3 s while any rotation runs. Notes every origin's stamp. */
export const edgeSummaryQuery = () =>
  createQuery(() => ({
    queryKey: edgeKeys.summary,
    queryFn: async ({ client }) => {
      const summary = await fetchEdgeSummary();
      noteOrigins(
        client,
        'summary',
        summary.relays.map((r) => [r.relay.slug, originStamp(r.relay)] as const),
      );
      return summary;
    },
    staleTime: 10_000,
    refetchInterval: (q) => ((q.state.data?.counts.rotating ?? 0) > 0 ? 3_000 : 30_000),
  }));

/** Ranked attention items: 15 s. Notes every origin's status stamp. */
export const attentionQuery = () =>
  createQuery(() => ({
    queryKey: edgeKeys.attention,
    queryFn: async ({ client }) => {
      const attention = await fetchAttention();
      noteOrigins(
        client,
        'attention',
        attention.origins.map((o) => [o.relaySlug, originStatusStamp(o.status)] as const),
      );
      return attention;
    },
    staleTime: 10_000,
    refetchInterval: 15_000,
  }));

/**
 * Guided-setup status for one origin (slug) or the fleet (null): 30 s, 5 s while
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

export const edgeConfigQuery = () =>
  createQuery(() => ({
    queryKey: edgeKeys.config,
    queryFn: fetchEdgeConfig,
    staleTime: 60_000,
  }));

const RUN_TERMINAL = new Set(['done', 'done_unbound', 'failed', 'cancelled']);

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
    // the backend: built once per card, never re-issued on a window focus.
    staleTime: 5 * 60_000,
    refetchOnWindowFocus: false,
    retry: false,
  }));

export const freedomDeliveryQuery = () =>
  createQuery(() => ({
    queryKey: edgeKeys.freedom,
    queryFn: fetchFreedomDelivery,
    staleTime: 15_000,
  }));

/** Read on demand (it counts members): the card asks for it, nothing polls it. */
export const freedomPreviewQuery = (enabled: () => boolean) =>
  createQuery(() => ({
    queryKey: edgeKeys.freedomPreview,
    queryFn: fetchFreedomPreview,
    enabled: enabled(),
    staleTime: 60_000,
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

/**
 * What an account reaches, for the location pickers. A catalog older than its
 * `staleAfterMs` (or never listed) is listed again once, in the background;
 * the stored one shows meanwhile.
 */
export const providerCatalogQuery = (accountId: () => string | null) =>
  createQuery(() => ({
    queryKey: edgeKeys.providerCatalog(accountId() ?? ''),
    queryFn: () => fetchProviderCatalog(accountId()!),
    enabled: accountId() !== null,
    staleTime: 15_000,
  }));

export const providerInventoryQuery = (
  accountId: () => string | null,
  locationId: () => string | null = () => null,
) =>
  createQuery(() => ({
    queryKey: [...edgeKeys.providerInventory(accountId() ?? ''), locationId() ?? 'default'],
    queryFn: () => fetchProviderInventory(accountId()!, locationId()),
    enabled: accountId() !== null,
    staleTime: 15_000,
  }));

export const templatesQuery = () =>
  createQuery(() => ({
    queryKey: edgeKeys.templates,
    queryFn: fetchTemplates,
    staleTime: 60_000,
  }));

/**
 * One origin by slug: 30 s, 4 s while a rotation, a restore or a delete runs on
 * it. Notes the origin's stamp. 404 = unknown slug.
 */
export const relayLookupQuery = (relaySlug: () => string | null) =>
  createQuery(() => ({
    queryKey: edgeKeys.relayLookup(relaySlug() ?? ''),
    queryFn: async ({ client }) => {
      const origin = await lookupRelay(relaySlug()!);
      noteOrigins(client, 'lookup', [[origin.slug, originStamp(origin)]]);
      return origin;
    },
    enabled: relaySlug() !== null,
    staleTime: 5_000,
    refetchInterval: (q) => liveInterval(!!q.state.data && originBusy(q.state.data)),
  }));

export const nodeCandidatesQuery = (backendServerId: () => string | null) =>
  createQuery(() => ({
    queryKey: edgeKeys.nodeCandidates(backendServerId() ?? ''),
    queryFn: () => fetchNodeCandidates(backendServerId()!),
    enabled: !!backendServerId(),
    staleTime: 30_000,
  }));

/**
 * Per-origin sub-resources. Keyed by SLUG (the page's route param) but fetched
 * by ID (the server's path param): pass both accessors; the query waits until
 * the id is known (from `relayLookupQuery`). Each polls every 30 s; `rotating`
 * (optional: a rotation, a setup run or a restore runs on the origin) speeds
 * that to 4 s. `poll: false` is for a dialog that reads once (a page's change
 * detection still refreshes it while it is mounted).
 */
type RelayRef = {
  slug: () => string | null;
  id: () => string | null;
  rotating?: () => boolean;
  poll?: boolean;
};
const relayEnabled = (r: RelayRef) => r.slug() !== null && r.id() !== null;
const relayInterval = (r: RelayRef) => (r.poll === false ? false : liveInterval(!!r.rotating?.()));

export const relaySimulationsQuery = (r: RelayRef) =>
  createQuery(() => ({
    queryKey: edgeKeys.relaySimulations(r.slug() ?? ''),
    queryFn: () => fetchRelaySimulations(r.id()!),
    enabled: relayEnabled(r),
    staleTime: 10_000,
    refetchInterval: relayInterval(r),
  }));

export const relayListenersQuery = (r: RelayRef) =>
  createQuery(() => ({
    queryKey: edgeKeys.relayListeners(r.slug() ?? ''),
    queryFn: () => fetchRelayListeners(r.id()!),
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
    refetchInterval: relayInterval(r),
  }));

export const relayProvidersQuery = (r: RelayRef) =>
  createQuery(() => ({
    queryKey: edgeKeys.relayProviders(r.slug() ?? ''),
    queryFn: () => fetchProviderSet(r.id()!),
    enabled: relayEnabled(r),
    staleTime: 10_000,
    refetchInterval: relayInterval(r),
  }));

export const relayEdgesQuery = (r: RelayRef) =>
  createQuery(() => ({
    queryKey: edgeKeys.relayEdges(r.slug() ?? ''),
    queryFn: () => fetchRelayEdges(r.id()!),
    enabled: relayEnabled(r),
    staleTime: 5_000,
    // Faster while an edge is being made, checked or destroyed, too.
    refetchInterval: (q) => liveInterval(!!r.rotating?.() || edgeInFlight(q.state.data ?? [])),
  }));

export const edgeDetailQuery = (edgeId: () => string | null) =>
  createQuery(() => ({
    queryKey: edgeKeys.edgeDetail(edgeId() ?? ''),
    queryFn: () => fetchEdgeDetail(edgeId()!),
    enabled: edgeId() !== null,
    staleTime: 5_000,
    // The detail carries the live view too: the drawer's one poller.
    refetchInterval: (q) => liveInterval(!!q.state.data && edgeInFlight([q.state.data.edge])),
  }));

/**
 * The live view alone. The edge drawer does not use it: it reads the snapshot
 * from `edgeDetailQuery` (one cache, one poller; `setEdgeLiveSnapshot`).
 */
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

/** One target's runs: 30 s, 4 s while one of them is requested or running. */
export const probeRunsQuery = (targetKey: () => string | null) =>
  createQuery(() => ({
    queryKey: edgeKeys.probeRuns(targetKey() ?? ''),
    queryFn: () => fetchProbeRuns(targetKey()!),
    enabled: !!targetKey(),
    staleTime: 10_000,
    refetchInterval: (q) =>
      liveInterval(
        (q.state.data?.runs ?? []).some((r) => r.status === 'requested' || r.status === 'running'),
      ),
  }));

/** Whether each probe source brings back evidence: 30 s. */
export const probeSourcesQuery = () =>
  createQuery(() => ({
    queryKey: edgeKeys.probeSources,
    queryFn: fetchProbeSources,
    staleTime: 15_000,
    refetchInterval: liveInterval(false),
  }));

/**
 * The checks from each country (one cache for every page that shows them):
 * 30 s, 4 s while `busy(data)` (a check the page asked for has not come back,
 * a setup run waits for its round; judged after every read). `poll: false`
 * reads once (a dialog); `enabled` keeps a mounted but hidden view from reading.
 */
export const edgeCountriesQuery = (
  o: {
    busy?: (data: EdgeCountriesResponse | undefined) => boolean;
    poll?: boolean;
    enabled?: () => boolean;
  } = {},
) =>
  createQuery(() => ({
    queryKey: edgeKeys.countries,
    queryFn: fetchEdgeCountries,
    enabled: o.enabled?.() ?? true,
    staleTime: 10_000,
    refetchInterval:
      o.poll === false
        ? (false as const)
        : (q: { state: { data: EdgeCountriesResponse | undefined } }) =>
            liveInterval(!!o.busy?.(q.state.data)),
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

/**
 * A "Refresh live" result goes into the edge's detail, the one place the
 * drawer reads its live snapshot from, so a later detail poll supersedes it.
 */
export function setEdgeLiveSnapshot(
  qc: QueryClient,
  edgeId: string,
  live: EdgeDetail['live'],
): void {
  qc.setQueryData<EdgeDetail>(edgeKeys.edgeDetail(edgeId), (old) => (old ? { ...old, live } : old));
}
