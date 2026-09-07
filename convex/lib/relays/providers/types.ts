/**
 * The relay-edge PROVIDER contract: how FCP drives one cloud load-balancer API.
 *
 * Design rules (docs/relays.md):
 *  - Provisioning is an ordered list of RESOURCE STEPS. Each step is one provider
 *    call that may create SEVERAL billable children (a compound "create LB" call
 *    can mint an LB + a floating IP + listeners); every child is reported back
 *    so the ledger records all of them, partial results included.
 *  - A timeout is an UNKNOWN outcome. The generic layer never retries an
 *    allocating call blindly: it asks `discover()` first, which answers with one
 *    of four outcomes. Only `confirmed_absent` permits another allocation.
 *  - Errors never carry provider response bodies, URLs or credentials (see
 *    ./http.ts); a short provider error CODE is the most detail they hold.
 *  - Nothing here touches the database. Adapters are pure HTTP clients (+ the
 *    Scaleway SDK); the "use node" actions in convex/relayProviderOps.ts call them
 *    and the isolate mutations own all state.
 */
import type { z } from 'zod';
import type { EdgeProviderId } from '../../edgeProviderIds';

// --- per-provider config (credentials + settings merged, as the actions see it) ---

export interface GcoreConfig {
  type: 'gcore';
  apiKey: string;
  projectId: number;
  regionId: number;
  networkId?: string;
  subnetId?: string;
}
export interface UpcloudConfig {
  type: 'upcloud';
  token: string;
  zone: string;
}
export interface ScalewayConfig {
  type: 'scaleway';
  accessKey: string;
  secretKey: string;
  projectId: string;
  zone: string;
}
export interface OvhConfig {
  type: 'ovh';
  applicationKey: string;
  applicationSecret: string;
  consumerKey: string;
  endpoint: 'ovh-eu' | 'ovh-ca' | 'ovh-us';
  serviceName: string;
  regionName: string;
  networkId: string;
  subnetId: string;
  gatewayId?: string;
}
export type RelayProviderConfig = GcoreConfig | UpcloudConfig | ScalewayConfig | OvhConfig;

// --- what to build -----------------------------------------------------------------

export interface EdgeListenerSpec {
  /** Client-facing port on the edge. */
  edgePort: number;
  /** Origin members the listener forwards to (v1: exactly one). */
  members: Array<{ address: string; port: number }>;
  /** Absent = tcp. Adapters forward TCP; a udp listener is refused unless the capability says otherwise. */
  transport?: 'tcp' | 'udp';
}

export interface EdgeSpec {
  /** Provider-side resource name == edges.name; the discovery key. */
  name: string;
  listeners: EdgeListenerSpec[];
}

// --- steps, ledger, outcomes --------------------------------------------------------

export type ResourceKind =
  | 'allocate_ip'
  | 'allocate_ipv6'
  | 'create_lb'
  | 'create_listener'
  | 'create_pool'
  | 'create_backend'
  | 'create_frontend'
  | 'attach_ip';

export type Discoverability = 'by_name' | 'by_tag' | 'none';

export interface ResourceStep {
  id: string;
  kind: ResourceKind;
  /** Deterministic provider-side name for the thing this step creates. */
  resourceName: string;
  discoverability: Discoverability;
}

export type StepState =
  | 'pending'
  | 'requested'
  | 'done'
  | 'unresolved'
  | 'ambiguous'
  | 'needs_operator';

export interface LedgerStep {
  stepId: string;
  kind: string;
  resourceName: string;
  state: StepState;
  opRef?: string;
  attempt: number;
  /** Consecutive unresolved discovery passes for this step. */
  discoverAttempts?: number;
  startedAt?: number;
  finishedAt?: number;
}

export type DeleteState = 'present' | 'delete_requested' | 'confirmed_gone';

export interface LedgerResource {
  stepId: string;
  kind: string;
  resourceId: string;
  ownership: 'created' | 'adopted';
  deleteState: DeleteState;
  /** Provider-specific JSON (e.g. an address, a vip port id, a task id). */
  meta?: string;
}

/** The persisted edge state an adapter reads (never writes). */
export interface Ledger {
  steps: LedgerStep[];
  resources: LedgerResource[];
}

export interface ChildResource {
  /** Provider-native resource kind (e.g. 'lb', 'floating_ip', 'ip', 'backend'). */
  kind: string;
  resourceId: string;
  ownership: 'created' | 'adopted';
  meta?: Record<string, unknown>;
}

export interface Addresses {
  v4?: string;
  v6?: string;
}

export type StepOutcome =
  /** The call completed; every child it created is listed. */
  | { status: 'done'; resources: ChildResource[]; addresses?: Addresses }
  /** The call failed after creating some children (all listed). */
  | { status: 'partial'; resources: ChildResource[]; code?: string }
  /** Async provider: an operation/task to poll; children known so far listed. */
  | { status: 'requested'; opRef: string; resources: ChildResource[] };

export type Discovery =
  | { status: 'found'; resources: ChildResource[]; addresses?: Addresses }
  /** The provider's listing is authoritative and the resource is not there. */
  | { status: 'confirmed_absent' }
  /** Not visible yet, or the listing cannot prove absence: keep reconciling. */
  | { status: 'unresolved' }
  /** Candidates exist but ownership cannot be proven: an operator decides. */
  | { status: 'ambiguous'; candidates: ChildResource[] };

export type EdgeState = 'pending' | 'active' | 'error' | 'gone';
export type EdgeHealth = 'online' | 'offline' | 'degraded' | 'unknown';

export interface EdgeDescription {
  state: EdgeState;
  addresses: Addresses;
  health: EdgeHealth;
  code?: string;
  /** Children first visible after creation (e.g. a floating IP the LB minted). */
  resources?: ChildResource[];
}

export type DestroyOutcome =
  | { status: 'delete_requested'; opRef?: string }
  | { status: 'confirmed_gone' }
  | { status: 'unresolved' };

// --- live views ------------------------------------------------------------------------

export interface InspectSummary {
  status?: string;
  operatingStatus?: string;
  flavor?: string;
  region?: string;
  createdAt?: string;
  addresses: Addresses;
  members: Array<{ address: string; port: number; health?: string }>;
  listeners: Array<{ port: number; protocol?: string }>;
  stats?: { connections?: number; bytesIn?: number; bytesOut?: number };
}

export interface InspectResult {
  summary: InspectSummary;
  /** The provider's own object, secrets stripped (admin-only display). */
  raw: unknown;
}

export interface InventoryLb {
  id: string;
  name: string;
  status?: string;
  addresses: Addresses;
  createdAt?: string;
}
export interface InventoryIp {
  id: string;
  address: string;
  attachedTo?: string | null;
}
export interface Inventory {
  loadBalancers: InventoryLb[];
  ips: InventoryIp[];
  flavors: Array<{ id: string; label: string }>;
}

// --- templates ---------------------------------------------------------------------------

export type TemplateFieldType = 'string' | 'number' | 'boolean' | 'select' | 'string-list';

/** A form-descriptor for one template field (the CMS renders a form from these). */
export interface TemplateFieldDescriptor {
  key: string; // dotted path into the template params
  label: string;
  type: TemplateFieldType;
  help?: string;
  options?: Array<{ value: string; label: string }>;
  required?: boolean;
}

export interface CredentialTestResult {
  ok: boolean;
  code?: string;
  detail?: string;
}

export interface DiscoverOption {
  id: string;
  label: string;
}
/** Choice lists for the account form; a missing key = not applicable or not yet discoverable. */
export interface DiscoverResult {
  projects?: DiscoverOption[];
  regions?: DiscoverOption[];
  networks?: Array<DiscoverOption & { subnets: DiscoverOption[] }>;
  /** Per-list failure codes (never bodies): the form shows the field as free text instead. */
  errors?: Record<string, string>;
}

// --- the adapter -----------------------------------------------------------------------------

export interface EdgeProvider<
  Cfg extends RelayProviderConfig = RelayProviderConfig,
  Tpl = Record<string, unknown>,
> {
  id: EdgeProviderId;
  /** Validates + defaults a template's params (the CMS + provisioning both use it). */
  templateSchema: z.ZodType<Tpl>;
  templateFields: TemplateFieldDescriptor[];
  defaultTemplate: Tpl;

  testCredentials(cfg: Cfg): Promise<CredentialTestResult>;
  listRegions?(cfg: Cfg): Promise<Array<{ id: string; label: string }>>;
  /**
   * What the account form can offer as choices, given the credentials and any
   * settings chosen so far (a PARTIAL config: adapters return only the lists
   * their inputs allow, e.g. OVH regions need the project first). Never throws
   * for a missing dependency; a failing call surfaces as `errors`.
   */
  discoverOptions?(partial: Partial<Cfg> & Record<string, unknown>): Promise<DiscoverResult>;

  /** The ordered steps for one edge; each is a single provider call. */
  planProvision(cfg: Cfg, spec: EdgeSpec, tpl: Tpl): ResourceStep[];
  runStep(
    cfg: Cfg,
    step: ResourceStep,
    spec: EdgeSpec,
    tpl: Tpl,
    ledger: Ledger,
  ): Promise<StepOutcome>;
  /** Async providers: advance a `requested` step by its opRef. */
  pollStep?(cfg: Cfg, step: ResourceStep, opRef: string, ledger: Ledger): Promise<StepOutcome>;
  /** REQUIRED for every allocating kind the provider plans. `attempt` counts
   *  consecutive discovery attempts, so listing-based adapters can promote a
   *  repeated absence to `confirmed_absent` where they document it as safe. */
  discover(
    cfg: Cfg,
    step: ResourceStep,
    spec: EdgeSpec,
    ledger: Ledger,
    attempt: number,
  ): Promise<Discovery>;

  describe(cfg: Cfg, ledger: Ledger): Promise<EdgeDescription>;
  inspect(cfg: Cfg, ledger: Ledger): Promise<InspectResult>;
  inventory(cfg: Cfg): Promise<Inventory>;

  /** Ledger resources in destroy order (reverse of creation), skipping gone ones. */
  planDestroy(cfg: Cfg, ledger: Ledger): LedgerResource[];
  runDestroy(cfg: Cfg, resource: LedgerResource, ledger: Ledger): Promise<DestroyOutcome>;
  /**
   * Async-delete providers: read the resource back after `delete_requested`
   * (404 → `confirmed_gone`, present → `unresolved`). Providers WITHOUT this
   * method delete synchronously; the dispatcher re-runs their idempotent
   * `runDestroy` to confirm instead of assuming the delete landed.
   */
  confirmDestroyed?(cfg: Cfg, resource: LedgerResource, ledger: Ledger): Promise<DestroyOutcome>;
}

// --- ledger helpers (pure) ------------------------------------------------------------------

export function resourcesOfKind(ledger: Ledger, kind: string): LedgerResource[] {
  return ledger.resources.filter((r) => r.kind === kind && r.deleteState !== 'confirmed_gone');
}

export function firstResource(ledger: Ledger, kind: string): LedgerResource | undefined {
  return resourcesOfKind(ledger, kind)[0];
}

export function metaOf(r: LedgerResource | undefined): Record<string, unknown> {
  if (!r?.meta) return {};
  try {
    const parsed = JSON.parse(r.meta) as unknown;
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

/** Default destroy order: reverse creation order, live resources only. */
export function reverseLiveResources(ledger: Ledger): LedgerResource[] {
  return [...ledger.resources].reverse().filter((r) => r.deleteState !== 'confirmed_gone');
}

export function stepOf(ledger: Ledger, stepId: string): LedgerStep | undefined {
  return ledger.steps.find((s) => s.stepId === stepId);
}
