/**
 * The origin-edge PROVIDER contract: how FCP drives one cloud load-balancer API.
 *
 * Design rules (docs/edges.md):
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
import type { ProviderPlan } from '../pricing';

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
  /** The location's, else the API key's default project (observed); absent for an account-level call. */
  projectId?: string;
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
/** The Cloudflare DNS zone a Fastly edge writes its records into (the referenced DNS account, resolved). */
export interface CloudflareDnsConfig {
  apiToken: string;
  zoneId: string;
  zoneName: string;
  /** The edgeProviderAccounts id the credentials came from (recorded in DNS resource meta). */
  accountId: string;
}
export interface CloudflareConfig {
  type: 'cloudflare';
  apiToken: string;
  zoneId: string;
  zoneName: string;
  accountId?: string;
  /**
   * The account is set to DNS and fronting (`edgeProviderAccounts.frontsTraffic`):
   * a location check then also runs the checks a front needs (its certificate,
   * CAA, the zone's privacy settings). Absent = DNS only.
   */
  frontsTraffic?: boolean;
}
export interface FastlyConfig {
  type: 'fastly';
  apiToken: string;
  certificateAuthority: 'certainly' | 'lets-encrypt' | 'globalsign';
  tlsConfigurationId?: string;
  /**
   * One certificate per front hostname (absent, the older default) or the
   * account's one shared wildcard (`*.<zone>`). Frozen per edge in its intent.
   */
  certificateScope?: 'per_host' | 'wildcard';
  /**
   * How the edge's hostname is attached to its service: a versionless (Domain
   * Management) domain for every edge planned now, a version-scoped domain
   * (absent, `classic`) for one planned before. Frozen per edge; not a setting.
   */
  domainModel?: 'classic' | 'versionless';
  /** Present once the referenced DNS account is resolved (edgeProviderOps.loadAdapter). */
  dns?: CloudflareDnsConfig;
}
export interface CloudFrontConfig {
  type: 'cloudfront';
  /** The IAM access key's public id (a settings identifier, rotates with the secret). */
  accessKeyId: string;
  secretAccessKey: string;
  /**
   * Always `wildcard`: every front of the account in one zone serves the
   * zone's one ACM certificate (`*.<zone>`). A certificate option so the
   * intent freezes it like Fastly's, which the shared-certificate locks and
   * watch read.
   */
  certificateScope?: 'wildcard';
  /** Present once the referenced DNS account is resolved (edgeProviderOps.loadAdapter). */
  dns?: CloudflareDnsConfig;
}
export type EdgeProviderConfig =
  | GcoreConfig
  | UpcloudConfig
  | ScalewayConfig
  | OvhConfig
  | CloudflareConfig
  | FastlyConfig
  | CloudFrontConfig;

// --- what to build -----------------------------------------------------------------

export interface EdgeListenerSpec {
  /** Client-facing port on the edge. */
  edgePort: number;
  /** Origin members the listener forwards to (v1: exactly one). */
  members: Array<{ address: string; port: number }>;
  /** Absent = tcp. Adapters forward TCP; a udp listener is refused unless the capability says otherwise. */
  transport?: 'tcp' | 'udp';
}

/** How the node is reached behind an L7 front (the slot's declaration, see lib/edges/layers.ts). */
export interface OriginTransportSpec {
  scheme: 'http' | 'https';
  certPublic: boolean;
  certNames: string[];
  acceptsHostHeader: 'any' | 'names';
}

export interface EdgeSpec {
  /** Provider-side resource name == edges.name; the discovery key. */
  name: string;
  listeners: EdgeListenerSpec[];
  /** L7 only: the fronted hostname (minted by lib/edges/hostname.ts, frozen in the intent). */
  hostname?: string;
  /** L7 only: what the front dials. */
  originTransport?: OriginTransportSpec;
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
  | 'attach_ip'
  // L7 (CDN) kinds
  | 'create_dns_record'
  | 'create_origin_rule'
  | 'create_header_rule'
  | 'create_service'
  | 'create_snippet'
  | 'create_domain'
  | 'enable_product'
  | 'activate_version'
  | 'create_tls_subscription'
  | 'create_dns_acme'
  | 'await_tls';

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
  /** L7: the fronted hostname (the only address members receive). */
  hostname?: string;
}

export type ReadinessState = 'ready' | 'pending' | 'failed' | 'unknown';
/** L7 readiness dimensions; `front` is filled by the front qualification, not the adapter. */
export interface EdgeReadiness {
  dns: ReadinessState;
  certificate: ReadinessState;
}

export type StepOutcome =
  /** The call completed; every child it created is listed. */
  | { status: 'done'; resources: ChildResource[]; addresses?: Addresses }
  /**
   * The call failed after creating some children (all listed). `refused`: the
   * provider answered and refused what FCP built (a configuration that does
   * not compile), so the same call would be refused again; the run stops on
   * `code` at once and keeps what was built for the operator to read.
   * `detail`: the provider's own words on the refusal (`redactErrorDetail`d);
   * the ops layer scrubs the edge's names from it before it leaves the action.
   */
  | {
      status: 'partial';
      resources: ChildResource[];
      code?: string;
      refused?: true;
      detail?: string;
    }
  /**
   * Async provider: an operation/task to poll; children known so far listed.
   * `code`: what the wait is held up by, when the provider says (a code from a
   * fixed list, `L7_CERTIFICATE_CODES`; never the provider's own words).
   */
  | { status: 'requested'; opRef: string; resources: ChildResource[]; code?: string };

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
  /** L7 adapters: DNS and certificate readiness (state is `active` only when both are ready). */
  readiness?: EdgeReadiness;
}

/**
 * What saving an edge's configuration again did (`EdgeProvider.reapply`).
 * `sent`: the same configuration went out again (`settled`: the provider had
 * finished applying it when the call returned). `skipped`: nothing was sent,
 * and `code` says why (`lb_busy`: still applying an earlier change;
 * `lb_unusable`: in a state it does not leave by itself; `no_frontend`: the
 * ledger holds nothing to save again).
 */
export type ReapplyOutcome =
  | { status: 'sent'; settled: boolean }
  | { status: 'skipped'; code: 'lb_busy' | 'lb_unusable' | 'no_frontend' };

export type DestroyOutcome =
  | { status: 'delete_requested'; opRef?: string }
  | { status: 'confirmed_gone' }
  /** Read back and still deleting (or the answer cannot prove either way): keep confirming. */
  | { status: 'unresolved' }
  /**
   * Read back and NOT deleting (e.g. an LB still `ready`): the delete never
   * landed. The orchestrator re-issues `runDestroy` instead of waiting.
   */
  | { status: 'still_present' };

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
  /** L7: what the front dials (a DNS record's content, a service backend's address). */
  content?: string;
  /** L7: every hostname the resource serves (the import ownership boundary). */
  hostnames?: string[];
}
export interface InventoryIp {
  id: string;
  address: string;
  attachedTo?: string | null;
}
export interface Inventory {
  loadBalancers: InventoryLb[];
  ips: InventoryIp[];
  /**
   * `multicloud`: the provider says the size takes a backend server outside
   * its own cloud (Scaleway `LbType.multicloud`; lib/edges/sizeCheck.ts).
   */
  flavors: Array<{ id: string; label: string; multicloud?: boolean }>;
}

// --- templates ---------------------------------------------------------------------------

export type { OptionField, OptionType } from './options';
/** The template fields are provider options (`./options`); the old names stay for the adapters. */
export type TemplateFieldType = import('./options').OptionType;
export type TemplateFieldDescriptor = import('./options').OptionField;

export interface CredentialTestResult {
  ok: boolean;
  code?: string;
  detail?: string;
  /**
   * Facts the test observed at the provider that the account keeps (stored as
   * `observedSettings`). A place's own facts (a zone's encryption mode) come
   * from `checkLocation`, never from the credential test.
   */
  observed?: Record<string, string>;
}

/** What checking one location found (`EdgeProvider.checkLocation`). */
export interface LocationCheckResult {
  ok: boolean;
  /** A short code when the location cannot be used (`zone_ssl_off`, `zone_unreadable`...). */
  code?: string;
  detail?: string;
  /**
   * Facts planning needs that the operator never enters (a zone's encryption
   * mode, WebSockets): stored on the location as `observed` and frozen into
   * each new edge's intent.
   */
  observed?: Record<string, string>;
  /** The place's readable name as the provider lists it (a zone name). */
  label?: string;
  /** A CDN place's zone name as the provider reads it (a location picked by zone id alone takes it). */
  zoneName?: string;
}

/**
 * What an L7 adapter learns about an EXISTING provider resource an operator
 * wants to import: the ledger children FCP should record (with the real ids,
 * versions and metadata discovery needs), the hostname it serves, whether the
 * resource also serves other hostnames (`shared` = FCP may delete only its own
 * children), and what it dials (must equal the origin's origin to be owned).
 */
export interface AdoptionInspection {
  resources: ChildResource[];
  hostname: string;
  hostnames: string[];
  shared: boolean;
  content?: string;
}

/**
 * A shared external resource cannot simply be deleted: removing one hostname
 * from it is a multi-step, persisted workflow (Fastly: clone → remove domain →
 * validate → activate → confirm). Adapters that own such a resource expose the
 * driver; the reconcile cron persists the state on the edge and advances ONE
 * phase per pass under an external lock. Terminal phases: `done`,
 * `needs_operator`.
 */
export interface SharedTeardownState {
  phase: string;
  serviceId: string;
  workVersion?: number;
  code?: string;
  [key: string]: unknown;
}
export interface SharedTeardownDriver<Cfg> {
  /** `null` when the ledger describes an exclusively owned resource (ordinary destroy). */
  plan(ledger: Ledger, opId: string, now?: number): SharedTeardownState | null;
  step(cfg: Cfg, state: SharedTeardownState): Promise<SharedTeardownState>;
}

/**
 * An account-wide certificate several edges share (Fastly's wildcard), as the
 * provider sees it now. `state` is the provider's (`pending`, `processing`,
 * `issued`, `renewing`, `failed`), or `absent` (none ordered yet) / `ambiguous`
 * (several, or one ordered differently, which no edge will reuse).
 */
export interface SharedCertificateStatus {
  name: string;
  subscriptionId?: string;
  state: string;
  /** What it waits on or why it failed (`L7_CERTIFICATE_CODES`). */
  code?: string;
  /** When the current certificate expires (ISO), when the provider says. */
  notAfter?: string;
}

export interface DiscoverOption {
  id: string;
  label: string;
  /** Short facts the pickers show next to the choice (a zone's status). */
  facts?: Record<string, string>;
}
/** Choice lists for the account form; a missing key = not applicable or not yet discoverable. */
export interface DiscoverResult {
  projects?: DiscoverOption[];
  regions?: DiscoverOption[];
  networks?: Array<DiscoverOption & { subnets: DiscoverOption[] }>;
  /** Load balancer flavors of the chosen region (a location's regional template value). */
  flavors?: DiscoverOption[];
  /** L7: DNS zones (Cloudflare) / TLS configurations (Fastly). */
  zones?: DiscoverOption[];
  tlsConfigurations?: DiscoverOption[];
  /** Lists that stopped at their cap (more exist than are listed). */
  truncated?: string[];
  /** Per-list failure codes: the form shows the field as free text instead. */
  errors?: Record<string, string>;
  /** Per failed list, the provider's redacted answer (`EdgeProviderError.meta.detail`). */
  errorDetails?: Record<string, string>;
}

// --- the adapter -----------------------------------------------------------------------------

export interface EdgeProvider<
  Cfg extends EdgeProviderConfig = EdgeProviderConfig,
  Tpl = Record<string, unknown>,
> {
  id: EdgeProviderId;
  /** Validates + defaults a template's params (the CMS + provisioning both use it). */
  templateSchema: z.ZodType<Tpl>;
  templateFields: TemplateFieldDescriptor[];
  defaultTemplate: Tpl;

  testCredentials(cfg: Cfg): Promise<CredentialTestResult>;
  /**
   * Whether the certificate options on `cfg` can be issued at all (a CDN
   * front's CAA preflight at the zone on `cfg`), for a node that chose other
   * certificate options than the ones the location's check covered. Absent =
   * nothing to check.
   */
  certificatePreflight?(
    cfg: Cfg,
  ): Promise<{ ok: true } | { ok: false; code: string; detail?: string }>;
  listRegions?(cfg: Cfg): Promise<Array<{ id: string; label: string }>>;
  /**
   * What the account form can offer as choices, given the credentials and any
   * settings chosen so far (a PARTIAL config: adapters return only the lists
   * their inputs allow, e.g. OVH regions need the project first). Never throws
   * for a missing dependency; a failing call surfaces as `errors`.
   */
  discoverOptions?(partial: Partial<Cfg> & Record<string, unknown>): Promise<DiscoverResult>;
  /**
   * L7 adapters: check ONE location with the account's credentials (`cfg`
   * carries the location's placement, and a Fastly front's resolved DNS
   * account): whether new edges can be created there, the facts planning
   * freezes from it and its readable name. Never throws for a refusal the
   * provider answered; an unreachable provider throws. A location of an L4
   * provider is read through `inventory` instead.
   */
  checkLocation?(cfg: Cfg): Promise<LocationCheckResult>;

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
   *  repeated absence to `confirmed_absent` where they document it as safe.
   *  Adapters that also need wall-clock settling read the step's `startedAt`
   *  from `ledger.steps` (stamped when the step was first requested) and
   *  compare it with `EdgeProviderCapabilities.discoverySettleMs`. */
  discover(
    cfg: Cfg,
    step: ResourceStep,
    spec: EdgeSpec,
    ledger: Ledger,
    attempt: number,
  ): Promise<Discovery>;

  describe(cfg: Cfg, ledger: Ledger): Promise<EdgeDescription>;
  /**
   * Save the edge's configuration again, unchanged, for a provider that can
   * accept a change and never apply it (Scaleway: a frontend created while
   * its load balancer was still applying the previous change). A guided run
   * offers it once when its outside check finds a new address unreachable.
   * Never creates or deletes anything. Absent = nothing to save again.
   */
  reapply?(cfg: Cfg, ledger: Ledger): Promise<ReapplyOutcome>;
  inspect(cfg: Cfg, ledger: Ledger): Promise<InspectResult>;
  inventory(cfg: Cfg): Promise<Inventory>;
  /**
   * Load balancer adapters: every size offered at the location on `cfg`, with
   * its list price, traffic terms and what it accepts (lib/edges/pricing.ts),
   * from the provider's own price list where it has one, else a dated table.
   * A read; never creates anything. A CDN adapter has none (never priced).
   */
  plans?(cfg: Cfg): Promise<ProviderPlan[]>;
  /**
   * L7 adapters: inspect an existing resource for import (real ids, versions,
   * every hostname it serves, what it dials). The import records exactly these
   * children; discovery never depends on a generated name for an adopted edge.
   */
  inspectForAdoption?(cfg: Cfg, resourceId: string, hostname: string): Promise<AdoptionInspection>;
  /** Adapters whose adopted edges can sit on a shared resource (see SharedTeardownDriver). */
  sharedTeardown?: SharedTeardownDriver<Cfg>;
  /**
   * Adapters whose edges can share one account-wide certificate: its state now
   * (null when the account does not use one). A read; never orders anything.
   */
  sharedCertificate?(
    cfg: Cfg,
    /** What edges of the account ordered (`orderedSharedResources`): theirs to name, whatever its authority. */
    opts?: { ordered?: readonly string[] },
  ): Promise<SharedCertificateStatus | null>;
  /**
   * Delete that shared certificate and the records FCP wrote for it (the
   * caller refuses while a live edge uses it). `code` names why nothing was
   * removed (a certificate the account would not have ordered is not its own).
   */
  removeSharedCertificate?(
    cfg: Cfg,
    opts: { ordered: readonly string[] },
  ): Promise<{ removed: boolean; code?: string }>;

  /**
   * Ledger resources in destroy order, skipping gone ones. Ordered by KIND
   * (what the provider's attach semantics require: the LB before the IP it
   * holds, before the gateway/network), never by ledger position — describe()
   * appends adopted children after the LB.
   */
  planDestroy(cfg: Cfg, ledger: Ledger): LedgerResource[];
  runDestroy(cfg: Cfg, resource: LedgerResource, ledger: Ledger): Promise<DestroyOutcome>;
  /**
   * Async-delete providers: read the resource back after `delete_requested`
   * (404 → `confirmed_gone`, present and deleting → `unresolved`, present and
   * NOT deleting → `still_present`). An unknown resource kind is `unresolved`
   * (never assumed gone). Providers WITHOUT this method delete synchronously;
   * the dispatcher re-runs their idempotent `runDestroy` to confirm instead of
   * assuming the delete landed.
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

/**
 * Destroy order by KIND: live resources sorted by their kind's position in
 * `order` (ties keep reverse ledger order). Kinds not in `order` come LAST, so
 * the adapter's `runDestroy` answers `unresolved` for them only after every
 * known child is gone.
 */
export function orderByKind(ledger: Ledger, order: readonly string[]): LedgerResource[] {
  const rank = (r: LedgerResource) => {
    const i = order.indexOf(r.kind);
    return i === -1 ? order.length : i;
  };
  return reverseLiveResources(ledger)
    .map((r, i) => ({ r, i }))
    .sort((a, b) => rank(a.r) - rank(b.r) || a.i - b.i)
    .map((x) => x.r);
}

export function stepOf(ledger: Ledger, stepId: string): LedgerStep | undefined {
  return ledger.steps.find((s) => s.stepId === stepId);
}
