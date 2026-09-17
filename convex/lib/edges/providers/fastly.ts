'use node';
/**
 * Fastly L7 (CDN) edge adapter: one hostname fronted by one VCL service.
 *
 * Model. A provisioned edge is a service + a single `origin` backend + a
 * `ws-upgrade` VCL snippet + the fronted domain + the WebSockets product + an
 * activated version, then a TLS subscription whose ACME challenge and whose
 * traffic CNAME are written into a SEPARATE DNS account (the `DnsClient`, a
 * zone this operator owns elsewhere). Members only ever receive the hostname.
 *
 * Version discipline. Every version-scoped step targets exactly ONE draft
 * version, recorded in the `service` ledger resource's meta the moment step 1
 * settles (or the moment discovery adopts an existing service and picks its
 * highest unlocked, inactive version). Nothing is ever recomputed from live
 * settings: the hostname, the CA, the TLS configuration id and the origin
 * transport all come from `spec` (which the orchestrator fills from the edge's
 * frozen provisioning intent).
 *
 * Discovery. Every allocating step is discoverable by a deterministic name, so
 * a lost response is answered by a read, never by a second allocating call.
 *
 * Errors. Fastly's two error envelopes both carry free text that echoes request
 * values (`Domain <name> is already taken`), so ./fastly/sdk.ts reduces them to
 * an HTTP status plus a code from a fixed allowlist; `detail` is never read.
 * Nothing here adds a body, a URL or a credential to an error.
 *
 * WebSockets constraints that shape the model: for WS traffic a backend honours
 * only `name`, `address`, `use_ssl` and `override_host`, so the origin port is
 * fixed (443 with `use_ssl`, 80 without) and an https origin must present a
 * publicly trusted certificate. Those are plan-time refusals below.
 */
import { z } from 'zod';
import type {
  AdoptionInspection,
  ChildResource,
  CredentialTestResult,
  Discovery,
  DiscoverResult,
  EdgeDescription,
  EdgeProvider,
  EdgeReadiness,
  EdgeSpec,
  FastlyConfig,
  InspectResult,
  Inventory,
  InventoryLb,
  Ledger,
  LedgerResource,
  ReadinessState,
  ResourceStep,
  SharedTeardownDriver,
  SharedTeardownState as GenericSharedTeardownState,
  StepOutcome,
  CloudflareDnsConfig,
} from './types';
import { firstResource, metaOf, resourcesOfKind } from './types';
import { EdgeProviderError } from './http';
import { acmeChallengeName } from '../hostname';
import type { DnsClient, DnsRecord } from './dns/types';
import {
  fastlyApiFor,
  isFastlyNotFound,
  type FastlyApi,
  type FastlyBackendBody,
  type FastlyJsonApiCollection,
  type FastlyJsonApiResource,
  type FastlySnippetBody,
  type FastlyServiceDetail,
  type FastlyVersion,
} from './fastly/sdk';
import { FastlyTemplate, FASTLY_TEMPLATE_FIELDS, type FastlyTemplateParams } from './templates';

export { FastlyTemplate, FASTLY_TEMPLATE_FIELDS } from './templates';
export type { FastlyTemplateParams } from './templates';

/** The only VCL this adapter installs: hand an Upgrade request to the WebSocket path. */
export const FASTLY_WS_UPGRADE_VCL = 'if (req.http.Upgrade) { return(upgrade); }';
const BACKEND_NAME = 'origin';
const SNIPPET_NAME = 'ws-upgrade';
/** Bounds the admin-triggered inventory sweep (services are listed, then detailed). */
const INVENTORY_PAGE_SIZE = 100;
const INVENTORY_MAX_PAGES = 5;
const INVENTORY_MAX_DETAILED = 100;

// --- DNS client injection ----------------------------------------------------------

type DnsClientFactory = (cfg: CloudflareDnsConfig) => DnsClient | Promise<DnsClient>;
let dnsFactory: DnsClientFactory | null = null;
/** Test seam: an in-memory DnsClient, so these tests never load the Cloudflare SDK. */
export function __setFastlyDnsClientFactory(f: DnsClientFactory | null): void {
  dnsFactory = f;
}

/**
 * The DNS writer for this edge's records. The Cloudflare implementation is
 * imported lazily so the module graph of a Fastly-only test (and of the isolate
 * bundle) never pulls it in.
 */
async function dnsClientFor(cfg: FastlyConfig): Promise<DnsClient> {
  const dns = cfg.dns;
  if (!dns)
    throw refusal('dns', 'dns_account_missing', 'the referenced DNS account is not resolved');
  if (dnsFactory) return await dnsFactory(dns);
  const mod = await import('./dns/cloudflareDns');
  return mod.cloudflareDnsClient(dns);
}

// --- small helpers -----------------------------------------------------------------

function refusal(step: string, code: string, why: string): EdgeProviderError {
  return new EdgeProviderError(`fastly ${step}: ${why}`, {
    provider: 'fastly',
    step,
    code,
    retryable: false,
    timedOut: false,
  });
}

function ledgerIncomplete(step: string): EdgeProviderError {
  return refusal(step, 'ledger_incomplete', 'the ledger is missing a prerequisite resource');
}

/** The persisted service id + draft version every version-scoped call targets. */
function serviceOf(ledger: Ledger): {
  id: string;
  version: number;
  name?: string;
  shared: boolean;
} {
  const r = firstResource(ledger, 'service');
  if (!r) throw ledgerIncomplete('service');
  const meta = metaOf(r);
  const version = typeof meta.version === 'number' ? meta.version : Number(meta.version);
  if (!Number.isFinite(version)) throw ledgerIncomplete('service');
  return {
    id: r.resourceId,
    version,
    name: typeof meta.name === 'string' ? meta.name : undefined,
    shared: meta.shared === true,
  };
}

/** The fronted hostname as the LEDGER knows it (describe/destroy get no spec). */
export function fastlyHostnameOf(ledger: Ledger): string | undefined {
  const domain = firstResource(ledger, 'domain');
  if (domain) return domain.resourceId;
  const sub = firstResource(ledger, 'tls_subscription');
  const h = metaOf(sub).hostname;
  if (typeof h === 'string') return h;
  for (const r of resourcesOfKind(ledger, 'dns_record')) {
    const meta = metaOf(r);
    if (meta.role === 'traffic' && typeof meta.name === 'string') return meta.name;
  }
  return undefined;
}

function requireHostname(spec: EdgeSpec, step: string): string {
  if (!spec.hostname) throw refusal(step, 'hostname_missing', 'the spec carries no hostname');
  return spec.hostname;
}

function originMember(spec: EdgeSpec, step: string): { address: string; port: number } {
  const m = spec.listeners[0]?.members[0];
  if (!m) throw refusal(step, 'spec_invalid', 'the spec has no origin member');
  return m;
}

/**
 * The origin transport refusals the WebSockets data path forces. A backend used
 * for WS honours neither `port` nor certificate overrides, so the origin must
 * sit on the scheme's own port and, over TLS, present a publicly trusted
 * certificate.
 */
export function assertFastlyOriginTransport(spec: EdgeSpec, step = 'plan'): void {
  const t = spec.originTransport;
  if (!t) throw refusal(step, 'origin_transport_missing', 'the slot declares no origin transport');
  const { port } = originMember(spec, step);
  if (t.scheme === 'https') {
    if (!t.certPublic)
      throw refusal(
        step,
        'origin_cert_not_public',
        'an https origin behind this front needs a publicly trusted certificate',
      );
    if (port !== 443)
      throw refusal(step, 'origin_port_unsupported', 'an https origin must listen on 443');
  } else if (port !== 80) {
    throw refusal(step, 'origin_port_unsupported', 'an http origin must listen on 80');
  }
}

function activeVersionNumber(detail: FastlyServiceDetail): number | undefined {
  const av = detail.active_version;
  if (typeof av === 'number') return av;
  if (av && typeof av === 'object' && typeof av.number === 'number') return av.number;
  const fromList = detail.versions?.find((v) => v.active === true);
  return fromList?.number;
}

/** The highest unlocked, inactive version: the draft an adopted service is edited on. */
export function highestDraftVersion(versions: FastlyVersion[]): FastlyVersion | undefined {
  return versions
    .filter((v) => v.locked !== true && v.active !== true && v.deleted_at == null)
    .sort((a, b) => b.number - a.number)[0];
}

// --- wire bodies (pure, pinned by the wire-contract test) ---------------------------

export function fastlyBackendBody(spec: EdgeSpec, tpl: FastlyTemplateParams): FastlyBackendBody {
  const hostname = requireHostname(spec, 'backend');
  const { address } = originMember(spec, 'backend');
  assertFastlyOriginTransport(spec, 'backend');
  return {
    name: BACKEND_NAME,
    address,
    use_ssl: spec.originTransport?.scheme === 'https',
    // The Host the front sends the node: the minted hostname, or the origin
    // address when the node only answers to its own name.
    override_host: tpl.overrideHost === 'hostname' ? hostname : address,
    comment: spec.name,
  };
}

export function fastlySnippetBody(): FastlySnippetBody {
  return {
    name: SNIPPET_NAME,
    type: 'recv',
    content: FASTLY_WS_UPGRADE_VCL,
    // Late enough to run after the generated boilerplate, string-typed as the API wants.
    priority: '100',
    dynamic: '0',
  };
}

export function fastlyTlsSubscriptionBody(
  hostname: string,
  certificateAuthority: string,
  tlsConfigurationId?: string,
): Record<string, unknown> {
  const relationships: Record<string, unknown> = {
    tls_domains: { data: [{ type: 'tls_domain', id: hostname }] },
  };
  // Omitted entirely when the account names no configuration: Fastly then uses
  // its default one, and sending a null relationship is a 422.
  if (tlsConfigurationId)
    relationships.tls_configuration = {
      data: { type: 'tls_configuration', id: tlsConfigurationId },
    };
  return {
    data: {
      type: 'tls_subscription',
      attributes: { certificate_authority: certificateAuthority },
      relationships,
    },
  };
}

// --- response readers (pure) --------------------------------------------------------

export interface TlsChallenge {
  type: string;
  record_type?: string;
  record_name?: string;
  values: string[];
}

const ChallengeSchema = z.looseObject({
  type: z.string(),
  record_type: z.string().optional(),
  record_name: z.string().optional(),
  values: z.array(z.string()).optional(),
});

/** Every DNS challenge in a `?include=tls_authorizations` subscription document. */
export function parseTlsChallenges(doc: unknown): TlsChallenge[] {
  const included = (doc as { included?: unknown })?.included;
  if (!Array.isArray(included)) return [];
  const out: TlsChallenge[] = [];
  for (const entry of included) {
    const res = entry as FastlyJsonApiResource | undefined;
    if (!res || res.type !== 'tls_authorization') continue;
    const challenges = (res.attributes as { challenges?: unknown } | undefined)?.challenges;
    if (!Array.isArray(challenges)) continue;
    for (const c of challenges) {
      const parsed = ChallengeSchema.safeParse(c);
      if (parsed.success)
        out.push({
          type: parsed.data.type,
          record_type: parsed.data.record_type,
          record_name: parsed.data.record_name,
          values: parsed.data.values ?? [],
        });
    }
  }
  return out;
}

/** The managed-DNS challenge is the only one FCP can satisfy without operator action. */
export function managedDnsChallenge(doc: unknown): TlsChallenge | undefined {
  return parseTlsChallenges(doc).find(
    (c) => c.type === 'managed-dns' && !!c.record_name && c.values.length > 0,
  );
}

/**
 * `GET .../domain/{name}/check` answers a positional triple
 * `[domain, cname, ok]`; `check_all` wraps triples in an outer array.
 */
export function parseDomainCheck(res: unknown): { cname?: string; ok: boolean } {
  if (!Array.isArray(res)) return { ok: false };
  const triple = Array.isArray(res[0]) ? (res[0] as unknown[]) : res;
  return {
    cname: typeof triple[1] === 'string' ? triple[1] : undefined,
    ok: triple[2] === true,
  };
}

/**
 * The CNAME every fronted hostname points at, read from
 * `GET /tls/configurations?include=dns_records`: the chosen configuration (the
 * account's, else the default one), then its included CNAME `dns_record`, whose
 * TARGET is its own JSON:API `id`. Never hard-coded.
 */
export function parseTrafficCname(
  doc: FastlyJsonApiCollection,
  tlsConfigurationId?: string,
): string | undefined {
  const configs = doc.data.filter((c) => c.type === 'tls_configuration');
  const chosen = tlsConfigurationId
    ? configs.find((c) => c.id === tlsConfigurationId)
    : (configs.find((c) => (c.attributes as { default?: unknown } | undefined)?.default === true) ??
      configs[0]);
  if (!chosen) return undefined;
  const rel = (chosen.relationships as { dns_records?: { data?: unknown } } | undefined)
    ?.dns_records?.data;
  const wanted = new Set(
    Array.isArray(rel)
      ? rel
          .map((r) => (r as { id?: unknown }).id)
          .filter((id): id is string => typeof id === 'string')
      : [],
  );
  const records = (doc.included ?? []).filter(
    (r) =>
      r.type === 'dns_record' &&
      (r.attributes as { record_type?: unknown } | undefined)?.record_type === 'CNAME',
  );
  const hit = records.find((r) => wanted.size === 0 || wanted.has(r.id)) ?? records[0];
  return hit?.id;
}

/**
 * The domains one TLS subscription covers, from its `tls_domains` relationship
 * (each linkage's `id` IS the domain name). A subscription that covers more
 * than the hostname being imported is SHARED: deleting it would drop somebody
 * else's certificate, so the import records it as shared rather than owned.
 * Source: https://www.fastly.com/documentation/reference/api/tls/subscriptions/, 2026-09-16.
 */
export function subscriptionDomains(res: FastlyJsonApiResource): string[] {
  const data = (res.relationships as { tls_domains?: { data?: unknown } } | undefined)?.tls_domains
    ?.data;
  if (!Array.isArray(data)) return [];
  return data
    .map((d) => (d as { id?: unknown }).id)
    .filter((id): id is string => typeof id === 'string');
}

/** The certificate authority one TLS subscription was issued by. */
export function subscriptionCertificateAuthority(res: FastlyJsonApiResource): string | undefined {
  const ca = (res.attributes as { certificate_authority?: unknown } | undefined)
    ?.certificate_authority;
  return typeof ca === 'string' ? ca : undefined;
}

/** The TLS configuration one subscription is attached to (absent = Fastly's default). */
export function subscriptionConfigurationId(res: FastlyJsonApiResource): string | undefined {
  const data = (
    res.relationships as { tls_configuration?: { data?: { id?: unknown } } } | undefined
  )?.tls_configuration?.data;
  const id = data?.id;
  return typeof id === 'string' ? id : undefined;
}

/**
 * Whether a subscription the provider returned for a hostname is the one THIS
 * edge's frozen intent describes: same certificate authority, and, when the
 * intent names a TLS configuration, the same configuration. Adopting a
 * subscription that differs would hand the edge a certificate somebody else
 * pays for and renews, and a destroy would then delete theirs.
 */
export function subscriptionMatchesIntent(
  res: FastlyJsonApiResource,
  want: { certificateAuthority: string; tlsConfigurationId?: string },
): boolean {
  if (subscriptionCertificateAuthority(res) !== want.certificateAuthority) return false;
  if (!want.tlsConfigurationId) return true;
  return subscriptionConfigurationId(res) === want.tlsConfigurationId;
}

function subscriptionState(doc: unknown): string | undefined {
  const data = (doc as { data?: FastlyJsonApiResource })?.data;
  const state = (data?.attributes as { state?: unknown } | undefined)?.state;
  return typeof state === 'string' ? state : undefined;
}

function certificateReadiness(state: string | undefined): ReadinessState {
  switch (state) {
    case 'issued':
    case 'renewing':
      return 'ready';
    case 'pending':
    case 'processing':
      return 'pending';
    case 'failed':
      return 'failed';
    default:
      return 'unknown';
  }
}

// --- steps -------------------------------------------------------------------------

const STEP_IDS = {
  service: 'service',
  backend: 'backend',
  snippet: 'snippet',
  domain: 'domain',
  product: 'product',
  activate: 'activate',
  tls: 'tls',
  acme: 'acme',
  await: 'await-tls',
  dns: 'dns',
} as const;

function planSteps(spec: EdgeSpec): ResourceStep[] {
  const hostname = requireHostname(spec, 'plan');
  return [
    {
      id: STEP_IDS.service,
      kind: 'create_service',
      resourceName: spec.name,
      discoverability: 'by_name',
    },
    {
      id: STEP_IDS.backend,
      kind: 'create_backend',
      resourceName: BACKEND_NAME,
      discoverability: 'by_name',
    },
    {
      id: STEP_IDS.snippet,
      kind: 'create_snippet',
      resourceName: SNIPPET_NAME,
      discoverability: 'by_name',
    },
    {
      id: STEP_IDS.domain,
      kind: 'create_domain',
      resourceName: hostname,
      discoverability: 'by_name',
    },
    {
      id: STEP_IDS.product,
      kind: 'enable_product',
      resourceName: 'websockets',
      discoverability: 'by_name',
    },
    {
      id: STEP_IDS.activate,
      kind: 'activate_version',
      resourceName: spec.name,
      discoverability: 'by_name',
    },
    {
      id: STEP_IDS.tls,
      kind: 'create_tls_subscription',
      resourceName: hostname,
      discoverability: 'by_name',
    },
    {
      id: STEP_IDS.acme,
      kind: 'create_dns_acme',
      resourceName: acmeChallengeName(hostname),
      discoverability: 'by_name',
    },
    { id: STEP_IDS.await, kind: 'await_tls', resourceName: hostname, discoverability: 'by_name' },
    {
      id: STEP_IDS.dns,
      kind: 'create_dns_record',
      resourceName: hostname,
      discoverability: 'by_name',
    },
  ];
}

function dnsResource(role: 'acme' | 'traffic', record: DnsRecord, dns: DnsClient): ChildResource {
  return {
    kind: 'dns_record',
    resourceId: record.id,
    ownership: 'created',
    // Everything reconciliation needs WITHOUT re-reading the account's settings.
    meta: {
      dnsAccountId: dns.accountId,
      zoneId: dns.zoneId,
      recordId: record.id,
      name: record.name,
      role,
    },
  };
}

// --- shared teardown (adopted, non-exclusive services) ------------------------------

export type SharedTeardownPhase =
  | 'clone'
  | 'remove_domain'
  | 'validate'
  | 'activate'
  | 'confirm'
  | 'done'
  | 'needs_operator';

/**
 * The persisted state of a service-wide teardown: the edge only owns ONE domain
 * on a service somebody else also uses, so the service is never deleted. The
 * caller persists this between calls and advances it one step at a time.
 */
export interface SharedTeardownState {
  phase: SharedTeardownPhase;
  serviceId: string;
  hostname: string;
  /** The active version the work version was cloned from (the drift reference). */
  fromVersion: number;
  /** Deterministic clone marker, so a lost clone response is recognisable. */
  marker: string;
  /** Only versions created at or after this may be suspected of being our lost clone. */
  opWindowStart: number;
  workVersion?: number;
  code?: string;
}

/** `null` when the ledger describes an exclusively owned service (ordinary destroy). */
export function planSharedTeardown(
  ledger: Ledger,
  opId: string,
  now: number = Date.now(),
): SharedTeardownState | null {
  const svc = firstResource(ledger, 'service');
  if (!svc || metaOf(svc).shared !== true) return null;
  const meta = metaOf(svc);
  const hostname = fastlyHostnameOf(ledger);
  if (!hostname) return null;
  const active = typeof meta.activeVersion === 'number' ? meta.activeVersion : undefined;
  const version = typeof meta.version === 'number' ? meta.version : undefined;
  return {
    phase: 'clone',
    serviceId: svc.resourceId,
    hostname,
    fromVersion: active ?? version ?? 0,
    marker: `fcp:${typeof meta.name === 'string' ? meta.name : svc.resourceId}:${opId}`,
    opWindowStart: now,
  };
}

function needsOperator(state: SharedTeardownState, code: string): SharedTeardownState {
  return { ...state, phase: 'needs_operator', code };
}

/**
 * Advance a shared teardown by EXACTLY one provider interaction. Every phase is
 * re-entrant: a lost response is recognised by reading the service back, never
 * by repeating a mutation.
 */
export async function sharedTeardownStep(
  cfg: FastlyConfig,
  state: SharedTeardownState,
): Promise<SharedTeardownState> {
  const api = fastlyApiFor(cfg);
  switch (state.phase) {
    case 'clone': {
      const versions = await api.listServiceVersions(state.serviceId);
      const drafts = versions.filter((v) => v.locked !== true && v.active !== true);
      const marked = drafts.filter((v) => (v.comment ?? '') === state.marker);
      if (marked.length === 1)
        return { ...state, workVersion: marked[0].number, phase: 'remove_domain' };
      if (marked.length > 1) return needsOperator(state, 'shared_teardown_ambiguous');
      // An unmarked draft made inside our op window could be our own clone whose
      // marker never landed, or somebody else's work. Never guess: ask an operator.
      const suspects = drafts.filter((v) => {
        const at = v.created_at ? Date.parse(v.created_at) : NaN;
        return Number.isFinite(at) && at >= state.opWindowStart;
      });
      if (suspects.length > 0) return needsOperator(state, 'shared_teardown_ambiguous');
      const clone = await api.cloneServiceVersion(state.serviceId, state.fromVersion);
      await api.updateServiceVersion(state.serviceId, clone.number, { comment: state.marker });
      return { ...state, workVersion: clone.number, phase: 'remove_domain' };
    }
    case 'remove_domain': {
      if (state.workVersion === undefined) return { ...state, phase: 'clone' };
      try {
        await api.deleteDomain(state.serviceId, state.workVersion, state.hostname);
      } catch (e) {
        // Already removed (a lost delete response): the phase is satisfied.
        if (!isFastlyNotFound(e)) throw e;
      }
      return { ...state, phase: 'validate' };
    }
    case 'validate': {
      if (state.workVersion === undefined) return { ...state, phase: 'clone' };
      const res = await api.validateServiceVersion(state.serviceId, state.workVersion);
      if (res.status !== 'ok') return needsOperator(state, 'shared_teardown_invalid');
      return { ...state, phase: 'activate' };
    }
    case 'activate': {
      if (state.workVersion === undefined) return { ...state, phase: 'clone' };
      const detail = await api.getServiceDetail(state.serviceId);
      const active = activeVersionNumber(detail);
      // A lost activation response: the work version is already live.
      if (active === state.workVersion) return { ...state, phase: 'confirm' };
      // Somebody activated a different version while we were working; the FCP
      // lock cannot prevent that, so stop rather than overwrite their change.
      if (active !== state.fromVersion)
        throw refusal(
          'shared-teardown',
          'service_version_drift',
          'the active service version changed since the clone',
        );
      await api.activateServiceVersion(state.serviceId, state.workVersion);
      return { ...state, phase: 'confirm' };
    }
    case 'confirm': {
      if (state.workVersion === undefined) return { ...state, phase: 'clone' };
      const detail = await api.getServiceDetail(state.serviceId);
      if (activeVersionNumber(detail) !== state.workVersion) return { ...state, phase: 'activate' };
      const domains = await api.listDomains(state.serviceId, state.workVersion);
      if (domains.some((d) => d.name === state.hostname))
        return needsOperator(state, 'shared_teardown_incomplete');
      return { ...state, phase: 'done' };
    }
    default:
      return state;
  }
}

/** Every phase `sharedTeardownStep` understands; anything else parks the workflow. */
const SHARED_TEARDOWN_PHASES: readonly SharedTeardownPhase[] = [
  'clone',
  'remove_domain',
  'validate',
  'activate',
  'confirm',
  'done',
  'needs_operator',
];

/**
 * The persisted (generic) state as this adapter's own. The reconcile cron
 * round-trips the state through the database, so every field is re-read
 * defensively and an unknown phase becomes `needs_operator` rather than a
 * silent re-clone.
 */
function asFastlyTeardown(state: GenericSharedTeardownState): SharedTeardownState {
  const phase = SHARED_TEARDOWN_PHASES.includes(state.phase as SharedTeardownPhase)
    ? (state.phase as SharedTeardownPhase)
    : 'needs_operator';
  return {
    ...state,
    phase,
    serviceId: state.serviceId,
    hostname: typeof state.hostname === 'string' ? state.hostname : '',
    fromVersion: typeof state.fromVersion === 'number' ? state.fromVersion : 0,
    marker: typeof state.marker === 'string' ? state.marker : '',
    opWindowStart: typeof state.opWindowStart === 'number' ? state.opWindowStart : 0,
  };
}

/**
 * The generic driver the orchestrator holds: `plan` answers `null` for an
 * exclusively owned service (an ordinary destroy), and `step` advances exactly
 * one phase. The terminal phases are `done` and `needs_operator`; stepping a
 * finished teardown is a no-op that returns the state unchanged.
 */
export const fastlySharedTeardown: SharedTeardownDriver<FastlyConfig> = {
  plan(ledger, opId, now) {
    const state = planSharedTeardown(ledger, opId, now);
    return state === null ? null : { ...state };
  },
  async step(cfg, state) {
    if (state.phase === 'done') return state;
    return { ...(await sharedTeardownStep(cfg, asFastlyTeardown(state))) };
  },
};

// --- destroy ordering ---------------------------------------------------------------

/**
 * Destroy order by kind (DNS role included): traffic record first so no client
 * is sent to a front being dismantled, then the subscription (which needs its
 * ACME record until it is gone), then the ACME record, then the version is
 * deactivated, the service deleted, and the WebSockets product last.
 */
export const FASTLY_DESTROY_ORDER = [
  'dns_record:traffic',
  'tls_subscription',
  'dns_record:acme',
  'active_version',
  'service',
  'backend',
  'snippet',
  'domain',
  'ws_product',
] as const;

/** Kinds a shared (adopted, non-exclusive) service lets FCP delete. */
const SHARED_DESTROYABLE = new Set(['dns_record', 'domain']);

export function fastlyDestroyKey(r: LedgerResource): string {
  const role = metaOf(r).role;
  return typeof role === 'string' ? `${r.kind}:${role}` : r.kind;
}

function destroyRank(r: LedgerResource): number {
  const i = (FASTLY_DESTROY_ORDER as readonly string[]).indexOf(fastlyDestroyKey(r));
  return i === -1 ? FASTLY_DESTROY_ORDER.length : i;
}

// --- the adapter ---------------------------------------------------------------------

export const fastlyProvider: EdgeProvider<FastlyConfig, FastlyTemplateParams> = {
  id: 'fastly',
  templateSchema: FastlyTemplate,
  templateFields: FASTLY_TEMPLATE_FIELDS,
  defaultTemplate: FastlyTemplate.parse({}),

  async testCredentials(cfg): Promise<CredentialTestResult> {
    const api = fastlyApiFor(cfg);
    try {
      const token = await api.getTokenCurrent();
      const scopes = (token.scope ?? '').split(/[\s,]+/).filter(Boolean);
      if (!scopes.includes('global'))
        return { ok: false, code: 'token_scope', detail: 'the token needs the global scope' };
      let detail = `scope=${scopes.join(' ')}`;
      try {
        const customer = await api.getLoggedInCustomer();
        if (customer.pricing_plan) detail += `; pricing_plan=${customer.pricing_plan}`;
      } catch {
        // The customer read is informational; a token without it still works.
        detail += '; pricing_plan=unknown';
      }
      return { ok: true, detail };
    } catch (e) {
      return {
        ok: false,
        code:
          e instanceof EdgeProviderError
            ? (e.meta.code ?? String(e.meta.status ?? 'error'))
            : 'error',
      };
    }
  },

  /** The account form offers the TLS configurations this token can see. */
  async discoverOptions(partial): Promise<DiscoverResult> {
    const cfg = partial as FastlyConfig;
    if (!cfg.apiToken) return {};
    try {
      const doc = await fastlyApiFor(cfg).listTlsConfigurations();
      return {
        tlsConfigurations: doc.data
          .filter((c) => c.type === 'tls_configuration')
          .map((c) => {
            const attrs = c.attributes as { name?: unknown; default?: unknown } | undefined;
            const name = typeof attrs?.name === 'string' ? attrs.name : c.id;
            return { id: c.id, label: attrs?.default === true ? `${name} (default)` : name };
          }),
      };
    } catch (e) {
      return {
        errors: {
          tlsConfigurations:
            e instanceof EdgeProviderError
              ? (e.meta.code ?? String(e.meta.status ?? 'error'))
              : 'error',
        },
      };
    }
  },

  planProvision(_cfg, spec) {
    // Feasibility is decided before any provider call: an unsupported origin
    // never turns into a half-built service.
    assertFastlyOriginTransport(spec, 'plan');
    return planSteps(spec);
  },

  async runStep(cfg, step, spec, tpl, ledger): Promise<StepOutcome> {
    const api = fastlyApiFor(cfg);
    const hostname = requireHostname(spec, step.id);
    switch (step.kind) {
      case 'create_service': {
        const svc = await api.createService({
          name: spec.name,
          type: 'vcl',
          comment: tpl.serviceComment,
        });
        const version = highestDraftVersion(svc.versions ?? [])?.number ?? 1;
        return {
          status: 'done',
          resources: [
            {
              kind: 'service',
              resourceId: svc.id,
              ownership: 'created',
              meta: { version, name: svc.name ?? spec.name },
            },
          ],
        };
      }
      case 'create_backend': {
        const svc = serviceOf(ledger);
        const backend = await api.createBackend(svc.id, svc.version, fastlyBackendBody(spec, tpl));
        return {
          status: 'done',
          resources: [{ kind: 'backend', resourceId: backend.name, ownership: 'created' }],
        };
      }
      case 'create_snippet': {
        const svc = serviceOf(ledger);
        const snippet = await api.createSnippet(svc.id, svc.version, fastlySnippetBody());
        return {
          status: 'done',
          resources: [
            { kind: 'snippet', resourceId: snippet.id ?? snippet.name, ownership: 'created' },
          ],
        };
      }
      case 'create_domain': {
        const svc = serviceOf(ledger);
        const domain = await api.createDomain(svc.id, svc.version, {
          name: hostname,
          comment: spec.name,
        });
        return {
          status: 'done',
          resources: [{ kind: 'domain', resourceId: domain.name, ownership: 'created' }],
        };
      }
      case 'enable_product': {
        const svc = serviceOf(ledger);
        try {
          await api.enableWebsockets(svc.id);
        } catch (e) {
          // A 4xx here is an account entitlement problem, not a transient fault.
          if (e instanceof EdgeProviderError && e.meta.status && e.meta.status < 500)
            throw refusal(
              step.id,
              'websockets_not_entitled',
              'the account cannot enable the WebSockets product',
            );
          throw e;
        }
        return {
          status: 'done',
          resources: [{ kind: 'ws_product', resourceId: svc.id, ownership: 'created' }],
        };
      }
      case 'activate_version': {
        const svc = serviceOf(ledger);
        const validation = await api.validateServiceVersion(svc.id, svc.version);
        if (validation.status !== 'ok')
          return { status: 'partial', resources: [], code: 'version_invalid' };
        await api.activateServiceVersion(svc.id, svc.version);
        return {
          status: 'done',
          resources: [
            {
              kind: 'active_version',
              resourceId: String(svc.version),
              ownership: 'created',
              meta: { serviceId: svc.id, version: svc.version },
            },
          ],
        };
      }
      case 'create_tls_subscription': {
        const doc = await api.createTlsSubscription(
          fastlyTlsSubscriptionBody(hostname, cfg.certificateAuthority, cfg.tlsConfigurationId),
        );
        return {
          status: 'done',
          resources: [
            {
              kind: 'tls_subscription',
              resourceId: doc.data.id,
              ownership: 'created',
              meta: { hostname },
            },
          ],
        };
      }
      case 'create_dns_acme': {
        const sub = firstResource(ledger, 'tls_subscription');
        if (!sub) throw ledgerIncomplete(step.id);
        const doc = await api.getTlsSubscription(sub.resourceId, 'tls_authorizations');
        const challenge = managedDnsChallenge(doc);
        if (!challenge)
          // The authorization appears within seconds of the subscription; a
          // retryable refusal lets the orchestrator come back rather than
          // recording a half-done step.
          throw new EdgeProviderError('fastly acme: no managed-dns challenge yet', {
            provider: 'fastly',
            step: step.id,
            code: 'acme_challenge_pending',
            retryable: true,
            timedOut: false,
          });
        const dns = await dnsClientFor(cfg);
        const record = await dns.createRecord({
          type: 'CNAME',
          name: challenge.record_name ?? acmeChallengeName(hostname),
          content: challenge.values[0],
          proxied: false,
          comment: spec.name,
        });
        return { status: 'done', resources: [dnsResource('acme', record, dns)] };
      }
      case 'await_tls': {
        const sub = firstResource(ledger, 'tls_subscription');
        if (!sub) throw ledgerIncomplete(step.id);
        return { status: 'requested', opRef: sub.resourceId, resources: [] };
      }
      case 'create_dns_record': {
        const doc = await api.listTlsConfigurations('dns_records');
        const target = parseTrafficCname(doc, cfg.tlsConfigurationId);
        if (!target)
          throw refusal(step.id, 'tls_configuration_missing', 'no CNAME target could be read');
        const dns = await dnsClientFor(cfg);
        const record = await dns.createRecord({
          type: 'CNAME',
          name: hostname,
          content: target,
          proxied: false,
          comment: spec.name,
        });
        return {
          status: 'done',
          resources: [dnsResource('traffic', record, dns)],
          addresses: { hostname },
        };
      }
      default:
        throw refusal(step.id, 'unknown_step', `unknown step kind ${step.kind}`);
    }
  },

  /** Only `await_tls` is asynchronous: certificate issuance takes minutes. */
  async pollStep(cfg, step, opRef, ledger): Promise<StepOutcome> {
    if (step.kind !== 'await_tls') throw refusal(step.id, 'unknown_step', 'not a polled step');
    const doc = await fastlyApiFor(cfg).getTlsSubscription(opRef);
    const state = subscriptionState(doc);
    if (state === 'issued' || state === 'renewing') {
      const hostname = fastlyHostnameOf(ledger);
      return { status: 'done', resources: [], ...(hostname ? { addresses: { hostname } } : {}) };
    }
    // Fastly only marks a subscription `failed` after days, so a stalled
    // issuance is bounded by the rotation's own clock, not by this step.
    if (state === 'failed') return { status: 'partial', resources: [], code: 'tls_failed' };
    return { status: 'requested', opRef, resources: [] };
  },

  async discover(cfg, step, spec, ledger): Promise<Discovery> {
    const api = fastlyApiFor(cfg);
    const hostname = spec.hostname ?? fastlyHostnameOf(ledger);
    switch (step.kind) {
      case 'create_service': {
        let svc;
        try {
          svc = await api.searchService(spec.name);
        } catch (e) {
          if (isFastlyNotFound(e)) return { status: 'confirmed_absent' };
          throw e;
        }
        // The draft version is chosen ONCE here and persisted in meta; nothing
        // downstream recomputes it.
        const versions = svc.versions ?? (await api.listServiceVersions(svc.id));
        const draft = highestDraftVersion(versions);
        if (!draft)
          return {
            status: 'ambiguous',
            candidates: [{ kind: 'service', resourceId: svc.id, ownership: 'adopted' }],
          };
        return {
          status: 'found',
          resources: [
            {
              kind: 'service',
              resourceId: svc.id,
              ownership: 'adopted',
              meta: { version: draft.number, name: svc.name ?? spec.name },
            },
          ],
        };
      }
      case 'create_backend': {
        const svc = serviceOf(ledger);
        try {
          const backend = await api.getBackend(svc.id, svc.version, BACKEND_NAME);
          return {
            status: 'found',
            resources: [{ kind: 'backend', resourceId: backend.name, ownership: 'adopted' }],
          };
        } catch (e) {
          if (isFastlyNotFound(e)) return { status: 'confirmed_absent' };
          throw e;
        }
      }
      case 'create_snippet': {
        const svc = serviceOf(ledger);
        try {
          const snippet = await api.getSnippet(svc.id, svc.version, SNIPPET_NAME);
          return {
            status: 'found',
            resources: [{ kind: 'snippet', resourceId: snippet.name, ownership: 'adopted' }],
          };
        } catch (e) {
          if (isFastlyNotFound(e)) return { status: 'confirmed_absent' };
          throw e;
        }
      }
      case 'create_domain': {
        const svc = serviceOf(ledger);
        if (!hostname) return { status: 'confirmed_absent' };
        try {
          const domain = await api.getDomain(svc.id, svc.version, hostname);
          return {
            status: 'found',
            resources: [{ kind: 'domain', resourceId: domain.name, ownership: 'adopted' }],
          };
        } catch (e) {
          if (isFastlyNotFound(e)) return { status: 'confirmed_absent' };
          throw e;
        }
      }
      case 'enable_product': {
        const svc = serviceOf(ledger);
        try {
          await api.getWebsockets(svc.id);
          return {
            status: 'found',
            resources: [{ kind: 'ws_product', resourceId: svc.id, ownership: 'adopted' }],
          };
        } catch (e) {
          if (e instanceof EdgeProviderError && e.meta.status && e.meta.status < 500)
            return { status: 'confirmed_absent' };
          throw e;
        }
      }
      case 'activate_version': {
        const svc = serviceOf(ledger);
        const detail = await api.getServiceDetail(svc.id);
        return activeVersionNumber(detail) === svc.version
          ? {
              status: 'found',
              resources: [
                {
                  kind: 'active_version',
                  resourceId: String(svc.version),
                  ownership: 'adopted',
                  meta: { serviceId: svc.id, version: svc.version },
                },
              ],
            }
          : { status: 'confirmed_absent' };
      }
      case 'create_tls_subscription': {
        if (!hostname) return { status: 'confirmed_absent' };
        // Ownership is PROVEN, never assumed: the account may hold several
        // subscriptions covering this hostname (an operator's own, an older
        // one), and adopting whichever the API listed first would let a destroy
        // delete a certificate this edge never created. A subscription is this
        // step's only when it is the single one covering the hostname AND its
        // certificate authority (plus the TLS configuration, when the frozen
        // intent names one) is what this edge was planned with.
        const doc = await api.listTlsSubscriptionsForDomain(hostname);
        const wanted = hostname.trim().toLowerCase();
        const covering = doc.data.filter(
          (d) =>
            d.type === 'tls_subscription' &&
            subscriptionDomains(d).some((n) => n.trim().toLowerCase() === wanted),
        );
        if (covering.length === 0) return { status: 'confirmed_absent' };
        const candidates = covering.map((d) => ({
          kind: 'tls_subscription' as const,
          resourceId: d.id,
          ownership: 'adopted' as const,
          meta: { hostname },
        }));
        const want = {
          certificateAuthority: cfg.certificateAuthority,
          ...(cfg.tlsConfigurationId ? { tlsConfigurationId: cfg.tlsConfigurationId } : {}),
        };
        if (covering.length > 1 || !subscriptionMatchesIntent(covering[0]!, want))
          return { status: 'ambiguous', candidates };
        return { status: 'found', resources: candidates };
      }
      case 'create_dns_acme':
      case 'create_dns_record': {
        if (!hostname) return { status: 'confirmed_absent' };
        const role = step.kind === 'create_dns_acme' ? 'acme' : 'traffic';
        const name = role === 'acme' ? acmeChallengeName(hostname) : hostname;
        const dns = await dnsClientFor(cfg);
        const records = await dns.findRecordsByName(name, 'CNAME');
        if (records.length === 0) return { status: 'confirmed_absent' };
        // Ownership is the comment marker; a same-name record we did not write
        // is never adopted or deleted.
        const ours = records.filter((r) => r.comment === spec.name);
        if (ours.length === 0)
          return {
            status: 'ambiguous',
            candidates: records.map((r) => ({
              kind: 'dns_record',
              resourceId: r.id,
              ownership: 'adopted' as const,
            })),
          };
        return {
          status: 'found',
          resources: [{ ...dnsResource(role, ours[0], dns), ownership: 'adopted' }],
          ...(role === 'traffic' ? { addresses: { hostname } } : {}),
        };
      }
      case 'await_tls': {
        const sub = firstResource(ledger, 'tls_subscription');
        if (!sub) return { status: 'confirmed_absent' };
        const doc = await api.getTlsSubscription(sub.resourceId);
        const state = subscriptionState(doc);
        if (state === 'issued' || state === 'renewing')
          return {
            status: 'found',
            resources: [],
            ...(hostname ? { addresses: { hostname } } : {}),
          };
        return { status: 'unresolved' };
      }
      default:
        return { status: 'confirmed_absent' };
    }
  },

  async describe(cfg, ledger): Promise<EdgeDescription> {
    const svcRes = firstResource(ledger, 'service');
    if (!svcRes)
      return { state: 'pending', addresses: {}, health: 'unknown', code: 'no_service_yet' };
    const svc = serviceOf(ledger);
    const hostname = fastlyHostnameOf(ledger);
    const api = fastlyApiFor(cfg);
    let detail: FastlyServiceDetail;
    try {
      detail = await api.getServiceDetail(svc.id);
    } catch (e) {
      if (isFastlyNotFound(e)) return { state: 'gone', addresses: {}, health: 'unknown' };
      throw e;
    }
    if (detail.deleted_at) return { state: 'gone', addresses: {}, health: 'unknown' };

    const versionActive = activeVersionNumber(detail) === svc.version;
    const readiness: EdgeReadiness = { dns: 'unknown', certificate: 'unknown' };
    if (hostname) {
      try {
        const check = parseDomainCheck(await api.checkDomain(svc.id, svc.version, hostname));
        readiness.dns = check.ok ? 'ready' : 'pending';
      } catch (e) {
        // A domain check is not authoritative about the edge; a 404 means the
        // domain is not on this version yet.
        readiness.dns = isFastlyNotFound(e) ? 'pending' : 'unknown';
      }
    }
    const sub = firstResource(ledger, 'tls_subscription');
    let certState: string | undefined;
    if (sub) {
      try {
        certState = subscriptionState(await api.getTlsSubscription(sub.resourceId));
      } catch (e) {
        if (!isFastlyNotFound(e)) throw e;
      }
    }
    readiness.certificate = certificateReadiness(certState);

    const ready = readiness.dns === 'ready' && readiness.certificate === 'ready' && versionActive;
    const state: EdgeDescription['state'] =
      readiness.certificate === 'failed' ? 'error' : ready ? 'active' : 'pending';
    return {
      state,
      // The hostname is reported as soon as the ledger knows it; publishability
      // is decided by `state` + `readiness` + the front qualification, not by
      // withholding the address (dropping it would look like an address loss).
      addresses: hostname ? { hostname } : {},
      // DNS and certificate existence say nothing about the origin, so an L7
      // front never claims member health (capabilities: memberHealth false).
      health: 'unknown',
      ...(readiness.certificate === 'failed' ? { code: 'tls_failed' } : {}),
      readiness,
    };
  },

  async inspect(cfg, ledger): Promise<InspectResult> {
    const svc = serviceOf(ledger);
    const api = fastlyApiFor(cfg);
    const detail = await api.getServiceDetail(svc.id);
    const [domains, backends] = await Promise.all([
      api.listDomains(svc.id, svc.version).catch(() => []),
      api.listBackends(svc.id, svc.version).catch(() => []),
    ]);
    const sub = firstResource(ledger, 'tls_subscription');
    let subscription: { id: string; state?: string } | undefined;
    if (sub) {
      const doc = await api.getTlsSubscription(sub.resourceId).catch(() => undefined);
      subscription = { id: sub.resourceId, state: doc ? subscriptionState(doc) : undefined };
    }
    const hostname = fastlyHostnameOf(ledger);
    return {
      summary: {
        status: activeVersionNumber(detail) === svc.version ? 'active' : 'draft',
        addresses: hostname ? { hostname } : {},
        members: backends.map((b) => ({
          address: b.address ?? b.hostname ?? '',
          port: b.use_ssl ? 443 : 80,
        })),
        listeners: [{ port: 443, protocol: 'https' }],
      },
      // Service/domain/backend objects carry no credentials; the subscription is
      // reduced to its id and state rather than passed through whole.
      raw: { service: detail, domains, backends, subscription },
    };
  },

  async inventory(cfg): Promise<Inventory> {
    const api = fastlyApiFor(cfg);
    const services: Awaited<ReturnType<FastlyApi['listServices']>> = [];
    for (let page = 1; page <= INVENTORY_MAX_PAGES; page++) {
      const batch = await api.listServices(page, INVENTORY_PAGE_SIZE);
      services.push(...batch);
      if (batch.length < INVENTORY_PAGE_SIZE) break;
    }
    const loadBalancers: InventoryLb[] = [];
    for (const svc of services.slice(0, INVENTORY_MAX_DETAILED)) {
      const active = svc.versions?.find((v) => v.active === true)?.number;
      const domains = await api.listServiceDomains(svc.id).catch(() => []);
      const hostnames = domains.map((d) => d.name);
      // The origin a service currently fronts: the import ownership check needs
      // it, and it is one cheap read on the active version.
      let content: string | undefined;
      if (active !== undefined) {
        const backends = await api.listBackends(svc.id, active).catch(() => []);
        content = backends[0]?.address ?? backends[0]?.hostname ?? undefined;
      }
      loadBalancers.push({
        id: svc.id,
        name: svc.name ?? svc.id,
        status: active !== undefined ? 'active' : 'inactive',
        addresses: hostnames[0] ? { hostname: hostnames[0] } : {},
        hostnames,
        ...(content ? { content } : {}),
      });
    }
    return { loadBalancers, ips: [], flavors: [] };
  },

  /**
   * Import: describe an EXISTING service as the children FCP would have
   * created, with the ids, the version and the sharing facts a later destroy
   * needs. Everything is read from the ACTIVE version (the one serving
   * traffic); a service with no active version is refused rather than adopted
   * against a draft nobody published.
   *
   * `shared` is the ownership boundary: a service that serves other hostnames,
   * or a certificate that covers other domains, may never be deleted, only
   * narrowed (see `sharedTeardown`). The subscription is recorded only when
   * exactly ONE covers the hostname; zero (the operator terminates TLS
   * elsewhere) or several (ambiguous) leave it out, and the import owns no
   * certificate.
   */
  async inspectForAdoption(cfg, resourceId, hostname): Promise<AdoptionInspection> {
    const step = 'adopt';
    const api = fastlyApiFor(cfg);
    const wanted = hostname.trim().toLowerCase();
    const detail = await api.getServiceDetail(resourceId);
    const activeVersion = activeVersionNumber(detail);
    if (activeVersion === undefined)
      throw refusal(step, 'service_not_active', 'the service has no active version');
    const domains = await api.listDomains(resourceId, activeVersion);
    const hostnames = domains.map((d) => d.name);
    const mine = hostnames.find((n) => n.trim().toLowerCase() === wanted);
    if (mine === undefined)
      throw refusal(step, 'hostname_mismatch', 'the service does not serve that hostname');

    const backends = await api.listBackends(resourceId, activeVersion).catch(() => []);
    const content = backends[0]?.address ?? backends[0]?.hostname ?? undefined;

    const subs = await api.listTlsSubscriptionsForDomain(mine);
    const covering = subs.data.filter(
      (d) =>
        d.type === 'tls_subscription' &&
        subscriptionDomains(d).some((n) => n.trim().toLowerCase() === wanted),
    );
    const subscription = covering.length === 1 ? covering[0] : undefined;
    const subscriptionShared =
      subscription !== undefined &&
      subscriptionDomains(subscription).some((n) => n.trim().toLowerCase() !== wanted);
    const shared = domains.length > 1 || subscriptionShared;

    const resources: ChildResource[] = [
      {
        kind: 'service',
        resourceId,
        ownership: 'adopted',
        meta: {
          name: detail.name ?? resourceId,
          version: activeVersion,
          activeVersion,
          shared,
        },
      },
      { kind: 'domain', resourceId: mine, ownership: 'adopted' },
    ];
    if (subscription)
      resources.push({
        kind: 'tls_subscription',
        resourceId: subscription.id,
        ownership: 'adopted',
        meta: { hostname: mine, shared: subscriptionShared },
      });
    // The product is account-and-service wide: recorded when it is already on,
    // never enabled here (an import changes nothing at the provider).
    try {
      await api.getWebsockets(resourceId);
      resources.push({ kind: 'ws_product', resourceId, ownership: 'adopted' });
    } catch (e) {
      if (!(e instanceof EdgeProviderError) || (e.meta.status ?? 500) >= 500) throw e;
    }
    // The DNS records live in the referenced account's zone: the traffic CNAME
    // under the hostname itself and the ACME challenge beside it.
    const dns = await dnsClientFor(cfg);
    for (const [role, name] of [
      ['traffic', mine],
      ['acme', acmeChallengeName(mine)],
    ] as const) {
      const record = (await dns.findRecordsByName(name, 'CNAME'))[0];
      if (record) resources.push({ ...dnsResource(role, record, dns), ownership: 'adopted' });
    }

    return {
      resources,
      hostname: mine,
      hostnames,
      shared,
      ...(content ? { content } : {}),
    };
  },

  sharedTeardown: fastlySharedTeardown,

  /**
   * On a SHARED service FCP deletes only what it owns THERE. A TLS
   * subscription is not part of the service: one covering only the imported
   * hostname is this edge's alone (`meta.shared !== true`, recorded at import
   * time), so it stays in the plan and is deleted; leaving it out would keep
   * paying for, and renewing, a certificate for a hostname nobody serves.
   */
  planDestroy(_cfg, ledger) {
    const svc = firstResource(ledger, 'service');
    const shared = !!svc && metaOf(svc).shared === true;
    const live = ledger.resources.filter((r) => r.deleteState !== 'confirmed_gone');
    const owned = shared
      ? live.filter(
          (r) =>
            SHARED_DESTROYABLE.has(r.kind) ||
            (r.kind === 'tls_subscription' && metaOf(r).shared !== true),
        )
      : live;
    return [...owned]
      .reverse()
      .map((r, i) => ({ r, i }))
      .sort((a, b) => destroyRank(a.r) - destroyRank(b.r) || a.i - b.i)
      .map((x) => x.r);
  },

  async runDestroy(cfg, r, ledger) {
    const api = fastlyApiFor(cfg);
    const svc = firstResource(ledger, 'service');
    const shared = !!svc && metaOf(svc).shared === true;
    const serviceGone = !svc || svc.deleteState === 'confirmed_gone';
    try {
      switch (r.kind) {
        case 'dns_record': {
          const dns = await dnsClientFor(cfg);
          const meta = metaOf(r);
          await dns.deleteRecord(typeof meta.recordId === 'string' ? meta.recordId : r.resourceId);
          return { status: 'delete_requested' };
        }
        case 'tls_subscription': {
          // The SUBSCRIPTION's own sharing decides, not the service's: one that
          // covers other hostnames too would drop their certificate.
          if (metaOf(r).shared === true) return { status: 'confirmed_gone' };
          await api.deleteTlsSubscription(r.resourceId);
          return { status: 'delete_requested' };
        }
        case 'active_version': {
          if (shared || serviceGone) return { status: 'confirmed_gone' };
          const meta = metaOf(r);
          const version = typeof meta.version === 'number' ? meta.version : Number(r.resourceId);
          const detail = await api.getServiceDetail(svc.resourceId);
          if (activeVersionNumber(detail) !== version) return { status: 'confirmed_gone' };
          await api.deactivateServiceVersion(svc.resourceId, version);
          return { status: 'delete_requested' };
        }
        case 'service': {
          if (shared) return { status: 'confirmed_gone' };
          await api.deleteService(r.resourceId);
          return { status: 'delete_requested' };
        }
        case 'domain': {
          // A domain on an exclusively owned service dies with the service; on a
          // SHARED service it is removed by the persisted shared teardown (see
          // planSharedTeardown / sharedTeardownStep), which the caller drives.
          if (shared) return { status: 'unresolved' };
          if (serviceGone) return { status: 'confirmed_gone' };
          return { status: 'unresolved' };
        }
        case 'backend':
        case 'snippet':
          return serviceGone ? { status: 'confirmed_gone' } : { status: 'unresolved' };
        case 'ws_product': {
          // Last, and pointless once the service is gone (it went with it).
          if (shared || serviceGone) return { status: 'confirmed_gone' };
          await api.disableWebsockets(r.resourceId);
          return { status: 'delete_requested' };
        }
        default:
          return { status: 'unresolved' };
      }
    } catch (e) {
      if (isFastlyNotFound(e)) return { status: 'confirmed_gone' };
      throw e;
    }
  },

  async confirmDestroyed(cfg, r, ledger) {
    const api = fastlyApiFor(cfg);
    const svc = firstResource(ledger, 'service');
    try {
      switch (r.kind) {
        case 'dns_record': {
          const dns = await dnsClientFor(cfg);
          const meta = metaOf(r);
          const id = typeof meta.recordId === 'string' ? meta.recordId : r.resourceId;
          return (await dns.getRecord(id)) === null
            ? { status: 'confirmed_gone' }
            : { status: 'still_present' };
        }
        case 'tls_subscription': {
          const hostname = (metaOf(r).hostname as string | undefined) ?? fastlyHostnameOf(ledger);
          if (!hostname) return { status: 'unresolved' };
          const doc = await api.listTlsSubscriptionsForDomain(hostname);
          return doc.data.length === 0 ? { status: 'confirmed_gone' } : { status: 'still_present' };
        }
        case 'service': {
          const name = (metaOf(r).name as string | undefined) ?? r.resourceId;
          try {
            const found = await api.searchService(name);
            // A deleted service may stay readable for a while; `deleted_at` is
            // the authoritative answer when the row is still served.
            return found.deleted_at ? { status: 'confirmed_gone' } : { status: 'still_present' };
          } catch (e) {
            if (isFastlyNotFound(e)) return { status: 'confirmed_gone' };
            throw e;
          }
        }
        case 'active_version': {
          if (!svc || svc.deleteState === 'confirmed_gone') return { status: 'confirmed_gone' };
          const meta = metaOf(r);
          const version = typeof meta.version === 'number' ? meta.version : Number(r.resourceId);
          const detail = await api.getServiceDetail(svc.resourceId);
          return activeVersionNumber(detail) === version
            ? { status: 'still_present' }
            : { status: 'confirmed_gone' };
        }
        case 'ws_product': {
          await api.getWebsockets(r.resourceId);
          return { status: 'still_present' };
        }
        case 'domain': {
          if (!svc || svc.deleteState === 'confirmed_gone') return { status: 'confirmed_gone' };
          const target = serviceOf(ledger);
          await api.getDomain(target.id, target.version, r.resourceId);
          return { status: 'still_present' };
        }
        case 'backend': {
          if (!svc || svc.deleteState === 'confirmed_gone') return { status: 'confirmed_gone' };
          const target = serviceOf(ledger);
          await api.getBackend(target.id, target.version, r.resourceId);
          return { status: 'still_present' };
        }
        case 'snippet': {
          if (!svc || svc.deleteState === 'confirmed_gone') return { status: 'confirmed_gone' };
          const target = serviceOf(ledger);
          await api.getSnippet(target.id, target.version, SNIPPET_NAME);
          return { status: 'still_present' };
        }
        default:
          return { status: 'unresolved' };
      }
    } catch (e) {
      if (isFastlyNotFound(e)) return { status: 'confirmed_gone' };
      throw e;
    }
  },
};
