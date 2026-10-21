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
 * WebSockets constraints that shape the model: Fastly's WebSockets guide lists
 * only `name`, `address`, `use_ssl` and `override_host` as the settings it
 * supports, and an https origin must present a publicly trusted certificate.
 * But the backend's `port` IS used, and defaults to 80 whatever `use_ssl` says
 * (found on a beta walk: the front spoke TLS to the origin's port 80). So FCP
 * keeps the origin on the scheme's own port (443 over TLS, 80 without, refused
 * at plan time otherwise) and always SENDS that port, with the origin's TLS
 * name for SNI and verification, instead of relying on any default.
 *
 * Domains. A new edge's hostname is a VERSIONLESS domain (Domain Management):
 * its own resource, linked to the service by id, created and deleted without a
 * service version. An edge planned before that (`domainModel: 'classic'`, the
 * intent's absence) keeps its version-scoped domain, which dies with the
 * service. Which one an edge has is read from the ledger (`versionless_domain`
 * vs `domain`) everywhere except the step that creates it.
 *
 * Certificates. `certificateScope: 'per_host'` orders one subscription per
 * front hostname (and deletes it with the edge). `'wildcard'` reuses ONE
 * subscription for `*.<zone>` per account: the step finds it by name or orders
 * it once, records it as `shared` (never deleted by an edge's destroy), and the
 * wait finishes at once when it is already issued. Its ACME record lives at
 * `_acme-challenge.<zone>` with a marker naming the subscription, and is
 * shared the same way.
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
  LocationCheckResult,
  ReadinessState,
  ResourceStep,
  SharedCertificateStatus,
  SharedTeardownDriver,
  SharedTeardownState as GenericSharedTeardownState,
  StepOutcome,
  CloudflareDnsConfig,
} from './types';
import { firstResource, metaOf, resourcesOfKind, stepOf } from './types';
import { EdgeProviderError, credentialTestFailure, noteDiscoverError } from './http';
import { acmeChallengeName, normalizeZoneName } from '../hostname';
import { addressFamily } from '../ip';
import { certCovers } from '../layers';
import {
  caaProbeName,
  checkCaa,
  wildcardBase,
  wildcardNameFor,
  type CaaLookup,
  type CaaRecord,
} from '../caa';
import type { L7CertificateCode } from '../../../../src/shared/contracts/edgeCodes';
import type { DnsClient, DnsCreateArgs, DnsRecord } from './dns/types';
import {
  fastlyApiFor,
  isFastlyNotFound,
  type FastlyApi,
  type FastlyBackendBody,
  type FastlyDomain,
  type FastlyJsonApiCollection,
  type FastlyJsonApiResource,
  type FastlySnippetBody,
  type FastlyServiceDetail,
  type FastlyVersion,
  type FastlyVersionlessDomain,
} from './fastly/sdk';
import {
  EDGE_TEMPLATES,
  FastlyTemplate,
  FASTLY_TEMPLATE_FIELDS,
  type FastlyTemplateParams,
} from './templates';
import { wireBody } from './options';

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

// --- CAA lookups (the credential test's issuance preflight) ---------------------------

let caaLookupOverride: CaaLookup | null = null;
/** Test seam: answer CAA lookups from a table (the offline suite refuses real DNS). */
export function __setFastlyCaaLookup(f: CaaLookup | null): void {
  caaLookupOverride = f;
}

/** A lookup is a few round trips; a resolver that cannot answer in this is `unchecked`. */
const CAA_TIMEOUT_MS = 4_000;

/**
 * CAA as public resolvers answer it, which is what the certificate authority
 * reads: no record (no data, or a name that does not exist) is `[]` so the walk
 * climbs; anything else that fails is thrown, and the verdict is `unchecked`.
 */
async function dnsCaaLookup(name: string): Promise<CaaRecord[]> {
  const { Resolver } = await import('node:dns/promises');
  const resolver = new Resolver({ timeout: CAA_TIMEOUT_MS, tries: 2 });
  try {
    const rows = (await resolver.resolveCaa(name)) as unknown as Array<Record<string, unknown>>;
    return rows.map((r) => {
      // Node names the property after its tag (`{ critical: 0, issue: 'x' }`).
      const tag = Object.keys(r).find((k) => k !== 'critical') ?? '';
      const value = r[tag];
      return {
        flags: typeof r.critical === 'number' ? r.critical : 0,
        tag,
        value: typeof value === 'string' ? value : '',
      };
    });
  } catch (e) {
    const code = (e as { code?: unknown }).code;
    if (code === 'ENODATA' || code === 'ENOTFOUND') return [];
    throw e;
  }
}

function caaLookup(): CaaLookup {
  return caaLookupOverride ?? dnsCaaLookup;
}

// --- per-edge choices (frozen in the intent; absent = how older edges were built) ----

/** `wildcard` = the account's one shared subscription; absent = one per front hostname. */
function certificateScopeOf(cfg: FastlyConfig): 'per_host' | 'wildcard' {
  return cfg.certificateScope === 'wildcard' ? 'wildcard' : 'per_host';
}

/** `versionless` = a Domain Management domain; absent = a version-scoped (classic) domain. */
function domainModelOf(cfg: FastlyConfig): 'classic' | 'versionless' {
  return cfg.domainModel === 'versionless' ? 'versionless' : 'classic';
}

/**
 * The DNS zone this account's fronts live in, as the resolved config carries it
 * (`edgeProviderOps.loadAdapter` fills `cfg.dns` from the frozen intent of an
 * existing edge, or from the account when planning). The ONE place the adapter
 * reads the zone outside a front's own hostname; undefined without a DNS account.
 */
export function fastlyZoneOf(cfg: FastlyConfig): string | undefined {
  return cfg.dns?.zoneName ? normalizeZoneName(cfg.dns.zoneName) : undefined;
}

/** The name the edge's certificate is ordered for: its hostname, or the zone's wildcard. */
function certificateNameOf(cfg: FastlyConfig, hostname: string): string {
  return certificateScopeOf(cfg) === 'wildcard' ? wildcardNameFor(hostname) : hostname;
}

/**
 * The ownership marker of the shared wildcard's ACME record: the Fastly
 * customer and the subscription it answers for. A record at the challenge
 * name with another customer's marker (a second FCP deployment or account on
 * the same zone) or none at all is never taken for ours, never replaced and
 * never deleted; one with OUR customer and a subscription that no longer
 * exists is our own stale record, replaced when the wildcard is ordered again.
 */
export function sharedAcmeMarker(customerId: string, subscriptionId: string): string {
  return `fcp-cert:${customerId}:${subscriptionId}`;
}

/** The customer and subscription a shared ACME record's comment names (null: not a marker). */
export function parseSharedAcmeMarker(
  comment: string | undefined,
): { customerId: string; subscriptionId: string } | null {
  const m = /^fcp-cert:([^:\s]+):([^:\s]+)$/.exec(comment ?? '');
  return m ? { customerId: m[1]!, subscriptionId: m[2]! } : null;
}

/**
 * A resource discovery saw but cannot prove is this edge's (a record at our
 * name with a foreign marker, a subscription ordered differently, a domain on
 * another service). It is recorded so an operator can see it, and it is never
 * planned for destroy or deleted: removing somebody else's certificate record
 * could stop their certificate from renewing.
 */
function candidateOf(r: ChildResource): ChildResource {
  return { ...r, ownership: 'adopted', meta: { ...(r.meta ?? {}), candidate: true } };
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
  const versionless = firstResource(ledger, 'versionless_domain');
  const fqdn = metaOf(versionless).fqdn;
  if (typeof fqdn === 'string') return fqdn;
  const domain = firstResource(ledger, 'domain');
  if (domain) return domain.resourceId;
  const sub = firstResource(ledger, 'tls_subscription');
  const h = metaOf(sub).hostname;
  // A shared subscription is ordered for the zone's wildcard, never for the front.
  if (typeof h === 'string' && !h.startsWith('*.')) return h;
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
 * The origin transport refusals the WebSockets data path forces: the origin
 * sits on the scheme's own port (the one place every Fastly setting agrees on)
 * and, over TLS, presents a publicly trusted certificate.
 */
export function assertFastlyOriginTransport(spec: EdgeSpec, step = 'plan'): void {
  const t = spec.originTransport;
  if (!t) throw refusal(step, 'origin_transport_missing', 'the slot declares no origin transport');
  const { address, port } = originMember(spec, step);
  if (t.scheme === 'https') {
    if (!t.certPublic)
      throw refusal(
        step,
        'origin_cert_not_public',
        'an https origin behind this front needs a publicly trusted certificate',
      );
    // The WebSocket path honours no TLS-name override: the front presents and
    // verifies the backend's own address, so that address must be a name the
    // origin's certificate covers.
    if (addressFamily(address) !== null || !certCovers(address, t.certNames))
      throw refusal(
        step,
        'origin_cert_name_uncovered',
        'an https origin behind this front must be addressed by a name its certificate covers',
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

/** The record options the template chose for the front's records (the traffic name may be flattened). */
export function dnsRecordOptions(
  tpl: Pick<FastlyTemplateParams, 'dnsTtl' | 'dnsTags' | 'dnsFlatten'>,
  traffic: boolean,
): Pick<DnsCreateArgs, 'ttl' | 'tags' | 'settings'> {
  const tags = Object.entries(tpl.dnsTags ?? {}).map(([k, v]) => `${k}:${v}`);
  return {
    ...(tpl.dnsTtl !== undefined ? { ttl: tpl.dnsTtl } : {}),
    ...(tags.length > 0 ? { tags } : {}),
    ...(traffic && tpl.dnsFlatten ? { settings: { flatten_cname: true } } : {}),
  };
}

/**
 * The name the front presents (SNI) and verifies the origin's certificate
 * against: the origin address itself (plan time refuses an https origin whose
 * address is not a name its certificate covers, since the WebSocket path
 * honours no override). Sent explicitly anyway, so a plain HTTP request
 * through the same backend agrees. None for a plaintext origin.
 */
export function fastlyOriginTlsName(spec: EdgeSpec): string | undefined {
  if (spec.originTransport?.scheme !== 'https') return undefined;
  const { address } = originMember(spec, 'backend');
  return address.toLowerCase().replace(/\.$/, '');
}

export function fastlyBackendBody(spec: EdgeSpec, tpl: FastlyTemplateParams): FastlyBackendBody {
  const hostname = requireHostname(spec, 'backend');
  const { address, port } = originMember(spec, 'backend');
  assertFastlyOriginTransport(spec, 'backend');
  const tlsName = fastlyOriginTlsName(spec);
  return {
    name: BACKEND_NAME,
    address,
    // Sent explicitly: Fastly defaults a backend's port to 80 even with
    // `use_ssl`, and the WebSocket path dials it (443 / 80, checked above).
    port,
    use_ssl: spec.originTransport?.scheme === 'https',
    ...(tlsName ? { ssl_cert_hostname: tlsName, ssl_sni_hostname: tlsName } : {}),
    // The Host the front sends the node: the minted hostname, or the origin
    // address when the node only answers to its own name.
    override_host: tpl.overrideHost === 'hostname' ? hostname : address,
    comment: spec.name,
    // The options the template (or the node) chose; nothing unset is sent.
    ...(wireBody(EDGE_TEMPLATES.fastly.fields, 'backend', tpl) as Partial<FastlyBackendBody>),
  };
}

/**
 * The request headers that can carry the member's address to the node, by
 * name: one more is one line here, and every snippet below removes it.
 *
 * Fastly's own: it sets `Fastly-Client-IP` and adds the address to
 * `X-Forwarded-For` on the incoming request, before any VCL runs (its header
 * reference, re-read 2026-10-21); `Fastly-Temp-XFF` is a name its generated
 * VCL has kept its copy of that chain under. `Fastly-WAF-Client-IP` is in none
 * of Fastly's documentation, yet a capture on a node showed it, with the
 * member's address, on every WebSocket request through a front built without
 * it here. The rest are only ever what a client (or a proxy on its side) sent,
 * removed so no client can pass an address on either. Never a protected header
 * (`Fastly-FF`, which names Fastly's own servers): VCL touching one fails to
 * compile, and the version would not activate.
 */
export const FASTLY_CLIENT_ADDRESS_HEADERS = [
  'Fastly-Client-IP',
  'X-Forwarded-For',
  'Fastly-Temp-XFF',
  'Fastly-WAF-Client-IP',
  'True-Client-IP',
  'X-Real-IP',
  'Forwarded',
  'X-Client-IP',
  'Client-IP',
  'X-Cluster-Client-IP',
] as const;

const unsetAll = (obj: 'req' | 'bereq') =>
  FASTLY_CLIENT_ADDRESS_HEADERS.map((h) => `unset ${obj}.http.${h};`).join(' ');

/**
 * The upgrade snippet of a front whose node must not see the member's
 * address (the default): every such header goes in `vcl_recv`, on EVERY
 * request, before the WebSocket handoff. `return(upgrade)` ends VCL there, so
 * no later VCL can put one back on the upgrade path. A header Fastly's
 * WebSocket path adds AFTER the handoff (it adds `CDN-Loop: Fanout`) is beyond
 * any VCL: only a capture on the node shows that none of these is one.
 */
export const FASTLY_WS_UPGRADE_VCL_NO_CLIENT_ADDRESS = `${unsetAll('req')} if (req.http.Upgrade) { return(upgrade); }`;

/**
 * What a request that is NOT handed off (a plain HTTP request through the same
 * backend) sends the node: removed again from the backend request, in
 * `vcl_miss` and `vcl_pass`, the two places it is built.
 */
export const FASTLY_NO_CLIENT_ADDRESS_BEREQ_VCL = unsetAll('bereq');

const STRIP_SNIPPET_NAMES = {
  miss: 'client-address-miss',
  pass: 'client-address-pass',
} as const;

export function fastlySnippetBody(
  tpl?: Pick<FastlyTemplateParams, 'forwardClientAddress'>,
): FastlySnippetBody {
  return {
    name: SNIPPET_NAME,
    type: 'recv',
    // Off unless the node's options pass it on (`forwardClientAddress`).
    content:
      tpl?.forwardClientAddress === true
        ? FASTLY_WS_UPGRADE_VCL
        : FASTLY_WS_UPGRADE_VCL_NO_CLIENT_ADDRESS,
    // Late enough to run after the generated boilerplate, string-typed as the API wants.
    priority: '100',
    dynamic: '0',
  };
}

/**
 * Every snippet a front's service version gets, the upgrade snippet LAST: a
 * front that keeps the member's address from its node also strips it from the
 * backend request (`vcl_miss`, `vcl_pass`). Discovery keys on the upgrade
 * snippet, so finding it means the ones before it were made too.
 */
export function fastlySnippetBodies(
  tpl?: Pick<FastlyTemplateParams, 'forwardClientAddress'>,
): FastlySnippetBody[] {
  const strip: FastlySnippetBody[] =
    tpl?.forwardClientAddress === true
      ? []
      : (['miss', 'pass'] as const).map((type) => ({
          name: STRIP_SNIPPET_NAMES[type],
          type,
          content: FASTLY_NO_CLIENT_ADDRESS_BEREQ_VCL,
          priority: '100',
          dynamic: '0',
        }));
  return [...strip, fastlySnippetBody(tpl)];
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
  defaultConfigurationId?: string,
): boolean {
  if (subscriptionCertificateAuthority(res) !== want.certificateAuthority) return false;
  // The EFFECTIVE configuration on both sides: an intent that names none gets
  // the account's default one (and so does the traffic CNAME), and a
  // subscription without the relationship is on the default one too.
  const effective = want.tlsConfigurationId ?? defaultConfigurationId;
  if (effective === undefined) return true;
  return (subscriptionConfigurationId(res) ?? defaultConfigurationId) === effective;
}

/** The account's default TLS configuration (what an intent that names none fronts through). */
export function defaultConfigurationIdOf(doc: FastlyJsonApiCollection): string | undefined {
  const configs = doc.data.filter((c) => c.type === 'tls_configuration');
  return (
    configs.find((c) => (c.attributes as { default?: unknown } | undefined)?.default === true) ??
    configs[0]
  )?.id;
}

/** The subscriptions of a listing that cover exactly `name` (a hostname or a wildcard). */
function coveringSubscriptions(
  doc: FastlyJsonApiCollection,
  name: string,
): FastlyJsonApiResource[] {
  const wanted = name.trim().toLowerCase();
  return doc.data.filter(
    (d) =>
      d.type === 'tls_subscription' &&
      subscriptionDomains(d).some((n) => n.trim().toLowerCase() === wanted),
  );
}

function intentOfCfg(cfg: FastlyConfig): {
  certificateAuthority: string;
  tlsConfigurationId?: string;
} {
  return {
    certificateAuthority: cfg.certificateAuthority,
    ...(cfg.tlsConfigurationId ? { tlsConfigurationId: cfg.tlsConfigurationId } : {}),
  };
}

/**
 * The account's one wildcard subscription for `name`: `found` when exactly one
 * covers it and it was ordered the way this edge's intent orders (CA and TLS
 * configuration), `absent` when none does, `ambiguous` otherwise (several, or
 * one ordered differently: another CA's certificate is not ours to reuse).
 */
async function sharedSubscriptionOf(
  api: FastlyApi,
  name: string,
  cfg: FastlyConfig,
): Promise<
  | { status: 'found'; resource: FastlyJsonApiResource }
  | { status: 'absent' }
  | { status: 'ambiguous'; candidates: FastlyJsonApiResource[] }
> {
  const covering = coveringSubscriptions(await api.listTlsSubscriptionsForDomain(name), name);
  if (covering.length === 0) return { status: 'absent' };
  if (covering.length > 1) return { status: 'ambiguous', candidates: covering };
  const defaultId = defaultConfigurationIdOf(await api.listTlsConfigurations());
  if (!subscriptionMatchesIntent(covering[0]!, intentOfCfg(cfg), defaultId))
    return { status: 'ambiguous', candidates: covering };
  return { status: 'found', resource: covering[0]! };
}

/** The sole covering subscription when an edge of this account ordered it, else null. */
function orderedCandidate(
  candidates: FastlyJsonApiResource[],
  ordered: readonly string[] | undefined,
): FastlyJsonApiResource | null {
  if (candidates.length !== 1 || !ordered) return null;
  const only = candidates[0]!;
  return ordered.includes(`tls_subscription:${only.id}`) ? only : null;
}

function sharedSubscriptionResource(
  id: string,
  name: string,
  ownership: 'created' | 'adopted',
): ChildResource {
  return {
    kind: 'tls_subscription',
    resourceId: id,
    ownership,
    // `shared`: no edge's destroy ever deletes it (the account's other fronts use it).
    meta: { hostname: name, shared: true, wildcard: true },
  };
}

// --- what a waiting issuance reports -------------------------------------------------

/**
 * A shared certificate this close to expiry (or past it) is raised even when the
 * provider names no reason: its renewal is late. Certainly's 30-day
 * certificates renew with about ten days left, so a week left means the renewal
 * is days overdue, never a renewal that is merely due.
 */
export const CERTIFICATE_EXPIRY_WARN_MS = 7 * 24 * 60 * 60_000;

/** Unnamed warnings are reported only once issuance has waited this long (Certainly issues in minutes). */
export const TLS_WARNING_GRACE_MS = 5 * 60_000;

const AUTHORIZATION_FAILED_STATES = new Set(['failed', 'invalid', 'revoked', 'expired', 'error']);

/**
 * What the authorizations of a `?include=tls_authorizations` document say is
 * holding the certificate up, as a code from a fixed list (most specific
 * first). Fastly's warnings are `{ type, instructions }` with no documented
 * vocabulary, and `instructions` is free text that names the records, so it
 * is never read: only the TYPE is matched, by keyword, and only the code
 * leaves this function. An unrecognised warning is reported only when
 * `generic` is set (the caller decides when a wait is long enough for one).
 * Shape: go-fastly `TLSAuthorizations` / `TLSAuthorizationWarning`, read 2026-10-20.
 */
export function tlsAuthorizationCode(
  doc: unknown,
  opts: { generic?: boolean } = {},
): L7CertificateCode | undefined {
  const included = (doc as { included?: unknown })?.included;
  if (!Array.isArray(included)) return undefined;
  const found = new Set<L7CertificateCode>();
  for (const entry of included) {
    const res = entry as FastlyJsonApiResource | undefined;
    if (!res || res.type !== 'tls_authorization') continue;
    const attrs = (res.attributes ?? {}) as { state?: unknown; warnings?: unknown };
    if (typeof attrs.state === 'string' && AUTHORIZATION_FAILED_STATES.has(attrs.state))
      found.add('tls_authorization_failed');
    if (!Array.isArray(attrs.warnings)) continue;
    for (const w of attrs.warnings) {
      const type = (w as { type?: unknown } | null)?.type;
      const slug = typeof type === 'string' ? type.toLowerCase().replace(/[^a-z0-9]+/g, '_') : '';
      if (/caa/.test(slug)) found.add('tls_caa_conflict');
      else if (/conflict|duplicate|multiple|existing/.test(slug))
        found.add('tls_challenge_conflict');
      else found.add('tls_authorization_warning');
    }
  }
  for (const code of [
    'tls_caa_conflict',
    'tls_challenge_conflict',
    'tls_authorization_failed',
  ] as const)
    if (found.has(code)) return code;
  return opts.generic && found.has('tls_authorization_warning')
    ? 'tls_authorization_warning'
    : undefined;
}

const sameDnsName = (a: string, b: string) =>
  a.trim().toLowerCase().replace(/\.$/, '') === b.trim().toLowerCase().replace(/\.$/, '');

/**
 * FCP's own look at the validation record while a certificate waits: the
 * managed-DNS challenge names a record and the value it must hold, and the
 * zone either has that CNAME or it does not (`tls_challenge_missing`).
 */
async function challengeRecordProblem(
  cfg: FastlyConfig,
  doc: unknown,
): Promise<L7CertificateCode | undefined> {
  if (!cfg.dns) return undefined;
  const challenge = managedDnsChallenge(doc);
  if (!challenge?.record_name) return undefined;
  let records: DnsRecord[];
  try {
    const dns = await dnsClientFor(cfg);
    records = await dns.findRecordsByName(
      challenge.record_name.toLowerCase().replace(/\.$/, ''),
      'CNAME',
    );
  } catch {
    // The look is advisory: a DNS API that does not answer says nothing about
    // the record, and must not turn a plain wait into an unknown outcome.
    return undefined;
  }
  return records.some((r) => sameDnsName(r.content, challenge.values[0]!))
    ? undefined
    : 'tls_challenge_missing';
}

/**
 * The outcome of one look at a subscription the edge waits on: issued (or
 * renewing, a valid certificate) finishes the step; failed is partial; else
 * the step stays requested with what it waits on, when that is known.
 */
async function awaitOutcome(
  cfg: FastlyConfig,
  step: ResourceStep,
  opRef: string,
  ledger: Ledger,
  now: number = Date.now(),
): Promise<StepOutcome> {
  const doc = await fastlyApiFor(cfg).getTlsSubscription(
    opRef,
    'tls_authorizations,tls_certificates',
  );
  const state = subscriptionState(doc);
  // Issued (or renewing) AND a certificate still valid: Fastly keeps a
  // subscription `renewing` for days past the old certificate's expiry
  // before it fails, and an expired certificate fronts nobody.
  if (subscriptionServes(doc, now)) {
    const hostname = fastlyHostnameOf(ledger);
    return { status: 'done', resources: [], ...(hostname ? { addresses: { hostname } } : {}) };
  }
  // Fastly only marks a subscription `failed` after days, so a stalled
  // issuance is bounded by the rotation's own clock, not by this step.
  if (state === 'failed') return { status: 'partial', resources: [], code: 'tls_failed' };
  const startedAt = stepOf(ledger, step.id)?.startedAt;
  const longWait = startedAt !== undefined && now - startedAt >= TLS_WARNING_GRACE_MS;
  const code =
    tlsAuthorizationCode(doc, { generic: longWait }) ??
    (await challengeRecordProblem(cfg, doc)) ??
    (state === 'issued' || state === 'renewing' ? 'certificate_expiring' : undefined);
  return { status: 'requested', opRef, resources: [], ...(code ? { code } : {}) };
}

/**
 * Whether a subscription document (with `tls_certificates` included) serves a
 * certificate now: issued or renewing, and its latest certificate not past its
 * `not_after`. A document without certificates is judged by its state alone.
 */
export function subscriptionServes(doc: unknown, now: number = Date.now()): boolean {
  const state = subscriptionState(doc);
  if (state !== 'issued' && state !== 'renewing') return false;
  const notAfter = latestNotAfter(doc);
  return notAfter === undefined || Date.parse(notAfter) > now;
}

/** The latest `not_after` of the certificates a `?include=tls_certificates` document carries. */
function latestNotAfter(doc: unknown): string | undefined {
  const included = (doc as { included?: unknown })?.included;
  if (!Array.isArray(included)) return undefined;
  let best: number | undefined;
  for (const entry of included) {
    const res = entry as FastlyJsonApiResource | undefined;
    if (!res || res.type !== 'tls_certificate') continue;
    const raw = (res.attributes as { not_after?: unknown } | undefined)?.not_after;
    const at = typeof raw === 'string' ? Date.parse(raw) : NaN;
    if (Number.isFinite(at) && (best === undefined || at > best)) best = at;
  }
  return best === undefined ? undefined : new Date(best).toISOString();
}

/**
 * The CAA preflight of a front location's check: whether the DNS account's zone
 * lets the account's CA issue what this account orders (the zone's wildcard,
 * or one name under it: the walk then starts at the zone, since a front's own
 * label holds no records before FCP writes it). Recorded as observed facts
 * either way; a refusal only when records exist and none allows the CA.
 */
async function caaPreflight(cfg: FastlyConfig): Promise<
  | {
      observed: Record<string, string>;
      refusal?: { ok: false; code: L7CertificateCode; detail: string };
    }
  | undefined
> {
  const zone = fastlyZoneOf(cfg);
  if (!zone) return undefined;
  const wildcard = certificateScopeOf(cfg) === 'wildcard';
  // One front's name: a label under the zone that nothing serves, so a zone
  // wildcard (CNAME or CAA) answers for it as it would for a new front.
  const v = await checkCaa({
    name: wildcard ? `*.${zone}` : caaProbeName(zone),
    certificateAuthority: cfg.certificateAuthority,
    lookup: caaLookup(),
  });
  const observed: Record<string, string> = {
    caa: v.verdict,
    caaIssuer: v.issuer,
    caaCertificate: wildcard ? 'wildcard' : 'per_host',
    ...(v.decidedAt ? { caaAt: v.decidedAt } : {}),
  };
  if (v.verdict !== 'forbids') return { observed };
  return {
    observed,
    refusal: {
      ok: false,
      code: 'caa_forbids_ca',
      detail: `the CAA records at ${v.decidedAt} do not allow ${v.issuer}${wildcard ? ' for a wildcard (issuewild)' : ''}`,
    },
  };
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

function planSteps(cfg: FastlyConfig, spec: EdgeSpec): ResourceStep[] {
  const hostname = requireHostname(spec, 'plan');
  // The certificate steps name what they act on: the front, or the zone's wildcard.
  const certName = certificateNameOf(cfg, hostname);
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
      resourceName: certName,
      discoverability: 'by_name',
    },
    {
      id: STEP_IDS.acme,
      kind: 'create_dns_acme',
      resourceName: acmeChallengeName(wildcardBase(certName)),
      discoverability: 'by_name',
    },
    { id: STEP_IDS.await, kind: 'await_tls', resourceName: certName, discoverability: 'by_name' },
    {
      id: STEP_IDS.dns,
      kind: 'create_dns_record',
      resourceName: hostname,
      discoverability: 'by_name',
    },
  ];
}

function dnsResource(
  role: 'acme' | 'traffic',
  record: DnsRecord,
  dns: DnsClient,
  shared = false,
): ChildResource {
  return {
    kind: 'dns_record',
    resourceId: record.id,
    ownership: 'created',
    // Everything reconciliation needs WITHOUT re-reading the account's settings.
    // `shared`: the wildcard's ACME record, which every front of the account
    // renews through; no edge's destroy deletes it.
    meta: {
      dnsAccountId: dns.accountId,
      zoneId: dns.zoneId,
      recordId: record.id,
      name: record.name,
      role,
      ...(shared ? { shared: true } : {}),
    },
  };
}

/** A versionless domain as the ledger records it (`resourceId` = the domain's own id). */
function versionlessResource(
  d: FastlyVersionlessDomain,
  ownership: 'created' | 'adopted',
): ChildResource {
  return {
    kind: 'versionless_domain',
    resourceId: d.id,
    ownership,
    meta: { fqdn: d.fqdn, serviceId: d.service_id ?? null },
  };
}

/**
 * The ACME step of a WILDCARD edge, shared by the step and its discovery: the
 * record at `_acme-challenge.<zone>` carrying this customer's marker for this
 * subscription is ours (found). Our own marker for a subscription that no
 * longer exists is stale: absent, and the step replaces it. Anything else
 * there (another customer's marker, no marker, our marker for a subscription
 * that still exists) is somebody else's: ambiguous, recorded as candidates
 * that are never deleted.
 */
async function sharedAcmeRecord(
  cfg: FastlyConfig,
  api: FastlyApi,
  ledger: Ledger,
  hostname: string,
): Promise<
  | { status: 'found'; resource: ChildResource }
  | { status: 'absent'; marker: string; stale: DnsRecord[]; dns: DnsClient }
  | { status: 'ambiguous'; candidates: ChildResource[] }
> {
  const sub = firstResource(ledger, 'tls_subscription');
  if (!sub) throw ledgerIncomplete('acme');
  const customerId = (await api.getLoggedInCustomer()).id;
  if (!customerId)
    throw refusal('acme', 'customer_unknown', 'the provider did not name the customer');
  const name = acmeChallengeName(wildcardBase(wildcardNameFor(hostname)));
  const marker = sharedAcmeMarker(customerId, sub.resourceId);
  const dns = await dnsClientFor(cfg);
  const records = await dns.findRecordsByName(name, 'CNAME');
  const ours = records.find((r) => r.comment === marker);
  const stale: DnsRecord[] = [];
  if (ours) {
    // Ours, but is it still what the provider validates with? A record edited
    // by hand, or a challenge the provider moved for a renewal, is replaced
    // like a stale one; with no challenge on offer there is nothing to check.
    const challenge = managedDnsChallenge(
      await api.getTlsSubscription(sub.resourceId, 'tls_authorizations'),
    );
    if (!challenge || sameDnsName(ours.content, challenge.values[0]!))
      return {
        status: 'found',
        resource: { ...dnsResource('acme', ours, dns, true), ownership: 'adopted' },
      };
    stale.push(ours);
  }
  const foreign: DnsRecord[] = [];
  for (const r of records) {
    if (r === ours) continue;
    const m = parseSharedAcmeMarker(r.comment);
    if (!m || m.customerId !== customerId) {
      foreign.push(r);
      continue;
    }
    // Our own marker: stale only once its subscription is gone for good.
    let gone = false;
    try {
      await api.getTlsSubscription(m.subscriptionId);
    } catch (e) {
      if (!isFastlyNotFound(e)) throw e;
      gone = true;
    }
    (gone ? stale : foreign).push(r);
  }
  if (foreign.length > 0)
    return {
      status: 'ambiguous',
      candidates: foreign.map((r) => candidateOf(dnsResource('acme', r, dns, true))),
    };
  return { status: 'absent', marker, stale, dns };
}

/** Every domain a service serves: its version's classic domains and its versionless ones. */
async function serviceHostnames(
  api: FastlyApi,
  serviceId: string,
  version: number | undefined,
): Promise<{ classic: FastlyDomain[]; versionless: FastlyVersionlessDomain[] }> {
  const [classic, versionless] = await Promise.all([
    version === undefined ? Promise.resolve([]) : api.listDomains(serviceId, version),
    // An account the listing does not exist for has no versionless domains.
    api.listVersionlessDomainsOfService(serviceId).catch((e: unknown) => {
      if (isFastlyNotFound(e)) return [] as FastlyVersionlessDomain[];
      throw e;
    }),
  ]);
  return { classic, versionless };
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
  // A versionless domain is no part of the service's versions: removing it is
  // ONE delete the ordinary walk issues, with no version to clone or activate.
  if (firstResource(ledger, 'versionless_domain')) return null;
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
 * ACME record until it is gone), then the ACME record, then a versionless
 * domain (its own resource, so it does not go with the service, and only once
 * its certificate is gone), then the version is deactivated, the service
 * deleted, and the WebSockets product last. A shared certificate and its ACME
 * record keep their places but are left in place (`runDestroy`).
 */
export const FASTLY_DESTROY_ORDER = [
  'dns_record:traffic',
  'tls_subscription',
  'dns_record:acme',
  'versionless_domain',
  'active_version',
  'service',
  'backend',
  'snippet',
  'domain',
  'ws_product',
] as const;

/** Kinds a shared (adopted, non-exclusive) service lets FCP delete. */
const SHARED_DESTROYABLE = new Set(['dns_record', 'domain', 'versionless_domain']);

export function fastlyDestroyKey(r: LedgerResource): string {
  const role = metaOf(r).role;
  return typeof role === 'string' ? `${r.kind}:${role}` : r.kind;
}

function destroyRank(r: LedgerResource): number {
  const i = (FASTLY_DESTROY_ORDER as readonly string[]).indexOf(fastlyDestroyKey(r));
  return i === -1 ? FASTLY_DESTROY_ORDER.length : i;
}

/**
 * DNS readiness of a versionless domain. There is no version to run a domain
 * check on: the front is ready when the domain is still linked to the edge's
 * service and its traffic name points at the provider, which FCP knows from
 * the traffic record it wrote (or, for an import whose record lives
 * elsewhere, from the provider's own `activated` flag).
 */
async function versionlessDnsReadiness(
  api: FastlyApi,
  cfg: FastlyConfig,
  domain: LedgerResource,
  serviceId: string,
  ledger: Ledger,
): Promise<ReadinessState> {
  let d: FastlyVersionlessDomain;
  try {
    d = await api.getVersionlessDomain(domain.resourceId);
  } catch (e) {
    return isFastlyNotFound(e) ? 'pending' : 'unknown';
  }
  if (d.service_id !== serviceId) return 'pending';
  const traffic = resourcesOfKind(ledger, 'dns_record').find(
    (r) => metaOf(r).role === 'traffic' && metaOf(r).candidate !== true,
  );
  if (!traffic) return d.activated === true ? 'ready' : 'pending';
  // The record as the zone holds it NOW: still there, and still pointing at
  // the CNAME target of the TLS configuration the front uses.
  try {
    const meta = metaOf(traffic);
    const record = await (
      await dnsClientFor(cfg)
    ).getRecord(typeof meta.recordId === 'string' ? meta.recordId : traffic.resourceId);
    if (!record) return 'pending';
    const target = parseTrafficCname(
      await api.listTlsConfigurations('dns_records'),
      cfg.tlsConfigurationId,
    );
    return target && sameDnsName(record.content, target) ? 'ready' : 'pending';
  } catch {
    return 'unknown';
  }
}

// --- the adapter ---------------------------------------------------------------------

export const fastlyProvider: EdgeProvider<FastlyConfig, FastlyTemplateParams> = {
  id: 'fastly',
  templateSchema: FastlyTemplate,
  templateFields: FASTLY_TEMPLATE_FIELDS,
  defaultTemplate: FastlyTemplate.parse({}),

  async certificatePreflight(cfg) {
    const caa = await caaPreflight(cfg);
    return caa?.refusal
      ? { ok: false as const, code: caa.refusal.code, detail: caa.refusal.detail }
      : { ok: true as const };
  },

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
      return credentialTestFailure(e);
    }
  },

  /**
   * The account's one wildcard certificate as the provider sees it now, for the
   * account page and the renewal watch (null for a per-host account or one
   * without a DNS zone). Never orders anything.
   */
  async sharedCertificate(cfg, opts): Promise<SharedCertificateStatus | null> {
    const zone = fastlyZoneOf(cfg);
    if (!zone) return null;
    const name = `*.${zone}`;
    const api = fastlyApiFor(cfg);
    const found = await sharedSubscriptionOf(api, name, cfg);
    // An account switched back to one certificate per front still shows the
    // wildcard it left behind, so it can be removed; it never shows "absent".
    const wildcard = certificateScopeOf(cfg) === 'wildcard';
    if (found.status === 'absent') return wildcard ? { name, state: 'absent' } : null;
    if (found.status === 'ambiguous') {
      // One wildcard an edge of this account ORDERED, under another authority
      // than the account's now: not reusable, but the account's to remove,
      // whatever its scope (named, so the removal can find it).
      const own = orderedCandidate(found.candidates, opts?.ordered);
      if (own) return { name, subscriptionId: own.id, state: 'ambiguous' };
      return wildcard ? { name, state: 'ambiguous' } : null;
    }
    const doc = await api.getTlsSubscription(
      found.resource.id,
      'tls_authorizations,tls_certificates',
    );
    const state = subscriptionState(doc) ?? 'unknown';
    const notAfter = latestNotAfter(doc);
    // A renewal is a wait too: what holds it up is reported while it lasts,
    // and a certificate whose renewal is late (it expires within a week, or
    // has) is raised even when the provider names no reason.
    const code: L7CertificateCode | undefined =
      state === 'failed'
        ? 'tls_failed'
        : state === 'issued'
          ? undefined
          : (tlsAuthorizationCode(doc, { generic: true }) ??
            (await challengeRecordProblem(cfg, doc)));
    const late =
      notAfter !== undefined && Date.parse(notAfter) - Date.now() < CERTIFICATE_EXPIRY_WARN_MS;
    const reported = code ?? (late ? 'certificate_expiring' : undefined);
    return {
      name,
      subscriptionId: found.resource.id,
      state,
      ...(reported ? { code: reported } : {}),
      ...(notAfter ? { notAfter } : {}),
    };
  },

  /**
   * Remove the account's wildcard and OUR records at its challenge name, for
   * an operator who no longer wants it (the caller refuses while a live edge
   * fronts through it). A wildcard this account would not order is not ours to
   * delete (`shared_certificate_ambiguous`); a record with another customer's
   * marker, or none, is never touched.
   */
  async removeSharedCertificate(cfg, opts): Promise<{ removed: boolean; code?: string }> {
    const zone = fastlyZoneOf(cfg);
    if (!zone) return { removed: false, code: 'dns_zone_missing' };
    const api = fastlyApiFor(cfg);
    const shared = await sharedSubscriptionOf(api, `*.${zone}`, cfg);
    // The one wildcard an edge of this account ordered is its to remove,
    // whatever authority it was ordered under (a node's choice, or the
    // account's default before it changed). Several, or one it did not order,
    // never are.
    const own =
      shared.status === 'ambiguous' ? orderedCandidate(shared.candidates, opts.ordered) : null;
    const found: typeof shared = own ? { status: 'found', resource: own } : shared;
    if (found.status === 'ambiguous')
      return { removed: false, code: 'shared_certificate_ambiguous' };
    // Only a wildcard an edge of this account ORDERED is ever deleted: one it
    // found and reused may still serve somebody else's services.
    if (found.status === 'found' && !opts.ordered.includes(`tls_subscription:${found.resource.id}`))
      return { removed: false, code: 'shared_certificate_not_ours' };
    if (found.status === 'found') {
      try {
        await api.deleteTlsSubscription(found.resource.id);
      } catch (e) {
        if (!isFastlyNotFound(e)) throw e;
      }
    }
    const customerId = (await api.getLoggedInCustomer()).id;
    if (customerId) {
      const dns = await dnsClientFor(cfg);
      for (const r of await dns.findRecordsByName(acmeChallengeName(zone), 'CNAME')) {
        const m = parseSharedAcmeMarker(r.comment);
        if (!m || m.customerId !== customerId) continue;
        let gone = m.subscriptionId === (found.status === 'found' ? found.resource.id : null);
        if (!gone)
          try {
            await api.getTlsSubscription(m.subscriptionId);
          } catch (e) {
            if (!isFastlyNotFound(e)) throw e;
            gone = true;
          }
        if (gone) await dns.deleteRecord(r.id);
      }
    }
    return { removed: found.status === 'found' };
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
      const out: DiscoverResult = {};
      noteDiscoverError(out, 'tlsConfigurations', e);
      return out;
    }
  },

  /**
   * One front location is usable: its DNS account's credentials read its zone
   * (active, the name the location recorded; paused is only noted), and the TLS
   * configuration it names, if any, is one this token sees. The label is the
   * zone's name, with the TLS configuration's when one is named.
   */
  async checkLocation(cfg): Promise<LocationCheckResult> {
    const detail: string[] = [];
    try {
      const dns = await dnsClientFor(cfg);
      const zone = await dns.readZone();
      let label = zone.name;
      const observed: Record<string, string> = {
        zoneStatus: zone.paused ? 'paused' : zone.status,
        // What the zone's plan offers decides record tags and per-record flattening.
        ...(zone.plan ? { zonePlan: zone.plan } : {}),
      };
      const out = (code?: string): LocationCheckResult => ({
        ok: !code,
        ...(code ? { code } : {}),
        detail: detail.join(' '),
        observed,
        label,
        zoneName: zone.name,
      });
      if (cfg.dns?.zoneName && zone.name !== cfg.dns.zoneName.toLowerCase())
        return out('zone_name_mismatch');
      // A paused zone still answers DNS, and a front needs only unproxied
      // records there: a fact for the admin, never a refusal.
      if (zone.paused) detail.push('zone_paused');
      if (zone.status !== 'active') {
        detail.push('zone_not_active');
        return out('zone_not_active');
      }
      // The issuance preflight: the zone's CAA records must let the
      // certificate authority this zone's fronts get (the account's default)
      // issue, for the wildcard when its fronts share one.
      const caa = await caaPreflight(cfg);
      if (caa) Object.assign(observed, caa.observed);
      if (caa?.refusal) {
        detail.push(caa.refusal.detail);
        return out('caa_forbids_ca');
      }
      if (cfg.tlsConfigurationId) {
        const doc = await fastlyApiFor(cfg).listTlsConfigurations();
        const chosen = doc.data.find(
          (c) => c.type === 'tls_configuration' && c.id === cfg.tlsConfigurationId,
        );
        if (!chosen) {
          detail.push('tls_configuration_missing');
          return out('tls_configuration_missing');
        }
        const attrs = chosen.attributes as { name?: unknown } | undefined;
        if (typeof attrs?.name === 'string') label = `${zone.name} (${attrs.name})`;
      }
      return out();
    } catch (e) {
      const failed = credentialTestFailure(e);
      if (failed.code === 'error' || !(e instanceof EdgeProviderError) || e.meta.retryable) throw e;
      return { ok: false, code: failed.code, detail: failed.detail };
    }
  },

  planProvision(cfg, spec) {
    // Feasibility is decided before any provider call: an unsupported origin
    // never turns into a half-built service.
    assertFastlyOriginTransport(spec, 'plan');
    return planSteps(cfg, spec);
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
        // In order, the upgrade snippet last. A retry after a partial run finds
        // the ones it already made (the version is this edge's own draft).
        let snippet: { name: string; id?: string } = { name: SNIPPET_NAME };
        for (const body of fastlySnippetBodies(tpl)) {
          try {
            snippet = await api.createSnippet(svc.id, svc.version, body);
          } catch (e) {
            const made = await api.getSnippet(svc.id, svc.version, body.name).catch(() => null);
            if (!made) throw e;
            snippet = made;
          }
        }
        return {
          status: 'done',
          resources: [
            { kind: 'snippet', resourceId: snippet.id ?? snippet.name, ownership: 'created' },
          ],
        };
      }
      case 'create_domain': {
        const svc = serviceOf(ledger);
        if (domainModelOf(cfg) === 'versionless') {
          // Its own resource, linked to the service: no version holds it, so
          // it needs no activation and the service's rollback never drops it.
          const d = await api.createVersionlessDomain({
            fqdn: hostname,
            service_id: svc.id,
            description: spec.name,
          });
          return { status: 'done', resources: [versionlessResource(d, 'created')] };
        }
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
        if (certificateScopeOf(cfg) === 'wildcard') {
          // ONE subscription per account and zone: found by its name and
          // reused, ordered only when none exists (the step holds the
          // account's certificate lock, so two edges never both order it).
          const name = wildcardNameFor(hostname);
          const found = await sharedSubscriptionOf(api, name, cfg);
          if (found.status === 'found')
            return {
              status: 'done',
              resources: [sharedSubscriptionResource(found.resource.id, name, 'adopted')],
            };
          if (found.status === 'ambiguous')
            throw refusal(
              step.id,
              'shared_certificate_ambiguous',
              'the wildcard is covered by a subscription this account would not order',
            );
          const doc = await api.createTlsSubscription(
            fastlyTlsSubscriptionBody(name, cfg.certificateAuthority, cfg.tlsConfigurationId),
          );
          return {
            status: 'done',
            resources: [sharedSubscriptionResource(doc.data.id, name, 'created')],
          };
        }
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
        let shared: Awaited<ReturnType<typeof sharedAcmeRecord>> | null = null;
        if (certificateScopeOf(cfg) === 'wildcard') {
          shared = await sharedAcmeRecord(cfg, api, ledger, hostname);
          if (shared.status === 'found') return { status: 'done', resources: [shared.resource] };
          if (shared.status === 'ambiguous')
            throw refusal(
              step.id,
              'acme_name_in_use',
              'the challenge name already holds a record FCP did not write',
            );
        }
        const doc = await api.getTlsSubscription(sub.resourceId, 'tls_authorizations');
        const challenge = managedDnsChallenge(doc);
        if (!challenge) {
          // An issued wildcard that offers no challenge (validated some other
          // way) has nothing for this edge to write.
          const state = subscriptionState(doc);
          if (shared && (state === 'issued' || state === 'renewing'))
            return { status: 'done', resources: [] };
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
        }
        const dns = await dnsClientFor(cfg);
        // Our own record for a wildcard subscription that is gone (it failed
        // and was deleted at the provider): the name takes one CNAME, so it is
        // replaced. Only a record carrying OUR customer's marker is ever
        // removed here (`sharedAcmeRecord`).
        if (shared?.status === 'absent')
          for (const old of shared.stale) await dns.deleteRecord(old.id);
        const record = await dns.createRecord({
          type: 'CNAME',
          name:
            challenge.record_name ??
            acmeChallengeName(wildcardBase(certificateNameOf(cfg, hostname))),
          content: challenge.values[0],
          proxied: false,
          comment: shared?.status === 'absent' ? shared.marker : spec.name,
          ...dnsRecordOptions(tpl, false),
        });
        return { status: 'done', resources: [dnsResource('acme', record, dns, !!shared)] };
      }
      case 'await_tls': {
        const sub = firstResource(ledger, 'tls_subscription');
        if (!sub) throw ledgerIncomplete(step.id);
        // One look before waiting: an already issued certificate (the account's
        // shared wildcard, typically) finishes the step without a poll.
        return awaitOutcome(cfg, step, sub.resourceId, ledger);
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
          ...dnsRecordOptions(tpl, true),
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

  /**
   * Only `await_tls` is asynchronous: certificate issuance takes minutes. Each
   * look reads the authorizations too, so a wait that cannot end by itself (a
   * CAA record forbidding the CA, a missing validation record) is reported as
   * a code while it lasts instead of looking like a silent wait.
   */
  async pollStep(cfg, step, opRef, ledger): Promise<StepOutcome> {
    if (step.kind !== 'await_tls') throw refusal(step.id, 'unknown_step', 'not a polled step');
    return awaitOutcome(cfg, step, opRef, ledger);
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
        if (domainModelOf(cfg) === 'versionless') {
          // A domain name is unique per account: the exact-name listing is
          // authoritative. Ours is the one linked to THIS service; the same
          // name anywhere else is somebody else's and is never taken over.
          const named = (await api.findVersionlessDomains(hostname)).filter((d) =>
            sameDnsName(d.fqdn, hostname),
          );
          if (named.length === 0) return { status: 'confirmed_absent' };
          if (named.length === 1 && named[0]!.service_id === svc.id)
            return { status: 'found', resources: [versionlessResource(named[0]!, 'adopted')] };
          return {
            status: 'ambiguous',
            candidates: named.map((d) => candidateOf(versionlessResource(d, 'adopted'))),
          };
        }
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
        if (certificateScopeOf(cfg) === 'wildcard') {
          // The shared wildcard: the same rule as the step, so a lost order
          // response is recognised and never ordered twice.
          const name = wildcardNameFor(hostname);
          const found = await sharedSubscriptionOf(api, name, cfg);
          if (found.status === 'absent') return { status: 'confirmed_absent' };
          if (found.status === 'ambiguous')
            return {
              status: 'ambiguous',
              candidates: found.candidates.map((d) =>
                candidateOf(sharedSubscriptionResource(d.id, name, 'adopted')),
              ),
            };
          return {
            status: 'found',
            resources: [sharedSubscriptionResource(found.resource.id, name, 'adopted')],
          };
        }
        // Ownership is PROVEN, never assumed: the account may hold several
        // subscriptions covering this hostname (an operator's own, an older
        // one), and adopting whichever the API listed first would let a destroy
        // delete a certificate this edge never created. A subscription is this
        // step's only when it is the single one covering the hostname AND its
        // certificate authority and its EFFECTIVE TLS configuration (the
        // account's default one when the intent names none) are what this
        // edge was planned with.
        const covering = coveringSubscriptions(
          await api.listTlsSubscriptionsForDomain(hostname),
          hostname,
        );
        if (covering.length === 0) return { status: 'confirmed_absent' };
        const candidates = covering.map((d) => ({
          kind: 'tls_subscription' as const,
          resourceId: d.id,
          ownership: 'adopted' as const,
          meta: { hostname },
        }));
        const defaultId =
          covering.length === 1
            ? defaultConfigurationIdOf(await api.listTlsConfigurations())
            : undefined;
        if (
          covering.length > 1 ||
          !subscriptionMatchesIntent(covering[0]!, intentOfCfg(cfg), defaultId)
        )
          return { status: 'ambiguous', candidates: candidates.map(candidateOf) };
        return { status: 'found', resources: candidates };
      }
      case 'create_dns_acme':
      case 'create_dns_record': {
        if (!hostname) return { status: 'confirmed_absent' };
        if (step.kind === 'create_dns_acme' && certificateScopeOf(cfg) === 'wildcard') {
          const shared = await sharedAcmeRecord(cfg, api, ledger, hostname);
          if (shared.status === 'found') return { status: 'found', resources: [shared.resource] };
          if (shared.status === 'ambiguous')
            return { status: 'ambiguous', candidates: shared.candidates };
          return { status: 'confirmed_absent' };
        }
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
            candidates: records.map((r) => candidateOf(dnsResource(role, r, dns))),
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
        const doc = await api.getTlsSubscription(sub.resourceId, 'tls_certificates');
        if (subscriptionServes(doc))
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
    const versionless = firstResource(ledger, 'versionless_domain');
    if (versionless) {
      readiness.dns = await versionlessDnsReadiness(api, cfg, versionless, svc.id, ledger);
    } else if (hostname) {
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
    let expired = false;
    if (sub) {
      try {
        const doc = await api.getTlsSubscription(sub.resourceId, 'tls_certificates');
        certState = subscriptionState(doc);
        // Issued or renewing with a certificate past its expiry serves nothing.
        expired = (certState === 'issued' || certState === 'renewing') && !subscriptionServes(doc);
      } catch (e) {
        if (!isFastlyNotFound(e)) throw e;
      }
    }
    readiness.certificate = expired ? 'pending' : certificateReadiness(certState);

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
      ...(readiness.certificate === 'failed'
        ? { code: 'tls_failed' }
        : expired
          ? { code: 'certificate_expiring' }
          : {}),
      readiness,
    };
  },

  async inspect(cfg, ledger): Promise<InspectResult> {
    const svc = serviceOf(ledger);
    const api = fastlyApiFor(cfg);
    const detail = await api.getServiceDetail(svc.id);
    const [classic, versionless, backends] = await Promise.all([
      api.listDomains(svc.id, svc.version).catch(() => []),
      api.listVersionlessDomainsOfService(svc.id).catch(() => []),
      api.listBackends(svc.id, svc.version).catch(() => []),
    ]);
    const domains = [
      ...classic,
      ...versionless.map((d) => ({ name: d.fqdn, versionless: true, activated: d.activated })),
    ];
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
          // The port Fastly dials: its own field (80 when the API has none).
          port: b.port ?? 80,
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
      const [classic, versionless] = await Promise.all([
        api.listServiceDomains(svc.id).catch(() => []),
        api.listVersionlessDomainsOfService(svc.id).catch(() => []),
      ]);
      const hostnames = [
        ...new Set([...classic.map((d) => d.name), ...versionless.map((d) => d.fqdn)]),
      ];
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
   * certificate. With none for the name itself, a single wildcard covering it
   * is recorded as shared (it serves the zone, never this front alone).
   *
   * The hostname may be a classic domain of the active version or a
   * versionless domain linked to the service; the ledger records which.
   */
  async inspectForAdoption(cfg, resourceId, hostname): Promise<AdoptionInspection> {
    const step = 'adopt';
    const api = fastlyApiFor(cfg);
    const wanted = hostname.trim().toLowerCase();
    const detail = await api.getServiceDetail(resourceId);
    const activeVersion = activeVersionNumber(detail);
    if (activeVersion === undefined)
      throw refusal(step, 'service_not_active', 'the service has no active version');
    const { classic, versionless } = await serviceHostnames(api, resourceId, activeVersion);
    const hostnames = [
      ...new Set([...classic.map((d) => d.name), ...versionless.map((d) => d.fqdn)]),
    ];
    const mineVersionless = versionless.find((d) => d.fqdn.trim().toLowerCase() === wanted);
    const mine =
      mineVersionless?.fqdn ??
      classic.map((d) => d.name).find((n) => n.trim().toLowerCase() === wanted);
    if (mine === undefined)
      throw refusal(step, 'hostname_mismatch', 'the service does not serve that hostname');

    const backends = await api.listBackends(resourceId, activeVersion).catch(() => []);
    const content = backends[0]?.address ?? backends[0]?.hostname ?? undefined;

    const covering = coveringSubscriptions(await api.listTlsSubscriptionsForDomain(mine), mine);
    let subscription = covering.length === 1 ? covering[0] : undefined;
    let subscriptionShared =
      subscription !== undefined &&
      subscriptionDomains(subscription).some((n) => n.trim().toLowerCase() !== wanted);
    let subscriptionName = mine;
    if (covering.length === 0) {
      const wildcard = wildcardNameFor(mine);
      const wild = coveringSubscriptions(
        await api.listTlsSubscriptionsForDomain(wildcard),
        wildcard,
      );
      if (wild.length === 1) {
        subscription = wild[0];
        subscriptionShared = true;
        subscriptionName = wildcard;
      }
    }
    const shared = hostnames.length > 1 || subscriptionShared;

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
      mineVersionless
        ? versionlessResource(mineVersionless, 'adopted')
        : { kind: 'domain', resourceId: mine, ownership: 'adopted' },
    ];
    const wildcardSubscription = subscriptionName !== mine;
    if (subscription)
      resources.push(
        wildcardSubscription
          ? sharedSubscriptionResource(subscription.id, subscriptionName, 'adopted')
          : {
              kind: 'tls_subscription',
              resourceId: subscription.id,
              ownership: 'adopted',
              meta: { hostname: mine, shared: subscriptionShared },
            },
      );
    // The product is account-and-service wide: recorded when it is already on,
    // never enabled here (an import changes nothing at the provider).
    try {
      await api.getWebsockets(resourceId);
      resources.push({ kind: 'ws_product', resourceId, ownership: 'adopted' });
    } catch (e) {
      if (!(e instanceof EdgeProviderError) || (e.meta.status ?? 500) >= 500) throw e;
    }
    // The DNS records live in the referenced account's zone: the traffic CNAME
    // under the hostname itself and the ACME challenge beside it (a wildcard's
    // challenge belongs to the zone's certificate, not to this front).
    const dns = await dnsClientFor(cfg);
    for (const [role, name] of [
      ['traffic', mine],
      ...(wildcardSubscription ? [] : ([['acme', acmeChallengeName(mine)]] as const)),
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
    // A candidate discovery could not prove is this edge's is never destroyed.
    const live = ledger.resources.filter(
      (r) => r.deleteState !== 'confirmed_gone' && metaOf(r).candidate !== true,
    );
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
    // Never somebody else's: a candidate is left exactly as it was found.
    if (metaOf(r).candidate === true) return { status: 'confirmed_gone' };
    try {
      switch (r.kind) {
        case 'dns_record': {
          const meta = metaOf(r);
          // The shared wildcard's ACME record: the account's other fronts renew
          // through it, so no edge's destroy removes it.
          if (meta.shared === true) return { status: 'confirmed_gone' };
          const dns = await dnsClientFor(cfg);
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
        case 'versionless_domain': {
          // Its own resource: deleted by id, on a shared service too (no
          // version to rewrite), once its certificate is gone (destroy order).
          await api.deleteVersionlessDomain(r.resourceId);
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
    if (metaOf(r).candidate === true) return { status: 'confirmed_gone' };
    try {
      switch (r.kind) {
        case 'dns_record': {
          const meta = metaOf(r);
          if (meta.shared === true) return { status: 'confirmed_gone' };
          const dns = await dnsClientFor(cfg);
          const id = typeof meta.recordId === 'string' ? meta.recordId : r.resourceId;
          return (await dns.getRecord(id)) === null
            ? { status: 'confirmed_gone' }
            : { status: 'still_present' };
        }
        case 'versionless_domain': {
          await api.getVersionlessDomain(r.resourceId);
          return { status: 'still_present' };
        }
        case 'tls_subscription': {
          // Never deleted by an edge, so never waited for.
          if (metaOf(r).shared === true) return { status: 'confirmed_gone' };
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
