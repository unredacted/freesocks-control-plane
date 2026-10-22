'use node';
/**
 * Cloudflare L7 edge adapter.
 *
 * An edge is ONE proxied DNS record in the account's zone: clients reach the
 * CDN on 443 with SNI = the minted hostname, the CDN terminates TLS and dials
 * the origin. Three resource kinds:
 *
 *  - `dns_record`: the proxied A/AAAA/CNAME carrying the edge hostname. Its
 *    `comment` is the ownership marker (`<prefix>:<spec.name>`), which is what
 *    discovery proves ownership with. `tags` are not available on Free plans
 *    and comments are capped at 100 characters there, so the comment is the
 *    only marker this adapter relies on.
 *  - `origin_rule`: an Origin Rule (`http_request_origin` phase) overriding the
 *    destination port, needed ONLY when the origin's origin port is not the
 *    zone encryption mode's effective default. Cloudflare dials port 80 for a
 *    `flexible` zone and 443 for `full`/`strict`; the client-facing port is
 *    always 443, so the incoming proxied-port allowlist never applies here.
 *  - `header_rule`: a request-header Transform Rule (`http_request_late_transform`
 *    phase) for the edge hostname only, removing the member's address headers a
 *    rule may remove (`CLOUDFLARE_CLIENT_ADDRESS_HEADERS`), unless the node's
 *    options pass them on (`forwardClientAddress`). Never zone-wide.
 *
 * An account fronts only when it is set to DNS and fronting (role `dns`,
 * `frontsTraffic`); its location checks then also check what a front needs:
 * the zone's edge certificate, its CAA records for Cloudflare's certificate
 * authorities, Full (strict) encryption, and the zone settings that put more of
 * the member on the request (`frontingChecks`).
 *
 * Everything goes through the shared SDK client in ./dns/cloudflareDns.ts, so
 * retries (none), logging (off), the pinned API version and the body-free
 * error reduction are defined in exactly one place. Errors carry an HTTP
 * status and the numeric Cloudflare error code, never a body, URL, zone name
 * or token.
 *
 * Readiness: DNS existence is not origin health (`memberHealth: false`), so
 * `describe` reports `health: 'unknown'` always and `state: 'active'` only when
 * the record is proxied AND Universal SSL covers the hostname. Publishability
 * comes from the end-to-end front qualification, not from this adapter.
 */
import type {
  Addresses,
  AdoptionInspection,
  ChildResource,
  CloudflareConfig,
  CloudflareDnsConfig,
  CredentialTestResult,
  DiscoverResult,
  EdgeDescription,
  EdgeProvider,
  EdgeSpec,
  InspectResult,
  Inventory,
  LedgerResource,
  LocationCheckResult,
  ReadinessState,
  ResourceStep,
  StepOutcome,
} from './types';
import { firstResource, metaOf, orderByKind } from './types';
import { EdgeProviderError, credentialTestFailure, noteDiscoverError } from './http';
import { addressFamily } from '../ip';
import { isFirstLevelUnder } from '../hostname';
import { checkCaa, type CaaLookup, type CaaRecord, type CaaVerdictKind } from '../caa';
import { dnsCaaLookup } from './dns/caaLookup';
import {
  cfCall,
  cloudflareApi,
  cloudflareClient,
  cloudflareDnsClient,
  isCloudflareNotFound,
  normalizeDnsName,
  verifyCloudflareToken,
  __setCloudflareApiFactory,
  type FetchLike,
} from './dns/cloudflareDns';
import {
  CloudflareTemplate,
  CLOUDFLARE_TEMPLATE_FIELDS,
  type CloudflareTemplateParams,
} from './templates';

export { CloudflareTemplate, CLOUDFLARE_TEMPLATE_FIELDS } from './templates';
export type { CloudflareTemplateParams } from './templates';
export { cloudflareApi, __setCloudflareApiFactory, cloudflareDnsClient };

/** Ledger resource kinds this adapter owns, in destroy order (rules before the record). */
export const CLOUDFLARE_DESTROY_ORDER = ['header_rule', 'origin_rule', 'dns_record'] as const;

/** The Origin Rules phase; a zone has exactly one entry point ruleset per phase. */
const ORIGIN_PHASE = 'http_request_origin';
/** The request-header Transform Rules phase (late: after every other rule has run). */
const HEADER_PHASE = 'http_request_late_transform';
type RulePhase = typeof ORIGIN_PHASE | typeof HEADER_PHASE;
/** DNS record comments are capped at 100 characters on every plan. */
const MAX_COMMENT = 100;
/** Client-facing port of an L7 edge: always 443 (the CDN terminates TLS). */
export const CLOUDFLARE_EDGE_PORT = 443;

export type ZoneSslMode = 'flexible' | 'full' | 'strict';

// --- pure helpers (wire-contract surface; no I/O) -----------------------------------

/**
 * The port Cloudflare dials on the origin when no Origin Rule overrides it.
 * `flexible` proxies to the origin over plain HTTP on 80; `full` and `strict`
 * proxy over HTTPS on 443.
 * Source: https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/, 2026-09-16.
 */
export function defaultOriginPort(mode: ZoneSslMode): number {
  return mode === 'flexible' ? 80 : 443;
}

/** True when the slot's origin port needs a destination-port Origin Rule. */
export function originRuleNeeded(originPort: number, mode: ZoneSslMode): boolean {
  return originPort !== defaultOriginPort(mode);
}

function providerError(step: string, code: string, retryable = false): EdgeProviderError {
  return new EdgeProviderError(`cloudflare ${code} on ${step}`, {
    provider: 'cloudflare',
    step,
    code,
    retryable,
    timedOut: false,
  });
}

/**
 * The zone's encryption mode for THIS edge. `planProvision` must stay pure, so
 * the mode is never read from the API here: `testCredentials` observes it, the
 * orchestrator freezes it into the edge's provisionIntent and passes it back as
 * a rendered template param. An ABSENT mode is refused (`zone_mode_unknown`)
 * rather than guessed: inferring it from the origin scheme would plan an edge
 * against a zone setting nobody checked, and the guess decides both the
 * effective origin port and whether the origin leg is encrypted at all.
 *
 * The mode and the slot's origin transport must also agree, so a plan that
 * would silently downgrade or break the origin leg is refused up front:
 *  - a plaintext-HTTP origin needs `flexible` (any other mode dials 443 over TLS);
 *  - an https origin needs `full` or `strict` (`flexible` would dial port 80);
 *  - `strict` additionally validates the origin certificate, so an origin whose
 *    certificate is not publicly trusted cannot sit behind it.
 * `full` encrypts the origin leg without checking whose certificate answers;
 * `strict` checks it against the FRONT's hostname, which an enrolled node's
 * certificate (its origin name only) never carries, so `full` stays allowed
 * (docs/edges.md § "Cloudflare fronts", the origin leg).
 * Source: https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/, 2026-09-16.
 */
export function zoneSslModeOf(
  spec: EdgeSpec,
  tpl: CloudflareTemplateParams,
  step = 'plan',
): ZoneSslMode {
  const raw = (tpl as unknown as Record<string, unknown>).zoneSslMode;
  if (raw !== 'flexible' && raw !== 'full' && raw !== 'strict')
    throw providerError(step, 'zone_mode_unknown');
  const transport = spec.originTransport;
  if (transport) {
    if (transport.scheme === 'http' && raw !== 'flexible')
      throw providerError(step, 'origin_tls_mismatch');
    if (transport.scheme === 'https') {
      if (raw === 'flexible') throw providerError(step, 'origin_tls_mismatch');
      if (raw === 'strict' && !transport.certPublic)
        throw providerError(step, 'origin_tls_mismatch');
    }
  }
  return raw;
}

function listenerOf(spec: EdgeSpec, step: string): { address: string; port: number } {
  const member = spec.listeners[0]?.members[0];
  if (!member) throw providerError(step, 'spec_invalid');
  return member;
}

export function originPortOf(spec: EdgeSpec, step = 'plan'): number {
  return listenerOf(spec, step).port;
}

function originAddressOf(spec: EdgeSpec, step: string): string {
  return listenerOf(spec, step).address;
}

function hostnameOf(spec: EdgeSpec, step: string): string {
  if (!spec.hostname) throw providerError(step, 'hostname_missing');
  return normalizeDnsName(spec.hostname);
}

/**
 * `<prefix>:<spec.name>`, capped at the 100-character comment limit. The SPEC
 * NAME is never truncated (it is the ownership key discovery matches on); the
 * prefix gives way instead.
 */
export function recordComment(prefix: string, specName: string): string {
  const suffix = `:${specName}`;
  const room = Math.max(0, MAX_COMMENT - suffix.length);
  return `${prefix.slice(0, room)}${suffix}`;
}

export interface CloudflareRecordBody {
  zone_id: string;
  type: 'A' | 'AAAA' | 'CNAME';
  name: string;
  content: string;
  proxied: true;
  ttl: 1;
  comment: string;
  tags?: string[];
  settings?: { ipv4_only?: boolean; ipv6_only?: boolean };
}

/**
 * The exact DNS create body FCP sends. `proxied: true` is what makes this an
 * edge at all (an unproxied record would hand members the origin address);
 * `ttl: 1` means "automatic" and is the only TTL a proxied record accepts.
 */
export function cloudflareRecordBody(
  cfg: CloudflareConfig,
  spec: EdgeSpec,
  tpl: CloudflareTemplateParams,
  step = 'dns',
): CloudflareRecordBody {
  const hostname = hostnameOf(spec, step);
  if (!isFirstLevelUnder(hostname, cfg.zoneName)) throw providerError(step, 'hostname_not_in_zone');
  const content = originAddressOf(spec, step);
  const fam = addressFamily(content);
  return {
    zone_id: cfg.zoneId,
    // A hostname origin (null family) is a CNAME; an IP literal is A or AAAA.
    type: fam === 'v4' ? 'A' : fam === 'v6' ? 'AAAA' : 'CNAME',
    name: hostname,
    content,
    proxied: true,
    ttl: 1,
    comment: recordComment(tpl.commentPrefix, spec.name),
    ...(tpl.recordTags && Object.keys(tpl.recordTags).length > 0
      ? { tags: Object.entries(tpl.recordTags).map(([k, v]) => `${k}:${v}`) }
      : {}),
    ...(tpl.answerFamily === 'ipv4'
      ? { settings: { ipv4_only: true } }
      : tpl.answerFamily === 'ipv6'
        ? { settings: { ipv6_only: true } }
        : {}),
  };
}

export interface CloudflareOriginRule {
  action: 'route';
  action_parameters: { origin: { port: number } };
  expression: string;
  description: string;
  ref: string;
  enabled: true;
}

/**
 * The Origin Rule body. `ref` is the discovery key: a lost `rules.create`
 * response is recovered by reading the ruleset back and finding the rule with
 * our `ref`, so no duplicate rule is ever added (Free zones allow 10).
 */
export function cloudflareOriginRule(spec: EdgeSpec, originPort: number): CloudflareOriginRule {
  const hostname = hostnameOf(spec, 'rule');
  return {
    action: 'route',
    action_parameters: { origin: { port: originPort } },
    expression: `(http.host eq "${hostname}")`,
    description: spec.name,
    ref: spec.name,
    enabled: true,
  };
}

/**
 * Whether an Origin Rule expression targets EXACTLY one hostname: the operand
 * of an `http.host eq "<name>"` comparison, compared as a hostname (case
 * insensitive, trailing dot tolerated) and never as a substring of the
 * expression. `ba.example.org` contains `a.example.org`, so a substring match
 * would adopt (and later delete) a rule that belongs to another host.
 * The shape is the one `cloudflareOriginRule` writes; an expression this
 * function cannot read is not this edge's rule.
 */
export function originRuleTargetsHost(expression: unknown, hostname: string): boolean {
  if (typeof expression !== 'string') return false;
  const wanted = normalizeDnsName(hostname);
  if (!wanted) return false;
  for (const m of expression.matchAll(/http\.host\s+eq\s+"([^"]*)"/gi))
    if (normalizeDnsName(m[1]) === wanted) return true;
  return false;
}

/**
 * The request headers carrying the member's address that a Transform Rule may
 * REMOVE at the CDN: the header rule of every front whose node must not see
 * the member's address (the default) removes each of them, for the front's
 * hostname only. Cloudflare's rules may not touch a `cf-` or `x-cf-` header
 * except `cf-connecting-ip` (Request Header Transform Rules, Important
 * remarks, re-read 2026-10-21), so that is the one name today.
 *
 * What no rule removes at Cloudflare, by its own documentation (the node's
 * Caddy removes them all before the proxy reads the request; that layer stays):
 *  - `X-Forwarded-For`: a rule may remove it, but the proxy adds it back with
 *    the member's address after every rule phase, managed transforms included;
 *    asking would change nothing, so it is not asked;
 *  - `CF-Connecting-IPv6` (sent while the zone's Pseudo IPv4 is on) and every
 *    other `cf-` header (`CF-IPCountry`, `CF-Ray`, `CF-Visitor`): refused.
 * A name joins this list only once a front built with it shows it gone in a
 * capture at the node: Cloudflare documents no removal of `True-Client-IP`,
 * `X-Real-IP` or `Forwarded`, and a list is no proof (one name Fastly refused
 * failed every front there). `cloudflare.test.ts` keeps the known ones out.
 */
export const CLOUDFLARE_CLIENT_ADDRESS_HEADERS = ['cf-connecting-ip'] as const;

/** Address headers that reach the node from a Cloudflare front whatever FCP asks (docs and tests). */
export const CLOUDFLARE_ADDRESS_HEADERS_KEPT = ['x-forwarded-for', 'cf-connecting-ipv6'] as const;

export interface CloudflareHeaderRule {
  action: 'rewrite';
  action_parameters: { headers: Record<string, { operation: 'remove' }> };
  expression: string;
  description: string;
  ref: string;
  enabled: true;
}

/**
 * The header rule body: the removals for EXACTLY this hostname (the expression
 * `cloudflareOriginRule` writes), never the zone. `ref` is its discovery key in
 * the late-transform entry point, as for the origin rule.
 */
export function cloudflareHeaderRule(spec: EdgeSpec): CloudflareHeaderRule {
  const hostname = hostnameOf(spec, 'headers');
  return {
    action: 'rewrite',
    action_parameters: {
      headers: Object.fromEntries(
        CLOUDFLARE_CLIENT_ADDRESS_HEADERS.map((h) => [h, { operation: 'remove' as const }]),
      ),
    },
    expression: `(http.host eq "${hostname}")`,
    description: spec.name,
    ref: spec.name,
    enabled: true,
  };
}

/** Whether a front keeps the member's address from its node (the default; `forwardClientAddress` off). */
export function stripsClientAddress(tpl: Pick<CloudflareTemplateParams, 'forwardClientAddress'>) {
  return tpl.forwardClientAddress !== true;
}

// --- SDK plumbing ------------------------------------------------------------------

function dnsFor(cfg: CloudflareConfig, fetchImpl?: FetchLike) {
  // The adapter owns its zone directly, so the DNS account id is its own (and
  // may be absent: it is only recorded in resource meta for cross-account writes).
  const dnsCfg: CloudflareDnsConfig = {
    apiToken: cfg.apiToken,
    zoneId: cfg.zoneId,
    zoneName: cfg.zoneName,
    accountId: cfg.accountId ?? '',
  };
  return cloudflareDnsClient(dnsCfg, fetchImpl);
}

/** One rule as the phase/rule endpoints return it (the SDK types it as a 21-way union). */
interface RawRule {
  id?: string;
  ref?: string;
  action?: string;
  description?: string;
  enabled?: boolean;
  expression?: string;
  action_parameters?: {
    origin?: { port?: number };
    headers?: Record<string, { operation?: string }>;
  };
}

/** A ruleset as the phase/rule endpoints return it. */
interface RawRuleset {
  id?: string;
  rules?: RawRule[];
}

async function getPhase(
  cfg: CloudflareConfig,
  phase: RulePhase,
  step: string,
): Promise<RawRuleset | null> {
  try {
    const found = await cfCall(step, () =>
      cloudflareClient(cfg).rulesets.phases.get(phase, { zone_id: cfg.zoneId }),
    );
    return found as unknown as RawRuleset;
  } catch (e) {
    // No entry point ruleset exists for the phase yet.
    if (isCloudflareNotFound(e)) return null;
    throw e;
  }
}

const getOriginPhase = (cfg: CloudflareConfig, step: string) => getPhase(cfg, ORIGIN_PHASE, step);

/**
 * Add one rule to the zone's entry point ruleset of a phase, creating the entry
 * point with that rule when the phase has none yet (the create IS the write
 * then). The zone lock the orchestrator holds (`stepLockKey`) keeps a
 * concurrent edge from replacing a ruleset created meanwhile. Both endpoints
 * answer with the WHOLE ruleset.
 */
async function addZoneRule(
  cfg: CloudflareConfig,
  phase: RulePhase,
  rule: CloudflareOriginRule | CloudflareHeaderRule,
  step: string,
): Promise<RawRuleset> {
  const existing = await getPhase(cfg, phase, step);
  if (!existing?.id) {
    const created = await cfCall(step, () =>
      cloudflareClient(cfg).rulesets.phases.update(phase, {
        zone_id: cfg.zoneId,
        name: 'default',
        rules: [rule as never],
      }),
    );
    return created as unknown as RawRuleset;
  }
  const updated = await cfCall(step, () =>
    cloudflareClient(cfg).rulesets.rules.create(
      existing.id as string,
      {
        zone_id: cfg.zoneId,
        ...rule,
      } as never,
    ),
  );
  return { ...(updated as unknown as RawRuleset), id: (updated as RawRuleset).id ?? existing.id };
}

function findRuleByRef(ruleset: RawRuleset | null, ref: string) {
  return (ruleset?.rules ?? []).find((r) => r.ref === ref);
}

// --- readiness ----------------------------------------------------------------------

interface CertPack {
  id: string;
  status: string;
  hosts: string[];
  type?: string;
}

/**
 * Universal SSL state for one hostname: an ACTIVE certificate pack listing the
 * hostname itself or the zone's first-level wildcard covers it. An error here
 * is `unknown` (the token may lack "SSL and Certificates Read"), never a
 * failure: a missing read must not fail an otherwise healthy edge (the front
 * qualification proves the certificate end to end either way). While nothing
 * covers it, `code` says why: one is still being issued
 * (`edge_certificate_pending`) or none is on its way (`edge_certificate_missing`).
 */
async function certificateReadiness(
  cfg: CloudflareConfig,
  hostname: string,
): Promise<{ state: ReadinessState; packs: CertPack[]; code?: string }> {
  try {
    const page = await cfCall('describe-cert', () =>
      cloudflareClient(cfg).ssl.certificatePacks.list({
        zone_id: cfg.zoneId,
        status: 'all',
        per_page: 50,
      }),
    );
    const packs = (page.result as unknown as CertPack[]) ?? [];
    const wildcard = `*.${normalizeDnsName(cfg.zoneName)}`;
    const covers = (p: CertPack) =>
      (p.hosts ?? []).some((h) => {
        const n = normalizeDnsName(h);
        return n === hostname || n === wildcard;
      });
    if (packs.some((p) => p.status === 'active' && covers(p))) return { state: 'ready', packs };
    const coming = packs.some((p) => covers(p) && /^(initializing|pending)/.test(p.status ?? ''));
    return {
      state: 'pending',
      packs,
      code: coming ? 'edge_certificate_pending' : 'edge_certificate_missing',
    };
  } catch {
    return { state: 'unknown', packs: [] };
  }
}

/** One zone setting's value as a plain string (`websockets`, `ssl`). */
async function zoneSetting(
  cfg: CloudflareConfig,
  id: string,
  step: string,
): Promise<string | null> {
  try {
    const setting = await cfCall(step, () =>
      cloudflareClient(cfg).zones.settings.get(id, { zone_id: cfg.zoneId }),
    );
    const value = (setting as unknown as { value?: unknown }).value;
    return typeof value === 'string' ? value : null;
  } catch {
    return null;
  }
}

// --- what a front needs of its zone (DNS and fronting accounts only) ----------------

let caaLookupOverride: CaaLookup | null = null;
/** Test seam: answer CAA lookups from a table (the offline suite refuses real DNS). */
export function __setCloudflareCaaLookup(f: CaaLookup | null): void {
  caaLookupOverride = f;
}

/**
 * The certificate authorities Universal SSL issues from, by their CAA issuer
 * domain. Cloudflare chooses among them and may change it at a renewal
 * without notice, so a zone must let at least one issue (Sectigo is used for
 * backup certificates only).
 * Source: https://developers.cloudflare.com/ssl/reference/certificate-authorities/, 2026-10-21.
 */
export const CLOUDFLARE_UNIVERSAL_CAS = ['letsencrypt.org', 'pki.goog', 'ssl.com'] as const;

/**
 * The CAA preflight of a fronting zone: the zone's edge certificate is its
 * `*.<zone>` wildcard (Universal SSL covers the apex and first-level names
 * only, which is where every front is minted), so the walk is the wildcard's
 * (`issuewild`, else `issue`), from the zone up. Cloudflare adds CAA records
 * for its own authorities to a zone it hosts that has any; records ABOVE the
 * zone (a zone for a subdomain) are inherited and never touched, which is what
 * this walk is for. `forbids` only when records exist and allow none of the
 * authorities; a lookup that fails anywhere is `unchecked` and passes.
 */
export async function cloudflareCaaPreflight(zone: string): Promise<{
  verdict: CaaVerdictKind;
  allowed: string[];
  decidedAt?: string;
}> {
  const lookup = caaLookupOverride ?? dnsCaaLookup;
  // Every authority walks the same names: one lookup per name.
  const seen = new Map<string, Promise<CaaRecord[]>>();
  const once: CaaLookup = (name) => {
    let p = seen.get(name);
    if (!p) seen.set(name, (p = lookup(name)));
    return p;
  };
  const verdicts = [];
  for (const ca of CLOUDFLARE_UNIVERSAL_CAS)
    verdicts.push(await checkCaa({ name: `*.${zone}`, certificateAuthority: ca, lookup: once }));
  const allowed = verdicts.filter((v) => v.verdict === 'allows').map((v) => v.issuer);
  const decidedAt = verdicts.find((v) => v.decidedAt)?.decidedAt;
  const verdict: CaaVerdictKind = verdicts.some((v) => v.verdict === 'unchecked')
    ? allowed.length > 0
      ? 'allows'
      : 'unchecked'
    : verdicts[0]!.verdict === 'no_records'
      ? 'no_records'
      : allowed.length > 0
        ? 'allows'
        : 'forbids';
  return { verdict, allowed, ...(decidedAt ? { decidedAt } : {}) };
}

/** A certificate pack's state for the zone's wildcard: ready, on its way, none, or unreadable. */
export type ZoneCertificateState = 'active' | 'pending' | 'none' | 'unknown';

/**
 * The zone's edge certificate for its fronts: a certificate pack (Universal,
 * Advanced or Total TLS) listing `*.<zone>`, the best one first (active, then
 * one still being issued). An error is `unknown` (the token may lack "SSL and
 * Certificates Read"): reported, never a refusal.
 */
async function zoneCertificate(
  cfg: CloudflareConfig,
  zone: string,
): Promise<{ state: ZoneCertificateState; authority?: string; type?: string }> {
  let packs: Array<CertPack & { certificate_authority?: string }>;
  try {
    const page = await cfCall('location', () =>
      cloudflareClient(cfg).ssl.certificatePacks.list({
        zone_id: cfg.zoneId,
        status: 'all',
        per_page: 50,
      }),
    );
    packs = (page.result as unknown as typeof packs) ?? [];
  } catch {
    return { state: 'unknown' };
  }
  const wildcard = `*.${normalizeDnsName(zone)}`;
  const mine = packs.filter((p) => (p.hosts ?? []).some((h) => normalizeDnsName(h) === wildcard));
  const active = mine.find((p) => p.status === 'active');
  const pending = mine.find((p) => /^(initializing|pending)/.test(p.status ?? ''));
  const best = active ?? pending;
  if (!best) return { state: 'none' };
  return {
    state: active ? 'active' : 'pending',
    ...(best.certificate_authority ? { authority: best.certificate_authority } : {}),
    ...(best.type ? { type: best.type } : {}),
  };
}

/**
 * What a front needs of its zone, for an account set to DNS and fronting (a
 * DNS-only account's zone is never judged by it):
 *  - an edge certificate for `*.<zone>` (`edge_certificate_missing` when none
 *    is active or on its way: Universal SSL switched off, or nothing ordered);
 *  - CAA records that let one of Cloudflare's authorities issue it
 *    (`caa_forbids_ca`, the refusal every CDN's zone check shares);
 *  - recorded, never refused: Full without strict (`zone_ssl_not_strict`: the
 *    origin leg is encrypted but its certificate is not checked; strict checks
 *    it against the front's name, which an enrolled node's certificate does
 *    not carry), the lowest TLS version members may use, and the zone-wide
 *    settings that put more of the member on the request (Pseudo IPv4 adds the
 *    address in `CF-Connecting-IPv6`, IP geolocation the country in
 *    `CF-IPCountry`; no rule removes either at the CDN).
 */
async function frontingChecks(
  cfg: CloudflareConfig,
  zone: string,
  ssl: string | null,
): Promise<{ observed: Record<string, string>; detail: string[]; refusal?: string }> {
  const observed: Record<string, string> = {};
  const detail: string[] = [];
  const [minTls, pseudoIpv4, ipGeolocation] = await Promise.all([
    zoneSetting(cfg, 'min_tls_version', 'location'),
    zoneSetting(cfg, 'pseudo_ipv4', 'location'),
    zoneSetting(cfg, 'ip_geolocation', 'location'),
  ]);
  if (minTls) {
    observed.minTlsVersion = minTls;
    if (minTls === '1.0' || minTls === '1.1') detail.push(`min_tls_${minTls}`);
  }
  if (pseudoIpv4) {
    observed.pseudoIpv4 = pseudoIpv4;
    if (pseudoIpv4 !== 'off') detail.push('pseudo_ipv4_on');
  }
  if (ipGeolocation) {
    observed.ipGeolocation = ipGeolocation;
    if (ipGeolocation === 'on') detail.push('ip_country_header_on');
  }
  if (ssl === 'full') detail.push('zone_ssl_not_strict');
  const cert = await zoneCertificate(cfg, zone);
  observed.edgeCertificate = cert.state;
  if (cert.authority) observed.edgeCertificateAuthority = cert.authority;
  if (cert.type) observed.edgeCertificateType = cert.type;
  if (cert.state === 'none') {
    detail.push('edge_certificate_missing');
    return { observed, detail, refusal: 'edge_certificate_missing' };
  }
  if (cert.state !== 'active') detail.push(`edge_certificate_${cert.state}`);
  const caa = await cloudflareCaaPreflight(zone);
  observed.caa = caa.verdict;
  observed.caaIssuer = (caa.allowed.length > 0 ? caa.allowed : CLOUDFLARE_UNIVERSAL_CAS).join(' ');
  observed.caaCertificate = 'wildcard';
  if (caa.decidedAt) observed.caaAt = caa.decidedAt;
  if (caa.verdict === 'forbids') {
    detail.push(
      `the CAA records at ${caa.decidedAt} allow none of ${CLOUDFLARE_UNIVERSAL_CAS.join(', ')} for the wildcard (issuewild)`,
    );
    return { observed, detail, refusal: 'caa_forbids_ca' };
  }
  return { observed, detail };
}

/** One zone as the listing shows it. */
interface ListedZone {
  id: string;
  name: string;
  status: string;
  paused: boolean;
  /** The Cloudflare account the zone belongs to (an account-owned token's verify needs it). */
  accountId?: string;
}

/** Zones per listing page, and the most pages one listing reads (1,000 zones). */
const ZONE_PAGE = 50;
const ZONE_PAGES_MAX = 20;

/**
 * The zones a token reaches, page by page up to `maxPages` (`truncated` when
 * more exist). Each page is one request against the rate limit shared with the
 * dashboard, so a credential test reads one page and the catalog all of them.
 */
async function listZones(
  apiToken: string,
  step: string,
  maxPages = ZONE_PAGES_MAX,
): Promise<{ zones: ListedZone[]; truncated: boolean }> {
  const client = cloudflareClient({ apiToken });
  const zones: ListedZone[] = [];
  for (let page = 1; page <= maxPages; page++) {
    const res = await cfCall(step, () => client.zones.list({ per_page: ZONE_PAGE, page }), [
      apiToken,
    ]);
    for (const z of res.result) {
      zones.push({
        id: z.id,
        name: normalizeDnsName(z.name),
        status: typeof z.status === 'string' ? z.status : 'unknown',
        paused: z.paused === true,
        ...(z.account?.id ? { accountId: z.account.id } : {}),
      });
    }
    if (res.result.length < ZONE_PAGE) return { zones, truncated: false };
  }
  return { zones, truncated: true };
}

// --- the adapter ---------------------------------------------------------------------

export const cloudflareProvider: EdgeProvider<CloudflareConfig, CloudflareTemplateParams> = {
  id: 'cloudflare',
  templateSchema: CloudflareTemplate,
  templateFields: CLOUDFLARE_TEMPLATE_FIELDS,
  defaultTemplate: CloudflareTemplate.parse({}),

  /**
   * The token works, is active and reaches at least one zone. The account is
   * the whole Cloudflare account: which zone a front or a DNS record lives in
   * is its location's, checked by `checkLocation`, so no zone is read here.
   *
   * User tokens and account-owned tokens both pass (`verifyCloudflareToken`);
   * an account token's account id is the first listed zone's, else the
   * settings' `accountId`. One page of zones is read either way.
   */
  async testCredentials(cfg): Promise<CredentialTestResult> {
    const detail: string[] = [];
    let listing: ReturnType<typeof listZones> | undefined;
    const listOnce = () => (listing ??= listZones(cfg.apiToken, 'test', 1));
    try {
      const token = await verifyCloudflareToken(cfg, async () => {
        try {
          return (await listOnce()).zones[0]?.accountId || cfg.accountId || undefined;
        } catch (e) {
          if (cfg.accountId) return cfg.accountId;
          // A listing that may succeed next time is not a rejection: with no
          // account id to fall back to, the test fails retryable on it.
          if (e instanceof EdgeProviderError && e.meta.retryable) throw e;
          return undefined;
        }
      });
      if (token.status !== 'active') return { ok: false, code: 'token_not_active' };
      detail.push(`token_${token.kind}`);
      const { zones, truncated } = await listOnce();
      if (zones.length === 0) {
        detail.push('zones_none');
        return { ok: false, code: 'no_zones', detail: detail.join(' ') };
      }
      detail.push(truncated ? `zones_${zones.length}_plus` : `zones_${zones.length}`);
      return { ok: true, detail: detail.join(' ') };
    } catch (e) {
      return credentialTestFailure(e);
    }
  },

  /**
   * One zone (the location's) is usable: readable with this token, active,
   * not paused, its name the one the location recorded. The soft
   * preconditions are reported as short codes in `detail` (never as free text
   * from the API). The zone's `ssl` mode is RECORDED, not required:
   * `flexible|full|strict` are all usable and the feasibility check against a
   * slot's origin transport happens at plan time, not here. Only `off` is
   * refused outright; an account set to DNS and fronting also has what a
   * front needs of its zone checked (`frontingChecks`).
   *
   * The two settings also travel as `observed`, the machine-readable half of
   * `detail`: the orchestrator stores them on the location and freezes
   * `zoneSslMode` into each new edge's intent, which is the ONLY way the mode
   * reaches `planProvision` (see `zoneSslModeOf`). A setting the token cannot
   * read leaves `zoneSslMode` out entirely (planning then refuses) and reports
   * `websockets: 'off'`, the conservative answer. A zone the token cannot read
   * fails on that read's own code.
   */
  async checkLocation(cfg): Promise<LocationCheckResult> {
    const detail: string[] = [];
    try {
      const zone = await cfCall(
        'location',
        () => cloudflareClient(cfg).zones.get({ zone_id: cfg.zoneId }),
        [cfg.apiToken],
      );
      const name = normalizeDnsName(zone.name);
      if (cfg.zoneName && name !== normalizeDnsName(cfg.zoneName))
        return { ok: false, code: 'zone_name_mismatch', detail: 'zone_name_mismatch', label: name };
      const ssl = await zoneSetting(cfg, 'ssl', 'location');
      const websockets = await zoneSetting(cfg, 'websockets', 'location');
      const plan = (zone.plan as { legacy_id?: string } | undefined)?.legacy_id;
      const observed: Record<string, string> = {
        ...(ssl ? { zoneSslMode: ssl } : {}),
        websockets: websockets === 'on' ? 'on' : 'off',
        // What the zone's plan offers decides record tags and per-record flattening.
        ...(plan ? { zonePlan: plan } : {}),
        zoneStatus: zone.paused === true ? 'paused' : String(zone.status ?? 'unknown'),
      };
      if (ssl) detail.push(`ssl_${ssl}`);
      else detail.push('ssl_unknown');
      if (websockets === 'on') detail.push('websockets_on');
      else if (websockets === null) detail.push('websockets_unknown');
      else detail.push('websockets_off');
      // Free zones cap DNS comments and Origin Rules; useful for the operator.
      if (plan === 'free') detail.push('plan_free');
      const out = (code?: string): LocationCheckResult => ({
        ok: !code,
        ...(code ? { code } : {}),
        detail: detail.join(' '),
        observed,
        label: name,
        zoneName: name,
      });
      if (ssl === 'off') return out('zone_ssl_off');
      if (zone.paused === true) {
        detail.push('zone_paused');
        return out('zone_paused');
      }
      if (zone.status !== 'active') {
        detail.push('zone_not_active');
        return out('zone_not_active');
      }
      // What a front needs of the zone: only for an account that fronts.
      if (cfg.frontsTraffic) {
        const front = await frontingChecks(cfg, name, ssl);
        Object.assign(observed, front.observed);
        detail.push(...front.detail);
        if (front.refusal) return out(front.refusal);
      }
      return out();
    } catch (e) {
      const failed = credentialTestFailure(e);
      if (failed.code === 'error' || !(e instanceof EdgeProviderError) || e.meta.retryable) throw e;
      return { ok: false, code: failed.code ?? 'zone_unreadable', detail: failed.detail };
    }
  },

  /** Cloudflare has no regions; the places it offers are the zones the token reaches. */
  async listRegions(cfg) {
    return (await listZones(cfg.apiToken, 'zones')).zones.map((z) => ({ id: z.id, label: z.name }));
  },

  async discoverOptions(partial): Promise<DiscoverResult> {
    const apiToken = typeof partial.apiToken === 'string' ? partial.apiToken : '';
    if (!apiToken) return {};
    try {
      const { zones, truncated } = await listZones(apiToken, 'zones');
      return {
        zones: zones.map((z) => ({
          id: z.id,
          label: z.name,
          facts: {
            status: z.paused ? 'paused' : z.status,
            ...(z.accountId ? { account: z.accountId } : {}),
          },
        })),
        ...(truncated ? { truncated: ['zones'] } : {}),
      };
    } catch (e) {
      const out: DiscoverResult = {};
      noteDiscoverError(out, 'zones', e);
      return out;
    }
  },

  /**
   * Pure: one DNS record, an Origin Rule only when the origin port is not the
   * zone mode's effective default, and the header rule unless the node's
   * options pass the member's address on.
   */
  planProvision(_cfg, spec, tpl) {
    const originPort = originPortOf(spec, 'plan');
    const steps: ResourceStep[] = [
      { id: 'dns', kind: 'create_dns_record', resourceName: spec.name, discoverability: 'by_name' },
    ];
    if (originRuleNeeded(originPort, zoneSslModeOf(spec, tpl))) {
      if (!tpl.allowOriginPortOverride)
        throw providerError('plan', 'origin_port_override_disabled');
      steps.push({
        id: 'rule',
        kind: 'create_origin_rule',
        resourceName: `${spec.name}-rule`,
        discoverability: 'by_name',
      });
    }
    if (stripsClientAddress(tpl))
      steps.push({
        id: 'headers',
        kind: 'create_header_rule',
        resourceName: `${spec.name}-headers`,
        discoverability: 'by_name',
      });
    return steps;
  },

  async runStep(cfg, step, spec, tpl): Promise<StepOutcome> {
    switch (step.kind) {
      case 'create_dns_record': {
        const body = cloudflareRecordBody(cfg, spec, tpl, step.id);
        const record = await dnsFor(cfg).createRecord({
          type: body.type,
          name: body.name,
          content: body.content,
          proxied: body.proxied,
          comment: body.comment,
        });
        const addresses: Addresses = { hostname: record.name };
        return {
          status: 'done',
          resources: [
            {
              kind: 'dns_record',
              resourceId: record.id,
              ownership: 'created',
              meta: { name: record.name, zoneId: cfg.zoneId, type: record.type },
            },
          ],
          addresses,
        };
      }
      case 'create_origin_rule': {
        const originPort = originPortOf(spec, step.id);
        const ruleset = await addZoneRule(
          cfg,
          ORIGIN_PHASE,
          cloudflareOriginRule(spec, originPort),
          step.id,
        );
        // The whole ruleset comes back: ours is the one with our ref.
        const mine = findRuleByRef(ruleset, spec.name);
        if (!mine?.id) return { status: 'partial', resources: [], code: 'rule_not_returned' };
        return {
          status: 'done',
          resources: [
            {
              kind: 'origin_rule',
              resourceId: mine.id,
              ownership: 'created',
              meta: { rulesetId: ruleset.id ?? '' },
            },
          ],
        };
      }
      case 'create_header_rule': {
        let ruleset: RawRuleset;
        try {
          ruleset = await addZoneRule(cfg, HEADER_PHASE, cloudflareHeaderRule(spec), step.id);
        } catch (e) {
          // A token without Transform Rules: Edit (or a zone at its rule limit,
          // answered the same way) is refused on every try: the run stops on
          // it now, and the operator fixes the token or the zone.
          if (e instanceof EdgeProviderError && e.meta.status === 403)
            return {
              status: 'partial',
              resources: [],
              code: 'header_rule_forbidden',
              refused: true,
            };
          throw e;
        }
        const mine = findRuleByRef(ruleset, spec.name);
        if (!mine?.id) return { status: 'partial', resources: [], code: 'rule_not_returned' };
        return {
          status: 'done',
          resources: [
            {
              kind: 'header_rule',
              resourceId: mine.id,
              ownership: 'created',
              meta: { rulesetId: ruleset.id ?? '' },
            },
          ],
        };
      }
      default:
        throw providerError(step.id, 'unknown_step');
    }
  },

  /**
   * The DNS listing is authoritative and instant (`discoverySettleMs: 0`), so a
   * name with no record is `confirmed_absent` on the first look. Ownership is
   * proven by BOTH the comment marker (or a record id already in the ledger,
   * for adopted records) AND the content matching the origin origin: a record
   * with our hostname but someone else's content is never adopted or deleted.
   */
  async discover(cfg, step, spec, ledger) {
    switch (step.kind) {
      case 'create_dns_record': {
        const hostname = hostnameOf(spec, step.id);
        const origin = originAddressOf(spec, step.id);
        const hits = await dnsFor(cfg).findRecordsByName(hostname);
        if (hits.length === 0) return { status: 'confirmed_absent' };
        const known = new Set(
          ledger.resources.filter((r) => r.kind === 'dns_record').map((r) => r.resourceId),
        );
        const marker = `:${spec.name}`;
        const mine = hits.find(
          (h) =>
            (h.comment?.endsWith(marker) === true || known.has(h.id)) &&
            normalizeDnsName(h.content) === normalizeDnsName(origin),
        );
        if (mine)
          return {
            status: 'found',
            resources: [
              {
                kind: 'dns_record',
                resourceId: mine.id,
                ownership: 'adopted',
                meta: { name: mine.name, zoneId: cfg.zoneId, type: mine.type },
              },
            ],
            addresses: { hostname: mine.name },
          };
        return {
          status: 'ambiguous',
          candidates: hits.map((h) => ({
            kind: 'dns_record',
            resourceId: h.id,
            ownership: 'adopted' as const,
            meta: { name: h.name, zoneId: cfg.zoneId, type: h.type },
          })),
        };
      }
      case 'create_origin_rule':
      case 'create_header_rule': {
        const header = step.kind === 'create_header_rule';
        const phase = await getPhase(cfg, header ? HEADER_PHASE : ORIGIN_PHASE, step.id);
        if (!phase) return { status: 'confirmed_absent' };
        const mine = findRuleByRef(phase, spec.name);
        if (!mine?.id) return { status: 'confirmed_absent' };
        return {
          status: 'found',
          resources: [
            {
              kind: header ? 'header_rule' : 'origin_rule',
              resourceId: mine.id,
              ownership: 'adopted',
              meta: { rulesetId: phase.id ?? '' },
            },
          ],
        };
      }
      default:
        return { status: 'confirmed_absent' };
    }
  },

  async describe(cfg, ledger): Promise<EdgeDescription> {
    const rec = firstResource(ledger, 'dns_record');
    if (!rec) return { state: 'pending', addresses: {}, health: 'unknown', code: 'no_record_yet' };
    const record = await dnsFor(cfg).getRecord(rec.resourceId);
    if (!record) return { state: 'gone', addresses: {}, health: 'unknown' };
    const hostname = record.name;
    const cert = await certificateReadiness(cfg, hostname);
    const dnsReady: ReadinessState = record.proxied ? 'ready' : 'pending';
    // An unproxied record hands members the ORIGIN address: an error, not a
    // wait. A certificate this token cannot read is left to the front
    // qualification, which proves it end to end.
    const state: EdgeDescription['state'] = !record.proxied
      ? 'error'
      : cert.state === 'pending'
        ? 'pending'
        : 'active';
    return {
      state,
      addresses: { hostname },
      // memberHealth is false for this provider: a DNS record says nothing
      // about whether the origin is up, so health is never claimed.
      health: 'unknown',
      ...(record.proxied ? (cert.code ? { code: cert.code } : {}) : { code: 'unproxied' }),
      readiness: { dns: dnsReady, certificate: cert.state },
    };
  },

  async inspect(cfg, ledger): Promise<InspectResult> {
    const rec = firstResource(ledger, 'dns_record');
    if (!rec) throw providerError('inspect', 'no_record');
    const record = await dnsFor(cfg).getRecord(rec.resourceId);
    if (!record) throw providerError('inspect', 'record_gone');
    const [ssl, websockets, cert] = await Promise.all([
      zoneSetting(cfg, 'ssl', 'inspect'),
      zoneSetting(cfg, 'websockets', 'inspect'),
      certificateReadiness(cfg, record.name),
    ]);
    // The live origin port: an Origin Rule's override when one exists, else the
    // zone encryption mode's default.
    const ruleRes = firstResource(ledger, 'origin_rule');
    let originPort = defaultOriginPort(
      ssl === 'flexible' || ssl === 'full' || ssl === 'strict' ? ssl : 'full',
    );
    let rule: RawRule | undefined;
    if (ruleRes) {
      const phase = await getOriginPhase(cfg, 'inspect');
      rule = (phase?.rules ?? []).find((r) => r.id === ruleRes.resourceId);
      const port = rule?.action_parameters?.origin?.port;
      if (typeof port === 'number') originPort = port;
    }
    // The header rule: which headers it removes now (none = the member's
    // address reaches the node in every header the CDN sets).
    const headerRes = firstResource(ledger, 'header_rule');
    let headerRule: RawRule | undefined;
    if (headerRes) {
      const phase = await getPhase(cfg, HEADER_PHASE, 'inspect');
      headerRule = (phase?.rules ?? []).find((r) => r.id === headerRes.resourceId);
    }
    return {
      summary: {
        status: record.proxied ? 'proxied' : 'dns-only',
        addresses: { hostname: record.name },
        members: [{ address: record.content, port: originPort }],
        listeners: [{ port: CLOUDFLARE_EDGE_PORT, protocol: 'https' }],
      },
      // Secrets-free: ids, names, statuses and the two settings. No token, no
      // account identifiers beyond the zone the operator already configured.
      raw: {
        record: {
          id: record.id,
          name: record.name,
          type: record.type,
          content: record.content,
          proxied: record.proxied,
          comment: record.comment,
        },
        settings: { ssl, websockets },
        certificate: {
          state: cert.state,
          packs: cert.packs.map((p) => ({
            id: p.id,
            status: p.status,
            hosts: p.hosts,
            type: p.type,
          })),
        },
        ...(rule
          ? {
              originRule: {
                id: rule.id,
                ref: rule.ref,
                port: rule.action_parameters?.origin?.port,
              },
            }
          : {}),
        ...(headerRes
          ? {
              headerRule: {
                id: headerRes.resourceId,
                found: headerRule !== undefined,
                removes: Object.entries(headerRule?.action_parameters?.headers ?? {})
                  .filter(([, op]) => op?.operation === 'remove')
                  .map(([name]) => name),
              },
            }
          : {}),
      },
    };
  },

  /**
   * Import surface: every proxied A/AAAA/CNAME record in the zone. Paginated by
   * hand (page/per_page) rather than through the SDK's async iterator so the
   * request count is bounded and visible in the wire contract.
   */
  async inventory(cfg): Promise<Inventory> {
    const client = cloudflareClient(cfg);
    const rows: Array<{
      id: string;
      name: string;
      type: string;
      content?: string;
      proxied?: boolean;
    }> = [];
    const MAX_PAGES = 10;
    for (let page = 1; page <= MAX_PAGES; page++) {
      const res = await cfCall('inventory', () =>
        client.dns.records.list({ zone_id: cfg.zoneId, proxied: true, page, per_page: 100 }),
      );
      const batch = res.result as unknown as typeof rows;
      rows.push(...batch);
      if (batch.length < 100) break;
    }
    const fronted = rows.filter((r) => r.type === 'A' || r.type === 'AAAA' || r.type === 'CNAME');
    return {
      loadBalancers: fronted.map((r) => {
        const name = normalizeDnsName(r.name);
        return {
          id: r.id,
          name,
          addresses: { hostname: name },
          content: r.content ?? '',
          hostnames: [name],
          status: r.proxied ? 'proxied' : 'dns-only',
        };
      }),
      ips: [],
      flavors: [],
    };
  },

  /**
   * Import: read ONE existing proxied record back and describe it as the
   * children FCP would have created. A Cloudflare edge is never shared (a DNS
   * record serves exactly one name), so `shared` is always false.
   *
   * Refusals rather than a best guess: a record that is gone is `not_found`,
   * a record whose name is not the hostname the operator named is
   * `hostname_mismatch` (importing it would hand members somebody else's name),
   * and a DNS-only record is `record_not_proxied`: nothing fronts it, so its
   * content is the origin's own address and importing it would publish the node
   * itself as an "edge". The `meta.proxied:false` marker is kept as well, so the
   * orchestrator refuses a stale inspection the same way.
   *
   * The zone's origin rules are read too: the rule whose expression names
   * EXACTLY this hostname belongs to this edge and is adopted with it, so a
   * later destroy removes the port override the operator set up by hand. The
   * operand is parsed rather than substring-matched: `ba.example.org` contains
   * `a.example.org`, and adopting that rule would delete another host's
   * override. A request-header rule naming exactly this hostname is adopted
   * the same way; an imported front without one gets none from FCP (it is
   * never edited), so its node sees `CF-Connecting-IP` until it is replaced.
   */
  async inspectForAdoption(cfg, resourceId, hostname): Promise<AdoptionInspection> {
    const step = 'adopt';
    const wanted = normalizeDnsName(hostname);
    const record = await dnsFor(cfg).getRecord(resourceId);
    if (!record) throw providerError(step, 'not_found');
    if (record.name !== wanted) throw providerError(step, 'hostname_mismatch');
    if (!record.proxied) throw providerError(step, 'record_not_proxied');
    const resources: ChildResource[] = [
      {
        kind: 'dns_record',
        resourceId: record.id,
        ownership: 'adopted',
        meta: {
          name: record.name,
          zoneId: cfg.zoneId,
          type: record.type,
          ...(record.proxied ? {} : { proxied: false }),
        },
      },
    ];
    const phase = await getOriginPhase(cfg, step);
    const rule = (phase?.rules ?? []).find((r) => originRuleTargetsHost(r.expression, wanted));
    if (rule?.id) {
      const port = rule.action_parameters?.origin?.port;
      resources.push({
        kind: 'origin_rule',
        resourceId: rule.id,
        ownership: 'adopted',
        meta: {
          rulesetId: phase?.id ?? '',
          ...(typeof port === 'number' ? { port } : {}),
        },
      });
    }
    // A token that cannot read Transform Rules imports the front without its
    // header rule: the rule stays at the provider for the operator.
    const headers = await getPhase(cfg, HEADER_PHASE, step).catch(() => null);
    const headerRule = (headers?.rules ?? []).find(
      (r) => r.action === 'rewrite' && originRuleTargetsHost(r.expression, wanted),
    );
    if (headerRule?.id)
      resources.push({
        kind: 'header_rule',
        resourceId: headerRule.id,
        ownership: 'adopted',
        meta: { rulesetId: headers?.id ?? '' },
      });
    return {
      resources,
      hostname: record.name,
      hostnames: [record.name],
      shared: false,
      content: record.content,
    };
  },

  planDestroy: (_cfg, ledger): LedgerResource[] => orderByKind(ledger, CLOUDFLARE_DESTROY_ORDER),

  /**
   * Every delete is synchronous and idempotent, so there is no
   * `confirmDestroyed` (capability `asyncDelete: false`): a 404 IS the
   * confirmation. An unknown kind stays `unresolved` and parks the edge.
   */
  async runDestroy(cfg, r) {
    switch (r.kind) {
      case 'header_rule':
      case 'origin_rule': {
        const rulesetId = metaOf(r).rulesetId;
        if (typeof rulesetId !== 'string' || rulesetId.length === 0)
          return { status: 'unresolved' };
        try {
          await cfCall('destroy', () =>
            // ruleID first, then the params carrying ruleset_id + zone_id.
            cloudflareClient(cfg).rulesets.rules.delete(r.resourceId, {
              ruleset_id: rulesetId,
              zone_id: cfg.zoneId,
            }),
          );
        } catch (e) {
          if (!isCloudflareNotFound(e)) throw e;
        }
        return { status: 'confirmed_gone' };
      }
      case 'dns_record': {
        // deleteRecord already treats 404 as success.
        await dnsFor(cfg).deleteRecord(r.resourceId);
        return { status: 'confirmed_gone' };
      }
      default:
        return { status: 'unresolved' };
    }
  },
};
