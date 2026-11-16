'use node';
/**
 * Tencent Cloud EdgeOne L7 (CDN) edge adapter: one hostname, one acceleration
 * domain in the operator's EdgeOne zone, in front of one WebSocket origin.
 *
 * Model. A provisioned edge is four steps:
 *  1. `create_service`: the acceleration domain `<label>.<zone>` (an
 *     `IP_DOMAIN` origin: the node's address, its scheme and port, and the
 *     Host the node receives). Before it, the zone's service area is compared
 *     with the template's (`serviceArea`, outside the Chinese mainland by
 *     default): FCP never changes a zone's area, it refuses a mismatch.
 *  2. `create_dns_record`: the front's name pointed at the domain's CNAME
 *     target. Two ways, by how the zone is connected to EdgeOne, frozen per
 *     edge (the location names a DNS account or not):
 *       - NS access (EdgeOne hosts the zone's DNS): EdgeOne adds a CNAME for a
 *         new domain itself, switched off; the step switches it on
 *         (`ModifyDnsRecordsStatus`), or writes one (`CreateDnsRecord`) when
 *         EdgeOne added none. Such a record goes with the domain.
 *       - CNAME access: the CNAME is written into the zone of the location's
 *         DNS account (Cloudflare, Gandi), commented with the edge's name.
 *  3. `create_tls_subscription`: EdgeOne's free certificate for the name
 *     (`ModifyHostsCertificate`, `eofreecert`). On a CNAME-access zone EdgeOne
 *     validates it over HTTP at its edge, so it refuses the request until the
 *     name resolves to EdgeOne (`tls_waiting_for_dns`): the step then waits
 *     and asks again (`tls_challenge_missing`).
 *  4. `await_tls`: wait until the certificate is deployed and the domain is
 *     `online`.
 *
 * WebSocket is a ZONE setting at EdgeOne (`DescribeL7AccSetting`): the
 * location check records it, FCP never changes it. Tencent's plan table lists
 * no WebSocket on the free plan, while the API reference says a zone with the
 * switch off still carries WebSocket with a 15 s idle timeout. The front
 * qualification (a real tunnel through the front) is what decides.
 *
 * Ownership. An acceleration domain carries no comment or tag: discovery owns
 * one only when its name is the front's AND it dials the front's origin. A
 * DNS account's record carries the edge's name as its comment.
 *
 * Errors. ./edgeone/sdk.ts reduces every SDK error to a status and a short
 * code; a plan or quota refusal is `plan_limit`, which stops the run (a
 * definite refusal), and the CAM action a refusal needed travels in the
 * refusal's words.
 */
import type {
  ChildResource,
  CredentialTestResult,
  Discovery,
  DnsZoneConfig,
  EdgeDescription,
  EdgeOneConfig,
  EdgeProvider,
  EdgeReadiness,
  EdgeSpec,
  InspectResult,
  Inventory,
  Ledger,
  LedgerResource,
  LocationCheckResult,
  ReadinessState,
  ResourceStep,
  StepOutcome,
} from './types';
import { metaOf, resourcesOfKind } from './types';
import { EdgeProviderError, credentialTestFailure, noteDiscoverError, refusedCreate } from './http';
import { normalizeZoneName } from '../hostname';
import { addressFamily } from '../ip';
import { caaProbeName, checkCaa, type CaaLookup } from '../caa';
import { dnsCaaLookup } from './dns/caaLookup';
import type { L7CertificateCode } from '../../../../src/shared/contracts/edgeCodes';
import type { DnsClient, DnsRecord } from './dns/types';
import { originPortDialable } from './capabilities';
import {
  edgeOneApiFor,
  isEdgeOneCode,
  isEdgeOneNotFound,
  type EdgeOneApi,
  type EdgeOneDomain,
  type EdgeOneDomainSpec,
  type EdgeOneZone,
} from './edgeone/sdk';
import { EdgeOneTemplate, EDGEONE_TEMPLATE_FIELDS, type EdgeOneTemplateParams } from './templates';
import { deepMerge, defaultsOf } from './options';

export { EdgeOneTemplate, EDGEONE_TEMPLATE_FIELDS } from './templates';
export type { EdgeOneTemplateParams } from './templates';

/** The authorities EdgeOne issues its free certificate from (it picks): CAA must allow both. */
export const EDGEONE_CERTIFICATE_AUTHORITIES = ['lets-encrypt', 'trustasia'] as const;

// --- DNS client and CAA injection -----------------------------------------------------------

type DnsClientFactory = (cfg: DnsZoneConfig) => DnsClient | Promise<DnsClient>;
let dnsFactory: DnsClientFactory | null = null;
/** Test seam: an in-memory DnsClient. */
export function __setEdgeOneDnsClientFactory(f: DnsClientFactory | null): void {
  dnsFactory = f;
}

async function dnsClientFor(cfg: EdgeOneConfig): Promise<DnsClient> {
  const dns = cfg.dns;
  if (!dns)
    throw refusal('dns', 'dns_account_missing', 'the referenced DNS account is not resolved');
  if (dnsFactory) return await dnsFactory(dns);
  const mod = await import('./dns/clients');
  return mod.dnsClientForZone(dns);
}

let caaLookupOverride: CaaLookup | null = null;
/** Test seam: answer CAA lookups from a table (the offline suite refuses real DNS). */
export function __setEdgeOneCaaLookup(f: CaaLookup | null): void {
  caaLookupOverride = f;
}

// --- small helpers ---------------------------------------------------------------------------

function refusal(step: string, code: string, why: string, retryable = false): EdgeProviderError {
  return new EdgeProviderError(`edgeone ${step}: ${why}`, {
    provider: 'edgeone',
    step,
    code,
    retryable,
    timedOut: false,
  });
}

const sameDnsName = (a: string | undefined, b: string | undefined) =>
  !!a && !!b && normalizeZoneName(a) === normalizeZoneName(b);

/** How the front's name gets its record: EdgeOne's own DNS (NS access) or a DNS account. */
export type EdgeOneDnsMode = 'edgeone' | 'account';
export const edgeOneDnsModeOf = (cfg: EdgeOneConfig): EdgeOneDnsMode =>
  cfg.dns || cfg.dnsAccountId ? 'account' : 'edgeone';

function requireHostname(spec: EdgeSpec, step: string): string {
  if (!spec.hostname) throw refusal(step, 'hostname_missing', 'the spec carries no hostname');
  return normalizeZoneName(spec.hostname);
}

function requireZone(cfg: EdgeOneConfig, step: string): string {
  if (!cfg.zoneId) throw refusal(step, 'dns_zone_missing', 'the location names no EdgeOne zone');
  return cfg.zoneId;
}

function originMember(spec: EdgeSpec, step: string): { address: string; port: number } {
  const m = spec.listeners[0]?.members[0];
  if (!m) throw refusal(step, 'spec_invalid', 'the spec has no origin member');
  return {
    address: m.address
      .trim()
      .toLowerCase()
      .replace(/^\[|\]$/g, ''),
    port: m.port,
  };
}

type EffectiveEdgeOneParams = EdgeOneTemplateParams &
  Required<Pick<EdgeOneTemplateParams, 'overrideHost' | 'ipv6' | 'serviceArea'>>;

/** The template with every option the operator left unset at its declared default. */
export function effectiveEdgeOneParams(
  tpl: Partial<EdgeOneTemplateParams>,
): EffectiveEdgeOneParams {
  return deepMerge(defaultsOf(EDGEONE_TEMPLATE_FIELDS), tpl) as EffectiveEdgeOneParams;
}

/**
 * The origin refusals decided before any call: an origin transport is
 * declared, on a port the front dials (1-65535), and a node that
 * receives its own name as Host is addressed by a name (an address literal is
 * no Host a node's certificate names).
 */
export function assertEdgeOneOrigin(
  spec: EdgeSpec,
  tpl: Partial<EdgeOneTemplateParams>,
  step = 'plan',
): void {
  if (!spec.originTransport)
    throw refusal(step, 'origin_transport_missing', 'the slot declares no origin transport');
  const { address, port } = originMember(spec, step);
  if (!originPortDialable('edgeone', port))
    throw refusal(step, 'origin_port_unsupported', 'EdgeOne dials ports 1 to 65535');
  if (effectiveEdgeOneParams(tpl).overrideHost === 'origin' && addressFamily(address) !== null)
    throw refusal(step, 'origin_not_a_name', 'the node address sent as Host is not a name');
}

/** What the acceleration domain is created with. */
export function edgeOneDomainSpec(
  cfg: EdgeOneConfig,
  spec: EdgeSpec,
  tpl: Partial<EdgeOneTemplateParams>,
): EdgeOneDomainSpec {
  assertEdgeOneOrigin(spec, tpl, 'domain');
  const p = effectiveEdgeOneParams(tpl);
  const hostname = requireHostname(spec, 'domain');
  const { address, port } = originMember(spec, 'domain');
  const tls = spec.originTransport!.scheme === 'https';
  return {
    zoneId: requireZone(cfg, 'domain'),
    name: hostname,
    origin: address,
    hostHeader: p.overrideHost === 'origin' ? address : hostname,
    originProtocol: tls ? 'HTTPS' : 'HTTP',
    httpPort: tls ? 80 : port,
    httpsPort: tls ? port : 443,
    ipv6Status: p.ipv6,
  };
}

const candidateOf = (r: ChildResource): ChildResource => ({
  ...r,
  meta: { ...(r.meta ?? {}), candidate: true },
});

function domainResource(d: EdgeOneDomain, ownership: 'created' | 'adopted'): ChildResource {
  return {
    kind: 'acceleration_domain',
    resourceId: d.name,
    ownership,
    meta: {
      zoneId: d.zoneId,
      hostname: d.name,
      ...(d.cname ? { cname: d.cname } : {}),
      ...(d.origin ? { origin: d.origin } : {}),
    },
  };
}

function ownDomainOf(ledger: Ledger): LedgerResource | undefined {
  return resourcesOfKind(ledger, 'acceleration_domain').find((r) => metaOf(r).candidate !== true);
}

/** The front's hostname as the ledger records it. */
export function edgeOneHostnameOf(ledger: Ledger): string | undefined {
  const d = ownDomainOf(ledger);
  const h = metaOf(d).hostname;
  return typeof h === 'string' ? h : d?.resourceId;
}

function accountRecordResource(record: DnsRecord, dns: DnsClient, cname: string): ChildResource {
  return {
    kind: 'dns_record',
    resourceId: record.id,
    ownership: 'created',
    meta: {
      via: 'account',
      role: 'traffic',
      dnsAccountId: dns.accountId,
      zoneId: dns.zoneId,
      recordId: record.id,
      name: record.name,
      cname,
    },
  };
}

function edgeOneRecordResource(
  zoneId: string,
  id: string,
  name: string,
  cname: string,
  ownership: 'created' | 'adopted',
): ChildResource {
  return {
    kind: 'dns_record',
    resourceId: id,
    ownership,
    // EdgeOne's own record for the name: it goes with the domain, and the
    // destroy after the domain removes whatever is left at the name.
    meta: { via: 'edgeone', role: 'traffic', zoneId, recordId: id, name, cname },
  };
}

function certificateResource(zoneId: string, hostname: string): ChildResource {
  return {
    kind: 'tls_subscription',
    resourceId: hostname,
    ownership: 'created',
    // Part of the domain at EdgeOne: deleting the domain removes it.
    meta: { zoneId, hostname, mode: 'eofreecert', withDomain: true },
  };
}

/** Whether a domain dials the front's origin: the one thing that proves it FCP's. */
function dialsOrigin(d: EdgeOneDomain, spec: EdgeSpec): boolean {
  const m = spec.listeners[0]?.members[0];
  return (
    !!m && d.originType === 'IP_DOMAIN' && sameDnsName(d.origin, m.address.replace(/^\[|\]$/g, ''))
  );
}

async function domainOrThrow(
  api: EdgeOneApi,
  zoneId: string,
  name: string,
  step: string,
): Promise<EdgeOneDomain> {
  const d = await api.getDomain(zoneId, name);
  if (!d) throw refusal(step, 'ledger_incomplete', 'the acceleration domain is not listed', true);
  return d;
}

/** The domain's free certificate is deployed (and not failed). */
export function certificateState(d: EdgeOneDomain | null | undefined): ReadinessState {
  if (!d) return 'unknown';
  const list = d.certificates;
  if (list.some((c) => c.status === 'deployed')) return 'ready';
  if (list.some((c) => c.status === 'failed' || c.status === 'issued')) return 'failed';
  if (d.certificateMode && d.certificateMode !== 'eofreecert') return 'pending';
  return 'pending';
}

/** What the front's name resolves to, as its record holds it now (`null`: no record). */
async function trafficRecordPoints(
  cfg: EdgeOneConfig,
  api: EdgeOneApi,
  hostname: string,
  cname: string | undefined,
): Promise<ReadinessState> {
  if (!cname) return 'pending';
  try {
    if (edgeOneDnsModeOf(cfg) === 'account') {
      const dns = await dnsClientFor(cfg);
      const records = await dns.findRecordsByName(hostname, 'CNAME');
      return records.some((r) => sameDnsName(r.content, cname)) ? 'ready' : 'pending';
    }
    const records = await api.findDnsRecords(cfg.zoneId, hostname);
    return records.some(
      (r) => r.type === 'CNAME' && sameDnsName(r.content, cname) && r.status !== 'disable',
    )
      ? 'ready'
      : 'pending';
  } catch {
    return 'unknown';
  }
}

/**
 * One look at the domain the edge waits on: the certificate deployed and the
 * domain online finish the step; a failed certificate stops the run; else the
 * step stays requested with what it waits on.
 */
async function awaitServing(cfg: EdgeOneConfig, hostname: string): Promise<StepOutcome> {
  const api = edgeOneApiFor(cfg);
  const d = await domainOrThrow(api, requireZone(cfg, 'await-tls'), hostname, 'await-tls');
  const cert = certificateState(d);
  if (cert === 'failed')
    return { status: 'partial', resources: [], code: 'tls_failed', refused: true };
  if (cert === 'ready' && d.status === 'online')
    return { status: 'done', resources: [], addresses: { hostname } };
  let code: L7CertificateCode | undefined;
  if (cert !== 'ready' && (await trafficRecordPoints(cfg, api, hostname, d.cname)) === 'pending')
    code = 'tls_challenge_missing';
  else if (d.status !== 'online') code = 'domain_not_activated';
  return { status: 'requested', opRef: hostname, resources: [], ...(code ? { code } : {}) };
}

/** Ask for the free certificate; a name not pointing at EdgeOne yet waits and asks again. */
async function requestCertificate(cfg: EdgeOneConfig, hostname: string): Promise<StepOutcome> {
  const zoneId = requireZone(cfg, 'certificate');
  try {
    await edgeOneApiFor(cfg).requestFreeCertificate(zoneId, hostname);
  } catch (e) {
    if (isEdgeOneCode(e, 'tls_waiting_for_dns'))
      return { status: 'requested', opRef: hostname, resources: [], code: 'tls_challenge_missing' };
    const refused = refusedCreate(e, codeOf(e));
    if (refused) return refused;
    throw e;
  }
  return { status: 'done', resources: [certificateResource(zoneId, hostname)] };
}

const codeOf = (e: unknown): string =>
  e instanceof EdgeProviderError && e.meta.code ? e.meta.code : 'create_refused';

/**
 * The location check's CAA verdict: EdgeOne picks the authority for each free
 * certificate (Let's Encrypt or TrustAsia), so the zone's CAA records must let
 * BOTH issue a front's own name (checked from a label no front uses, as a new
 * front's name will be), under the validation the zone's access mode gets:
 * DNS records EdgeOne writes for a zone it hosts, a file at its edge (HTTP)
 * for a zone connected by CNAME.
 * Source: https://cloud.tencent.com/document/product/1552/90437, 2026-11-15.
 */
async function caaPreflight(cfg: EdgeOneConfig): Promise<{
  observed: Record<string, string>;
  refusal?: { code: L7CertificateCode; detail: string };
}> {
  const validationMethod = edgeOneDnsModeOf(cfg) === 'account' ? 'http-01' : 'dns-01';
  const verdicts = [];
  for (const certificateAuthority of EDGEONE_CERTIFICATE_AUTHORITIES)
    verdicts.push(
      await checkCaa({
        name: caaProbeName(cfg.zoneName),
        certificateAuthority,
        validationMethod,
        lookup: caaLookupOverride ?? dnsCaaLookup,
      }),
    );
  const forbidden = verdicts.filter((v) => v.verdict === 'forbids');
  // One verdict to keep: the first refusal, else an unchecked look, else the first.
  const kept = forbidden[0] ?? verdicts.find((v) => v.verdict === 'unchecked') ?? verdicts[0]!;
  const observed: Record<string, string> = {
    caa: kept.verdict,
    caaIssuer: verdicts.map((v) => v.issuer).join(','),
    caaCertificate: 'per_host',
    ...(kept.decidedAt ? { caaAt: kept.decidedAt } : {}),
  };
  if (forbidden.length === 0) return { observed };
  return {
    observed,
    refusal: {
      code: 'caa_forbids_ca',
      detail: `the CAA records at ${kept.decidedAt} do not allow ${forbidden.map((v) => v.issuer).join(' or ')} (${validationMethod}); EdgeOne may issue from either authority`,
    },
  };
}

// --- steps -----------------------------------------------------------------------------------

const STEP_IDS = { domain: 'domain', dns: 'dns', tls: 'tls', await: 'await-tls' } as const;

function planSteps(spec: EdgeSpec): ResourceStep[] {
  const hostname = requireHostname(spec, 'plan');
  return [
    {
      id: STEP_IDS.domain,
      kind: 'create_service',
      resourceName: hostname,
      discoverability: 'by_name',
    },
    {
      id: STEP_IDS.dns,
      kind: 'create_dns_record',
      resourceName: hostname,
      discoverability: 'by_name',
    },
    {
      id: STEP_IDS.tls,
      kind: 'create_tls_subscription',
      resourceName: hostname,
      discoverability: 'by_name',
    },
    { id: STEP_IDS.await, kind: 'await_tls', resourceName: hostname, discoverability: 'by_name' },
  ];
}

/** The front's zone as the key reads it, or a refusal. */
async function zoneOrThrow(api: EdgeOneApi, zoneId: string, step: string): Promise<EdgeOneZone> {
  const zone = (await api.listZones(zoneId)).items.find((z) => z.id === zoneId);
  if (!zone) throw refusal(step, 'zone_unreadable', 'the key does not see the EdgeOne zone');
  return zone;
}

async function createDomain(
  cfg: EdgeOneConfig,
  spec: EdgeSpec,
  tpl: EdgeOneTemplateParams,
): Promise<StepOutcome> {
  const api = edgeOneApiFor(cfg);
  const want = edgeOneDomainSpec(cfg, spec, tpl);
  // The zone's service area is the zone's: FCP never changes it, and refuses
  // to build a front in a zone serving somewhere the template does not allow.
  const zone = await zoneOrThrow(api, want.zoneId, STEP_IDS.domain);
  const area = effectiveEdgeOneParams(tpl).serviceArea;
  // An area the zone does not report is no proof it is the template's: refused too.
  if (zone.area !== area)
    return {
      status: 'partial',
      resources: [],
      code: 'zone_area_mismatch',
      refused: true,
      detail: zone.area
        ? `the zone serves ${zone.area}, the template allows ${area}`
        : 'the zone reports no service area',
    };
  try {
    await api.createDomain(want);
  } catch (e) {
    // A create whose answer was lost, repeated: the name is there already.
    const there = await api.getDomain(want.zoneId, want.name).catch(() => null);
    if (there && dialsOrigin(there, spec))
      return { status: 'done', resources: [domainResource(there, 'adopted')] };
    const refused = refusedCreate(e, codeOf(e));
    if (refused) return refused;
    throw e;
  }
  // Read back for the CNAME target the record needs (listed within seconds).
  const d = await api.getDomain(want.zoneId, want.name).catch(() => null);
  return {
    status: 'done',
    resources: [
      domainResource(
        d ?? { zoneId: want.zoneId, name: want.name, certificates: [], restrictions: [] },
        'created',
      ),
    ],
  };
}

async function writeTrafficRecord(
  cfg: EdgeOneConfig,
  spec: EdgeSpec,
  tpl: EdgeOneTemplateParams,
  ledger: Ledger,
): Promise<StepOutcome> {
  const api = edgeOneApiFor(cfg);
  const zoneId = requireZone(cfg, STEP_IDS.dns);
  const hostname = requireHostname(spec, STEP_IDS.dns);
  const own = ownDomainOf(ledger);
  if (!own) throw refusal(STEP_IDS.dns, 'ledger_incomplete', 'no acceleration domain yet');
  const known = metaOf(own).cname;
  const cname =
    typeof known === 'string' && known
      ? known
      : (await domainOrThrow(api, zoneId, hostname, STEP_IDS.dns)).cname;
  if (!cname)
    throw refusal(
      STEP_IDS.dns,
      'cname_pending',
      'EdgeOne has not named the CNAME target yet',
      true,
    );
  const ttl = typeof tpl.dnsTtl === 'number' && tpl.dnsTtl >= 60 ? tpl.dnsTtl : undefined;
  if (edgeOneDnsModeOf(cfg) === 'account') {
    const dns = await dnsClientFor(cfg);
    const records = await dns.findRecordsByName(hostname, 'CNAME');
    const ours = records.find((r) => r.comment === spec.name);
    if (ours) {
      if (!sameDnsName(ours.content, cname) && dns.updateRecord) {
        const moved = await dns.updateRecord(ours.id, {
          type: 'CNAME',
          name: hostname,
          content: cname,
          proxied: false,
          comment: spec.name,
          ...(ttl ? { ttl } : {}),
        });
        return {
          status: 'done',
          resources: [accountRecordResource(moved, dns, cname)],
          addresses: { hostname },
        };
      }
      return {
        status: 'done',
        resources: [{ ...accountRecordResource(ours, dns, cname), ownership: 'adopted' }],
        addresses: { hostname },
      };
    }
    if (records.length > 0)
      return { status: 'partial', resources: [], code: 'dns_record_exists', refused: true };
    let record: DnsRecord;
    try {
      record = await dns.createRecord({
        type: 'CNAME',
        name: hostname,
        content: cname,
        proxied: false,
        comment: spec.name,
        ...(ttl ? { ttl } : {}),
      });
    } catch (e) {
      const refused = refusedCreate(e, 'create_refused');
      if (refused) return refused;
      throw e;
    }
    return {
      status: 'done',
      resources: [accountRecordResource(record, dns, cname)],
      addresses: { hostname },
    };
  }
  // NS access: EdgeOne's own record for the name.
  const records = (await api.findDnsRecords(zoneId, hostname)).filter((r) => r.type === 'CNAME');
  const ours = records.find((r) => sameDnsName(r.content, cname));
  if (ours) {
    if (ours.status === 'disable') await api.enableDnsRecords(zoneId, [ours.id]);
    return {
      status: 'done',
      resources: [edgeOneRecordResource(zoneId, ours.id, hostname, cname, 'adopted')],
      addresses: { hostname },
    };
  }
  if (records.length > 0)
    return { status: 'partial', resources: [], code: 'dns_record_exists', refused: true };
  let id: string;
  try {
    id = await api.createDnsRecord(zoneId, {
      name: hostname,
      type: 'CNAME',
      content: cname,
      ...(ttl ? { ttl } : {}),
    });
  } catch (e) {
    const refused = refusedCreate(e, codeOf(e));
    if (refused) return refused;
    throw e;
  }
  return {
    status: 'done',
    resources: [edgeOneRecordResource(zoneId, id, hostname, cname, 'created')],
    addresses: { hostname },
  };
}

// --- the adapter -----------------------------------------------------------------------------

export const edgeOneProvider: EdgeProvider<EdgeOneConfig, EdgeOneTemplateParams> = {
  id: 'edgeone',
  templateSchema: EdgeOneTemplate,
  templateFields: EDGEONE_TEMPLATE_FIELDS,
  defaultTemplate: EdgeOneTemplate.parse({}),

  /**
   * The key lists its zones; with a zone at hand (a location's), it also
   * reads the zone's domains, settings and (NS access) records, the reads
   * every step needs. A key that may read but not write passes and is refused
   * at its first write; every refusal names the CAM action it needed.
   */
  async testCredentials(cfg): Promise<CredentialTestResult> {
    const api = edgeOneApiFor(cfg, 'test');
    try {
      const zones = await api.listZones();
      const detail = [`zones=${zones.items.length}${zones.truncated ? '+' : ''}`];
      if (cfg.zoneId) {
        const domains = await api.listDomains(cfg.zoneId);
        await api.zoneSettings(cfg.zoneId);
        // Every read the steps make: a zone EdgeOne hosts also has its records read.
        const zone = zones.items.find((z) => z.id === cfg.zoneId);
        if (zone?.type === 'full' && edgeOneDnsModeOf(cfg) === 'edgeone')
          await api.findDnsRecords(cfg.zoneId, caaProbeName(zone.name));
        detail.push(`domains=${domains.items.length}${domains.truncated ? '+' : ''}`);
      }
      return { ok: true, detail: detail.join('; '), observed: { site: cfg.site ?? 'intl' } };
    } catch (e) {
      return credentialTestFailure(e);
    }
  },

  async discoverOptions(partial) {
    const out: import('./types').DiscoverResult = {};
    try {
      const { items, truncated } = await edgeOneApiFor(
        partial as EdgeOneConfig,
        'zones',
      ).listZones();
      out.zones = items.map((z) => ({
        id: z.id,
        label: z.name,
        facts: {
          ...(z.status ? { status: z.paused ? 'paused' : z.status } : {}),
          ...(z.type
            ? { access: z.type === 'full' ? 'ns' : z.type === 'partial' ? 'cname' : z.type }
            : {}),
          ...(z.area ? { area: z.area } : {}),
        },
      }));
      if (truncated) out.truncated = ['zones'];
    } catch (e) {
      noteDiscoverError(out, 'zones', e);
    }
    return out;
  },

  /**
   * One location is usable: the key reads the EdgeOne zone (active, not
   * paused, the name the location recorded); its access mode matches the
   * location (NS access needs no DNS account, CNAME access needs one, whose
   * zone is the same domain); its CAA records let EdgeOne's free certificate
   * issue. Its service area, WebSocket and client-address settings are
   * recorded, never changed.
   */
  async checkLocation(cfg): Promise<LocationCheckResult> {
    const detail: string[] = [];
    try {
      const api = edgeOneApiFor(cfg, 'location');
      const zone = (await api.listZones(cfg.zoneId)).items.find((z) => z.id === cfg.zoneId);
      if (!zone)
        return { ok: false, code: 'zone_unreadable', detail: 'the key does not see this zone' };
      const observed: Record<string, string> = {
        zoneStatus: zone.paused ? 'paused' : (zone.status ?? 'unknown'),
        zoneAccess:
          zone.type === 'full'
            ? 'ns'
            : zone.type === 'partial'
              ? 'cname'
              : (zone.type ?? 'unknown'),
        ...(zone.area ? { zoneArea: zone.area } : {}),
      };
      const out = (code?: string): LocationCheckResult => ({
        ok: !code,
        ...(code ? { code } : {}),
        detail: detail.join(' '),
        observed,
        label: zone.name,
        zoneName: zone.name,
      });
      if (cfg.zoneName && zone.name !== normalizeZoneName(cfg.zoneName))
        return out('zone_name_mismatch');
      if (zone.paused) return out('zone_paused');
      // `ActiveStatus` is whether the site is in effect (a zone can be `active`
      // and not yet in effect): any value it reports but `active` refuses.
      if (zone.status !== 'active' || (zone.activeStatus && zone.activeStatus !== 'active'))
        return out('zone_not_active');
      const viaAccount = edgeOneDnsModeOf(cfg) === 'account';
      if (zone.type === 'partial' && !viaAccount) return out('zone_needs_dns_account');
      if (zone.type === 'full' && viaAccount) return out('zone_dns_at_edgeone');
      if (zone.type !== 'full' && zone.type !== 'partial') return out('zone_access_unsupported');
      if (viaAccount) {
        const dns = await dnsClientFor(cfg);
        const z = await dns.readZone();
        if (normalizeZoneName(z.name) !== zone.name) {
          detail.push('the DNS zone is another domain');
          return out('zone_name_mismatch');
        }
        if (z.paused || z.status !== 'active') return out('zone_not_active');
      }
      // A zone EdgeOne hosts: the DNS step reads its records; a key that may
      // not is refused here, before any front is half built.
      if (!viaAccount) await api.findDnsRecords(zone.id, caaProbeName(zone.name));
      const settings = await api.zoneSettings(zone.id);
      observed.edgeoneWebSocket = settings.webSocket ?? 'unknown';
      if (settings.webSocketTimeout !== undefined)
        observed.edgeoneWebSocketTimeout = String(settings.webSocketTimeout);
      if (settings.clientIpHeader) observed.edgeoneClientIpHeader = settings.clientIpHeader;
      if (settings.webSocket !== 'on')
        detail.push(
          'WebSocket is off for the zone: EdgeOne then closes a quiet tunnel after 15 s.',
        );
      if (settings.clientIpHeader === 'on')
        detail.push("The zone sends the member's address to the node in a header of its own.");
      const caa = await caaPreflight(cfg);
      Object.assign(observed, caa.observed);
      if (caa.refusal) {
        detail.push(caa.refusal.detail);
        return out('caa_forbids_ca');
      }
      return out();
    } catch (e) {
      const failed = credentialTestFailure(e);
      if (failed.code === 'error' || !(e instanceof EdgeProviderError) || e.meta.retryable) throw e;
      return { ok: false, code: failed.code, detail: failed.detail };
    }
  },

  planProvision(_cfg, spec, tpl) {
    assertEdgeOneOrigin(spec, tpl ?? {}, 'plan');
    return planSteps(spec);
  },

  async runStep(cfg, step, spec, tpl, ledger): Promise<StepOutcome> {
    const hostname = requireHostname(spec, step.id);
    switch (step.kind) {
      case 'create_service':
        return createDomain(cfg, spec, tpl);
      case 'create_dns_record':
        return writeTrafficRecord(cfg, spec, tpl, ledger);
      case 'create_tls_subscription':
        return requestCertificate(cfg, hostname);
      case 'await_tls':
        return awaitServing(cfg, hostname);
      default:
        throw refusal(step.id, 'unknown_step', `unknown step kind ${step.kind}`);
    }
  },

  /** The certificate request (until the name points at EdgeOne) and the wait for it to serve. */
  async pollStep(cfg, step, opRef): Promise<StepOutcome> {
    if (step.kind === 'create_tls_subscription') return requestCertificate(cfg, opRef);
    if (step.kind === 'await_tls') return awaitServing(cfg, opRef);
    throw refusal(step.id, 'unknown_step', 'not a polled step');
  },

  async discover(cfg, step, spec, ledger): Promise<Discovery> {
    const api = edgeOneApiFor(cfg);
    const hostname = spec.hostname ? normalizeZoneName(spec.hostname) : edgeOneHostnameOf(ledger);
    if (!hostname) return { status: 'confirmed_absent' };
    const zoneId = requireZone(cfg, step.id);
    switch (step.kind) {
      case 'create_service': {
        // The listing by exact name is authoritative: absent is safe to act on.
        const d = await api.getDomain(zoneId, hostname);
        if (!d) return { status: 'confirmed_absent' };
        if (dialsOrigin(d, spec))
          return { status: 'found', resources: [domainResource(d, 'adopted')] };
        return { status: 'ambiguous', candidates: [candidateOf(domainResource(d, 'adopted'))] };
      }
      case 'create_dns_record': {
        const own = ownDomainOf(ledger);
        const cnameMeta = metaOf(own).cname;
        const cname =
          typeof cnameMeta === 'string'
            ? cnameMeta
            : (await api.getDomain(zoneId, hostname))?.cname;
        if (!cname) return { status: 'confirmed_absent' };
        if (edgeOneDnsModeOf(cfg) === 'account') {
          const dns = await dnsClientFor(cfg);
          const records = await dns.findRecordsByName(hostname, 'CNAME');
          if (records.length === 0) return { status: 'confirmed_absent' };
          const ours = records.find((r) => r.comment === spec.name);
          if (!ours)
            return {
              status: 'ambiguous',
              candidates: records.map((r) => candidateOf(accountRecordResource(r, dns, cname))),
            };
          // Ours but pointing at an old target: not done, the step moves it.
          if (!sameDnsName(ours.content, cname)) return { status: 'confirmed_absent' };
          return {
            status: 'found',
            resources: [{ ...accountRecordResource(ours, dns, cname), ownership: 'adopted' }],
            addresses: { hostname },
          };
        }
        const records = (await api.findDnsRecords(zoneId, hostname)).filter(
          (r) => r.type === 'CNAME',
        );
        const ours = records.find((r) => sameDnsName(r.content, cname) && r.status !== 'disable');
        // A record switched off is the step's to switch on: not done yet.
        if (!ours) return { status: 'confirmed_absent' };
        return {
          status: 'found',
          resources: [edgeOneRecordResource(zoneId, ours.id, hostname, cname, 'adopted')],
          addresses: { hostname },
        };
      }
      case 'create_tls_subscription': {
        const d = await api.getDomain(zoneId, hostname);
        // Asking again is harmless: absent until EdgeOne says the free certificate is the mode.
        return d?.certificateMode === 'eofreecert'
          ? { status: 'found', resources: [certificateResource(zoneId, hostname)] }
          : { status: 'confirmed_absent' };
      }
      case 'await_tls': {
        const d = await api.getDomain(zoneId, hostname);
        return d && certificateState(d) === 'ready' && d.status === 'online'
          ? { status: 'found', resources: [], addresses: { hostname } }
          : { status: 'unresolved' };
      }
      default:
        return { status: 'confirmed_absent' };
    }
  },

  async describe(cfg, ledger): Promise<EdgeDescription> {
    const own = ownDomainOf(ledger);
    if (!own) return { state: 'pending', addresses: {}, health: 'unknown', code: 'no_service_yet' };
    const hostname = edgeOneHostnameOf(ledger)!;
    const api = edgeOneApiFor(cfg);
    const d = await api.getDomain(requireZone(cfg, 'describe'), hostname);
    if (!d) return { state: 'gone', addresses: {}, health: 'unknown' };
    const readiness: EdgeReadiness = {
      dns: await trafficRecordPoints(cfg, api, hostname, d.cname),
      certificate: certificateState(d),
    };
    const online = d.status === 'online';
    const ready = readiness.dns === 'ready' && readiness.certificate === 'ready' && online;
    const code =
      readiness.certificate === 'failed'
        ? 'tls_failed'
        : d.restrictions.length > 0
          ? 'domain_restricted'
          : !online
            ? 'domain_not_activated'
            : undefined;
    return {
      state: readiness.certificate === 'failed' ? 'error' : ready ? 'active' : 'pending',
      addresses: { hostname },
      // DNS and certificate say nothing about the origin (memberHealth false).
      health: 'unknown',
      ...(code ? { code } : {}),
      readiness,
    };
  },

  async inspect(cfg, ledger): Promise<InspectResult> {
    const hostname = edgeOneHostnameOf(ledger);
    if (!hostname) throw refusal('inspect', 'ledger_incomplete', 'no acceleration domain yet');
    const d = await domainOrThrow(
      edgeOneApiFor(cfg),
      requireZone(cfg, 'inspect'),
      hostname,
      'inspect',
    );
    const tls = d.originProtocol === 'HTTPS';
    return {
      summary: {
        ...(d.status ? { status: d.status } : {}),
        addresses: { hostname },
        members: d.origin
          ? [{ address: d.origin, port: (tls ? d.httpsPort : d.httpPort) ?? (tls ? 443 : 80) }]
          : [],
        listeners: [{ port: 443, protocol: 'https' }],
      },
      // The domain as read: it carries no credentials.
      raw: { domain: d },
    };
  },

  async inventory(cfg): Promise<Inventory> {
    const { items } = await edgeOneApiFor(cfg).listDomains(requireZone(cfg, 'inventory'));
    return {
      loadBalancers: items.map((d) => ({
        id: d.name,
        name: d.name,
        status: d.status ?? 'unknown',
        addresses: { hostname: d.name },
        hostnames: [d.name],
        ...(d.origin ? { content: d.origin } : {}),
      })),
      ips: [],
      flavors: [],
    };
  },

  /**
   * Destroy order by kind: a DNS account's record first, so no member is sent
   * to a front being dismantled; the domain (its certificate goes with it);
   * then whatever EdgeOne's own DNS still holds at the name. A candidate
   * discovery could not prove is this edge's is never destroyed.
   */
  planDestroy(_cfg, ledger) {
    const live = ledger.resources.filter(
      (r) => r.deleteState !== 'confirmed_gone' && metaOf(r).candidate !== true,
    );
    return [...live]
      .reverse()
      .map((r, i) => ({ r, i }))
      .sort((a, b) => destroyRank(a.r) - destroyRank(b.r) || a.i - b.i)
      .map((x) => x.r);
  },

  /**
   * Every delete answers at once; the dispatcher runs this again to confirm,
   * and a resource no longer there is `confirmed_gone`.
   */
  async runDestroy(cfg, r, ledger) {
    if (metaOf(r).candidate === true) return { status: 'confirmed_gone' };
    const meta = metaOf(r);
    try {
      switch (edgeOneDestroyKey(r)) {
        case 'dns_record:account': {
          const dns = await dnsClientFor(cfg);
          const id = typeof meta.recordId === 'string' ? meta.recordId : r.resourceId;
          if ((await dns.getRecord(id)) === null) return { status: 'confirmed_gone' };
          await dns.deleteRecord(id);
          return { status: 'delete_requested' };
        }
        case 'acceleration_domain': {
          const api = edgeOneApiFor(cfg);
          const zoneId =
            typeof meta.zoneId === 'string' ? meta.zoneId : requireZone(cfg, 'destroy');
          if (!(await api.getDomain(zoneId, r.resourceId))) return { status: 'confirmed_gone' };
          await api.deleteDomain(zoneId, r.resourceId);
          return { status: 'delete_requested' };
        }
        case 'tls_subscription':
          // Part of the domain: gone once the domain is.
          return ownDomainOf(ledger) ? { status: 'unresolved' } : { status: 'confirmed_gone' };
        case 'dns_record:edgeone': {
          // After the domain: whatever EdgeOne's DNS still holds at the name
          // pointing at the domain's CNAME target (a record FCP wrote, or one
          // EdgeOne left).
          if (ownDomainOf(ledger)) return { status: 'unresolved' };
          const api = edgeOneApiFor(cfg);
          const zoneId =
            typeof meta.zoneId === 'string' ? meta.zoneId : requireZone(cfg, 'destroy');
          const name = typeof meta.name === 'string' ? meta.name : '';
          const cname = typeof meta.cname === 'string' ? meta.cname : '';
          const left = (await api.findDnsRecords(zoneId, name)).filter(
            (x) => x.type === 'CNAME' && sameDnsName(x.content, cname),
          );
          if (left.length === 0) return { status: 'confirmed_gone' };
          await api.deleteDnsRecords(
            zoneId,
            left.map((x) => x.id),
          );
          return { status: 'delete_requested' };
        }
        default:
          return { status: 'unresolved' };
      }
    } catch (e) {
      if (isEdgeOneNotFound(e)) return { status: 'confirmed_gone' };
      throw e;
    }
  },
};

// --- destroy ordering --------------------------------------------------------------------------

/** Destroy order by kind (the DNS record by where it lives). */
export const EDGEONE_DESTROY_ORDER = [
  'dns_record:account',
  'acceleration_domain',
  'tls_subscription',
  'dns_record:edgeone',
] as const;

export function edgeOneDestroyKey(r: LedgerResource): string {
  if (r.kind !== 'dns_record') return r.kind;
  return metaOf(r).via === 'edgeone' ? 'dns_record:edgeone' : 'dns_record:account';
}

function destroyRank(r: LedgerResource): number {
  const i = (EDGEONE_DESTROY_ORDER as readonly string[]).indexOf(edgeOneDestroyKey(r));
  return i === -1 ? EDGEONE_DESTROY_ORDER.length : i;
}
