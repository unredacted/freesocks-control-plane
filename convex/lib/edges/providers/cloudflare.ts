/**
 * Cloudflare L7 edge adapter.
 *
 * An edge is ONE proxied DNS record in the account's zone: clients reach the
 * CDN on 443 with SNI = the minted hostname, the CDN terminates TLS and dials
 * the relay origin. Two resource kinds:
 *
 *  - `dns_record`: the proxied A/AAAA/CNAME carrying the edge hostname. Its
 *    `comment` is the ownership marker (`<prefix>:<spec.name>`), which is what
 *    discovery proves ownership with. `tags` are not available on Free plans
 *    and comments are capped at 100 characters there, so the comment is the
 *    only marker this adapter relies on.
 *  - `origin_rule`: an Origin Rule (`http_request_origin` phase) overriding the
 *    destination port, needed ONLY when the relay's origin port is not the
 *    zone encryption mode's effective default. Cloudflare dials port 80 for a
 *    `flexible` zone and 443 for `full`/`strict`; the client-facing port is
 *    always 443, so the incoming proxied-port allowlist never applies here.
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
  CloudflareConfig,
  CloudflareDnsConfig,
  DiscoverResult,
  EdgeDescription,
  EdgeProvider,
  EdgeSpec,
  InspectResult,
  Inventory,
  LedgerResource,
  ReadinessState,
  ResourceStep,
  StepOutcome,
} from './types';
import { firstResource, metaOf, orderByKind } from './types';
import { EdgeProviderError } from './http';
import { addressFamily } from '../ip';
import { isFirstLevelUnder } from '../hostname';
import {
  cfCall,
  cloudflareApi,
  cloudflareClient,
  cloudflareDnsClient,
  isCloudflareNotFound,
  normalizeDnsName,
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

/** Ledger resource kinds this adapter owns, in destroy order (rule before record). */
export const CLOUDFLARE_DESTROY_ORDER = ['origin_rule', 'dns_record'] as const;

/** The Origin Rules phase; a zone has exactly one entry point ruleset per phase. */
const ORIGIN_PHASE = 'http_request_origin';
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
 * the mode is not read from the API here: the orchestrator freezes it into the
 * edge's provisionIntent and passes it through as a rendered template param.
 * A slot whose origin speaks plaintext HTTP implies `flexible`; otherwise the
 * conservative default is `full` (encrypted origin on 443).
 */
export function zoneSslModeOf(spec: EdgeSpec, tpl: CloudflareTemplateParams): ZoneSslMode {
  const raw = (tpl as unknown as Record<string, unknown>).zoneSslMode;
  if (raw === 'flexible' || raw === 'full' || raw === 'strict') return raw;
  if (spec.originTransport?.scheme === 'http') return 'flexible';
  return 'full';
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
  action_parameters?: { origin?: { port?: number } };
}

/** A ruleset as the phase/rule endpoints return it. */
interface RawRuleset {
  id?: string;
  rules?: RawRule[];
}

async function getOriginPhase(cfg: CloudflareConfig, step: string): Promise<RawRuleset | null> {
  try {
    const phase = await cfCall(step, () =>
      cloudflareClient(cfg).rulesets.phases.get(ORIGIN_PHASE, { zone_id: cfg.zoneId }),
    );
    return phase as unknown as RawRuleset;
  } catch (e) {
    // No entry point ruleset exists for the phase yet.
    if (isCloudflareNotFound(e)) return null;
    throw e;
  }
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
 * failure: a missing read must not fail an otherwise healthy edge.
 */
async function certificateReadiness(
  cfg: CloudflareConfig,
  hostname: string,
): Promise<{ state: ReadinessState; packs: CertPack[] }> {
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
    const covered = packs.some(
      (p) =>
        p.status === 'active' &&
        (p.hosts ?? []).some((h) => {
          const n = normalizeDnsName(h);
          return n === hostname || n === wildcard;
        }),
    );
    return { state: covered ? 'ready' : 'pending', packs };
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

// --- the adapter ---------------------------------------------------------------------

export const cloudflareProvider: EdgeProvider<CloudflareConfig, CloudflareTemplateParams> = {
  id: 'cloudflare',
  templateSchema: CloudflareTemplate,
  templateFields: CLOUDFLARE_TEMPLATE_FIELDS,
  defaultTemplate: CloudflareTemplate.parse({}),

  /**
   * Token works and is active, the zone is usable, and the soft preconditions
   * are reported as short codes in `detail` (never as free text from the API).
   * The zone's `ssl` mode is RECORDED, not required: `flexible|full|strict` are
   * all usable and the feasibility check against a slot's origin transport
   * happens at plan time, not here. Only `off` is refused outright.
   */
  async testCredentials(cfg) {
    const detail: string[] = [];
    try {
      const token = await cfCall('test', () => cloudflareClient(cfg).user.tokens.verify());
      if (token.status !== 'active') return { ok: false, code: 'token_not_active' };
      const zone = await cfCall('test', () =>
        cloudflareClient(cfg).zones.get({ zone_id: cfg.zoneId }),
      );
      const ssl = await zoneSetting(cfg, 'ssl', 'test');
      const websockets = await zoneSetting(cfg, 'websockets', 'test');
      if (ssl) detail.push(`ssl_${ssl}`);
      else detail.push('ssl_unknown');
      if (websockets === 'on') detail.push('websockets_on');
      else if (websockets === null) detail.push('websockets_unknown');
      else detail.push('websockets_off');
      // Free zones cap DNS comments and Origin Rules; useful for the operator.
      if ((zone.plan as { legacy_id?: string } | undefined)?.legacy_id === 'free')
        detail.push('plan_free');
      if (ssl === 'off') return { ok: false, code: 'zone_ssl_off', detail: detail.join(' ') };
      if (zone.paused === true) {
        detail.push('zone_paused');
        return { ok: false, code: 'zone_paused', detail: detail.join(' ') };
      }
      if (zone.status !== 'active') {
        detail.push('zone_not_active');
        return { ok: false, code: 'zone_not_active', detail: detail.join(' ') };
      }
      return { ok: true, detail: detail.join(' ') };
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

  /** Cloudflare has no regions; the account's "region" choice is its DNS zone. */
  async listRegions(cfg) {
    const page = await cfCall('zones', () => cloudflareClient(cfg).zones.list({ per_page: 50 }));
    return page.result.map((z) => ({ id: z.id, label: z.name }));
  },

  async discoverOptions(partial): Promise<DiscoverResult> {
    const apiToken = typeof partial.apiToken === 'string' ? partial.apiToken : '';
    if (!apiToken) return {};
    try {
      const page = await cfCall('zones', () =>
        cloudflareClient({ apiToken }).zones.list({ per_page: 50 }),
      );
      return { zones: page.result.map((z) => ({ id: z.id, label: z.name })) };
    } catch (e) {
      const code =
        e instanceof EdgeProviderError
          ? (e.meta.code ?? String(e.meta.status ?? 'error'))
          : 'error';
      return { errors: { zones: code } };
    }
  },

  /**
   * Pure: one DNS record, plus an Origin Rule only when the origin port is not
   * the zone mode's effective default.
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
        const rule = cloudflareOriginRule(spec, originPort);
        const phase = await getOriginPhase(cfg, step.id);
        let ruleset: RawRuleset;
        if (!phase?.id) {
          // No entry point ruleset for the phase yet: creating it with our one
          // rule IS the create. The zone lock the orchestrator holds is what
          // keeps a concurrent edge from replacing a ruleset created meanwhile.
          const created = await cfCall(step.id, () =>
            cloudflareClient(cfg).rulesets.phases.update(ORIGIN_PHASE, {
              zone_id: cfg.zoneId,
              name: 'default',
              rules: [rule as never],
            }),
          );
          ruleset = created as unknown as RawRuleset;
        } else {
          const updated = await cfCall(step.id, () =>
            cloudflareClient(cfg).rulesets.rules.create(
              phase.id as string,
              {
                zone_id: cfg.zoneId,
                ...rule,
              } as never,
            ),
          );
          ruleset = updated as unknown as RawRuleset;
        }
        // Both endpoints answer with the WHOLE ruleset: ours is the one with our ref.
        const mine = findRuleByRef(ruleset, spec.name);
        if (!mine?.id) return { status: 'partial', resources: [], code: 'rule_not_returned' };
        return {
          status: 'done',
          resources: [
            {
              kind: 'origin_rule',
              resourceId: mine.id,
              ownership: 'created',
              meta: { rulesetId: ruleset.id ?? phase?.id ?? '' },
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
   * for adopted records) AND the content matching the relay origin: a record
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
      case 'create_origin_rule': {
        const phase = await getOriginPhase(cfg, step.id);
        if (!phase) return { status: 'confirmed_absent' };
        const mine = findRuleByRef(phase, spec.name);
        if (!mine?.id) return { status: 'confirmed_absent' };
        return {
          status: 'found',
          resources: [
            {
              kind: 'origin_rule',
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
    // An unproxied record hands members the ORIGIN address: an error, not a wait.
    const state: EdgeDescription['state'] = !record.proxied
      ? 'error'
      : cert.state === 'ready'
        ? 'active'
        : 'pending';
    return {
      state,
      addresses: { hostname },
      // memberHealth is false for this provider: a DNS record says nothing
      // about whether the origin is up, so health is never claimed.
      health: 'unknown',
      ...(record.proxied ? {} : { code: 'unproxied' }),
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

  planDestroy: (_cfg, ledger): LedgerResource[] => orderByKind(ledger, CLOUDFLARE_DESTROY_ORDER),

  /**
   * Both deletes are synchronous and idempotent, so there is no
   * `confirmDestroyed` (capability `asyncDelete: false`): a 404 IS the
   * confirmation. An unknown kind stays `unresolved` and parks the edge.
   */
  async runDestroy(cfg, r) {
    switch (r.kind) {
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

/** The ledger kinds this adapter creates (the wire-contract table reads them). */
export const CLOUDFLARE_RESOURCE_KINDS = ['dns_record', 'origin_rule'] as const;
