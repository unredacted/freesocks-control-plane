/**
 * UpCloud Managed Load Balancer adapter (API 1.3). Hand-rolled: the only npm
 * SDK is archived and predates the load-balancer product.
 *
 * Model: `POST /1.3/load-balancer` creates the service with its TCP frontend +
 * backend inline (synchronous; the service then reaches `operational_state:
 * running` in the background). The service's own public address is documented
 * as NOT stable, so by default a floating IPv4 is allocated and delegated to
 * the service and THAT is the published address. Public networks are IPv4-only.
 *
 * Discovery: the service list, read page by page, is authoritative (found /
 * confirmed_absent by exact name). Floating IPs carry no name or tag, so an
 * unknown-outcome allocation is `ambiguous` whenever the account holds any
 * unattached floating IPv4 in the zone (an operator adopts or releases it), and
 * `confirmed_absent` when it holds none. Absent only on a second quiet look
 * past the settle floor (`discoverySettleMs`): a create that outlived its
 * timeout can still land.
 *
 * Deletes are synchronous HTTP calls but the service tears down in the
 * background, so a 2xx is reported as `delete_requested` and the dispatcher
 * re-issues the idempotent DELETE until it answers 404 (`confirmed_gone`).
 * Destroy order is by kind: the service first, then the floating IP delegated
 * to it. The API exposes no per-member health, so a running service reports
 * `unknown` (never `online`) — see `memberHealth` in capabilities.ts.
 *
 * Each step is one request, so a create the API refuses for good (a 4xx
 * validation error, a quota) built nothing: the run stops on `create_refused`
 * with the provider's words (`refusedCreate`).
 */
import { z } from 'zod';
import type {
  DiscoverResult,
  ChildResource,
  Discovery,
  EdgeDescription,
  EdgeSpec,
  EdgeProvider,
  ResourceStep,
  StepOutcome,
  UpcloudConfig,
} from './types';
import { firstResource, metaOf, orderByKind, stepOf } from './types';
import { discoveryMaySettle } from './capabilities';
import {
  isProviderNotFound,
  providerFetch,
  EdgeProviderError,
  credentialTestFailure,
  noteDiscoverError,
  refusedCreate,
} from './http';
import {
  EDGE_TEMPLATES,
  UpcloudTemplate,
  UPCLOUD_TEMPLATE_FIELDS,
  type UpcloudTemplateParams,
} from './templates';
import { wireBody } from './options';
import type { ProviderPlan } from '../pricing';

const BASE = 'https://api.upcloud.com/1.3';

export { UpcloudTemplate, UPCLOUD_TEMPLATE_FIELDS } from './templates';
export type { UpcloudTemplateParams } from './templates';

// --- schemas ------------------------------------------------------------------------

const IpAddr = z.object({ address: z.string(), listen: z.boolean().nullish() }).passthrough();
const Lb = z
  .object({
    uuid: z.string(),
    name: z.string().nullish(),
    plan: z.string().nullish(),
    zone: z.string().nullish(),
    operational_state: z.string().nullish(),
    created_at: z.string().nullish(),
    networks: z
      .array(
        z
          .object({
            name: z.string().nullish(),
            type: z.string().nullish(),
            dns_name: z.string().nullish(),
          })
          .passthrough(),
      )
      .nullish(),
    nodes: z
      .array(
        z
          .object({
            operational_state: z.string().nullish(),
            networks: z
              .array(
                z
                  .object({ type: z.string().nullish(), ip_addresses: z.array(IpAddr).nullish() })
                  .passthrough(),
              )
              .nullish(),
          })
          .passthrough(),
      )
      .nullish(),
    frontends: z
      .array(z.object({ port: z.number().nullish(), mode: z.string().nullish() }).passthrough())
      .nullish(),
    backends: z
      .array(
        z
          .object({
            members: z
              .array(
                z.object({ ip: z.string().nullish(), port: z.number().nullish() }).passthrough(),
              )
              .nullish(),
          })
          .passthrough(),
      )
      .nullish(),
  })
  .passthrough();
const LbList = z.array(Lb);
const FloatingIpCreate = z.object({ ip_address: z.object({ address: z.string() }).passthrough() });
const IpAddressList = z.object({
  ip_addresses: z.object({
    ip_address: z
      .array(
        z
          .object({
            address: z.string(),
            floating: z.string().nullish(),
            family: z.string().nullish(),
            zone: z.string().nullish(),
            server: z.string().nullish(),
          })
          .passthrough(),
      )
      .default([]),
  }),
});
const ZoneList = z.object({
  zones: z.object({
    zone: z
      .array(z.object({ id: z.string(), description: z.string().nullish() }).passthrough())
      .default([]),
  }),
});
/**
 * One plan of `GET /1.3/load-balancer/plans`, which answers a bare JSON array
 * (paged: `limit` 10 by default, at most 100). Only `name` is needed; the
 * label's facts are kept when they are numbers, and fields UpCloud adds are
 * carried along unread.
 */
const PlanRow = z
  .object({
    name: z.string().trim().min(1),
    server_number: z.number().nullish().catch(null),
    per_server_max_sessions: z.number().nullish().catch(null),
  })
  .passthrough();
export type UpcloudPlanRow = z.infer<typeof PlanRow>;
/**
 * `GET /1.3/price`: `prices.zone[]`, one object per zone, its `name` and every
 * priced item as `{ amount, price }` (price in cents an hour for `amount`
 * units). A zone entry of another shape is skipped, not fatal.
 */
const PriceList = z
  .object({
    prices: z
      .object({
        zone: z.array(z.unknown()).default([]),
        /** Not in UpCloud's documented example; taken when an answer carries it. */
        currency: z.string().nullish().catch(null),
      })
      .passthrough(),
  })
  .passthrough();
const PriceZone = z.object({ name: z.string() }).catchall(z.unknown());
/** `GET /1.3/account` (the key's own account) and `GET /1.3/account/details/{username}` (its currency). */
const AccountSelf = z
  .object({ account: z.object({ username: z.string() }).passthrough() })
  .passthrough();
const AccountDetails = z
  .object({ account: z.object({ currency: z.string().nullish() }).passthrough() })
  .passthrough();
const PriceItem = z
  .object({ amount: z.number().nullish().catch(null), price: z.number() })
  .passthrough();

// --- helpers -------------------------------------------------------------------------

function headers(cfg: UpcloudConfig): Record<string, string> {
  return { authorization: `Bearer ${cfg.token}` };
}

async function up<T>(
  cfg: UpcloudConfig,
  step: string,
  method: 'GET' | 'POST' | 'DELETE' | 'PATCH',
  path: string,
  schema: z.ZodType<T>,
  body?: unknown,
  okStatuses?: number[],
): Promise<T> {
  return providerFetch({
    provider: 'upcloud',
    step,
    url: `${BASE}${path}`,
    method,
    headers: headers(cfg),
    body,
    schema,
    okStatuses,
  });
}

/** The create-service body (exported for tests). */
export function upcloudLbBody(cfg: UpcloudConfig, spec: EdgeSpec, tpl: UpcloudTemplateParams) {
  return {
    name: spec.name,
    plan: tpl.plan,
    zone: cfg.zone,
    configured_status: 'started',
    ...wireBody(EDGE_TEMPLATES.upcloud.fields, 'loadbalancer', tpl),
    networks: [{ name: 'public', type: 'public', family: 'IPv4' }],
    frontends: spec.listeners.map((l, i) => ({
      name: `tcp-${l.edgePort}${i > 0 ? `-${i}` : ''}`,
      mode: 'tcp',
      port: l.edgePort,
      default_backend: `origin-${l.edgePort}`,
      networks: [{ name: 'public' }],
      properties: { timeout_client: tpl.timeoutClient },
    })),
    backends: spec.listeners.map((l) => ({
      name: `origin-${l.edgePort}`,
      members: l.members.map((m, j) => ({
        name: `member-${j}`,
        type: 'static',
        ip: m.address,
        port: m.port,
        weight: 100,
        max_sessions: tpl.maxSessions ?? 1000,
        enabled: true,
      })),
      properties: {
        timeout_server: tpl.timeoutServer,
        timeout_tunnel: tpl.timeoutTunnel,
        health_check_type: 'tcp',
        health_check_interval: tpl.healthCheck.interval,
        health_check_fall: tpl.healthCheck.fall,
        health_check_rise: tpl.healthCheck.rise,
        ...(tpl.closeOnFailure ? { health_check_on_down: 'shutdown-sessions' } : {}),
      },
    })),
    ...(tpl.labels.length > 0 ? { labels: tpl.labels } : {}),
  };
}

function lbState(lb: z.infer<typeof Lb>): EdgeDescription['state'] {
  const s = (lb.operational_state ?? '').toLowerCase();
  if (s === 'running') return 'active';
  if (s === 'error') return 'error';
  return 'pending';
}

function nodePublicV4(lb: z.infer<typeof Lb>): string | undefined {
  for (const n of lb.nodes ?? []) {
    for (const net of n.networks ?? []) {
      if ((net.type ?? '') !== 'public') continue;
      for (const ip of net.ip_addresses ?? []) if (ip.address.includes('.')) return ip.address;
    }
  }
  return undefined;
}

/** The page size of the service list (UpCloud answers 10 by default, at most 100). */
const LB_PAGE = 100;

/**
 * Every service of the account, page by page: the list answers 10 services
 * unless asked for more, so one unpaged look misses the rest (a discovery
 * would call a created service absent and create it again).
 */
async function listLbs(cfg: UpcloudConfig, step: string): Promise<z.infer<typeof LbList>> {
  const out: z.infer<typeof LbList> = [];
  for (let offset = 0; ; offset += LB_PAGE) {
    const page = await up(
      cfg,
      step,
      'GET',
      `/load-balancer?limit=${LB_PAGE}&offset=${offset}`,
      LbList,
    );
    out.push(...page);
    if (page.length < LB_PAGE) return out;
  }
}

/**
 * The plan list's answer as plans (exported for tests): a list of named
 * plans, else `plan_list_unreadable` saying what is missing. A size is never
 * guessed from an answer that does not name it.
 */
export function upcloudPlanListOf(answer: unknown, step = 'plans'): UpcloudPlanRow[] {
  const unreadable = (why: string) =>
    new EdgeProviderError(`upcloud plan list unreadable on ${step}: ${why}`, {
      provider: 'upcloud',
      step,
      code: 'plan_list_unreadable',
      retryable: false,
      timedOut: false,
    });
  if (!Array.isArray(answer)) throw unreadable('the answer is not a list');
  return answer.map((raw, i) => {
    const row = PlanRow.safeParse(raw);
    if (!row.success) throw unreadable(`plan ${i + 1} has no name`);
    return row.data;
  });
}

/** Every load balancer plan, page by page (the list answers 10 unless asked for more). */
async function listPlans(cfg: UpcloudConfig, step: string): Promise<UpcloudPlanRow[]> {
  const out: UpcloudPlanRow[] = [];
  for (let offset = 0; ; offset += LB_PAGE) {
    const answer = await up(
      cfg,
      step,
      'GET',
      `/load-balancer/plans?limit=${LB_PAGE}&offset=${offset}`,
      z.unknown(),
    );
    const page = upcloudPlanListOf(answer, step);
    out.push(...page);
    if (page.length < LB_PAGE) return out;
  }
}

function getLb(cfg: UpcloudConfig, step: string, uuid: string) {
  return up(cfg, step, 'GET', `/load-balancer/${encodeURIComponent(uuid)}`, Lb);
}

// --- the adapter -------------------------------------------------------------------------

async function upcloudZones(cfg: UpcloudConfig): Promise<Array<{ id: string; label: string }>> {
  const z = await up(cfg, 'zones', 'GET', `/zone`, ZoneList);
  return z.zones.zone.map((x) => ({ id: x.id, label: x.description ?? x.id }));
}

export const upcloudProvider: EdgeProvider<UpcloudConfig, UpcloudTemplateParams> = {
  id: 'upcloud',
  templateSchema: UpcloudTemplate,
  templateFields: UPCLOUD_TEMPLATE_FIELDS,
  defaultTemplate: UpcloudTemplate.parse({}),

  async testCredentials(cfg) {
    try {
      await up(cfg, 'test', 'GET', `/account`, z.unknown());
      return { ok: true };
    } catch (e) {
      return credentialTestFailure(e);
    }
  },

  listRegions: (cfg) => upcloudZones(cfg),

  /** Only the zone is a choice; the token alone lists them. */
  async discoverOptions(
    partial: Partial<UpcloudConfig> & Record<string, unknown>,
  ): Promise<DiscoverResult> {
    try {
      return { regions: await upcloudZones(partial as UpcloudConfig) };
    } catch (e) {
      const out: DiscoverResult = {};
      noteDiscoverError(out, 'regions', e);
      return out;
    }
  },

  planProvision(_cfg, spec, tpl) {
    const steps: ResourceStep[] = [
      { id: 'lb', kind: 'create_lb', resourceName: spec.name, discoverability: 'by_name' },
    ];
    if (tpl.delegateFloatingIp) {
      steps.push({
        id: 'ip',
        kind: 'allocate_ip',
        resourceName: spec.name,
        discoverability: 'none',
      });
      steps.push({
        id: 'attach',
        kind: 'attach_ip',
        resourceName: spec.name,
        discoverability: 'by_name',
      });
    }
    return steps;
  },

  async runStep(cfg, step, spec, tpl, ledger): Promise<StepOutcome> {
    switch (step.kind) {
      case 'create_lb': {
        let lb: z.infer<typeof Lb>;
        try {
          lb = await up(cfg, step.id, 'POST', `/load-balancer`, Lb, upcloudLbBody(cfg, spec, tpl));
        } catch (e) {
          const refused = refusedCreate(e, 'create_refused');
          if (refused) return refused;
          throw e;
        }
        return {
          status: 'done',
          resources: [{ kind: 'lb', resourceId: lb.uuid, ownership: 'created' }],
        };
      }
      case 'allocate_ip': {
        let res: z.infer<typeof FloatingIpCreate>;
        try {
          res = await up(cfg, step.id, 'POST', `/ip_address`, FloatingIpCreate, {
            ip_address: { zone: cfg.zone, floating: 'yes', family: 'IPv4' },
          });
        } catch (e) {
          const refused = refusedCreate(e, 'create_refused');
          if (refused) return refused;
          throw e;
        }
        const address = res.ip_address.address;
        return {
          status: 'done',
          resources: [
            { kind: 'floating_ip', resourceId: address, ownership: 'created', meta: { address } },
          ],
          addresses: { v4: address },
        };
      }
      case 'attach_ip': {
        const lb = firstResource(ledger, 'lb');
        const ip = firstResource(ledger, 'floating_ip');
        if (!lb || !ip)
          throw new EdgeProviderError('upcloud attach_ip: missing lb or floating ip', {
            provider: 'upcloud',
            step: step.id,
            code: 'ledger_incomplete',
            retryable: false,
            timedOut: false,
          });
        try {
          await up(
            cfg,
            step.id,
            'POST',
            `/load-balancer/${encodeURIComponent(lb.resourceId)}/ip-addresses`,
            z.unknown(),
            // The address and the service network it listens on (the public one
            // the create body names).
            { address: ip.resourceId, network_name: 'public' },
          );
        } catch (e) {
          const refused = refusedCreate(e, 'create_refused');
          if (refused) return refused;
          throw e;
        }
        return { status: 'done', resources: [], addresses: { v4: ip.resourceId } };
      }
      default:
        throw new EdgeProviderError(`upcloud: unknown step kind ${step.kind}`, {
          provider: 'upcloud',
          step: step.id,
          code: 'unknown_step',
          retryable: false,
          timedOut: false,
        });
    }
  },

  async discover(cfg, step, spec, ledger, attempt) {
    // A create that outlived its timeout can still land: an empty listing
    // proves nothing until a second look past the settle floor.
    const absent = (): Discovery =>
      discoveryMaySettle('upcloud', attempt, stepOf(ledger, step.id)?.startedAt)
        ? { status: 'confirmed_absent' }
        : { status: 'unresolved' };
    switch (step.kind) {
      case 'create_lb': {
        const list = await listLbs(cfg, step.id);
        const hit = list.find((l) => l.name === spec.name);
        return hit
          ? {
              status: 'found',
              resources: [{ kind: 'lb', resourceId: hit.uuid, ownership: 'adopted' }],
            }
          : absent();
      }
      case 'allocate_ip': {
        const list = await up(cfg, step.id, 'GET', `/ip_address`, IpAddressList);
        const candidates: ChildResource[] = list.ip_addresses.ip_address
          .filter(
            (ip) =>
              (ip.floating ?? '').toLowerCase() === 'yes' &&
              !ip.server &&
              (ip.family ?? 'IPv4') === 'IPv4' &&
              (!ip.zone || ip.zone === cfg.zone),
          )
          .map((ip) => ({
            kind: 'floating_ip',
            resourceId: ip.address,
            ownership: 'adopted',
            meta: { address: ip.address },
          }));
        return candidates.length === 0 ? absent() : { status: 'ambiguous', candidates };
      }
      case 'attach_ip': {
        const lb = firstResource(ledger, 'lb');
        const ip = firstResource(ledger, 'floating_ip');
        if (!lb || !ip) return { status: 'confirmed_absent' };
        const obj = await getLb(cfg, step.id, lb.resourceId);
        const attached = (obj.nodes ?? []).some((n) =>
          (n.networks ?? []).some((net) =>
            (net.ip_addresses ?? []).some((a) => a.address === ip.resourceId),
          ),
        );
        return attached
          ? { status: 'found', resources: [], addresses: { v4: ip.resourceId } }
          : { status: 'confirmed_absent' };
      }
      default:
        return { status: 'confirmed_absent' };
    }
  },

  async describe(cfg, ledger) {
    const lb = firstResource(ledger, 'lb');
    if (!lb) return { state: 'pending', addresses: {}, health: 'unknown', code: 'no_lb_yet' };
    let obj: z.infer<typeof Lb>;
    try {
      obj = await getLb(cfg, 'describe', lb.resourceId);
    } catch (e) {
      if (isProviderNotFound(e)) return { state: 'gone', addresses: {}, health: 'unknown' };
      throw e;
    }
    const state = lbState(obj);
    const fip = firstResource(ledger, 'floating_ip');
    const attachDone = ledger.steps.some((s) => s.kind === 'attach_ip' && s.state === 'done');
    const v4 =
      fip && attachDone ? String(metaOf(fip).address ?? fip.resourceId) : nodePublicV4(obj);
    // No member/backend health on the wire: a running service whose nodes all
    // run is `unknown` (never `online`); a node not running degrades it.
    const nodeStates = (obj.nodes ?? []).map((n) => (n.operational_state ?? '').toLowerCase());
    const health: EdgeDescription['health'] =
      state !== 'active'
        ? 'unknown'
        : nodeStates.some((n) => n === 'error')
          ? 'offline'
          : nodeStates.some((n) => n !== '' && n !== 'running')
            ? 'degraded'
            : 'unknown';
    return {
      state,
      addresses: v4 ? { v4 } : {},
      health,
      ...(fip && !attachDone && ledger.steps.some((s) => s.kind === 'attach_ip')
        ? { code: 'floating_ip_not_attached' }
        : {}),
    };
  },

  async inspect(cfg, ledger) {
    const lb = firstResource(ledger, 'lb');
    if (!lb)
      throw new EdgeProviderError('upcloud inspect: no lb in ledger', {
        provider: 'upcloud',
        step: 'inspect',
        code: 'no_lb',
        retryable: false,
        timedOut: false,
      });
    const obj = await getLb(cfg, 'inspect', lb.resourceId);
    const fip = firstResource(ledger, 'floating_ip');
    return {
      summary: {
        status: obj.operational_state ?? undefined,
        flavor: obj.plan ?? undefined,
        region: obj.zone ?? cfg.zone,
        createdAt: obj.created_at ?? undefined,
        addresses: { v4: fip?.resourceId ?? nodePublicV4(obj) },
        members: (obj.backends ?? []).flatMap((b) =>
          (b.members ?? []).flatMap((m) =>
            m.ip && m.port ? [{ address: m.ip, port: m.port }] : [],
          ),
        ),
        listeners: (obj.frontends ?? []).flatMap((f) =>
          f.port ? [{ port: f.port, protocol: f.mode ?? undefined }] : [],
        ),
      },
      raw: obj,
    };
  },

  async inventory(cfg) {
    const [lbs, ips, plans] = await Promise.all([
      listLbs(cfg, 'inventory'),
      up(cfg, 'inventory', 'GET', `/ip_address`, IpAddressList).catch(() => ({
        ip_addresses: { ip_address: [] },
      })),
      // A plan list that cannot be read leaves the size picker empty; the
      // price read that follows the pull records why (`plansError`).
      listPlans(cfg, 'inventory').catch(() => []),
    ]);
    // The listings cover the whole account; an inventory is one location's
    // (its zone), so a resource of another zone belongs to another location.
    const inZone = (zone: string | null | undefined) => !cfg.zone || !zone || zone === cfg.zone;
    return {
      loadBalancers: lbs
        .filter((l) => inZone(l.zone))
        .map((l) => ({
          id: l.uuid,
          name: l.name ?? l.uuid,
          status: l.operational_state ?? undefined,
          addresses: { v4: nodePublicV4(l) },
          createdAt: l.created_at ?? undefined,
        })),
      ips: ips.ip_addresses.ip_address
        .filter((ip) => inZone(ip.zone))
        .filter((ip) => (ip.floating ?? '').toLowerCase() === 'yes')
        .map((ip) => ({ id: ip.address, address: ip.address, attachedTo: ip.server ?? null })),
      flavors: plans.map((p) => ({ id: p.name, label: p.name })),
    };
  },

  /**
   * Every load balancer plan with its price: the account's price list for the
   * location's zone (`GET /1.3/price`, cents an hour in the account's billing
   * currency, which the list does not name: read from the account's details)
   * where it names the plan, else the dated table of the pricing page
   * (`UPCLOUD_LB_PRICES`), else not known. A price list whose currency cannot
   * be read is not used. Only an unreadable plan list fails the read
   * (`plan_list_unreadable`). UpCloud charges no data transfer for a load
   * balancer.
   */
  async plans(cfg) {
    // Every call settles before the read answers: a failed plan list never
    // leaves the price reads running unawaited.
    const [listed, priceList, currency] = await Promise.allSettled([
      listPlans(cfg, 'plans'),
      up(cfg, 'plans', 'GET', `/price`, z.unknown()),
      upcloudCurrency(cfg),
    ]);
    if (listed.status === 'rejected') throw listed.reason;
    const list =
      priceList.status === 'fulfilled' ? upcloudZonePricesOf(priceList.value, cfg.zone) : null;
    const billed = list?.currency ?? (currency.status === 'fulfilled' ? currency.value : null);
    const prices = billed ? (list?.plans ?? null) : null;
    const plans = listed.value.map((p) => upcloudPlanOf(p, prices, billed));
    // UpCloud does not document the key of a load balancer plan in the price
    // list: say which keys the zone's list holds when a plan is not among
    // them, so the key can be read from the logs (item names only, never a price).
    const unnamed = prices ? listed.value.filter((p) => !prices.has(priceKey(p.name))) : [];
    if (unnamed.length > 0 && list)
      console.warn(
        `[upcloud plans] the zone's price list names no price for ${unnamed.map((p) => p.name).join(', ')}; ` +
          `its other items: ${list.otherKeys.join(', ') || 'none'}`,
      );
    return plans;
  },

  planDestroy: (_cfg, ledger) => orderByKind(ledger, UPCLOUD_DESTROY_ORDER),

  /**
   * Idempotent DELETE: 404 → gone; a 2xx only means accepted (the service
   * tears down afterwards) → `delete_requested`, confirmed by the next re-issue.
   * A kind this adapter never creates is `unresolved`, never assumed gone.
   */
  async runDestroy(cfg, r) {
    const path =
      r.kind === 'lb'
        ? `/load-balancer/${encodeURIComponent(r.resourceId)}`
        : r.kind === 'floating_ip'
          ? `/ip_address/${encodeURIComponent(r.resourceId)}`
          : null;
    if (!path) return { status: 'unresolved' };
    try {
      // `okStatuses` turns a 404 into an `undefined` result; a 2xx yields the marker.
      const res = await up(
        cfg,
        'destroy',
        'DELETE',
        path,
        z.unknown().transform(() => 'accepted' as const),
        undefined,
        [404],
      );
      return res === undefined ? { status: 'confirmed_gone' } : { status: 'delete_requested' };
    } catch (e) {
      if (isProviderNotFound(e)) return { status: 'confirmed_gone' };
      throw e;
    }
  },
};

/** The floating IP is delegated to the service: the service goes first. */
const UPCLOUD_DESTROY_ORDER = ['lb', 'floating_ip'] as const;

/**
 * The managed load balancer plans of the pricing page, per month (UpCloud's
 * own figures, "estimates based on a 30-day month"), for a price list that
 * does not name the plan: https://upcloud.com/pricing/ (read 2026-10-22).
 */
export const UPCLOUD_LB_PRICES = {
  asOf: '2026-10-22',
  currency: 'EUR',
  monthly: {
    essentials: 0,
    development: 10,
    'production-small': 30,
    'production-medium': 75,
  } as Record<string, number>,
} as const;

/**
 * The hours of a month UpCloud bills an hourly price for: at most 672 (28
 * days), as UpCloud's own CLI prices a month (`upctl server plans --prices`).
 * A price-list price a month is its hourly price times this.
 */
export const UPCLOUD_BILLED_HOURS_PER_MONTH = 672;

/** How plan names and price-list keys are compared: trimmed, lower case, `_` for `-`. */
function priceKey(s: string): string {
  return s.trim().toLowerCase().replace(/-/g, '_');
}

/**
 * A price-list key that prices a load balancer plan, as `priceKey` spells it:
 * the plan's name after a load balancer prefix (`managed_load_balancer_`,
 * `load_balancer_`, `loadbalancer_`, with or without `plan_` after it, the way
 * a server plan is `server_plan_<name>`). UpCloud documents the list's shape
 * but not this key, so every spelling of the product is taken.
 */
const LB_PRICE_KEY = /^(?:managed_)?load_?balancer_(?:plan_)?(.+)$/;

/** One zone's load balancer prices in the price list (`upcloudZonePricesOf`). */
export interface UpcloudZonePrices {
  /** The list's own currency, when it names one (UpCloud's documented example does not). */
  currency: string | null;
  /** Plan (`priceKey` of its name) -> price an hour; null when the list has no such zone. */
  plans: Map<string, number> | null;
  /** The zone's item keys that price neither a server plan nor a load balancer plan. */
  otherKeys: string[];
}

/**
 * The load balancer plan prices of one zone of a `GET /1.3/price` answer
 * (exported for tests): each item's `price` is cents an hour for `amount`
 * units (1 for a plan), so a plan's price an hour is `price / 100 / amount`.
 * An item of another shape is skipped. Null when the answer is not the
 * documented shape at all.
 */
export function upcloudZonePricesOf(answer: unknown, zone: string): UpcloudZonePrices | null {
  const list = PriceList.safeParse(answer);
  if (!list.success) return null;
  const c = list.data.prices.currency?.trim().toUpperCase();
  const currency = c && /^[A-Z]{3}$/.test(c) ? c : null;
  const entry = list.data.prices.zone
    .map((z) => PriceZone.safeParse(z))
    .find((z) => z.success && z.data.name === zone)?.data;
  if (!entry) return { currency, plans: null, otherKeys: [] };
  const plans = new Map<string, number>();
  const otherKeys: string[] = [];
  for (const [key, raw] of Object.entries(entry)) {
    if (key === 'name' || key.startsWith('server_plan_')) continue;
    const plan = LB_PRICE_KEY.exec(priceKey(key))?.[1];
    if (!plan) {
      otherKeys.push(key);
      continue;
    }
    const item = PriceItem.safeParse(raw);
    if (item.success && item.data.price >= 0)
      plans.set(plan, item.data.price / 100 / Math.max(1, item.data.amount ?? 1));
  }
  return { currency, plans, otherKeys: otherKeys.sort() };
}

/**
 * The account's billing currency (`account.currency` of its details): what
 * the price list's amounts are in. Null when the details name none.
 */
async function upcloudCurrency(cfg: UpcloudConfig): Promise<string | null> {
  const self = await up(cfg, 'plans', 'GET', `/account`, AccountSelf);
  const details = await up(
    cfg,
    'plans',
    'GET',
    `/account/details/${encodeURIComponent(self.account.username)}`,
    AccountDetails,
  );
  const c = details.account.currency?.trim().toUpperCase();
  return c && /^[A-Z]{3}$/.test(c) ? c : null;
}

/**
 * One plan of `GET /load-balancer/plans` as a plan, priced from the zone's
 * price list (`prices`, an hour in `currency`, the account's billing one; a
 * month is `UPCLOUD_BILLED_HOURS_PER_MONTH` of them) or the pricing page's
 * table (exported for tests). With no zone list (or no currency for it), the
 * table; a plan in neither has no known price.
 */
export function upcloudPlanOf(
  p: UpcloudPlanRow,
  prices: ReadonlyMap<string, number> | null,
  currency: string | null,
): ProviderPlan {
  const nodes = typeof p.server_number === 'number' ? p.server_number : null;
  const sessions = typeof p.per_server_max_sessions === 'number' ? p.per_server_max_sessions : null;
  const facts = [
    nodes !== null ? `${nodes} node${nodes === 1 ? '' : 's'}` : null,
    sessions !== null ? `${sessions.toLocaleString('en-US')} sessions each` : null,
  ].filter(Boolean);
  const base = {
    size: p.name,
    label: facts.length > 0 ? `${p.name} (${facts.join(', ')})` : p.name,
    traffic: { kind: 'unlimited' as const },
    bandwidthMbps: null,
    acceptsOutsideNode: null,
  };
  const perHour = currency ? (prices?.get(priceKey(p.name)) ?? null) : null;
  if (perHour !== null && currency)
    return {
      ...base,
      perHour,
      perMonth: Math.round(perHour * UPCLOUD_BILLED_HOURS_PER_MONTH * 100) / 100,
      currency,
      source: 'api',
    };
  const listed = UPCLOUD_LB_PRICES.monthly[p.name.toLowerCase()];
  if (listed !== undefined)
    return {
      ...base,
      perHour: null,
      perMonth: listed,
      currency: UPCLOUD_LB_PRICES.currency,
      source: 'catalog',
      catalogAsOf: UPCLOUD_LB_PRICES.asOf,
    };
  return { ...base, perHour: null, perMonth: null, currency: null, source: 'api' };
}
