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
 * Discovery: the service list is authoritative (found / confirmed_absent by
 * exact name). Floating IPs carry no name or tag, so an unknown-outcome
 * allocation is `ambiguous` whenever the account holds any unattached floating
 * IPv4 in the zone (an operator adopts or releases it), and `confirmed_absent`
 * when it holds none.
 *
 * Deletes are synchronous HTTP calls but the service tears down in the
 * background, so a 2xx is reported as `delete_requested` and the dispatcher
 * re-issues the idempotent DELETE until it answers 404 (`confirmed_gone`).
 * Destroy order is by kind: the service first, then the floating IP delegated
 * to it. The API exposes no per-member health, so a running service reports
 * `unknown` (never `online`) — see `memberHealth` in capabilities.ts.
 */
import { z } from 'zod';
import type {
  DiscoverResult,
  ChildResource,
  EdgeDescription,
  EdgeSpec,
  Ledger,
  EdgeProvider,
  ResourceStep,
  StepOutcome,
  TemplateFieldDescriptor,
  UpcloudConfig,
} from './types';
import { firstResource, metaOf, orderByKind } from './types';
import { isProviderNotFound, providerFetch, EdgeProviderError } from './http';
import { UpcloudTemplate, UPCLOUD_TEMPLATE_FIELDS, type UpcloudTemplateParams } from './templates';

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
const Plans = z
  .object({ plans: z.array(z.object({ name: z.string() }).passthrough()).default([]) })
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
        max_sessions: 1000,
        enabled: true,
      })),
      properties: {
        timeout_server: tpl.timeoutServer,
        timeout_tunnel: tpl.timeoutTunnel,
        health_check_type: 'tcp',
        health_check_interval: tpl.healthCheck.interval,
        health_check_timeout: tpl.healthCheck.timeout,
        health_check_fall: tpl.healthCheck.fall,
        health_check_rise: tpl.healthCheck.rise,
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
      return {
        ok: false,
        code:
          e instanceof EdgeProviderError
            ? (e.meta.code ?? String(e.meta.status ?? 'error'))
            : 'error',
      };
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
      return {
        errors: {
          regions:
            e instanceof EdgeProviderError
              ? (e.meta.code ?? String(e.meta.status ?? 'error'))
              : 'error',
        },
      };
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
        const lb = await up(
          cfg,
          step.id,
          'POST',
          `/load-balancer`,
          Lb,
          upcloudLbBody(cfg, spec, tpl),
        );
        return {
          status: 'done',
          resources: [{ kind: 'lb', resourceId: lb.uuid, ownership: 'created' }],
        };
      }
      case 'allocate_ip': {
        const res = await up(cfg, step.id, 'POST', `/ip_address`, FloatingIpCreate, {
          ip_address: { zone: cfg.zone, floating: 'yes', family: 'IPv4' },
        });
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
        await up(
          cfg,
          step.id,
          'POST',
          `/load-balancer/${encodeURIComponent(lb.resourceId)}/ip-addresses`,
          z.unknown(),
          {
            ip_addresses: [{ address: ip.resourceId, listen: true }],
          },
        );
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

  async discover(cfg, step, spec, ledger) {
    switch (step.kind) {
      case 'create_lb': {
        const list = await up(cfg, step.id, 'GET', `/load-balancer`, LbList);
        const hit = list.find((l) => l.name === spec.name);
        return hit
          ? {
              status: 'found',
              resources: [{ kind: 'lb', resourceId: hit.uuid, ownership: 'adopted' }],
            }
          : { status: 'confirmed_absent' };
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
        return candidates.length === 0
          ? { status: 'confirmed_absent' }
          : { status: 'ambiguous', candidates };
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
      up(cfg, 'inventory', 'GET', `/load-balancer`, LbList),
      up(cfg, 'inventory', 'GET', `/ip_address`, IpAddressList).catch(() => ({
        ip_addresses: { ip_address: [] },
      })),
      up(cfg, 'inventory', 'GET', `/load-balancer/plans`, Plans).catch(() => ({ plans: [] })),
    ]);
    return {
      loadBalancers: lbs.map((l) => ({
        id: l.uuid,
        name: l.name ?? l.uuid,
        status: l.operational_state ?? undefined,
        addresses: { v4: nodePublicV4(l) },
        createdAt: l.created_at ?? undefined,
      })),
      ips: ips.ip_addresses.ip_address
        .filter((ip) => (ip.floating ?? '').toLowerCase() === 'yes')
        .map((ip) => ({ id: ip.address, address: ip.address, attachedTo: ip.server ?? null })),
      flavors: plans.plans.map((p) => ({ id: p.name, label: p.name })),
    };
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
