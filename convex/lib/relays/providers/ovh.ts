/**
 * OVHcloud Public Cloud Load Balancer adapter (the Octavia-based regional
 * product under /cloud/project/{serviceName}/region/{regionName}/loadbalancing).
 * Hand-rolled with signed requests (./ovhSign.ts): the npm client is stale,
 * CommonJS and untyped. The legacy IP Load Balancing product is not supported.
 *
 * Model: ONE compound step. Creating the balancer with its network (private
 * network + subnet, a floating IP the provider mints, an existing gateway) and
 * the TCP listener/pool inline returns an OPERATION that is polled at
 * `GET /cloud/project/{sn}/operation/{id}`; the balancer's floating IP becomes
 * visible on the balancer object and is adopted into the ledger by describe().
 *
 * Discovery: balancers are listed by our deterministic name; a repeated absence
 * (attempt >= 2) is treated as confirmed while an operation may still be
 * registering the object on the first look.
 */
import { z } from 'zod';
import type {
  ChildResource,
  EdgeDescription,
  EdgeSpec,
  Ledger,
  OvhConfig,
  RelayProvider,
  ResourceStep,
  StepOutcome,
  TemplateFieldDescriptor,
} from './types';
import { firstResource, reverseLiveResources, stepOf } from './types';
import { isProviderNotFound, providerFetch, RelayProviderError } from './http';
import { OVH_ENDPOINTS, ovhSignedHeaders } from './ovhSign';
import { OvhTemplate, OVH_TEMPLATE_FIELDS, type OvhTemplateParams } from './templates';

export { OvhTemplate, OVH_TEMPLATE_FIELDS } from './templates';
export type { OvhTemplateParams } from './templates';

// --- schemas ---------------------------------------------------------------------

const Operation = z
  .object({
    id: z.string(),
    status: z.string(),
    resourceId: z.string().nullish(),
    action: z.string().nullish(),
  })
  .passthrough();
const FloatingIp = z.object({ id: z.string(), ip: z.string().nullish() }).passthrough();
const Lb = z
  .object({
    id: z.string(),
    name: z.string().nullish(),
    provisioningStatus: z.string().nullish(),
    operatingStatus: z.string().nullish(),
    vipAddress: z.string().nullish(),
    floatingIp: FloatingIp.nullish(),
    flavorId: z.string().nullish(),
    createdAt: z.string().nullish(),
  })
  .passthrough();
const LbList = z.array(Lb);
const FipList = z.array(FloatingIp.extend({ associatedEntity: z.unknown().nullish() }));
const Flavors = z.array(z.object({ id: z.string(), name: z.string().nullish() }).passthrough());
const Regions = z.array(z.string());

// --- signed fetch -----------------------------------------------------------------

let skewCache: { skew: number; at: number } | null = null;
const SKEW_TTL_MS = 5 * 60_000;

/** Server-time delta (seconds), cached per module for a few minutes. Exported for tests. */
export async function ovhSkewSeconds(cfg: OvhConfig, force = false): Promise<number> {
  if (!force && skewCache && Date.now() - skewCache.at < SKEW_TTL_MS) return skewCache.skew;
  const serverNow = await providerFetch({
    provider: 'ovh',
    step: 'auth-time',
    url: `${OVH_ENDPOINTS[cfg.endpoint]}/auth/time`,
    method: 'GET',
    headers: {},
    schema: z.number(),
  });
  const skew = serverNow - Math.floor(Date.now() / 1000);
  skewCache = { skew, at: Date.now() };
  return skew;
}
export function __resetOvhSkewCache(): void {
  skewCache = null;
}

async function ovh<T>(
  cfg: OvhConfig,
  step: string,
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  path: string,
  schema: z.ZodType<T>,
  body?: unknown,
  okStatuses?: number[],
): Promise<T> {
  const url = `${OVH_ENDPOINTS[cfg.endpoint]}${path}`;
  const bodyStr = body !== undefined ? JSON.stringify(body) : '';
  const skew = await ovhSkewSeconds(cfg);
  const signed = await ovhSignedHeaders({
    applicationKey: cfg.applicationKey,
    applicationSecret: cfg.applicationSecret,
    consumerKey: cfg.consumerKey,
    method,
    url,
    body: bodyStr,
    skewSeconds: skew,
  });
  return providerFetch({
    provider: 'ovh',
    step,
    url,
    method,
    headers: signed,
    body,
    schema,
    okStatuses,
  });
}

const base = (cfg: OvhConfig) =>
  `/cloud/project/${encodeURIComponent(cfg.serviceName)}/region/${encodeURIComponent(cfg.regionName)}`;

/** The create-LB request body (exported for tests). */
export function ovhLbBody(cfg: OvhConfig, spec: EdgeSpec, tpl: OvhTemplateParams) {
  if (!tpl.flavorId) {
    throw new RelayProviderError('ovh template needs flavorId', {
      provider: 'ovh',
      step: 'plan',
      code: 'template_flavor_required',
      retryable: false,
      timedOut: false,
    });
  }
  return {
    flavorId: tpl.flavorId,
    name: spec.name,
    network: {
      private: {
        network: { id: cfg.networkId, subnetId: cfg.subnetId },
        floatingIpCreate: { description: spec.name },
        ...(cfg.gatewayId
          ? { gateway: { id: cfg.gatewayId } }
          : { gatewayCreate: { model: tpl.gatewayModel, name: `${spec.name}-gw` } }),
      },
    },
    listeners: spec.listeners.map((l, i) => ({
      name: `${spec.name}-l${l.edgePort}${i > 0 ? `-${i}` : ''}`,
      port: l.edgePort,
      protocol: 'tcp',
      ...(tpl.allowedCidrs.length > 0 ? { allowedCidrs: tpl.allowedCidrs } : {}),
      timeoutClientData: tpl.timeoutClientDataMs,
      pool: {
        name: `${spec.name}-p${l.edgePort}`,
        algorithm: tpl.algorithm,
        protocol: 'tcp',
        healthMonitor: {
          name: `${spec.name}-hm${l.edgePort}`,
          monitorType: 'tcp',
          delay: tpl.healthMonitor.delay,
          timeout: tpl.healthMonitor.timeout,
          maxRetries: tpl.healthMonitor.maxRetries,
        },
        members: l.members.map((m, j) => ({
          name: `${spec.name}-m${j}`,
          address: m.address,
          protocolPort: m.port,
        })),
      },
    })),
  };
}

function lbState(lb: z.infer<typeof Lb>): EdgeDescription['state'] {
  const p = (lb.provisioningStatus ?? '').toUpperCase();
  if (p === 'ACTIVE') return 'active';
  if (p === 'ERROR') return 'error';
  return 'pending';
}
function lbHealth(lb: z.infer<typeof Lb>): EdgeDescription['health'] {
  const o = (lb.operatingStatus ?? '').toUpperCase();
  if (o === 'ONLINE') return 'online';
  if (o === 'DEGRADED') return 'degraded';
  if (o === 'OFFLINE' || o === 'ERROR') return 'offline';
  return 'unknown';
}

async function pollOperation(cfg: OvhConfig, step: string, opId: string): Promise<StepOutcome> {
  const op = await ovh(
    cfg,
    step,
    'GET',
    `/cloud/project/${encodeURIComponent(cfg.serviceName)}/operation/${encodeURIComponent(opId)}`,
    Operation,
  );
  const st = op.status.toLowerCase();
  if (st === 'completed') {
    return op.resourceId
      ? {
          status: 'done',
          resources: [{ kind: 'lb', resourceId: op.resourceId, ownership: 'created' }],
        }
      : { status: 'done', resources: [] };
  }
  if (st === 'in-error' || st === 'error')
    return { status: 'partial', resources: [], code: 'operation_error' };
  return { status: 'requested', opRef: opId, resources: [] };
}

const getLb = (cfg: OvhConfig, step: string, id: string) =>
  ovh(cfg, step, 'GET', `${base(cfg)}/loadbalancing/loadbalancer/${encodeURIComponent(id)}`, Lb);

export const ovhProvider: RelayProvider<OvhConfig, OvhTemplateParams> = {
  id: 'ovh',
  templateSchema: OvhTemplate,
  templateFields: OVH_TEMPLATE_FIELDS,
  defaultTemplate: OvhTemplate.parse({}),

  async testCredentials(cfg) {
    try {
      await ovh(
        cfg,
        'test',
        'GET',
        `/cloud/project/${encodeURIComponent(cfg.serviceName)}`,
        z.unknown(),
      );
      return { ok: true };
    } catch (e) {
      return {
        ok: false,
        code:
          e instanceof RelayProviderError
            ? (e.meta.code ?? String(e.meta.status ?? 'error'))
            : 'error',
      };
    }
  },

  async listRegions(cfg) {
    const regions = await ovh(
      cfg,
      'regions',
      'GET',
      `/cloud/project/${encodeURIComponent(cfg.serviceName)}/region`,
      Regions,
    );
    return regions.map((r) => ({ id: r, label: r }));
  },

  planProvision(_cfg, spec) {
    return [{ id: 'lb', kind: 'create_lb', resourceName: spec.name, discoverability: 'by_name' }];
  },

  async runStep(cfg, step, spec, tpl) {
    if (step.kind !== 'create_lb')
      throw new RelayProviderError(`ovh: unknown step kind ${step.kind}`, {
        provider: 'ovh',
        step: step.id,
        code: 'unknown_step',
        retryable: false,
        timedOut: false,
      });
    const op = await ovh(
      cfg,
      step.id,
      'POST',
      `${base(cfg)}/loadbalancing/loadbalancer`,
      Operation,
      ovhLbBody(cfg, spec, tpl),
    );
    return { status: 'requested', opRef: op.id, resources: [] };
  },

  pollStep: (cfg, step, opRef) => pollOperation(cfg, step.id, opRef),

  async discover(cfg, step, spec, ledger, attempt) {
    const ls = stepOf(ledger, step.id);
    if (ls?.opRef) {
      const out = await pollOperation(cfg, step.id, ls.opRef);
      if (out.status === 'requested') return { status: 'unresolved' };
      if (out.status === 'done' && out.resources.length > 0)
        return { status: 'found', resources: out.resources };
      // Completed without a resource id, or errored: fall through to the listing.
    }
    const list = await ovh(cfg, step.id, 'GET', `${base(cfg)}/loadbalancing/loadbalancer`, LbList);
    const hit = list.find((l) => l.name === spec.name);
    if (hit) {
      const resources: ChildResource[] = [{ kind: 'lb', resourceId: hit.id, ownership: 'adopted' }];
      if (hit.floatingIp?.id)
        resources.push({
          kind: 'floating_ip',
          resourceId: hit.floatingIp.id,
          ownership: 'adopted',
        });
      return {
        status: 'found',
        resources,
        addresses: hit.floatingIp?.ip ? { v4: hit.floatingIp.ip } : {},
      };
    }
    return attempt >= 2 ? { status: 'confirmed_absent' } : { status: 'unresolved' };
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
    const resources: ChildResource[] = [];
    if (obj.floatingIp?.id && !ledger.resources.some((r) => r.resourceId === obj.floatingIp?.id)) {
      resources.push({ kind: 'floating_ip', resourceId: obj.floatingIp.id, ownership: 'created' });
    }
    return {
      state: lbState(obj),
      addresses: obj.floatingIp?.ip ? { v4: obj.floatingIp.ip } : {},
      health: lbHealth(obj),
      ...(resources.length > 0 ? { resources } : {}),
    };
  },

  async inspect(cfg, ledger) {
    const lb = firstResource(ledger, 'lb');
    if (!lb)
      throw new RelayProviderError('ovh inspect: no lb in ledger', {
        provider: 'ovh',
        step: 'inspect',
        code: 'no_lb',
        retryable: false,
        timedOut: false,
      });
    const obj = await getLb(cfg, 'inspect', lb.resourceId);
    const stats = await ovh(
      cfg,
      'inspect',
      'GET',
      `${base(cfg)}/loadbalancing/loadbalancer/${encodeURIComponent(lb.resourceId)}/stats`,
      z.unknown(),
    ).catch(() => null);
    return {
      summary: {
        status: obj.provisioningStatus ?? undefined,
        operatingStatus: obj.operatingStatus ?? undefined,
        flavor: obj.flavorId ?? undefined,
        region: cfg.regionName,
        createdAt: obj.createdAt ?? undefined,
        addresses: obj.floatingIp?.ip ? { v4: obj.floatingIp.ip } : {},
        members: [],
        listeners: [],
      },
      raw: { lb: obj, stats },
    };
  },

  async inventory(cfg) {
    const [lbs, fips, flavors] = await Promise.all([
      ovh(cfg, 'inventory', 'GET', `${base(cfg)}/loadbalancing/loadbalancer`, LbList),
      ovh(cfg, 'inventory', 'GET', `${base(cfg)}/floatingip`, FipList).catch(() => []),
      ovh(cfg, 'inventory', 'GET', `${base(cfg)}/loadbalancing/flavor`, Flavors).catch(() => []),
    ]);
    return {
      loadBalancers: lbs.map((l) => ({
        id: l.id,
        name: l.name ?? l.id,
        status: l.provisioningStatus ?? undefined,
        addresses: l.floatingIp?.ip ? { v4: l.floatingIp.ip } : {},
        createdAt: l.createdAt ?? undefined,
      })),
      ips: fips.map((f) => ({
        id: f.id,
        address: f.ip ?? '',
        attachedTo: f.associatedEntity ? 'attached' : null,
      })),
      flavors: flavors.map((f) => ({ id: f.id, label: f.name ?? f.id })),
    };
  },

  planDestroy: (_cfg, ledger) => reverseLiveResources(ledger),

  async runDestroy(cfg, r) {
    try {
      if (r.kind === 'lb') {
        const res = await ovh(
          cfg,
          'destroy',
          'DELETE',
          `${base(cfg)}/loadbalancing/loadbalancer/${encodeURIComponent(r.resourceId)}`,
          Operation.or(z.unknown()),
          undefined,
          [404],
        );
        const opRef =
          res && typeof res === 'object' && 'id' in res
            ? String((res as { id: unknown }).id)
            : undefined;
        return { status: 'delete_requested', opRef };
      }
      if (r.kind === 'floating_ip') {
        await ovh(
          cfg,
          'destroy',
          'DELETE',
          `${base(cfg)}/floatingip/${encodeURIComponent(r.resourceId)}`,
          z.unknown(),
          undefined,
          [404],
        );
        return { status: 'delete_requested' };
      }
      return { status: 'confirmed_gone' };
    } catch (e) {
      if (isProviderNotFound(e)) return { status: 'confirmed_gone' };
      throw e;
    }
  },

  async confirmDestroyed(cfg, r) {
    const path =
      r.kind === 'lb'
        ? `${base(cfg)}/loadbalancing/loadbalancer/${encodeURIComponent(r.resourceId)}`
        : r.kind === 'floating_ip'
          ? `${base(cfg)}/floatingip/${encodeURIComponent(r.resourceId)}`
          : null;
    if (!path) return { status: 'confirmed_gone' };
    try {
      await ovh(cfg, 'confirm-destroy', 'GET', path, z.unknown());
      return { status: 'unresolved' };
    } catch (e) {
      if (isProviderNotFound(e)) return { status: 'confirmed_gone' };
      throw e;
    }
  },
};

export type { Ledger as OvhLedger, ResourceStep as OvhResourceStep };
