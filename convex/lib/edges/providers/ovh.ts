/**
 * OVHcloud Public Cloud Load Balancer adapter (the Octavia-based regional
 * product under /cloud/project/{serviceName}/region/{regionName}/loadbalancing).
 * Hand-rolled with signed requests (./ovhSign.ts): the npm client is stale,
 * CommonJS and untyped. The legacy IP Load Balancing product is not supported.
 *
 * Model: ONE compound step. Creating the balancer with its network (private
 * network + subnet, a floating IP the provider mints, an existing gateway OR a
 * gateway the operation creates under the FCP-chosen name `<edge>-gw`) and the
 * TCP listener/pool inline returns an OPERATION that is polled at
 * `GET /cloud/project/{sn}/operation/{id}`. The children the compound call
 * mints (floating IP, gateway) are ledgered as soon as they are discoverable:
 * the poll that sees the operation complete looks them up by their FCP names,
 * and describe()/discover() adopt any the ledger still lacks.
 *
 * Discovery: balancers are listed by our deterministic name; absence is
 * confirmed only after >= 2 quiet looks AND `discoverySettleMs` since the step
 * was requested, and never while the project reports an in-flight balancer
 * operation. FCP-named children found WITHOUT their balancer (the partial
 * failure window) are reported `ambiguous`: re-running the step would mint
 * duplicates and there is no balancer to adopt, so the operator decides with
 * the orphans already ledgered for destroy.
 *
 * Destroy order is by kind: balancer → floating IP → gateway (the balancer's
 * VIP sits behind the gateway). Every kind is read back after its delete; a
 * balancer that is not PENDING_DELETE means the delete never landed.
 */
import { z } from 'zod';
import type {
  DiscoverResult,
  ChildResource,
  EdgeDescription,
  EdgeSpec,
  Ledger,
  OvhConfig,
  EdgeProvider,
  ResourceStep,
  StepOutcome,
  TemplateFieldDescriptor,
} from './types';
import { firstResource, orderByKind, stepOf } from './types';
import { discoveryMaySettle } from './capabilities';
import { isProviderNotFound, providerFetch, EdgeProviderError } from './http';
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
    createdAt: z.string().nullish(),
  })
  .passthrough();
const OperationList = z.array(Operation);
const FloatingIp = z
  .object({
    id: z.string(),
    ip: z.string().nullish(),
    /** `floatingIpCreate.description` carries the edge name: our ownership mark. */
    description: z.string().nullish(),
    status: z.string().nullish(),
  })
  .passthrough();
const Gateway = z
  .object({ id: z.string(), name: z.string().nullish(), status: z.string().nullish() })
  .passthrough();
const GatewayList = z.array(Gateway);
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
const PrivateNetworks = z.array(
  z
    .object({
      id: z.string(),
      name: z.string().nullish(),
      regions: z.array(z.object({ region: z.string() }).passthrough()).nullish(),
    })
    .passthrough(),
);
const Subnets = z.array(
  z
    .object({
      id: z.string(),
      cidr: z.string().nullish(),
      ipPools: z.array(z.object({ region: z.string().nullish() }).passthrough()).nullish(),
    })
    .passthrough(),
);

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
const projectBase = (cfg: OvhConfig) => `/cloud/project/${encodeURIComponent(cfg.serviceName)}`;

/** The FCP-chosen name of the gateway the compound create mints when no gateway id is configured. */
export function ovhGatewayName(edgeName: string): string {
  return `${edgeName}-gw`;
}

/**
 * The gateway the create step minted for this edge, when the account has no
 * fixed gateway: looked up by its FCP name. Fail-soft (a listing error yields
 * nothing; describe/discover adopt it later).
 */
async function findOwnedGateway(
  cfg: OvhConfig,
  step: string,
  edgeName: string,
  ownership: ChildResource['ownership'],
): Promise<ChildResource[]> {
  if (cfg.gatewayId) return [];
  try {
    const list = await ovh(cfg, step, 'GET', `${base(cfg)}/gateway`, GatewayList);
    const name = ovhGatewayName(edgeName);
    return list
      .filter((g) => g.name === name)
      .map((g) => ({ kind: 'gateway', resourceId: g.id, ownership }));
  } catch {
    return [];
  }
}

/** Floating IPs whose description carries this edge's name (minted by `floatingIpCreate`). Fail-soft. */
async function findOwnedFloatingIps(
  cfg: OvhConfig,
  step: string,
  edgeName: string,
  ownership: ChildResource['ownership'],
): Promise<ChildResource[]> {
  try {
    const list = await ovh(cfg, step, 'GET', `${base(cfg)}/floatingip`, FipList);
    return list
      .filter((f) => f.description === edgeName)
      .map((f) => ({
        kind: 'floating_ip',
        resourceId: f.id,
        ownership,
        ...(f.ip ? { meta: { address: f.ip } } : {}),
      }));
  } catch {
    return [];
  }
}

const OP_TERMINAL = new Set(['completed', 'in-error', 'error']);

/**
 * True when the project reports a balancer operation that is still running and
 * started no earlier than `since` (when known): the object may be registering,
 * so absence cannot be confirmed yet. Fail-soft: an unreadable listing is "no".
 */
async function hasInFlightLbOperation(
  cfg: OvhConfig,
  step: string,
  since: number | undefined,
): Promise<boolean> {
  try {
    const ops = await ovh(cfg, step, 'GET', `${projectBase(cfg)}/operation`, OperationList);
    return ops.some((op) => {
      if (OP_TERMINAL.has(op.status.toLowerCase())) return false;
      if (!/loadbalanc/i.test(op.action ?? '')) return false;
      if (since !== undefined && op.createdAt) {
        const t = Date.parse(op.createdAt);
        if (Number.isFinite(t) && t < since - 60_000) return false;
      }
      return true;
    });
  } catch {
    return false;
  }
}

/** The create-LB request body (exported for tests). */
export function ovhLbBody(cfg: OvhConfig, spec: EdgeSpec, tpl: OvhTemplateParams) {
  if (!tpl.flavorId) {
    throw new EdgeProviderError('ovh template needs flavorId', {
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

/**
 * Advance the compound create by its operation. On completion the children it
 * minted (a gateway under the FCP name, the floating IP) are looked up and
 * listed alongside the balancer so the ledger records them at once; on an
 * error the same lookups report whatever was left behind (`partial`).
 */
async function pollOperation(
  cfg: OvhConfig,
  step: string,
  opId: string,
  edgeName: string,
): Promise<StepOutcome> {
  const op = await ovh(
    cfg,
    step,
    'GET',
    `${projectBase(cfg)}/operation/${encodeURIComponent(opId)}`,
    Operation,
  );
  const st = op.status.toLowerCase();
  if (st === 'completed') {
    // `resourceId` is optional on the wire: a completed operation without it
    // must not count as done with nothing created (the LB may well exist), so
    // hand the step to discovery, which finds the LB by name.
    if (!op.resourceId)
      return { status: 'partial', resources: [], code: 'operation_completed_without_resource' };
    const children = await findOwnedGateway(cfg, step, edgeName, 'created');
    return {
      status: 'done',
      resources: [{ kind: 'lb', resourceId: op.resourceId, ownership: 'created' }, ...children],
    };
  }
  if (st === 'in-error' || st === 'error') {
    const leftovers = [
      ...(await findOwnedFloatingIps(cfg, step, edgeName, 'created')),
      ...(await findOwnedGateway(cfg, step, edgeName, 'created')),
    ];
    return { status: 'partial', resources: leftovers, code: 'operation_error' };
  }
  return { status: 'requested', opRef: opId, resources: [] };
}

const getLb = (cfg: OvhConfig, step: string, id: string) =>
  ovh(cfg, step, 'GET', `${base(cfg)}/loadbalancing/loadbalancer/${encodeURIComponent(id)}`, Lb);

async function ovhRegions(cfg: OvhConfig): Promise<Array<{ id: string; label: string }>> {
  const regions = await ovh(
    cfg,
    'regions',
    'GET',
    `/cloud/project/${encodeURIComponent(cfg.serviceName)}/region`,
    Regions,
  );
  return regions.map((r) => ({ id: r, label: r }));
}

export const ovhProvider: EdgeProvider<OvhConfig, OvhTemplateParams> = {
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
          e instanceof EdgeProviderError
            ? (e.meta.code ?? String(e.meta.status ?? 'error'))
            : 'error',
      };
    }
  },

  listRegions: (cfg) => ovhRegions(cfg),

  /**
   * Projects need only the keys; regions and private networks (with their
   * subnets, filtered to the chosen region when one is set) need the project.
   */
  async discoverOptions(
    partial: Partial<OvhConfig> & Record<string, unknown>,
  ): Promise<DiscoverResult> {
    const cfg = partial as OvhConfig;
    const out: DiscoverResult = { errors: {} };
    const code = (e: unknown) =>
      e instanceof EdgeProviderError ? (e.meta.code ?? String(e.meta.status ?? 'error')) : 'error';
    try {
      const ids = await ovh(cfg, 'projects', 'GET', `/cloud/project`, z.array(z.string()));
      const projects: Array<{ id: string; label: string }> = [];
      for (const id of ids.slice(0, 50)) {
        try {
          const p = await ovh(
            cfg,
            'project',
            'GET',
            `/cloud/project/${encodeURIComponent(id)}`,
            z.object({ description: z.string().nullish() }).passthrough(),
          );
          projects.push({ id, label: p.description ? `${p.description} (${id})` : id });
        } catch {
          projects.push({ id, label: id });
        }
      }
      out.projects = projects;
    } catch (e) {
      out.errors!.projects = code(e);
    }
    if (cfg.serviceName) {
      try {
        out.regions = await ovhRegions(cfg);
      } catch (e) {
        out.errors!.regions = code(e);
      }
      try {
        const nets = await ovh(
          cfg,
          'networks',
          'GET',
          `/cloud/project/${encodeURIComponent(cfg.serviceName)}/network/private`,
          PrivateNetworks,
        );
        const networks: NonNullable<DiscoverResult['networks']> = [];
        for (const n of nets) {
          if (cfg.regionName && !n.regions?.some((r) => r.region === cfg.regionName)) continue;
          let subnets: Array<{ id: string; label: string }> = [];
          try {
            const subs = await ovh(
              cfg,
              'subnets',
              'GET',
              `/cloud/project/${encodeURIComponent(cfg.serviceName)}/network/private/${encodeURIComponent(n.id)}/subnet`,
              Subnets,
            );
            subnets = subs
              .filter(
                (s) =>
                  !cfg.regionName ||
                  !s.ipPools?.length ||
                  s.ipPools.some((p) => p.region === cfg.regionName),
              )
              .map((s) => ({ id: s.id, label: s.cidr ?? s.id }));
          } catch {
            /* subnets unavailable for this network: offer the network alone */
          }
          networks.push({ id: n.id, label: n.name ?? n.id, subnets });
        }
        out.networks = networks;
      } catch (e) {
        out.errors!.networks = code(e);
      }
    }
    return out;
  },

  planProvision(_cfg, spec) {
    return [{ id: 'lb', kind: 'create_lb', resourceName: spec.name, discoverability: 'by_name' }];
  },

  async runStep(cfg, step, spec, tpl) {
    if (step.kind !== 'create_lb')
      throw new EdgeProviderError(`ovh: unknown step kind ${step.kind}`, {
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

  // The create step's resourceName IS the edge name (see planProvision).
  pollStep: (cfg, step, opRef) => pollOperation(cfg, step.id, opRef, step.resourceName),

  async discover(cfg, step, spec, ledger, attempt) {
    const ls = stepOf(ledger, step.id);
    if (ls?.opRef) {
      const out = await pollOperation(cfg, step.id, ls.opRef, spec.name);
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
      resources.push(...(await findOwnedGateway(cfg, step.id, spec.name, 'adopted')));
      return {
        status: 'found',
        resources,
        addresses: hit.floatingIp?.ip ? { v4: hit.floatingIp.ip } : {},
      };
    }
    // No balancer. FCP-named children left behind by a failed compound create
    // are orphans: ledger them, but neither re-run (duplicates) nor adopt (no
    // balancer) — the operator decides.
    const orphans = [
      ...(await findOwnedFloatingIps(cfg, step.id, spec.name, 'adopted')),
      ...(await findOwnedGateway(cfg, step.id, spec.name, 'adopted')),
    ];
    if (orphans.length > 0) return { status: 'ambiguous', candidates: orphans };
    if (await hasInFlightLbOperation(cfg, step.id, ls?.startedAt)) return { status: 'unresolved' };
    return discoveryMaySettle('ovh', attempt, ls?.startedAt)
      ? { status: 'confirmed_absent' }
      : { status: 'unresolved' };
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
    const known = new Set(ledger.resources.map((r) => r.resourceId));
    const resources: ChildResource[] = [];
    if (obj.floatingIp?.id && !known.has(obj.floatingIp.id)) {
      resources.push({ kind: 'floating_ip', resourceId: obj.floatingIp.id, ownership: 'created' });
    }
    // A gateway the compound create minted and the ledger does not hold yet.
    if (!cfg.gatewayId && !ledger.resources.some((r) => r.kind === 'gateway')) {
      const edgeName = obj.name ?? stepOf(ledger, lb.stepId)?.resourceName;
      if (edgeName)
        for (const g of await findOwnedGateway(cfg, 'describe', edgeName, 'created'))
          if (!known.has(g.resourceId)) resources.push(g);
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
      throw new EdgeProviderError('ovh inspect: no lb in ledger', {
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

  planDestroy: (_cfg, ledger) => orderByKind(ledger, OVH_DESTROY_ORDER),

  /** Deletes return an operation (or nothing); a kind this adapter never creates is `unresolved`. */
  async runDestroy(cfg, r) {
    const path = resourcePath(cfg, r.kind, r.resourceId);
    if (!path) return { status: 'unresolved' };
    try {
      const res = await ovh(
        cfg,
        'destroy',
        'DELETE',
        path,
        Operation.or(z.unknown()),
        undefined,
        [404],
      );
      const opRef =
        res && typeof res === 'object' && 'id' in res
          ? String((res as { id: unknown }).id)
          : undefined;
      return { status: 'delete_requested', opRef };
    } catch (e) {
      if (isProviderNotFound(e)) return { status: 'confirmed_gone' };
      throw e;
    }
  },

  /**
   * Read back: 404 → gone; a balancer/gateway whose status says deleting →
   * unresolved; anything else readable → still_present (the delete never landed).
   */
  async confirmDestroyed(cfg, r) {
    const path = resourcePath(cfg, r.kind, r.resourceId);
    if (!path) return { status: 'unresolved' };
    try {
      const obj = await ovh(
        cfg,
        'confirm-destroy',
        'GET',
        path,
        z
          .object({ provisioningStatus: z.string().nullish(), status: z.string().nullish() })
          .passthrough(),
      );
      const st = (obj.provisioningStatus ?? obj.status ?? '').toUpperCase();
      if (st === 'DELETED') return { status: 'confirmed_gone' };
      if (st.includes('DELET')) return { status: 'unresolved' };
      return { status: 'still_present' };
    } catch (e) {
      if (isProviderNotFound(e)) return { status: 'confirmed_gone' };
      throw e;
    }
  },
};

/** The balancer holds the floating IP and sits behind the gateway. */
const OVH_DESTROY_ORDER = ['lb', 'floating_ip', 'gateway'] as const;

function resourcePath(cfg: OvhConfig, kind: string, id: string): string | null {
  const enc = encodeURIComponent(id);
  return kind === 'lb'
    ? `${base(cfg)}/loadbalancing/loadbalancer/${enc}`
    : kind === 'floating_ip'
      ? `${base(cfg)}/floatingip/${enc}`
      : kind === 'gateway'
        ? `${base(cfg)}/gateway/${enc}`
        : null;
}

export type { Ledger as OvhLedger, ResourceStep as OvhResourceStep };
