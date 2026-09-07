/**
 * Gcore Cloud Load Balancer adapter (the Cloud API under /cloud/v1; the Edge
 * Proxy product is NOT used). Hand-rolled on the documented REST schema — Gcore
 * publishes no JavaScript SDK.
 *
 * Model: ONE compound step. `POST /cloud/v1/loadbalancers/{project}/{region}`
 * creates the LB with its TCP listener + pool + health monitor inline and
 * returns `{ tasks: [id] }`; the task is polled at `GET /cloud/v1/tasks/{id}`
 * and reports every created resource id (LB, and a floating IP when the
 * template asks for a private VIP). Deletes are tasks too.
 *
 * Discovery: the LB list is filtered by our deterministic name. The list
 * includes PENDING_CREATE balancers, so a repeated absence (attempt >= 2, i.e.
 * two polls apart) is treated as confirmed absence; a first miss is
 * `unresolved` in case the create is still registering.
 */
import { z } from 'zod';
import type {
  DiscoverResult,
  Addresses,
  ChildResource,
  Discovery,
  EdgeDescription,
  EdgeSpec,
  Inventory,
  InspectResult,
  Ledger,
  LedgerResource,
  EdgeProvider,
  ResourceStep,
  StepOutcome,
  DestroyOutcome,
  GcoreConfig,
  TemplateFieldDescriptor,
} from './types';
import { firstResource, metaOf, reverseLiveResources, stepOf } from './types';
import { isProviderNotFound, providerFetch, EdgeProviderError } from './http';
import { addressFamily } from '../ip';
import { GcoreTemplate, GCORE_TEMPLATE_FIELDS, type GcoreTemplateParams } from './templates';

const BASE = 'https://api.gcore.com';

export { GcoreTemplate, GCORE_TEMPLATE_FIELDS } from './templates';
export type { GcoreTemplateParams } from './templates';

// --- schemas (lenient: only the fields we read) ---------------------------------

const Tasks = z.object({ tasks: z.array(z.string()).min(1) });
const Task = z
  .object({
    id: z.string(),
    state: z.string(),
    created_resources: z
      .object({
        loadbalancers: z.array(z.string()).nullish(),
        floatingips: z.array(z.string()).nullish(),
        listeners: z.array(z.string()).nullish(),
        pools: z.array(z.string()).nullish(),
      })
      .passthrough()
      .nullish(),
    error: z.string().nullish(),
  })
  .passthrough();
const FloatingIp = z
  .object({ id: z.string().nullish(), floating_ip_address: z.string().nullish() })
  .passthrough();
const Lb = z
  .object({
    id: z.string(),
    name: z.string().nullish(),
    provisioning_status: z.string().nullish(),
    operating_status: z.string().nullish(),
    vip_address: z.string().nullish(),
    vip_ipv6_address: z.string().nullish(),
    floating_ips: z.array(FloatingIp).nullish(),
    flavor: z
      .union([z.string(), z.object({ flavor_name: z.string().nullish() }).passthrough()])
      .nullish(),
    created_at: z.string().nullish(),
    listeners: z
      .array(
        z.object({ id: z.string().nullish(), protocol_port: z.number().nullish() }).passthrough(),
      )
      .nullish(),
  })
  .passthrough();
const LbList = z.object({ results: z.array(Lb).default([]) }).passthrough();
const FipList = z
  .object({ results: z.array(FloatingIp.extend({ id: z.string() })).default([]) })
  .passthrough();
const ProjectList = z
  .object({
    results: z
      .array(z.object({ id: z.number(), name: z.string().nullish() }).passthrough())
      .default([]),
  })
  .passthrough();
const NetworkList = z
  .object({
    results: z
      .array(z.object({ id: z.string(), name: z.string().nullish() }).passthrough())
      .default([]),
  })
  .passthrough();
const SubnetList = z
  .object({
    results: z
      .array(
        z
          .object({
            id: z.string(),
            name: z.string().nullish(),
            network_id: z.string().nullish(),
            cidr: z.string().nullish(),
          })
          .passthrough(),
      )
      .default([]),
  })
  .passthrough();
const RegionList = z
  .object({
    results: z
      .array(z.object({ id: z.number(), display_name: z.string().nullish() }).passthrough())
      .default([]),
  })
  .passthrough();
const FlavorList = z
  .object({
    results: z.array(z.object({ flavor_name: z.string().nullish() }).passthrough()).default([]),
  })
  .passthrough();

// --- helpers ----------------------------------------------------------------------

function headers(cfg: GcoreConfig): Record<string, string> {
  return { authorization: `APIKey ${cfg.apiKey}` };
}
const scope = (cfg: GcoreConfig) => `${cfg.projectId}/${cfg.regionId}`;

async function gcore<T>(
  cfg: GcoreConfig,
  step: string,
  method: 'GET' | 'POST' | 'DELETE' | 'PATCH',
  path: string,
  schema: z.ZodType<T>,
  body?: unknown,
  okStatuses?: number[],
): Promise<T> {
  return providerFetch({
    provider: 'gcore',
    step,
    url: `${BASE}${path}`,
    method,
    headers: headers(cfg),
    body,
    schema,
    okStatuses,
  });
}

/** The create-LB request body (exported for tests). */
export function gcoreLbBody(cfg: GcoreConfig, spec: EdgeSpec, tpl: GcoreTemplateParams) {
  if (tpl.vipMode === 'private' && !(cfg.networkId && cfg.subnetId)) {
    throw new EdgeProviderError('gcore private VIP mode needs networkId + subnetId', {
      provider: 'gcore',
      step: 'plan',
      code: 'template_network_required',
      retryable: false,
      timedOut: false,
    });
  }
  return {
    name: spec.name,
    flavor: tpl.flavor,
    vip_ip_family: tpl.ipFamily,
    ...(tpl.vipMode === 'private'
      ? {
          vip_network_id: cfg.networkId,
          vip_subnet_id: cfg.subnetId,
          floating_ip: { source: 'new' },
        }
      : {}),
    listeners: spec.listeners.map((l, i) => ({
      name: `${spec.name}-l${l.edgePort}${i > 0 ? `-${i}` : ''}`,
      protocol: 'TCP',
      protocol_port: l.edgePort,
      ...(tpl.allowedCidrs.length > 0 ? { allowed_cidrs: tpl.allowedCidrs } : {}),
      ...(tpl.connectionLimit > 0 ? { connection_limit: tpl.connectionLimit } : {}),
      timeout_client_data: tpl.timeoutClientDataMs,
      timeout_member_connect: tpl.timeoutMemberConnectMs,
      timeout_member_data: tpl.timeoutMemberDataMs,
      pools: [
        {
          name: `${spec.name}-p${l.edgePort}`,
          protocol: 'TCP',
          lb_algorithm: tpl.lbAlgorithm,
          members: l.members.map((m) => ({ address: m.address, protocol_port: m.port, weight: 1 })),
          healthmonitor: {
            type: 'TCP',
            delay: tpl.healthMonitor.delay,
            timeout: tpl.healthMonitor.timeout,
            max_retries: tpl.healthMonitor.maxRetries,
            max_retries_down: tpl.healthMonitor.maxRetriesDown,
          },
        },
      ],
    })),
    tags: { ...tpl.tags, fcp_edge: spec.name },
  };
}

function taskResources(t: z.infer<typeof Task>): ChildResource[] {
  const out: ChildResource[] = [];
  for (const id of t.created_resources?.loadbalancers ?? [])
    out.push({ kind: 'lb', resourceId: id, ownership: 'created' });
  for (const id of t.created_resources?.floatingips ?? [])
    out.push({ kind: 'floating_ip', resourceId: id, ownership: 'created' });
  return out;
}

function lbAddresses(lb: z.infer<typeof Lb>): Addresses {
  const out: Addresses = {};
  const fip = lb.floating_ips?.find((f) => f.floating_ip_address)?.floating_ip_address ?? undefined;
  const candidates = [fip, lb.vip_address ?? undefined, lb.vip_ipv6_address ?? undefined].filter(
    (x): x is string => !!x,
  );
  for (const c of candidates) {
    const fam = addressFamily(c);
    if (fam === 'v4' && !out.v4) out.v4 = c;
    if (fam === 'v6' && !out.v6) out.v6 = c;
  }
  return out;
}

function lbState(lb: z.infer<typeof Lb>): EdgeDescription['state'] {
  const p = (lb.provisioning_status ?? '').toUpperCase();
  if (p === 'ACTIVE') return 'active';
  if (p === 'ERROR') return 'error';
  return 'pending';
}
function lbHealth(lb: z.infer<typeof Lb>): EdgeDescription['health'] {
  const o = (lb.operating_status ?? '').toUpperCase();
  if (o === 'ONLINE') return 'online';
  if (o === 'DEGRADED') return 'degraded';
  if (o === 'OFFLINE' || o === 'ERROR') return 'offline';
  return 'unknown';
}

async function getLb(cfg: GcoreConfig, step: string, id: string) {
  return gcore(
    cfg,
    step,
    'GET',
    `/cloud/v1/loadbalancers/${scope(cfg)}/${encodeURIComponent(id)}`,
    Lb,
  );
}

async function pollTask(cfg: GcoreConfig, step: string, taskId: string): Promise<StepOutcome> {
  const t = await gcore(cfg, step, 'GET', `/cloud/v1/tasks/${encodeURIComponent(taskId)}`, Task);
  const state = t.state.toUpperCase();
  if (state === 'FINISHED') return { status: 'done', resources: taskResources(t) };
  if (state === 'ERROR')
    return { status: 'partial', resources: taskResources(t), code: 'task_error' };
  return { status: 'requested', opRef: taskId, resources: taskResources(t) };
}

// --- the adapter -------------------------------------------------------------------

export const gcoreProvider: EdgeProvider<GcoreConfig, GcoreTemplateParams> = {
  id: 'gcore',
  templateSchema: GcoreTemplate,
  templateFields: GCORE_TEMPLATE_FIELDS,
  defaultTemplate: GcoreTemplate.parse({}),

  async testCredentials(cfg) {
    try {
      await gcore(cfg, 'test', 'GET', `/cloud/v1/loadbalancers/${scope(cfg)}?limit=1`, LbList);
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

  listRegions: (cfg) => gcoreRegions(cfg),

  /** Projects and regions need only the API key; networks need a project + region (optional: public VIP needs none). */
  async discoverOptions(
    partial: Partial<GcoreConfig> & Record<string, unknown>,
  ): Promise<DiscoverResult> {
    const cfg = partial as GcoreConfig;
    const out: DiscoverResult = { errors: {} };
    try {
      const p = await gcore(cfg, 'projects', 'GET', `/cloud/v1/projects`, ProjectList);
      out.projects = p.results.map((x) => ({ id: String(x.id), label: x.name ?? String(x.id) }));
    } catch (e) {
      out.errors!.projects = codeOf(e);
    }
    try {
      out.regions = await gcoreRegions(cfg);
    } catch (e) {
      out.errors!.regions = codeOf(e);
    }
    if (cfg.projectId && cfg.regionId) {
      try {
        const nets = await gcore(
          cfg,
          'networks',
          'GET',
          `/cloud/v1/networks/${scope(cfg)}`,
          NetworkList,
        );
        const subnets = await gcore(
          cfg,
          'subnets',
          'GET',
          `/cloud/v1/subnets/${scope(cfg)}`,
          SubnetList,
        );
        out.networks = nets.results.map((n) => ({
          id: n.id,
          label: n.name ?? n.id,
          subnets: subnets.results
            .filter((s) => s.network_id === n.id)
            .map((s) => ({ id: s.id, label: `${s.name ?? s.id}${s.cidr ? ` (${s.cidr})` : ''}` })),
        }));
      } catch (e) {
        out.errors!.networks = codeOf(e);
      }
    }
    return out;
  },

  planProvision(_cfg, spec) {
    return [{ id: 'lb', kind: 'create_lb', resourceName: spec.name, discoverability: 'by_name' }];
  },

  async runStep(cfg, step, spec, tpl) {
    if (step.kind !== 'create_lb') throw unknownStep(step);
    const res = await gcore(
      cfg,
      step.id,
      'POST',
      `/cloud/v1/loadbalancers/${scope(cfg)}`,
      Tasks,
      gcoreLbBody(cfg, spec, tpl),
    );
    return { status: 'requested', opRef: res.tasks[0], resources: [] };
  },

  pollStep: (cfg, step, opRef) => pollTask(cfg, step.id, opRef),

  async discover(cfg, step, spec, ledger, attempt) {
    const ls = stepOf(ledger, step.id);
    if (ls?.opRef) {
      const out = await pollTask(cfg, step.id, ls.opRef);
      if (out.status === 'done') return { status: 'found', resources: out.resources };
      if (out.status === 'requested') return { status: 'unresolved' };
      // The task errored: whatever it created is recorded; nothing more exists.
      return out.resources.length > 0
        ? { status: 'found', resources: out.resources }
        : { status: 'confirmed_absent' };
    }
    const list = await gcore(
      cfg,
      step.id,
      'GET',
      `/cloud/v1/loadbalancers/${scope(cfg)}?name=${encodeURIComponent(spec.name)}`,
      LbList,
    );
    const hit = list.results.find((l) => l.name === spec.name);
    if (hit) {
      const resources: ChildResource[] = [{ kind: 'lb', resourceId: hit.id, ownership: 'adopted' }];
      for (const f of hit.floating_ips ?? [])
        if (f.id) resources.push({ kind: 'floating_ip', resourceId: f.id, ownership: 'adopted' });
      return { status: 'found', resources, addresses: lbAddresses(hit) };
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
    const known = new Set(ledger.resources.map((r) => r.resourceId));
    const resources: ChildResource[] = [];
    for (const f of obj.floating_ips ?? []) {
      if (f.id && !known.has(f.id))
        resources.push({ kind: 'floating_ip', resourceId: f.id, ownership: 'created' });
    }
    return {
      state: lbState(obj),
      addresses: lbAddresses(obj),
      health: lbHealth(obj),
      ...(resources.length > 0 ? { resources } : {}),
    };
  },

  async inspect(cfg, ledger) {
    const lb = firstResource(ledger, 'lb');
    if (!lb)
      throw new EdgeProviderError('gcore inspect: no lb in ledger', {
        provider: 'gcore',
        step: 'inspect',
        code: 'no_lb',
        retryable: false,
        timedOut: false,
      });
    const obj = await getLb(cfg, 'inspect', lb.resourceId);
    const flavor =
      typeof obj.flavor === 'string' ? obj.flavor : (obj.flavor?.flavor_name ?? undefined);
    return {
      summary: {
        status: obj.provisioning_status ?? undefined,
        operatingStatus: obj.operating_status ?? undefined,
        flavor,
        region: String(cfg.regionId),
        createdAt: obj.created_at ?? undefined,
        addresses: lbAddresses(obj),
        members: [],
        listeners: (obj.listeners ?? []).flatMap((l) =>
          l.protocol_port ? [{ port: l.protocol_port, protocol: 'TCP' }] : [],
        ),
      },
      raw: obj,
    };
  },

  async inventory(cfg) {
    const [lbs, fips, flavors] = await Promise.all([
      gcore(cfg, 'inventory', 'GET', `/cloud/v1/loadbalancers/${scope(cfg)}?limit=1000`, LbList),
      gcore(
        cfg,
        'inventory',
        'GET',
        `/cloud/v1/floatingips/${scope(cfg)}?limit=1000`,
        FipList,
      ).catch(() => ({ results: [] })),
      gcore(cfg, 'inventory', 'GET', `/cloud/v1/lbflavors/${scope(cfg)}`, FlavorList).catch(() => ({
        results: [],
      })),
    ]);
    const inv: Inventory = {
      loadBalancers: lbs.results.map((l) => ({
        id: l.id,
        name: l.name ?? l.id,
        status: l.provisioning_status ?? undefined,
        addresses: lbAddresses(l),
        createdAt: l.created_at ?? undefined,
      })),
      ips: fips.results.map((f) => ({
        id: f.id,
        address: f.floating_ip_address ?? '',
        attachedTo: null,
      })),
      flavors: flavors.results.flatMap((f) =>
        f.flavor_name ? [{ id: f.flavor_name, label: f.flavor_name }] : [],
      ),
    };
    return inv;
  },

  planDestroy: (_cfg, ledger) => reverseLiveResources(ledger),

  async runDestroy(cfg, r) {
    const path =
      r.kind === 'lb'
        ? `/cloud/v1/loadbalancers/${scope(cfg)}/${encodeURIComponent(r.resourceId)}`
        : r.kind === 'floating_ip'
          ? `/cloud/v1/floatingips/${scope(cfg)}/${encodeURIComponent(r.resourceId)}`
          : null;
    if (!path) return { status: 'confirmed_gone' }; // listeners/pools die with the LB
    try {
      const res = await gcore(
        cfg,
        'destroy',
        'DELETE',
        path,
        Tasks.or(z.unknown()),
        undefined,
        [404],
      );
      const opRef =
        res && typeof res === 'object' && 'tasks' in res
          ? (res as { tasks: string[] }).tasks[0]
          : undefined;
      return { status: 'delete_requested', opRef };
    } catch (e) {
      if (isProviderNotFound(e)) return { status: 'confirmed_gone' };
      throw e;
    }
  },

  async confirmDestroyed(cfg, r) {
    const path =
      r.kind === 'lb'
        ? `/cloud/v1/loadbalancers/${scope(cfg)}/${encodeURIComponent(r.resourceId)}`
        : r.kind === 'floating_ip'
          ? `/cloud/v1/floatingips/${scope(cfg)}/${encodeURIComponent(r.resourceId)}`
          : null;
    if (!path) return { status: 'confirmed_gone' };
    try {
      await gcore(cfg, 'confirm-destroy', 'GET', path, z.unknown());
      return { status: 'unresolved' };
    } catch (e) {
      if (isProviderNotFound(e)) return { status: 'confirmed_gone' };
      throw e;
    }
  },
};

async function gcoreRegions(cfg: GcoreConfig): Promise<Array<{ id: string; label: string }>> {
  const res = await gcore(cfg, 'regions', 'GET', `/cloud/v1/regions`, RegionList);
  return res.results.map((r) => ({ id: String(r.id), label: r.display_name ?? String(r.id) }));
}

function codeOf(e: unknown): string {
  return e instanceof EdgeProviderError
    ? (e.meta.code ?? String(e.meta.status ?? 'error'))
    : 'error';
}

function unknownStep(step: ResourceStep): EdgeProviderError {
  return new EdgeProviderError(`gcore: unknown step kind ${step.kind}`, {
    provider: 'gcore',
    step: step.id,
    code: 'unknown_step',
    retryable: false,
    timedOut: false,
  });
}

export type {
  LedgerResource as GcoreLedgerResource,
  DestroyOutcome as GcoreDestroyOutcome,
  InspectResult as GcoreInspectResult,
  Discovery as GcoreDiscovery,
};
export { metaOf as gcoreMetaOf };
