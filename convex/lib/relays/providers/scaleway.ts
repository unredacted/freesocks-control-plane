/**
 * Scaleway Load Balancer adapter, driven by the official `@scaleway/sdk-lb` +
 * `@scaleway/sdk-client` (zero runtime deps, native fetch — the fetch used is
 * injectable so tests stub it).
 *
 * Model (synchronous zoned API, five small steps): allocate a flexible IPv4
 * (+ an IPv6 when the template asks), create the LB with those IP ids, add a
 * TCP backend pointing at the origin, add a frontend on the edge port. Deletes
 * are asynchronous on the LB (`to_delete` → gone); IPs release synchronously.
 *
 * Discovery: every resource carries our deterministic name or tag and the
 * listings are authoritative, so each step answers found / confirmed_absent.
 */
import { z } from 'zod';
import { createClient } from '@scaleway/sdk-client';
import { Lbv1 } from '@scaleway/sdk-lb';
import type {
  Addresses,
  ChildResource,
  EdgeDescription,
  EdgeSpec,
  Ledger,
  RelayProvider,
  ResourceStep,
  ScalewayConfig,
  StepOutcome,
  TemplateFieldDescriptor,
} from './types';
import { firstResource, resourcesOfKind, reverseLiveResources } from './types';
import { RelayProviderError, toProviderError } from './http';
import { addressFamily } from '../ip';
import {
  ScalewayTemplate,
  SCALEWAY_TEMPLATE_FIELDS,
  type ScalewayTemplateParams,
} from './templates';

export { ScalewayTemplate, SCALEWAY_TEMPLATE_FIELDS } from './templates';
export type { ScalewayTemplateParams } from './templates';

export const SCALEWAY_ZONES = [
  'fr-par-1',
  'fr-par-2',
  'nl-ams-1',
  'nl-ams-2',
  'nl-ams-3',
  'pl-waw-1',
  'pl-waw-2',
  'pl-waw-3',
];

type ZonedApi = InstanceType<typeof Lbv1.ZonedAPI>;
type FetchLike = typeof fetch;

/** Build the SDK client. `fetchImpl` is injectable for tests. */
export function scalewayApi(cfg: ScalewayConfig, fetchImpl?: FetchLike): ZonedApi {
  const client = createClient({
    accessKey: cfg.accessKey,
    secretKey: cfg.secretKey,
    defaultProjectId: cfg.projectId,
    defaultZone: cfg.zone as never,
    httpClient: fetchImpl ?? ((input, init) => fetch(input, init)),
    userAgent: 'fcp-relay/1',
  });
  return new Lbv1.ZonedAPI(client);
}

let apiFactory: (cfg: ScalewayConfig) => ZonedApi = (cfg) => scalewayApi(cfg);
/** Test seam: replace the SDK client factory. */
export function __setScalewayApiFactory(f: ((cfg: ScalewayConfig) => ZonedApi) | null): void {
  apiFactory = f ?? ((cfg) => scalewayApi(cfg));
}

async function sdk<T>(step: string, fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    throw toProviderError('scaleway', step, e);
  }
}

function isNotFound(e: unknown): boolean {
  return e instanceof RelayProviderError && e.meta.status === 404;
}

function addressesOf(ips: Array<{ ipAddress: string }>): Addresses {
  const out: Addresses = {};
  for (const ip of ips) {
    const fam = addressFamily(ip.ipAddress);
    if (fam === 'v4' && !out.v4) out.v4 = ip.ipAddress;
    if (fam === 'v6' && !out.v6) out.v6 = ip.ipAddress;
  }
  return out;
}

function lbState(status: string): EdgeDescription['state'] {
  switch (status) {
    case 'ready':
      return 'active';
    case 'error':
    case 'locked':
    case 'stopped':
      return 'error';
    default:
      return 'pending';
  }
}

export const scalewayProvider: RelayProvider<ScalewayConfig, ScalewayTemplateParams> = {
  id: 'scaleway',
  templateSchema: ScalewayTemplate,
  templateFields: SCALEWAY_TEMPLATE_FIELDS,
  defaultTemplate: ScalewayTemplate.parse({}),

  async testCredentials(cfg) {
    try {
      await sdk('test', () => apiFactory(cfg).listLbs({ pageSize: 1, projectId: cfg.projectId }));
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

  async listRegions() {
    return SCALEWAY_ZONES.map((z) => ({ id: z, label: z }));
  },

  planProvision(_cfg, spec, tpl) {
    const steps: ResourceStep[] = [
      { id: 'ip4', kind: 'allocate_ip', resourceName: spec.name, discoverability: 'by_tag' },
    ];
    if (tpl.ipv6)
      steps.push({
        id: 'ip6',
        kind: 'allocate_ipv6',
        resourceName: spec.name,
        discoverability: 'by_tag',
      });
    steps.push({
      id: 'lb',
      kind: 'create_lb',
      resourceName: spec.name,
      discoverability: 'by_name',
    });
    steps.push({
      id: 'backend',
      kind: 'create_backend',
      resourceName: `${spec.name}-backend`,
      discoverability: 'by_name',
    });
    steps.push({
      id: 'frontend',
      kind: 'create_frontend',
      resourceName: `${spec.name}-frontend`,
      discoverability: 'by_name',
    });
    return steps;
  },

  async runStep(cfg, step, spec, tpl, ledger): Promise<StepOutcome> {
    const api = apiFactory(cfg);
    const listener = spec.listeners[0];
    if (!listener)
      throw new RelayProviderError('scaleway: spec has no listener', {
        provider: 'scaleway',
        step: step.id,
        code: 'spec_invalid',
        retryable: false,
        timedOut: false,
      });
    switch (step.kind) {
      case 'allocate_ip':
      case 'allocate_ipv6': {
        const isIpv6 = step.kind === 'allocate_ipv6';
        const ip = await sdk(step.id, () =>
          api.createIp({ projectId: cfg.projectId, isIpv6, tags: [spec.name] }),
        );
        return {
          status: 'done',
          resources: [
            {
              kind: isIpv6 ? 'ipv6' : 'ip',
              resourceId: ip.id,
              ownership: 'created',
              meta: { address: ip.ipAddress },
            },
          ],
          addresses: isIpv6 ? { v6: ip.ipAddress } : { v4: ip.ipAddress },
        };
      }
      case 'create_lb': {
        const ipIds = [...resourcesOfKind(ledger, 'ip'), ...resourcesOfKind(ledger, 'ipv6')].map(
          (r) => r.resourceId,
        );
        const lb = await sdk(step.id, () =>
          api.createLb({
            name: spec.name,
            description: 'relay edge',
            type: tpl.type,
            projectId: cfg.projectId,
            ipIds,
            assignFlexibleIp: false,
            tags: [spec.name, ...tpl.tags],
          }),
        );
        return {
          status: 'done',
          resources: [{ kind: 'lb', resourceId: lb.id, ownership: 'created' }],
          addresses: addressesOf(lb.ip),
        };
      }
      case 'create_backend': {
        const lb = firstResource(ledger, 'lb');
        if (!lb) throw ledgerIncomplete(step);
        const backend = await sdk(step.id, () =>
          api.createBackend({
            lbId: lb.resourceId,
            name: step.resourceName,
            forwardProtocol: 'tcp',
            forwardPort: listener.members[0]?.port ?? 443,
            forwardPortAlgorithm: tpl.forwardPortAlgorithm,
            stickySessions: 'none',
            stickySessionsCookieName: '',
            healthCheck: {
              port: listener.members[0]?.port ?? 443,
              checkDelay: tpl.healthCheck.checkDelay,
              checkTimeout: tpl.healthCheck.checkTimeout,
              checkMaxRetries: tpl.healthCheck.checkMaxRetries,
              tcpConfig: {},
              checkSendProxy: false,
            },
            serverIp: listener.members.map((m) => m.address),
            timeoutServer: tpl.timeoutServer,
            timeoutConnect: tpl.timeoutConnect,
            timeoutTunnel: tpl.timeoutTunnel,
            proxyProtocol: 'proxy_protocol_none',
            onMarkedDownAction: 'on_marked_down_action_none',
          }),
        );
        return {
          status: 'done',
          resources: [{ kind: 'backend', resourceId: backend.id, ownership: 'created' }],
        };
      }
      case 'create_frontend': {
        const lb = firstResource(ledger, 'lb');
        const backend = firstResource(ledger, 'backend');
        if (!lb || !backend) throw ledgerIncomplete(step);
        const frontend = await sdk(step.id, () =>
          api.createFrontend({
            lbId: lb.resourceId,
            name: step.resourceName,
            inboundPort: listener.edgePort,
            backendId: backend.resourceId,
            timeoutClient: tpl.timeoutClient,
            enableHttp3: false,
            enableAccessLogs: false,
          }),
        );
        return {
          status: 'done',
          resources: [{ kind: 'frontend', resourceId: frontend.id, ownership: 'created' }],
        };
      }
      default:
        throw new RelayProviderError(`scaleway: unknown step kind ${step.kind}`, {
          provider: 'scaleway',
          step: step.id,
          code: 'unknown_step',
          retryable: false,
          timedOut: false,
        });
    }
  },

  async discover(cfg, step, spec, ledger) {
    const api = apiFactory(cfg);
    switch (step.kind) {
      case 'allocate_ip':
      case 'allocate_ipv6': {
        const wantV6 = step.kind === 'allocate_ipv6';
        const ips = await sdk(step.id, () => api.listIPs({ projectId: cfg.projectId }).all());
        const hit = ips.find(
          (ip) => ip.tags.includes(spec.name) && (addressFamily(ip.ipAddress) === 'v6') === wantV6,
        );
        return hit
          ? {
              status: 'found',
              resources: [
                {
                  kind: wantV6 ? 'ipv6' : 'ip',
                  resourceId: hit.id,
                  ownership: 'adopted',
                  meta: { address: hit.ipAddress },
                },
              ],
              addresses: wantV6 ? { v6: hit.ipAddress } : { v4: hit.ipAddress },
            }
          : { status: 'confirmed_absent' };
      }
      case 'create_lb': {
        const lbs = await sdk(step.id, () =>
          api.listLbs({ name: spec.name, projectId: cfg.projectId }).all(),
        );
        const hit = lbs.find((l) => l.name === spec.name);
        return hit
          ? {
              status: 'found',
              resources: [{ kind: 'lb', resourceId: hit.id, ownership: 'adopted' }],
              addresses: addressesOf(hit.ip),
            }
          : { status: 'confirmed_absent' };
      }
      case 'create_backend': {
        const lb = firstResource(ledger, 'lb');
        if (!lb) return { status: 'confirmed_absent' };
        const list = await sdk(step.id, () =>
          api.listBackends({ lbId: lb.resourceId, name: step.resourceName }).all(),
        );
        const hit = list.find((b) => b.name === step.resourceName);
        return hit
          ? {
              status: 'found',
              resources: [{ kind: 'backend', resourceId: hit.id, ownership: 'adopted' }],
            }
          : { status: 'confirmed_absent' };
      }
      case 'create_frontend': {
        const lb = firstResource(ledger, 'lb');
        if (!lb) return { status: 'confirmed_absent' };
        const list = await sdk(step.id, () =>
          api.listFrontends({ lbId: lb.resourceId, name: step.resourceName }).all(),
        );
        const hit = list.find((f) => f.name === step.resourceName);
        return hit
          ? {
              status: 'found',
              resources: [{ kind: 'frontend', resourceId: hit.id, ownership: 'adopted' }],
            }
          : { status: 'confirmed_absent' };
      }
      default:
        return { status: 'confirmed_absent' };
    }
  },

  async describe(cfg, ledger) {
    const lb = firstResource(ledger, 'lb');
    if (!lb) return { state: 'pending', addresses: {}, health: 'unknown', code: 'no_lb_yet' };
    const api = apiFactory(cfg);
    let obj;
    try {
      obj = await sdk('describe', () => api.getLb({ lbId: lb.resourceId }));
    } catch (e) {
      if (isNotFound(e)) return { state: 'gone', addresses: {}, health: 'unknown' };
      throw e;
    }
    const state = lbState(obj.status);
    let health: EdgeDescription['health'] = 'unknown';
    if (state === 'active') {
      try {
        const stats = await sdk('describe-stats', () => api.getLbStats({ lbId: lb.resourceId }));
        const checks = stats.backendServersStats.map((s) => String(s.lastHealthCheckStatus));
        if (checks.length > 0)
          health = checks.some((c) => c === 'passed')
            ? 'online'
            : checks.every((c) => c === 'failed')
              ? 'offline'
              : 'degraded';
      } catch {
        health = 'unknown';
      }
    }
    // Adopt IPs the LB reports that the ledger does not know (e.g. assigned by the provider).
    const known = new Set(ledger.resources.map((r) => r.resourceId));
    const resources: ChildResource[] = obj.ip
      .filter((ip) => !known.has(ip.id))
      .map((ip) => ({
        kind: addressFamily(ip.ipAddress) === 'v6' ? 'ipv6' : 'ip',
        resourceId: ip.id,
        ownership: 'created' as const,
        meta: { address: ip.ipAddress },
      }));
    return {
      state,
      addresses: addressesOf(obj.ip),
      health,
      ...(resources.length > 0 ? { resources } : {}),
    };
  },

  async inspect(cfg, ledger) {
    const lb = firstResource(ledger, 'lb');
    if (!lb)
      throw new RelayProviderError('scaleway inspect: no lb in ledger', {
        provider: 'scaleway',
        step: 'inspect',
        code: 'no_lb',
        retryable: false,
        timedOut: false,
      });
    const api = apiFactory(cfg);
    const obj = await sdk('inspect', () => api.getLb({ lbId: lb.resourceId }));
    const [backends, frontends, stats] = await Promise.all([
      sdk('inspect', () => api.listBackends({ lbId: lb.resourceId }).all()).catch(() => []),
      sdk('inspect', () => api.listFrontends({ lbId: lb.resourceId }).all()).catch(() => []),
      sdk('inspect', () => api.getLbStats({ lbId: lb.resourceId })).catch(() => null),
    ]);
    const healthByIp = new Map(
      (stats?.backendServersStats ?? []).map((s) => [s.ip, String(s.lastHealthCheckStatus)]),
    );
    return {
      summary: {
        status: obj.status,
        flavor: obj.type,
        region: obj.zone,
        createdAt: obj.createdAt?.toISOString(),
        addresses: addressesOf(obj.ip),
        members: backends.flatMap((b) =>
          b.pool.map((ip) => ({ address: ip, port: b.forwardPort, health: healthByIp.get(ip) })),
        ),
        listeners: frontends.map((f) => ({ port: f.inboundPort, protocol: 'tcp' })),
      },
      raw: { lb: obj, backends, frontends, stats },
    };
  },

  async inventory(cfg) {
    const api = apiFactory(cfg);
    const [lbs, ips, types] = await Promise.all([
      sdk('inventory', () => api.listLbs({ projectId: cfg.projectId }).all()),
      sdk('inventory', () => api.listIPs({ projectId: cfg.projectId }).all()).catch(() => []),
      sdk('inventory', () => api.listLbTypes({}).all()).catch(() => []),
    ]);
    return {
      loadBalancers: lbs.map((l) => ({
        id: l.id,
        name: l.name,
        status: l.status,
        addresses: addressesOf(l.ip),
        createdAt: l.createdAt?.toISOString(),
      })),
      ips: ips.map((ip) => ({ id: ip.id, address: ip.ipAddress, attachedTo: ip.lbId ?? null })),
      flavors: types.map((t) => ({ id: t.name, label: t.name })),
    };
  },

  planDestroy: (_cfg, ledger) => reverseLiveResources(ledger),

  async runDestroy(cfg, r) {
    const api = apiFactory(cfg);
    try {
      switch (r.kind) {
        case 'frontend':
          await sdk('destroy', () => api.deleteFrontend({ frontendId: r.resourceId }));
          return { status: 'confirmed_gone' };
        case 'backend':
          await sdk('destroy', () => api.deleteBackend({ backendId: r.resourceId }));
          return { status: 'confirmed_gone' };
        case 'lb':
          await sdk('destroy', () => api.deleteLb({ lbId: r.resourceId, releaseIp: false }));
          return { status: 'delete_requested' };
        case 'ip':
        case 'ipv6':
          await sdk('destroy', () => api.releaseIp({ ipId: r.resourceId }));
          return { status: 'confirmed_gone' };
        default:
          return { status: 'confirmed_gone' };
      }
    } catch (e) {
      if (isNotFound(e)) return { status: 'confirmed_gone' };
      throw e;
    }
  },

  async confirmDestroyed(cfg, r) {
    if (r.kind !== 'lb') return { status: 'confirmed_gone' };
    try {
      const lb = await sdk('confirm-destroy', () => apiFactory(cfg).getLb({ lbId: r.resourceId }));
      return lb.status === 'deleting' || lb.status === 'to_delete'
        ? { status: 'unresolved' }
        : { status: 'unresolved' };
    } catch (e) {
      if (isNotFound(e)) return { status: 'confirmed_gone' };
      throw e;
    }
  },
};

function ledgerIncomplete(step: ResourceStep): RelayProviderError {
  return new RelayProviderError(`scaleway ${step.id}: ledger missing a prerequisite resource`, {
    provider: 'scaleway',
    step: step.id,
    code: 'ledger_incomplete',
    retryable: false,
    timedOut: false,
  });
}

export type { Ledger as ScalewayLedger, EdgeSpec as ScalewayEdgeSpec };
