/**
 * The Gcore Cloud API transport both Gcore modules share (`gcore.ts`, the load
 * balancer adapter, and `gcoreDdos.ts`, its Advanced DDoS protection): the
 * base URL, the API key header, the project/region path scope and the task
 * shapes every write answers with.
 */
import { z } from 'zod';
import type { Addresses, GcoreConfig } from './types';
import { providerFetch } from './http';
import { addressFamily, isPublicIpLiteral } from '../ip';

export const GCORE_BASE = 'https://api.gcore.com';

/** Every write answers with the tasks it started (`GET /cloud/v1/tasks/{id}` reads one). */
export const GcoreTasks = z.object({ tasks: z.array(z.string()).min(1) });
export const GcoreTask = z
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
export type GcoreTaskBody = z.infer<typeof GcoreTask>;

export function gcoreHeaders(cfg: GcoreConfig): Record<string, string> {
  return { authorization: `APIKey ${cfg.apiKey}` };
}

/** `{project}/{region}`: the path scope of every regional collection. */
export const gcoreScope = (cfg: GcoreConfig) => `${cfg.projectId}/${cfg.regionId}`;

export async function gcore<T>(
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
    url: `${GCORE_BASE}${path}`,
    method,
    headers: gcoreHeaders(cfg),
    body,
    schema,
    okStatuses,
  });
}

export async function gcoreTask(cfg: GcoreConfig, step: string, taskId: string) {
  return gcore(cfg, step, 'GET', `/cloud/v1/tasks/${encodeURIComponent(taskId)}`, GcoreTask);
}

/** A task's state, reduced: `FINISHED`, `ERROR`, or still running. */
export function taskState(t: GcoreTaskBody): 'finished' | 'error' | 'running' {
  const s = t.state.toUpperCase();
  return s === 'FINISHED' ? 'finished' : s === 'ERROR' ? 'error' : 'running';
}

// --- the load balancer object --------------------------------------------------------

/** A profile as one load balancer reports it (`?with_ddos=true`; `GetClientProfileSerializer`). */
export const GcoreLbDdosProfile = z
  .object({
    id: z.number(),
    options: z
      .object({ active: z.boolean().nullish(), bgp: z.boolean().nullish() })
      .passthrough()
      .nullish(),
    status: z
      .object({ status: z.string().nullish(), error_description: z.string().nullish() })
      .passthrough()
      .nullish(),
    profile_template: z
      .object({ id: z.number().nullish(), name: z.string().nullish() })
      .passthrough()
      .nullish(),
  })
  .passthrough();

export const GcoreFloatingIp = z
  .object({ id: z.string().nullish(), floating_ip_address: z.string().nullish() })
  .passthrough();
export const GcoreLb = z
  .object({
    id: z.string(),
    name: z.string().nullish(),
    provisioning_status: z.string().nullish(),
    operating_status: z.string().nullish(),
    vip_address: z.string().nullish(),
    vip_ipv6_address: z.string().nullish(),
    // Where the current API reports a second (IPv6) VIP.
    additional_vips: z
      .array(z.object({ ip_address: z.string().nullish() }).passthrough())
      .nullish(),
    floating_ips: z.array(GcoreFloatingIp).nullish(),
    flavor: z
      .union([z.string(), z.object({ flavor_name: z.string().nullish() }).passthrough()])
      .nullish(),
    created_at: z.string().nullish(),
    listeners: z
      .array(
        z.object({ id: z.string().nullish(), protocol_port: z.number().nullish() }).passthrough(),
      )
      .nullish(),
    /** Present only when read `?with_ddos=true` and a profile is attached. */
    ddos_profile: GcoreLbDdosProfile.nullish(),
  })
  .passthrough();
export type GcoreLbBody = z.infer<typeof GcoreLb>;

/**
 * One load balancer. `withDdos`: also its Advanced DDoS protection profile
 * (`ddos_profile`, null without one).
 */
export async function getGcoreLb(
  cfg: GcoreConfig,
  step: string,
  id: string,
  opts: { withDdos?: boolean } = {},
) {
  return gcore(
    cfg,
    step,
    'GET',
    `/cloud/v1/loadbalancers/${gcoreScope(cfg)}/${encodeURIComponent(id)}${opts.withDdos ? '?with_ddos=true' : ''}`,
    GcoreLb,
  );
}

/**
 * Public addresses only. In private VIP mode `vip_address` is the private VIP
 * (the floating IP is the public one): a non-public literal is never surfaced
 * as the edge's address. Exported for tests.
 */
export function gcoreLbAddresses(lb: {
  vip_address?: string | null;
  vip_ipv6_address?: string | null;
  additional_vips?: Array<{ ip_address?: string | null }> | null;
  floating_ips?: Array<{ floating_ip_address?: string | null }> | null;
}): Addresses {
  const out: Addresses = {};
  const fip = lb.floating_ips?.find((f) => f.floating_ip_address)?.floating_ip_address ?? undefined;
  const extra = (lb.additional_vips ?? []).map((v) => v.ip_address ?? undefined);
  const candidates = [
    fip,
    lb.vip_address ?? undefined,
    lb.vip_ipv6_address ?? undefined,
    ...extra,
  ].filter((x): x is string => !!x && isPublicIpLiteral(x));
  for (const c of candidates) {
    const fam = addressFamily(c);
    if (fam === 'v4' && !out.v4) out.v4 = c;
    if (fam === 'v6' && !out.v6) out.v6 = c;
  }
  return out;
}
