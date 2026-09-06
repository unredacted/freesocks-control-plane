/**
 * Per-provider edge-template schemas, form descriptors and defaults, kept
 * SDK-free so isolate code (mutations validating an admin's template edit) can
 * import them without dragging the Scaleway SDK into the isolate bundle. The
 * adapters re-export their own schema from here.
 */
import { z } from 'zod';
import type { EdgeProviderId } from '../../edgeProviderIds';
import type { TemplateFieldDescriptor } from './types';

// --- Gcore -------------------------------------------------------------------------

export const GcoreTemplate = z.object({
  flavor: z.string().min(1).max(64).default('lb1-1-2'),
  /** public = the provider assigns a public VIP directly; private = private VIP + floating IP. */
  vipMode: z.enum(['public', 'private']).default('public'),
  ipFamily: z.enum(['dual', 'ipv4', 'ipv6']).default('dual'),
  lbAlgorithm: z.enum(['ROUND_ROBIN', 'LEAST_CONNECTIONS', 'SOURCE_IP']).default('ROUND_ROBIN'),
  timeoutClientDataMs: z.number().int().min(1_000).max(3_600_000).default(300_000),
  timeoutMemberConnectMs: z.number().int().min(1_000).max(60_000).default(5_000),
  timeoutMemberDataMs: z.number().int().min(1_000).max(3_600_000).default(300_000),
  /** 0 = provider default (field omitted). */
  connectionLimit: z.number().int().min(0).max(1_000_000).default(0),
  allowedCidrs: z.array(z.string().min(1)).max(50).default([]),
  healthMonitor: z
    .object({
      delay: z.number().int().min(1).max(600).default(10),
      timeout: z.number().int().min(1).max(600).default(5),
      maxRetries: z.number().int().min(1).max(10).default(3),
      maxRetriesDown: z.number().int().min(1).max(10).default(3),
    })
    .default({ delay: 10, timeout: 5, maxRetries: 3, maxRetriesDown: 3 }),
  tags: z.record(z.string().min(1).max(64), z.string().max(128)).default({}),
});
export type GcoreTemplateParams = z.infer<typeof GcoreTemplate>;

export const GCORE_TEMPLATE_FIELDS: TemplateFieldDescriptor[] = [
  {
    key: 'flavor',
    label: 'Flavor',
    type: 'string',
    help: 'Load balancer flavor name for the region.',
  },
  {
    key: 'vipMode',
    label: 'VIP mode',
    type: 'select',
    options: [
      { value: 'public', label: 'Public VIP' },
      { value: 'private', label: 'Private VIP + floating IP (needs network + subnet)' },
    ],
  },
  {
    key: 'ipFamily',
    label: 'IP family',
    type: 'select',
    options: [
      { value: 'dual', label: 'IPv4 + IPv6' },
      { value: 'ipv4', label: 'IPv4 only' },
      { value: 'ipv6', label: 'IPv6 only' },
    ],
  },
  {
    key: 'lbAlgorithm',
    label: 'Algorithm',
    type: 'select',
    options: [
      { value: 'ROUND_ROBIN', label: 'Round robin' },
      { value: 'LEAST_CONNECTIONS', label: 'Least connections' },
      { value: 'SOURCE_IP', label: 'Source IP' },
    ],
  },
  { key: 'timeoutClientDataMs', label: 'Client idle timeout (ms)', type: 'number' },
  { key: 'timeoutMemberConnectMs', label: 'Origin connect timeout (ms)', type: 'number' },
  { key: 'timeoutMemberDataMs', label: 'Origin idle timeout (ms)', type: 'number' },
  { key: 'connectionLimit', label: 'Connection limit (0 = default)', type: 'number' },
  { key: 'allowedCidrs', label: 'Allowed client CIDRs', type: 'string-list' },
  { key: 'healthMonitor.delay', label: 'Health check delay (s)', type: 'number' },
  { key: 'healthMonitor.timeout', label: 'Health check timeout (s)', type: 'number' },
  { key: 'healthMonitor.maxRetries', label: 'Health check retries up', type: 'number' },
  { key: 'healthMonitor.maxRetriesDown', label: 'Health check retries down', type: 'number' },
];

// --- UpCloud -----------------------------------------------------------------------

export const UpcloudTemplate = z.object({
  plan: z.string().min(1).max(64).default('development'),
  delegateFloatingIp: z.boolean().default(true),
  timeoutClient: z.number().int().min(10).max(86_400).default(300),
  timeoutServer: z.number().int().min(10).max(86_400).default(300),
  timeoutTunnel: z.number().int().min(10).max(86_400).default(3600),
  healthCheck: z
    .object({
      interval: z.number().int().min(1).max(3600).default(10),
      timeout: z.number().int().min(1).max(600).default(10),
      fall: z.number().int().min(1).max(100).default(3),
      rise: z.number().int().min(1).max(100).default(3),
    })
    .default({ interval: 10, timeout: 10, fall: 3, rise: 3 }),
  labels: z
    .array(z.object({ key: z.string().min(1).max(32), value: z.string().max(255) }))
    .max(10)
    .default([]),
});
export type UpcloudTemplateParams = z.infer<typeof UpcloudTemplate>;

export const UPCLOUD_TEMPLATE_FIELDS: TemplateFieldDescriptor[] = [
  { key: 'plan', label: 'Plan', type: 'string', help: 'development, production-small, …' },
  {
    key: 'delegateFloatingIp',
    label: 'Delegate a floating IPv4',
    type: 'boolean',
    help: 'The service address is not stable without one.',
  },
  { key: 'timeoutClient', label: 'Client idle timeout (s)', type: 'number' },
  { key: 'timeoutServer', label: 'Origin idle timeout (s)', type: 'number' },
  { key: 'timeoutTunnel', label: 'Tunnel timeout (s)', type: 'number' },
  { key: 'healthCheck.interval', label: 'Health check interval (s)', type: 'number' },
  { key: 'healthCheck.timeout', label: 'Health check timeout (s)', type: 'number' },
  { key: 'healthCheck.fall', label: 'Unhealthy threshold', type: 'number' },
  { key: 'healthCheck.rise', label: 'Healthy threshold', type: 'number' },
];

// --- Scaleway ----------------------------------------------------------------------

const DURATION = /^\d{1,7}(ms|s|m|h)$/;

export const ScalewayTemplate = z.object({
  type: z.string().min(1).max(32).default('LB-S'),
  ipv6: z.boolean().default(true),
  forwardPortAlgorithm: z.enum(['roundrobin', 'leastconn', 'first']).default('roundrobin'),
  timeoutClient: z.string().regex(DURATION).default('600s'),
  timeoutServer: z.string().regex(DURATION).default('600s'),
  timeoutTunnel: z.string().regex(DURATION).default('3600s'),
  timeoutConnect: z.string().regex(DURATION).default('5s'),
  healthCheck: z
    .object({
      checkDelay: z.string().regex(DURATION).default('5s'),
      checkTimeout: z.string().regex(DURATION).default('3s'),
      checkMaxRetries: z.number().int().min(1).max(20).default(3),
    })
    .default({ checkDelay: '5s', checkTimeout: '3s', checkMaxRetries: 3 }),
  tags: z.array(z.string().min(1).max(64)).max(10).default([]),
});
export type ScalewayTemplateParams = z.infer<typeof ScalewayTemplate>;

export const SCALEWAY_TEMPLATE_FIELDS: TemplateFieldDescriptor[] = [
  { key: 'type', label: 'Offer type', type: 'string', help: 'LB-S, LB-GP-M, LB-GP-L, …' },
  { key: 'ipv6', label: 'Also allocate a flexible IPv6', type: 'boolean' },
  {
    key: 'forwardPortAlgorithm',
    label: 'Algorithm',
    type: 'select',
    options: [
      { value: 'roundrobin', label: 'Round robin' },
      { value: 'leastconn', label: 'Least connections' },
      { value: 'first', label: 'First available' },
    ],
  },
  { key: 'timeoutClient', label: 'Client idle timeout', type: 'string', help: 'e.g. 600s' },
  { key: 'timeoutServer', label: 'Origin idle timeout', type: 'string' },
  { key: 'timeoutTunnel', label: 'Tunnel timeout', type: 'string' },
  { key: 'timeoutConnect', label: 'Origin connect timeout', type: 'string' },
  { key: 'healthCheck.checkDelay', label: 'Health check delay', type: 'string' },
  { key: 'healthCheck.checkTimeout', label: 'Health check timeout', type: 'string' },
  { key: 'healthCheck.checkMaxRetries', label: 'Health check retries', type: 'number' },
  { key: 'tags', label: 'Extra tags', type: 'string-list' },
];

// --- OVH ---------------------------------------------------------------------------

export const OvhTemplate = z.object({
  /** Required at provisioning time: the regional LB flavor id (see inventory.flavors). */
  flavorId: z.string().max(64).default(''),
  gatewayModel: z.enum(['s', 'm', 'l']).default('s'),
  algorithm: z.enum(['roundRobin', 'leastConnections', 'sourceIp']).default('roundRobin'),
  healthMonitor: z
    .object({
      delay: z.number().int().min(1).max(600).default(5),
      timeout: z.number().int().min(1).max(600).default(3),
      maxRetries: z.number().int().min(1).max(10).default(3),
    })
    .default({ delay: 5, timeout: 3, maxRetries: 3 }),
  timeoutClientDataMs: z.number().int().min(1000).max(3_600_000).default(300_000),
  timeoutMemberDataMs: z.number().int().min(1000).max(3_600_000).default(300_000),
  allowedCidrs: z.array(z.string().min(1)).max(50).default([]),
});
export type OvhTemplateParams = z.infer<typeof OvhTemplate>;

export const OVH_TEMPLATE_FIELDS: TemplateFieldDescriptor[] = [
  {
    key: 'flavorId',
    label: 'Flavor id',
    type: 'string',
    required: true,
    help: 'From the account inventory (Pull live).',
  },
  {
    key: 'gatewayModel',
    label: 'Gateway model (only when no gateway id is set)',
    type: 'select',
    options: [
      { value: 's', label: 'S' },
      { value: 'm', label: 'M' },
      { value: 'l', label: 'L' },
    ],
  },
  {
    key: 'algorithm',
    label: 'Algorithm',
    type: 'select',
    options: [
      { value: 'roundRobin', label: 'Round robin' },
      { value: 'leastConnections', label: 'Least connections' },
      { value: 'sourceIp', label: 'Source IP' },
    ],
  },
  { key: 'healthMonitor.delay', label: 'Health check delay (s)', type: 'number' },
  { key: 'healthMonitor.timeout', label: 'Health check timeout (s)', type: 'number' },
  { key: 'healthMonitor.maxRetries', label: 'Health check retries', type: 'number' },
  { key: 'timeoutClientDataMs', label: 'Client idle timeout (ms)', type: 'number' },
  { key: 'timeoutMemberDataMs', label: 'Origin idle timeout (ms)', type: 'number' },
  { key: 'allowedCidrs', label: 'Allowed client CIDRs', type: 'string-list' },
];

// --- registry ----------------------------------------------------------------------

export interface TemplateDefinition {
  schema: z.ZodType<Record<string, unknown>>;
  fields: TemplateFieldDescriptor[];
  defaults: Record<string, unknown>;
}

export const EDGE_TEMPLATES: Record<EdgeProviderId, TemplateDefinition> = {
  gcore: {
    schema: GcoreTemplate as unknown as z.ZodType<Record<string, unknown>>,
    fields: GCORE_TEMPLATE_FIELDS,
    defaults: GcoreTemplate.parse({}),
  },
  upcloud: {
    schema: UpcloudTemplate as unknown as z.ZodType<Record<string, unknown>>,
    fields: UPCLOUD_TEMPLATE_FIELDS,
    defaults: UpcloudTemplate.parse({}),
  },
  scaleway: {
    schema: ScalewayTemplate as unknown as z.ZodType<Record<string, unknown>>,
    fields: SCALEWAY_TEMPLATE_FIELDS,
    defaults: ScalewayTemplate.parse({}),
  },
  ovh: {
    schema: OvhTemplate as unknown as z.ZodType<Record<string, unknown>>,
    fields: OVH_TEMPLATE_FIELDS,
    defaults: OvhTemplate.parse({}),
  },
};

/** Validate raw params for a provider; returns the parsed params or a short issue list. */
export function validateTemplateParams(
  provider: EdgeProviderId,
  raw: unknown,
): { ok: true; params: Record<string, unknown> } | { ok: false; issues: string[] } {
  const res = EDGE_TEMPLATES[provider].schema.safeParse(raw ?? {});
  if (res.success) return { ok: true, params: res.data };
  return {
    ok: false,
    issues: res.error.issues
      .slice(0, 10)
      .map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`),
  };
}
