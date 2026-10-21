/**
 * Per-provider edge-template schemas, form descriptors and defaults, kept
 * SDK-free so isolate code (mutations validating an admin's template edit) can
 * import them without dragging the Scaleway SDK into the isolate bundle. The
 * adapters re-export their own schema from here.
 */
import { z } from 'zod';
import type { EdgeProviderId } from '../../edgeProviderIds';
import type { TemplateFieldDescriptor } from './types';
import {
  deepMerge,
  describeFields,
  pickKeys,
  setKeys,
  splitChoices,
  type OptionLevel,
  type Values,
} from './options';

/** Methods an HTTP health check may send (Gcore and OVH take the same list). */
const HTTP_METHODS = [
  'GET',
  'HEAD',
  'POST',
  'PUT',
  'DELETE',
  'OPTIONS',
  'PATCH',
  'CONNECT',
  'TRACE',
] as const;

// --- Gcore -------------------------------------------------------------------------

/** Health check kinds Gcore offers a TCP pool (K8S and UDP-CONNECT left out: not ours). */
const GCORE_MONITOR_TYPES = ['TCP', 'TLS-HELLO', 'PING', 'HTTP', 'HTTPS'] as const;

export const GcoreTemplate = z.object({
  flavor: z.string().min(1).max(64).default('lb1-1-2'),
  /** public = the provider assigns a public VIP directly; private = private VIP + floating IP. */
  vipMode: z.enum(['public', 'private']).default('public'),
  /**
   * Publishing needs an IPv4 (the template Host and every member's primary
   * entry are v4), so an IPv6-only edge could never be published: refused.
   */
  ipFamily: z
    .enum(['dual', 'ipv4', 'ipv6'])
    .default('dual')
    .refine((f) => f !== 'ipv6', {
      message: 'IPv6-only edges cannot be published (an IPv4 is required): use dual or ipv4',
    }),
  lbAlgorithm: z.enum(['ROUND_ROBIN', 'LEAST_CONNECTIONS', 'SOURCE_IP']).default('ROUND_ROBIN'),
  timeoutClientDataMs: z.number().int().min(1_000).max(3_600_000).default(300_000),
  timeoutMemberConnectMs: z.number().int().min(1_000).max(60_000).default(5_000),
  timeoutMemberDataMs: z.number().int().min(1_000).max(3_600_000).default(300_000),
  /** 0 = provider default (field omitted). */
  connectionLimit: z.number().int().min(0).max(1_000_000).default(0),
  allowedCidrs: z.array(z.string().min(1)).max(100).default([]),
  healthMonitor: z
    .object({
      delay: z.number().int().min(1).max(600).default(10),
      timeout: z.number().int().min(1).max(600).default(5),
      maxRetries: z.number().int().min(1).max(10).default(3),
      maxRetriesDown: z.number().int().min(1).max(10).default(3),
      // Options added with provider options: optional, the adapter applies the default.
      type: z.enum(GCORE_MONITOR_TYPES).optional(),
      httpMethod: z.enum(HTTP_METHODS).optional(),
      urlPath: z
        .string()
        .regex(/^\/[^?#%]{0,254}$/, 'a path starting with /, without ? # or %')
        .optional(),
      expectedCodes: z
        .string()
        .regex(/^\d{3}(-\d{3})?(,\d{3}(-\d{3})?)*$/, 'like 200, 200,202 or 200-299')
        .optional(),
      httpVersion: z.enum(['1.0', '1.1']).optional(),
      domainName: z
        .string()
        .regex(/^[A-Za-z0-9._-]{1,253}$/, 'a host name')
        .optional(),
      port: z.number().int().min(1).max(65_535).optional(),
    })
    .default({ delay: 10, timeout: 5, maxRetries: 3, maxRetriesDown: 3 }),
  tags: z.record(z.string().min(1).max(64), z.string().max(128)).default({}),
});
export type GcoreTemplateParams = z.infer<typeof GcoreTemplate>;

const GCORE_HTTP_CHECK = { key: 'healthMonitor.type', in: ['HTTP', 'HTTPS'] };

export const GCORE_TEMPLATE_FIELDS: TemplateFieldDescriptor[] = [
  {
    key: 'flavor',
    label: 'Size',
    type: 'string',
    regional: true,
    prominent: true,
    from: 'flavors',
    group: 'Load balancer',
    help: 'The load balancer flavor of the region: bigger sizes carry more traffic and cost more.',
    wire: { resource: 'loadbalancer', field: 'flavor', manual: true },
    live: 'in_place',
  },
  {
    key: 'ipFamily',
    label: 'IP versions',
    type: 'select',
    prominent: true,
    group: 'Load balancer',
    help: 'An IPv4 address, or IPv4 and IPv6. A private address with a floating IP is IPv4 only.',
    options: [
      { value: 'dual', label: 'IPv4 and IPv6' },
      { value: 'ipv4', label: 'IPv4 only' },
    ],
    wire: { resource: 'loadbalancer', field: 'vip_ip_family', manual: true },
    live: 'rebuild',
  },
  {
    key: 'vipMode',
    label: 'Address type',
    type: 'select',
    group: 'Load balancer',
    advanced: true,
    help: "Public gives the edge a public address directly; private puts a floating IPv4 in front of a private one (the location's network and subnet).",
    options: [
      { value: 'public', label: 'Public address' },
      { value: 'private', label: 'Private address and a floating IP' },
    ],
    wire: { resource: 'loadbalancer', field: 'vip_network_id', manual: true },
    live: 'rebuild',
  },
  {
    key: 'tags',
    label: 'Extra tags',
    type: 'key-value',
    group: 'Load balancer',
    advanced: true,
    help: "Labels added to the load balancer, shown in Gcore's lists and billing.",
    wire: { resource: 'loadbalancer', field: 'tags', manual: true },
    live: 'in_place',
  },
  {
    key: 'connectionLimit',
    label: 'Most connections at once',
    type: 'number',
    group: 'Listener',
    prominent: true,
    help: "Connections the edge accepts at once. 0 keeps Gcore's default (100000).",
    wire: { resource: 'listener', field: 'connection_limit', manual: true },
    live: 'in_place',
  },
  {
    key: 'timeoutClientDataMs',
    label: 'Client idle timeout',
    type: 'number',
    unit: 'ms',
    group: 'Listener',
    help: 'Closes a member connection after this long with no data.',
    wire: { resource: 'listener', field: 'timeout_client_data', manual: true },
    live: 'in_place',
  },
  {
    key: 'allowedCidrs',
    label: 'Allowed client ranges',
    type: 'string-list',
    group: 'Listener',
    advanced: true,
    help: 'Only these address ranges may connect. Empty lets everyone connect; an IPv4-only edge takes IPv4 ranges only.',
    wire: { resource: 'listener', field: 'allowed_cidrs', manual: true },
    live: 'in_place',
  },
  {
    key: 'timeoutMemberConnectMs',
    label: 'Node connect timeout',
    type: 'number',
    unit: 'ms',
    group: 'Listener',
    help: 'Gives up reaching the node after this long.',
    // On the listener, where FCP has always sent it (an existing node's next
    // replacement sends exactly what it did before).
    wire: { resource: 'listener', field: 'timeout_member_connect', manual: true },
    live: 'in_place',
  },
  {
    key: 'timeoutMemberDataMs',
    label: 'Node idle timeout',
    type: 'number',
    unit: 'ms',
    group: 'Listener',
    help: 'Closes the connection to the node after this long with no data.',
    wire: { resource: 'listener', field: 'timeout_member_data', manual: true },
    live: 'in_place',
  },
  {
    key: 'lbAlgorithm',
    label: 'Balancing method',
    type: 'select',
    group: 'Pool',
    advanced: true,
    help: 'How connections are shared between nodes. Each edge has one node, so this changes nothing today.',
    options: [
      { value: 'ROUND_ROBIN', label: 'Round robin' },
      { value: 'LEAST_CONNECTIONS', label: 'Least connections' },
      { value: 'SOURCE_IP', label: 'Source IP' },
    ],
    wire: { resource: 'pool', field: 'lb_algorithm', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthMonitor.type',
    label: 'Check type',
    type: 'select',
    group: 'Health check',
    default: 'TCP',
    help: 'TCP checks that the port answers; TLS hello also completes a handshake. An HTTP check on the traffic port reaches the decoy site of a REALITY node: use it with a check port.',
    options: [
      { value: 'TCP', label: 'TCP' },
      { value: 'TLS-HELLO', label: 'TLS hello' },
      { value: 'PING', label: 'Ping' },
      { value: 'HTTP', label: 'HTTP' },
      { value: 'HTTPS', label: 'HTTPS' },
    ],
    wire: { resource: 'health_monitor', field: 'type', manual: true },
    live: 'rebuild',
  },
  {
    key: 'healthMonitor.delay',
    label: 'Check interval',
    type: 'number',
    unit: 's',
    group: 'Health check',
    help: 'Seconds between health checks; must be above the check timeout.',
    wire: { resource: 'health_monitor', field: 'delay', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthMonitor.timeout',
    label: 'Check timeout',
    type: 'number',
    unit: 's',
    group: 'Health check',
    help: 'Seconds to wait for an answer; must be below the interval.',
    wire: { resource: 'health_monitor', field: 'timeout', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthMonitor.maxRetries',
    label: 'Healthy after',
    type: 'number',
    group: 'Health check',
    help: 'Passing checks in a row before the node gets traffic again.',
    wire: { resource: 'health_monitor', field: 'max_retries', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthMonitor.maxRetriesDown',
    label: 'Unhealthy after',
    type: 'number',
    group: 'Health check',
    help: 'Failed checks in a row before the node is marked down.',
    wire: { resource: 'health_monitor', field: 'max_retries_down', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthMonitor.port',
    label: 'Check port',
    type: 'number',
    group: 'Health check',
    advanced: true,
    help: "Check this port on the node instead of the traffic port. Empty checks the node's own port.",
    wire: { resource: 'member', field: 'monitor_port', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthMonitor.httpMethod',
    label: 'HTTP check method',
    type: 'select',
    group: 'Health check',
    default: 'GET',
    when: GCORE_HTTP_CHECK,
    help: 'The request method an HTTP check sends.',
    wire: { resource: 'health_monitor', field: 'http_method', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthMonitor.urlPath',
    label: 'HTTP check path',
    type: 'string',
    group: 'Health check',
    default: '/',
    when: GCORE_HTTP_CHECK,
    help: 'The path an HTTP check requests on the node.',
    wire: { resource: 'health_monitor', field: 'url_path', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthMonitor.expectedCodes',
    label: 'Healthy status codes',
    type: 'string',
    group: 'Health check',
    default: '200',
    when: GCORE_HTTP_CHECK,
    help: 'HTTP codes that count as healthy, like 200 or 200-399.',
    wire: { resource: 'health_monitor', field: 'expected_codes', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthMonitor.httpVersion',
    label: 'HTTP check version',
    type: 'select',
    group: 'Health check',
    default: '1.0',
    when: GCORE_HTTP_CHECK,
    help: 'The HTTP version an HTTP check speaks.',
    wire: { resource: 'health_monitor', field: 'http_version', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthMonitor.domainName',
    label: 'HTTP check host name',
    type: 'string',
    group: 'Health check',
    when: GCORE_HTTP_CHECK,
    help: 'The Host header an HTTP check sends. Empty sends none.',
    wire: { resource: 'health_monitor', field: 'domain_name', manual: true },
    live: 'in_place',
  },
];

// --- UpCloud -----------------------------------------------------------------------

const WEEKDAYS = [
  'monday',
  'tuesday',
  'wednesday',
  'thursday',
  'friday',
  'saturday',
  'sunday',
] as const;

export const UpcloudTemplate = z.object({
  plan: z.string().min(1).max(64).default('development'),
  delegateFloatingIp: z.boolean().default(true),
  timeoutClient: z.number().int().min(10).max(86_400).default(300),
  timeoutServer: z.number().int().min(10).max(86_400).default(300),
  timeoutTunnel: z.number().int().min(10).max(3_024_000).default(3600),
  healthCheck: z
    .object({
      interval: z.number().int().min(1).max(3600).default(10),
      // Not an UpCloud setting (never sent); kept so stored templates parse as before.
      timeout: z.number().int().min(1).max(600).default(10),
      fall: z.number().int().min(1).max(100).default(3),
      rise: z.number().int().min(1).max(100).default(3),
    })
    .default({ interval: 10, timeout: 10, fall: 3, rise: 3 }),
  labels: z
    .array(z.object({ key: z.string().min(1).max(32), value: z.string().max(255) }))
    .max(10)
    .default([]),
  // Options added with provider options: optional, the adapter applies the default.
  maxSessions: z.number().int().min(1).max(500_000).optional(),
  closeOnFailure: z.boolean().optional(),
  maintenanceDow: z.enum(WEEKDAYS).optional(),
  maintenanceTime: z
    .string()
    .regex(/^([01]\d|2[0-3]):[0-5]\d:[0-5]\dZ$/, 'a UTC time like 03:00:00Z')
    .optional(),
});
export type UpcloudTemplateParams = z.infer<typeof UpcloudTemplate>;

export const UPCLOUD_TEMPLATE_FIELDS: TemplateFieldDescriptor[] = [
  {
    key: 'plan',
    label: 'Plan',
    type: 'string',
    group: 'Load balancer',
    prominent: true,
    from: 'flavors',
    help: 'Size of the load balancer: bigger plans run more nodes and allow more connections.',
    wire: { resource: 'loadbalancer', field: 'plan', manual: true },
    live: 'in_place',
  },
  {
    key: 'maintenanceDow',
    label: 'Maintenance day',
    type: 'select',
    group: 'Load balancer',
    advanced: true,
    help: 'The weekday UpCloud may update the load balancer. Empty lets UpCloud pick; a one-node plan drops traffic for a minute or two.',
    options: WEEKDAYS.map((d) => ({ value: d, label: d[0]!.toUpperCase() + d.slice(1) })),
    wire: { resource: 'loadbalancer', field: 'maintenance_dow' },
    live: 'in_place',
  },
  {
    key: 'maintenanceTime',
    label: 'Maintenance time (UTC)',
    type: 'string',
    group: 'Load balancer',
    advanced: true,
    help: 'Start of the two-hour update window, like 03:00:00Z. Empty lets UpCloud pick.',
    wire: { resource: 'loadbalancer', field: 'maintenance_time' },
    live: 'in_place',
  },
  {
    key: 'labels',
    label: 'Labels',
    type: 'key-value',
    pairs: true,
    group: 'Load balancer',
    advanced: true,
    help: 'Extra key=value labels on the load balancer, seen only in the provider account.',
    wire: { resource: 'loadbalancer', field: 'labels', manual: true },
    live: 'in_place',
  },
  {
    key: 'timeoutClient',
    label: 'Client idle timeout',
    type: 'number',
    unit: 's',
    group: 'Frontend',
    help: 'How long an idle member connection stays open.',
    wire: { resource: 'frontend', field: 'properties.timeout_client', manual: true },
    live: 'in_place',
  },
  {
    key: 'timeoutServer',
    label: 'Node idle timeout',
    type: 'number',
    unit: 's',
    group: 'Backend',
    help: 'How long an idle connection to the node stays open.',
    wire: { resource: 'backend', field: 'properties.timeout_server', manual: true },
    live: 'in_place',
  },
  {
    key: 'timeoutTunnel',
    label: 'Tunnel timeout',
    type: 'number',
    unit: 's',
    group: 'Backend',
    help: 'How long an idle proxied tunnel stays open on both sides.',
    wire: { resource: 'backend', field: 'properties.timeout_tunnel', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthCheck.interval',
    label: 'Check interval',
    type: 'number',
    unit: 's',
    group: 'Health check',
    help: 'Time between connection checks to the node.',
    wire: { resource: 'backend', field: 'properties.health_check_interval', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthCheck.fall',
    label: 'Unhealthy after',
    type: 'number',
    group: 'Health check',
    help: 'Failed checks before the node stops getting traffic.',
    wire: { resource: 'backend', field: 'properties.health_check_fall', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthCheck.rise',
    label: 'Healthy after',
    type: 'number',
    group: 'Health check',
    help: 'Passing checks before the node gets traffic again.',
    wire: { resource: 'backend', field: 'properties.health_check_rise', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthCheck.timeout',
    label: 'Check timeout',
    type: 'number',
    group: 'Health check',
    hidden: true,
  },
  {
    key: 'closeOnFailure',
    label: 'Close connections on failure',
    type: 'boolean',
    group: 'Health check',
    default: false,
    help: 'Drop open connections at once when the node fails its check, so members reconnect sooner.',
    wire: { resource: 'backend', field: 'properties.health_check_on_down', manual: true },
    live: 'in_place',
  },
  {
    key: 'maxSessions',
    label: 'Most connections at once',
    type: 'number',
    group: 'Member',
    prominent: true,
    default: 1000,
    help: 'Open connections to the node before new ones wait in a queue.',
    wire: { resource: 'member', field: 'max_sessions', manual: true },
    live: 'in_place',
  },
  {
    key: 'delegateFloatingIp',
    label: 'Delegate a floating IPv4',
    type: 'boolean',
    group: 'Address',
    help: 'Publish a reserved address that survives load balancer changes. Without one the address is not stable.',
    wire: { resource: 'ip_address', field: 'floating', manual: true },
    live: 'rebuild',
  },
];

// --- Scaleway ----------------------------------------------------------------------

/** A duration as stored; decimals read back since provider options (`0.5s`). */
const DURATION = /^\d{1,7}(\.\d{1,3})?(ms|s|m|h)$/;
/** What Scaleway documents and its own SDKs send: seconds, with an `s` (written values). */
const SECONDS = /^\d{1,7}(\.\d{1,3})?s$/;

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
      // Options added with provider options: optional, the adapter applies the default.
      transientCheckDelay: z.string().regex(DURATION).optional(),
    })
    .default({ checkDelay: '5s', checkTimeout: '3s', checkMaxRetries: 3 }),
  tags: z.array(z.string().min(1).max(64)).max(10).default([]),
  description: z.string().max(200).optional(),
  reverse: z
    .string()
    .max(253)
    .regex(/^[a-z0-9.-]*$/, 'a host name in lowercase letters, digits, dots and dashes')
    .optional(),
  maxConnections: z.number().int().min(1).max(3_000_000).optional(),
  timeoutQueue: z.string().regex(DURATION).optional(),
  maxRetries: z.number().int().min(0).max(100).optional(),
  closeOnFailure: z.boolean().optional(),
  connectionRateLimit: z.number().int().min(0).max(1_000_000).optional(),
});
export type ScalewayTemplateParams = z.infer<typeof ScalewayTemplate>;

const SCALEWAY_DURATION_HELP = 'In seconds with an s, like 600s or 2.5s.';

export const SCALEWAY_TEMPLATE_FIELDS: TemplateFieldDescriptor[] = [
  {
    key: 'type',
    label: 'Size',
    type: 'string',
    regional: true,
    prominent: true,
    from: 'flavors',
    group: 'Load balancer',
    help: 'The load balancer offer. Bigger offers carry more bandwidth and connections; only multi-cloud offers accept a node outside Scaleway.',
    wire: { resource: 'loadbalancer', field: 'type', manual: true },
    live: 'in_place',
  },
  {
    key: 'description',
    label: 'Description',
    type: 'string',
    group: 'Load balancer',
    advanced: true,
    default: 'origin edge',
    help: 'Shown only in the provider console. Never put a host name or a node address here.',
    wire: { resource: 'loadbalancer', field: 'description', manual: true },
    live: 'in_place',
  },
  {
    key: 'tags',
    label: 'Extra tags',
    type: 'string-list',
    group: 'Load balancer',
    advanced: true,
    help: 'Labels added to the load balancer for your own bookkeeping (not to its addresses).',
    wire: { resource: 'loadbalancer', field: 'tags', manual: true },
    live: 'in_place',
  },
  {
    key: 'ipv6',
    label: 'Also an IPv6 address',
    type: 'boolean',
    prominent: true,
    group: 'Address',
    help: 'Members get an IPv6 entry for this edge as well as the IPv4 one.',
    wire: { resource: 'ip', field: 'is_ipv6', manual: true },
    live: 'rebuild',
  },
  {
    key: 'reverse',
    label: 'Reverse DNS name',
    type: 'string',
    group: 'Address',
    advanced: true,
    help: "Empty keeps the provider's generated name. A custom name links the address to your domain for anyone who looks it up.",
    wire: { resource: 'ip', field: 'reverse', manual: true },
    live: 'in_place',
  },
  {
    key: 'timeoutClient',
    label: 'Client idle timeout',
    type: 'string',
    group: 'Frontend',
    help: `How long a member connection may stay silent before it is closed. ${SCALEWAY_DURATION_HELP}`,
    wire: { resource: 'frontend', field: 'timeout_client', manual: true },
    live: 'in_place',
  },
  {
    key: 'connectionRateLimit',
    label: 'New connections per second',
    type: 'number',
    group: 'Frontend',
    advanced: true,
    default: 0,
    help: 'Caps how fast new connections are accepted on this edge. 0 means no limit.',
    wire: { resource: 'frontend', field: 'connection_rate_limit', manual: true },
    live: 'in_place',
  },
  {
    key: 'timeoutServer',
    label: 'Node idle timeout',
    type: 'string',
    group: 'Backend',
    help: `How long the node may stay silent before the connection is closed. ${SCALEWAY_DURATION_HELP}`,
    wire: { resource: 'backend', field: 'timeout_server', manual: true },
    live: 'in_place',
  },
  {
    key: 'timeoutConnect',
    label: 'Node connect timeout',
    type: 'string',
    group: 'Backend',
    help: `How long to wait for the node to accept a new connection. ${SCALEWAY_DURATION_HELP}`,
    wire: { resource: 'backend', field: 'timeout_connect', manual: true },
    live: 'in_place',
  },
  {
    key: 'timeoutTunnel',
    label: 'Tunnel timeout',
    type: 'string',
    group: 'Backend',
    help: `How long an open connection may stay silent in both directions. ${SCALEWAY_DURATION_HELP}`,
    wire: { resource: 'backend', field: 'timeout_tunnel', manual: true },
    live: 'in_place',
  },
  {
    key: 'maxConnections',
    label: 'Most connections at once',
    type: 'number',
    group: 'Backend',
    prominent: true,
    help: 'Open connections to the node before new ones wait in a queue. Empty means no cap.',
    wire: { resource: 'backend', field: 'max_connections', manual: true },
    live: 'in_place',
  },
  {
    key: 'timeoutQueue',
    label: 'Queue wait limit',
    type: 'string',
    group: 'Backend',
    advanced: true,
    help: `How long a connection waits for a free slot once the cap is reached. ${SCALEWAY_DURATION_HELP}`,
    wire: { resource: 'backend', field: 'timeout_queue', manual: true },
    live: 'in_place',
  },
  {
    key: 'maxRetries',
    label: 'Node connect retries',
    type: 'number',
    group: 'Backend',
    advanced: true,
    help: 'How many times to retry a failed connection to the node. Empty keeps the provider default.',
    wire: { resource: 'backend', field: 'max_retries', manual: true },
    live: 'in_place',
  },
  {
    key: 'forwardPortAlgorithm',
    label: 'Balancing method',
    type: 'select',
    group: 'Backend',
    advanced: true,
    help: 'How connections are shared between nodes. Each edge has one node, so this changes nothing today.',
    options: [
      { value: 'roundrobin', label: 'Round robin' },
      { value: 'leastconn', label: 'Least connections' },
      { value: 'first', label: 'First available' },
    ],
    wire: { resource: 'backend', field: 'forward_port_algorithm', manual: true },
    live: 'in_place',
  },
  {
    key: 'closeOnFailure',
    label: 'Close connections on failure',
    type: 'boolean',
    group: 'Health check',
    default: false,
    help: 'Drop open connections at once when the node fails its check, so members reconnect sooner.',
    wire: { resource: 'backend', field: 'on_marked_down_action', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthCheck.checkDelay',
    label: 'Check interval',
    type: 'string',
    group: 'Health check',
    help: `Time between two checks of the node. ${SCALEWAY_DURATION_HELP}`,
    wire: { resource: 'backend', field: 'health_check.check_delay', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthCheck.checkTimeout',
    label: 'Check timeout',
    type: 'string',
    group: 'Health check',
    help: `How long the node has to answer one check. ${SCALEWAY_DURATION_HELP}`,
    wire: { resource: 'backend', field: 'health_check.check_timeout', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthCheck.checkMaxRetries',
    label: 'Unhealthy after',
    type: 'number',
    group: 'Health check',
    help: 'Failed checks in a row before the node is marked down.',
    wire: { resource: 'backend', field: 'health_check.check_max_retries', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthCheck.transientCheckDelay',
    label: 'Recheck interval while changing state',
    type: 'string',
    group: 'Health check',
    advanced: true,
    default: '0.5s',
    help: `Time between checks while the node is going up or down. ${SCALEWAY_DURATION_HELP}`,
    wire: { resource: 'backend', field: 'health_check.transient_check_delay', manual: true },
    live: 'in_place',
  },
];

// --- OVH ---------------------------------------------------------------------------

/** Health check kinds a TCP pool accepts (OVH's compatibility matrix). */
const OVH_MONITOR_TYPES = ['tcp', 'tls-hello', 'ping', 'http', 'https'] as const;

export const OvhTemplate = z.object({
  /** Required at provisioning time: the regional LB flavor id (see inventory.flavors). */
  flavorId: z.string().max(64).default(''),
  gatewayModel: z.enum(['s', 'm', 'l', 'xl', '2xl', '3xl']).default('s'),
  // `sourceIp` is the stored spelling; the API's is `sourceIP` (ovhLbBody maps it).
  algorithm: z.enum(['roundRobin', 'leastConnections', 'sourceIp']).default('roundRobin'),
  healthMonitor: z
    .object({
      delay: z.number().int().min(1).max(600).default(5),
      timeout: z.number().int().min(1).max(600).default(3),
      maxRetries: z.number().int().min(1).max(10).default(3),
      // Options added with provider options: optional, the adapter applies the default.
      type: z.enum(OVH_MONITOR_TYPES).optional(),
      maxRetriesDown: z.number().int().min(1).max(10).optional(),
      httpMethod: z.enum(HTTP_METHODS).optional(),
      urlPath: z
        .string()
        .regex(/^\/[\x21-\x7e]{0,254}$/, 'a path starting with /')
        .optional(),
      expectedCodes: z
        .string()
        .regex(/^\d{3}(-\d{3})?(,\d{3}(-\d{3})?)*$/, 'like 200, 200,202 or 200-299')
        .optional(),
      httpVersion: z.enum(['1.0', '1.1']).optional(),
      domainName: z.string().max(253).optional(),
    })
    .default({ delay: 5, timeout: 3, maxRetries: 3 }),
  timeoutClientDataMs: z.number().int().min(1000).max(3_600_000).default(300_000),
  // Never sent (see its descriptor); `nodeIdleTimeoutMs` is the one that is.
  timeoutMemberDataMs: z.number().int().min(1000).max(3_600_000).default(300_000),
  nodeIdleTimeoutMs: z.number().int().min(1000).max(3_600_000).optional(),
  allowedCidrs: z.array(z.string().min(1)).max(50).default([]),
});
export type OvhTemplateParams = z.infer<typeof OvhTemplate>;

const OVH_HTTP_CHECK = { key: 'healthMonitor.type', in: ['http', 'https'] };

export const OVH_TEMPLATE_FIELDS: TemplateFieldDescriptor[] = [
  {
    key: 'flavorId',
    label: 'Size',
    type: 'string',
    required: true,
    regional: true,
    prominent: true,
    from: 'flavors',
    group: 'Load balancer',
    help: 'The load balancer flavor of the region: bigger sizes carry more connections and cost more.',
    wire: { resource: 'loadbalancer', field: 'flavorId', manual: true },
    live: 'in_place',
  },
  {
    key: 'gatewayModel',
    label: 'Gateway size',
    type: 'select',
    group: 'Gateway',
    prominent: true,
    help: 'Caps the edge bandwidth (S is up to 200 Mbps); bigger sizes cost more. Used only when the location has no gateway of its own.',
    options: [
      { value: 's', label: 'S (200 Mbps)' },
      { value: 'm', label: 'M (500 Mbps)' },
      { value: 'l', label: 'L (2 Gbps)' },
      { value: 'xl', label: 'XL (4 Gbps)' },
      { value: '2xl', label: '2XL (8 Gbps)' },
      { value: '3xl', label: '3XL' },
    ],
    wire: { resource: 'gateway', field: 'model', manual: true },
    live: 'in_place',
  },
  {
    key: 'timeoutClientDataMs',
    label: 'Client idle timeout',
    type: 'number',
    unit: 'ms',
    group: 'Listener',
    help: 'Closes a member connection after this long with no data.',
    wire: { resource: 'listener', field: 'timeoutClientData', manual: true },
    live: 'rebuild',
  },
  {
    // Shown before options existed but never sent: kept (stored templates hold
    // it and their hashes include it), hidden, and still never sent, so an
    // existing node's next replacement sends what it always did.
    key: 'timeoutMemberDataMs',
    label: 'Node idle timeout (unused)',
    type: 'number',
    unit: 'ms',
    group: 'Listener',
    hidden: true,
  },
  {
    key: 'nodeIdleTimeoutMs',
    label: 'Node idle timeout',
    type: 'number',
    unit: 'ms',
    group: 'Listener',
    advanced: true,
    help: "Closes the connection to the node after this long with no data. Unset: the provider's own default.",
    wire: { resource: 'listener', field: 'timeoutMemberData', manual: true },
    live: 'rebuild',
  },
  {
    key: 'allowedCidrs',
    label: 'Allowed client ranges',
    type: 'string-list',
    group: 'Listener',
    advanced: true,
    help: 'Only these IPv4 ranges may connect. Empty lets everyone connect.',
    wire: { resource: 'listener', field: 'allowedCidrs', manual: true },
    live: 'in_place',
  },
  {
    key: 'algorithm',
    label: 'Balancing method',
    type: 'select',
    group: 'Pool',
    advanced: true,
    help: 'How connections are shared between nodes. Each edge has one node, so this changes nothing today.',
    options: [
      { value: 'roundRobin', label: 'Round robin' },
      { value: 'leastConnections', label: 'Least connections' },
      { value: 'sourceIp', label: 'Source IP' },
    ],
    wire: { resource: 'pool', field: 'algorithm', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthMonitor.type',
    label: 'Check type',
    type: 'select',
    group: 'Health check',
    default: 'tcp',
    help: 'TCP checks that the port answers; TLS hello also completes a handshake; HTTP checks need an HTTP endpoint on the node.',
    options: [
      { value: 'tcp', label: 'TCP' },
      { value: 'tls-hello', label: 'TLS hello' },
      { value: 'ping', label: 'Ping' },
      { value: 'http', label: 'HTTP' },
      { value: 'https', label: 'HTTPS' },
    ],
    wire: { resource: 'health_monitor', field: 'monitorType', manual: true },
    live: 'rebuild',
  },
  {
    key: 'healthMonitor.delay',
    label: 'Check interval',
    type: 'number',
    unit: 's',
    group: 'Health check',
    help: 'Seconds between two checks of the node; must be above the check timeout.',
    wire: { resource: 'health_monitor', field: 'delay', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthMonitor.timeout',
    label: 'Check timeout',
    type: 'number',
    unit: 's',
    group: 'Health check',
    help: 'How long one check waits for an answer; must be below the interval.',
    wire: { resource: 'health_monitor', field: 'timeout', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthMonitor.maxRetries',
    label: 'Healthy after',
    type: 'number',
    group: 'Health check',
    help: 'Passing checks in a row before the node gets traffic again.',
    wire: { resource: 'health_monitor', field: 'maxRetries', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthMonitor.maxRetriesDown',
    label: 'Unhealthy after',
    type: 'number',
    group: 'Health check',
    default: 3,
    help: 'Failed checks in a row before the node stops getting traffic.',
    wire: { resource: 'health_monitor', field: 'maxRetriesDown', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthMonitor.httpMethod',
    label: 'HTTP check method',
    type: 'select',
    group: 'Health check',
    default: 'GET',
    when: OVH_HTTP_CHECK,
    help: 'The request method an HTTP check sends.',
    wire: { resource: 'health_monitor', field: 'httpConfiguration.httpMethod', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthMonitor.urlPath',
    label: 'HTTP check path',
    type: 'string',
    group: 'Health check',
    default: '/',
    when: OVH_HTTP_CHECK,
    help: 'The path an HTTP check requests on the node.',
    wire: { resource: 'health_monitor', field: 'httpConfiguration.urlPath', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthMonitor.expectedCodes',
    label: 'Healthy status codes',
    type: 'string',
    group: 'Health check',
    default: '200',
    when: OVH_HTTP_CHECK,
    help: 'HTTP codes that count as healthy, like 200 or 200-399.',
    wire: { resource: 'health_monitor', field: 'httpConfiguration.expectedCodes', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthMonitor.httpVersion',
    label: 'HTTP check version',
    type: 'select',
    group: 'Health check',
    default: '1.0',
    when: OVH_HTTP_CHECK,
    help: 'The HTTP version an HTTP check speaks.',
    wire: { resource: 'health_monitor', field: 'httpConfiguration.httpVersion', manual: true },
    live: 'in_place',
  },
  {
    key: 'healthMonitor.domainName',
    label: 'HTTP check host name',
    type: 'string',
    group: 'Health check',
    when: OVH_HTTP_CHECK,
    help: 'The Host header an HTTP check sends. Empty sends none.',
    wire: { resource: 'health_monitor', field: 'httpConfiguration.domainName', manual: true },
    live: 'in_place',
  },
];

// --- Cloudflare (L7) ---------------------------------------------------------------

/** Hostname label settings shared by the L7 templates (lib/edges/hostname.ts). */
const LABEL_FIELDS = {
  labelLength: z.number().int().min(8).max(16).default(12),
  labelPrefix: z
    .string()
    .regex(/^[a-z0-9-]{0,8}$/, 'lowercase letters, digits, dashes; up to 8 chars')
    .default(''),
};

/**
 * Cloudflare record tags: `name:value`, a name of letters, digits, - and _
 * (32 at most), a value of 100 at most; paid zones only (a Free zone refuses them).
 */
const RECORD_TAGS = z
  .record(
    z.string().regex(/^[A-Za-z0-9_-]{1,32}$/, 'letters, digits, - and _'),
    z.string().max(100),
  )
  .refine((t) => Object.keys(t).length <= 20, { message: 'at most 20 tags' });

/** The hostname label fields' descriptors, shared by the L7 providers. */
const LABEL_FIELD_DESCRIPTORS: TemplateFieldDescriptor[] = [
  {
    key: 'labelLength',
    label: 'Name length',
    type: 'number',
    group: 'Names',
    advanced: true,
    help: 'Characters in the random label of each front name, 8 to 16.',
    live: 'rebuild',
  },
  {
    key: 'labelPrefix',
    label: 'Name prefix',
    type: 'string',
    group: 'Names',
    advanced: true,
    help: 'Optional text before the random label, up to 8 lowercase characters.',
    live: 'rebuild',
  },
];

export const CloudflareTemplate = z.object({
  ...LABEL_FIELDS,
  /** Marker prefix for the DNS record comment (the discovery/ownership key follows). */
  commentPrefix: z.string().max(24).default('fcp'),
  /**
   * Any origin port other than the zone mode's effective default (443 for full/
   * strict, 80 for flexible) needs an Origin Rule (destination-port override,
   * 10 rules on Free). False refuses such slots at plan time.
   */
  allowOriginPortOverride: z.boolean().default(true),
  // Options added with provider options: optional, the adapter applies the default.
  answerFamily: z.enum(['both', 'ipv4', 'ipv6']).optional(),
  recordTags: RECORD_TAGS.optional(),
});
export type CloudflareTemplateParams = z.infer<typeof CloudflareTemplate>;

export const CLOUDFLARE_TEMPLATE_FIELDS: TemplateFieldDescriptor[] = [
  ...LABEL_FIELD_DESCRIPTORS,
  {
    key: 'commentPrefix',
    label: 'Record comment prefix',
    type: 'string',
    group: 'DNS record',
    advanced: true,
    help: 'Text before the edge name in the comment FCP leaves on the record.',
    wire: { resource: 'dns_record', field: 'comment', manual: true },
    live: 'in_place',
  },
  {
    key: 'answerFamily',
    label: 'Answer addresses',
    type: 'select',
    group: 'DNS record',
    prominent: true,
    default: 'both',
    help: 'Which address families members get for the front name. Both is normal.',
    options: [
      { value: 'both', label: 'IPv4 and IPv6' },
      { value: 'ipv4', label: 'IPv4 only' },
      { value: 'ipv6', label: 'IPv6 only' },
    ],
    wire: { resource: 'dns_record', field: 'settings.ipv4_only', manual: true },
    live: 'in_place',
  },
  {
    key: 'recordTags',
    label: 'Record tags',
    type: 'key-value',
    group: 'DNS record',
    advanced: true,
    help: 'Extra name:value labels on the record. Paid zones only.',
    wire: { resource: 'dns_record', field: 'tags', manual: true },
    live: 'in_place',
  },
  {
    key: 'allowOriginPortOverride',
    label: 'Allow a node port override',
    type: 'boolean',
    group: 'Origin rule',
    advanced: true,
    help: "Needed when the node does not listen on the encryption mode's default port (an Origin Rule; 10 on a Free zone).",
    wire: { resource: 'origin_rule', field: 'action_parameters.origin.port', manual: true },
    live: 'in_place',
  },
];

// --- Fastly (L7) -------------------------------------------------------------------

const TLS_VERSIONS = ['1.0', '1.1', '1.2', '1.3'] as const;
/**
 * Fastly's WebSocket guide documents only name, address, TLS and Host for a
 * WebSocket backend; the other backend fields are sent as Fastly takes them,
 * but their effect on a WebSocket front is unproven until a beta walk shows it.
 */
const FASTLY_WS_UNPROVEN = 'Its effect on a WebSocket front is not proven yet.';

export const FastlyTemplate = z.object({
  ...LABEL_FIELDS,
  /**
   * The Host header the front sends the origin: the fronted hostname (the node
   * accepts any / the minted name) or the origin address itself.
   */
  overrideHost: z.enum(['hostname', 'origin']).default('hostname'),
  /** Comment stamped on the service (never the public hostname). */
  serviceComment: z.string().max(64).default('origin edge'),
  // Options added with provider options: optional, the adapter applies the default.
  preferIpv6: z.boolean().optional(),
  minTlsVersion: z.enum(TLS_VERSIONS).optional(),
  maxTlsVersion: z.enum(TLS_VERSIONS).optional(),
  sslCiphers: z
    .string()
    .max(500)
    .regex(/^[A-Za-z0-9:+!@_.-]*$/, 'an OpenSSL cipher list')
    .optional(),
  connectTimeoutMs: z.number().int().min(100).max(60_000).optional(),
  firstByteTimeoutMs: z.number().int().min(100).max(600_000).optional(),
  maxConn: z.number().int().min(1).max(100_000).optional(),
  tcpKeepalive: z.boolean().optional(),
  tcpKeepaliveTime: z.number().int().min(1).max(7200).optional(),
  tcpKeepaliveInterval: z.number().int().min(1).max(300).optional(),
  tcpKeepaliveProbes: z.number().int().min(1).max(30).optional(),
  forwardClientAddress: z.boolean().optional(),
  dnsTtl: z.union([z.literal(1), z.number().int().min(60).max(86_400)]).optional(),
  dnsTags: RECORD_TAGS.optional(),
  dnsFlatten: z.boolean().optional(),
});
export type FastlyTemplateParams = z.infer<typeof FastlyTemplate>;

const FASTLY_KEEPALIVE = { key: 'tcpKeepalive', in: [true] };

export const FASTLY_TEMPLATE_FIELDS: TemplateFieldDescriptor[] = [
  ...LABEL_FIELD_DESCRIPTORS,
  {
    key: 'serviceComment',
    label: 'Service note',
    type: 'string',
    group: 'Service',
    advanced: true,
    help: 'A note on the Fastly service, seen only in the provider account. Never the front name.',
    wire: { resource: 'service', field: 'comment', manual: true },
    live: 'new_version',
  },
  {
    key: 'overrideHost',
    label: 'Host sent to the node',
    type: 'select',
    group: 'Backend',
    help: 'The Host header the front sends: the front name, or the node address when the node answers only to its own name.',
    options: [
      { value: 'hostname', label: 'The front name' },
      { value: 'origin', label: 'The node address' },
    ],
    wire: { resource: 'backend', field: 'override_host', manual: true },
    live: 'new_version',
  },
  {
    key: 'preferIpv6',
    label: 'Prefer IPv6 to the node',
    type: 'boolean',
    group: 'Backend',
    prominent: true,
    default: false,
    help: `Connect to the node over IPv6 when its name has an IPv6 address. ${FASTLY_WS_UNPROVEN}`,
    wire: { resource: 'backend', field: 'prefer_ipv6' },
    live: 'new_version',
  },
  {
    key: 'connectTimeoutMs',
    label: 'Node connect timeout',
    type: 'number',
    unit: 'ms',
    group: 'Backend',
    default: 1000,
    help: `How long to wait for the node to accept a connection. ${FASTLY_WS_UNPROVEN}`,
    wire: { resource: 'backend', field: 'connect_timeout' },
    live: 'new_version',
  },
  {
    key: 'firstByteTimeoutMs',
    label: 'Upgrade answer timeout',
    type: 'number',
    unit: 'ms',
    group: 'Backend',
    default: 15_000,
    help: `How long to wait for the node to answer the upgrade request. ${FASTLY_WS_UNPROVEN}`,
    wire: { resource: 'backend', field: 'first_byte_timeout' },
    live: 'new_version',
  },
  {
    key: 'maxConn',
    label: 'Most connections per Fastly server',
    type: 'number',
    group: 'Backend',
    prominent: true,
    default: 200,
    help: `Open connections one Fastly server keeps to the node; each member tunnel holds one. ${FASTLY_WS_UNPROVEN}`,
    wire: { resource: 'backend', field: 'max_conn' },
    live: 'new_version',
  },
  {
    key: 'minTlsVersion',
    label: 'Lowest TLS version to the node',
    type: 'select',
    group: 'Backend TLS',
    advanced: true,
    help: `Refuse to talk to the node below this TLS version. Empty takes what the node offers. ${FASTLY_WS_UNPROVEN}`,
    wire: { resource: 'backend', field: 'min_tls_version' },
    live: 'new_version',
  },
  {
    key: 'maxTlsVersion',
    label: 'Highest TLS version to the node',
    type: 'select',
    group: 'Backend TLS',
    advanced: true,
    help: `The newest TLS version used with the node. Empty takes what the node offers. ${FASTLY_WS_UNPROVEN}`,
    wire: { resource: 'backend', field: 'max_tls_version' },
    live: 'new_version',
  },
  {
    key: 'sslCiphers',
    label: 'Ciphers to the node',
    type: 'string',
    group: 'Backend TLS',
    advanced: true,
    help: `An OpenSSL cipher list allowed with the node. Empty keeps Fastly's list. ${FASTLY_WS_UNPROVEN}`,
    wire: { resource: 'backend', field: 'ssl_ciphers' },
    live: 'new_version',
  },
  {
    key: 'tcpKeepalive',
    label: 'TCP keepalive to the node',
    type: 'boolean',
    group: 'Backend keepalive',
    advanced: true,
    help: `Send TCP keepalives on idle connections to the node. Empty leaves it to Fastly. ${FASTLY_WS_UNPROVEN}`,
    wire: { resource: 'backend', field: 'tcp_keepalive_enable' },
    live: 'new_version',
  },
  {
    key: 'tcpKeepaliveTime',
    label: 'Keepalive idle time',
    type: 'number',
    unit: 's',
    group: 'Backend keepalive',
    advanced: true,
    default: 300,
    when: FASTLY_KEEPALIVE,
    help: 'Seconds of silence before the first keepalive probe.',
    wire: { resource: 'backend', field: 'tcp_keepalive_time' },
    live: 'new_version',
  },
  {
    key: 'tcpKeepaliveInterval',
    label: 'Keepalive interval',
    type: 'number',
    unit: 's',
    group: 'Backend keepalive',
    advanced: true,
    default: 10,
    when: FASTLY_KEEPALIVE,
    help: 'Seconds between keepalive probes.',
    wire: { resource: 'backend', field: 'tcp_keepalive_interval' },
    live: 'new_version',
  },
  {
    key: 'tcpKeepaliveProbes',
    label: 'Keepalive probes',
    type: 'number',
    group: 'Backend keepalive',
    advanced: true,
    default: 3,
    when: FASTLY_KEEPALIVE,
    help: 'Unanswered probes before the connection is dropped.',
    wire: { resource: 'backend', field: 'tcp_keepalive_probes' },
    live: 'new_version',
  },
  {
    key: 'forwardClientAddress',
    label: "Pass the member's address to the node",
    type: 'boolean',
    group: 'Request',
    default: false,
    help: "Off (the default): the front removes every header that can carry the member's address (Fastly-Client-IP, X-Forwarded-For and the like) before the node sees the request. On passes Fastly's own two through.",
    wire: { resource: 'snippet', field: 'content', manual: true },
    live: 'new_version',
  },
  {
    key: 'dnsTtl',
    label: 'Record TTL',
    type: 'number',
    unit: 's',
    group: 'DNS records',
    advanced: true,
    default: 1,
    help: 'How long resolvers may cache the records written for the front: 1 is automatic (5 minutes), else 60 to 86400.',
    wire: { resource: 'dns_record', field: 'ttl', manual: true },
    live: 'in_place',
  },
  {
    key: 'dnsTags',
    label: 'Record tags',
    type: 'key-value',
    group: 'DNS records',
    advanced: true,
    help: 'Extra name:value labels on the records written for the front. Paid DNS zones only.',
    wire: { resource: 'dns_record', field: 'tags', manual: true },
    live: 'in_place',
  },
  {
    key: 'dnsFlatten',
    label: 'Flatten the front name',
    type: 'boolean',
    group: 'DNS records',
    advanced: true,
    default: false,
    help: "Answer the front name with Fastly's addresses instead of a CNAME that names Fastly. Paid DNS zones only.",
    wire: { resource: 'dns_record', field: 'settings.flatten_cname', manual: true },
    live: 'in_place',
  },
];

// --- certificate options (CDN fronts) -------------------------------------------------

/**
 * What a CDN front's certificate is, per provider: defaults on the ACCOUNT
 * (`edgeProviderAccounts.optionDefaults`), choosable per node, frozen in each
 * edge's intent and outside the template hash (lib/edges/providers/options.ts).
 * Every key is optional: absent = the declared default.
 */
export const FastlyCertificateOptions = z.object({
  certificateAuthority: z.enum(['certainly', 'lets-encrypt', 'globalsign']).optional(),
  certificateScope: z.enum(['per_host', 'wildcard']).optional(),
});

export const FASTLY_CERTIFICATE_FIELDS: TemplateFieldDescriptor[] = [
  {
    key: 'certificateAuthority',
    label: 'Certificate authority',
    type: 'select',
    kind: 'certificate',
    group: 'Certificate',
    prominent: true,
    default: 'certainly',
    help: 'Who issues the certificate members see. GlobalSign needs a paid plan.',
    options: [
      { value: 'certainly', label: 'Certainly' },
      { value: 'lets-encrypt', label: "Let's Encrypt" },
      { value: 'globalsign', label: 'GlobalSign' },
    ],
    wire: { resource: 'tls_subscription', field: 'certificate_authority', manual: true },
    live: 'rebuild',
  },
  {
    key: 'certificateScope',
    label: 'Certificate',
    type: 'select',
    kind: 'certificate',
    group: 'Certificate',
    prominent: true,
    // What an account from before the choice existed (and its fronts) use.
    default: 'per_host',
    help: 'A wildcard is issued once for the zone and shared: a new front never waits for a certificate, and its name never appears in public certificate logs before members use it.',
    options: [
      { value: 'wildcard', label: 'One wildcard for every front' },
      { value: 'per_host', label: 'One per front' },
    ],
    wire: { resource: 'tls_subscription', field: 'tls_domains', manual: true },
    live: 'rebuild',
  },
];

/**
 * Option defaults a NEW account starts with where they differ from the
 * declared ones (an existing account keeps the declared, older behaviour until
 * it is switched): a new Fastly account shares one wildcard certificate.
 */
export const EDGE_NEW_ACCOUNT_OPTION_DEFAULTS: Partial<
  Record<EdgeProviderId, Record<string, unknown>>
> = {
  fastly: { certificateScope: 'wildcard' },
};

const NO_CERTIFICATE = z.object({});

// --- registry ----------------------------------------------------------------------

export interface TemplateDefinition {
  schema: z.ZodType<Record<string, unknown>>;
  fields: TemplateFieldDescriptor[];
  defaults: Record<string, unknown>;
}

function template(schema: z.ZodType, fields: TemplateFieldDescriptor[]): TemplateDefinition {
  return {
    schema: schema as unknown as z.ZodType<Record<string, unknown>>,
    fields: describeFields(schema, fields),
    defaults: schema.parse({}) as Record<string, unknown>,
  };
}

export const EDGE_TEMPLATES: Record<EdgeProviderId, TemplateDefinition> = {
  gcore: template(GcoreTemplate, GCORE_TEMPLATE_FIELDS),
  upcloud: template(UpcloudTemplate, UPCLOUD_TEMPLATE_FIELDS),
  scaleway: template(ScalewayTemplate, SCALEWAY_TEMPLATE_FIELDS),
  ovh: template(OvhTemplate, OVH_TEMPLATE_FIELDS),
  cloudflare: template(CloudflareTemplate, CLOUDFLARE_TEMPLATE_FIELDS),
  fastly: template(FastlyTemplate, FASTLY_TEMPLATE_FIELDS),
};

export interface CertificateDefinition {
  schema: z.ZodType<Record<string, unknown>>;
  fields: TemplateFieldDescriptor[];
}

function certificate(schema: z.ZodType, fields: TemplateFieldDescriptor[]): CertificateDefinition {
  return {
    schema: schema as unknown as z.ZodType<Record<string, unknown>>,
    fields: describeFields(schema, fields),
  };
}

export const EDGE_CERTIFICATE_OPTIONS: Record<EdgeProviderId, CertificateDefinition> = {
  gcore: certificate(NO_CERTIFICATE, []),
  upcloud: certificate(NO_CERTIFICATE, []),
  scaleway: certificate(NO_CERTIFICATE, []),
  ovh: certificate(NO_CERTIFICATE, []),
  cloudflare: certificate(NO_CERTIFICATE, []),
  fastly: certificate(FastlyCertificateOptions, FASTLY_CERTIFICATE_FIELDS),
};

/** Every option of a provider, tuning then certificate: what the forms render. */
export function optionFieldsOf(provider: EdgeProviderId): TemplateFieldDescriptor[] {
  return [...EDGE_TEMPLATES[provider].fields, ...EDGE_CERTIFICATE_OPTIONS[provider].fields];
}

/** The certificate keys of a provider (frozen in the L7 intent, outside the template hash). */
export function certificateKeysOf(provider: EdgeProviderId): string[] {
  return EDGE_CERTIFICATE_OPTIONS[provider].fields.map((f) => f.key);
}

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

const IPV4_CIDR = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/(3[0-2]|[12]?\d)$/;

/**
 * Rules a provider enforces across fields (a check timeout under its interval)
 * or on a value's shape that the read schema is too loose for. They apply to
 * WRITES only (a template saved, an option chosen): adding one to the read
 * schema would make a stored template that breaks it fail to parse, and
 * `resolveTemplateFor` would then silently fall back to another template.
 */
const WRITE_CHECKS: Partial<
  Record<
    EdgeProviderId,
    (params: Record<string, unknown>, label: (k: string) => string) => string[]
  >
> = {
  scaleway: (p, label) => {
    const out: string[] = [];
    const hc = p.healthCheck as Record<string, unknown>;
    const durations: Array<[string, unknown]> = [
      ['timeoutClient', p.timeoutClient],
      ['timeoutServer', p.timeoutServer],
      ['timeoutTunnel', p.timeoutTunnel],
      ['timeoutConnect', p.timeoutConnect],
      ['timeoutQueue', p.timeoutQueue],
      ['healthCheck.checkDelay', hc.checkDelay],
      ['healthCheck.checkTimeout', hc.checkTimeout],
      ['healthCheck.transientCheckDelay', hc.transientCheckDelay],
    ];
    for (const [k, v] of durations)
      if (typeof v === 'string' && !SECONDS.test(v))
        out.push(`${label(k)}: give it in seconds with an s, like 600s or 2.5s`);
    return out;
  },
  ovh: (p, label) => {
    const out: string[] = [];
    const hm = p.healthMonitor as { delay: number; timeout: number };
    if (hm.timeout >= hm.delay)
      out.push(`${label('healthMonitor.timeout')}: must be below the check interval`);
    // The v1 API takes IPv4 ranges only.
    for (const c of (p.allowedCidrs as string[] | undefined) ?? [])
      if (!IPV4_CIDR.test(c)) out.push(`${label('allowedCidrs')}: "${c}" is not an IPv4 range`);
    return out;
  },
  gcore: (p, label) => {
    const out: string[] = [];
    const hm = p.healthMonitor as { delay: number; timeout: number };
    if (hm.timeout >= hm.delay)
      out.push(`${label('healthMonitor.timeout')}: must be below the check interval`);
    // Gcore tags: no whitespace or = in a key; a value that is not empty and on one line.
    for (const [k, v] of Object.entries((p.tags as Record<string, string> | undefined) ?? {})) {
      if (/[\s=]/.test(k)) out.push(`${label('tags')}: "${k}" may not hold a space or =`);
      if (v.length === 0 || /[\t\r\n]/.test(v))
        out.push(`${label('tags')}: the value of "${k}" must be one non-empty line`);
    }
    // An IPv4-only edge takes IPv4 ranges only.
    if (p.ipFamily === 'ipv4')
      for (const c of (p.allowedCidrs as string[] | undefined) ?? [])
        if (c.includes(':'))
          out.push(`${label('allowedCidrs')}: "${c}" is IPv6 on an IPv4-only edge`);
    return out;
  },
  fastly: (p, label) => {
    const out: string[] = [];
    // Fastly refuses a backend whose lowest TLS version is above its highest.
    const min = p.minTlsVersion as string | undefined;
    const max = p.maxTlsVersion as string | undefined;
    if (min && max && Number(min) > Number(max))
      out.push(`${label('minTlsVersion')}: must not be above ${label('maxTlsVersion')} (${max})`);
    // Keepalive timings only mean something with keepalive on.
    if (p.tcpKeepalive !== true)
      for (const k of ['tcpKeepaliveTime', 'tcpKeepaliveInterval', 'tcpKeepaliveProbes'])
        if (p[k] !== undefined) out.push(`${label(k)}: only with ${label('tcpKeepalive')} on`);
    return out;
  },
  upcloud: (p, label) => {
    const out: string[] = [];
    // UpCloud label keys: 2 to 32 printable characters, not starting with an underscore.
    for (const l of (p.labels as Array<{ key: string }> | undefined) ?? [])
      if (!/^[\x21-\x7e]{2,32}$/.test(l.key) || l.key.startsWith('_'))
        out.push(`${label('labels')}: "${l.key}" must be 2 to 32 characters, not starting with _`);
    return out;
  },
};

/**
 * Where an edge is about to be built: facts its template cannot know. A
 * REALITY transport on the L4 load balancer (`realityL4`); the plan of the
 * Cloudflare zone its DNS records go to (`zonePlan`, from the credential
 * test; unknown until a test reads it).
 */
export interface BuildContext {
  realityL4?: boolean;
  zonePlan?: string | null;
}

/**
 * What the built params ask that this place cannot do, in words (empty when
 * nothing): an HTTP health check against a REALITY port (it answers no plain
 * HTTP request, so every member would be marked down), or record tags and
 * per-record flattening on a Free zone (Cloudflare offers them on paid plans
 * only). Checked when a pick is planned and again when an edge is built.
 */
export function contextProblems(
  provider: EdgeProviderId,
  params: Record<string, unknown>,
  c: BuildContext,
): string[] {
  const label = labelOf(provider);
  const out: string[] = [];
  if (c.realityL4 && (provider === 'gcore' || provider === 'ovh')) {
    const type = String((params.healthMonitor as { type?: string } | undefined)?.type ?? '');
    if (/^https?$/i.test(type))
      out.push(
        `${label('healthMonitor.type')}: a REALITY transport answers no HTTP check; choose a TCP check`,
      );
  }
  if (c.zonePlan === 'free') {
    const tagKey =
      provider === 'cloudflare' ? 'recordTags' : provider === 'fastly' ? 'dnsTags' : null;
    const tags = tagKey ? (params[tagKey] as Record<string, string> | undefined) : undefined;
    if (tagKey && tags && Object.keys(tags).length > 0)
      out.push(
        `${label(tagKey)}: the zone is on Cloudflare's Free plan, which takes no record tags`,
      );
    if (provider === 'fastly' && params.dnsFlatten === true)
      out.push(`${label('dnsFlatten')}: only a paid Cloudflare zone flattens one record`);
  }
  return out;
}

function labelOf(provider: EdgeProviderId): (key: string) => string {
  const fields = optionFieldsOf(provider);
  return (key) => fields.find((f) => f.key === key)?.label ?? key;
}

function issuesInWords(
  provider: EdgeProviderId,
  issues: readonly { path: PropertyKey[]; message: string }[],
): string[] {
  const label = labelOf(provider);
  return issues
    .slice(0, 10)
    .map((i) => `${i.path.length > 0 ? label(i.path.join('.')) : '(root)'}: ${i.message}`);
}

/** A template being SAVED: the read schema, no certificate option, and the provider's write rules. */
export function validateTemplateWrite(
  provider: EdgeProviderId,
  raw: unknown,
): { ok: true; params: Record<string, unknown> } | { ok: false; issues: string[] } {
  const res = validateTemplateParams(provider, raw);
  if (!res.ok) return res;
  const cert = setKeys((raw ?? {}) as Values, EDGE_CERTIFICATE_OPTIONS[provider].fields).filter(
    (k) => certificateKeysOf(provider).includes(k),
  );
  if (cert.length > 0) {
    const label = labelOf(provider);
    return {
      ok: false,
      issues: cert.map((k) => `${label(k)}: set on the account or for one node, not in a template`),
    };
  }
  const issues = WRITE_CHECKS[provider]?.(res.params, labelOf(provider)) ?? [];
  return issues.length > 0 ? { ok: false, issues } : res;
}

export type OptionCheck =
  | { ok: true; values: Values }
  | {
      ok: false;
      code: 'edge.option_unknown' | 'edge.option_invalid' | 'edge.option_not_here';
      issues: string[];
    };

/**
 * The options chosen for ONE node's pick: any option of the provider. Returns
 * only the keys chosen, normalised by the schema. Tuning choices are checked
 * laid over the provider defaults here, and over the template the location
 * resolves when a run plans (`checkBuiltParams`).
 */
export function validatePickOptions(provider: EdgeProviderId, raw: unknown): OptionCheck {
  return checkOptions(provider, raw, 'pick');
}

/** The account's defaults: certificate options only (tuning defaults live in templates). */
export function validateAccountOptionDefaults(provider: EdgeProviderId, raw: unknown): OptionCheck {
  return checkOptions(provider, raw, 'account');
}

function checkOptions(provider: EdgeProviderId, raw: unknown, level: OptionLevel): OptionCheck {
  if (raw === null || raw === undefined) return { ok: true, values: {} };
  if (typeof raw !== 'object' || Array.isArray(raw))
    return { ok: false, code: 'edge.option_invalid', issues: ['options: an object is required'] };
  const fields = optionFieldsOf(provider);
  const keys = setKeys(raw as Values, fields);
  const known = new Set(fields.map((f) => f.key));
  const unknown = keys.filter((k) => !known.has(k));
  if (unknown.length > 0)
    return {
      ok: false,
      code: 'edge.option_unknown',
      issues: unknown.slice(0, 10).map((k) => `${k}: not an option of this provider`),
    };
  const certKeys = certificateKeysOf(provider);
  if (level === 'account') {
    const tuning = keys.filter((k) => !certKeys.includes(k));
    if (tuning.length > 0) {
      const label = labelOf(provider);
      return {
        ok: false,
        code: 'edge.option_not_here',
        issues: tuning.map((k) => `${label(k)}: a template sets this, not the account`),
      };
    }
  }
  const { tuning, certificate } = splitChoices(fields, raw as Values);
  const certRes = EDGE_CERTIFICATE_OPTIONS[provider].schema.safeParse(certificate);
  if (!certRes.success)
    return {
      ok: false,
      code: 'edge.option_invalid',
      issues: issuesInWords(provider, certRes.error.issues),
    };
  const tuningKeys = keys.filter((k) => !certKeys.includes(k));
  let tuningValues: Values = {};
  if (tuningKeys.length > 0) {
    const merged = deepMerge(EDGE_TEMPLATES[provider].defaults, tuning);
    const tplRes = EDGE_TEMPLATES[provider].schema.safeParse(merged);
    if (!tplRes.success)
      return {
        ok: false,
        code: 'edge.option_invalid',
        issues: issuesInWords(provider, tplRes.error.issues),
      };
    // Values only: rules across fields are checked once the pick is laid over
    // the template its location builds with (`checkBuiltParams`), never
    // against the compiled defaults (a pick may lean on its template's interval
    // or its keepalive switch).
    tuningValues = pickKeys(tplRes.data, tuningKeys);
  }
  return { ok: true, values: deepMerge(tuningValues, certRes.data as Values) };
}

/**
 * The params a node's pick builds with (the location's template with the
 * pick's tuning choices laid over it), checked as a whole: a choice valid on
 * its own may break a rule together with the template (a check timeout above
 * the template's interval).
 */
export function checkBuiltParams(
  provider: EdgeProviderId,
  params: Values,
): { ok: true; params: Values } | { ok: false; issues: string[] } {
  const res = EDGE_TEMPLATES[provider].schema.safeParse(params);
  if (!res.success) return { ok: false, issues: issuesInWords(provider, res.error.issues) };
  const rules = WRITE_CHECKS[provider]?.(res.data, labelOf(provider)) ?? [];
  return rules.length > 0 ? { ok: false, issues: rules } : { ok: true, params: res.data };
}

/**
 * Template fields whose value differs per region (a load balancer flavor id is
 * only valid in the region that offers it): the descriptors marked `regional`.
 * A location may set its own value for each (`edgeLocations.regionalParams`),
 * laid over the template when it provisions (lib/edges/locations.ts).
 */
export const EDGE_TEMPLATE_REGIONAL_FIELDS: Record<EdgeProviderId, readonly string[]> =
  Object.fromEntries(
    (Object.keys(EDGE_TEMPLATES) as EdgeProviderId[]).map((p) => [
      p,
      EDGE_TEMPLATES[p].fields.filter((f) => f.regional).map((f) => f.key),
    ]),
  ) as unknown as Record<EdgeProviderId, readonly string[]>;
