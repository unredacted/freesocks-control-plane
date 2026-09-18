/**
 * The WIRE CONTRACT: every HTTP endpoint FCP's edge adapters call, per provider.
 *
 * Why this exists. Four of the six adapters are hand-rolled and two drive
 * vendor SDKs, so the set of endpoints FCP depends on is otherwise spread over
 * six files and two node_modules trees. A provider's API change, an SDK upgrade
 * that moves a path, or a new call slipped into an adapter are all invisible in
 * review; here they are one diff. `wireContract.test.ts` drives each adapter's
 * FULL lifecycle against a recording HTTP transport and asserts both directions:
 * every recorded request matches an entry below, and every entry below is
 * exercised by the lifecycle (so the table cannot list endpoints nothing calls).
 * `docs/edges.md` carries the rendered table, pinned by the same test.
 *
 * Paths are RegExp SOURCES matched against the request path (no host, no query),
 * with `[^/]+` where an id, a name or a version number goes. Query and body keys
 * are the ones that must be PRESENT (extra keys are fine): they pin filters,
 * pagination and the fields an allocating call cannot lose.
 *
 * Each entry's `source` is the vendor documentation the calls were read from,
 * with the date, so a reviewer can check a shape against the vendor rather than
 * against another hand-written mock.
 */
import type { EdgeProviderId } from '../../edgeProviderIds';

export interface WireCall {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  /** RegExp source matched against the URL path; `[^/]+` stands for an id. */
  path: string;
  /** What FCP uses the call for (one short clause, no provider-choice detail). */
  purpose: string;
  /** Query keys that must be present on every such call. */
  query?: string[];
  /** Top-level body keys that must be present when the call sends a body. */
  body?: string[];
}

export interface WireContract {
  /** Vendor documentation (or generated SDK source) the calls were read from, with a date. */
  source: string;
  calls: WireCall[];
}

/** What the test observed on the wire, reduced to what the contract talks about. */
export interface ObservedCall {
  method: string;
  path: string;
  queryKeys?: readonly string[];
  bodyKeys?: readonly string[];
}

export const WIRE_CONTRACTS: Record<EdgeProviderId, WireContract> = {
  // --- L4: Gcore Cloud load balancers ------------------------------------------------
  gcore: {
    source: 'https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16',
    calls: [
      {
        method: 'GET',
        path: '^/cloud/v1/loadbalancers/[^/]+/[^/]+$',
        purpose: 'list load balancers: credential test, region check, discovery by name, inventory',
      },
      {
        method: 'POST',
        path: '^/cloud/v1/loadbalancers/[^/]+/[^/]+$',
        purpose: 'create the load balancer with its TCP listener, pool and health monitor',
        body: ['name', 'flavor', 'listeners', 'tags'],
      },
      {
        method: 'GET',
        path: '^/cloud/v1/loadbalancers/[^/]+/[^/]+/[^/]+$',
        purpose: 'read one load balancer: describe, inspect, delete confirmation',
      },
      {
        method: 'DELETE',
        path: '^/cloud/v1/loadbalancers/[^/]+/[^/]+/[^/]+$',
        purpose: 'delete the load balancer (answers with a task)',
      },
      {
        method: 'GET',
        path: '^/cloud/v1/tasks/[^/]+$',
        purpose: 'poll the create or delete task and read the resources it created',
      },
      {
        method: 'GET',
        path: '^/cloud/v1/floatingips/[^/]+/[^/]+$',
        purpose: 'list floating IPs (inventory)',
      },
      {
        method: 'GET',
        path: '^/cloud/v1/floatingips/[^/]+/[^/]+/[^/]+$',
        purpose: 'read a floating IP back after its delete',
      },
      {
        method: 'DELETE',
        path: '^/cloud/v1/floatingips/[^/]+/[^/]+/[^/]+$',
        purpose: 'release the floating IP the load balancer held',
      },
      {
        method: 'GET',
        path: '^/cloud/v1/lbflavors/[^/]+/[^/]+$',
        purpose: 'list load balancer flavors (inventory)',
      },
      {
        method: 'GET',
        path: '^/cloud/v1/projects$',
        purpose: 'account form: the projects the key can see',
      },
      {
        method: 'GET',
        path: '^/cloud/v1/regions$',
        purpose: 'account form: the regions the key can see',
      },
      {
        method: 'GET',
        path: '^/cloud/v1/networks/[^/]+/[^/]+$',
        purpose: 'account form: private networks for a private VIP',
      },
      {
        method: 'GET',
        path: '^/cloud/v1/subnets/[^/]+/[^/]+$',
        purpose: 'account form: the subnets of those networks',
      },
    ],
  },

  // --- L4: UpCloud managed load balancers ---------------------------------------------
  upcloud: {
    source: 'https://developers.upcloud.com/1.3/ (Managed Load Balancer), 2026-09-16',
    calls: [
      { method: 'GET', path: '^/1\\.3/account$', purpose: 'credential test' },
      { method: 'GET', path: '^/1\\.3/zone$', purpose: 'account form: the zones' },
      {
        method: 'POST',
        path: '^/1\\.3/load-balancer$',
        purpose: 'create the service with its TCP frontend and backend inline',
        body: ['name', 'plan', 'zone', 'frontends', 'backends'],
      },
      {
        method: 'GET',
        path: '^/1\\.3/load-balancer$',
        purpose: 'list services: discovery by name and inventory',
      },
      {
        method: 'GET',
        path: '^/1\\.3/load-balancer/plans$',
        purpose: 'list the service plans (inventory)',
      },
      {
        method: 'GET',
        path: '^/1\\.3/load-balancer/(?!plans$)[^/]+$',
        purpose: 'read one service: describe, inspect, attachment check',
      },
      {
        method: 'DELETE',
        path: '^/1\\.3/load-balancer/(?!plans$)[^/]+$',
        purpose: 'delete the service (idempotent; re-issued until it answers 404)',
      },
      {
        method: 'POST',
        path: '^/1\\.3/load-balancer/[^/]+/ip-addresses$',
        purpose: 'delegate the floating IP to the service',
        body: ['ip_addresses'],
      },
      {
        method: 'POST',
        path: '^/1\\.3/ip_address$',
        purpose: 'allocate the floating IPv4 that is published',
        body: ['ip_address'],
      },
      {
        method: 'GET',
        path: '^/1\\.3/ip_address$',
        purpose: 'list IP addresses: unknown-outcome discovery and inventory',
      },
      {
        method: 'DELETE',
        path: '^/1\\.3/ip_address/[^/]+$',
        purpose: 'release the floating IP',
      },
    ],
  },

  // --- L4: Scaleway load balancers (official SDK, zoned API) ---------------------------
  scaleway: {
    source:
      'https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16',
    calls: [
      {
        method: 'GET',
        path: '^/lb/v1/zones/[^/]+/lbs$',
        purpose: 'list load balancers: credential test, discovery by name, inventory',
      },
      {
        method: 'POST',
        path: '^/lb/v1/zones/[^/]+/lbs$',
        purpose: 'create the load balancer over the already allocated IPs',
        body: ['name', 'type', 'ip_ids', 'project_id'],
      },
      {
        method: 'GET',
        path: '^/lb/v1/zones/[^/]+/lbs/[^/]+$',
        purpose: 'read one load balancer: describe, inspect, delete confirmation',
      },
      {
        method: 'DELETE',
        path: '^/lb/v1/zones/[^/]+/lbs/[^/]+$',
        purpose: 'delete the load balancer without releasing its IPs',
        query: ['release_ip'],
      },
      {
        method: 'POST',
        path: '^/lb/v1/zones/[^/]+/ips$',
        purpose: 'allocate a flexible IP (v4, and v6 when the template asks)',
        body: ['project_id', 'tags'],
      },
      {
        method: 'GET',
        path: '^/lb/v1/zones/[^/]+/ips$',
        purpose: 'list flexible IPs: discovery by tag and inventory',
      },
      {
        method: 'GET',
        path: '^/lb/v1/zones/[^/]+/ips/[^/]+$',
        purpose: 'read a flexible IP back after its release',
      },
      {
        method: 'DELETE',
        path: '^/lb/v1/zones/[^/]+/ips/[^/]+$',
        purpose: 'release a flexible IP',
      },
      {
        method: 'POST',
        path: '^/lb/v1/zones/[^/]+/lbs/[^/]+/backends$',
        purpose: 'create the TCP backend pointing at the origin',
        body: ['name', 'forward_protocol', 'forward_port', 'server_ip'],
      },
      {
        method: 'GET',
        path: '^/lb/v1/zones/[^/]+/lbs/[^/]+/backends$',
        purpose: 'list backends: discovery by name and inspect',
      },
      {
        method: 'GET',
        path: '^/lb/v1/zones/[^/]+/backends/[^/]+$',
        purpose: 'read a backend back after its delete',
      },
      {
        method: 'DELETE',
        path: '^/lb/v1/zones/[^/]+/backends/[^/]+$',
        purpose: 'delete the backend',
      },
      {
        method: 'POST',
        path: '^/lb/v1/zones/[^/]+/lbs/[^/]+/frontends$',
        purpose: 'create the frontend on the edge port',
        body: ['name', 'inbound_port', 'backend_id'],
      },
      {
        method: 'GET',
        path: '^/lb/v1/zones/[^/]+/lbs/[^/]+/frontends$',
        purpose: 'list frontends: discovery by name and inspect',
      },
      {
        method: 'GET',
        path: '^/lb/v1/zones/[^/]+/frontends/[^/]+$',
        purpose: 'read a frontend back after its delete',
      },
      {
        method: 'DELETE',
        path: '^/lb/v1/zones/[^/]+/frontends/[^/]+$',
        purpose: 'delete the frontend',
      },
      {
        method: 'GET',
        path: '^/lb/v1/zones/[^/]+/lbs/[^/]+/stats$',
        purpose: 'backend health for describe and inspect',
      },
      {
        method: 'GET',
        path: '^/lb/v1/zones/[^/]+/lb-types$',
        purpose: 'list load balancer types (inventory)',
      },
    ],
  },

  // --- L4: OVHcloud public cloud load balancers (signed requests) -----------------------
  ovh: {
    source: 'https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16',
    calls: [
      {
        method: 'GET',
        path: '^/1\\.0/auth/time$',
        purpose: 'server clock for the request signature (cached, unsigned)',
      },
      { method: 'GET', path: '^/1\\.0/cloud/project$', purpose: 'account form: the project ids' },
      {
        method: 'GET',
        path: '^/1\\.0/cloud/project/[^/]+$',
        purpose: 'credential test and the project label in the account form',
      },
      {
        method: 'GET',
        path: '^/1\\.0/cloud/project/[^/]+/region$',
        purpose: 'account form: the regions of the project',
      },
      {
        method: 'GET',
        path: '^/1\\.0/cloud/project/[^/]+/network/private$',
        purpose: 'account form: the private networks',
      },
      {
        method: 'GET',
        path: '^/1\\.0/cloud/project/[^/]+/network/private/[^/]+/subnet$',
        purpose: 'account form: the subnets of a private network',
      },
      {
        method: 'GET',
        path: '^/1\\.0/cloud/project/[^/]+/operation$',
        purpose: 'in-flight balancer operations: absence is never confirmed during one',
      },
      {
        method: 'GET',
        path: '^/1\\.0/cloud/project/[^/]+/operation/[^/]+$',
        purpose: 'poll the compound create operation',
      },
      {
        method: 'POST',
        path: '^/1\\.0/cloud/project/[^/]+/region/[^/]+/loadbalancing/loadbalancer$',
        purpose: 'create the balancer with its network, floating IP and listener inline',
        body: ['flavorId', 'name', 'network', 'listeners'],
      },
      {
        method: 'GET',
        path: '^/1\\.0/cloud/project/[^/]+/region/[^/]+/loadbalancing/loadbalancer$',
        purpose: 'list balancers: discovery by name and inventory',
      },
      {
        method: 'GET',
        path: '^/1\\.0/cloud/project/[^/]+/region/[^/]+/loadbalancing/loadbalancer/[^/]+$',
        purpose: 'read one balancer: describe, inspect, delete confirmation',
      },
      {
        method: 'DELETE',
        path: '^/1\\.0/cloud/project/[^/]+/region/[^/]+/loadbalancing/loadbalancer/[^/]+$',
        purpose: 'delete the balancer',
      },
      {
        method: 'GET',
        path: '^/1\\.0/cloud/project/[^/]+/region/[^/]+/loadbalancing/loadbalancer/[^/]+/stats$',
        purpose: 'balancer statistics (inspect)',
      },
      {
        method: 'GET',
        path: '^/1\\.0/cloud/project/[^/]+/region/[^/]+/loadbalancing/flavor$',
        purpose: 'list balancer flavors (inventory)',
      },
      {
        method: 'GET',
        path: '^/1\\.0/cloud/project/[^/]+/region/[^/]+/floatingip$',
        purpose: 'find the floating IP the compound create minted, by its description marker',
      },
      {
        method: 'GET',
        path: '^/1\\.0/cloud/project/[^/]+/region/[^/]+/floatingip/[^/]+$',
        purpose: 'read a floating IP back after its delete',
      },
      {
        method: 'DELETE',
        path: '^/1\\.0/cloud/project/[^/]+/region/[^/]+/floatingip/[^/]+$',
        purpose: 'release the floating IP',
      },
      {
        method: 'GET',
        path: '^/1\\.0/cloud/project/[^/]+/region/[^/]+/gateway$',
        purpose: 'find the gateway the compound create minted, by its FCP name',
      },
      {
        method: 'GET',
        path: '^/1\\.0/cloud/project/[^/]+/region/[^/]+/gateway/[^/]+$',
        purpose: 'read a gateway back after its delete',
      },
      {
        method: 'DELETE',
        path: '^/1\\.0/cloud/project/[^/]+/region/[^/]+/gateway/[^/]+$',
        purpose: 'delete the gateway the compound create minted',
      },
    ],
  },

  // --- L7: Cloudflare (own zone) + the DNS writes a Fastly edge makes here --------------
  cloudflare: {
    source: 'https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16',
    calls: [
      {
        method: 'GET',
        path: '^/client/v4/user/tokens/verify$',
        purpose: 'credential test: the token is active',
      },
      {
        method: 'GET',
        path: '^/client/v4/zones$',
        purpose: 'account form: the zones the token can see',
        query: ['per_page'],
      },
      {
        method: 'GET',
        path: '^/client/v4/zones/[^/]+$',
        purpose: 'credential test: the zone is active and not paused',
      },
      {
        method: 'GET',
        path: '^/client/v4/zones/[^/]+/settings/(ssl|websockets)$',
        purpose: 'zone encryption mode and WebSockets setting (recorded, not required)',
      },
      {
        method: 'POST',
        path: '^/client/v4/zones/[^/]+/dns_records$',
        purpose:
          'create the proxied record that IS the edge; also the ACME and traffic records a Fastly edge writes into this zone',
        body: ['type', 'name', 'content', 'proxied', 'ttl', 'comment'],
      },
      {
        method: 'GET',
        path: '^/client/v4/zones/[^/]+/dns_records$',
        purpose:
          'look one name up (unknown-outcome discovery, CAA preflight), including for a Fastly edge',
        query: ['name.exact', 'per_page'],
      },
      {
        method: 'GET',
        path: '^/client/v4/zones/[^/]+/dns_records$',
        purpose: 'paged sweep of proxied records for the import inventory',
        query: ['page', 'per_page', 'proxied'],
      },
      {
        method: 'GET',
        path: '^/client/v4/zones/[^/]+/dns_records/[^/]+$',
        purpose: 'read the record back: describe, inspect, import inspection, delete confirmation',
      },
      {
        method: 'DELETE',
        path: '^/client/v4/zones/[^/]+/dns_records/[^/]+$',
        purpose: 'delete the record (a Fastly edge deletes its records here too)',
      },
      {
        method: 'GET',
        path: '^/client/v4/zones/[^/]+/rulesets/phases/http_request_origin/entrypoint$',
        purpose:
          'read the origin-rules entry point (404 = none yet), and the rule an imported hostname already carries',
      },
      {
        method: 'PUT',
        path: '^/client/v4/zones/[^/]+/rulesets/phases/http_request_origin/entrypoint$',
        purpose: 'bootstrap the entry point with our one origin rule, under the zone lock',
        body: ['rules'],
      },
      {
        method: 'POST',
        path: '^/client/v4/zones/[^/]+/rulesets/[^/]+/rules$',
        purpose: 'add the destination-port origin rule, recovered by its ref',
        body: ['action', 'action_parameters', 'expression', 'ref'],
      },
      {
        method: 'DELETE',
        path: '^/client/v4/zones/[^/]+/rulesets/[^/]+/rules/[^/]+$',
        purpose: 'delete the origin rule',
      },
      {
        method: 'GET',
        path: '^/client/v4/zones/[^/]+/ssl/certificate_packs$',
        purpose: 'certificate readiness for the minted hostname',
      },
    ],
  },

  // --- L7: Fastly (service + domain + TLS subscription) ---------------------------------
  fastly: {
    source:
      'https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare`',
    calls: [
      {
        method: 'POST',
        path: '^/service$',
        purpose: 'create the VCL service (form encoded)',
        body: ['name', 'type'],
      },
      {
        method: 'GET',
        path: '^/service$',
        purpose: 'paged service sweep for the import inventory',
        query: ['page', 'per_page'],
      },
      {
        method: 'GET',
        path: '^/service/search$',
        purpose: 'discover the service by its deterministic name (404 = absent)',
        query: ['name'],
      },
      {
        method: 'GET',
        path: '^/service/[^/]+/details$',
        purpose: 'active version: activation discovery, describe, import inspection, drift check',
      },
      {
        method: 'GET',
        path: '^/service/[^/]+/domain$',
        purpose: 'every domain a service serves (the import ownership boundary)',
      },
      {
        method: 'DELETE',
        path: '^/service/[^/]+$',
        purpose: 'delete an exclusively owned service',
      },
      {
        method: 'GET',
        path: '^/service/[^/]+/version$',
        purpose: 'the version list: pick the draft, recognise a lost clone by its marker',
      },
      {
        method: 'PUT',
        path: '^/service/[^/]+/version/[^/]+$',
        purpose: 'stamp the clone marker comment on the work version',
        body: ['comment'],
      },
      {
        method: 'PUT',
        path: '^/service/[^/]+/version/[^/]+/clone$',
        purpose: 'clone the active version for a shared teardown',
      },
      {
        method: 'GET',
        path: '^/service/[^/]+/version/[^/]+/validate$',
        purpose: 'validate a version before activating it',
      },
      {
        method: 'PUT',
        path: '^/service/[^/]+/version/[^/]+/activate$',
        purpose: 'activate the version',
      },
      {
        method: 'PUT',
        path: '^/service/[^/]+/version/[^/]+/deactivate$',
        purpose: 'deactivate the active version before deleting the service',
      },
      {
        method: 'POST',
        path: '^/service/[^/]+/version/[^/]+/backend$',
        purpose: 'create the single origin backend (only fields the WebSocket path honours)',
        body: ['name', 'address', 'use_ssl', 'override_host'],
      },
      {
        method: 'GET',
        path: '^/service/[^/]+/version/[^/]+/backend$',
        purpose: 'list backends: inspect and the import ownership check',
      },
      {
        method: 'GET',
        path: '^/service/[^/]+/version/[^/]+/backend/[^/]+$',
        purpose: 'discover the backend by name; read it back after a destroy',
      },
      {
        method: 'POST',
        path: '^/service/[^/]+/version/[^/]+/snippet$',
        purpose: 'install the VCL snippet that hands an Upgrade request to the WebSocket path',
        body: ['name', 'type', 'content'],
      },
      {
        method: 'GET',
        path: '^/service/[^/]+/version/[^/]+/snippet/[^/]+$',
        purpose: 'discover the snippet by name; read it back after a destroy',
      },
      {
        method: 'POST',
        path: '^/service/[^/]+/version/[^/]+/domain$',
        purpose: 'add the fronted hostname to the draft version',
        body: ['name'],
      },
      {
        method: 'GET',
        path: '^/service/[^/]+/version/[^/]+/domain$',
        purpose:
          'list the version domains: inspect, the import ownership boundary, shared-teardown confirmation',
      },
      {
        method: 'GET',
        path: '^/service/[^/]+/version/[^/]+/domain/[^/]+$',
        purpose: 'discover the domain by name; read it back after a destroy',
      },
      {
        method: 'GET',
        path: '^/service/[^/]+/version/[^/]+/domain/[^/]+/check$',
        purpose: 'DNS readiness of the fronted hostname',
      },
      {
        method: 'DELETE',
        path: '^/service/[^/]+/version/[^/]+/domain/[^/]+$',
        purpose: 'remove only our hostname from a shared service',
      },
      {
        method: 'PUT',
        path: '^/enabled-products/v1/websockets/services/[^/]+$',
        purpose: 'enable the WebSockets product on the service (idempotent)',
      },
      {
        method: 'GET',
        path: '^/enabled-products/v1/websockets/services/[^/]+$',
        purpose: 'discover the product state, on import too; read it back after a destroy',
      },
      {
        method: 'DELETE',
        path: '^/enabled-products/v1/websockets/services/[^/]+$',
        purpose: 'disable the product last, after the service is gone',
      },
      {
        method: 'POST',
        path: '^/tls/subscriptions$',
        purpose: 'order the certificate for the fronted hostname (JSON:API)',
        body: ['data'],
      },
      {
        method: 'GET',
        path: '^/tls/subscriptions$',
        purpose:
          'discover the subscription by domain, and the certificate an imported hostname already has; confirm its removal',
        query: ['filter[tls_domains.id]'],
      },
      {
        method: 'GET',
        path: '^/tls/subscriptions/[^/]+$',
        purpose: 'issuance state and (with the include) the managed-DNS challenge',
      },
      {
        method: 'DELETE',
        path: '^/tls/subscriptions/[^/]+$',
        purpose: 'delete the subscription (force, since its domain is enabled)',
        query: ['force'],
      },
      {
        method: 'GET',
        path: '^/tls/configurations$',
        purpose: 'account form choices, and the CNAME target every fronted hostname points at',
      },
      {
        method: 'GET',
        path: '^/tokens/self$',
        purpose: 'credential test: the token scope',
      },
      {
        method: 'GET',
        path: '^/current_customer$',
        purpose: 'credential test: the pricing plan (informational)',
      },
    ],
  },
};

// --- matching --------------------------------------------------------------------------

function matches(entry: WireCall, call: ObservedCall): boolean {
  if (entry.method !== call.method.toUpperCase()) return false;
  if (!new RegExp(entry.path).test(call.path)) return false;
  const queryKeys = new Set(call.queryKeys ?? []);
  for (const k of entry.query ?? []) if (!queryKeys.has(k)) return false;
  const bodyKeys = call.bodyKeys;
  // Body keys are only required when the call actually sent a body: a `GET` and
  // a body-less `DELETE` of the same path are covered by the same entry.
  if (entry.body && bodyKeys && bodyKeys.length > 0) {
    const set = new Set(bodyKeys);
    for (const k of entry.body) if (!set.has(k)) return false;
  }
  return true;
}

/** The contract entry a recorded call satisfies, if any. */
export function matchWireCall(id: EdgeProviderId, call: ObservedCall): WireCall | undefined {
  return WIRE_CONTRACTS[id].calls.find((entry) => matches(entry, call));
}

/** Recorded calls that no contract entry covers (an undeclared endpoint). */
export function unmatchedCalls(id: EdgeProviderId, calls: readonly ObservedCall[]): ObservedCall[] {
  return calls.filter((c) => !matchWireCall(id, c));
}

/** Contract entries the observed lifecycle never exercised (a dead entry). */
export function uncoveredEntries(id: EdgeProviderId, calls: readonly ObservedCall[]): WireCall[] {
  return WIRE_CONTRACTS[id].calls.filter((entry) => !calls.some((c) => matches(entry, c)));
}

/** `GET /foo/[^/]+$` as one readable line (the doc table cell). */
export function wireCallLabel(entry: WireCall): string {
  const q = entry.query?.length ? ` ?${entry.query.join('&')}` : '';
  return `${entry.path}${q}`;
}

// --- documentation ------------------------------------------------------------------------

/** A markdown table cell: pipes would end the cell, newlines the row. */
function cell(text: string): string {
  return text.replace(/\|/g, '\\|').replace(/\s*\n\s*/g, ' ');
}

export const WIRE_CONTRACT_HEADING = '## Provider wire contracts';

/**
 * The docs/edges.md section, rendered from `WIRE_CONTRACTS` alone: the test
 * beside this file re-renders it and fails when the checked-in section drifts,
 * so the documented endpoints are always the ones the adapters call.
 */
export function renderWireContractTable(): string {
  const rows: string[] = [
    '| provider | method | path | purpose | source |',
    '| --- | --- | --- | --- | --- |',
  ];
  for (const [id, contract] of Object.entries(WIRE_CONTRACTS)) {
    for (const entry of contract.calls) {
      rows.push(
        `| ${id} | ${entry.method} | \`${cell(wireCallLabel(entry))}\` | ${cell(entry.purpose)} | ${cell(contract.source)} |`,
      );
    }
  }
  return rows.join('\n');
}

/**
 * One markdown table row as trimmed cells; `null` for anything that is not a
 * row (prose, the `| --- |` separator). Comparing CELLS rather than lines is
 * what lets the checked-in doc be padded by the repo formatter and still be
 * pinned to this contract.
 */
export function tableRowCells(line: string): string[] | null {
  const trimmed = line.trim();
  if (!trimmed.startsWith('|') || !trimmed.endsWith('|')) return null;
  const cells = trimmed
    .slice(1, -1)
    .split(/(?<!\\)\|/)
    .map((c) => c.trim().replace(/\\\|/g, '|'));
  if (cells.length === 0) return null;
  if (cells.every((c) => /^:?-{2,}:?$/.test(c))) return null;
  return cells;
}

/** The rendered table as trimmed cells (header row included). */
export function wireContractCells(): string[][] {
  return renderWireContractTable()
    .split('\n')
    .map(tableRowCells)
    .filter((row): row is string[] => row !== null);
}
