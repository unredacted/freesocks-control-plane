/**
 * A location picked by its REGION alone (the protect sheet, a node's "Add a
 * location"): the rest of its placement is completed from what the key
 * reaches, so an account added with its credentials alone can be used
 * without a location form (docs/edges.md § "Provider accounts and
 * locations"). Pure and isolate-safe: the provider listings come in, the
 * placement goes out.
 *
 *  - `REGION_KEYS`: the placement key a region's id goes in (a load balancer
 *    provider's; a CDN's place is a zone, picked in the location form);
 *  - `projectDefault`: the project the account's other locations all use,
 *    else the only, else the first one the key lists;
 *  - `networkDefault`: where a provider needs a private network (OVH), the
 *    first listed network with a subnet in the region, and its first subnet.
 *    Gcore's network stays empty (a public address);
 *  - `completePlacement`: the chosen values, never replaced, plus those
 *    defaults; `missing` names what could not be chosen (the caller asks for
 *    it, `edge.location_options_needed`).
 */
import type { EdgeProviderId } from '../edgeProviderIds';

interface Choice {
  id: string;
  label: string;
}
interface Network extends Choice {
  subnets: Choice[];
}

/** The placement key a region's id goes in, per load balancer provider. */
export const REGION_KEYS: Partial<Record<EdgeProviderId, string>> = {
  gcore: 'regionId',
  upcloud: 'zone',
  scaleway: 'zone',
  ovh: 'regionName',
};

/** The placement key of the project a region is used in (a provider with projects). */
export const PROJECT_KEYS: Partial<Record<EdgeProviderId, string>> = {
  gcore: 'projectId',
  ovh: 'serviceName',
};

/** Providers whose location needs a private network and a subnet in its region. */
const NETWORK_REQUIRED: ReadonlySet<EdgeProviderId> = new Set(['ovh']);

/** Placement keys the adapter takes as numbers (a listing's ids are strings). */
const NUMERIC_KEYS: Partial<Record<EdgeProviderId, readonly string[]>> = {
  gcore: ['projectId', 'regionId'],
};

/** Whether a region alone can name a location of this provider (a load balancer provider). */
export function pickableByRegion(provider: EdgeProviderId): boolean {
  return REGION_KEYS[provider] !== undefined;
}

/** Whether a project still has to be chosen for this placement. */
export function needsProject(provider: EdgeProviderId, chosen: Record<string, unknown>): boolean {
  const key = PROJECT_KEYS[provider];
  return key !== undefined && !present(chosen[key]);
}

/** Whether a private network still has to be chosen for this placement. */
export function needsNetwork(provider: EdgeProviderId, chosen: Record<string, unknown>): boolean {
  return NETWORK_REQUIRED.has(provider) && !(present(chosen.networkId) && present(chosen.subnetId));
}

const present = (v: unknown): boolean => v !== undefined && v !== null && v !== '';

/**
 * The project a new location of the account is created in: the one every
 * other location of the account uses (the operator chose it once), when the
 * key still lists it or the listing failed; else the only listed project;
 * else the first. Null when nothing names one.
 */
export function projectDefault(
  provider: EdgeProviderId,
  projects: readonly Choice[] | undefined,
  accountPlacements: ReadonlyArray<Record<string, unknown>>,
): string | null {
  const key = PROJECT_KEYS[provider];
  if (!key) return null;
  const used = [
    ...new Set(
      accountPlacements
        .map((p) => p[key])
        .filter(present)
        .map((v) => String(v)),
    ),
  ];
  if (used.length === 1 && (!projects || projects.some((p) => p.id === used[0]))) return used[0]!;
  return projects?.[0]?.id ?? null;
}

/**
 * The network and subnet a location needs (OVH): the chosen network's first
 * subnet, else the first listed network that has a subnet. The listing is the
 * one asked with the region, so every network and subnet in it serves there.
 */
export function networkDefault(
  networks: readonly Network[] | undefined,
  chosenNetworkId?: string,
): { networkId: string; subnetId: string } | null {
  const list = networks ?? [];
  const net = chosenNetworkId
    ? list.find((n) => n.id === chosenNetworkId)
    : list.find((n) => n.subnets.length > 0);
  const subnet = net?.subnets[0];
  return net && subnet ? { networkId: net.id, subnetId: subnet.id } : null;
}

/**
 * The placement with its defaults laid under what was chosen. `found` holds
 * the listings: `projects` (asked without a project) and `networks` (asked
 * with the project and the region). `missing` names the keys no default
 * could fill.
 */
export function completePlacement(
  provider: EdgeProviderId,
  chosen: Record<string, unknown>,
  found: { projects?: readonly Choice[]; networks?: readonly Network[] },
  accountPlacements: ReadonlyArray<Record<string, unknown>> = [],
): { placement: Record<string, unknown>; missing: string[] } {
  const out: Record<string, unknown> = Object.fromEntries(
    Object.entries(chosen).filter(([k, v]) => k !== 'type' && present(v)),
  );
  const missing: string[] = [];
  const regionKey = REGION_KEYS[provider];
  if (regionKey && !present(out[regionKey])) missing.push(regionKey);
  const projectKey = PROJECT_KEYS[provider];
  if (projectKey && !present(out[projectKey])) {
    const project = projectDefault(provider, found.projects, accountPlacements);
    if (project !== null) out[projectKey] = project;
    else missing.push(projectKey);
  }
  if (NETWORK_REQUIRED.has(provider) && !(present(out.networkId) && present(out.subnetId))) {
    const net = networkDefault(
      found.networks,
      present(out.networkId) ? String(out.networkId) : undefined,
    );
    if (net) Object.assign(out, net);
    else missing.push(...(['networkId', 'subnetId'] as const).filter((k) => !present(out[k])));
  }
  for (const key of NUMERIC_KEYS[provider] ?? []) {
    const n = Number(out[key]);
    if (present(out[key]) && Number.isFinite(n)) out[key] = n;
  }
  return { placement: out, missing };
}
