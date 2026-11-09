/**
 * Admin -> Servers paths (pure; unit-tested). Every Servers page lives under
 * `/admin/servers`, with one tab bar (components/ServersNav.svelte):
 *
 *   Overview | Nodes | Countries | SNIs | Probes | Providers | Settings
 *
 * This file spells the section's own pages; the pages that came from the old
 * Edges section are spelled in ../../edges/lib/routes.ts (same root).
 *
 *   /admin/servers/nodes[?backend=<slug>][&show=][&columns=technical][&add=origin][&front=1][&node=][&run=]
 *                                                   Nodes: every node of every backend in one table (lib/nodesTable.ts);
 *                                                   `backend` keeps one backend, `show` a filter, `columns=technical`
 *                                                   the old All origins columns, `add=origin` opens "Add an origin by hand",
 *                                                   `front=1` the protect sheet (`backend`, `node` preset it), `run` a run's progress
 *   /admin/servers/nodes/:uuid[?backend=<slug>][&test=<edgeId>]
 *                                                   one node: its machine, activation and edges
 *   /admin/servers/settings/backends                Settings -> Backends: the backend servers FCP issues keys on
 *   /admin/servers/settings/mode-pools              Settings -> Mode pools: which mode groups each connection mode issues into
 *
 * Old addresses keep working: legacyRoutes.ts maps them here.
 */
import { matchRoute } from '../../../../lib/matchRoute';
import { resolveEdgesRoute, type EdgesRoute } from '../../edges/lib/routes';

export const SERVERS_ROOT = '/admin/servers';

const withBackend = (path: string, backend?: string) =>
  backend ? `${path}?backend=${encodeURIComponent(backend)}` : path;

/** The Nodes tab's own query (see the table above); empty values are left out. */
export interface NodesParams {
  backend?: string;
  show?: string;
  columns?: 'technical';
  add?: 'origin';
  front?: '1';
  node?: string;
  run?: string;
}

export const serversPaths = {
  /** The Overview tab (the section root). */
  overview: () => SERVERS_ROOT,
  /** The Nodes tab; `backend` keeps one backend server (by slug), the rest as in NodesParams. */
  nodes: (opts: NodesParams = {}) => {
    const qs = (['backend', 'show', 'columns', 'add', 'front', 'node', 'run'] as const)
      .filter((k) => opts[k])
      .map((k) => `${k}=${encodeURIComponent(opts[k]!)}`)
      .join('&');
    return `${SERVERS_ROOT}/nodes${qs ? `?${qs}` : ''}`;
  },
  /** Settings -> Backends. */
  backends: () => `${SERVERS_ROOT}/settings/backends`,
  /** Settings -> Mode pools. */
  pools: () => `${SERVERS_ROOT}/settings/mode-pools`,
  /** One node of a backend (`test` opens the edges panel's test card for that address). */
  node: (uuid: string, opts: { backend?: string; test?: string } = {}) => {
    const path = withBackend(`${SERVERS_ROOT}/nodes/${encodeURIComponent(uuid)}`, opts.backend);
    if (!opts.test) return path;
    return `${path}${path.includes('?') ? '&' : '?'}test=${encodeURIComponent(opts.test)}`;
  },
};

/** The tabs of the Servers tab bar, in order. */
export const SERVERS_TABS = [
  'overview',
  'nodes',
  'countries',
  'snis',
  'probes',
  'providers',
  'settings',
] as const;
export type ServersTab = (typeof SERVERS_TABS)[number];

/** The section's own pages (everything else under the root is an Edges page). */
export type ServersRoute =
  | { page: 'nodes' }
  | { page: 'backends' }
  | { page: 'pools' }
  | { page: 'node'; uuid: string }
  | { page: 'not-found' };

export function resolveServersRoute(pathname: string): ServersRoute {
  if (matchRoute(`${SERVERS_ROOT}/nodes`, pathname)) return { page: 'nodes' };
  if (matchRoute(`${SERVERS_ROOT}/settings/backends`, pathname)) return { page: 'backends' };
  if (matchRoute(`${SERVERS_ROOT}/settings/mode-pools`, pathname)) return { page: 'pools' };
  const m = matchRoute(`${SERVERS_ROOT}/nodes/:uuid`, pathname);
  if (m) return { page: 'node', uuid: m.params.uuid ?? '' };
  return { page: 'not-found' };
}

/** Any page of the section: one of its own, or one that came from Edges. */
export type SectionRoute =
  { from: 'servers'; route: ServersRoute } | { from: 'edges'; route: EdgesRoute };

export function resolveSectionRoute(pathname: string): SectionRoute {
  const own = resolveServersRoute(pathname);
  if (own.page !== 'not-found') return { from: 'servers', route: own };
  return { from: 'edges', route: resolveEdgesRoute(pathname) };
}

/** The tab a page lights up. */
export function tabOf(r: SectionRoute): ServersTab {
  if (r.from === 'servers') {
    if (r.route.page === 'backends' || r.route.page === 'pools') return 'settings';
    return 'nodes';
  }
  switch (r.route.page) {
    case 'node':
    case 'relay':
      return 'nodes';
    case 'countries':
    case 'country':
    case 'lists':
    case 'list':
      return 'countries';
    case 'names':
    case 'family':
    case 'findNames':
    case 'findNetwork':
      return 'snis';
    case 'probes':
      return 'probes';
    case 'providers':
    case 'provider':
    case 'templates':
      return 'providers';
    case 'settings':
      return 'settings';
    default:
      return 'overview';
  }
}

/** The backend server a URL names (`?backend=`) when it is one of `instances`, else null (every backend). */
export function backendOf(search: string, instances: readonly { slug: string }[]): string | null {
  const wanted = new URLSearchParams(search).get('backend');
  return wanted && instances.some((i) => i.slug === wanted) ? wanted : null;
}

/** The backend server a URL selects (`?backend=`), else the first observable one, else the first. */
export function pickInstance(
  search: string,
  instances: readonly { slug: string; observable: boolean }[],
): string | null {
  const wanted = new URLSearchParams(search).get('backend');
  if (wanted && instances.some((i) => i.slug === wanted)) return wanted;
  return (instances.find((i) => i.observable) ?? instances[0])?.slug ?? null;
}

/** The slug of the backend server with this id (the Edges pages know a node by server id). */
export function instanceSlugOf(
  instances: readonly { id: string; slug: string }[] | undefined,
  backendServerId: string,
): string | null {
  return instances?.find((i) => i.id === backendServerId)?.slug ?? null;
}

/** An Edges origin, as far as finding its node goes (`RelayOrigin`). */
export type OriginRef =
  | { kind: 'panel-node'; backendServerId: string; nodeName: string; nodeUuid: string | null }
  | { kind: 'backend-server'; backendServerId: string }
  | { kind: 'manual' };

/**
 * The ONE page of the node behind an Edges origin: its Servers node page
 * (an origin's page, `/admin/servers/origins/<slug>`, redirects there).
 * Null when the origin is not a backend node, its backend server is not
 * known, or (an origin made before node uuids were recorded) its node is not
 * among `nodes` yet.
 */
export function nodeHomeOf(
  origin: OriginRef,
  instances: readonly { id: string; slug: string }[] | undefined,
  nodes?: readonly { nodeUuid: string; name: string }[],
  test?: string,
): string | null {
  if (origin.kind !== 'panel-node') return null;
  const instance = instanceSlugOf(instances, origin.backendServerId);
  if (!instance) return null;
  const uuid = origin.nodeUuid ?? nodes?.find((n) => n.name === origin.nodeName)?.nodeUuid ?? null;
  return uuid ? serversPaths.node(uuid, { backend: instance, test }) : null;
}
