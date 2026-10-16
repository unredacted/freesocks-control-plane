/**
 * Admin -> Servers paths (pure; unit-tested). The only place the section's
 * paths are spelled. The section is ONE sidebar leaf with three tabs:
 *
 *   /admin/servers/backends                       Backends: the backend servers FCP issues keys on
 *   /admin/servers[?instance=<slug>]              Nodes: the nodes of one instance (the default tab)
 *   /admin/servers/pools                          Mode pools: which mode groups each connection mode issues into
 *   /admin/servers/nodes/:uuid[?instance=<slug>][&test=<edgeId>]
 *                                                 one node: its machine, activation and edges
 *
 * Old addresses keep working: `legacyServersRedirect` maps them here.
 */
import { matchRoute } from '../../../../lib/matchRoute';

export const SERVERS_ROOT = '/admin/servers';

const withInstance = (path: string, instance?: string) =>
  instance ? `${path}?instance=${encodeURIComponent(instance)}` : path;

export const serversPaths = {
  /** The Nodes tab; `instance` selects a backend server by slug. */
  home: (opts: { instance?: string } = {}) => withInstance(SERVERS_ROOT, opts.instance),
  /** The Backends tab. */
  backends: () => `${SERVERS_ROOT}/backends`,
  /** The Mode pools tab. */
  pools: () => `${SERVERS_ROOT}/pools`,
  /** One node of an instance (`test` opens the edges panel's test card for that address). */
  node: (uuid: string, opts: { instance?: string; test?: string } = {}) => {
    const path = withInstance(`${SERVERS_ROOT}/nodes/${encodeURIComponent(uuid)}`, opts.instance);
    if (!opts.test) return path;
    return `${path}${path.includes('?') ? '&' : '?'}test=${encodeURIComponent(opts.test)}`;
  },
};

export type ServersTab = 'backends' | 'nodes' | 'pools';

export type ServersRoute =
  | { page: 'home' }
  | { page: 'backends' }
  | { page: 'pools' }
  | { page: 'node'; uuid: string }
  | { page: 'not-found' };

export function resolveServersRoute(pathname: string): ServersRoute {
  if (matchRoute(SERVERS_ROOT, pathname)) return { page: 'home' };
  if (matchRoute(`${SERVERS_ROOT}/backends`, pathname)) return { page: 'backends' };
  if (matchRoute(`${SERVERS_ROOT}/pools`, pathname)) return { page: 'pools' };
  const m = matchRoute(`${SERVERS_ROOT}/nodes/:uuid`, pathname);
  if (m) return { page: 'node', uuid: m.params.uuid ?? '' };
  return { page: 'not-found' };
}

/** The tab a route lights up (a node page belongs to Nodes). */
export function serversTabOf(route: ServersRoute): ServersTab {
  if (route.page === 'backends') return 'backends';
  if (route.page === 'pools') return 'pools';
  return 'nodes';
}

/**
 * The pages the Servers leaf absorbed, and where they live now (the search
 * string is kept). Null = not a moved address.
 */
export function legacyServersRedirect(pathname: string, search = ''): string | null {
  const path = pathname.replace(/\/+$/, '') || '/';
  if (path === '/admin/backend-servers') return `${serversPaths.backends()}${search}`;
  if (path === '/admin/remnawave') return `${serversPaths.pools()}${search}`;
  return null;
}

/** The instance a URL selects, else the first observable one, else the first. */
export function pickInstance(
  search: string,
  instances: readonly { slug: string; observable: boolean }[],
): string | null {
  const wanted = new URLSearchParams(search).get('instance');
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
 * (`/admin/edges/nodes/<slug>` redirects there, the Edges rows link there).
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
  return uuid ? serversPaths.node(uuid, { instance, test }) : null;
}
