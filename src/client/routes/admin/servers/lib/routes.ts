/**
 * Admin -> Servers paths (pure; unit-tested). The only place the section's
 * paths are spelled.
 *
 *   /admin/servers[?instance=<slug>]              the nodes of one instance
 *   /admin/servers/nodes/:uuid[?instance=<slug>]  one node
 */
import { matchRoute } from '../../../../lib/matchRoute';

export const SERVERS_ROOT = '/admin/servers';

const withInstance = (path: string, instance?: string) =>
  instance ? `${path}?instance=${encodeURIComponent(instance)}` : path;

export const serversPaths = {
  /** The nodes page; `instance` selects a backend server by slug. */
  home: (opts: { instance?: string } = {}) => withInstance(SERVERS_ROOT, opts.instance),
  /** One node of an instance. */
  node: (uuid: string, opts: { instance?: string } = {}) =>
    withInstance(`${SERVERS_ROOT}/nodes/${encodeURIComponent(uuid)}`, opts.instance),
};

export type ServersRoute =
  | { page: 'home' }
  | { page: 'node'; uuid: string }
  | { page: 'not-found' };

export function resolveServersRoute(pathname: string): ServersRoute {
  if (matchRoute(SERVERS_ROOT, pathname)) return { page: 'home' };
  const m = matchRoute(`${SERVERS_ROOT}/nodes/:uuid`, pathname);
  if (m) return { page: 'node', uuid: m.params.uuid ?? '' };
  return { page: 'not-found' };
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
