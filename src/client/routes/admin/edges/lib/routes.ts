/**
 * The Admin -> Edges route table (pure; unit-tested). The ONLY place the
 * section's paths are spelled: pages and shared components build links through
 * `edgesPaths`, the router resolves a pathname through `resolveEdgesRoute`.
 *
 * Exports:
 *   EDGES_ROUTES                     pattern -> page id, in match order
 *   resolveEdgesRoute(pathname)      -> EdgesRoute (page 'not-found' when nothing matches)
 *   edgesPaths                       link builders (slug / id URL-encoded, optional search params)
 *   RELAY_TABS / RelayTab            the `?tab` values of the relay page
 */
import { matchRoute } from '../../../../lib/matchRoute';

export const RELAY_TABS = ['overview', 'edges', 'listeners', 'rotations', 'probes'] as const;
export type RelayTab = (typeof RELAY_TABS)[number];

export type EdgesRoute =
  | { page: 'overview' }
  | { page: 'setup' }
  | { page: 'relay'; slug: string }
  | { page: 'providers' }
  | { page: 'provider'; id: string }
  | { page: 'templates' }
  | { page: 'probes' }
  | { page: 'settings' }
  | { page: 'not-found' };

export const EDGES_ROUTES = [
  ['/admin/edges', 'overview'],
  ['/admin/edges/setup', 'setup'],
  ['/admin/edges/relays/:slug', 'relay'],
  ['/admin/edges/providers', 'providers'],
  ['/admin/edges/providers/:id', 'provider'],
  ['/admin/edges/templates', 'templates'],
  ['/admin/edges/probes', 'probes'],
  ['/admin/edges/settings', 'settings'],
] as const;

export function resolveEdgesRoute(pathname: string): EdgesRoute {
  for (const [pattern, page] of EDGES_ROUTES) {
    const m = matchRoute(pattern, pathname);
    if (!m) continue;
    if (page === 'relay') return { page, slug: m.params.slug ?? '' };
    if (page === 'provider') return { page, id: m.params.id ?? '' };
    return { page };
  }
  return { page: 'not-found' };
}

type Params = Record<string, string | null | undefined>;
function withSearch(path: string, params?: Params): string {
  if (!params) return path;
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== null && v !== undefined && v !== '') qs.set(k, v);
  }
  const s = qs.toString();
  return s ? `${path}?${s}` : path;
}

const enc = encodeURIComponent;
export const edgesPaths = {
  overview: (params?: { filter?: string; layer?: string }) => withSearch('/admin/edges', params),
  setup: (params?: { relay?: string | null; step?: string | null }) =>
    withSearch('/admin/edges/setup', params),
  relay: (
    slug: string,
    params?: {
      tab?: RelayTab;
      edge?: string | null;
      rotation?: string | null;
      listener?: string | null;
    },
  ) => withSearch(`/admin/edges/relays/${enc(slug)}`, params),
  providers: () => '/admin/edges/providers',
  provider: (id: string, params?: { tab?: string; edit?: string }) =>
    withSearch(`/admin/edges/providers/${enc(id)}`, params),
  templates: (params?: { template?: string; provider?: string }) =>
    withSearch('/admin/edges/templates', params),
  probes: (params?: { target?: string; range?: string }) =>
    withSearch('/admin/edges/probes', params),
  settings: (params?: { section?: string }) => withSearch('/admin/edges/settings', params),
};
