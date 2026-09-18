/**
 * The Admin -> Edges route table (pure; unit-tested). The ONLY place the
 * section's paths are spelled: pages and shared components build links through
 * `edgesPaths`, the router resolves a pathname through `resolveEdgesRoute`.
 *
 * The section has two faces. The simple screens (`simple/`): the home at
 * `/admin/edges` (nodes), the per-node page, Providers and the Advanced index.
 * The technical pages keep their old addresses under Advanced (the old
 * dashboard moved to `/admin/edges/advanced/relays`; every other URL is unchanged).
 *
 * Exports:
 *   EDGES_ROUTES                     pattern -> page id, in match order
 *   resolveEdgesRoute(pathname)      -> EdgesRoute (page 'not-found' when nothing matches)
 *   edgesPaths                       link builders (slug / id URL-encoded, optional search params)
 *   sectionTabOf(route)              which in-page header link the route lights up
 *   RELAY_TABS / RelayTab            the `?tab` values of the relay page
 */
import { matchRoute } from '../../../../lib/matchRoute';

export const RELAY_TABS = ['overview', 'edges', 'listeners', 'rotations', 'probes'] as const;
export type RelayTab = (typeof RELAY_TABS)[number];

export type EdgesRoute =
  | { page: 'home' }
  | { page: 'node'; slug: string }
  | { page: 'advanced' }
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
  ['/admin/edges', 'home'],
  ['/admin/edges/nodes/:slug', 'node'],
  ['/admin/edges/advanced', 'advanced'],
  ['/admin/edges/advanced/relays', 'overview'],
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
    if (page === 'relay' || page === 'node') return { page, slug: m.params.slug ?? '' };
    if (page === 'provider') return { page, id: m.params.id ?? '' };
    return { page };
  }
  return { page: 'not-found' };
}

/** The in-page header: Nodes | Providers | Advanced. */
export type SectionTab = 'nodes' | 'providers' | 'advanced';
export function sectionTabOf(route: EdgesRoute): SectionTab {
  switch (route.page) {
    case 'home':
    case 'node':
    case 'not-found':
      return 'nodes';
    case 'providers':
    case 'provider':
      return 'providers';
    default:
      return 'advanced';
  }
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
  /** The section root: the nodes list (`?protect=1` opens the Protect-a-node sheet, `?run=<id>` its progress). */
  home: (params?: { protect?: string | null; run?: string | null }) =>
    withSearch('/admin/edges', params),
  /** The simple per-node page (`?test=<edgeId>` opens the test card for that address). */
  node: (slug: string, params?: { test?: string | null }) =>
    withSearch(`/admin/edges/nodes/${enc(slug)}`, params),
  advanced: () => '/admin/edges/advanced',
  /** The technical fleet dashboard (all relays), under Advanced. */
  overview: (params?: { filter?: string; layer?: string }) =>
    withSearch('/admin/edges/advanced/relays', params),
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
  providers: (params?: { edit?: string | null }) => withSearch('/admin/edges/providers', params),
  provider: (id: string, params?: { tab?: string; edit?: string }) =>
    withSearch(`/admin/edges/providers/${enc(id)}`, params),
  templates: (params?: { template?: string; provider?: string }) =>
    withSearch('/admin/edges/templates', params),
  probes: (params?: { target?: string; range?: string }) =>
    withSearch('/admin/edges/probes', params),
  settings: (params?: { section?: string }) => withSearch('/admin/edges/settings', params),
};
