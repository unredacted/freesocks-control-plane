/**
 * The Admin -> Edges route table (pure; unit-tested). The ONLY place the
 * section's paths are spelled: pages and shared components build links through
 * `edgesPaths`, the router resolves a pathname through `resolveEdgesRoute`.
 *
 * The section has two faces. The simple screens (`simple/`): the home at
 * `/admin/edges` (nodes), Providers and the Advanced index. A backend node's
 * page is its Servers node page (`/admin/edges/nodes/<slug>` redirects there;
 * an origin that is not a backend node keeps its edges panel at that
 * address). The technical pages live under Advanced: All origins at
 * `/admin/edges/advanced/origins`, an origin's details at
 * `/admin/edges/relays/<slug>`, and the rest at their old addresses.
 *
 * Panel nodes are set up with Autopilot only (the protect sheet); a manual or
 * whole-server origin is created from All origins (`?new=1`) and gets its
 * first edge on its own page. Moved addresses resolve to `redirect`:
 * `/admin/edges/setup[?relay=<slug>]` (the old step-by-step wizard) and
 * `/admin/edges/advanced/relays` (All origins' old address).
 *
 * Exports:
 *   EDGES_ROUTES                     pattern -> page id, in match order
 *   resolveEdgesRoute(pathname)      -> EdgesRoute (page 'not-found' when nothing matches)
 *   legacyEdgesRedirect(path, search)  the new address of a moved page, or null
 *   edgesPaths                       link builders (slug / id URL-encoded, optional search params)
 *   setupStepTarget(step, slug)      where a readiness step is done now
 *   sectionTabOf(route)              which in-page header link the route lights up
 *   RELAY_TABS / RelayTab            the `?tab` values of the origin page
 */
import { matchRoute } from '../../../../lib/matchRoute';
import type { SetupStepId } from '../../../../../shared/contracts/edgeCodes';

export const RELAY_TABS = ['overview', 'edges', 'listeners', 'rotations', 'probes'] as const;
export type RelayTab = (typeof RELAY_TABS)[number];

export type EdgesRoute =
  | { page: 'home' }
  | { page: 'node'; slug: string }
  | { page: 'advanced' }
  | { page: 'overview' }
  | { page: 'relay'; slug: string }
  | { page: 'providers' }
  | { page: 'provider'; id: string }
  | { page: 'templates' }
  | { page: 'probes' }
  | { page: 'settings' }
  | { page: 'names' }
  | { page: 'family'; slug: string }
  | { page: 'not-found' };

export const EDGES_ROUTES = [
  ['/admin/edges', 'home'],
  ['/admin/edges/nodes/:slug', 'node'],
  ['/admin/edges/advanced', 'advanced'],
  ['/admin/edges/advanced/origins', 'overview'],
  ['/admin/edges/relays/:slug', 'relay'],
  ['/admin/edges/providers', 'providers'],
  ['/admin/edges/providers/:id', 'provider'],
  ['/admin/edges/templates', 'templates'],
  ['/admin/edges/probes', 'probes'],
  ['/admin/edges/settings', 'settings'],
  ['/admin/edges/names', 'names'],
  ['/admin/edges/names/:slug', 'family'],
] as const;

export function resolveEdgesRoute(pathname: string): EdgesRoute {
  for (const [pattern, page] of EDGES_ROUTES) {
    const m = matchRoute(pattern, pathname);
    if (!m) continue;
    if (page === 'relay' || page === 'node' || page === 'family')
      return { page, slug: m.params.slug ?? '' };
    if (page === 'provider') return { page, id: m.params.id ?? '' };
    return { page };
  }
  return { page: 'not-found' };
}

/**
 * Pages that moved inside the section, and where they live now. The old
 * step-by-step wizard (`/admin/edges/setup`) is gone: with `?relay=<slug>` it
 * lands on that origin's page, otherwise on All origins.
 */
export function legacyEdgesRedirect(pathname: string, search = ''): string | null {
  const path = pathname.replace(/\/+$/, '') || '/';
  const params = new URLSearchParams(search);
  if (path === '/admin/edges/advanced/relays') return `/admin/edges/advanced/origins${search}`;
  if (path === '/admin/edges/setup') {
    const relay = params.get('relay');
    return relay ? edgesPaths.relay(relay) : edgesPaths.overview();
  }
  return null;
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
  /**
   * The section root: the nodes list (`?protect=1` opens the Protect-a-node sheet,
   * `?run=<id>` its progress). With `protect`, `server` (a backend's slug or id) and
   * `node` (its node uuid) preselect the node, as the Servers page links to it.
   */
  home: (params?: {
    protect?: string | null;
    run?: string | null;
    server?: string | null;
    node?: string | null;
  }) => withSearch('/admin/edges', params),
  /** The simple per-node page (`?test=<edgeId>` opens the test card for that address). */
  node: (slug: string, params?: { test?: string | null }) =>
    withSearch(`/admin/edges/nodes/${enc(slug)}`, params),
  advanced: () => '/admin/edges/advanced',
  /** All origins (the technical fleet dashboard), under Advanced; `?new=1` opens "New origin". */
  overview: (params?: { filter?: string; layer?: string; new?: string | null }) =>
    withSearch('/admin/edges/advanced/origins', params),
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
  /** Server-name families (under Advanced). */
  names: () => '/admin/edges/names',
  family: (slug: string) => `/admin/edges/names/${enc(slug)}`,
};

/**
 * Where a readiness step (`setup-status`) is done now that the step-by-step
 * wizard is gone: the origin's own page (its tabs), Providers, Templates or a
 * Settings section. Without an origin, the origin steps open "New origin".
 */
export function setupStepTarget(step: SetupStepId, slug: string | null): string {
  switch (step) {
    case 'origin':
      return slug ? edgesPaths.relay(slug) : edgesPaths.overview({ new: '1' });
    case 'relay':
      return slug
        ? edgesPaths.relay(slug, { tab: 'listeners' })
        : edgesPaths.overview({ new: '1' });
    case 'account':
      return edgesPaths.providers();
    case 'template':
      return edgesPaths.templates();
    case 'edge':
    case 'qualification':
    case 'publish':
      return slug ? edgesPaths.relay(slug, { tab: 'edges' }) : edgesPaths.overview();
    case 'rendering':
      return edgesPaths.settings({ section: 'rendering' });
    case 'automation':
      return edgesPaths.settings({ section: 'rotation' });
  }
}
