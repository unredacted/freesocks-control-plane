/**
 * The pages that came from the old Admin -> Edges section (pure; unit-tested).
 * They live under `/admin/servers` with the Servers section's own pages
 * (../../servers/lib/routes.ts) and share its tab bar. The ONLY place these
 * paths are spelled: pages and shared components build links through
 * `edgesPaths`, the section resolves a pathname through `resolveEdgesRoute`.
 *
 *   /admin/servers                                  Overview (today: the fronted nodes and what needs you)
 *   /admin/servers/origins                          All origins (Nodes, technical view); `?new=1` opens "New origin"
 *   /admin/servers/origins/:slug                    an origin: a backend node redirects to its node page,
 *                                                   any other origin shows its edges panel here
 *   /admin/servers/origins/:slug/details            an origin's technical details (`?tab=`)
 *   /admin/servers/countries[/:CC]                  Countries (`/:CC?section=` one section of a country)
 *   /admin/servers/countries/lists[/:id]            Countries -> Lists
 *   /admin/servers/snis                             SNIs: the SNI lists
 *   /admin/servers/snis/lists/:slug                 one SNI list (its own namespace, so no slug
 *                                                   can collide with Find more)
 *   /admin/servers/snis/find[/:slug]                SNIs -> Find more: every network, one network
 *   /admin/servers/probes                           Probes
 *   /admin/servers/providers[/:id]                  Providers, one account
 *   /admin/servers/providers/templates              Providers -> All templates
 *   /admin/servers/settings                         Settings (`?section=`)
 *
 * The old `/admin/edges/...` addresses redirect (../../servers/lib/legacyRoutes.ts).
 *
 * Exports:
 *   EDGES_ROUTES                     pattern -> page id, in match order
 *   resolveEdgesRoute(pathname)      -> EdgesRoute (page 'not-found' when nothing matches)
 *   edgesPaths                       link builders (slug / id URL-encoded, optional search params)
 *   setupStepTarget(step, slug)      where a readiness step is done now
 *   RELAY_TABS / RelayTab            the `?tab` values of an origin's details
 */
import { matchRoute } from '../../../../lib/matchRoute';
import type { SetupStepId } from '../../../../../shared/contracts/edgeCodes';

export const RELAY_TABS = ['overview', 'edges', 'listeners', 'rotations', 'probes'] as const;
export type RelayTab = (typeof RELAY_TABS)[number];

export type EdgesRoute =
  | { page: 'home' }
  | { page: 'node'; slug: string }
  | { page: 'overview' }
  | { page: 'relay'; slug: string }
  | { page: 'providers' }
  | { page: 'provider'; id: string }
  | { page: 'templates' }
  | { page: 'probes' }
  | { page: 'settings' }
  | { page: 'names' }
  | { page: 'family'; slug: string }
  | { page: 'findNames' }
  | { page: 'findNetwork'; slug: string }
  | { page: 'countries' }
  | { page: 'country'; code: string }
  | { page: 'lists' }
  | { page: 'list'; id: string }
  | { page: 'not-found' };

const R = '/admin/servers';

export const EDGES_ROUTES = [
  [R, 'home'],
  [`${R}/origins`, 'overview'],
  [`${R}/origins/:slug`, 'node'],
  [`${R}/origins/:slug/details`, 'relay'],
  [`${R}/providers`, 'providers'],
  // Before `:id`: "templates" is no account.
  [`${R}/providers/templates`, 'templates'],
  [`${R}/providers/:id`, 'provider'],
  [`${R}/probes`, 'probes'],
  [`${R}/settings`, 'settings'],
  [`${R}/snis`, 'names'],
  [`${R}/snis/lists/:slug`, 'family'],
  [`${R}/snis/find`, 'findNames'],
  [`${R}/snis/find/:slug`, 'findNetwork'],
  [`${R}/countries`, 'countries'],
  // Before `:code`: "lists" is no country.
  [`${R}/countries/lists`, 'lists'],
  [`${R}/countries/lists/:id`, 'list'],
  [`${R}/countries/:code`, 'country'],
] as const;

export function resolveEdgesRoute(pathname: string): EdgesRoute {
  for (const [pattern, page] of EDGES_ROUTES) {
    const m = matchRoute(pattern, pathname);
    if (!m) continue;
    if (page === 'relay' || page === 'node' || page === 'family' || page === 'findNetwork')
      return { page, slug: m.params.slug ?? '' };
    if (page === 'provider' || page === 'list') return { page, id: m.params.id ?? '' };
    if (page === 'country') {
      // An ISO 3166-1 alpha-2 code; anything else is not a country page.
      const code = (m.params.code ?? '').toUpperCase();
      return /^[A-Z]{2}$/.test(code) ? { page, code } : { page: 'not-found' };
    }
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
  /**
   * The Overview tab, the section root (`?protect=1` opens the Protect-a-node sheet,
   * `?run=<id>` its progress). With `protect`, `server` (a backend's slug or id) and
   * `node` (its node uuid) preselect the node, as the Servers page links to it.
   */
  home: (params?: {
    protect?: string | null;
    run?: string | null;
    server?: string | null;
    node?: string | null;
  }) => withSearch(R, params),
  /** An origin's page (`?test=<edgeId>` opens the test card for that address). */
  node: (slug: string, params?: { test?: string | null }) =>
    withSearch(`${R}/origins/${enc(slug)}`, params),
  /** All origins (the technical fleet dashboard, under Nodes); `?new=1` opens "New origin". */
  overview: (params?: { filter?: string; layer?: string; new?: string | null }) =>
    withSearch(`${R}/origins`, params),
  relay: (
    slug: string,
    params?: {
      tab?: RelayTab;
      edge?: string | null;
      rotation?: string | null;
      listener?: string | null;
    },
  ) => withSearch(`${R}/origins/${enc(slug)}/details`, params),
  /** `edit: 'new'` opens the add-account flow; `provider` preselects one in it. */
  providers: (params?: { edit?: string | null; provider?: string | null }) =>
    withSearch(`${R}/providers`, params),
  provider: (id: string, params?: { tab?: string }) =>
    withSearch(`${R}/providers/${enc(id)}`, params),
  /** All templates, under Providers. */
  templates: (params?: { template?: string; provider?: string }) =>
    withSearch(`${R}/providers/templates`, params),
  probes: (params?: { target?: string; range?: string }) => withSearch(`${R}/probes`, params),
  settings: (params?: { section?: string }) => withSearch(`${R}/settings`, params),
  /** SNI lists (the SNIs tab), and one list. */
  names: () => `${R}/snis`,
  family: (slug: string) => `${R}/snis/lists/${enc(slug)}`,
  /** Finding more SNIs: every network, and one network's candidates. */
  findNames: () => `${R}/snis/find`,
  findNetwork: (slug: string) => `${R}/snis/find/${enc(slug)}`,
  /**
   * The Countries tab: every censored country (with the list editor and the
   * Delivery card), and one country in full (`section` picks one of its
   * sections, ../countries/sections.ts; Summary when left out).
   */
  countries: () => `${R}/countries`,
  country: (code: string, params?: { section?: string | null }) =>
    withSearch(`${R}/countries/${enc(code.toUpperCase())}`, params),
  /** Country lists: every list FCP follows, and one list. */
  lists: () => `${R}/countries/lists`,
  list: (id: string) => `${R}/countries/lists/${enc(id)}`,
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
