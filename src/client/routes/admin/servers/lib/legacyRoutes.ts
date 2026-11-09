/**
 * Every moved Servers address and where it lives now (pure; unit-tested in
 * legacyRoutes.test.ts, one test per rule). AdminRouter replaces a moved
 * address with its new one before anything renders. The search string is kept
 * unless a rule says otherwise. Nothing on the server builds these addresses,
 * so this is the whole move.
 *
 *   /admin/servers?instance=X              -> /admin/servers/nodes?backend=X (the root is Overview now)
 *   /admin/servers/nodes/:uuid?instance=X  -> the same page, ?backend=X
 *   /admin/servers/backends, /admin/backend-servers -> /admin/servers/settings/backends
 *   /admin/servers/pools, /admin/remnawave          -> /admin/servers/settings/mode-pools
 *   /admin/telemetry/probes                -> /admin/servers/probes
 *   /admin/servers/origins (All origins)   -> /admin/servers/nodes?columns=technical (`originsToNodesSearch`:
 *                                             ?filter= -> ?show=, ?layer= kept, ?new=1 -> ?add=origin)
 *   /admin/edges                           -> /admin/servers/nodes?show=fronted (the old Edges home listed the fronted nodes);
 *                                             ?protect=1[&server=&node=] -> /admin/servers/nodes?front=1[&backend=&node=],
 *                                             ?run=ID -> /admin/servers/nodes?run=ID
 *   /admin/edges/nodes/:slug               -> /admin/servers/origins/:slug
 *   /admin/edges/advanced                  -> /admin/servers
 *   /admin/edges/advanced/origins, /admin/edges/advanced/relays -> as /admin/servers/origins
 *   /admin/edges/setup[?relay=S]           -> S's details, else as /admin/servers/origins
 *   /admin/edges/relays/:slug              -> /admin/servers/origins/:slug/details
 *   /admin/edges/providers[/:id]           -> /admin/servers/providers[/:id]
 *   /admin/edges/templates                 -> /admin/servers/providers/templates
 *   /admin/edges/probes                    -> /admin/servers/probes
 *   /admin/edges/settings                  -> /admin/servers/settings
 *   /admin/edges/names[/:slug]             -> /admin/servers/snis[/:slug]
 *   /admin/edges/find-names[/:slug]        -> /admin/servers/snis/find[/:slug]
 *   /admin/edges/countries[/...]           -> /admin/servers/countries[/...]
 */
import { edgesPaths, originsToNodesSearch } from '../../edges/lib/routes';
import { serversPaths } from './routes';

/** `search` with `from` renamed to `to` (other params kept, in order). */
function renameParam(search: string, from: string, to: string): string {
  const params = new URLSearchParams(search);
  if (!params.has(from)) return search;
  const out = new URLSearchParams();
  for (const [k, v] of params) out.append(k === from ? to : k, v);
  const s = out.toString();
  return s ? `?${s}` : '';
}

/**
 * The old Edges home listed the fronted nodes and held the protect sheet: the
 * Nodes tab does both now. `?protect=1` opens the sheet there (`server` becomes
 * `backend`, `node` stays), `?run=` a run's progress; plain, the fronted nodes.
 */
function edgesHomeRedirect(search: string): string {
  const params = new URLSearchParams(search);
  const run = params.get('run');
  if (run) return serversPaths.nodes({ run });
  if (params.get('protect') === '1')
    return serversPaths.nodes({
      front: '1',
      backend: params.get('server') ?? undefined,
      node: params.get('node') ?? undefined,
    });
  return serversPaths.nodes({ show: 'fronted' });
}

/** Old Edges prefixes that only changed their prefix: old -> new, most specific first. */
const PREFIXES: ReadonlyArray<readonly [string, string]> = [
  ['/admin/edges/find-names', '/admin/servers/snis/find'],
  ['/admin/edges/names', '/admin/servers/snis'],
  ['/admin/edges/countries', '/admin/servers/countries'],
  ['/admin/edges/providers', '/admin/servers/providers'],
  ['/admin/edges/nodes', '/admin/servers/origins'],
];

/** The new address of a moved page, or null when `pathname` did not move. */
export function legacyRedirect(pathname: string, search = ''): string | null {
  const path = pathname.replace(/\/+$/, '') || '/';

  // The Servers section's own moves.
  if (path === '/admin/servers' && new URLSearchParams(search).has('instance'))
    return `${serversPaths.nodes()}${renameParam(search, 'instance', 'backend')}`;
  if (/^\/admin\/servers\/nodes\/[^/]+$/.test(path) && new URLSearchParams(search).has('instance'))
    return `${path}${renameParam(search, 'instance', 'backend')}`;
  if (path === '/admin/servers/backends' || path === '/admin/backend-servers')
    return `${serversPaths.backends()}${search}`;
  if (path === '/admin/servers/pools' || path === '/admin/remnawave')
    return `${serversPaths.pools()}${search}`;
  if (path === '/admin/telemetry/probes') return `${edgesPaths.probes()}${search}`;
  // All origins is the Nodes table with its technical columns now.
  if (path === '/admin/servers/origins')
    return `${serversPaths.nodes()}${originsToNodesSearch(search)}`;

  // The old Edges section, page by page.
  if (path !== '/admin/edges' && !path.startsWith('/admin/edges/')) return null;
  if (path === '/admin/edges') return edgesHomeRedirect(search);
  if (path === '/admin/edges/advanced') return `${edgesPaths.home()}${search}`;
  if (path === '/admin/edges/advanced/origins' || path === '/admin/edges/advanced/relays')
    return `${serversPaths.nodes()}${originsToNodesSearch(search)}`;
  if (path === '/admin/edges/setup') {
    const relay = new URLSearchParams(search).get('relay');
    return relay ? edgesPaths.relay(relay) : edgesPaths.overview();
  }
  const relay = /^\/admin\/edges\/relays\/([^/]+)$/.exec(path);
  if (relay) return `/admin/servers/origins/${relay[1]}/details${search}`;
  if (path === '/admin/edges/templates') return `${edgesPaths.templates()}${search}`;
  if (path === '/admin/edges/probes') return `${edgesPaths.probes()}${search}`;
  if (path === '/admin/edges/settings') return `${edgesPaths.settings()}${search}`;
  for (const [from, to] of PREFIXES) {
    if (path === from || path.startsWith(`${from}/`))
      return `${to}${path.slice(from.length)}${search}`;
  }
  return null;
}
