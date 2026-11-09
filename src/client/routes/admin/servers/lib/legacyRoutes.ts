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
 *   /admin/{edges,servers}/providers?edit=new -> /admin/servers/providers?add=1 (the add-account flow)
 *   /admin/edges/templates                 -> /admin/servers/providers/templates (with ?provider=P
 *                                             that page lands on P's first account, Templates tab)
 *   /admin/edges/probes                    -> /admin/servers/probes
 *   /admin/edges/settings                  -> /admin/servers/settings
 *   .../settings?section=S                 -> /admin/servers/settings?group=<S's group> (an unknown S is dropped)
 *   /admin/edges/names                     -> /admin/servers/snis
 *   /admin/edges/names/:slug               -> /admin/servers/snis/lists/:slug
 *   /admin/edges/find-names[/:slug]        -> /admin/servers/snis/find[/:slug]
 *   /admin/edges/countries[/...]           -> /admin/servers/countries[/...]
 */
import { edgesPaths, originsToNodesSearch } from '../../edges/lib/routes';
import { groupOfSection } from '../../edges/settings/groups';
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

/** The add-account flow was `?edit=new`; it is `?add=1` now (other params kept, in order). */
function editNewToAdd(search: string): string {
  const params = new URLSearchParams(search);
  if (params.get('edit') !== 'new') return search;
  const out = new URLSearchParams();
  for (const [k, v] of params) {
    if (k === 'edit') out.append('add', '1');
    else out.append(k, v);
  }
  return `?${out.toString()}`;
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

/**
 * `search` with the old Settings card (`section`) made the group that holds it
 * now (`group`, in its place). A `group` already there wins; an unknown card
 * is dropped, which shows every group.
 */
function sectionToGroup(search: string): string {
  const params = new URLSearchParams(search);
  const section = params.get('section');
  const group = groupOfSection(section);
  const out = new URLSearchParams();
  for (const [k, v] of params) {
    if (k !== 'section') out.append(k, v);
    else if (group && !params.has('group')) out.append('group', group);
  }
  const s = out.toString();
  return s ? `?${s}` : '';
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
  if (path === '/admin/servers/providers' && new URLSearchParams(search).get('edit') === 'new')
    return `${edgesPaths.providers()}${editNewToAdd(search)}`;
  // All origins is the Nodes table with its technical columns now.
  if (path === '/admin/servers/origins')
    return `${serversPaths.nodes()}${originsToNodesSearch(search)}`;
  if (path === '/admin/servers/settings' && new URLSearchParams(search).has('section'))
    return `${edgesPaths.settings()}${sectionToGroup(search)}`;

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
  if (path === '/admin/edges/providers') return `${edgesPaths.providers()}${editNewToAdd(search)}`;
  if (path === '/admin/edges/templates') return `${edgesPaths.templates()}${search}`;
  if (path === '/admin/edges/probes') return `${edgesPaths.probes()}${search}`;
  if (path === '/admin/edges/settings') return `${edgesPaths.settings()}${sectionToGroup(search)}`;
  // One SNI list: its own namespace now, so a list called "find" stays a list.
  const list = /^\/admin\/edges\/names\/([^/]+)$/.exec(path);
  if (list) return `/admin/servers/snis/lists/${list[1]}${search}`;
  for (const [from, to] of PREFIXES) {
    if (path === from || path.startsWith(`${from}/`))
      return `${to}${path.slice(from.length)}${search}`;
  }
  return null;
}
