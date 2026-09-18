/**
 * Deep link into "Create API token" on the admin tokens page:
 *   /admin/tokens?new=1&scope=<scope>[&scope=<scope>...][&name=<name>][&servers=<id,id>][&nodes=<a,b>]
 * (`servers` / `nodes` preset the registration boundary of an `admin:edges:register` token.)
 * The page opens the create dialog with those scopes ticked and the name
 * filled in, then drops the params (replace) so a reload does not reopen it.
 * Scopes the dialog does not know are ignored. Nothing here is a secret: the
 * token itself is only ever shown by the dialog that mints it.
 *
 * Exports:
 *   NEW_TOKEN_PARAMS                      every param this link uses (for clearing)
 *   newTokenHref({ scope, name? })        -> string
 *   parseNewTokenParams(URLSearchParams)  -> { scopes, name } | null
 */
import { ApiScope } from '../../../shared/contracts/scopes';

export const TOKENS_PATH = '/admin/tokens';
export const NEW_TOKEN_PARAMS = ['new', 'scope', 'name', 'servers', 'nodes'] as const;
const NAME_MAX = 128;

export interface NewTokenPrefill {
  scopes: ApiScope[];
  name: string;
  /** Registration boundary presets (backend server ids, node names). */
  servers: string[];
  nodes: string[];
}

export function newTokenHref(opts: {
  scope: ApiScope | ApiScope[];
  name?: string;
  servers?: string[];
  nodes?: string[];
}): string {
  const params = new URLSearchParams({ new: '1' });
  for (const s of Array.isArray(opts.scope) ? opts.scope : [opts.scope]) params.append('scope', s);
  if (opts.name) params.set('name', opts.name.slice(0, NAME_MAX));
  if (opts.servers?.length) params.set('servers', opts.servers.join(','));
  if (opts.nodes?.length) params.set('nodes', opts.nodes.join(','));
  return `${TOKENS_PATH}?${params.toString()}`;
}

export function parseNewTokenParams(params: URLSearchParams): NewTokenPrefill | null {
  if (params.get('new') !== '1') return null;
  const scopes: ApiScope[] = [];
  for (const raw of params.getAll('scope').flatMap((v) => v.split(','))) {
    const parsed = ApiScope.safeParse(raw.trim());
    if (parsed.success && !scopes.includes(parsed.data)) scopes.push(parsed.data);
  }
  const list = (key: string): string[] => [
    ...new Set(
      (params.get(key) ?? '')
        .split(',')
        .map((v) => v.trim())
        .filter((v) => v !== '' && v.length <= NAME_MAX),
    ),
  ];
  return {
    scopes,
    name: (params.get('name') ?? '').trim().slice(0, NAME_MAX),
    servers: list('servers'),
    nodes: list('nodes'),
  };
}
