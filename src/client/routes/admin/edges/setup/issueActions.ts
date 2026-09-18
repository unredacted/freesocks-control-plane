/**
 * For a guided-setup blocker or warning: where the operator fixes it when the
 * fix is NOT a button of the step itself (pure; unit-tested). The step bodies
 * carry the in-place actions (test again, seed defaults, provision, publish);
 * this maps the rest to a page of the admin console.
 *
 * Exports:
 *   backendServersHref(returnTo)      Admin -> Backend servers, with a `return` param
 *   TOKENS_PATH
 *   issueLink(code, ctx)              -> { label, href } | null
 */
import { edgesPaths } from '../lib/routes';

export const BACKEND_SERVERS_PATH = '/admin/backend-servers';
export const TOKENS_PATH = '/admin/tokens';

export function backendServersHref(returnTo: string): string {
  return `${BACKEND_SERVERS_PATH}?return=${encodeURIComponent(returnTo)}`;
}

export interface IssueLinkContext {
  relaySlug: string | null;
  accountId: string | null;
  /** The wizard's own URL, for pages that can send the operator back. */
  returnTo: string;
}

export interface IssueLink {
  label: string;
  href: string;
}

export function issueLink(code: string, ctx: IssueLinkContext): IssueLink | null {
  const bare = code.replace(/^edge\./, '');
  const relayTab = (tab: 'listeners' | 'edges' | 'overview'): string | null =>
    ctx.relaySlug ? edgesPaths.relay(ctx.relaySlug, { tab }) : null;
  switch (bare) {
    case 'no_backend_server':
    case 'backend_unreachable':
    case 'backend_no_host_management':
    case 'backend_no_node_inventory':
      return { label: 'Open Backend servers', href: backendServersHref(ctx.returnTo) };
    case 'credentials_untested':
    case 'credentials_failed':
    case 'dns_account_missing':
    case 'zone_mode_unknown':
    case 'zone_websockets_off':
    case 'account_budget_exhausted':
    case 'account_capacity_reached':
    case 'qualification_stale':
      return ctx.accountId
        ? { label: 'Open the account', href: edgesPaths.provider(ctx.accountId) }
        : { label: 'Open Providers', href: edgesPaths.providers() };
    case 'no_compatible_account':
      return { label: 'Open Providers', href: edgesPaths.providers() };
    case 'template_invalid':
    case 'no_default_template':
      return { label: 'Open Templates', href: edgesPaths.templates() };
    case 'listener_not_deployed':
    case 'listener_disabled':
    case 'needs_target':
    case 'needs_names':
    case 'invalid_combination':
    case 'no_udp_provider': {
      const href = relayTab('listeners');
      return href ? { label: 'Open the listeners', href } : null;
    }
    case 'quarantined':
    case 'relay_deleting':
    case 'relay_disabled':
    case 'mirrors_unvalidated': {
      const href = relayTab('overview');
      return href ? { label: 'Open the relay', href } : null;
    }
    case 'no_publishable_edge':
    case 'provision_failed': {
      const href = relayTab('edges');
      return href ? { label: 'Open the edges', href } : null;
    }
    case 'probe_sources_none':
    case 'probe_countries_none':
      return { label: 'Open probe settings', href: edgesPaths.settings({ section: 'probes' }) };
    default:
      return null;
  }
}
