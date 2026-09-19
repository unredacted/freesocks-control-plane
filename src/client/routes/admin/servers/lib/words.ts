/**
 * Plain-words logic for Admin -> Servers (pure; unit-tested): one dot and one
 * sentence per node, a one-line summary per inbound, the instance headline and
 * the things an operator should notice. No em-dashes, no API paths, no bare
 * code words: copy only.
 */
import type {
  PanelInboundView,
  PanelNodeView,
  ServerObserveState,
  ServerTree,
} from '../../../../../shared/contracts/servers';

export type Dot = 'green' | 'amber' | 'red' | 'grey';

export interface NodeWords {
  dot: Dot;
  sentence: string;
}

export function nodeWords(
  n: Pick<PanelNodeView, 'online' | 'isDisabled' | 'profile' | 'inbounds' | 'usersOnline'>,
): NodeWords {
  if (n.isDisabled) return { dot: 'grey', sentence: 'Turned off in the panel.' };
  if (!n.profile)
    return { dot: 'amber', sentence: 'No config profile is assigned, so it serves nothing.' };
  if (n.inbounds.length === 0)
    return { dot: 'amber', sentence: 'A profile is assigned but no inbound is switched on.' };
  if (!n.online) return { dot: 'red', sentence: 'The panel cannot reach this node.' };
  const people = n.usersOnline === 1 ? '1 person' : `${n.usersOnline} people`;
  return { dot: 'green', sentence: `Online, ${people} connected.` };
}

const SECURITY_WORDS: Record<string, string> = { reality: 'REALITY', tls: 'TLS', none: 'no TLS' };

/** `VLESS over TCP, REALITY, port 443`. */
export function inboundSummary(
  i: Pick<PanelInboundView, 'protocol' | 'network' | 'security' | 'port'>,
): string {
  const transport = i.network === 'raw' ? 'TCP' : i.network.toUpperCase();
  const security = SECURITY_WORDS[i.security] ?? i.security;
  const port = i.port === null ? 'several ports' : `port ${i.port}`;
  return `${i.protocol.toUpperCase()} over ${transport}, ${security}, ${port}`;
}

/** `3 server names` / `1 server name` / null when the inbound presents none. */
export function serverNamesLabel(i: Pick<PanelInboundView, 'serverNames'>): string | null {
  if (!i.serverNames) return null;
  const n = i.serverNames.length;
  if (n === 0) return 'No server names';
  return n === 1 ? '1 server name' : `${n} server names`;
}

/** How fresh the picture is, in the words of someone reading the page. */
export function observedWords(s: ServerObserveState, observeOn: boolean, now: number): string {
  if (s.ok === null)
    return observeOn
      ? 'Not read yet. It is read every ten minutes, or press Refresh.'
      : 'Not read yet. Press Refresh to read it once, or turn on regular reading below.';
  const when = s.observedAt ? ago(now - Date.parse(s.observedAt)) : null;
  if (!s.ok)
    return when
      ? `The last read failed. Showing what was read ${when}.`
      : 'The panel could not be read. Check the address and the API token of this server.';
  return `Read ${when ?? 'just now'}.`;
}

export function ago(ms: number): string {
  const min = Math.round(ms / 60_000);
  if (min < 1) return 'just now';
  if (min < 60) return min === 1 ? '1 minute ago' : `${min} minutes ago`;
  const h = Math.round(min / 60);
  if (h < 48) return h === 1 ? '1 hour ago' : `${h} hours ago`;
  const d = Math.round(h / 24);
  return `${d} days ago`;
}

export interface Notice {
  tone: 'warn' | 'info';
  text: string;
}

/** What is worth a second look on this instance. Empty when nothing is. */
export function notices(tree: Pick<ServerTree, 'nodes' | 'unattached'>): Notice[] {
  const out: Notice[] = [];
  for (const n of tree.nodes)
    for (const i of n.inbounds) {
      if (i.realityPublicKeyMismatch)
        out.push({
          tone: 'warn',
          text: `On ${n.name}, the public key stored for ${i.tag} does not match its private key. People who were given the stored key cannot connect.`,
        });
      if (i.hosts.length === 0)
        out.push({
          tone: 'info',
          text: `On ${n.name}, ${i.tag} has no Host, so nobody is given an address for it.`,
        });
      if (i.squads.length === 0)
        out.push({
          tone: 'info',
          text: `On ${n.name}, ${i.tag} is in no squad, so no key can use it.`,
        });
    }
  if (tree.unattached.hosts.length > 0)
    out.push({
      tone: 'warn',
      text: `${list(tree.unattached.hosts)} ${tree.unattached.hosts.length === 1 ? 'points' : 'point'} at an inbound no node serves. People given ${tree.unattached.hosts.length === 1 ? 'it' : 'them'} cannot connect.`,
    });
  if (tree.unattached.profiles.length > 0)
    out.push({
      tone: 'info',
      text: `No node runs ${list(tree.unattached.profiles)}.`,
    });
  return out;
}

function list(names: readonly string[]): string {
  if (names.length <= 3) return names.join(', ');
  return `${names.slice(0, 3).join(', ')} and ${names.length - 3} more`;
}

/** One line for a toast when a server call failed, from its error code. */
const ERROR_WORDS: Record<string, string> = {
  'backend.panel_read_failed':
    'The panel could not be read. Check the address and the API token of this server.',
  'servers.unsupported_backend': 'This kind of server has nothing to show here.',
  'rate_limit.exceeded': 'That was a lot of refreshing. Wait a minute and try again.',
  not_found: 'That server no longer exists.',
};
export function serverErrorWords(code: string | null | undefined): string {
  return (code && ERROR_WORDS[code]) || 'That did not work. Try again in a moment.';
}
