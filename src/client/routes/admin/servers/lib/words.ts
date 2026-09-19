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

/** The country under a node name; the panel's `XX` placeholder is nothing. */
export function countryLabel(code: string | null | undefined): string | null {
  if (!code || code.toUpperCase() === 'XX') return null;
  try {
    return new Intl.DisplayNames(['en'], { type: 'region' }).of(code.toUpperCase()) ?? code;
  } catch {
    return code;
  }
}

/** The instance in one sentence: how many nodes are up, and how many people are on them. */
export function fleetSentence(
  nodes: readonly Pick<PanelNodeView, 'online' | 'isDisabled' | 'usersOnline'>[],
): {
  dot: Dot;
  text: string;
} {
  if (nodes.length === 0) return { dot: 'grey', text: 'No nodes on this panel yet.' };
  const on = nodes.filter((n) => !n.isDisabled);
  const online = on.filter((n) => n.online);
  const people = online.reduce((a, n) => a + n.usersOnline, 0);
  const who = people === 1 ? '1 person connected' : `${people} people connected`;
  if (online.length === on.length && on.length > 0)
    return {
      dot: 'green',
      text: `${on.length === 1 ? 'The node is' : `All ${on.length} nodes are`} online, ${who}.`,
    };
  if (online.length === 0) return { dot: 'red', text: 'No node is reachable from the panel.' };
  return {
    dot: 'amber',
    text: `${online.length} of ${on.length} nodes online, ${who}. The panel cannot reach the ${on.length - online.length === 1 ? 'other one' : 'others'}.`,
  };
}

export interface AttentionRow {
  /** Stable key for lists. */
  key: string;
  text: string;
  /** Where the row leads; absent = the text is the whole point. */
  nodeUuid?: string;
}

/**
 * What needs an operator, in one line each: a stored key that does not match,
 * addresses pointing at nothing, a profile edited elsewhere. Everything else is
 * a quiet note (`quietNotes`), not a call to action.
 */
export function needsYou(
  tree: Pick<ServerTree, 'nodes' | 'unattached' | 'profiles'>,
): AttentionRow[] {
  const out: AttentionRow[] = [];
  for (const n of tree.nodes)
    for (const i of n.inbounds)
      if (i.realityPublicKeyMismatch)
        out.push({
          key: `key:${n.nodeUuid}:${i.tag}`,
          text: `The public key stored for ${i.tag} on ${n.name} is not the one its private key makes. People given the stored key cannot connect.`,
          nodeUuid: n.nodeUuid,
        });
  for (const p of tree.profiles)
    if (p.foreignEditAt)
      out.push({
        key: `edit:${p.profileUuid}`,
        text: `${p.name} was changed on the panel, not from here. What this page shows of it may be out of date.`,
      });
  if (tree.unattached.hosts.length > 0)
    out.push({
      key: 'unattached-hosts',
      text: `${list(tree.unattached.hosts)} ${tree.unattached.hosts.length === 1 ? 'points' : 'point'} at an inbound no node serves. People given ${tree.unattached.hosts.length === 1 ? 'it' : 'them'} cannot connect.`,
    });
  return out;
}

/**
 * Leftovers worth knowing, grouped so one unused inbound on three nodes is one
 * line, not six. Nothing here is broken.
 */
export function quietNotes(tree: Pick<ServerTree, 'nodes' | 'unattached'>): string[] {
  const out: string[] = [];
  // tag -> the nodes on which it has nobody to serve (no address, or no squad).
  const unused = new Map<string, { nodes: string[]; noHost: boolean; noSquad: boolean }>();
  for (const n of tree.nodes)
    for (const i of n.inbounds) {
      const noHost = i.hosts.length === 0;
      const noSquad = i.squads.length === 0;
      if (!noHost && !noSquad) continue;
      const at = unused.get(i.tag) ?? { nodes: [], noHost: false, noSquad: false };
      at.nodes.push(n.name);
      at.noHost ||= noHost;
      at.noSquad ||= noSquad;
      unused.set(i.tag, at);
    }
  for (const [tag, u] of unused) {
    const why =
      u.noHost && u.noSquad
        ? 'no address and no squad'
        : u.noHost
          ? 'no address for members'
          : 'in no squad';
    const where =
      u.nodes.length === tree.nodes.length && tree.nodes.length > 1
        ? 'every node'
        : u.nodes.length === 1
          ? u.nodes[0]!
          : `${u.nodes.length} nodes`;
    out.push(`${tag} is unused on ${where}: ${why}.`);
  }
  if (tree.unattached.profiles.length > 0)
    out.push(`No node runs ${list(tree.unattached.profiles)}.`);
  return out;
}

/** The notes of one node only, for its page. */
export function nodeNotes(n: Pick<PanelNodeView, 'inbounds'>): string[] {
  const out: string[] = [];
  for (const i of n.inbounds) {
    if (i.hosts.length === 0 && i.squads.length === 0)
      out.push(`${i.tag} has no address for members and is in no squad.`);
    else if (i.hosts.length === 0) out.push(`${i.tag} has no address for members.`);
    else if (i.squads.length === 0) out.push(`${i.tag} is in no squad, so no key can use it.`);
  }
  return out;
}

function list(names: readonly string[]): string {
  if (names.length <= 3) return names.join(', ');
  return `${names.slice(0, 3).join(', ')} and ${names.length - 3} more`;
}

/** A profile was edited on the panel by something other than this page. */
export function foreignEditWords(name: string, agoWords: string): string {
  return `${name} was changed on the panel ${agoWords}, not from here. What this page shows of it may be out of date.`;
}

/** One line for a toast when a server call failed, from its error code. */
const ERROR_WORDS: Record<string, string> = {
  'backend.panel_read_failed':
    'The panel could not be read. Check the address and the API token of this server.',
  'servers.unsupported_backend': 'This kind of server has nothing to show here.',
  'rate_limit.exceeded': 'That was a lot at once. Wait a minute and try again.',
  not_found: 'That no longer exists. Refresh and look again.',
  validation: 'Something in the form is not valid. Check the fields and try again.',
  conflict: 'That is already settled. Refresh and look again.',
  // Before anything is sent.
  'servers.manage_disabled': 'Changing panels from here is turned off. Turn it on below first.',
  'servers.handoff_missing':
    'The node role has not handed this panel over yet. Run it with fcp_managed set, then try again.',
  'servers.op_running': 'Another change to this is still running. Wait for it to finish.',
  'servers.op_uncertain':
    'An earlier change to this has an unknown outcome. Settle it under Recent changes first.',
  'servers.relay_setup_running':
    'A relay setup is using this right now. Try again when it is done.',
  'servers.reservation_open':
    'The node role reserved this name and has not said how that ended. See Reserved by the node role.',
  'servers.tombstoned': 'This was removed on purpose. Tick "bring it back" to create it again.',
  'servers.exists': 'This already exists on the panel.',
  // Hosts and squads.
  'servers.host_edge_owned': 'This address belongs to a relay. Change it from Edges.',
  'servers.relay_remark': 'Names ending in -relay are kept for relays. Pick another name.',
  'servers.unknown_inbound': 'That inbound is not on this panel. Refresh and pick again.',
  'servers.duplicate_object':
    'The panel has more than one of these, so there is no telling which is meant. Remove the extra one on the panel.',
  'servers.squad_in_placement':
    'New keys are issued into this squad. Take it out of the connection mode first.',
  'servers.squad_has_members': 'This squad still has members. Move them first.',
  'servers.squad_name_taken': 'A squad with that name already exists.',
  // Nodes.
  'servers.node_name_taken': 'A node with that name already exists.',
  'servers.node_relay_origin':
    'A relay forwards to this node. Its address, port and inbounds are changed from Edges, and it is not turned off or removed here.',
  'servers.node_rename_referenced':
    'Relays or pinned members refer to this node by name, so it cannot be renamed yet.',
  'servers.node_still_on': 'Turn the node off first, and wait for that to finish.',
  'servers.node_off': 'This node is turned off.',
  'servers.already': 'It is already in that state.',
  // Profile edits.
  'servers.profile_changed':
    'The profile changed on the panel since the preview. Preview again before applying.',
  'servers.nothing_to_change': 'The panel already had exactly this, so nothing was sent.',
  'servers.name_in_use':
    'Members are still given one of the names being removed. Retire it on the relay first.',
  'servers.inbound_sni_managed':
    'A server name family manages the names of this inbound. Change them under Edges.',
  'servers.not_reality': 'That inbound does not use REALITY.',
  'servers.too_many_names': 'That is more server names than one inbound may carry.',
  'servers.profile_malformed': 'The profile on the panel is not in a shape this can edit safely.',
  'servers.inbound_uuid_changed':
    'The panel replaced an inbound while this was applied. Look at the panel before anything else.',
  // Settling.
  'servers.recovery_incomplete': 'Every condition has to hold before this can be released.',
  'servers.panel_refused': 'The panel refused it. Nothing was changed.',
  'servers.outcome_unknown':
    'The panel did not answer clearly, so it is not known whether this happened.',
};
export function serverErrorWords(code: string | null | undefined): string {
  return (code && ERROR_WORDS[code]) || 'That did not work. Try again in a moment.';
}
/** Every code with its own words (pinned by the tests against the server's vocabulary). */
export const WORDED_CODES: readonly string[] = Object.keys(ERROR_WORDS);

// --- one change to a panel, in words ------------------------------------------------------------

export interface OpLike {
  kind: 'host' | 'squad' | 'node' | 'profile';
  verb: string;
  label: string;
  state: 'working' | 'waiting_for_nodes' | 'done' | 'refused' | 'outcome_unknown' | 'recovered';
  errorCode: string | null;
}

const KIND: Record<OpLike['kind'], string> = {
  host: 'address',
  squad: 'squad',
  node: 'node',
  profile: 'config profile',
};
const VERB: Record<string, string> = {
  create: 'Add',
  update: 'Change',
  delete: 'Remove',
  reorder: 'Reorder',
  enable: 'Turn on',
  disable: 'Turn off',
  restart: 'Restart',
  patch: 'Edit',
};

/** "Restart node node-one". */
export function opTitle(op: OpLike): string {
  const verb = VERB[op.verb] ?? op.verb;
  if (op.verb === 'reorder') return 'Reorder addresses';
  return `${verb} ${KIND[op.kind]} ${op.label}`;
}

/** What state a change is in, and what (if anything) the operator should do. */
export function opWords(op: OpLike): { dot: Dot; sentence: string } {
  switch (op.state) {
    case 'working':
      return { dot: 'amber', sentence: 'Sent. Waiting to see it on the panel.' };
    case 'waiting_for_nodes':
      return {
        dot: 'amber',
        sentence: 'The panel has it. Waiting for the nodes to pick it up.',
      };
    case 'done':
      return op.errorCode === 'servers.adopted_existing'
        ? { dot: 'green', sentence: 'Done. It was already there, so nothing was created twice.' }
        : { dot: 'green', sentence: 'Done, and seen on the panel.' };
    case 'refused': {
      if (op.errorCode === 'servers.never_sent')
        return { dot: 'grey', sentence: 'Never sent. Nothing was changed.' };
      // Most refusals are FCP's own (the profile moved since the preview, the
      // panel already had it, two matches): say which, never "the panel refused".
      const reason = op.errorCode ? ERROR_WORDS[op.errorCode] : undefined;
      return { dot: 'grey', sentence: reason ?? 'The panel refused it. Nothing was changed.' };
    }
    case 'outcome_unknown':
      return {
        dot: 'red',
        sentence:
          'It is not known whether this happened. Nothing else can change this item until it is seen on the panel or settled by hand.',
      };
    case 'recovered':
      return { dot: 'grey', sentence: 'Settled by hand.' };
  }
}

/** One server name per line or comma; trimmed, blanks dropped, order kept, no repeats. */
export function parseNames(text: string): string[] {
  const out: string[] = [];
  for (const raw of text.split(/[\s,]+/)) {
    const name = raw.trim();
    if (name && !out.includes(name)) out.push(name);
  }
  return out;
}

/** "3 added, 1 removed" for a preview of server names. */
export function namesDelta(before: readonly string[], after: readonly string[]): string {
  const added = after.filter((n) => !before.includes(n)).length;
  const removed = before.filter((n) => !after.includes(n)).length;
  if (added === 0 && removed === 0) return 'Same names, new order';
  const parts: string[] = [];
  if (added) parts.push(`${added} added`);
  if (removed) parts.push(`${removed} removed`);
  return parts.join(', ');
}
