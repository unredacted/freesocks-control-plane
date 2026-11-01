/**
 * Plain-words logic for Admin -> Servers (pure; unit-tested): one dot and one
 * sentence per node, a one-line summary per transport, the instance headline and
 * the things an operator should notice. No em-dashes, no API paths, no bare
 * code words: copy only.
 */
import type {
  AddressView,
  TransportView,
  NodeView,
  ServerTree,
} from '../../../../../shared/contracts/servers';

export type Dot = 'green' | 'amber' | 'red' | 'grey';

export interface NodeWords {
  dot: Dot;
  sentence: string;
}

export function nodeWords(
  n: Pick<NodeView, 'online' | 'isDisabled' | 'profile' | 'transports' | 'usersOnline'>,
  opts: { restarting?: boolean } = {},
): NodeWords {
  if (n.isDisabled) return { dot: 'grey', sentence: 'Turned off on the backend.' };
  if (!n.profile)
    return { dot: 'amber', sentence: 'No config profile is assigned, so it serves nothing.' };
  if (n.transports.length === 0)
    return { dot: 'amber', sentence: 'A profile is assigned but no transport is switched on.' };
  if (!n.online && opts.restarting)
    return { dot: 'amber', sentence: 'Restarting while a change is applied. Back in a moment.' };
  if (!n.online) return { dot: 'red', sentence: 'The backend cannot reach this node.' };
  const people = n.usersOnline === 1 ? '1 person' : `${n.usersOnline} people`;
  return { dot: 'green', sentence: `Online, ${people} connected.` };
}

const SECURITY_WORDS: Record<string, string> = { reality: 'REALITY', tls: 'TLS', none: 'no TLS' };

/** `VLESS over TCP, REALITY, port 443`. */
export function inboundSummary(
  i: Pick<TransportView, 'protocol' | 'network' | 'security' | 'port'>,
): string {
  const transport = i.network === 'raw' ? 'TCP' : i.network.toUpperCase();
  const security = SECURITY_WORDS[i.security] ?? i.security;
  const port = i.port === null ? 'several ports' : `port ${i.port}`;
  return `${i.protocol.toUpperCase()} over ${transport}, ${security}, ${port}`;
}

/** `3 server names` / `1 server name` / null when the transport presents none. */
export function serverNamesLabel(i: Pick<TransportView, 'serverNames'>): string | null {
  if (!i.serverNames) return null;
  const n = i.serverNames.length;
  if (n === 0) return 'No server names';
  return n === 1 ? '1 server name' : `${n} server names`;
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

/** The country under a node name; the backend's `XX` placeholder is nothing. */
export function countryLabel(code: string | null | undefined): string | null {
  if (!code || code.toUpperCase() === 'XX') return null;
  try {
    return new Intl.DisplayNames(['en'], { type: 'region' }).of(code.toUpperCase()) ?? code;
  } catch {
    return code;
  }
}

/**
 * The instance in one sentence: how many nodes are up, and how many people are
 * on them. `restarting(n)` says an offline node is down because a change is
 * being applied to it right now (a role run, a profile change the nodes pick
 * up): that is a moment, not an outage, and never turns the headline red.
 */
export function fleetSentence<N extends Pick<NodeView, 'online' | 'isDisabled' | 'usersOnline'>>(
  nodes: readonly N[],
  restarting: (n: N) => boolean = () => false,
): {
  dot: Dot;
  text: string;
} {
  if (nodes.length === 0) return { dot: 'grey', text: 'No nodes on this backend yet.' };
  const on = nodes.filter((n) => !n.isDisabled);
  const online = on.filter((n) => n.online);
  const people = online.reduce((a, n) => a + n.usersOnline, 0);
  const who = people === 1 ? '1 person connected' : `${people} people connected`;
  if (online.length === on.length && on.length > 0)
    return {
      dot: 'green',
      text: `${on.length === 1 ? 'The node is' : `All ${on.length} nodes are`} online, ${who}.`,
    };
  const offline = on.filter((n) => !n.online);
  const unreachable = offline.filter((n) => !restarting(n));
  if (unreachable.length === 0) {
    const back = offline.length === 1 ? '1 node is' : `${offline.length} nodes are`;
    return {
      dot: 'amber',
      text:
        online.length === 0
          ? `${back} restarting while a change is applied. Back in a moment.`
          : `${online.length} of ${on.length} nodes online, ${who}. ${back} restarting while a change is applied.`,
    };
  }
  const restartingCount = offline.length - unreachable.length;
  if (restartingCount === 0) {
    if (online.length === 0) return { dot: 'red', text: 'No node is reachable from the backend.' };
    return {
      dot: 'amber',
      text: `${online.length} of ${on.length} nodes online, ${who}. The backend cannot reach the ${offline.length === 1 ? 'other one' : 'others'}.`,
    };
  }
  return {
    dot: 'amber',
    text: `${online.length} of ${on.length} nodes online, ${who}. ${restartingCount} restarting while a change is applied, and the backend cannot reach ${unreachable.length === 1 ? '1 more' : `${unreachable.length} more`}.`,
  };
}

/** The nodes an open change is waiting on right now (the backend restarts them for it). */
export function nodesBeingChanged(
  ops: readonly { open: boolean; state: string; asyncNodeUuids: readonly string[] }[],
): Set<string> {
  return new Set(
    ops.filter((o) => o.open && o.state === 'waiting_for_nodes').flatMap((o) => o.asyncNodeUuids),
  );
}

/**
 * Whether the node an enrolled intent describes is being changed right now, so
 * an offline reading is its restart: the role reported in within the last
 * three minutes (a run starts with a report), the machine settings it was given
 * are not applied yet, a reconcile holds it, or its activation is running.
 */
export function intentRestarting(
  i: {
    state: string;
    machineRevision: number;
    appliedRevision: number | null;
    roleSeenAt: string | null;
    run: { state: string } | null;
  },
  now: number,
): boolean {
  if (i.state === 'pending') return true;
  if (i.appliedRevision !== null && i.appliedRevision < i.machineRevision) return true;
  if (i.run?.state === 'running') return true;
  return i.roleSeenAt !== null && now - Date.parse(i.roleSeenAt) < 3 * 60_000;
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
    for (const i of n.transports)
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
        text: `${p.name} was changed on the backend, not from here. What this page shows of it may be out of date.`,
      });
  if (tree.unattached.addresses.length > 0)
    out.push({
      key: 'unattached-addresses',
      text: `${list(tree.unattached.addresses)} ${tree.unattached.addresses.length === 1 ? 'points' : 'point'} at a transport no node serves. People given ${tree.unattached.addresses.length === 1 ? 'it' : 'them'} cannot connect.`,
    });
  return out;
}

/**
 * Leftovers worth knowing, grouped so one unused transport on three nodes is one
 * line, not six. Nothing here is broken.
 */
export function quietNotes(tree: Pick<ServerTree, 'nodes' | 'unattached'>): string[] {
  const out: string[] = [];
  // tag -> the nodes on which it has nobody to serve (no address, or no group).
  const unused = new Map<string, { nodes: string[]; noAddress: boolean; noGroup: boolean }>();
  for (const n of tree.nodes)
    for (const i of n.transports) {
      const noAddress = splitAddresses(i.addresses).members.length === 0;
      const noGroup = i.modeGroups.length === 0;
      if (!noAddress && !noGroup) continue;
      const at = unused.get(i.tag) ?? { nodes: [], noAddress: false, noGroup: false };
      at.nodes.push(n.name);
      at.noAddress ||= noAddress;
      at.noGroup ||= noGroup;
      unused.set(i.tag, at);
    }
  for (const [tag, u] of unused) {
    const why =
      u.noAddress && u.noGroup
        ? 'no address and no mode group'
        : u.noAddress
          ? 'no address for members'
          : 'in no mode group';
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
export function nodeNotes(n: Pick<NodeView, 'transports'>): string[] {
  const out: string[] = [];
  for (const i of n.transports) {
    const noAddress = splitAddresses(i.addresses).members.length === 0;
    if (noAddress && i.modeGroups.length === 0)
      out.push(`${i.tag} has no address for members and is in no mode group.`);
    else if (noAddress) out.push(`${i.tag} has no address for members.`);
    else if (i.modeGroups.length === 0)
      out.push(`${i.tag} is in no mode group, so no key can use it.`);
  }
  return out;
}

/**
 * A transport's addresses on one node: the ones members get, and the
 * operator's own fronts (a load balancer made by hand) that members no longer
 * get because the node is bound to its edges. Order is kept.
 */
export function splitAddresses<A extends Pick<AddressView, 'operatorFront'>>(
  addresses: readonly A[],
): { members: A[]; fronts: A[] } {
  return {
    members: addresses.filter((a) => !a.operatorFront),
    fronts: addresses.filter((a) => a.operatorFront),
  };
}

/** The line under a node's own fronts on its page (`splitAddresses`). */
export function frontsHint(count: number): string {
  return count === 1
    ? "Members get this node's edges instead. Once its traffic stops, delete this front at its provider, and its address here."
    : "Members get this node's edges instead. Once their traffic stops, delete these fronts at their provider, and their addresses here.";
}

function list(names: readonly string[]): string {
  if (names.length <= 3) return names.join(', ');
  return `${names.slice(0, 3).join(', ')} and ${names.length - 3} more`;
}

/** One line for a toast when a server call failed, from its error code. */
const ERROR_WORDS: Record<string, string> = {
  'backend.panel_read_failed':
    'The backend could not be read. Check the address and the API token of this server.',
  'servers.unsupported_backend': 'This kind of server has nothing to show here.',
  'rate_limit.exceeded': 'That was a lot at once. Wait a minute and try again.',
  not_found: 'That no longer exists. Refresh and look again.',
  validation: 'Something in the form is not valid. Check the fields and try again.',
  conflict: 'That is already settled. Refresh and look again.',
  // Before anything is sent.
  'servers.manage_disabled': 'Changing backends from here is turned off. Turn it on below first.',
  'servers.not_set_up': 'Set up this backend first. Until then nothing on it is changed from here.',
  'servers.op_running': 'Another change to this is still running. Wait for it to finish.',
  'servers.op_uncertain':
    'An earlier change to this has an unknown outcome. Settle it under Recent changes first.',
  'servers.relay_setup_running':
    'An origin setup is using this right now. Try again when it is done.',
  'servers.tombstoned': 'This was removed on purpose. Tick "bring it back" to create it again.',
  'servers.exists': 'This already exists on the backend.',
  // Addresses and mode groups.
  'servers.host_edge_owned': 'This address belongs to an origin. Change it from Edges.',
  'servers.relay_remark': 'Names ending in -origin are kept for origins. Pick another name.',
  'servers.unknown_inbound': 'That transport is not on this backend. Refresh and pick again.',
  'servers.duplicate_object':
    'The backend has more than one of these, so there is no telling which is meant. Remove the extra one there.',
  'servers.squad_in_placement':
    'New keys are issued into this group. Take it out of the connection mode first.',
  'servers.squad_has_members': 'This group still has members. Move them first.',
  'servers.squad_name_taken': 'A group with that name already exists.',
  // Nodes.
  'servers.node_name_taken': 'A node has, or had, that name. Pick another one.',
  'servers.node_relay_origin':
    'An origin in Edges covers this node. Its address, port and transports are changed there, and it is not turned off or removed here.',
  'servers.node_rename_separate': 'A node is renamed on its own. Use Rename.',
  'servers.node_rename_running': 'This node is being renamed. Wait for that to finish.',
  'servers.node_rename_not_running': 'That rename is not running any more.',
  'servers.rename_host_refused':
    'The backend refused to rename one of its addresses. Fix what it refused, then press Retry.',
  'servers.node_rename_foreign_hosts':
    'Hosts the operator named carry this node: an origin in front of it uses Hosts the operator writes, or it was adopted with them. Their remarks name the node, and they are not changed from here.',
  'servers.node_name_origin':
    'An origin in front of this node keeps its name as a DNS label: lower-case letters, digits and dashes only.',
  'servers.node_name_too_long':
    'With this name a Host remark would be longer than the backend allows. Pick a shorter name.',
  'servers.node_still_on': 'Turn the node off first, and wait for that to finish.',
  'servers.node_off': 'This node is turned off.',
  'servers.already': 'It is already in that state.',
  // Profile edits.
  'servers.profile_changed':
    'The profile changed on the backend since the preview. Preview again before applying.',
  'servers.nothing_to_change': 'The backend already had exactly this, so nothing was sent.',
  'servers.name_in_use':
    'Members are still given one of the names being removed. Retire it on the origin first.',
  'servers.inbound_sni_managed':
    'A server name family manages the names of this transport. Change them under Edges.',
  'servers.not_reality': 'That transport does not use REALITY.',
  'servers.too_many_names': 'That is more server names than one transport may carry.',
  'servers.not_admitted': 'The change was not sent. Nothing on the backend changed.',
  // Ports and new transports.
  'servers.port_loopback':
    "This transport listens only inside the node, behind the node's own proxy. Its port is not changed here.",
  'servers.port_not_single':
    'This transport listens on more than one port. Only a single port is changed here.',
  'servers.port_edge_bound':
    'An origin in Edges forwards to this transport at its port. Remove that protection before moving it.',
  'servers.port_taken': 'A node on this transport already uses that port. Pick another one.',
  'servers.port_change_staged':
    "A port change waits until every node's firewall lets the new port in. Use Change port.",
  'servers.port_change_waiting':
    'A port change of this profile is still waiting. Finish or cancel it first.',
  'servers.port_change_not_waiting': 'That port change is not waiting any more.',
  'servers.firewall_unconfirmed':
    'Not every node has confirmed that its firewall lets the new port in.',
  'servers.firewall_role_confirms':
    'The node role confirms this node itself, once it has opened the port. Run the role on it.',
  'servers.tag_taken':
    'A transport with that tag already exists on this backend. Pick another tag.',
  'servers.template_invalid': 'The transport template does not fit. Check the fields.',
  'servers.profile_malformed': 'The profile on the backend is not in a shape this can edit safely.',
  'servers.inbound_uuid_changed':
    'The backend replaced a transport while this was applied. Look at the backend before anything else.',
  // Settling.
  'servers.recovery_incomplete': 'Every condition has to hold before this can be released.',
  'servers.panel_refused': 'The backend refused it. Nothing was changed.',
  'servers.outcome_unknown':
    'The backend did not answer clearly, so it is not known whether this happened.',
  // Setting up a backend.
  'servers.setup_running': 'The backend is being set up right now. Wait for it to finish.',
  'servers.setup_failed': 'Setting up stopped on an error. Look at the backend, then try again.',
  'servers.adopt_required':
    'This backend already has nodes or addresses. Adopt it (typed) to make FCP its writer.',
  // Changing the setup of a backend FCP writes.
  'servers.setup_profile_kept':
    'A set-up backend keeps its profile: its nodes run it. Keep the profile name as it is.',
  'servers.setup_mode_kept':
    'A mode stays as it was set up, since nodes and members rely on it. Add a new mode instead.',
  'servers.adopt_group_narrows':
    "A mode's group already grants its members another transport that a Host serves, and setting up would take that away from them. Take the transport out of the group yourself, or move those members to another group, then set up again.",
  'servers.setup_mode_drifted':
    "A mode's group changed on the backend since it was set up (it no longer carries exactly its transport). Look at it under Mode groups, then change the setup.",
  'servers.setup_transport_missing':
    "The profile has no usable transport for the new mode yet. Add it with Add a transport on a node's page (its tag is the group name in capitals), then add the mode.",
  'servers.origin_zone_in_use':
    'WebSocket nodes have origin names in this zone. Keep it (another account holding the same zone is fine), or retire those nodes first.',
  'servers.origin_account_unusable':
    'Origin names need a DNS account that is switched on. Switch it on under Edges, Providers, or pick another account.',
  'servers.origin_zone_required':
    'This account reaches several zones. Pick the one for origin names.',
  'servers.origin_zone_unknown':
    'That zone is not one this account reaches. Refresh its zones, then pick it again.',
  'servers.origin_zone_inactive':
    'That zone is not active at its provider yet. Finish setting it up there, or pick another zone.',
  'servers.modes_invalid': 'The modes are not usable. Check their names and shapes.',
  'servers.mode_unknown':
    'No such connection mode exists yet, or this backend is not set up for it. Add it under Connection modes first.',
  'servers.family_missing':
    'A REALITY mode names a server-name family that does not exist or is off.',
  'servers.family_empty':
    'That family has no usable name yet. Add names to it and let them qualify first.',
  'servers.family_target_mismatch':
    'The backend already forwards this mode to a different site than its family checks. Pick the family that matches, or change the site from the profile.',
  'servers.family_unbound': 'The mode is not bound to its family yet. Set up the backend again.',
  'servers.family_bound_elsewhere':
    "This mode's transport already answers to another server-name family, whose rollouts would keep moving its names. Unbind it under Server names, or pick that family here.",
  // Adopting a node that already serves members.
  'servers.node_exists': 'This node is already enrolled.',
  'servers.node_not_on_mode':
    'The node does not run that mode on this backend. Pick the mode whose transport it serves.',
  // A shared change (a profile edit) that reaches nodes FCP does not manage.
  'servers.unmanaged_nodes_affected':
    'Nodes FCP does not manage run this profile too. Choose to hold them closed or acknowledge that they change in place.',
  'servers.obligation_unresolved':
    'A call to the backend or the DNS provider did not answer clearly. It is looked at again shortly.',
  'servers.observe_lag': 'The backend does not show it yet. It is looked at again shortly.',
  'servers.profile_incompatible':
    'A profile with this name exists but is not the shape nodes need. Rename it on the backend or pick another name.',
  'servers.privacy_drifted':
    'The profile logs more than it may. Harden it from the backend server page.',
  'servers.placement_skipped':
    'A connection mode this backend feeds does not exist, so its group is not bound.',
  'servers.template_drifted':
    'A subscription template on the backend is not what it should be, and could not be set.',
  // Enrolling a node.
  'servers.contract_version': 'The node role is too old for this backend. Update the role.',
  'servers.panel_not_set_up': 'Set up this backend first.',
  'servers.node_retiring': 'This node is being retired.',
  'servers.not_retiring': 'This node is not being retired.',
  'servers.retirement_stage': 'The node is not at that point of its retirement.',
  'servers.node_adopted':
    'This node was adopted as it was. The node role does not run its machine.',
  'servers.adopt_addresses_missing':
    "No address on this node's transport carries its name or address. Tick the addresses members use for it.",
  'servers.adopt_address_unknown':
    'An address you ticked is turned off, not on that transport any more, or another node has it. Refresh and pick again.',
  'servers.adopt_edges_retest':
    'Edges protect this node. Adopting it would keep its tested addresses from members until each is tested again, so it stays as it is. Its server names and edges work without adopting it.',
  'servers.mode_change_needs_admin':
    'A node keeps its mode. Change it from here, then run the role again.',
  'servers.node_exists_unowned':
    'The backend already has this node or address. Adopt it here before the role enrolls it.',
  'servers.origin_label_invalid': 'The name cannot be made into a DNS label.',
  'servers.registration_boundary': 'This token may not act for that node.',
  'servers.revision_stale': 'The machine settings changed. Run the role again.',
  'servers.revision_unknown': 'That machine revision was never handed out.',
  'servers.reconcile_failed': 'The node could not be reconciled with the backend.',
  'servers.address_remark_collision':
    'Two server names of this node would get the same address name. Remove one of them from the family, then run the role again.',
  'servers.maintenance_required':
    'This change rewrites the running path. Start it as a maintenance transition: the node is closed until it is approved again.',
  'servers.maintenance_open': 'A maintenance transition is open on this node.',
  // Machine readiness.
  'servers.config_moved': 'The profile changed under this node. It is checked again.',
  'servers.foreign_profile_edit': 'The profile was edited outside FCP. See it, then try again.',
  'servers.node_offline': 'The node is not connected to the backend.',
  'servers.origin_hostname_missing':
    'This front node has no origin name yet. Give the backend a zone for origin names (Change setup), or set a hostname under Settings.',
  'servers.adopt_origin_name_required':
    'A WebSocket node needs its origin name, the name its CDN fronts dial. Fill it in, then adopt.',
  'servers.origin_name_in_use':
    'Another node of this backend already has this origin name. Each node has its own.',
  'servers.origin_name_taken':
    'Something else holds a DNS record at the origin name. Free it in the zone, then try again.',
  'servers.origin_not_resolving': 'The origin name does not resolve to the node yet.',
  'servers.origin_certificate':
    'The node does not present a valid certificate for its origin name yet.',
  'servers.ingress_path': 'The WebSocket path is not proxied to the transport.',
  'servers.ingress_host_header': 'The node does not answer a foreign Host header.',
  // Activation.
  'servers.machine_not_ready': 'The machine is not ready yet.',
  'servers.direct_unconfirmed': 'Test the direct connection and tick it first.',
  'servers.confirmation_stale':
    'What you tested is not what the node serves now. Build a new test link.',
  'servers.credential_unavailable': 'No test credential could be made on the backend.',
  'servers.inbound_missing': 'The REALITY transport is gone from the profile.',
  'servers.stage': 'The node is not at the point where this can be done.',
  'servers.review_stale': 'The review changed since you read it. Read it again.',
  'servers.host_missing': 'The node has no address to enable.',
  'servers.rehearsal_failed':
    'The bodies the backend served did not carry this node as expected. Nothing was released.',
  'servers.rehearsal_missing': 'The rehearsal has not run.',
  'servers.activation_failed': 'Activation stopped on an error.',
  'servers.run_superseded': 'A newer approval replaced this one.',
  'servers.run_not_running': 'This activation is not running.',
  'servers.revision_moved': 'Something changed since the approval. Review and approve again.',
  'servers.delivery_changed':
    'An address members would keep changed since the last check. It is checked again, then goes live.',
  'servers.node_not_approved':
    'The node is waiting for your approval to go live. Approve it in its protection progress.',
  'servers.standbys_missing':
    'Protect this node in Edges first. Its new addresses come from there.',
  'servers.standbys_unverified':
    'Not every new address of this node is tested yet. Try each one in its protection progress.',
  'servers.credential_unresolved':
    'A test credential of this node has an unknown outcome on the backend. Look at its users.',
  'servers.delete_not_applied': 'An origin record was not removed. It is tried again.',
  'servers.create_not_observed': 'An origin record was not created. It is tried again.',
  // Retirement.
  'servers.relay_draining': 'Its edges are still being taken down.',
  'servers.credentials_pending': 'Its test credentials are still being removed from the backend.',
  'servers.retirement_failed': 'Retiring stopped on an error. It is tried again shortly.',
  'servers.migration_not_built':
    'Moving members to another node is not available yet. Choose to keep them dark.',
};
// --- the bootstrap contract: enrolled nodes and their ladder -----------------------------------
// (stageWords / setupWords / shapeWords; tested in words.test.ts)

/** "REALITY, direct" / "WebSocket, fronted through an edge": a mode's shape in words. */
export function shapeWords(s: { transport: string; fronting: string }): string {
  const transport =
    s.transport === 'ws'
      ? 'WebSocket'
      : s.transport === 'xhttp-reality'
        ? 'XHTTP + REALITY'
        : 'REALITY';
  const fronting = s.fronting === 'direct' ? 'direct' : 'fronted through an edge';
  return `${transport}, ${fronting}`;
}

/** The open guided setup run protecting a fronted node, as `NodeIntentView.protection` carries it. */
export interface ProtectionLike {
  state: string;
  need: string | null;
}

/**
 * One sentence and a dot for where an enrolled node is on its way to members.
 * A fronted node (`mode.shape.fronting` not direct) goes live through its
 * protection in Edges: Start, try each address, approve go-live.
 */
export function stageWords(i: {
  stage: string;
  disposition: string;
  state: string;
  code: string | null;
  maintenance: boolean;
  retirement: { stage: string } | null;
  mode?: { shape: { fronting: string } };
  protection?: ProtectionLike | null;
}): { dot: Dot; sentence: string } {
  if (i.retirement) {
    const s = i.retirement.stage;
    // A role's request leaves the node serving until the admin decides.
    if (s === 'needs_admin')
      return i.disposition === 'retiring'
        ? { dot: 'amber', sentence: 'Retiring. Needs your decision.' }
        : {
            dot: 'amber',
            sentence: 'The node role asked to retire it. It serves members until you decide.',
          };
    if (s === 'ready_to_wipe')
      return { dot: 'grey', sentence: 'Retired here. Waiting for the machine to be wiped.' };
    if (s === 'retired') return { dot: 'grey', sentence: 'Retired.' };
    return { dot: 'grey', sentence: 'Retiring. Members no longer get it.' };
  }
  if (i.maintenance)
    return { dot: 'amber', sentence: 'Closed for maintenance. Finish it, then approve again.' };
  if (i.state === 'blocked')
    return { dot: 'red', sentence: `Stopped: ${serverErrorWords(i.code)}` };
  const fronted = !!i.mode && i.mode.shape.fronting !== 'direct';
  // Once approved (activating) the run's parked need is stale for a moment: the stage speaks.
  const p = fronted && i.stage !== 'activating' ? (i.protection ?? null) : null;
  if (p?.state === 'needs_you') {
    if (p.need === 'node_not_approved')
      return {
        dot: 'amber',
        sentence:
          i.stage === 'live'
            ? 'Live. Its new addresses are tested and wait for you to approve go-live.'
            : 'Tested. Waiting for you to approve go-live.',
      };
    return {
      dot: 'amber',
      sentence:
        i.stage === 'live'
          ? 'Live. Its protection in Edges needs you.'
          : 'Being protected in Edges. It needs you there.',
    };
  }
  if (p && i.stage !== 'live') return { dot: 'amber', sentence: 'Being protected in Edges.' };
  switch (i.stage) {
    case 'registered':
      return {
        dot: 'grey',
        sentence: 'Enrolled. Waiting for the role to fetch its configuration.',
      };
    case 'bootstrap_available':
      return { dot: 'grey', sentence: 'Configuration served. Waiting for the role to apply it.' };
    case 'machine_applied':
      return { dot: 'amber', sentence: 'The role applied it. Checking the machine.' };
    case 'machine_ready':
      return fronted
        ? { dot: 'amber', sentence: 'The machine is ready. Protect it from Edges to go live.' }
        : { dot: 'amber', sentence: 'The machine is ready. Test the connection, then approve.' };
    case 'candidates_verified':
      return fronted
        ? {
            dot: 'amber',
            sentence: 'Its addresses are tested. Approve go-live in its protection progress.',
          }
        : { dot: 'amber', sentence: 'Tested. Review and approve to release it to members.' };
    case 'awaiting_approval':
      return fronted
        ? {
            dot: 'amber',
            sentence: 'Waiting for you to approve go-live in its protection progress.',
          }
        : { dot: 'amber', sentence: 'Waiting for your approval.' };
    case 'activating':
      return {
        dot: 'amber',
        sentence: 'Releasing to members. Nobody sees it until this finishes.',
      };
    case 'live':
      return i.disposition === 'live'
        ? { dot: 'green', sentence: 'Live for members.' }
        : { dot: 'amber', sentence: 'Approved, but not served right now.' };
    default:
      return { dot: 'grey', sentence: 'Enrolled.' };
  }
}

// --- retiring a node (docs/servers.md "Retirement") --------------------------------------------

/** A retirement as `NodeIntentView.retirement` carries it. */
export interface RetirementLike {
  stage: string;
  code: string | null;
  /** Where `draining` stopped last: origin | credentials | addresses | dns | panel_row. */
  step: string | null;
  requestedBy: 'role' | 'admin';
  /** It waited for an admin's decision, or got one (a plain request never does). */
  decision: boolean;
  /** When the ladder began waiting where it is (ISO). */
  since: string | null;
}

export interface RetireStep {
  key: string;
  label: string;
  state: 'done' | 'current' | 'todo';
  /** Why the current step waits, in words. */
  why: string | null;
}

/** How often the sweep pushes a retirement along (`backend-bootstrap-sweep`). */
const RETIRE_SWEEP = 'FCP looks again every 5 minutes';

/** The retire confirm: members lose the node the moment it is confirmed. */
export function retireConfirmWords(i: { adopted: boolean }): string {
  return (
    'Members lose this node at once: it closes now and nobody is given it again. ' +
    'Members whose key is on it get the unavailable answer; moving them to another node is not offered. ' +
    'Then FCP takes down its edges and removes its addresses, origin name and panel row, looking again every 5 minutes until each is done, ' +
    (i.adopted
      ? 'and you confirm here once you have cleaned up the machine, since FCP never ran it.'
      : 'and the node role wipes the machine.') +
    ' This cannot be undone.'
  );
}

/**
 * The retirement ladder as steps, with the one it is on and why it waits
 * there. The server records where `draining` stopped (`step`) and why
 * (`code`); a stage after `draining` speaks for itself.
 */
export function retirementSteps(
  i: { adopted: boolean; retirement: RetirementLike; disposition?: string },
  now: number = Date.now(),
): RetireStep[] {
  const r = i.retirement;
  // A role's request is decided first: the node is closed only once it is. A
  // request an earlier release recorded closed it at once (it is `retiring`).
  const asked = r.decision || r.stage === 'needs_admin';
  const closedFirst = r.stage === 'needs_admin' && i.disposition === 'retiring';
  const keys = [
    ...(asked && !closedFirst ? ['decision'] : []),
    'closed',
    ...(closedFirst ? ['decision'] : []),
    'edges',
    'addresses',
    'dns',
    'panel',
    'wipe',
    'retired',
  ];
  const LABEL: Record<string, string> = {
    closed: 'Closed to members',
    decision: 'Your decision',
    edges: 'Edges taken down, test credentials released',
    addresses: 'Its own addresses deleted from the panel',
    dns: 'Its origin name withdrawn from DNS',
    panel: 'Removed from the panel, its name marked retired',
    wipe: i.adopted ? 'You confirm the machine is gone' : 'The node role wipes the machine',
    retired: 'Retired',
  };
  const DRAINING_AT: Record<string, string> = {
    origin: 'edges',
    credentials: 'edges',
    addresses: 'addresses',
    dns: 'dns',
    panel_row: 'panel',
  };
  const current =
    r.stage === 'needs_admin'
      ? 'decision'
      : r.stage === 'requested'
        ? 'edges'
        : r.stage === 'draining'
          ? (DRAINING_AT[r.step ?? ''] ?? 'edges')
          : r.stage === 'panel_removed' || r.stage === 'ready_to_wipe'
            ? 'wipe'
            : null;
  const at = current ? keys.indexOf(current) : keys.length;
  const started = r.since ? ` (this step started ${ago(now - Date.parse(r.since))})` : '';
  const why = (): string => {
    if (current === 'decision')
      return closedFirst
        ? 'The node role asked to retire it, and members on it already get the unavailable answer. Decide below.'
        : 'The node role asked to retire it, and it serves members meanwhile. Retire it (members on it get the unavailable answer from then on), or reject the request.';
    if (current === 'wipe')
      return i.adopted
        ? 'FCP never ran this machine. Stop and clean it up yourself, then choose The machine is gone.'
        : 'Waiting for the node role to wipe the machine and report back.';
    const key = r.code ? (r.code.split(':')[0] ?? '') : '';
    const reason = !r.code
      ? 'Under way.'
      : WORDED_CODES.includes(key)
        ? serverErrorWords(r.code)
        : `It stopped on an error (${r.code}).`;
    return `${reason} ${RETIRE_SWEEP}${started}.`;
  };
  return keys.map((key, idx) => ({
    key,
    label: LABEL[key] ?? key,
    state: r.stage === 'retired' || idx < at ? 'done' : idx === at ? 'current' : 'todo',
    why: idx === at && r.stage !== 'retired' ? why() : null,
  }));
}

/** The line beside "Open progress" on a fronted node's page, while its protection is open. */
export function protectionWords(p: ProtectionLike, stage?: string): string {
  if (stage === 'activating') return 'Approved. Its protection carries on in a moment.';
  if (p.state === 'needs_you')
    return p.need === 'node_not_approved'
      ? 'Its new addresses are tested. Approve go-live below, or in its protection progress.'
      : 'Its protection in Edges needs you.';
  return 'Being protected in Edges. It carries on by itself.';
}

/**
 * One standby a fronted node's approval releases, in words:
 * `main: members get 203.0.113.7:443, an address in Main account (Region A).`
 * The location is named for an address only: a CDN name has no region.
 */
export function standbyWords(s: {
  listenerKey: string;
  layer: 'l4' | 'l7';
  endpoint: string | null;
  accountName: string | null;
  locationLabel?: string | null;
}): string {
  const kind = s.layer === 'l7' ? 'a CDN name' : 'an address';
  const place = s.layer === 'l4' && s.locationLabel ? ` (${s.locationLabel})` : '';
  const where = s.accountName ? `, ${kind} in ${s.accountName}${place}` : '';
  return `${s.listenerKey}: members get ${s.endpoint ?? 'a new address'}${where}.`;
}

/** The setup row in Needs you, or null when there is nothing to do. */
export function setupWords(s: {
  exists: boolean;
  state: string | null;
  code: string | null;
  running: boolean;
}): string | null {
  if (!s.exists) return 'This backend is not set up yet. Set it up so nodes can enroll.';
  if (s.running) return 'Setting up the backend.';
  if (s.state === 'failed') return `Setting up stopped: ${serverErrorWords(s.code)}`;
  if (s.state === 'pending') return `Setting up paused: ${serverErrorWords(s.code)}`;
  return null;
}

export function serverErrorWords(code: string | null | undefined): string {
  // Codes carry detail after a colon (`servers.profile_incompatible:TAG:field`).
  const key = code ? (code.split(':')[0] ?? '') : '';
  return ERROR_WORDS[key] || 'That did not work. Try again in a moment.';
}
/** Every code with its own words (pinned by the tests against the server's vocabulary). */
export const WORDED_CODES: readonly string[] = Object.keys(ERROR_WORDS);

/**
 * The review card's blockers: a few codes read differently there than as a
 * refused write (a toast); the rest share `serverErrorWords`.
 */
const BLOCKER_WORDS: Record<string, string> = {
  'servers.stage':
    'The node is not at a step where it can be approved. Wait for the step it is on to finish.',
  'servers.maintenance_required':
    'Put the node in maintenance first: a live node gets a new address only while members are held off it.',
  'servers.standbys_unverified:key_changed':
    'The node’s REALITY key changed since its new addresses were tried. Try each one again with the new key (its protection progress, or the node in Edges), then approve.',
};
export function blockerWords(code: string): string {
  return BLOCKER_WORDS[code] ?? BLOCKER_WORDS[code.split(':')[0] ?? ''] ?? serverErrorWords(code);
}

// --- one change to a backend, in words ------------------------------------------------------------

export interface OpLike {
  kind: 'host' | 'squad' | 'node' | 'profile';
  verb: string;
  label: string;
  state: 'working' | 'waiting_for_nodes' | 'done' | 'refused' | 'outcome_unknown' | 'recovered';
  errorCode: string | null;
}

const KIND: Record<OpLike['kind'], string> = {
  host: 'address',
  squad: 'mode group',
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
      return { dot: 'amber', sentence: 'Sent. Waiting to see it on the backend.' };
    case 'waiting_for_nodes':
      return {
        dot: 'amber',
        sentence: 'The backend has it. Waiting for the nodes to pick it up.',
      };
    case 'done':
      return op.errorCode === 'servers.adopted_existing'
        ? { dot: 'green', sentence: 'Done. It was already there, so nothing was created twice.' }
        : { dot: 'green', sentence: 'Done, and seen on the backend.' };
    case 'refused': {
      if (op.errorCode === 'servers.never_sent')
        return { dot: 'grey', sentence: 'Never sent. Nothing was changed.' };
      // Most refusals are FCP's own (the profile moved since the preview, the
      // backend already had it, two matches): say which, never "the backend refused".
      const reason = op.errorCode ? ERROR_WORDS[op.errorCode] : undefined;
      return { dot: 'grey', sentence: reason ?? 'The backend refused it. Nothing was changed.' };
    }
    case 'outcome_unknown':
      return {
        dot: 'red',
        sentence:
          'It is not known whether this happened. Nothing else can change this item until it is seen on the backend or settled by hand.',
      };
    case 'recovered':
      return { dot: 'grey', sentence: 'Settled by hand.' };
  }
}

/**
 * The words for `count` identical changes in a row (Recent changes folds them):
 * one change reads as `opWords`; a retried create that never went out reads
 * "Tried 40 times, never sent".
 */
export function opRepeatWords(op: OpLike, count: number): { dot: Dot; sentence: string } {
  const w = opWords(op);
  if (count < 2) return w;
  if (op.state === 'refused' && op.errorCode === 'servers.never_sent')
    return { dot: w.dot, sentence: `Tried ${count} times, never sent. Nothing was changed.` };
  return { dot: w.dot, sentence: `${count} times in a row. ${w.sentence}` };
}

/** What makes two changes the same for folding: never an open one (it has its own buttons). */
export function opRepeatKey(op: OpLike & { open: boolean }): string | null {
  return op.open ? null : [op.kind, op.verb, op.label, op.state, op.errorCode ?? ''].join('\u0000');
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

// --- port changes and new transports ----------------------------------------------------------------

export interface PortChangeLike {
  transportTag: string;
  fromPort: number | null;
  toPort: number;
  state: 'waiting' | 'applying' | 'applied' | 'refused' | 'cancelled' | 'recovered';
  code: string | null;
  nodes: { name: string; confirmedBy: 'role' | 'operator'; state: string }[];
}

/** "Move PRIVACY_REALITY from port 443 to 8443". */
export function portChangeTitle(c: Pick<PortChangeLike, 'transportTag' | 'fromPort' | 'toPort'>) {
  return c.fromPort === null
    ? `Move ${c.transportTag} to port ${c.toPort}`
    : `Move ${c.transportTag} from port ${c.fromPort} to ${c.toPort}`;
}

/** Where a port change stands, and what (if anything) the operator should do. */
export function portChangeWords(c: PortChangeLike): { dot: Dot; sentence: string } {
  const waiting = c.nodes.filter((n) => n.state === 'waiting');
  switch (c.state) {
    case 'waiting': {
      if (waiting.length === 0)
        return c.code === 'servers.op_running' || c.code === 'servers.op_uncertain'
          ? {
              dot: 'amber',
              sentence: `Every node lets port ${c.toPort} in. Waiting for another change to this profile to finish.`,
            }
          : { dot: 'amber', sentence: `Every node lets port ${c.toPort} in. Sending it now.` };
      const n = waiting.length === 1 ? '1 node' : `${waiting.length} nodes`;
      return {
        dot: 'amber',
        sentence: `Nothing is sent until every node lets port ${c.toPort} in. Waiting for ${n}.`,
      };
    }
    case 'applying':
      return {
        dot: 'amber',
        sentence:
          'Sent. The nodes on it are closed until they are verified and approved on the new port.',
      };
    case 'applied':
      return {
        dot: 'green',
        sentence: `Done. The nodes listen on port ${c.toPort}, and come back once verified and approved.`,
      };
    case 'refused':
      return { dot: 'grey', sentence: `Not sent: ${serverErrorWords(c.code)}` };
    case 'cancelled':
      return { dot: 'grey', sentence: 'Cancelled. Nothing was sent.' };
    case 'recovered':
      return {
        dot: 'red',
        sentence: `Settled by hand. Whether the nodes listen on port ${c.toPort} is not known: look at the profile and the nodes.`,
      };
  }
}

/** One node a port change waits for, in words. */
export function firewallNodeWords(
  n: { confirmedBy: 'role' | 'operator'; state: string },
  port: number,
): string {
  if (n.state === 'confirmed') return `Lets port ${port} in.`;
  if (n.state === 'cancelled') return 'Not needed any more.';
  return n.confirmedBy === 'role'
    ? `Waiting for the node role to open port ${port} and report it. Run the role on this node.`
    : `No role reports for this node. Open port ${port} in its firewall, then confirm it here.`;
}

const TEMPLATE_WORDS: Record<string, string> = {
  reality: 'VLESS over TCP with REALITY',
  'xhttp-reality': 'VLESS over XHTTP with REALITY',
  ws: 'VLESS over WebSocket, on loopback behind the node proxy',
};
export const templateWords = (kind: string): string => TEMPLATE_WORDS[kind] ?? kind;

/**
 * Whether a transport's port is changed from here: one plain port, not
 * loopback (a loopback transport sits behind the node's own proxy, whose
 * route to it is a node setting). The server is what decides.
 */
export function portChangeable(i: Pick<TransportView, 'port' | 'listen'>): boolean {
  if (i.port === null) return false;
  const l = (i.listen ?? '')
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '');
  return !(l === 'localhost' || l === '::1' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(l));
}

// --- renaming a node ----------------------------------------------------------------------------

export interface RenameLike {
  from: string;
  to: string;
  state: 'running' | 'done' | 'failed';
  step: 'backend' | 'hosts' | 'subscriptions' | 'done';
  code: string | null;
  refusedHosts?: { remark: string; code: string }[];
}

const RENAME_STEP: Record<RenameLike['step'], string> = {
  backend: 'Renaming it on the backend.',
  hosts: 'Renaming the addresses that carry its name.',
  subscriptions: "Moving members' keys to the new name.",
  done: 'Finishing.',
};

/** Where a rename stands. Members keep connecting throughout; the old name keeps working. */
export function renameWords(r: RenameLike): { dot: Dot; sentence: string } {
  if (r.state === 'done') return { dot: 'green', sentence: `Renamed from ${r.from}.` };
  if (r.state === 'failed')
    return { dot: 'grey', sentence: `Not renamed to ${r.to}: ${serverErrorWords(r.code)}` };
  if (r.code === 'servers.rename_host_refused')
    return {
      dot: 'red',
      sentence: `Renaming to ${r.to} holds: the backend refused to rename ${r.refusedHosts?.map((h) => h.remark).join(', ') || 'an address'}. Members keep connecting. Fix what it refused, then retry.`,
    };
  const waiting =
    r.code === 'servers.op_running' || r.code === 'servers.op_uncertain'
      ? ' Waiting for a change on the backend to settle.'
      : '';
  return {
    dot: 'amber',
    sentence: `Being renamed from ${r.from} to ${r.to}. ${RENAME_STEP[r.step]}${waiting} Members keep connecting.`,
  };
}
