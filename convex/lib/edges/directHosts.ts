/**
 * Pure helpers for a node's DIRECT Hosts: the backend Hosts that still hand the
 * node's own address to members (the entries a guided setup hides once the
 * edges serve, and the restore workflow re-enables).
 *
 * A direct Host is: enabled, on one of THIS node's transports, dialling the
 * origin address, not an FCP origin remark (`<node>-origin-<key>`), and not a
 * Host a listener adopted (`legacyHosts`). `covered` = its transport has a
 * frontable listener (the edge replaces it), `uncovered` = it does not (the
 * operator must approve hiding it, by uuid).
 */
import type { BackendHost } from '../backends/types';
import { sha256Hex } from '../crypto';
import { splitPanelRemark } from '../nodePinning';
import { normalizeAddress, sameAddress } from './hosts';
import { canonicalIp } from './ip';

export interface DirectHost {
  uuid: string;
  remark: string;
  inboundUuid: string;
  address: string;
  port: number;
  sni: string | null;
  host: string | null;
  isDisabled: boolean;
}

export interface DirectHostContext {
  originAddress: string;
  /**
   * Other addresses that are the node itself (an enrolled node whose origin is
   * a hostname: its public addresses), so a Host dialling one is direct too.
   */
  alsoAddresses?: string[];
  /** The transports this node serves (lowercase or not; compared case-insensitively). */
  nodeInboundUuids: string[];
  /** Remarks FCP owns on this node (listener remarks + the origin convention). */
  fcpRemarks: string[];
  /** Hosts a listener adopted (never a direct Host, whatever their address). */
  legacyHostUuids: string[];
  /** Transports a frontable listener covers. */
  coveredInboundUuids: string[];
}

function lower(xs: readonly string[]): Set<string> {
  return new Set(xs.map((x) => x.toLowerCase()));
}

export function toDirectHost(h: BackendHost): DirectHost {
  return {
    uuid: h.uuid,
    remark: h.remark,
    inboundUuid: h.inbound?.configProfileInboundUuid ?? '',
    address: h.address,
    port: h.port,
    sni: h.sni ? h.sni : null,
    host: h.host ? h.host : null,
    isDisabled: h.isDisabled,
  };
}

/**
 * Whether a Host is a direct Host of the node, disabled or not (the enabled
 * filter is applied by `classifyDirectHosts`; the restore workflow needs the
 * disabled ones too).
 */
export function isDirectHost(h: BackendHost, ctx: DirectHostContext): boolean {
  const inbound = h.inbound?.configProfileInboundUuid?.toLowerCase();
  if (!inbound || !lower(ctx.nodeInboundUuids).has(inbound)) return false;
  if (
    !sameAddress(h.address, ctx.originAddress) &&
    !(ctx.alsoAddresses ?? []).some((a) => sameAddress(h.address, a))
  )
    return false;
  if (ctx.fcpRemarks.includes(h.remark)) return false;
  if (ctx.legacyHostUuids.includes(h.uuid)) return false;
  return true;
}

/**
 * Names one look may ask about. Every name is asked (one dropped could be the
 * node, never hidden and never refused by the leak check); past this many the
 * look refuses instead (`edge.too_many_host_names`). A node's Hosts are few.
 */
export const MAX_NODE_NAME_LOOKUPS = 200;

/**
 * The Hosts worth a lookup to tell whether they dial the node: a Host that
 * would be a direct Host but for its address, which is a name the node is not
 * known by yet.
 */
export function nodeNameHosts(
  hosts: readonly BackendHost[],
  ctx: DirectHostContext,
): BackendHost[] {
  const known = [ctx.originAddress, ...(ctx.alsoAddresses ?? [])];
  const inbounds = lower(ctx.nodeInboundUuids);
  return hosts.filter((h) => {
    const inbound = h.inbound?.configProfileInboundUuid?.toLowerCase();
    if (!inbound || !inbounds.has(inbound)) return false;
    if (canonicalIp(h.address) !== null || known.some((a) => sameAddress(h.address, a)))
      return false;
    return !ctx.fcpRemarks.includes(h.remark) && !ctx.legacyHostUuids.includes(h.uuid);
  });
}

/**
 * The names to resolve: every one `nodeNameHosts` dial, plus the origin itself
 * when it is a name (its answers are the node's addresses).
 */
export function nodeNameCandidates(
  hosts: readonly BackendHost[],
  ctx: DirectHostContext,
): string[] {
  const names = new Set<string>();
  if (canonicalIp(ctx.originAddress) === null) names.add(normalizeAddress(ctx.originAddress));
  for (const h of nodeNameHosts(hosts, ctx)) names.add(normalizeAddress(h.address));
  return [...names];
}

/**
 * What the answers say the node is, besides what it is known by: an origin
 * that is a name answers with the node's addresses; and a candidate name that
 * answers with an address the node is known by (an IP among the origin, its
 * `alsoAddresses` and the origin's answers) is the node, with everything it
 * answers (the node's other family). Empty when nothing new is the node.
 */
export function nodeNamesOf(
  ctx: Pick<DirectHostContext, 'originAddress' | 'alsoAddresses'>,
  answers: Readonly<Record<string, readonly string[]>>,
): string[] {
  const origin = normalizeAddress(ctx.originAddress);
  const known = [ctx.originAddress, ...(ctx.alsoAddresses ?? [])];
  const ips = [...known, ...(answers[origin] ?? [])].filter((a) => canonicalIp(a) !== null);
  const out: string[] = [];
  const add = (a: string) => {
    if (![...known, ...out].some((x) => sameAddress(x, a))) out.push(a);
  };
  for (const a of answers[origin] ?? []) add(a);
  for (const [name, ans] of Object.entries(answers)) {
    if (name === origin || !ans.some((a) => ips.some((ip) => sameAddress(ip, a)))) continue;
    add(name);
    for (const a of ans) add(a);
  }
  return out;
}

/**
 * The candidate names (`nodeNameCandidates`) that answered with addresses
 * none of which is the node: both lookups (A and AAAA) answered conclusively
 * (a record, or "no such record"), at least one address came back, and no
 * answer is an address the node is known by (the origin and `alsoAddresses`,
 * the origin's own answers, and every name `nodeNamesOf` found to be the
 * node, with its answers). A front the operator built at a name of its own (a
 * CDN hostname) is such a name. A name one of whose lookups failed
 * (`inconclusive`) is never one: the missing family could be the node.
 */
export function namesElsewhere(
  ctx: Pick<DirectHostContext, 'originAddress' | 'alsoAddresses'>,
  answers: Readonly<Record<string, readonly string[]>>,
  nodeNames: readonly string[],
  inconclusive: readonly string[] = [],
): string[] {
  const origin = normalizeAddress(ctx.originAddress);
  const node = [
    ctx.originAddress,
    ...(ctx.alsoAddresses ?? []),
    ...(answers[origin] ?? []),
    ...nodeNames,
  ];
  return Object.entries(answers)
    .filter(
      ([name, ans]) =>
        name !== origin &&
        !inconclusive.includes(name) &&
        !node.some((a) => sameAddress(a, name)) &&
        ans.some((a) => canonicalIp(a) !== null) &&
        !ans.some((a) => node.some((n) => sameAddress(n, a))),
    )
    .map(([name]) => name);
}

/** The node's ENABLED direct Hosts, split by whether a frontable listener covers their transport. */
export function classifyDirectHosts(
  hosts: readonly BackendHost[],
  ctx: DirectHostContext,
): { covered: DirectHost[]; uncovered: DirectHost[] } {
  const covered: DirectHost[] = [];
  const uncovered: DirectHost[] = [];
  const coveredInbounds = lower(ctx.coveredInboundUuids);
  for (const h of hosts) {
    if (h.isDisabled || !isDirectHost(h, ctx)) continue;
    const d = toDirectHost(h);
    (coveredInbounds.has(d.inboundUuid.toLowerCase()) ? covered : uncovered).push(d);
  }
  return { covered, uncovered };
}

/**
 * A node's OPERATOR FRONTS: enabled Hosts on a protected transport that dial
 * an IP that is neither the node (by any address it is known by) nor an
 * address of the origin's own edges, and are not FCP's (a listener remark, an
 * adopted Host). They are a front the operator built by hand, such as a load
 * balancer at its own public address. Members get them until the node is bound
 * to its edges; from then on a member render leaves them out (`withheld`), so
 * they can be deleted at their provider. A Host by a NAME is one only when this
 * look resolved that name elsewhere, conclusively (`frontNames`, from
 * `namesElsewhere`), such as a CDN front's hostname: a name a lookup failed for
 * could be the node itself, so it keeps the fail-closed alert. A Host whose
 * remark names ANOTHER node of the backend (`otherNodeNames`, read as the
 * pinner reads it) is that node's, whatever it dials: nodes that share a
 * transport list each other's Hosts, and members pinned to this node never get
 * them. `fcpRemarks` here are the listeners' own: the
 * origin convention (`relayRemarkRegex`) also matches the bare `<node>-relay`
 * an operator gives such a Host.
 */
export function operatorFrontHosts(
  hosts: readonly BackendHost[],
  ctx: DirectHostContext & {
    edgeAddresses?: readonly string[];
    /** Names this look resolved elsewhere (`namesElsewhere`). */
    frontNames?: readonly string[];
    /** The backend's other nodes, by name. */
    otherNodeNames?: readonly string[];
  },
): BackendHost[] {
  const covered = lower(ctx.coveredInboundUuids);
  const known = [ctx.originAddress, ...(ctx.alsoAddresses ?? []), ...(ctx.edgeAddresses ?? [])];
  const named = new Set((ctx.frontNames ?? []).map(normalizeAddress));
  const others = new Set(ctx.otherNodeNames ?? []);
  return hosts.filter((h) => {
    const inbound = h.inbound?.configProfileInboundUuid?.toLowerCase();
    if (h.isDisabled || !inbound || !covered.has(inbound)) return false;
    const node = splitPanelRemark(h.remark, h.sni)?.node;
    if (node !== undefined && others.has(node)) return false;
    if (canonicalIp(h.address) === null && !named.has(normalizeAddress(h.address))) return false;
    if (known.some((a) => sameAddress(h.address, a))) return false;
    return !ctx.fcpRemarks.includes(h.remark) && !ctx.legacyHostUuids.includes(h.uuid);
  });
}

/**
 * The Hosts of this node that matter to delivery: its direct Hosts (enabled or
 * disabled) and FCP's own, with their `isDisabled` bit. Hashed so two listings
 * taken around a slow operation can be compared for identity.
 */
export function relevantHosts(
  hosts: readonly BackendHost[],
  ctx: DirectHostContext,
): BackendHost[] {
  return hosts
    .filter((h) => isDirectHost(h, ctx) || ctx.fcpRemarks.includes(h.remark))
    .sort((a, b) => a.uuid.localeCompare(b.uuid));
}

export async function listingHash(
  hosts: readonly BackendHost[],
  ctx: DirectHostContext,
): Promise<string> {
  const canon = relevantHosts(hosts, ctx).map((h) => ({
    uuid: h.uuid,
    remark: h.remark,
    address: h.address.toLowerCase(),
    port: h.port,
    sni: h.sni ? h.sni : null,
    host: h.host ? h.host : null,
    inbound: h.inbound?.configProfileInboundUuid?.toLowerCase() ?? null,
    isDisabled: h.isDisabled,
  }));
  return sha256Hex(JSON.stringify(canon));
}

/** The observed tuple the hide ledger persists before any write. */
export function observedTuple(h: BackendHost): {
  remark: string;
  address: string;
  port: number;
  sni: string | null;
  host: string | null;
  inboundUuid: string | null;
  isDisabled: boolean;
} {
  return {
    remark: h.remark,
    address: h.address,
    port: h.port,
    sni: h.sni ? h.sni : null,
    host: h.host ? h.host : null,
    inboundUuid: h.inbound?.configProfileInboundUuid ?? null,
    isDisabled: h.isDisabled,
  };
}

/**
 * Whether a live Host is still the one the ledger observed: address, port and
 * transport agree (an administrator who re-pointed or re-bound it changed it, and
 * FCP then releases the row without writing).
 */
export function sameTuple(
  live: BackendHost,
  observed: { address: string; port: number; inboundUuid: string | null },
): boolean {
  return (
    sameAddress(live.address, observed.address) &&
    live.port === observed.port &&
    (live.inbound?.configProfileInboundUuid ?? null)?.toLowerCase() ===
      observed.inboundUuid?.toLowerCase()
  );
}
