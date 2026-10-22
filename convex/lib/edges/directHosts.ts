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

/** Names asked per look: each is one DNS query, and a node's Hosts are few. */
export const MAX_NODE_NAME_LOOKUPS = 20;

/**
 * The names worth resolving to tell whether they are the node: a Host that
 * would be a direct Host but for its address, which is a name the node is not
 * known by yet (plus the origin itself when it is a name: its answers are the
 * node's addresses). Bounded by MAX_NODE_NAME_LOOKUPS.
 */
export function nodeNameCandidates(
  hosts: readonly BackendHost[],
  ctx: DirectHostContext,
): string[] {
  const known = [ctx.originAddress, ...(ctx.alsoAddresses ?? [])];
  const inbounds = lower(ctx.nodeInboundUuids);
  const names = new Set<string>();
  if (canonicalIp(ctx.originAddress) === null) names.add(normalizeAddress(ctx.originAddress));
  for (const h of hosts) {
    const inbound = h.inbound?.configProfileInboundUuid?.toLowerCase();
    if (!inbound || !inbounds.has(inbound)) continue;
    if (canonicalIp(h.address) !== null || known.some((a) => sameAddress(h.address, a))) continue;
    if (ctx.fcpRemarks.includes(h.remark) || ctx.legacyHostUuids.includes(h.uuid)) continue;
    names.add(normalizeAddress(h.address));
  }
  return [...names].slice(0, MAX_NODE_NAME_LOOKUPS);
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
