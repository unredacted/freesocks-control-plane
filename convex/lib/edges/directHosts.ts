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
import { sameAddress } from './hosts';

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
  if (!sameAddress(h.address, ctx.originAddress)) return false;
  if (ctx.fcpRemarks.includes(h.remark)) return false;
  if (ctx.legacyHostUuids.includes(h.uuid)) return false;
  return true;
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
