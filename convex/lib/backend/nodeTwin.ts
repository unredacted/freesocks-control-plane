/**
 * A node serving its mode's ENCRYPTED TWIN (pure; convex/nodeTwins.ts,
 * docs/servers.md "A node serving the encrypted twin"). The twin is the mode's
 * own WebSocket transport a second time, with VLESS Encryption inside the
 * stream, on another loopback port and another path of the same node, behind
 * the same fronts. It is never a listener of its own: it rides the listener of
 * the node's own transport as a second address (`<node>-relay-<twin key>`) at
 * the same target.
 *
 * Nothing here touches the node's own transport, its address or its approval:
 * the twin has a lifecycle and evidence of its own, and closing it leaves the
 * plain path exactly as it was.
 */
import { canonicalJson } from './digest';
import { HOST_REMARK_MAX } from './hostRemark';
import { clientEncryptionProblem } from './vlessEncryption';

export type NodeTwinState = 'activating' | 'serving' | 'removing';

/** Whether the twin's transport is on for the node in this state. */
export const twinTransportOn = (state: NodeTwinState, hostUuid?: string): boolean =>
  state === 'activating' || state === 'serving' || (state === 'removing' && !!hostUuid);

/** The mode's twin on the setup row, as far as the rules below read it. */
export interface SetupTwin {
  tag: string;
  uuid: string;
  listen?: string;
  port: number;
  path: string;
  detaching?: boolean;
}

/** The twin's transport as last observed on the profile. */
export interface ObservedTwinInbound {
  inboundUuid: string;
  protocol: string;
  network: string;
  security: string;
  port: number | null;
  listen?: string;
  path?: string | null;
  vlessEncryption?: { digest: string | null; encryption: string | null };
}

/** The route the node's front server needs for the twin: its path to its loopback port. */
export function twinRoute(twin: SetupTwin): { path: string; port: number } {
  return { path: twin.path, port: twin.port };
}

/**
 * Why a node cannot be checked on its mode's twin right now, as a code word,
 * or null. Judged on every run: a twin that stops being checkable while it
 * serves is closed before the run stops.
 */
export function nodeTwinProblem(a: {
  twin: SetupTwin | undefined;
  inbound: ObservedTwinInbound | undefined;
  /** The transports the node's row serves on the backend; null = no row yet. */
  activeInboundUuids: readonly string[] | null;
  /** The node's own listener has a settled address FCP wrote, named by FCP's own form. */
  listenerReady: boolean;
  twinRemark: string | null;
}): string | null {
  if (!a.twin || a.twin.detaching) return 'servers.twin_absent';
  if (!a.listenerReady || !a.twinRemark) return 'servers.node_twin_no_front';
  if (a.twinRemark.length > HOST_REMARK_MAX) return 'servers.node_twin_remark_long';
  const i = a.inbound;
  if (
    !i ||
    i.protocol !== 'vless' ||
    i.network !== 'ws' ||
    i.security !== 'none' ||
    i.port === null ||
    !i.path
  )
    return 'servers.twin_not_websocket';
  if (!i.vlessEncryption) return 'servers.twin_not_encrypted';
  if (i.vlessEncryption.encryption === null || i.vlessEncryption.digest === null)
    return 'servers.twin_encryption_unreadable';
  if (clientEncryptionProblem(i.vlessEncryption.encryption))
    return 'servers.twin_encryption_unsupported';
  if (!a.activeInboundUuids || !a.activeInboundUuids.includes(i.inboundUuid))
    return 'servers.node_twin_transport_off';
  return null;
}

/** The fields of the listener's own address the twin's address repeats. */
export interface ListenerHostTuple {
  address: string;
  port: number;
  sni?: string | null;
  host?: string | null;
  alpn?: string | null;
  fingerprint?: string | null;
  securityLayer?: string | null;
}

/** The address FCP keeps for a node's twin: the listener's own, on the twin's transport. */
export interface TwinHost {
  remark: string;
  address: string;
  port: number;
  sni: string | null;
  host: string | null;
  alpn: string | null;
  fingerprint: string | null;
  securityLayer: string | null;
}

const orNull = (v: string | null | undefined): string | null => (v ? v : null);

/**
 * The twin's address: where the listener's own address points (the renderer
 * rewrites both per front anyway), under the twin's remark. It writes no path:
 * the path is the twin transport's own, which is the whole difference.
 */
export function desiredTwinHost(listenerHost: ListenerHostTuple, remark: string): TwinHost {
  return {
    remark,
    address: listenerHost.address,
    port: listenerHost.port,
    sni: orNull(listenerHost.sni),
    host: orNull(listenerHost.host),
    alpn: orNull(listenerHost.alpn),
    fingerprint: orNull(listenerHost.fingerprint),
    // The backend reads an unset layer back as its default word.
    securityLayer:
      listenerHost.securityLayer && listenerHost.securityLayer !== 'DEFAULT'
        ? listenerHost.securityLayer
        : null,
  };
}

/** The fields of `have` that differ from `want` (the update to send), or null when it matches. */
export function twinHostDiff(
  have: ListenerHostTuple & { remark: string },
  want: TwinHost,
): Partial<TwinHost> | null {
  const got = desiredTwinHost(have, have.remark);
  const out: Partial<TwinHost> = {};
  if (got.remark !== want.remark) out.remark = want.remark;
  if (got.address !== want.address) out.address = want.address;
  if (got.port !== want.port) out.port = want.port;
  if (got.sni !== want.sni) out.sni = want.sni;
  if (got.host !== want.host) out.host = want.host;
  if (got.alpn !== want.alpn) out.alpn = want.alpn;
  if (got.fingerprint !== want.fingerprint) out.fingerprint = want.fingerprint;
  if (got.securityLayer !== want.securityLayer) out.securityLayer = want.securityLayer;
  return Object.keys(out).length > 0 ? out : null;
}

/**
 * What a serving twin's checks are bound to, besides the front each was made
 * through: the twin's transport, what its node is verified by (`authDigest`
 * moves on a new key, mode or padding), its loopback port and path, and the
 * listener it rides. A change of any of it closes the twin on this node until
 * every front is checked again. Public values and a keyed digest only.
 *
 * The address members are handed is NOT part of it: the twin's address follows
 * the listener's own (a replaced front), and a front never checked on the twin
 * is simply not handed out encrypted.
 */
export function twinRevision(a: {
  transportUuid: string;
  authDigest: string;
  port: number;
  path: string;
  listenerId: string;
}): string {
  return canonicalJson({
    v: 1,
    transport: a.transportUuid,
    auth: a.authDigest,
    port: a.port,
    path: a.path,
    listener: a.listenerId,
  });
}

/** One front a twin was checked through. */
export interface TwinEdgeCheck {
  edgeId: string;
  checkedAt: number;
}

/**
 * Which published fronts need a twin check now: one never checked, or checked
 * longer ago than `ttlMs`. Fresh checks of fronts no longer published are
 * dropped by `keptChecks`.
 */
export function dueEdges(
  published: readonly string[],
  checks: readonly TwinEdgeCheck[],
  now: number,
  ttlMs: number,
): string[] {
  const fresh = new Set(checks.filter((c) => now - c.checkedAt < ttlMs).map((c) => c.edgeId));
  return published.filter((id) => !fresh.has(id));
}

/** The checks that still count: of a published front, and not one checked again in this run. */
export function keptChecks(
  published: readonly string[],
  checks: readonly TwinEdgeCheck[],
  rechecked: ReadonlySet<string>,
): TwinEdgeCheck[] {
  const live = new Set(published);
  return checks.filter((c) => live.has(c.edgeId) && !rechecked.has(c.edgeId));
}

/**
 * The fronts a twin may be handed out through at `now`: checked within
 * `maxAgeMs`. The run re-checks each front well inside that window; a check
 * older than it means the run stopped, and the twin is withheld rather than
 * handed out on old evidence.
 */
export function servableEdges(
  checks: readonly TwinEdgeCheck[] | undefined,
  now: number,
  maxAgeMs: number,
): string[] {
  return (checks ?? []).filter((c) => now - c.checkedAt < maxAgeMs).map((c) => c.edgeId);
}
