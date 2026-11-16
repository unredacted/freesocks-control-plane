/**
 * Whether a transport of a profile can be a mode's ENCRYPTED TWIN (pure;
 * convex/backendTwins.ts, docs/backends.md "VLESS Encryption"). The twin is
 * the mode's own transport a second time, with VLESS Encryption inside the
 * stream: same kind of transport, another loopback port and another path, so
 * the node's front server routes both and the same fronts reach both.
 *
 * Everything is judged from what FCP last observed of the profile, which
 * holds only what is public about the layer (lib/backend/digest.ts): never a
 * key.
 */
import { clientEncryptionProblem } from './vlessEncryption';

export type TwinProblem =
  | 'servers.twin_unsupported'
  | 'servers.twin_present'
  | 'servers.twin_transport_unknown'
  | 'servers.twin_transport_taken'
  | 'servers.twin_not_websocket'
  | 'servers.twin_not_encrypted'
  | 'servers.twin_encryption_unreadable'
  | 'servers.twin_encryption_unsupported'
  | 'servers.twin_same_route';

interface ModeLike {
  slug: string;
  shape: { transport: string; fronting: string };
  tag: string;
  transport?: { uuid: string; port: number; path?: string };
  twin?: { tag: string; uuid: string };
}

interface InboundLike {
  tag: string;
  inboundUuid: string;
  protocol: string;
  port: number | null;
  listen?: string;
  network: string;
  security: string;
  path?: string | null;
  vlessEncryption?: { encryption: string | null };
}

function isLoopback(listen: string | undefined): boolean {
  if (!listen) return false;
  const l = listen
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '');
  return l === 'localhost' || l === '::1' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(l);
}

/** A code word for the first thing wrong with `tag` as `mode`'s encrypted twin, or null. */
export function twinProblem(a: {
  mode: ModeLike;
  /** Every mode of the setup: a transport serves ONE mode, as its own or as its twin. */
  modes: readonly ModeLike[];
  /** The setup's profile, as last observed. */
  inbounds: readonly InboundLike[];
  tag: string;
}): TwinProblem | null {
  const { mode, tag } = a;
  // The layer answers a CDN that holds the stream in the clear: a WebSocket
  // mode behind L7 fronts. A REALITY mode is end to end already.
  if (mode.shape.transport !== 'ws' || mode.shape.fronting !== 'edge-l7')
    return 'servers.twin_unsupported';
  if (mode.twin) return mode.twin.tag === tag ? null : 'servers.twin_present';
  const inbound = a.inbounds.find((i) => i.tag === tag);
  if (!inbound) return 'servers.twin_transport_unknown';
  if (
    a.modes.some(
      (m) => m.tag === tag || m.twin?.tag === tag || m.transport?.uuid === inbound.inboundUuid,
    )
  )
    return 'servers.twin_transport_taken';
  if (
    inbound.protocol !== 'vless' ||
    inbound.network !== 'ws' ||
    inbound.security !== 'none' ||
    !isLoopback(inbound.listen) ||
    inbound.port === null ||
    !inbound.path
  )
    return 'servers.twin_not_websocket';
  if (!inbound.vlessEncryption) return 'servers.twin_not_encrypted';
  if (inbound.vlessEncryption.encryption === null) return 'servers.twin_encryption_unreadable';
  // FCP proves a twin through each front before members get it, so it has to
  // be one FCP's own session can speak.
  if (clientEncryptionProblem(inbound.vlessEncryption.encryption))
    return 'servers.twin_encryption_unsupported';
  if (inbound.port === mode.transport?.port || inbound.path === (mode.transport?.path ?? null))
    return 'servers.twin_same_route';
  return null;
}
