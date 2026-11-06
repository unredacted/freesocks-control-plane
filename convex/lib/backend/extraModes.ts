/**
 * A node serving an EXTRA mode beside its own (pure; docs/servers.md "A node
 * serving an extra mode"). Today the one kind is a Hysteria 2 transport on UDP
 * 443 next to a direct REALITY one on TCP 443: each mode's group still holds
 * exactly its own transport, the node's active transport set is its own plus
 * the extra ones, and the extra mode has a lifecycle, evidence and an address
 * of its own, so a Hysteria change never closes REALITY.
 */
import { addressRemark } from './hostRemark';
import { hostMapperJson, hysteriaHostMapper } from './hostMapper';
import { canonicalJson } from './digest';
import type { HostMapper } from '../backends/types';
import type { ModeShape } from './profileTemplate';

export type ExtraModeState = 'waiting_firewall' | 'activating' | 'serving' | 'removing';

/** What a mode is set up as, as far as the rules below read it. */
export interface ExtraModeSetup {
  slug: string;
  shape: ModeShape;
  transport?: { uuid: string; port: number; serverNames?: string[] } | null;
}

/**
 * Why a node may not serve `extra` beside its own `primary` mode, as a code
 * word, or null. Only a direct Hysteria transport is an extra mode (no edge
 * forwards UDP); the node must be a direct one itself; a mode is served once;
 * the two transports must not share a (port, protocol); and the Hysteria
 * server name must not be one of the REALITY names (both addresses are
 * remarked `<node> | <server name>`).
 */
export function extraModeProblem(a: {
  primary: ExtraModeSetup;
  extra: ExtraModeSetup | undefined;
  served: readonly string[];
  /** What the node's other extra modes listen on. */
  otherOpenings?: readonly { port: number; protocol: 'tcp' | 'udp' }[];
  primaryOpening: { port: number; protocol: 'tcp' | 'udp' } | null;
  extraOpening: { port: number; protocol: 'tcp' | 'udp' } | null;
  primaryNames: readonly string[];
  extraName: string | null;
  fallbackModeSlug?: string | null;
}): string | null {
  if (!a.extra || !a.extra.transport) return 'servers.mode_unknown';
  if (a.extra.slug === a.primary.slug || a.served.includes(a.extra.slug))
    return 'servers.extra_mode_present';
  if (a.extra.shape.transport !== 'hysteria' || a.extra.shape.fronting !== 'direct')
    return 'servers.extra_mode_unsupported';
  if (a.primary.shape.fronting !== 'direct') return 'servers.extra_mode_node_not_direct';
  if (a.fallbackModeSlug && a.fallbackModeSlug !== a.primary.slug)
    return 'servers.extra_mode_fallback_missing';
  if (!a.extraOpening || !a.extraName) return 'servers.extra_mode_certificate';
  const x = a.extraOpening;
  if (
    [a.primaryOpening, ...(a.otherOpenings ?? [])].some(
      (o) => !!o && o.port === x.port && o.protocol === x.protocol,
    )
  )
    return 'servers.port_taken';
  if (a.primaryNames.some((n) => n.toLowerCase() === a.extraName!.toLowerCase()))
    return 'servers.extra_mode_name_collision';
  return null;
}

/** The address FCP keeps for a node's Hysteria transport. */
export interface ExtraHost {
  remark: string;
  address: string;
  port: number;
  sni: string;
  alpn: 'h3';
  securityLayer: 'TLS';
  pinnedPeerCertSha256: string;
  mapper: HostMapper;
  /** The mapper as the backend reads it back (canonical JSON). */
  mapperJson: string;
}

export function desiredExtraHost(a: {
  nodeName: string;
  originAddress: string;
  port: number;
  auth: { serverName: string; pinHex: string; spkiB64: string };
}): ExtraHost {
  const mapper = hysteriaHostMapper(a.auth);
  return {
    remark: addressRemark(a.nodeName, a.auth.serverName),
    address: a.originAddress,
    port: a.port,
    sni: a.auth.serverName,
    alpn: 'h3',
    securityLayer: 'TLS',
    pinnedPeerCertSha256: a.auth.pinHex,
    mapper,
    mapperJson: hostMapperJson(mapper)!,
  };
}

/** An observed Host, as far as the comparison reads it. */
export interface ObservedExtraHost {
  remark: string;
  address: string;
  port: number;
  sni?: string | null;
  alpn?: string | null;
  securityLayer?: string | null;
  pinnedPeerCertSha256?: string | null;
  mapperJson?: string | null;
  configProfileInboundUuid?: string | null;
}

/** The fields of `have` that differ from `want` (the update to send), or null when it matches. */
export function extraHostDiff(
  have: ObservedExtraHost,
  want: ExtraHost,
): Partial<Omit<ExtraHost, 'mapperJson'>> | null {
  const out: Partial<Omit<ExtraHost, 'mapperJson'>> = {};
  if (have.remark !== want.remark) out.remark = want.remark;
  if (have.address !== want.address) out.address = want.address;
  if (have.port !== want.port) out.port = want.port;
  if ((have.sni ?? null) !== want.sni) out.sni = want.sni;
  if ((have.alpn ?? null) !== want.alpn) out.alpn = want.alpn;
  if ((have.securityLayer ?? null) !== want.securityLayer) out.securityLayer = want.securityLayer;
  if ((have.pinnedPeerCertSha256 ?? null) !== want.pinnedPeerCertSha256)
    out.pinnedPeerCertSha256 = want.pinnedPeerCertSha256;
  if ((have.mapperJson ?? null) !== want.mapperJson) out.mapper = want.mapper;
  return Object.keys(out).length > 0 ? out : null;
}

/**
 * What a serving extra mode's evidence is bound to: the transport, the
 * certificate identity (`authDigest` moves on a new certificate, server name,
 * ALPN, Salamander or Salamander password), and the address members are given.
 * Any change of it closes the mode until a new rehearsal passes. Public values
 * and a keyed digest only.
 */
export function extraRevision(a: {
  transportUuid: string;
  authDigest: string;
  host: ExtraHost;
}): string {
  return canonicalJson({
    v: 1,
    transport: a.transportUuid,
    auth: a.authDigest,
    remark: a.host.remark,
    address: a.host.address,
    port: a.host.port,
    sni: a.host.sni,
    pin: a.host.pinnedPeerCertSha256,
    mapper: a.host.mapperJson,
  });
}

/** Whether the transport of an extra mode in this state is on for the node. */
export const extraTransportOn = (state: ExtraModeState, hostUuid?: string): boolean =>
  state === 'activating' || state === 'serving' || (state === 'removing' && !!hostUuid);
