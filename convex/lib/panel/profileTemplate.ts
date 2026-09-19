/**
 * The bootstrap config profile (pure). What "Set up this panel" creates on a
 * fresh panel: the same profile the node role used to create, so a panel set
 * up either way is the same panel (docs/servers.md, "Setting up a panel").
 *
 * Three inbounds, one per node purpose:
 *   VLESS_WS_CDN          WebSocket on loopback: a front node's Caddy terminates
 *                         TLS on the public port and proxies the path to it.
 *   VLESS_REALITY         REALITY on the public port: a direct node.
 *   VLESS_RELAY_REALITY   REALITY on the public port behind an L4 edge: a relay
 *                         node. Its own key pair and its own decoy.
 *
 * The no-client-IP log block and `statsUserOnline: false` are the posture
 * `hardenXrayLoggingConfig` enforces, so the profile is born compliant. Key
 * material is INJECTED by the caller and never read back out of the result by
 * anything but the provider call that sends it.
 */
import { PRIVACY_XRAY_LOG } from '../backends/remnawave';

export const BOOTSTRAP_TAGS = {
  cdn: 'VLESS_WS_CDN',
  reality: 'VLESS_REALITY',
  relay: 'VLESS_RELAY_REALITY',
} as const;
export type BootstrapInboundKind = keyof typeof BOOTSTRAP_TAGS;

export const BOOTSTRAP_DEFAULTS = {
  profileName: 'FreeSocks-Config',
  cdn: { listen: '127.0.0.1', path: '/ws', port: 8443 },
  /** Dual-stack public listen for the REALITY inbounds. */
  publicListen: '::',
  realityPort: 443,
  relayPort: 443,
  network: 'raw',
  minClientVer: '1.8.1',
  /** One empty short id: what the role shipped; every client can use it. */
  shortIds: [''],
} as const;

export interface RealityTemplateInput {
  /** The decoy: a real TLS 1.3 host the node can reach, serving EVERY name below. */
  target: { address: string; port: number };
  serverNames: string[];
  minClientVer?: string;
}

export interface BootstrapProfileInput {
  cdn: { path: string; port: number };
  reality: RealityTemplateInput;
  relay: RealityTemplateInput & { acceptProxyProtocol: boolean };
}

export interface BootstrapProfileKeys {
  reality: { privateKey: string; shortIds: readonly string[] };
  relay: { privateKey: string; shortIds: readonly string[] };
}

const HOSTNAME_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$/;
const PATH_RE = /^\/[A-Za-z0-9._~\-/]{0,127}$/;
const SHORT_ID_RE = /^(?:[0-9a-f]{2}){0,8}$/;

/** A code word for the first thing wrong with the input, or null. */
export function checkBootstrapInput(input: BootstrapProfileInput): string | null {
  if (!PATH_RE.test(input.cdn.path)) return 'cdn_path';
  if (!Number.isInteger(input.cdn.port) || input.cdn.port < 1024 || input.cdn.port > 65535)
    return 'cdn_port';
  for (const [kind, r] of [
    ['reality', input.reality],
    ['relay', input.relay],
  ] as const) {
    const host = r.target.address.trim().toLowerCase();
    if (!HOSTNAME_RE.test(host)) return `${kind}_target`;
    if (!Number.isInteger(r.target.port) || r.target.port < 1 || r.target.port > 65535)
      return `${kind}_target_port`;
    const names = r.serverNames.map((n) => n.trim().toLowerCase());
    if (names.length === 0 || names.some((n) => !HOSTNAME_RE.test(n))) return `${kind}_names`;
    if (new Set(names).size !== names.length) return `${kind}_names`;
    if (r.minClientVer !== undefined && !/^\d+\.\d+\.\d+$/.test(r.minClientVer))
      return `${kind}_min_client_ver`;
  }
  return null;
}

/** Short ids are hex, at most 16 chars, an even count; the empty id is allowed. */
export function checkShortIds(shortIds: readonly string[]): boolean {
  return shortIds.length > 0 && shortIds.every((s) => SHORT_ID_RE.test(s));
}

const SNIFFING = { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true };

function realityInbound(
  tag: string,
  port: number,
  r: RealityTemplateInput,
  keys: { privateKey: string; shortIds: readonly string[] },
  extra: Record<string, unknown>,
): Record<string, unknown> {
  return {
    tag,
    listen: BOOTSTRAP_DEFAULTS.publicListen,
    port,
    protocol: 'vless',
    settings: { clients: [], decryption: 'none' },
    streamSettings: {
      network: BOOTSTRAP_DEFAULTS.network,
      security: 'reality',
      realitySettings: {
        dest: `${r.target.address.trim().toLowerCase()}:${r.target.port}`,
        serverNames: r.serverNames.map((n) => n.trim().toLowerCase()),
        privateKey: keys.privateKey,
        shortIds: [...keys.shortIds],
        minClientVer: r.minClientVer ?? BOOTSTRAP_DEFAULTS.minClientVer,
      },
      ...extra,
    },
    sniffing: SNIFFING,
  };
}

/** The complete Xray config of the bootstrap profile. Throws on bad input. */
export function buildBootstrapProfile(
  input: BootstrapProfileInput,
  keys: BootstrapProfileKeys,
): Record<string, unknown> {
  const bad = checkBootstrapInput(input);
  if (bad) throw new Error(`bootstrap profile input: ${bad}`);
  if (!checkShortIds(keys.reality.shortIds) || !checkShortIds(keys.relay.shortIds))
    throw new Error('bootstrap profile input: short_ids');
  const cdn = {
    tag: BOOTSTRAP_TAGS.cdn,
    listen: BOOTSTRAP_DEFAULTS.cdn.listen,
    port: input.cdn.port,
    protocol: 'vless',
    settings: { clients: [], decryption: 'none' },
    streamSettings: { network: 'ws', security: 'none', wsSettings: { path: input.cdn.path } },
    sniffing: SNIFFING,
  };
  const reality = realityInbound(
    BOOTSTRAP_TAGS.reality,
    BOOTSTRAP_DEFAULTS.realityPort,
    input.reality,
    keys.reality,
    {},
  );
  // Many L4 forwarders prepend a PROXY-protocol header; Xray has to be told or
  // REALITY reads it as a malformed ClientHello and every connection fails.
  const relay = realityInbound(
    BOOTSTRAP_TAGS.relay,
    BOOTSTRAP_DEFAULTS.relayPort,
    input.relay,
    keys.relay,
    input.relay.acceptProxyProtocol
      ? { [`${BOOTSTRAP_DEFAULTS.network}Settings`]: { acceptProxyProtocol: true } }
      : {},
  );
  return {
    log: { ...PRIVACY_XRAY_LOG },
    // The per-user online-IP tracker OFF costs the panel's usersOnline signal;
    // that trade is deliberate (docs/privacy.md).
    policy: { levels: { '0': { statsUserOnline: false } } },
    inbounds: [cdn, reality, relay],
    outbounds: [
      // UseIPv4v6: v4-first for dual-stack destinations, v6 for AAAA-only ones.
      { protocol: 'freedom', tag: 'DIRECT', settings: { domainStrategy: 'UseIPv4v6' } },
      { protocol: 'blackhole', tag: 'BLOCK' },
    ],
  };
}
