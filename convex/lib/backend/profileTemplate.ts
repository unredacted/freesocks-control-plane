/**
 * The profile a backend is set up with (pure): one transport per mode, named
 * after the mode's group (docs/servers.md "Setting up a backend").
 *
 *   reality         VLESS + REALITY on the public port: a direct node, or one
 *                   fronted through an L4 edge. Its target and names come from
 *                   the mode's server-name family.
 *   xhttp-reality   VLESS over XHTTP under REALITY on the public port, fronted
 *                   through an L4 edge. Xray and Mihomo clients only.
 *   ws              VLESS over WebSocket on loopback: the node's Caddy
 *                   terminates TLS on the public port and proxies the path.
 *   hysteria        Hysteria 2 (QUIC) on UDP 443 of a direct node, under a
 *                   self-signed certificate members verify by pin only
 *                   (hysteriaCert.ts). UDP 443 never collides with a REALITY
 *                   transport on TCP 443, so a node may serve both (an extra
 *                   mode beside its primary one).
 *
 * Every REALITY transport listens on TCP 443 (a node serves ONE REALITY mode,
 * so they never collide) and carries its own key pair. The no-client-IP log block and
 * `statsUserOnline: false` are the posture `hardenXrayLoggingConfig` enforces,
 * so the profile is born compliant. Key material is INJECTED by the caller
 * and never read back out of the result by anything but the provider call.
 */
import { PRIVACY_XRAY_LOG } from '../backends/xrayPrivacy';

export type ModeTransport = 'reality' | 'xhttp-reality' | 'ws' | 'hysteria';
export type ModeFronting = 'direct' | 'edge-l4' | 'edge-l7';
export interface ModeShape {
  transport: ModeTransport;
  fronting: ModeFronting;
}

export const PROFILE_DEFAULTS = {
  profileName: 'FreeSocks-Config',
  ws: { listen: '127.0.0.1', path: '/ws', port: 8443 },
  /** Dual-stack public listen for the REALITY transports. */
  publicListen: '::',
  publicPort: 443,
  xhttpPath: '/',
  minClientVer: '1.8.1',
  /** One empty short id: what the role shipped; every client can use it. */
  shortIds: [''],
} as const;

/** The transport tag of a mode: its group name, upper-cased, `-` as `_`. */
export function transportTagOf(groupName: string): string {
  return groupName
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '_');
}

export interface RealityTemplateInput {
  /** The family's target: a real TLS 1.3 host the node can reach, serving EVERY name below. */
  target: { address: string; port: number };
  serverNames: string[];
  minClientVer?: string;
}

/**
 * A Hysteria 2 transport as asked for: the one server name its certificate is
 * for (and clients present as SNI), and whether Salamander obfuscation wraps
 * the QUIC packets (off by default: plain QUIC looks like ordinary HTTP/3).
 */
export interface HysteriaTemplateInput {
  serverName: string;
  salamander: boolean;
}

/** One mode as the template builds it. */
export type ModeTemplateInput = {
  slug: string;
  name: string;
  shape: ModeShape;
  acceptProxyProtocol?: boolean;
} & (
  | { shape: { transport: 'reality' | 'xhttp-reality' }; reality: RealityTemplateInput }
  | { shape: { transport: 'ws' }; ws: { path: string; port: number } }
  | { shape: { transport: 'hysteria' }; hysteria: HysteriaTemplateInput }
);

export interface ModeTemplateKeys {
  /** By mode slug, for every REALITY transport. */
  [slug: string]: { privateKey: string; shortIds: readonly string[] };
}

/**
 * A Hysteria transport's secrets, injected like a REALITY key: the
 * certificate and its private key (PEM lines, Xray's inline form) and the
 * Salamander password when obfuscation is on. Never stored by FCP.
 */
export interface HysteriaMaterial {
  certificate: string[];
  key: string[];
  obfsPassword?: string;
}
export interface ModeTemplateMaterial {
  /** By mode slug, for every Hysteria transport. */
  [slug: string]: HysteriaMaterial;
}

const HOSTNAME_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$/;
const PATH_RE = /^\/[A-Za-z0-9._~\-/]{0,127}$/;
const SHORT_ID_RE = /^(?:[0-9a-f]{2}){0,8}$/;
const GROUP_NAME_RE = /^[A-Za-z0-9_-]{2,20}$/;
const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,39}$/;

export const SHAPES: readonly ModeShape[] = [
  { transport: 'reality', fronting: 'direct' },
  { transport: 'reality', fronting: 'edge-l4' },
  { transport: 'xhttp-reality', fronting: 'edge-l4' },
  { transport: 'ws', fronting: 'edge-l7' },
  { transport: 'hysteria', fronting: 'direct' },
];
export const shapeAllowed = (s: ModeShape): boolean =>
  SHAPES.some((m) => m.transport === s.transport && m.fronting === s.fronting);
/** A REALITY transport: needs a server-name family (target + names) and a key pair. */
export const isReality = (s: Pick<ModeShape, 'transport'>): boolean =>
  s.transport === 'reality' || s.transport === 'xhttp-reality';
/** A Hysteria 2 (QUIC, UDP) transport: needs a server name, a certificate and its pins. */
export const isHysteria = (s: Pick<ModeShape, 'transport'>): boolean => s.transport === 'hysteria';
/** Whether a node of this shape is fronted by CDNs only (its WebSocket transport behind Caddy). */
export const isCdnFronted = (s: Pick<ModeShape, 'fronting'>): boolean => s.fronting === 'edge-l7';

/** What a mode definition carries before its family is resolved. */
export interface ModeDefinition {
  slug: string;
  name: string;
  shape: ModeShape;
  familySlug?: string;
  ws?: { path: string; port: number };
  hysteria?: HysteriaTemplateInput;
}

/** A code word for the first thing wrong with the mode DEFINITIONS (names, shapes, ws), or null. */
export function checkModeDefinitions(modes: readonly ModeDefinition[]): string | null {
  if (modes.length === 0) return 'modes_empty';
  const slugs = new Set<string>();
  const names = new Set<string>();
  const tags = new Set<string>();
  for (const m of modes) {
    if (!SLUG_RE.test(m.slug)) return `${m.slug}:slug`;
    if (!GROUP_NAME_RE.test(m.name)) return `${m.slug}:name`;
    if (!shapeAllowed(m.shape)) return `${m.slug}:shape`;
    if (slugs.has(m.slug)) return `${m.slug}:duplicate_slug`;
    if (names.has(m.name.toLowerCase())) return `${m.slug}:duplicate_name`;
    const tag = transportTagOf(m.name);
    if (tags.has(tag)) return `${m.slug}:duplicate_tag`;
    slugs.add(m.slug);
    names.add(m.name.toLowerCase());
    tags.add(tag);
    if (m.shape.transport === 'ws') {
      if (!m.ws) return `${m.slug}:ws`;
      if (!PATH_RE.test(m.ws.path)) return `${m.slug}:ws_path`;
      if (!Number.isInteger(m.ws.port) || m.ws.port < 1024 || m.ws.port > 65535)
        return `${m.slug}:ws_port`;
    } else if (isHysteria(m.shape)) {
      if (!m.hysteria) return `${m.slug}:hysteria`;
      if (!HOSTNAME_RE.test(m.hysteria.serverName.trim().toLowerCase()))
        return `${m.slug}:hysteria_name`;
    } else if (!m.familySlug) return `${m.slug}:family`;
  }
  return null;
}

/** A code word for the first thing wrong with the modes as the template builds them, or null. */
export function checkModes(modes: readonly ModeTemplateInput[]): string | null {
  const bad = checkModeDefinitions(
    modes.map((m) => ({
      slug: m.slug,
      name: m.name,
      shape: m.shape,
      familySlug: isReality(m.shape) ? 'resolved' : undefined,
      ws: 'ws' in m ? m.ws : undefined,
      hysteria: 'hysteria' in m ? m.hysteria : undefined,
    })),
  );
  if (bad) return bad;
  for (const m of modes) {
    if (!isReality(m.shape)) continue;
    if (!('reality' in m) || !m.reality) return `${m.slug}:reality`;
    const r = m.reality;
    const host = r.target.address.trim().toLowerCase();
    if (!HOSTNAME_RE.test(host)) return `${m.slug}:target`;
    if (!Number.isInteger(r.target.port) || r.target.port < 1 || r.target.port > 65535)
      return `${m.slug}:target_port`;
    const list = r.serverNames.map((n) => n.trim().toLowerCase());
    if (list.length === 0 || list.some((n) => !HOSTNAME_RE.test(n))) return `${m.slug}:names`;
    if (new Set(list).size !== list.length) return `${m.slug}:names`;
    if (r.minClientVer !== undefined && !/^\d+\.\d+\.\d+$/.test(r.minClientVer))
      return `${m.slug}:min_client_ver`;
  }
  return null;
}

/** Short ids are hex, at most 16 chars, an even count; the empty id is allowed. */
export function checkShortIds(shortIds: readonly string[]): boolean {
  return shortIds.length > 0 && shortIds.every((s) => SHORT_ID_RE.test(s));
}

const SNIFFING = { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true };

function realitySettings(
  r: RealityTemplateInput,
  keys: { privateKey: string; shortIds: readonly string[] },
): Record<string, unknown> {
  return {
    dest: `${r.target.address.trim().toLowerCase()}:${r.target.port}`,
    serverNames: r.serverNames.map((n) => n.trim().toLowerCase()),
    privateKey: keys.privateKey,
    shortIds: [...keys.shortIds],
    minClientVer: r.minClientVer ?? PROFILE_DEFAULTS.minClientVer,
  };
}

/**
 * What a Hysteria transport answers anyone who is not a member (an HTTP/3
 * request without a valid password): a plain 404, never a fetch of another
 * site from the node.
 */
const HYSTERIA_MASQUERADE = { type: 'string', content: 'not found', statusCode: 404 } as const;

/** A Salamander password: 32 random bytes, base64url. */
export function generateObfsPassword(
  random: (n: number) => Uint8Array = (n) => crypto.getRandomValues(new Uint8Array(n)),
): string {
  let bin = '';
  for (const x of random(32)) bin += String.fromCharCode(x);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function hysteriaTransport(
  tag: string,
  h: HysteriaTemplateInput,
  material: HysteriaMaterial,
): Record<string, unknown> {
  if (h.salamander && !material.obfsPassword)
    throw new Error('profile template: no Salamander password');
  return {
    tag,
    listen: PROFILE_DEFAULTS.publicListen,
    port: PROFILE_DEFAULTS.publicPort,
    protocol: 'hysteria',
    settings: { version: 2, clients: [] },
    streamSettings: {
      network: 'hysteria',
      security: 'tls',
      tlsSettings: {
        serverName: h.serverName.trim().toLowerCase(),
        alpn: ['h3'],
        certificates: [{ certificate: [...material.certificate], key: [...material.key] }],
      },
      hysteriaSettings: { version: 2, masquerade: { ...HYSTERIA_MASQUERADE } },
      // BBR, never Brutal: Brutal ignores loss and is unfair to other traffic.
      finalmask: {
        quicParams: { congestion: 'bbr' },
        ...(h.salamander
          ? { udp: [{ type: 'salamander', settings: { password: material.obfsPassword } }] }
          : {}),
      },
    },
    sniffing: SNIFFING,
  };
}

/** One transport of the profile, from its mode and (REALITY) its keys or (Hysteria) its material. */
export function buildTransport(
  m: ModeTemplateInput,
  keys: { privateKey: string; shortIds: readonly string[] } | undefined,
  material?: HysteriaMaterial,
): Record<string, unknown> {
  const tag = transportTagOf(m.name);
  if (m.shape.transport === 'hysteria') {
    if (!material) throw new Error(`profile template: no certificate for ${m.slug}`);
    return hysteriaTransport(tag, (m as { hysteria: HysteriaTemplateInput }).hysteria, material);
  }
  if (m.shape.transport === 'ws') {
    const ws = (m as { ws: { path: string; port: number } }).ws;
    return {
      tag,
      listen: PROFILE_DEFAULTS.ws.listen,
      port: ws.port,
      protocol: 'vless',
      settings: { clients: [], decryption: 'none' },
      streamSettings: { network: 'ws', security: 'none', wsSettings: { path: ws.path } },
      sniffing: SNIFFING,
    };
  }
  if (!keys) throw new Error(`profile template: no keys for ${m.slug}`);
  const r = (m as { reality: RealityTemplateInput }).reality;
  // Many L4 forwarders prepend a PROXY-protocol header; Xray has to be told or
  // REALITY reads it as a malformed ClientHello and every connection fails.
  const proxy = m.acceptProxyProtocol ? { acceptProxyProtocol: true } : {};
  const stream: Record<string, unknown> =
    m.shape.transport === 'xhttp-reality'
      ? {
          network: 'xhttp',
          security: 'reality',
          xhttpSettings: { path: PROFILE_DEFAULTS.xhttpPath, mode: 'auto', ...proxy },
          realitySettings: realitySettings(r, keys),
        }
      : {
          network: 'raw',
          security: 'reality',
          realitySettings: realitySettings(r, keys),
          ...(m.acceptProxyProtocol ? { rawSettings: { acceptProxyProtocol: true } } : {}),
        };
  return {
    tag,
    listen: PROFILE_DEFAULTS.publicListen,
    port: PROFILE_DEFAULTS.publicPort,
    protocol: 'vless',
    settings: { clients: [], decryption: 'none' },
    streamSettings: stream,
    sniffing: SNIFFING,
  };
}

/** The complete Xray config of the profile. Throws on bad input. */
export function buildProfile(
  modes: readonly ModeTemplateInput[],
  keys: ModeTemplateKeys,
  material: ModeTemplateMaterial = {},
): Record<string, unknown> {
  const bad = checkModes(modes);
  if (bad) throw new Error(`profile template: ${bad}`);
  for (const m of modes) {
    if (!isReality(m.shape)) continue;
    const k = keys[m.slug];
    if (!k || !checkShortIds(k.shortIds)) throw new Error('profile template: short_ids');
  }
  return {
    log: { ...PRIVACY_XRAY_LOG },
    // The per-user online-IP tracker OFF costs the backend's usersOnline signal;
    // that trade is deliberate (docs/privacy.md).
    policy: { levels: { '0': { statsUserOnline: false } } },
    inbounds: modes.map((m) => buildTransport(m, keys[m.slug], material[m.slug])),
    outbounds: [
      // UseIPv4v6: v4-first for dual-stack destinations, v6 for AAAA-only ones.
      { protocol: 'freedom', tag: 'DIRECT', settings: { domainStrategy: 'UseIPv4v6' } },
      { protocol: 'blackhole', tag: 'BLOCK' },
    ],
  };
}
