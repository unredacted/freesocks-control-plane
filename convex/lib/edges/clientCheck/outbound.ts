/**
 * The test link -> a real engine's outbound (docs/edges.md § "FCP's own client
 * check"). FCP's client check uses exactly the artifact a human test uses: the
 * one-entry share link `edgeTestLinks.build` renders for an address. This turns
 * it into the outbound each engine needs, or says why an engine cannot speak
 * it (sing-box has no XHTTP and no VLESS encryption; Mihomo is given VLESS and
 * Trojan only, the protocols whose names a send proves). Pure; unit tested per
 * combination.
 *
 * Only what the link carries is used: nothing is invented except the uTLS
 * fingerprint REALITY requires (`chrome`, what the panel writes when it names
 * none), and, for Mihomo, the ML-KEM key share every Clash body FCP serves asks
 * for (lib/realityKeyShares.ts), so the check offers what members' Mihomo
 * offers. The client check service rebuilds the result from its own allowlist
 * (sanitize.ts) before an engine sees it.
 */
import type { ClientCheckEngine } from '../../../../src/shared/contracts/edgeCodes';
import type { ListenerProto } from '../protocols';
import { MLKEM_KEY_SHARE_OPTION } from '../../realityKeyShares';
import { parseProxyUri, type ParsedUri } from '../render/uri';

type Obj = Record<string, unknown>;

/** Why an engine was left out for a link. */
export type EngineSkip = 'no_xhttp' | 'vless_encryption' | 'unsupported_transport' | 'no_codec';

export interface LinkOutbounds {
  proto: ListenerProto;
  /** The outbound speaks REALITY. */
  reality: boolean;
  /** The address the link dials (an IP literal for every edge FCP renders). */
  address: string;
  port: number;
  outbounds: Partial<Record<ClientCheckEngine, Obj>>;
  skipped: Partial<Record<ClientCheckEngine, EngineSkip>>;
}

function decode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/** Drop undefined / empty-string fields (the engines read absent and empty differently). */
function compact(o: Obj): Obj {
  return Object.fromEntries(
    Object.entries(o).filter(([, v]) => v !== undefined && v !== '' && v !== null),
  );
}

function truthy(v: string | null): boolean {
  return v === '1' || v === 'true';
}

function streamOf(type: string): ListenerProto['streamTransport'] | null {
  const t = type.toLowerCase();
  if (t === '' || t === 'tcp' || t === 'raw' || t === 'none') return 'raw';
  if (t === 'splithttp' || t === 'xhttp') return 'xhttp';
  if (t === 'ws' || t === 'grpc' || t === 'httpupgrade') return t;
  return null;
}

/** SIP002 userinfo: base64url(method:password), or the two percent-encoded (2022 ciphers). */
function shadowsocksUser(userinfo: string): { method: string; password: string } | null {
  const plain = decode(userinfo);
  const colon = plain.indexOf(':');
  if (colon > 0) return { method: plain.slice(0, colon), password: plain.slice(colon + 1) };
  try {
    const b64 = userinfo.replace(/-/g, '+').replace(/_/g, '/');
    const text = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
    const i = text.indexOf(':');
    return i > 0 ? { method: text.slice(0, i), password: text.slice(i + 1) } : null;
  } catch {
    return null;
  }
}

/** A WebSocket path with Xray's `?ed=N` early-data suffix, split for sing-box. */
function wsPath(path: string): { path: string; earlyData: number | null } {
  const m = /^(.*?)\?ed=(\d+)$/.exec(path);
  return m ? { path: m[1] || '/', earlyData: Number(m[2]) } : { path, earlyData: null };
}

interface Common {
  u: ParsedUri;
  stream: ListenerProto['streamTransport'];
  security: ListenerProto['security'];
  sni: string;
  fp: string;
  alpn: string[] | undefined;
  insecure: boolean;
  path: string;
  host: string;
}

function singboxTls(c: Common): Obj | undefined {
  const p = c.u.params;
  if (c.security === 'reality')
    return {
      enabled: true,
      server_name: c.sni,
      utls: { enabled: true, fingerprint: c.fp || 'chrome' },
      reality: { enabled: true, public_key: p.get('pbk') ?? '', short_id: p.get('sid') ?? '' },
    };
  if (c.security === 'tls')
    return compact({
      enabled: true,
      server_name: c.sni,
      alpn: c.alpn,
      insecure: c.insecure || undefined,
      utls: c.fp ? { enabled: true, fingerprint: c.fp } : undefined,
    });
  return undefined;
}

function singboxTransport(c: Common): Obj | undefined | null {
  const p = c.u.params;
  switch (c.stream) {
    case 'raw':
      return undefined;
    case 'ws': {
      const { path, earlyData } = wsPath(c.path || '/');
      return compact({
        type: 'ws',
        path,
        headers: c.host ? { Host: c.host } : undefined,
        max_early_data: earlyData ?? undefined,
        early_data_header_name: earlyData !== null ? 'Sec-WebSocket-Protocol' : undefined,
      });
    }
    case 'grpc':
      return compact({ type: 'grpc', service_name: decode(p.get('serviceName') ?? '') });
    case 'httpupgrade':
      return compact({ type: 'httpupgrade', path: c.path || '/', host: c.host });
    default:
      return null;
  }
}

/** Mihomo's proxy fields for the link's security and transport; null: it has none for them. */
function mihomoStream(c: Common, scheme: 'vless' | 'trojan'): Obj | null {
  const p = c.u.params;
  const out: Obj = { udp: false };
  if (c.stream === 'raw') out.network = 'tcp';
  else if (c.stream === 'ws' || c.stream === 'httpupgrade') {
    const { path, earlyData } =
      c.stream === 'ws' ? wsPath(c.path || '/') : { path: c.path || '/', earlyData: null };
    out.network = 'ws';
    out['ws-opts'] = compact({
      path,
      headers: c.host ? { Host: c.host } : undefined,
      'max-early-data': earlyData ?? undefined,
      'early-data-header-name': earlyData !== null ? 'Sec-WebSocket-Protocol' : undefined,
      'v2ray-http-upgrade': c.stream === 'httpupgrade' || undefined,
    });
  } else if (c.stream === 'grpc') {
    out.network = 'grpc';
    out['grpc-opts'] = compact({ 'grpc-service-name': decode(p.get('serviceName') ?? '') });
  } else return null;
  if (c.security === 'none') return out;
  out.tls = true;
  out[scheme === 'vless' ? 'servername' : 'sni'] = c.sni || undefined;
  if (c.alpn) out.alpn = c.alpn;
  if (c.insecure) out['skip-cert-verify'] = true;
  if (c.security === 'reality') {
    out['client-fingerprint'] = c.fp || 'chrome';
    out['reality-opts'] = compact({
      'public-key': p.get('pbk') ?? '',
      'short-id': p.get('sid') ?? '',
      [MLKEM_KEY_SHARE_OPTION]: true,
    });
  } else if (c.fp) out['client-fingerprint'] = c.fp;
  return compact(out);
}

function xrayStream(c: Common): Obj {
  const p = c.u.params;
  const network = c.stream === 'raw' ? 'raw' : c.stream;
  const out: Obj = { network, security: c.security };
  if (c.security === 'reality')
    out.realitySettings = compact({
      serverName: c.sni,
      fingerprint: c.fp || 'chrome',
      publicKey: p.get('pbk') ?? '',
      shortId: p.get('sid') ?? '',
      spiderX: decode(p.get('spx') ?? ''),
      mldsa65Verify: p.get('pqv') ?? undefined,
    });
  if (c.security === 'tls')
    out.tlsSettings = compact({
      serverName: c.sni,
      fingerprint: c.fp,
      alpn: c.alpn,
      allowInsecure: c.insecure || undefined,
    });
  if (c.stream === 'ws') out.wsSettings = compact({ path: c.path || '/', host: c.host });
  if (c.stream === 'grpc')
    out.grpcSettings = compact({
      serviceName: decode(p.get('serviceName') ?? ''),
      authority: p.get('authority') ?? undefined,
      multiMode: p.get('mode') === 'multi' || undefined,
    });
  if (c.stream === 'httpupgrade')
    out.httpupgradeSettings = compact({ path: c.path || '/', host: c.host });
  if (c.stream === 'xhttp') {
    let extra: Obj | undefined;
    try {
      const raw = p.get('extra');
      const parsed: unknown = raw ? JSON.parse(decode(raw)) : undefined;
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) extra = parsed as Obj;
    } catch {
      extra = undefined;
    }
    out.xhttpSettings = compact({
      path: c.path || '/',
      host: c.host,
      mode: p.get('mode') ?? undefined,
      extra,
    });
  }
  return out;
}

/** The outbounds for one share link, or null when it is not a link FCP renders. */
export function outboundsForLink(link: string): LinkOutbounds | null {
  const u = parseProxyUri(link.trim().split(/\r?\n/)[0] ?? '');
  if (!u) return null;
  const p = u.params;
  const scheme = u.scheme === 'hy2' ? 'hysteria2' : u.scheme;
  const sni = decode(p.get('sni') ?? p.get('peer') ?? '');
  const alpnRaw = p.get('alpn');
  const common = (
    stream: ListenerProto['streamTransport'],
    security: ListenerProto['security'],
  ): Common => ({
    u,
    stream,
    security,
    sni,
    fp: p.get('fp') ?? '',
    alpn: alpnRaw ? decode(alpnRaw).split(',').filter(Boolean) : undefined,
    insecure: truthy(p.get('allowInsecure')) || truthy(p.get('insecure')),
    path: decode(p.get('path') ?? ''),
    host: decode(p.get('host') ?? ''),
  });
  const base = { address: u.host, port: u.port };

  if (scheme === 'vless' || scheme === 'trojan') {
    const stream = streamOf(p.get('type') ?? 'tcp');
    if (!stream) return null;
    const security = (
      scheme === 'trojan' ? (p.get('security') ?? 'tls') : (p.get('security') ?? 'none')
    ).toLowerCase() as ListenerProto['security'];
    if (!['none', 'tls', 'reality'].includes(security)) return null;
    const c = common(stream, security);
    const proto: ListenerProto = { protocol: scheme, streamTransport: stream, security };
    const outbounds: LinkOutbounds['outbounds'] = {};
    const skipped: LinkOutbounds['skipped'] = {};
    const secret = decode(u.userinfo);
    const flow = p.get('flow') ?? '';
    const encryption = p.get('encryption') ?? 'none';

    // sing-box
    const transport = singboxTransport(c);
    if (stream === 'xhttp') skipped['sing-box'] = 'no_xhttp';
    else if (scheme === 'vless' && encryption !== 'none') skipped['sing-box'] = 'vless_encryption';
    else if (transport === null) skipped['sing-box'] = 'unsupported_transport';
    else
      outbounds['sing-box'] = compact({
        type: scheme,
        server: u.host,
        server_port: u.port,
        ...(scheme === 'vless' ? { uuid: secret, flow } : { password: secret }),
        tls: singboxTls(c),
        transport,
      });

    // Mihomo
    const mh = mihomoStream(c, scheme);
    if (stream === 'xhttp') skipped.mihomo = 'no_xhttp';
    else if (scheme === 'vless' && encryption !== 'none') skipped.mihomo = 'vless_encryption';
    else if (!mh) skipped.mihomo = 'unsupported_transport';
    else
      outbounds.mihomo = compact({
        type: scheme,
        server: u.host,
        port: u.port,
        ...(scheme === 'vless' ? { uuid: secret, flow } : { password: secret }),
        ...mh,
      });

    // Xray
    outbounds.xray = {
      protocol: scheme,
      settings:
        scheme === 'vless'
          ? {
              vnext: [
                {
                  address: u.host,
                  port: u.port,
                  users: [compact({ id: secret, encryption, flow })],
                },
              ],
            }
          : { servers: [{ address: u.host, port: u.port, password: secret }] },
      streamSettings: xrayStream(c),
    };
    return { proto, reality: security === 'reality', ...base, outbounds, skipped };
  }

  if (scheme === 'ss') {
    // A plugin (obfs, v2ray-plugin) is a second program neither engine runs here.
    if (p.get('plugin')) return null;
    const user = shadowsocksUser(u.userinfo);
    if (!user) return null;
    return {
      proto: { protocol: 'shadowsocks', streamTransport: 'raw', security: 'none' },
      reality: false,
      ...base,
      outbounds: {
        'sing-box': {
          type: 'shadowsocks',
          server: u.host,
          server_port: u.port,
          method: user.method,
          password: user.password,
        },
        xray: {
          protocol: 'shadowsocks',
          settings: {
            servers: [
              { address: u.host, port: u.port, method: user.method, password: user.password },
            ],
          },
        },
      },
      skipped: { mihomo: 'no_codec' },
    };
  }

  if (scheme === 'hysteria2' || scheme === 'tuic') {
    const c = common('udp', 'tls');
    const tls = singboxTls(c);
    const outbound =
      scheme === 'hysteria2'
        ? compact({
            type: 'hysteria2',
            server: u.host,
            server_port: u.port,
            password: decode(u.userinfo),
            tls,
            obfs: p.get('obfs')
              ? { type: p.get('obfs'), password: decode(p.get('obfs-password') ?? '') }
              : undefined,
          })
        : (() => {
            // Split the RAW userinfo at its first separator: an encoded colon
            // belongs to the password.
            const at = u.userinfo.indexOf(':');
            const uuid = decode(at < 0 ? u.userinfo : u.userinfo.slice(0, at));
            const password = at < 0 ? '' : decode(u.userinfo.slice(at + 1));
            return compact({
              type: 'tuic',
              server: u.host,
              server_port: u.port,
              uuid,
              password,
              congestion_control: p.get('congestion_control') ?? undefined,
              tls,
            });
          })();
    return {
      proto: { protocol: scheme, streamTransport: 'udp', security: 'tls' },
      reality: false,
      ...base,
      outbounds: { 'sing-box': outbound },
      skipped: { xray: 'no_codec', mihomo: 'no_codec' },
    };
  }
  return null;
}
