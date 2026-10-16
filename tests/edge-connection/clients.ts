/**
 * The member's two reference engines in the edge connection test (the pinned
 * sing-box and Mihomo of the compat suite, tests/compat/manifest.ts), and the
 * only things the test does to what FCP serves before an engine runs it.
 *
 * A served body is adapted to the sandbox and NOTHING else: the container has
 * no TUN device (a local listener carries the test's requests), the client
 * network has no public resolver (every plain DNS server points at the
 * network's own), nothing may be downloaded or exposed (no controller, no
 * extra ports), and the test picks which of the body's proxies carries its
 * request (the route's final outbound, a Mihomo MATCH rule). The proxies
 * themselves, where everything FCP rendered lives, are untouched; the caller
 * asserts it.
 *
 * A try_it test link (one share link, what an operator's client imports) is
 * turned into the same engines' configuration by the same rules a client
 * applies: `vless://`, `trojan://` and `ss://` (SIP002, base64 user info).
 */
import YAML from 'yaml';
import { ADDR } from './stack';

export type Engine = 'singbox' | 'mihomo';

/** One proxy endpoint, as a share link or a served entry describes it. */
export interface Endpoint {
  protocol: 'vless' | 'trojan' | 'shadowsocks';
  server: string;
  port: number;
  /** VLESS id, Trojan password, or Shadowsocks password. */
  secret: string;
  method?: string;
  flow?: string;
  security: 'none' | 'tls' | 'reality';
  sni?: string;
  alpn?: string[];
  fingerprint?: string;
  reality?: { publicKey: string; shortId: string };
  network: 'tcp' | 'ws' | 'httpupgrade' | 'grpc' | 'xhttp';
  path?: string;
  host?: string;
  serviceName?: string;
  mode?: string;
}

const b64 = (s: string) =>
  Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString();

/** A share link as a client imports it. Throws for anything this harness does not speak. */
export function parseShareLink(link: string): Endpoint {
  const u = new URL(link);
  const q = u.searchParams;
  const server = u.hostname.replace(/^\[|\]$/g, '');
  const port = Number(u.port || 443);
  if (u.protocol === 'ss:') {
    const info = decodeURIComponent(u.username);
    const plain = info.includes(':') ? info : b64(info);
    const at = plain.indexOf(':');
    return {
      protocol: 'shadowsocks',
      server,
      port,
      method: plain.slice(0, at),
      secret: plain.slice(at + 1),
      security: 'none',
      network: 'tcp',
    };
  }
  if (u.protocol !== 'vless:' && u.protocol !== 'trojan:')
    throw new Error(`the test link speaks ${u.protocol}, which this harness does not import`);
  const type = (q.get('type') ?? 'tcp') as Endpoint['network'];
  const security = (q.get('security') ?? (u.protocol === 'trojan:' ? 'tls' : 'none')) as
    | 'none'
    | 'tls'
    | 'reality';
  return {
    protocol: u.protocol === 'vless:' ? 'vless' : 'trojan',
    server,
    port,
    secret: decodeURIComponent(u.username),
    ...(q.get('flow') ? { flow: q.get('flow')! } : {}),
    security,
    ...(q.get('sni') ? { sni: q.get('sni')! } : {}),
    ...(q.get('alpn') ? { alpn: q.get('alpn')!.split(',') } : {}),
    ...(q.get('fp') ? { fingerprint: q.get('fp')! } : {}),
    ...(security === 'reality'
      ? { reality: { publicKey: q.get('pbk') ?? '', shortId: q.get('sid') ?? '' } }
      : {}),
    network: type === ('raw' as never) ? 'tcp' : type,
    ...(q.get('path') ? { path: q.get('path')! } : {}),
    ...(q.get('host') ? { host: q.get('host')! } : {}),
    ...(q.get('serviceName') ? { serviceName: q.get('serviceName')! } : {}),
    ...(q.get('mode') && type === 'xhttp' ? { mode: q.get('mode')! } : {}),
  };
}

/** sing-box has no XHTTP; every other endpoint has an outbound. */
export function engineFor(e: Endpoint): Engine {
  return e.network === 'xhttp' ? 'mihomo' : 'singbox';
}

function singboxOutbound(e: Endpoint, tag: string): Record<string, unknown> {
  const out: Record<string, unknown> = {
    type: e.protocol,
    tag,
    server: e.server,
    server_port: e.port,
  };
  if (e.protocol === 'vless') out.uuid = e.secret;
  else out.password = e.secret;
  if (e.protocol === 'shadowsocks') out.method = e.method;
  if (e.flow) out.flow = e.flow;
  if (e.security !== 'none')
    out.tls = {
      enabled: true,
      server_name: e.sni,
      ...(e.alpn ? { alpn: e.alpn } : {}),
      ...(e.fingerprint || e.reality
        ? { utls: { enabled: true, fingerprint: e.fingerprint || 'chrome' } }
        : {}),
      ...(e.reality
        ? {
            reality: {
              enabled: true,
              public_key: e.reality.publicKey,
              short_id: e.reality.shortId,
            },
          }
        : {}),
    };
  if (e.network === 'ws' || e.network === 'httpupgrade')
    out.transport = {
      type: e.network,
      path: e.path ?? '/',
      ...(e.host ? (e.network === 'ws' ? { headers: { Host: e.host } } : { host: e.host }) : {}),
    };
  if (e.network === 'grpc') out.transport = { type: 'grpc', service_name: e.serviceName ?? '' };
  return out;
}

function mihomoProxy(e: Endpoint, name: string): Record<string, unknown> {
  const p: Record<string, unknown> = {
    name,
    type: e.protocol === 'shadowsocks' ? 'ss' : e.protocol,
    server: e.server,
    port: e.port,
    udp: false,
  };
  if (e.protocol === 'vless') p.uuid = e.secret;
  else p.password = e.secret;
  if (e.protocol === 'shadowsocks') p.cipher = e.method;
  if (e.flow) p.flow = e.flow;
  if (e.security !== 'none') {
    if (e.protocol === 'vless') {
      p.tls = true;
      p.servername = e.sni;
    } else p.sni = e.sni;
    if (e.alpn) p.alpn = e.alpn;
    p['client-fingerprint'] = e.fingerprint || 'chrome';
  }
  if (e.reality)
    p['reality-opts'] = { 'public-key': e.reality.publicKey, 'short-id': e.reality.shortId };
  if (e.network !== 'tcp') p.network = e.network === 'httpupgrade' ? 'ws' : e.network;
  if (e.network === 'ws' || e.network === 'httpupgrade')
    p['ws-opts'] = {
      path: e.path ?? '/',
      ...(e.host ? { headers: { Host: e.host } } : {}),
      ...(e.network === 'httpupgrade' ? { 'v2ray-http-upgrade': true } : {}),
    };
  if (e.network === 'grpc') p['grpc-opts'] = { 'grpc-service-name': e.serviceName ?? '' };
  if (e.network === 'xhttp')
    p['xhttp-opts'] = {
      path: e.path ?? '/',
      ...(e.host ? { host: e.host } : {}),
      ...(e.mode ? { mode: e.mode } : {}),
    };
  return p;
}

const SANDBOX_DNS = ADDR.dns;

/**
 * A complete engine configuration for ONE endpoint (an imported test link),
 * listening on `port`; the engine is the endpoint's own unless one is named.
 */
export function configForEndpoint(
  e: Endpoint,
  port: number,
  engine: Engine = engineFor(e),
): { engine: Engine; config: string } {
  if (engine === 'singbox' && e.network === 'xhttp')
    throw new Error('sing-box has no XHTTP transport');
  if (engine === 'singbox')
    return {
      engine,
      config: JSON.stringify({
        log: { level: 'warn' },
        dns: { servers: [{ type: 'udp', tag: 'ec-dns', server: SANDBOX_DNS }], final: 'ec-dns' },
        inbounds: [{ type: 'mixed', tag: 'in', listen: '127.0.0.1', listen_port: port }],
        outbounds: [singboxOutbound(e, 'test-link')],
        route: { final: 'test-link', default_domain_resolver: 'ec-dns' },
      }),
    };
  return {
    engine,
    config: YAML.stringify({
      ...MIHOMO_SANDBOX(port),
      proxies: [mihomoProxy(e, 'test-link')],
      rules: ['MATCH,test-link'],
    }),
  };
}

/** The sandbox half of a Mihomo config: a local listener, the network's resolver, nothing else. */
const MIHOMO_SANDBOX = (port: number) => ({
  'mixed-port': port,
  'allow-lan': false,
  'bind-address': '127.0.0.1',
  mode: 'rule',
  'log-level': 'warning',
  ipv6: false,
  'geodata-mode': false,
  'geo-auto-update': false,
  dns: {
    enable: true,
    ipv6: false,
    'enhanced-mode': 'redir-host',
    'default-nameserver': [SANDBOX_DNS],
    nameserver: [SANDBOX_DNS],
    'proxy-server-nameserver': [SANDBOX_DNS],
  },
});

/** The proxies of a served body, in either format: what FCP rendered. */
export function servedEntries(
  engine: Engine,
  body: string,
): Array<{ name: string; server: string; port: number; raw: Record<string, unknown> }> {
  if (engine === 'singbox') {
    const c = JSON.parse(body) as { outbounds?: Array<Record<string, unknown>> };
    return (c.outbounds ?? [])
      .filter((o) => typeof o.server === 'string' && typeof o.server_port === 'number')
      .map((o) => ({
        name: String(o.tag),
        server: String(o.server),
        port: Number(o.server_port),
        raw: o,
      }));
  }
  const c = YAML.parse(body) as { proxies?: Array<Record<string, unknown>> };
  return (c.proxies ?? []).map((p) => ({
    name: String(p.name),
    server: String(p.server),
    port: Number(p.port),
    raw: p,
  }));
}

/**
 * A served body adapted to the sandbox, `pick` (an entry's name) carrying the
 * test's request. Returns the config and the local listener's port.
 */
export function sandboxServed(
  engine: Engine,
  body: string,
  pick: string,
): { config: string; port: number } {
  if (engine === 'singbox') {
    const c = JSON.parse(body);
    c.inbounds = (c.inbounds ?? []).filter((i: { type: string }) => i.type !== 'tun');
    const mixed = c.inbounds.find((i: { type: string }) => i.type === 'mixed');
    if (!mixed) throw new Error('the served sing-box body has no mixed listener');
    if (c.dns?.servers)
      c.dns.servers = c.dns.servers.map((s: { type: string; tag: string }) =>
        ['udp', 'tcp', 'tls', 'https', 'quic', 'h3'].includes(s.type)
          ? { type: 'udp', tag: s.tag, server: SANDBOX_DNS }
          : s,
      );
    c.route = { ...(c.route ?? {}), final: pick };
    return { config: JSON.stringify(c), port: Number(mixed.listen_port) };
  }
  const c = YAML.parse(body) as Record<string, unknown>;
  const port = 7890;
  const out: Record<string, unknown> = {
    ...MIHOMO_SANDBOX(port),
    proxies: c.proxies,
    'proxy-groups': c['proxy-groups'],
    rules: [`MATCH,${pick}`],
  };
  return { config: YAML.stringify(out), port };
}
