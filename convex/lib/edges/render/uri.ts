/**
 * Generic proxy share-link codec: `scheme://userinfo@host:port[/path][?query][#fragment]`.
 * Covers vless://, trojan://, ss:// (SIP002, incl. the Outline `/?outline=1`
 * path), hysteria2:// / hy2:// and tuic://. Userinfo (a uuid, a password, the
 * SIP002 method:password blob, a `uuid:password` pair) is NEVER touched, nor is
 * anything that is the node's own routing (`path`, `serviceName`, `pbk`, `sid`,
 * `spx`, `fp`, `flow`, `security`, `type`, `encryption`, `congestion_control`).
 * Only the address, the port, the fragment (label), `sni`, `host` and
 * `authority` are rewritten, and only when the listener presents them.
 *
 * `vmess://` (a base64 JSON blob) has no codec here: it is left alone and
 * reported as unsupported by the matcher.
 */
import { bracketIfV6 } from '../ip';
import { codecFor, type ListenerProto } from '../protocols';

export interface ParsedUri {
  scheme: string;
  userinfo: string;
  host: string;
  port: number;
  path: string;
  params: URLSearchParams;
  fragment: string | null;
}

const URI_RE =
  /^([a-z0-9+.-]+):\/\/(?:([^@/?#]*)@)?(\[[^\]]+\]|[^:/?#]+):(\d{1,5})(\/[^?#]*)?(\?[^#]*)?(#.*)?$/i;

export function parseProxyUri(line: string): ParsedUri | null {
  const m = URI_RE.exec(line.trim());
  if (!m) return null;
  const [, scheme, userinfo, host, port, path, query, frag] = m;
  const p = Number(port);
  if (!Number.isInteger(p) || p < 1 || p > 65535) return null;
  return {
    scheme: scheme.toLowerCase(),
    userinfo: userinfo ?? '',
    host: host.replace(/^\[|\]$/g, ''),
    port: p,
    path: path ?? '',
    params: new URLSearchParams(query ? query.slice(1) : ''),
    fragment: frag && frag.length > 1 ? frag.slice(1) : null,
  };
}

export function fragmentText(u: ParsedUri): string | null {
  if (u.fragment === null) return null;
  try {
    return decodeURIComponent(u.fragment);
  } catch {
    return u.fragment;
  }
}

function serialize(u: ParsedUri, label: string | null): string {
  const q = u.params.toString();
  const user = u.userinfo ? `${u.userinfo}@` : '';
  return `${u.scheme}://${user}${bracketIfV6(u.host)}:${u.port}${u.path}${q ? `?${q}` : ''}${
    label !== null ? `#${encodeURIComponent(label)}` : ''
  }`;
}

/** Whether the link's scheme is one the codec rewrites for this listener. */
export function uriSupported(u: ParsedUri, proto: ListenerProto): boolean {
  return codecFor(proto, 'links').includes(u.scheme);
}

/**
 * Whether the link's own transport / security parameters agree with the
 * listener. A mismatch means the template describes a different inbound than
 * the listener claims (or the wrong listener matched): never rewrite it.
 */
export function uriAgrees(u: ParsedUri, proto: ListenerProto): boolean {
  const p = u.params;
  const type = (p.get('type') ?? 'tcp').toLowerCase();
  const stream = proto.streamTransport;
  const typeAgrees =
    stream === 'raw'
      ? type === 'tcp' || type === 'raw' || type === 'none'
      : stream === 'udp'
        ? true
        : type === stream;
  switch (proto.protocol) {
    case 'vless': {
      const security = (p.get('security') ?? 'none').toLowerCase();
      return typeAgrees && security === proto.security;
    }
    case 'trojan': {
      // Trojan links imply TLS; `security=none` would be a plaintext oddity we do not rewrite.
      const security = (p.get('security') ?? 'tls').toLowerCase();
      return typeAgrees && security === 'tls' && proto.security === 'tls';
    }
    case 'shadowsocks':
      return proto.security === 'none';
    case 'hysteria2':
    case 'tuic':
      return proto.security === 'tls';
  }
}

export interface UriTarget {
  address: string;
  port: number;
  sni: string | null;
  hostHeader?: string | null;
  label: string;
}

/**
 * Rewrite one link's host, port, label, SNI and HTTP Host. A null `sni` leaves
 * the line's own TLS parameters alone. `hostHeader` is written to `host=` for an
 * HTTP transport (always for `type=ws|httpupgrade`, otherwise only when the
 * template carried the parameter) and to `authority=` for `type=grpc` when the
 * template carried one.
 */
export function rewriteProxyUri(u: ParsedUri, target: UriTarget): string {
  const params = new URLSearchParams(u.params);
  const hostHeader = target.hostHeader ?? null;
  if (target.sni !== null) {
    params.set('sni', target.sni);
    // A listener with no Host of its own (REALITY / plain TLS) must still not
    // keep the template's `host=`: it would carry the origin's name.
    if (hostHeader === null && params.has('host')) params.set('host', target.sni);
  }
  if (hostHeader !== null) {
    const type = (params.get('type') ?? '').toLowerCase();
    if (params.has('host') || type === 'ws' || type === 'httpupgrade')
      params.set('host', hostHeader);
    if (type === 'grpc' && params.has('authority')) params.set('authority', hostHeader);
  }
  return serialize({ ...u, host: target.address, port: target.port, params }, target.label);
}
