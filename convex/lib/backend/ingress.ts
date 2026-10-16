/**
 * A front node's declared ingress (pure). The WebSocket transport of the
 * bootstrap profile listens on loopback: the node's public address never
 * reaches it, and discovery rightly refuses it (`loopback`). What reaches it is
 * Caddy on the node, terminating TLS on the public port with the origin
 * hostname's certificate and proxying the path. Only the machine side can
 * describe that hop, so the node's intent carries it, versioned, and
 * `applyIngress` turns the loopback transport into what the world sees: TLS on
 * the external port, the origin hostname as its certificate name, the same
 * path. The origin probe then verifies that external hop exactly as it does
 * for any HTTPS origin; nothing here asserts that the hop works.
 */
import type { BackendTransport } from '../backends/types';

export interface IngressInternal {
  inboundTag: string;
  listen: string;
  port: number;
  path: string;
  /**
   * How the terminator speaks to the transport: `h2c` (HTTP/2 cleartext) is
   * what a gRPC transport needs; absent = HTTP/1.1, which carries WebSocket,
   * HTTP Upgrade and XHTTP but never a gRPC stream.
   */
  upstream?: 'h2c';
}

export interface IngressMapping {
  /** The origin hostname Caddy holds a certificate for. */
  hostname: string;
  external: {
    port: number;
    tls: 'caddy';
    /** `any`: the catch-all site answers a foreign Host; `hostname`: only the origin name. */
    hostHeader: 'any' | 'hostname';
  };
  internal: IngressInternal[];
}

function isLoopback(listen: string | null | undefined): boolean {
  if (!listen) return false;
  const l = listen
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '');
  return l === 'localhost' || l === '::1' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(l);
}

/**
 * The route a gRPC transport is reached by: its service name as the path
 * prefix (`/<serviceName>`; the calls are `/<serviceName>/Tun` and
 * `/<serviceName>/TunMulti`), what the terminator proxies over HTTP/2.
 */
function grpcRoute(ib: BackendTransport): string | null {
  const name = ib.grpc?.serviceName?.trim();
  if (!name) return null;
  return name.startsWith('/') ? name : `/${name}`;
}

/**
 * Rewrite each loopback transport that the ingress maps into the externally
 * visible listener. A mapping names the transport by tag, internal port and
 * path (a gRPC transport's path is its service name, `grpcRoute`). A transport without a mapping (or one whose declared
 * internal port or path disagree with the backend) is returned unchanged, so it
 * still fails discovery as `loopback`: a stale declaration never promotes an
 * transport it does not describe.
 */
export function applyIngress(
  inbounds: readonly BackendTransport[],
  ingress: IngressMapping | null | undefined,
): BackendTransport[] {
  if (!ingress) return [...inbounds];
  const byTag = new Map(ingress.internal.map((i) => [i.inboundTag, i]));
  return inbounds.map((ib) => {
    const m = byTag.get(ib.tag);
    if (!m || !isLoopback(ib.listen) || ib.port !== m.port) return ib;
    const path = ib.ws?.path ?? ib.httpupgrade?.path ?? ib.xhttp?.path ?? grpcRoute(ib) ?? null;
    if (path !== m.path) return ib;
    // A gRPC stream crosses the terminator only over HTTP/2: a route the role
    // would proxy over HTTP/1.1 is not a way in, so the transport stays loopback.
    if ((ib.network === 'grpc' || ib.network === 'gun') && m.upstream !== 'h2c') return ib;
    if (ib.security !== 'none') return ib;
    return {
      ...ib,
      listen: null,
      port: ingress.external.port,
      security: 'tls',
      tls: { serverName: ingress.hostname },
    };
  });
}

/** What of the ingress is machine configuration (what the role renders Caddy from). */
export function ingressMachineFacts(ingress: IngressMapping): {
  hostname: string;
  externalPort: number;
  routes: IngressRoute[];
} {
  return {
    hostname: ingress.hostname,
    externalPort: ingress.external.port,
    routes: ingress.internal.map(ingressRoute),
  };
}

/** One route as the role renders it: the path, the loopback port, and `h2c` when the transport needs it. */
export interface IngressRoute {
  path: string;
  port: number;
  upstream?: 'h2c';
}

export function ingressRoute(i: IngressInternal): IngressRoute {
  return { path: i.path, port: i.port, ...(i.upstream ? { upstream: i.upstream } : {}) };
}
