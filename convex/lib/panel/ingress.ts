/**
 * A front node's declared ingress (pure). The WebSocket inbound of the
 * bootstrap profile listens on loopback: the node's public address never
 * reaches it, and discovery rightly refuses it (`loopback`). What reaches it is
 * Caddy on the node, terminating TLS on the public port with the origin
 * hostname's certificate and proxying the path. Only the machine side can
 * describe that hop, so the node's intent carries it, versioned, and
 * `applyIngress` turns the loopback inbound into what the world sees: TLS on
 * the external port, the origin hostname as its certificate name, the same
 * path. The origin probe then verifies that external hop exactly as it does
 * for any HTTPS origin; nothing here asserts that the hop works.
 */
import type { PanelInbound } from '../backends/types';

export interface IngressInternal {
  inboundTag: string;
  listen: string;
  port: number;
  path: string;
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
 * Rewrite each loopback inbound that the ingress maps into the externally
 * visible listener. An inbound without a mapping (or one whose declared
 * internal port or path disagree with the panel) is returned unchanged, so it
 * still fails discovery as `loopback`: a stale declaration never promotes an
 * inbound it does not describe.
 */
export function applyIngress(
  inbounds: readonly PanelInbound[],
  ingress: IngressMapping | null | undefined,
): PanelInbound[] {
  if (!ingress) return [...inbounds];
  const byTag = new Map(ingress.internal.map((i) => [i.inboundTag, i]));
  return inbounds.map((ib) => {
    const m = byTag.get(ib.tag);
    if (!m || !isLoopback(ib.listen) || ib.port !== m.port) return ib;
    const path = ib.ws?.path ?? ib.httpupgrade?.path ?? ib.xhttp?.path ?? null;
    if (path !== m.path) return ib;
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
  routes: { path: string; port: number }[];
} {
  return {
    hostname: ingress.hostname,
    externalPort: ingress.external.port,
    routes: ingress.internal.map((i) => ({ path: i.path, port: i.port })),
  };
}
