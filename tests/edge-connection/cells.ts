/**
 * The cases behind the supported matrix (tests/compat/manifest.ts `edgeMatrix`):
 * for every cell a harness node serves, where it comes from and how the node
 * serves it. The member test proves each `tested` cell of the manifest with
 * the case named here and refuses a tested cell without one, so a claim
 * cannot outlive its proof.
 *
 * Two kinds of node serve them:
 *  - ENROLLED nodes (the node role's contract): FCP builds the profile from the
 *    node's connection mode, one transport per node;
 *  - OPERATOR nodes: a panel node serving a profile the operator wrote, which
 *    FCP discovers and fronts. Xray terminates TLS itself on every TLS
 *    transport, with the per-run certificate for `EC_TLS_NAME` that also
 *    covers the fake CDN zone (what an origin certificate for a zone does).
 *    The L4 operator node serves eight transports (the most one guided setup
 *    fronts); the L7 operator node serves the HTTP transports on the ports a
 *    CDN dials, gRPC on 443 (the only port a CDN proxies gRPC to).
 *
 * Fixture values only: RFC 5737 addresses, `*.example` names.
 */
import { readFileSync } from 'node:fs';
import { edgeCellKey, edgeMatrix, type EdgeEngine } from '../compat/manifest';
import { ADDR } from './stack';

export type OperatorNode = 'l4m' | 'l7m';
export type EnrolledNode = 'reality' | 'xhttpReality' | 'ws';

export interface OperatorInbound {
  tag: string;
  node: OperatorNode;
  protocol: 'vless' | 'trojan' | 'shadowsocks';
  network: 'raw' | 'ws' | 'httpupgrade' | 'grpc' | 'xhttp';
  security: 'tls' | 'none';
  port: number;
  /** The path (ws, httpupgrade, xhttp) or the gRPC service name. */
  path?: string;
  serviceName?: string;
  /** XHTTP's mode; a CDN passes `packet-up` in both directions. */
  mode?: string;
  /** What the node's TLS offers: one protocol per transport, as the front dials it. */
  alpn?: string[];
}

export const OPERATOR_INBOUNDS: OperatorInbound[] = [
  // L4: every transport behind a TCP forwarder, on the node's public ports.
  {
    tag: 'M4_VLESS_TLS',
    node: 'l4m',
    protocol: 'vless',
    network: 'raw',
    security: 'tls',
    port: 8443,
    alpn: ['http/1.1'],
  },
  {
    tag: 'M4_VLESS_WS',
    node: 'l4m',
    protocol: 'vless',
    network: 'ws',
    security: 'tls',
    port: 8444,
    path: '/m4ws',
    alpn: ['http/1.1'],
  },
  {
    tag: 'M4_VLESS_HU',
    node: 'l4m',
    protocol: 'vless',
    network: 'httpupgrade',
    security: 'tls',
    port: 8445,
    path: '/m4hu',
    alpn: ['http/1.1'],
  },
  {
    tag: 'M4_VLESS_GRPC',
    node: 'l4m',
    protocol: 'vless',
    network: 'grpc',
    security: 'tls',
    port: 8446,
    serviceName: 'm4grpc',
    alpn: ['h2'],
  },
  {
    tag: 'M4_VLESS_XHTTP',
    node: 'l4m',
    protocol: 'vless',
    network: 'xhttp',
    security: 'tls',
    port: 8447,
    path: '/m4xh',
    mode: 'auto',
    alpn: ['h2', 'http/1.1'],
  },
  {
    tag: 'M4_TROJAN_TLS',
    node: 'l4m',
    protocol: 'trojan',
    network: 'raw',
    security: 'tls',
    port: 8448,
    alpn: ['http/1.1'],
  },
  {
    tag: 'M4_TROJAN_WS',
    node: 'l4m',
    protocol: 'trojan',
    network: 'ws',
    security: 'tls',
    port: 8449,
    path: '/m4tw',
    alpn: ['http/1.1'],
  },
  {
    tag: 'M4_SS',
    node: 'l4m',
    protocol: 'shadowsocks',
    network: 'raw',
    security: 'none',
    port: 8388,
  },
  // L7: the HTTP transports a CDN carries, on ports it dials.
  {
    tag: 'M7_VLESS_HU',
    node: 'l7m',
    protocol: 'vless',
    network: 'httpupgrade',
    security: 'tls',
    port: 2053,
    path: '/m7hu',
    alpn: ['http/1.1'],
  },
  {
    tag: 'M7_VLESS_GRPC',
    node: 'l7m',
    protocol: 'vless',
    network: 'grpc',
    security: 'tls',
    port: 443,
    serviceName: 'm7grpc',
    alpn: ['h2'],
  },
  {
    tag: 'M7_VLESS_XHTTP',
    node: 'l7m',
    protocol: 'vless',
    network: 'xhttp',
    security: 'tls',
    port: 2083,
    path: '/m7xh',
    mode: 'packet-up',
    alpn: ['h2', 'http/1.1'],
  },
  {
    tag: 'M7_TROJAN_WS',
    node: 'l7m',
    protocol: 'trojan',
    network: 'ws',
    security: 'tls',
    port: 2087,
    path: '/m7tw',
    alpn: ['http/1.1'],
  },
];

export const OPERATOR_NODES: Record<
  OperatorNode,
  { name: string; mode: string; edge: string; origin: string }
> = {
  l4m: { name: 'ec-l4m', mode: 'ec-l4-matrix', ...ADDR.l4Matrix },
  l7m: { name: 'ec-l7m', mode: 'ec-l7-matrix', ...ADDR.l7Matrix },
};

/** The listener catalogue's stream name for an Xray network. */
const STREAM: Record<OperatorInbound['network'], string> = {
  raw: 'raw',
  ws: 'ws',
  httpupgrade: 'httpupgrade',
  grpc: 'grpc',
  xhttp: 'xhttp',
};

/** Who proves one tested cell: an enrolled node of a mode, or an operator inbound. */
export type CellCase =
  | { kind: 'enrolled'; node: EnrolledNode }
  | { kind: 'operator'; inbound: OperatorInbound }
  /** The Outline server origin (its member's `ss://` key, the `outline` column). */
  | { kind: 'outline' };

const ENROLLED_BY_MODE: Record<string, EnrolledNode> = {
  'freedom-reality': 'reality',
  'freedom-xhttp': 'xhttpReality',
  'freedom-ws': 'ws',
};

export interface TestedCell {
  key: string;
  layer: 'l4' | 'l7';
  /** `outline`: an Outline key, run in the reference sing-box's Shadowsocks. */
  engines: Array<EdgeEngine | 'outline'>;
  case: CellCase;
}

/**
 * Every tested cell of the manifest with its case. Throws for a tested cell no
 * harness node serves (the claim has no proof) and for an operator inbound no
 * tested cell names (a proof of nothing the matrix claims).
 */
export function testedCells(): TestedCell[] {
  const out: TestedCell[] = [];
  const used = new Set<string>();
  for (const cell of edgeMatrix) {
    const key = edgeCellKey(cell);
    if (cell.outline === 'tested')
      out.push({ key, layer: cell.layer, engines: ['outline'], case: { kind: 'outline' } });
    const engines = (Object.keys(cell.engines) as EdgeEngine[]).filter(
      (e) => cell.engines[e] === 'tested',
    );
    if (engines.length === 0) continue;
    let c: CellCase | null = null;
    if (cell.source && typeof cell.source === 'object') {
      const node = ENROLLED_BY_MODE[cell.source.mode];
      if (node) c = { kind: 'enrolled', node };
    } else if (cell.source === 'operator') {
      const inbound = OPERATOR_INBOUNDS.find(
        (i) =>
          (i.node === 'l4m') === (cell.layer === 'l4') &&
          i.protocol === cell.protocol &&
          STREAM[i.network] === cell.streamTransport &&
          i.security === cell.security,
      );
      if (inbound) {
        c = { kind: 'operator', inbound };
        used.add(inbound.tag);
      }
    }
    if (!c) throw new Error(`the matrix claims ${key} but no harness node serves it`);
    out.push({ key, layer: cell.layer, engines, case: c });
  }
  for (const i of OPERATOR_INBOUNDS)
    if (!used.has(i.tag)) throw new Error(`${i.tag} proves no cell the matrix claims`);
  return out;
}

const PKI = '.cache/edge-connection-test/pki';

/**
 * The operator's Xray profile for one node: every inbound of the node, Xray
 * terminating TLS with the per-run certificate (inline, as an operator pastes
 * it), clients managed by the panel.
 */
export function operatorProfile(node: OperatorNode, tlsName: string): Record<string, unknown> {
  const certificate = readFileSync(`${PKI}/matrix.pem`, 'utf8').trim().split('\n');
  const key = readFileSync(`${PKI}/matrix-key.pem`, 'utf8').trim().split('\n');
  const inbounds = OPERATOR_INBOUNDS.filter((i) => i.node === node).map((i) => {
    const stream: Record<string, unknown> = { network: i.network };
    if (i.network === 'ws') stream.wsSettings = { path: i.path };
    if (i.network === 'httpupgrade') stream.httpupgradeSettings = { path: i.path };
    if (i.network === 'grpc') stream.grpcSettings = { serviceName: i.serviceName };
    if (i.network === 'xhttp') stream.xhttpSettings = { path: i.path, mode: i.mode };
    if (i.security === 'tls') {
      stream.security = 'tls';
      stream.tlsSettings = {
        serverName: tlsName,
        alpn: i.alpn,
        certificates: [{ certificate, key }],
      };
    }
    return {
      tag: i.tag,
      listen: '0.0.0.0',
      port: i.port,
      protocol: i.protocol,
      settings:
        i.protocol === 'vless'
          ? { clients: [], decryption: 'none' }
          : i.protocol === 'shadowsocks'
            ? { clients: [], network: 'tcp,udp' }
            : { clients: [] },
      streamSettings: stream,
    };
  });
  return {
    log: { loglevel: 'warning' },
    inbounds,
    outbounds: [{ protocol: 'freedom', tag: 'DIRECT' }],
  };
}
