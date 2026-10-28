/** Versioned test inputs, not a claim that a GUI sharing an engine was tested. */
export const artifacts = {
  singbox: {
    repo: 'SagerNet/sing-box',
    version: '1.14.0',
    asset: 'sing-box-1.14.0-linux-amd64.tar.gz',
    sha256: '2375de6999f4f56ab46b4fc5ddf26a6aba1d3e61a0f4e7ddec2f4690457d5f63',
  },
  mihomo: {
    repo: 'MetaCubeX/mihomo',
    version: '1.19.30',
    asset: 'mihomo-linux-amd64-v1.19.30.gz',
    sha256: 'cf06ce2c7d1421bdbda14ee4a5b6046672dc35ebf8eecd8e77504ec3c0ed9a84',
  },
  sfl: {
    repo: 'SagerNet/sing-box',
    version: '1.14.0',
    asset: 'SFL-1.14.0-amd64.deb',
    sha256: '8502e0c7aafbc7af03d8ddfbeb5b8de7f4c0b9cbe6ee3c19038a57b4c12e1a0e',
  },
} as const;

export type Format = 'singbox' | 'mihomo' | 'links' | 'outline';
export interface CompatibilityClient {
  name: string;
  format: Format;
  /** Regression/contract inputs; only SFL is captured from a pinned package. */
  userAgents: string[];
  application: 'automated-sfl' | 'manual';
  limitation: string;
}
export const clients: CompatibilityClient[] = [
  {
    name: 'sing-box',
    format: 'singbox',
    userAgents: [
      'SFL (sing-box 1.14.0; language en_US)',
      'SFL (sing-box 1.14.0; language zh_CN)',
      'SFW (sing-box 1.14.0; language en_US)',
      'SFL/1.14.0',
      'SFA/1.14.0',
      'SFI/1.14.0',
      'SFM/1.14.0',
    ],
    application: 'automated-sfl',
    limitation:
      'SFL package import/refresh automated on Linux; other shells require device verification.',
  },
  {
    name: 'Hiddify',
    format: 'links',
    userAgents: ['Hiddify/2.0'],
    application: 'manual',
    limitation:
      'Subscription contract only; bundled parser, engine and GUI need device verification.',
  },
  {
    name: 'Karing',
    format: 'singbox',
    userAgents: ['Karing/1.0'],
    application: 'manual',
    limitation:
      'Contract plus reference sing-box engine; bundled engine, HWID and GUI require device verification.',
  },
  {
    name: 'Anywhere',
    format: 'links',
    userAgents: ['Anywhere/1.0'],
    application: 'manual',
    limitation: 'Apple hardware and installed App Store build required.',
  },
  {
    name: 'v2rayNG',
    format: 'links',
    userAgents: ['v2rayNG/1.8.29'],
    application: 'manual',
    limitation: 'Android application and bundled Xray engine require device verification.',
  },
  {
    name: 'v2rayN',
    format: 'links',
    userAgents: ['v2rayN/7.0'],
    application: 'manual',
    limitation: 'Application and bundled Xray engine require device verification.',
  },
  {
    name: 'Clash',
    format: 'mihomo',
    userAgents: ['Clash-Verge/v2.0'],
    application: 'manual',
    limitation:
      'Contract plus reference Mihomo engine; packaged application requires device verification.',
  },
  {
    name: 'FlClash',
    format: 'mihomo',
    // Default UA built by v0.9.2 lib/common/package.dart; custom UAs remain possible.
    // https://github.com/chen08209/FlClash/blob/v0.9.2/lib/common/package.dart
    userAgents: [
      'FlClash/v0.9.2 clash-verge Platform/linux',
      'FlClash/v0.9.2 clash-verge Platform/android',
      'FlClash/v0.9.2 clash-verge Platform/windows',
      'FlClash/v0.9.2 clash-verge Platform/macos',
      'FlClash/0.8',
    ],
    application: 'manual',
    limitation:
      'Contract plus reference Mihomo engine; packaged application requires device verification.',
  },
  {
    name: 'Mihomo Party',
    format: 'mihomo',
    userAgents: ['mihomo/1.19.30'],
    application: 'manual',
    limitation:
      'Contract plus reference Mihomo engine; packaged application requires device verification.',
  },
  {
    name: 'Throne',
    format: 'links',
    userAgents: ['Throne/1.0'],
    application: 'manual',
    limitation:
      'Subscription contract only; packaged application and HWID require device verification.',
  },
  {
    name: 'Shadowrocket',
    format: 'links',
    userAgents: ['Shadowrocket/2.2'],
    application: 'manual',
    limitation: 'Licensed iOS application on Apple hardware required.',
  },
  {
    name: 'Outline',
    format: 'outline',
    userAgents: [],
    application: 'manual',
    limitation:
      'Static ss:// key contract only; Outline application and Shadowsocks transport require device verification.',
  },
];

/**
 * THE SUPPORTED MATRIX of edge-fronted delivery (docs/edges.md "Supported
 * matrix", rendered from this list and pinned to it by
 * convex/edgeMatrix.test.ts): what a member's client can reach through an L4
 * or an L7 edge, per protocol × transport × security × layer × client format.
 *
 * A `tested` cell is a claim only because a real connection test proves it:
 * `bun run test:integration:edge-connection` takes a real node through the
 * real lifecycle, fetches the member's real `/api/v1/sub` body in that format,
 * and the pinned reference engine (sing-box or Mihomo, `artifacts` above)
 * fetches a page through the edge with it (tests/edge-connection/cells.ts maps
 * every tested cell to its case, and the harness refuses a cell without one).
 * Everything else names why it is not offered.
 */
/** The reference engines a served body runs in (the subscription formats with an engine). */
export type EdgeEngine = 'singbox' | 'mihomo';
export type EdgeCellVerdict = 'tested' | { unsupported: string };
export interface EdgeMatrixCell {
  protocol: 'vless' | 'trojan' | 'shadowsocks' | 'hysteria2' | 'tuic';
  streamTransport: 'raw' | 'ws' | 'httpupgrade' | 'grpc' | 'xhttp' | 'udp';
  security: 'none' | 'tls' | 'reality';
  layer: 'l4' | 'l7';
  /**
   * Where the node's transport comes from: a connection mode FCP builds the
   * profile for (the node role enrolls the node), or an operator's own profile
   * FCP discovers on a panel node. Null for a cell nothing serves.
   */
  source: { mode: string } | 'operator' | null;
  engines: Record<EdgeEngine, EdgeCellVerdict>;
  /**
   * An Outline access key (`ss://`, delivered as the dynamic `ssconf://` key)
   * from an Outline server origin: Shadowsocks rows only, connected with the
   * Shadowsocks of the reference sing-box (what an Outline client speaks).
   */
  outline?: EdgeCellVerdict;
}

const NO_SINGBOX_XHTTP: EdgeCellVerdict = {
  unsupported: 'sing-box has no XHTTP transport (the panel leaves the entry out of its body)',
};
const both: Record<EdgeEngine, EdgeCellVerdict> = { singbox: 'tested', mihomo: 'tested' };
const none = (reason: string): Record<EdgeEngine, EdgeCellVerdict> => ({
  singbox: { unsupported: reason },
  mihomo: { unsupported: reason },
});
const NOT_HTTP = 'not an HTTP transport: a CDN front carries HTTP only';
const NODE_TERMINATES = 'REALITY terminates on the node: a CDN front would have to terminate it';
const NO_UDP =
  'UDP: no edge adapter forwards UDP yet (docs/edges.md "UDP"); served direct, never fronted';

export const edgeMatrix: EdgeMatrixCell[] = [
  // L4: a TCP forwarder carries the member's bytes untouched to the node.
  {
    protocol: 'vless',
    streamTransport: 'raw',
    security: 'reality',
    layer: 'l4',
    source: { mode: 'freedom-reality' },
    engines: both,
  },
  {
    protocol: 'vless',
    streamTransport: 'xhttp',
    security: 'reality',
    layer: 'l4',
    source: { mode: 'freedom-xhttp' },
    engines: { singbox: NO_SINGBOX_XHTTP, mihomo: 'tested' },
  },
  {
    protocol: 'vless',
    streamTransport: 'raw',
    security: 'tls',
    layer: 'l4',
    source: 'operator',
    engines: both,
  },
  {
    protocol: 'vless',
    streamTransport: 'ws',
    security: 'tls',
    layer: 'l4',
    source: 'operator',
    engines: both,
  },
  {
    protocol: 'vless',
    streamTransport: 'httpupgrade',
    security: 'tls',
    layer: 'l4',
    source: 'operator',
    engines: both,
  },
  {
    protocol: 'vless',
    streamTransport: 'grpc',
    security: 'tls',
    layer: 'l4',
    source: 'operator',
    engines: both,
  },
  {
    protocol: 'vless',
    streamTransport: 'xhttp',
    security: 'tls',
    layer: 'l4',
    source: 'operator',
    engines: { singbox: NO_SINGBOX_XHTTP, mihomo: 'tested' },
  },
  {
    protocol: 'trojan',
    streamTransport: 'raw',
    security: 'tls',
    layer: 'l4',
    source: 'operator',
    engines: both,
  },
  {
    protocol: 'trojan',
    streamTransport: 'ws',
    security: 'tls',
    layer: 'l4',
    source: 'operator',
    engines: both,
  },
  {
    protocol: 'shadowsocks',
    streamTransport: 'raw',
    security: 'none',
    layer: 'l4',
    source: 'operator',
    engines: both,
    outline: 'tested',
  },
  {
    protocol: 'hysteria2',
    streamTransport: 'udp',
    security: 'tls',
    layer: 'l4',
    source: null,
    engines: none(NO_UDP),
  },
  {
    protocol: 'tuic',
    streamTransport: 'udp',
    security: 'tls',
    layer: 'l4',
    source: null,
    engines: none(NO_UDP),
  },
  // L7: a CDN terminates TLS and proxies HTTP to the node's own TLS.
  {
    protocol: 'vless',
    streamTransport: 'ws',
    security: 'tls',
    layer: 'l7',
    source: { mode: 'freedom-ws' },
    engines: both,
  },
  {
    protocol: 'vless',
    streamTransport: 'httpupgrade',
    security: 'tls',
    layer: 'l7',
    source: 'operator',
    engines: both,
  },
  {
    protocol: 'vless',
    streamTransport: 'grpc',
    security: 'tls',
    layer: 'l7',
    source: 'operator',
    engines: both,
  },
  {
    protocol: 'vless',
    streamTransport: 'xhttp',
    security: 'tls',
    layer: 'l7',
    source: 'operator',
    engines: { singbox: NO_SINGBOX_XHTTP, mihomo: 'tested' },
  },
  {
    protocol: 'trojan',
    streamTransport: 'ws',
    security: 'tls',
    layer: 'l7',
    source: 'operator',
    engines: both,
  },
  {
    protocol: 'vless',
    streamTransport: 'raw',
    security: 'reality',
    layer: 'l7',
    source: null,
    engines: none(NODE_TERMINATES),
  },
  {
    protocol: 'vless',
    streamTransport: 'xhttp',
    security: 'reality',
    layer: 'l7',
    source: null,
    engines: none(NODE_TERMINATES),
  },
  {
    protocol: 'vless',
    streamTransport: 'raw',
    security: 'tls',
    layer: 'l7',
    source: null,
    engines: none(NOT_HTTP),
  },
  {
    protocol: 'trojan',
    streamTransport: 'raw',
    security: 'tls',
    layer: 'l7',
    source: null,
    engines: none(NOT_HTTP),
  },
  {
    protocol: 'shadowsocks',
    streamTransport: 'raw',
    security: 'none',
    layer: 'l7',
    source: null,
    engines: none(NOT_HTTP),
    outline: { unsupported: NOT_HTTP },
  },
  {
    protocol: 'hysteria2',
    streamTransport: 'udp',
    security: 'tls',
    layer: 'l7',
    source: null,
    engines: none(NO_UDP),
  },
  {
    protocol: 'tuic',
    streamTransport: 'udp',
    security: 'tls',
    layer: 'l7',
    source: null,
    engines: none(NO_UDP),
  },
];

/** What is outside the matrix altogether, and why (docs/edges.md lists these under the table). */
export const edgeMatrixUnsupported: Array<{ what: string; reason: string }> = [
  { what: 'VMess', reason: 'no renderer codec; not in the listener catalogue' },
  {
    what: 'Xray JSON subscriptions',
    reason:
      'the renderer rewrites share links, sing-box JSON and Clash/Mihomo YAML; an Xray JSON body is refused (`unsupported_format`), never served with the origin in it',
  },
  {
    what: 'Outline keys over WebSocket (WSS dynamic keys)',
    reason:
      'an Outline origin is a plain Shadowsocks key rewritten by address; there is no WebSocket form to front',
  },
  { what: 'sing-box over XHTTP', reason: 'sing-box has no XHTTP transport' },
];

/** `protocol/streamTransport/security@layer`: the stable key of a matrix cell. */
export const edgeCellKey = (
  c: Pick<EdgeMatrixCell, 'protocol' | 'streamTransport' | 'security' | 'layer'>,
) => `${c.protocol}/${c.streamTransport}/${c.security}@${c.layer}`;
