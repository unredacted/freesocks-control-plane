/**
 * Synthetic subscription bodies for the admin render preview: one template
 * entry per slot remark, in the format a client family receives and for the
 * slot's own PROTOCOL, with EXAMPLE parameters (RFC 5737 origin, placeholder
 * key). The preview shows the operator exactly how the renderer rewrites the
 * address, the port, the server name and the HTTP Host for that protocol,
 * without touching a real member's subscription.
 *
 * Clash has no `httpupgrade` network: mihomo carries an HTTP-Upgrade inbound as
 * `network: ws`, so the Clash fixture for it is the ws one (and the renderer
 * writes `ws-opts.headers.Host` exactly as for a ws slot).
 */
import type { SubscriptionFormat } from './clientFamilies';
import type { SlotProtocol } from './protocols';

const EXAMPLE_UUID = '00000000-0000-4000-8000-000000000000';
const EXAMPLE_ORIGIN = '192.0.2.10';
const EXAMPLE_PBK = 'EXAMPLE_PUBLIC_KEY_EXAMPLE_PUBLIC_KEY_EXAMPLE';
/** The name the template presents today (what the renderer replaces). */
const EXAMPLE_NAME = 'node.example';
const EXAMPLE_PATH = '/ws';
const EXAMPLE_SERVICE = 'GunService';

type Obj = Record<string, unknown>;

/** The link query string for one protocol (everything but the address/port/remark). */
function linkQuery(protocol: SlotProtocol): string {
  switch (protocol) {
    case 'reality':
      return `encryption=none&flow=xtls-rprx-vision&security=reality&sni=target.example&fp=chrome&pbk=${EXAMPLE_PBK}&sid=0123abcd&type=tcp`;
    case 'tls':
      return `encryption=none&security=tls&sni=${EXAMPLE_NAME}&fp=chrome&type=tcp`;
    case 'plain':
      return 'encryption=none&security=none&type=tcp';
    case 'ws':
      return `encryption=none&security=tls&sni=${EXAMPLE_NAME}&fp=chrome&type=ws&path=${encodeURIComponent(EXAMPLE_PATH)}&host=${EXAMPLE_NAME}`;
    case 'httpupgrade':
      return `encryption=none&security=tls&sni=${EXAMPLE_NAME}&fp=chrome&type=httpupgrade&path=${encodeURIComponent(EXAMPLE_PATH)}&host=${EXAMPLE_NAME}`;
    case 'grpc':
      return `encryption=none&security=tls&sni=${EXAMPLE_NAME}&fp=chrome&type=grpc&serviceName=${EXAMPLE_SERVICE}&authority=${EXAMPLE_NAME}&mode=gun`;
  }
}

/** The sing-box `tls` block for one protocol (absent for `plain`). */
function singboxTls(protocol: SlotProtocol): Obj | null {
  if (protocol === 'plain') return null;
  if (protocol === 'reality') {
    return {
      enabled: true,
      server_name: 'target.example',
      utls: { enabled: true, fingerprint: 'chrome' },
      reality: { enabled: true, public_key: EXAMPLE_PBK, short_id: '0123abcd' },
    };
  }
  return {
    enabled: true,
    server_name: EXAMPLE_NAME,
    utls: { enabled: true, fingerprint: 'chrome' },
  };
}

/** The sing-box `transport` block for one protocol (absent for the raw-TCP ones). */
function singboxTransport(protocol: SlotProtocol): Obj | null {
  switch (protocol) {
    case 'ws':
      return { type: 'ws', path: EXAMPLE_PATH, headers: { Host: EXAMPLE_NAME } };
    case 'httpupgrade':
      return { type: 'httpupgrade', path: EXAMPLE_PATH, host: EXAMPLE_NAME };
    case 'grpc':
      return { type: 'grpc', service_name: EXAMPLE_SERVICE };
    default:
      return null;
  }
}

/** The Clash proxy keys for one protocol (TLS name, network and its options). */
function clashTransportLines(protocol: SlotProtocol): string[] {
  switch (protocol) {
    case 'reality':
      return [
        '    tls: true',
        '    servername: target.example',
        '    client-fingerprint: chrome',
        '    network: tcp',
        '    reality-opts:',
        `      public-key: ${EXAMPLE_PBK}`,
        '      short-id: 0123abcd',
      ];
    case 'tls':
      return [
        '    tls: true',
        `    servername: ${EXAMPLE_NAME}`,
        '    client-fingerprint: chrome',
        '    network: tcp',
      ];
    case 'plain':
      return ['    network: tcp'];
    // Clash has no httpupgrade network: mihomo serves such an inbound as ws.
    case 'ws':
    case 'httpupgrade':
      return [
        '    tls: true',
        `    servername: ${EXAMPLE_NAME}`,
        '    client-fingerprint: chrome',
        '    network: ws',
        '    ws-opts:',
        `      path: ${EXAMPLE_PATH}`,
        '      headers:',
        `        Host: ${EXAMPLE_NAME}`,
      ];
    case 'grpc':
      return [
        '    tls: true',
        `    servername: ${EXAMPLE_NAME}`,
        '    client-fingerprint: chrome',
        '    network: grpc',
        '    grpc-opts:',
        `      grpc-service-name: ${EXAMPLE_SERVICE}`,
      ];
  }
}

export function previewBody(
  format: SubscriptionFormat,
  remarks: readonly string[],
  protocol: SlotProtocol = 'reality',
): string {
  const names = remarks.length > 0 ? remarks : ['node-relay-a'];
  switch (format) {
    case 'links':
      return names
        .map(
          (r) =>
            `vless://${EXAMPLE_UUID}@${EXAMPLE_ORIGIN}:443?${linkQuery(protocol)}#${encodeURIComponent(r)}`,
        )
        .join('\n');
    case 'singbox-json': {
      const tls = singboxTls(protocol);
      const transport = singboxTransport(protocol);
      return JSON.stringify(
        {
          outbounds: [
            { type: 'selector', tag: 'proxy', outbounds: [...names, 'direct'], default: names[0] },
            ...names.map((r) => ({
              type: 'vless',
              tag: r,
              server: EXAMPLE_ORIGIN,
              server_port: 443,
              uuid: EXAMPLE_UUID,
              ...(protocol === 'reality' ? { flow: 'xtls-rprx-vision' } : {}),
              ...(tls ? { tls } : {}),
              ...(transport ? { transport } : {}),
            })),
            { type: 'direct', tag: 'direct' },
          ],
        },
        null,
        2,
      );
    }
    case 'clash-yaml':
      return [
        'proxies:',
        ...names.flatMap((r) => [
          `  - name: "${r}"`,
          '    type: vless',
          `    server: ${EXAMPLE_ORIGIN}`,
          '    port: 443',
          `    uuid: ${EXAMPLE_UUID}`,
          ...(protocol === 'reality' ? ['    flow: xtls-rprx-vision'] : []),
          ...clashTransportLines(protocol),
        ]),
        'proxy-groups:',
        '  - name: PROXY',
        '    type: select',
        '    proxies:',
        ...names.map((r) => `      - "${r}"`),
      ].join('\n');
  }
}
