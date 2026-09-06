/**
 * Synthetic subscription bodies for the admin render preview: one template
 * entry per slot remark in the format a client family receives, with EXAMPLE
 * REALITY parameters (RFC 5737 origin, placeholder key). The preview shows the
 * operator exactly how the renderer rewrites entries for a family without
 * touching a real member's subscription.
 */
import type { SubscriptionFormat } from './clientFamilies';

const EXAMPLE_UUID = '00000000-0000-4000-8000-000000000000';
const EXAMPLE_ORIGIN = '192.0.2.10';
const EXAMPLE_PBK = 'EXAMPLE_PUBLIC_KEY_EXAMPLE_PUBLIC_KEY_EXAMPLE';

export function previewBody(format: SubscriptionFormat, remarks: readonly string[]): string {
  const names = remarks.length > 0 ? remarks : ['node-relay-a'];
  switch (format) {
    case 'links':
      return names
        .map(
          (r) =>
            `vless://${EXAMPLE_UUID}@${EXAMPLE_ORIGIN}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=target.example&fp=chrome&pbk=${EXAMPLE_PBK}&sid=0123abcd&type=tcp#${encodeURIComponent(r)}`,
        )
        .join('\n');
    case 'singbox-json':
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
              flow: 'xtls-rprx-vision',
              tls: {
                enabled: true,
                server_name: 'target.example',
                utls: { enabled: true, fingerprint: 'chrome' },
                reality: { enabled: true, public_key: EXAMPLE_PBK, short_id: '0123abcd' },
              },
            })),
            { type: 'direct', tag: 'direct' },
          ],
        },
        null,
        2,
      );
    case 'clash-yaml':
      return [
        'proxies:',
        ...names.flatMap((r) => [
          `  - name: "${r}"`,
          '    type: vless',
          `    server: ${EXAMPLE_ORIGIN}`,
          '    port: 443',
          `    uuid: ${EXAMPLE_UUID}`,
          '    flow: xtls-rprx-vision',
          '    tls: true',
          '    servername: target.example',
          '    client-fingerprint: chrome',
          '    reality-opts:',
          `      public-key: ${EXAMPLE_PBK}`,
          '      short-id: 0123abcd',
        ]),
        'proxy-groups:',
        '  - name: PROXY',
        '    type: select',
        '    proxies:',
        ...names.map((r) => `      - "${r}"`),
      ].join('\n');
  }
}
