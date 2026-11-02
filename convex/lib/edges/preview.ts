/**
 * Synthetic subscription bodies for the admin render preview: one template
 * entry per listener, in the format a client family receives and for what
 * the listener SPEAKS, with EXAMPLE parameters (RFC 5737 origin, placeholder
 * key). The preview shows the operator exactly how the renderer rewrites the
 * address, the port, the server name and the HTTP Host for that listener,
 * without touching a real member's subscription.
 *
 * Clash has no `httpupgrade` network: mihomo carries an HTTP-Upgrade transport as
 * `network: ws`, so the Clash fixture for it is the ws one.
 *
 * A listener a format cannot carry at all (sing-box has no XHTTP) gets no entry
 * in that format's sample (`previewSample`), as the panel builds none for it.
 */
import { RENDER_FORMAT_OF, type SubscriptionFormat } from './clientFamilies';
import { formatSupported, listenerCombo, type ListenerProto } from './protocols';
import type { ListenerMatch } from './render/types';

const EXAMPLE_UUID = '00000000-0000-4000-8000-000000000000';
const EXAMPLE_ORIGIN = '192.0.2.10';
const EXAMPLE_PBK = 'EXAMPLE_PUBLIC_KEY_EXAMPLE_PUBLIC_KEY_EXAMPLE';
/** The name the template presents today (what the renderer replaces). */
const EXAMPLE_NAME = 'node.example';
const EXAMPLE_PATH = '/ws';
const EXAMPLE_SERVICE = 'GunService';
const EXAMPLE_PASSWORD = 'example-password';
/** SIP002 userinfo: base64("chacha20-ietf-poly1305:example-password"). */
const EXAMPLE_SS_USERINFO = 'Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpleGFtcGxlLXBhc3N3b3Jk';

type Obj = Record<string, unknown>;

export const PREVIEW_DEFAULT_PROTO: ListenerProto = {
  protocol: 'vless',
  streamTransport: 'raw',
  security: 'reality',
};

function tlsQuery(p: ListenerProto): string {
  if (p.security === 'reality')
    return `security=reality&sni=target.example&fp=chrome&pbk=${EXAMPLE_PBK}&sid=0123abcd`;
  if (p.security === 'tls') return `security=tls&sni=${EXAMPLE_NAME}&fp=chrome`;
  return 'security=none';
}

function streamQuery(p: ListenerProto): string {
  switch (p.streamTransport) {
    case 'ws':
      return `type=ws&path=${encodeURIComponent(EXAMPLE_PATH)}&host=${EXAMPLE_NAME}`;
    case 'httpupgrade':
      return `type=httpupgrade&path=${encodeURIComponent(EXAMPLE_PATH)}&host=${EXAMPLE_NAME}`;
    case 'grpc':
      return `type=grpc&serviceName=${EXAMPLE_SERVICE}&authority=${EXAMPLE_NAME}&mode=gun`;
    case 'xhttp':
      return `type=xhttp&path=${encodeURIComponent(EXAMPLE_PATH)}&host=${EXAMPLE_NAME}&mode=packet-up`;
    default:
      return 'type=tcp';
  }
}

/** One share link for the listener (the link-list codec's input). */
function linkFor(p: ListenerProto, remark: string): string {
  const tag = `#${encodeURIComponent(remark)}`;
  switch (p.protocol) {
    case 'vless': {
      const flow = p.security === 'reality' ? '&flow=xtls-rprx-vision' : '';
      return `vless://${EXAMPLE_UUID}@${EXAMPLE_ORIGIN}:443?encryption=none${flow}&${tlsQuery(p)}&${streamQuery(p)}${tag}`;
    }
    case 'trojan':
      return `trojan://${EXAMPLE_PASSWORD}@${EXAMPLE_ORIGIN}:443?${tlsQuery(p)}&${streamQuery(p)}${tag}`;
    case 'shadowsocks':
      return `ss://${EXAMPLE_SS_USERINFO}@${EXAMPLE_ORIGIN}:8388${tag}`;
    case 'hysteria2':
      return `hysteria2://${EXAMPLE_PASSWORD}@${EXAMPLE_ORIGIN}:443?sni=${EXAMPLE_NAME}${tag}`;
    case 'tuic':
      return `tuic://${EXAMPLE_UUID}:${EXAMPLE_PASSWORD}@${EXAMPLE_ORIGIN}:443?sni=${EXAMPLE_NAME}&congestion_control=bbr${tag}`;
  }
}

function singboxTls(p: ListenerProto): Obj | null {
  if (p.security === 'none') return null;
  if (p.security === 'reality') {
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

function singboxTransport(p: ListenerProto): Obj | null {
  switch (p.streamTransport) {
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

function singboxOutbound(p: ListenerProto, remark: string): Obj {
  const tls = singboxTls(p);
  const transport = singboxTransport(p);
  switch (p.protocol) {
    case 'vless':
      return {
        type: 'vless',
        tag: remark,
        server: EXAMPLE_ORIGIN,
        server_port: 443,
        uuid: EXAMPLE_UUID,
        ...(p.security === 'reality' ? { flow: 'xtls-rprx-vision' } : {}),
        ...(tls ? { tls } : {}),
        ...(transport ? { transport } : {}),
      };
    case 'trojan':
      return {
        type: 'trojan',
        tag: remark,
        server: EXAMPLE_ORIGIN,
        server_port: 443,
        password: EXAMPLE_PASSWORD,
        ...(tls ? { tls } : {}),
        ...(transport ? { transport } : {}),
      };
    case 'shadowsocks':
      return {
        type: 'shadowsocks',
        tag: remark,
        server: EXAMPLE_ORIGIN,
        server_port: 8388,
        method: 'chacha20-ietf-poly1305',
        password: EXAMPLE_PASSWORD,
      };
    case 'hysteria2':
      return {
        type: 'hysteria2',
        tag: remark,
        server: EXAMPLE_ORIGIN,
        server_port: 443,
        password: EXAMPLE_PASSWORD,
        tls,
      };
    case 'tuic':
      return {
        type: 'tuic',
        tag: remark,
        server: EXAMPLE_ORIGIN,
        server_port: 443,
        uuid: EXAMPLE_UUID,
        password: EXAMPLE_PASSWORD,
        congestion_control: 'bbr',
        tls,
      };
  }
}

function clashTlsLines(p: ListenerProto): string[] {
  if (p.security === 'none') return [];
  if (p.security === 'reality')
    return [
      '    tls: true',
      '    servername: target.example',
      '    client-fingerprint: chrome',
      '    reality-opts:',
      `      public-key: ${EXAMPLE_PBK}`,
      '      short-id: 0123abcd',
    ];
  return ['    tls: true', `    servername: ${EXAMPLE_NAME}`, '    client-fingerprint: chrome'];
}

function clashStreamLines(p: ListenerProto): string[] {
  switch (p.streamTransport) {
    // Clash has no httpupgrade network: mihomo serves such a transport as ws.
    case 'ws':
    case 'httpupgrade':
      return [
        '    network: ws',
        '    ws-opts:',
        `      path: ${EXAMPLE_PATH}`,
        '      headers:',
        `        Host: ${EXAMPLE_NAME}`,
      ];
    case 'grpc':
      return ['    network: grpc', '    grpc-opts:', `      grpc-service-name: ${EXAMPLE_SERVICE}`];
    case 'xhttp':
      return [
        '    network: xhttp',
        '    xhttp-opts:',
        `      path: ${EXAMPLE_PATH}`,
        `      host: ${EXAMPLE_NAME}`,
        '      mode: packet-up',
      ];
    case 'udp':
      return [];
    default:
      return ['    network: tcp'];
  }
}

function clashProxy(p: ListenerProto, remark: string): string[] {
  const head = [`  - name: "${remark}"`];
  switch (p.protocol) {
    case 'vless':
      return [
        ...head,
        '    type: vless',
        `    server: ${EXAMPLE_ORIGIN}`,
        '    port: 443',
        `    uuid: ${EXAMPLE_UUID}`,
        ...(p.security === 'reality' ? ['    flow: xtls-rprx-vision'] : []),
        ...clashTlsLines(p),
        ...clashStreamLines(p),
      ];
    case 'trojan':
      return [
        ...head,
        '    type: trojan',
        `    server: ${EXAMPLE_ORIGIN}`,
        '    port: 443',
        `    password: ${EXAMPLE_PASSWORD}`,
        ...clashTlsLines(p).filter((l) => !l.includes('tls: true')),
        ...clashStreamLines(p),
      ];
    case 'shadowsocks':
      return [
        ...head,
        '    type: ss',
        `    server: ${EXAMPLE_ORIGIN}`,
        '    port: 8388',
        '    cipher: chacha20-ietf-poly1305',
        `    password: ${EXAMPLE_PASSWORD}`,
      ];
    case 'hysteria2':
      return [
        ...head,
        '    type: hysteria2',
        `    server: ${EXAMPLE_ORIGIN}`,
        '    port: 443',
        `    password: ${EXAMPLE_PASSWORD}`,
        `    sni: ${EXAMPLE_NAME}`,
      ];
    case 'tuic':
      return [
        ...head,
        '    type: tuic',
        `    server: ${EXAMPLE_ORIGIN}`,
        '    port: 443',
        `    uuid: ${EXAMPLE_UUID}`,
        `    password: ${EXAMPLE_PASSWORD}`,
        `    sni: ${EXAMPLE_NAME}`,
        '    congestion-controller: bbr',
      ];
  }
}

export function previewBody(
  format: SubscriptionFormat,
  remarks: readonly string[],
  proto: ListenerProto = PREVIEW_DEFAULT_PROTO,
): string {
  const names = remarks.length > 0 ? remarks : ['node-relay-a'];
  return bodyOf(
    format,
    names.map((remark) => ({ remark, proto })),
  );
}

/** One live listener of an origin, as its preview sample needs it. */
export interface PreviewListener {
  key: string;
  remark: string;
  proto: ListenerProto;
}

/**
 * The sample body one format receives for an origin: one template entry per
 * live listener, each in that listener's own shape. A listener the format
 * cannot carry gets no entry and is named in `uncarried`; when it carries none,
 * the body holds no connection, as the panel serves that app (`no_entries`).
 * An origin with no live listener gets one example entry.
 */
export function previewSample(
  format: SubscriptionFormat,
  listeners: readonly PreviewListener[],
): { body: string; uncarried: string[] } {
  if (listeners.length === 0) return { body: previewBody(format, []), uncarried: [] };
  const carried = listeners.filter((l) => formatSupported(l.proto, RENDER_FORMAT_OF[format]));
  return {
    body: bodyOf(format, carried),
    uncarried: listeners.filter((l) => !carried.includes(l)).map((l) => l.key),
  };
}

/** The per-listener result with every listener the format cannot carry said so (`family_cannot_carry`). */
export function withUncarried(
  listeners: readonly ListenerMatch[],
  uncarried: readonly string[],
): Array<ListenerMatch | { listenerKey: string; matched: false; reason: 'family_cannot_carry' }> {
  const cannot = (listenerKey: string) => ({
    listenerKey,
    matched: false as const,
    reason: 'family_cannot_carry' as const,
  });
  const out = listeners.map((l) => (uncarried.includes(l.listenerKey) ? cannot(l.listenerKey) : l));
  for (const k of uncarried) if (!out.some((l) => l.listenerKey === k)) out.push(cannot(k));
  return out;
}

function bodyOf(
  format: SubscriptionFormat,
  entries: ReadonlyArray<{ remark: string; proto: ListenerProto }>,
): string {
  for (const e of entries)
    if (!listenerCombo(e.proto)) throw new Error('preview: invalid listener combination');
  const names = entries.map((e) => e.remark);
  switch (format) {
    case 'links':
      return entries.map((e) => linkFor(e.proto, e.remark)).join('\n');
    case 'singbox-json':
      return JSON.stringify(
        {
          outbounds: [
            {
              type: 'selector',
              tag: 'proxy',
              outbounds: [...names, 'direct'],
              default: names[0] ?? 'direct',
            },
            ...entries.map((e) => singboxOutbound(e.proto, e.remark)),
            { type: 'direct', tag: 'direct' },
          ],
        },
        null,
        2,
      );
    case 'clash-yaml':
      return [
        'proxies:',
        ...entries.flatMap((e) => clashProxy(e.proto, e.remark)),
        'proxy-groups:',
        '  - name: PROXY',
        '    type: select',
        '    proxies:',
        ...names.map((r) => `      - "${r}"`),
      ].join('\n');
  }
}
