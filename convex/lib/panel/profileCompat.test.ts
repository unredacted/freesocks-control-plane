import { describe, expect, test } from 'vitest';
import type { PanelObservedInbound } from '../backends/types';
import { checkProfileCompatibility, findTransport } from './profileCompat';
import type { ModeShape } from './profileTemplate';

const base = (over: Partial<PanelObservedInbound>): PanelObservedInbound => ({
  tag: 'X',
  configProfileUuid: 'p1',
  configProfileInboundUuid: 'i-x',
  protocol: 'vless',
  port: 443,
  listen: '::',
  network: 'raw',
  security: 'reality',
  reality: { target: 'decoy.example:443', serverNames: ['decoy.example'] },
  realityAuth: { digest: 'd', publicKey: 'pk', publicKeyMismatch: false },
  ...over,
});

const good: PanelObservedInbound[] = [
  base({
    tag: 'FREEDOM_WEBSOCKET',
    configProfileInboundUuid: 'i-ws',
    port: 8443,
    listen: '127.0.0.1',
    network: 'ws',
    security: 'none',
    reality: undefined,
    realityAuth: undefined,
    ws: { path: '/ws', host: null },
  }),
  base({ tag: 'PRIVACY_REALITY', configProfileInboundUuid: 'i-direct' }),
  base({
    tag: 'FREEDOM_REALITY',
    configProfileInboundUuid: 'i-fronted',
    reality: { target: 'relay-decoy.example:443', serverNames: ['a.example', 'b.example'] },
  }),
  base({
    tag: 'FREEDOM_XHTTP',
    configProfileInboundUuid: 'i-xhttp',
    network: 'xhttp',
    xhttp: { path: '/', host: null, mode: 'auto' },
  }),
];

const shape = (transport: ModeShape['transport'], fronting: ModeShape['fronting']): ModeShape => ({
  transport,
  fronting,
});
const modes = [
  { slug: 'freedom-ws', name: 'Freedom-WebSocket', shape: shape('ws', 'edge-l7') },
  { slug: 'privacy-reality', name: 'Privacy-Reality', shape: shape('reality', 'direct') },
  { slug: 'freedom-reality', name: 'Freedom-Reality', shape: shape('reality', 'edge-l4') },
  { slug: 'freedom-xhttp', name: 'Freedom-XHTTP', shape: shape('xhttp-reality', 'edge-l4') },
];

describe('checkProfileCompatibility', () => {
  test("adopts a compatible profile and returns each mode's effective transport", () => {
    const r = checkProfileCompatibility({ inbounds: good }, modes);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.effective['freedom-ws']).toEqual({
      kind: 'ws',
      tag: 'FREEDOM_WEBSOCKET',
      uuid: 'i-ws',
      listen: '127.0.0.1',
      port: 8443,
      path: '/ws',
    });
    expect(r.effective['freedom-reality']).toMatchObject({
      kind: 'reality',
      uuid: 'i-fronted',
      serverNames: ['a.example', 'b.example'],
      target: { address: 'relay-decoy.example', port: 443 },
      publicKey: 'pk',
    });
    expect(r.effective['freedom-xhttp']).toMatchObject({ kind: 'xhttp-reality', path: '/' });
  });

  test('a transport an earlier setup tagged is found under its legacy tag and kept', () => {
    const legacy = [
      { ...good[0]!, tag: 'VLESS_WS_CDN' },
      { ...good[1]!, tag: 'VLESS_REALITY' },
      { ...good[2]!, tag: 'VLESS_RELAY_REALITY' },
    ];
    expect(findTransport(legacy, modes[1]!)?.tag).toBe('VLESS_REALITY');
    const r = checkProfileCompatibility({ inbounds: legacy }, modes.slice(0, 3));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.effective['freedom-ws']!.tag).toBe('VLESS_WS_CDN');
    expect(r.effective['freedom-reality']!.tag).toBe('VLESS_RELAY_REALITY');
  });

  test.each([
    ['missing', good.slice(0, 3), 'FREEDOM_XHTTP', 'freedom-xhttp'],
    [
      'protocol',
      [{ ...good[1]!, protocol: 'trojan' }, good[0]!, good[2]!, good[3]!],
      'PRIVACY_REALITY',
      'privacy-reality',
    ],
    [
      'network',
      [{ ...good[0]!, network: 'grpc' }, good[1]!, good[2]!, good[3]!],
      'FREEDOM_WEBSOCKET',
      'freedom-ws',
    ],
    [
      'network',
      [good[0]!, good[1]!, good[2]!, { ...good[3]!, network: 'raw' }],
      'FREEDOM_XHTTP',
      'freedom-xhttp',
    ],
    [
      'security',
      [{ ...good[0]!, security: 'tls' }, good[1]!, good[2]!, good[3]!],
      'FREEDOM_WEBSOCKET',
      'freedom-ws',
    ],
    [
      'listen',
      [{ ...good[0]!, listen: '0.0.0.0' }, good[1]!, good[2]!, good[3]!],
      'FREEDOM_WEBSOCKET',
      'freedom-ws',
    ],
    [
      'listen',
      [good[0]!, { ...good[1]!, listen: '127.0.0.1' }, good[2]!, good[3]!],
      'PRIVACY_REALITY',
      'privacy-reality',
    ],
    [
      'port',
      [good[0]!, { ...good[1]!, port: null }, good[2]!, good[3]!],
      'PRIVACY_REALITY',
      'privacy-reality',
    ],
    [
      'path',
      [{ ...good[0]!, ws: { path: null, host: null } }, good[1]!, good[2]!, good[3]!],
      'FREEDOM_WEBSOCKET',
      'freedom-ws',
    ],
    [
      'server_names',
      [
        good[0]!,
        good[1]!,
        { ...good[2]!, reality: { target: 'x.example:443', serverNames: [] } },
        good[3]!,
      ],
      'FREEDOM_REALITY',
      'freedom-reality',
    ],
    [
      'target',
      [
        good[0]!,
        { ...good[1]!, reality: { target: null, serverNames: ['a.example'] } },
        good[2]!,
        good[3]!,
      ],
      'PRIVACY_REALITY',
      'privacy-reality',
    ],
    [
      'reality_key',
      [good[0]!, { ...good[1]!, realityAuth: undefined }, good[2]!, good[3]!],
      'PRIVACY_REALITY',
      'privacy-reality',
    ],
    [
      'public_key_mismatch',
      [
        good[0]!,
        { ...good[1]!, realityAuth: { digest: 'd', publicKey: 'pk', publicKeyMismatch: true } },
        good[2]!,
        good[3]!,
      ],
      'PRIVACY_REALITY',
      'privacy-reality',
    ],
  ])('refuses %s with the tag and the mode', (field, inbounds, tag, slug) => {
    const r = checkProfileCompatibility({ inbounds }, modes);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.issue).toEqual({ slug, tag, field });
  });
});
