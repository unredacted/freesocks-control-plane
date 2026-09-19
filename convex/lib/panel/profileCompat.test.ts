import { describe, expect, test } from 'vitest';
import type { PanelObservedInbound } from '../backends/types';
import { checkProfileCompatibility } from './profileCompat';

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
    tag: 'VLESS_WS_CDN',
    configProfileInboundUuid: 'i-cdn',
    port: 8443,
    listen: '127.0.0.1',
    network: 'ws',
    security: 'none',
    reality: undefined,
    realityAuth: undefined,
    ws: { path: '/ws', host: null },
  }),
  base({ tag: 'VLESS_REALITY', configProfileInboundUuid: 'i-reality' }),
  base({
    tag: 'VLESS_RELAY_REALITY',
    configProfileInboundUuid: 'i-relay',
    reality: { target: 'relay-decoy.example:443', serverNames: ['a.example', 'b.example'] },
  }),
];

describe('checkProfileCompatibility', () => {
  test('adopts a compatible profile and returns its effective values', () => {
    const r = checkProfileCompatibility({ inbounds: good });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.effective.cdn).toEqual({
      kind: 'cdn',
      tag: 'VLESS_WS_CDN',
      inboundUuid: 'i-cdn',
      listen: '127.0.0.1',
      port: 8443,
      path: '/ws',
    });
    expect(r.effective.relay).toMatchObject({
      kind: 'relay',
      inboundUuid: 'i-relay',
      serverNames: ['a.example', 'b.example'],
      target: { address: 'relay-decoy.example', port: 443 },
      publicKey: 'pk',
    });
  });

  test.each([
    ['missing', good.slice(0, 2), 'VLESS_RELAY_REALITY'],
    ['protocol', [{ ...good[1]!, protocol: 'trojan' }, good[0]!, good[2]!], 'VLESS_REALITY'],
    ['network', [{ ...good[0]!, network: 'grpc' }, good[1]!, good[2]!], 'VLESS_WS_CDN'],
    ['security', [{ ...good[0]!, security: 'tls' }, good[1]!, good[2]!], 'VLESS_WS_CDN'],
    ['listen', [{ ...good[0]!, listen: '0.0.0.0' }, good[1]!, good[2]!], 'VLESS_WS_CDN'],
    ['listen', [good[0]!, { ...good[1]!, listen: '127.0.0.1' }, good[2]!], 'VLESS_REALITY'],
    ['port', [good[0]!, { ...good[1]!, port: null }, good[2]!], 'VLESS_REALITY'],
    ['path', [{ ...good[0]!, ws: { path: null, host: null } }, good[1]!, good[2]!], 'VLESS_WS_CDN'],
    [
      'server_names',
      [good[0]!, good[1]!, { ...good[2]!, reality: { target: 'x.example:443', serverNames: [] } }],
      'VLESS_RELAY_REALITY',
    ],
    [
      'target',
      [good[0]!, { ...good[1]!, reality: { target: null, serverNames: ['a.example'] } }, good[2]!],
      'VLESS_REALITY',
    ],
    ['reality_key', [good[0]!, { ...good[1]!, realityAuth: undefined }, good[2]!], 'VLESS_REALITY'],
    [
      'public_key_mismatch',
      [
        good[0]!,
        { ...good[1]!, realityAuth: { digest: 'd', publicKey: 'pk', publicKeyMismatch: true } },
        good[2]!,
      ],
      'VLESS_REALITY',
    ],
  ])('refuses %s with the tag', (field, inbounds, tag) => {
    const r = checkProfileCompatibility({ inbounds });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.issue).toEqual({ tag, field });
  });
});
