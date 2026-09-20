import { describe, expect, test } from 'vitest';
import type { BackendTransport } from '../backends/types';
import { mapTransportsToListeners } from '../edges/inboundMapping';
import { applyIngress, type IngressMapping } from './ingress';

const PROFILE = '11111111-1111-4111-8111-111111111111';
const INBOUND = '22222222-2222-4222-8222-222222222222';
const cdn: BackendTransport = {
  tag: 'VLESS_WS_CDN',
  configProfileUuid: PROFILE,
  configProfileInboundUuid: INBOUND,
  protocol: 'vless',
  port: 8443,
  listen: '127.0.0.1',
  network: 'ws',
  security: 'none',
  ws: { path: '/ws', host: null },
  active: true,
};
const ingress: IngressMapping = {
  hostname: 'node-a.origin.example',
  external: { port: 443, tls: 'caddy', hostHeader: 'any' },
  internal: [{ inboundTag: 'VLESS_WS_CDN', listen: '127.0.0.1', port: 8443, path: '/ws' }],
};
const origin = { kind: 'panel-node' as const, backendServerId: 'b1' as never, nodeName: 'node-a' };

describe('applyIngress', () => {
  test('a mapped loopback transport becomes the external TLS listener', () => {
    const [out] = applyIngress([cdn], ingress);
    expect(out).toMatchObject({
      listen: null,
      port: 443,
      security: 'tls',
      tls: { serverName: 'node-a.origin.example' },
      ws: { path: '/ws', host: null },
    });
  });

  test('no mapping, a stale port or a stale path leave the transport as it is', () => {
    expect(applyIngress([cdn], null)[0]).toBe(cdn);
    expect(applyIngress([cdn], { ...ingress, internal: [] })[0]).toBe(cdn);
    expect(
      applyIngress([cdn], { ...ingress, internal: [{ ...ingress.internal[0]!, port: 9000 }] })[0],
    ).toBe(cdn);
    expect(
      applyIngress([cdn], {
        ...ingress,
        internal: [{ ...ingress.internal[0]!, path: '/other' }],
      })[0],
    ).toBe(cdn);
  });

  test('discovery refuses the loopback transport without an ingress and maps it with one', async () => {
    const without = await mapTransportsToListeners([cdn], { existingKeys: [], origin });
    expect(without.candidates).toHaveLength(0);
    expect(without.unsupported[0]).toMatchObject({ tag: 'VLESS_WS_CDN', reason: 'loopback' });

    const withIngress = await mapTransportsToListeners([cdn], {
      existingKeys: [],
      origin,
      ingress,
    });
    expect(withIngress.unsupported).toHaveLength(0);
    expect(withIngress.candidates[0]!.listenerSpec).toMatchObject({
      protocol: 'vless',
      streamTransport: 'ws',
      security: 'tls',
      originPort: 443,
      tlsNames: ['node-a.origin.example'],
      transportParams: { path: '/ws' },
      panelBinding: { inboundTag: 'VLESS_WS_CDN', configProfileInboundUuid: INBOUND },
    });
    // Still L4-only until the origin probe fills `originTransport`.
    expect(withIngress.candidates[0]!.layers.layers).toEqual(['l4']);
  });
});
