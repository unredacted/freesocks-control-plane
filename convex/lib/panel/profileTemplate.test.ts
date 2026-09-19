import { describe, expect, test } from 'vitest';
import { PRIVACY_XRAY_LOG } from '../backends/remnawave';
import {
  BOOTSTRAP_TAGS,
  buildBootstrapProfile,
  checkBootstrapInput,
  checkShortIds,
  type BootstrapProfileInput,
} from './profileTemplate';

const input: BootstrapProfileInput = {
  cdn: { path: '/ws', port: 8443 },
  reality: { target: { address: 'decoy-a.example', port: 443 }, serverNames: ['decoy-a.example'] },
  relay: {
    target: { address: 'decoy-b.example', port: 443 },
    serverNames: ['decoy-b.example', 'www.decoy-b.example'],
    acceptProxyProtocol: false,
  },
};
const keys = {
  reality: { privateKey: 'reality-private-key-placeholder', shortIds: [''] },
  relay: { privateKey: 'relay-private-key-placeholder', shortIds: ['', 'a1b2c3d4'] },
};

type Inbound = Record<string, unknown> & {
  streamSettings: Record<string, unknown> & { realitySettings?: Record<string, unknown> };
};

describe('buildBootstrapProfile', () => {
  const config = buildBootstrapProfile(input, keys);
  const inbounds = config.inbounds as Inbound[];
  const byTag = Object.fromEntries(inbounds.map((i) => [i.tag as string, i]));

  test('is born with the privacy posture', () => {
    expect(config.log).toEqual(PRIVACY_XRAY_LOG);
    expect(config.policy).toEqual({ levels: { '0': { statsUserOnline: false } } });
    expect(config.outbounds).toEqual([
      { protocol: 'freedom', tag: 'DIRECT', settings: { domainStrategy: 'UseIPv4v6' } },
      { protocol: 'blackhole', tag: 'BLOCK' },
    ]);
  });

  test('carries the three inbounds in order with the role shapes', () => {
    expect(inbounds.map((i) => i.tag)).toEqual([
      BOOTSTRAP_TAGS.cdn,
      BOOTSTRAP_TAGS.reality,
      BOOTSTRAP_TAGS.relay,
    ]);
    expect(byTag.VLESS_WS_CDN).toMatchObject({
      listen: '127.0.0.1',
      port: 8443,
      protocol: 'vless',
      settings: { clients: [], decryption: 'none' },
      streamSettings: { network: 'ws', security: 'none', wsSettings: { path: '/ws' } },
      sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true },
    });
    expect(byTag.VLESS_REALITY).toMatchObject({
      listen: '::',
      port: 443,
      streamSettings: {
        network: 'raw',
        security: 'reality',
        realitySettings: {
          dest: 'decoy-a.example:443',
          serverNames: ['decoy-a.example'],
          privateKey: keys.reality.privateKey,
          shortIds: [''],
          minClientVer: '1.8.1',
        },
      },
    });
    expect(byTag.VLESS_RELAY_REALITY!.streamSettings.realitySettings).toMatchObject({
      dest: 'decoy-b.example:443',
      privateKey: keys.relay.privateKey,
      shortIds: ['', 'a1b2c3d4'],
    });
    expect(byTag.VLESS_RELAY_REALITY!.streamSettings.rawSettings).toBeUndefined();
  });

  test('PROXY protocol acceptance is opt-in on the relay inbound only', () => {
    const c = buildBootstrapProfile(
      { ...input, relay: { ...input.relay, acceptProxyProtocol: true } },
      keys,
    );
    const relay = (c.inbounds as Inbound[]).find((i) => i.tag === BOOTSTRAP_TAGS.relay)!;
    const reality = (c.inbounds as Inbound[]).find((i) => i.tag === BOOTSTRAP_TAGS.reality)!;
    expect(relay.streamSettings.rawSettings).toEqual({ acceptProxyProtocol: true });
    expect(reality.streamSettings.rawSettings).toBeUndefined();
  });

  test('names and targets are normalised', () => {
    const c = buildBootstrapProfile(
      {
        ...input,
        reality: {
          target: { address: ' Decoy-A.example ', port: 443 },
          serverNames: [' A.Example'],
        },
      },
      keys,
    );
    const rs = (c.inbounds as Inbound[])[1]!.streamSettings.realitySettings!;
    expect(rs.dest).toBe('decoy-a.example:443');
    expect(rs.serverNames).toEqual(['a.example']);
  });

  test('refuses bad input by code', () => {
    expect(checkBootstrapInput({ ...input, cdn: { path: 'ws', port: 8443 } })).toBe('cdn_path');
    expect(checkBootstrapInput({ ...input, cdn: { path: '/ws', port: 80 } })).toBe('cdn_port');
    expect(checkBootstrapInput({ ...input, reality: { ...input.reality, serverNames: [] } })).toBe(
      'reality_names',
    );
    expect(
      checkBootstrapInput({
        ...input,
        relay: { ...input.relay, target: { address: 'not a host', port: 443 } },
      }),
    ).toBe('relay_target');
    expect(checkBootstrapInput(input)).toBeNull();
    expect(checkShortIds([''])).toBe(true);
    expect(checkShortIds(['abc'])).toBe(false);
    expect(checkShortIds([])).toBe(false);
    expect(() =>
      buildBootstrapProfile(input, { ...keys, relay: { ...keys.relay, shortIds: ['zz'] } }),
    ).toThrow(/short_ids/);
  });
});
