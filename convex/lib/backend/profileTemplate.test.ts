import { describe, expect, test } from 'vitest';
import { PRIVACY_XRAY_LOG } from '../backends/remnawave';
import {
  buildProfile,
  generateObfsPassword,
  isHysteria,
  isReality,
  checkModeDefinitions,
  checkModes,
  checkShortIds,
  transportTagOf,
  type ModeTemplateInput,
} from './profileTemplate';

const direct: ModeTemplateInput = {
  slug: 'privacy-reality',
  name: 'Privacy-Reality',
  shape: { transport: 'reality', fronting: 'direct' },
  reality: { target: { address: 'decoy-a.example', port: 443 }, serverNames: ['decoy-a.example'] },
};
const fronted: ModeTemplateInput = {
  slug: 'freedom-reality',
  name: 'Freedom-Reality',
  shape: { transport: 'reality', fronting: 'edge-l4' },
  acceptProxyProtocol: false,
  reality: {
    target: { address: 'decoy-b.example', port: 443 },
    serverNames: ['decoy-b.example', 'www.decoy-b.example'],
  },
};
const xhttp: ModeTemplateInput = {
  slug: 'freedom-xhttp',
  name: 'Freedom-XHTTP',
  shape: { transport: 'xhttp-reality', fronting: 'edge-l4' },
  reality: { target: { address: 'decoy-b.example', port: 443 }, serverNames: ['decoy-b.example'] },
};
const ws: ModeTemplateInput = {
  slug: 'freedom-ws',
  name: 'Freedom-WebSocket',
  shape: { transport: 'ws', fronting: 'edge-l7' },
  ws: { path: '/ws', port: 8443 },
};
const modes = [direct, fronted, xhttp, ws];
const keys = {
  'privacy-reality': { privateKey: 'direct-private-key-placeholder', shortIds: [''] },
  'freedom-reality': { privateKey: 'fronted-private-key-placeholder', shortIds: ['', 'a1b2c3d4'] },
  'freedom-xhttp': { privateKey: 'xhttp-private-key-placeholder', shortIds: [''] },
};

type Inbound = Record<string, unknown> & {
  streamSettings: Record<string, unknown> & { realitySettings?: Record<string, unknown> };
};

describe('buildProfile', () => {
  const config = buildProfile(modes, keys);
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

  test('one transport per mode, tagged after the group, in order', () => {
    expect(inbounds.map((i) => i.tag)).toEqual([
      'PRIVACY_REALITY',
      'FREEDOM_REALITY',
      'FREEDOM_XHTTP',
      'FREEDOM_WEBSOCKET',
    ]);
    expect(transportTagOf('Freedom-WebSocket')).toBe('FREEDOM_WEBSOCKET');
    expect(byTag.FREEDOM_WEBSOCKET).toMatchObject({
      listen: '127.0.0.1',
      port: 8443,
      protocol: 'vless',
      settings: { clients: [], decryption: 'none' },
      streamSettings: { network: 'ws', security: 'none', wsSettings: { path: '/ws' } },
      sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true },
    });
    expect(byTag.PRIVACY_REALITY).toMatchObject({
      listen: '::',
      port: 443,
      streamSettings: {
        network: 'raw',
        security: 'reality',
        realitySettings: {
          dest: 'decoy-a.example:443',
          serverNames: ['decoy-a.example'],
          privateKey: keys['privacy-reality'].privateKey,
          shortIds: [''],
          minClientVer: '1.8.1',
        },
      },
    });
    expect(byTag.FREEDOM_REALITY!.streamSettings.realitySettings).toMatchObject({
      dest: 'decoy-b.example:443',
      privateKey: keys['freedom-reality'].privateKey,
      shortIds: ['', 'a1b2c3d4'],
    });
    expect(byTag.FREEDOM_REALITY!.streamSettings.rawSettings).toBeUndefined();
  });

  test('XHTTP under REALITY: the node terminates, on the public port, its own key', () => {
    expect(byTag.FREEDOM_XHTTP).toMatchObject({
      listen: '::',
      port: 443,
      streamSettings: {
        network: 'xhttp',
        security: 'reality',
        xhttpSettings: { path: '/', mode: 'auto' },
        realitySettings: {
          dest: 'decoy-b.example:443',
          privateKey: keys['freedom-xhttp'].privateKey,
        },
      },
    });
  });

  test('PROXY protocol acceptance is opt-in per edge-fronted mode', () => {
    const c = buildProfile([direct, { ...fronted, acceptProxyProtocol: true }], keys);
    const [d, f] = c.inbounds as Inbound[];
    expect(f!.streamSettings.rawSettings).toEqual({ acceptProxyProtocol: true });
    expect(d!.streamSettings.rawSettings).toBeUndefined();
  });

  test('names and targets are normalised', () => {
    const c = buildProfile(
      [
        {
          ...direct,
          reality: {
            target: { address: ' Decoy-A.example ', port: 443 },
            serverNames: [' A.Example'],
          },
        },
      ],
      keys,
    );
    const rs = (c.inbounds as Inbound[])[0]!.streamSettings.realitySettings!;
    expect(rs.dest).toBe('decoy-a.example:443');
    expect(rs.serverNames).toEqual(['a.example']);
  });

  test('refuses bad definitions and bad modes by code', () => {
    expect(checkModeDefinitions([])).toBe('modes_empty');
    expect(checkModeDefinitions([{ ...ws, ws: { path: 'ws', port: 8443 } }])).toBe(
      'freedom-ws:ws_path',
    );
    expect(checkModeDefinitions([{ ...ws, ws: { path: '/ws', port: 80 } }])).toBe(
      'freedom-ws:ws_port',
    );
    expect(
      checkModeDefinitions([
        { slug: 'x', name: 'X-Mode', shape: { transport: 'reality', fronting: 'direct' } },
      ]),
    ).toBe('x:family');
    expect(
      checkModeDefinitions([
        { ...direct, familySlug: 'f' },
        { ...direct, slug: 'other', familySlug: 'f' },
      ]),
    ).toBe('other:duplicate_name');
    expect(
      checkModeDefinitions([
        {
          slug: 'a',
          name: 'Same-Name',
          shape: { transport: 'ws', fronting: 'edge-l7' },
          ws: { path: '/a', port: 8443 },
        },
        {
          slug: 'b',
          name: 'same_name',
          shape: { transport: 'ws', fronting: 'edge-l7' },
          ws: { path: '/b', port: 8444 },
        },
      ]),
    ).toBe('b:duplicate_tag');
    expect(
      checkModeDefinitions([
        {
          ...direct,
          familySlug: 'f',
          shape: { transport: 'ws', fronting: 'direct' },
          ws: { path: '/ws', port: 8443 },
        },
      ]),
    ).toBe('privacy-reality:shape');
    expect(checkModes([{ ...direct, reality: { ...direct.reality, serverNames: [] } }])).toBe(
      'privacy-reality:names',
    );
    expect(
      checkModes([
        {
          ...fronted,
          reality: { ...fronted.reality, target: { address: 'not a host', port: 443 } },
        },
      ]),
    ).toBe('freedom-reality:target');
    expect(checkModes(modes)).toBeNull();
    expect(checkShortIds([''])).toBe(true);
    expect(checkShortIds(['abc'])).toBe(false);
    expect(checkShortIds([])).toBe(false);
    expect(() =>
      buildProfile(modes, {
        ...keys,
        'freedom-reality': { ...keys['freedom-reality'], shortIds: ['zz'] },
      }),
    ).toThrow(/short_ids/);
    expect(() => buildProfile([direct], {})).toThrow(/short_ids/);
  });
});

describe('the Hysteria 2 transport', () => {
  const hysteria: ModeTemplateInput = {
    slug: 'privacy-hysteria',
    name: 'Privacy-Hysteria',
    shape: { transport: 'hysteria', fronting: 'direct' },
    hysteria: { serverName: 'Quic.Example', salamander: false },
  };
  const material = {
    'privacy-hysteria': {
      certificate: ['-----BEGIN CERTIFICATE-----', 'cert', '-----END CERTIFICATE-----'],
      key: ['-----BEGIN EC PRIVATE KEY-----', 'key', '-----END EC PRIVATE KEY-----'],
    },
  };

  test('is not REALITY: no family, no key pair', () => {
    expect(isReality(hysteria.shape)).toBe(false);
    expect(isHysteria(hysteria.shape)).toBe(true);
    expect(isReality(direct.shape)).toBe(true);
    expect(isReality(ws.shape)).toBe(false);
    expect(checkModeDefinitions([{ ...hysteria }])).toBeNull();
    expect(checkModes([hysteria])).toBeNull();
  });

  test('needs a server name that is a host name, on a direct node', () => {
    const { hysteria: _h, ...noSettings } = hysteria as ModeTemplateInput & { hysteria: unknown };
    expect(checkModeDefinitions([noSettings])).toBe('privacy-hysteria:hysteria');
    expect(
      checkModeDefinitions([
        { ...hysteria, hysteria: { serverName: 'not a name', salamander: false } },
      ]),
    ).toBe('privacy-hysteria:hysteria_name');
    // Only direct: no edge forwards UDP.
    expect(
      checkModeDefinitions([
        { ...hysteria, shape: { transport: 'hysteria', fronting: 'edge-l4' } },
      ]),
    ).toBe('privacy-hysteria:shape');
  });

  test('a QUIC inbound on UDP 443 under the injected certificate, BBR, a 404 for strangers', () => {
    const config = buildProfile([direct, hysteria], keys, material);
    const ib = (config.inbounds as Inbound[]).find((i) => i.tag === 'PRIVACY_HYSTERIA')!;
    expect(ib).toMatchObject({
      listen: '::',
      port: 443,
      protocol: 'hysteria',
      settings: { version: 2, clients: [] },
    });
    expect(ib.streamSettings).toEqual({
      network: 'hysteria',
      security: 'tls',
      tlsSettings: {
        serverName: 'quic.example',
        alpn: ['h3'],
        certificates: [
          {
            certificate: material['privacy-hysteria'].certificate,
            key: material['privacy-hysteria'].key,
          },
        ],
      },
      hysteriaSettings: {
        version: 2,
        masquerade: { type: 'string', content: 'not found', statusCode: 404 },
      },
      finalmask: { quicParams: { congestion: 'bbr' } },
    });
    // The REALITY transport beside it is unchanged, on TCP 443.
    expect((config.inbounds as Inbound[])[0]!.port).toBe(443);
    expect(config.log).toEqual(PRIVACY_XRAY_LOG);
  });

  test('Salamander wraps the packets with the injected password', () => {
    const on: ModeTemplateInput = {
      ...hysteria,
      hysteria: { serverName: 'quic.example', salamander: true },
    };
    const config = buildProfile(
      [on],
      {},
      { 'privacy-hysteria': { ...material['privacy-hysteria'], obfsPassword: 'pw' } },
    );
    const ib = (config.inbounds as Inbound[])[0]!;
    expect(ib.streamSettings.finalmask).toEqual({
      quicParams: { congestion: 'bbr' },
      udp: [{ type: 'salamander', settings: { password: 'pw' } }],
    });
    expect(() => buildProfile([on], {}, material)).toThrow(/Salamander password/);
  });

  test('refuses to build without its certificate', () => {
    expect(() => buildProfile([hysteria], {})).toThrow(/no certificate/);
  });

  test('a Salamander password is 32 random bytes, base64url', () => {
    const pw = generateObfsPassword();
    expect(pw).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(generateObfsPassword()).not.toBe(pw);
  });
});
