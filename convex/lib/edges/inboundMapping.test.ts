/**
 * Golden tests for inbound discovery: every supported combination maps to the
 * by-slug listener shape, every unsupported reason is named, the listener key
 * algorithm is deterministic and collision-resistant, and nothing secret can
 * cross the mapper (its input is already the allowlisted projection; the
 * output is checked once more for the words that must never appear).
 *
 * Fixtures use RFC 5737 / RFC 3849 addresses and `*.example` names only.
 */
import { describe, expect, test } from 'vitest';
import type { Id } from '../../_generated/dataModel';
import type { PanelInbound } from '../backends/types';
import { isSlotKey } from './hosts';
import {
  listenerKeyForTag,
  mapInboundsToListeners,
  parseRealityTarget,
  type PanelNodeOrigin,
} from './inboundMapping';

const ORIGIN: PanelNodeOrigin = {
  kind: 'panel-node',
  backendServerId: 'server_1' as Id<'backendServers'>,
  nodeName: 'node-one',
};
const PROFILE = '0f1e2d3c-4b5a-4968-8776-655443322110';
const INBOUND = '11111111-2222-4333-8444-555555555555';

function inbound(over: Partial<PanelInbound> & { tag: string }): PanelInbound {
  return {
    configProfileUuid: PROFILE,
    configProfileInboundUuid: INBOUND,
    protocol: 'vless',
    port: 443,
    network: 'tcp',
    security: 'reality',
    reality: { target: 'decoy.example:443', serverNames: ['decoy.example'] },
    active: true,
    ...over,
  };
}

async function map(inbounds: PanelInbound[], existingKeys: string[] = []) {
  return mapInboundsToListeners(inbounds, { existingKeys, origin: ORIGIN });
}

describe('listenerKeyForTag', () => {
  test('is deterministic, at most 16 chars, and a valid slot key', async () => {
    const a = await listenerKeyForTag('VLESS_REALITY_443');
    const b = await listenerKeyForTag('VLESS_REALITY_443');
    expect(a).toBe(b);
    expect(a.length).toBe(16);
    expect(isSlotKey(a)).toBe(true);
    expect(a.startsWith('vlessreali')).toBe(true);
  });

  test('a 64-char underscore tag still yields a 16-char key', async () => {
    const tag = `${'A_'.repeat(31)}ZZ`; // 64 chars, half of them underscores
    expect(tag.length).toBe(64);
    const key = await listenerKeyForTag(tag);
    expect(key.length).toBe(16);
    expect(isSlotKey(key)).toBe(true);
    expect(key.startsWith('aaaaaaaaaa')).toBe(true);
  });

  test('a tag with no alphanumerics is just the digest', async () => {
    const key = await listenerKeyForTag('___');
    expect(key.length).toBe(6);
    expect(isSlotKey(key)).toBe(true);
  });

  test('a collision pair on the slug gets distinct keys through the digest', async () => {
    // Same first ten alphanumerics, different tags.
    const a = await listenerKeyForTag('VLESS_REALITY_A');
    const b = await listenerKeyForTag('VLESS_REALITY_B');
    expect(a.slice(0, 10)).toBe(b.slice(0, 10));
    expect(a).not.toBe(b);
  });
});

describe('parseRealityTarget', () => {
  test('accepts host:port, v4:port and [v6]:port', () => {
    expect(parseRealityTarget('decoy.example:443')).toEqual({
      address: 'decoy.example',
      port: 443,
    });
    expect(parseRealityTarget('192.0.2.10:8443')).toEqual({ address: '192.0.2.10', port: 8443 });
    expect(parseRealityTarget('[2001:db8::1]:443')).toEqual({ address: '2001:db8::1', port: 443 });
  });
  test('rejects a bare port, a socket path, a range and an empty value', () => {
    expect(parseRealityTarget('443')).toBeNull();
    expect(parseRealityTarget('/dev/shm/decoy.sock')).toBeNull();
    expect(parseRealityTarget('decoy.example:0')).toBeNull();
    expect(parseRealityTarget('decoy.example:70000')).toBeNull();
    expect(parseRealityTarget(null)).toBeNull();
  });
});

describe('mapInboundsToListeners: supported combinations', () => {
  test('vless/raw/reality -> realityTarget + tlsNames from serverNames', async () => {
    const { candidates, unsupported } = await map([
      inbound({
        tag: 'VLESS_REALITY',
        reality: {
          target: 'decoy.example:443',
          serverNames: ['decoy.example', 'www.decoy.example'],
        },
      }),
    ]);
    expect(unsupported).toEqual([]);
    expect(candidates).toHaveLength(1);
    const c = candidates[0];
    const key = await listenerKeyForTag('VLESS_REALITY');
    expect(c.listenerSpec).toEqual({
      protocol: 'vless',
      streamTransport: 'raw',
      security: 'reality',
      listenerKey: key,
      originPort: 443,
      tlsNames: ['decoy.example', 'www.decoy.example'],
      realityTarget: { address: 'decoy.example', port: 443 },
      panelBinding: {
        inboundTag: 'VLESS_REALITY',
        configProfileUuid: PROFILE,
        configProfileInboundUuid: INBOUND,
      },
      matchRule: { kind: 'remark', remark: `node-one-relay-${key}` },
    });
    expect(c.needsName).toBe(false);
    expect(c.sourceTag).toBe('VLESS_REALITY');
    expect(c.formats).toEqual({ links: true, singbox: true, clash: true });
    // No origin transport yet: L4 only.
    expect(c.layers.layers).toEqual(['l4']);
    expect(c.layers.excluded.l7).toBe('protocol_not_http_transport');
    expect('originTransport' in c.listenerSpec).toBe(false);
  });

  test('vless/raw/tls -> tlsNames from serverName; missing serverName = needsName', async () => {
    const { candidates } = await map([
      inbound({
        tag: 'VLESS_TLS',
        security: 'tls',
        reality: undefined,
        tls: { serverName: 'Node.Example.' },
      }),
      inbound({
        tag: 'VLESS_TLS_NONAME',
        security: 'tls',
        reality: undefined,
        tls: { serverName: null },
        port: 8443,
      }),
    ]);
    expect(candidates).toHaveLength(2);
    expect(candidates[0].listenerSpec.tlsNames).toEqual(['node.example']);
    expect(candidates[0].needsName).toBe(false);
    expect(candidates[0].listenerSpec.security).toBe('tls');
    expect(candidates[1].listenerSpec.tlsNames).toEqual([]);
    expect(candidates[1].needsName).toBe(true);
    expect(candidates[1].listenerSpec.originPort).toBe(8443);
    // Nameless: nothing to emit behind an L4 forwarder until a name exists.
    expect(candidates[1].layers.layers).toEqual(['l4']);
  });

  test('ws / httpupgrade / grpc over tls carry transportParams and start L4-only', async () => {
    const { candidates, unsupported } = await map([
      inbound({
        tag: 'VLESS_WS',
        network: 'ws',
        security: 'tls',
        reality: undefined,
        tls: { serverName: 'ws.example' },
        ws: { path: '/ws', host: 'ws.example' },
      }),
      inbound({
        tag: 'VLESS_HU',
        network: 'httpupgrade',
        security: 'tls',
        reality: undefined,
        tls: { serverName: 'hu.example' },
        httpupgrade: { path: '/up', host: null },
        port: 8443,
      }),
      inbound({
        tag: 'VLESS_GRPC',
        network: 'grpc',
        security: 'tls',
        reality: undefined,
        tls: { serverName: 'grpc.example' },
        grpc: { serviceName: 'svc' },
        port: 2053,
      }),
      inbound({
        tag: 'TROJAN_WS',
        protocol: 'trojan',
        network: 'ws',
        security: 'tls',
        reality: undefined,
        tls: { serverName: 'tj.example' },
        ws: { path: null, host: null },
        port: 2083,
      }),
    ]);
    expect(unsupported).toEqual([]);
    expect(candidates.map((c) => c.listenerSpec.streamTransport)).toEqual([
      'ws',
      'httpupgrade',
      'grpc',
      'ws',
    ]);
    expect(candidates[0].listenerSpec.transportParams).toEqual({ path: '/ws', host: 'ws.example' });
    expect(candidates[1].listenerSpec.transportParams).toEqual({ path: '/up' });
    expect(candidates[2].listenerSpec.transportParams).toEqual({ serviceName: 'svc' });
    expect(candidates[3].listenerSpec.transportParams).toEqual({});
    expect(candidates[3].listenerSpec.protocol).toBe('trojan');
    // Without an origin transport an HTTP-transport listener is L4-only.
    for (const c of candidates) {
      expect(c.layers.layers).toEqual(['l4']);
      expect(c.layers.excluded.l7).toBe('protocol_not_http_transport');
    }
  });

  test('trojan/raw/tls and shadowsocks/raw/none', async () => {
    const { candidates, unsupported } = await map([
      inbound({
        tag: 'TROJAN',
        protocol: 'trojan',
        security: 'tls',
        reality: undefined,
        tls: { serverName: 'tj.example' },
      }),
      inbound({
        tag: 'SS',
        protocol: 'shadowsocks',
        network: 'tcp',
        security: 'none',
        reality: undefined,
        port: 8388,
      }),
    ]);
    expect(unsupported).toEqual([]);
    expect(candidates[0].listenerSpec).toMatchObject({
      protocol: 'trojan',
      streamTransport: 'raw',
      security: 'tls',
      tlsNames: ['tj.example'],
    });
    expect(candidates[1].listenerSpec).toMatchObject({
      protocol: 'shadowsocks',
      streamTransport: 'raw',
      security: 'none',
      tlsNames: [],
      originPort: 8388,
    });
    expect(candidates[1].needsName).toBe(false);
    expect(candidates[1].listenerSpec.transportParams).toBeUndefined();
    expect(candidates[1].listenerSpec.realityTarget).toBeUndefined();
  });

  test('a raw network and a gun/websocket alias map like tcp/grpc/ws', async () => {
    const { candidates } = await map([
      inbound({ tag: 'RAW', network: 'raw' }),
      inbound({
        tag: 'GUN',
        network: 'gun',
        security: 'tls',
        reality: undefined,
        tls: { serverName: 'g.example' },
        grpc: { serviceName: null },
        port: 2053,
      }),
    ]);
    expect(candidates.map((c) => c.listenerSpec.streamTransport)).toEqual(['raw', 'grpc']);
  });
});

describe('mapInboundsToListeners: unsupported reasons', () => {
  test('one row per reason', async () => {
    const { candidates, unsupported } = await map([
      inbound({ tag: 'OFF', active: false }),
      inbound({ tag: 'bad-tag' }),
      inbound({ tag: 'VMESS', protocol: 'vmess' }),
      inbound({
        tag: 'XHTTP',
        network: 'xhttp',
        security: 'tls',
        tls: { serverName: 'x.example' },
      }),
      inbound({ tag: 'KCP', network: 'kcp' }),
      inbound({ tag: 'ODD_SEC', security: 'xtls' }),
      // Valid fields but not a catalogue combination: shadowsocks over reality.
      inbound({ tag: 'SS_REALITY', protocol: 'shadowsocks', security: 'reality' }),
      // A port range is not one origin port.
      inbound({ tag: 'RANGE', port: null }),
      // REALITY without a dialable target.
      inbound({ tag: 'NO_TARGET', reality: { target: null, serverNames: ['d.example'] } }),
      // A server name the validator refuses.
      inbound({
        tag: 'BAD_NAME',
        reality: { target: 'd.example:443', serverNames: ['not a name'] },
      }),
    ]);
    expect(candidates).toEqual([]);
    expect(unsupported).toEqual([
      { tag: 'OFF', reason: 'inactive' },
      { tag: 'bad-tag', reason: 'tag' },
      { tag: 'VMESS', reason: 'protocol', detail: 'vmess' },
      { tag: 'XHTTP', reason: 'transport', detail: 'xhttp' },
      { tag: 'KCP', reason: 'transport', detail: 'kcp' },
      { tag: 'ODD_SEC', reason: 'security', detail: 'xtls' },
      { tag: 'SS_REALITY', reason: 'invalid', detail: 'invalid_combination' },
      { tag: 'RANGE', reason: 'invalid', detail: 'port' },
      { tag: 'NO_TARGET', reason: 'invalid', detail: 'reality_target' },
      { tag: 'BAD_NAME', reason: 'invalid', detail: 'invalid server name: not a name' },
    ]);
  });

  test('inactive wins over every other reason (nothing to fix on a served-nowhere inbound)', async () => {
    const { unsupported } = await map([
      inbound({ tag: 'vmess-off', protocol: 'vmess', active: false }),
    ]);
    expect(unsupported).toEqual([{ tag: 'vmess-off', reason: 'inactive' }]);
  });
});

describe('mapInboundsToListeners: listener keys', () => {
  test('a key already on the relay makes the inbound invalid (never a duplicate listener)', async () => {
    const key = await listenerKeyForTag('VLESS_REALITY');
    const { candidates, unsupported } = await map([inbound({ tag: 'VLESS_REALITY' })], [key]);
    expect(candidates).toEqual([]);
    expect(unsupported).toEqual([
      { tag: 'VLESS_REALITY', reason: 'invalid', detail: 'listener_key_collision' },
    ]);
  });

  test('the same tag twice in one batch: the second is a collision', async () => {
    const { candidates, unsupported } = await map([
      inbound({ tag: 'VLESS_REALITY' }),
      inbound({ tag: 'VLESS_REALITY', port: 8443 }),
    ]);
    expect(candidates).toHaveLength(1);
    expect(unsupported).toEqual([
      { tag: 'VLESS_REALITY', reason: 'invalid', detail: 'listener_key_collision' },
    ]);
  });

  test('a slug collision pair maps to two distinct listeners', async () => {
    const { candidates, unsupported } = await map([
      inbound({ tag: 'VLESS_REALITY_A' }),
      inbound({ tag: 'VLESS_REALITY_B', port: 8443 }),
    ]);
    expect(unsupported).toEqual([]);
    const keys = candidates.map((c) => c.listenerSpec.listenerKey);
    expect(new Set(keys).size).toBe(2);
    expect(keys.every(isSlotKey)).toBe(true);
    expect(keys[0].slice(0, 10)).toBe(keys[1].slice(0, 10));
  });

  test('keys are stable across runs', async () => {
    const a = await map([inbound({ tag: 'VLESS_REALITY' })]);
    const b = await map([inbound({ tag: 'VLESS_REALITY' })]);
    expect(a.candidates[0].listenerSpec.listenerKey).toBe(b.candidates[0].listenerSpec.listenerKey);
  });
});

describe('mapInboundsToListeners: nothing secret leaves', () => {
  test('the output never carries key material, short ids, clients or certificates', async () => {
    const out = await map([
      inbound({ tag: 'VLESS_REALITY' }),
      inbound({
        tag: 'VLESS_WS',
        network: 'ws',
        security: 'tls',
        reality: undefined,
        tls: { serverName: 'ws.example' },
        ws: { path: '/ws', host: 'ws.example' },
      }),
      inbound({ tag: 'VMESS', protocol: 'vmess' }),
    ]);
    const json = JSON.stringify(out);
    for (const word of [
      'privateKey',
      'shortId',
      'clients',
      'certificate',
      'password',
      'rawInbound',
    ])
      expect(json).not.toContain(word);
  });
});
