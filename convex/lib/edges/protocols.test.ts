/**
 * The listener catalogue ⇔ the renderer codec table. A combination without a
 * codec for every subscription format never ships; an unlisted combination is
 * `invalid_combination`; the only authenticated L7 proof is VLESS over an HTTP
 * transport under TLS.
 */
import { describe, expect, test } from 'vitest';
import {
  CODECS,
  LISTENER_COMBOS,
  LISTENER_PROTOCOL_IDS,
  LISTENER_SECURITY_IDS,
  LISTENER_STREAM_TRANSPORT_IDS,
  RENDER_FORMATS,
  codecFor,
  comboKey,
  formatSupported,
  isValidListenerCombo,
  listenerCombo,
  protocolDescriptor,
  protocolIsHttpTransport,
  protocolL7Proof,
  protocolLabel,
  protocolNeedsTarget,
  protocolTransport,
  protocolUsesHostHeader,
  protocolUsesSni,
  type ListenerProto,
} from './protocols';

const REALITY: ListenerProto = { protocol: 'vless', streamTransport: 'raw', security: 'reality' };
const WS: ListenerProto = { protocol: 'vless', streamTransport: 'ws', security: 'tls' };
const GRPC: ListenerProto = { protocol: 'vless', streamTransport: 'grpc', security: 'tls' };
const SS: ListenerProto = { protocol: 'shadowsocks', streamTransport: 'raw', security: 'none' };
const HY2: ListenerProto = { protocol: 'hysteria2', streamTransport: 'udp', security: 'tls' };
const TROJAN_WS: ListenerProto = { protocol: 'trojan', streamTransport: 'ws', security: 'tls' };

describe('listener catalogue ⇔ codec table', () => {
  test.each(LISTENER_COMBOS.map((c) => [c.key, c] as const))(
    '%s has a codec row, non-empty for every format a client can speak',
    (_key, combo) => {
      const codecs = CODECS[combo.key];
      expect(codecs).toBeDefined();
      // Xray and Mihomo speak XHTTP; sing-box has no transport for it.
      const clientless = combo.streamTransport === 'xhttp' ? ['singbox'] : [];
      for (const format of RENDER_FORMATS) {
        if (clientless.includes(format)) {
          expect(codecs![format], `${combo.key} ${format}`).toEqual([]);
          expect(formatSupported(combo, format)).toBe(false);
          continue;
        }
        expect(codecs![format].length, `${combo.key} ${format}`).toBeGreaterThan(0);
        expect(codecFor(combo, format)).toEqual(codecs![format]);
        expect(formatSupported(combo, format)).toBe(true);
      }
    },
  );

  test('the codec table names only catalogued combinations (no orphan codecs)', () => {
    const keys = new Set(LISTENER_COMBOS.map((c) => c.key));
    for (const k of Object.keys(CODECS)) expect(keys.has(k as never), k).toBe(true);
    expect(Object.keys(CODECS).sort()).toEqual([...keys].sort());
  });

  test('the catalogue is exactly the twelve supported combinations, keyed uniquely', () => {
    expect(LISTENER_COMBOS.map((c) => c.key).sort()).toEqual(
      [
        'vless/raw/reality',
        'vless/raw/tls',
        'vless/ws/tls',
        'vless/httpupgrade/tls',
        'vless/grpc/tls',
        'vless/xhttp/tls',
        'vless/xhttp/reality',
        'trojan/raw/tls',
        'trojan/ws/tls',
        'shadowsocks/raw/none',
        'hysteria2/udp/tls',
        'tuic/udp/tls',
      ].sort(),
    );
    expect(new Set(LISTENER_COMBOS.map((c) => c.key)).size).toBe(LISTENER_COMBOS.length);
    for (const c of LISTENER_COMBOS) {
      expect(comboKey(c)).toBe(c.key);
      expect(listenerCombo(c)).toBe(c);
      expect(c.label.length).toBeGreaterThan(0);
    }
  });

  test('every unlisted (protocol, streamTransport, security) triple is invalid, and helpers throw on it', () => {
    let invalid = 0;
    for (const protocol of LISTENER_PROTOCOL_IDS)
      for (const streamTransport of LISTENER_STREAM_TRANSPORT_IDS)
        for (const security of LISTENER_SECURITY_IDS) {
          const p: ListenerProto = { protocol, streamTransport, security };
          const valid = isValidListenerCombo(p);
          expect(valid).toBe(!!listenerCombo(p));
          if (!valid) {
            invalid++;
            expect(() => protocolDescriptor(p)).toThrow(/invalid listener combination/);
            expect(codecFor(p, 'links')).toEqual([]);
            expect(formatSupported(p, 'singbox')).toBe(false);
            // The label of an unknown combination is its key, never a crash.
            expect(protocolLabel(p)).toBe(comboKey(p));
          }
        }
    expect(invalid).toBe(
      LISTENER_PROTOCOL_IDS.length *
        LISTENER_STREAM_TRANSPORT_IDS.length *
        LISTENER_SECURITY_IDS.length -
        LISTENER_COMBOS.length,
    );
    // The headline rejections: REALITY only over raw VLESS; Shadowsocks only plain; UDP only for the QUIC protocols.
    for (const p of [
      { protocol: 'vless', streamTransport: 'ws', security: 'reality' },
      { protocol: 'trojan', streamTransport: 'raw', security: 'reality' },
      { protocol: 'shadowsocks', streamTransport: 'raw', security: 'tls' },
      { protocol: 'shadowsocks', streamTransport: 'ws', security: 'none' },
      { protocol: 'vless', streamTransport: 'udp', security: 'tls' },
      { protocol: 'hysteria2', streamTransport: 'raw', security: 'tls' },
      { protocol: 'vless', streamTransport: 'raw', security: 'none' },
    ] as const) {
      expect(isValidListenerCombo(p), comboKey(p)).toBe(false);
    }
  });
});

describe('protocol helpers derive from the three fields', () => {
  test('l7Proof is `vless` ONLY for vless + an HTTP transport + tls', () => {
    for (const c of LISTENER_COMBOS) {
      const expected =
        c.protocol === 'vless' &&
        (c.streamTransport === 'ws' ||
          c.streamTransport === 'httpupgrade' ||
          c.streamTransport === 'grpc' ||
          c.streamTransport === 'xhttp') &&
        c.security === 'tls'
          ? 'vless'
          : 'unsupported';
      expect(protocolL7Proof(c), c.key).toBe(expected);
    }
    expect(protocolL7Proof(WS)).toBe('vless');
    expect(protocolL7Proof(GRPC)).toBe('vless');
    expect(
      protocolL7Proof({ protocol: 'vless', streamTransport: 'httpupgrade', security: 'tls' }),
    ).toBe('vless');
    // Trojan over WebSocket is HTTP-carried but has no authenticated proof.
    expect(protocolL7Proof(TROJAN_WS)).toBe('unsupported');
    expect(protocolIsHttpTransport(TROJAN_WS)).toBe(true);
    expect(protocolL7Proof(REALITY)).toBe('unsupported');
    expect(protocolL7Proof(HY2)).toBe('unsupported');
  });

  test('transport, SNI, target and Host-header flags follow the stream transport and security', () => {
    expect(protocolTransport(REALITY)).toBe('tcp');
    expect(protocolTransport(HY2)).toBe('udp');
    expect(protocolTransport({ protocol: 'tuic', streamTransport: 'udp', security: 'tls' })).toBe(
      'udp',
    );
    expect(protocolUsesSni(REALITY)).toBe(true);
    expect(protocolUsesSni(WS)).toBe(true);
    expect(protocolUsesSni(SS)).toBe(false);
    expect(protocolNeedsTarget(REALITY)).toBe(true);
    expect(protocolNeedsTarget(WS)).toBe(false);
    expect(protocolNeedsTarget(SS)).toBe(false);
    expect(protocolIsHttpTransport(REALITY)).toBe(false);
    expect(protocolIsHttpTransport(WS)).toBe(true);
    expect(protocolIsHttpTransport(GRPC)).toBe(true);
    // ws / httpupgrade write a Host header; gRPC follows the SNI.
    expect(protocolUsesHostHeader(WS)).toBe(true);
    expect(
      protocolUsesHostHeader({
        protocol: 'vless',
        streamTransport: 'httpupgrade',
        security: 'tls',
      }),
    ).toBe(true);
    expect(protocolUsesHostHeader(GRPC)).toBe(false);
    expect(protocolUsesHostHeader(REALITY)).toBe(false);
    expect(protocolLabel(REALITY)).toBe('VLESS + REALITY');
    expect(protocolLabel(SS)).toBe('Shadowsocks');
  });

  test('the legacy single-word id (renderer fixtures) is derived, never stored', () => {
    const legacy = Object.fromEntries(LISTENER_COMBOS.map((c) => [c.key, c.legacy]));
    expect(legacy).toEqual({
      'vless/raw/reality': 'reality',
      'vless/raw/tls': 'tls',
      'vless/ws/tls': 'ws',
      'vless/httpupgrade/tls': 'httpupgrade',
      'vless/grpc/tls': 'grpc',
      'vless/xhttp/tls': 'xhttp',
      'vless/xhttp/reality': 'reality',
      'trojan/raw/tls': 'tls',
      'trojan/ws/tls': 'ws',
      'shadowsocks/raw/none': 'plain',
      'hysteria2/udp/tls': 'udp',
      'tuic/udp/tls': 'udp',
    });
  });
});
