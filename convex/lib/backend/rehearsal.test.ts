import { describe, expect, test } from 'vitest';
import { bodyHasEndpoint } from './rehearsal';

const e = { address: '203.0.113.10', port: 443, publicKey: 'pk-expected' };
/** The same endpoint, and the server name the address is there to serve. */
const named = { ...e, sni: 'decoy.example' };
const found = { found: true, keyMismatch: false };
const link = (pbk: string, host = '203.0.113.10', port = 443, sni = 'decoy.example') =>
  `vless://11111111-1111-4111-8111-111111111111@${host}:${port}?encryption=none&security=reality&type=tcp&sni=${sni}&fp=chrome&pbk=${pbk}&sid=#node-a%20%7C%20decoy.example`;

describe('bodyHasEndpoint', () => {
  test('link lists, plain and base64', () => {
    expect(bodyHasEndpoint('links', link('pk-expected'), e)).toEqual(found);
    expect(bodyHasEndpoint('links', btoa(link('pk-expected')), e)).toEqual(found);
    expect(bodyHasEndpoint('links', link('pk-other'), e)).toEqual({
      found: false,
      keyMismatch: true,
      sniMismatch: false,
    });
    expect(bodyHasEndpoint('links', link('pk-expected', '198.51.100.1'), e)).toEqual({
      found: false,
      keyMismatch: false,
      sniMismatch: false,
    });
  });
  test('link lists carry the name the address serves', () => {
    expect(bodyHasEndpoint('links', link('pk-expected'), named)).toEqual(found);
    // The endpoint and the key are right, the name is another family name: this
    // address is not the one that was approved for it.
    expect(
      bodyHasEndpoint('links', link('pk-expected', '203.0.113.10', 443, 'other.example'), named),
    ).toEqual({ found: false, keyMismatch: false, sniMismatch: true });
  });
  test('sing-box JSON', () => {
    const body = JSON.stringify({
      outbounds: [
        { type: 'direct', tag: 'direct' },
        {
          type: 'vless',
          tag: 'node-a | decoy.example',
          server: '203.0.113.10',
          server_port: 443,
          tls: {
            enabled: true,
            server_name: 'decoy.example',
            reality: { enabled: true, public_key: 'pk-expected' },
          },
        },
      ],
    });
    expect(bodyHasEndpoint('singbox', body, e)).toEqual({ ...found, sniMismatch: false });
    expect(bodyHasEndpoint('singbox', body, named)).toEqual({ ...found, sniMismatch: false });
    expect(bodyHasEndpoint('singbox', body.replace('pk-expected', 'pk-other'), e)).toEqual({
      found: false,
      keyMismatch: true,
      sniMismatch: false,
    });
    expect(
      bodyHasEndpoint('singbox', body.replace('server_name: ', 'server_name: '), {
        ...named,
        sni: 'other.example',
      }),
    ).toEqual({ found: false, keyMismatch: false, sniMismatch: true });
    expect(bodyHasEndpoint('singbox', 'not json', e)).toEqual({
      found: false,
      keyMismatch: false,
    });
  });
  test('Clash YAML', () => {
    const body = `proxies:
  - name: node-a | decoy.example
    type: vless
    server: 203.0.113.10
    port: 443
    servername: decoy.example
    reality-opts:
      public-key: pk-expected
  - name: other
    type: vless
    server: 198.51.100.2
    port: 443
`;
    expect(bodyHasEndpoint('clash', body, e)).toEqual(found);
    expect(bodyHasEndpoint('clash', body, named)).toEqual(found);
    expect(bodyHasEndpoint('clash', body.replace('pk-expected', 'pk-other'), e)).toEqual({
      found: false,
      keyMismatch: true,
      sniMismatch: false,
    });
    expect(bodyHasEndpoint('clash', body, { ...named, sni: 'other.example' })).toEqual({
      found: false,
      keyMismatch: false,
      sniMismatch: true,
    });
    expect(bodyHasEndpoint('clash', body, { ...e, port: 8443 })).toEqual({
      found: false,
      keyMismatch: false,
      sniMismatch: false,
    });
  });
});
