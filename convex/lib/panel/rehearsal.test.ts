import { describe, expect, test } from 'vitest';
import { bodyHasEndpoint } from './rehearsal';

const e = { address: '203.0.113.10', port: 443, publicKey: 'pk-expected' };
const link = (pbk: string, host = '203.0.113.10', port = 443) =>
  `vless://11111111-1111-4111-8111-111111111111@${host}:${port}?encryption=none&security=reality&type=tcp&sni=decoy.example&fp=chrome&pbk=${pbk}&sid=#node-a-reality`;

describe('bodyHasEndpoint', () => {
  test('link lists, plain and base64', () => {
    expect(bodyHasEndpoint('links', link('pk-expected'), e)).toEqual({
      found: true,
      keyMismatch: false,
    });
    expect(bodyHasEndpoint('links', btoa(link('pk-expected')), e)).toEqual({
      found: true,
      keyMismatch: false,
    });
    expect(bodyHasEndpoint('links', link('pk-other'), e)).toEqual({
      found: false,
      keyMismatch: true,
    });
    expect(bodyHasEndpoint('links', link('pk-expected', '198.51.100.1'), e)).toEqual({
      found: false,
      keyMismatch: false,
    });
  });
  test('sing-box JSON', () => {
    const body = JSON.stringify({
      outbounds: [
        { type: 'direct', tag: 'direct' },
        {
          type: 'vless',
          tag: 'node-a-reality',
          server: '203.0.113.10',
          server_port: 443,
          tls: { enabled: true, reality: { enabled: true, public_key: 'pk-expected' } },
        },
      ],
    });
    expect(bodyHasEndpoint('singbox', body, e)).toEqual({ found: true, keyMismatch: false });
    expect(bodyHasEndpoint('singbox', body.replace('pk-expected', 'pk-other'), e)).toEqual({
      found: false,
      keyMismatch: true,
    });
    expect(bodyHasEndpoint('singbox', 'not json', e)).toEqual({ found: false, keyMismatch: false });
  });
  test('Clash YAML', () => {
    const body = `proxies:
  - name: node-a-reality
    type: vless
    server: 203.0.113.10
    port: 443
    reality-opts:
      public-key: pk-expected
  - name: other
    type: vless
    server: 198.51.100.2
    port: 443
`;
    expect(bodyHasEndpoint('clash', body, e)).toEqual({ found: true, keyMismatch: false });
    expect(bodyHasEndpoint('clash', body.replace('pk-expected', 'pk-other'), e)).toEqual({
      found: false,
      keyMismatch: true,
    });
    expect(bodyHasEndpoint('clash', body, { ...e, port: 8443 })).toEqual({
      found: false,
      keyMismatch: false,
    });
  });
});
