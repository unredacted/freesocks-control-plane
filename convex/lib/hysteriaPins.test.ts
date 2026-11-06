/**
 * How each format's Hysteria entries verify their server: only an expected pin
 * passes; "insecure", CA-only, a wrong pin and an override are all refused, and
 * a body that names Hysteria in a way no reader understands is flagged.
 */
import { describe, expect, test } from 'vitest';
import { encodeBase64 } from './edges/render/base64';
import { hysteriaEndpointVerified, scanHysteria } from './hysteriaPins';

const PIN = 'ab'.repeat(32);
const OTHER = 'cd'.repeat(32);
const SPKI = 'c3BraS1waW4=';
const pins = { pinHex: [PIN], spkiB64: [SPKI] };
const uuid = '11111111-2222-4333-8444-555555555555';
const hy = (q: string, host = '203.0.113.10') => `hysteria2://${uuid}@${host}:443/?${q}#n`;
const trustOf = (body: string) => scanHysteria(body, pins).entries.map((e) => e.trust);

describe('links', () => {
  test('pinned, insecure, missing pin, wrong pin', () => {
    const body = [
      'vless://x@203.0.113.9:443?security=reality#r',
      hy(`sni=q.example&pinSHA256=${PIN.toUpperCase().match(/../g)!.join(':')}`),
      hy(`sni=q.example&pinSHA256=${PIN}&insecure=1`),
      hy('sni=q.example'),
      hy(`sni=q.example&pinSHA256=${OTHER}`),
      `hy2://${uuid}@203.0.113.11:443/?sni=q.example&pinSHA256=${PIN}&insecure=0#n`,
    ].join('\n');
    const scan = scanHysteria(body, pins);
    expect(scan.format).toBe('links');
    expect(scan.entries.map((e) => [e.ref, e.trust])).toEqual([
      ['1', 'pinned'],
      ['2', 'insecure'],
      ['3', 'no_pin'],
      ['4', 'wrong_pin'],
      ['5', 'pinned'],
    ]);
    expect(scan.unreadable).toBe(false);
  });

  test('a base64-wrapped list is read the same way', () => {
    expect(trustOf(encodeBase64(hy(`sni=q.example&pinSHA256=${PIN}`)))).toEqual(['pinned']);
  });
});

describe('Clash / Mihomo', () => {
  const yaml = (extra: string) =>
    `proxies:\n  - name: h\n    type: hysteria2\n    server: 203.0.113.10\n    port: 443\n    password: x\n    sni: q.example\n${extra}`;
  test.each([
    [`    fingerprint: ${PIN}\n`, 'pinned'],
    [`    fingerprint: ${PIN}\n    skip-cert-verify: false\n`, 'pinned'],
    ['    skip-cert-verify: true\n', 'insecure'],
    // CA-only: not accepted either.
    ['', 'no_pin'],
    [`    fingerprint: ${OTHER}\n`, 'wrong_pin'],
  ])('%s -> %s', (extra, trust) => {
    expect(trustOf(yaml(extra))).toEqual([trust]);
  });
});

describe('sing-box', () => {
  const body = (tls: Record<string, unknown>) =>
    JSON.stringify({
      outbounds: [
        { type: 'direct', tag: 'direct' },
        {
          type: 'hysteria2',
          tag: 'h',
          server: '203.0.113.10',
          server_port: 443,
          password: 'x',
          tls,
        },
      ],
    });
  test.each([
    [{ enabled: true, server_name: 'q.example', certificate_public_key_sha256: [SPKI] }, 'pinned'],
    [
      {
        enabled: true,
        server_name: 'q.example',
        certificate_public_key_sha256: [SPKI],
        insecure: true,
      },
      'insecure',
    ],
    [{ enabled: true, server_name: 'q.example' }, 'no_pin'],
    // The certificate pin is not the public-key pin.
    [{ enabled: true, certificate_public_key_sha256: [PIN] }, 'wrong_pin'],
    [
      { enabled: true, certificate_public_key_sha256: [SPKI], certificate: ['-----BEGIN'] },
      'wrong_pin',
    ],
  ])('%j -> %s', (tls, trust) => {
    const scan = scanHysteria(body(tls), pins);
    expect(scan.format).toBe('singbox');
    expect(scan.entries.map((e) => e.trust)).toEqual([trust]);
  });
});

describe('Xray JSON (an object or an array of configs)', () => {
  const out = (tls: Record<string, unknown>) => ({
    protocol: 'hysteria',
    tag: 'h',
    settings: { version: 2, address: '203.0.113.10', port: 443 },
    streamSettings: { network: 'hysteria', security: 'tls', tlsSettings: tls },
  });
  test('an array of configs, each verified', () => {
    const body = JSON.stringify([
      { outbounds: [out({ serverName: 'q.example', pinnedPeerCertSha256: PIN })] },
      { outbounds: [out({ serverName: 'q.example', pinnedPeerCertSha256: `${PIN},${OTHER}` })] },
      { outbounds: [out({ serverName: 'q.example', allowInsecure: true })] },
      { outbounds: [{ protocol: 'freedom' }, out({ serverName: 'q.example' })] },
    ]);
    const scan = scanHysteria(body, pins);
    expect(scan.format).toBe('xray');
    expect(scan.entries.map((e) => [e.ref, e.trust])).toEqual([
      ['0/0', 'pinned'],
      ['1/0', 'wrong_pin'],
      ['2/0', 'insecure'],
      ['3/1', 'no_pin'],
    ]);
  });
  test('a single config object with Xray outbounds is Xray, not sing-box', () => {
    const body = JSON.stringify({ outbounds: [out({ pinnedPeerCertSha256: PIN })] });
    expect(scanHysteria(body, pins).format).toBe('xray');
  });
});

describe('what cannot be read', () => {
  test('a mention of Hysteria no reader understands is flagged', () => {
    expect(scanHysteria('<html>hysteria</html>', pins).unreadable).toBe(true);
    expect(scanHysteria('{"hysteria": true', pins).unreadable).toBe(true);
    expect(scanHysteria('vless://x@203.0.113.9:443#r', pins)).toMatchObject({
      entries: [],
      unreadable: false,
    });
  });
});

describe('hysteriaEndpointVerified', () => {
  test('the endpoint, presenting its name, pinned', () => {
    const body = [
      hy(`sni=other.example&pinSHA256=${PIN}`),
      hy(`sni=q.example&pinSHA256=${PIN}`, '203.0.113.12'),
      hy(`sni=q.example&pinSHA256=${PIN}`),
    ].join('\n');
    expect(
      hysteriaEndpointVerified(body, pins, {
        address: '203.0.113.10',
        port: 443,
        sni: 'q.example',
      }),
    ).toEqual({ found: true, trust: 'pinned', format: 'links' });
    expect(
      hysteriaEndpointVerified(hy('sni=q.example&insecure=1'), pins, {
        address: '203.0.113.10',
        port: 443,
        sni: 'q.example',
      }),
    ).toEqual({ found: false, trust: 'insecure', format: 'links' });
  });
});
