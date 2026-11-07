/**
 * The delivery guard: only Hysteria entries verified by an expected pin reach
 * a member. Anything else is dropped with every reference repaired, or the
 * body is refused; it is never handed out as it came.
 */
import { describe, expect, test } from 'vitest';
import YAML from 'yaml';
import { decodeBase64Loose, encodeBase64 } from './edges/render/base64';
import { guardHysteria } from './hysteriaGuard';

const PIN = 'ab'.repeat(32);
const SPKI = 'c3BraS1waW4=';
const pins = { pinHex: [PIN], spkiB64: [SPKI] };
const uuid = '11111111-2222-4333-8444-555555555555';
const reality = `vless://${uuid}@203.0.113.10:443?security=reality&sni=d.example#node-a%20%7C%20d.example`;
const hy = (q: string) =>
  `hysteria2://${uuid}@203.0.113.10:443/?sni=q.example&${q}#node-a%20%7C%20q.example`;

describe('a body without Hysteria', () => {
  test('is handed back as it was, unread', () => {
    const body = encodeBase64(reality);
    expect(guardHysteria(body, pins)).toEqual({ kind: 'kept', content: body, dropped: 0 });
  });
});

describe('links (plain and base64)', () => {
  test('a pinned entry stays; the body is unchanged', () => {
    const body = [reality, hy(`pinSHA256=${PIN}`)].join('\n');
    expect(guardHysteria(body, pins)).toEqual({ kind: 'kept', content: body, dropped: 0 });
  });

  test('insecure, missing and wrong pins go; REALITY stays; the encoding is kept', () => {
    const body = encodeBase64(
      [reality, hy('insecure=1'), hy(''), hy(`pinSHA256=${'cd'.repeat(32)}`)].join('\n'),
    );
    const out = guardHysteria(body, pins);
    expect(out).toMatchObject({ kind: 'kept', dropped: 3 });
    expect(decodeBase64Loose((out as { content: string }).content)).toBe(reality);
  });

  test('nothing left to connect with: refused', () => {
    expect(guardHysteria(hy('insecure=1'), pins)).toEqual({
      kind: 'refuse',
      reason: 'hysteria_unverifiable',
      dropped: 1,
    });
  });
});

describe('Clash / Mihomo', () => {
  const doc = (hyExtra: Record<string, unknown>, groupMembers = ['r', 'h'], rules: string[] = []) =>
    YAML.stringify({
      proxies: [
        { name: 'r', type: 'vless', server: '203.0.113.10', port: 443 },
        {
          name: 'h',
          type: 'hysteria2',
          server: '203.0.113.10',
          port: 443,
          sni: 'q.example',
          ...hyExtra,
        },
      ],
      'proxy-groups': [{ name: 'Auto', type: 'url-test', proxies: groupMembers }],
      rules: ['MATCH,Auto', ...rules],
    });

  test('a skip-verify entry goes and the group no longer names it', () => {
    const out = guardHysteria(doc({ 'skip-cert-verify': true }), pins);
    expect(out).toMatchObject({ kind: 'kept', dropped: 1 });
    const parsed = YAML.parse((out as { content: string }).content);
    expect(parsed.proxies.map((p: { name: string }) => p.name)).toEqual(['r']);
    expect(parsed['proxy-groups'][0].proxies).toEqual(['r']);
  });

  test('CA-only is not accepted either', () => {
    expect(guardHysteria(doc({}), pins)).toMatchObject({ kind: 'kept', dropped: 1 });
    expect(guardHysteria(doc({ fingerprint: PIN }), pins)).toMatchObject({
      kind: 'kept',
      dropped: 0,
    });
  });

  test('a group the drop would empty, or a rule naming the entry: refused', () => {
    expect(guardHysteria(doc({}, ['h']), pins).kind).toBe('refuse');
    expect(guardHysteria(doc({}, ['r', 'h'], ['DOMAIN,x.example,h']), pins).kind).toBe('refuse');
  });
});

describe('sing-box', () => {
  const body = (tls: Record<string, unknown>, extra: Record<string, unknown> = {}) =>
    JSON.stringify({
      outbounds: [
        { type: 'selector', tag: 'select', outbounds: ['r', 'h'], default: 'h' },
        { type: 'vless', tag: 'r', server: '203.0.113.10', server_port: 443 },
        { type: 'hysteria2', tag: 'h', server: '203.0.113.10', server_port: 443, tls },
        { type: 'direct', tag: 'direct' },
      ],
      route: { final: 'select' },
      ...extra,
    });

  test('an insecure entry goes; the selector loses it and its default moves', () => {
    const out = guardHysteria(body({ enabled: true, insecure: true }), pins);
    expect(out).toMatchObject({ kind: 'kept', dropped: 1 });
    const parsed = JSON.parse((out as { content: string }).content);
    expect(parsed.outbounds.map((o: { tag: string }) => o.tag)).toEqual(['select', 'r', 'direct']);
    expect(parsed.outbounds[0]).toMatchObject({ outbounds: ['r'], default: 'r' });
  });

  test('pinned by the public key: kept', () => {
    expect(
      guardHysteria(body({ enabled: true, certificate_public_key_sha256: [SPKI] }), pins),
    ).toMatchObject({ kind: 'kept', dropped: 0 });
  });

  test('a reference the guard cannot remove (a route rule): refused', () => {
    expect(
      guardHysteria(
        body({ enabled: true }, { route: { final: 'select', rules: [{ outbound: 'h' }] } }),
        pins,
      ).kind,
    ).toBe('refuse');
  });
});

describe('Xray JSON', () => {
  const cfg = (tls: Record<string, unknown>) => ({
    outbounds: [
      {
        protocol: 'hysteria',
        tag: 'proxy',
        settings: { version: 2, address: '203.0.113.10', port: 443 },
        streamSettings: { network: 'hysteria', security: 'tls', tlsSettings: tls },
      },
      { protocol: 'freedom', tag: 'direct' },
    ],
  });
  const realityCfg = {
    outbounds: [{ protocol: 'vless', tag: 'proxy', settings: {} }, { protocol: 'freedom' }],
  };

  test('in an array, an unpinned config goes whole', () => {
    const body = JSON.stringify([realityCfg, cfg({ serverName: 'q.example' })]);
    const out = guardHysteria(body, pins);
    expect(out).toMatchObject({ kind: 'kept', dropped: 1 });
    expect(JSON.parse((out as { content: string }).content)).toEqual([realityCfg]);
  });

  test('a pinned config stays', () => {
    const body = JSON.stringify([cfg({ serverName: 'q.example', pinnedPeerCertSha256: PIN })]);
    expect(guardHysteria(body, pins)).toMatchObject({ kind: 'kept', dropped: 0 });
  });

  test('the only config insecure: refused', () => {
    expect(guardHysteria(JSON.stringify([cfg({ allowInsecure: true })]), pins).kind).toBe('refuse');
  });
});

describe('what cannot be read', () => {
  test('a body that names Hysteria in a way no reader understands: refused', () => {
    expect(guardHysteria('<html>hysteria</html>', pins).kind).toBe('refuse');
    expect(guardHysteria('{"hysteria": ', pins).kind).toBe('refuse');
  });
});

describe('what a review found (escapes, loose flags, mixed shapes, dead links)', () => {
  test('a type spelled with escapes is still read and judged', () => {
    const singbox =
      '{"outbounds":[{"type":"vless","tag":"r","server":"203.0.113.10","server_port":443},' +
      '{"type":"hy\\u0073teria2","tag":"h","server":"203.0.113.10","server_port":443,' +
      '"tls":{"enabled":true,"insecure":true}}]}';
    const out = guardHysteria(singbox, pins);
    expect(out).toMatchObject({ kind: 'kept', dropped: 1 });
    expect((out as { content: string }).content).not.toContain('"h"');
    const yaml =
      'proxies:\n  - {name: r, type: vless, server: 203.0.113.10, port: 443}\n' +
      '  - {name: h, type: "hy\\x73teria2", server: 203.0.113.10, port: 443, skip-cert-verify: true}\n';
    expect(guardHysteria(yaml, pins)).toMatchObject({ kind: 'kept', dropped: 1 });
    // A Clash body written as a flow mapping JSON refuses is read too.
    expect(
      guardHysteria(
        '{proxies: [{name: h, type: hysteria2, server: 203.0.113.10, port: 443}]}',
        pins,
      ).kind,
    ).toBe('refuse');
  });

  test('Mihomo reads its flags loosely: 1, "true" and "t" switch verification off', () => {
    const mihomo = (skip: unknown) =>
      YAML.stringify({
        proxies: [
          { name: 'r', type: 'vless', server: '203.0.113.10', port: 443 },
          {
            name: 'h',
            type: 'hysteria2',
            server: '203.0.113.10',
            port: 443,
            fingerprint: PIN,
            'skip-cert-verify': skip,
          },
        ],
      });
    for (const on of [1, 'true', 't', 'yes'])
      expect(guardHysteria(mihomo(on), pins)).toMatchObject({ kind: 'kept', dropped: 1 });
    for (const off of [false, 0, 'false', '0'])
      expect(guardHysteria(mihomo(off), pins)).toMatchObject({ kind: 'kept', dropped: 0 });
  });

  test('sing-box type and Xray protocol markers together: refused when Hysteria is in it', () => {
    const mixed = JSON.stringify({
      outbounds: [
        { protocol: 'vless', type: 'vless', settings: {} },
        {
          protocol: 'hysteria',
          tag: 'h',
          settings: { version: 2, address: '203.0.113.10', port: 443 },
          streamSettings: { network: 'hysteria', security: 'tls', tlsSettings: {} },
        },
      ],
    });
    expect(guardHysteria(mixed, pins).kind).toBe('refuse');
    // Without Hysteria, such a body is none of the guard's business.
    const plain = JSON.stringify({ outbounds: [{ protocol: 'vless', type: 'vless' }] });
    expect(guardHysteria(plain, pins)).toEqual({ kind: 'kept', content: plain, dropped: 0 });
  });

  test('a link that cannot connect is not a connection left', () => {
    expect(guardHysteria([hy('insecure=1'), 'vless://'].join('\n'), pins).kind).toBe('refuse');
  });

  test('a body only a client might read, with an escape in it: refused', () => {
    const bomb = 'a: &a [x]\nb: *a\nc: "hy\\x73teria2"\nd: [' + '*a,'.repeat(200) + ']\n';
    expect(guardHysteria(bomb, pins).kind).toBe('refuse');
  });
});
