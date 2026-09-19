import { describe, expect, test } from 'vitest';
import { parseProxyUri, rewriteProxyUri, uriAgrees } from './uri';
import type { ListenerProto } from '../protocols';

const XHTTP: ListenerProto = { protocol: 'vless', streamTransport: 'xhttp', security: 'tls' };
const link = (type: string) =>
  `vless://00000000-0000-4000-8000-000000000000@origin.example:443?encryption=none&security=tls&sni=origin.example&type=${type}&path=%2Fxh&mode=packet-up#node`;

describe('xhttp share links', () => {
  test.each(['xhttp', 'splithttp'])('type=%s is an XHTTP listener entry', (type) => {
    const u = parseProxyUri(link(type))!;
    expect(uriAgrees(u, XHTTP)).toBe(true);
  });

  test('a ws link is not', () => {
    expect(uriAgrees(parseProxyUri(link('ws'))!, XHTTP)).toBe(false);
  });

  test.each(['xhttp', 'splithttp'])(
    'type=%s gains the edge Host even when the template carried none',
    (type) => {
      const out = rewriteProxyUri(parseProxyUri(link(type))!, {
        address: 'front.example',
        port: 443,
        sni: 'front.example',
        hostHeader: 'front.example',
        label: 'Primary',
      });
      const qs = new URLSearchParams(out.slice(out.indexOf('?') + 1, out.indexOf('#')));
      expect(qs.get('host')).toBe('front.example');
      expect(qs.get('sni')).toBe('front.example');
      // The node's routing is never touched; the spelling the client understands stays.
      expect(qs.get('path')).toBe('/xh');
      expect(qs.get('type')).toBe(type);
      expect(out).not.toContain('origin.example');
    },
  );
});
