import { describe, expect, test } from 'vitest';
import { certCovers, hostTargetFor, matchesCertName, slotLayers } from './layers';

const names = (...snis: string[]) => snis.map((sni) => ({ sni, status: 'active' as const }));

describe('matchesCertName (RFC 6125)', () => {
  test('exact, case-insensitive, trailing dot tolerant', () => {
    expect(matchesCertName('A.Example.org.', 'a.example.org')).toBe(true);
    expect(matchesCertName('b.example.org', 'a.example.org')).toBe(false);
  });
  test('single leftmost wildcard matches exactly one label', () => {
    expect(matchesCertName('a.example.org', '*.example.org')).toBe(true);
    expect(matchesCertName('a.b.example.org', '*.example.org')).toBe(false);
    expect(matchesCertName('example.org', '*.example.org')).toBe(false);
    expect(matchesCertName('a.example.org', 'f*.example.org')).toBe(false);
    expect(matchesCertName('a.example.org', '*.*.org')).toBe(false);
    expect(matchesCertName('a.example.org', '*')).toBe(false);
  });
  test('certCovers is any-of', () => {
    expect(certCovers('x.example.org', ['other.example', '*.example.org'])).toBe(true);
    expect(certCovers('x.example.org', ['other.example'])).toBe(false);
  });
});

describe('slotLayers', () => {
  test('legacy slot (no originTransport) is L4 only', () => {
    expect(slotLayers({}, { protocol: 'reality', serverNames: names('a.example') }).layers).toEqual(['l4']);
    expect(slotLayers({}, { protocol: 'ws', serverNames: names('a.example') })).toEqual({
      layers: ['l4'],
      excluded: { l7: 'protocol_not_http_transport' },
    });
  });
  test('plaintext origin behind the CDN is L7 only', () => {
    const r = slotLayers(
      { originTransport: { scheme: 'http', certPublic: false, certNames: [], acceptsHostHeader: 'any' } },
      { protocol: 'ws', serverNames: [] },
    );
    expect(r.layers).toEqual(['l7']);
    expect(r.excluded.l4).toBe('origin_plaintext');
  });
  test('https origin with a public cert covering every active name is both layers', () => {
    const r = slotLayers(
      {
        originTransport: {
          scheme: 'https',
          certPublic: true,
          certNames: ['*.example.org'],
          acceptsHostHeader: 'any',
        },
      },
      { protocol: 'ws', serverNames: [...names('a.example.org'), { sni: 'zzz.other', status: 'retired' }] },
    );
    expect(r.layers).toEqual(['l4', 'l7']);
  });
  test('public trust and name coverage are separate requirements', () => {
    const notPublic = slotLayers(
      { originTransport: { scheme: 'https', certPublic: false, certNames: ['*.example.org'], acceptsHostHeader: 'any' } },
      { protocol: 'ws', serverNames: names('a.example.org') },
    );
    expect(notPublic.layers).toEqual(['l7']);
    expect(notPublic.excluded.l4).toBe('cert_not_public');
    const uncovered = slotLayers(
      { originTransport: { scheme: 'https', certPublic: true, certNames: ['a.example.org'], acceptsHostHeader: 'any' } },
      { protocol: 'ws', serverNames: names('a.example.org', 'b.example.org') },
    );
    expect(uncovered.layers).toEqual(['l7']);
    expect(uncovered.excluded.l4).toBe('cert_name_uncovered');
  });
  test('a non-HTTP protocol on an https origin is L4 only', () => {
    const r = slotLayers(
      { originTransport: { scheme: 'https', certPublic: true, certNames: ['*.example.org'], acceptsHostHeader: 'any' } },
      { protocol: 'tls', serverNames: names('a.example.org') },
    );
    expect(r.layers).toEqual(['l4']);
    expect(r.excluded.l7).toBe('protocol_not_http_transport');
  });
  test('plain protocol on an https origin needs no name coverage', () => {
    const r = slotLayers(
      { originTransport: { scheme: 'https', certPublic: false, certNames: [], acceptsHostHeader: 'any' } },
      { protocol: 'plain', serverNames: [] },
    );
    expect(r.layers).toEqual(['l4']);
  });
});

describe('hostTargetFor', () => {
  const l4 = { layer: 'l4' as const, addresses: { v4: '203.0.113.10' }, edgePort: 443 };
  test('L7 uses the hostname for address, SNI and Host', () => {
    expect(
      hostTargetFor({ layer: 'l7', addresses: { hostname: 'abc.example.org' }, edgePort: 443 }, 'ws', null),
    ).toEqual({ address: 'abc.example.org', port: 443, sni: 'abc.example.org', host: 'abc.example.org' });
    expect(hostTargetFor({ layer: 'l7', addresses: {}, edgePort: 443 }, 'ws', null)).toBeNull();
  });
  test('L4 HTTP transport sets SNI and Host to the selected name; reality/tls SNI only; plain neither', () => {
    expect(hostTargetFor(l4, 'ws', 'a.example')).toEqual({ address: '203.0.113.10', port: 443, sni: 'a.example', host: 'a.example' });
    expect(hostTargetFor(l4, 'grpc', 'a.example')).toEqual({ address: '203.0.113.10', port: 443, sni: 'a.example', host: null });
    expect(hostTargetFor(l4, 'reality', 'a.example')).toEqual({ address: '203.0.113.10', port: 443, sni: 'a.example', host: null });
    expect(hostTargetFor(l4, 'plain', null)).toEqual({ address: '203.0.113.10', port: 443, sni: null, host: null });
    expect(hostTargetFor(l4, 'tls', null)).toBeNull();
    expect(hostTargetFor({ ...l4, addresses: {} }, 'plain', null)).toBeNull();
  });
});
