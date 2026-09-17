import { describe, expect, test } from 'vitest';
import {
  certCovers,
  hostTargetFor,
  l7HostHeaderFor,
  matchesCertName,
  slotLayers,
  zoneModeCarriesOrigin,
} from './layers';

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
    expect(slotLayers({}, { protocol: 'reality', serverNames: names('a.example') }).layers).toEqual(
      ['l4'],
    );
    expect(slotLayers({}, { protocol: 'ws', serverNames: names('a.example') })).toEqual({
      layers: ['l4'],
      excluded: { l7: 'protocol_not_http_transport' },
    });
  });
  test('plaintext origin behind the CDN is L7 only', () => {
    const r = slotLayers(
      {
        originTransport: {
          scheme: 'http',
          certPublic: false,
          certNames: [],
          acceptsHostHeader: 'any',
        },
      },
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
      {
        protocol: 'ws',
        serverNames: [...names('a.example.org'), { sni: 'zzz.other', status: 'retired' }],
      },
    );
    expect(r.layers).toEqual(['l4', 'l7']);
  });
  test('public trust and name coverage are separate requirements', () => {
    const notPublic = slotLayers(
      {
        originTransport: {
          scheme: 'https',
          certPublic: false,
          certNames: ['*.example.org'],
          acceptsHostHeader: 'any',
        },
      },
      { protocol: 'ws', serverNames: names('a.example.org') },
    );
    expect(notPublic.layers).toEqual(['l7']);
    expect(notPublic.excluded.l4).toBe('cert_not_public');
    const uncovered = slotLayers(
      {
        originTransport: {
          scheme: 'https',
          certPublic: true,
          certNames: ['a.example.org'],
          acceptsHostHeader: 'any',
        },
      },
      { protocol: 'ws', serverNames: names('a.example.org', 'b.example.org') },
    );
    expect(uncovered.layers).toEqual(['l7']);
    expect(uncovered.excluded.l4).toBe('cert_name_uncovered');
  });
  test('a non-HTTP protocol on an https origin is L4 only', () => {
    const r = slotLayers(
      {
        originTransport: {
          scheme: 'https',
          certPublic: true,
          certNames: ['*.example.org'],
          acceptsHostHeader: 'any',
        },
      },
      { protocol: 'tls', serverNames: names('a.example.org') },
    );
    expect(r.layers).toEqual(['l4']);
    expect(r.excluded.l7).toBe('protocol_not_http_transport');
  });
  // --- the Host header an L7 front sends the origin (F13) --------------------------
  test('a node that answers only for its certificate names refuses a front Host it does not cover', () => {
    const slot = {
      originTransport: {
        scheme: 'https' as const,
        certPublic: true,
        certNames: ['a.example.org'],
        acceptsHostHeader: 'names' as const,
      },
    };
    const profile = { protocol: 'ws' as const, serverNames: names('a.example.org') };
    // The minted hostname is NOT on the origin certificate: the origin would
    // reject every member connection the front forwards.
    const rewritten = slotLayers(slot, profile, { l7Host: 'front-1.cdn.example' });
    expect(rewritten.layers).toEqual(['l4']);
    expect(rewritten.excluded.l7).toBe('host_header_rejected');
    // A front that passes the ORIGIN's own address through is always accepted.
    expect(slotLayers(slot, profile, { l7Host: 'origin' }).layers).toEqual(['l4', 'l7']);
    // A covered hostname is accepted.
    expect(slotLayers(slot, profile, { l7Host: 'a.example.org' }).layers).toEqual(['l4', 'l7']);
  });
  test('with no Host decided yet, only a first-level wildcard admits L7', () => {
    const profile = { protocol: 'ws' as const, serverNames: [] };
    const exact = slotLayers(
      {
        originTransport: {
          scheme: 'http',
          certPublic: false,
          certNames: ['a.example.org'],
          acceptsHostHeader: 'names',
        },
      },
      profile,
    );
    expect(exact.layers).toEqual([]);
    expect(exact.excluded.l7).toBe('host_header_rejected');
    const wildcard = slotLayers(
      {
        originTransport: {
          scheme: 'http',
          certPublic: false,
          certNames: ['*.example.org'],
          acceptsHostHeader: 'names',
        },
      },
      profile,
    );
    expect(wildcard.layers).toEqual(['l7']);
  });
  test('acceptsHostHeader `any` is unconditional', () => {
    expect(
      slotLayers(
        {
          originTransport: {
            scheme: 'http',
            certPublic: false,
            certNames: [],
            acceptsHostHeader: 'any',
          },
        },
        { protocol: 'ws', serverNames: [] },
        { l7Host: 'anything.example' },
      ).layers,
    ).toEqual(['l7']);
  });

  // --- name-free HTTP-transport profiles (F12) -------------------------------------
  test('an SNI-presenting profile with NO active name cannot use L4', () => {
    const r = slotLayers(
      {
        originTransport: {
          scheme: 'https',
          certPublic: true,
          certNames: ['*.example.org'],
          acceptsHostHeader: 'any',
        },
      },
      { protocol: 'ws', serverNames: [{ sni: 'a.example.org', status: 'retired' }] },
    );
    // Assignment could never SELECT a name, so the coverage check over an empty
    // set must not pass vacuously.
    expect(r.layers).toEqual(['l7']);
    expect(r.excluded.l4).toBe('no_server_names');
  });

  test('plain protocol on an https origin needs no name coverage', () => {
    const r = slotLayers(
      {
        originTransport: {
          scheme: 'https',
          certPublic: false,
          certNames: [],
          acceptsHostHeader: 'any',
        },
      },
      { protocol: 'plain', serverNames: [] },
    );
    expect(r.layers).toEqual(['l4']);
  });
});

describe('zoneModeCarriesOrigin', () => {
  const https = {
    scheme: 'https' as const,
    certPublic: true,
    certNames: [],
    acceptsHostHeader: 'any' as const,
  };
  const http = { ...https, scheme: 'http' as const, certPublic: false };
  test('a plaintext origin needs the mode that dials HTTP; an HTTPS origin the ones that dial HTTPS', () => {
    expect(zoneModeCarriesOrigin('flexible', http)).toBe(true);
    expect(zoneModeCarriesOrigin('full', http)).toBe(false);
    expect(zoneModeCarriesOrigin('strict', http)).toBe(false);
    expect(zoneModeCarriesOrigin('full', https)).toBe(true);
    expect(zoneModeCarriesOrigin('Strict', https)).toBe(true);
    expect(zoneModeCarriesOrigin('flexible', https)).toBe(false);
    expect(zoneModeCarriesOrigin('off', https)).toBe(false);
  });
  test('the strictest mode validates the origin certificate, so a private one fails it', () => {
    expect(zoneModeCarriesOrigin('strict', { ...https, certPublic: false })).toBe(false);
    expect(zoneModeCarriesOrigin('full', { ...https, certPublic: false })).toBe(true);
  });
});

describe('l7HostHeaderFor', () => {
  test('the template decides between the minted hostname and the origin address', () => {
    expect(l7HostHeaderFor('a.example', 'hostname')).toBe('a.example');
    expect(l7HostHeaderFor('a.example', 'origin')).toBe('origin');
    expect(l7HostHeaderFor(null, undefined)).toBeUndefined();
  });
});

describe('hostTargetFor', () => {
  const l4 = { layer: 'l4' as const, addresses: { v4: '203.0.113.10' }, edgePort: 443 };
  test('L7 uses the hostname for address, SNI and Host', () => {
    expect(
      hostTargetFor(
        { layer: 'l7', addresses: { hostname: 'abc.example.org' }, edgePort: 443 },
        'ws',
        null,
      ),
    ).toEqual({
      address: 'abc.example.org',
      port: 443,
      sni: 'abc.example.org',
      host: 'abc.example.org',
    });
    expect(hostTargetFor({ layer: 'l7', addresses: {}, edgePort: 443 }, 'ws', null)).toBeNull();
  });
  test('L4 HTTP transport sets SNI and Host to the selected name; reality/tls SNI only; plain neither', () => {
    expect(hostTargetFor(l4, 'ws', 'a.example')).toEqual({
      address: '203.0.113.10',
      port: 443,
      sni: 'a.example',
      host: 'a.example',
    });
    expect(hostTargetFor(l4, 'grpc', 'a.example')).toEqual({
      address: '203.0.113.10',
      port: 443,
      sni: 'a.example',
      host: null,
    });
    expect(hostTargetFor(l4, 'reality', 'a.example')).toEqual({
      address: '203.0.113.10',
      port: 443,
      sni: 'a.example',
      host: null,
    });
    expect(hostTargetFor(l4, 'plain', null)).toEqual({
      address: '203.0.113.10',
      port: 443,
      sni: null,
      host: null,
    });
    expect(hostTargetFor(l4, 'tls', null)).toBeNull();
    expect(hostTargetFor({ ...l4, addresses: {} }, 'plain', null)).toBeNull();
  });
});
