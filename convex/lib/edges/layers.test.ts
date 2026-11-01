import { describe, expect, test } from 'vitest';
import {
  certCovers,
  frontHostAccepted,
  hostTargetFor,
  l7HostHeaderFor,
  listenerAllowsLayer,
  listenerLayers,
  matchesCertName,
  originHostNeeded,
  originHostSupport,
  withOriginHost,
  zoneModeCarriesOrigin,
  type OriginTransport,
} from './layers';
import type { ListenerProto } from './protocols';

const names = (...list: string[]) => list.map((name) => ({ name, status: 'active' as const }));

const REALITY: ListenerProto = { protocol: 'vless', streamTransport: 'raw', security: 'reality' };
const TLS: ListenerProto = { protocol: 'vless', streamTransport: 'raw', security: 'tls' };
const WS: ListenerProto = { protocol: 'vless', streamTransport: 'ws', security: 'tls' };
const UPGRADE: ListenerProto = {
  protocol: 'vless',
  streamTransport: 'httpupgrade',
  security: 'tls',
};
const GRPC: ListenerProto = { protocol: 'vless', streamTransport: 'grpc', security: 'tls' };
const TROJAN_WS: ListenerProto = { protocol: 'trojan', streamTransport: 'ws', security: 'tls' };
const SS: ListenerProto = { protocol: 'shadowsocks', streamTransport: 'raw', security: 'none' };
const HY2: ListenerProto = { protocol: 'hysteria2', streamTransport: 'udp', security: 'tls' };
const TUIC: ListenerProto = { protocol: 'tuic', streamTransport: 'udp', security: 'tls' };

const httpsOrigin = (over: Partial<OriginTransport> = {}): OriginTransport => ({
  scheme: 'https',
  certPublic: true,
  certNames: ['*.example.org'],
  acceptsHostHeader: 'any',
  ...over,
});

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

describe('listenerLayers', () => {
  test('a listener without originTransport is L4 only', () => {
    expect(listenerLayers({ ...REALITY, tlsNames: names('a.example') }).layers).toEqual(['l4']);
    expect(listenerLayers({ ...WS, tlsNames: names('a.example') })).toEqual({
      layers: ['l4'],
      excluded: { l7: 'protocol_not_http_transport' },
    });
  });
  test('plaintext origin behind the CDN is L7 only', () => {
    const r = listenerLayers({
      ...WS,
      originTransport: {
        scheme: 'http',
        certPublic: false,
        certNames: [],
        acceptsHostHeader: 'any',
      },
      tlsNames: [],
    });
    expect(r.layers).toEqual(['l7']);
    expect(r.excluded.l4).toBe('origin_plaintext');
  });
  test('https origin with a public cert covering every active name is both layers', () => {
    const r = listenerLayers({
      ...WS,
      originTransport: httpsOrigin(),
      tlsNames: [...names('a.example.org'), { name: 'zzz.other', status: 'retired' }],
    });
    expect(r.layers).toEqual(['l4', 'l7']);
    expect(
      listenerAllowsLayer(
        { ...WS, originTransport: httpsOrigin(), tlsNames: names('a.example.org') },
        'l7',
      ),
    ).toBe(true);
  });
  test('public trust and name coverage are separate requirements', () => {
    const notPublic = listenerLayers({
      ...WS,
      originTransport: httpsOrigin({ certPublic: false }),
      tlsNames: names('a.example.org'),
    });
    expect(notPublic.layers).toEqual(['l7']);
    expect(notPublic.excluded.l4).toBe('cert_not_public');
    const uncovered = listenerLayers({
      ...WS,
      originTransport: httpsOrigin({ certNames: ['a.example.org'] }),
      tlsNames: names('a.example.org', 'b.example.org'),
    });
    expect(uncovered.layers).toEqual(['l7']);
    expect(uncovered.excluded.l4).toBe('cert_name_uncovered');
  });
  test('a non-HTTP stream on an https origin is L4 only', () => {
    const r = listenerLayers({
      ...TLS,
      originTransport: httpsOrigin(),
      tlsNames: names('a.example.org'),
    });
    expect(r.layers).toEqual(['l4']);
    expect(r.excluded.l7).toBe('protocol_not_http_transport');
  });
  test('Trojan over WebSocket has its own authenticated proof and is L7-frontable', () => {
    const r = listenerLayers({
      ...TROJAN_WS,
      originTransport: httpsOrigin(),
      tlsNames: names('a.example.org'),
    });
    expect(r.layers).toEqual(['l4', 'l7']);
    expect(r.excluded.l7).toBeUndefined();
    // gRPC VLESS has the proof and is frontable.
    expect(
      listenerLayers({ ...GRPC, originTransport: httpsOrigin(), tlsNames: names('a.example.org') })
        .layers,
    ).toEqual(['l4', 'l7']);
  });
  test('a UDP listener needs a provider that carries UDP; no L7 front ever does', () => {
    for (const proto of [HY2, TUIC]) {
      const none = listenerLayers({
        ...proto,
        originTransport: httpsOrigin(),
        tlsNames: names('a.example.org'),
      });
      expect(none).toEqual({
        layers: [],
        excluded: { l7: 'protocol_not_http_transport', l4: 'no_udp_provider' },
      });
      const withUdp = listenerLayers(
        { ...proto, tlsNames: names('a.example.org') },
        { udpProviderAvailable: true },
      );
      expect(withUdp.layers).toEqual(['l4']);
      expect(withUdp.excluded).toEqual({ l7: 'protocol_not_http_transport' });
    }
  });
  // --- the Host header an L7 front sends the origin (F13) --------------------------
  test('a node that answers only for its certificate names refuses a front Host it does not cover', () => {
    const listener = {
      ...WS,
      originTransport: httpsOrigin({ certNames: ['a.example.org'], acceptsHostHeader: 'names' }),
      tlsNames: names('a.example.org'),
    };
    // The minted hostname is NOT on the origin certificate: the origin would
    // reject every member connection the front forwards.
    const rewritten = listenerLayers(listener, { l7Host: 'front-1.cdn.example' });
    expect(rewritten.layers).toEqual(['l4']);
    expect(rewritten.excluded.l7).toBe('host_header_rejected');
    // A front that passes the ORIGIN's own address through is always accepted.
    expect(listenerLayers(listener, { l7Host: 'origin' }).layers).toEqual(['l4', 'l7']);
    // A covered hostname is accepted.
    expect(listenerLayers(listener, { l7Host: 'a.example.org' }).layers).toEqual(['l4', 'l7']);
  });
  test('with no front decided yet, a node that answers only for its own names stays L7 where a front can send that name', () => {
    const own = httpsOrigin({ certNames: ['origin.example.org'], acceptsHostHeader: 'names' });
    // WebSocket: some provider's front sends the origin's own name (a template
    // option, or always), so L7 stays open; each provider is judged on its own
    // (`frontHostAccepted`).
    const ws = listenerLayers({
      ...WS,
      originTransport: own,
      tlsNames: names('origin.example.org'),
    });
    expect(ws.layers).toEqual(['l4', 'l7']);
    expect(ws.excluded.l7).toBeUndefined();
    expect(
      listenerLayers(
        { ...WS, originTransport: own, tlsNames: names('origin.example.org') },
        { websocketNode: true },
      ).layers,
    ).toEqual(['l7']);
    // HTTP Upgrade and gRPC: no provider that carries them can send the
    // origin's name, so only a first-level wildcard admits L7.
    for (const proto of [UPGRADE, GRPC]) {
      const exact = listenerLayers({ ...proto, originTransport: own, tlsNames: [] });
      expect(exact.layers).toEqual([]);
      expect(exact.excluded.l7).toBe('host_header_rejected');
      const wildcard = listenerLayers({
        ...proto,
        originTransport: httpsOrigin({ certNames: ['*.example.org'], acceptsHostHeader: 'names' }),
        tlsNames: [],
      });
      expect(wildcard.layers).toEqual(['l7']);
    }
    // A decided Host is judged as it is.
    expect(
      listenerLayers(
        { ...WS, originTransport: own, tlsNames: names('origin.example.org') },
        { l7Host: 'front-1.cdn.example' },
      ).excluded.l7,
    ).toBe('host_header_rejected');
  });
  test('acceptsHostHeader `any` is unconditional', () => {
    expect(
      listenerLayers(
        {
          ...WS,
          originTransport: {
            scheme: 'http',
            certPublic: false,
            certNames: [],
            acceptsHostHeader: 'any',
          },
          tlsNames: [],
        },
        { l7Host: 'anything.example' },
      ).layers,
    ).toEqual(['l7']);
  });

  // --- name-free HTTP-transport listeners (F12) -------------------------------------
  test('an SNI-presenting listener with NO active name cannot use L4', () => {
    const r = listenerLayers({
      ...WS,
      originTransport: httpsOrigin(),
      tlsNames: [{ name: 'a.example.org', status: 'retired' }],
    });
    // Assignment could never SELECT a name, so the coverage check over an empty
    // set must not pass vacuously.
    expect(r.layers).toEqual(['l7']);
    expect(r.excluded.l4).toBe('no_server_names');
  });

  test('a no-name listener (shadowsocks) on an https origin needs no name coverage', () => {
    const r = listenerLayers({
      ...SS,
      originTransport: httpsOrigin({ certPublic: false, certNames: [] }),
      tlsNames: [],
    });
    expect(r.layers).toEqual(['l4']);
  });

  // --- a WebSocket node (lib/edges/websocketNode.ts) ---------------------------------
  test("a WebSocket node's HTTP transport is L7 only, however well its certificate covers the name", () => {
    const listener = {
      ...WS,
      originTransport: httpsOrigin({ certNames: ['origin.example.org'] }),
      tlsNames: names('origin.example.org'),
    };
    // Elsewhere the same listener is both layers.
    expect(listenerLayers(listener).layers).toEqual(['l4', 'l7']);
    const r = listenerLayers(listener, { websocketNode: true });
    expect(r.layers).toEqual(['l7']);
    expect(r.excluded.l4).toBe('l4_not_for_websocket');
    expect(listenerAllowsLayer(listener, 'l4', { websocketNode: true })).toBe(false);
    // Before its origin answered a probe it has no layer at all (never L4-only).
    const unprobed = listenerLayers(
      { ...WS, tlsNames: names('origin.example.org') },
      {
        websocketNode: true,
      },
    );
    expect(unprobed.layers).toEqual([]);
    expect(unprobed.excluded.l4).toBe('l4_not_for_websocket');
    // A plaintext origin keeps its own reason; the rule bars nothing but HTTP transports.
    expect(
      listenerLayers(
        { ...WS, originTransport: httpsOrigin({ scheme: 'http' }) },
        {
          websocketNode: true,
        },
      ).excluded.l4,
    ).toBe('origin_plaintext');
    expect(
      listenerLayers(
        { ...REALITY, originTransport: httpsOrigin(), tlsNames: names('a.example.org') },
        { websocketNode: true },
      ).layers,
    ).toEqual(['l4']);
    expect(
      listenerLayers(
        { ...REALITY, tlsNames: names('a.example.org') },
        {
          websocketNode: true,
        },
      ).layers,
    ).toEqual(['l4']);
  });
});

describe('zoneModeCarriesOrigin', () => {
  const https = httpsOrigin({ certNames: [] });
  const http: OriginTransport = { ...https, scheme: 'http', certPublic: false };
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
    // A provider that always sends the origin's own name, whatever the template says.
    expect(l7HostHeaderFor('a.example', 'hostname', 'cloudfront')).toBe('origin');
    // A template option is read as frozen: a front built to send the front name sends it.
    expect(l7HostHeaderFor('a.example', 'hostname', 'fastly')).toBe('a.example');
  });
});

describe("the origin's own name as Host", () => {
  const own = httpsOrigin({ certNames: ['origin.example.org'], acceptsHostHeader: 'names' });
  const anyHost = httpsOrigin({ certNames: ['origin.example.org'], acceptsHostHeader: 'any' });
  const wildcard = httpsOrigin({ certNames: ['*.cdn.example'], acceptsHostHeader: 'names' });

  test('originHostSupport reads the capability', () => {
    expect(originHostSupport('cloudfront')).toBe('always');
    expect(originHostSupport('fastly')).toBe('option');
    expect(originHostSupport('cloudflare')).toBeNull();
    expect(originHostSupport('gcore')).toBeNull();
    expect(originHostSupport(null)).toBeNull();
    expect(originHostSupport('nope')).toBeNull();
  });

  test('originHostNeeded: a names-only node and a front name it does not cover', () => {
    expect(originHostNeeded(anyHost)).toBe(false);
    expect(originHostNeeded(own)).toBe(true);
    expect(originHostNeeded(own, 'front-1.cdn.example')).toBe(true);
    expect(originHostNeeded(own, 'origin.example.org')).toBe(false);
    // A first-level wildcard: unknown name = could be covered; a known one is checked.
    expect(originHostNeeded(wildcard)).toBe(false);
    expect(originHostNeeded(wildcard, 'front-1.cdn.example')).toBe(false);
    expect(originHostNeeded(wildcard, 'front-1.other.example')).toBe(true);
  });

  test('withOriginHost sets the template option on a new front only where the node needs it', () => {
    const tpl = { overrideHost: 'hostname', serviceComment: 'origin edge' };
    // A names-only node behind a front whose template can send the origin's name.
    expect(withOriginHost('fastly', tpl, own, 'front-1.cdn.example')).toEqual({
      overrideHost: 'origin',
      serviceComment: 'origin edge',
    });
    // The template row is never mutated.
    expect(tpl.overrideHost).toBe('hostname');
    // The params the front is built with then send the origin's name.
    expect(
      l7HostHeaderFor(
        'front-1.cdn.example',
        withOriginHost('fastly', tpl, own, 'front-1.cdn.example').overrideHost,
        'fastly',
      ),
    ).toBe('origin');
    // A node that takes any Host, or a front name it covers, keeps the template.
    expect(withOriginHost('fastly', tpl, anyHost, 'front-1.cdn.example')).toBe(tpl);
    expect(withOriginHost('fastly', tpl, wildcard, 'front-1.cdn.example')).toBe(tpl);
    // A provider without the option (or one that always sends it) is not touched.
    expect(withOriginHost('cloudflare', tpl, own, 'front-1.cdn.example')).toBe(tpl);
    expect(withOriginHost('cloudfront', tpl, own, 'front-1.cdn.example')).toBe(tpl);
    // No origin transport: nothing to decide.
    expect(withOriginHost('fastly', tpl, null, 'front-1.cdn.example')).toBe(tpl);
  });

  test('frontHostAccepted judges each provider', () => {
    expect(frontHostAccepted('fastly', own)).toBe(true);
    expect(frontHostAccepted('cloudfront', own)).toBe(true);
    expect(frontHostAccepted('cloudflare', own)).toBe(false);
    expect(frontHostAccepted('cloudflare', anyHost)).toBe(true);
    expect(frontHostAccepted('cloudflare', wildcard)).toBe(true);
    expect(frontHostAccepted('cloudflare', wildcard, 'front-1.other.example')).toBe(false);
  });
});

describe('hostTargetFor', () => {
  const l4 = { layer: 'l4' as const, addresses: { v4: '203.0.113.10' }, edgePort: 443 };
  test('L7 uses the hostname for address, SNI and Host', () => {
    expect(
      hostTargetFor(
        { layer: 'l7', addresses: { hostname: 'abc.example.org' }, edgePort: 443 },
        WS,
        null,
      ),
    ).toEqual({
      address: 'abc.example.org',
      port: 443,
      sni: 'abc.example.org',
      host: 'abc.example.org',
    });
    expect(hostTargetFor({ layer: 'l7', addresses: {}, edgePort: 443 }, WS, null)).toBeNull();
  });
  test('L4 HTTP transport sets SNI and Host to the selected name; reality/tls SNI only; no-name neither', () => {
    expect(hostTargetFor(l4, WS, 'a.example')).toEqual({
      address: '203.0.113.10',
      port: 443,
      sni: 'a.example',
      host: 'a.example',
    });
    expect(hostTargetFor(l4, GRPC, 'a.example')).toEqual({
      address: '203.0.113.10',
      port: 443,
      sni: 'a.example',
      host: null,
    });
    expect(hostTargetFor(l4, REALITY, 'a.example')).toEqual({
      address: '203.0.113.10',
      port: 443,
      sni: 'a.example',
      host: null,
    });
    expect(hostTargetFor(l4, SS, null)).toEqual({
      address: '203.0.113.10',
      port: 443,
      sni: null,
      host: null,
    });
    expect(hostTargetFor(l4, TLS, null)).toBeNull();
    expect(hostTargetFor({ ...l4, addresses: {} }, SS, null)).toBeNull();
  });
});
