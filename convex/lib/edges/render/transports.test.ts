/**
 * Every listener combination x every subscription format: what the renderer
 * rewrites (address, port, server name, HTTP Host) and what it must leave
 * alone (the node's own path / service name / credentials), behind an L4 edge
 * (an IP literal, the name comes from the listener) and behind an L7 edge (one
 * fronted hostname that is address, SNI and Host at once).
 *
 * The bodies are the admin preview fixtures, so the preview and the member's
 * real subscription are exercised by the same assertions.
 */
import { describe, expect, test } from 'vitest';
import YAML from 'yaml';
import { EDGE_DEFAULTS, defaultClientRule } from '../../edgeConfig';
import { assignEndpoints, type PublishedEdge } from '../assignment';
import { previewBody } from '../preview';
import {
  LISTENER_COMBOS,
  comboKey,
  formatSupported,
  protocolUsesHostHeader,
  type ListenerProto,
  type RenderFormat,
} from '../protocols';
import { effectiveRule, renderEdgeEndpoints, renderEntries } from '../render';
import { orderEndpoints, type RenderEndpoint, type RenderMatcher } from './types';

const TEMPLATE = 'node-a-relay-a1';
const KEY = 'ab'.repeat(32);
/** The preview fixtures' origin. */
const ORIGIN = '192.0.2.10';
const L4_ADDRESS = '203.0.113.10';
const L4_NAME = 'cdn-a.example';
const HOSTNAME = 'front-a.example';
/** What the preview fixtures carry before the rewrite. */
const TEMPLATE_NAME = 'node.example';
const TEMPLATE_PATH = '/ws';
const TEMPLATE_SERVICE = 'GunService';

const cfg = { ...EDGE_DEFAULTS.render, enabled: true };
const rules = {
  links: effectiveRule(cfg, defaultClientRule('v2rayng')),
  'singbox-json': effectiveRule(cfg, defaultClientRule('singbox')),
  'clash-yaml': effectiveRule(cfg, defaultClientRule('mihomo')),
} as const;
type Format = keyof typeof rules;
const FORMATS = Object.keys(rules) as Format[];
/** The body format's name in the codec table. */
const FORMAT_OF: Record<Format, RenderFormat> = {
  links: 'links',
  'singbox-json': 'singbox',
  'clash-yaml': 'clash',
};

const proto = (p: ListenerProto): ListenerProto => ({
  protocol: p.protocol,
  streamTransport: p.streamTransport,
  security: p.security,
});
const originPortOf = (p: ListenerProto) => (p.protocol === 'shadowsocks' ? 8388 : 443);

const base = {
  poolIndex: 0,
  provider: 'gcore',
  listenerId: 'l1',
  listenerKey: 'a1',
  matchRule: { kind: 'remark' as const, remark: TEMPLATE },
  serverNames: [{ sni: L4_NAME, status: 'active' as const }],
};
const l4 = (p: ListenerProto): PublishedEdge => ({
  ...base,
  edgeId: 'e4',
  proto: proto(p),
  edgePort: 8443,
  addresses: { v4: L4_ADDRESS },
});
const l7 = (p: ListenerProto): PublishedEdge => ({
  ...base,
  edgeId: 'e7',
  proto: proto(p),
  layer: 'l7',
  edgePort: 443,
  addresses: { hostname: HOSTNAME },
  serverNames: [],
});
const matcherFor = (p: ListenerProto): RenderMatcher => ({
  listenerKey: 'a1',
  rule: { kind: 'remark', remark: TEMPLATE },
  proto: proto(p),
  originAddress: ORIGIN,
  originPort: originPortOf(p),
});

function render(edge: PublishedEdge, format: Format, p: ListenerProto) {
  const assigned = assignEndpoints(KEY, [edge], {
    now: Date.now(),
    preferDistinctProviders: false,
    includeBackup: false,
  });
  const out = renderEdgeEndpoints({
    body: previewBody(format, [TEMPLATE], proto(p)),
    matchers: [matcherFor(p)],
    assigned,
    rule: rules[format],
    originAddress: ORIGIN,
  });
  expect(out.delivery).toEqual({ kind: 'serve' });
  expect(out.applied).toBe(true);
  expect(out.emitted).toBe(1);
  return { out, assigned };
}

/** The one rewritten entry, normalised across the three formats. */
interface Emitted {
  address: string;
  port: number;
  sni: string | null;
  host: string | null;
  path: string | null;
  service: string | null;
}

function emittedLink(body: string): Emitted {
  const line = body.split('\n')[0];
  const q = line.indexOf('?');
  const hash = line.indexOf('#');
  const qs = new URLSearchParams(q < 0 ? '' : line.slice(q + 1, hash));
  const at = line.lastIndexOf('@');
  const hostPort = line.slice(at + 1, q < 0 ? hash : q);
  const colon = hostPort.lastIndexOf(':');
  return {
    address: hostPort.slice(0, colon),
    port: Number(hostPort.slice(colon + 1)),
    sni: qs.get('sni'),
    host: qs.get('host') ?? qs.get('authority'),
    path: qs.get('path'),
    service: qs.get('serviceName'),
  };
}

function emittedSingbox(body: string): Emitted {
  const doc = JSON.parse(body) as { outbounds: Array<Record<string, unknown>> };
  const ob = doc.outbounds.find((o) => String(o.tag).startsWith('FreeSocks Primary'))!;
  const tls = (ob.tls ?? null) as { server_name?: string } | null;
  const transport = (ob.transport ?? null) as {
    type?: string;
    path?: string;
    host?: string;
    service_name?: string;
    headers?: Record<string, string>;
  } | null;
  return {
    address: String(ob.server),
    port: Number(ob.server_port),
    sni: tls?.server_name ?? null,
    host: transport?.headers?.Host ?? transport?.host ?? null,
    path: transport?.path ?? null,
    service: transport?.service_name ?? null,
  };
}

function emittedClash(body: string): Emitted {
  const doc = YAML.parse(body) as { proxies: Array<Record<string, unknown>> };
  const p = doc.proxies.find((x) => String(x.name).startsWith('FreeSocks Primary'))!;
  const ws = (p['ws-opts'] ?? null) as { path?: string; headers?: Record<string, string> } | null;
  const grpc = (p['grpc-opts'] ?? null) as Record<string, string> | null;
  const xhttp = (p['xhttp-opts'] ?? null) as { path?: string; host?: string } | null;
  return {
    address: String(p.server),
    port: Number(p.port),
    sni: (p.servername ?? p.sni ?? null) as string | null,
    host: ws?.headers?.Host ?? xhttp?.host ?? null,
    path: ws?.path ?? xhttp?.path ?? null,
    service: grpc?.['grpc-service-name'] ?? null,
  };
}

const READ: Record<Format, (body: string) => Emitted> = {
  links: emittedLink,
  'singbox-json': emittedSingbox,
  'clash-yaml': emittedClash,
};

const isHttp = (p: ListenerProto) =>
  p.streamTransport === 'ws' ||
  p.streamTransport === 'httpupgrade' ||
  p.streamTransport === 'xhttp';

describe('every listener combination x every format', () => {
  for (const combo of LISTENER_COMBOS) {
    const key = comboKey(combo);
    for (const format of FORMATS) {
      // A format with no codec for the combination (sing-box has no XHTTP) is never served through an edge: the origin entry must not leak,
      // so delivery is unavailable rather than a body with the node in it.
      if (!formatSupported(combo, FORMAT_OF[format])) {
        test(`${key} / ${format}: no codec, so delivery is unavailable and the origin never leaves`, () => {
          const assigned = assignEndpoints(KEY, [l4(combo)], {
            now: Date.now(),
            preferDistinctProviders: false,
            includeBackup: false,
          });
          const out = renderEdgeEndpoints({
            body: previewBody(format, [TEMPLATE], proto(combo)),
            matchers: [matcherFor(combo)],
            assigned,
            rule: rules[format],
            originAddress: ORIGIN,
          });
          expect(out.delivery).toEqual({ kind: 'unavailable', reason: 'entry_mismatch' });
          expect(out.applied).toBe(false);
        });
        continue;
      }
      test(`${key} / ${format}: L4 edge swaps address, port and name only`, () => {
        const { out } = render(l4(combo), format, combo);
        const e = READ[format](out.body);
        expect(e.address).toBe(L4_ADDRESS);
        expect(e.port).toBe(8443);
        // `none` security carries no name: the template's own parameters stand.
        expect(e.sni).toBe(combo.security === 'none' ? null : L4_NAME);
        // The HTTP transports get the selected name as Host; a link list keeps
        // the template's `authority=` when there is no Host to write (gRPC).
        const wantHost =
          format === 'links' && combo.streamTransport === 'grpc'
            ? TEMPLATE_NAME
            : protocolUsesHostHeader(combo)
              ? L4_NAME
              : null;
        expect(e.host).toBe(wantHost);
        // Never touched: the node's own routing.
        if (isHttp(combo)) expect(e.path).toBe(TEMPLATE_PATH);
        if (combo.streamTransport === 'grpc' && format !== 'links')
          expect(e.service).toBe(TEMPLATE_SERVICE);
        expect(out.body).not.toContain(ORIGIN);
      });

      test(`${key} / ${format}: L7 edge is the hostname as address, SNI and Host`, () => {
        const { out } = render(l7(combo), format, combo);
        const e = READ[format](out.body);
        expect(e.address).toBe(HOSTNAME);
        expect(e.port).toBe(443);
        // A sing-box `none` template carries no `tls` block and the renderer
        // never invents one (such a listener is not L7-frontable anyway: only
        // the HTTP transports are, see lib/edges/layers.ts).
        expect(e.sni).toBe(
          format === 'singbox-json' && combo.security === 'none' ? null : HOSTNAME,
        );
        // The Host is written wherever the transport carries one; a raw
        // template has no Host field (and gRPC takes the authority from the
        // name), so only an existing parameter is synced.
        const carriesHost =
          protocolUsesHostHeader(combo) || (format === 'links' && combo.streamTransport === 'grpc');
        expect(e.host).toBe(carriesHost ? HOSTNAME : null);
        if (isHttp(combo)) expect(e.path).toBe(TEMPLATE_PATH);
        if (combo.streamTransport === 'grpc' && format !== 'links')
          expect(e.service).toBe(TEMPLATE_SERVICE);
        // Exactly one entry: an L7 front has no address families of its own.
        const bodies = {
          links: () => out.body.split('\n').filter((l) => l.includes('FreeSocks')).length,
          'singbox-json': () =>
            (
              JSON.parse(out.body) as { outbounds: Array<{ tag: string; type: string }> }
            ).outbounds.filter(
              (o) => o.type !== 'selector' && o.type !== 'urltest' && o.tag.startsWith('FreeSocks'),
            ).length,
          'clash-yaml': () =>
            (YAML.parse(out.body) as { proxies: Array<{ name: string }> }).proxies.filter((p) =>
              p.name.startsWith('FreeSocks'),
            ).length,
        };
        expect(bodies[format]()).toBe(1);
      });
    }
  }

  test('a shadowsocks L4 template keeps its userinfo and gains no TLS parameter', () => {
    const ss: ListenerProto = { protocol: 'shadowsocks', streamTransport: 'raw', security: 'none' };
    const { out } = render(l4(ss), 'links', ss);
    const line = out.body.split('\n')[0];
    expect(line.startsWith('ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpleGFtcGxlLXBhc3N3b3Jk@')).toBe(
      true,
    );
    expect(line).not.toContain('sni=');
    expect(line).not.toContain('security=');
  });

  test('REALITY credentials survive every rewrite', () => {
    const reality: ListenerProto = {
      protocol: 'vless',
      streamTransport: 'raw',
      security: 'reality',
    };
    for (const format of FORMATS) {
      const { out } = render(l4(reality), format, reality);
      expect(out.body).toContain('EXAMPLE_PUBLIC_KEY');
      expect(out.body).toContain('0123abcd');
    }
  });

  test('the preview body for a listener never matches a template speaking something else', () => {
    // A ws/tls body against a REALITY matcher: the entry is there by remark but disagrees.
    const ws: ListenerProto = { protocol: 'vless', streamTransport: 'ws', security: 'tls' };
    const reality: ListenerProto = {
      protocol: 'vless',
      streamTransport: 'raw',
      security: 'reality',
    };
    for (const format of FORMATS) {
      const assigned = assignEndpoints(KEY, [l4(reality)], {
        now: Date.now(),
        preferDistinctProviders: false,
        includeBackup: false,
      });
      const out = renderEdgeEndpoints({
        body: previewBody(format, [TEMPLATE], ws),
        matchers: [matcherFor(reality)],
        assigned,
        rule: rules[format],
        originAddress: ORIGIN,
      });
      expect(out.delivery).toEqual({ kind: 'unavailable', reason: 'entry_mismatch' });
    }
  });
});

describe('renderEntries and hostname edges', () => {
  const ws: ListenerProto = { protocol: 'vless', streamTransport: 'ws', security: 'tls' };
  const reality: ListenerProto = { protocol: 'vless', streamTransport: 'raw', security: 'reality' };
  const entryOf = (edge: PublishedEdge, ipv6Mode: 'off' | 'both'): RenderEndpoint[] => {
    const assigned = assignEndpoints(KEY, [edge], {
      now: Date.now(),
      preferDistinctProviders: false,
      includeBackup: false,
    });
    return renderEntries(assigned, { ...rules.links, ipv6Mode }, false);
  };

  test('a hostname edge yields exactly one `name` entry, whatever the IPv6 mode', () => {
    for (const mode of ['off', 'both'] as const) {
      const entries = entryOf(l7(ws), mode);
      expect(entries).toHaveLength(1);
      expect(entries[0]).toMatchObject({
        family: 'name',
        address: HOSTNAME,
        sni: HOSTNAME,
        hostHeader: HOSTNAME,
        port: 443,
        listenerKey: 'a1',
      });
    }
  });

  test('a `name` entry is ordered like a v4 one (the endpoint, ahead of any v6 sibling)', () => {
    const entries: RenderEndpoint[] = [
      {
        role: 'backup',
        label: 'B',
        edgeId: 'e4',
        listenerKey: 'a1',
        address: L4_ADDRESS,
        family: 'v4',
        port: 443,
        sni: null,
        hostHeader: null,
      },
      {
        role: 'backup',
        label: 'B6',
        edgeId: 'e4',
        listenerKey: 'a1',
        address: '2001:db8::10',
        family: 'v6',
        port: 443,
        sni: null,
        hostHeader: null,
      },
      {
        role: 'primary',
        label: 'P',
        edgeId: 'e7',
        listenerKey: 'a1',
        address: HOSTNAME,
        family: 'name',
        port: 443,
        sni: HOSTNAME,
        hostHeader: HOSTNAME,
      },
    ];
    expect(orderEndpoints(entries, rules.links).map((e) => e.label)).toEqual(['P', 'B', 'B6']);
    expect(
      orderEndpoints(entries, { ...rules.links, order: 'backup-first' }).map((e) => e.label),
    ).toEqual(['B', 'B6', 'P']);
  });

  test('a hostname edge that also carries IP literals still renders only the hostname', () => {
    const both: PublishedEdge = {
      ...l7(ws),
      addresses: { hostname: HOSTNAME, v4: L4_ADDRESS, v6: '2001:db8::10' },
    };
    const entries = entryOf(both, 'both');
    expect(entries.map((e) => [e.family, e.address])).toEqual([['name', HOSTNAME]]);
  });

  test('IPv4/IPv6 expansion is untouched for L4 edges', () => {
    const dual: PublishedEdge = {
      ...l4(reality),
      addresses: { v4: L4_ADDRESS, v6: '2001:db8::10' },
    };
    expect(entryOf(dual, 'both').map((e) => [e.family, e.address])).toEqual([
      ['v4', L4_ADDRESS],
      ['v6', '2001:db8::10'],
    ]);
    expect(entryOf(dual, 'off').map((e) => e.family)).toEqual(['v4']);
  });
});
