/**
 * Names for load balancer addresses in member bodies (lib/edges/render.ts): an
 * address with a name is dialled by it in every format; where the app switches
 * by itself (an auto group) its IPs follow as fallbacks; a single key keeps the
 * IP. Every value is RFC 5737 / RFC 3849 / `*.example`.
 */
import { describe, expect, test } from 'vitest';
import YAML from 'yaml';
import { EDGE_DEFAULTS, defaultClientRule } from '../edgeConfig';
import type { AssignedEndpoint, PublishedEdge } from './assignment';
import { edgeAddressesOf, effectiveRule, renderEdgeEndpoints } from './render';
import { orderEndpoints, type RenderMatcher, type RenderEndpoint } from './render/types';
import type { ListenerProto } from './protocols';

const NODE = 'node-a';
const TEMPLATE = `${NODE}-relay-a1`;
const ORIGIN = '192.0.2.10';
const UUID = '11111111-2222-3333-4444-555555555555';
const REALITY: ListenerProto = { protocol: 'vless', streamTransport: 'raw', security: 'reality' };
const REALITY_QS =
  'security=reality&encryption=none&pbk=PUBKEY_BASE64&fp=chrome&sni=old.example&sid=abcd1234&type=tcp&flow=xtls-rprx-vision';
const templateLink = `vless://${UUID}@${ORIGIN}:443?${REALITY_QS}#${encodeURIComponent(TEMPLATE)}`;
const NAME_A = 'shiny-orchestra.names.example';

const matchers: RenderMatcher[] = [
  {
    listenerKey: 'a1',
    rule: { kind: 'remark', remark: TEMPLATE },
    proto: REALITY,
    originAddress: ORIGIN,
    originPort: 443,
  },
];

const edgeA: PublishedEdge = {
  edgeId: 'eA',
  poolIndex: 0,
  provider: 'gcore',
  listenerId: 'l1',
  listenerKey: 'a1',
  matchRule: { kind: 'remark', remark: TEMPLATE },
  proto: REALITY,
  edgePort: 443,
  addresses: { v4: '203.0.113.10', v6: '2001:db8::10' },
  addressName: NAME_A,
  serverNames: [{ sni: 'cdn-a.example', status: 'active' }],
};
const edgeB: PublishedEdge = {
  ...edgeA,
  edgeId: 'eB',
  poolIndex: 1,
  provider: 'scaleway',
  addresses: { v4: '203.0.113.20' },
  addressName: undefined,
};
const assigned: { primary: AssignedEndpoint; backup: AssignedEndpoint } = {
  primary: { role: 'primary', edge: edgeA, sni: 'cdn-a.example', hostHeader: null },
  backup: { role: 'backup', edge: edgeB, sni: 'cdn-b.example', hostHeader: null },
};

const cfg = { ...EDGE_DEFAULTS.render, enabled: true };
const linksRule = effectiveRule(cfg, defaultClientRule('v2rayng'));
const autoRule = effectiveRule(cfg, defaultClientRule('singbox'));
const mihomoRule = effectiveRule(cfg, defaultClientRule('mihomo'));

const render = (body: string, over: Partial<Parameters<typeof renderEdgeEndpoints>[0]> = {}) =>
  renderEdgeEndpoints({
    body,
    matchers,
    assigned,
    rule: linksRule,
    originAddress: ORIGIN,
    ...over,
  });

const singbox = {
  outbounds: [
    { tag: 'proxy', type: 'selector', outbounds: [TEMPLATE], default: TEMPLATE },
    {
      type: 'vless',
      tag: TEMPLATE,
      server: ORIGIN,
      server_port: 443,
      uuid: UUID,
      flow: 'xtls-rprx-vision',
      tls: {
        enabled: true,
        server_name: 'old.example',
        utls: { enabled: true, fingerprint: 'chrome' },
        reality: { enabled: true, public_key: 'PUBKEY', short_id: 'abcd1234' },
      },
    },
    { tag: 'direct', type: 'direct' },
  ],
};

describe('an address with a name', () => {
  test('a link list dials the name in place of the IPv4 entry; the IPv6 entry stays', () => {
    const out = render(templateLink);
    expect(out.delivery).toEqual({ kind: 'serve' });
    const lines = out.body.split('\n');
    expect(lines).toHaveLength(3);
    expect(lines[0]).toContain(`@${NAME_A}:443?`);
    expect(new URLSearchParams(lines[0]!.split('?')[1]!.split('#')[0]).get('sni')).toBe(
      'cdn-a.example',
    );
    // Where IPv4 is blocked and IPv6 works, the member can still pick IPv6.
    expect(lines[1]).toContain('@[2001:db8::10]:443?');
    // The backup has no name: its IP, as before.
    expect(lines[2]).toContain('@203.0.113.20:443?');
    // No IPv4 literal of the named address in a list that never switches by itself.
    expect(out.body).not.toContain('@203.0.113.10:');
  });

  test('IPv6 off for the family: the name alone, no IPv6 entry', () => {
    const out = render(templateLink, { rule: { ...linksRule, ipv6Mode: 'off' } });
    expect(out.body.split('\n')[0]).toContain(`@${NAME_A}:443?`);
    expect(out.body).not.toContain('2001:db8::10');
  });

  test('sing-box: the name first, the IPv6 entry as before, the IPv4 as a fallback in the group', () => {
    const out = render(JSON.stringify(singbox), { rule: autoRule });
    expect(out.delivery).toEqual({ kind: 'serve' });
    const doc = JSON.parse(out.body) as { outbounds: Array<Record<string, unknown>> };
    const emitted = doc.outbounds.filter(
      (o) => o.type === 'vless' && String(o.tag).startsWith('FreeSocks'),
    );
    expect(emitted.map((o) => [o.tag, o.server])).toEqual([
      ['FreeSocks', NAME_A],
      ['FreeSocks (IPv6)', '2001:db8::10'],
      ['FreeSocks (backup)', '203.0.113.20'],
      ['FreeSocks (IP)', '203.0.113.10'],
    ]);
    // The server name is the listener's, never the address's name.
    for (const o of emitted.filter((x) => x.tag !== 'FreeSocks (backup)'))
      expect((o.tls as { server_name: string }).server_name).toBe('cdn-a.example');
    const auto = doc.outbounds.find((o) => o.type === 'urltest') as { outbounds: string[] };
    expect(auto.outbounds).toEqual(emitted.map((o) => o.tag));
  });

  test('Mihomo: the name in `server`, the IP fallback in the group too', () => {
    const body = YAML.stringify({
      proxies: [
        {
          name: TEMPLATE,
          type: 'vless',
          server: ORIGIN,
          port: 443,
          uuid: UUID,
          network: 'tcp',
          tls: true,
          servername: 'old.example',
          flow: 'xtls-rprx-vision',
          'client-fingerprint': 'chrome',
          'reality-opts': { 'public-key': 'PUBKEY', 'short-id': 'abcd1234' },
        },
      ],
      'proxy-groups': [{ name: 'proxy', type: 'select', proxies: [TEMPLATE] }],
      rules: ['MATCH,proxy'],
    });
    const out = render(body, { rule: mihomoRule });
    expect(out.delivery).toEqual({ kind: 'serve' });
    const doc = YAML.parse(out.body) as {
      proxies: Array<{ name: string; server: string; servername: string }>;
    };
    const ours = doc.proxies.filter((p) => p.name.startsWith('FreeSocks'));
    expect(ours.find((p) => p.name === 'FreeSocks')).toMatchObject({
      server: NAME_A,
      servername: 'cdn-a.example',
    });
    expect(ours.find((p) => p.name === 'FreeSocks (IP)')?.server).toBe('203.0.113.10');
  });

  test('a single key keeps the IP: it has no room for a fallback', () => {
    const out = render(templateLink, { deliveryStyle: 'single-key' });
    expect(out.delivery).toEqual({ kind: 'serve' });
    expect(out.body).toContain('@203.0.113.10:443?');
    expect(out.body).not.toContain(NAME_A);
  });

  test('further server names dial the name too; the IP fallback outranks them under a cap', () => {
    const withAlternates = {
      ...assigned,
      primary: {
        ...assigned.primary,
        alternates: [{ sni: 'cdn-c.example', hostHeader: null }],
      },
    };
    const out = render(JSON.stringify(singbox), { rule: autoRule, assigned: withAlternates });
    const doc = JSON.parse(out.body) as { outbounds: Array<Record<string, unknown>> };
    const second = doc.outbounds.find((o) => o.tag === 'FreeSocks 2')!;
    expect(second.server).toBe(NAME_A);
    const entries: RenderEndpoint[] = [
      { ...base('v4'), label: 'alt', variant: 1, address: NAME_A, family: 'name' },
      { ...base('v4'), label: 'ip', fallback: true },
      { ...base('v4'), label: 'first', address: NAME_A, family: 'name' },
    ];
    expect(orderEndpoints(entries, { ...autoRule, maxEntries: 2 }).map((e) => e.label)).toEqual([
      'first',
      'ip',
    ]);
  });

  test('a name whose address is the node is refused like the node itself', () => {
    const leaky = { ...edgeA, addresses: { v4: ORIGIN } };
    const out = render(templateLink, {
      assigned: { primary: { ...assigned.primary, edge: leaky }, backup: null },
    });
    expect(out.delivery).toEqual({ kind: 'unavailable', reason: 'leak_detected' });
  });

  test('a retained entry at the name is one of the edges, never withheld', () => {
    expect(edgeAddressesOf([edgeA])).toContain(NAME_A);
  });
});

function base(family: 'v4' | 'v6'): RenderEndpoint {
  return {
    role: 'primary',
    label: '',
    edgeId: 'eA',
    listenerKey: 'a1',
    address: '203.0.113.10',
    family,
    port: 443,
    sni: 'cdn-a.example',
    hostHeader: null,
  };
}
