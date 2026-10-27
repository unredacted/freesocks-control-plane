// @vitest-environment node
import { describe, expect, test } from 'vitest';
import YAML from 'yaml';
import { clients, artifacts, type Format } from '../tests/compat/manifest';
import { assertSubscription } from '../tests/compat/assertions';
import { COMPAT_ENDPOINTS, COMPAT_NODE } from '../tests/compat/fixture';
import { selectProxy } from '../tests/compat/sandbox';
import { addressRemark } from './lib/backend/hostRemark';
import { pinSubscriptionToNode } from './lib/nodePinning';
import { finishMemberBody } from './lib/subscriptionDelivery';
import { DEFAULT_CLIENTS } from './lib/clientCatalog';
import { classifyClient } from './lib/edges/clientFamilies';

describe('client compatibility coverage', () => {
  test('every enabled recommendation has an explicit coverage entry', () => {
    expect(clients.map((c) => c.name).sort()).toEqual(
      DEFAULT_CLIENTS.filter((c) => c.enabled)
        .map((c) => c.name)
        .sort(),
    );
    expect(new Set(clients.map((c) => c.name)).size).toBe(clients.length);
    for (const client of clients) expect(client.limitation.length).toBeGreaterThan(15);
    for (const artifact of Object.values(artifacts))
      expect(artifact.sha256).toMatch(/^[a-f0-9]{64}$/);
  });
  test('every manifest User-Agent classifies to the format the manifest expects', () => {
    // The manifest says what the PANEL serves each UA; classifyClient is what
    // the /api/v1/sub handler expects for edge rendering. They must agree, or a
    // client can pass the suite while the renderer picks the wrong family.
    const expected = { singbox: 'singbox-json', mihomo: 'clash-yaml', links: 'links' } as const;
    for (const client of clients) {
      if (client.format === 'outline') continue;
      for (const ua of client.userAgents)
        expect(classifyClient(ua).expectedFormat, `${client.name}: ${ua}`).toBe(
          expected[client.format],
        );
    }
  });
  test('base64 VLESS input cannot pass as sing-box JSON', () => {
    const body = Buffer.from(
      'vless://00000000-0000-4000-8000-000000000000@example.test:443',
    ).toString('base64');
    expect(() => assertSubscription(body, 'singbox')).toThrow('non-JSON');
    expect(() => assertSubscription(body, 'links')).not.toThrow();
  });
  test('empty configurations and HTTP error pages cannot produce a pass', () => {
    for (const body of ['{}', '{"outbounds":[]}', 'denied', '<html>error</html>', '']) {
      for (const format of ['singbox', 'mihomo', 'links'] as const)
        expect(() => assertSubscription(body, format)).toThrow();
    }
  });
});

const GROUP = '→ Remnawave';
const UUID = '00000000-0000-4000-8000-000000000000';
type Endpoint = { server: string; port: number; serverName: string };
function fixture(
  format: Exclude<Format, 'outline'>,
  endpoints: readonly Endpoint[] = COMPAT_ENDPOINTS,
): string {
  const names = endpoints.map((e) => addressRemark(COMPAT_NODE, e.serverName));
  if (format === 'links')
    return endpoints
      .map(
        (e, i) =>
          `vless://${UUID}@${e.server}:${e.port}?security=reality&sni=${e.serverName}#${encodeURIComponent(names[i]!)}`,
      )
      .join('\n');
  if (format === 'singbox')
    return JSON.stringify({
      outbounds: [
        { type: 'selector', tag: GROUP, outbounds: names },
        ...endpoints.map((e, i) => ({
          type: 'vless',
          tag: names[i],
          server: e.server,
          server_port: e.port,
          uuid: UUID,
          tls: { enabled: true, server_name: e.serverName, reality: { enabled: true } },
        })),
      ],
      route: { final: GROUP },
    });
  return YAML.stringify({
    mode: 'rule',
    proxies: endpoints.map((e, i) => ({
      type: 'vless',
      name: names[i],
      server: e.server,
      port: e.port,
      uuid: UUID,
      servername: e.serverName,
      tls: true,
      'reality-opts': { 'public-key': 'fixture' },
    })),
    'proxy-groups': [{ type: 'select', name: GROUP, proxies: names }],
    rules: [`MATCH,${GROUP}`],
  });
}

describe('multi-endpoint client compatibility regression', () => {
  for (const format of ['links', 'singbox', 'mihomo'] as const) {
    test(`${format}: pinning, private names and serialization preserve all three endpoints`, () => {
      const pinned = pinSubscriptionToNode(fixture(format), 'compat-key');
      expect(pinned.node).toBe(COMPAT_NODE);
      const served = finishMemberBody(pinned.content, { siteName: 'FreeSocks', place: null });
      assertSubscription(served, format, COMPAT_ENDPOINTS);
      expect(served).not.toContain(COMPAT_NODE);
    });
    test(`${format}: a syntactically valid three-to-one reduction fails`, () => {
      expect(() =>
        assertSubscription(fixture(format, COMPAT_ENDPOINTS.slice(0, 1)), format, COMPAT_ENDPOINTS),
      ).toThrow('endpoint set differs');
    });
    test(`${format}: a changed endpoint cannot pass by keeping the same count`, () => {
      const changed = COMPAT_ENDPOINTS.map((e, i) => (i === 2 ? { ...e, port: 9999 } : e));
      expect(() => assertSubscription(fixture(format, changed), format, COMPAT_ENDPOINTS)).toThrow(
        'endpoint set differs',
      );
    });
    test(`${format}: duplicate names are refused`, () => {
      const body = fixture(format).replaceAll(
        format === 'links'
          ? encodeURIComponent(addressRemark(COMPAT_NODE, COMPAT_ENDPOINTS[1].serverName))
          : addressRemark(COMPAT_NODE, COMPAT_ENDPOINTS[1].serverName),
        format === 'links'
          ? encodeURIComponent(addressRemark(COMPAT_NODE, COMPAT_ENDPOINTS[0].serverName))
          : addressRemark(COMPAT_NODE, COMPAT_ENDPOINTS[0].serverName),
      );
      expect(() => assertSubscription(body, format, COMPAT_ENDPOINTS)).toThrow(/uplicate/);
    });
  }
  test('base64 link lists preserve all three named endpoints too', () => {
    assertSubscription(Buffer.from(fixture('links')).toString('base64'), 'links', COMPAT_ENDPOINTS);
  });
  for (const engine of ['singbox', 'mihomo'] as const) {
    const parse = (body: string): Record<string, any> =>
      engine === 'singbox' ? JSON.parse(body) : YAML.parse(body);
    const encode = (config: Record<string, any>): string =>
      engine === 'singbox' ? JSON.stringify(config) : YAML.stringify(config);
    test(`${engine}: three defined proxies with only one selectable fails`, () => {
      const config = parse(fixture(engine));
      const group = engine === 'singbox' ? config.outbounds[0] : config['proxy-groups'][0];
      const key = engine === 'singbox' ? 'outbounds' : 'proxies';
      group[key] = group[key].slice(0, 1);
      expect(() => assertSubscription(encode(config), engine, COMPAT_ENDPOINTS)).toThrow(
        'missing from the default selector',
      );
    });
    test(`${engine}: a dangling group reference fails`, () => {
      const config = parse(fixture(engine));
      const group = engine === 'singbox' ? config.outbounds[0] : config['proxy-groups'][0];
      group[engine === 'singbox' ? 'outbounds' : 'proxies'].push('missing');
      expect(() => assertSubscription(encode(config), engine, COMPAT_ENDPOINTS)).toThrow(
        'dangling',
      );
    });
    test(`${engine}: each endpoint probe has one choice and keeps the served proxies intact`, () => {
      const body = fixture(engine);
      const original = parse(body);
      const proxies = engine === 'singbox' ? original.outbounds.slice(1) : original.proxies;
      for (const proxy of proxies) {
        const name = engine === 'singbox' ? proxy.tag : proxy.name;
        const selected = parse(selectProxy(engine, body, name));
        expect(engine === 'singbox' ? selected.outbounds.slice(1) : selected.proxies).toEqual(
          proxies,
        );
        const group = engine === 'singbox' ? selected.outbounds[0] : selected['proxy-groups'][0];
        expect(group[engine === 'singbox' ? 'outbounds' : 'proxies']).toEqual([name]);
      }
      expect(parse(body)).toEqual(original);
    });
  }
  test('malformed YAML errors do not echo subscription credentials', () => {
    expect(() => assertSubscription('proxies: [secret-credential', 'mihomo')).toThrow(
      'Expected Mihomo YAML',
    );
  });
});
