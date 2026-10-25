import { describe, expect, test } from 'vitest';
import YAML from 'yaml';
import { addressRemark } from './backend/hostRemark';
import {
  nodeNameFromLink,
  nodeNameFromTag,
  nodelessBody,
  placeholderBody,
  pickNode,
  pinSubscriptionToNode,
  splitPanelRemark,
} from './nodePinning';

const NODE_A = 'xray1-front-mci1-beta-fs-ce';
const NODE_B = 'xray2-front-mci1-beta-fs-ce';
const NODE_C = 'homed-vivify-braving';

function wsLink(node: string, edge: string, hash?: string): string {
  const remark = hash ? `${node}-ws-${hash}` : `${node}-ws`;
  return `vless://uuid-1@${edge}:443?encryption=none&type=ws&path=%2Fws&host=${edge}&security=tls&sni=${edge}#${remark}`;
}

const LINES = [
  wsLink(NODE_A, 'a1.example.org', 'a1a1a1'),
  wsLink(NODE_A, 'a2.example.org', 'b2b2b2'),
  wsLink(NODE_B, 'b1.example.org', 'c3c3c3'),
  wsLink(NODE_B, 'b2.example.org', 'd4d4d4'),
  wsLink(NODE_C, 'c1.example.org'), // legacy bare remark
];

describe('nodeNameFromLink', () => {
  test('strips transport + 6-hex hash suffix', () => {
    expect(nodeNameFromLink(LINES[0])).toBe(NODE_A);
  });
  test('strips bare transport suffix', () => {
    expect(nodeNameFromLink(LINES[4])).toBe(NODE_C);
  });
  test('parses reality remarks', () => {
    expect(nodeNameFromLink(`vless://u@x.org:443?security=reality#${NODE_B}-reality`)).toBe(NODE_B);
  });
  test('returns null without a remark or without a transport suffix', () => {
    expect(nodeNameFromLink('vless://u@x.org:443')).toBeNull();
    expect(nodeNameFromLink('vless://u@x.org:443#plainname')).toBeNull();
  });
  test('origin template remarks (<node>-origin-<slotKey>) pin with their node', () => {
    expect(nodeNameFromLink(`vless://u@x.org:443?security=reality#${NODE_B}-relay-a`)).toBe(NODE_B);
    expect(nodeNameFromLink(`vless://u@x.org:443#${NODE_B}-relay-gc1`)).toBe(NODE_B);
    expect(nodeNameFromTag(`${NODE_B}-relay-a`)).toBe(NODE_B);
  });
  test("an operator's hand-built front (<node>-relay) and the v1 role forms pin with their node", () => {
    expect(nodeNameFromLink(`vless://u@198.51.100.20:443?security=reality#${NODE_B}-relay`)).toBe(
      NODE_B,
    );
    expect(nodeNameFromTag(`${NODE_B}-relay`)).toBe(NODE_B);
    expect(splitPanelRemark(`${NODE_B}-relay`)).toEqual({ node: NODE_B, entry: 'relay' });
    expect(nodeNameFromTag(`${NODE_B}-reality`)).toBe(NODE_B);
    expect(nodeNameFromTag(`${NODE_B}-ws-6a536a`)).toBe(NODE_B);
    // A bare suffix names nothing on its own.
    expect(nodeNameFromTag('-relay')).toBeNull();
  });
});

describe('FCP address remarks (<node> | <server name>)', () => {
  // FCP's own addresses of a direct node (lib/backend/hostRemark.ts).
  const fcpLink = (node: string, sni: string, address: string) =>
    `vless://u@${address}:443?security=reality&sni=${sni}#${encodeURIComponent(addressRemark(node, sni))}`;

  test('name the node, with the server name (or its tag) as the entry', () => {
    expect(splitPanelRemark(addressRemark('node-a', 'www.decoy-a.example'))).toEqual({
      node: 'node-a',
      entry: 'www.decoy-a.example',
    });
    const long = `${'a'.repeat(40)}.decoy.example`;
    expect(splitPanelRemark(addressRemark('node-a', long))?.node).toBe('node-a');
    expect(splitPanelRemark(addressRemark('node with spaces', 'x.example'))?.node).toBe(
      'node with spaces',
    );
    expect(nodeNameFromLink(fcpLink('node-a', 'x.example', '192.0.2.1'))).toBe('node-a');
    expect(nodeNameFromTag(addressRemark('node-a', 'x.example'))).toBe('node-a');
    // Not a node: a group, an edge label, a name with no node before the separator.
    for (const other of ['proxy', 'FreeSocks Primary', ' | x.example', 'ab | x.example'])
      expect(splitPanelRemark(other)).toBeNull();
  });

  test('need the entry’s own server name (or a server-name shape) after the separator', () => {
    const long = `${'a'.repeat(40)}.decoy.example`;
    expect(splitPanelRemark(addressRemark('node-a', long), long)?.node).toBe('node-a');
    expect(splitPanelRemark('node-a | x.example', 'X.EXAMPLE')?.node).toBe('node-a');
    expect(splitPanelRemark('node-a | x.example', 'y.example')).toBeNull();
    // Operator display remarks: no server name of theirs, and not shaped like one.
    expect(splitPanelRemark('USA | VLESS')).toBeNull();
    expect(splitPanelRemark('Europe | VLESS', 'x.example')).toBeNull();
    expect(nodeNameFromLink('vless://u@192.0.2.1:443?sni=x.example#USA%20%7C%20VLESS')).toBeNull();
    // A single-label name counts only with the entry's own as evidence.
    expect(splitPanelRemark('node-a | origin-name')).toBeNull();
    expect(splitPanelRemark('node-a | origin-name', 'origin-name')?.node).toBe('node-a');
  });

  test('a body of two direct nodes pins to one of them, in every format', () => {
    const names = ['www.decoy-a.example', 'cdn.decoy-b.example'];
    const nodes = [
      { node: 'node-alpha', address: '192.0.2.1' },
      { node: 'node-beta', address: '198.51.100.1' },
    ];
    const lines = nodes.flatMap((n) => names.map((sni) => fcpLink(n.node, sni, n.address)));
    const pinned = pinSubscriptionToNode(lines.join('\n'), 'short-1');
    const chosen = nodes.find((n) => n.node === pinned.node)!;
    expect(chosen).toBeTruthy();
    expect(pinned.content.split('\n')).toEqual(
      lines.filter((l) => l.includes(`@${chosen.address}:`)),
    );
    const tags = nodes.flatMap((n) => names.map((sni) => addressRemark(n.node, sni)));
    const sb = pinSubscriptionToNode(
      JSON.stringify({
        outbounds: [
          { type: 'selector', tag: 'proxy', outbounds: tags },
          ...tags.map((tag) => ({ type: 'vless', tag, server: '192.0.2.9', server_port: 443 })),
        ],
      }),
      'short-1',
    );
    expect(sb.node).toBe(pinned.node);
    const clash = pinSubscriptionToNode(
      YAML.stringify({
        proxies: tags.map((name) => ({ name, type: 'vless', server: '192.0.2.9', port: 443 })),
        'proxy-groups': [{ name: 'proxy', type: 'select', proxies: tags }],
      }),
      'short-1',
    );
    expect(clash.node).toBe(pinned.node);
  });
});

describe('pickNode', () => {
  test('is deterministic for the same key', () => {
    const nodes = [NODE_A, NODE_B, NODE_C];
    expect(pickNode('k1', nodes)).toBe(pickNode('k1', nodes));
  });
  test('distributes different keys across nodes', () => {
    const nodes = [NODE_A, NODE_B, NODE_C];
    const picks = new Set(Array.from({ length: 40 }, (_, i) => pickNode(`key-${i}`, nodes)));
    expect(picks.size).toBeGreaterThan(1);
  });
  test('excludeNode is avoided when others exist, ignored when it would empty the pool', () => {
    const nodes = [NODE_A, NODE_B];
    expect(pickNode('k1', nodes, NODE_A)).toBe(NODE_B);
    expect(pickNode('k1', nodes, NODE_B)).toBe(NODE_A);
    expect(pickNode('k1', [NODE_A], NODE_A)).toBe(NODE_A);
  });
});

describe('pinSubscriptionToNode', () => {
  test('serves exactly one node (with all of its edges), deterministically', () => {
    const body = LINES.join('\n');
    const first = pinSubscriptionToNode(body, 'short-id-1');
    const second = pinSubscriptionToNode(body, 'short-id-1');
    expect(first.content).toBe(second.content);
    expect(first.node).not.toBeNull();
    expect(first.node).toBe(second.node);
    const keptLines = first.content.trim().split('\n');
    expect(keptLines).toHaveLength(2);
    expect(keptLines.every((l) => l.includes(`#${first.node}-`))).toBe(true);
  });

  test('only users of a removed node move (rendezvous stability)', () => {
    const body = LINES.join('\n');
    const keys = Array.from({ length: 30 }, (_, i) => `user-${i}`);
    const before = new Map(keys.map((k) => [k, pinSubscriptionToNode(body, k)]));
    const afterRemoval = new Map(
      keys.map((k) => {
        const filtered = pinSubscriptionToNode(
          LINES.filter((l) => !l.includes(`#${NODE_B}-`)).join('\n'),
          k,
        );
        return [k, filtered];
      }),
    );
    for (const k of keys) {
      const wasB = before.get(k)!.node === NODE_B;
      if (!wasB) expect(afterRemoval.get(k)!.content).toBe(before.get(k)!.content);
      expect(afterRemoval.get(k)!.node).not.toBe(NODE_B);
    }
  });

  test('excludeNode steers a regenerated key to a DIFFERENT node', () => {
    const body = LINES.join('\n');
    const before = pinSubscriptionToNode(body, 'new-short-id');
    const after = pinSubscriptionToNode(body, 'new-short-id', before.node!);
    expect(before.node).not.toBeNull();
    expect(after.node).not.toBe(before.node);
    expect([NODE_A, NODE_B, NODE_C]).toContain(after.node);
  });

  test('exclusion never empties the pool (single live node still serves)', () => {
    const body = LINES.filter((l) => l.includes(`#${NODE_A}-`)).join('\n');
    expect(pinSubscriptionToNode(body, 'k', NODE_A).content).toBe(body);
  });

  test('round-trips base64-encoded bodies', () => {
    const encoded = btoa(LINES.join('\n'));
    const out = pinSubscriptionToNode(encoded, 'short-id-1');
    expect(out.content).not.toContain('\n');
    const decoded = atob(out.content);
    const keptNodes = [NODE_A, NODE_B, NODE_C].filter((n) => decoded.includes(`#${n}-`));
    expect(keptNodes).toHaveLength(1);
  });

  test('single-node content passes through verbatim AND reports the node (the one-mode group-per-node topology)', () => {
    const body = [wsLink(NODE_A, 'a1.example.org'), wsLink(NODE_A, 'a2.example.org')].join('\n');
    const res = pinSubscriptionToNode(body, 'k');
    expect(res.content).toBe(body);
    expect(res.node).toBe(NODE_A);
    // excludeNode cannot empty the pool: the single node is still the answer.
    expect(pinSubscriptionToNode(body, 'k', NODE_A)).toEqual({ content: body, node: NODE_A });
    // Base64-wrapped single node: verbatim (still encoded), node reported.
    const encoded = btoa(body);
    expect(pinSubscriptionToNode(encoded, 'k')).toEqual({ content: encoded, node: NODE_A });
  });

  test('URL-safe / unpadded base64 bodies are decoded (and re-encoded standard)', () => {
    const urlSafe = btoa(LINES.join('\n'))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    const out = pinSubscriptionToNode(urlSafe, 'short-id-1');
    expect(out.node).toBe(pinSubscriptionToNode(LINES.join('\n'), 'short-id-1').node);
    const decoded = atob(out.content);
    expect([NODE_A, NODE_B, NODE_C].filter((n) => decoded.includes(`#${n}-`))).toHaveLength(1);
  });

  test('unknown formats pass through verbatim', () => {
    expect(pinSubscriptionToNode('{"outbounds": []}', 'k')).toEqual({
      content: '{"outbounds": []}',
      node: null,
    });
    expect(pinSubscriptionToNode('proxies: []', 'k')).toEqual({
      content: 'proxies: []',
      node: null,
    });
    expect(pinSubscriptionToNode('<html></html>', 'k').content).toBe('<html></html>');
    expect(pinSubscriptionToNode('', 'k').content).toBe('');
  });

  test('unparseable lines are kept alongside the pinned node', () => {
    const body = [...LINES, 'ss://method:pass@legacy.example.org:8388#no-transport-suffix'].join(
      '\n',
    );
    const out = pinSubscriptionToNode(body, 'k');
    expect(out.content).toContain('legacy.example.org');
  });
});

// --- sing-box JSON configs -------------------------------------------------------

const TAG_A1 = `${NODE_A}-ws-a1a1a1`;
const TAG_A2 = `${NODE_A}-ws-b2b2b2`;
const TAG_B1 = `${NODE_B}-ws-c3c3c3`;
const TAG_B2 = `${NODE_B}-ws-d4d4d4`;
const TAG_C = `${NODE_C}-ws`;
const ALL_TAGS = [TAG_A1, TAG_A2, TAG_B1, TAG_B2, TAG_C];

function singboxConfig(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    log: { level: 'info' },
    outbounds: [
      { type: 'selector', tag: 'proxy', outbounds: ['auto', ...ALL_TAGS], default: 'auto' },
      { type: 'urltest', tag: 'auto', outbounds: ALL_TAGS },
      ...ALL_TAGS.map((tag) => ({
        type: 'vless',
        tag,
        server: `${tag}.example.org`,
        server_port: 443,
      })),
      { type: 'direct', tag: 'direct' },
    ],
    route: { final: 'proxy', rules: [{ protocol: 'dns', outbound: 'direct' }] },
    ...overrides,
  });
}

describe('nodeNameFromTag', () => {
  test('strips transport (+hash) suffixes, rejects group tags', () => {
    expect(nodeNameFromTag(TAG_A1)).toBe(NODE_A);
    expect(nodeNameFromTag(TAG_C)).toBe(NODE_C);
    expect(nodeNameFromTag('proxy')).toBeNull();
    expect(nodeNameFromTag('auto')).toBeNull();
    expect(nodeNameFromTag('direct')).toBeNull();
  });
});

describe('pinSubscriptionToNode: sing-box JSON', () => {
  test('keeps one node, prunes groups, stays valid JSON, matches the link-list pick', () => {
    const out = pinSubscriptionToNode(singboxConfig(), 'short-id-1');
    expect(out.node).toBe(pinSubscriptionToNode(LINES.join('\n'), 'short-id-1').node);
    const cfg = JSON.parse(out.content) as {
      outbounds: { tag: string; outbounds?: string[]; server?: string }[];
      route: unknown;
    };
    const keptNodeTags = cfg.outbounds.map((o) => o.tag).filter((t) => nodeNameFromTag(t) !== null);
    // All of the chosen node's edges kept, no other node's.
    expect(keptNodeTags.length).toBeGreaterThan(0);
    expect(keptNodeTags.every((t) => nodeNameFromTag(t) === out.node)).toBe(true);
    // Groups list only surviving tags (plus the nested group reference).
    const selector = cfg.outbounds.find((o) => o.tag === 'proxy')!;
    expect(selector.outbounds).toEqual(['auto', ...keptNodeTags]);
    const auto = cfg.outbounds.find((o) => o.tag === 'auto')!;
    expect(auto.outbounds).toEqual(keptNodeTags);
    // Non-node outbounds and the rest of the config survive untouched.
    expect(cfg.outbounds.some((o) => o.tag === 'direct')).toBe(true);
    expect(cfg.route).toEqual({ final: 'proxy', rules: [{ protocol: 'dns', outbound: 'direct' }] });
  });

  test('is deterministic and honors excludeNode', () => {
    const body = singboxConfig();
    const first = pinSubscriptionToNode(body, 'k7');
    expect(pinSubscriptionToNode(body, 'k7').content).toBe(first.content);
    const moved = pinSubscriptionToNode(body, 'k7', first.node!);
    expect(moved.node).not.toBe(first.node);
  });

  test('rewrites a group default that pointed at a dropped node', () => {
    // Pick a key that does NOT land on NODE_B, then make B the default.
    const nodes = [NODE_A, NODE_B, NODE_C];
    const key = ['k1', 'k2', 'k3', 'k4', 'k5'].find((k) => pickNode(k, nodes) !== NODE_B)!;
    const body = JSON.stringify({
      outbounds: [
        { type: 'selector', tag: 'proxy', outbounds: ALL_TAGS, default: TAG_B1 },
        ...ALL_TAGS.map((tag) => ({ type: 'vless', tag, server: 'x', server_port: 443 })),
      ],
    });
    const out = pinSubscriptionToNode(body, key);
    const cfg = JSON.parse(out.content) as {
      outbounds: { tag: string; outbounds?: string[]; default?: string }[];
    };
    const selector = cfg.outbounds.find((o) => o.tag === 'proxy')!;
    expect(selector.outbounds).toContain(selector.default);
  });

  test('fails open when a group would be emptied or a route rule targets a node tag', () => {
    const nodes = [NODE_A, NODE_B, NODE_C];
    const key = ['k1', 'k2', 'k3', 'k4', 'k5'].find((k) => pickNode(k, nodes) !== NODE_B)!;
    // A group holding ONLY node-B tags empties when B is dropped → verbatim.
    const emptied = JSON.stringify({
      outbounds: [
        { type: 'selector', tag: 'proxy', outbounds: ALL_TAGS },
        { type: 'urltest', tag: 'b-only', outbounds: [TAG_B1, TAG_B2] },
        ...ALL_TAGS.map((tag) => ({ type: 'vless', tag, server: 'x', server_port: 443 })),
      ],
    });
    expect(pinSubscriptionToNode(emptied, key).content).toBe(emptied);
    // A route rule pinned to a node tag we would drop → verbatim.
    const routed = singboxConfig({
      route: { final: 'proxy', rules: [{ domain: ['x.org'], outbound: TAG_B1 }] },
    });
    const out = pinSubscriptionToNode(routed, key);
    expect(out.content).toBe(routed);
    expect(out.node).toBeNull();
    // A KEPT outbound whose detour chains through a dropped node tag would be
    // a dangling reference after pinning → verbatim (Review PR#38).
    const detoured = JSON.stringify({
      outbounds: [
        { type: 'selector', tag: 'proxy', outbounds: ALL_TAGS },
        ...ALL_TAGS.map((tag) => ({ type: 'vless', tag, server: 'x', server_port: 443 })),
        { type: 'http', tag: 'chained-helper', server: 'y', server_port: 8080, detour: TAG_B1 },
      ],
    });
    const out2 = pinSubscriptionToNode(detoured, key);
    expect(out2.content).toBe(detoured);
    expect(out2.node).toBeNull();
  });

  test('single-node JSON passes through verbatim WITH the node; non-config JSON has none', () => {
    const single = JSON.stringify({
      outbounds: [
        { type: 'selector', tag: 'proxy', outbounds: [TAG_A1, TAG_A2] },
        { type: 'vless', tag: TAG_A1, server: 'x', server_port: 443 },
        { type: 'vless', tag: TAG_A2, server: 'x', server_port: 443 },
      ],
    });
    expect(pinSubscriptionToNode(single, 'k')).toEqual({ content: single, node: NODE_A });
    expect(pinSubscriptionToNode(single, 'k', NODE_A)).toEqual({ content: single, node: NODE_A });
    const envelope = '{"error":{"code":"not_found"}}';
    expect(pinSubscriptionToNode(envelope, 'k')).toEqual({ content: envelope, node: null });
  });
});

// --- Clash / Mihomo YAML ---------------------------------------------------------

function clashConfig(names: string[], extra = ''): string {
  return [
    'mixed-port: 7890',
    'proxies:',
    ...names.map((n) => `  - {name: ${n}, type: vless, server: x, port: 443, uuid: u}`),
    'proxy-groups:',
    `  - {name: proxy, type: select, proxies: [auto, ${names.join(', ')}]}`,
    `  - {name: auto, type: url-test, proxies: [${names.join(', ')}], url: http://x/}`,
    'rules:',
    '  - MATCH,proxy',
    extra,
  ].join('\n');
}

describe('pinSubscriptionToNode: Clash YAML', () => {
  test('keeps one node, prunes groups, matches the link-list pick', () => {
    const out = pinSubscriptionToNode(clashConfig(ALL_TAGS), 'short-id-1');
    expect(out.node).toBe(pinSubscriptionToNode(LINES.join('\n'), 'short-id-1').node);
    const doc = YAML.parse(out.content) as {
      proxies: { name: string }[];
      'proxy-groups': { name: string; proxies: string[] }[];
      rules: string[];
    };
    const kept = doc.proxies.map((p) => p.name);
    expect(kept.length).toBeGreaterThan(0);
    expect(kept.every((n) => nodeNameFromTag(n) === out.node)).toBe(true);
    expect(doc['proxy-groups'][0].proxies).toEqual(['auto', ...kept]);
    expect(doc['proxy-groups'][1].proxies).toEqual(kept);
    expect(doc.rules).toEqual(['MATCH,proxy']);
  });

  test('is deterministic, honors excludeNode, and reports a single node verbatim', () => {
    const body = clashConfig(ALL_TAGS);
    const a = pinSubscriptionToNode(body, 'k1');
    expect(pinSubscriptionToNode(body, 'k1')).toEqual(a);
    expect(pinSubscriptionToNode(body, 'k1', a.node!).node).not.toBe(a.node);
    const single = clashConfig([TAG_A1, TAG_A2]);
    expect(pinSubscriptionToNode(single, 'k')).toEqual({ content: single, node: NODE_A });
    expect(pinSubscriptionToNode(single, 'k', NODE_A)).toEqual({ content: single, node: NODE_A });
  });

  test('fails open when a rule targets a dropped proxy by name or a group would empty', () => {
    // Find a key whose pick is NOT node B, so B's proxies are dropped.
    let key = 'k';
    for (let i = 0; i < 50; i++) {
      key = `k${i}`;
      if (pinSubscriptionToNode(clashConfig(ALL_TAGS), key).node !== NODE_B) break;
    }
    const ruled = clashConfig(ALL_TAGS, `  - DOMAIN-SUFFIX,example.com,${TAG_B1}`);
    expect(pinSubscriptionToNode(ruled, key)).toEqual({ content: ruled, node: null });
    const emptyGroup = clashConfig(ALL_TAGS, '').replace(
      'rules:',
      `  - {name: b-only, type: select, proxies: [${TAG_B1}, ${TAG_B2}]}\nrules:`,
    );
    expect(pinSubscriptionToNode(emptyGroup, key)).toEqual({ content: emptyGroup, node: null });
  });
});

describe('nodelessBody (the backend placeholder the fronted route never caches)', () => {
  const link = (remark: string, host = '198.51.100.9', port = 443) =>
    `vless://11111111-2222-4333-8444-555555555555@${host}:${port}?security=reality#${remark}`;
  test('an empty body, or entries that all point nowhere and name no node, is the placeholder', () => {
    expect(nodelessBody('')).toBe(true);
    expect(nodelessBody('  \n ')).toBe(true);
    expect(nodelessBody(link('No hosts', '0.0.0.0', 1))).toBe(true);
    expect(nodelessBody(btoa(link('No hosts', '0.0.0.0', 1)))).toBe(true);
    expect(nodelessBody(JSON.stringify({ outbounds: [{ tag: 'direct', type: 'direct' }] }))).toBe(
      true,
    );
    expect(
      nodelessBody(
        JSON.stringify({
          outbounds: [{ tag: 'No hosts', type: 'vless', server: '0.0.0.0', server_port: 1 }],
        }),
      ),
    ).toBe(true);
    expect(nodelessBody(YAML.stringify({ proxies: [] }))).toBe(true);
  });
  test('a real entry is never the placeholder, whatever its remark; nor is an unknown shape', () => {
    // A Host whose remark carries no node suffix still serves members.
    expect(nodelessBody(link('my-host'))).toBe(false);
    expect(nodelessBody(link('node-one-reality'))).toBe(false);
    expect(
      nodelessBody(
        JSON.stringify({ outbounds: [{ tag: 'x', type: 'vless', server: '198.51.100.9' }] }),
      ),
    ).toBe(false);
    expect(
      nodelessBody(
        YAML.stringify({ proxies: [{ name: 'x', type: 'ss', server: '198.51.100.9' }] }),
      ),
    ).toBe(false);
    expect(nodelessBody('RAW-CONFIG-1')).toBe(false);
    expect(nodelessBody('<html></html>')).toBe(false);
    expect(nodelessBody('{"error":"x"}')).toBe(false);
  });
});

describe('placeholderBody (an expired or disabled key: delivery hands it out as it is)', () => {
  const link = (remark: string, host = '198.51.100.9', port = 443) =>
    `vless://11111111-2222-4333-8444-555555555555@${host}:${port}?security=reality#${remark}`;
  const expired = [
    link('⌛ Subscription expired', '0.0.0.0', 1),
    link('Contact support', '0.0.0.0', 1),
  ];
  test('placeholder entries in every shape are one', () => {
    expect(placeholderBody(expired.join('\n'))).toBe(true);
    expect(placeholderBody(Buffer.from(expired.join('\n')).toString('base64'))).toBe(true);
    expect(
      placeholderBody(
        JSON.stringify({
          outbounds: [
            { tag: 'select', type: 'selector', outbounds: ['expired'] },
            { tag: 'expired', type: 'vless', server: '0.0.0.0', server_port: 1 },
          ],
        }),
      ),
    ).toBe(true);
    expect(
      placeholderBody(
        YAML.stringify({ proxies: [{ name: 'expired', type: 'vless', server: '0.0.0.0' }] }),
      ),
    ).toBe(true);
  });
  test('an EMPTY body is not one (an empty 200 would wipe the client), nor a body with no proxy entry', () => {
    expect(placeholderBody('')).toBe(false);
    expect(placeholderBody('  \n ')).toBe(false);
    expect(placeholderBody(btoa(''))).toBe(false);
    expect(
      placeholderBody(JSON.stringify({ outbounds: [{ tag: 'direct', type: 'direct' }] })),
    ).toBe(false);
    expect(placeholderBody(YAML.stringify({ proxies: [] }))).toBe(false);
  });
  test('a link list with any other line is not one: no line may pass unread', () => {
    expect(placeholderBody([...expired, 'socks://203.0.113.7:1080'].join('\n'))).toBe(false);
    expect(placeholderBody([...expired, 'https://203.0.113.7/'].join('\n'))).toBe(false);
    expect(
      placeholderBody(Buffer.from([...expired, 'note 203.0.113.7'].join('\n')).toString('base64')),
    ).toBe(false);
  });
  test('any real entry, or a node-named one, makes it a real body', () => {
    expect(placeholderBody([...expired, link('my-host')].join('\n'))).toBe(false);
    expect(placeholderBody(link('node-one-reality', '0.0.0.0', 1))).toBe(false);
  });
});
