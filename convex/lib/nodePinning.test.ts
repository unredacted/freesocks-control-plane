import { describe, expect, test } from 'vitest';
import { nodeNameFromLink, nodeNameFromTag, pickNode, pinSubscriptionToNode } from './nodePinning';

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

  test('single-node content passes through verbatim', () => {
    const body = [wsLink(NODE_A, 'a1.example.org'), wsLink(NODE_A, 'a2.example.org')].join('\n');
    const res = pinSubscriptionToNode(body, 'k');
    expect(res.content).toBe(body);
    expect(res.node).toBeNull();
  });

  test('unknown formats pass through verbatim', () => {
    expect(pinSubscriptionToNode('{"outbounds": []}', 'k').content).toBe('{"outbounds": []}');
    expect(pinSubscriptionToNode('proxies: []', 'k').content).toBe('proxies: []');
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
  });

  test('single-node and non-config JSON pass through verbatim', () => {
    const single = JSON.stringify({
      outbounds: [
        { type: 'selector', tag: 'proxy', outbounds: [TAG_A1, TAG_A2] },
        { type: 'vless', tag: TAG_A1, server: 'x', server_port: 443 },
        { type: 'vless', tag: TAG_A2, server: 'x', server_port: 443 },
      ],
    });
    expect(pinSubscriptionToNode(single, 'k').content).toBe(single);
    const envelope = '{"error":{"code":"not_found"}}';
    expect(pinSubscriptionToNode(envelope, 'k').content).toBe(envelope);
  });
});
