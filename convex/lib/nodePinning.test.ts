import { describe, expect, test } from 'vitest';
import { nodeNameFromLink, pickNode, pinSubscriptionToNode } from './nodePinning';

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
