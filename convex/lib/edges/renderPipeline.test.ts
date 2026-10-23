/**
 * Listener-aware assignment: an edge whose listener has no matching, agreeing
 * template entry in THIS body is ineligible BEFORE the PRF pick, keeping its
 * pool index so the walk stays stable for every other subscriber. The
 * snapshot the DB half persists lists the listeners that resolved and the
 * edges that were handed out.
 */
import { describe, expect, test } from 'vitest';
import { EDGE_DEFAULTS, defaultClientRule } from '../edgeConfig';
import { assignEndpoints, type PublishedEdge } from './assignment';
import type { ListenerProto } from './protocols';
import { effectiveRule } from './render';
import type { RenderMatcher } from './render/types';
import { applyEdgeRender, type EdgeRenderContext } from './renderPipeline';

const NODE = 'node-a';
const ORIGIN = '192.0.2.10';
const UUID = '11111111-2222-3333-4444-555555555555';
const REALITY_REMARK = `${NODE}-relay-a`;
const SS_REMARK = `${NODE}-relay-s`;
const REALITY: ListenerProto = { protocol: 'vless', streamTransport: 'raw', security: 'reality' };
const SS: ListenerProto = { protocol: 'shadowsocks', streamTransport: 'raw', security: 'none' };

const realityLink = `vless://${UUID}@${ORIGIN}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=target.example&fp=chrome&pbk=PUBKEY&sid=abcd&type=tcp#${encodeURIComponent(REALITY_REMARK)}`;
const ssLink = `ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpleGFtcGxlLXBhc3N3b3Jk@${ORIGIN}:8388#${encodeURIComponent(SS_REMARK)}`;

const matchers: RenderMatcher[] = [
  {
    listenerKey: 'a',
    rule: { kind: 'remark', remark: REALITY_REMARK },
    proto: REALITY,
    originAddress: ORIGIN,
    originPort: 443,
  },
  {
    listenerKey: 's',
    rule: { kind: 'remark', remark: SS_REMARK },
    proto: SS,
    originAddress: ORIGIN,
    originPort: 8388,
  },
];

const edgeA: PublishedEdge = {
  edgeId: 'eA',
  poolIndex: 0,
  provider: 'gcore',
  listenerId: 'l-a',
  listenerKey: 'a',
  matchRule: { kind: 'remark', remark: REALITY_REMARK },
  proto: REALITY,
  edgePort: 443,
  addresses: { v4: '203.0.113.10' },
  serverNames: [{ sni: 'cdn-a.example', status: 'active' }],
};
const edgeS: PublishedEdge = {
  edgeId: 'eS',
  poolIndex: 1,
  provider: 'scaleway',
  listenerId: 'l-s',
  listenerKey: 's',
  matchRule: { kind: 'remark', remark: SS_REMARK },
  proto: SS,
  edgePort: 8388,
  addresses: { v4: '203.0.113.20' },
  serverNames: [],
};

const cfg = { ...EDGE_DEFAULTS.render, enabled: true };
const rule = effectiveRule(cfg, defaultClientRule('v2rayng'));
const rctx = (
  published: PublishedEdge[],
  over: Partial<EdgeRenderContext> = {},
): EdgeRenderContext => ({
  epoch: 3,
  matchers,
  published,
  rule,
  preferDistinctProviders: true,
  originAddress: ORIGIN,
  ...over,
});

const key = (i: number) => ((i * 2654435761) >>> 0).toString(16).padStart(8, '0') + 'cd'.repeat(28);
const NOW = 1_700_000_000_000;

describe('applyEdgeRender: three server names for one member', () => {
  const pool = ['n0', 'n1', 'n2', 'n3', 'n4', 'n5'].map((n) => ({
    sni: `${n}.example`,
    status: 'active' as const,
  }));

  test('an hrw1 listener renders three entries with three distinct names; a legacy one renders one', () => {
    const hrw = { ...edgeA, serverNames: pool, sniPick: 'hrw1' as const };
    for (let i = 0; i < 100; i++) {
      const out = applyEdgeRender(rctx([hrw]), realityLink, key(i), { now: NOW });
      const lines = out.body.split('\n').filter((l) => l.startsWith('vless://'));
      const snis = lines.map((l) =>
        new URL(l.replace('vless://', 'http://')).searchParams.get('sni'),
      );
      expect(snis).toHaveLength(3);
      expect(new Set(snis).size).toBe(3);
      expect(out.emitted).toBe(3);
      // Same endpoint and credentials on every line.
      for (const l of lines) expect(l).toContain(`${UUID}@203.0.113.10:443?`);
      // The persisted snapshot names edges only: never which names a member holds.
      expect(JSON.stringify(out.snapshot)).not.toContain('.example');
    }
    const legacy = applyEdgeRender(rctx([{ ...edgeA, serverNames: pool }]), realityLink, key(1), {
      now: NOW,
    });
    expect(legacy.emitted).toBe(1);
  });
});

describe('applyEdgeRender: listener-aware assignment', () => {
  test('a body carrying only the REALITY entry makes the shadowsocks edge ineligible: every subscriber lands on the REALITY edge', () => {
    for (let i = 0; i < 300; i++) {
      const out = applyEdgeRender(rctx([edgeA, edgeS]), realityLink, key(i), { now: NOW });
      expect(out.delivery).toEqual({ kind: 'serve' });
      expect(out.listeners).toEqual([
        { listenerKey: 'a', matched: true },
        { listenerKey: 's', matched: false, reason: 'no_match' },
      ]);
      // The PRF walked past the ineligible position; no backup exists.
      expect(out.snapshot).toEqual({
        listenerKeys: ['a'],
        primaryEdgeId: 'eA',
        backupEdgeId: null,
      });
      expect(out.emitted).toBe(1);
      expect(out.body).toContain('@203.0.113.10:443?');
      expect(out.body).not.toContain('203.0.113.20');
      expect(out.body).not.toContain(ORIGIN);
    }
  });

  test('positions stay stable: the pick equals an explicit eligible:false at the same pool index', () => {
    for (let i = 0; i < 300; i++) {
      const implicit = applyEdgeRender(rctx([edgeA, edgeS]), realityLink, key(i), { now: NOW });
      const explicit = applyEdgeRender(
        rctx([edgeA, { ...edgeS, eligible: false }]),
        realityLink,
        key(i),
        { now: NOW },
      );
      expect(implicit.body).toBe(explicit.body);
      expect(implicit.snapshot).toEqual(explicit.snapshot);
    }
  });

  test('a body carrying BOTH templates lets both edges serve; dropping one template moves only that edge holders', () => {
    const both = [realityLink, ssLink].join('\n');
    let movedToA = 0;
    let stayed = 0;
    for (let i = 0; i < 400; i++) {
      const full = applyEdgeRender(rctx([edgeA, edgeS]), both, key(i), { now: NOW });
      expect(full.delivery).toEqual({ kind: 'serve' });
      expect(full.snapshot.listenerKeys).toEqual(['a', 's']);
      // Two eligible edges of different providers: one is primary, the other backup.
      expect(new Set([full.snapshot.primaryEdgeId, full.snapshot.backupEdgeId])).toEqual(
        new Set(['eA', 'eS']),
      );
      // The same pick as the pure assignment over the full pool.
      const direct = assignEndpoints(key(i), [edgeA, edgeS], {
        now: NOW,
        preferDistinctProviders: true,
        includeBackup: true,
      });
      expect(full.snapshot.primaryEdgeId).toBe(direct.primary!.edge.edgeId);
      // Without the SS template the SS edge is ineligible for this body only.
      const reality = applyEdgeRender(rctx([edgeA, edgeS]), realityLink, key(i), { now: NOW });
      expect(reality.snapshot.primaryEdgeId).toBe('eA');
      if (full.snapshot.primaryEdgeId === 'eS') movedToA++;
      else stayed++;
    }
    expect(movedToA).toBeGreaterThan(0);
    expect(stayed).toBeGreaterThan(0);
  });

  test('the SS edge renders its own template (address/port only) when the body carries it', () => {
    const both = [realityLink, ssLink].join('\n');
    // Find a key whose primary is the SS edge.
    let k = key(0);
    for (let i = 0; i < 400; i++) {
      k = key(i);
      if (
        applyEdgeRender(rctx([edgeA, edgeS]), both, k, { now: NOW }).snapshot.primaryEdgeId === 'eS'
      )
        break;
    }
    const out = applyEdgeRender(rctx([edgeA, edgeS]), both, k, { now: NOW });
    expect(out.snapshot.primaryEdgeId).toBe('eS');
    const lines = out.body.split('\n');
    const primary = lines.find((l) => l.endsWith('#FreeSocks'))!;
    expect(
      primary.startsWith(
        'ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpleGFtcGxlLXBhc3N3b3Jk@203.0.113.20:8388',
      ),
    ).toBe(true);
    const backup = lines.find((l) => l.endsWith('#FreeSocks%20(backup)'))!;
    expect(backup.startsWith(`vless://${UUID}@203.0.113.10:443?`)).toBe(true);
    expect(backup).toContain('sni=cdn-a.example');
    expect(out.body).not.toContain(ORIGIN);
  });

  test('a body carrying no listener template at all is unavailable, with an empty snapshot', () => {
    const other = `vless://${UUID}@edge.example:443?encryption=none&security=tls&type=ws&path=%2Fws#other-node-ws`;
    const out = applyEdgeRender(rctx([edgeA, edgeS]), other, key(1), { now: NOW });
    // Every edge lost eligibility, so the pool is judged empty before any codec runs.
    expect(out.delivery).toEqual({ kind: 'unavailable', reason: 'empty_pool' });
    expect(out.applied).toBe(false);
    expect(out.snapshot).toEqual({ listenerKeys: [], primaryEdgeId: null, backupEdgeId: null });
  });

  test('an already-ineligible edge (undeployed / disabled listener) stays ineligible even when its template is present', () => {
    const both = [realityLink, ssLink].join('\n');
    for (let i = 0; i < 100; i++) {
      const out = applyEdgeRender(rctx([edgeA, { ...edgeS, eligible: false }]), both, key(i), {
        now: NOW,
      });
      expect(out.snapshot.listenerKeys).toEqual(['a', 's']); // resolved in the body...
      expect(out.snapshot.primaryEdgeId).toBe('eA'); // ...but its edge is not handed out
      expect(out.snapshot.backupEdgeId).toBeNull();
    }
  });

  test('sing-box bodies go through the same eligibility pass', () => {
    const body = JSON.stringify({
      outbounds: [
        {
          type: 'selector',
          tag: 'proxy',
          outbounds: [REALITY_REMARK, 'direct'],
          default: REALITY_REMARK,
        },
        {
          type: 'vless',
          tag: REALITY_REMARK,
          server: ORIGIN,
          server_port: 443,
          uuid: UUID,
          tls: {
            enabled: true,
            server_name: 'target.example',
            reality: { enabled: true, public_key: 'P' },
          },
        },
        { type: 'direct', tag: 'direct' },
      ],
    });
    const out = applyEdgeRender(
      rctx([edgeA, edgeS], { rule: effectiveRule(cfg, defaultClientRule('singbox')) }),
      body,
      key(7),
      { now: NOW },
    );
    expect(out.delivery).toEqual({ kind: 'serve' });
    expect(out.snapshot).toEqual({ listenerKeys: ['a'], primaryEdgeId: 'eA', backupEdgeId: null });
    expect(out.body).not.toContain('203.0.113.20');
  });
});

describe('applyEdgeRender: the node by any of its addresses', () => {
  const direct = (address: string, remark: string) =>
    `vless://${UUID}@${address}:443?encryption=none&security=reality&sni=target.example&type=tcp#${encodeURIComponent(remark)}`;

  test('a retained entry at another address of the node, or another spelling of it, refuses the body', () => {
    for (const address of ['[2001:db8::10]', 'node-a.example.net', '[::ffff:192.0.2.10]']) {
      const body = [realityLink, direct(address, `${NODE}-reality`)].join('\n');
      const out = applyEdgeRender(
        rctx([edgeA], { nodeAddresses: ['2001:db8:0:0::10', 'node-a.example.net'] }),
        body,
        key(1),
        { now: NOW },
      );
      expect(out.delivery).toEqual({ kind: 'unavailable', reason: 'leak_detected' });
    }
    // An entry elsewhere is no leak: the body is served, without that entry
    // (on the listener's transport and at no edge, FCP cannot place it).
    const other = [realityLink, direct('198.51.100.99', 'other')].join('\n');
    const served = applyEdgeRender(
      rctx([edgeA], { nodeAddresses: ['2001:db8::10'] }),
      other,
      key(1),
      { now: NOW },
    );
    expect(served.delivery).toEqual({ kind: 'serve' });
    expect(served.withheld).toEqual(['other']);
    expect(served.body).not.toContain('198.51.100.99');
  });

  test("an edge at one of the node's addresses is never handed out", () => {
    const out = applyEdgeRender(
      rctx([edgeA], { nodeAddresses: ['::ffff:203.0.113.10'] }),
      realityLink,
      key(1),
      { now: NOW },
    );
    expect(out.delivery).toEqual({ kind: 'unavailable', reason: 'leak_detected' });
  });
});

describe('applyEdgeRender: an entry FCP cannot place on a covered transport', () => {
  // A Host added on the node's own transport that dials it by a name FCP never
  // resolved: neither the template, nor an edge, nor a known node address.
  const BY_NAME = 'node-a.wildcard.example.net';
  const realityAt = (address: string, remark: string) =>
    `vless://${UUID}@${address}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=target.example&fp=chrome&pbk=PUBKEY&sid=abcd&type=tcp#${encodeURIComponent(remark)}`;
  const wsAt = (address: string, remark: string) =>
    `vless://${UUID}@${address}:443?encryption=none&security=tls&sni=cdn.example&type=ws&host=cdn.example&path=%2Fws#${encodeURIComponent(remark)}`;
  const edgeB: PublishedEdge = {
    ...edgeA,
    edgeId: 'eB',
    poolIndex: 1,
    provider: 'upcloud',
    addresses: { v4: '203.0.113.30' },
  };

  test('links: a retained by-name entry on the listener transport is left out and reported; the body is served', () => {
    const body = [realityLink, realityAt(BY_NAME, `${NODE}-direct`)].join('\n');
    for (let i = 0; i < 20; i++) {
      const out = applyEdgeRender(rctx([edgeA]), body, key(i), { now: NOW });
      expect(out.delivery).toEqual({ kind: 'serve' });
      expect(out.body).not.toContain(BY_NAME);
      expect(out.body).toContain('203.0.113.10');
      expect(out.withheld).toEqual([`${NODE}-direct`]);
    }
  });

  test('links: an entry on a transport no listener covers passes, and so does one at an edge of the origin', () => {
    const body = [
      realityLink,
      wsAt(BY_NAME, `${NODE}-ws`),
      realityAt('203.0.113.30', 'by-hand-front'),
    ].join('\n');
    const out = applyEdgeRender(rctx([edgeA, edgeB]), body, key(1), { now: NOW });
    expect(out.delivery).toEqual({ kind: 'serve' });
    expect(out.body).toContain(`${BY_NAME}:443`);
    expect(out.body).toContain('by-hand-front');
    expect(out.withheld).toBeUndefined();
  });

  test('a known node address is still refused outright, never quietly left out', () => {
    const body = [realityLink, realityAt(BY_NAME, `${NODE}-direct`)].join('\n');
    const out = applyEdgeRender(rctx([edgeA], { nodeAddresses: [BY_NAME] }), body, key(1), {
      now: NOW,
    });
    expect(out.delivery).toEqual({ kind: 'unavailable', reason: 'leak_detected' });
  });

  test('sing-box: the outbound goes from every group, a default and a route rule naming it', () => {
    const direct = `${NODE}-direct`;
    const body = JSON.stringify({
      outbounds: [
        {
          type: 'selector',
          tag: 'proxy',
          outbounds: [REALITY_REMARK, direct, `${NODE}-ws`],
          default: direct,
        },
        {
          type: 'vless',
          tag: REALITY_REMARK,
          server: ORIGIN,
          server_port: 443,
          uuid: UUID,
          tls: { enabled: true, server_name: 'target.example', reality: { enabled: true } },
        },
        {
          type: 'vless',
          tag: direct,
          server: BY_NAME,
          server_port: 443,
          uuid: UUID,
          tls: { enabled: true, server_name: 'target.example', reality: { enabled: true } },
        },
        {
          type: 'vless',
          tag: `${NODE}-ws`,
          server: BY_NAME,
          server_port: 443,
          uuid: UUID,
          tls: { enabled: true, server_name: 'cdn.example' },
          transport: { type: 'ws', path: '/ws' },
        },
        { type: 'direct', tag: 'direct' },
      ],
      route: { rules: [{ domain: ['example.org'], outbound: direct }], final: 'proxy' },
    });
    const out = applyEdgeRender(
      rctx([edgeA], { rule: effectiveRule(cfg, defaultClientRule('singbox')) }),
      body,
      key(3),
      { now: NOW },
    );
    expect(out.delivery).toEqual({ kind: 'serve' });
    expect(out.withheld).toEqual([direct]);
    const doc = JSON.parse(out.body) as {
      outbounds: Array<{ tag: string; server?: string; outbounds?: string[]; default?: string }>;
      route: { rules: Array<{ outbound: string }> };
    };
    const tags = doc.outbounds.map((o) => o.tag);
    expect(tags).not.toContain(direct);
    // The WebSocket entry is on a transport no listener covers: it stays.
    expect(tags).toContain(`${NODE}-ws`);
    const proxy = doc.outbounds.find((o) => o.tag === 'proxy')!;
    expect(proxy.outbounds).not.toContain(direct);
    expect(proxy.default).not.toBe(direct);
    expect(doc.route.rules[0]!.outbound).not.toBe(direct);
    expect(doc.outbounds.filter((o) => o.server === BY_NAME).map((o) => o.tag)).toEqual([
      `${NODE}-ws`,
    ]);
  });

  test('Clash: the proxy goes from every group and rule naming it', () => {
    const direct = `${NODE}-direct`;
    const body = [
      'proxies:',
      `  - { name: ${REALITY_REMARK}, type: vless, server: ${ORIGIN}, port: 443, uuid: ${UUID}, network: tcp, tls: true, servername: target.example, reality-opts: { public-key: P } }`,
      `  - { name: ${direct}, type: vless, server: ${BY_NAME}, port: 443, uuid: ${UUID}, network: tcp, tls: true, servername: target.example, reality-opts: { public-key: P } }`,
      'proxy-groups:',
      `  - { name: Proxy, type: select, proxies: [${REALITY_REMARK}, ${direct}] }`,
      'rules:',
      `  - DOMAIN-SUFFIX,example.org,${direct}`,
      '  - MATCH,Proxy',
    ].join('\n');
    const out = applyEdgeRender(
      rctx([edgeA], { rule: effectiveRule(cfg, defaultClientRule('mihomo')) }),
      body,
      key(5),
      { now: NOW },
    );
    expect(out.delivery).toEqual({ kind: 'serve' });
    expect(out.withheld).toEqual([direct]);
    expect(out.body).not.toContain(BY_NAME);
    expect(out.body).not.toContain(direct);
    expect(out.body).toContain('203.0.113.10');
  });
});
