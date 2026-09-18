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
    const primary = lines.find((l) => l.endsWith('#FreeSocks%20Primary'))!;
    expect(
      primary.startsWith(
        'ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpleGFtcGxlLXBhc3N3b3Jk@203.0.113.20:8388',
      ),
    ).toBe(true);
    const backup = lines.find((l) => l.endsWith('#FreeSocks%20Backup'))!;
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
