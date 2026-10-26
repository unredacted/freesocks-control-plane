import { describe, expect, test } from 'vitest';
import type { PublishedEdge } from './assignment';
import { pickMoves } from './edgePick';

const edge = (id: string, poolIndex: number, provider: string): PublishedEdge => ({
  edgeId: id,
  poolIndex,
  provider,
  listenerId: 'l1',
  listenerKey: 'a1',
  matchRule: { kind: 'remark', remark: 'r' },
  proto: { protocol: 'vless', streamTransport: 'raw', security: 'reality' },
  edgePort: 443,
  addresses: { v4: `203.0.113.${poolIndex + 1}` },
  serverNames: [{ sni: 'a.example', status: 'active' }],
});

describe('pickMoves', () => {
  const two = [edge('e1', 0, 'p1'), edge('e2', 1, 'p2')];
  const opts = { now: 1, preferDistinctProviders: true };
  test('two addresses, both handed out: nobody is handed anything new', () => {
    expect(pickMoves(two, null, 'hrw1', { ...opts, includeBackup: true }).moved).toBe(0);
  });
  test('two addresses, one handed out (single key, no backup): about half move', () => {
    const m = pickMoves(two, null, 'hrw1', { ...opts, includeBackup: false });
    expect(m.sampled).toBe(600);
    expect(m.moved / m.sampled).toBeGreaterThan(0.35);
    expect(m.moved / m.sampled).toBeLessThan(0.65);
  });
  test('an empty pool samples nothing', () => {
    expect(pickMoves([], null, 'hrw1', { ...opts, includeBackup: true })).toEqual({
      sampled: 0,
      moved: 0,
    });
  });
});
