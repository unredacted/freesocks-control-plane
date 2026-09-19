import { describe, expect, test } from 'vitest';
import { gateToken, isCandidateEdge, isCandidateHost, nodeGateOf } from './deliveryGate';

const committed = { hostUuids: ['h-live'], edgeIds: ['e-live'] };
const live = { delivery: { disposition: 'live' as const }, approved: { committed } };

describe('nodeGateOf', () => {
  test('an unmanaged node is open unless a maintenance transition closed it', () => {
    expect(nodeGateOf(null, [], 1, false).state).toBe('open');
    expect(nodeGateOf(null, [], 1, true).state).toBe('blocked');
  });
  test('only live opens; maintenance closes a live node', () => {
    expect(nodeGateOf(live, [], 1, false).state).toBe('open');
    expect(nodeGateOf({ ...live, maintenance: { id: 'm' } }, [], 1, false).state).toBe('blocked');
    for (const d of ['staged', 'activating', 'unavailable', 'retiring'] as const)
      expect(nodeGateOf({ delivery: { disposition: d } }, [], 1, false).state).toBe('blocked');
  });
  test('a live node preparing a replacement stays open on the committed set and hides the candidate set', () => {
    const g = nodeGateOf(
      live,
      [
        { state: 'running', resources: { hostUuids: ['h-cand'], edgeIds: ['e-cand'] } },
        { state: 'superseded', resources: { hostUuids: ['h-old'], edgeIds: [] } },
      ],
      7,
      false,
    );
    expect(g.state).toBe('open');
    expect(g.committed).toEqual(committed);
    expect(g.candidates).toEqual({ hostUuids: ['h-cand'], edgeIds: ['e-cand'] });
    expect(isCandidateHost(g, 'h-cand')).toBe(true);
    expect(isCandidateHost(g, 'h-live')).toBe(false);
    expect(isCandidateHost(g, null)).toBe(false);
    expect(isCandidateEdge(g, 'e-cand')).toBe(true);
    expect(isCandidateEdge(g, 'e-old')).toBe(false);
    expect(gateToken(g)).toBe('7:1:1');
  });
});
