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
        { state: 'committed', resources: { hostUuids: ['h-live'], edgeIds: ['e-live'] } },
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
    expect(isCandidateEdge(g, 'e-live')).toBe(false);
  });
  test('a superseded, blocked or failed run keeps its candidates isolated until a commit takes them over', () => {
    const runs = [
      { state: 'superseded', resources: { hostUuids: ['h-old'], edgeIds: ['e-old'] } },
      { state: 'blocked', resources: { hostUuids: [], edgeIds: ['e-blocked'] } },
      { state: 'failed', resources: { hostUuids: [], edgeIds: ['e-failed'] } },
      // A resource of an uncommitted run that a later commit took over is not a candidate.
      { state: 'superseded', resources: { hostUuids: ['h-live'], edgeIds: ['e-live'] } },
    ];
    const g = nodeGateOf(live, runs, 7, false);
    expect(g.candidates).toEqual({
      hostUuids: ['h-old'],
      edgeIds: ['e-blocked', 'e-failed', 'e-old'],
    });
    expect(isCandidateEdge(g, 'e-old')).toBe(true);
    expect(isCandidateEdge(g, 'e-live')).toBe(false);
  });
  test('the token names the candidate set: a new candidate moves it', () => {
    const none = nodeGateOf(live, [], 7, false);
    expect(gateToken(none)).toBe('7:1:1:0');
    const one = nodeGateOf(
      live,
      [{ state: 'running', resources: { hostUuids: [], edgeIds: ['e-cand'] } }],
      7,
      false,
    );
    const two = nodeGateOf(
      live,
      [{ state: 'running', resources: { hostUuids: [], edgeIds: ['e-cand', 'e-cand-2'] } }],
      7,
      false,
    );
    expect(gateToken(one)).not.toBe(gateToken(none));
    expect(gateToken(two)).not.toBe(gateToken(one));
    // Same set, same version: same token (order does not matter).
    const same = nodeGateOf(
      live,
      [{ state: 'running', resources: { hostUuids: [], edgeIds: ['e-cand-2', 'e-cand'] } }],
      7,
      false,
    );
    expect(gateToken(same)).toBe(gateToken(two));
  });
});
