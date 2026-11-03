/**
 * The edge-address mark rules (docs/edges.md "Edge addresses against
 * allowlists"): a check's outcome, the state a mark reads as now, and when it
 * asks for a look. Documentation addresses only.
 */
import { describe, expect, test } from 'vitest';
import { leftNeedsLook, markSince, markState, nextMark, type MarkFields } from './edgeMarks';

const A = '192.0.2.10';
const B = '198.51.100.5';

describe('nextMark', () => {
  test('first check: listed sets both dates; not listed sets none', () => {
    expect(nextMark(null, { address: A, versionId: 'v1', listed: true, now: 10 })).toEqual({
      address: A,
      versionId: 'v1',
      listed: true,
      checkedAt: 10,
      firstListedAt: 10,
      lastListedAt: 10,
    });
    expect(nextMark(null, { address: A, versionId: 'v1', listed: false, now: 10 })).toEqual({
      address: A,
      versionId: 'v1',
      listed: false,
      checkedAt: 10,
    });
  });

  test('listed, gone, listed again: first date kept, left date set then cleared, seen kept', () => {
    let m: MarkFields = nextMark(null, { address: A, versionId: 'v1', listed: true, now: 10 });
    m = nextMark(m, { address: A, versionId: 'v2', listed: false, now: 20 });
    expect(m).toMatchObject({ listed: false, firstListedAt: 10, lastListedAt: 10, leftAt: 20 });
    m = { ...m, seenAt: 25 };
    // Still gone in the next version: it left when it first did.
    m = nextMark(m, { address: A, versionId: 'v3', listed: false, now: 30 });
    expect(m).toMatchObject({ leftAt: 20, seenAt: 25, versionId: 'v3' });
    m = nextMark(m, { address: A, versionId: 'v4', listed: true, now: 40 });
    expect(m).toMatchObject({ listed: true, firstListedAt: 10, lastListedAt: 40, seenAt: 25 });
    expect(m.leftAt).toBeUndefined();
  });

  test('a new address starts over', () => {
    const old: MarkFields = {
      address: A,
      versionId: 'v1',
      listed: false,
      firstListedAt: 10,
      lastListedAt: 10,
      leftAt: 20,
      seenAt: 25,
      checkedAt: 20,
    };
    expect(nextMark(old, { address: B, versionId: 'v1', listed: false, now: 30 })).toEqual({
      address: B,
      versionId: 'v1',
      listed: false,
      checkedAt: 30,
    });
  });
});

describe('markState and leftNeedsLook', () => {
  const now = { address: A, activeVersionId: 'v2' };
  const left: MarkFields = {
    address: A,
    versionId: 'v2',
    listed: false,
    firstListedAt: 10,
    lastListedAt: 10,
    leftAt: 20,
    checkedAt: 20,
  };

  test('not checked: no mark, another version, another address, no address', () => {
    expect(markState(null, now)).toBe('checking');
    expect(markState({ ...left, versionId: 'v1' }, now)).toBe('checking');
    expect(markState(left, { ...now, address: B })).toBe('checking');
    expect(markState(left, { ...now, address: undefined })).toBe('checking');
    expect(markState(left, { ...now, activeVersionId: undefined })).toBe('checking');
  });

  test('listed, left, never listed', () => {
    expect(markState({ ...left, listed: true }, now)).toBe('listed');
    expect(markState(left, now)).toBe('left');
    const never = { address: A, versionId: 'v2', listed: false, checkedAt: 20 };
    expect(markState(never, now)).toBe('not_listed');
    expect(leftNeedsLook(never, now)).toBe(false);
  });

  test('a look until seen after it was last listed', () => {
    expect(leftNeedsLook(left, now)).toBe(true);
    expect(leftNeedsLook({ ...left, seenAt: 25 }, now)).toBe(false);
    // Seen before it was listed again: it asks again.
    expect(leftNeedsLook({ ...left, seenAt: 5 }, now)).toBe(true);
    // Not current: nothing asked.
    expect(leftNeedsLook({ ...left, versionId: 'v1' }, now)).toBe(false);
  });

  test('since: first listed, or when it left', () => {
    expect(markSince({ ...left, listed: true }, 'listed')).toBe(10);
    expect(markSince(left, 'left')).toBe(20);
    expect(markSince(left, 'checking')).toBeNull();
    expect(markSince(null, 'listed')).toBeNull();
  });
});
