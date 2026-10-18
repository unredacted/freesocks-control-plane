import { describe, expect, it } from 'vitest';
import {
  edgeInFlight,
  LIVE_BUSY_MS,
  LIVE_DEBOUNCE_MS,
  LIVE_IDLE_MS,
  liveInterval,
  originBusy,
  originStamp,
  originStatusStamp,
  OriginStamps,
  updatedAgoWords,
} from './livePoll';

const origin = {
  publicationEpoch: 4,
  activeRotationId: null as string | null,
  lastRotatedAt: '2026-10-18T10:00:00.000Z' as string | null,
  publishedEdgeIds: ['e1', null, 'e2'] as Array<string | null>,
  standbyEdgeIds: ['s2', 's1'],
  quarantine: null as { rotationId: string } | null,
  restore: null as { phase: string } | null,
  deleting: false,
};

describe('liveInterval', () => {
  it('is never off: idle 30 s, busy a few seconds', () => {
    expect(liveInterval(false)).toBe(LIVE_IDLE_MS);
    expect(liveInterval(true)).toBe(LIVE_BUSY_MS);
    expect(LIVE_IDLE_MS).toBe(30_000);
    expect(LIVE_BUSY_MS).toBeGreaterThanOrEqual(3_000);
    expect(LIVE_BUSY_MS).toBeLessThanOrEqual(5_000);
  });
});

describe('edgeInFlight / originBusy', () => {
  it('counts an edge being made, checked or destroyed, or holding an operation', () => {
    expect(edgeInFlight([])).toBe(false);
    expect(edgeInFlight([{ status: 'active', currentOp: null }])).toBe(false);
    expect(edgeInFlight([{ status: 'draining', currentOp: null }])).toBe(false);
    for (const status of ['planning', 'provisioning', 'verifying', 'destroying'])
      expect(edgeInFlight([{ status: 'active' }, { status }])).toBe(true);
    expect(edgeInFlight([{ status: 'active', currentOp: { opId: 'x' } }])).toBe(true);
  });

  it('a rotation, a restore or a delete makes the origin busy', () => {
    expect(originBusy(origin)).toBe(false);
    expect(originBusy({ ...origin, activeRotationId: 'r1' })).toBe(true);
    expect(originBusy({ ...origin, restore: { phase: 'hosts' } })).toBe(true);
    expect(originBusy({ ...origin, deleting: true })).toBe(true);
  });
});

describe('originStamp', () => {
  it('moves with what members get, not with the row being written', () => {
    const base = originStamp(origin);
    expect(originStamp({ ...origin })).toBe(base);
    // Spare order is not a change.
    expect(originStamp({ ...origin, standbyEdgeIds: ['s1', 's2'] })).toBe(base);
    const moved = [
      { publicationEpoch: 5 },
      { activeRotationId: 'r1' },
      { lastRotatedAt: '2026-10-18T10:00:40.000Z' },
      { publishedEdgeIds: ['e3', null, 'e2'] },
      { standbyEdgeIds: ['s1'] },
      { quarantine: { rotationId: 'r1' } },
      { restore: { phase: 'hosts' } },
      { deleting: true },
    ];
    for (const m of moved) expect(originStamp({ ...origin, ...m })).not.toBe(base);
  });

  it('the attention stamp moves with the status, the run and the counts', () => {
    const s = {
      kind: 'protected',
      code: null,
      runId: null,
      step: null,
      published: 2,
      standbys: 1,
      offline: 0,
    };
    const base = originStatusStamp(s);
    expect(originStatusStamp({ ...s })).toBe(base);
    expect(originStatusStamp({ ...s, standbys: 0 })).not.toBe(base);
    expect(originStatusStamp({ ...s, kind: 'needs-you', code: 'needs_test' })).not.toBe(base);
    expect(originStatusStamp({ ...s, runId: 'run1', step: 2 })).not.toBe(base);
  });
});

describe('OriginStamps', () => {
  it('a first sighting is not a change; a moved stamp is, once', () => {
    const book = new OriginStamps();
    expect(book.observe('lookup', [['a', '1']], 0)).toEqual([]);
    expect(book.observe('lookup', [['a', '1']], 10_000)).toEqual([]);
    expect(book.observe('lookup', [['a', '2']], 20_000)).toEqual(['a']);
    expect(book.observe('lookup', [['a', '2']], 30_000)).toEqual([]);
  });

  it('compares each source with its own last reading (a slow summary cannot ping-pong)', () => {
    const book = new OriginStamps();
    book.observe('lookup', [['a', 'old']], 0);
    book.observe('summary', [['a', 'old']], 0);
    expect(book.observe('lookup', [['a', 'new']], 10_000)).toEqual(['a']);
    // A summary read that started before the change still says `old`: nothing moved for it.
    expect(book.observe('summary', [['a', 'old']], 20_000)).toEqual([]);
    expect(book.observe('summary', [['a', 'new']], 40_000)).toEqual(['a']);
  });

  it('refreshes one origin at most once per debounce window, per origin', () => {
    const book = new OriginStamps();
    book.observe('lookup', [['a', '1']], 0);
    book.observe(
      'attention',
      [
        ['a', 'x'],
        ['b', 'y'],
      ],
      0,
    );
    expect(book.observe('lookup', [['a', '2']], 50_000)).toEqual(['a']);
    // Attention sees the same change a moment later: already being read.
    expect(
      book.observe(
        'attention',
        [
          ['a', 'x2'],
          ['b', 'y2'],
        ],
        50_000 + LIVE_DEBOUNCE_MS - 1,
      ),
    ).toEqual(['b']);
    // After the window a new move counts again.
    expect(book.observe('attention', [['a', 'x3']], 50_000 + LIVE_DEBOUNCE_MS)).toEqual(['a']);
  });

  it('the detector case: a rotation that starts and ends between two list polls', () => {
    // The lists poll every 30 s; the lookup sees the epoch move once the replacement is done.
    const book = new OriginStamps();
    const before = originStamp(origin);
    book.observe('lookup', [['node-a', before]], 0);
    const after = originStamp({
      ...origin,
      publicationEpoch: 5,
      lastRotatedAt: '2026-10-18T10:00:40.000Z',
      publishedEdgeIds: ['s1', null, 'e2'],
      standbyEdgeIds: ['s2'],
    });
    expect(book.observe('lookup', [['node-a', after]], 30_000)).toEqual(['node-a']);
  });
});

describe('updatedAgoWords', () => {
  it('words the age in 5 s steps, then minutes and hours, no em-dash', () => {
    expect(updatedAgoWords(-50)).toBe('Updated just now');
    expect(updatedAgoWords(4_999)).toBe('Updated just now');
    expect(updatedAgoWords(5_000)).toBe('Updated 5 s ago');
    expect(updatedAgoWords(27_400)).toBe('Updated 25 s ago');
    expect(updatedAgoWords(59_999)).toBe('Updated 55 s ago');
    expect(updatedAgoWords(60_000)).toBe('Updated 1 min ago');
    expect(updatedAgoWords(59 * 60_000)).toBe('Updated 59 min ago');
    expect(updatedAgoWords(3 * 3_600_000)).toBe('Updated 3 h ago');
    for (const ms of [0, 7_000, 90_000, 7_200_000]) expect(updatedAgoWords(ms)).not.toContain('—');
  });
});
