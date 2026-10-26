import { describe, expect, test } from 'vitest';
import {
  attributable,
  freshWindow,
  isSuspected,
  liveStrikes,
  trustExpiresAt,
  trustMark,
  trustPepper,
  withStrike,
} from './trust';

const H = 3_600_000;
const DAY = 24 * H;
const S = {
  windowDays: 7,
  firstWaveHours: 24,
  maxFreshHolders: 50,
  strikeSpacingHours: 24,
  strikesToSuspect: 3,
  strikeDays: 30,
};

describe('the mark', () => {
  test('a stable pseudonym per account under the pepper, nothing without one', () => {
    const a = trustMark('pepper', 'user1');
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(trustMark('pepper', 'user1')).toBe(a);
    expect(trustMark('pepper', 'user2')).not.toBe(a);
    expect(trustMark('other', 'user1')).not.toBe(a);
    expect(trustMark('', 'user1')).toBeNull();
    expect(trustMark(undefined, 'user1')).toBeNull();
    expect(trustPepper({ EDGE_MARK_PEPPER: 'x', IP_HASH_SALT: 'y' })).toBe('x');
    expect(trustPepper({ IP_HASH_SALT: 'y' })).toBe('y');
    expect(trustPepper({})).toBeNull();
  });
});

describe('strikes', () => {
  test('fresh means handed in the window before the evidence began, after the first wave', () => {
    // An address long in use: the window alone.
    expect(freshWindow(10 * DAY, 0, S)).toEqual({ from: 3 * DAY, to: 10 * DAY });
    // A new one: nobody handed it in its first day counts.
    expect(freshWindow(10 * DAY, 9 * DAY, S)).toEqual({ from: 10 * DAY, to: 10 * DAY });
    expect(freshWindow(10 * DAY, 8 * DAY, S)).toEqual({ from: 9 * DAY, to: 10 * DAY });
  });

  test('a block is attributable with 1 to the cutoff fresh holders', () => {
    expect(attributable(0, S)).toBe(false);
    expect(attributable(1, S)).toBe(true);
    expect(attributable(50, S)).toBe(true);
    expect(attributable(51, S)).toBe(false);
  });

  test('one strike per spacing, three suspect, they expire', () => {
    let st: number[] = [];
    const add = (at: number) => {
      const r = withStrike(st, at, S);
      st = r.strikes;
      return r.added;
    };
    expect(add(0)).toBe(true);
    expect(add(5 * H)).toBe(false); // the same mass block, or the same day
    expect(add(DAY)).toBe(true);
    expect(isSuspected(st, DAY, S)).toBe(false);
    expect(add(2 * DAY)).toBe(true);
    expect(isSuspected(st, 2 * DAY, S)).toBe(true);
    expect(liveStrikes(st, 2 * DAY, S)).toBe(3);
    // The first one stops counting 30 days on: no longer suspected.
    expect(isSuspected(st, 30 * DAY, S)).toBe(false);
    expect(trustExpiresAt(st, S)).toBe(32 * DAY);
    // An old strike is dropped when a new one lands.
    expect(withStrike(st, 40 * DAY, S).strikes).toEqual([40 * DAY]);
  });

  test('spacing 0 counts every strike', () => {
    const r = withStrike([1000], 1000, { ...S, strikeSpacingHours: 0 });
    expect(r).toEqual({ strikes: [1000, 1000], added: true });
  });
});
