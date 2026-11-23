import { describe, expect, test } from 'vitest';
import { carryPeriodEnd, keyTrafficLimit, liveCarryBytes } from './quotaCarry';

const GB = 1024 ** 3;
const at = (iso: string) => Date.parse(iso);

describe('quota carry periods', () => {
  test('a period ends at the next UTC month, day or Monday', () => {
    const now = at('2026-11-22T17:00:00Z'); // a Sunday
    expect(carryPeriodEnd('MONTH', now)).toBe(at('2026-12-01T00:00:00Z'));
    expect(carryPeriodEnd(undefined, now)).toBe(at('2026-12-01T00:00:00Z'));
    expect(carryPeriodEnd('DAY', now)).toBe(at('2026-11-23T00:00:00Z'));
    expect(carryPeriodEnd('WEEK', now)).toBe(at('2026-11-23T00:00:00Z'));
    expect(carryPeriodEnd('WEEK', at('2026-11-23T00:00:00Z'))).toBe(at('2026-11-30T00:00:00Z'));
    expect(carryPeriodEnd('MONTH', at('2026-12-31T23:59:59Z'))).toBe(at('2027-01-01T00:00:00Z'));
    expect(carryPeriodEnd('NO_RESET', now)).toBe(Number.MAX_SAFE_INTEGER);
  });

  test('a carry counts only until its period ends', () => {
    const now = at('2026-11-22T00:00:00Z');
    const sub = { periodCarryBytes: 5 * GB, periodCarryUntil: at('2026-12-01T00:00:00Z') };
    expect(liveCarryBytes(sub, now)).toBe(5 * GB);
    expect(liveCarryBytes(sub, at('2026-12-01T00:00:00Z'))).toBe(0);
    expect(liveCarryBytes({ periodCarryBytes: 5 * GB }, now)).toBe(0);
    expect(liveCarryBytes({}, now)).toBe(0);
  });

  test('the key limit subtracts a live carry and never reaches 0', () => {
    const now = at('2026-11-22T00:00:00Z');
    const until = at('2026-12-01T00:00:00Z');
    expect(
      keyTrafficLimit(50 * GB, { periodCarryBytes: 10 * GB, periodCarryUntil: until }, now),
    ).toBe(40 * GB);
    expect(
      keyTrafficLimit(50 * GB, { periodCarryBytes: 99 * GB, periodCarryUntil: until }, now),
    ).toBe(1);
    expect(keyTrafficLimit(50 * GB, {}, now)).toBe(50 * GB);
    expect(
      keyTrafficLimit(null, { periodCarryBytes: GB, periodCarryUntil: until }, now),
    ).toBeNull();
  });
});
