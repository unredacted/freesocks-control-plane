import { describe, expect, test } from 'vitest';
import {
  MAX_MEANT_FOR,
  changedCountries,
  cleanMeantFor,
  firstAddressMoves,
  firstEndpointOf,
  firstMeantFor,
  groupKeyOfLocation,
  liveGrade,
  meantForBlocked,
} from './meantFor';
import type { PublishedEdge } from './assignment';

describe('cleanMeantFor', () => {
  test('trimmed, upper case, each once, in the order given; listed codes only', () => {
    expect(cleanMeantFor([' ir', 'RU', 'IR', ''], ['IR', 'RU', 'CN'])).toEqual({
      ok: true,
      codes: ['IR', 'RU'],
    });
    expect(cleanMeantFor(['IR', 'TR'], ['IR'])).toEqual({
      ok: false,
      code: 'meant_for_unlisted',
      country: 'TR',
    });
    expect(cleanMeantFor([], ['IR'])).toEqual({ ok: true, codes: [] });
  });

  test(`at most ${MAX_MEANT_FOR} countries`, () => {
    const listed = Array.from({ length: 12 }, (_, i) => `C${i}`);
    expect(cleanMeantFor(listed.slice(0, MAX_MEANT_FOR), listed).ok).toBe(true);
    expect(cleanMeantFor(listed.slice(0, MAX_MEANT_FOR + 1), listed)).toMatchObject({
      ok: false,
      code: 'meant_for_too_many',
    });
  });
});

test('changedCountries: added or removed, each once, sorted', () => {
  expect(changedCountries(['IR', 'RU'], ['RU', 'CN'])).toEqual(['CN', 'IR']);
  expect(changedCountries(['IR'], ['IR'])).toEqual([]);
});

test('a location grades where its addresses do: a CDN zone with every front of its provider', () => {
  expect(groupKeyOfLocation({ provider: 'upcloud', placeKey: 'de-fra1' })).toBe('upcloud:de-fra1');
  expect(groupKeyOfLocation({ provider: 'fastly', placeKey: 'anycast' })).toBe('fastly:global');
});

describe('meantForBlocked', () => {
  test('a mark wins, then the grade, then every address in use blocked there', () => {
    expect(meantForBlocked({ groupMark: 'proven', grade: 'blocked', published: [true] })).toBe(
      false,
    );
    expect(meantForBlocked({ groupMark: 'blocked', grade: null, published: [] })).toBe(true);
    expect(meantForBlocked({ groupMark: null, grade: 'blocked', published: [false] })).toBe(true);
    expect(meantForBlocked({ groupMark: null, grade: 'mixed', published: [true, true] })).toBe(
      true,
    );
    expect(meantForBlocked({ groupMark: null, grade: null, published: [true, false] })).toBe(false);
    // Nothing in use and nothing graded: not known, not blocked.
    expect(meantForBlocked({ groupMark: null, grade: null, published: [] })).toBe(false);
  });
});

describe('codes that left the censored-country list', () => {
  test('one the location already has may stay or go; a new one must be listed', () => {
    expect(cleanMeantFor(['IR', 'RU'], ['RU'], ['IR', 'RU'])).toEqual({
      ok: true,
      codes: ['IR', 'RU'],
    });
    expect(cleanMeantFor(['RU'], ['RU'], ['IR', 'RU'])).toEqual({ ok: true, codes: ['RU'] });
    expect(cleanMeantFor(['TR'], ['RU'], ['IR', 'RU'])).toMatchObject({
      ok: false,
      code: 'meant_for_unlisted',
      country: 'TR',
    });
  });
});

test('liveGrade: a grade past its until counts for nothing', () => {
  expect(liveGrade(null, 10)).toBeNull();
  expect(liveGrade({ state: 'blocked' }, 10)).toBe('blocked');
  expect(liveGrade({ state: 'blocked', until: 11 }, 10)).toBe('blocked');
  expect(liveGrade({ state: 'blocked', until: 10 }, 10)).toBeNull();
});

describe('the address handed out first', () => {
  const pe = (over: Partial<PublishedEdge> & { edgeId: string; poolIndex: number }) =>
    ({
      provider: 'p1',
      listenerId: 'l1',
      listenerKey: 'k',
      matchRule: { kind: 'remark', remark: 'r' },
      edgePort: 443,
      addresses: { v4: `203.0.113.${over.poolIndex + 1}` },
      proto: { protocol: 'shadowsocks', streamTransport: 'raw', security: 'none' },
      serverNames: [],
      ...over,
    }) as PublishedEdge;
  const opts = {
    now: 1,
    preferDistinctProviders: true,
    includeBackup: true,
    curated: ['IR'],
  };
  // The primary stays the proven meant-for address; the edit only makes e3 the backup.
  const before = [
    pe({ edgeId: 'e1', poolIndex: 0, meantFor: ['IR'], provenIn: ['IR'] }),
    pe({ edgeId: 'e2', poolIndex: 1, provider: 'p2' }),
    pe({ edgeId: 'e3', poolIndex: 2, provider: 'p3' }),
  ];
  const after = before.map((e) => (e.edgeId === 'e3' ? { ...e, meantFor: ['IR'] } : e));

  test('the primary, unless the rule hands out the backup first', () => {
    expect(firstAddressMoves(before, after, 'IR', opts).moved).toBe(0);
    const backupFirst = firstAddressMoves(before, after, 'IR', { ...opts, backupFirst: true });
    // On the legacy walk every seat's backup was e2 (the next in pool order): all move to e3.
    expect(backupFirst.sampled).toBeGreaterThan(0);
    expect(backupFirst.moved).toBe(backupFirst.sampled);
  });

  test('firstEndpointOf and firstMeantFor follow the same rule', () => {
    const a = {
      primary: { edge: before[0]! } as never,
      backup: { edge: before[1]! } as never,
      primaryMeantFor: true as const,
    };
    expect(firstEndpointOf(a, false)).toBe(a.primary);
    expect(firstEndpointOf(a, true)).toBe(a.backup);
    expect(firstEndpointOf({ ...a, backup: null }, true)).toBe(a.primary);
    expect(firstMeantFor(a, false)).toBe(true);
    expect(firstMeantFor(a, true)).toBe(false);
  });
});
