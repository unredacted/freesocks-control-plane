import { describe, expect, test } from 'vitest';
import { CountryListHoldReason, type CountryListVersion } from '@shared/contracts/countryLists';
import { edgesPaths, resolveEdgesRoute } from '../lib/routes';
import { resolveSectionRoute, tabOf } from '../../servers/lib/routes';
import { parseAsns } from '../names/lib/words';
import {
  countsLine,
  diffLine,
  droppedLine,
  edgeCountsLine,
  freshnessLine,
  HOLD_REASON_WORDS,
  listErrorWords,
  markRowWords,
  marksWaitLine,
  OUTCOME_WORDS,
  parseLookup,
  REGIME_WORDS,
  sourceLine,
  STATUS_WORDS,
  watchLine,
  watchWaitsLine,
} from './listWords';

const counts: CountryListVersion['counts'] = {
  entries: 4,
  names: 2,
  wildcards: 1,
  v4Ranges: 1,
  v6Ranges: 0,
  v4: 256,
  v6: 0,
  invalid: 1,
  nonPublic: 0,
  tooBroad: 0,
  capped: 0,
};

describe('list words', () => {
  test('every hold reason has words', () => {
    expect(Object.keys(HOLD_REASON_WORDS).sort()).toEqual(
      [...CountryListHoldReason.options].sort(),
    );
  });

  test('every sentence is plain: no em-dash, no API path, ends with a full stop', () => {
    const all = [
      ...Object.values(HOLD_REASON_WORDS),
      ...Object.values(OUTCOME_WORDS),
      ...Object.values(REGIME_WORDS).map((r) => r.explain),
      ...['edge.list.bad_url', 'edge.list.busy', 'edge.list.version_stale', 'nope'].map((c) =>
        listErrorWords(c),
      ),
    ];
    for (const s of all) {
      expect(s).not.toMatch(/—/);
      expect(s).not.toMatch(/\/api\//);
      expect(s.trim().endsWith('.')).toBe(true);
    }
    for (const s of Object.values(STATUS_WORDS)) expect(s).not.toMatch(/—/);
  });

  test('counts, what was left out, and what changed', () => {
    expect(countsLine(counts)).toBe('2 hostnames, 1 wildcard, 1 IPv4 range (256 addresses).');
    expect(droppedLine(counts)).toBe('Left out: 1 line that could not be read.');
    expect(droppedLine({ ...counts, invalid: 0 })).toBeNull();
    expect(
      diffLine({
        names: { added: 1, removed: 0, common: 2 },
        v4: { added: 0, removed: 0, common: 256 },
        v6: { added: 0, removed: 0, common: 0 },
      }),
    ).toBe('Hostnames: 1 hostname new, none gone.');
    expect(
      diffLine({
        names: { added: 0, removed: 0, common: 2 },
        v4: { added: 0, removed: 0, common: 256 },
        v6: { added: 0, removed: 0, common: 0 },
      }),
    ).toBe('The same hostnames and ranges as before.');
    expect(diffLine(null)).toBeNull();
  });

  test('where a list comes from, and whether it is fresh', () => {
    expect(
      sourceLine({
        source: { kind: 'url', url: 'https://example.com/a.txt' },
        fetchEveryHours: 24,
      }),
    ).toBe('Fetched from example.com every 24 hours.');
    expect(sourceLine({ source: { kind: 'paste' }, fetchEveryHours: 24 })).toBe('Pasted by hand.');
    const now = Date.UTC(2026, 10, 2);
    const active = { id: 'v' } as CountryListVersion;
    expect(freshnessLine({ active: null, confirmedAt: null, fresh: false }, 30, now)).toBe(
      'No version in use yet.',
    );
    expect(
      freshnessLine(
        { active, confirmedAt: new Date(now - 3_600_000).toISOString(), fresh: true },
        30,
        now,
      ),
    ).toBe('Confirmed 1 h ago.');
    expect(freshnessLine({ active, confirmedAt: '2026-01-01', fresh: false }, 30, now)).toContain(
      'Stale',
    );
  });

  test('a list takes up to 32 networks; a name network still 8', () => {
    const nine = Array.from({ length: 9 }, (_, i) => `AS${64500 + i}`).join(' ');
    expect(parseAsns(nine)).toBeNull();
    expect(parseAsns(nine, 32)).toHaveLength(9);
  });

  test('lookup entries', () => {
    expect(parseLookup('example.com, 192.0.2.1\nexample.com')).toEqual([
      'example.com',
      '192.0.2.1',
    ]);
  });
});

describe('edge addresses against a list', () => {
  const NOW = Date.UTC(2026, 10, 3, 12);
  test('the switch, why checks wait, and the counts', () => {
    expect(watchLine(true)).toMatch(/^On\. /);
    expect(watchLine(false)).toMatch(/^Off\. /);
    const l = { enabled: true, fresh: true, active: null };
    expect(watchWaitsLine(l, false)).toMatch(/Country lists are off/);
    expect(watchWaitsLine({ ...l, enabled: false }, true)).toMatch(/This list is off/);
    expect(watchWaitsLine(l, true)).toMatch(/No version is in use/);
    expect(watchWaitsLine({ ...l, fresh: false, active: {} as never }, true)).toMatch(/stale/);
    expect(watchWaitsLine({ ...l, active: {} as never }, true)).toBeNull();
    expect(edgeCountsLine({ listed: 2, not_listed: 1, left: 1, checking: 0 })).toBe(
      'Of 4 edge addresses: 2 addresses on it, 1 left it, 1 never on it.',
    );
    expect(edgeCountsLine({ listed: 0, not_listed: 0, left: 0, checking: 0 })).toBe(
      'No edge has an IP address to check.',
    );
  });

  test('one address on the sheet', () => {
    const row = {
      family: 'v4' as const,
      address: '192.0.2.10',
      since: new Date(NOW - 2 * 3_600_000).toISOString(),
      checkedAt: null,
      markId: 'm',
      leftAt: null,
      needsLook: true,
    };
    expect(markRowWords({ ...row, state: 'left' }, NOW)).toBe('Left it 2 h ago.');
    expect(markRowWords({ ...row, state: 'listed' }, NOW)).toBe('On it, first seen there 2 h ago.');
    expect(markRowWords({ ...row, state: 'not_listed', since: null }, NOW)).toBe(
      'Not on it, and never was.',
    );
    expect(markRowWords({ ...row, state: 'checking', since: null }, NOW)).toBe(
      'Not checked against the version in use yet.',
    );
    const l = { checked: false, enabled: true, fresh: true };
    expect(marksWaitLine({ ...l, checked: true }, true)).toBeNull();
    expect(marksWaitLine(l, false)).toBe('Not checked now: country lists are off.');
    expect(marksWaitLine({ ...l, fresh: false }, true)).toBe(
      'Not checked now: this list is stale.',
    );
    for (const e of [
      'edge.list.watch_allowlist_only',
      'edge.list.mark_not_left',
      'edge.list.mark_moved',
      'edge.list.watch_cap',
      'edge.list.prefer_allowlist_only',
    ])
      expect(listErrorWords(e)).not.toBe(listErrorWords('nope'));
  });
});

describe('list routes', () => {
  test('lists sit under Countries, and "lists" is no country', () => {
    expect(resolveEdgesRoute(edgesPaths.lists())).toEqual({ page: 'lists' });
    expect(resolveEdgesRoute(edgesPaths.list('abc'))).toEqual({ page: 'list', id: 'abc' });
    expect(resolveEdgesRoute('/admin/servers/countries/ru')).toEqual({
      page: 'country',
      code: 'RU',
    });
    expect(tabOf(resolveSectionRoute(edgesPaths.list('abc')))).toBe('countries');
  });
});
