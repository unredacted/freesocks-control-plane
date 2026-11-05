import { describe, expect, test } from 'vitest';
import type { EdgeAdmin } from '@shared/contracts/edges';
import type { EdgeCountryLine } from '../lib/countryChecks';
import {
  CHECKED_BY_FCP,
  accountText,
  addressDot,
  addressForms,
  addressHealthLine,
  addressStateWord,
  countrySummary,
  testedWord,
} from './addressWords';

const reach = (...verdicts: string[]) =>
  ({ byCountry: verdicts.map((verdict) => ({ verdict })) }) as unknown as EdgeAdmin['reachability'];

describe('an address row', () => {
  test('shows IPv4 first with IPv6 beside it, and a CDN front by its name', () => {
    expect(
      addressForms({
        name: 'e1',
        addresses: { v4: '192.0.2.1', v6: '2001:db8::1', hostname: null },
      }),
    ).toEqual({ main: '192.0.2.1', others: ['2001:db8::1'] });
    expect(
      addressForms({ name: 'e1', addresses: { v4: null, v6: '2001:db8::1', hostname: null } }),
    ).toEqual({
      main: '2001:db8::1',
      others: [],
    });
    expect(
      addressForms({ name: 'e1', addresses: { hostname: 'a.example', v4: '192.0.2.1', v6: null } }),
    ).toEqual({ main: 'a.example', others: ['192.0.2.1'] });
    expect(addressForms({ name: 'e1', addresses: { v4: null, v6: null, hostname: null } })).toEqual(
      { main: 'e1', others: [] },
    );
  });

  test('its dot: red offline or unreachable, amber degraded or partly, green online', () => {
    expect(addressDot({ health: 'online', reachability: reach('reachable') })).toBe('green');
    expect(addressDot({ health: 'online', reachability: null })).toBe('green');
    expect(addressDot({ health: 'online', reachability: reach('reachable', 'unreachable') })).toBe(
      'amber',
    );
    expect(addressDot({ health: 'degraded', reachability: null })).toBe('amber');
    expect(addressDot({ health: 'online', reachability: reach('unreachable') })).toBe('red');
    expect(addressDot({ health: 'offline', reachability: null })).toBe('red');
    expect(addressDot({ health: 'unknown', reachability: null })).toBe('grey');
  });

  test('its details say what the provider and the outside checks found', () => {
    expect(addressHealthLine({ health: 'online', reachability: reach('reachable') })).toMatch(
      /^Provider check: .+\. Reachable from outside\.$/,
    );
  });

  test('what it is, with its lane only while lanes are on, and who it is only for', () => {
    const w = (
      publication: EdgeAdmin['publication'],
      lane: EdgeAdmin['lane'],
      lanes: boolean,
      audience: string[] = [],
    ) => addressStateWord({ publication, lane, audience }, lanes);
    expect(w('published', null, false)).toBe('In use');
    expect(w('published', 'trusted', true)).toBe('In use (trusted)');
    expect(w('published', null, true)).toBe('In use (open)');
    expect(w('unpublished', null, true)).toBe('Spare');
    expect(w('draining', null, false)).toBe('Retiring');
    expect(w('published', null, false, ['IR', 'RU'])).toBe('In use (only for Iran, Russia)');
    expect(w('unpublished', null, false, ['IR'])).toBe('Spare (only for Iran)');
  });

  test('whether it is tested, and only when a test is asked of it', () => {
    const v = (verification: Partial<EdgeAdmin['verification']>) =>
      ({ verification: { required: true, current: false, stale: false, ...verification } }) as Pick<
        EdgeAdmin,
        'verification'
      >;
    expect(testedWord(v({ required: false }), false)).toBeNull();
    expect(testedWord(v({ current: true }), true)).toBeNull();
    expect(testedWord(v({ current: true }), false)).toEqual({ word: 'tested', needsTest: false });
    expect(
      testedWord(
        v({ current: true, record: { method: 'client_check' } } as Partial<
          EdgeAdmin['verification']
        >),
        false,
      ),
    ).toEqual({ word: CHECKED_BY_FCP, needsTest: false });
    expect(testedWord(v({ stale: true }), false)).toEqual({
      word: 'retest needed',
      needsTest: true,
    });
    expect(testedWord(v({}), false)).toEqual({ word: 'not tested yet', needsTest: true });
  });

  test('the countries in one line: problems first, each group in list order', () => {
    const mark = (state: 'proven' | 'blocked') =>
      ({ scope: 'edge', state }) as unknown as EdgeCountryLine['edgeMark'];
    const lines: EdgeCountryLine[] = [
      { country: 'CN', row: null, edgeMark: mark('proven'), groupMark: null },
      { country: 'IR', row: null, edgeMark: mark('blocked'), groupMark: null },
      { country: 'RU', row: null, edgeMark: mark('proven'), groupMark: null },
      { country: 'AE', row: null, edgeMark: null, groupMark: null },
    ];
    const groups = countrySummary(lines, Date.now());
    expect(groups.map((g) => [g.label, g.countries.map((c) => c.code)])).toEqual([
      ['Blocked', ['IR']],
      ['Works', ['CN', 'RU']],
      ['Not checked yet', ['AE']],
    ]);
    expect(groups[0]!.tone).toBe('danger');
    expect(groups[0]!.countries[0]!.title).toMatch(/^Iran: blocked\./);
  });

  test('a provider is named once when the account carries its name', () => {
    expect(accountText('upcloud', 'upcloud')).toBe('UpCloud');
    expect(accountText('Main', 'upcloud')).toBe('Main (UpCloud)');
  });

  test('no em-dash in any word', () => {
    const all = [
      addressHealthLine({ health: 'offline', reachability: reach('unreachable') }),
      CHECKED_BY_FCP,
      accountText('Main', 'upcloud'),
    ].join(' ');
    expect(all).not.toMatch(/—/);
  });
});
