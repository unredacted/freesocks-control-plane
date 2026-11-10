/**
 * The words of a country's SNIs: plain, short, "SNIs" never bare "names"
 * (a "name list" is the admin's own word for one), no dash between clauses.
 */
import { describe, expect, test } from 'vitest';
import type { CountryViewSni } from '@shared/contracts/edges';
import {
  SNI_CARD_EMPTY,
  SNI_CARD_INTRO,
  countryShort,
  sniCardTitle,
  sniHandedLine,
  sniPreferLine,
  SNI_PREFER_BADGE,
  sniScopeBadge,
  sniScopeLine,
  sniSummaryLine,
  sniVerdictLine,
} from './sniWords';

const sni = (over: Partial<CountryViewSni> = {}): CountryViewSni => ({
  preferred: false,
  preferDoubt: null,
  name: 'a.example',
  family: 'fam',
  familyLabel: 'Fam',
  state: 'unknown',
  basis: 'none',
  scope: 'shared',
  blockedElsewhere: [],
  handed: 0,
  transports: 1,
  ...over,
});

describe('sniWords', () => {
  test('where else an SNI is used', () => {
    expect(sniScopeLine(sni(), 'IR')).toBe(
      'Shared: used in every listed country and outside them.',
    );
    expect(sniScopeLine(sni({ scope: 'some', blockedElsewhere: ['CN'] }), 'IR')).toBe(
      'Shared, but not in China: blocked there.',
    );
    expect(sniScopeLine(sni({ scope: 'some', blockedElsewhere: ['CN', 'RU', 'TR'] }), 'IR')).toBe(
      'Shared, but not in China, Russia or Türkiye: blocked there.',
    );
    expect(sniScopeLine(sni({ scope: 'only_here', blockedElsewhere: ['RU'] }), 'IR')).toBe(
      'Only for Iran: blocked in every other listed country.',
    );
    expect(sniScopeLine(sni({ scope: 'not_here' }), 'IR')).toBe('Not used in Iran: blocked here.');
  });

  test('badges only where the scope is not the usual one', () => {
    expect(sniScopeBadge(sni(), 'IR')).toBeNull();
    expect(sniScopeBadge(sni({ scope: 'some' }), 'IR')).toBeNull();
    expect(sniScopeBadge(sni({ scope: 'only_here' }), 'IR')).toBe('Only for Iran');
    expect(sniScopeBadge(sni({ scope: 'not_here' }), 'IR')).toBe('Not used here');
  });

  test('its state here and why, and how many members get it', () => {
    expect(sniVerdictLine(sni({ state: 'blocked', basis: 'mark' }))).toBe(
      'Blocked here. An operator marked it for this country.',
    );
    expect(sniHandedLine(sni())).toBeNull();
    expect(sniHandedLine(sni({ handed: 0.4, transports: 2 }))).toBe(
      'Handed to 40% of members here. On 2 transports.',
    );
  });

  test('the countries list count', () => {
    expect(sniSummaryLine({ used: 0, onlyHere: 0 }, 'IR')).toBeNull();
    expect(sniSummaryLine({ used: 1, onlyHere: 0 }, 'IR')).toBe('1 SNI in use there.');
    expect(sniSummaryLine({ used: 12, onlyHere: 2 }, 'IR')).toBe(
      '12 SNIs in use there, 2 only for Iran.',
    );
  });

  test('the card and the country name', () => {
    expect(sniCardTitle('IR')).toBe('SNIs in Iran');
    expect(countryShort('XX')).toBe('XX');
  });

  test('plain words: SNIs, never bare names; no dashes; no "meant for"', () => {
    const all = [
      SNI_CARD_INTRO,
      SNI_CARD_EMPTY,
      sniCardTitle('IR'),
      ...(['shared', 'some', 'only_here', 'not_here'] as const).map((scope) =>
        sniScopeLine(sni({ scope, blockedElsewhere: ['RU'] }), 'IR'),
      ),
      sniSummaryLine({ used: 3, onlyHere: 1 }, 'IR')!,
    ];
    for (const line of all) {
      expect(line).not.toMatch(/[–—]/);
      expect(line).not.toMatch(/meant for|intended for/i);
      // "Name list" is the admin's word for a cover site's list.
      expect(line.replace(/server names \(SNIs\)|name lists?/gi, '')).not.toMatch(/\bnames?\b/i);
    }
  });
});

describe('an SNI a list of what works puts first', () => {
  test('says what members here get, and what speaks against it', () => {
    expect(sniPreferLine(sni())).toBeNull();
    expect(sniPreferLine(sni({ preferred: true }))).toBe(
      'On a list of what works here, so members here get it before SNIs nobody has judged.',
    );
    expect(sniPreferLine(sni({ preferred: true, preferDoubt: 'checks' }))).toBe(
      'On a list of what works here, but the checks from inside say blocked. Members here still get it first. Mark it Blocked here on its SNI list to stop that.',
    );
    expect(sniPreferLine(sni({ preferred: true, preferDoubt: 'reports' }))).toBe(
      'On a list of what works here, but members here report it more than other SNIs. Members here still get it first.',
    );
    expect(SNI_PREFER_BADGE).toBe('On a list of what works');
  });

  test('the countries list counts them', () => {
    expect(sniSummaryLine({ used: 12, onlyHere: 2, preferred: 3 }, 'IR')).toBe(
      '12 SNIs in use there, 2 only for Iran, 3 preferred from lists.',
    );
    expect(sniSummaryLine({ used: 5, onlyHere: 0, preferred: 1 }, 'IR')).toBe(
      '5 SNIs in use there, 1 preferred from lists.',
    );
    expect(sniSummaryLine({ used: 5, onlyHere: 0, preferred: 0 }, 'IR')).toBe(
      '5 SNIs in use there.',
    );
  });
});
