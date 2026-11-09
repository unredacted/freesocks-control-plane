/**
 * The censored-country list edits: every one builds a new whole list from the
 * one on record, never touching another country.
 */
import { describe, expect, it } from 'vitest';
import type { CensoredCountry } from '@shared/contracts/admin';
import {
  CENSORED_LIST_USES,
  CHECK_SWITCHES,
  movedCountry,
  withCheck,
  withCountry,
  withoutCountry,
} from './censored';

const row = (code: string, over: Partial<CensoredCountry> = {}): CensoredCountry => ({
  code,
  checkEdges: true,
  checkNamesInside: false,
  ...over,
});
const LIST = [row('AA'), row('BB', { checkNamesInside: true }), row('CC', { checkEdges: false })];

describe('adding a country', () => {
  it('adds at the end with edge checks on and SNI checks from inside off', () => {
    expect(withCountry(LIST, 'dd', 40).at(-1)).toEqual(row('DD'));
  });

  it('ignores a repeat, a bad code, and a full list', () => {
    expect(withCountry(LIST, 'BB', 40)).toEqual(LIST);
    expect(withCountry(LIST, 'B', 40)).toEqual(LIST);
    expect(withCountry(LIST, 'DD', 3)).toEqual(LIST);
  });

  it('never changes the list it was given', () => {
    const before = JSON.stringify(LIST);
    withCountry(LIST, 'DD', 40);
    withoutCountry(LIST, 'AA');
    movedCountry(LIST, 0, 1);
    withCheck(LIST, 'AA', 'checkEdges', false);
    expect(JSON.stringify(LIST)).toBe(before);
  });
});

describe('removing and moving', () => {
  it('removes only that country', () => {
    expect(withoutCountry(LIST, 'BB').map((r) => r.code)).toEqual(['AA', 'CC']);
  });

  it('moves a row up or down, and stops at the ends', () => {
    expect(movedCountry(LIST, 0, 1).map((r) => r.code)).toEqual(['BB', 'AA', 'CC']);
    expect(movedCountry(LIST, 2, -1).map((r) => r.code)).toEqual(['AA', 'CC', 'BB']);
    expect(movedCountry(LIST, 0, -1)).toEqual(LIST);
    expect(movedCountry(LIST, 2, 1)).toEqual(LIST);
  });
});

describe('one switch of one country (Checks from here)', () => {
  it('sets only that switch of only that country', () => {
    const next = withCheck(LIST, 'BB', 'checkEdges', false);
    expect(next[1]).toEqual(row('BB', { checkEdges: false, checkNamesInside: true }));
    expect(next[0]).toEqual(LIST[0]);
    expect(next[2]).toEqual(LIST[2]);
  });

  it('leaves the list as it was for a country not on it', () => {
    expect(withCheck(LIST, 'ZZ', 'checkNamesInside', true)).toEqual(LIST);
  });
});

describe('words', () => {
  it('says what the list drives, and the risk of checks from inside', () => {
    expect(CENSORED_LIST_USES).toContain('Where are you connecting from?');
    expect(CENSORED_LIST_USES).toContain('status page matrix');
    expect(CENSORED_LIST_USES).toContain('mode suggestion');
    const inside = CHECK_SWITCHES.find((s) => s.key === 'checkNamesInside');
    expect(inside?.help).toContain('sees the address and the SNI');
  });

  it('carries no dash, no "meant for", and never "names"', () => {
    const all = [CENSORED_LIST_USES, ...CHECK_SWITCHES.flatMap((s) => [s.label, s.help])];
    for (const s of all) {
      expect(s).not.toMatch(/[–—]/);
      expect(s).not.toMatch(/meant for/i);
      expect(s).not.toMatch(/\bnames\b/i);
    }
  });
});
