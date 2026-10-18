import { describe, expect, it } from 'vitest';
import { ownCountryOf } from './countries';

describe('ownCountryOf', () => {
  const view = (source: string, choice: string | null) => ({ source, choice });

  it('is the member’s own listed answer', () => {
    expect(ownCountryOf(view('choice', 'IR'))).toBe('IR');
  });

  it('never a guess, "Somewhere else", nothing or an unknown code', () => {
    expect(ownCountryOf(view('guess', 'IR'))).toBeNull();
    expect(ownCountryOf(view('choice', 'ZZ'))).toBeNull();
    expect(ownCountryOf(view('none', null))).toBeNull();
    expect(ownCountryOf(view('choice', null))).toBeNull();
    expect(ownCountryOf(view('choice', 'XX'))).toBeNull();
    expect(ownCountryOf(undefined)).toBeNull();
    expect(ownCountryOf(null)).toBeNull();
  });
});
