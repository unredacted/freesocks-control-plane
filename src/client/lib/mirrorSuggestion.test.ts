import { describe, expect, test } from 'vitest';
import {
  chosenLink,
  mirrorLinks,
  mirrorSuggested,
  suggestionCountry,
  withMirror,
  withoutMirrors,
} from './mirrorSuggestion';

const MAIN = 'https://site.example/api/v1/sub/token-1';
const A = 'https://cdn-1.example/mirrors/aaaa';
const B = 'https://cdn-2.example/mirrors/aaaa';

describe('mirrorSuggested', () => {
  const base = {
    geoCountry: 'IR',
    geoCountryCensored: true,
    mirrorsEnabled: true,
    rawConfig: false,
  };

  test('a censored country on a deployment with mirrors, in a link mode', () => {
    expect(mirrorSuggested(base)).toBe(true);
  });

  test('no country, no suggestion, whatever the flag says', () => {
    expect(mirrorSuggested({ ...base, geoCountry: null })).toBe(false);
    expect(mirrorSuggested({ ...base, geoCountry: undefined })).toBe(false);
  });

  test('a country not on the list, or an older server without the flag', () => {
    expect(mirrorSuggested({ ...base, geoCountryCensored: false })).toBe(false);
    expect(mirrorSuggested({ ...base, geoCountryCensored: undefined })).toBe(false);
  });

  test("the member's own answer wins over this request's country", () => {
    // Said a listed country: suggested even when the request looks elsewhere (a VPN).
    expect(
      mirrorSuggested({ ...base, geoCountry: 'DE', geoCountryCensored: false, storedChoice: 'IR' }),
    ).toBe(true);
    expect(
      suggestionCountry({ geoCountry: 'DE', geoCountryCensored: false, storedChoice: 'IR' }),
    ).toBe('IR');
    // Said "Somewhere else": never suggested, whatever this request says.
    expect(mirrorSuggested({ ...base, storedChoice: 'ZZ' })).toBe(false);
    expect(suggestionCountry({ ...base, storedChoice: 'ZZ' })).toBeNull();
    // No answer: this request's listed country, as before.
    expect(suggestionCountry({ ...base, storedChoice: null })).toBe('IR');
  });

  test('no mirrors on this deployment, or a rawConfig mode (no public mirrors)', () => {
    expect(mirrorSuggested({ ...base, mirrorsEnabled: false })).toBe(false);
    expect(mirrorSuggested({ ...base, mirrorsEnabled: undefined })).toBe(false);
    expect(mirrorSuggested({ ...base, rawConfig: true })).toBe(false);
  });
});

describe('mirrorLinks', () => {
  test("the server's order, without the main link, blanks or repeats", () => {
    expect(
      mirrorLinks(
        [
          { publicUrl: B },
          { publicUrl: MAIN },
          { publicUrl: '' },
          { publicUrl: A },
          { publicUrl: B },
        ],
        MAIN,
      ),
    ).toEqual([B, A]);
  });
});

describe('chosenLink', () => {
  test('no mirror yet: the main link', () => {
    expect(chosenLink(MAIN, [], null)).toBe(MAIN);
  });

  test('a mirror and no pick: the mirror (the recommendation)', () => {
    expect(chosenLink(MAIN, [A, B], null)).toBe(A);
  });

  test('the pick wins while it is on offer, the main link included', () => {
    expect(chosenLink(MAIN, [A, B], B)).toBe(B);
    expect(chosenLink(MAIN, [A], MAIN)).toBe(MAIN);
  });

  test('a pick no longer on offer (removed, or an old key) falls back', () => {
    expect(chosenLink(MAIN, [A], B)).toBe(A);
    expect(chosenLink(MAIN, [], A)).toBe(MAIN);
    expect(chosenLink('https://site.example/api/v1/sub/token-2', [], MAIN)).toBe(
      'https://site.example/api/v1/sub/token-2',
    );
  });
});

describe('withMirror', () => {
  const view = {
    geoCountry: 'IR',
    subscription: { url: MAIN, mirrors: [{ provider: 'p1', publicUrl: A }] },
  };

  test('adds the new mirror to the cached view without touching the rest', () => {
    const next = withMirror(view, { provider: 'p2', publicUrl: B });
    expect(next?.subscription?.mirrors.map((m) => m.publicUrl)).toEqual([A, B]);
    expect(next?.geoCountry).toBe('IR');
    expect(view.subscription.mirrors).toHaveLength(1);
  });

  test('a mirror already listed, no view, or no key: unchanged', () => {
    expect(withMirror(view, { provider: 'p1', publicUrl: A })).toBe(view);
    expect(withMirror(undefined, { provider: 'p2', publicUrl: B })).toBeUndefined();
    const keyless = { subscription: null };
    expect(withMirror(keyless, { provider: 'p2', publicUrl: B })).toBe(keyless);
  });
});

describe('withoutMirrors', () => {
  test('empties the cached list and keeps the rest', () => {
    const view = {
      geoCountry: 'IR',
      subscription: { url: MAIN, mirrors: [{ provider: 'p1', publicUrl: A }] },
    };
    const next = withoutMirrors(view);
    expect(next?.subscription?.mirrors).toEqual([]);
    expect(next?.geoCountry).toBe('IR');
    expect(view.subscription.mirrors).toHaveLength(1);
  });

  test('nothing to clear: unchanged', () => {
    const empty = { subscription: { mirrors: [] as { provider: string; publicUrl: string }[] } };
    expect(withoutMirrors(empty)).toBe(empty);
    expect(withoutMirrors(undefined)).toBeUndefined();
    const keyless = { subscription: null };
    expect(withoutMirrors(keyless)).toBe(keyless);
  });
});
