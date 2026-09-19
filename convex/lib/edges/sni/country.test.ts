import { describe, expect, test } from 'vitest';
import type { PublishedEdge } from '../assignment';
import { bodyIsCacheable, cacheIsServable, isCountrySensitive, resolveWhere } from './country';

const CURATED = ['CN', 'RU', 'IR', 'MM'];

describe('resolveWhere', () => {
  test("the member's own answer beats the request; both count only when curated", () => {
    expect(resolveWhere({ override: 'ir', inferred: 'CN', curated: CURATED })).toEqual({
      where: { country: 'IR', curated: CURATED },
      source: 'override',
    });
    expect(resolveWhere({ override: null, inferred: 'CN', curated: CURATED }).source).toBe(
      'inferred',
    );
    // Not curated: no country logic, the universal pool.
    expect(resolveWhere({ override: null, inferred: 'DE', curated: CURATED })).toEqual({
      where: { country: null, curated: CURATED },
      source: 'none',
    });
    // An answer that is no longer curated falls through to the request.
    expect(resolveWhere({ override: 'DE', inferred: 'RU', curated: CURATED })).toMatchObject({
      where: { country: 'RU' },
      source: 'inferred',
    });
    // No CDN country (the deployment is not fronted, so the header is ignored upstream).
    expect(resolveWhere({ inferred: null, curated: CURATED }).source).toBe('none');
  });
});

describe('caching', () => {
  const edge = (names: PublishedEdge['serverNames'], sniPick?: 'hrw1'): PublishedEdge =>
    ({ edgeId: 'e', serverNames: names, sniPick }) as PublishedEdge;
  const marked = [{ sni: 'a.example', status: 'active' as const, blockedIn: ['CN'] }];
  const plain = [{ sni: 'a.example', status: 'active' as const }];

  test('a body is country-sensitive only when an hrw1 listener has judged names', () => {
    expect(isCountrySensitive([edge(marked, 'hrw1')])).toBe(true);
    expect(isCountrySensitive([edge(plain, 'hrw1')])).toBe(false);
    expect(isCountrySensitive([edge(marked)])).toBe(false);
    expect(isCountrySensitive([])).toBe(false);
  });

  test('an inferred country is never stored and never shared', () => {
    expect(bodyIsCacheable('inferred', true)).toBe(false);
    expect(cacheIsServable('inferred', true)).toBe(false);
    // The member's own answer is stored by their choice; no country is no country.
    for (const s of ['override', 'none'] as const) {
      expect(bodyIsCacheable(s, true)).toBe(true);
      expect(cacheIsServable(s, true)).toBe(true);
    }
    // Nothing is judged per country: caching is exactly as before.
    expect(bodyIsCacheable('inferred', false)).toBe(true);
    expect(cacheIsServable('inferred', false)).toBe(true);
  });
});
