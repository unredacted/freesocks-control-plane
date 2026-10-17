import { describe, expect, test } from 'vitest';
import { bodyIsCacheable, cacheIsServable, resolveWhere } from './country';

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
