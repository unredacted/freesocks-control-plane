/**
 * Names on a country's allowlist in the pick (docs/edges.md "Names on a
 * country's allowlist"): proven first, then listed, then not judged; a name
 * blocked there is never offered; nobody outside that country moves.
 */
import { describe, expect, test } from 'vitest';
import { countryTier, fnv1a32, rankSniHrw, type AssignableSni } from './assignment';

const CURATED = ['RU', 'IR', 'CN'];
const where = (country: string | null) => ({ country, curated: CURATED });
const keyOf = (i: number) =>
  (fnv1a32(`member:${i}`) >>> 0).toString(16).padStart(8, '0') + 'cd'.repeat(28);
const name = (sni: string, over: Partial<AssignableSni> = {}): AssignableSni => ({
  sni,
  status: 'active',
  ...over,
});
const PLAIN = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'].map((x) => name(`${x}.example`));
const withMarks = (marks: Record<string, Partial<AssignableSni>>) =>
  PLAIN.map((n) => ({ ...n, ...(marks[n.sni] ?? {}) }));

describe('the tier of a name', () => {
  test('proven, then on a list, then not judged; blocked never', () => {
    expect(countryTier(name('x', { provenIn: ['RU'] }), where('RU'))).toBe(0);
    expect(countryTier(name('x', { listedIn: ['RU'] }), where('RU'))).toBe(1);
    expect(countryTier(name('x'), where('RU'))).toBe(2);
    // A judgement beats a list both ways.
    expect(countryTier(name('x', { provenIn: ['RU'], listedIn: ['RU'] }), where('RU'))).toBe(0);
    expect(countryTier(name('x', { blockedIn: ['RU'], listedIn: ['RU'] }), where('RU'))).toBeNull();
  });

  test('a list for one country says nothing anywhere else', () => {
    const n = name('x', { listedIn: ['RU'] });
    expect(countryTier(n, where('IR'))).toBe(2);
    // The universal pool reads blocks only.
    expect(countryTier(n, where(null))).toBe(0);
    expect(countryTier(n, where('DE'))).toBe(0);
    expect(countryTier(n)).toBe(0);
  });
});

describe('the ranking', () => {
  const listed = withMarks({
    'c.example': { listedIn: ['RU'] },
    'f.example': { listedIn: ['RU'] },
  });

  test('a member there holds the listed names first, in their own rendezvous order', () => {
    for (let i = 0; i < 200; i++) {
      const before = rankSniHrw(keyOf(i), 'edge-1', PLAIN, where('RU'));
      const after = rankSniHrw(keyOf(i), 'edge-1', listed, where('RU'));
      expect(new Set(after.slice(0, 2))).toEqual(new Set(['c.example', 'f.example']));
      // Inside each tier the order is the one the member already had.
      const isListed = (s: string) => s === 'c.example' || s === 'f.example';
      expect(after.slice(0, 2)).toEqual(before.filter(isListed));
      expect(after.slice(2)).toEqual(before.filter((s) => !isListed(s)));
    }
  });

  test('members in another country, with none, and mirrors do not move', () => {
    for (let i = 0; i < 200; i++)
      for (const w of [where('IR'), where(null), where('DE'), undefined])
        expect(rankSniHrw(keyOf(i), 'edge-1', listed, w)).toEqual(
          rankSniHrw(keyOf(i), 'edge-1', PLAIN, w),
        );
  });

  test('proven names stay ahead of listed ones, and a blocked one is gone', () => {
    const names = withMarks({
      'a.example': { provenIn: ['RU'] },
      'c.example': { listedIn: ['RU'] },
      'f.example': { listedIn: ['RU'], blockedIn: ['RU'] },
    });
    for (let i = 0; i < 100; i++) {
      const r = rankSniHrw(keyOf(i), 'edge-1', names, where('RU'));
      expect(r.slice(0, 2)).toEqual(['a.example', 'c.example']);
      expect(r).not.toContain('f.example');
      expect(r).toHaveLength(7);
    }
  });

  test('how many first names move when a list starts counting: about the unlisted share', () => {
    let moved = 0;
    const N = 2000;
    for (let i = 0; i < N; i++)
      if (
        rankSniHrw(keyOf(i), 'edge-1', PLAIN, where('RU'))[0] !==
        rankSniHrw(keyOf(i), 'edge-1', listed, where('RU'))[0]
      )
        moved++;
    // 2 of 8 names are listed: a member whose first name was one of them keeps it.
    expect(moved / N).toBeGreaterThan(0.68);
    expect(moved / N).toBeLessThan(0.82);
  });
});
