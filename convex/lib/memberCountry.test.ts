import { describe, expect, test } from 'vitest';
import {
  MEMBER_COUNTRY_DEFAULTS,
  liveGuess,
  memberCountryConfig,
  memberCountryView,
  memberWhere,
  nextGuess,
  storedCountry,
  suggestionCountry,
  type CountryFields,
  type MemberFamily,
  steeringCountry,
  wideGuesses,
} from './memberCountry';

const NOW = 1_800_000_000_000;
const H = 3_600_000;
const D = 24 * H;
const LISTED = ['IR', 'RU', 'CN'];
const ON = { ...MEMBER_COUNTRY_DEFAULTS, detect: true };
const guessed = (country: string, ageMs: number, firstAgeMs = ageMs): CountryFields => ({
  regionSeenCountry: country,
  regionSeenAt: NOW - ageMs,
  regionSeenFirstAt: NOW - firstAgeMs,
});
const next = (
  sub: CountryFields,
  reading: string | null,
  o: { ownExit?: boolean; family?: MemberFamily; cfg?: typeof ON } = {},
) =>
  nextGuess({
    family: o.family ?? 'freedom',
    sub,
    cfg: o.cfg ?? ON,
    listed: LISTED,
    now: NOW,
    reading,
    ownExit: o.ownExit ?? false,
  });

describe('memberCountryConfig', () => {
  test('defaults, bounds and the ranges list', () => {
    expect(memberCountryConfig({})).toEqual(MEMBER_COUNTRY_DEFAULTS);
    expect(
      memberCountryConfig({
        'delivery.country.detect': true,
        'delivery.country.stickyDays': 500,
        'delivery.country.refreshHours': 2,
        'delivery.country.ownExitRanges': ['192.0.2.0/24', 7],
      }),
    ).toEqual({
      detect: true,
      stickyDays: 30,
      refreshHours: 2,
      ownExitRanges: ['192.0.2.0/24'],
      steer: false,
      latency: false,
    });
    expect(memberCountryConfig({ 'delivery.country.detect': 'true' }).detect).toBe(false);
    expect(memberCountryConfig({ 'delivery.country.steer': true }).steer).toBe(true);
    expect(memberCountryConfig({ 'delivery.country.latency': true }).latency).toBe(true);
  });
});

describe('steeringCountry', () => {
  const at = (country: string | null, source: 'override' | 'inferred' | 'none') => ({
    where: { country, curated: ['IR'] },
    source,
  });
  test('only a STORED country orders edges, and only with steering on', () => {
    expect(steeringCountry({ steer: true }, at('IR', 'override'))).toBe('IR');
    expect(steeringCountry({ steer: false }, at('IR', 'override'))).toBeNull();
    // A transient CDN reading never orders anything.
    expect(steeringCountry({ steer: true }, at('IR', 'inferred'))).toBeNull();
    // "Somewhere else" (stored, no country) and nothing at all.
    expect(steeringCountry({ steer: true }, at(null, 'override'))).toBeNull();
    expect(steeringCountry({ steer: true }, at(null, 'none'))).toBeNull();
  });
});

describe('the stored country', () => {
  test('the choice wins; ZZ is no country; an unlisted choice does not count', () => {
    expect(storedCountry({ sniRegion: 'RU', ...guessed('IR', H) }, ON, LISTED, NOW)).toBe('RU');
    expect(storedCountry({ sniRegion: 'ZZ', ...guessed('IR', H) }, ON, LISTED, NOW)).toBeNull();
    expect(storedCountry({ sniRegion: 'DE', ...guessed('IR', H) }, ON, LISTED, NOW)).toBe('IR');
  });

  test('a guess counts only with detection on, listed, and within the sticky window', () => {
    expect(storedCountry(guessed('IR', 29 * D), ON, LISTED, NOW)).toBe('IR');
    expect(storedCountry(guessed('IR', 31 * D), ON, LISTED, NOW)).toBeNull();
    expect(storedCountry(guessed('IR', H), MEMBER_COUNTRY_DEFAULTS, LISTED, NOW)).toBeNull();
    expect(storedCountry(guessed('TR', H), ON, LISTED, NOW)).toBeNull();
    expect(liveGuess(guessed('IR', H, 5 * D), ON, LISTED, NOW)).toEqual({
      country: 'IR',
      firstAt: NOW - 5 * D,
      at: NOW - H,
    });
  });
});

describe('nextGuess', () => {
  test('nothing for a key that is not freedom-family, or with detection off', () => {
    for (const family of ['privacy', 'none'] as const)
      expect(next({}, 'IR', { family })).toEqual({ kind: 'none' });
    expect(next({}, 'IR', { cfg: MEMBER_COUNTRY_DEFAULTS })).toEqual({ kind: 'none' });
  });

  test("the member's choice stops detection, ZZ included", () => {
    expect(next({ sniRegion: 'RU' }, 'IR')).toEqual({ kind: 'none' });
    expect(next({ sniRegion: 'ZZ' }, 'IR')).toEqual({ kind: 'none' });
  });

  test('a listed reading sets or replaces the guess; the same one refreshes when due', () => {
    expect(next({}, 'ir')).toEqual({ kind: 'set', country: 'IR' });
    expect(next(guessed('IR', H), 'RU')).toEqual({ kind: 'set', country: 'RU' });
    expect(next(guessed('IR', H), 'IR')).toEqual({ kind: 'none' });
    expect(next(guessed('IR', 7 * H), 'IR')).toEqual({ kind: 'refresh' });
  });

  test('anything else leaves the guess (sticky), and clears one that already lapsed', () => {
    for (const reading of ['DE', null, 'XX'])
      expect(next(guessed('IR', 10 * D), reading)).toEqual({ kind: 'none' });
    expect(next(guessed('IR', 31 * D), 'DE')).toEqual({ kind: 'clear' });
    expect(next({}, 'DE')).toEqual({ kind: 'none' });
  });

  test("a reading from one of FCP's own exits never sets or changes it, only keeps it alive", () => {
    expect(next({}, 'TR', { ownExit: true })).toEqual({ kind: 'none' });
    expect(next({}, 'IR', { ownExit: true })).toEqual({ kind: 'none' });
    expect(next(guessed('IR', H), 'RU', { ownExit: true })).toEqual({ kind: 'none' });
    expect(next(guessed('IR', 7 * H), 'RU', { ownExit: true })).toEqual({ kind: 'refresh' });
  });
});

describe('memberWhere', () => {
  const where = (
    sub: CountryFields,
    reading: string | null,
    family: MemberFamily = 'freedom',
    cfg = ON,
  ) => memberWhere({ family, sub, cfg, listed: LISTED, now: NOW, reading });

  test('a key that is not freedom-family gets no country, whatever is stored or read', () => {
    expect(where({ sniRegion: 'IR' }, 'IR', 'privacy')).toMatchObject({
      where: { country: null },
      source: 'none',
    });
    expect(where({}, 'IR', 'none', MEMBER_COUNTRY_DEFAULTS).source).toBe('none');
  });

  test('a stored country (choice, ZZ or guess) is the cacheable override', () => {
    expect(where({ sniRegion: 'RU' }, 'IR')).toMatchObject({
      where: { country: 'RU' },
      source: 'override',
    });
    expect(where({ sniRegion: 'ZZ' }, 'IR')).toMatchObject({
      where: { country: null },
      source: 'override',
    });
    expect(where(guessed('IR', H), 'DE')).toMatchObject({
      where: { country: 'IR' },
      source: 'override',
    });
  });

  test('detection on with nothing stored: no country (the reading is never used transiently)', () => {
    expect(where({}, 'IR').source).toBe('none');
  });

  test('detection off: the transient reading, as before', () => {
    expect(where({}, 'IR', 'freedom', MEMBER_COUNTRY_DEFAULTS)).toMatchObject({
      where: { country: 'IR' },
      source: 'inferred',
    });
  });
});

describe('suggestionCountry', () => {
  test('a stored answer stands, "Somewhere else" included; the request only when nothing is stored', () => {
    expect(suggestionCountry({ effective: null, source: 'choice' }, 'IR')).toBeNull();
    expect(suggestionCountry({ effective: 'RU', source: 'guess' }, 'IR')).toBe('RU');
    expect(suggestionCountry({ effective: null, source: 'none' }, 'IR')).toBe('IR');
  });
});

describe('memberCountryView', () => {
  test('says what is used and where it came from', () => {
    expect(memberCountryView('privacy', { sniRegion: 'IR' }, ON, LISTED, NOW)).toMatchObject({
      applies: false,
      effective: null,
    });
    expect(memberCountryView('freedom', guessed('IR', H, D), ON, LISTED, NOW)).toEqual({
      applies: true,
      choice: null,
      guess: { country: 'IR', firstAt: NOW - D, lastAt: NOW - H },
      effective: 'IR',
      source: 'guess',
    });
    expect(memberCountryView('freedom', { sniRegion: 'ZZ' }, ON, LISTED, NOW)).toMatchObject({
      choice: 'ZZ',
      effective: null,
      source: 'choice',
    });
  });
});

describe('wide guesses (latency ordering on: any real country, a day before another takes over)', () => {
  const WIDE = { ...ON, steer: true, latency: true };
  const pending = (sub: CountryFields, country: string, ageMs: number): CountryFields => ({
    ...sub,
    regionNextCountry: country,
    regionNextAt: NOW - ageMs,
  });

  test('only with detection, steering and latency ordering all on', () => {
    expect(wideGuesses(WIDE)).toBe(true);
    expect(wideGuesses({ ...WIDE, steer: false })).toBe(false);
    expect(wideGuesses({ ...WIDE, detect: false })).toBe(false);
    expect(wideGuesses({ ...WIDE, latency: false })).toBe(false);
  });

  test('the first guess is any real country, at once; CDN codes are never one', () => {
    expect(next({}, 'de', { cfg: WIDE })).toEqual({ kind: 'set', country: 'DE' });
    expect(next({}, 'US', { cfg: WIDE })).toEqual({ kind: 'set', country: 'US' });
    for (const reading of ['XX', 'T1', 'ZZ', null])
      expect(next({}, reading, { cfg: WIDE })).toEqual({ kind: 'none' });
  });

  test('another country is pending first, and replaces the guess only a day after it was first seen', () => {
    const ir = guessed('IR', H, 30 * D);
    expect(next(ir, 'DE', { cfg: WIDE })).toEqual({ kind: 'next', country: 'DE' });
    expect(next(pending(ir, 'DE', 23 * H), 'DE', { cfg: WIDE })).toEqual({ kind: 'none' });
    expect(next(pending(ir, 'DE', D), 'DE', { cfg: WIDE })).toEqual({ kind: 'set', country: 'DE' });
    // A third country starts its own day.
    expect(next(pending(ir, 'DE', 2 * D), 'FR', { cfg: WIDE })).toEqual({
      kind: 'next',
      country: 'FR',
    });
    // Listed or not, the same rule: Iran to Russia waits a day too.
    expect(next(ir, 'RU', { cfg: WIDE })).toEqual({ kind: 'next', country: 'RU' });
  });

  test('a reading of the guess itself drops a pending country; own exits never touch it', () => {
    const ir = pending(guessed('IR', H), 'DE', 5 * H);
    expect(next(ir, 'IR', { cfg: WIDE })).toEqual({ kind: 'refresh', dropNext: true });
    expect(next(ir, 'DE', { cfg: WIDE, ownExit: true })).toEqual({ kind: 'none' });
    expect(
      next(pending(guessed('IR', 7 * H), 'DE', 2 * D), 'DE', { cfg: WIDE, ownExit: true }),
    ).toEqual({
      kind: 'refresh',
    });
  });

  test('an Iranian visiting Germany flips after a day, and back a day after returning', () => {
    let sub: CountryFields = guessed('IR', H, 60 * D);
    const step = (reading: string, at: number) => {
      const u = nextGuess({
        family: 'freedom',
        sub,
        cfg: WIDE,
        listed: LISTED,
        now: at,
        reading,
        ownExit: false,
      });
      if (u.kind === 'set')
        sub = { regionSeenCountry: u.country, regionSeenFirstAt: at, regionSeenAt: at };
      if (u.kind === 'next') sub = { ...sub, regionNextCountry: u.country, regionNextAt: at };
      if (u.kind === 'refresh')
        sub = {
          ...sub,
          regionSeenAt: at,
          ...(u.dropNext ? { regionNextCountry: null, regionNextAt: null } : {}),
        };
      return storedCountry(sub, WIDE, LISTED, at);
    };
    const t0 = NOW;
    expect(step('DE', t0)).toBe('IR');
    expect(step('DE', t0 + 12 * H)).toBe('IR');
    expect(step('DE', t0 + D)).toBe('DE');
    // Back home: still Germany for a day, then Iran again.
    expect(step('IR', t0 + 10 * D)).toBe('DE');
    expect(step('IR', t0 + 10 * D + 20 * H)).toBe('DE');
    expect(step('IR', t0 + 11 * D)).toBe('IR');
  });

  test('a single fetch through a foreign VPN flips nothing', () => {
    let sub: CountryFields = guessed('IR', H, 60 * D);
    const u1 = next(sub, 'DE', { cfg: WIDE });
    expect(u1.kind).toBe('next');
    sub = { ...sub, regionNextCountry: 'DE', regionNextAt: NOW };
    // The next direct fetch is from Iran again: the pending country goes.
    expect(next(sub, 'IR', { cfg: WIDE })).toEqual({ kind: 'refresh', dropNext: true });
  });

  test("the member's own choice still wins over any guess", () => {
    expect(next({ sniRegion: 'IR' }, 'DE', { cfg: WIDE })).toEqual({ kind: 'none' });
    expect(storedCountry({ sniRegion: 'IR', ...guessed('DE', H) }, WIDE, LISTED, NOW)).toBe('IR');
    expect(storedCountry({ sniRegion: 'ZZ', ...guessed('DE', H) }, WIDE, LISTED, NOW)).toBeNull();
  });

  test('a guess off the list counts only while wide, and only where an origin covers the place', () => {
    const de = guessed('DE', H);
    expect(liveGuess(de, WIDE, LISTED, NOW)?.country).toBe('DE');
    expect(liveGuess(de, ON, LISTED, NOW)).toBeNull();
    const at = (covered?: boolean) =>
      memberWhere({
        family: 'freedom',
        sub: de,
        cfg: WIDE,
        listed: LISTED,
        now: NOW,
        reading: null,
        covered,
      });
    expect(at()).toMatchObject({ where: { country: 'DE' }, source: 'override' });
    expect(at(false).source).toBe('none');
    expect(steeringCountry(WIDE, at())).toBe('DE');
  });

  test('outside wide mode nothing changes: a listed reading replaces at once, others leave it', () => {
    expect(next(guessed('IR', H), 'RU')).toEqual({ kind: 'set', country: 'RU' });
    expect(next(pending(guessed('IR', H), 'RU', 2 * D), 'IR')).toEqual({ kind: 'none' });
    expect(next(guessed('IR', H), 'DE')).toEqual({ kind: 'none' });
  });
});
