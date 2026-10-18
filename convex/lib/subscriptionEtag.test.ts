import { describe, expect, test } from 'vitest';
import {
  ifNoneMatchHits,
  parseIfNoneMatch,
  publicCacheControl,
  subscriptionEtag,
  withinValidity,
} from './subscriptionEtag';
import { drainWarningCodes } from '../../src/shared/contracts/edgeCodes';
import { drainWarnings, EDGE_DEFAULTS } from './edgeConfig';

const base = {
  content: 'vless://a@192.0.2.10:443#FreeSocks\n',
  contentType: 'text/plain',
  title: 'base64:RnJlZVNvY2tz',
  updateInterval: '1',
};

describe('the subscription tag', () => {
  test('is weak, fixed-length and names the content and the applied headers', async () => {
    const tag = await subscriptionEtag(base);
    expect(tag).toMatch(/^W\/"fs1-[A-Za-z0-9_-]{22}"$/);
    expect(await subscriptionEtag({ ...base })).toBe(tag);
    for (const change of [
      { content: base.content.replace('192.0.2.10', '192.0.2.11') },
      { contentType: 'application/json' },
      { title: 'base64:T3Vycw==' },
      { updateInterval: '2' },
      { updateInterval: null },
    ])
      expect(await subscriptionEtag({ ...base, ...change })).not.toBe(tag);
  });

  test('field boundaries cannot be shifted into one another', async () => {
    const a = await subscriptionEtag({ ...base, contentType: 'ab', title: 'c' });
    const b = await subscriptionEtag({ ...base, contentType: 'a', title: 'bc' });
    expect(a).not.toBe(b);
  });
});

describe('If-None-Match (RFC 9110 weak comparison)', () => {
  const tag = 'W/"fs1-AAAAAAAAAAAAAAAAAAAAAA"';

  test('matches the same opaque tag, with or without W/, alone or in a list', () => {
    expect(ifNoneMatchHits(tag, tag)).toBe(true);
    expect(ifNoneMatchHits('"fs1-AAAAAAAAAAAAAAAAAAAAAA"', tag)).toBe(true);
    expect(ifNoneMatchHits(`"other", ${tag}`, tag)).toBe(true);
    expect(ifNoneMatchHits(` , W/"x" ,${tag} , `, tag)).toBe(true);
    expect(ifNoneMatchHits('*', tag)).toBe(true);
  });

  test('a different tag is no match', () => {
    expect(ifNoneMatchHits('W/"fs1-BBBBBBBBBBBBBBBBBBBBBB"', tag)).toBe(false);
    expect(ifNoneMatchHits(null, tag)).toBe(false);
    expect(ifNoneMatchHits('', tag)).toBe(false);
  });

  test('anything malformed is ignored as a whole, never matched', () => {
    for (const bad of [
      // an arbitrary suffix after the opaque tag (a proxy rewrite FCP does not undo)
      'W/"fs1-AAAAAAAAAAAAAAAAAAAAAA"-gzip',
      'W/"fs1-AAAAAAAAAAAAAAAAAAAAAA-gzip"',
      // unquoted, unterminated, empty, W/ without quotes
      'fs1-AAAAAAAAAAAAAAAAAAAAAA',
      'W/"fs1-AAAAAAAAAAAAAAAAAAAAAA',
      '""x',
      'W/fs1-AAAAAAAAAAAAAAAAAAAAAA',
      // a list with a garbage entry next to the real tag
      `${tag}, garbage`,
      `garbage, ${tag}`,
      // a control character inside the quotes
      'W/"fs1-AAAA\u0001AAAAAAAAAAAAAAAAA"',
    ])
      expect(ifNoneMatchHits(bad, tag), bad).toBe(false);
    expect(parseIfNoneMatch('W/"fs1-x"-gzip')).toBeNull();
    expect(parseIfNoneMatch(`${tag}, garbage`)).toBeNull();
    expect(parseIfNoneMatch('W/fs1')).toBeNull();
    expect(parseIfNoneMatch('"a", W/"b"')).toEqual(['"a"', '"b"']);
    expect(parseIfNoneMatch(' , ')).toBeNull();
  });
});

describe('freshness of a public subscription response', () => {
  const now = 1_000_000_000;

  test('a body without L7 fronts keeps the 30 s cache', () => {
    expect(publicCacheControl(null, now)).toBe('public, max-age=30');
    expect(publicCacheControl(undefined, now)).toBe('public, max-age=30');
  });

  test('a body with fronts is never fresh past their proofs, and must be revalidated', () => {
    expect(publicCacheControl(now + 5_000, now)).toBe('public, max-age=5, must-revalidate');
    expect(publicCacheControl(now + 5_999, now)).toBe('public, max-age=5, must-revalidate');
    expect(publicCacheControl(now + 3_600_000, now)).toBe('public, max-age=30, must-revalidate');
    expect(publicCacheControl(now - 1, now)).toBe('public, max-age=0, must-revalidate');
    expect(publicCacheControl(now, now)).toBe('public, max-age=0, must-revalidate');
  });

  test('a cached body is servable only before its validity ends', () => {
    expect(withinValidity(null, now)).toBe(true);
    expect(withinValidity(now + 1, now)).toBe(true);
    expect(withinValidity(now, now)).toBe(false);
    expect(withinValidity(now - 1, now)).toBe(false);
  });
});

describe('drains against the refresh hint', () => {
  test('a replaced edge should outlive two intervals, a burned one an interval and 30 minutes', () => {
    expect(drainWarningCodes(EDGE_DEFAULTS)).toEqual([]);
    expect(
      drainWarningCodes({ drainMinutes: 119, burnedDrainMinutes: 90, updateIntervalHours: 1 }),
    ).toEqual(['drain_below_refresh']);
    expect(
      drainWarningCodes({ drainMinutes: 1440, burnedDrainMinutes: 89, updateIntervalHours: 1 }),
    ).toEqual(['burned_drain_below_refresh']);
    expect(
      drainWarningCodes({ drainMinutes: 1440, burnedDrainMinutes: 120, updateIntervalHours: 12 }),
    ).toEqual(['burned_drain_below_refresh']);
    expect(
      drainWarningCodes({ drainMinutes: 1439, burnedDrainMinutes: 750, updateIntervalHours: 12 }),
    ).toEqual(['drain_below_refresh']);
  });

  test("an origin's own drain is judged alone; the server speaks the edge.<code> form", () => {
    const cfg = { drainMinutes: 1440, burnedDrainMinutes: 0, updateIntervalHours: 1 };
    expect(drainWarningCodes(cfg, 60)).toEqual(['drain_below_refresh']);
    expect(drainWarningCodes(cfg, 120)).toEqual([]);
    expect(drainWarnings(cfg)).toEqual(['edge.burned_drain_below_refresh']);
  });

  test('the shipped defaults: burned drain twice the one-hour hint', () => {
    expect(EDGE_DEFAULTS.burnedDrainMinutes).toBe(120);
    expect(EDGE_DEFAULTS.updateIntervalHours).toBe(1);
  });
});
