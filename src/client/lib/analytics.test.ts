/**
 * The pageview beacon's security-relevant guards, pure and DOM-free (the suite
 * runs under edge-runtime): the /admin exclusion + dedupe (shouldTrack), the
 * query/hash strip, the referrer origin-reduction, and the screen bucketing.
 * The wire shape + server-side allowlist are covered in convex/lib/umami.test.ts
 * and convex/http.test.ts.
 */
import { describe, expect, test } from 'vitest';
import { originOnly, screenBucket, shouldTrack, stripQueryHash } from './analytics';

describe('shouldTrack', () => {
  test('never reports admin navigation', () => {
    expect(shouldTrack('/admin', '')).toBe(false);
    expect(shouldTrack('/admin/settings', '')).toBe(false);
    expect(shouldTrack('/admin/connection-modes', '/account')).toBe(false);
  });

  test('dedupes repeats of the same path (config refetch re-runs the effect)', () => {
    expect(shouldTrack('/account', '/account')).toBe(false);
    expect(shouldTrack('/account', '/')).toBe(true);
  });

  test('member routes track, including A→B→A oscillation', () => {
    expect(shouldTrack('/', '')).toBe(true);
    expect(shouldTrack('/get-account', '/')).toBe(true);
    expect(shouldTrack('/get-account', '/account')).toBe(true);
  });
});

describe('stripQueryHash', () => {
  test('drops query strings and fragments (never leak ?ref= codes)', () => {
    expect(stripQueryHash('/get-account?ref=FSR-SECRET-CODE')).toBe('/get-account');
    expect(stripQueryHash('/account?tab=usage#top')).toBe('/account');
    expect(stripQueryHash('/status#loc-mci')).toBe('/status');
    expect(stripQueryHash('/')).toBe('/');
  });
});

describe('originOnly', () => {
  test('external URLs reduce to origin', () => {
    expect(originOnly('https://forum.example/private-thread?p=3')).toBe('https://forum.example');
    expect(originOnly('http://a.example/x')).toBe('http://a.example');
  });

  test('empty / non-http / garbage → empty', () => {
    expect(originOnly('')).toBe('');
    expect(originOnly('javascript:alert(1)')).toBe('');
    expect(originOnly('not a url')).toBe('');
  });
});

describe('screenBucket', () => {
  test('three coarse classes only', () => {
    expect(screenBucket(390)).toBe('480x854');
    expect(screenBucket(767)).toBe('480x854');
    expect(screenBucket(768)).toBe('834x1112');
    expect(screenBucket(1279)).toBe('834x1112');
    expect(screenBucket(1280)).toBe('1920x1080');
    expect(screenBucket(3840)).toBe('1920x1080');
  });

  test('junk widths → empty', () => {
    expect(screenBucket(0)).toBe('');
    expect(screenBucket(-1)).toBe('');
    expect(screenBucket(NaN)).toBe('');
  });
});
