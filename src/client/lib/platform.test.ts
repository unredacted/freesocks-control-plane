import { describe, expect, test } from 'vitest';
import { detectPlatform } from './platform';

describe('detectPlatform', () => {
  test('Android phones and tablets', () => {
    expect(
      detectPlatform(
        'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Mobile Safari/537.36',
      ),
    ).toBe('android');
  });

  test('iPhone and iPod', () => {
    expect(detectPlatform('Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X)')).toBe('ios');
    expect(detectPlatform('Mozilla/5.0 (iPod touch; CPU iPhone OS 15_0 like Mac OS X)')).toBe(
      'ios',
    );
  });

  test('iPad: explicit, and iPadOS 13+ Macintosh-with-touch', () => {
    expect(detectPlatform('Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X)')).toBe('ios');
    expect(detectPlatform('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', 5)).toBe('ios');
  });

  test('a real Mac (Macintosh, no touch) is desktop, not ios', () => {
    expect(detectPlatform('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', 0)).toBe('desktop');
    expect(detectPlatform('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', 1)).toBe('desktop');
  });

  test('Windows', () => {
    expect(detectPlatform('Mozilla/5.0 (Windows NT 10.0; Win64; x64)')).toBe('windows');
  });

  test('Linux and ChromeOS are desktop', () => {
    expect(detectPlatform('Mozilla/5.0 (X11; Linux x86_64)')).toBe('desktop');
    expect(detectPlatform('Mozilla/5.0 (X11; CrOS x86_64 14541.0.0)')).toBe('desktop');
  });

  test('unknown UA falls back to android (mobile-majority audience)', () => {
    expect(detectPlatform('')).toBe('android');
    expect(detectPlatform('SomeExoticBot/1.0')).toBe('android');
  });
});
