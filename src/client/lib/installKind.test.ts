import { describe, expect, test } from 'vitest';
import { installKind } from './installKind';

describe('installKind', () => {
  test('classifies store / repo / download hosts', () => {
    expect(installKind('https://play.google.com/store/apps/details?id=com.example')).toBe('play');
    expect(installKind('https://apps.apple.com/app/shadowrocket/id932747118')).toBe('appStore');
    expect(installKind('https://itunes.apple.com/app/id932747118')).toBe('appStore');
    expect(installKind('https://github.com/2dust/v2rayNG/releases/latest')).toBe('github');
    expect(installKind('https://hiddify.com')).toBe('website');
    expect(installKind('https://www.play.google.com/store/apps/details?id=x')).toBe('play'); // www. stripped
  });

  test('a direct .apk download outranks its host', () => {
    expect(installKind('https://github.com/org/app/releases/download/v1/app.APK')).toBe('apk');
    expect(installKind('https://example.com/downloads/app.apk')).toBe('apk');
  });

  test('garbage input falls back to website', () => {
    expect(installKind('not a url')).toBe('website');
    expect(installKind('')).toBe('website');
  });
});
