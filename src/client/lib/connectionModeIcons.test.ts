import { describe, expect, test } from 'vitest';
import { DEFAULT_MODE_ICON_ID, MODE_ICON_IDS, isModeIconId } from './connectionModeIconIds';
import { humanizeSlug } from './humanize';

describe('mode icon id registry (pure)', () => {
  test('the seeded family icons are registered; the default id is in the set', () => {
    expect(MODE_ICON_IDS).toContain('zap');
    expect(MODE_ICON_IDS).toContain('shield-check');
    expect(isModeIconId(DEFAULT_MODE_ICON_ID)).toBe(true);
  });

  test('isModeIconId rejects unknown / null / empty', () => {
    expect(isModeIconId('no-such-icon')).toBe(false);
    expect(isModeIconId(null)).toBe(false);
    expect(isModeIconId('')).toBe(false);
    for (const id of MODE_ICON_IDS) expect(isModeIconId(id)).toBe(true);
  });
});

describe('humanizeSlug (the raw-slug-never-renders backstop)', () => {
  test('title-cases hyphenated slugs', () => {
    expect(humanizeSlug('my-new-mode')).toBe('My New Mode');
    expect(humanizeSlug('x')).toBe('X');
    expect(humanizeSlug('a--b')).toBe('A B');
  });
});
