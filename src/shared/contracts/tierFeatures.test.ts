import { describe, expect, test } from 'vitest';
import {
  MAX_TIER_FEATURES,
  defaultTierFeatures,
  resolveTierFeatures,
  validateTierFeatures,
} from './tierFeatures';

describe('tier features', () => {
  test('defaults: the free tier names the mirrors, others the membership extras', () => {
    expect(defaultTierFeatures(true).map((f) => f.preset)).toEqual(['mirrors']);
    expect(defaultTierFeatures(false).map((f) => f.preset)).toEqual([
      'fasterSpeeds',
      'alternateLocations',
      'mirrors',
      'supportsFree',
    ]);
    expect(resolveTierFeatures(undefined, false)).toEqual(defaultTierFeatures(false));
    expect(resolveTierFeatures([], false)).toEqual([]);
  });

  test('a valid list is cleaned: labels trimmed, a blank preset label means the translation', () => {
    expect(
      validateTierFeatures([
        { preset: 'fasterSpeeds', iconId: 'zap', label: '  ' },
        { preset: null, iconId: 'heart', label: ' Priority support ' },
      ]),
    ).toEqual({
      ok: true,
      features: [
        { preset: 'fasterSpeeds', iconId: 'zap', label: null },
        { preset: null, iconId: 'heart', label: 'Priority support' },
      ],
    });
  });

  test('refuses unknown icons and presets, empty custom lines, long text and long lists', () => {
    expect(validateTierFeatures('x').ok).toBe(false);
    expect(validateTierFeatures([{ preset: null, iconId: 'skull', label: 'x' }]).ok).toBe(false);
    expect(validateTierFeatures([{ preset: 'free-beer', iconId: 'zap', label: null }]).ok).toBe(
      false,
    );
    expect(validateTierFeatures([{ preset: null, iconId: 'zap', label: ' ' }]).ok).toBe(false);
    expect(validateTierFeatures([{ preset: null, iconId: 'zap', label: 'x'.repeat(81) }]).ok).toBe(
      false,
    );
    const many = Array.from({ length: MAX_TIER_FEATURES + 1 }, () => ({
      preset: 'mirrors',
      iconId: 'layers',
      label: null,
    }));
    expect(validateTierFeatures(many).ok).toBe(false);
  });
});
