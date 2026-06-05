import { describe, expect, test } from 'vitest';
import {
  accountIdPrefix,
  formatAccountId,
  generateAccountId,
  isValidAccountId,
  normalizeAccountId,
} from './accountId';

describe('generateAccountId', () => {
  test('produces exactly 16 decimal digits', () => {
    for (let i = 0; i < 50; i++) {
      expect(generateAccountId()).toMatch(/^\d{16}$/);
    }
  });

  test('is (essentially) non-repeating across calls', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 100; i++) seen.add(generateAccountId());
    // Collisions among 100 draws from 10^16 are astronomically unlikely.
    expect(seen.size).toBe(100);
  });
});

describe('normalizeAccountId', () => {
  test('strips spaces and hyphens', () => {
    expect(normalizeAccountId('1234 5678 9012 3456')).toBe('1234567890123456');
    expect(normalizeAccountId('1234-5678-9012-3456')).toBe('1234567890123456');
    expect(normalizeAccountId('  1234 - 5678 ')).toBe('12345678');
  });

  test('leaves a canonical number unchanged', () => {
    expect(normalizeAccountId('1234567890123456')).toBe('1234567890123456');
  });
});

describe('isValidAccountId', () => {
  test('accepts a canonical 16-digit string', () => {
    expect(isValidAccountId('1234567890123456')).toBe(true);
  });

  test('rejects wrong length or non-digits', () => {
    expect(isValidAccountId('123456789012345')).toBe(false); // 15
    expect(isValidAccountId('12345678901234567')).toBe(false); // 17
    expect(isValidAccountId('12345678901234ab')).toBe(false);
    expect(isValidAccountId('1234 5678 9012 3456')).toBe(false); // not normalized
    expect(isValidAccountId('')).toBe(false);
  });
});

describe('formatAccountId', () => {
  test('groups a canonical number into space-separated quads', () => {
    expect(formatAccountId('1234567890123456')).toBe('1234 5678 9012 3456');
  });
});

describe('accountIdPrefix', () => {
  test('returns the first 4 characters', () => {
    expect(accountIdPrefix('1234567890123456')).toBe('1234');
  });
});
