import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import {
  accountIdPrefix,
  formatAccountId,
  generateAccountId,
  hashAccountId,
  isValidAccountId,
  normalizeAccountId,
} from './accountId';

const CANONICAL = '12345678901234567890123456789012'; // 32 digits

describe('generateAccountId', () => {
  test('produces exactly 32 decimal digits', () => {
    for (let i = 0; i < 50; i++) {
      expect(generateAccountId()).toMatch(/^\d{32}$/);
    }
  });

  test('is (essentially) non-repeating across calls', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 100; i++) seen.add(generateAccountId());
    // Collisions among 100 draws from 10^32 are astronomically unlikely.
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
    expect(normalizeAccountId(CANONICAL)).toBe(CANONICAL);
  });
});

describe('isValidAccountId', () => {
  test('accepts a canonical 32-digit string', () => {
    expect(isValidAccountId(CANONICAL)).toBe(true);
  });

  test('rejects wrong length or non-digits', () => {
    expect(isValidAccountId('1234567890123456')).toBe(false); // 16 (old length)
    expect(isValidAccountId(CANONICAL.slice(0, 31))).toBe(false); // 31
    expect(isValidAccountId(CANONICAL + '3')).toBe(false); // 33
    expect(isValidAccountId(CANONICAL.slice(0, 30) + 'ab')).toBe(false); // non-digits
    expect(isValidAccountId(formatAccountId(CANONICAL))).toBe(false); // not normalized
    expect(isValidAccountId('')).toBe(false);
  });
});

describe('formatAccountId', () => {
  test('groups a canonical number into space-separated quads', () => {
    expect(formatAccountId(CANONICAL)).toBe('1234 5678 9012 3456 7890 1234 5678 9012');
  });
});

describe('accountIdPrefix', () => {
  test('returns the first 4 characters', () => {
    expect(accountIdPrefix(CANONICAL)).toBe('1234');
  });
});

describe('hashAccountId', () => {
  beforeEach(() => vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper'));
  afterEach(() => vi.unstubAllEnvs());

  test('is deterministic for the same input + pepper', async () => {
    expect(await hashAccountId(CANONICAL)).toBe(await hashAccountId(CANONICAL));
  });

  test('normalizes input (spaced form hashes the same as canonical)', async () => {
    expect(await hashAccountId(formatAccountId(CANONICAL))).toBe(await hashAccountId(CANONICAL));
  });

  test('depends on the pepper (different pepper → different hash)', async () => {
    const a = await hashAccountId(CANONICAL);
    vi.stubEnv('ACCOUNT_ID_PEPPER', 'a-different-pepper');
    const b = await hashAccountId(CANONICAL);
    expect(a).not.toBe(b);
  });

  test('fails closed when the pepper is missing', async () => {
    vi.unstubAllEnvs();
    await expect(hashAccountId(CANONICAL)).rejects.toThrow(/ACCOUNT_ID_PEPPER/);
  });
});
