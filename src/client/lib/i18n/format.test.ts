import { describe, expect, test, vi } from 'vitest';

// format.ts imports getLocale() from ./index.svelte, a $state runes module the
// plugin-less vitest config can't compile — mock it to a fixed locale so the
// date-guard logic is testable headless.
vi.mock('./index.svelte', () => ({ getLocale: () => 'en-US' }));

import { formatDate, formatDateTime } from './format';

describe('formatDate', () => {
  test('formats a valid ISO string / epoch number', () => {
    const iso = formatDate('2026-07-07T12:00:00Z');
    expect(iso).not.toBe('Invalid Date');
    expect(iso).toContain('2026');

    const epoch = formatDate(Date.UTC(2026, 6, 7, 12));
    expect(epoch).not.toBe('Invalid Date');
    expect(epoch).toContain('2026');
  });

  test('returns the raw value for unparseable input (no literal "Invalid Date")', () => {
    // The device firstSeen/lastSeen fields are deliberately lenient strings.
    expect(formatDate('not-a-date')).toBe('not-a-date');
    expect(formatDate('')).toBe('');
  });
});

describe('formatDateTime', () => {
  test('formats a valid date and guards garbage', () => {
    expect(formatDateTime('2026-07-07T12:00:00Z')).not.toBe('Invalid Date');
    expect(formatDateTime('nonsense')).toBe('nonsense');
  });
});
