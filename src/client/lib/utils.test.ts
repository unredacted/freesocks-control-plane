import { afterEach, describe, expect, test, vi } from 'vitest';
import { formatBytes, daysUntil, copyText } from './utils';

const DAY = 86_400_000;

describe('formatBytes', () => {
  test('non-positive + non-finite → "0 B" (the over-quota "NaN undefined" bug)', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(-1)).toBe('0 B');
    expect(formatBytes(-1024 * 1024)).toBe('0 B'); // limit - used gone negative
    expect(formatBytes(NaN)).toBe('0 B');
    expect(formatBytes(Infinity)).toBe('0 B');
  });

  test('scales + rounds by unit', () => {
    expect(formatBytes(500)).toBe('500 B');
    expect(formatBytes(1023)).toBe('1023 B'); // boundary: still bytes
    expect(formatBytes(1024)).toBe('1 KB'); // boundary: rolls to KB
    expect(formatBytes(1536)).toBe('1.5 KB');
    expect(formatBytes(1024 * 1024)).toBe('1 MB');
    expect(formatBytes(5 * 1024 * 1024 * 1024)).toBe('5 GB');
  });

  test('clamps the unit index — a petabyte-scale value never renders "undefined"', () => {
    const out = formatBytes(1024 ** 5); // beyond TB
    expect(out).toContain('TB');
    expect(out).not.toContain('undefined');
    expect(out).not.toContain('NaN');
  });
});

describe('daysUntil', () => {
  test('absent / unparseable → null', () => {
    expect(daysUntil(null)).toBeNull();
    expect(daysUntil(undefined)).toBeNull();
    expect(daysUntil('not-a-date')).toBeNull();
  });

  test('future + past, across input types (rounded up)', () => {
    expect(daysUntil(Date.now() + 5 * DAY)).toBe(5); // epoch ms
    expect(daysUntil(new Date(Date.now() + 3 * DAY))).toBe(3); // Date
    expect(daysUntil(Date.now() - 5 * DAY)).toBe(-5); // past
  });
});

describe('copyText', () => {
  afterEach(() => vi.unstubAllGlobals());

  test('returns false (no throw) when navigator.clipboard is unavailable', async () => {
    vi.stubGlobal('navigator', {}); // insecure context / old browser
    await expect(copyText('x')).resolves.toBe(false);
  });

  test('returns false when the platform navigator is absent entirely', async () => {
    vi.stubGlobal('navigator', undefined);
    await expect(copyText('x')).resolves.toBe(false);
  });

  test('writes + returns true when clipboard is present', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('navigator', { clipboard: { writeText } });
    await expect(copyText('hello')).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledWith('hello');
  });

  test('returns false (no throw) when writeText rejects', async () => {
    vi.stubGlobal('navigator', {
      clipboard: { writeText: vi.fn().mockRejectedValue(new Error('denied')) },
    });
    await expect(copyText('x')).resolves.toBe(false);
  });
});
