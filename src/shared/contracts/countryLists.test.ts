import { describe, expect, test } from 'vitest';
import { splitUploadParts, UPLOAD_PART_BYTES } from './countryLists';

const size = (s: string) => new TextEncoder().encode(JSON.stringify(s)).length;

describe('splitUploadParts', () => {
  test('parts join back to the text and each fits', () => {
    const text = Array.from(
      { length: 5_000 },
      (_, i) => `n${i}.example.com # ${'é'.repeat(i % 7)}`,
    ).join('\n');
    const parts = splitUploadParts(text);
    expect(parts.length).toBeGreaterThan(1);
    expect(parts.join('')).toBe(text);
    for (const p of parts) expect(size(p)).toBeLessThanOrEqual(UPLOAD_PART_BYTES);
  });

  test('cuts at line ends', () => {
    expect(splitUploadParts('aaaa\nbbbb\ncccc', 11)).toEqual(['aaaa\n', 'bbbb\n', 'cccc']);
  });

  test('a line longer than a part is cut where it must', () => {
    const parts = splitUploadParts('x'.repeat(25), 12);
    expect(parts.join('')).toBe('x'.repeat(25));
    for (const p of parts) expect(size(p)).toBeLessThanOrEqual(12);
  });

  test('nothing to send is no parts', () => {
    expect(splitUploadParts('')).toEqual([]);
  });
});
