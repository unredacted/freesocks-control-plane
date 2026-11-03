import { describe, expect, test } from 'vitest';
import { encodedBytes, splitUploadParts, UPLOAD_PART_BYTES } from './countryLists';

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

  test('counts encoded bytes exactly as JSON writes them', () => {
    for (const s of [
      '',
      'example.com\n',
      'quote " and \\ backslash',
      'tab\tcr\r\u0001\u007f',
      'пример.рф',
      '\u{1F600} emoji',
      'lone \ud800 surrogate',
    ])
      expect(encodedBytes(s)).toBe(size(s));
  });

  test('a long line splits in linear time', () => {
    const line = 'x'.repeat(2 * 1024 * 1024) + 'é'.repeat(1024 * 1024);
    const t0 = Date.now();
    const parts = splitUploadParts(line);
    expect(Date.now() - t0).toBeLessThan(5_000);
    expect(parts.join('')).toBe(line);
    for (const p of parts) expect(size(p)).toBeLessThanOrEqual(UPLOAD_PART_BYTES);
  });

  test('nothing to send is no parts', () => {
    expect(splitUploadParts('')).toEqual([]);
  });
});
