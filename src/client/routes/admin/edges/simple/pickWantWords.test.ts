/** A pick's address count in words (pure). */
import { describe, expect, it } from 'vitest';
import { wantLine, wantPreviewLines } from './pickWantWords';

const cost = {
  monthly: 15,
  currency: 'EUR',
  basis: 'list' as const,
  plusTraffic: false,
  listMonthly: 15,
  listCurrency: 'EUR',
};
const preview = (over: Partial<Parameters<typeof wantPreviewLines>[0]> = {}) => ({
  want: 2,
  carries: ['a'],
  adds: 1,
  fits: 1,
  each: cost,
  total: 3,
  tooLarge: false,
  ...over,
});

describe('a pick address count in words', () => {
  it('says the count, per transport when there are several', () => {
    expect(wantLine(null, ['a'])).toBe('Addresses here: at least one, of any transport.');
    expect(wantLine(2, ['a'], () => 'REALITY')).toBe('Addresses here: 2 (REALITY).');
    expect(wantLine(3, ['a', 'b'])).toBe('Addresses here: 3 of each transport (a, b).');
  });

  it('says what saving adds and costs, and what the cap allows', () => {
    const [adds] = wantPreviewLines(preview({ adds: 2, fits: 2 }));
    expect(adds).toMatch(/^Adds 2 more addresses in use here, about .*30.* a month more/);
    expect(wantPreviewLines(preview({ adds: 2, fits: 1 }))).toContain(
      "Only 1 of 2 fit under this account's monthly cap.",
    );
    expect(wantPreviewLines(preview({ adds: 2, fits: 0 }))[1]).toMatch(/None of them fits/);
    expect(wantPreviewLines(preview({ adds: 0, fits: 0 }))[0]).toMatch(/^No new address/);
    expect(wantPreviewLines(preview({ tooLarge: true, total: 70 }))).toEqual([
      'The node would then want 70 addresses in use, over the limit of 64. Lower the count.',
    ]);
    for (const line of wantPreviewLines(preview({ adds: 2, fits: 1 })))
      expect(line).not.toMatch(/—/);
  });
});
