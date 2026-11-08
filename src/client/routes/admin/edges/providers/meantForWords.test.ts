import { describe, expect, test } from 'vitest';
import { estimateLines, meantForLine } from './meantForWords';

const NAMES: Record<string, string> = { IR: 'Iran', RU: 'Russia' };
const nameOf = (c: string) => NAMES[c] ?? c;

describe('meant-for words', () => {
  test('the line under a location', () => {
    expect(meantForLine([], nameOf)).toBe('Set for no country in particular.');
    expect(meantForLine(['IR', 'RU'], nameOf)).toBe(
      'Set for Iran, Russia: members there get an address here first, unless it is blocked there.',
    );
  });

  test('what saving would move', () => {
    expect(estimateLines(undefined, nameOf)).toBeNull();
    expect(
      estimateLines({ valid: true, code: null, steering: true, countries: [] }, nameOf),
    ).toBeNull();
    expect(
      estimateLines({ valid: true, code: null, steering: false, countries: [] }, nameOf)![0],
    ).toMatch(/nothing moves until that is on/);
    expect(
      estimateLines(
        {
          valid: true,
          code: null,
          steering: true,
          countries: [
            {
              country: 'IR',
              nodes: [
                { relaySlug: 'node-a', label: null, sampled: 600, moved: 300 },
                { relaySlug: 'node-b', label: 'B', sampled: 0, moved: 0 },
              ],
            },
            { country: 'RU', nodes: [] },
          ],
        },
        nameOf,
      ),
    ).toEqual([
      'Iran: about 50% of members on node-a, about 0% of members on B get a different first address.',
      'Russia: no node has an address in use here yet.',
    ]);
    expect(
      estimateLines(
        { valid: false, code: 'meant_for_too_many', steering: true, countries: [] },
        nameOf,
      ),
    ).toEqual(['A location takes at most 8 countries.']);
  });

  test('no em-dash in any sentence', () => {
    const all = [
      meantForLine(['IR'], nameOf),
      ...(estimateLines({ valid: true, code: null, steering: false, countries: [] }, nameOf) ?? []),
    ];
    for (const s of all) expect(s).not.toContain('—');
  });
});
