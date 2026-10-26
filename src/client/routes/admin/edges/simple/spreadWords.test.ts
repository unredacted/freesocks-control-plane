import { describe, expect, test } from 'vitest';
import { SPREAD_CARD, SPREAD_CONFIRM, spreadMovesWords } from './spreadWords';

const view = (sampled: number, moved: number) => ({
  relaySlug: 'n',
  edgePick: null,
  published: 4,
  switchTo: 'hrw1' as const,
  sampled,
  moved,
});

describe('spreadMovesWords', () => {
  test('a share of the members', () => {
    expect(spreadMovesWords(view(600, 450))).toBe(
      "About 75% of this node's members get at least one different address.",
    );
  });
  test('loading, nobody handed anything, nobody moving', () => {
    expect(spreadMovesWords(null)).toBeNull();
    expect(spreadMovesWords(view(0, 0))).toMatch(/nobody moves/);
    expect(spreadMovesWords(view(600, 1))).toBe('Hardly any member gets a different address.');
  });
  test('no em-dashes in the copy', () => {
    for (const s of [...Object.values(SPREAD_CARD), ...Object.values(SPREAD_CONFIRM)])
      expect(s).not.toMatch(/—/);
  });
});
