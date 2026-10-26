import { describe, expect, it } from 'vitest';
import { answerTargets, coverageOf, MAX_ANSWER_TARGETS, newestAnswers } from './coverage';

describe('which addresses a view reads answers for', () => {
  it('probed origins and published addresses first, then the rest, bounded', () => {
    const targets = [
      { key: 'edge:spare1', first: false },
      { key: 'edge:pub1', first: true },
      { key: 'relay:o1', first: true },
      { key: 'edge:spare2', first: false },
    ];
    expect(answerTargets(targets)).toEqual(['edge:pub1', 'relay:o1', 'edge:spare1', 'edge:spare2']);
    expect(answerTargets(targets, 3)).toEqual(['edge:pub1', 'relay:o1', 'edge:spare1']);
    // A fleet far past the bound still costs at most MAX_ANSWER_TARGETS index ranges.
    const many = Array.from({ length: 1000 }, (_, i) => ({ key: `edge:${i}`, first: i % 2 === 0 }));
    const picked = answerTargets(many);
    expect(picked).toHaveLength(MAX_ANSWER_TARGETS);
    expect(picked.every((k) => Number(k.slice(5)) % 2 === 0)).toBe(true);
  });
});

const MIN = 60_000;
const NOW = 1_000 * MIN;
const WINDOW = 60 * MIN;

describe('probe coverage of a country', () => {
  const answers = newestAnswers([
    // Two addresses: the newest answer per (country, source) wins.
    { country: 'RU', source: 'checkhost', updatedAt: NOW - 20 * MIN },
    { country: 'RU', source: 'checkhost', updatedAt: NOW - 5 * MIN },
    { country: 'RU', source: 'globalping', updatedAt: NOW - 3 * 60 * MIN },
    { country: 'CN', source: 'globalping', updatedAt: NOW - 90 * MIN },
    // FCP's own host is never a country's answer.
    { country: 'XX', source: 'internal', updatedAt: NOW },
  ]);
  const opts = { asked: true, windowMs: WINDOW, now: NOW };

  it("tells each source's newest answer from there, and whether it still counts", () => {
    expect(coverageOf(answers, 'RU', ['globalping', 'checkhost', 'internal'], opts)).toEqual({
      asked: true,
      windowMs: WINDOW,
      sources: [
        { source: 'globalping', lastAt: NOW - 180 * MIN, fresh: false },
        { source: 'checkhost', lastAt: NOW - 5 * MIN, fresh: true },
      ],
    });
  });

  it('a source that never answered from there has no time; one switched off is not listed', () => {
    expect(coverageOf(answers, 'CN', ['checkhost'], opts).sources).toEqual([
      { source: 'checkhost', lastAt: null, fresh: false },
    ]);
    expect(coverageOf(answers, 'BY', ['globalping', 'checkhost'], opts).sources).toEqual([
      { source: 'globalping', lastAt: null, fresh: false },
      { source: 'checkhost', lastAt: null, fresh: false },
    ]);
  });

  it('an answer exactly at the window edge still counts', () => {
    const a = newestAnswers([{ country: 'IR', source: 'globalping', updatedAt: NOW - WINDOW }]);
    expect(coverageOf(a, 'IR', ['globalping'], opts).sources[0]!.fresh).toBe(true);
  });

  it('a country the probes do not ask says so', () => {
    expect(coverageOf(answers, 'MM', ['globalping'], { ...opts, asked: false }).asked).toBe(false);
  });
});
