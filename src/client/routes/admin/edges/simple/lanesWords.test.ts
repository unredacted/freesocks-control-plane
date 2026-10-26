import { describe, expect, test } from 'vitest';
import {
  LANES_CARD,
  LANES_DIALOG,
  LANES_OFF,
  laneLine,
  lanesInputProblem,
  openBudgetLine,
} from './lanesWords';

const row = (o: Partial<Parameters<typeof laneLine>[0]> = {}) => ({
  listenerId: 'l',
  listenerKey: 'a',
  open: 1,
  trusted: 2,
  openExcess: 0,
  trustedDeficit: 0,
  openDeficit: 0,
  ...o,
});

describe('lanes words', () => {
  test('one line per transport', () => {
    expect(laneLine(row(), { open: 1, trusted: 2 })).toBe('2 of 2 trusted, 1 of 1 open.');
    expect(
      laneLine(row({ open: 3, trusted: 0, openExcess: 2, trustedDeficit: 2 }), {
        open: 1,
        trusted: 2,
      }),
    ).toBe('0 of 2 trusted, 3 of 1 open, 2 old addresses leave once the trusted ones are in.');
    expect(laneLine(row({ open: 2, openExcess: 1 }), { open: 1, trusted: 2 })).toBe(
      '2 of 2 trusted, 2 of 1 open, 1 old address is leaving.',
    );
    expect(openBudgetLine({ openReplacesToday: 1, openReplacesPerDay: 1 })).toBe(
      'Open addresses replaced today: 1 of 1.',
    );
  });

  test('the numbers are checked as the server checks them', () => {
    expect(lanesInputProblem(1, 4)).toBeNull();
    expect(lanesInputProblem(0, 1)).toBeNull();
    expect(lanesInputProblem(-1, 4)).toMatch(/Open/);
    expect(lanesInputProblem(1, 0)).toMatch(/Trusted/);
    expect(lanesInputProblem(1, 33)).toMatch(/Trusted/);
    expect(lanesInputProblem(1.5, 2)).toMatch(/Open/);
  });

  test('no em-dashes in the copy', () => {
    const all = [
      ...Object.values(LANES_CARD).map((v) => (typeof v === 'function' ? v(14) : v)),
      ...Object.values(LANES_DIALOG),
      ...Object.values(LANES_OFF),
    ];
    for (const s of all) expect(s).not.toMatch(/—/);
  });
});
