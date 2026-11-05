import { describe, expect, test } from 'vitest';
import { exitRows, exitSentence, slotsOf, withSlot } from './countryExits';

describe('editing exit locations', () => {
  const rows = [
    { country: 'IR', locations: ['loc-a', 'loc-b'] },
    { country: 'RU', locations: ['loc-c'] },
  ];

  test('slots are padded and read back', () => {
    expect(slotsOf(rows, 'IR')).toEqual(['loc-a', 'loc-b', '']);
    expect(slotsOf(rows, 'CN')).toEqual(['', '', '']);
  });

  test('a slot set closes up in order, without repeats, in its place', () => {
    expect(withSlot(rows, 'IR', 2, 'loc-c')).toEqual([
      { country: 'IR', locations: ['loc-a', 'loc-b', 'loc-c'] },
      rows[1],
    ]);
    expect(withSlot(rows, 'IR', 0, '')).toEqual([{ country: 'IR', locations: ['loc-b'] }, rows[1]]);
    expect(withSlot(rows, 'IR', 1, 'loc-a')).toEqual([
      { country: 'IR', locations: ['loc-a'] },
      rows[1],
    ]);
  });

  test('a new country is added; one left with none is dropped', () => {
    expect(withSlot(rows, 'CN', 1, 'loc-a')).toEqual([
      ...rows,
      { country: 'CN', locations: ['loc-a'] },
    ]);
    expect(withSlot(rows, 'RU', 0, '')).toEqual([rows[0]]);
  });

  test('whatever the settings bag holds is read as rows or none', () => {
    expect(exitRows(undefined)).toEqual([]);
    expect(exitRows([{ country: 'IR', locations: ['loc-a', 3] }, 'x'])).toEqual([
      { country: 'IR', locations: ['loc-a'] },
    ]);
  });
});

describe('the country page sentence', () => {
  test('names the locations in order, or says where to set them', () => {
    expect(exitSentence(['Alpha'])).toContain('go to Alpha, the first');
    expect(exitSentence(['Alpha', 'Beta', 'Gamma'])).toContain('go to Alpha, Beta or Gamma');
    expect(exitSentence([])).toContain('least-loaded');
    for (const s of [exitSentence([]), exitSentence(['Alpha', 'Beta'])])
      expect(s).not.toContain(String.fromCharCode(0x2014));
  });
});
