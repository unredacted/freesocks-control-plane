/**
 * Countries -> Delivery: the card's own settings, read and written back
 * inside the server's bounds, and nothing else in its PATCH.
 */
import { describe, expect, it } from 'vitest';
import {
  DELIVERY_KEYS,
  clampWhole,
  deliveryChanged,
  deliveryDraft,
  deliveryPatch,
  parseExitRanges,
  STICKY_DAYS,
  withExitRow,
  withoutDeliveryKeys,
} from './delivery';

const STORED = {
  'delivery.country.detect': true,
  'delivery.country.ask': false,
  'delivery.country.steer': true,
  'delivery.country.latency': false,
  'delivery.country.stickyDays': 14,
  'delivery.country.refreshHours': 3,
  'delivery.country.ownExitRanges': ['192.0.2.0/24'],
  'delivery.country.exits': [{ country: 'AA', locations: ['loc-a'] }],
  'delivery.country.modes': [{ country: 'AA', modes: ['m'] }],
  'subscription.siteName': 'Svc',
};

describe('the working copy', () => {
  it('reads what is stored', () => {
    expect(deliveryDraft(STORED)).toEqual({
      detect: true,
      ask: false,
      steer: true,
      latency: false,
      stickyDays: 14,
      refreshHours: 3,
      ownExitRanges: ['192.0.2.0/24'],
      exits: [{ country: 'AA', locations: ['loc-a'] }],
    });
  });

  it('fills the defaults when nothing is stored', () => {
    const d = deliveryDraft(undefined);
    expect(d.stickyDays).toBe(30);
    expect(d.refreshHours).toBe(6);
    expect(d.ownExitRanges).toEqual([]);
    expect(d.exits).toEqual([]);
    expect(d.ask).toBe(false);
  });

  it('is unchanged until an edit, changed after one', () => {
    const d = deliveryDraft(STORED);
    expect(deliveryChanged(d, STORED)).toBe(false);
    expect(deliveryChanged({ ...d, ask: true }, STORED)).toBe(true);
  });
});

describe('the PATCH body', () => {
  it('holds exactly the card keys', () => {
    expect(Object.keys(deliveryPatch(deliveryDraft(STORED))).sort()).toEqual(
      [...DELIVERY_KEYS].sort(),
    );
  });

  it('keeps numbers inside the server bounds', () => {
    const p = deliveryPatch({ ...deliveryDraft(STORED), stickyDays: 400, refreshHours: -2 });
    expect(p['delivery.country.stickyDays']).toBe(90);
    expect(p['delivery.country.refreshHours']).toBe(1);
  });

  it('reads an empty or odd number as the default', () => {
    expect(clampWhole('', STICKY_DAYS)).toBe(30);
    expect(clampWhole('abc', STICKY_DAYS)).toBe(30);
    expect(clampWhole('7.6', STICKY_DAYS)).toBe(8);
  });
});

describe('exit ranges', () => {
  it('splits on any space, drops blanks, keeps at most 64', () => {
    expect(parseExitRanges(' 192.0.2.0/24\n\n198.51.100.0/24  ')).toEqual([
      '192.0.2.0/24',
      '198.51.100.0/24',
    ]);
    const many = Array.from({ length: 70 }, (_, i) => `10.0.${i}.0/24`).join('\n');
    expect(parseExitRanges(many)).toHaveLength(64);
  });
});

describe("one country's exit row", () => {
  const ROWS = [
    { country: 'AA', locations: ['a'] },
    { country: 'BB', locations: ['b', 'c'] },
  ];

  it('replaces the row in place', () => {
    expect(withExitRow(ROWS, 'AA', ['x', '', 'x', 'y'])).toEqual([
      { country: 'AA', locations: ['x', 'y'] },
      ROWS[1],
    ]);
  });

  it('adds a new country at the end and drops one left with none', () => {
    expect(withExitRow(ROWS, 'CC', ['z', '', ''])).toEqual([
      ...ROWS,
      { country: 'CC', locations: ['z'] },
    ]);
    expect(withExitRow(ROWS, 'BB', ['', '', ''])).toEqual([ROWS[0]]);
  });
});

describe('Admin -> Settings save', () => {
  it('leaves the card keys out and keeps everything else', () => {
    const out = withoutDeliveryKeys(STORED);
    for (const k of DELIVERY_KEYS) expect(out).not.toHaveProperty(k);
    expect(out['subscription.siteName']).toBe('Svc');
    expect(out['delivery.country.modes']).toEqual(STORED['delivery.country.modes']);
  });
});
