import { describe, expect, test } from 'vitest';
import type { Id } from '../../_generated/dataModel';
import { locationAssigned, pickUsable } from './assignedLocation';

const id = 'loc1' as Id<'edgeLocations'>;
const base = { _id: id, enabled: true, qualified: false, qualification: undefined };

describe('assigned locations (no person tests an address first)', () => {
  test("one of the node's picks is assigned, tested or not", () => {
    expect(locationAssigned(base, new Set(['loc1']))).toBe(true);
    expect(locationAssigned(base, new Set())).toBe(false);
  });

  test('trusted by an operator is assigned with or without a tested address there', () => {
    const byHand = { ...base, qualified: true, qualification: { by: 'admin' as const, at: 1 } };
    expect(locationAssigned(byHand, new Set())).toBe(true);
  });

  test('off, or untrusted by hand, is never assigned, even as a pick', () => {
    expect(locationAssigned({ ...base, enabled: false }, new Set(['loc1']))).toBe(false);
    expect(locationAssigned({ ...base, autoQualifyHold: true }, new Set(['loc1']))).toBe(false);
    expect(locationAssigned(null, new Set(['loc1']))).toBe(false);
  });

  test('upkeep may use an untested L4 pick only while the check is ready', () => {
    const loc = { enabled: true, qualified: false };
    expect(pickUsable(loc, { l4: true, clientCheckReady: true })).toBe(true);
    expect(pickUsable(loc, { l4: true, clientCheckReady: false })).toBe(false);
    expect(pickUsable(loc, { l4: false, clientCheckReady: true })).toBe(false);
    expect(
      pickUsable({ ...loc, autoQualifyHold: true }, { l4: true, clientCheckReady: true }),
    ).toBe(false);
    expect(pickUsable({ ...loc, qualified: true }, { l4: false, clientCheckReady: false })).toBe(
      true,
    );
  });
});
