import { describe, expect, it } from 'vitest';
import {
  countryGroupKey,
  effectiveState,
  gradeOf,
  liveCountryState,
  providerOfGroup,
} from './group';

const NOW = 1_000_000;

describe('countryGroupKey', () => {
  it('groups L4 edges by provider and location, never by account', () => {
    expect(countryGroupKey({ _id: 'e1', provider: 'gcore', placeKey: 'r-1', managed: true })).toBe(
      'gcore:r-1',
    );
  });
  it('puts CDN fronts in one global group per provider', () => {
    expect(countryGroupKey({ _id: 'e1', provider: 'fastly', layer: 'l7', managed: true })).toBe(
      'fastly:global',
    );
    expect(
      countryGroupKey({
        _id: 'e2',
        provider: 'fastly',
        managed: true,
        addresses: { hostname: 'front.example.org' },
      }),
    ).toBe('fastly:global');
  });
  it('gives an adopted edge, or one without a location, its own group', () => {
    expect(countryGroupKey({ _id: 'e1', managed: false })).toBe('adopted:e1');
    expect(countryGroupKey({ _id: 'e2', provider: 'gcore', managed: true })).toBe('edge:e2');
    expect(providerOfGroup('gcore:r-1')).toBe('gcore');
    expect(providerOfGroup('edge:e2')).toBeNull();
  });
});

describe('gradeOf', () => {
  it('is blocked with two blocked edges, at least half the decided, none proven', () => {
    expect(
      gradeOf([{ state: 'blocked' }, { state: 'blocked' }, { state: 'unknown' }], NOW).state,
    ).toBe('blocked');
  });
  it('one blocked edge is not a blocked group', () => {
    expect(gradeOf([{ state: 'blocked' }, { state: 'unknown' }], NOW).state).toBe('unknown');
  });
  it('is proven with a proven edge and none blocked, mixed with both', () => {
    expect(gradeOf([{ state: 'proven' }, { state: 'unknown' }], NOW).state).toBe('proven');
    expect(
      gradeOf([{ state: 'proven' }, { state: 'blocked' }, { state: 'blocked' }], NOW).state,
    ).toBe('mixed');
  });
  it('ignores expired states and carries the earliest expiry', () => {
    const g = gradeOf(
      [
        { state: 'blocked', until: NOW + 10 },
        { state: 'blocked', until: NOW + 5 },
        { state: 'blocked', until: NOW - 1 },
      ],
      NOW,
    );
    expect(g).toMatchObject({ state: 'blocked', until: NOW + 5 });
    expect(g.counts).toEqual({ edges: 3, proven: 0, blocked: 2 });
  });
});

describe('effectiveState', () => {
  const base = { edgeMark: null, groupMark: null, own: null, grade: null, now: NOW };
  it('puts marks first, the edge mark before the group mark', () => {
    expect(
      effectiveState({
        ...base,
        edgeMark: 'proven',
        groupMark: 'blocked',
        own: { state: 'blocked' },
      }),
    ).toEqual({ state: 'proven', from: 'mark' });
    expect(effectiveState({ ...base, groupMark: 'blocked', own: { state: 'proven' } })).toEqual({
      state: 'blocked',
      from: 'mark',
    });
  });
  it("uses the edge's own decided state before the group", () => {
    expect(
      effectiveState({
        ...base,
        own: { state: 'proven', until: NOW + 5 },
        grade: { state: 'blocked', until: NOW + 9 },
      }),
    ).toEqual({ state: 'proven', from: 'edge', until: NOW + 5 });
  });
  it("inherits only the group's blocked grade, never a proven one", () => {
    expect(effectiveState({ ...base, grade: { state: 'blocked', until: NOW + 9 } })).toEqual({
      state: 'blocked',
      from: 'group',
      until: NOW + 9,
    });
    expect(effectiveState({ ...base, grade: { state: 'proven' } })).toEqual({ state: 'unknown' });
  });
  it('reads anything past its expiry as unknown', () => {
    expect(effectiveState({ ...base, own: { state: 'blocked', until: NOW } })).toEqual({
      state: 'unknown',
    });
    expect(liveCountryState([{ until: NOW - 1 }, { until: NOW + 1 }, {}], NOW)).toHaveLength(2);
  });
});
