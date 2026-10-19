import { describe, expect, test } from 'vitest';
import type { EdgeCountriesResponse, EdgeCountryRow } from '../../../../../shared/contracts/edges';
import {
  CHECK_WAIT_MS,
  checkPending,
  edgeCountryLines,
  edgeHasCountryData,
  locationGrades,
  locationGroupKey,
  markConflict,
  newestRoundAt,
} from './countryChecks';

const NOW = Date.parse('2026-10-18T12:00:00Z');
const at = (msAgo: number) => new Date(NOW - msAgo).toISOString();

const row = (country: string, roundAt: string | null): EdgeCountryRow => ({
  country,
  combined: 'unknown',
  blockedSince: null,
  effective: null,
  address: {
    state: 'unknown',
    reason: null,
    decidedAt: null,
    until: null,
    blockedRounds: 0,
    repeatAt: null,
  },
  handshake: { state: 'none', reason: null, until: null, pathBatches: 0, lastBatchAt: null },
  lastRound: roundAt
    ? {
        roundId: 'r',
        at: roundAt,
        result: 'proven',
        reason: null,
        ok: 3,
        fail: 0,
        networks: 2,
        controlsOk: 2,
        v6Result: null,
      }
    : null,
});

const data: EdgeCountriesResponse = {
  enabled: true,
  countries: ['IR', 'RU', 'CN'],
  controls: ['DE', 'US'],
  groups: [
    {
      groupKey: 'prov-a:place-1',
      provider: 'prov-a',
      country: 'IR',
      state: 'blocked',
      counts: { edges: 2, proven: 0, blocked: 2 },
      until: null,
    },
  ],
  edges: [
    {
      edgeId: 'e1',
      relaySlug: 'node-a',
      groupKey: 'prov-a:place-1',
      provider: 'prov-a',
      status: 'active',
      publication: 'published',
      countries: [row('IR', at(60_000)), row('RU', at(3_600_000))],
    },
    {
      edgeId: 'e2',
      relaySlug: 'node-a',
      groupKey: 'prov-a:place-1',
      provider: 'prov-a',
      status: 'active',
      publication: 'unpublished',
      countries: [row('IR', at(120_000))],
    },
  ],
  marks: [
    { scope: 'edge', edgeId: 'e1', groupKey: null, country: 'RU', state: 'proven', at: at(1) },
    {
      scope: 'group',
      edgeId: null,
      groupKey: 'prov-a:place-1',
      country: 'IR',
      state: 'proven',
      at: at(1),
    },
  ],
  sources: [],
};

test('locationGroupKey keys a location the way the server keys its edges', () => {
  expect(locationGroupKey({ provider: 'prov-a', placeKey: 'place-1', layer: 'l4' })).toBe(
    'prov-a:place-1',
  );
  expect(locationGroupKey({ provider: 'cdn-b', placeKey: 'anycast', layer: 'l7' })).toBe(
    'cdn-b:global',
  );
  expect(locationGroupKey({ provider: 'prov-a', placeKey: null, layer: 'l4' })).toBeNull();
});

describe('edgeCountryLines', () => {
  test('one line per checked country, with its row and both marks', () => {
    const lines = edgeCountryLines(data, 'e1');
    expect(lines.map((l) => l.country)).toEqual(['IR', 'RU', 'CN']);
    expect(lines[0]!.row?.country).toBe('IR');
    expect(lines[0]!.groupMark?.state).toBe('proven');
    expect(lines[1]!.edgeMark?.state).toBe('proven');
    expect(lines[2]!.row).toBeNull();
  });
  test('an edge never checked still gets every country', () => {
    expect(edgeCountryLines(data, 'nope').map((l) => [l.country, l.row])).toEqual([
      ['IR', null],
      ['RU', null],
      ['CN', null],
    ]);
    expect(edgeCountryLines(undefined, 'e1')).toEqual([]);
  });
});

describe('locationGrades', () => {
  test('grade, newest round, edges checked, mark and conflict per country', () => {
    const cells = locationGrades(data, 'prov-a:place-1');
    expect(cells[0]).toMatchObject({
      country: 'IR',
      checkedAt: at(60_000),
      checkedEdges: 2,
      conflict: true,
    });
    expect(cells[0]!.grade?.state).toBe('blocked');
    expect(cells[1]).toMatchObject({
      country: 'RU',
      grade: null,
      checkedEdges: 1,
      conflict: false,
    });
    expect(cells[2]).toMatchObject({ country: 'CN', checkedAt: null, checkedEdges: 0 });
    expect(locationGrades(data, null)).toEqual([]);
  });
});

test('markConflict: a mark against decided or mixed checks', () => {
  expect(markConflict({ state: 'proven' }, 'blocked')).toBe(true);
  expect(markConflict({ state: 'blocked' }, 'proven')).toBe(true);
  expect(markConflict({ state: 'blocked' }, 'mixed')).toBe(true);
  expect(markConflict({ state: 'blocked' }, 'blocked')).toBe(false);
  expect(markConflict({ state: 'proven' }, 'unknown')).toBe(false);
  expect(markConflict(null, 'blocked')).toBe(false);
});

test('checkPending compares server rounds only, and gives up after the wait', () => {
  const edge = data.edges[0]!;
  const newest = newestRoundAt(edge);
  expect(newest).toBe(at(60_000));
  // Asked while that round was the newest: still out, whatever this tab's clock says.
  expect(checkPending({ at: NOW - 30_000, before: newest }, edge, NOW)).toBe(true);
  expect(checkPending({ at: NOW + 3_600_000, before: newest }, edge, NOW + 3_600_000)).toBe(true);
  // A round newer than it came back (even one stamped before this tab's request time).
  expect(checkPending({ at: NOW, before: at(120_000) }, edge, NOW)).toBe(false);
  // Nothing on record before: the first round is the answer.
  expect(checkPending({ at: NOW, before: null }, edge, NOW)).toBe(false);
  expect(checkPending({ at: NOW - 1000, before: null }, null, NOW)).toBe(true);
  expect(checkPending({ at: NOW - CHECK_WAIT_MS, before: newest }, edge, NOW)).toBe(false);
});

test('edgeHasCountryData: evidence or a mark of its own', () => {
  expect(edgeHasCountryData(data, 'e1')).toBe(true);
  expect(edgeHasCountryData({ ...data, edges: [] }, 'e1')).toBe(true);
  expect(edgeHasCountryData({ ...data, edges: [], marks: [] }, 'e1')).toBe(false);
  expect(edgeHasCountryData(null, 'e1')).toBe(false);
  expect(newestRoundAt(null)).toBeNull();
});
