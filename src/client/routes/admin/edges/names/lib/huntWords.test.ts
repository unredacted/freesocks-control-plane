/**
 * Find names wording (docs/edges.md "Finding names"): every state, source,
 * reading and sweep error has words, the copy carries no codes and no
 * em-dashes, and the filters split candidates the way the page promises.
 */
import { describe, expect, test } from 'vitest';
import {
  CT_STATE_WORDS,
  COUNTRY_READING_WORDS,
  HUNT_FILTERS,
  HUNT_FILTER_LABEL,
  HUNT_SOURCE_WORDS,
  SWEEP_ERROR_WORDS,
  candidateWords,
  countryWords,
  extraWords,
  huntSwitchLine,
  placeLine,
  sweepCostWords,
  familySlugFor,
  huntImportWords,
  matchesHuntFilter,
  nearWords,
  parsePlace,
  scoreWords,
  siteOoniWords,
  sweepWords,
} from './huntWords';
import {
  HUNT_SOURCES,
  HUNT_STATES,
  usableCandidate,
  type SniCandidateRow,
} from '../../../../../../shared/contracts/sni';

const base: SniCandidateRow = {
  id: 'c1',
  name: 'www.example.com',
  site: 'example.com',
  sources: ['toplist'],
  rank: 12_345,
  state: 'new',
  inFamily: null,
  check: {
    at: '2026-10-26T00:00:00.000Z',
    code: null,
    tlsVersion: 'TLSv1.3',
    alpn: 'h2',
    answers: { v4: 1, v6: 0, onNetwork: 'all' },
    shown: ['192.0.2.1'],
    dialled: '192.0.2.10',
    port: 443,
  },
  extra: { x25519: true, mlkem: false, error: null },
  passes: 1,
  baseScore: 40,
  score: 65,
  parts: null,
  listed: true,
  timing: null,
  own: null,
  ooni: null,
  countries: [],
  firstSeenAt: '2026-10-26T00:00:00.000Z',
};

describe('find names words', () => {
  test('every source, filter, reading, log state and sweep error has words, without codes', () => {
    for (const s of HUNT_SOURCES) expect(HUNT_SOURCE_WORDS[s]).toBeTruthy();
    for (const f of HUNT_FILTERS) expect(HUNT_FILTER_LABEL[f]).toBeTruthy();
    const all = [
      ...Object.values(HUNT_SOURCE_WORDS),
      ...Object.values(HUNT_FILTER_LABEL),
      ...Object.values(COUNTRY_READING_WORDS),
      ...Object.values(CT_STATE_WORDS),
      ...Object.values(SWEEP_ERROR_WORDS),
    ];
    for (const w of all) expect(w).not.toMatch(/—|_/);
  });

  test('a candidate in words: ready, failing with the check reason, in a family', () => {
    expect(candidateWords(base)).toEqual({
      dot: 'green',
      sentence: 'It would qualify (TLS 1.3, HTTP/2).',
    });
    const failing = {
      ...base,
      state: 'failing' as const,
      check: { ...base.check!, code: 'q_cert' },
    };
    expect(candidateWords(failing).dot).toBe('red');
    expect(candidateWords(failing).sentence).toMatch(/certificate/);
    expect(
      candidateWords({ ...base, state: 'added', inFamily: { slug: 'f', label: 'Family F' } })
        .sentence,
    ).toBe('In the family Family F.');
    expect(candidateWords({ ...base, check: null }).sentence).toBe('Not checked yet.');
    expect(extraWords(base)).toBe('It takes an X25519-only offer, refuses ML-KEM.');
  });

  test('near the node names the leg it measured', () => {
    expect(nearWords(base, true)).toMatch(/Not measured/);
    const timed = {
      ...base,
      timing: {
        at: '2026-10-26T00:00:00.000Z',
        place: 'US/Springfield',
        endpoint: '192.0.2.10',
        port: 443,
        connectMs: 120,
        tlsMs: null,
        probes: 2,
      },
      own: {
        at: '2026-10-26T00:00:00.000Z',
        place: 'US/Springfield',
        endpoint: '192.0.2.1',
        port: 443,
        connectMs: 5,
        tlsMs: null,
        probes: 2,
      },
    };
    expect(nearWords(timed, true)).toBe(
      'About 120 ms from Springfield (US) to the cover site. Its own site answers there in about 5 ms.',
    );
    expect(nearWords(timed, false)).toBe('About 120 ms from Springfield (US) to its own address.');
  });

  test('countries: readings first, OONI for the exact name, the site only as context', () => {
    const c = {
      ...base,
      countries: [
        {
          cc: 'IR',
          at: 'x',
          reading: 'interference' as const,
          vantages: 3,
          networks: 2,
          singled: 3,
        },
      ],
      ooni: {
        at: 'x',
        exact: [
          { cc: 'IR', status: 'ok' as const, measurements: 20 },
          { cc: 'RU', status: 'blocked' as const, measurements: 20 },
        ],
        site: [{ cc: 'CN', status: 'blocked' as const, measurements: 20 }],
      },
    };
    expect(countryWords(c)).toEqual([
      'IR: interfered with there (3 vantages)',
      'RU: OONI sees it blocked',
    ]);
    expect(siteOoniWords(c)).toMatch(/site example\.com blocked in CN/);
    expect(scoreWords(c)).toBe('Score 65 of 100 (40 before measurements).');
  });

  test('three filters: usable, not usable, all', () => {
    expect(matchesHuntFilter(base, 'usable')).toBe(true);
    expect(matchesHuntFilter(base, 'not_usable')).toBe(false);
    expect(matchesHuntFilter({ ...base, state: 'gone' }, 'not_usable')).toBe(true);
    expect(matchesHuntFilter({ ...base, check: null }, 'not_usable')).toBe(false);
    expect(matchesHuntFilter({ ...base, state: 'ignored' }, 'all')).toBe(true);
    // Not checked yet is not "would not qualify".
    expect(scoreWords({ ...base, check: null })).toBe('No score until it is checked.');
    expect(scoreWords({ ...base, check: { ...base.check!, code: 'q_unreachable' } })).toBe(
      'No score: it would not qualify.',
    );
  });

  test('the Advanced page: switch, sweep cost, place', () => {
    expect(huntSwitchLine(true, 30)).toMatch(/^On\. .*every 30 days/);
    expect(huntSwitchLine(false, 30)).toMatch(/^Off\./);
    expect(sweepCostWords({ depth: 300_000, wwwDepth: 100_000, lookupsPerSecond: 20 })).toBe(
      "It looks up the 300,000 most visited sites in DNS: up to 800,000 lookups over about 12 hours. Most setups do not need it: a cover site's certificate and certificate logs come first.",
    );
    expect(placeLine({ country: 'US', city: 'Example City' }, 'node')).toBe(
      'Timed from Example City (US), taken from a node on it.',
    );
    expect(placeLine({ country: 'DE' }, null)).toBe('Timed from DE.');
    expect(placeLine(null, null)).toMatch(/^Not set/);
  });

  test('"ready" and "would qualify" follow the one rule every count uses', () => {
    for (const state of HUNT_STATES)
      for (const code of [null, 'q_cert'])
        for (const check of [null, { ...base.check!, code }]) {
          const c = { ...base, state, check };
          expect(matchesHuntFilter(c, 'usable')).toBe(usableCandidate(c));
          // Green "it would qualify" only for a usable candidate (an added one says its family).
          if (state !== 'added')
            expect(candidateWords(c).sentence.startsWith('It would qualify')).toBe(
              usableCandidate(c),
            );
        }
  });

  test('the sweep, an import, a place and a family id in words', () => {
    expect(sweepWords(null)).toBe('No search has run yet.');
    expect(
      sweepWords({
        state: 'running',
        listDate: null,
        depth: 300000,
        wwwDepth: 100000,
        total: 400000,
        cursor: 12300,
        hits: 45,
        lookups: 24600,
        error: null,
        startedAt: 'x',
        finishedAt: null,
      }),
    ).toBe('Looking up the top-sites list: 12,300 of 400,000 names, 45 names found on a network.');
    expect(
      huntImportWords({
        added: 2,
        known: 1,
        ignored: 0,
        inFamily: 1,
        invalid: 0,
        capped: 0,
        proposals: { networks: [], families: [] },
      }),
    ).toBe('2 names added, 1 already here, 1 already in a family.');
    expect(parsePlace(' us ', ' Springfield ')).toEqual({ country: 'US', city: 'Springfield' });
    expect(parsePlace('USA', '')).toBeNull();
    expect(familySlugFor('www.example.co.uk')).toBe('example-co-uk');
  });
});
