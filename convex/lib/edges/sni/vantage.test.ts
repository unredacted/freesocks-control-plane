/**
 * Checks of names from inside a country: the scoring (pure).
 *
 *  - a failure counts against a name only when the same batch got through for
 *    another name (same network = `singled`, another network = `unpaired`);
 *    when nothing got through it is the address, never the name;
 *  - blocked needs enough vantages and networks, one same-network control, and
 *    a transition, a repeat or member reports agreeing;
 *  - proven needs enough working vantages and networks, no failing newest
 *    look, and no report saying otherwise;
 *  - a suggestion never replaces an operator's mark.
 *
 * Fixtures use `*.example` names only.
 */
import { describe, expect, test } from 'vitest';
import { SNI_VANTAGE_REASONS } from '../../../../src/shared/contracts/sni';
import {
  REPEAT_GAP_MS,
  SUGGEST_REASONS,
  aggregateEvidence,
  countriesForTick,
  decide,
  pickBatchNames,
  pickTargetIndex,
  preferredTarget,
  rotateForTick,
  suggest,
  type Measurement,
  type VantageReading,
} from './vantage';

const H = 3_600_000;
const T0 = Date.parse('2026-10-01T00:00:00Z');
const OPTS = { reportSuspect: false, minVantages: 3, minNetworks: 2 };

const ok = (asn: string): VantageReading => ({ asn, outcome: 'ok' });
const rst = (asn: string): VantageReading => ({ asn, outcome: 'reset' });
const slow = (asn: string): VantageReading => ({ asn, outcome: 'timeout' });

/** One batch: every name measured from the given vantages. */
function batch(
  id: string,
  at: number,
  byName: Record<string, VantageReading[]>,
  opts: { target?: string; source?: string } = {},
): Measurement[] {
  return Object.entries(byName).map(([name, results]) => ({
    batch: id,
    source: opts.source ?? 'globalping',
    target: opts.target ?? 'edge:e1',
    name,
    at,
    results,
  }));
}

const NETS = ['AS1', 'AS2', 'AS3'];
const allOk = NETS.map(ok);
const allReset = NETS.map(rst);

describe('aggregateEvidence', () => {
  test('a name failing where its control got through, from the same networks, is singled out', () => {
    const e = aggregateEvidence(
      'x.example',
      batch('b1', T0, { 'x.example': allReset, 'y.example': allOk }),
      null,
    );
    expect(e.latest).toBe('failing');
    expect(e.streak).toMatchObject({ nameFailures: 3, networks: 3, singled: 3, pathFailures: 0 });
    expect(e.okVantages).toBe(0);
  });

  test('when no name of the batch got through, it is the address, not the name', () => {
    const e = aggregateEvidence(
      'x.example',
      batch('b1', T0, { 'x.example': allReset, 'y.example': NETS.map(slow) }),
      null,
    );
    expect(e.streak).toMatchObject({ nameFailures: 0, pathFailures: 3 });
    expect(suggest(e, OPTS)).toEqual({ suggestion: null, reason: 'no_control', basis: null });
  });

  test('a control from another network makes the failure name-specific but unpaired', () => {
    const e = aggregateEvidence(
      'x.example',
      batch('b1', T0, {
        'x.example': [rst('AS1'), rst('AS2'), rst('AS3')],
        'y.example': [ok('AS9')],
      }),
      null,
    );
    expect(e.streak).toMatchObject({ nameFailures: 3, singled: 0 });
    expect(suggest(e, OPTS).reason).toBe('not_paired');
  });

  test('`answered` opens the path for the control but never counts as working', () => {
    const e = aggregateEvidence(
      'x.example',
      batch('b1', T0, {
        'x.example': allReset,
        'y.example': NETS.map((asn) => ({ asn, outcome: 'answered' as const })),
      }),
      null,
    );
    expect(e.streak?.singled).toBe(3);
    const y = aggregateEvidence(
      'y.example',
      batch('b1', T0, {
        'x.example': allReset,
        'y.example': NETS.map((asn) => ({ asn, outcome: 'answered' as const })),
      }),
      null,
    );
    expect(y.okVantages).toBe(0);
    expect(y.latest).toBe('none');
  });

  test('refused and errors are not evidence either way', () => {
    const e = aggregateEvidence(
      'x.example',
      batch('b1', T0, {
        'x.example': [
          { asn: 'AS1', outcome: 'refused' },
          { asn: 'AS2', outcome: 'error' },
        ],
        'y.example': allOk,
      }),
      null,
    );
    expect(e.latest).toBe('none');
    expect(suggest(e, OPTS).reason).toBe('no_data');
  });

  test('two sources of one batch are one look, two batches an hour apart are a repeat', () => {
    const one = aggregateEvidence(
      'x.example',
      [
        ...batch('b1', T0, { 'x.example': allReset, 'y.example': allOk }),
        ...batch(
          'b1',
          T0 + 1000,
          { 'x.example': allReset, 'y.example': allOk },
          { source: 'ripeatlas' },
        ),
      ],
      null,
    );
    expect(one.streak?.batches).toBe(1);
    const two = aggregateEvidence(
      'x.example',
      [
        ...batch('b1', T0, { 'x.example': allReset, 'y.example': allOk }),
        ...batch('b2', T0 + REPEAT_GAP_MS, { 'x.example': allReset, 'y.example': allOk }),
      ],
      null,
    );
    expect(two.streak?.batches).toBe(2);
    // A second request a minute later is not a repeat.
    const soon = aggregateEvidence(
      'x.example',
      [
        ...batch('b1', T0, { 'x.example': allReset, 'y.example': allOk }),
        ...batch('b2', T0 + 60_000, { 'x.example': allReset, 'y.example': allOk }),
      ],
      null,
    );
    expect(soon.streak?.batches).toBe(1);
  });

  test('the sources of one batch are one look, whichever finished last', () => {
    // Globalping got through for x, RIPE Atlas saw x singled out: the newest look disagrees.
    const gp = batch('b1', T0, { 'x.example': allOk, 'y.example': allOk });
    const atlas = batch(
      'b1',
      T0 + 5000,
      { 'x.example': ['AS7', 'AS8', 'AS9'].map(rst), 'y.example': ['AS7', 'AS8', 'AS9'].map(ok) },
      { source: 'ripeatlas' },
    );
    for (const order of [
      [...gp, ...atlas],
      [...atlas, ...gp],
    ]) {
      const e = aggregateEvidence('x.example', order, null);
      expect(e.latest).toBe('mixed');
      expect(suggest(e, OPTS).reason).toBe('mixed');
    }
    // Atlas finishing FIRST must not decide it either.
    const early = aggregateEvidence(
      'x.example',
      [...gp.map((m) => ({ ...m, at: T0 + 9000 })), ...atlas],
      null,
    );
    expect(early.latest).toBe('mixed');
  });

  test('a transition: it worked from there before the failing streak began', () => {
    const e = aggregateEvidence(
      'x.example',
      [
        ...batch('b1', T0, { 'x.example': allOk, 'y.example': allOk }),
        ...batch('b2', T0 + 72 * H, { 'x.example': allReset, 'y.example': allOk }),
      ],
      null,
    );
    expect(e.streak?.transition).toBe(true);
    expect(e.okVantages).toBe(3);
    expect(e.lastOkAt).toBe(T0);
    // ...or before the window, kept on the evidence row as `everOkAt`.
    const old = aggregateEvidence(
      'x.example',
      batch('b2', T0, { 'x.example': allReset, 'y.example': allOk }),
      T0 - 30 * 24 * H,
    );
    expect(old.streak?.transition).toBe(true);
  });

  test('working through one address and failing through another is mixed', () => {
    const e = aggregateEvidence(
      'x.example',
      [
        ...batch('b1', T0, { 'x.example': allOk, 'y.example': allOk }, { target: 'edge:e1' }),
        ...batch(
          'b2',
          T0 + H,
          { 'x.example': allReset, 'y.example': allOk },
          { target: 'edge:e2' },
        ),
      ],
      null,
    );
    expect(e.latest).toBe('mixed');
    expect(suggest(e, OPTS).reason).toBe('mixed');
  });

  test('a recovered name: the newest look works again, so the old streak is over', () => {
    const e = aggregateEvidence(
      'x.example',
      [
        ...batch('b1', T0, { 'x.example': allReset, 'y.example': allOk }),
        ...batch('b2', T0 + 72 * H, { 'x.example': allOk, 'y.example': allOk }),
      ],
      null,
    );
    expect(e.latest).toBe('ok');
    expect(e.streak).toBeNull();
    expect(e.lastFailAt).toBe(T0);
  });

  test('only the name asked about is aggregated; other names are its controls', () => {
    const e = aggregateEvidence(
      'y.example',
      batch('b1', T0, { 'x.example': allReset, 'y.example': allOk }),
      null,
    );
    expect(e).toMatchObject({ latest: 'ok', okVantages: 3, okNetworks: 3, measurements: 1 });
  });
});

describe('suggest', () => {
  const failing = (n: number, nets: number) => ({
    measurements: 1,
    okVantages: 0,
    okNetworks: 0,
    lastOkAt: null,
    lastFailAt: T0,
    lastAt: T0,
    latest: 'failing' as const,
    streak: {
      nameFailures: n,
      networks: nets,
      singled: n,
      pathFailures: 0,
      batches: 1,
      startedAt: T0,
      transition: false,
    },
  });

  test('one look at a name that never worked there waits for a repeat', () => {
    expect(suggest(failing(3, 3), OPTS).reason).toBe('needs_repeat');
  });

  test('a repeat, a transition, or member reports make it a block suggestion', () => {
    const repeated = failing(3, 3);
    repeated.streak.batches = 2;
    expect(suggest(repeated, OPTS)).toEqual({
      suggestion: 'blocked',
      reason: null,
      basis: { transition: false, repeated: true, reports: false },
    });
    const transition = failing(3, 3);
    transition.streak.transition = true;
    expect(suggest(transition, OPTS).suggestion).toBe('blocked');
    expect(suggest(failing(3, 3), { ...OPTS, reportSuspect: true }).basis).toEqual({
      transition: false,
      repeated: false,
      reports: true,
    });
  });

  test('too few vantages or networks suggest nothing', () => {
    const r = failing(2, 2);
    r.streak.batches = 2;
    expect(suggest(r, OPTS).reason).toBe('not_enough_vantages');
    const one = failing(3, 1);
    one.streak.batches = 2;
    expect(suggest(one, OPTS).reason).toBe('not_enough_networks');
  });

  test('proven needs enough working vantages on enough networks, and no report against it', () => {
    const working = {
      ...failing(0, 0),
      latest: 'ok' as const,
      streak: null,
      okVantages: 4,
      okNetworks: 2,
    };
    expect(suggest(working, OPTS).suggestion).toBe('proven');
    expect(suggest({ ...working, okVantages: 2 }, OPTS).reason).toBe('not_enough_vantages');
    expect(suggest({ ...working, okNetworks: 1 }, OPTS).reason).toBe('not_enough_networks');
    expect(suggest(working, { ...OPTS, reportSuspect: true }).reason).toBe('reports_disagree');
  });

  test('end to end: two looks three days apart from three networks', () => {
    const ms = [
      ...batch('b1', T0, { 'x.example': allReset, 'y.example': allOk }),
      ...batch('b2', T0 + 72 * H, { 'x.example': allReset, 'y.example': allOk }),
    ];
    expect(suggest(aggregateEvidence('x.example', ms, null), OPTS).suggestion).toBe('blocked');
    expect(suggest(aggregateEvidence('y.example', ms, null), OPTS).suggestion).toBe('proven');
  });
});

describe('the wire', () => {
  test('every reason the scoring gives is one the contract (and so the page) knows', () => {
    expect([...SUGGEST_REASONS].sort()).toEqual([...SNI_VANTAGE_REASONS].sort());
  });
});

describe('decide', () => {
  test('an operator mark is never replaced, a mark the checks wrote may be', () => {
    expect(decide('blocked', null)).toBe('suggest');
    expect(decide('blocked', { state: 'blocked', source: 'operator' })).toBe('agrees');
    expect(decide('blocked', { state: 'proven', source: 'operator' })).toBe('conflict');
    expect(decide('blocked', { state: 'proven', source: 'probe' })).toBe('suggest');
    expect(decide(null, { state: 'proven', source: 'operator' })).toBe('none');
  });
});

describe('planning', () => {
  const c = (name: string, seq: number, over: Record<string, unknown> = {}) => ({
    name,
    seq,
    due: true,
    spare: true,
    priority: false,
    lastRequestedAt: null,
    lastOkAt: null,
    ...over,
  });

  test('due names first (reported ones before the rest), up to the batch size', () => {
    expect(
      pickBatchNames(
        [c('a.example', 1), c('b.example', 2), c('c.example', 3, { priority: true })],
        2,
      ),
    ).toEqual(['c.example', 'a.example']);
  });

  test('the longest waiting go first, never checked before anything else, so none starves', () => {
    expect(
      pickBatchNames(
        [
          c('a.example', 1, { lastRequestedAt: 5 }),
          c('b.example', 2, { lastRequestedAt: 9 }),
          c('c.example', 3, { lastRequestedAt: 1 }),
          c('d.example', 4),
        ],
        3,
      ),
    ).toEqual(['d.example', 'c.example', 'a.example']);
  });

  test('a lone due name gets a spare control: the one that last worked from there', () => {
    expect(
      pickBatchNames(
        [
          c('a.example', 1),
          c('b.example', 2, { due: false, lastOkAt: 5 }),
          c('c.example', 3, { due: false, lastOkAt: 9 }),
        ],
        3,
      ),
    ).toEqual(['a.example', 'c.example']);
    // Nothing else on the listener: the name goes alone.
    expect(pickBatchNames([c('a.example', 1)], 3)).toEqual(['a.example']);
    expect(pickBatchNames([c('a.example', 1, { due: false })], 3)).toEqual([]);
  });

  test('a control is a check too: with no spare within the interval, the batch waits', () => {
    expect(
      pickBatchNames(
        [
          c('a.example', 1),
          c('b.example', 2, { due: false, spare: false, lastOkAt: 9 }),
          c('c.example', 3, { due: false, spare: false }),
        ],
        3,
      ),
    ).toEqual([]);
  });

  test('a name on several addresses takes them in turn, never checked first', () => {
    const keys = ['edge:a:198.51.100.1:443', 'edge:b:198.51.100.2:443'];
    expect(preferredTarget(keys, new Map())).toBe(keys[0]);
    expect(preferredTarget(keys, new Map([[keys[0]!, 10]]))).toBe(keys[1]);
    expect(
      preferredTarget(
        keys,
        new Map([
          [keys[0]!, 10],
          [keys[1]!, 20],
        ]),
      ),
    ).toBe(keys[0]);
    expect(preferredTarget([], new Map())).toBeNull();
  });

  test('never an address the address-level probes find unreachable; reachable ones first', () => {
    expect(pickTargetIndex(['unreachable', 'unknown', 'reachable'])).toBe(2);
    expect(pickTargetIndex(['unreachable', null])).toBe(1);
    expect(pickTargetIndex(['unreachable'])).toBe(-1);
  });

  test('each opted-in country gets its turn, and a bounded scan starts elsewhere each tick', () => {
    const tick = 600_000;
    expect(countriesForTick(['IR', 'RU', 'CN'], 0, tick)).toEqual(['IR', 'RU', 'CN']);
    expect(countriesForTick(['IR', 'RU', 'CN'], tick, tick)).toEqual(['RU', 'CN', 'IR']);
    expect(countriesForTick([], 0, tick)).toEqual([]);
    expect(rotateForTick([1, 2, 3, 4], 2 * tick, tick)).toEqual([3, 4, 1, 2]);
  });
});
