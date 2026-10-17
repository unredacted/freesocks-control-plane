/**
 * The one origin status (pure facts, no db): every judgement the CMS used to
 * make on its own (simple/nodeStatus.ts, overview/derive.ts,
 * relay/relayLogic.ts `deriveDelivery`) as kind / dot / code / step / counts,
 * plus the run, the attention rank and the fleet headline. Fixture values only.
 */
import { describe, expect, test } from 'vitest';
import {
  ATTENTION_KINDS,
  SETUP_RUN_STAGES,
  SETUP_RUN_STAGE_STEP,
} from '../../../src/shared/contracts/edgeCodes';
import { OriginStatus, FleetStatus } from '../../../src/shared/contracts/edges';
import {
  ATTENTION_RANK,
  attentionRankOf,
  deliveryOf,
  fleetStatusOf,
  layersOf,
  membersDarkCode,
  originStatusOf,
  worstHealthOf,
  type DeliveryFacts,
  type OriginStatusFacts,
  type StatusAttentionFacts,
  type StatusRunFacts,
} from './originStatus';

/** A bound, enabled backend node with one healthy L4 edge published and render on. */
const facts = (over: Partial<OriginStatusFacts> = {}): OriginStatusFacts => ({
  originKind: 'panel-node',
  enabled: true,
  quarantined: false,
  restore: false,
  deleting: false,
  bindingDeferred: false,
  setupOwned: false,
  published: 1,
  pool: [{ health: 'online', layer: 'l4' }],
  standbys: 0,
  bound: true,
  renderEnabled: true,
  run: null,
  attention: [],
  ...over,
});
const run = (over: Partial<StatusRunFacts> = {}): StatusRunFacts => ({
  id: 'run-1',
  stage: 'provision',
  state: 'running',
  ...over,
});
const item = (over: Partial<StatusAttentionFacts> = {}): StatusAttentionFacts => ({
  kind: 'block_suspected',
  severity: 'warning',
  code: null,
  ...over,
});
const status = (over: Partial<OriginStatusFacts> = {}) => {
  const s = originStatusOf(facts(over));
  // Every judgement parses with the shared contract.
  expect(OriginStatus.parse(s)).toEqual(s);
  return s;
};

describe('the attention rank', () => {
  test('ranks exactly the shared kinds, unknown kinds last', () => {
    expect([...ATTENTION_RANK].sort()).toEqual([...ATTENTION_KINDS].sort());
    expect(attentionRankOf('quarantine')).toBe(0);
    expect(attentionRankOf('not_a_kind')).toBe(ATTENTION_RANK.length);
  });
});

describe('the plain stage of a run', () => {
  test('folds every machine stage onto the four plain ones (done = 5)', () => {
    for (const s of SETUP_RUN_STAGES) expect(SETUP_RUN_STAGE_STEP[s]).toBeGreaterThanOrEqual(1);
    const stepAt = (stage: StatusRunFacts['stage']) => status({ run: run({ stage }) }).step;
    expect(stepAt('prepare')).toBe(1);
    expect(stepAt('provision')).toBe(1);
    expect(stepAt('verify')).toBe(2);
    expect(stepAt('try_it')).toBe(3);
    // An enrolled node waits for its go-live approval at publish: "Going live".
    expect(stepAt('publish')).toBe(4);
    expect(stepAt('go_live')).toBe(4);
    expect(SETUP_RUN_STAGE_STEP.done).toBe(5);
  });
});

describe('originStatusOf: a live run first', () => {
  test('a running run is setting-up (blue) with its step, id and kind', () => {
    expect(status({ run: run() })).toMatchObject({
      kind: 'setting-up',
      dot: 'blue',
      code: null,
      step: 1,
      runId: 'run-1',
      runKind: 'protect',
    });
    expect(status({ run: run({ state: 'waiting', stage: 'verify' }) })).toMatchObject({
      kind: 'setting-up',
      step: 2,
    });
  });

  test('a run that waits on the operator is needs-you (amber) with its need code', () => {
    expect(
      status({ run: run({ state: 'needs_you', stage: 'try_it', need: { code: 'try_it' } }) }),
    ).toMatchObject({ kind: 'needs-you', dot: 'amber', step: 3, code: 'try_it' });
    expect(
      status({
        run: run({ state: 'needs_you', stage: 'publish', need: { code: 'node_not_approved' } }),
      }),
    ).toMatchObject({ kind: 'needs-you', dot: 'amber', step: 4, code: 'node_not_approved' });
  });

  test('a re-protect run reports its kind', () => {
    expect(status({ run: run({ kind: 'reprotect', stage: 'verify' }) })).toMatchObject({
      kind: 'setting-up',
      runKind: 'reprotect',
      step: 2,
    });
  });

  test('a terminal run is ignored', () => {
    for (const state of ['done', 'done_unbound', 'failed', 'cancelled'] as const) {
      expect(status({ run: run({ state }) })).toMatchObject({
        kind: 'protected',
        runId: null,
        runKind: null,
        step: null,
      });
    }
  });

  test('the run wins over everything else', () => {
    const s = status({
      run: run({ stage: 'try_it' }),
      deleting: true,
      restore: true,
      quarantined: true,
      enabled: false,
      published: 0,
      pool: [],
      attention: [item({ kind: 'quarantine', severity: 'critical' })],
    });
    expect(s).toMatchObject({ kind: 'setting-up', dot: 'blue', step: 3 });
  });
});

describe('originStatusOf: the order after the run', () => {
  test('removing, then paused', () => {
    expect(status({ restore: true })).toMatchObject({
      kind: 'removing',
      dot: 'grey',
      code: 'restore',
    });
    expect(status({ deleting: true })).toMatchObject({ kind: 'removing', code: 'deleting' });
    expect(status({ deleting: true, quarantined: true }).kind).toBe('removing');
    expect(status({ quarantined: true })).toMatchObject({ kind: 'paused', dot: 'red' });
    expect(
      status({ quarantined: true, attention: [item({ kind: 'quarantine', severity: 'critical' })] })
        .kind,
    ).toBe('paused');
  });

  test('an urgent attention item: red for critical, amber for warning, code = its kind', () => {
    expect(status({ attention: [item({ severity: 'critical' })] })).toMatchObject({
      kind: 'needs-you',
      dot: 'red',
      code: 'block_suspected',
      attention: true,
    });
    expect(status({ attention: [item({ severity: 'warning' })] })).toMatchObject({
      kind: 'needs-you',
      dot: 'amber',
      code: 'block_suspected',
    });
    // An info item is not urgent, but still flags the origin.
    expect(
      status({ attention: [item({ kind: 'restore_in_progress', severity: 'info' })] }),
    ).toMatchObject({ kind: 'protected', attention: true });
    expect(status().attention).toBe(false);
    // An urgent item outranks the switch and the deferral.
    expect(status({ enabled: false, attention: [item({ severity: 'critical' })] }).kind).toBe(
      'needs-you',
    );
  });

  test('the attention rank decides which item is the code', () => {
    const s = status({
      attention: [
        item({ kind: 'rotation_failed', severity: 'warning' }),
        item({ kind: 'needs_operator', severity: 'critical' }),
        item({ kind: 'block_suspected', severity: 'warning' }),
      ],
    });
    expect(s).toMatchObject({ kind: 'needs-you', dot: 'red', code: 'needs_operator' });
    // Severity does not reorder: the higher-ranked warning wins over a lower-ranked one.
    expect(
      status({
        attention: [
          item({ kind: 'spare_untested', severity: 'warning' }),
          item({ kind: 'block_suspected', severity: 'warning' }),
        ],
      }).code,
    ).toBe('block_suspected');
    // An info item never becomes the code, whatever its rank.
    expect(
      status({
        attention: [
          item({ kind: 'quarantine', severity: 'info' }),
          item({ kind: 'spare_untested', severity: 'warning' }),
        ],
      }).code,
    ).toBe('spare_untested');
  });

  test('off, not live, unprotected, offline, protected', () => {
    expect(status({ enabled: false })).toMatchObject({ kind: 'off', dot: 'grey' });
    expect(status({ bindingDeferred: true, bound: false })).toMatchObject({
      kind: 'not-live',
      dot: 'amber',
    });
    expect(status({ setupOwned: true, bound: false }).kind).toBe('not-live');
    expect(status({ published: 0, pool: [], bound: false })).toMatchObject({
      kind: 'unprotected',
      dot: 'red',
      worstHealth: null,
      layers: [],
    });
    expect(status({ pool: [{ health: 'offline', layer: 'l4' }] })).toMatchObject({
      kind: 'needs-you',
      dot: 'red',
      code: 'offline',
      offline: 1,
      worstHealth: 'offline',
    });
    expect(
      status({
        published: 2,
        pool: [
          { health: 'online', layer: 'l4' },
          { health: 'online', layer: 'l7' },
        ],
        standbys: 1,
      }),
    ).toMatchObject({
      kind: 'protected',
      dot: 'green',
      code: null,
      published: 2,
      standbys: 1,
      offline: 0,
      layers: ['l4', 'l7'],
      delivery: { kind: 'serving', code: null },
    });
  });

  test('a deferred origin with something published is not live; members get the direct address', () => {
    const deferred = { bindingDeferred: true, setupOwned: true, bound: false };
    expect(status(deferred)).toMatchObject({
      kind: 'not-live',
      dot: 'amber',
      delivery: { kind: 'direct', code: null },
    });
    // Its go-live item restates the same state.
    expect(
      status({ ...deferred, attention: [item({ kind: 'go_live_pending', severity: 'warning' })] }),
    ).toMatchObject({ kind: 'not-live', dot: 'amber', code: null, attention: true });
    // ... and so does a pool short of anything published.
    expect(
      status({
        ...deferred,
        published: 0,
        pool: [],
        attention: [item({ kind: 'pool_below_desired', severity: 'warning' })],
      }),
    ).toMatchObject({ kind: 'not-live', delivery: { kind: 'direct' } });
  });

  test('a bound origin with nothing published is unprotected and its members are dark', () => {
    const empty = { published: 0, pool: [] };
    expect(status(empty)).toMatchObject({
      kind: 'unprotected',
      dot: 'red',
      delivery: { kind: 'dark', code: 'empty_pool' },
    });
    // The server's own items for it restate the empty pool: still unprotected.
    const s = status({
      ...empty,
      attention: [
        item({ kind: 'members_dark', severity: 'critical', code: 'empty_pool' }),
        item({ kind: 'pool_below_desired', severity: 'warning' }),
      ],
    });
    expect(s).toMatchObject({
      kind: 'unprotected',
      dot: 'red',
      code: null,
      attention: true,
      delivery: { kind: 'dark', code: 'empty_pool' },
    });
    // Switched off as well: members are still dark, never a grey `off`.
    expect(
      status({
        ...empty,
        enabled: false,
        attention: [item({ kind: 'members_dark', severity: 'critical', code: 'empty_pool' })],
      }).kind,
    ).toBe('unprotected');
    // A more urgent item still wins.
    expect(
      status({
        ...empty,
        attention: [
          item({ kind: 'members_dark', severity: 'critical', code: 'empty_pool' }),
          item({ kind: 'needs_operator', severity: 'critical' }),
        ],
      }),
    ).toMatchObject({ kind: 'needs-you', code: 'needs_operator' });
  });

  test('members dark for any other reason is needs-you', () => {
    expect(
      status({
        enabled: false,
        attention: [item({ kind: 'members_dark', severity: 'critical', code: 'relay_disabled' })],
      }),
    ).toMatchObject({
      kind: 'needs-you',
      dot: 'red',
      code: 'members_dark',
      delivery: { kind: 'dark', code: 'relay_disabled' },
    });
  });

  test('an unbound origin short of anything published is unprotected', () => {
    expect(
      status({
        bound: false,
        published: 0,
        pool: [],
        attention: [item({ kind: 'pool_below_desired', severity: 'warning' })],
      }),
    ).toMatchObject({ kind: 'unprotected', dot: 'red', delivery: { kind: 'direct' } });
    // With something published the shortfall is info only: not urgent.
    expect(
      status({ attention: [item({ kind: 'pool_below_desired', severity: 'info' })] }).kind,
    ).toBe('protected');
  });
});

describe('pool figures', () => {
  test('layers L4 first, worst health, null when nothing is published', () => {
    const pool = [
      { health: 'online', layer: 'l7' as const },
      { health: 'degraded', layer: 'l4' as const },
    ];
    expect(layersOf(pool)).toEqual(['l4', 'l7']);
    expect(layersOf([])).toEqual([]);
    expect(worstHealthOf(pool)).toBe('degraded');
    expect(worstHealthOf([{ health: 'unknown', layer: 'l4' }, ...pool])).toBe('degraded');
    expect(
      worstHealthOf([
        { health: 'online', layer: 'l4' },
        { health: 'unknown', layer: 'l4' },
      ]),
    ).toBe('unknown');
    expect(worstHealthOf([...pool, { health: 'offline', layer: 'l4' }])).toBe('offline');
    expect(worstHealthOf([])).toBeNull();
  });
});

describe('deliveryOf', () => {
  const d = (over: Partial<DeliveryFacts> = {}) =>
    deliveryOf({
      originKind: 'panel-node',
      bound: true,
      published: 1,
      enabled: true,
      renderEnabled: true,
      ...over,
    });
  const blockers = (...b: Array<{ code: string; detail?: string | null }>) =>
    b.map((x) => ({ code: x.code, detail: x.detail ?? null }));

  test('serves when bound, published, enabled and rendering is clean', () => {
    expect(d()).toEqual({ kind: 'serving', code: null });
    expect(d({ renderBlockers: [] })).toEqual({ kind: 'serving', code: null });
  });

  test('a manual origin has nothing to deliver', () => {
    expect(d({ originKind: 'manual', bound: false, published: 0 })).toEqual({
      kind: 'manual',
      code: null,
    });
  });

  test('no binding: members get the direct address, whatever is published', () => {
    expect(d({ bound: false })).toEqual({ kind: 'direct', code: null });
    expect(d({ bound: false, published: 0, enabled: false, renderEnabled: false })).toEqual({
      kind: 'direct',
      code: null,
    });
    expect(d({ bound: false, renderBlockers: blockers({ code: 'entry_mismatch' }) }).kind).toBe(
      'direct',
    );
  });

  test('bound: dark with an empty pool, a disabled origin or rendering off (that order)', () => {
    expect(d({ published: 0 })).toEqual({ kind: 'dark', code: 'empty_pool' });
    expect(d({ published: 0, enabled: false, renderEnabled: false }).code).toBe('empty_pool');
    expect(d({ enabled: false })).toEqual({ kind: 'dark', code: 'relay_disabled' });
    expect(d({ enabled: false, renderEnabled: false }).code).toBe('relay_disabled');
    expect(d({ renderEnabled: false })).toEqual({ kind: 'dark', code: 'render_disabled' });
    // Dark wins over a soft render problem.
    expect(
      d({ renderEnabled: false, renderBlockers: blockers({ code: 'entry_mismatch' }) }).kind,
    ).toBe('dark');
  });

  test('the members_dark rule is the dark delivery', () => {
    expect(
      membersDarkCode({ bound: false, published: 0, enabled: true, renderEnabled: true }),
    ).toBe(null);
    expect(membersDarkCode({ bound: true, published: 0, enabled: true, renderEnabled: true })).toBe(
      'empty_pool',
    );
    expect(membersDarkCode({ bound: true, published: 1, enabled: true, renderEnabled: true })).toBe(
      null,
    );
  });

  test('a binding left by a departed origin: dark relay_missing, whatever this origin publishes', () => {
    // Not this origin's binding: it names one deleted keep-dark, so members get a 503.
    expect(d({ bound: false, foreignBinding: true })).toEqual({
      kind: 'dark',
      code: 'relay_missing',
    });
    expect(
      membersDarkCode({
        bound: false,
        foreignBinding: true,
        published: 2,
        enabled: true,
        renderEnabled: true,
      }),
    ).toBe('relay_missing');
    // The status says so too: needs-you, not protected.
    const st = originStatusOf(
      facts({
        bound: false,
        foreignBinding: true,
        bindingDeferred: true,
        published: 1,
        attention: [{ kind: 'members_dark', severity: 'critical', code: 'relay_missing' }],
      }),
    );
    expect([st.kind, st.dot, st.code]).toEqual(['needs-you', 'red', 'members_dark']);
    expect(st.delivery).toEqual({ kind: 'dark', code: 'relay_missing' });
  });

  test('degraded on a soft render problem, using the sample render reason', () => {
    expect(
      d({ renderBlockers: blockers({ code: 'preview_not_applied', detail: 'no_match' }) }),
    ).toEqual({ kind: 'degraded', code: 'no_match' });
    expect(d({ renderBlockers: blockers({ code: 'preview_not_applied' }) })).toEqual({
      kind: 'degraded',
      code: 'preview_not_applied',
    });
    expect(d({ renderBlockers: blockers({ code: 'entry_mismatch', detail: 'x' }) })).toEqual({
      kind: 'degraded',
      code: 'entry_mismatch',
    });
    expect(d({ renderBlockers: blockers({ code: 'mirrors_unvalidated', detail: '3' }) })).toEqual({
      kind: 'degraded',
      code: 'mirrors_unvalidated',
    });
    // Hard blockers of the step are not soft; the first soft one wins.
    expect(
      d({
        renderBlockers: blockers(
          { code: 'no_relay' },
          { code: 'entry_mismatch' },
          { code: 'mirrors_unvalidated' },
        ),
      }).code,
    ).toBe('entry_mismatch');
  });

  test('the status carries delivery without the render blockers', () => {
    expect(status({ published: 0, pool: [] }).delivery).toEqual({
      kind: 'dark',
      code: 'empty_pool',
    });
    expect(status({ originKind: 'manual', bound: false }).delivery.kind).toBe('manual');
  });
});

describe('fleetStatusOf', () => {
  const s = (...kinds: OriginStatus['kind'][]) => kinds.map((kind) => ({ kind }));
  const fleet = (...kinds: OriginStatus['kind'][]) => {
    const f = fleetStatusOf(s(...kinds));
    expect(FleetStatus.parse(f)).toEqual(f);
    return f;
  };

  test('says the one thing that matters most', () => {
    expect(fleet()).toEqual({ kind: 'empty', dot: 'grey', count: 0, total: 0, protected: 0 });
    expect(fleet('protected', 'protected')).toEqual({
      kind: 'protected',
      dot: 'green',
      count: 2,
      total: 2,
      protected: 2,
    });
    expect(fleet('protected')).toMatchObject({ kind: 'protected', count: 1, total: 1 });
    expect(fleet('protected', 'needs-you')).toMatchObject({
      kind: 'needs-you',
      dot: 'amber',
      count: 1,
      total: 2,
      protected: 1,
    });
    expect(fleet('protected', 'setting-up')).toMatchObject({
      kind: 'setting-up',
      dot: 'blue',
      count: 1,
    });
    expect(fleet('protected', 'not-live')).toMatchObject({
      kind: 'not-live',
      dot: 'amber',
      count: 1,
    });
    expect(fleet('protected', 'off')).toEqual({
      kind: 'partial',
      dot: 'green',
      count: 1,
      total: 2,
      protected: 1,
    });
  });

  test('paused and unprotected need you too; the order is needs-you, setting-up, not-live', () => {
    expect(fleet('paused', 'unprotected', 'needs-you', 'setting-up', 'not-live')).toMatchObject({
      kind: 'needs-you',
      count: 3,
      total: 5,
    });
    expect(fleet('setting-up', 'not-live', 'setting-up')).toMatchObject({
      kind: 'setting-up',
      count: 2,
    });
    expect(fleet('not-live', 'off')).toMatchObject({ kind: 'not-live', count: 1 });
  });

  test('partial is grey when nothing is protected', () => {
    expect(fleet('off', 'removing')).toEqual({
      kind: 'partial',
      dot: 'grey',
      count: 2,
      total: 2,
      protected: 0,
    });
  });
});
