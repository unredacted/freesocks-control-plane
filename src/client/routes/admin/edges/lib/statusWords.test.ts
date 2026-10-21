import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, test } from 'vitest';
import type { EdgeCountryRow, OriginStatus } from '../../../../../shared/contracts/edges';
import {
  COUNTRY_GROUP_GRADES,
  COUNTRY_REASONS,
  COUNTRY_ROUND_RESULTS,
  COUNTRY_STATE_FROM,
  PROBE_FAILURE_CLASSES,
} from '../../../../../shared/contracts/edgeCodes';
import {
  COUNTRY_REASON_WORDS,
  GROUP_GRADE_WORDS,
  PROBE_FAILURE_WORDS,
  ROUND_RESULT_WORDS,
  STATE_FROM_WORDS,
  countryChip,
  countryLine,
  countryReasonSentence,
  deliveryWords,
  fleetSentence,
  gradeWords,
  originSentence,
  probeFailureWords,
  sourceWords,
  statusOf,
} from './statusWords';

const status = (over: Partial<OriginStatus> = {}): OriginStatus => ({
  kind: 'protected',
  dot: 'green',
  code: null,
  runId: null,
  runKind: null,
  step: null,
  published: 1,
  standbys: 0,
  offline: 0,
  worstHealth: 'online',
  layers: ['l4'],
  attention: false,
  delivery: { kind: 'serving', code: null },
  failedRunId: null,
  fronted: false,
  ...over,
});

describe('originSentence', () => {
  test('a live run speaks first, in four plain steps', () => {
    expect(
      originSentence(status({ kind: 'setting-up', runId: 'r', runKind: 'protect', step: 2 })),
    ).toBe('Setting up, step 2 of 4.');
    expect(
      originSentence(
        status({
          kind: 'needs-you',
          runId: 'r',
          runKind: 'protect',
          step: 4,
          code: 'node_not_approved',
        }),
      ),
    ).toBe('Every address works. Waiting for you to approve go-live.');
    expect(
      originSentence(
        status({ kind: 'needs-you', runId: 'r', runKind: 'protect', step: 3, code: 'try_it' }),
      ),
    ).toBe('Setting up, step 3 of 4. It needs you.');
  });

  test('a re-protect says members keep what they have', () => {
    expect(
      originSentence(status({ kind: 'setting-up', runId: 'r', runKind: 'reprotect', step: 1 })),
    ).toBe('Protecting again, step 1 of 4. Members keep what they have.');
    expect(
      originSentence(
        status({ kind: 'needs-you', runId: 'r', runKind: 'reprotect', step: 3, code: 'try_it' }),
      ),
    ).toBe('Protecting again, step 3 of 4. It needs you.');
  });

  test('every other kind', () => {
    expect(originSentence(status({ kind: 'removing', code: 'restore' }))).toBe(
      'Removing protection.',
    );
    expect(originSentence(status({ kind: 'removing', code: 'deleting' }))).toBe('Being removed.');
    expect(originSentence(status({ kind: 'paused', dot: 'red' }))).toBe(
      'Paused for safety. It needs you.',
    );
    expect(originSentence(status({ kind: 'needs-you', code: 'offline', offline: 2 }))).toBe(
      '2 addresses are offline.',
    );
    expect(originSentence(status({ kind: 'needs-you', code: 'offline', offline: 1 }))).toBe(
      '1 address is offline.',
    );
    expect(originSentence(status({ kind: 'needs-you', code: 'members_dark' }))).toMatch(
      /It needs you\.$/,
    );
    expect(originSentence(status({ kind: 'off' }))).toBe('Protection is switched off (Advanced).');
    expect(originSentence(status({ kind: 'not-live', published: 1 }))).toBe(
      'Address ready, not live yet. Members still use the direct address.',
    );
    expect(originSentence(status({ kind: 'not-live', published: 0 }))).toBe(
      'Not protected yet. Members use the direct address.',
    );
    // A fronted node (a WebSocket front, say) has no direct address to fall back on.
    expect(originSentence(status({ kind: 'not-live', published: 0, fronted: true }))).toBe(
      'Not protected yet. Members get no address for this node until it goes live.',
    );
    expect(originSentence(status({ kind: 'not-live', published: 1, fronted: true }))).toBe(
      'Address ready, not live yet. Members get no address for this node until it goes live.',
    );
    expect(originSentence(status({ kind: 'needs-you', code: 'setup_run_failed' }))).toBe(
      'Setup stopped. It needs you.',
    );
    expect(originSentence(status({ kind: 'unprotected', published: 0 }))).toBe(
      'No address in use. Members get nothing.',
    );
    expect(originSentence(status({ published: 2, standbys: 1 }))).toBe(
      'Protected. 2 addresses in use, 1 spare.',
    );
    expect(originSentence(status({ published: 1 }))).toBe('Protected. 1 address in use.');
  });
});

describe('fleetSentence', () => {
  test('what matters most, then the count', () => {
    expect(fleetSentence(null)).toBe('');
    expect(fleetSentence({ kind: 'empty', dot: 'grey', count: 0, total: 0, protected: 0 })).toBe(
      'No node is protected yet.',
    );
    expect(
      fleetSentence({ kind: 'needs-you', dot: 'amber', count: 1, total: 3, protected: 2 }),
    ).toBe('1 node needs you.');
    expect(
      fleetSentence({ kind: 'needs-you', dot: 'amber', count: 2, total: 3, protected: 1 }),
    ).toBe('2 nodes need you.');
    expect(
      fleetSentence({ kind: 'setting-up', dot: 'blue', count: 1, total: 2, protected: 1 }),
    ).toBe('Setting up 1 node.');
    expect(
      fleetSentence({ kind: 'not-live', dot: 'amber', count: 2, total: 2, protected: 0 }),
    ).toBe('2 nodes are not live yet.');
    expect(
      fleetSentence({ kind: 'protected', dot: 'green', count: 1, total: 1, protected: 1 }),
    ).toBe('Your node is protected.');
    expect(
      fleetSentence({ kind: 'protected', dot: 'green', count: 6, total: 6, protected: 6 }),
    ).toBe('All 6 nodes protected.');
    expect(fleetSentence({ kind: 'partial', dot: 'green', count: 1, total: 3, protected: 1 })).toBe(
      '1 of 3 nodes protected.',
    );
  });
});

describe('deliveryWords', () => {
  test('one headline per kind; a reason and a fix only when something is wrong', () => {
    expect(deliveryWords({ kind: 'manual', code: null }).headline).toBe('Nothing to deliver');
    expect(deliveryWords({ kind: 'direct', code: null }).headline).toBe(
      'Members use the direct address',
    );
    const serving = deliveryWords({ kind: 'serving', code: null });
    expect([serving.tone, serving.reason]).toEqual(['success', null]);
    const dark = deliveryWords({ kind: 'dark', code: 'empty_pool' });
    expect(dark.tone).toBe('danger');
    expect(dark.reason).toBeTruthy();
    expect(deliveryWords({ kind: 'degraded', code: 'entry_mismatch' }).tone).toBe('warning');
    for (const k of ['manual', 'direct', 'serving', 'degraded', 'dark'] as const) {
      const w = deliveryWords({ kind: k, code: k === 'dark' ? 'relay_disabled' : null });
      expect(`${w.headline} ${w.detail} ${w.reason ?? ''}`).not.toMatch(/—/);
    }
  });
});

test('statusOf finds one origin by slug', () => {
  const s = status();
  expect(statusOf([{ relayId: 'r1', relaySlug: 'a', status: s }], 'a')).toBe(s);
  expect(statusOf([], 'a')).toBeNull();
  expect(statusOf(undefined, 'a')).toBeNull();
});

// --- checks from each country -----------------------------------------------------------------

const ROOT = resolve(__dirname, '../../../../../..');
const serverSource = (path: string) => readFileSync(resolve(ROOT, path), 'utf8');

/** Every `'literal'` the server's rules assign to a reason (`reason: …` / `reason = …`). */
function reasonsWritten(source: string): string[] {
  const out = new Set<string>();
  for (const line of source.split('\n')) {
    const m = /\breason\s*(?::|=(?!=))/.exec(line);
    if (!m) continue;
    for (const lit of line.slice(m.index).matchAll(/'([a-z_]+)'/g)) out.add(lit[1]!);
  }
  return [...out].sort();
}

const isSentence = (s: string) => {
  expect(s.trim().length).toBeGreaterThan(10);
  expect(s).toMatch(/[.!]$/);
  expect(s).not.toMatch(/—/);
};

describe('every check result, reason and failure has a sentence', () => {
  test('round results, grades and where a state comes from', () => {
    for (const r of COUNTRY_ROUND_RESULTS) {
      expect(ROUND_RESULT_WORDS[r].label).toBeTruthy();
      isSentence(ROUND_RESULT_WORDS[r].sentence);
    }
    for (const g of COUNTRY_GROUP_GRADES) {
      expect(GROUP_GRADE_WORDS[g].label).toBeTruthy();
      isSentence(GROUP_GRADE_WORDS[g].sentence);
    }
    for (const f of COUNTRY_STATE_FROM) expect(STATE_FROM_WORDS[f]).toBeTruthy();
    // The four grades the provider page and the protect sheet show.
    expect(COUNTRY_GROUP_GRADES.map((g) => GROUP_GRADE_WORDS[g].label)).toEqual([
      'Works',
      'Blocked',
      'Some addresses blocked',
      'Not checked yet',
    ]);
  });

  test('every reason in the vocabulary', () => {
    for (const r of COUNTRY_REASONS) isSentence(COUNTRY_REASON_WORDS[r]);
  });

  test('every failure class in the vocabulary', () => {
    for (const c of PROBE_FAILURE_CLASSES) {
      expect(PROBE_FAILURE_WORDS[c].label).toBeTruthy();
      isSentence(PROBE_FAILURE_WORDS[c].sentence);
    }
  });

  test('every reason the server rules write is in the vocabulary', () => {
    const written = reasonsWritten(serverSource('convex/lib/edges/country/verdict.ts'));
    // The pin is only worth something while it finds the rules' literals.
    expect(written).toEqual(expect.arrayContaining(['too_few', 'country_wide', 'handshake']));
    for (const r of written) expect(COUNTRY_REASONS, r).toContain(r);
    const results = /export type RoundResult = ([^;]+);/.exec(
      serverSource('convex/lib/edges/country/verdict.ts'),
    );
    expect([...(results?.[1] ?? '').matchAll(/'([a-z]+)'/g)].map((m) => m[1]).sort()).toEqual(
      [...COUNTRY_ROUND_RESULTS].sort(),
    );
  });

  test('every failure class the server stores is in the vocabulary', () => {
    const src = serverSource('convex/lib/edges/country/sourceHealth.ts');
    const fn = src.slice(
      src.indexOf('export function failureCode'),
      src.indexOf('export interface'),
    );
    const classes = [...fn.matchAll(/return '([a-z_]+)'/g)].map((m) => m[1]!);
    expect(classes.length).toBeGreaterThan(8);
    // A run that finished with nothing, and a settled run without a class.
    for (const c of [...classes, 'no_results', 'failed', 'timeout'])
      expect(PROBE_FAILURE_CLASSES, c).toContain(c);
  });

  test('an unknown code still reads as words', () => {
    expect(countryReasonSentence('brand_new_reason')).toBe('Brand new reason.');
    expect(countryReasonSentence(null)).toBeNull();
    expect(probeFailureWords('brand_new').label).toBe('Brand new');
    expect(probeFailureWords(null).label).toBe('Failed');
  });
});

const NOW = Date.parse('2026-10-18T12:00:00Z');
const H = 3_600_000;
const at = (msAgo: number) => new Date(NOW - msAgo).toISOString();

function row(over: Partial<EdgeCountryRow> = {}): EdgeCountryRow {
  return {
    country: 'IR',
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
    lastRound: {
      roundId: 'r1',
      at: at(H),
      result: 'unknown',
      reason: 'too_few',
      ok: 1,
      fail: 0,
      networks: 1,
      controlsOk: 2,
      v6Result: null,
    },
    ...over,
  };
}
const line = (
  r: EdgeCountryRow | null,
  marks: { edge?: 'proven' | 'blocked'; group?: 'proven' | 'blocked' } = {},
) =>
  countryLine(
    {
      country: 'IR',
      row: r,
      edgeMark: marks.edge
        ? {
            scope: 'edge',
            edgeId: 'e1',
            groupKey: null,
            country: 'IR',
            state: marks.edge,
            at: at(2 * H),
          }
        : null,
      groupMark: marks.group
        ? {
            scope: 'group',
            edgeId: null,
            groupKey: 'p:x',
            country: 'IR',
            state: marks.group,
            at: at(3 * H),
          }
        : null,
    },
    NOW,
  );

describe('countryLine', () => {
  test('never checked', () => {
    expect(line(null)).toMatchObject({
      label: 'Not checked yet',
      tone: 'muted',
      from: null,
      checked: null,
    });
  });

  test('works, from its own checks', () => {
    const w = line(
      row({ combined: 'proven', effective: { country: 'IR', state: 'proven', from: 'edge' } }),
    );
    expect(w).toMatchObject({
      label: 'Works',
      tone: 'success',
      from: 'From its own checks',
      checked: 'Checked 1 h ago',
    });
  });

  test('blocked since the transition, with the reason of the blocking track', () => {
    const blocked = row({
      combined: 'blocked',
      blockedSince: at(5 * H),
      effective: { country: 'IR', state: 'blocked', from: 'edge' },
      address: {
        state: 'blocked',
        reason: 'blocked',
        decidedAt: at(H),
        until: null,
        blockedRounds: 3,
        repeatAt: null,
      },
    });
    expect(line(blocked)).toMatchObject({
      label: 'Blocked for 5 h',
      tone: 'danger',
      reason: COUNTRY_REASON_WORDS.blocked,
    });
    const byName = row({
      combined: 'blocked',
      effective: { country: 'IR', state: 'blocked', from: 'edge' },
      handshake: {
        state: 'blocked',
        reason: 'handshake',
        until: null,
        pathBatches: 2,
        lastBatchAt: at(H),
      },
    });
    expect(line(byName)).toMatchObject({
      label: 'Blocked',
      reason: COUNTRY_REASON_WORDS.handshake,
    });
  });

  test('blocked through its location', () => {
    expect(
      line(row({ effective: { country: 'IR', state: 'blocked', from: 'group' } })),
    ).toMatchObject({ label: 'Blocked', from: 'From its location' });
  });

  test('a mark wins, and says when the checks disagree', () => {
    const w = line(row({ combined: 'blocked' }), { edge: 'proven' });
    expect(w).toMatchObject({
      label: 'Works',
      from: 'Your mark',
      conflict: 'The checks say blocked.',
    });
    expect(line(row({ combined: 'proven' }), { group: 'blocked' })).toMatchObject({
      label: 'Blocked',
      from: 'Your mark on its location',
      conflict: 'The checks say it works.',
    });
    expect(line(row(), { edge: 'blocked' }).conflict).toBeNull();
  });

  test('down, held, waiting for the repeat, not known', () => {
    expect(
      line(row({ lastRound: { ...row().lastRound!, result: 'down', reason: 'controls_failed' } })),
    ).toMatchObject({ label: 'Down', reason: COUNTRY_REASON_WORDS.controls_failed });
    expect(line(row({ address: { ...row().address, reason: 'country_wide' } }))).toMatchObject({
      label: 'Held, not known',
      tone: 'warning',
    });
    expect(
      line(row({ address: { ...row().address, reason: 'needs_repeat', blockedRounds: 1 } })),
    ).toMatchObject({ label: 'Blocked once, checking again' });
    expect(line(row())).toMatchObject({ label: 'Not known', reason: COUNTRY_REASON_WORDS.too_few });
  });
});

describe('gradeWords', () => {
  const cell = (state: 'proven' | 'blocked' | 'mixed' | 'unknown' | null, extra = {}) => ({
    country: 'IR',
    grade: state
      ? {
          groupKey: 'p:x',
          provider: 'p',
          country: 'IR',
          state,
          counts: { edges: 2, proven: 0, blocked: 2 },
          until: null,
        }
      : null,
    checkedAt: state ? at(2 * H) : null,
    checkedEdges: state ? 2 : 0,
    mark: null,
    conflict: false,
    ...extra,
  });
  test('the four grades, with age', () => {
    expect(gradeWords(cell('proven'), NOW)).toMatchObject({
      label: 'Works',
      age: 'checked 2 h ago',
    });
    expect(gradeWords(cell('blocked'), NOW).label).toBe('Blocked');
    expect(gradeWords(cell('mixed'), NOW).label).toBe('Some addresses blocked');
    expect(gradeWords(cell(null), NOW)).toMatchObject({ label: 'Not checked yet', age: null });
    expect(gradeWords(cell('unknown'), NOW).label).toBe('Not known yet');
  });
  test('a mark and its conflict', () => {
    const w = gradeWords(
      cell('blocked', {
        mark: {
          scope: 'group',
          edgeId: null,
          groupKey: 'p:x',
          country: 'IR',
          state: 'proven',
          at: at(H),
        },
        conflict: true,
      }),
      NOW,
    );
    expect(w.mark).toBe('Marked: works there');
    expect(w.markState).toBe('proven');
    expect(w.conflict).toBe('Your mark says it works; the checks say blocked.');
  });
});

describe('sourceWords', () => {
  const h = (over = {}) => ({
    source: 'globalping',
    runs: 10,
    withEvidence: 7,
    failed: 3,
    empty: 0,
    streak: 0,
    lastOkAt: at(H),
    lastFailAt: at(2 * H),
    lastError: 'timeout',
    failing: false,
    ...over,
  });
  test('working, working with failures, failing, idle', () => {
    expect(sourceWords(h(), NOW)).toMatchObject({ label: 'Working', tone: 'success' });
    expect(sourceWords(h({ streak: 1 }), NOW)).toMatchObject({ label: 'Working, with failures' });
    const failing = sourceWords(
      h({ streak: 5, failing: true, lastError: 'auth', lastOkAt: null }),
      NOW,
    );
    expect(failing.label).toBe('Failing: credential refused');
    expect(failing.detail).toMatch(/5 runs in a row brought nothing/);
    expect(sourceWords(h({ runs: 0 }), NOW).label).toBe('No runs yet');
    for (const w of [sourceWords(h(), NOW), failing]) expect(w.detail).not.toMatch(/—/);
  });
});

test('countryChip: short, and "checking" while the first round is out', () => {
  const fresh = { country: 'IR', row: null, edgeMark: null, groupMark: null };
  expect(countryChip(fresh, NOW, true)).toMatchObject({ label: 'checking', tone: 'muted' });
  expect(countryChip(fresh, NOW, false).label).toBe('not checked yet');
  const works = {
    ...fresh,
    row: row({ combined: 'proven', effective: { country: 'IR', state: 'proven', from: 'edge' } }),
  };
  expect(countryChip(works, NOW, true)).toMatchObject({
    label: 'works',
    tone: 'success',
    title: 'From its own checks',
  });
});
