/**
 * One name list as one list: one state per name (its own names and the names
 * found for it), one sentence each, three filters, and the line the Server
 * names page shows, with the same counts. No codes, no em-dashes, no "ready".
 */
import { describe, expect, test } from 'vitest';
import type {
  SniCandidateRow,
  SniFamilySummary,
  SniNameRow,
} from '../../../../../../shared/contracts/sni';
import {
  LIST_FILTERS,
  checksWantWords,
  STATE_LABEL,
  listDot,
  listLine,
  listRows,
  listSwitchLine,
  matchesListFilter,
  nameActionWords,
  namesSwitchLine,
  autoTestSwitchLine,
} from './listWords';

function name(n: string, o: Partial<SniNameRow> = {}): SniNameRow {
  return {
    name: n,
    seq: 1,
    status: 'active',
    qualification: 'ok',
    code: null,
    tlsVersion: 'TLSv1.3',
    alpn: 'h2',
    checkedAt: null,
    blockedIn: [],
    provenIn: [],
    suspectIn: [],
    probeMarkedIn: [],
    vantage: [],
    delivery: { state: 'in_use', inUseOn: 1, nodes: 1 },
    ...o,
  };
}
function found(n: string, o: Partial<SniCandidateRow> = {}): SniCandidateRow {
  return {
    id: `c-${n}`,
    name: n,
    site: 'site.example',
    sources: ['cert'],
    rank: null,
    state: 'new',
    inFamily: null,
    check: {
      at: '2026-10-27T00:00:00.000Z',
      code: null,
      tlsVersion: 'TLSv1.3',
      alpn: 'h2',
      answers: { v4: 1, v6: 0, onNetwork: 'all' },
      shown: ['192.0.2.1'],
      dialled: '192.0.2.1',
      port: 443,
    },
    extra: null,
    passes: 1,
    baseScore: 0,
    score: 0,
    parts: null,
    listed: false,
    timing: null,
    own: null,
    ooni: null,
    countries: [],
    firstSeenAt: '2026-10-27T00:00:00.000Z',
    ...o,
  };
}

describe('one list', () => {
  const rows = listRows(
    [
      name('a.site.example'),
      name('b.site.example', { delivery: { state: 'waiting_test', inUseOn: 1, nodes: 2 } }),
      name('c.site.example', {
        qualification: 'pending',
        delivery: { state: 'checking', inUseOn: 0, nodes: 2 },
      }),
      name('d.site.example', {
        qualification: 'failed',
        code: 'q_cert',
        delivery: { state: 'failing', inUseOn: 0, nodes: 2 },
      }),
      name('e.site.example', {
        status: 'retired',
        delivery: { state: 'off', inUseOn: 0, nodes: 2 },
      }),
      name('f.site.example', { delivery: { state: 'to_send', inUseOn: 0, nodes: 2 } }),
    ],
    [
      found('new.site.example'),
      found('a.site.example', { state: 'added' }),
      found('odd.site.example', { state: 'ignored' }),
      found('bad.site.example', {
        state: 'failing',
        check: { ...found('x').check!, code: 'q_tls12' },
      }),
      found('fresh.site.example', { check: null }),
    ],
    true,
  );

  test('one state per name, what needs a decision first, a held find never twice', () => {
    expect(rows.map((r) => [r.name, r.state])).toEqual([
      ['new.site.example', 'suggested'],
      ['b.site.example', 'waiting_test'],
      ['f.site.example', 'to_send'],
      ['d.site.example', 'failing'],
      ['c.site.example', 'checking'],
      ['fresh.site.example', 'checking'],
      ['a.site.example', 'in_use'],
      ['bad.site.example', 'not_usable'],
      ['odd.site.example', 'ignored'],
      ['e.site.example', 'retired'],
    ]);
  });

  test('the sentences say the state and why, in plain words', () => {
    const say = Object.fromEntries(rows.map((r) => [r.name, r.sentence]));
    expect(say).toMatchObject({
      'b.site.example': 'On the node, waiting for a test. Members get it on 1 of 2 nodes.',
      'a.site.example': 'Members get it.',
      'f.site.example': 'Checked. Waiting to be sent to the node.',
      'd.site.example': 'The cover site has no valid certificate for this name.',
      'c.site.example': 'Being checked against the cover site.',
      'bad.site.example': 'Not usable. The cover site does not offer TLS 1.3 for this name.',
      'e.site.example': 'Retired: no longer given out.',
    });
    for (const r of rows) {
      expect(r.sentence).not.toMatch(/—|q_|family|target|transport|ready|score/i);
      expect(STATE_LABEL[r.state]).toBeTruthy();
    }
  });

  test('three filters: what needs you, what is in use, everything', () => {
    const pick = (f: (typeof LIST_FILTERS)[number]) =>
      rows.filter((r) => matchesListFilter(r, f)).map((r) => r.name);
    expect(pick('needs_you')).toEqual([
      'new.site.example',
      'b.site.example',
      'f.site.example',
      'd.site.example',
    ]);
    expect(pick('in_use')).toEqual(['b.site.example', 'a.site.example']);
    expect(pick('all')).toHaveLength(rows.length);
    // A name members report in a country more than the others needs a look, in use or not.
    const flagged = listRows([name('r.site.example', { suspectIn: ['IR'] })], [], true);
    expect(matchesListFilter(flagged[0]!, 'needs_you')).toBe(true);
  });

  test('a list no port uses says so', () => {
    const r = listRows(
      [name('a.site.example', { delivery: { state: 'idle', inUseOn: 0, nodes: 0 } })],
      [],
      false,
    );
    expect(r[0]!.sentence).toBe('Checked. Not used by any port yet.');
  });
});

describe('the Server names page', () => {
  const summary = (o: Partial<SniFamilySummary> = {}): SniFamilySummary => ({
    id: 'f',
    slug: 'f',
    label: 'List',
    target: { kind: 'static', address: 'site.example', port: 443 },
    enabled: true,
    requireH2: false,
    network: null,
    bindings: 1,
    counts: { total: 6, ready: 6, waiting: 0, failing: 0, suspended: 0, retired: 0, burned: 0 },
    delivery: { inUse: 4, waitingTest: 2, toSend: 0, idle: 0, checking: 0, failing: 0, off: 0 },
    suggestions: 11,
    ...o,
  });
  test('the same counts as the list page, and its dot', () => {
    expect(listLine(summary())).toBe(
      '4 names in use · 2 waiting for a test · 11 suggestions · used by 1 port',
    );
    expect(
      listLine(
        summary({
          bindings: 0,
          suggestions: 0,
          delivery: {
            inUse: 0,
            waitingTest: 0,
            toSend: 0,
            idle: 0,
            checking: 0,
            failing: 0,
            off: 0,
          },
        }),
      ),
    ).toBe('No names yet · not used by any port');
    // Every name retired or burned: not an empty list.
    expect(
      listLine(
        summary({
          suggestions: 0,
          delivery: {
            inUse: 0,
            waitingTest: 0,
            toSend: 0,
            idle: 0,
            checking: 0,
            failing: 0,
            off: 3,
          },
        }),
      ),
    ).toBe('No name in use (3 retired or burned) · used by 1 port');
    expect(listDot(summary())).toBe('amber');
    expect(
      listDot(
        summary({
          delivery: {
            inUse: 4,
            waitingTest: 0,
            toSend: 0,
            idle: 0,
            checking: 0,
            failing: 0,
            off: 0,
          },
        }),
      ),
    ).toBe('green');
    expect(listDot(summary({ enabled: false }))).toBe('grey');
  });
  test('switch lines say what is true now', () => {
    expect(namesSwitchLine(true)).toMatch(/^On\./);
    expect(namesSwitchLine(false)).toMatch(/^Off\./);
    expect(autoTestSwitchLine(false, 'ready')).toMatch(/^Off\. After a send, a person tests/);
    expect(autoTestSwitchLine(true, 'ready')).toMatch(
      /^On\. After a send, FCP's own sing-box, Xray and Mihomo/,
    );
    expect(autoTestSwitchLine(true, 'not_configured')).toMatch(/not set up here/);
    expect(autoTestSwitchLine(true, 'unhealthy')).toMatch(/did not answer/);
    expect(listSwitchLine(true)).toMatch(/^On\./);
    expect(listSwitchLine(false)).toMatch(/^Off\./);
  });
});

describe('what an action on names did', () => {
  test('a busy node is said, with what to do', () => {
    expect(nameActionWords('recheck', { count: 3, relays: null })).toBe(
      '3 names checked again soon.',
    );
    expect(
      nameActionWords('retire', {
        count: 2,
        relays: { listeners: 0, retired: 0, skipped: 1, kept: 0 },
      }),
    ).toBe(
      '2 names retired. 1 node was busy and still hands them out: retire them again in a few minutes.',
    );
    expect(
      nameActionWords('retire', {
        count: 1,
        relays: { listeners: 1, retired: 0, skipped: 0, kept: 1 },
      }),
    ).toBe('1 name retired. 1 node keeps handing out its last name.');
  });
});

describe('why the checks want a look', () => {
  const v = (
    country: string,
    decision: 'suggest' | 'conflict' | 'agrees',
    suggestion: 'blocked' | 'proven',
  ) => ({
    country,
    latest: 'failing' as const,
    suggestion,
    reason: null,
    decision,
    okVantages: 0,
    okNetworks: 0,
    failVantages: 2,
    failNetworks: 2,
    pathFailures: 0,
    reportsAgree: false,
    lastAt: null,
    lastOkAt: null,
    lastRequestedAt: null,
  });
  test('a block suggestion and a disagreement are said on the row', () => {
    expect(checksWantWords(name('a.site.example'))).toBeNull();
    expect(
      checksWantWords(
        name('a.site.example', {
          vantage: [v('CN', 'conflict', 'proven'), v('IR', 'suggest', 'blocked')],
        }),
      ),
    ).toBe(
      'The checks from inside a country suggest it is blocked in IR and disagree with your mark in CN: see Details.',
    );
    expect(
      checksWantWords(name('a.site.example', { vantage: [v('CN', 'agrees', 'blocked')] })),
    ).toBeNull();
  });
});
