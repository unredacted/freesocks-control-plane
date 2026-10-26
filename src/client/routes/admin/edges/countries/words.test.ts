/**
 * The country view's words: every basis has its sentence, no copy carries an
 * em-dash or an API path, and the evidence lines say what was seen and when.
 */
import { describe, expect, it } from 'vitest';
import {
  COUNTRY_VIEW_ADDRESS_BASES,
  COUNTRY_VIEW_HANDED_REASONS,
  COUNTRY_VIEW_NAME_BASES,
  REAL_HOST_READINGS,
} from '@shared/contracts/edgeCodes';
import type {
  CountryViewAddress,
  CountryViewHanded,
  CountryViewListener,
  CountryViewName,
} from '@shared/contracts/edges';
import * as W from './words';

const NOW = 1_800_000_000_000;
const H = 3_600_000;

function address(over: Partial<CountryViewAddress> = {}): CountryViewAddress {
  return {
    edgeId: 'e1',
    kind: 'edge',
    layer: 'l4',
    provider: 'p',
    location: 'L',
    publication: 'published',
    poolIndex: 0,
    address: '198.51.100.1',
    v6: null,
    state: 'unknown',
    basis: 'none',
    until: null,
    evidence: {
      mark: null,
      grade: null,
      address: null,
      handshake: null,
      round: null,
      probes: null,
      answers: [],
      realHost: null,
    },
    handed: { primary: 0, backup: 0 },
    ...over,
  };
}

const handed = (over: Partial<CountryViewHanded> = {}): CountryViewHanded => ({
  computed: true,
  reason: null,
  steered: false,
  namesByCountry: false,
  sample: 240,
  primary: [
    { id: 'a', share: 0.5 },
    { id: 'b', share: 0.5 },
  ],
  backup: [],
  names: [],
  none: 0,
  onBlockedAddress: 1,
  onBlockedFirst: 0.5,
  onBlockedName: 0,
  ...over,
});

const name = (over: Partial<CountryViewName> = {}): CountryViewName => ({
  name: 'n.example',
  family: 'f',
  status: 'active',
  drainUntil: null,
  qualified: true,
  state: 'unknown',
  basis: 'none',
  markAt: null,
  offered: true,
  checks: null,
  reports: null,
  realHost: null,
  handed: 0,
  ...over,
});

/** Every string the module can produce from a spread of inputs. */
function everyString(): string[] {
  const out: string[] = [
    ...Object.values(W.ADDRESS_BASIS_WORDS),
    ...Object.values(W.NAME_BASIS_WORDS),
    ...Object.values(W.STATE_WORDS).map((s) => s.label),
  ];
  for (const reason of COUNTRY_VIEW_HANDED_REASONS)
    out.push(...W.handedWords(handed({ computed: false, reason })));
  out.push(
    ...W.handedWords(
      handed({ steered: true, namesByCountry: true, onBlockedName: 0.2, none: 0.1 }),
    ),
  );
  out.push(W.HANDED_SCOPE, W.untilLine(NOW + H, NOW)!, W.untilLine(NOW - 1, NOW)!);
  const off = {
    probes: false,
    countryChecks: false,
    steering: false,
    render: true,
    names: true,
    nameChecks: false,
    realHost: false,
  };
  out.push(...W.switchNotes(off, false), ...W.switchNotes(off, true));
  for (const w of Object.values(W.REAL_HOST_WORDS)) out.push(w.short, w.sentence);
  return out;
}

describe('country view words', () => {
  it('has a sentence for every basis and every reason the server sends', () => {
    for (const b of COUNTRY_VIEW_ADDRESS_BASES) expect(W.ADDRESS_BASIS_WORDS[b]).toMatch(/\.$/);
    for (const b of COUNTRY_VIEW_NAME_BASES) expect(W.NAME_BASIS_WORDS[b]).toMatch(/\.$/);
    for (const reason of COUNTRY_VIEW_HANDED_REASONS)
      expect(W.handedWords(handed({ computed: false, reason }))[0]).toMatch(/\.$/);
  });

  it('never uses an em-dash or names an API path', () => {
    for (const s of everyString()) {
      expect(s).not.toMatch(/—/);
      expect(s).not.toMatch(/\/api\//);
    }
  });

  it('tells a probes-only block from a broken address', () => {
    const blocked = address({
      state: 'blocked',
      basis: 'probes',
      evidence: {
        ...address().evidence,
        probes: {
          country: 'IR',
          verdict: 'unreachable',
          okVantages: 0,
          failVantages: 3,
          lastAt: NOW - H,
        },
      },
    });
    expect(W.addressWhy(blocked)).toContain('while other countries reached it');
    const broken = address({ ...blocked, state: 'unknown' });
    expect(W.addressWhy(broken)).toContain('broken, not blocked');
    expect(W.probesLine(blocked, NOW)).toBe(
      'Probes could not reach it (0 vantages reached it, 3 failed), 1 h ago.',
    );
  });

  it('says why the probes alone decided nothing: too few vantages, or mixed answers', () => {
    const probes = (verdict: 'unknown' | 'mixed', ok: number, fail: number) =>
      address({
        basis: 'probes',
        evidence: {
          ...address().evidence,
          probes: {
            country: 'KZ',
            verdict,
            okVantages: ok,
            failVantages: fail,
            lastAt: NOW - H,
          },
        },
      });
    // One datacenter vantage reached it: not enough to call it working.
    expect(W.addressWhy(probes('unknown', 1, 0))).toContain(
      'Too few vantages there reached it to call it working: that takes one on a residential network, or two others.',
    );
    expect(W.addressWhy(probes('unknown', 0, 1))).toContain(
      'from too few networks to call it blocked',
    );
    expect(W.addressWhy(probes('mixed', 1, 2))).toContain(
      'Some vantages there reached it and some did not',
    );
  });

  it('an address whose probe answers from there aged out says so, not "nothing checked it"', () => {
    const aged = address({
      evidence: {
        ...address().evidence,
        answers: [
          { source: 'globalping', lastAt: NOW - 2 * H, fresh: false },
          { source: 'checkhost', lastAt: null, fresh: false },
        ],
      },
    });
    expect(W.addressWhy(aged)).toBe(
      'No probe answer about it from there is recent enough to count.',
    );
    expect(W.staleAnswersLine(aged, NOW)).toBe(
      'Globalping last answered about it from here 2 h ago, too long ago to count.',
    );
    expect(W.addressWhy(address())).toBe('Nothing has checked it from there yet.');
    expect(W.staleAnswersLine(address(), NOW)).toBeNull();
    // While its summary still holds the country, the probes line says it with its age:
    // no second line claiming the same answer no longer counts.
    const held = address({
      ...aged,
      basis: 'probes',
      state: 'proven',
      evidence: {
        ...aged.evidence,
        probes: {
          country: 'CN',
          verdict: 'reachable',
          okVantages: 3,
          failVantages: 0,
          lastAt: NOW - 2 * H,
        },
      },
    });
    expect(W.staleAnswersLine(held, NOW)).toBeNull();
  });

  describe('which outside probes answer from there', () => {
    const MIN = 60_000;
    const coverage = (
      sources: Array<[string, number | null, boolean]>,
      asked = true,
    ): Parameters<typeof W.coverageNote>[0] => ({
      asked,
      windowMs: 60 * MIN,
      sources: sources.map(([source, lastAt, fresh]) => ({ source, lastAt, fresh })),
    });
    const health = (source: string, over = {}) => ({
      source,
      runs: 10,
      withEvidence: 10,
      failed: 0,
      empty: 0,
      streak: 0,
      lastOkAt: null,
      lastFailAt: null,
      lastError: null,
      failing: false,
      cap: null,
      ...over,
    });
    const capped = health('globalping', { cap: { used: 399, perHour: 400, perRun: 21 } });

    it('a country whose only source went quiet: when, and why (its cap, or failing)', () => {
      const cn = coverage([
        ['globalping', NOW - 3 * H, false],
        ['checkhost', null, false],
      ]);
      expect(W.coverageNote(cn, [capped], true, NOW)).toBe(
        'No probe has answered from here in the last 1 h: Globalping last answered 3 h ago, and its hourly cap leaves no room for another run (399 of 400 tests used in the last hour, 21 a run).',
      );
      const failing = health('globalping', { failing: true, lastError: 'auth', streak: 4 });
      expect(W.coverageNote(cn, [failing], true, NOW)).toBe(
        'No probe has answered from here in the last 1 h: Globalping last answered 3 h ago, and it is failing (credential refused).',
      );
      expect(W.coverageLines(cn, [capped], true, NOW)).toEqual([
        'No probe has answered from here in the last 1 h, so the probes judge nothing here.',
        'Globalping last answered 3 h ago, and its hourly cap leaves no room for another run (399 of 400 tests used in the last hour, 21 a run); an answer counts for 1 h.',
        'check-host.net has never answered from here: it may have no vantage here.',
      ]);
    });

    it('a country another source still answers from: only it, and what went quiet', () => {
      const kz = coverage([
        ['globalping', NOW - 3 * H, false],
        ['checkhost', NOW - 13 * MIN, true],
      ]);
      expect(W.coverageNote(kz, [], true, NOW)).toBe(
        'Only check-host.net answers from here now: Globalping last answered 3 h ago.',
      );
      expect(W.coverageLines(kz, [], true, NOW)[0]).toBe(
        'Answering from here: check-host.net (13 min ago).',
      );
    });

    it('nothing to flag when every source that answered from there still does', () => {
      const cn = coverage([
        ['globalping', NOW - 5 * MIN, true],
        ['checkhost', null, false],
      ]);
      expect(W.coverageNote(cn, [capped], true, NOW)).toBeNull();
      const both = coverage([
        ['globalping', NOW - 5 * MIN, true],
        ['checkhost', NOW - 7 * MIN, true],
      ]);
      expect(W.coverageLines(both, [], true, NOW)).toEqual([
        'Answering from here: Globalping (5 min ago) and check-host.net (7 min ago).',
      ]);
    });

    it('a country not asked, one nobody answers from, and probes off', () => {
      const mm = coverage([['globalping', null, false]], false);
      expect(W.coverageNote(mm, [], true, NOW)).toBe('Edges are not checked from here.');
      expect(W.coverageLines(mm, [], true, NOW)[0]).toContain(
        '"Check edges from here" is off for this country',
      );
      const by = coverage([
        ['globalping', null, false],
        ['checkhost', null, false],
      ]);
      expect(W.coverageNote(by, [], true, NOW)).toBe(
        'No probe has answered from here yet: the sources in use may have no vantage here.',
      );
      expect(W.coverageNote(coverage([]), [], true, NOW)).toBe(
        'No outside probe source is in use.',
      );
      // Probes off: the page says so once (switchNotes), not per country.
      expect(W.coverageNote(by, [], false, NOW)).toBeNull();
      expect(W.coverageLines(by, [], false, NOW)).toEqual([]);
    });

    it('never an em-dash', () => {
      const all = [
        coverage([['globalping', NOW - 3 * H, false]]),
        coverage([['globalping', null, false]], false),
        coverage([
          ['globalping', NOW - 3 * H, false],
          ['checkhost', NOW, true],
        ]),
      ];
      for (const c of all) {
        expect(W.coverageNote(c, [capped], true, NOW) ?? '').not.toMatch(/—/);
        for (const l of W.coverageLines(c, [capped], true, NOW)) expect(l).not.toMatch(/—/);
      }
    });
  });

  it('words the round, the mark, the location and the handshake track with their age', () => {
    const a = address({
      evidence: {
        ...address().evidence,
        grade: { state: 'blocked', counts: { edges: 3, proven: 0, blocked: 2 }, until: NOW + H },
        mark: { state: 'blocked', at: NOW - 2 * H, scope: 'location' },
        round: { at: NOW - H, result: 'blocked', ok: 0, fail: 3, networks: 2, controlsOk: 2 },
        handshake: { state: 'blocked', lastBatchAt: NOW - H, batches: 2 },
      },
    });
    expect(W.markLine(a, NOW)).toBe(
      'An operator marked its provider location blocked here, 2 h ago.',
    );
    expect(W.gradeLine(a, NOW)).toBe(
      'Its provider location here: blocked, 2 of 3 addresses blocked and 0 working, for another 1 h.',
    );
    expect(W.gradeLine(address(), NOW)).toBeNull();
    expect(W.roundLine(a, NOW)).toBe(
      'Last round: blocked, 0 reached and 3 failed on 2 networks, 2 controls reached it, 1 h ago.',
    );
    expect(W.handshakeLine(a, NOW)).toContain('no name got through in 2 paired checks');
  });

  it('words what the checks from inside and member reports say about a name', () => {
    const n = name({
      checks: {
        latest: 'failing',
        okVantages: 0,
        okNetworks: 0,
        failVantages: 3,
        failNetworks: 2,
        pathFailures: 0,
        suggestion: null,
        reason: 'needs_repeat',
        lastAt: NOW - H,
        lastOkAt: null,
      },
      reports: { weight: 2.5, suspect: true },
    });
    expect(W.checksLine(n, NOW)).toBe(
      'Checks from inside: failed from 3 vantages on 2 networks while other names got through (last 1 h ago). It failed once. It is checked again before anything is suggested.',
    );
    expect(W.reportsLine(n)).toContain('more than with its other names (2.5 reports)');
  });

  it('says what a member is handed, steered or not', () => {
    expect(W.handedWords(handed())[0]).toContain('not chosen by country');
    expect(W.handedWords(handed())[1]).toBe(
      '100% of members here hold an address blocked here (50% as their first one).',
    );
    expect(W.handedWords(handed({ onBlockedFirst: 0 }))[1]).toBe(
      '100% of members here hold an address blocked here, as their backup only.',
    );
    expect(W.handedWords(handed({ steered: true, onBlockedAddress: 0 }))[0]).toContain(
      'chosen for this country',
    );
  });

  it('has words for every real-host reading, and reads a name and an address', () => {
    for (const r of REAL_HOST_READINGS) expect(W.REAL_HOST_WORDS[r].sentence).toMatch(/\.$/);
    const n = name({
      realHost: {
        at: NOW - H,
        target: 'edge:e1:198.51.100.1:443',
        realAddress: '192.0.2.50',
        reading: 'ip_name_match',
        counts: {
          works: 0,
          nameBlocked: 0,
          addressBlocked: 0,
          ipNameMatch: 3,
          oursOnly: 0,
          inconclusive: 0,
        },
        vantages: 3,
        networks: 2,
        timing: null,
      },
    });
    expect(W.realHostLine(n, NOW)).toBe(
      'Real-site check against 192.0.2.50: Its real site works from the same vantages, and this address connects, but the handshake with the name fails: the censor likely checks the name against its real address or network. 3 vantages on 2 networks, 1 h ago.',
    );
    expect(W.realHostLine(name(), NOW)).toBeNull();
    const timed = name({
      realHost: {
        ...n.realHost!,
        reading: 'works',
        timing: { pairs: 3, oursMs: 140, realMs: 6, addsMs: 133 },
      },
    });
    expect(W.realHostLine(timed, NOW)).toContain(
      'Beyond one round trip, its handshake took 140 ms on this address and 6 ms on the real site (3 vantages).',
    );
    const a = address({
      evidence: {
        ...address().evidence,
        realHost: {
          at: NOW - H,
          names: [
            { name: 'a', reading: 'address_blocked' },
            { name: 'b', reading: 'address_blocked' },
            { name: 'c', reading: 'works' },
          ],
        },
      },
    });
    expect(W.addressRealHostLine(a, NOW)).toBe(
      'Real-site checks of 3 names on it: 2 the address is blocked, 1 works, 1 h ago.',
    );
  });

  it('says what a transport’s target adds, and flags a large gap', () => {
    const listener = (targetAdds: CountryViewListener['targetAdds']): CountryViewListener => ({
      listenerId: 'L',
      key: 'a',
      protocol: 'vless',
      streamTransport: 'raw',
      security: 'reality',
      usable: true,
      addresses: [],
      names: [],
      members: handed(),
      openMembers: null,
      targetAdds,
    });
    expect(W.targetAddsLine(listener(null), NOW)).toBeNull();
    const far = { ms: 133, oursMs: 140, realMs: 6, pairs: 6, names: 2, at: NOW - H, flagged: true };
    expect(W.targetAddsLine(listener(far), NOW)).toBe(
      'The transport’s target adds about 133 ms to a handshake from here (this address 140 ms beyond one round trip, the names’ real sites 6 ms; 6 vantages, 2 names, 1 h ago). Flagged: the target sits far from the node.',
    );
    expect(
      W.targetAddsLine(listener({ ...far, ms: -2, flagged: false }), NOW)?.startsWith(
        'The transport’s target adds nothing measurable',
      ),
    ).toBe(true);
    expect(W.TARGET_ADDS_FLAG_WORDS).not.toMatch(/—/);
  });

  it('counts in words that agree', () => {
    const totals = (p: number, b: number, u: number, np: number) => ({
      addresses: { proven: p, blocked: b, unknown: u },
      names: { proven: np, blocked: 0, unknown: 2 },
      originsAtRisk: 0,
      lastEvidenceAt: null,
    });
    expect(W.totalsLine(totals(1, 1, 1, 1))).toBe(
      '1 of 3 published addresses works, 1 blocked, 1 not known. 1 server name works, 0 blocked, 2 not judged.',
    );
    // "0 of 1 works, 0 blocked" alone reads as a contradiction: the rest is not known.
    expect(W.totalsLine(totals(0, 0, 1, 2))).toBe(
      '0 of 1 published address work, 0 blocked, 1 not known. 2 server names work, 0 blocked, 2 not judged.',
    );
    expect(W.totalsLine(totals(1, 0, 0, 0))).toBe(
      '1 of 1 published address works, 0 blocked. 0 server names work, 0 blocked, 2 not judged.',
    );
    expect(W.handedWords(handed({ primary: [{ id: 'a', share: 1 }] }))[0]).toContain(
      'spread over 1 address,',
    );
    expect(W.handedWords(handed())[0]).toContain('spread over 2 addresses,');
    expect(W.untilLine(NOW + 26 * H, NOW)).toBe('Stands for another 1 d 2 h.');
    expect(W.untilLine(null, NOW)).toBeNull();
  });

  it('formats shares and countries', () => {
    expect(W.percent(0)).toBe('0%');
    expect(W.percent(0.004)).toBe('under 1%');
    expect(W.percent(0.4167)).toBe('42%');
    expect(W.countryLabel('IR')).toBe('Iran (IR)');
    expect(
      W.countryDot({
        addresses: { proven: 1, blocked: 1, unknown: 0 },
        names: { proven: 0, blocked: 0, unknown: 0 },
        originsAtRisk: 0,
        lastEvidenceAt: null,
      }),
    ).toBe('amber');
  });
});
