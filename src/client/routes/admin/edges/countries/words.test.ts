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
import { TARGET_ADDS_FLAG_MS as SERVER_FLAG_MS } from '../../../../../../convex/lib/edges/sni/realHost';

const NOW = 1_800_000_000_000;
const H = 3_600_000;

function address(over: Partial<CountryViewAddress> = {}): CountryViewAddress {
  return {
    path: null,
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
    lists: [],
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
  onMeantFirst: 0,
  ...over,
});

const name = (over: Partial<CountryViewName> = {}): CountryViewName => ({
  lists: null,
  name: 'n.example',
  family: 'f',
  familyLabel: null,
  blockedElsewhere: [],
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
  out.push(
    ...W.switchNotes(off, { checkNamesInside: false, nameChecksRun: false }),
    ...W.switchNotes(off, { checkNamesInside: true, nameChecksRun: true }),
  );
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
      'Too few vantages there reached it to call it working. That takes one on a home network, or two others.',
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
    const capped = health('globalping', {
      cap: { used: 399, perHour: 400, perRun: 21, rounds: 4, skipped: 0 },
    });
    const leftOut = health('globalping', {
      cap: { used: 300, perHour: 400, perRun: 21, rounds: 4, skipped: 2 },
    });

    it('a country whose only source went quiet: when, and why (its cap, or failing)', () => {
      const cn = coverage([
        ['globalping', NOW - 3 * H, false],
        ['checkhost', null, false],
      ]);
      expect(W.coverageNote(cn, [capped], true, NOW)).toBe(
        'No probe has answered from here in the last 1 h: Globalping last answered 3 h ago, and its hourly cap leaves no room for another run (399 of 400 tests used in the last hour, 21 a run).',
      );
      // Left out of rounds of several runs while one run would still fit.
      expect(W.coverageNote(cn, [leftOut], true, NOW)).toBe(
        'No probe has answered from here in the last 1 h: Globalping last answered 3 h ago, and its hourly cap left it out of 2 of the 4 rounds in the last hour.',
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
    expect(W.handshakeLine(a, NOW)).toContain('no SNI got through in 2 paired checks');
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
      'Checks from inside: failed from 3 vantages on 2 networks while other SNIs got through (last 1 h ago). Failed once. It is checked again before anything is suggested.',
    );
    expect(W.reportsLine(n)).toContain('more than with its other SNIs (2.5 reports)');
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
      'Real-site check against 192.0.2.50: Its real site works and this address connects, but the handshake fails. The censor likely checks the SNI against its real address or network. 3 vantages on 2 networks, 1 h ago.',
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
          timing: null,
        },
      },
    });
    expect(W.addressRealHostLine(a, NOW)).toBe(
      'Real-site checks of 3 SNIs on it: 2 the address is blocked, 1 works, 1 h ago.',
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
    const far = {
      ms: 133,
      oursMs: 140,
      realMs: 6,
      pairs: 6,
      names: 2,
      at: NOW - H,
      flagged: true,
      addresses: { timed: 2, lowMs: 120, highMs: 140, clear: 0 },
    };
    // Every address slow: either leg may be long.
    expect(W.targetAddsLine(listener(far), NOW)).toBe(
      'A handshake on this transport’s addresses takes about 133 ms longer from here than on its SNIs’ real sites (the addresses 140 ms beyond one round trip, the SNIs’ real sites 6 ms; 6 vantages, 2 SNIs, 1 h ago). Flagged: the node sits far from its target, or every address measured sits far from the node.',
    );
    // One address under the flag: the slow ones are far from the node, and the spread is said.
    expect(
      W.targetAddsLine(
        listener({ ...far, addresses: { timed: 3, lowMs: 20, highMs: 330, clear: 1 } }),
        NOW,
      ),
    ).toBe(
      'A handshake on this transport’s addresses takes about 133 ms longer from here than on its SNIs’ real sites (the addresses 140 ms beyond one round trip, the SNIs’ real sites 6 ms; 6 vantages, 2 SNIs, 1 h ago). By address it ranges from 20 to 330 ms (see each address’s evidence). Flagged: the slow addresses sit far from the node. An address under the threshold shows the node’s own leg to its target is short.',
    );
    expect(
      W.targetAddsLine(listener({ ...far, ms: -2, flagged: false }), NOW)?.startsWith(
        'A handshake on this transport’s addresses takes no measurably longer',
      ),
    ).toBe(true);
    expect(W.TARGET_ADDS_FLAG_WORDS).not.toMatch(/—/);
    expect(W.TARGET_ADDS_FLAG_MS).toBe(SERVER_FLAG_MS);
  });

  it('says the handshake gap on one address, and which leg a flag points at', () => {
    const t = {
      ms: 330,
      oursMs: 340,
      realMs: 10,
      pairs: 3,
      names: 1,
      at: NOW - H,
      flagged: true,
      addresses: null,
    };
    const on = (kind: 'edge' | 'origin', timing: typeof t | null) =>
      address({
        kind,
        evidence: {
          ...address().evidence,
          realHost: { at: NOW - H, names: [{ name: 'a', reading: 'works' }], timing },
        },
      });
    expect(W.addressTimingLine(address(), NOW)).toBeNull();
    expect(W.addressTimingLine(on('edge', null), NOW)).toBeNull();
    expect(W.addressTimingLine(on('edge', t), NOW)).toBe(
      'A handshake on it takes about 330 ms longer from here than on the SNIs’ real sites (it 340 ms beyond one round trip, the real sites 10 ms; 3 vantages, 1 SNI, 1 h ago). Flagged: this address sits far from the node, or the node far from its target.',
    );
    expect(W.addressTimingLine(on('origin', t), NOW)).toMatch(
      /Flagged: the node sits far from its target\.$/,
    );
    expect(W.addressTimingLine(on('edge', { ...t, ms: 20, flagged: false }), NOW)).not.toMatch(
      /Flagged/,
    );
  });

  it('says what the watched lists say about an address, and how many names they hold', () => {
    expect(W.addressListsLine(address(), NOW)).toBeNull();
    expect(
      W.addressListsLine(
        address({
          lists: [{ label: 'Works', family: 'v4', state: 'listed', at: NOW - 2 * H }],
        }),
        NOW,
      ),
    ).toBe('On the list Works.');
    expect(
      W.addressListsLine(
        address({
          v6: { address: '2001:db8::1', state: null },
          lists: [
            { label: 'Works', family: 'v4', state: 'left', at: NOW - 2 * H },
            { label: 'Works', family: 'v6', state: 'not_listed', at: null },
          ],
        }),
        NOW,
      ),
    ).toBe('Left the list Works 2 h ago (IPv4); not on the list Works (IPv6).');
    expect(
      W.addressListsLine(
        address({ lists: [{ label: 'Works', family: 'v4', state: 'checking', at: null }] }),
        NOW,
      ),
    ).toBe('Not checked yet against the list Works.');
    const listener = (over: Partial<CountryViewListener>): CountryViewListener => ({
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
      targetAdds: null,
      ...over,
    });
    const allow = { allow: true, block: false, suggestion: null };
    // No list says anything about this transport: nothing to count.
    expect(
      W.namesOnListsLine(listener({ names: [name(), name({ name: 'm.example' })] })),
    ).toBeNull();
    expect(
      W.namesOnListsLine(
        listener({
          names: [
            name({ lists: allow }),
            name({ name: 'm.example' }),
            name({ name: 'old.example', status: 'retired', lists: allow }),
          ],
        }),
      ),
    ).toBe(
      '1 of 2 SNIs are on a list of what works here. Where only listed addresses and SNIs get through, only those work.',
    );
    // A watched list for here says something about the addresses: the count shows, even at 0.
    expect(
      W.namesOnListsLine(
        listener({
          addresses: [
            address({ lists: [{ label: 'Works', family: 'v4', state: 'listed', at: null }] }),
          ],
          names: [name()],
        }),
      )?.startsWith('0 of 1 SNI is on a list'),
    ).toBe(true);
    for (const w of Object.values(W.LIST_MARK_WORDS)) expect(w).not.toMatch(/—/);
  });

  it('counts in words that agree', () => {
    const totals = (p: number, b: number, u: number, np: number) => ({
      addresses: { proven: p, blocked: b, unknown: u },
      names: { proven: np, blocked: 0, unknown: 2 },
      originsAtRisk: 0,
      lastEvidenceAt: null,
    });
    expect(W.totalsLine(totals(1, 1, 1, 1))).toBe(
      '1 of 3 published addresses works, 1 blocked, 1 not known. 1 SNI works, 0 blocked, 2 not judged.',
    );
    // "0 of 1 works, 0 blocked" alone reads as a contradiction: the rest is not known.
    expect(W.totalsLine(totals(0, 0, 1, 2))).toBe(
      '0 of 1 published address work, 0 blocked, 1 not known. 2 SNIs work, 0 blocked, 2 not judged.',
    );
    expect(W.totalsLine(totals(1, 0, 0, 0))).toBe(
      '1 of 1 published address works, 0 blocked. 0 SNIs work, 0 blocked, 2 not judged.',
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

describe('locations meant for a country', () => {
  const loc = (over: Partial<Parameters<typeof W.meantForWords>[0]> = {}) => ({
    locationId: 'l1',
    accountId: 'a1',
    label: 'Place',
    provider: 'upcloud',
    grade: null,
    mark: null,
    blocked: false,
    nodes: [],
    ...over,
  });
  it('says its state here and its addresses per node', () => {
    expect(W.meantForWords(loc())).toEqual({
      state: 'Not known here yet.',
      detail: 'No node has an address in use there yet.',
    });
    expect(
      W.meantForWords(
        loc({
          blocked: true,
          grade: 'blocked',
          nodes: [{ relaySlug: 'node-a', label: null, published: 2, blocked: 2 }],
        }),
      ),
    ).toEqual({
      state:
        'Blocked here: members here get other addresses. Its addresses are graded blocked here.',
      detail: 'node-a: 2 addresses in use, 2 blocked here.',
    });
    expect(W.meantForWords(loc({ mark: 'proven' })).state).toBe('Works here. Marked working here.');
  });
  it('the handed line names the share that starts on such a location, steered only', () => {
    const steered = W.handedWords(handed({ steered: true, onMeantFirst: 0.75 }));
    expect(steered).toContain('75% of members here start on a location set for this country.');
    expect(W.handedWords(handed({ onMeantFirst: 0.75 })).join(' ')).not.toMatch(/set for/);
  });
});

describe('the whole path of an address', () => {
  it('says how far it is and how it is known; nothing without a figure', () => {
    expect(W.pathLine({ path: null }, 'IR')).toBeNull();
    expect(W.pathLine({ path: { ms: 210, measured: false } }, 'IR')).toBe(
      'About 210 ms over the whole path to the node (from the map).',
    );
    expect(W.pathLine({ path: { ms: 200, measured: true } }, 'IR')).toBe(
      `About 200 ms over the whole path to the node (timed from ${W.countryLabel('IR')} to the address, the rest from the map).`,
    );
  });
});

describe('namePoolLines', () => {
  const at = Date.parse('2026-11-05T00:00:00Z');
  const base = { at, limit: 3, needs: 3, networks: 'home_first' as const };
  it('says nothing before a batch, or where home-network probes were enough', () => {
    expect(W.namePoolLines(null)).toEqual([]);
    expect(W.namePoolLines({ ...base, mode: 'eyeball', eyeball: 30, total: 40 })).toEqual([]);
    // Any network: nothing to say about home networks.
    expect(
      W.namePoolLines({ ...base, networks: 'any', mode: 'any', eyeball: 0, total: 9 }),
    ).toEqual([]);
    // Home only with enough of them: nothing either.
    expect(
      W.namePoolLines({ ...base, networks: 'home', mode: 'eyeball', eyeball: 3, total: 9 }),
    ).toEqual([]);
  });

  it('a country topped up with data-centre probes says so', () => {
    expect(W.namePoolLines({ ...base, mode: 'topped_up', eyeball: 2, total: 9 })).toEqual([
      'Globalping has only 2 home-network probes here, fewer than the 3 vantages an SNI verdict needs, so the SNI checks here also use data-centre probes.',
    ]);
  });

  it('a country with fewer probes in all than a verdict needs says plainly that names stay not judged', () => {
    const lines = W.namePoolLines({ ...base, mode: 'any', eyeball: 0, total: 1 });
    expect(lines[0]).toMatch(/^Globalping has no home-network probe here/);
    expect(lines[0]).toMatch(/use any probe there/);
    expect(lines[1]).toMatch(
      /^Globalping has only one probe here in all and an SNI verdict needs 3 vantages/,
    );
    expect(lines[1]).toMatch(/stay not judged/);
    for (const l of lines) expect(l).not.toMatch(/—|_/);
    // The same holds under any network.
    expect(
      W.namePoolLines({ ...base, networks: 'any', mode: 'any', eyeball: 0, total: 1 }),
    ).toHaveLength(1);
  });

  it('home networks only, too few of them: says checks may not reach a verdict and how to top them up', () => {
    const lines = W.namePoolLines({
      ...base,
      networks: 'home',
      mode: 'eyeball',
      eyeball: 2,
      total: 9,
    });
    expect(lines).toEqual([
      'Globalping has only 2 home-network probes here, fewer than the 3 vantages a verdict needs. Probes come from home networks only, so checks from here may not reach a verdict. "Home networks first" in the probe settings tops them up with data centres.',
    ]);
    for (const l of lines) expect(l).not.toMatch(/—|_|names|meant for/);
  });
});

describe('switchNotes', () => {
  const on = {
    probes: true,
    countryChecks: true,
    steering: true,
    render: true,
    names: true,
    nameChecks: true,
    realHost: true,
  };
  it('a switch that is on but runs nowhere is not called off', () => {
    expect(W.switchNotes(on, { checkNamesInside: false, nameChecksRun: false })).toEqual([
      'SNIs are not checked from inside this country. Turn it on under Checks from here.',
    ]);
    expect(W.switchNotes(on, { checkNamesInside: true, nameChecksRun: false })).toEqual([
      W.NAME_CHECKS_IDLE,
    ]);
    expect(W.switchNotes(on, { checkNamesInside: true, nameChecksRun: true })).toEqual([]);
  });
});
