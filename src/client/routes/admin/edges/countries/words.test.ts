/**
 * The country view's words: every basis has its sentence, no copy carries an
 * em-dash or an API path, and the evidence lines say what was seen and when.
 */
import { describe, expect, it } from 'vitest';
import {
  COUNTRY_VIEW_ADDRESS_BASES,
  COUNTRY_VIEW_HANDED_REASONS,
  COUNTRY_VIEW_NAME_BASES,
} from '@shared/contracts/edgeCodes';
import type {
  CountryViewAddress,
  CountryViewHanded,
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
  out.push(
    ...W.switchNotes(
      {
        probes: false,
        countryChecks: false,
        steering: false,
        render: true,
        names: true,
        nameChecks: false,
      },
      false,
    ),
  );
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

  it('counts in words that agree', () => {
    const totals = (p: number, b: number, u: number, np: number) => ({
      addresses: { proven: p, blocked: b, unknown: u },
      names: { proven: np, blocked: 0, unknown: 2 },
      originsAtRisk: 0,
      lastEvidenceAt: null,
    });
    expect(W.totalsLine(totals(1, 1, 1, 1))).toBe(
      '1 of 3 published addresses works, 1 blocked. 1 server name works, 0 blocked, 2 not judged.',
    );
    expect(W.totalsLine(totals(0, 0, 1, 2))).toBe(
      '0 of 1 published address work, 0 blocked. 2 server names work, 0 blocked, 2 not judged.',
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
