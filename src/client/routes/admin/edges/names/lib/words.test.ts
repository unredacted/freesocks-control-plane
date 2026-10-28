import { describe, expect, test } from 'vitest';
import {
  CHECK_WORDS,
  WORDED_CODES,
  importWords,
  networkLine,
  NETWORK_REFRESH_WORDS,
  parseAsns,
  parseRanges,
  sniErrorWords,
  suspectWords,
  VANTAGE_REASON_WORDS,
  ago,
  vantageAppliedWords,
  vantageLine,
  vantageRequestedWords,
  vantageState,
  vantageSuggestionWords,
  vantageWantsLook,
} from './words';
import { SNI_VANTAGE_REASONS, type SniVantageRow } from '../../../../../../shared/contracts/sni';

const name = (over: Record<string, unknown> = {}) => ({
  name: 'a.example',
  seq: 1,
  status: 'active' as const,
  qualification: 'ok' as const,
  code: null,
  tlsVersion: 'TLSv1.3',
  alpn: 'h2',
  checkedAt: null,
  blockedIn: [],
  provenIn: [],
  suspectIn: [] as string[],
  probeMarkedIn: [] as string[],
  vantage: [] as SniVantageRow[],
  delivery: { state: 'in_use' as const, inUseOn: 1, nodes: 1 },
  ...over,
});
describe('networks', () => {
  const net = (over: Record<string, unknown> = {}) => ({
    id: 'n1',
    slug: 'net-a',
    label: 'Net A',
    asns: [64500],
    manualPrefixes: [] as string[],
    ranges: { v4: 3, v6: 1 },
    truncated: false,
    refreshedAt: new Date(1_000_000).toISOString(),
    refreshError: null as string | null,
    families: [{ slug: 'fam-a', label: 'Family A' }],
    locations: [] as { id: string; label: string; provider: string; source: 'operator' }[],
    ...over,
  });
  test('a network in one line', () => {
    expect(networkLine(net(), 1_000_000)).toBe(
      'AS64500 · 4 ranges · read today · 1 name list on it',
    );
    expect(
      networkLine(
        net({ refreshError: 'timeout', families: [], ranges: { v4: 0, v6: 0 }, truncated: true }),
        1_000_000,
      ),
    ).toBe(
      'AS64500 · no ranges yet · the last read failed (no answer in time) · no name list on it',
    );
    expect(
      networkLine(net({ asns: [], manualPrefixes: ['192.0.2.0/24'], refreshedAt: null })),
    ).toBe('4 ranges · 1 by hand · 1 name list on it');
  });
  test('every refresh failure the server records has words', async () => {
    const src = import.meta.glob('../../../../../../../convex/lib/edges/networks.ts', {
      query: '?raw',
      import: 'default',
      eager: true,
    }) as Record<string, string>;
    const codes = new Set<string>();
    for (const text of Object.values(src)) {
      const list = /NETWORK_REFRESH_ERRORS = \[([^\]]*)\]/.exec(text)?.[1] ?? '';
      for (const m of list.matchAll(/'([a-z_]+)'/g)) codes.add(m[1]!);
    }
    expect(codes.size).toBeGreaterThan(3);
    expect([...codes].filter((c) => !NETWORK_REFRESH_WORDS[c])).toEqual([]);
  });
  test('typed ASNs and ranges', () => {
    expect(parseAsns('AS64500 64501, as64502 64500')).toEqual([64500, 64501, 64502]);
    expect(parseAsns('')).toEqual([]);
    expect(parseAsns('AS-1')).toBeNull();
    expect(parseAsns('1 2 3 4 5 6 7 8 9')).toBeNull();
    expect(parseRanges('192.0.2.0/24\n2001:db8::/32')).toEqual(['192.0.2.0/24', '2001:db8::/32']);
    expect(parseRanges('192.0.2.0')).toBeNull();
    expect(parseRanges('not/24')).toBeNull();
  });
});

describe('names', () => {
  test('every check code the server can record has words', async () => {
    const src = import.meta.glob('../../../../../../../convex/lib/edges/sni/family.ts', {
      query: '?raw',
      import: 'default',
      eager: true,
    }) as Record<string, string>;
    const codes = new Set<string>();
    for (const text of Object.values(src))
      for (const m of text.matchAll(/'(q_[a-z0-9_]+)'/g)) codes.add(m[1]!);
    expect(codes.size).toBeGreaterThan(4);
    expect([...codes].filter((c) => !CHECK_WORDS[c])).toEqual([]);
  });

  test('a report hint names the countries and only suggests', () => {
    expect(suspectWords(['IR', 'CN'])).toMatch(/^Members in IR, CN report/);
  });

  test('an import says what happened to every kind of line', () => {
    const words = importWords({
      added: 2,
      lines: [
        { input: 'a.example', name: 'a.example', verdict: 'added' },
        { input: 'b.example', name: 'b.example', verdict: 'added' },
        { input: 'a.example', name: 'a.example', verdict: 'duplicate' },
        { input: 'x y', name: null, verdict: 'invalid' },
        { input: 'c.example', name: 'c.example', verdict: 'burned' },
        { input: 'd.example', name: 'd.example', verdict: 'in_other_family' },
      ],
    });
    expect(words).toHaveLength(5);
    expect(words[0]).toMatch(/^2 names added/);
  });
});

describe('checks from inside a country', () => {
  const NOW = Date.parse('2026-10-16T12:00:00Z');
  const row = (over: Partial<SniVantageRow> = {}): SniVantageRow => ({
    country: 'IR',
    latest: 'ok',
    suggestion: null,
    reason: null,
    decision: 'none',
    okVantages: 4,
    okNetworks: 3,
    failVantages: 0,
    failNetworks: 0,
    pathFailures: 0,
    reportsAgree: false,
    lastAt: '2026-10-14T09:00:00Z',
    lastOkAt: '2026-10-14T09:00:00Z',
    lastRequestedAt: '2026-10-14T08:59:00Z',
    ...over,
  });

  test('what was seen, separately from what it suggests', () => {
    expect(ago(null, NOW)).toBe('never');
    expect(ago('2026-10-16T01:00:00Z', NOW)).toBe('today');
    expect(ago('2026-10-15T01:00:00Z', NOW)).toBe('yesterday');
    expect(vantageLine(row(), NOW)).toBe(
      'From IR: the handshake completed from 4 vantages on 3 networks (last checked 2 days ago).',
    );
    expect(vantageLine(row({ latest: 'failing', failVantages: 3, failNetworks: 2 }), NOW)).toMatch(
      /^From IR: failed from 3 vantages on 2 networks while other names got through/,
    );
    // Every name of the address failed: that is the address, said as such.
    expect(vantageLine(row({ latest: 'failing', failVantages: 0 }), NOW)).toMatch(
      /no name of that address got through/,
    );
    expect(vantageLine(row({ latest: 'none', lastAt: null }), NOW)).toMatch(/first check/);
  });

  test('a suggestion never reads as a verdict, and a conflict names the operator', () => {
    expect(vantageSuggestionWords(row({ suggestion: 'proven', decision: 'suggest' }))).toBe(
      'The checks suggest it works in IR.',
    );
    expect(vantageSuggestionWords(row({ suggestion: 'blocked', decision: 'suggest' }))).toBe(
      'The checks suggest it is blocked in IR.',
    );
    expect(vantageSuggestionWords(row({ suggestion: 'blocked', decision: 'conflict' }))).toMatch(
      /disagree with the mark an operator set/,
    );
    expect(vantageSuggestionWords(row({ suggestion: 'proven', decision: 'agrees' }))).toBeNull();
    expect(vantageSuggestionWords(row({ reason: 'needs_repeat' }))).toMatch(/checked again/);
  });

  test('every reason the scoring can give has words', () => {
    for (const r of SNI_VANTAGE_REASONS) expect(VANTAGE_REASON_WORDS[r]).toBeTruthy();
    for (const w of Object.values(VANTAGE_REASON_WORDS)) expect(w).not.toMatch(/—|_/);
  });

  test('a block suggestion or a conflict wants a look', () => {
    const blocked = name({ vantage: [row({ suggestion: 'blocked', decision: 'suggest' })] });
    const conflict = name({ vantage: [row({ suggestion: 'proven', decision: 'conflict' })] });
    const fine = name({ vantage: [row({ suggestion: 'proven', decision: 'suggest' })] });
    expect(vantageWantsLook(blocked)).toBe(true);
    expect(vantageWantsLook(conflict)).toBe(true);
    expect(vantageWantsLook(fine)).toBe(false);
  });

  test('the switch says what runs right now', () => {
    expect(vantageState(false, true, ['IR'])).toMatch(/Server names are off/);
    expect(vantageState(true, true, [])).toMatch(/until at least one country/);
    expect(vantageState(true, false, ['IR', 'RU'])).toBe('Off. Turned on, it checks from IR, RU.');
    expect(vantageState(true, true, ['IR'])).toBe('Checking from IR.');
  });

  test('what a button did', () => {
    expect(vantageRequestedWords({ batches: 1, measurements: 3, skipped: 0 })).toBe(
      '3 checks started. Results arrive in a few minutes.',
    );
    expect(vantageAppliedWords({ proven: 2, blocked: 1, skipped: 1 })).toBe(
      '2 names marked as working, 1 name marked as blocked. 1 name left unchanged.',
    );
    expect(vantageAppliedWords({ proven: 0, blocked: 0, skipped: 2 })).toMatch(/^Nothing to apply/);
  });
});

describe('refusals', () => {
  test('every edge.sni refusal the server can answer has its own words', () => {
    const sources = import.meta.glob(['../../../../../../../convex/sni*.ts', '!**/*.test.ts'], {
      query: '?raw',
      import: 'default',
      eager: true,
    }) as Record<string, string>;
    const codes = new Set<string>();
    for (const text of Object.values(sources))
      for (const m of text.matchAll(/refuse\(\s*'(edge\.sni\.[a-z_.]+)'/g)) codes.add(m[1]!);
    expect(codes.size).toBeGreaterThan(5);
    expect([...codes].filter((c) => !WORDED_CODES.includes(c))).toEqual([]);
  });

  test('no em-dashes and no codes in the copy', () => {
    for (const code of WORDED_CODES) expect(sniErrorWords(code)).not.toMatch(/—|edge\.|servers\./);
    for (const w of Object.values(CHECK_WORDS)) expect(w).not.toMatch(/—|q_/);
  });
});
