import { describe, expect, test } from 'vitest';
import {
  CHECK_WORDS,
  WORDED_CODES,
  familyDot,
  familyLine,
  importWords,
  matchesFilter,
  nameWords,
  nodeLine,
  planWords,
  rolloutWords,
  sniErrorWords,
} from './words';

const family = (over: Record<string, unknown> = {}, counts: Record<string, number> = {}) => ({
  id: 'f1',
  slug: 'fam-a',
  label: 'Family A',
  target: { kind: 'static', address: 'target.example', port: 443 },
  enabled: true,
  requireH2: false,
  bindings: 1,
  counts: {
    total: 3,
    ready: 3,
    waiting: 0,
    failing: 0,
    suspended: 0,
    retired: 0,
    burned: 0,
    ...counts,
  },
  ...over,
});
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
  ...over,
});
const status = (over: Record<string, unknown> = {}) => ({
  id: 'r1',
  generation: 2,
  phase: 'panel_confirmed' as const,
  errorCode: null,
  added: 2,
  removed: 0,
  hasWitness: true,
  nodes: [
    {
      relaySlug: 'relay-a',
      listenerKey: 'reality',
      edges: [],
      proven: 1,
      pending: 2,
      generationProven: false,
    },
  ],
  ...over,
});

describe('families', () => {
  test('a family in one line, and its dot', () => {
    expect(familyLine(family())).toBe('3 names ready · used by 1 inbound');
    expect(familyLine(family({ bindings: 0 }, { ready: 1, waiting: 2, failing: 1 }))).toBe(
      '1 name ready · 2 waiting for a check · 1 failing · not used by any inbound',
    );
    expect(familyDot(family())).toBe('green');
    expect(familyDot(family({}, { failing: 1 }))).toBe('amber');
    expect(familyDot(family({}, { ready: 0 }))).toBe('red');
    expect(familyDot(family({ enabled: false }))).toBe('grey');
  });
});

describe('names', () => {
  test('the three facts are never blurred: a checked name says only that the target serves it', () => {
    expect(nameWords(name()).sentence).toBe('The target site serves this name.');
    expect(nameWords(name({ qualification: 'pending' })).dot).toBe('grey');
    expect(nameWords(name({ qualification: 'failed', code: 'q_tls12' })).sentence).toMatch(
      /TLS 1.3/,
    );
    expect(nameWords(name({ status: 'suspended', code: 'q_cert' })).sentence).toMatch(
      /^Suspended.*certificate/,
    );
    expect(nameWords(name({ status: 'burned' })).dot).toBe('red');
  });

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

  test('filters', () => {
    expect(matchesFilter(name(), 'ready')).toBe(true);
    expect(matchesFilter(name({ qualification: 'failed' }), 'problems')).toBe(true);
    expect(matchesFilter(name({ status: 'suspended' }), 'problems')).toBe(true);
    expect(matchesFilter(name({ status: 'burned' }), 'problems')).toBe(false);
    expect(matchesFilter(name({ status: 'burned' }), 'off')).toBe(true);
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

describe('rollouts', () => {
  const plan = (over: Record<string, unknown> = {}) => ({
    inboundTag: 'reality-in',
    generation: 2,
    names: ['a.example', 'b.example'],
    added: ['b.example'],
    removed: [],
    witness: 'b.example' as string | null,
    overflow: 0,
    changed: true,
    ...over,
  });

  test('the plan says whether one test proves everything', () => {
    expect(planWords(plan()).join(' ')).toMatch(/One test per node will prove all/);
    expect(planWords(plan({ witness: null })).join(' ')).toMatch(/each has to be tested by itself/);
    expect(planWords(plan({ changed: false, added: [] }))).toHaveLength(1);
    expect(planWords(plan({ overflow: 3 })).join(' ')).toMatch(/3 ready names will wait/);
  });

  test('being on the panel is not being given to members', () => {
    expect(rolloutWords(status()).sentence).toMatch(/until that node has proven it/);
    expect(rolloutWords(status()).dot).toBe('amber');
    const proven = status({
      nodes: [
        {
          relaySlug: 'r',
          listenerKey: 'k',
          edges: [],
          proven: 3,
          pending: 0,
          generationProven: true,
        },
      ],
    });
    expect(rolloutWords(proven).dot).toBe('green');
    expect(rolloutWords(status({ phase: 'failed' })).dot).toBe('red');
    expect(nodeLine(status().nodes[0]!)).toBe('1 proven, 2 waiting for a test');
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
      for (const m of text.matchAll(/refuse\(\s*'(edge\.sni\.[a-z_]+)'/g)) codes.add(m[1]!);
    expect(codes.size).toBeGreaterThan(5);
    expect([...codes].filter((c) => !WORDED_CODES.includes(c))).toEqual([]);
  });

  test('no em-dashes and no codes in the copy', () => {
    for (const code of WORDED_CODES) expect(sniErrorWords(code)).not.toMatch(/—|edge\.|servers\./);
    for (const w of Object.values(CHECK_WORDS)) expect(w).not.toMatch(/—|q_/);
  });
});
