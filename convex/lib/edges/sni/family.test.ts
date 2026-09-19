import { describe, expect, test } from 'vitest';
import { judgeHandshake, judgeImport, planAllowlist, sameTarget, targetString } from './family';

describe('judgeImport', () => {
  test('every line gets a verdict; nothing is decided silently', () => {
    const existing = new Map([
      ['mine.example', { familyId: 'f1', status: 'active' }],
      ['theirs.example', { familyId: 'f2', status: 'active' }],
      ['dead.example', { familyId: 'f2', status: 'burned' }],
    ]);
    const out = judgeImport(
      [
        'New.Example.',
        '',
        '# a comment',
        'new.example',
        'mine.example',
        'theirs.example',
        'dead.example',
        'not a name',
      ],
      'f1',
      existing,
    );
    expect(out.map((l) => [l.name, l.verdict])).toEqual([
      ['new.example', 'added'],
      ['new.example', 'duplicate'],
      ['mine.example', 'duplicate'],
      ['theirs.example', 'in_other_family'],
      ['dead.example', 'burned'],
      [null, 'invalid'],
    ]);
  });
});

describe('judgeHandshake', () => {
  const ok = { ok: true, authorized: true, protocol: 'TLSv1.3', alpn: 'h2' };
  test('TLS 1.3 with a certificate valid for the name qualifies', () => {
    expect(judgeHandshake(ok, { requireH2: false })).toEqual({
      ok: true,
      tlsVersion: 'TLSv1.3',
      alpn: 'h2',
    });
    expect(judgeHandshake({ ...ok, alpn: 'http/1.1' }, { requireH2: false }).ok).toBe(true);
  });
  test('each way of failing has its own code word', () => {
    expect(judgeHandshake({ ...ok, authorized: false }, { requireH2: false }).code).toBe('q_cert');
    expect(judgeHandshake({ ...ok, protocol: 'TLSv1.2' }, { requireH2: false }).code).toBe(
      'q_tls12',
    );
    expect(judgeHandshake({ ...ok, alpn: 'http/1.1' }, { requireH2: true }).code).toBe('q_no_h2');
    expect(judgeHandshake({ ok: false, error: 'timeout' }, { requireH2: false }).code).toBe(
      'q_timeout',
    );
    expect(judgeHandshake({ ok: false, error: 'private_address' }, { requireH2: false }).code).toBe(
      'q_private_target',
    );
    expect(judgeHandshake({ ok: false, error: 'no_address' }, { requireH2: false }).code).toBe(
      'q_resolve',
    );
    expect(judgeHandshake({ ok: false, error: 'cert_invalid' }, { requireH2: false }).code).toBe(
      'q_cert',
    );
    expect(judgeHandshake({ ok: false, error: 'refused' }, { requireH2: false }).code).toBe(
      'q_unreachable',
    );
  });
});

describe('planAllowlist', () => {
  const fam = (n: number, over: Partial<{ status: string; qualified: boolean }> = {}) =>
    Array.from({ length: n }, (_, i) => ({
      name: `n${i}.example`,
      seq: i + 1,
      status: 'active',
      qualified: true,
      ...over,
    }));

  test('retained names stay whatever the family says; the family fills the rest in seq order', () => {
    const plan = planAllowlist(
      [{ name: 'z.example', seq: 9, status: 'active', qualified: true }, ...fam(3)],
      ['legacy.example', 'draining.example'],
    );
    expect(plan.names).toEqual([
      'legacy.example',
      'draining.example',
      'n0.example',
      'n1.example',
      'n2.example',
      'z.example',
    ]);
  });

  test('only active, qualified names are eligible', () => {
    const plan = planAllowlist(
      [
        ...fam(1),
        ...fam(1, { qualified: false }).map((n) => ({ ...n, name: 'unq.example' })),
        { name: 'burned.example', seq: 5, status: 'burned', qualified: true },
      ],
      [],
    );
    expect(plan.names).toEqual(['n0.example']);
  });

  test('the cap is over the WHOLE list, with headroom kept for the next drain', () => {
    const plan = planAllowlist(fam(600), ['a.example', 'b.example'], { max: 512, headroom: 64 });
    expect(plan.familyBudget).toBe(512 - 64 - 2);
    expect(plan.names).toHaveLength(448);
    expect(plan.overflow).toBe(600 - 446);
    // Retire one + add its replacement: both fit on the panel at once, under the cap.
    expect(plan.names.length + 1 + 1).toBeLessThanOrEqual(512);
    // Deterministic: the same inputs choose the same names for every listener.
    expect(planAllowlist(fam(600).reverse(), ['a.example', 'b.example']).names).toEqual(plan.names);
  });

  test('a name both retained and in the family is listed once', () => {
    expect(planAllowlist(fam(2), ['n0.example']).names).toEqual(['n0.example', 'n1.example']);
  });

  test('retained names alone can exhaust the budget: the family gets nothing, never a negative', () => {
    const plan = planAllowlist(
      fam(5),
      Array.from({ length: 20 }, (_, i) => `r${i}.example`),
      { max: 16, headroom: 4 },
    );
    expect(plan.familyBudget).toBe(0);
    expect(plan.names).toHaveLength(20);
    expect(plan.overflow).toBe(5);
  });
});

describe('targets', () => {
  test('spelling and comparison', () => {
    expect(targetString({ address: 'target.example', port: 443 })).toBe('target.example:443');
    expect(targetString({ address: '2001:db8::1', port: 443 })).toBe('[2001:db8::1]:443');
    expect(
      sameTarget(
        { address: 'Target.Example', port: 443 },
        { address: 'target.example', port: 443 },
      ),
    ).toBe(true);
    expect(
      sameTarget(
        { address: 'target.example', port: 8443 },
        { address: 'target.example', port: 443 },
      ),
    ).toBe(false);
    expect(sameTarget(null, { address: 'target.example', port: 443 })).toBe(false);
  });
});
