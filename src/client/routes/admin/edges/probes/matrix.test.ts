import { describe, expect, it } from 'vitest';
import type { ProbeMatrixTarget } from '../../../../../shared/contracts/edges';
import {
  countryTally,
  familyLabel,
  groupTargets,
  matrixCell,
  parseSkipped,
  probeRequestSummary,
  skipNotes,
  targetDetail,
} from './matrix';

const target = (
  key: string,
  kind: ProbeMatrixTarget['kind'],
  byCountry: ProbeMatrixTarget['reachability']['byCountry'] = [],
): ProbeMatrixTarget => ({
  key,
  kind,
  ref: key.split(':')[1] ?? '',
  label: key,
  detail: kind === 'edge' ? 'published · upcloud' : 'x',
  enabled: true,
  reachability: { byCountry, updatedAt: null },
});

describe('groupTargets', () => {
  const all = [target('custom:c1', 'custom'), target('edge:e1', 'edge'), target('edge:e2', 'edge')];
  it('orders edges first and drops empty groups', () => {
    const g = groupTargets(all);
    expect(g.map((x) => x.kind)).toEqual(['edge', 'custom']);
    expect(g[0]?.targets.map((t) => t.key)).toEqual(['edge:e1', 'edge:e2']);
  });
  it('applies the key filter', () => {
    const g = groupTargets(all, (k) => k === 'edge:e2');
    expect(g).toHaveLength(1);
    expect(g[0]?.targets.map((t) => t.key)).toEqual(['edge:e2']);
  });
});

describe('matrixCell', () => {
  it('says "Not probed" without a row for the country', () => {
    expect(matrixCell(target('edge:e1', 'edge'), 'AA')).toMatchObject({
      probed: false,
      label: 'Not probed',
      tone: 'muted',
    });
  });
  it('puts the verdict and the extra paths in words', () => {
    const t = target('edge:e1', 'edge', [
      {
        country: 'AA',
        verdict: 'unreachable',
        v6Verdict: 'reachable',
        nameVerdict: 'mixed',
        okVantages: 0,
        failVantages: 1,
        lastAt: '2026-01-01T00:00:00.000Z',
      },
    ]);
    const c = matrixCell(t, 'AA');
    expect(c.label).toBe('Unreachable');
    expect(c.tone).toBe('danger');
    expect(c.extras).toEqual(['IPv6 reachable', 'by name mixed']);
    expect(c.vantages).toBe('0 ok, 1 failing vantage');
  });
});

describe('skipped entries', () => {
  it('maps the UDP refusal to words', () => {
    expect(parseSkipped('edge:abc: probe.udp_unsupported')).toEqual({
      key: 'edge:abc',
      code: 'probe.udp_unsupported',
      words: 'not probed (UDP)',
    });
  });
  it('never shows a bare code for an unknown reason', () => {
    const p = parseSkipped('relay:r1: probe.something_new');
    expect(p.key).toBe('relay:r1');
    expect(p.words).not.toContain('_');
    expect(p.words).not.toContain('probe.');
  });
  it('builds notes and a summary line', () => {
    const skipped = ['edge:a: probe.udp_unsupported', 'edge:b: probe.budget_exhausted'];
    expect(skipNotes(skipped)['edge:a']).toBe('not probed (UDP)');
    expect(probeRequestSummary({ runIds: ['1'], skipped })).toContain('1 probe run requested');
    expect(probeRequestSummary({ runIds: ['1', '2'], skipped: [] })).toBe('2 probe runs requested');
  });
});

describe('small labels', () => {
  it('folds vantage results per country', () => {
    const base = {
      asn: null,
      network: null,
      vantageClass: 'unknown' as const,
      rttMs: null,
      error: null,
    };
    expect(
      countryTally([
        { ...base, country: 'AA', ok: true },
        { ...base, country: 'AA', ok: false },
        { ...base, country: 'BB', ok: true },
      ]),
    ).toEqual([
      { country: 'AA', ok: 1, fail: 1 },
      { country: 'BB', ok: 1, fail: 0 },
    ]);
  });
  it('labels the address family', () => {
    expect(familyLabel(4)).toBe('IPv4');
    expect(familyLabel(null)).toBe('by name');
  });
  it('puts an edge detail in words', () => {
    expect(targetDetail({ kind: 'edge', detail: 'published · adopted' })).toContain('Imported');
    expect(targetDetail({ kind: 'custom', detail: '198.51.100.9:443' })).toBe('198.51.100.9:443');
  });
});
