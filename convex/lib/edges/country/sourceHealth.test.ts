import { describe, expect, it } from 'vitest';
import { failureCode, sourceHealth, type SourceRun } from './sourceHealth';

const H = 60 * 60_000;
const NOW = 100 * H;

describe('failureCode', () => {
  it('classifies without keeping any service text', () => {
    expect(failureCode('globalping create failed: 401')).toBe('auth');
    expect(failureCode('globalping create failed: 429')).toBe('rate_limited');
    expect(failureCode('globalping get failed: 503')).toBe('service_error');
    expect(failureCode('globalping create failed: 400')).toBe('request_refused');
    expect(failureCode('check-host timeout')).toBe('timeout');
    expect(failureCode('check-host: no nodes for the requested countries')).toBe('no_vantages');
    expect(failureCode('ripe atlas key not set')).toBe('no_key');
    expect(failureCode('globalping_limit')).toBe('globalping_limit');
    expect(failureCode('something odd at 192.0.2.1')).toBe('error');
  });
});

describe('sourceHealth', () => {
  const run = (
    source: string,
    at: number,
    status: SourceRun['status'],
    results = 0,
    error?: string,
  ): SourceRun => ({
    source,
    status,
    requestedAt: at,
    finishedAt: at + 1000,
    results,
    ...(error ? { error } : {}),
  });

  it('flags a source whose recent runs all failed and that has not worked for hours', () => {
    const runs = [
      run('globalping', NOW - 3 * H, 'failed', 0, 'auth'),
      run('globalping', NOW - 2 * H, 'failed', 0, 'auth'),
      run('globalping', NOW - 1 * H, 'failed', 0, 'auth'),
      run('checkhost', NOW - 1 * H, 'finished', 6),
    ];
    const [gp, ch] = sourceHealth(['globalping', 'checkhost'], runs, NOW);
    expect(gp).toMatchObject({
      failing: true,
      streak: 3,
      lastError: 'auth',
      withEvidence: 0,
      failed: 3,
    });
    expect(ch).toMatchObject({ failing: false, streak: 0, withEvidence: 1 });
  });

  it('counts a finished run with no results as no evidence', () => {
    const runs = [1, 2, 3].map((i) => run('checkhost', NOW - i * H, 'finished', 0));
    expect(sourceHealth(['checkhost'], runs, NOW)[0]).toMatchObject({
      failing: true,
      empty: 3,
      lastError: 'no_results',
    });
  });

  it('does not flag a source that worked recently, or that only just started failing', () => {
    const recent = [
      run('globalping', NOW - 4 * H, 'finished', 5),
      run('globalping', NOW - 3 * H, 'failed'),
      run('globalping', NOW - 2 * H, 'failed'),
      run('globalping', NOW - 1 * H, 'failed'),
    ];
    expect(sourceHealth(['globalping'], recent, NOW)[0]!.failing).toBe(false);
    const two = [run('globalping', NOW - 2 * H, 'failed'), run('globalping', NOW - H, 'timeout')];
    expect(sourceHealth(['globalping'], two, NOW)[0]!.failing).toBe(false);
  });

  it('ignores runs that have not settled', () => {
    const runs = [run('globalping', NOW - H, 'running'), run('globalping', NOW - H, 'requested')];
    expect(sourceHealth(['globalping'], runs, NOW)[0]).toMatchObject({ runs: 0, failing: false });
  });
});
