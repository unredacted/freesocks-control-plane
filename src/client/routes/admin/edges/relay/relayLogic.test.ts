import { describe, expect, it } from 'vitest';
import type { EdgeAdmin } from '@shared/contracts/edges';
import {
  REASON_MAX,
  highlightedColumn,
  justificationText,
  recommendKeep,
  relayProbeTargetKeys,
  replaceAutoWords,
  rotationDurationMs,
  rotationOutcomeWords,
  suspicionChip,
  timelineLinkParams,
  tupleLine,
  type QuarantineListener,
} from './relayLogic';

describe('suspicionChip', () => {
  const base = {
    state: 'suspected' as const,
    hintLevel: 'corroborated' as const,
    score: 1,
    reportScore: 0,
    loadScore: 0,
    probeScore: 0,
    scope: 'regional' as const,
    countries: [{ code: 'AA', count: 3 }],
    edgeEvidence: [],
    firstSeenAt: null,
    lastEvalAt: '2026-01-01T00:00:00.000Z',
    quietEvals: 0,
    baselineWarm: true,
    veto: null,
  };
  it('says nothing for a clear origin or no data', () => {
    expect(suspicionChip(null)).toBeNull();
    expect(suspicionChip({ ...base, state: 'clear' })).toBeNull();
  });
  it('names the region, and a veto in words', () => {
    expect(suspicionChip(base)).toMatchObject({ tone: 'danger', label: 'Block suspected in AA' });
    const held = suspicionChip({ ...base, veto: 'node_offline' });
    expect(held?.tone).toBe('warning');
    expect(held?.label).toContain('Node offline');
    expect(held?.label).not.toContain('node_offline');
  });
});

const ql = (listenerKey: string, match: QuarantineListener['match']): QuarantineListener => ({
  listenerKey,
  remark: null,
  previous: null,
  current: null,
  live: null,
  match,
});

describe('quarantine helpers', () => {
  it('formats tuples', () => {
    const t = { address: '198.51.100.7', port: 443, sni: 'a.example', host: null };
    expect(tupleLine(t)).toBe('198.51.100.7:443');
    expect(tupleLine(null)).toBe('');
  });
  it('highlights only a recorded binding', () => {
    expect(highlightedColumn('previous')).toBe('previous');
    expect(highlightedColumn('current')).toBe('current');
    for (const m of ['neither', 'absent', 'unknown'] as const)
      expect(highlightedColumn(m)).toBeNull();
  });
  it('recommends only a unanimous binding', () => {
    expect(recommendKeep([ql('a', 'current'), ql('b', 'current')])).toBe('current');
    expect(recommendKeep([ql('a', 'current'), ql('b', 'previous')])).toBeNull();
    expect(recommendKeep([ql('a', 'unknown')])).toBeNull();
    expect(recommendKeep([])).toBeNull();
  });
  it('writes a justification that fits the server limit and carries no em-dash', () => {
    const at = '2026-09-18T10:11:12.000Z';
    const ok = justificationText({
      keep: 'current',
      listeners: [ql('a', 'current')],
      inspectedAt: at,
    });
    expect(ok).toContain('Keep current');
    expect(ok).toContain('a');
    expect(ok).toContain('2026-09-18T10:11');
    expect(justificationText({ keep: 'previous', listeners: [], inspectedAt: null })).toContain(
      'not inspected',
    );
    const many = Array.from({ length: 40 }, (_, i) => ql(`listener-number-${i}`, 'current'));
    const long = justificationText({ keep: 'current', listeners: many, inspectedAt: at });
    expect(long.length).toBeLessThanOrEqual(REASON_MAX);
    const mixed = justificationText({
      keep: 'previous',
      listeners: [ql('a', 'previous'), ql('b', 'neither')],
      inspectedAt: at,
    });
    expect(mixed).toContain('not for b');
    for (const s of [ok, long, mixed]) expect(s).not.toContain('—');
  });
});

describe('misc', () => {
  it('collects the probe targets of a origin', () => {
    const keys = relayProbeTargetKeys('r1', [{ id: 'e1' }, { id: 'e2' }] as EdgeAdmin[]);
    expect([...keys].sort()).toEqual(['edge:e1', 'edge:e2', 'relay:r1']);
  });
  it('measures a rotation against now until it finishes', () => {
    const startedAt = '2026-01-01T00:00:00.000Z';
    const t0 = new Date(startedAt).getTime();
    expect(rotationDurationMs({ startedAt, finishedAt: null }, t0 + 5000)).toBe(5000);
    expect(rotationDurationMs({ startedAt, finishedAt: '2026-01-01T00:01:00.000Z' }, 0)).toBe(
      60_000,
    );
  });
  it('words a rotation outcome without bare codes', () => {
    expect(rotationOutcomeWords({ terminal: false, outcome: null, reason: null })).toBe('Running');
    const failed = rotationOutcomeWords({
      terminal: true,
      outcome: 'rolled_back',
      reason: 'cooldown',
    });
    expect(failed).not.toContain('_');
  });
  it('a publish the pool held back says why instead of a silent "Standby"', () => {
    expect(
      rotationOutcomeWords({
        terminal: true,
        outcome: 'standby',
        reason: null,
        standbyReason: 'pool_reserved',
      }),
    ).toBe('Standby: Slot held');
    expect(
      rotationOutcomeWords({
        terminal: true,
        outcome: 'standby',
        reason: 'by hand',
        standbyReason: 'pool_full',
      }),
    ).toBe('Standby: Pool full');
  });
  it('replaceAutoWords: the tested spare Automatic uses, or the location of the new address', () => {
    expect(
      replaceAutoWords(
        { standbyEdgeId: 's1', accountName: null, locationLabel: null },
        { name: '192.0.2.7', place: 'Region A' },
      ),
    ).toBe('Automatic uses the tested spare 192.0.2.7 in Region A.');
    // No tested spare: the new address is named by where it is created (it can be dearer).
    expect(
      replaceAutoWords(
        { standbyEdgeId: null, accountName: 'Acct B', locationLabel: 'Region B' },
        null,
      ),
    ).toBe('Automatic creates a new address in Region B (Acct B).');
    expect(
      replaceAutoWords({ standbyEdgeId: null, accountName: 'Acct B', locationLabel: null }, null),
    ).toBe('Automatic creates a new address in Acct B.');
    expect(
      replaceAutoWords({ standbyEdgeId: null, accountName: null, locationLabel: null }, null),
    ).toBeNull();
  });
  it('links timeline entries to the right drawer', () => {
    expect(timelineLinkParams({ targetType: 'edge_rotation', targetId: 'rot1' })).toEqual({
      rotation: 'rot1',
    });
    expect(
      timelineLinkParams({ targetType: 'edge', targetId: 'e1', payload: { rotationId: 'rot2' } }),
    ).toEqual({ rotation: 'rot2' });
    expect(timelineLinkParams({ targetType: 'edge', targetId: 'e1', payload: null })).toEqual({
      edge: 'e1',
    });
    expect(
      timelineLinkParams({
        targetType: 'relay_listener',
        targetId: 'l1',
        payload: { listenerKey: 'main' },
      }),
    ).toEqual({ tab: 'listeners', listener: 'main' });
    expect(timelineLinkParams({ targetType: 'relay', targetId: 'r1', payload: {} })).toBeNull();
  });
});
