import { describe, expect, it } from 'vitest';
import type { AttentionItem, EdgeAdmin, SetupStatusResponse } from '@shared/contracts/edges';
import {
  REASON_MAX,
  deriveDelivery,
  highlightedColumn,
  justificationText,
  recommendKeep,
  relayProbeTargetKeys,
  rotationDurationMs,
  rotationOutcomeWords,
  suspicionChip,
  timelineLinkParams,
  tupleLine,
  tuplesEqual,
  type QuarantineListener,
} from './relayLogic';

const relay = (over: Partial<Parameters<typeof deriveDelivery>[0]['relay']> = {}) => ({
  id: 'r1',
  origin: { kind: 'panel-node' as const, backendServerId: 'b1', nodeName: 'n1', nodeUuid: null },
  enabled: true,
  publishedCount: 1,
  ...over,
});
const renderingStep = (
  blockers: Array<{ code: string; detail?: string | null }>,
  renderEnabled = true,
): Pick<SetupStatusResponse, 'steps'> => ({
  steps: [
    {
      id: 'rendering',
      status: blockers.length === 0 ? 'done' : 'blocked',
      blockers: blockers.map((b) => ({ code: b.code, subject: null, detail: b.detail ?? null })),
      warnings: [],
      facts: { renderEnabled },
    },
  ],
});

describe('deriveDelivery', () => {
  it('serves when published, enabled and rendering is clean', () => {
    expect(deriveDelivery({ relay: relay(), setup: renderingStep([]) }).kind).toBe('serving');
  });
  it('a manual origin has nothing to deliver', () => {
    expect(deriveDelivery({ relay: relay({ origin: { kind: 'manual' } }) }).kind).toBe('manual');
  });
  it('is dark with an empty pool, a disabled origin or rendering off', () => {
    expect(deriveDelivery({ relay: relay({ publishedCount: 0 }) })).toMatchObject({
      kind: 'dark',
      code: 'empty_pool',
    });
    expect(deriveDelivery({ relay: relay({ enabled: false }) }).code).toBe('relay_disabled');
    expect(deriveDelivery({ relay: relay(), setup: renderingStep([], false) }).code).toBe(
      'render_disabled',
    );
  });
  it('prefers the server attention item for this origin and ignores other origins', () => {
    const item = (relayId: string): AttentionItem =>
      ({ kind: 'members_dark', relayId, code: 'render_disabled' }) as AttentionItem;
    expect(deriveDelivery({ relay: relay(), attention: [item('r1')] }).code).toBe(
      'render_disabled',
    );
    expect(deriveDelivery({ relay: relay(), attention: [item('other')] }).kind).toBe('serving');
  });
  it('is degraded when the sample render did not apply, using the delivery reason', () => {
    const d = deriveDelivery({
      relay: relay(),
      setup: renderingStep([{ code: 'preview_not_applied', detail: 'no_match' }]),
    });
    expect(d).toMatchObject({ kind: 'degraded', code: 'no_match' });
    expect(d.reason).not.toContain('no_match');
  });
});

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
  it('formats and compares tuples', () => {
    const t = { address: '198.51.100.7', port: 443, sni: 'a.example', host: null };
    expect(tupleLine(t)).toBe('198.51.100.7:443');
    expect(tupleLine(null)).toBe('');
    expect(tuplesEqual(t, { ...t })).toBe(true);
    expect(tuplesEqual(t, { ...t, sni: 'b.example' })).toBe(false);
    expect(tuplesEqual(t, null)).toBe(false);
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
