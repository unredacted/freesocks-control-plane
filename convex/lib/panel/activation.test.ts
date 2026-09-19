import { describe, expect, test } from 'vitest';
import {
  classifyChange,
  evidenceHolds,
  gateOpen,
  publicationAdmitted,
  retainEvidence,
  reviewHashOf,
  stageAfterChange,
  type Evidence,
  type Revisions,
} from './activation';

const now: Revisions = {
  machineRevision: 3,
  configRevision: 'c1',
  authRevision: 'a1',
  deliveryRevision: 'd1',
};
const ev = (kind: string, over: Partial<Evidence> = {}): Evidence => ({
  kind,
  machineRevision: 3,
  configRevision: 'c1',
  authRevision: 'a1',
  deliveryRevision: 'd1',
  at: 1,
  ...over,
});

describe('evidence and revisions', () => {
  test('a revision bump drops exactly the evidence bound to it', () => {
    const rows = [
      ev('machine_applied'),
      ev('machine_ready'),
      ev('direct_confirmed'),
      ev('standbys_verified'),
    ];
    expect(retainEvidence(rows, { ...now, deliveryRevision: 'd2' }).map((e) => e.kind)).toEqual([
      'machine_applied',
      'machine_ready',
      'direct_confirmed',
    ]);
    expect(retainEvidence(rows, { ...now, authRevision: 'a2' }).map((e) => e.kind)).toEqual([
      'machine_applied',
      'machine_ready',
      'standbys_verified',
    ]);
    expect(retainEvidence(rows, { ...now, machineRevision: 4 })).toEqual([]);
    expect(retainEvidence(rows, { ...now, configRevision: 'c2' }).map((e) => e.kind)).toEqual([
      'machine_applied',
    ]);
  });
  test('an unchanged rerun keeps every row', () => {
    const rows = [ev('machine_applied'), ev('machine_ready')];
    expect(retainEvidence(rows, now)).toEqual(rows);
  });
  test('evidence missing a bound revision never holds', () => {
    expect(evidenceHolds(ev('direct_confirmed', { authRevision: undefined }), now)).toBe(false);
  });
  test('the ladder falls to the earliest stage whose evidence is gone, never rises', () => {
    expect(stageAfterChange('live', [])).toBe('bootstrap_available');
    expect(stageAfterChange('live', [ev('machine_applied')])).toBe('machine_applied');
    expect(stageAfterChange('live', [ev('machine_applied'), ev('machine_ready')])).toBe(
      'machine_ready',
    );
    expect(
      stageAfterChange('live', [
        ev('machine_applied'),
        ev('machine_ready'),
        ev('direct_confirmed'),
      ]),
    ).toBe('candidates_verified');
    expect(stageAfterChange('registered', [ev('machine_applied'), ev('machine_ready')])).toBe(
      'registered',
    );
  });
});

describe('reviewHash', () => {
  const shape = {
    purpose: 'relay' as const,
    ingress: null,
    configRevision: 'c1',
    authRevision: 'a1',
    listenerKeys: ['k1'],
    provider: { accountId: 'acc', templateHash: 't1' },
    subscriptionTemplates: { SINGBOX: 'h1' },
    hostTuple: null,
  };
  test('is stable and blind to key order, and moves on any shape change', async () => {
    const a = await reviewHashOf(shape);
    const b = await reviewHashOf({
      ...shape,
      subscriptionTemplates: { ...shape.subscriptionTemplates },
    });
    expect(a).toBe(b);
    expect(await reviewHashOf({ ...shape, listenerKeys: ['k1', 'k2'] })).not.toBe(a);
    expect(
      await reviewHashOf({ ...shape, provider: { accountId: 'acc', templateHash: 't2' } }),
    ).not.toBe(a);
  });
});

describe('classifyChange and the gates', () => {
  test('resource isolation decides, not the wording', () => {
    expect(classifyChange({})).toBe('none');
    expect(classifyChange({ addsPath: true })).toBe('preparable');
    expect(classifyChange({ providerChanged: true })).toBe('preparable');
    expect(classifyChange({ addsPath: true, mutatesCommitted: true })).toBe('in_place');
    expect(classifyChange({ rewritesPath: true })).toBe('in_place');
    expect(classifyChange({ profileChanged: true })).toBe('in_place');
    expect(classifyChange({ authChanged: true })).toBe('in_place');
  });
  test('the gate opens only when live', () => {
    expect(gateOpen('live')).toBe(true);
    for (const d of ['staged', 'activating', 'unavailable', 'retiring'] as const)
      expect(gateOpen(d)).toBe(false);
  });
  test('publication needs lifecycle eligibility and a revision match', () => {
    const base = {
      underMaintenance: false,
      matchesCommitted: false,
      matchesApprovedCandidate: false,
    };
    expect(publicationAdmitted({ ...base, disposition: 'live', matchesCommitted: true })).toBe(
      'committed',
    );
    expect(
      publicationAdmitted({ ...base, disposition: 'activating', matchesApprovedCandidate: true }),
    ).toBe('candidate');
    expect(
      publicationAdmitted({ ...base, disposition: 'live', matchesApprovedCandidate: true }),
    ).toBe('candidate');
    expect(
      publicationAdmitted({ ...base, disposition: 'activating', matchesCommitted: true }),
    ).toBeNull();
    expect(
      publicationAdmitted({
        ...base,
        disposition: 'live',
        matchesCommitted: true,
        underMaintenance: true,
      }),
    ).toBeNull();
    expect(
      publicationAdmitted({ ...base, disposition: 'retiring', matchesCommitted: true }),
    ).toBeNull();
    expect(
      publicationAdmitted({ ...base, disposition: 'unavailable', matchesApprovedCandidate: true }),
    ).toBeNull();
    expect(publicationAdmitted({ ...base, disposition: 'staged' })).toBeNull();
  });
});
