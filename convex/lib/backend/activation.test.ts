import { describe, expect, test } from 'vitest';
import {
  classifyChange,
  evidenceHolds,
  gateOpen,
  publicationAdmitted,
  publicationFits,
  retainEvidence,
  reviewHashOf,
  stageAfterChange,
  type Evidence,
  type PublicationShape,
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
    mode: 'freedom-reality',
    modeShape: { transport: 'reality', fronting: 'edge-l4' },
    ingress: null,
    configRevision: 'c1',
    authRevision: 'a1',
    listeners: [{ listenerKey: 'k1', accountId: 'acc', templateHash: 't1' }],
    subscriptionTemplates: { SINGBOX: 'h1' },
    addressTuples: [],
  };
  test('is stable and blind to key order, and moves on any shape change', async () => {
    const a = await reviewHashOf(shape);
    const b = await reviewHashOf({
      ...shape,
      subscriptionTemplates: { ...shape.subscriptionTemplates },
    });
    expect(a).toBe(b);
    // Every listener counts, never one representative edge.
    expect(
      await reviewHashOf({
        ...shape,
        listeners: [
          ...shape.listeners,
          { listenerKey: 'k2', accountId: 'acc', templateHash: 't1' },
        ],
      }),
    ).not.toBe(a);
    expect(
      await reviewHashOf({
        ...shape,
        listeners: [{ listenerKey: 'k1', accountId: 'acc', templateHash: 't2' }],
      }),
    ).not.toBe(a);
  });
});

describe('publicationFits', () => {
  const approved = {
    listeners: [
      { listenerKey: 'k1', accountId: 'acc', locationId: 'loc', templateHash: 't1' },
      { listenerKey: 'k2', accountId: 'acc', locationId: 'loc', templateHash: null },
    ],
  };
  const pub = (over: Partial<PublicationShape>): PublicationShape => ({
    listenerKey: 'k1',
    accountId: 'acc',
    locationId: 'loc',
    templateHash: 't1',
    ...over,
  });
  test('a replacement address within the approved shape fits; another account, location, template or listener does not', () => {
    expect(publicationFits(approved, pub({}))).toBe(true);
    expect(publicationFits(approved, pub({ listenerKey: 'k2', templateHash: null }))).toBe(true);
    expect(publicationFits(approved, pub({ accountId: 'other' }))).toBe(false);
    expect(publicationFits(approved, pub({ locationId: 'elsewhere' }))).toBe(false);
    expect(publicationFits(approved, pub({ templateHash: 't2' }))).toBe(false);
    expect(publicationFits(approved, pub({ listenerKey: 'k3' }))).toBe(false);
  });
  test('a listener may hold several approved picks: each one fits, nothing else does', () => {
    const both = {
      listeners: [
        { listenerKey: 'k1', accountId: 'a1', locationId: 'l1', templateHash: 't1' },
        { listenerKey: 'k1', accountId: 'a2', locationId: 'l2', templateHash: 't2' },
      ],
    };
    expect(publicationFits(both, pub({ accountId: 'a1', locationId: 'l1' }))).toBe(true);
    expect(
      publicationFits(both, pub({ accountId: 'a2', locationId: 'l2', templateHash: 't2' })),
    ).toBe(true);
    expect(publicationFits(both, pub({ accountId: 'a1', locationId: 'l2' }))).toBe(false);
  });
  test('another certificate is a new review; an entry approved before options takes any', () => {
    const withCert = {
      listeners: [
        {
          listenerKey: 'k1',
          accountId: 'acc',
          locationId: 'loc',
          templateHash: 't1',
          certificate: 'c1',
        },
      ],
    };
    expect(publicationFits(withCert, pub({ certificate: 'c1' }))).toBe(true);
    // A replacement that changes only the authority or the scope: same template, new review.
    expect(publicationFits(withCert, pub({ certificate: 'c2' }))).toBe(false);
    expect(publicationFits(withCert, pub({}))).toBe(false);
    // Approved before the certificate was a node's option: nothing to compare.
    expect(publicationFits(approved, pub({ certificate: 'c2' }))).toBe(true);
  });
  test('an entry stored before locations (an account, no location) fails closed', () => {
    const legacy = { listeners: [{ listenerKey: 'k1', accountId: 'acc', templateHash: 't1' }] };
    expect(publicationFits(legacy, pub({}))).toBe(false);
    expect(publicationFits(legacy, pub({ locationId: null }))).toBe(false);
  });
  test('an adopted front with no account fits as no account, no location', () => {
    const adopted = {
      listeners: [{ listenerKey: 'k1', accountId: null, locationId: null, templateHash: null }],
    };
    expect(
      publicationFits(adopted, pub({ accountId: null, locationId: null, templateHash: null })),
    ).toBe(true);
    expect(publicationFits(adopted, pub({}))).toBe(false);
  });
  test('an approval without a per-listener shape (or none at all) fits nothing', () => {
    expect(publicationFits(null, pub({}))).toBe(false);
    expect(publicationFits({} as never, pub({}))).toBe(false);
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
