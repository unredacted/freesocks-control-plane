/**
 * The binding a front qualification is a proof OF.
 *
 * The property that matters is that nothing which changes what a member would
 * connect to can leave the binding unchanged: if it could, a stale proof would
 * pass as a current one and FCP would publish an edge nobody can reach.
 */
import { describe, expect, test } from 'vitest';
import { bindingsMatch, canonicalTransportParams, qualificationBinding } from './binding';
import { qualificationVerdict } from '../intent';

const intent = {
  hostname: 'a1b2c3d4.edge.example',
  zoneId: 'z',
  zoneName: 'edge.example',
  originTransport: {
    scheme: 'https' as const,
    certPublic: true,
    certNames: ['node.example'],
    acceptsHostHeader: 'any' as const,
  },
  originPort: 443,
  templateHash: 'th',
  templateParams: {},
};

const base = {
  slot: { _id: 'slot1', revision: 2, originPort: 443, originTransport: intent.originTransport },
  profile: { _id: 'prof1', revision: 4, protocol: 'ws' as const },
  intent,
  params: { path: '/relay', upgradeToken: 'websocket' },
};

describe('canonicalTransportParams', () => {
  test('absent fields become null so two different absences cannot collide', () => {
    expect(canonicalTransportParams({ path: '/a' })).toEqual({
      path: '/a',
      host: null,
      serviceName: null,
      upgradeToken: null,
    });
    // Same value, different field: the hash must not treat these as equal.
    const a = qualificationBinding({ ...base, params: { path: 'x' } });
    const b = qualificationBinding({ ...base, params: { host: 'x' } });
    expect(a.transportParamsHash).not.toBe(b.transportParamsHash);
  });

  test('an undefined and an explicit null field are the same absence', () => {
    expect(canonicalTransportParams({ path: undefined })).toEqual(
      canonicalTransportParams({ path: null }),
    );
  });
});

describe('qualificationBinding', () => {
  test('is stable for the same configuration', () => {
    expect(qualificationBinding(base)).toEqual(qualificationBinding({ ...base }));
    expect(bindingsMatch(qualificationBinding(base), qualificationBinding({ ...base }))).toBe(true);
  });

  test('legacy rows without revision counters read as 0', () => {
    const legacy = qualificationBinding({
      ...base,
      slot: { ...base.slot, revision: undefined },
      profile: { ...base.profile, revision: undefined },
    });
    expect(legacy.slotRevision).toBe(0);
    expect(legacy.profileRevision).toBe(0);
  });

  test.each([
    ['a new hostname', { intent: { ...intent, hostname: 'other.edge.example' } }],
    ['a slot write', { slot: { ...base.slot, revision: 3 } }],
    ['a profile write', { profile: { ...base.profile, revision: 5 } }],
    ['a different protocol', { profile: { ...base.profile, protocol: 'grpc' as const } }],
    ['a moved path', { params: { path: '/moved', upgradeToken: 'websocket' } }],
    ['a changed upgrade token', { params: { path: '/relay', upgradeToken: 'custom' } }],
    ['a re-planned intent', { intent: { ...intent, originPort: 8443 } }],
  ])('%s invalidates the proof', (_name, override) => {
    const changed = qualificationBinding({ ...base, ...override });
    expect(bindingsMatch(qualificationBinding(base), changed)).toBe(false);
  });

  test('a stored qualification goes stale rather than silently matching', () => {
    const stored = {
      ok: true,
      checkedAt: 1_000,
      expiresAt: 61_000,
      binding: qualificationBinding(base),
    };
    const moved = qualificationBinding({ ...base, params: { path: '/moved' } });
    expect(qualificationVerdict(stored, stored.binding, 2_000)).toBe('ok');
    expect(qualificationVerdict(stored, moved, 2_000)).toBe('stale');
    expect(qualificationVerdict(stored, stored.binding, 61_001)).toBe('expired');
    expect(qualificationVerdict({ ...stored, ok: false }, stored.binding, 2_000)).toBe('failed');
  });
});
