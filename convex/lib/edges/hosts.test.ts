import { describe, expect, test } from 'vitest';
import type { BackendHost } from '../backends/types';
import {
  diffHosts,
  isSlotKey,
  matchSlotHosts,
  planFromMatches,
  relayRemarkRegex,
  rollbackTargetFor,
  sameAddress,
  templateHostRemark,
} from './hosts';

const host = (over: Partial<BackendHost>): BackendHost => ({
  uuid: 'u1',
  remark: 'node-a-relay-a1',
  address: '192.0.2.10',
  port: 443,
  sni: 'www.example',
  isDisabled: false,
  inbound: { configProfileUuid: 'cp', configProfileInboundUuid: 'in-1' },
  ...over,
});

describe('remarks', () => {
  test('template remark + regex accept bare, slot-keyed and legacy hash remarks', () => {
    expect(templateHostRemark('node-a', 'a1')).toBe('node-a-relay-a1');
    const re = relayRemarkRegex('node-a');
    expect(re.test('node-a-relay')).toBe(true);
    expect(re.test('node-a-relay-a1')).toBe(true);
    expect(re.test('node-a-relay-6a536a')).toBe(true);
    expect(re.test('node-a-reality')).toBe(false);
    expect(re.test('node-a-relay-ws')).toBe(true); // any short key is an origin remark
    expect(re.test('node-ab-relay')).toBe(false); // prefix-sharing hostname
    expect(re.test('xnode-a-relay')).toBe(false);
  });

  test('slot keys are short lowercase alphanumerics', () => {
    expect(isSlotKey('a1')).toBe(true);
    expect(isSlotKey('A1')).toBe(false);
    expect(isSlotKey('')).toBe(false);
    expect(isSlotKey('x'.repeat(17))).toBe(false);
  });
});

describe('matchSlotHosts', () => {
  const slots = [
    { slotId: 's1', slotKey: 'a1', templateHostRemark: 'node-a-relay-a1' },
    { slotId: 's2', slotKey: 'b2', templateHostRemark: 'node-a-relay-b2' },
  ];

  test('matches by exact remark, reports duplicates and leaks', () => {
    const hosts = [
      host({ uuid: 'u1', remark: 'node-a-relay-a1' }),
      host({ uuid: 'u1b', remark: 'node-a-relay-a1' }),
      host({ uuid: 'u2', remark: 'node-a-relay-b2', address: '198.51.100.7' }),
      host({ uuid: 'other', remark: 'node-b-relay-a1' }),
    ];
    const m = matchSlotHosts(hosts, slots, '198.51.100.7');
    expect(m[0].host?.uuid).toBe('u1');
    expect(m[0].duplicates).toBe(1);
    expect(m[0].leaks).toBe(false);
    expect(m[1].host?.uuid).toBe('u2');
    expect(m[1].leaks).toBe(true); // points at the origin itself
  });

  test('a slot without a Host yields null', () => {
    const m = matchSlotHosts([], slots, '198.51.100.7');
    expect(m.every((x) => x.host === null)).toBe(true);
  });

  test('planFromMatches skips leaking and missing Hosts', () => {
    const hosts = [
      host({ uuid: 'u1' }),
      host({ uuid: 'u2', remark: 'node-a-relay-b2', address: '198.51.100.7' }),
    ];
    const plan = planFromMatches(matchSlotHosts(hosts, slots, '198.51.100.7'));
    expect(plan).toEqual([
      {
        uuid: 'u1',
        oldAddress: '192.0.2.10',
        oldPort: 443,
        inboundUuid: 'in-1',
        // Version 2 captures the FULL previous tuple so a rollback can restore
        // it, clears included.
        snapshotVersion: 2,
        oldSni: 'www.example',
        oldHost: null,
      },
    ]);
  });

  test('planFromMatches records an empty backend field as a known null, not as unknown', () => {
    const plan = planFromMatches(
      matchSlotHosts([host({ uuid: 'u1', sni: '', host: '' })], slots, '198.51.100.7'),
    );
    expect(plan[0].oldSni).toBeNull();
    expect(plan[0].oldHost).toBeNull();
  });
});

describe('rollbackTargetFor', () => {
  test('a version-2 entry restores the whole tuple, clears included', () => {
    expect(
      rollbackTargetFor({
        uuid: 'u1',
        oldAddress: '192.0.2.10',
        oldPort: 443,
        snapshotVersion: 2,
        oldSni: 'www.example',
        oldHost: null,
      }),
    ).toEqual({ address: '192.0.2.10', port: 443, sni: 'www.example', host: null });
  });

  test('a LEGACY entry restores address and port only: unknown is never written as a clear', () => {
    const t = rollbackTargetFor({ uuid: 'u1', oldAddress: '192.0.2.10', oldPort: 443 });
    expect(t).toEqual({ address: '192.0.2.10', port: 443 });
    expect('sni' in t).toBe(false);
    expect('host' in t).toBe(false);
  });
});

describe('diffHosts', () => {
  const plan = [
    { uuid: 'u1', oldAddress: '192.0.2.10', oldPort: 443, inboundUuid: 'in-1' },
    { uuid: 'u2', oldAddress: '192.0.2.10', oldPort: 443, inboundUuid: 'in-1' },
  ];
  const target = { address: '203.0.113.5', port: 443 };

  test('splits at-target vs needs-write and converges only when all are at target', () => {
    const live = [host({ uuid: 'u1', address: '203.0.113.5' }), host({ uuid: 'u2' })];
    const d = diffHosts(live, plan, target);
    expect(d.atTarget.map((p) => p.uuid)).toEqual(['u1']);
    expect(d.needsWrite.map((p) => p.uuid)).toEqual(['u2']);
    expect(d.converged).toBe(false);
    const d2 = diffHosts(
      [host({ uuid: 'u1', address: '203.0.113.5' }), host({ uuid: 'u2', address: '203.0.113.5' })],
      plan,
      target,
    );
    expect(d2.converged).toBe(true);
  });

  test('a missing or re-inbounded uuid is hostsChanged, never convergence', () => {
    const d = diffHosts([host({ uuid: 'u1', address: '203.0.113.5' })], plan, target);
    expect(d.missing.map((p) => p.uuid)).toEqual(['u2']);
    expect(d.hostsChanged).toBe(true);
    expect(d.converged).toBe(false);
    const d2 = diffHosts(
      [
        host({ uuid: 'u1', address: '203.0.113.5' }),
        host({
          uuid: 'u2',
          address: '203.0.113.5',
          inbound: { configProfileUuid: 'cp', configProfileInboundUuid: 'in-NEW' },
        }),
      ],
      plan,
      target,
    );
    expect(d2.changedInbound.map((p) => p.uuid)).toEqual(['u2']);
    expect(d2.converged).toBe(false);
    // A binding that DISAPPEARED (transport null on the live row) is the same drift.
    const d3 = diffHosts(
      [
        host({ uuid: 'u1', address: '203.0.113.5' }),
        { ...host({ uuid: 'u2', address: '203.0.113.5' }), inbound: null },
      ],
      plan,
      target,
    );
    expect(d3.changedInbound.map((p) => p.uuid)).toEqual(['u2']);
    expect(d3.hostsChanged).toBe(true);
  });

  test('an empty plan never converges', () => {
    expect(diffHosts([], [], target).converged).toBe(false);
  });

  test('address comparison tolerates case, brackets and trailing dots', () => {
    expect(sameAddress('[2001:DB8::1]', '2001:db8::1')).toBe(true);
    expect(sameAddress('edge.example.', 'edge.example')).toBe(true);
    expect(sameAddress('192.0.2.1', '192.0.2.2')).toBe(false);
  });
});

describe('diffHosts: the full tuple', () => {
  const plan = [{ uuid: 'u1', oldAddress: '192.0.2.10', oldPort: 443, inboundUuid: 'in-1' }];

  test('an L4 → L7 transition is not converged while the backend keeps the old SNI', () => {
    const live = [host({ uuid: 'u1', address: 'cdn.example', port: 443, sni: 'www.example' })];
    const target = { address: 'cdn.example', port: 443, sni: 'cdn.example', host: 'cdn.example' };
    const d = diffHosts(live, plan, target);
    expect(d.converged).toBe(false);
    expect(d.needsWrite).toHaveLength(1);
  });

  test('an L7 → L4 transition needs the CDN hostname cleared from SNI and Host', () => {
    const live = [
      host({
        uuid: 'u1',
        address: '203.0.113.5',
        port: 443,
        sni: 'cdn.example',
        host: 'cdn.example',
      }),
    ];
    // `plain` presents nothing: both fields must be cleared.
    const d = diffHosts(live, plan, { address: '203.0.113.5', port: 443, sni: null, host: null });
    expect(d.converged).toBe(false);
    const cleared = diffHosts(
      [host({ uuid: 'u1', address: '203.0.113.5', port: 443, sni: '', host: '' })],
      plan,
      { address: '203.0.113.5', port: 443, sni: null, host: null },
    );
    expect(cleared.converged).toBe(true);
  });

  test('a target that does not define sni/host does not compare them (legacy callers)', () => {
    const live = [host({ uuid: 'u1', address: '203.0.113.5', port: 443, sni: 'anything' })];
    expect(diffHosts(live, plan, { address: '203.0.113.5', port: 443 }).converged).toBe(true);
  });

  test('a partial write (address landed, SNI lost) still needs a write', () => {
    const live = [host({ uuid: 'u1', address: 'cdn.example', port: 443, sni: null })];
    const d = diffHosts(live, plan, {
      address: 'cdn.example',
      port: 443,
      sni: 'cdn.example',
      host: 'cdn.example',
    });
    expect(d.needsWrite.map((p) => p.uuid)).toEqual(['u1']);
    expect(d.hostsChanged).toBe(false);
  });
});
