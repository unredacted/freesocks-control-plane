import { describe, expect, test } from 'vitest';
import type { BackendHost } from '../backends/types';
import {
  diffHosts,
  isSlotKey,
  matchSlotHosts,
  planFromMatches,
  relayRemarkRegex,
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
    expect(re.test('node-a-relay-ws')).toBe(true); // any short key is a relay remark
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
      { uuid: 'u1', oldAddress: '192.0.2.10', oldPort: 443, inboundUuid: 'in-1' },
    ]);
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
    // A binding that DISAPPEARED (inbound null on the live row) is the same drift.
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
