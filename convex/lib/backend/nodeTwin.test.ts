import { describe, expect, test } from 'vitest';
import {
  desiredTwinHost,
  dueEdges,
  keptChecks,
  nodeTwinProblem,
  servableEdges,
  twinHostDiff,
  twinRevision,
  twinRoute,
  twinTransportOn,
} from './nodeTwin';
import { clientEncryption, generateVlessEncryption } from './vlessEncryption';

const encryption = clientEncryption(generateVlessEncryption().decryption)!;
const twin = { tag: 'WS_E', uuid: 'twin-uuid', listen: '127.0.0.1', port: 8444, path: '/ws-e' };
const inbound = {
  inboundUuid: 'twin-uuid',
  protocol: 'vless',
  network: 'ws',
  security: 'none',
  port: 8444,
  listen: '127.0.0.1',
  path: '/ws-e',
  vlessEncryption: { digest: 'd1', encryption },
};
const ok = {
  twin,
  inbound,
  activeInboundUuids: ['own-uuid', 'twin-uuid'],
  listenerReady: true,
  twinRemark: 'node-a-relay-wse123456',
};

describe('whether a node can be checked on its twin', () => {
  test('a twin that is on, readable and behind a front has no problem', () => {
    expect(nodeTwinProblem(ok)).toBeNull();
  });

  test.each([
    ['the mode has none', { twin: undefined }, 'servers.twin_absent'],
    ['it is being taken away', { twin: { ...twin, detaching: true } }, 'servers.twin_absent'],
    ['no front of FCP’s', { listenerReady: false }, 'servers.node_twin_no_front'],
    ['a listener FCP did not name', { twinRemark: null }, 'servers.node_twin_no_front'],
    ['a name too long', { twinRemark: 'n'.repeat(41) }, 'servers.node_twin_remark_long'],
    [
      'a name longer than its listener’s own, past what every backend takes',
      { twinRemark: 'n'.repeat(45), listenerRemarkLength: 44 },
      'servers.node_twin_remark_long',
    ],
    [
      'a name past what any backend takes',
      { twinRemark: 'n'.repeat(101), listenerRemarkLength: 101 },
      'servers.node_twin_remark_long',
    ],
    ['not on the profile', { inbound: undefined }, 'servers.twin_not_websocket'],
    [
      'another transport',
      { inbound: { ...inbound, network: 'tcp' } },
      'servers.twin_not_websocket',
    ],
    [
      'plain',
      { inbound: { ...inbound, vlessEncryption: undefined } },
      'servers.twin_not_encrypted',
    ],
    [
      'a client string FCP could not read',
      { inbound: { ...inbound, vlessEncryption: { digest: 'd1', encryption: null } } },
      'servers.twin_encryption_unreadable',
    ],
    [
      'an identity FCP could not derive',
      { inbound: { ...inbound, vlessEncryption: { digest: null, encryption } } },
      'servers.twin_encryption_unreadable',
    ],
    [
      'an appearance FCP cannot speak',
      {
        inbound: {
          ...inbound,
          vlessEncryption: { digest: 'd1', encryption: encryption.replace('.native.', '.random.') },
        },
      },
      'servers.twin_encryption_unsupported',
    ],
    ['no node row yet', { activeInboundUuids: null }, 'servers.node_twin_transport_off'],
    [
      'the transport not on for the node',
      { activeInboundUuids: ['own-uuid'] },
      'servers.node_twin_transport_off',
    ],
  ])('%s', (_name, change, code) => {
    expect(nodeTwinProblem({ ...ok, ...change })).toBe(code);
  });
});

test('a name as long as its listener’s own is one the backend already took', () => {
  expect(
    nodeTwinProblem({ ...ok, twinRemark: 'n'.repeat(44), listenerRemarkLength: 44 }),
  ).toBeNull();
});

describe('the twin’s transport and route', () => {
  test('on while it activates or serves, and until its address is gone', () => {
    expect(twinTransportOn('activating')).toBe(true);
    expect(twinTransportOn('serving')).toBe(true);
    expect(twinTransportOn('removing', 'host-1')).toBe(true);
    expect(twinTransportOn('removing')).toBe(false);
  });

  test('the route is its path to its loopback port', () => {
    expect(twinRoute(twin)).toEqual({ path: '/ws-e', port: 8444 });
  });
});

describe('the twin’s address', () => {
  const listenerHost = {
    address: 'front.example.org',
    port: 443,
    sni: 'front.example.org',
    host: 'front.example.org',
    securityLayer: 'TLS',
  };

  test('repeats the listener’s own address under the twin’s remark, with no path', () => {
    const want = desiredTwinHost(listenerHost, 'node-a-relay-wse123456');
    expect(want).toEqual({
      remark: 'node-a-relay-wse123456',
      address: 'front.example.org',
      port: 443,
      sni: 'front.example.org',
      host: 'front.example.org',
      alpn: null,
      fingerprint: null,
      securityLayer: 'TLS',
    });
    expect(want).not.toHaveProperty('path');
  });

  test('an unset layer and the backend’s default word are the same thing', () => {
    const want = desiredTwinHost({ ...listenerHost, securityLayer: undefined }, 'r');
    expect(
      twinHostDiff({ ...listenerHost, securityLayer: 'DEFAULT', remark: 'r' }, want),
    ).toBeNull();
  });

  test('follows the listener’s address when a front is replaced', () => {
    const want = desiredTwinHost(
      { ...listenerHost, address: 'next.example.org', sni: 'next.example.org' },
      'r',
    );
    expect(twinHostDiff({ ...listenerHost, remark: 'r' }, want)).toEqual({
      address: 'next.example.org',
      sni: 'next.example.org',
    });
  });
});

describe('what a serving twin’s checks are bound to', () => {
  const base = {
    transportUuid: 'twin-uuid',
    authDigest: 'd1',
    port: 8444,
    path: '/ws-e',
    listenerId: 'l1',
  };

  test('a new key, port, path, transport or listener is another revision', () => {
    const r = twinRevision(base);
    expect(twinRevision({ ...base })).toBe(r);
    for (const change of [
      { authDigest: 'd2' },
      { port: 8445 },
      { path: '/other' },
      { transportUuid: 'u2' },
      { listenerId: 'l2' },
    ])
      expect(twinRevision({ ...base, ...change })).not.toBe(r);
  });
});

describe('which fronts are checked, kept and handed out through', () => {
  const HOUR = 3_600_000;
  const now = 10 * HOUR;
  const checks = [
    { edgeId: 'a', checkedAt: now - 10 * 60_000 },
    { edgeId: 'b', checkedAt: now - 61 * 60_000 },
    { edgeId: 'gone', checkedAt: now - 60_000 },
  ];

  test('due: never checked, or checked longer ago than the window', () => {
    expect(dueEdges(['a', 'b', 'c'], checks, now, HOUR)).toEqual(['b', 'c']);
  });

  test('kept: of a published front, and not one checked again in this run', () => {
    expect(keptChecks(['a', 'b', 'c'], checks, new Set(['b']))).toEqual([checks[0]]);
  });

  test('handed out through: fronts checked within the limit, none without checks', () => {
    expect(servableEdges(checks, now, 3 * HOUR)).toEqual(['a', 'b', 'gone']);
    expect(servableEdges(checks, now + 3 * HOUR, 3 * HOUR)).toEqual([]);
    expect(servableEdges(undefined, now, 3 * HOUR)).toEqual([]);
  });
});
