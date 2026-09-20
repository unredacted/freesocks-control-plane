import { describe, expect, test } from 'vitest';
import {
  asyncWorkFinished,
  callResultOf,
  claimsReleasable,
  classifyRequest,
  displayState,
  fieldsMatch,
  hostIdentity,
  hostLock,
  hostsMatchingIdentity,
  looksLikeRelayRemark,
} from './ops';

describe('classifyRequest', () => {
  test('only the pre-mutation allowlist proves nothing changed', () => {
    expect(classifyRequest({ kind: 'ok' })).toBe('acknowledged');
    expect(classifyRequest({ kind: 'not_sent' })).toBe('rejected_pre_mutation');
    expect(classifyRequest({ kind: 'http', status: 401 })).toBe('rejected_pre_mutation');
    expect(classifyRequest({ kind: 'http', status: 403 })).toBe('rejected_pre_mutation');
  });

  test('every 5xx, every other 4xx and every timeout is uncertain', () => {
    // Measured: the backend answers an invalid config with 500 and stores nothing,
    // but a gateway can answer a 5xx while upstream commits. Never on the list.
    for (const status of [400, 404, 409, 422, 429, 500, 502, 503, 504])
      expect(classifyRequest({ kind: 'http', status })).toBe('uncertain');
    expect(classifyRequest({ kind: 'unknown' })).toBe('uncertain');
  });

  test('callResultOf reads a status or a connect code, never a message', () => {
    expect(callResultOf({ meta: { status: 502 }, message: 'secret body' })).toEqual({
      kind: 'http',
      status: 502,
    });
    expect(callResultOf({ cause: { code: 'ECONNREFUSED' } })).toEqual({ kind: 'not_sent' });
    expect(callResultOf({ code: 'ENOTFOUND' })).toEqual({ kind: 'not_sent' });
    // A reset or a timeout may have happened after the request was received.
    expect(callResultOf({ cause: { code: 'ECONNRESET' } })).toEqual({ kind: 'unknown' });
    expect(callResultOf(new Error('The operation was aborted'))).toEqual({ kind: 'unknown' });
    expect(callResultOf(null)).toEqual({ kind: 'unknown' });
  });
});

describe('claimsReleasable', () => {
  const op = (o: Partial<Parameters<typeof claimsReleasable>[0]>) => ({
    request: 'acknowledged' as const,
    panelState: 'unobserved' as const,
    asyncEffect: 'none' as const,
    ...o,
  });
  test('a provable pre-mutation rejection releases at once', () => {
    expect(claimsReleasable(op({ request: 'rejected_pre_mutation' }))).toBe(true);
  });
  test('an acknowledged write holds its claims until the result is SEEN', () => {
    expect(claimsReleasable(op({}))).toBe(false);
    expect(claimsReleasable(op({ panelState: 'observed' }))).toBe(true);
  });
  test('queued node work holds them further; reading the row alone is not enough', () => {
    expect(claimsReleasable(op({ panelState: 'observed', asyncEffect: 'pending' }))).toBe(false);
    expect(claimsReleasable(op({ panelState: 'observed', asyncEffect: 'unresolved' }))).toBe(false);
    expect(claimsReleasable(op({ panelState: 'observed', asyncEffect: 'complete' }))).toBe(true);
  });
  test('an uncertain, unobserved attempt is fenced: nothing but a recovery releases it', () => {
    const stuck = op({ request: 'uncertain' });
    expect(claimsReleasable(stuck)).toBe(false);
    expect(displayState(stuck)).toBe('outcome_unknown');
    expect(claimsReleasable({ ...stuck, recovery: { at: 1 } })).toBe(true);
    // Seeing the result resolves it: one outstanding attempt, so it landed and is finished.
    expect(claimsReleasable(op({ request: 'uncertain', panelState: 'observed' }))).toBe(true);
  });
  test('display words', () => {
    expect(displayState(op({ request: 'pending' }))).toBe('working');
    expect(displayState(op({ request: 'rejected_pre_mutation' }))).toBe('refused');
    expect(displayState(op({ panelState: 'observed' }))).toBe('done');
    expect(displayState(op({ panelState: 'observed', asyncEffect: 'pending' }))).toBe(
      'waiting_for_nodes',
    );
  });
});

describe('host identity and discovery', () => {
  const h = (uuid: string, over = {}) => ({
    hostUuid: uuid,
    remark: 'node-one-direct',
    address: '192.0.2.10',
    port: 443,
    configProfileInboundUuid: 'i-1',
    ...over,
  });
  const id = hostIdentity({
    remark: 'node-one-direct',
    inboundUuid: 'i-1',
    address: '192.0.2.10',
    port: 443,
  });
  test('zero, one (adopt) and several (an operator call) matches', () => {
    expect(hostsMatchingIdentity([h('a', { port: 8443 })], id)).toHaveLength(0);
    expect(
      hostsMatchingIdentity([h('a'), h('b', { remark: 'other' })], id).map((x) => x.hostUuid),
    ).toEqual(['a']);
    expect(hostsMatchingIdentity([h('a'), h('b')], id)).toHaveLength(2);
  });
  test('the address compares case-insensitively; the remark does not', () => {
    expect(
      hostsMatchingIdentity(
        [h('a', { address: 'Front.Example' })],
        hostIdentity({
          remark: 'node-one-direct',
          inboundUuid: 'i-1',
          address: 'front.example',
          port: 443,
        }),
      ),
    ).toHaveLength(1);
    expect(hostsMatchingIdentity([h('a', { remark: 'Node-One-Direct' })], id)).toHaveLength(0);
  });
});

describe('fieldsMatch', () => {
  test('null, undefined and the empty string are the same "unset"; arrays compare as sets', () => {
    expect(fieldsMatch({ sni: '', port: 443 }, { sni: null, port: 443 })).toBe(true);
    expect(fieldsMatch({ sni: 'a.example' }, { sni: null })).toBe(false);
    expect(fieldsMatch({ inboundUuids: ['b', 'a'] }, { inboundUuids: ['a', 'b'] })).toBe(true);
    expect(fieldsMatch({ inboundUuids: ['a'] }, { inboundUuids: ['a', 'b'] })).toBe(false);
    expect(fieldsMatch(null, {})).toBe(false);
  });
});

describe('asyncWorkFinished', () => {
  const before = [
    { nodeUuid: 'n1', before: 't0' },
    { nodeUuid: 'n2', before: null },
  ];
  test('every recorded node must show a moved lastStatusChange', () => {
    expect(
      asyncWorkFinished(before, [
        { nodeUuid: 'n1', lastStatusChange: 't1', isDisabled: false },
        { nodeUuid: 'n2', lastStatusChange: 't1', isDisabled: false },
      ]),
    ).toBe(true);
    // One node has not applied yet (unreachable: the backend delivers on reconnect).
    expect(
      asyncWorkFinished(before, [
        { nodeUuid: 'n1', lastStatusChange: 't0', isDisabled: false },
        { nodeUuid: 'n2', lastStatusChange: 't1', isDisabled: false },
      ]),
    ).toBe(false);
    expect(
      asyncWorkFinished(before, [
        { nodeUuid: 'n1', lastStatusChange: 't1', isDisabled: false },
        { nodeUuid: 'n2', lastStatusChange: null, isDisabled: false },
      ]),
    ).toBe(false);
  });
  test('a node that is gone or disabled has nothing left to wait for', () => {
    expect(
      asyncWorkFinished(before, [{ nodeUuid: 'n2', lastStatusChange: null, isDisabled: true }]),
    ).toBe(true);
    expect(asyncWorkFinished([], [])).toBe(true);
  });
});

describe('host locks', () => {
  const refs = {
    listenerHostUuids: new Set(['h-edge']),
    legacyHostUuids: new Set(['h-legacy']),
    hideLedgerUuids: new Set(['h-hidden']),
  };
  test('a Host the edges machinery owns is locked, and says why', () => {
    expect(hostLock('h-edge', refs)).toBe('edge');
    expect(hostLock('h-legacy', refs)).toBe('legacy');
    expect(hostLock('h-hidden', refs)).toBe('hide-ledger');
    expect(hostLock('h-free', refs)).toBeNull();
  });
  test('an operator may not create a remark the edges machinery would own', () => {
    const nodes = ['node-one', 'node.two'];
    expect(looksLikeRelayRemark('node-one-relay', nodes)).toBe(true);
    expect(looksLikeRelayRemark('node-one-relay-a1', nodes)).toBe(true);
    expect(looksLikeRelayRemark('node.two-relay-x', nodes)).toBe(true);
    expect(looksLikeRelayRemark('nodeXtwo-relay-x', nodes)).toBe(false);
    expect(looksLikeRelayRemark('node-one-direct', nodes)).toBe(false);
    expect(looksLikeRelayRemark('other-relay', nodes)).toBe(false);
  });
});
