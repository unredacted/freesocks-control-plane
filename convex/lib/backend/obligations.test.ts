import { describe, expect, test } from 'vitest';
import { claimAvailable, fenceHolds } from './fencing';
import {
  blockingObligation,
  callbackAdvancesCurrent,
  onLeaseExpiry,
  settleResource,
} from './obligations';

describe('settleResource', () => {
  test('a late create the current generation still needs is reused, never deleted', () => {
    expect(
      settleResource(
        { kind: 'node', verb: 'create', ownership: 'created' },
        { needed: true, referenced: false },
      ),
    ).toEqual({ outcome: 'reuse' });
  });
  test('an update never authorises a delete; shared and adopted objects are never disposable', () => {
    expect(
      settleResource(
        { kind: 'host', verb: 'update', ownership: 'created' },
        { needed: false, referenced: false },
      ),
    ).toEqual({ outcome: 'retain', reason: 'update' });
    expect(
      settleResource(
        { kind: 'profile.create', verb: 'create', ownership: 'shared' },
        { needed: false, referenced: false },
      ),
    ).toEqual({ outcome: 'retain', reason: 'shared' });
    expect(
      settleResource(
        { kind: 'host', verb: 'create', ownership: 'adopted' },
        { needed: false, referenced: false },
      ),
    ).toEqual({ outcome: 'retain', reason: 'adopted' });
  });
  test('only a created, unneeded, unreferenced resource is deleted', () => {
    expect(
      settleResource(
        { kind: 'dns.record', verb: 'create', ownership: 'created' },
        { needed: false, referenced: true },
      ),
    ).toEqual({ outcome: 'retain', reason: 'referenced' });
    expect(
      settleResource(
        { kind: 'dns.record', verb: 'create', ownership: 'created' },
        { needed: false, referenced: false },
      ),
    ).toEqual({ outcome: 'delete' });
  });
});

describe('fences and leases', () => {
  test('a stale generation or a foreign attempt never acts', () => {
    const row = { generation: 2, claim: { attemptId: 'a2', expiresAt: 10 } };
    expect(fenceHolds(row, { generation: 2, attemptId: 'a2' })).toBe(true);
    expect(fenceHolds(row, { generation: 1, attemptId: 'a2' })).toBe(false);
    expect(fenceHolds(row, { generation: 2, attemptId: 'a1' })).toBe(false);
    expect(fenceHolds({ generation: 2, claim: null }, { generation: 2, attemptId: 'a2' })).toBe(
      false,
    );
  });
  test('a lease is available only when absent or expired', () => {
    expect(claimAvailable({ generation: 1, claim: null }, 5)).toBe(true);
    expect(claimAvailable({ generation: 1, claim: { attemptId: 'a', expiresAt: 10 } }, 5)).toBe(
      false,
    );
    expect(claimAvailable({ generation: 1, claim: { attemptId: 'a', expiresAt: 10 } }, 10)).toBe(
      true,
    );
  });
  test('an outstanding obligation blocks its identity whatever generation owns it', () => {
    expect(blockingObligation([{ state: 'confirmed' }, { state: 'unresolved' }])).toBe(1);
    expect(blockingObligation([{ state: 'confirmed' }, { state: 'failed' }])).toBe(-1);
  });
  test('a lease expiry only resumes discovery of the same attempt', () => {
    expect(onLeaseExpiry({ state: 'sent' })).toBe('discover');
    expect(onLeaseExpiry({ state: 'unresolved' })).toBe('discover');
    expect(onLeaseExpiry({ state: 'pending' })).toBe('nothing');
    expect(onLeaseExpiry({ state: 'confirmed' })).toBe('nothing');
  });
  test('a callback of a superseded generation never advances the current one', () => {
    expect(callbackAdvancesCurrent({ ownerGeneration: 1 }, 2)).toBe(false);
    expect(callbackAdvancesCurrent({ ownerGeneration: 2 }, 2)).toBe(true);
  });
});
