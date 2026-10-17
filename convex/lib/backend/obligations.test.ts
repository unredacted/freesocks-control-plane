import { describe, expect, test } from 'vitest';
import { claimAvailable, fenceHolds } from './fencing';
import { blocksIdentity } from './obligations';

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
    expect(blocksIdentity({ state: 'pending' })).toBe(true);
    expect(blocksIdentity({ state: 'sent' })).toBe(true);
    expect(blocksIdentity({ state: 'unresolved' })).toBe(true);
    expect(blocksIdentity({ state: 'confirmed' })).toBe(false);
    expect(blocksIdentity({ state: 'failed' })).toBe(false);
  });
});
