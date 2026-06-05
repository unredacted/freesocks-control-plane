import { describe, expect, it } from 'vitest';
import { ApiScope, ApiScopeArray, SCOPE_GROUPS } from '../../../src/shared/contracts/scopes';

describe('ApiScope contract', () => {
  it('accepts every documented scope', () => {
    const all = [...SCOPE_GROUPS.member, ...SCOPE_GROUPS.admin];
    for (const scope of all) {
      expect(() => ApiScope.parse(scope)).not.toThrow();
    }
  });

  it('rejects unknown scopes', () => {
    expect(() => ApiScope.parse('admin:secrets:read')).toThrow();
    expect(() => ApiScope.parse('subscription:*')).toThrow();
  });

  it('ApiScopeArray validates a non-empty list', () => {
    expect(() => ApiScopeArray.parse(['subscription:read', 'account:read'])).not.toThrow();
    expect(() => ApiScopeArray.parse([])).not.toThrow(); // empty allowed at the array level
  });

  it('member group does not include admin scopes', () => {
    const memberSet = new Set(SCOPE_GROUPS.member);
    for (const adminScope of SCOPE_GROUPS.admin) {
      expect(memberSet.has(adminScope as never)).toBe(false);
    }
  });
});
