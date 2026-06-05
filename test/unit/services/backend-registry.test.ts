import { describe, expect, it } from 'vitest';
import { BackendRegistry } from '../../../src/server/services/backend-registry';
import type { ProxyBackendProvider } from '../../../src/server/providers/backend';

/**
 * `BackendRegistry` is the single dispatch point that keeps the rest of the
 * codebase backend-agnostic. These tests pin down the contract that callers
 * rely on:
 *
 * - `fromTier` / `fromSubscription` route on the row's `backend` column.
 * - A missing/undefined `backend` falls back to `remnawave` so legacy rows
 *   (which only existed before migration 0004) keep working.
 * - Unknown backend ids throw rather than silently routing to remnawave —
 *   silent fallback would mask config errors.
 */

function stubProvider(id: 'remnawave' | 'outline'): ProxyBackendProvider {
  return {
    id,
    // The unit tests don't exercise these methods; cast through `unknown` to
    // keep the stub minimal but type-correct from the caller's perspective.
    issueUser: () => Promise.reject(new Error('stub')),
    getUser: () => Promise.reject(new Error('stub')),
    updateUser: () => Promise.reject(new Error('stub')),
    resetUserTraffic: () => Promise.reject(new Error('stub')),
    deleteUser: () => Promise.reject(new Error('stub')),
    fetchSubscriptionContent: () => Promise.reject(new Error('stub')),
  } as ProxyBackendProvider;
}

describe('BackendRegistry', () => {
  function buildRegistry() {
    const providers = new Map([
      ['remnawave', stubProvider('remnawave')],
      ['outline', stubProvider('outline')],
    ] as const);
    return new BackendRegistry(providers);
  }

  it('get(id) returns the registered provider', () => {
    const reg = buildRegistry();
    expect(reg.get('remnawave').id).toBe('remnawave');
    expect(reg.get('outline').id).toBe('outline');
  });

  it('get(id) throws for an unregistered backend', () => {
    const reg = new BackendRegistry(new Map());
    expect(() => reg.get('remnawave')).toThrow(/not registered/);
  });

  it('has(id) reflects registration', () => {
    const reg = buildRegistry();
    expect(reg.has('remnawave')).toBe(true);
    expect(reg.has('outline')).toBe(true);
    expect(reg.has('wireguard' as never)).toBe(false);
  });

  it('fromTier routes on the row.backend column', () => {
    const reg = buildRegistry();
    expect(reg.fromTier({ backend: 'remnawave' }).id).toBe('remnawave');
    expect(reg.fromTier({ backend: 'outline' }).id).toBe('outline');
  });

  it('fromSubscription routes on the row.backend column', () => {
    const reg = buildRegistry();
    expect(reg.fromSubscription({ backend: 'remnawave' }).id).toBe('remnawave');
    expect(reg.fromSubscription({ backend: 'outline' }).id).toBe('outline');
  });

  it('falls back to remnawave when the backend column is undefined', () => {
    const reg = buildRegistry();
    // Simulates a legacy row from before migration 0004 added the column.
    expect(reg.fromSubscription({}).id).toBe('remnawave');
    expect(reg.fromTier({}).id).toBe('remnawave');
  });

  it('falls back to remnawave when the backend column is null', () => {
    const reg = buildRegistry();
    expect(reg.fromSubscription({ backend: null }).id).toBe('remnawave');
  });

  it('registeredIds() lists every registered backend', () => {
    const reg = buildRegistry();
    const ids = reg.registeredIds().sort();
    expect(ids).toEqual(['outline', 'remnawave']);
  });
});
