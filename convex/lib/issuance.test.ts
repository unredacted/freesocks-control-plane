/// <reference types="vite/client" />
/**
 * Issuance-saga compensation (Phase 3): when the backend create succeeded but a
 * LATER step fails, the saga must not strand anything — the backend user is
 * deleted (bounded retry), the local row is deleted too (no sweep reclaims a
 * stray `active` row), the instance keyCount is handed back, and a delete that
 * still fails is audited as the operator's orphan-cleanup queue.
 *
 * `issueNewSubscription` is a plain helper, so these run against a hand-stubbed
 * ActionCtx (no convex-test needed); dispatch is matched on function NAME (the
 * `_generated/api` proxies mint a fresh reference object per access, so an
 * identity comparison would never hit).
 */
import { afterEach, describe, expect, test, vi } from 'vitest';
import { getFunctionName } from 'convex/server';
import { issueNewSubscription } from './issuance';
import type { ActionCtx } from '../_generated/server';
import type { Id } from '../_generated/dataModel';

const ISSUED = {
  backendUserId: 'bu-1',
  backendShortId: 's1',
  subscriptionUrl: 'https://panel.test/sub/s1',
  backendServerId: 'srv-1' as Id<'backendServers'>,
};

const SPEC = { username: 'u', trafficLimitBytes: 100, expireAt: null, tag: 'free' };

interface StubOpts {
  failRepoint?: boolean;
  deleteFailures?: number; // how many times deleteUser throws before succeeding
}

function stubCtx(opts: StubOpts = {}) {
  const calls: { fn: string; args: unknown }[] = [];
  let deleteAttempts = 0;
  const ctx = {
    runAction: vi.fn(async (fn: unknown, args: unknown) => {
      const name = getFunctionName(fn as Parameters<typeof getFunctionName>[0]);
      if (name === 'backends:issueUser') return ISSUED;
      if (name === 'backends:deleteUser') {
        deleteAttempts++;
        calls.push({ fn: 'deleteUser', args });
        if (deleteAttempts <= (opts.deleteFailures ?? 0)) throw new Error('panel unreachable');
        return null;
      }
      throw new Error(`unexpected action ${name}`);
    }),
    runMutation: vi.fn(async (fn: unknown, args: unknown) => {
      const name = getFunctionName(fn as Parameters<typeof getFunctionName>[0]);
      if (name === 'subscriptions:insertSubscription') return 'sub-1';
      if (name === 'subscriptions:setCurrentSubscription') {
        if (opts.failRepoint) throw new Error('db blip');
        return null;
      }
      if (name === 'subscriptions:markSubscriptionDeleted') {
        calls.push({ fn: 'markDeleted', args });
        return null;
      }
      if (name === 'backendServers:bumpKeyCount') {
        calls.push({ fn: 'bump', args });
        return null;
      }
      if (name === 'audit:record') {
        calls.push({ fn: 'audit', args });
        return null;
      }
      throw new Error(`unexpected mutation ${name}`);
    }),
    runQuery: vi.fn(),
    scheduler: { runAfter: vi.fn() },
  } as unknown as ActionCtx;
  return { ctx, calls, deleteAttempts: () => deleteAttempts };
}

afterEach(() => {
  vi.useRealTimers();
});

describe('issueNewSubscription compensation', () => {
  test('happy path: no compensation at all', async () => {
    const { ctx, calls } = stubCtx();
    const out = await issueNewSubscription(ctx, {
      userId: 'u1' as Id<'users'>,
      backend: 'remnawave',
      spec: SPEC,
    });
    expect(out.subscriptionId).toBe('sub-1');
    expect(calls).toHaveLength(0);
  });

  test('a repoint failure deletes the backend user, the local row, and hands back the keyCount', async () => {
    const { ctx, calls } = stubCtx({ failRepoint: true });
    await expect(
      issueNewSubscription(ctx, { userId: 'u1' as Id<'users'>, backend: 'remnawave', spec: SPEC }),
    ).rejects.toThrow('db blip');
    expect(calls.map((c) => c.fn)).toEqual(['deleteUser', 'markDeleted', 'bump']);
    expect(calls.find((c) => c.fn === 'bump')?.args).toMatchObject({ id: 'srv-1', delta: -1 });
    expect(calls.find((c) => c.fn === 'markDeleted')?.args).toMatchObject({
      subscriptionId: 'sub-1',
    });
  });

  test('a delete that keeps failing retries (bounded), then audits the orphan', async () => {
    vi.useFakeTimers();
    const { ctx, calls, deleteAttempts } = stubCtx({ failRepoint: true, deleteFailures: 3 });
    const saga = issueNewSubscription(ctx, {
      userId: 'u1' as Id<'users'>,
      backend: 'remnawave',
      spec: SPEC,
    });
    const assertion = expect(saga).rejects.toThrow('db blip');
    await vi.advanceTimersByTimeAsync(5_000);
    await assertion;
    expect(deleteAttempts()).toBe(3); // bounded, not infinite
    const audit = calls.find((c) => c.fn === 'audit');
    expect(audit?.args).toMatchObject({
      actorType: 'system',
      action: 'subscription.compensation_failed',
      payload: { backend: 'remnawave', backendUserId: 'bu-1' },
    });
    // The local row is still cleaned even though the panel delete failed.
    expect(calls.some((c) => c.fn === 'markDeleted')).toBe(true);
  });

  test('a transient delete blip succeeds on retry (no audit)', async () => {
    vi.useFakeTimers();
    const { ctx, calls, deleteAttempts } = stubCtx({ failRepoint: true, deleteFailures: 1 });
    const saga = issueNewSubscription(ctx, {
      userId: 'u1' as Id<'users'>,
      backend: 'remnawave',
      spec: SPEC,
    });
    const assertion = expect(saga).rejects.toThrow('db blip');
    await vi.advanceTimersByTimeAsync(5_000);
    await assertion;
    expect(deleteAttempts()).toBe(2);
    expect(calls.some((c) => c.fn === 'audit')).toBe(false);
  });
});
