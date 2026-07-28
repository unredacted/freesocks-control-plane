/// <reference types="vite/client" />
/**
 * The generic placement seam: the resolver registry ⇔ capability invariant,
 * the trivial resolver's contract, and THE priority regression — a mode
 * declared on both backends with no pool bound anywhere is gated on the
 * placement-capable backend but issues placement-null (un-audited) on the
 * placement-less one.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from '../schema';
import { internal } from '../_generated/api';
import type { Id } from '../_generated/dataModel';
import { BACKEND_IDS } from './backendIds';
import { CAPABILITIES } from './backends/capabilities';
import { PLACEMENT_RESOLVERS, TRIVIAL_RESOLVER, resolverFor } from './placement';

const modules = import.meta.glob('../**/*.*s');

describe('registry ⇔ capability invariant', () => {
  test('a backend has a resolver exactly when its placement capability is true', () => {
    for (const b of BACKEND_IDS) {
      expect(PLACEMENT_RESOLVERS[b] !== undefined).toBe(CAPABILITIES[b].placement);
    }
  });

  test('resolverFor falls back to the trivial resolver for placement-less backends', () => {
    for (const b of BACKEND_IDS) {
      if (!CAPABILITIES[b].placement) expect(resolverFor(b)).toBe(TRIVIAL_RESOLVER);
      else expect(resolverFor(b)).not.toBe(TRIVIAL_RESOLVER);
    }
  });
});

describe('trivial resolver contract', () => {
  test('never resolves a placement, never blocks, refuses config writes', async () => {
    const t = convexTest(schema, modules);
    const target = await t.run((ctx) => TRIVIAL_RESOLVER.resolveTarget(ctx.db, 'freedom-ws', {}));
    expect(target).toEqual({ placement: null, serverId: null });
    expect(await t.run((ctx) => TRIVIAL_RESOLVER.effectiveGate(ctx.db, 'freedom-ws'))).toEqual({
      blocked: false,
    });
    expect(() => TRIVIAL_RESOLVER.applyConfigPatch(null, { squadUuids: [] })).toThrow(
      /no placement configuration/i,
    );
    expect(TRIVIAL_RESOLVER.summarize(null)).toEqual({ bound: false, count: 0 });
  });
});

describe('priority regression: multi-backend mode, no pools bound anywhere', () => {
  beforeEach(() => {
    vi.stubEnv('DEV_MOCK_BACKEND', 'true');
    vi.stubEnv('ENVIRONMENT', 'development');
  });
  afterEach(() => vi.unstubAllEnvs());

  async function seedTier(
    t: ReturnType<typeof convexTest>,
    backend: 'remnawave' | 'outline',
  ): Promise<Id<'tiers'>> {
    return t.run((ctx) =>
      ctx.db.insert('tiers', {
        slug: `free-${backend}`,
        name: 'Free',
        backend,
        monthlyTrafficGb: 50,
        deviceLimit: 1,
        hwidLimit: 1,
        hwidEnabled: true,
        trafficStrategy: 'MONTH',
        isDefaultFree: true,
        isActive: true,
        priority: 0,
        expirationDaysAfterMembershipLapse: 0,
        updatedAt: Date.now(),
      }),
    );
  }

  test('outline: issues placement-null WITHOUT the placement-less audit', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, 'outline');
    const userId: Id<'users'> = await t.run((ctx) =>
      ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() }),
    );
    const out = await t.action(internal.account.regenerate, { userId });
    expect(out.subscriptionUrl).toBeTruthy();
    await t.run(async (ctx) => {
      const subs = await ctx.db.query('subscriptions').collect();
      expect(subs).toHaveLength(1);
      expect(subs[0]!.backendPlacement).toBeUndefined();
      // The squad-less-key audit is a placement-capable concept: it must NOT
      // fire for a backend with no placement at all.
      const audits = await ctx.db
        .query('auditLog')
        .withIndex('by_action', (q) => q.eq('action', 'subscription.issued_without_placement'))
        .collect();
      expect(audits).toHaveLength(0);
    });
  });

  test('remnawave: all-unbound bring-up issues squad-less + AUDITED (the WS1 safety net)', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, 'remnawave');
    const userId: Id<'users'> = await t.run((ctx) =>
      ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() }),
    );
    const out = await t.action(internal.account.regenerate, { userId });
    expect(out.subscriptionUrl).toBeTruthy();
    await t.run(async (ctx) => {
      const audits = await ctx.db
        .query('auditLog')
        .withIndex('by_action', (q) => q.eq('action', 'subscription.issued_without_placement'))
        .collect();
      expect(audits).toHaveLength(1);
    });
  });
});
