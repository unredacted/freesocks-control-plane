/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';

const modules = import.meta.glob('./**/*.*s');

async function seedTier(t: ReturnType<typeof convexTest>): Promise<Id<'tiers'>> {
  return t.run((ctx) =>
    ctx.db.insert('tiers', {
      slug: 'free',
      name: 'Free',
      backend: 'remnawave',
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

function subFields(
  userId: Id<'users'>,
  backendUserId: string,
  state: 'active' | 'disabled' | 'deleted',
) {
  return {
    userId,
    backend: 'remnawave' as const,
    backendUserId,
    backendShortId: `short-${backendUserId}`,
    subscriptionUrl: `https://sub.example/${backendUserId}`,
    subscriptionMirrors: [],
    state,
    updatedAt: Date.now(),
  };
}

describe('subscriptions.resolveCurrentOrActive', () => {
  test('prefers the user.currentSubscriptionId when it is active', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const { userId, currentId } = await t.run(async (ctx) => {
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      // Newest row is "other"; current points at an older but active row.
      const currentId = await ctx.db.insert('subscriptions', subFields(userId, 'cur', 'active'));
      await ctx.db.insert('subscriptions', subFields(userId, 'newer', 'active'));
      await ctx.db.patch(userId, { currentSubscriptionId: currentId });
      return { userId, currentId };
    });
    const res = await t.query(internal.subscriptions.resolveCurrentOrActive, { userId });
    expect(res?._id).toBe(currentId);
    expect(res?.backendUserId).toBe('cur');
  });

  test('falls back to the newest active row when currentSubscriptionId is unset', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const { userId, newerId } = await t.run(async (ctx) => {
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      await ctx.db.insert('subscriptions', subFields(userId, 'older', 'active'));
      const newerId = await ctx.db.insert('subscriptions', subFields(userId, 'newer', 'active'));
      return { userId, newerId };
    });
    const res = await t.query(internal.subscriptions.resolveCurrentOrActive, { userId });
    expect(res?._id).toBe(newerId);
  });

  test('ignores a deleted currentSubscriptionId and falls back to active', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const { userId, activeId } = await t.run(async (ctx) => {
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      const deletedId = await ctx.db.insert('subscriptions', subFields(userId, 'gone', 'deleted'));
      const activeId = await ctx.db.insert('subscriptions', subFields(userId, 'live', 'active'));
      await ctx.db.patch(userId, { currentSubscriptionId: deletedId });
      return { userId, activeId };
    });
    const res = await t.query(internal.subscriptions.resolveCurrentOrActive, { userId });
    expect(res?._id).toBe(activeId);
    expect(res?.state).toBe('active');
  });

  test('returns null when the user has only deleted subscriptions', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await t.run(async (ctx) => {
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      await ctx.db.insert('subscriptions', subFields(userId, 'd1', 'deleted'));
      return userId;
    });
    expect(await t.query(internal.subscriptions.resolveCurrentOrActive, { userId })).toBeNull();
  });
});

describe('subscriptions.updateMirrors — refresh merge (Review #2)', () => {
  test('a failed provider is retained (status:failed) not dropped; triedProviders (cap) holds', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const { userId, subId } = await t.run(async (ctx) => {
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      const subId = await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave' as const,
        backendUserId: 'bu',
        backendShortId: 'short',
        subscriptionUrl: 'https://sub.example/x',
        subscriptionMirrors: [
          { provider: 'A', publicUrl: 'https://a/old', objectPath: 'p', status: 'ok' as const },
          { provider: 'B', publicUrl: 'https://b/old', objectPath: 'p', status: 'ok' as const },
        ],
        state: 'active' as const,
        updatedAt: Date.now(),
      });
      await ctx.db.patch(userId, { currentSubscriptionId: subId });
      return { userId, subId };
    });

    // Refresh round: A refreshed (new URL), B failed.
    await t.mutation(internal.subscriptions.updateMirrors, {
      subscriptionId: subId,
      successes: [{ provider: 'A', publicUrl: 'https://a/new', objectPath: 'p', status: 'ok' }],
      failedProviders: ['B'],
      rawContentHash: 'h2',
    });

    const row = await t.run((ctx) => ctx.db.get(subId));
    const byProvider = new Map((row?.subscriptionMirrors ?? []).map((m) => [m.provider, m]));
    expect(byProvider.get('A')?.publicUrl).toBe('https://a/new'); // refreshed in place
    expect(byProvider.get('A')?.status).toBe('ok');
    expect(byProvider.get('B')).toBeTruthy(); // NOT dropped…
    expect(byProvider.get('B')?.status).toBe('failed'); // …marked failed…
    expect(byProvider.get('B')?.publicUrl).toBe('https://b/old'); // …stale entry retained

    // The per-user cap counts BOTH providers still (failed one included), so the
    // member can't re-provision past the cap.
    const mc = await t.query(internal.subscriptions.mirrorContextForUser, { userId });
    expect(new Set(mc?.triedProviders)).toEqual(new Set(['A', 'B']));
  });
});

describe('subscriptions.pageActiveForMirror', () => {
  test('carries excludeNode so the refresh re-pins like the live route', async () => {
    // Node pinning is deterministic: a refresh that fetches WITHOUT the exclusion
    // regenerates the node the member just switched away from, the content hash
    // matches, and storage.refreshActiveMirrors skips the re-upload — parking the
    // mirror on the old server indefinitely.
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() }),
    );
    await t.run(async (ctx) => {
      await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'k1',
        backendShortId: 'short1',
        subscriptionUrl: 'https://panel.test/sub/short1',
        subscriptionMirrors: [{ provider: 'p1', publicUrl: 'https://mirror/x', objectPath: 'x' }],
        excludeNode: 'xray1',
        state: 'active',
        updatedAt: Date.now(),
      });
    });

    const page = await t.query(internal.subscriptions.pageActiveForMirror, {
      cursor: null,
      numItems: 10,
    });
    expect(page.items).toHaveLength(1);
    expect(page.items[0]!.excludeNode).toBe('xray1');
  });

  test('reports null when the key has never been switched', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() }),
    );
    await t.run(async (ctx) => {
      await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'k2',
        backendShortId: 'short2',
        subscriptionUrl: 'https://panel.test/sub/short2',
        subscriptionMirrors: [{ provider: 'p1', publicUrl: 'https://mirror/y', objectPath: 'y' }],
        state: 'active',
        updatedAt: Date.now(),
      });
    });

    const page = await t.query(internal.subscriptions.pageActiveForMirror, {
      cursor: null,
      numItems: 10,
    });
    expect(page.items[0]!.excludeNode).toBeNull();
  });
});

describe('subscriptions.insertSubscription — mirror carry', () => {
  const MIRROR = { provider: 'p1', publicUrl: 'https://cdn.test/x', objectPath: 'subs/x' };

  async function seedOld(t: ReturnType<typeof convexTest>, withMirror: boolean) {
    const tierId = await seedTier(t);
    return t.run(async (ctx) => {
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      const id = await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'old',
        backendShortId: 'oldshort',
        subscriptionUrl: 'https://panel.test/sub/oldshort',
        subToken: 'tok-abc',
        subscriptionMirrors: withMirror ? [MIRROR] : [],
        rawContentHash: 'hash-old',
        state: 'active',
        updatedAt: Date.now(),
      });
      return { userId, id };
    });
  }

  test('carries mirrors with the token and VACATES them from the old row', async () => {
    // The member's imported mirror URL must keep working across a switch. It can
    // only do so if the new row owns the entry (the refresh cron pages ACTIVE
    // rows) and the old row no longer does — teardown deletes the S3 objects
    // listed on the row it tears down, which would destroy the live object.
    const t = convexTest(schema, modules);
    const { userId, id: oldId } = await seedOld(t, true);
    const newId = await t.run((ctx) =>
      ctx.runMutation(internal.subscriptions.insertSubscription, {
        userId,
        backend: 'remnawave',
        backendUserId: 'new',
        backendShortId: 'newshort',
        subscriptionUrl: 'https://panel.test/sub/newshort',
        subscriptionMirrors: [],
        carrySubTokenFromId: oldId,
      }),
    );

    await t.run(async (ctx) => {
      const fresh = (await ctx.db.get(newId))!;
      expect(fresh.subscriptionMirrors).toEqual([MIRROR]);
      expect(fresh.subToken).toBe('tok-abc');
      // No hash on the new row → the next refresh cannot short-circuit, so the
      // object is rewritten with the new key's config.
      expect(fresh.rawContentHash).toBeUndefined();
      const old = (await ctx.db.get(oldId))!;
      expect(old.subscriptionMirrors).toEqual([]); // vacated: teardown won't delete it
      expect(old.subToken).toBeUndefined();
    });
  });

  test('a rotation (no token carry) leaves the old mirrors behind to be swept', async () => {
    // regenerate deliberately invalidates the old link; its mirror must go with it.
    const t = convexTest(schema, modules);
    const { userId, id: oldId } = await seedOld(t, true);
    const newId = await t.run((ctx) =>
      ctx.runMutation(internal.subscriptions.insertSubscription, {
        userId,
        backend: 'remnawave',
        backendUserId: 'new',
        backendShortId: 'newshort',
        subscriptionUrl: 'https://panel.test/sub/newshort',
        subscriptionMirrors: [],
      }),
    );

    await t.run(async (ctx) => {
      expect((await ctx.db.get(newId))!.subscriptionMirrors).toEqual([]);
      expect((await ctx.db.get(oldId))!.subscriptionMirrors).toEqual([MIRROR]);
    });
  });
});

describe('subscriptions.updateMirrors — partial rounds hold the hash', () => {
  test('omitting rawContentHash leaves the stored one intact', async () => {
    // A partial round must not advance the hash, or the next refresh takes the
    // unchanged-content short-circuit and never retries the stale provider.
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const subId = await t.run(async (ctx) => {
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      return ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'k',
        backendShortId: 's',
        subscriptionUrl: 'https://panel.test/sub/s',
        subscriptionMirrors: [
          { provider: 'p1', publicUrl: 'https://cdn.test/a', objectPath: 'a' },
          { provider: 'p2', publicUrl: 'https://cdn2.test/a', objectPath: 'a' },
        ],
        rawContentHash: 'hash-old',
        state: 'active',
        updatedAt: Date.now(),
      });
    });

    await t.mutation(internal.subscriptions.updateMirrors, {
      subscriptionId: subId,
      successes: [{ provider: 'p1', publicUrl: 'https://cdn.test/a', objectPath: 'a' }],
      failedProviders: ['p2'],
      // no rawContentHash — p2 is still serving the old content
    });

    await t.run(async (ctx) => {
      const row = (await ctx.db.get(subId))!;
      expect(row.rawContentHash).toBe('hash-old'); // held, so p2 is retried
      expect(row.subscriptionMirrors.find((m) => m.provider === 'p2')!.status).toBe('failed');
    });
  });
});

describe('subscriptions.updateMirrors — an in-flight refresh cannot reclaim a carry', () => {
  test('drops successes for providers the row no longer lists', async () => {
    // The refresh pages the old row, then a switch vacates its mirrors onto the
    // replacement, then the in-flight upload reports success against the OLD id.
    // Re-attaching would leave two rows owning one object path — and tearing the
    // old row down would delete the object the live row is serving.
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const { oldId, newId } = await t.run(async (ctx) => {
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      const oldId = await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'old',
        backendShortId: 'oldshort',
        subscriptionUrl: 'https://panel.test/sub/oldshort',
        subToken: 'tok-abc',
        subscriptionMirrors: [
          { provider: 'p1', publicUrl: 'https://cdn.test/x', objectPath: 'subs/x' },
        ],
        state: 'active',
        updatedAt: Date.now(),
      });
      const newId = await ctx.runMutation(internal.subscriptions.insertSubscription, {
        userId,
        backend: 'remnawave',
        backendUserId: 'new',
        backendShortId: 'newshort',
        subscriptionUrl: 'https://panel.test/sub/newshort',
        subscriptionMirrors: [],
        carrySubTokenFromId: oldId,
      });
      return { oldId, newId };
    });

    // The straggler write lands on the (still active) old row.
    await t.mutation(internal.subscriptions.updateMirrors, {
      subscriptionId: oldId,
      successes: [{ provider: 'p1', publicUrl: 'https://cdn.test/x', objectPath: 'subs/x' }],
      failedProviders: [],
      rawContentHash: 'hash-new',
    });

    await t.run(async (ctx) => {
      // The old row stays empty: exactly one row owns the object path.
      expect((await ctx.db.get(oldId))!.subscriptionMirrors).toEqual([]);
      expect((await ctx.db.get(newId))!.subscriptionMirrors).toHaveLength(1);
    });
  });
});

describe('subscriptions.markSubscriptionDeleted — compensation returns the carry', () => {
  const MIRROR = { provider: 'p1', publicUrl: 'https://cdn.test/x', objectPath: 'subs/x' };

  test('hands BOTH the token and the mirrors back to the still-live source row', async () => {
    // A saga that inserts the replacement and then fails (e.g. setCurrentSubscription)
    // must leave the original exactly as it found it. Restoring only the token
    // would strand the mirrors on a deleted row: never refreshed again, and the
    // member's imported mirror URL goes stale.
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const { sourceId, dyingId } = await t.run(async (ctx) => {
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      const sourceId = await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'old',
        backendShortId: 'oldshort',
        subscriptionUrl: 'https://panel.test/sub/oldshort',
        subToken: 'tok-abc',
        subscriptionMirrors: [MIRROR],
        state: 'active',
        updatedAt: Date.now(),
      });
      // The replacement, minted by insertSubscription (which vacated both).
      const dyingId = await ctx.runMutation(internal.subscriptions.insertSubscription, {
        userId,
        backend: 'remnawave',
        backendUserId: 'new',
        backendShortId: 'newshort',
        subscriptionUrl: 'https://panel.test/sub/newshort',
        subscriptionMirrors: [],
        carrySubTokenFromId: sourceId,
      });
      return { sourceId, dyingId };
    });

    await t.mutation(internal.subscriptions.markSubscriptionDeleted, {
      subscriptionId: dyingId,
      returnSubTokenToId: sourceId,
    });

    await t.run(async (ctx) => {
      const source = (await ctx.db.get(sourceId))!;
      expect(source.subToken).toBe('tok-abc');
      expect(source.subscriptionMirrors).toEqual([MIRROR]);
      const dying = (await ctx.db.get(dyingId))!;
      expect(dying.state).toBe('deleted');
      expect(dying.subToken).toBeUndefined();
      // Released too, so tearing down the dead row cannot delete the S3 object
      // the source row now owns again.
      expect(dying.subscriptionMirrors).toEqual([]);
    });
  });
});

describe('subscriptions.updateMirrors — a stale writer names the current owner', () => {
  test('reports staleWriter + the owner so the caller can repair the object', async () => {
    // Dropping the DB write stops the old row reclaiming ownership, but its S3
    // upload already overwrote the shared object with the old key's config. The
    // mutation reports that, and who owns the object now, so the caller can
    // re-drive the owner's refresh instead of leaving a dead key in the mirror.
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const { oldId, newId } = await t.run(async (ctx) => {
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      const oldId = await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'old',
        backendShortId: 'oldshort',
        subscriptionUrl: 'https://panel.test/sub/oldshort',
        subToken: 'tok-abc',
        subscriptionMirrors: [
          { provider: 'p1', publicUrl: 'https://cdn.test/x', objectPath: 'subs/x' },
        ],
        rawContentHash: 'old-hash',
        state: 'active',
        updatedAt: Date.now(),
      });
      await ctx.db.patch(userId, { currentSubscriptionId: oldId });
      const newId = await ctx.runMutation(internal.subscriptions.insertSubscription, {
        userId,
        backend: 'remnawave',
        backendUserId: 'new',
        backendShortId: 'newshort',
        subscriptionUrl: 'https://panel.test/sub/newshort',
        subscriptionMirrors: [],
        carrySubTokenFromId: oldId,
      });
      await ctx.db.patch(userId, { currentSubscriptionId: newId });
      return { oldId, newId };
    });

    const res = await t.mutation(internal.subscriptions.updateMirrors, {
      subscriptionId: oldId,
      successes: [{ provider: 'p1', publicUrl: 'https://cdn.test/x', objectPath: 'subs/x' }],
      failedProviders: [],
      rawContentHash: 'stale-hash',
    });

    expect(res).toEqual({ staleWriter: true, currentOwner: newId });
    await t.run(async (ctx) => {
      // Ownership did not move back.
      expect((await ctx.db.get(oldId))!.subscriptionMirrors).toEqual([]);
    });
  });

  test('a normal round reports no stale writer', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const subId = await t.run(async (ctx) => {
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      const subId = await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'k',
        backendShortId: 's',
        subscriptionUrl: 'https://panel.test/sub/s',
        subscriptionMirrors: [{ provider: 'p1', publicUrl: 'https://cdn.test/a', objectPath: 'a' }],
        state: 'active',
        updatedAt: Date.now(),
      });
      await ctx.db.patch(userId, { currentSubscriptionId: subId });
      return subId;
    });

    const res = await t.mutation(internal.subscriptions.updateMirrors, {
      subscriptionId: subId,
      successes: [{ provider: 'p1', publicUrl: 'https://cdn.test/a', objectPath: 'a' }],
      failedProviders: [],
      rawContentHash: 'h',
    });

    expect(res).toEqual({ staleWriter: false, currentOwner: null });
  });
});

describe('subscriptions.appendMirror — a superseded row is refused', () => {
  test('refuses a late provision against a row a re-issue has replaced', async () => {
    // provisionMirror reads its context, a switch re-issues, and the upload then
    // reports back against the OLD id. That row is still `active` until the
    // tombstone a moment later, so state alone does not catch it — and appending
    // would hand the member a URL that is deleted with the old row.
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const { oldId, newId } = await t.run(async (ctx) => {
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      const oldId = await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'old',
        backendShortId: 'oldshort',
        subscriptionUrl: 'https://panel.test/sub/oldshort',
        subToken: 'tok-abc',
        subscriptionMirrors: [],
        state: 'active',
        updatedAt: Date.now(),
      });
      await ctx.db.patch(userId, { currentSubscriptionId: oldId });
      const newId = await ctx.runMutation(internal.subscriptions.insertSubscription, {
        userId,
        backend: 'remnawave',
        backendUserId: 'new',
        backendShortId: 'newshort',
        subscriptionUrl: 'https://panel.test/sub/newshort',
        subscriptionMirrors: [],
        carrySubTokenFromId: oldId,
      });
      // The saga repoints the user before the old row is tombstoned.
      await ctx.db.patch(userId, { currentSubscriptionId: newId });
      return { oldId, newId };
    });

    const res = await t.mutation(internal.subscriptions.appendMirror, {
      subscriptionId: oldId,
      mirror: { provider: 'p1', publicUrl: 'https://cdn.test/x', objectPath: 'subs/x' },
      rawContentHash: 'h',
      cap: 3,
    });

    expect(res).toEqual({ appended: false, reason: 'superseded' });
    await t.run(async (ctx) => {
      expect((await ctx.db.get(oldId))!.subscriptionMirrors).toEqual([]);
      expect((await ctx.db.get(newId))!.subscriptionMirrors).toEqual([]);
    });
  });

  test('refuses in the window BEFORE the user pointer is repointed', async () => {
    // issueNewSubscription inserts the replacement and repoints
    // currentSubscriptionId in two separate mutations. In between, the pointer
    // still names the old row while its replacement already exists — a
    // pointer-only check would wave the late append through exactly there.
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const { oldId } = await t.run(async (ctx) => {
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      const oldId = await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'old',
        backendShortId: 'oldshort',
        subscriptionUrl: 'https://panel.test/sub/oldshort',
        subToken: 'tok-abc',
        subscriptionMirrors: [],
        state: 'active',
        updatedAt: Date.now(),
      });
      await ctx.db.patch(userId, { currentSubscriptionId: oldId });
      await ctx.runMutation(internal.subscriptions.insertSubscription, {
        userId,
        backend: 'remnawave',
        backendUserId: 'new',
        backendShortId: 'newshort',
        subscriptionUrl: 'https://panel.test/sub/newshort',
        subscriptionMirrors: [],
        carrySubTokenFromId: oldId,
      });
      // Deliberately NOT repointed: this is the gap between the two mutations.
      return { oldId };
    });

    const res = await t.mutation(internal.subscriptions.appendMirror, {
      subscriptionId: oldId,
      mirror: { provider: 'p1', publicUrl: 'https://cdn.test/x', objectPath: 'subs/x' },
      rawContentHash: 'h',
      cap: 3,
    });

    expect(res).toEqual({ appended: false, reason: 'superseded' });
    await t.run(async (ctx) => {
      expect((await ctx.db.get(oldId))!.subscriptionMirrors).toEqual([]);
    });
  });

  test('still appends normally to the current subscription', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const subId = await t.run(async (ctx) => {
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      const subId = await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'k',
        backendShortId: 's',
        subscriptionUrl: 'https://panel.test/sub/s',
        subscriptionMirrors: [],
        state: 'active',
        updatedAt: Date.now(),
      });
      await ctx.db.patch(userId, { currentSubscriptionId: subId });
      return subId;
    });

    const res = await t.mutation(internal.subscriptions.appendMirror, {
      subscriptionId: subId,
      mirror: { provider: 'p1', publicUrl: 'https://cdn.test/x', objectPath: 'subs/x' },
      rawContentHash: 'h',
      cap: 3,
    });

    expect(res.appended).toBe(true);
    await t.run(async (ctx) => {
      expect((await ctx.db.get(subId))!.subscriptionMirrors).toHaveLength(1);
    });
  });
});
