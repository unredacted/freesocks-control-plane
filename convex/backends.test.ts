/// <reference types="vite/client" />
/**
 * Generic backend dispatch tests (pass 2): instance pick on issue, the
 * delete-hint path (issuance compensation, where no subscription row exists),
 * and already-gone tolerance. The provider wire functions have their own
 * suites under lib/backends; this covers the dispatch in convex/backends.ts.
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { computeExpireAtIso, gbToBytes } from './lib/backends/types';

const modules = import.meta.glob('./**/*.*s');

describe('issuance spec helpers', () => {
  test('gbToBytes uses binary GiB so a tier of 50 shows as "50 GiB" in Remnawave', () => {
    expect(gbToBytes(50)).toBe(50 * 1024 ** 3);
    expect(gbToBytes(0)).toBe(0);
  });

  test('computeExpireAtIso: a member term wins; free falls to now + window', () => {
    const termMs = Date.UTC(2030, 0, 1);
    expect(computeExpireAtIso(termMs, 90)).toBe(new Date(termMs).toISOString());
    // Free (no membership): ~90 days out (a few seconds of slack for the clock).
    const freeMs = Date.parse(computeExpireAtIso(null, 90));
    expect(freeMs).toBeGreaterThan(Date.now() + 89 * 86_400_000);
    expect(freeMs).toBeLessThan(Date.now() + 91 * 86_400_000);
  });
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

const SPEC = {
  username: 'freesocks-test-user',
  trafficLimitBytes: null,
  expireAt: null,
  tag: 'free',
};

async function seedServer(t: ReturnType<typeof convexTest>): Promise<Id<'backendServers'>> {
  return t.run((ctx) =>
    ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'Test RW',
      slug: 'test-rw',
      config: { type: 'remnawave', baseUrl: 'https://panel.test.example', apiToken: 'tkn' },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: Date.now(),
    }),
  );
}

describe('backends dispatch', () => {
  test('issueUser with zero active instances throws the pool-empty error', async () => {
    const t = convexTest(schema, modules);
    await expect(
      t.action(internal.backends.issueUser, { backend: 'remnawave', spec: SPEC }),
    ).rejects.toThrow(/No active remnawave instances/);
  });

  test('deleteUser with no hint and no resolvable row is a tolerated no-op', async () => {
    const fetchSpy = vi.fn(async () => new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', fetchSpy);
    const t = convexTest(schema, modules);
    const out = await t.action(internal.backends.deleteUser, {
      backend: 'remnawave',
      backendUserId: 'ghost-user',
    });
    expect(out).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test('deleteUser honors the backendServerId hint (compensation path)', async () => {
    const fetchSpy = vi.fn(
      async (..._args: unknown[]) =>
        new Response(JSON.stringify({ response: {} }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    );
    vi.stubGlobal('fetch', fetchSpy);
    const t = convexTest(schema, modules);
    const serverId = await seedServer(t);

    // No subscription row exists — only the hint can resolve the instance.
    await t.action(internal.backends.deleteUser, {
      backend: 'remnawave',
      backendUserId: 'uuid-123',
      backendServerId: serverId,
    });
    expect(fetchSpy).toHaveBeenCalled();
    const firstUrl = String(fetchSpy.mock.calls[0]?.[0]);
    expect(firstUrl).toContain('https://panel.test.example');
    expect(firstUrl).toContain('uuid-123');
  });

  test('issueUser picks an active instance and bumps its keyCount', async () => {
    // Stub the Remnawave issue round-trip: the provider POSTs /api/users and
    // expects a {response: user} envelope matching its RemnawaveUser schema.
    const user = {
      uuid: '7b51b8a0-7a4c-4f0b-9e76-0d6a4c1f2a3b',
      shortUuid: 'short-1',
      username: SPEC.username,
      status: 'ACTIVE',
      trafficLimitBytes: null,
      trafficLimitStrategy: 'MONTH',
      usedTrafficBytes: 0,
      expireAt: null,
      hwidDeviceLimit: null,
      subscriptionUrl: 'https://sub.test.example/short-1',
    };
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(JSON.stringify({ response: user }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
      ),
    );
    const t = convexTest(schema, modules);
    const serverId = await seedServer(t);

    const issued = await t.action(internal.backends.issueUser, {
      backend: 'remnawave',
      spec: SPEC,
    });
    expect(issued.backendServerId).toBe(serverId);
    expect(issued.backendUserId).toBe('7b51b8a0-7a4c-4f0b-9e76-0d6a4c1f2a3b');
    await t.run(async (ctx) => {
      const row = await ctx.db.get(serverId);
      expect(row!.keyCount).toBe(1);
    });
  });

  test('issueUser sends a Remnawave-safe body: uppercased tag + non-null expireAt', async () => {
    const user = {
      uuid: '7b51b8a0-7a4c-4f0b-9e76-0d6a4c1f2a3b',
      shortUuid: 'short-1',
      username: 'freesocks-member-x',
      status: 'ACTIVE',
      trafficLimitBytes: null,
      trafficLimitStrategy: 'MONTH',
      usedTrafficBytes: 0,
      expireAt: null,
      hwidDeviceLimit: null,
      subscriptionUrl: 'https://sub.test.example/short-1',
    };
    const fetchSpy = vi.fn(
      async (_url: string | URL, _init?: RequestInit) =>
        new Response(JSON.stringify({ response: user }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    );
    vi.stubGlobal('fetch', fetchSpy);
    const t = convexTest(schema, modules);
    await seedServer(t);

    // A lowercase slug tag + null expiry — exactly what account.ts builds, and
    // what Remnawave rejected (tag regex + "expireAt is required") before the fix.
    await t.action(internal.backends.issueUser, {
      backend: 'remnawave',
      spec: {
        username: 'freesocks-member-x',
        trafficLimitBytes: null,
        expireAt: null,
        tag: 'member',
      },
    });

    const init = (fetchSpy.mock.calls[0]?.[1] ?? {}) as RequestInit;
    const sent = JSON.parse(String(init.body)) as { tag?: unknown; expireAt?: unknown };
    expect(sent.tag).toBe('MEMBER');
    expect(typeof sent.expireAt).toBe('string');
    expect((sent.expireAt as string).length).toBeGreaterThan(0);
  });
});
