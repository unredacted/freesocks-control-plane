/// <reference types="vite/client" />
/**
 * Finding names: the counts every page shows agree with the candidates
 * (docs/edges.md "Finding names").
 *
 *  - a scope's counts move with each change at once (an insert, a check that
 *    passes or stops passing, an ignore, a family taking a name, a delete),
 *    so the overview never waits for a cron tick;
 *  - the recount that makes them absolute again runs whether finding names is
 *    on or not, oldest-marked scope first, so a busy scope never starves another;
 *  - a family moved to another network loses what was found for it on the old one;
 *  - a network's page lists what was found for the families on it, apart from
 *    its own sites.
 *
 * Fixtures use RFC 5737 / RFC 3849 addresses and `*.example.*` names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { signValue } from './lib/cookies';
import { __setHuntDepsForTests, type HuntDeps } from './sniHuntOps';
import { SniHuntScopeView, usableCandidate } from '../src/shared/contracts/sni';

const modules = import.meta.glob('./**/*.*s');
const ADMIN_SIGN_KEY = 'test-admin-sign';
type T = TestConvex<typeof schema>;
const NET = { v4: ['192.0.2.0/24'], v6: ['2001:db8::/32'] };
const TARGET_IP = '192.0.2.10';
const MIN = 60_000;

let clock = 0;
beforeEach(() => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval'] });
  clock = Date.UTC(2026, 9, 26, 12);
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', ADMIN_SIGN_KEY);
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});
afterEach(() => {
  __setHuntDepsForTests(null);
  vi.useRealTimers();
  vi.unstubAllEnvs();
});

// The names on the target's certificate (the target's own hostname among them).
const CERT = [
  'target.example.com',
  'www.example.com',
  ...Array.from({ length: 10 }, (_, i) => `n${i}.example.com`),
];

function deps() {
  const zone: Record<string, string[]> = { 'target.example.com': [TARGET_IP] };
  CERT.forEach((n, i) => (zone[n] ??= [`192.0.2.${20 + i}`]));
  const d: Partial<HuntDeps> = {
    resolve4: async (n) => zone[n] ?? (n.endsWith('.example.net') ? ['192.0.2.99'] : []),
    resolve6: async () => [],
    lookup: async (n) => zone[n] ?? [],
    tlsInspect: async () => ({
      ok: true,
      authorized: true,
      protocol: 'TLSv1.3',
      alpn: 'h2',
      names: CERT,
    }),
    now: () => clock,
    sleep: async () => undefined,
  };
  __setHuntDepsForTests(d);
}

async function net(t: T, slug: string) {
  return t.run((ctx) =>
    ctx.db.insert('edgeNetworks', {
      slug,
      label: slug,
      asns: [64500],
      announced: NET,
      manualPrefixes: [],
      prefixes: NET,
      hunt: { enabled: false },
      updatedAt: clock,
    }),
  );
}

async function setHunt(t: T, on: boolean) {
  await t.mutation(internal.sniFamilies.patchConfig, { patch: { hunt: { enabled: on } } });
}

async function seed() {
  const t = convexTest(schema, modules);
  await setHunt(t, true);
  const networkId = await net(t, 'net-a');
  const familyId = await t.run((ctx) =>
    ctx.db.insert('sniFamilies', {
      slug: 'fam-a',
      label: 'Fam A',
      target: { kind: 'static', address: 'target.example.com', port: 443 },
      enabled: true,
      requireH2: true,
      networkId,
      nextSeq: 1,
      updatedAt: clock,
    }),
  );
  const adminUserId = await t.run((ctx) =>
    ctx.db.insert('adminUsers', {
      username: 'op',
      displayName: 'Op',
      isActive: true,
      updatedAt: clock,
    }),
  );
  const sid = `asid-${Math.random().toString(36).slice(2)}`;
  await t.mutation(internal.sessions.create, { sid, kind: 'admin', adminUserId, ttlMs: 3_600_000 });
  const cookie = `fs_admin_session=${await signValue(sid, ADMIN_SIGN_KEY)}`;
  const get = async (path: string) =>
    SniHuntScopeView.parse(
      await (
        await t.fetch(`/api/v1/admin/edges/${path}`, { method: 'GET', headers: { cookie } })
      ).json(),
    );
  return { t, networkId, familyId, get };
}

const famCounts = async (t: T) =>
  (await t.query(internal.sniHunt.overview, {})).families.find((f) => f.slug === 'fam-a')
    ?.candidates;

/** The family's candidates as its page reads them, usable ones counted by the shared rule. */
const liveUsable = async (get: Awaited<ReturnType<typeof seed>>['get']) =>
  (await get('sni/hunt/families/fam-a?state=all')).candidates.filter(usableCandidate).length;

describe('counts move with each change', () => {
  test('a check that passes moves the overview at once, with no tick between', async () => {
    const { t, get } = await seed();
    deps();
    await t.action(internal.sniHuntOps.readCert, { slug: 'fam-a' });
    expect(await famCounts(t)).toEqual({ total: 12, ready: 0 });
    // The tick recounts before the check run it schedules has run.
    await t.mutation(internal.sniHunt.tick, { now: clock });
    await t.action(internal.sniHuntOps.check, {});
    expect(await liveUsable(get)).toBe(12);
    expect(await famCounts(t)).toEqual({ total: 12, ready: 12 });
    // The family page's own counts say the same.
    expect((await get('sni/hunt/families/fam-a')).counts.usable).toBe(12);
  });

  test('an ignore, its undo, a family taking a name and a delete keep the counts exact', async () => {
    const { t, get } = await seed();
    deps();
    await t.action(internal.sniHuntOps.readCert, { slug: 'fam-a' });
    await t.action(internal.sniHuntOps.check, {});
    const ids = (await get('sni/hunt/families/fam-a?state=new')).candidates
      .filter((c) => c.name.startsWith('n'))
      .map((c) => c.id);
    await t.mutation(internal.sniHunt.setCandidates, {
      ids: ids.slice(0, 2),
      action: 'ignore',
      kind: 'name',
    });
    expect(await famCounts(t)).toEqual({ total: 12, ready: 10 });
    await t.mutation(internal.sniHunt.setCandidates, { ids: ids.slice(0, 1), action: 'unignore' });
    expect(await famCounts(t)).toEqual({ total: 12, ready: 11 });
    // Adding one to the family marks its candidate added.
    await t.mutation(internal.sniFamilies.importNames, {
      slug: 'fam-a',
      lines: ['www.example.com'],
    });
    expect(await famCounts(t)).toEqual({ total: 12, ready: 10 });
    expect(await liveUsable(get)).toBe(10);
    // Removing the family's finds (here: a move to no network) takes both counts down.
    await t.run(async (ctx) => {
      const c = (await ctx.db.query('sniCandidates').collect()).find(
        (x) => x.name === 'n9.example.com',
      )!;
      await ctx.db.patch(c._id, { goneAt: clock - 31 * 24 * 60 * MIN });
    });
    await t.mutation(internal.sniHunt.tick, { now: clock });
    expect(await famCounts(t)).toEqual({ total: 11, ready: 9 });
  });
});

describe('the recount', () => {
  test('runs with finding names switched off', async () => {
    const { t, familyId } = await seed();
    deps();
    await t.action(internal.sniHuntOps.readCert, { slug: 'fam-a' });
    await t.action(internal.sniHuntOps.check, {});
    // A row that drifted (whatever was missed) is put right by the next tick.
    await t.run(async (ctx) => {
      const row = (await ctx.db
        .query('sniHuntScopes')
        .withIndex('by_family', (q) => q.eq('familyId', familyId))
        .first())!;
      await ctx.db.patch(row._id, { ready: 0, dirty: true, dirtyAt: clock });
    });
    await setHunt(t, false);
    clock += 10 * MIN;
    expect(await t.mutation(internal.sniHunt.tick, { now: clock })).toMatchObject({
      reason: 'off',
    });
    expect(await famCounts(t)).toEqual({ total: 12, ready: 12 });
  });

  test('takes the oldest-marked scope first, however often older scopes are marked again', async () => {
    const { t, familyId } = await seed();
    deps();
    for (const s of ['net-b', 'net-c', 'net-d', 'net-e', 'net-f']) {
      await net(t, s);
      await t.mutation(internal.sniHunt.importCandidates, {
        network: s,
        lines: [`seed.${s}.example.net`],
      });
    }
    await t.action(internal.sniHuntOps.readCert, { slug: 'fam-a' });
    const counted: boolean[] = [];
    for (let tick = 0; tick < 3; tick++) {
      // A sweep's hits land in two older scopes between ticks.
      for (const s of ['net-b', 'net-c'])
        await t.mutation(internal.sniHunt.importCandidates, {
          network: s,
          lines: [`hit${tick}.${s}.example.net`],
        });
      clock += 10 * MIN;
      await t.mutation(internal.sniHunt.tick, { now: clock });
      const row = await t.run((ctx) =>
        ctx.db
          .query('sniHuntScopes')
          .withIndex('by_family', (q) => q.eq('familyId', familyId))
          .first(),
      );
      counted.push(row?.countedAt !== undefined);
    }
    // Six marked rows, two a tick, first marked first served: the family's by the third.
    expect(counted).toEqual([false, false, true]);
  });
});

describe('scopes', () => {
  test('a family moved to another network loses what was found for it on the old one', async () => {
    const { t, get } = await seed();
    deps();
    await net(t, 'net-b');
    await t.action(internal.sniHuntOps.readCert, { slug: 'fam-a' });
    await t.action(internal.sniHuntOps.check, {});
    expect(await famCounts(t)).toEqual({ total: 12, ready: 12 });
    await t.mutation(internal.sniFamilies.update, { slug: 'fam-a', network: 'net-b' });
    await t.finishAllScheduledFunctions(vi.runAllTimers);
    expect((await get('sni/hunt/families/fam-a?state=all')).candidates).toEqual([]);
    expect(await famCounts(t)).toBeUndefined();
    expect(await t.run((ctx) => ctx.db.query('sniCandidates').collect())).toEqual([]);
  });

  test('moved away and back before the cleanup ran, its finds there are kept', async () => {
    const { t, get } = await seed();
    deps();
    await net(t, 'net-b');
    await t.action(internal.sniHuntOps.readCert, { slug: 'fam-a' });
    await t.action(internal.sniHuntOps.check, {});
    await t.mutation(internal.sniFamilies.update, { slug: 'fam-a', network: 'net-b' });
    // The old network's page no longer lists it, cleanup or not.
    expect((await get('sni/hunt/networks/net-a')).families).toEqual([]);
    await t.mutation(internal.sniFamilies.update, { slug: 'fam-a', network: 'net-a' });
    await t.finishAllScheduledFunctions(vi.runAllTimers);
    expect(await liveUsable(get)).toBe(12);
    expect(await famCounts(t)).toEqual({ total: 12, ready: 12 });
  });

  test('a certificate-log read for the network a family left adds nothing', async () => {
    const { t } = await seed();
    deps();
    await net(t, 'net-b');
    await t.mutation(internal.sniHunt.requestCt, {
      domains: ['example.com'],
      family: 'fam-a',
      now: clock,
    });
    const read = (await t.run((ctx) => ctx.db.query('sniHuntCt').first()))!;
    await t.mutation(internal.sniFamilies.update, { slug: 'fam-a', network: 'net-b' });
    // Its answer arrives before the cleanup ran.
    expect(
      await t.mutation(internal.sniHunt.recordCt, {
        id: read._id,
        outcome: { kind: 'page', names: ['late.example.com'], lastId: null, done: true },
        now: clock,
      }),
    ).toEqual({ ok: false });
    expect(await t.run((ctx) => ctx.db.query('sniCandidates').collect())).toEqual([]);
    expect(await t.run((ctx) => ctx.db.query('sniHuntCt').collect())).toEqual([]);
  });

  test("a network's page lists what was found for its families, apart from its own sites", async () => {
    const { t, get } = await seed();
    deps();
    await t.action(internal.sniHuntOps.readCert, { slug: 'fam-a' });
    await t.action(internal.sniHuntOps.check, {});
    const n = await get('sni/hunt/networks/net-a');
    // Checked against the family's target, never as sites of the network itself.
    expect(n.groups).toEqual([]);
    expect(n.families).toEqual([
      { slug: 'fam-a', label: 'Fam A', candidates: { total: 12, ready: 12 } },
    ]);
  });
});
