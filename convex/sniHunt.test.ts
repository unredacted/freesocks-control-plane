/// <reference types="vite/client" />
/**
 * Finding names (docs/edges.md "Finding names", convex/sniHunt.ts, sniHuntOps.ts):
 *
 *  - the top-sites sweep: a leased chain of short steps, each checkpoint a
 *    compare-and-set; a step that runs out of time hands the lease back and
 *    the next resumes from the cursor; a duplicate step gets nothing; a
 *    cancel during DNS work discards what was resolved; AAAA counts on its own;
 *  - checks: qualification's own verdict, against the family's target for a
 *    family candidate (the name presented there) and against its own address
 *    for a network candidate; every A and AAAA answer judged; the extra
 *    handshakes never change the verdict; a run past its deadline releases
 *    what it did not reach;
 *  - certificate transparency: pages after the last id, every request counted,
 *    a 429 resumes from where it stopped, `truncated` is never complete;
 *  - imports, ignores and adding through the family's normal path.
 *
 * Fixtures use documentation ranges and example names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { signValue } from './lib/cookies';
import { __setHuntDepsForTests, type HuntDeps } from './sniHuntOps';
import { SniHuntOverview, SniHuntScopeView } from '../src/shared/contracts/sni';

const modules = import.meta.glob('./**/*.*s');
const ADMIN_SIGN_KEY = 'test-admin-sign';
type T = TestConvex<typeof schema>;

const NET_PREFIXES = { v4: ['192.0.2.0/24'], v6: ['2001:db8::/32'] };
const TARGET_IP = '192.0.2.10';

let clock = 0;
beforeEach(() => {
  // Scheduled follow-ups (the next step, the next page) never run on their own here.
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

/** DNS for the fixtures: name -> answers. */
type Zone = Record<string, { a?: string[]; aaaa?: string[] }>;

function fakeDeps(zone: Zone, over: Partial<HuntDeps> = {}) {
  const shakes: { host: string; port: number; servername: string; ecdhCurve?: string }[] = [];
  const deps: Partial<HuntDeps> = {
    resolve4: async (n) => zone[n]?.a ?? [],
    resolve6: async (n) => zone[n]?.aaaa ?? [],
    lookup: async (n) => [...(zone[n]?.a ?? []), ...(zone[n]?.aaaa ?? [])],
    tlsInspect: async (o) => {
      shakes.push(o);
      return { ok: true, authorized: true, protocol: 'TLSv1.3', alpn: 'h2' };
    },
    now: () => clock,
    sleep: async () => undefined,
    ...over,
  };
  __setHuntDepsForTests(deps);
  return { shakes };
}

async function setting(t: T, key: string, value: unknown) {
  await t.run(async (ctx) => {
    await ctx.db.insert('appSettings', { key, value: JSON.stringify(value), updatedAt: clock });
  });
}

async function seed(opts: { hunting?: boolean } = {}) {
  const t = convexTest(schema, modules);
  await setting(t, 'edge.sni.hunt.enabled', true);
  const networkId = await t.run((ctx) =>
    ctx.db.insert('edgeNetworks', {
      slug: 'net-a',
      label: 'Net A',
      asns: [64500],
      announced: NET_PREFIXES,
      manualPrefixes: [],
      prefixes: NET_PREFIXES,
      hunt: { enabled: opts.hunting ?? true },
      updatedAt: clock,
    }),
  );
  const familyId = await t.run((ctx) =>
    ctx.db.insert('sniFamilies', {
      slug: 'fam-a',
      label: 'Fam A',
      target: { kind: 'static', address: 'target.example.com', port: 443 },
      enabled: true,
      requireH2: true,
      networkId,
      nextSeq: 0,
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
  const call = (method: string, path: string, body?: unknown) =>
    t.fetch(`/api/v1/admin/edges/${path}`, {
      method,
      headers: { cookie, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  return { t, networkId, familyId, call };
}

const candidates = (t: T) => t.run((ctx) => ctx.db.query('sniCandidates').collect());

/** A run whose list is already stored (the download is tested on its own). */
async function storedRun(t: T, names: string[]) {
  return t.run(async (ctx) => {
    const { gzipSync } = await import('node:zlib');
    const text = names.map((n, i) => `${i + 1}\t${n}`).join('\n');
    const chunk = await ctx.storage.store(new Blob([new Uint8Array(gzipSync(text))]));
    return ctx.db.insert('sniHuntRuns', {
      state: 'running',
      gen: 1,
      depth: names.length,
      wwwDepth: 0,
      chunks: [chunk],
      total: names.length,
      cursor: 0,
      hits: 0,
      lookups: 0,
      leaseUntil: 0,
      startedAt: clock,
      updatedAt: clock,
    });
  });
}

describe('the top-sites sweep', () => {
  test('downloads the list once and stores it in chunks, then resolves it', async () => {
    const { t } = await seed();
    const fetched: string[] = [];
    fakeDeps(
      { 'site1.example': { a: ['192.0.2.20'] } },
      {
        fetch: (async (url: string) => {
          fetched.push(String(url));
          if (String(url).includes('/api/lists/'))
            return new Response(
              JSON.stringify({ list_id: 'ABC12', created_on: '2026-10-25T22:00' }),
            );
          return new Response('1,site1.example\n2,site2.example\n');
        }) as typeof fetch,
      },
    );
    const { runId } = await t.mutation(internal.sniHunt.startSweep, {});
    const r = await t.action(internal.sniHuntOps.downloadList, {
      runId: runId as Id<'sniHuntRuns'>,
      gen: 1,
    });
    // Each site and, within the www depth, its www name.
    expect(r).toMatchObject({ ok: true, total: 4 });
    // The list is asked for at the configured depth, never a URL taken from an answer.
    expect(fetched[1]).toBe('https://tranco-list.eu/download/ABC12/300000');
    const run = await t.run((ctx) => ctx.db.get(runId as Id<'sniHuntRuns'>));
    expect(run).toMatchObject({ state: 'running', total: 4, listId: 'ABC12' });
    expect(run!.chunks).toHaveLength(1);
    await t.action(internal.sniHuntOps.sweepStep, { runId: runId as Id<'sniHuntRuns'> });
    const c = await candidates(t);
    expect(c.map((x) => [x.name, x.sources, x.rank])).toEqual([['site1.example', ['toplist'], 1]]);
    expect((await t.run((ctx) => ctx.db.get(runId as Id<'sniHuntRuns'>)))!.state).toBe('done');
  });

  test('an AAAA-only name is a hit when the network has IPv6 ranges', async () => {
    const { t } = await seed();
    const runId = await storedRun(t, ['v6only.example', 'v4off.example']);
    fakeDeps({
      'v6only.example': { aaaa: ['2001:db8::5'] },
      'v4off.example': { a: ['198.51.100.1'] },
    });
    await t.action(internal.sniHuntOps.sweepStep, { runId });
    expect((await candidates(t)).map((x) => x.name)).toEqual(['v6only.example']);
    expect((await t.run((ctx) => ctx.db.get(runId)))!.lookups).toBe(4);
  });

  test('a step that runs out of time hands the lease back; the next resumes from the cursor', async () => {
    const { t } = await seed();
    const names = Array.from({ length: 250 }, (_, i) => `s${i}.example`);
    const runId = await storedRun(t, names);
    const zone: Zone = { 's5.example': { a: ['192.0.2.5'] }, 's205.example': { a: ['192.0.2.6'] } };
    // Each batch of 100 takes 25 s (A and AAAA at 20 a second, plus the slowest
    // lookup's tail, is planned at 18 s): two fit in the 60 s budget, the third waits.
    let batches = 0;
    fakeDeps(zone, {
      resolve4: async (n) => {
        if (['s0.example', 's100.example', 's200.example'].includes(n)) {
          batches++;
          clock += 25_000;
        }
        return zone[n]?.a ?? [];
      },
    });
    const first = await t.action(internal.sniHuntOps.sweepStep, { runId });
    expect(first).toMatchObject({ claimed: true, batches: 2 });
    let run = (await t.run((ctx) => ctx.db.get(runId)))!;
    expect(run.cursor).toBe(200);
    expect(run.leaseUntil).toBe(0);
    const second = await t.action(internal.sniHuntOps.sweepStep, { runId });
    expect(second).toMatchObject({ claimed: true, done: true, batches: 1 });
    run = (await t.run((ctx) => ctx.db.get(runId)))!;
    expect(run.cursor).toBe(250);
    while (run.state === 'running') {
      await t.action(internal.sniHuntOps.sweepStep, { runId });
      run = (await t.run((ctx) => ctx.db.get(runId)))!;
    }
    expect(run).toMatchObject({ state: 'done', cursor: 250 });
    expect((await candidates(t)).map((x) => x.name).sort()).toEqual(['s205.example', 's5.example']);
    expect(batches).toBe(3);
  });

  test('a duplicate step finds the lease held and gets nothing', async () => {
    const { t } = await seed();
    const runId = await storedRun(t, ['a.example']);
    const one = await t.mutation(internal.sniHunt.stepClaim, { runId, leaseId: 'one', now: clock });
    expect(one).not.toBeNull();
    const two = await t.mutation(internal.sniHunt.stepClaim, { runId, leaseId: 'two', now: clock });
    expect(two).toBeNull();
    // The holder's checkpoint applies; one from the wrong lease does not.
    const bad = await t.mutation(internal.sniHunt.stepCheckpoint, {
      runId,
      gen: 1,
      leaseId: 'two',
      from: 0,
      to: 1,
      lookups: 2,
      hits: [],
      now: clock,
    });
    expect(bad.ok).toBe(false);
    // Once the lease lapses, another step may take over.
    const later = await t.mutation(internal.sniHunt.stepClaim, {
      runId,
      leaseId: 'three',
      now: clock + 4 * 60_000,
    });
    expect(later).not.toBeNull();
  });

  test('a cancel during DNS work discards what the step resolved', async () => {
    const { t } = await seed();
    const runId = await storedRun(t, ['hit.example']);
    fakeDeps(
      {},
      {
        resolve4: async () => {
          await t.mutation(internal.sniHunt.cancelSweep, {});
          return ['192.0.2.7'];
        },
      },
    );
    const r = await t.action(internal.sniHuntOps.sweepStep, { runId });
    expect(r).toMatchObject({ claimed: true, discarded: true });
    expect(await candidates(t)).toEqual([]);
    const run = (await t.run((ctx) => ctx.db.get(runId)))!;
    expect(run).toMatchObject({ state: 'cancelled', gen: 2, cursor: 0, chunks: [] });
  });

  test('a network not hunting keeps nothing from a sweep', async () => {
    const { t } = await seed({ hunting: false });
    await expect(t.mutation(internal.sniHunt.startSweep, {})).rejects.toThrow(/no network/i);
  });
});

describe('checks', () => {
  async function addFamilyCandidate(
    t: T,
    familyId: Id<'sniFamilies'>,
    networkId: Id<'edgeNetworks'>,
    name: string,
  ) {
    return t.run((ctx) =>
      ctx.db.insert('sniCandidates', {
        name,
        site: name,
        networkId,
        familyId,
        sources: ['cert'],
        state: 'new',
        checkGen: 0,
        checkDueAt: 0,
        passes: 0,
        baseScore: 0,
        score: 0,
        firstSeenAt: clock,
        updatedAt: clock,
      }),
    );
  }

  test('a family candidate is checked against the family target, presenting the name', async () => {
    const { t, familyId, networkId } = await seed();
    const id = await addFamilyCandidate(t, familyId, networkId, 'www.example.com');
    const { shakes } = fakeDeps({
      'target.example.com': { a: [TARGET_IP] },
      'www.example.com': { a: ['192.0.2.11'], aaaa: ['2001:db8::11'] },
    });
    await t.action(internal.sniHuntOps.check, {});
    const c = (await t.run((ctx) => ctx.db.get(id)))!;
    expect(c.check).toMatchObject({
      code: null,
      alpn: 'h2',
      answers: { v4: 1, v6: 1, onNetwork: 'all' },
      shown: ['192.0.2.11', '2001:db8::11'],
    });
    expect(c.extra).toMatchObject({ x25519: true, mlkem: true });
    // Three handshakes, all to the target's address, all presenting the candidate.
    expect(shakes.map((s) => [s.host, s.servername, s.ecdhCurve])).toEqual([
      [TARGET_IP, 'www.example.com', undefined],
      [TARGET_IP, 'www.example.com', 'X25519'],
      [TARGET_IP, 'www.example.com', 'X25519MLKEM768'],
    ]);
    expect(c.baseScore).toBeGreaterThan(0);
  });

  test('an on-network A with an off-network AAAA is off the network', async () => {
    const { t, familyId, networkId } = await seed();
    const id = await addFamilyCandidate(t, familyId, networkId, 'mixed.example.com');
    const { shakes } = fakeDeps({
      'target.example.com': { a: [TARGET_IP] },
      'mixed.example.com': { a: ['192.0.2.12'], aaaa: ['2001:db9::1'] },
    });
    await t.action(internal.sniHuntOps.check, {});
    const c = (await t.run((ctx) => ctx.db.get(id)))!;
    expect(c.check).toMatchObject({ code: 'q_off_network', answers: { onNetwork: 'some' } });
    expect(c.state).toBe('failing');
    expect(shakes).toEqual([]);
  });

  test('a network candidate is its own target; AAAA-only passes', async () => {
    const { t, networkId } = await seed();
    await t.mutation(internal.sniHunt.importCandidates, {
      network: 'net-a',
      lines: ['v6.example.org'],
    });
    const { shakes } = fakeDeps({ 'v6.example.org': { aaaa: ['2001:db8::99'] } });
    await t.action(internal.sniHuntOps.check, {});
    const [c] = await candidates(t);
    expect(c!.networkId).toBe(networkId);
    expect(c!.check?.code).toBeNull();
    expect(shakes[0]).toMatchObject({
      host: '2001:db8::99',
      port: 443,
      servername: 'v6.example.org',
    });
  });

  test('extra handshakes that cannot reach the server leave the verdict alone', async () => {
    const { t, familyId, networkId } = await seed();
    const id = await addFamilyCandidate(t, familyId, networkId, 'www.example.com');
    fakeDeps(
      { 'target.example.com': { a: [TARGET_IP] }, 'www.example.com': { a: ['192.0.2.11'] } },
      {
        tlsInspect: async (o) =>
          o.ecdhCurve
            ? { ok: false, error: 'timeout' }
            : { ok: true, authorized: true, protocol: 'TLSv1.3', alpn: 'h2' },
      },
    );
    await t.action(internal.sniHuntOps.check, {});
    const c = (await t.run((ctx) => ctx.db.get(id)))!;
    expect(c.check?.code).toBeNull();
    expect(c.state).toBe('new');
    expect(c.extra).toMatchObject({ error: 'timeout' });
    expect(c.extra?.x25519).toBeUndefined();
  });

  test('a run past its deadline releases what it did not reach, and a stale result is refused', async () => {
    const { t, familyId, networkId } = await seed();
    const a = await addFamilyCandidate(t, familyId, networkId, 'a.example.com');
    const b = await addFamilyCandidate(t, familyId, networkId, 'b.example.com');
    fakeDeps(
      {
        'target.example.com': { a: [TARGET_IP] },
        'a.example.com': { a: ['192.0.2.1'] },
        'b.example.com': { a: ['192.0.2.2'] },
      },
      {
        tlsInspect: async () => {
          clock += 61_000;
          return { ok: true, authorized: true, protocol: 'TLSv1.3', alpn: 'h2' };
        },
      },
    );
    const r = await t.action(internal.sniHuntOps.check, {});
    expect(r).toEqual({ checked: 1, released: 1 });
    const rows = await t.run(async (ctx) => [await ctx.db.get(a), await ctx.db.get(b)]);
    const checked = rows.find((x) => x?.check)!;
    const left = rows.find((x) => !x?.check)!;
    expect(left.checkLeaseUntil).toBeUndefined();
    // A result for an older generation changes nothing.
    const stale = await t.mutation(internal.sniHunt.recordCheck, {
      id: checked._id,
      gen: checked.checkGen - 1,
      at: clock,
      code: 'q_cert',
      answers: { v4: 1, v6: 0, onNetwork: 'all' },
      shown: [],
    });
    expect(stale.ok).toBe(false);
  });

  test('ignored and added candidates are not checked', async () => {
    const { t, familyId, networkId } = await seed();
    const id = await addFamilyCandidate(t, familyId, networkId, 'www.example.com');
    await t.mutation(internal.sniHunt.setCandidates, { ids: [id], action: 'ignore' });
    const { shakes } = fakeDeps({});
    expect(await t.action(internal.sniHuntOps.check, {})).toEqual({ checked: 0, released: 0 });
    expect(shakes).toEqual([]);
  });
});

describe('a target certificate and certificate transparency', () => {
  test("the target's certificate names become the family's candidates (FCP dials only the target)", async () => {
    const { t } = await seed();
    const { shakes } = fakeDeps(
      { 'target.example.com': { a: [TARGET_IP] } },
      {
        tlsInspect: async (o) => {
          shakes.push(o);
          return {
            ok: true,
            authorized: true,
            protocol: 'TLSv1.3',
            alpn: 'h2',
            names: ['target.example.com', 'www.example.com', 'blog.example.com'],
          };
        },
      },
    );
    const r = await t.action(internal.sniHuntOps.readCert, { slug: 'fam-a' });
    expect(r).toMatchObject({ ok: true, listed: 3, added: 3 });
    expect(shakes).toEqual([
      expect.objectContaining({
        host: TARGET_IP,
        servername: 'target.example.com',
        wantNames: true,
      }),
    ]);
    expect((await candidates(t)).every((c) => c.sources.includes('cert') && c.familyId)).toBe(true);
  });

  test('pages after the last id until an empty page; a 429 resumes; requests are counted', async () => {
    const { t } = await seed();
    await setting(t, 'edge.sni.hunt.ctRequestsPerHour', 3);
    const urls: string[] = [];
    const pages: Array<() => Response> = [
      () =>
        new Response(
          JSON.stringify([{ id: '10', dns_names: ['old.example.com', 'other.example.net'] }]),
        ),
      () => new Response('', { status: 429, headers: { 'retry-after': '60' } }),
      () => new Response(JSON.stringify([{ id: '20', dns_names: ['useful.example.com'] }])),
      () => new Response('[]'),
    ];
    fakeDeps(
      {},
      {
        fetch: (async (url: string) => {
          urls.push(String(url));
          return pages.shift()!();
        }) as typeof fetch,
      },
    );
    await t.mutation(internal.sniHunt.requestCt, { domains: ['www.example.com'], family: 'fam-a' });
    await t.action(internal.sniHuntOps.ctStep, {});
    await t.action(internal.sniHuntOps.ctStep, {});
    let row = (await t.run((ctx) => ctx.db.query('sniHuntCt').first()))!;
    expect(row).toMatchObject({ domain: 'example.com', state: 'rate_limited', after: '10' });
    // Waiting out the backoff, it continues after the last id read.
    clock += 61_000;
    await t.action(internal.sniHuntOps.ctStep, {});
    // The hour's three requests are spent: the empty page waits.
    expect(await t.action(internal.sniHuntOps.ctStep, {})).toEqual({ read: false });
    row = (await t.run((ctx) => ctx.db.query('sniHuntCt').first()))!;
    expect(row).toMatchObject({ state: 'partial', after: '20' });
    expect(new URL(urls[2]!).searchParams.get('after')).toBe('10');
    expect(new URL(urls[0]!).searchParams.get('include_subdomains')).toBe('true');
    clock += 3_600_000;
    await t.action(internal.sniHuntOps.ctStep, {});
    row = (await t.run((ctx) => ctx.db.query('sniHuntCt').first()))!;
    expect(row.state).toBe('complete');
    // The useful name from page two is there; the other domain's name is not.
    expect((await candidates(t)).map((c) => c.name).sort()).toEqual([
      'old.example.com',
      'useful.example.com',
    ]);
    // A complete answer is reused within a week.
    expect(
      await t.mutation(internal.sniHunt.requestCt, { domains: ['example.com'], family: 'fam-a' }),
    ).toEqual({ queued: 0, cached: 1 });
  });

  test('reading stops at the page cap as truncated, never complete', async () => {
    const { t } = await seed();
    await setting(t, 'edge.sni.hunt.ctPagesPerDomain', 2);
    let id = 0;
    fakeDeps(
      {},
      {
        fetch: (async () =>
          new Response(
            JSON.stringify([{ id: String(++id), dns_names: [`n${id}.example.com`] }]),
          )) as typeof fetch,
      },
    );
    await t.mutation(internal.sniHunt.requestCt, { domains: ['example.com'], network: 'net-a' });
    await t.action(internal.sniHuntOps.ctStep, {});
    await t.action(internal.sniHuntOps.ctStep, {});
    expect(await t.action(internal.sniHuntOps.ctStep, {})).toEqual({ read: false });
    const row = (await t.run((ctx) => ctx.db.query('sniHuntCt').first()))!;
    expect(row).toMatchObject({ state: 'truncated', pages: 2, after: '2' });
    // Asked again, it reads further from where it stopped (not cached).
    expect(
      await t.mutation(internal.sniHunt.requestCt, { domains: ['example.com'], network: 'net-a' }),
    ).toEqual({ queued: 1, cached: 0 });
  });
});

describe('the cron', () => {
  test('starts a due sweep, takes over a step whose lease lapsed, and deletes what aged out', async () => {
    const { t, networkId } = await seed();
    const started = await t.mutation(internal.sniHunt.tick, { now: clock });
    expect(started.scheduled).toContain('sweep_start');
    const run = (await t.run((ctx) => ctx.db.query('sniHuntRuns').first()))!;
    expect(run.state).toBe('downloading');
    // A running sweep whose step died: the cron schedules a step once the lease lapsed.
    await t.run((ctx) =>
      ctx.db.patch(run._id, { state: 'running', leaseUntil: clock - 1, leaseId: 'gone' }),
    );
    expect((await t.mutation(internal.sniHunt.tick, { now: clock })).scheduled).toContain('sweep');
    await t.run((ctx) => ctx.db.patch(run._id, { leaseUntil: clock + 60_000 }));
    expect((await t.mutation(internal.sniHunt.tick, { now: clock })).scheduled).not.toContain(
      'sweep',
    );
    // A candidate gone for more than 30 days is deleted.
    await t.run((ctx) =>
      ctx.db.insert('sniCandidates', {
        name: 'old.example.com',
        site: 'example.com',
        networkId,
        sources: ['toplist'],
        state: 'gone',
        goneAt: clock - 31 * 24 * 3_600_000,
        checkGen: 1,
        checkDueAt: clock + 1e9,
        passes: 0,
        baseScore: 0,
        score: 0,
        firstSeenAt: clock,
        updatedAt: clock,
      }),
    );
    await t.mutation(internal.sniHunt.tick, { now: clock });
    expect(await candidates(t)).toEqual([]);
  });

  test('a sweep is not started again before it is due', async () => {
    const { t } = await seed();
    await t.run((ctx) =>
      ctx.db.insert('sniHuntRuns', {
        state: 'done',
        gen: 1,
        depth: 1,
        wwwDepth: 0,
        chunks: [],
        total: 1,
        cursor: 1,
        hits: 0,
        lookups: 1,
        leaseUntil: 0,
        startedAt: clock - 2 * 24 * 3_600_000,
        finishedAt: clock - 24 * 3_600_000,
        updatedAt: clock,
      }),
    );
    expect((await t.mutation(internal.sniHunt.tick, { now: clock })).scheduled).toEqual([]);
    const later = clock + 30 * 24 * 3_600_000;
    expect((await t.mutation(internal.sniHunt.tick, { now: later })).scheduled).toContain(
      'sweep_start',
    );
  });
});

describe('imports, ignores and adding', () => {
  test('a seed makes candidates and proposes what FCP lacks, creating nothing', async () => {
    const { t } = await seed();
    const r = await t.mutation(internal.sniHunt.importCandidates, {
      seed: {
        networks: [
          {
            network: { slug: 'net-a', label: 'Net A', asns: [64500] },
            families: [
              {
                create_family: { slug: 'fam-a', targetAddress: 'target.example.com' },
                import_names: { lines: ['a.example.com'] },
              },
              {
                create_family: { slug: 'fam-new', targetAddress: 'other.example.org' },
                import_names: { lines: ['b.example.org'] },
              },
            ],
          },
          { network: { slug: 'net-new', label: 'New', asns: [64501] }, families: [] },
        ],
      },
    });
    expect(r.added).toBe(3);
    expect(r.proposals.networks.map((n) => n.slug)).toEqual(['net-new']);
    expect(r.proposals.families.map((f) => f.slug)).toEqual(['fam-new']);
    const rows = await candidates(t);
    expect(rows.find((c) => c.name === 'a.example.com')?.familyId).toBeDefined();
    expect(rows.find((c) => c.name === 'other.example.org')?.familyId).toBeUndefined();
    expect(await t.run((ctx) => ctx.db.query('sniFamilies').collect())).toHaveLength(1);
  });

  test('an ignored site never comes back; adding goes through the family and marks it added', async () => {
    const { t, call } = await seed();
    await call('POST', 'sni/hunt/import', {
      network: 'net-a',
      lines: ['a.bad.example', 'b.bad.example', 'good.example.com'],
    });
    const rows = await candidates(t);
    const bad = rows.find((c) => c.name === 'a.bad.example')!;
    const res = await call('POST', 'sni/hunt/candidates/ignore', { ids: [bad._id], kind: 'site' });
    expect(await res.json()).toEqual({ changed: 2 });
    await t.run(async (ctx) => {
      for (const c of await ctx.db.query('sniCandidates').collect())
        if (c.site === 'bad.example') await ctx.db.delete(c._id);
    });
    const again = await t.mutation(internal.sniHunt.importCandidates, {
      network: 'net-a',
      lines: ['c.bad.example'],
    });
    expect(again).toMatchObject({ added: 0, ignored: 1 });
    const add = await call('POST', 'sni/hunt/candidates/add', {
      family: 'fam-a',
      names: ['good.example.com'],
    });
    expect(add.status).toBe(200);
    expect((await add.json()).added).toBe(1);
    const good = (await candidates(t)).find((c) => c.name === 'good.example.com')!;
    expect(good.state).toBe('added');
    const name = await t.run((ctx) =>
      ctx.db
        .query('sniNames')
        .withIndex('by_name', (q) => q.eq('name', 'good.example.com'))
        .unique(),
    );
    // Waiting for the family's normal qualification.
    expect(name?.qualification.state).toBe('pending');
  });

  test('the views parse with their contracts', async () => {
    const { call } = await seed();
    await call('POST', 'sni/hunt/import', { network: 'net-a', lines: ['a.example.com'] });
    SniHuntOverview.parse(await (await call('GET', 'sni/hunt')).json());
    const view = SniHuntScopeView.parse(
      await (await call('GET', 'sni/hunt/networks/net-a')).json(),
    );
    expect(view.candidates.map((c) => c.name)).toEqual(['a.example.com']);
    SniHuntScopeView.parse(await (await call('GET', 'sni/hunt/families/fam-a')).json());
  });

  test('switched off, nothing is checked and no sweep starts', async () => {
    const { t } = await seed();
    await t.run(async (ctx) => {
      const row = await ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.eq('key', 'edge.sni.hunt.enabled'))
        .unique();
      await ctx.db.patch(row!._id, { value: 'false' });
    });
    expect(await t.mutation(internal.sniHunt.tick, { now: clock })).toEqual({ reason: 'off' });
    await expect(t.mutation(internal.sniHunt.startSweep, {})).rejects.toThrow(/switched off/);
  });
});

describe('evidence', () => {
  /** A passing candidate, as a check leaves it. */
  async function passingCandidate(
    t: T,
    o: {
      name: string;
      networkId?: Id<'edgeNetworks'>;
      familyId?: Id<'sniFamilies'>;
      dialled: string;
      shown: string[];
      rank?: number;
      listed?: boolean;
      fresh?: boolean;
    },
  ) {
    return t.run((ctx) =>
      ctx.db.insert('sniCandidates', {
        name: o.name,
        site: o.name.split('.').slice(-2).join('.'),
        ...(o.networkId ? { networkId: o.networkId } : {}),
        ...(o.familyId ? { familyId: o.familyId } : {}),
        sources: ['toplist'],
        ...(o.rank ? { rank: o.rank } : {}),
        state: 'new',
        check: {
          at: clock,
          code: null,
          alpn: 'h2',
          answers: { v4: 1, v6: 0, onNetwork: 'all' },
          shown: o.shown,
          dialled: o.dialled,
          port: 443,
        },
        checkGen: 1,
        checkDueAt: clock + 1e9,
        passes: 1,
        ...(o.listed ? { listed: true } : {}),
        ...(o.fresh
          ? {
              timing: {
                at: clock,
                place: 'US',
                endpoint: o.dialled,
                port: 443,
                connectMs: 10,
                probes: 2,
              },
              ooni: { at: clock, exact: [], site: [] },
              evidenceAskedAt: clock,
            }
          : {}),
        baseScore: 0,
        score: 0,
        firstSeenAt: clock,
        updatedAt: clock,
      }),
    );
  }

  /** Globalping that answers by the address dialled: connect ms per address. */
  function timingGlobalping(ms: Record<string, number>) {
    const requests: Array<{ target: string; measurementOptions: { request: { host: string } } }> =
      [];
    const client = {
      async createMeasurement(req: unknown) {
        requests.push(req as (typeof requests)[number]);
        return { ok: true, data: { id: `m${requests.length}` } };
      },
      async getMeasurement(id: string) {
        const req = requests[Number(id.slice(1)) - 1]!;
        const tcp = ms[req.target] ?? 999;
        return {
          ok: true,
          data: {
            status: 'finished',
            results: [1, 2].map(() => ({
              probe: { country: 'US' },
              result: { status: 'finished', timings: { tcp, tls: tcp + 5 } },
            })),
          },
        };
      },
    };
    return { client, requests };
  }

  test('a family candidate is near only if the family target is: its own site is shown, not scored', async () => {
    const { t, familyId, networkId } = await seed();
    await t.run((ctx) =>
      ctx.db.patch(networkId, {
        hunt: { enabled: true, place: { country: 'US', city: 'Springfield' } },
      }),
    );
    const id = await passingCandidate(t, {
      name: 'www.example.com',
      networkId,
      familyId,
      dialled: TARGET_IP,
      shown: ['192.0.2.11'],
      listed: true,
    });
    const gp = timingGlobalping({ [TARGET_IP]: 120, '192.0.2.11': 5 });
    fakeDeps(
      {},
      {
        globalping: () => gp.client,
        fetch: (async () => new Response(JSON.stringify({ result: [] }))) as typeof fetch,
      },
    );
    const r = await t.action(internal.sniHuntOps.evidence, {});
    expect(r.timed).toBe(1);
    // The target leg, presenting the candidate, from the network's place.
    expect(gp.requests[0]).toMatchObject({
      target: TARGET_IP,
      locations: [{ country: 'US', city: 'Springfield', limit: 2 }],
      measurementOptions: { request: { host: 'www.example.com' } },
    });
    const c = (await t.run((ctx) => ctx.db.get(id)))!;
    expect(c.timing).toMatchObject({
      endpoint: TARGET_IP,
      connectMs: 120,
      place: 'US/Springfield',
    });
    expect(c.own).toMatchObject({ endpoint: '192.0.2.11', connectMs: 5 });
    expect(c.scoreParts?.near).toBe(4);
    // Two measurements were reserved in the hour's budget.
    expect(await t.run((ctx) => ctx.db.query('sniHuntCalls').collect())).toHaveLength(2);
  });

  test("OONI: the exact name scores; its site's apex and www are context only", async () => {
    const { t, networkId } = await seed();
    await setting(t, 'edge.sni.vantage.countries', ['IR']);
    const id = await passingCandidate(t, {
      name: 'blog.example.com',
      networkId,
      dialled: '192.0.2.30',
      shown: ['192.0.2.30'],
      listed: true,
    });
    const asked: string[] = [];
    fakeDeps(
      {},
      {
        fetch: (async (url: string) => {
          const domain = new URL(url).searchParams.get('domain')!;
          asked.push(domain);
          const result =
            domain === 'example.com'
              ? [
                  {
                    probe_cc: 'IR',
                    measurement_count: 40,
                    ok_count: 0,
                    anomaly_count: 40,
                    confirmed_count: 30,
                  },
                ]
              : [];
          return new Response(JSON.stringify({ result }));
        }) as typeof fetch,
      },
    );
    await t.action(internal.sniHuntOps.evidence, {});
    expect(asked.sort()).toEqual(['blog.example.com', 'example.com', 'www.example.com']);
    const c = (await t.run((ctx) => ctx.db.get(id)))!;
    const ir = (xs: Array<{ cc: string; status: string }>) => xs.find((x) => x.cc === 'IR')?.status;
    expect(ir(c.ooni!.exact)).toBe('no_data');
    expect(ir(c.ooni!.site)).toBe('blocked');
    expect(c.scoreParts?.penalty).toBe(0);
  });

  test('candidate eleven gets evidence while the measured ten stay listed with theirs', async () => {
    const { t, networkId } = await seed();
    await t.run((ctx) =>
      ctx.db.patch(networkId, { hunt: { enabled: true, place: { country: 'US' } } }),
    );
    const ids: Id<'sniCandidates'>[] = [];
    for (let i = 1; i <= 11; i++)
      ids.push(
        await passingCandidate(t, {
          name: `c${i}.example.com`,
          networkId,
          dialled: `192.0.2.${i}`,
          shown: [`192.0.2.${i}`],
          rank: i * 10,
          fresh: i <= 10,
        }),
      );
    // The rescore (one scope a tick) keeps the shortlist.
    await t.mutation(internal.sniHunt.tick, { now: clock });
    const listed = await t.run(async (ctx) =>
      (await ctx.db.query('sniCandidates').collect()).filter((c) => c.listed).map((c) => c.name),
    );
    expect(listed).toContain('c11.example.com');
    for (let i = 1; i <= 7; i++) expect(listed).toContain(`c${i}.example.com`);
    const work = await t.mutation(internal.sniHunt.claimEvidence, { now: clock });
    expect(work.timing.map((x) => x.host)).toEqual(['c11.example.com']);
    expect(work.ooni.map((x) => x.name)).toEqual(['c11.example.com']);
    // The measured ones keep their evidence and their place.
    const first = (await t.run((ctx) => ctx.db.get(ids[0]!)))!;
    expect(first.timing?.connectMs).toBe(10);
    expect(first.listed).toBe(true);
  });

  test('Measure now: a passing candidate is taken first; a failing one is not', async () => {
    const { t, networkId } = await seed();
    const id = await passingCandidate(t, {
      name: 'm.example.com',
      networkId,
      dialled: '192.0.2.40',
      shown: ['192.0.2.40'],
      fresh: true,
    });
    expect(
      await t.mutation(internal.sniHunt.setCandidates, { ids: [id], action: 'measure' }),
    ).toEqual({ changed: 1 });
    const work = await t.mutation(internal.sniHunt.claimEvidence, { now: clock });
    expect(work.ooni.map((x) => x.name)).toEqual(['m.example.com']);
    expect((await t.run((ctx) => ctx.db.get(id)))!.measureAt).toBeUndefined();
  });
});

describe('review fixes', () => {
  test('complete certificate-log reads never stand in front of one still to read', async () => {
    const { t, familyId, networkId } = await seed();
    await t.run(async (ctx) => {
      for (let i = 0; i < 150; i++)
        await ctx.db.insert('sniHuntCt', {
          domain: `d${i}.example.com`,
          familyId,
          networkId,
          state: 'complete',
          pages: 1,
          names: 0,
          nextAt: 0,
          completedAt: clock,
          requestedAt: clock,
          updatedAt: clock,
        });
      await ctx.db.insert('sniHuntCt', {
        domain: 'late.example.com',
        familyId,
        networkId,
        state: 'partial',
        pages: 0,
        names: 0,
        nextAt: clock,
        requestedAt: clock,
        updatedAt: clock,
      });
    });
    const claim = await t.mutation(internal.sniHunt.claimCt, { now: clock });
    expect(claim?.domain).toBe('late.example.com');
  });

  test('a deleted family takes every one of its reads, ignores and candidates with it', async () => {
    const { t, familyId, networkId } = await seed();
    await t.run(async (ctx) => {
      for (let i = 0; i < 450; i++) {
        await ctx.db.insert('sniHuntCt', {
          domain: `d${i}.example.com`,
          familyId,
          networkId,
          state: 'complete',
          pages: 1,
          names: 0,
          nextAt: 0,
          requestedAt: clock,
          updatedAt: clock,
        });
        await ctx.db.insert('sniHuntIgnores', {
          kind: 'name',
          key: `n${i}.example.com`,
          familyId,
          networkId,
          at: clock,
        });
      }
    });
    // Runs again until nothing is left (the follow-ups are scheduled).
    for (let i = 0; i < 5; i++) await t.mutation(internal.sniHunt.dropScope, { familyId });
    expect(await t.run((ctx) => ctx.db.query('sniHuntCt').collect())).toHaveLength(0);
    expect(await t.run((ctx) => ctx.db.query('sniHuntIgnores').collect())).toHaveLength(0);
  });

  test('a page of one state at a time: ignored rows never take the place of ones to decide', async () => {
    const { t, call } = await seed();
    const names = Array.from({ length: 250 }, (_, i) => `n${i}.example.com`);
    await t.mutation(internal.sniHunt.importCandidates, { network: 'net-a', lines: names });
    // The best-scored ones are ignored.
    await t.run(async (ctx) => {
      for (const c of await ctx.db.query('sniCandidates').collect()) {
        const i = Number(c.name.slice(1).split('.')[0]);
        await ctx.db.patch(c._id, { score: 1000 - i, ...(i < 30 ? { state: 'ignored' } : {}) });
      }
    });
    const first = SniHuntScopeView.parse(
      await (await call('GET', 'sni/hunt/networks/net-a')).json(),
    );
    expect(first.candidates).toHaveLength(200);
    expect(first.candidates.every((c) => c.state === 'new')).toBe(true);
    expect(first.page.done).toBe(false);
    const second = SniHuntScopeView.parse(
      await (
        await call(
          'GET',
          `sni/hunt/networks/net-a?cursor=${encodeURIComponent(first.page.cursor!)}`,
        )
      ).json(),
    );
    expect(second.candidates).toHaveLength(20);
    expect(second.page.done).toBe(true);
    const ignored = SniHuntScopeView.parse(
      await (await call('GET', 'sni/hunt/networks/net-a?state=ignored')).json(),
    );
    expect(ignored.candidates).toHaveLength(30);
  });

  test('a name found in many scopes is found again in each, never twice', async () => {
    const { t } = await seed();
    const nets = await t.run(async (ctx) => {
      const ids = [];
      for (let i = 0; i < 60; i++)
        ids.push(
          await ctx.db.insert('edgeNetworks', {
            slug: `n-${i}`,
            label: `N ${i}`,
            asns: [64500],
            announced: NET_PREFIXES,
            manualPrefixes: [],
            prefixes: NET_PREFIXES,
            updatedAt: clock,
          }),
        );
      return ids;
    });
    for (let i = 0; i < 60; i++)
      await t.mutation(internal.sniHunt.importCandidates, {
        network: `n-${i}`,
        lines: ['shared.example.com'],
      });
    const again = await t.mutation(internal.sniHunt.importCandidates, {
      network: 'n-59',
      lines: ['shared.example.com'],
    });
    expect(again).toMatchObject({ added: 0, known: 1 });
    expect((await candidates(t)).filter((c) => c.networkId === nets[59])).toHaveLength(1);
  });

  test("a target's certificate is not read during a maintenance freeze", async () => {
    const { t } = await seed();
    await t.run((ctx) =>
      ctx.db.insert('appState', {
        key: 'edge:maintenance',
        value: JSON.stringify({ frozen: true, since: clock, reason: 'test' }),
        updatedAt: clock,
      }),
    );
    const { shakes } = fakeDeps({ 'target.example.com': { a: [TARGET_IP] } });
    await expect(t.action(internal.sniHuntOps.readCert, { slug: 'fam-a' })).rejects.toThrow(
      /maintenance/i,
    );
    expect(shakes).toEqual([]);
  });

  test('an extra handshake that throws leaves a passing verdict alone', async () => {
    const { t, familyId, networkId } = await seed();
    const id = await t.run((ctx) =>
      ctx.db.insert('sniCandidates', {
        name: 'www.example.com',
        site: 'example.com',
        networkId,
        familyId,
        sources: ['cert'],
        state: 'new',
        checkGen: 0,
        checkDueAt: 0,
        passes: 0,
        baseScore: 0,
        score: 0,
        firstSeenAt: clock,
        updatedAt: clock,
      }),
    );
    fakeDeps(
      { 'target.example.com': { a: [TARGET_IP] }, 'www.example.com': { a: ['192.0.2.11'] } },
      {
        tlsInspect: async (o) => {
          if (o.ecdhCurve === 'X25519MLKEM768') throw new TypeError('Unsupported curve');
          return { ok: true, authorized: true, protocol: 'TLSv1.3', alpn: 'h2' };
        },
      },
    );
    await t.action(internal.sniHuntOps.check, {});
    const c = (await t.run((ctx) => ctx.db.get(id)))!;
    expect(c.check?.code).toBeNull();
    expect(c.extra).toMatchObject({ x25519: true, error: 'unsupported' });
  });

  test('a certificate read is audited as the admin who asked', async () => {
    const { t } = await seed();
    const adminId = await t.run((ctx) =>
      ctx.db.insert('adminUsers', {
        username: 'b',
        displayName: 'B',
        isActive: true,
        updatedAt: clock,
      }),
    );
    fakeDeps(
      { 'target.example.com': { a: [TARGET_IP] } },
      {
        tlsInspect: async () => ({
          ok: true,
          authorized: true,
          protocol: 'TLSv1.3',
          names: ['a.example.com'],
        }),
      },
    );
    await t.action(internal.sniHuntOps.readCert, { slug: 'fam-a', actorAdminId: adminId });
    const row = await t.run(async (ctx) =>
      (await ctx.db.query('auditLog').collect()).find((r) => r.action === 'edge.sni.hunt.cert'),
    );
    expect(row).toMatchObject({ actorType: 'admin', actorId: adminId });
  });

  test("stopping a site's ignore brings back every name of the site", async () => {
    const { t } = await seed();
    await t.mutation(internal.sniHunt.importCandidates, {
      network: 'net-a',
      lines: ['a.bad.example', 'b.bad.example', 'c.bad.example'],
    });
    const rows = await candidates(t);
    await t.mutation(internal.sniHunt.setCandidates, {
      ids: [rows[0]!._id],
      action: 'ignore',
      kind: 'site',
    });
    expect((await candidates(t)).every((c) => c.state === 'ignored')).toBe(true);
    const r = await t.mutation(internal.sniHunt.setCandidates, {
      ids: [rows[1]!._id],
      action: 'unignore',
    });
    expect(r.changed).toBe(3);
    expect((await candidates(t)).every((c) => c.state === 'new' && c.checkDueAt === 0)).toBe(true);
  });
});
