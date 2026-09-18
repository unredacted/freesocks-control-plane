/// <reference types="vite/client" />
/**
 * Probe runs end to end: request → executor (fake Globalping client, stubbed
 * fetch for the internal probe) → per-source rollup → the edge's cross-source
 * summary; plus the cron's due/budget logic and the stuck-run sweep.
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { realityListener, registerRelay } from './lib/edges/testing/fixtures';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { __setGlobalpingFactory, __setInternalProbeDeps } from './probeOps';
import { familiesOf, type ResolvedTarget } from './probes';
import { EDGE_DEFAULTS, type EdgeConfig } from './lib/edgeConfig';
import type { GlobalpingLike } from './lib/edges/probes/globalping';

const modules = import.meta.glob('./**/*.*s');

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  __setGlobalpingFactory(null);
  __setInternalProbeDeps(null);
});

const EDGE = '198.51.100.9';

/** A Globalping fake answering every configured country with the given per-country outcome. */
function fakeGlobalping(
  outcome: (country: string) => 'ok' | 'fail' | 'silent',
): GlobalpingLike & { requests: unknown[] } {
  const requests: unknown[] = [];
  return {
    requests,
    async createMeasurement(req) {
      requests.push(req);
      return { ok: true, data: { id: `m-${requests.length}`, probesCount: 6 } };
    },
    async getMeasurement(id) {
      const req = requests[Number(id.slice(2)) - 1] as { locations: Array<{ country: string }> };
      const results = req.locations.flatMap((l, i) => {
        const o = outcome(l.country);
        if (o === 'silent') return [];
        return [1, 2].map((k) => ({
          probe: {
            country: l.country,
            asn: 1000 * (i + 1) + k,
            network: `net-${l.country}-${k}`,
            tags: ['eyeball-network'],
          },
          result:
            o === 'ok'
              ? { status: 'finished', stats: { loss: 0, avg: 30 } }
              : { status: 'finished', stats: { loss: 100, avg: null } },
        }));
      });
      return { ok: true, data: { id, status: 'finished', results } };
    },
  };
}

/** A Globalping fake for `http` measurements (the tls/https path): every probe answers 200. */
function fakeGlobalpingHttp(
  statusCode: number | null = 200,
): GlobalpingLike & { requests: unknown[] } {
  const requests: unknown[] = [];
  return {
    requests,
    async createMeasurement(req) {
      requests.push(req);
      return { ok: true, data: { id: `m-${requests.length}` } };
    },
    async getMeasurement(id) {
      const req = requests[Number(id.slice(2)) - 1] as { locations: Array<{ country: string }> };
      const results = req.locations.flatMap((l, i) =>
        [1, 2].map((k) => ({
          probe: {
            country: l.country,
            asn: 1000 * (i + 1) + k,
            network: `net-${l.country}-${k}`,
            tags: ['eyeball-network'],
          },
          result:
            statusCode === null
              ? { status: 'failed', rawOutput: 'handshake failed' }
              : { status: 'finished', statusCode, timings: { total: 40 } },
        })),
      );
      return { ok: true, data: { id, status: 'finished', results } };
    },
  };
}

async function seed(
  opts: { probeEnabled?: boolean; countries?: string[]; internalOk?: boolean } = {},
) {
  vi.useFakeTimers();
  const t = convexTest(schema, modules);
  await t.run(async (ctx) => {
    await ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'panel-a',
      slug: 'panel-a',
      config: { type: 'remnawave', baseUrl: 'https://panel.example', apiToken: 'tok' },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: Date.now(),
    });
    await upsertSettingRow(ctx, 'edge.probe.enabled', JSON.stringify(opts.probeEnabled ?? true));
    await upsertSettingRow(
      ctx,
      'edge.probe.countries',
      JSON.stringify(opts.countries ?? ['IR', 'RU']),
    );
    // check-host / ripe atlas off: this test drives globalping + internal only.
    await upsertSettingRow(ctx, 'edge.probe.sources.checkhost', 'false');
  });
  const { relayId, listenerId } = await registerRelay(t, {
    listeners: [
      realityListener({
        listenerKey: 'u',
        tlsNames: ['a.example'],
        providerScope: { provider: 'upcloud' },
        panelBinding: {
          inboundTag: 'VLESS_RELAY_U',
          configProfileUuid: '11111111-1111-4111-8111-111111111111',
          configProfileInboundUuid: '22222222-2222-4222-8222-222222222222',
        },
      }),
    ],
  });
  const { edgeId } = await t.mutation(internal.relays.adoptEdge, {
    relayId,
    listenerId,
    ipv4: EDGE,
    publish: true,
    verified: true,
  });
  // The internal probe's fetch: any response = reachable; a connect error = down.
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => {
      if (opts.internalOk === false)
        throw Object.assign(new Error('fetch failed'), { cause: { code: 'ECONNREFUSED' } });
      return new Response(null, { status: 400 });
    }),
  );
  // The REALITY listener's internal run is the `tls-sni` shape check: a real
  // handshake, stubbed here the way `fetch` is (the same up/down switch).
  __setInternalProbeDeps({
    tlsConnect: async () =>
      opts.internalOk === false ? { ok: false, error: 'ECONNREFUSED' } : { ok: true },
  });
  return { t, relayId, edgeId: edgeId as Id<'edges'> };
}

async function drainRuns(t: ReturnType<typeof convexTest>) {
  for (let i = 0; i < 60; i++) {
    await vi.runAllTimersAsync();
    await t.finishInProgressScheduledFunctions();
    const pending = await t.run(async (ctx) => {
      const rows = await ctx.db.query('probeRuns').collect();
      return rows.filter((r) => r.status === 'requested' || r.status === 'running').length;
    });
    if (pending === 0) return;
  }
  throw new Error('probe runs did not settle');
}

describe('relayProbes', () => {
  test('requestProbes → executor → rollup: an edge unreachable from IR (two eyeball networks) and fine from RU', async () => {
    const gp = fakeGlobalping((c) => (c === 'IR' ? 'fail' : 'ok'));
    __setGlobalpingFactory(() => gp);
    const { t, edgeId } = await seed();
    const { runIds } = await t.mutation(internal.probes.requestProbes, {
      target: { kind: 'edge', ref: edgeId },
      trigger: 'manual',
    });
    expect(runIds).toHaveLength(2); // globalping + internal, v4 only
    await drainRuns(t);
    const runs = await t.query(internal.probes.listRuns, {
      target: { kind: 'edge', ref: edgeId },
    });
    expect(runs.map((r) => [r.source, r.status]).sort()).toEqual([
      ['globalping', 'finished'],
      ['internal', 'finished'],
    ]);
    expect(runs.find((r) => r.source === 'globalping')?.failVantages).toBe(2);
    // Request shape: TCP ping on the edge port, both countries.
    expect(gp.requests[0]).toMatchObject({
      type: 'ping',
      target: EDGE,
      measurementOptions: { protocol: 'TCP', port: 443 },
    });
    // Rollup rows: IR unreachable, RU reachable (two eyeball successes), XX (internal) reachable.
    const rows = await t.run((ctx) => ctx.db.query('probeReachability').collect());
    const by = Object.fromEntries(rows.map((r) => [`${r.source}:${r.country}`, r.verdict]));
    expect(by).toEqual({
      'globalping:IR': 'unreachable',
      'globalping:RU': 'reachable',
      'internal:XX': 'reachable',
    });
    // Edge summary across sources.
    const edge = (await t.query(internal.edges.get, { id: edgeId }))!;
    const summary = Object.fromEntries(
      edge.reachability!.byCountry.map((c) => [c.country, c.verdict]),
    );
    expect(summary).toEqual({ IR: 'unreachable', RU: 'reachable', XX: 'reachable' });
    // The rollup keeps the REAL distinct failing networks and stamps the
    // reachable-transition marker only where the verdict was reachable.
    const irRow = rows.find((r) => r.source === 'globalping' && r.country === 'IR')!;
    const ruRow = rows.find((r) => r.source === 'globalping' && r.country === 'RU')!;
    expect(irRow.failNetworks).toEqual(['AS1001', 'AS1002']);
    expect(irRow.lastReachableAt).toBeUndefined();
    expect(ruRow.failNetworks).toEqual([]);
    expect(ruRow.lastReachableAt).toBe(ruRow.updatedAt);
    // Verdict audits carry only ids/codes.
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    const verdicts = audit.filter((a) => a.action === 'probe.verdict');
    expect(verdicts.length).toBeGreaterThan(0);
    expect(JSON.stringify(audit)).not.toContain(EDGE);
    const matrix = await t.query(internal.probes.matrix, {});
    expect(matrix.countries).toEqual(['IR', 'RU']);
    const row = matrix.targets.find((x) => x.key === `edge:${edgeId}`)!;
    expect(row.kind).toBe('edge');
    expect(row.reachability.byCountry.find((c) => c.country === 'IR')?.verdict).toBe('unreachable');
    // Evidence expires at two probe intervals: once the external rows are that
    // old, an unrelated internal completion must NOT carry them forward, and a
    // disabled source contributes nothing even while fresh.
    await t.run(async (ctx) => {
      for (const r of await ctx.db.query('probeReachability').collect())
        if (r.source === 'globalping')
          await ctx.db.patch(r._id, { updatedAt: Date.now() - 31 * 60_000 });
    });
    await t.mutation(internal.probes.requestMany, {
      targets: [{ kind: 'edge', ref: edgeId }],
      sources: ['internal'],
    });
    await drainRuns(t);
    let after = (await t.query(internal.edges.get, { id: edgeId }))!;
    expect(after.reachability!.byCountry.map((c) => c.country)).toEqual(['XX']);
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.probe.sources.globalping', 'false'));
    await t.run(async (ctx) => {
      for (const r of await ctx.db.query('probeReachability').collect())
        await ctx.db.patch(r._id, { updatedAt: Date.now() });
    });
    await t.mutation(internal.probes.requestMany, {
      targets: [{ kind: 'edge', ref: edgeId }],
      sources: ['internal'],
    });
    await drainRuns(t);
    after = (await t.query(internal.edges.get, { id: edgeId }))!;
    expect(after.reachability!.byCountry.map((c) => c.country)).toEqual(['XX']);
  });

  test('one failing network is not agreement: the country stays unknown, not unreachable', async () => {
    const gp: GlobalpingLike = {
      async createMeasurement() {
        return { ok: true, data: { id: 'm-1' } };
      },
      async getMeasurement(id) {
        return {
          ok: true,
          data: {
            id,
            status: 'finished',
            results: [
              {
                probe: { country: 'IR', asn: 1, tags: ['eyeball-network'] },
                result: { status: 'finished', stats: { loss: 100 } },
              },
            ],
          },
        };
      },
    };
    __setGlobalpingFactory(() => gp);
    const { t, edgeId } = await seed({ countries: ['IR'] });
    await t.mutation(internal.probes.requestProbes, {
      target: { kind: 'edge', ref: edgeId },
      trigger: 'manual',
      sources: ['globalping'],
    });
    await drainRuns(t);
    const edge = (await t.query(internal.edges.get, { id: edgeId }))!;
    expect(edge.reachability!.byCountry).toEqual([
      expect.objectContaining({ country: 'IR', verdict: 'unknown' }),
    ]);
  });

  test('a service failure marks the run failed and leaves no partial verdict; the internal probe still lands', async () => {
    __setGlobalpingFactory(() => ({
      async createMeasurement() {
        return { ok: false, response: new Response(null, { status: 429 }) };
      },
      async getMeasurement() {
        return { ok: false };
      },
    }));
    const { t, edgeId } = await seed({ internalOk: false });
    await t.mutation(internal.probes.requestProbes, {
      target: { kind: 'edge', ref: edgeId },
      trigger: 'manual',
    });
    await drainRuns(t);
    const runs = await t.query(internal.probes.listRuns, {
      target: { kind: 'edge', ref: edgeId },
    });
    expect(runs.find((r) => r.source === 'globalping')?.status).toBe('failed');
    expect(runs.find((r) => r.source === 'internal')?.status).toBe('finished');
    const edge = (await t.query(internal.edges.get, { id: edgeId }))!;
    expect(edge.reachability!.byCountry).toEqual([
      expect.objectContaining({ country: 'XX', verdict: 'unreachable' }),
    ]);
  });

  test('cron: due edges are probed within the hourly budget; disabled config probes nothing', async () => {
    const gp = fakeGlobalping(() => 'ok');
    __setGlobalpingFactory(() => gp);
    const { t, edgeId } = await seed();
    const r1 = await t.action(internal.probes.run, {});
    expect(r1.requested).toBe(2);
    await drainRuns(t);
    // Not due again inside the interval.
    const r2 = await t.action(internal.probes.run, {});
    expect(r2.requested).toBe(0);
    // Budget exhausted → skipped, not requested.
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.probe.hourlyBudget', '1'));
    await t.run(async (ctx) => {
      // Make the edge due again by aging its runs.
      for (const run of await ctx.db.query('probeRuns').collect()) {
        await ctx.db.patch(run._id, { requestedAt: run.requestedAt - 16 * 60_000 });
      }
    });
    const r3 = await t.action(internal.probes.run, {});
    expect(r3.requested).toBe(0);
    expect(r3.skipped).toBe(1);
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.probe.enabled', 'false'));
    const r4 = await t.action(internal.probes.run, {});
    expect(r4).toMatchObject({ requested: 0, skipped: 0 });
    // An interval above an hour still sees its last run: aged 90 min with a
    // 120 min interval → not due; aged past the interval → due.
    await t.run(async (ctx) => {
      await upsertSettingRow(ctx, 'edge.probe.enabled', 'true');
      await upsertSettingRow(ctx, 'edge.probe.hourlyBudget', '200');
      await upsertSettingRow(ctx, 'edge.probe.intervalMinutes', '120');
      for (const run of await ctx.db.query('probeRuns').collect())
        await ctx.db.patch(run._id, { requestedAt: Date.now() - 90 * 60_000 });
    });
    const plan90 = await t.query(internal.probes.due, { now: Date.now() });
    expect(plan90.dueTargets).toEqual([]);
    expect(plan90.spentThisHour).toBe(0);
    const plan130 = await t.query(internal.probes.due, { now: Date.now() + 40 * 60_000 });
    expect(plan130.dueTargets.map((d) => d.target.ref)).toEqual([edgeId]);
  });

  test('stuck runs time out after the ceiling', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, edgeId } = await seed();
    const runId = await t.run((ctx) =>
      ctx.db.insert('probeRuns', {
        targetKind: 'edge',
        targetRef: edgeId,
        source: 'checkhost',
        target: `${EDGE}:443`,
        ipVersion: 4,
        status: 'running',
        trigger: 'cron',
        requestedAt: Date.now() - 11 * 60_000,
        results: [],
      }),
    );
    const r = await t.mutation(internal.probes.sweepStuck, { now: Date.now() });
    expect(r.timedOut).toBe(1);
    expect((await t.run((ctx) => ctx.db.get(runId)))!.status).toBe('timeout');
  });

  test('dual-stack rollups stay per address family: a failing v6 path never overwrites the v4 verdict', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, edgeId } = await seed();
    await t.run((ctx) => ctx.db.patch(edgeId, { addresses: { v4: EDGE, v6: '2001:db8::9' } }));
    const insertRun = (ipVersion: 4 | 6) =>
      t.run((ctx) =>
        ctx.db.insert('probeRuns', {
          targetKind: 'edge',
          targetRef: edgeId,
          source: 'globalping',
          target: ipVersion === 4 ? `${EDGE}:443` : '[2001:db8::9]:443',
          ipVersion,
          status: 'running',
          trigger: 'manual',
          requestedAt: Date.now(),
          results: [],
        }),
      );
    const results = (ok: boolean) =>
      [1, 2].map((k) => ({
        country: 'IR',
        asn: `AS${1000 + k}`,
        network: `net-${k}`,
        vantageClass: 'eyeball' as const,
        ok,
      }));
    await t.mutation(internal.probes.finishRun, {
      runId: await insertRun(4),
      results: results(true),
    });
    await t.mutation(internal.probes.finishRun, {
      runId: await insertRun(6),
      results: results(false),
    });
    const rows = await t.run((ctx) => ctx.db.query('probeReachability').collect());
    expect(rows.map((r) => [r.ipVersion, r.verdict]).sort()).toEqual([
      [4, 'reachable'],
      [6, 'unreachable'],
    ]);
    const edge = (await t.query(internal.edges.get, { id: edgeId }))!;
    const ir = edge.reachability!.byCountry.find((c) => c.country === 'IR')!;
    expect(ir.verdict).toBe('reachable');
    expect(ir.v6Verdict).toBe('unreachable');
    // A later v6 run does not touch the v4 verdict either.
    await t.mutation(internal.probes.finishRun, {
      runId: await insertRun(6),
      results: results(false),
    });
    const again = (await t.query(internal.edges.get, { id: edgeId }))!;
    expect(again.reachability!.byCountry.find((c) => c.country === 'IR')!.verdict).toBe(
      'reachable',
    );
  });

  test('retention: settled runs past two weeks are deleted, fresh and in-flight ones kept', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, edgeId } = await seed();
    const now = Date.now();
    const insert = (status: 'finished' | 'failed' | 'timeout' | 'running', ageMs: number) =>
      t.run((ctx) =>
        ctx.db.insert('probeRuns', {
          targetKind: 'edge',
          targetRef: edgeId,
          source: 'checkhost',
          target: `${EDGE}:443`,
          ipVersion: 4,
          status,
          trigger: 'cron',
          requestedAt: now - ageMs,
          finishedAt: status === 'running' ? undefined : now - ageMs,
          results: [],
        }),
      );
    const DAY = 24 * 60 * 60_000;
    const old1 = await insert('finished', 20 * DAY);
    const old2 = await insert('timeout', 15 * DAY);
    const fresh = await insert('failed', 3 * DAY);
    const running = await insert('running', 20 * DAY);
    const r = await t.mutation(internal.probes.sweepFinished, { now });
    expect(r.removed).toBe(2);
    expect(await t.run((ctx) => ctx.db.get(old1))).toBeNull();
    expect(await t.run((ctx) => ctx.db.get(old2))).toBeNull();
    expect(await t.run((ctx) => ctx.db.get(fresh))).not.toBeNull();
    expect(await t.run((ctx) => ctx.db.get(running))).not.toBeNull();
  });

  test('custom targets and relay nodes are probed like edges: CRUD, matrix rows, run history, audit feed', async () => {
    const gp = fakeGlobalping(() => 'ok');
    __setGlobalpingFactory(() => gp);
    const { t, relayId, edgeId } = await seed();
    // A custom target (hostname) and the relay node opting in.
    const created = await t.mutation(internal.probeTargets.create, {
      label: 'Decoy A',
      address: 'decoy.example',
      port: 8443,
    });
    expect(created.key).toBe(`custom:${created.id}`);
    await t.mutation(internal.relays.update, { id: relayId, probeNode: true });
    await expect(
      t.mutation(internal.probeTargets.create, { label: 'bad', address: 'not a host!' }),
    ).rejects.toThrow(/address/);
    const r = await t.mutation(internal.probes.requestMany, {
      targets: [
        { kind: 'custom', ref: created.id },
        { kind: 'relay', ref: relayId },
        { kind: 'edge', ref: edgeId },
      ],
    });
    expect(r.runIds).toHaveLength(6); // 3 targets × (globalping + internal)
    expect(r.skipped).toEqual([]);
    await drainRuns(t);
    // The custom target was probed at its own port; the node at its origin address.
    expect(gp.requests.map((q) => (q as { target: string }).target).sort()).toEqual(
      ['198.51.100.9', '203.0.113.10', 'decoy.example'].sort(),
    );
    const runs = await t.query(internal.probes.listRuns, {
      target: { kind: 'custom', ref: created.id },
    });
    expect(runs.map((x) => x.source).sort()).toEqual(['globalping', 'internal']);
    expect(runs[0].target).toEqual({
      kind: 'custom',
      ref: created.id,
      key: `custom:${created.id}`,
    });
    const matrix = await t.query(internal.probes.matrix, {});
    expect(matrix.targets.map((x) => x.kind).sort()).toEqual(['custom', 'edge', 'relay']);
    const custom = matrix.targets.find((x) => x.kind === 'custom')!;
    expect(custom.detail).toBe('decoy.example:8443');
    expect(custom.reachability.byCountry.find((c) => c.country === 'IR')?.verdict).toBe(
      'reachable',
    );
    const node = matrix.targets.find((x) => x.kind === 'relay')!;
    expect(node.enabled).toBe(true);
    expect((await t.query(internal.relays.get, { id: relayId }))!.reachability).toBeDefined();
    // Cron scheduling covers all three kinds.
    const plan = await t.query(internal.probes.due, { now: Date.now() + 60 * 60_000 });
    expect(plan.dueTargets.map((d) => d.target.kind).sort()).toEqual(['custom', 'edge', 'relay']);
    // Address change resets the custom target's history: the summary, the rollup
    // rows (else the next finish folds the old host's verdicts back in) and any
    // run still in flight against the old endpoint.
    const rollupsOf = () =>
      t.run((ctx) =>
        ctx.db
          .query('probeReachability')
          .withIndex('by_target_country', (q) =>
            q.eq('targetKind', 'custom').eq('targetRef', created.id),
          )
          .collect(),
      );
    expect((await rollupsOf()).length).toBeGreaterThan(0);
    const inflight = await t.run((ctx) =>
      ctx.db.insert('probeRuns', {
        targetKind: 'custom',
        targetRef: created.id,
        source: 'globalping',
        target: 'decoy.example:8443',
        ipVersion: 4,
        status: 'running',
        trigger: 'manual',
        requestedAt: Date.now(),
        results: [],
      }),
    );
    await t.mutation(internal.probeTargets.update, { id: created.id, address: 'decoy-b.example' });
    expect((await t.query(internal.probeTargets.list, {}))[0].reachability.updatedAt).toBeNull();
    expect(await rollupsOf()).toEqual([]);
    expect((await t.run((ctx) => ctx.db.get(inflight)))!.status).toBe('failed');
    // A late result for that run cannot resurrect the old host's evidence.
    await t.mutation(internal.probes.finishRun, {
      runId: inflight,
      results: [{ country: 'IR', vantageClass: 'eyeball', ok: false }],
    });
    expect(await rollupsOf()).toEqual([]);
    await t.mutation(internal.probeTargets.remove, { id: created.id });
    expect(await rollupsOf()).toEqual([]);
    // The audit feed carries the request, runs, verdicts and target edits, keys only.
    const feed = await t.query(internal.probes.auditFeed, {});
    const actions = new Set(feed.map((e) => e.action));
    for (const a of [
      'probe.requested',
      'probe.run',
      'probe.verdict',
      'probe.target.create',
      'probe.target.update',
      'probe.target.delete',
    ])
      expect(actions.has(a)).toBe(true);
    expect(JSON.stringify(feed)).not.toContain('decoy.example');
    expect(JSON.stringify(feed)).not.toContain('198.51.100.9');
  });

  test('every listener port is probed, per address family; a v6-only edge is due and probed over v6', async () => {
    const gp = fakeGlobalping(() => 'ok');
    __setGlobalpingFactory(() => gp);
    const { t, relayId, edgeId } = await seed();
    await t.run(async (ctx) => {
      const e = (await ctx.db.get(edgeId))!;
      await ctx.db.patch(edgeId, {
        addresses: { v4: EDGE, v6: '2001:db8::9' },
        listeners: [
          e.listeners[0],
          { ...e.listeners[0], edgePort: 8443 },
          { ...e.listeners[0], edgePort: 8443 }, // duplicate port: one run
        ],
      });
    });
    const { runIds } = await t.mutation(internal.probes.requestProbes, {
      target: { kind: 'edge', ref: edgeId },
      trigger: 'manual',
      sources: ['globalping'],
    });
    expect(runIds).toHaveLength(4); // 2 ports × 2 families
    const runs = await t.query(internal.probes.listRuns, { target: { kind: 'edge', ref: edgeId } });
    expect(runs.map((r) => [r.ipVersion, r.source]).sort()).toEqual([
      [4, 'globalping'],
      [4, 'globalping'],
      [6, 'globalping'],
      [6, 'globalping'],
    ]);
    const targets = (await t.run((ctx) => ctx.db.query('probeRuns').collect()))
      .map((r) => r.target)
      .sort();
    expect(targets).toEqual(
      [`${EDGE}:443`, `${EDGE}:8443`, '[2001:db8::9]:443', '[2001:db8::9]:8443'].sort(),
    );
    // The cron's budget estimate follows: sources × ports × families.
    const plan = await t.query(internal.probes.due, { now: Date.now() + 60 * 60_000 });
    expect(plan.dueTargets.find((d) => d.target.ref === edgeId)?.runsPerSource).toBe(4);
    // A v6-only edge (no v4 address) is still a due target.
    const { edgeId: v6Only } = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      listenerId: (await t.run((ctx) => ctx.db.get(edgeId)))!.listenerId,
      ipv4: '198.51.100.10',
      ipv6: '2001:db8::10',
      publish: true,
      verified: true,
    });
    await t.run((ctx) =>
      ctx.db.patch(v6Only as Id<'edges'>, { addresses: { v6: '2001:db8::10' } }),
    );
    const plan2 = await t.query(internal.probes.due, { now: Date.now() + 60 * 60_000 });
    expect(plan2.dueTargets.map((d) => d.target.ref)).toContain(v6Only);
    const v6Runs = await t.mutation(internal.probes.requestProbes, {
      target: { kind: 'edge', ref: v6Only },
      trigger: 'manual',
      sources: ['globalping'],
    });
    expect(v6Runs.runIds).toHaveLength(1);
    expect((await t.run((ctx) => ctx.db.get(v6Runs.runIds[0])))!.ipVersion).toBe(6);
  });

  test('the hourly budget counts EVERY run of the hour (manual, detector, any state), not only due candidates', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, edgeId } = await seed();
    const now = Date.now();
    const insert = (
      trigger: 'manual' | 'detector' | 'cron',
      status: 'finished' | 'failed' | 'running',
      ageMs: number,
    ) =>
      t.run((ctx) =>
        ctx.db.insert('probeRuns', {
          targetKind: 'custom',
          targetRef: 'gone-target', // a target that is not (or no longer) due
          source: 'checkhost',
          target: 'decoy.example:443',
          ipVersion: 4,
          status,
          trigger,
          requestedAt: now - ageMs,
          results: [],
        }),
      );
    await insert('manual', 'finished', 5 * 60_000);
    await insert('detector', 'failed', 20 * 60_000);
    await insert('cron', 'running', 50 * 60_000);
    await insert('manual', 'finished', 61 * 60_000); // outside the hour
    const plan = await t.query(internal.probes.due, { now });
    expect(plan.spentThisHour).toBe(3);
    expect(plan.dueTargets.map((d) => d.target.ref)).toEqual([edgeId]);
    // Budget 3 already spent → the due edge is skipped.
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.probe.hourlyBudget', '3'));
    const r = await t.action(internal.probes.run, {});
    expect(r).toMatchObject({ requested: 0, skipped: 1 });
  });

  test('runs against one external source are staggered across a batch; the internal probe is not delayed', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, relayId, edgeId } = await seed();
    const c1 = await t.mutation(internal.probeTargets.create, { label: 'A', address: 'a.example' });
    const c2 = await t.mutation(internal.probeTargets.create, { label: 'B', address: 'b.example' });
    const requestedAt = Date.now();
    await t.mutation(internal.probes.requestMany, {
      targets: [
        { kind: 'edge', ref: edgeId },
        { kind: 'custom', ref: c1.id },
        { kind: 'custom', ref: c2.id },
      ],
    });
    const runs = await t.run((ctx) => ctx.db.query('probeRuns').collect());
    const scheduled = await t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect());
    const offsetOf = (runId: Id<'probeRuns'>) => {
      const f = scheduled.find((s) => (s.args[0] as { runId: string }).runId === runId)!;
      return f.scheduledTime - requestedAt;
    };
    const gp = runs.filter((r) => r.source === 'globalping').map((r) => offsetOf(r._id));
    expect(gp.sort((a, b) => a - b)).toEqual([0, 1500, 3000]);
    const internalRuns = runs.filter((r) => r.source === 'internal').map((r) => offsetOf(r._id));
    expect(internalRuns).toEqual([0, 0, 0]);
    // Configurable spacing; the cron tick staggers the same way.
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.probe.sourceSpacingMs', '4000'));
    await t.mutation(internal.relays.update, { id: relayId, probeNode: true });
    await t.run(async (ctx) => {
      for (const run of await ctx.db.query('probeRuns').collect()) await ctx.db.delete(run._id);
    });
    const tick = await t.action(internal.probes.run, {});
    expect(tick.requested).toBe(8); // 4 targets × (globalping + internal)
    const runs2 = await t.run((ctx) => ctx.db.query('probeRuns').collect());
    const scheduled2 = await t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect());
    const gp2 = runs2
      .filter((r) => r.source === 'globalping')
      .map((r) => {
        const f = scheduled2.find((s) => (s.args[0] as { runId: string }).runId === r._id)!;
        return f.scheduledTime - r.requestedAt;
      })
      .sort((a, b) => a - b);
    expect(gp2).toEqual([0, 4000, 8000, 12000]);
  });

  test('a manual per-edge probe request is audited as probe.requested with the actor', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, edgeId } = await seed();
    const adminId = await t.run((ctx) =>
      ctx.db.insert('adminUsers', {
        username: 'ops',
        displayName: 'Ops',
        isActive: true,
        updatedAt: Date.now(),
      }),
    );
    await t.mutation(internal.probes.requestProbes, {
      target: { kind: 'edge', ref: edgeId },
      trigger: 'manual',
      actorAdminId: adminId,
    });
    // Cron / detector triggers do not spam the audit log with request rows.
    await t.mutation(internal.probes.requestProbes, {
      target: { kind: 'edge', ref: edgeId },
      trigger: 'detector',
    });
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    const requested = audit.filter((a) => a.action === 'probe.requested');
    expect(requested).toHaveLength(1);
    expect(requested[0]).toMatchObject({
      actorType: 'admin',
      actorId: adminId,
      targetId: `edge:${edgeId}`,
      payload: { targets: 1, runs: 2, sources: null },
    });
  });

  test('custom targets refuse loopback, private, link-local, unspecified and local-zone addresses', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t } = await seed();
    for (const address of [
      '127.0.0.1',
      '10.1.2.3',
      '172.16.0.1',
      '192.168.1.1',
      '169.254.169.254',
      '0.0.0.0',
      '100.64.0.1',
      '::1',
      '::',
      'fe80::1',
      'fd00::1',
      '[fc00::1]',
      '::ffff:10.0.0.1',
      'panel.localhost',
      'printer.local',
      'db.internal',
    ]) {
      await expect(
        t.mutation(internal.probeTargets.create, { label: 'x', address }),
      ).rejects.toThrow(/public/);
    }
    // A single label resolves through the control plane's own search domains
    // (`intranet` → `intranet.corp.example`), which is exactly the internal
    // reach a probe target must never have: refused on shape.
    for (const address of ['localhost', 'LOCALHOST', 'intranet', 'wpad', 'gateway']) {
      await expect(
        t.mutation(internal.probeTargets.create, { label: 'x', address }),
      ).rejects.toThrow(/dotted hostname/);
    }
    const ok = await t.mutation(internal.probeTargets.create, {
      label: 'ok',
      address: '2001:db8::5',
    });
    await expect(
      t.mutation(internal.probeTargets.update, { id: ok.id, address: '127.0.0.2' }),
    ).rejects.toThrow(/public/);
    await t.mutation(internal.probeTargets.update, { id: ok.id, address: '198.51.100.20' });
  });

  test('the chart aligns buckets to clock boundaries and never lists the internal probe as a country', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, edgeId } = await seed();
    const HOUR = 60 * 60_000;
    const now = Date.now();
    const insert = (ageMs: number, results: Array<{ country: string; ok: boolean }>) =>
      t.run((ctx) =>
        ctx.db.insert('probeRuns', {
          targetKind: 'edge',
          targetRef: edgeId,
          source: 'globalping',
          target: `${EDGE}:443`,
          ipVersion: 4,
          status: 'finished',
          trigger: 'cron',
          requestedAt: now - ageMs,
          finishedAt: now - ageMs,
          results: results.map((r) => ({ ...r, vantageClass: 'eyeball' as const })),
        }),
      );
    await insert(10 * 60_000, [
      { country: 'IR', ok: false },
      { country: 'XX', ok: true },
    ]);
    await insert(2 * HOUR, [{ country: 'RU', ok: true }]);
    const s = await t.query(internal.probes.summary, { windowMs: 6 * HOUR });
    expect(s.bucketMs).toBe(HOUR);
    for (const b of s.buckets) expect(b.start % HOUR).toBe(0);
    expect(s.buckets[0].start).toBeLessThanOrEqual(s.sinceMs);
    expect(s.buckets[s.buckets.length - 1].start + HOUR).toBeGreaterThanOrEqual(s.untilMs);
    expect(s.totals).toEqual({ runs: 2, ok: 2, fail: 1 });
    expect(s.byCountry.map((c) => c.country)).toEqual(['IR', 'RU']);
    for (const b of s.buckets) expect(Object.keys(b.byCountry)).not.toContain('XX');
    expect(s.bySource).toEqual([{ source: 'globalping', runs: 2, ok: 2, fail: 1 }]);
  });

  test('a country summary carries its OWN freshness and counts persisted networks, not placeholders', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, edgeId } = await seed();
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.probe.sources.checkhost', 'true'));
    const now = Date.now();
    const row = (
      country: string,
      source: 'globalping' | 'checkhost',
      over: Record<string, unknown>,
    ) =>
      t.run((ctx) =>
        ctx.db.insert('probeReachability', {
          targetKind: 'edge',
          targetRef: edgeId,
          country,
          source,
          ipVersion: 4,
          okCount: 0,
          failCount: 3,
          verdict: 'unreachable',
          updatedAt: now - 60_000,
          ...over,
        }),
      );
    // IR: an old globalping verdict (25 min) and a fresh checkhost one → the
    // country's lastAt is the newest CONTRIBUTING row, not the summary refresh.
    await row('IR', 'globalping', { updatedAt: now - 25 * 60_000, failNetworks: ['AS1', 'AS2'] });
    await row('IR', 'checkhost', { failNetworks: ['ch1', 'ch2'] });
    // RU: a lone legacy row (no persisted networks) with a failCount of 3 is ONE
    // network — the fake placeholder reconstruction is gone, so no agreement.
    await row('RU', 'globalping', {});
    const runId = await t.run((ctx) =>
      ctx.db.insert('probeRuns', {
        targetKind: 'edge',
        targetRef: edgeId,
        source: 'internal',
        target: `${EDGE}:443`,
        ipVersion: 4,
        status: 'running',
        trigger: 'manual',
        requestedAt: now,
        results: [],
      }),
    );
    await t.mutation(internal.probes.finishRun, {
      runId,
      results: [{ country: 'XX', vantageClass: 'datacenter', ok: true }],
    });
    const edge = (await t.query(internal.edges.get, { id: edgeId }))!;
    const by = Object.fromEntries(edge.reachability!.byCountry.map((c) => [c.country, c]));
    expect(by.IR.verdict).toBe('unreachable');
    expect(by.IR.lastAt).toBe(now - 60_000);
    expect(by.RU.verdict).toBe('unknown');
    expect(by.XX.lastAt).toBe(edge.reachability!.updatedAt);
  });

  test('the hourly budget gates EVERY request path: zero refuses, N truncates to whole targets, duplicates collapse', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, edgeId } = await seed();
    const c1 = await t.mutation(internal.probeTargets.create, { label: 'A', address: 'a.example' });
    const c2 = await t.mutation(internal.probeTargets.create, { label: 'B', address: 'b.example' });
    const edge = { kind: 'edge' as const, ref: edgeId as string };
    const t1 = { kind: 'custom' as const, ref: c1.id };
    const t2 = { kind: 'custom' as const, ref: c2.id };
    const runCount = () => t.run(async (ctx) => (await ctx.db.query('probeRuns').collect()).length);
    // Budget zero: the manual batch, a detector request and the cron all refuse; nothing is inserted.
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.probe.hourlyBudget', '0'));
    await expect(t.mutation(internal.probes.requestMany, { targets: [edge] })).rejects.toThrow(
      /probe\.budget_exhausted/,
    );
    await expect(
      t.mutation(internal.probes.requestProbes, { target: edge, trigger: 'detector' }),
    ).rejects.toThrow(/probe\.budget_exhausted/);
    // (all three targets are due: the published edge and both enabled customs)
    expect(await t.action(internal.probes.run, {})).toMatchObject({ requested: 0, skipped: 3 });
    expect(await runCount()).toBe(0);
    // Budget 4, three targets costing 2 each (globalping + internal): the first two
    // fit whole, the third is skipped with the budget reason — exactly 4 runs.
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.probe.hourlyBudget', '4'));
    const r = await t.mutation(internal.probes.requestMany, { targets: [edge, t1, t2] });
    expect(r.runIds).toHaveLength(4);
    expect(r.skipped).toEqual([`custom:${c2.id}: probe.budget_exhausted`]);
    expect(await runCount()).toBe(4);
    // Spent 4 of 4 (the runs are still `requested`; state does not matter): any
    // further request is refused, whichever path asks.
    await expect(t.mutation(internal.probes.requestMany, { targets: [t2] })).rejects.toThrow(
      /probe\.budget_exhausted/,
    );
    await expect(
      t.mutation(internal.probes.requestProbes, { target: t2, trigger: 'cron' }),
    ).rejects.toThrow(/probe\.budget_exhausted/);
    expect(await runCount()).toBe(4);
    // Duplicates collapse to one target: budget 6 leaves room for ONE round of
    // 2, and [t2, t2, t2] is that one round, nothing skipped, audited as 1 target.
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.probe.hourlyBudget', '6'));
    const d = await t.mutation(internal.probes.requestMany, { targets: [t2, t2, t2] });
    expect(d.runIds).toHaveLength(2);
    expect(d.skipped).toEqual([]);
    expect(await runCount()).toBe(6);
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    const requested = audit.filter((a) => a.action === 'probe.requested');
    expect(requested[requested.length - 1].payload).toMatchObject({ targets: 1, runs: 2 });
    // Runs older than the hour no longer count.
    await t.run(async (ctx) => {
      for (const run of await ctx.db.query('probeRuns').collect())
        await ctx.db.patch(run._id, { requestedAt: run.requestedAt - 61 * 60_000 });
    });
    const again = await t.mutation(internal.probes.requestMany, { targets: [edge, t1, t2] });
    expect(again.runIds).toHaveLength(6);
    expect(again.skipped).toEqual([]);
  });

  test('the reachable→unreachable transition marker is judged PER PORT: a listener blocked since it appeared is not evidence', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, edgeId } = await seed();
    const finish = async (port: number, ok: boolean) => {
      const runId = await t.run((ctx) =>
        ctx.db.insert('probeRuns', {
          targetKind: 'edge',
          targetRef: edgeId,
          source: 'globalping',
          target: `${EDGE}:${port}`,
          port,
          ipVersion: 4,
          status: 'running',
          trigger: 'manual',
          requestedAt: Date.now(),
          results: [],
        }),
      );
      await t.mutation(internal.probes.finishRun, {
        runId,
        results: [1, 2].map((k) => ({
          country: 'IR',
          asn: `AS${1000 + k}`,
          network: `net-${k}`,
          vantageClass: 'eyeball' as const,
          ok,
        })),
      });
    };
    const ir = async () =>
      (await t.query(internal.edges.get, { id: edgeId }))!.reachability!.byCountry.find(
        (c) => c.country === 'IR',
      )!;
    // 443 has a reachable history; 8443 has been unreachable since it appeared.
    await finish(443, true);
    await finish(8443, false);
    expect(await ir()).toMatchObject({ verdict: 'unreachable', wasReachable: false });
    // Once 8443 ITSELF was reached and then fails, the country is a transition.
    await finish(8443, true);
    expect(await ir()).toMatchObject({ verdict: 'reachable', wasReachable: true });
    await finish(8443, false);
    expect(await ir()).toMatchObject({ verdict: 'unreachable', wasReachable: true });
  });

  test('planFor reports the runs per source a round will cost without inserting; requestProbes returns the same number', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, edgeId } = await seed();
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.probe.enabled', 'true'));
    const plan = await t.query(internal.probes.planFor, {
      target: { kind: 'edge', ref: edgeId },
      sources: ['globalping'],
    });
    expect(plan.runsPerSource).toBeGreaterThan(0);
    expect(await t.run((ctx) => ctx.db.query('probeRuns').collect())).toHaveLength(0);
    const r = await t.mutation(internal.probes.requestProbes, {
      target: { kind: 'edge', ref: edgeId },
      trigger: 'manual',
      sources: ['globalping'],
    });
    expect(r.runsPerSource).toBe(plan.runsPerSource);
    expect(r.runIds).toHaveLength(plan.runsPerSource);
  });

  test('per-port rollup rows: a blocked listener makes the country unreachable; ports never overwrite each other', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, edgeId } = await seed();
    const insertRun = (port: number) =>
      t.run((ctx) =>
        ctx.db.insert('probeRuns', {
          targetKind: 'edge',
          targetRef: edgeId,
          source: 'globalping',
          target: `${EDGE}:${port}`,
          port,
          ipVersion: 4,
          status: 'running',
          trigger: 'manual',
          requestedAt: Date.now(),
          results: [],
        }),
      );
    const results = (ok: boolean, country = 'IR') =>
      [1, 2].map((k) => ({
        country,
        asn: `AS${1000 + k}`,
        network: `net-${k}`,
        vantageClass: 'eyeball' as const,
        ok,
      }));
    const finish = (port: number, ok: boolean, country?: string) =>
      insertRun(port).then((runId) =>
        t.mutation(internal.probes.finishRun, { runId, results: results(ok, country) }),
      );
    const rows = () =>
      t.run(async (ctx) =>
        (await ctx.db.query('probeReachability').collect())
          .map((r) => [r.country, r.port, r.verdict] as const)
          .sort((a, b) => `${a[0]}:${a[1]}`.localeCompare(`${b[0]}:${b[1]}`)),
      );
    const irVerdict = async () =>
      (await t.query(internal.edges.get, { id: edgeId }))!.reachability!.byCountry.find(
        (c) => c.country === 'IR',
      )!.verdict;
    // Two ports, one blocked: two rows, and the country is unreachable.
    await finish(443, true);
    await finish(8443, false);
    expect(await rows()).toEqual([
      ['IR', 443, 'reachable'],
      ['IR', 8443, 'unreachable'],
    ]);
    expect(await irVerdict()).toBe('unreachable');
    // Completion order is irrelevant: the open port finishing again leaves the block in place.
    await finish(443, true);
    expect(await rows()).toHaveLength(2);
    expect(await irVerdict()).toBe('unreachable');
    // Both reachable → reachable, still two rows.
    await finish(8443, true);
    expect(await rows()).toEqual([
      ['IR', 443, 'reachable'],
      ['IR', 8443, 'reachable'],
    ]);
    expect(await irVerdict()).toBe('reachable');
    // The run history shows which port each run hit.
    const runs = await t.query(internal.probes.listRuns, { target: { kind: 'edge', ref: edgeId } });
    expect(runs.map((r) => r.port).sort()).toEqual([443, 443, 8443, 8443]);
    // A legacy row (written before ports were kept) is adopted by the first run
    // on its path — stamped with the port, not duplicated.
    await t.run((ctx) =>
      ctx.db.insert('probeReachability', {
        targetKind: 'edge',
        targetRef: edgeId,
        country: 'RU',
        source: 'globalping',
        ipVersion: 4,
        okCount: 0,
        failCount: 2,
        failNetworks: ['AS1', 'AS2'],
        verdict: 'unreachable',
        updatedAt: Date.now() - 60_000,
      }),
    );
    await finish(443, true, 'RU');
    expect((await rows()).filter((r) => r[0] === 'RU')).toEqual([['RU', 443, 'reachable']]);
  });

  test('the stuck-run timeout counts from the scheduled start, not the request; a started run still times out', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, edgeId } = await seed();
    const MIN = 60_000;
    const now = Date.now();
    const insert = (over: Record<string, unknown>) =>
      t.run((ctx) =>
        ctx.db.insert('probeRuns', {
          targetKind: 'edge',
          targetRef: edgeId,
          source: 'checkhost',
          target: `${EDGE}:443`,
          port: 443,
          ipVersion: 4,
          status: 'requested',
          trigger: 'manual',
          requestedAt: now,
          results: [],
          ...over,
        }),
      );
    const staggered = await insert({ scheduledAt: now + 11 * MIN });
    const plain = await insert({});
    const started = await insert({
      status: 'running',
      scheduledAt: now + 5 * MIN,
      startedAt: now + 5 * MIN,
    });
    const statusOf = async (id: Id<'probeRuns'>) => (await t.run((ctx) => ctx.db.get(id)))!.status;
    // Minute 10: the plain request timed out; the staggered run is not even due yet.
    expect(await t.mutation(internal.probes.sweepStuck, { now: now + 10 * MIN })).toEqual({
      timedOut: 1,
    });
    expect(await statusOf(plain)).toBe('timeout');
    expect(await statusOf(staggered)).toBe('requested');
    expect(await statusOf(started)).toBe('running');
    // Minute 15: the run started at minute 5 times out; the one due at 11 is inside its window.
    expect(await t.mutation(internal.probes.sweepStuck, { now: now + 15 * MIN })).toEqual({
      timedOut: 1,
    });
    expect(await statusOf(started)).toBe('timeout');
    expect(await statusOf(staggered)).toBe('requested');
    // Minute 21: the staggered run, never started, finally times out.
    expect(await t.mutation(internal.probes.sweepStuck, { now: now + 21 * MIN })).toEqual({
      timedOut: 1,
    });
    expect(await statusOf(staggered)).toBe('timeout');
  });

  test('a batch is never staggered past one probe interval: the spacing shrinks to fit, a lone delay is clamped', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, edgeId } = await seed();
    const MIN = 60_000;
    await t.run(async (ctx) => {
      await upsertSettingRow(ctx, 'edge.probe.sourceSpacingMs', '60000');
      await upsertSettingRow(ctx, 'edge.probe.intervalMinutes', '5');
    });
    const customs = [];
    for (let i = 0; i < 7; i++)
      customs.push(
        await t.mutation(internal.probeTargets.create, {
          label: `T${i}`,
          address: `t${i}.example`,
        }),
      );
    const offsets = async (source: 'globalping' | 'internal') => {
      const runs = await t.run((ctx) => ctx.db.query('probeRuns').collect());
      const scheduled = await t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect());
      return runs
        .filter((r) => r.source === source)
        .map((r) => {
          const f = scheduled.find((s) => (s.args[0] as { runId: string }).runId === r._id)!;
          // The persisted scheduledAt IS the executor's scheduled time.
          expect(r.scheduledAt).toBe(f.scheduledTime);
          return f.scheduledTime - r.requestedAt;
        })
        .sort((a, b) => a - b);
    };
    // 7 targets × 1 run per source at 60 s spacing would span 6 minutes; the
    // spacing shrinks to floor(5 min / 6) = 50 s so the last run lands ON the cap.
    await t.mutation(internal.probes.requestMany, {
      targets: customs.map((c) => ({ kind: 'custom' as const, ref: c.id })),
      sources: ['globalping'],
    });
    expect(await offsets('globalping')).toEqual([0, 1, 2, 3, 4, 5, 6].map((i) => i * 50_000));
    // The cron tick fits its batch the same way (8 targets here: the edge + 7 customs).
    await t.run(async (ctx) => {
      for (const run of await ctx.db.query('probeRuns').collect()) await ctx.db.delete(run._id);
    });
    const tick = await t.action(internal.probes.run, {});
    expect(tick.requested).toBe(16); // 8 targets × (globalping + internal)
    const gp = await offsets('globalping');
    expect(gp).toEqual([0, 1, 2, 3, 4, 5, 6, 7].map((i) => i * Math.floor((5 * MIN) / 7)));
    expect(gp[gp.length - 1]).toBeLessThanOrEqual(5 * MIN);
    expect(await offsets('internal')).toEqual(new Array(8).fill(0));
    // A lone request with no batch context clamps its delay to the span instead.
    await t.run(async (ctx) => {
      for (const run of await ctx.db.query('probeRuns').collect()) await ctx.db.delete(run._id);
    });
    await t.mutation(internal.probes.requestProbes, {
      target: { kind: 'edge', ref: edgeId },
      trigger: 'detector',
      sources: ['globalping'],
      staggerIndex: 100,
    });
    expect(await offsets('globalping')).toEqual([5 * MIN]);
  });

  test('familiesOf: an edge follows the RENDER ipv6 setting, a relay or custom target follows probe.ipv6, a name is probed once', () => {
    const cfg = (over: { ipv6Mode?: 'off' | 'both'; probeIpv6?: boolean }): EdgeConfig =>
      ({
        ...EDGE_DEFAULTS,
        render: { ...EDGE_DEFAULTS.render, ipv6Mode: over.ipv6Mode ?? 'both' },
        probe: { ...EDGE_DEFAULTS.probe, ipv6: over.probeIpv6 ?? true },
      }) as EdgeConfig;
    const dual = (kind: ResolvedTarget['kind']): ResolvedTarget => ({
      kind,
      label: 'x',
      addresses: { v4: '198.51.100.9', v6: '2001:db8::9' },
      ports: [443],
      probeProtocol: 'tcp',
    });
    // An edge is probed over what members are RENDERED, whatever probe.ipv6 says.
    expect(familiesOf(dual('edge'), cfg({ ipv6Mode: 'both', probeIpv6: false }))).toEqual([4, 6]);
    expect(familiesOf(dual('edge'), cfg({ ipv6Mode: 'off', probeIpv6: true }))).toEqual([4]);
    // A relay node / custom target has nothing to do with rendering: its own knob decides.
    for (const kind of ['relay', 'custom'] as const) {
      expect(familiesOf(dual(kind), cfg({ ipv6Mode: 'off', probeIpv6: true }))).toEqual([4, 6]);
      expect(familiesOf(dual(kind), cfg({ ipv6Mode: 'both', probeIpv6: false }))).toEqual([4]);
    }
    // A v6-only target is probed over v6 either way (it is all there is).
    const v6Only = { ...dual('custom'), addresses: { v6: '2001:db8::9' } };
    expect(familiesOf(v6Only, cfg({ probeIpv6: false }))).toEqual([6]);
    // A name has no family: one run, no family requested.
    const named = { ...dual('edge'), addresses: { name: 'front.example' } };
    expect(familiesOf(named, cfg({ ipv6Mode: 'off' }))).toEqual(['any']);
  });

  test('a target with no listener port is not probeable: no fallback to 443, skipped by the cron and refused by name', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, relayId, edgeId } = await seed();
    await t.run((ctx) => ctx.db.patch(edgeId, { listeners: [] }));
    const target = { kind: 'edge' as const, ref: edgeId as string };
    expect(await t.query(internal.probes.planFor, { target })).toEqual({ runsPerSource: 0 });
    await expect(
      t.mutation(internal.probes.requestProbes, { target, trigger: 'manual' }),
    ).rejects.toThrow(/probe\.no_listeners/);
    const many = await t.mutation(internal.probes.requestMany, { targets: [target] });
    expect(many.runIds).toEqual([]);
    expect(many.skipped).toEqual([`edge:${edgeId}: probe.no_listeners`]);
    // The cron does not consider it either, and nothing was ever probed on 443.
    const plan = await t.query(internal.probes.due, { now: Date.now() + 60 * 60_000 });
    expect(plan.dueTargets.map((d) => d.target.ref)).not.toContain(edgeId);
    expect(await t.run((ctx) => ctx.db.query('probeRuns').collect())).toEqual([]);
    // A relay whose listeners are all undeployed is the same case.
    await t.mutation(internal.relays.update, { id: relayId, probeNode: true });
    await t.run(async (ctx) => {
      for (const l of await ctx.db.query('relayListeners').collect())
        await ctx.db.patch(l._id, { deployed: false });
    });
    const plan2 = await t.query(internal.probes.due, { now: Date.now() + 60 * 60_000 });
    expect(plan2.dueTargets.map((d) => d.target.kind)).not.toContain('relay');
    // A UDP listener is not probeable (the probes are TCP connects): a relay
    // whose only deployed listener is udp has no relay-node port either.
    await t.run(async (ctx) => {
      for (const l of await ctx.db.query('relayListeners').collect())
        await ctx.db.patch(l._id, { deployed: true });
    });
    await t.mutation(internal.relayListeners.upsert, {
      relayId,
      spec: {
        listenerKey: 'h',
        protocol: 'hysteria2',
        streamTransport: 'udp',
        security: 'tls',
        originPort: 8443,
        tlsNames: ['h.example'],
        panelBinding: {
          inboundTag: 'HY2',
          configProfileUuid: '11111111-1111-4111-8111-111111111111',
          configProfileInboundUuid: '66666666-6666-4666-8666-666666666666',
        },
      },
    });
    const relayTarget = { kind: 'relay' as const, ref: relayId as string };
    // Two deployed listeners, one tcp on 443 and one udp on 8443: only 443 is probed.
    expect(await t.query(internal.probes.planFor, { target: relayTarget })).toEqual({
      runsPerSource: 1,
    });
    await t.run(async (ctx) => {
      for (const l of await ctx.db.query('relayListeners').collect())
        if (l.transport === 'tcp') await ctx.db.patch(l._id, { deployed: false });
    });
    expect(await t.query(internal.probes.planFor, { target: relayTarget })).toEqual({
      runsPerSource: 0,
    });
    const plan3 = await t.query(internal.probes.due, { now: Date.now() + 60 * 60_000 });
    expect(plan3.dueTargets.map((d) => d.target.kind)).not.toContain('relay');
  });

  test('reachable history survives a disabled or aged-out source, and a degraded (mixed) verdict arms the transition too', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, edgeId } = await seed({ countries: ['IR', 'RU'] });
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.probe.sources.checkhost', 'true'));
    const finish = async (
      source: 'globalping' | 'checkhost',
      country: string,
      results: Array<{ ok: boolean; asn: string }>,
    ) => {
      const runId = await t.run((ctx) =>
        ctx.db.insert('probeRuns', {
          targetKind: 'edge',
          targetRef: edgeId,
          source,
          target: `${EDGE}:443`,
          port: 443,
          ipVersion: 4,
          status: 'running',
          trigger: 'manual',
          requestedAt: Date.now(),
          results: [],
        }),
      );
      await t.mutation(internal.probes.finishRun, {
        runId,
        results: results.map((r) => ({
          country,
          asn: r.asn,
          network: r.asn,
          vantageClass: 'eyeball' as const,
          ok: r.ok,
        })),
      });
    };
    const of = async (country: string) =>
      (await t.query(internal.edges.get, { id: edgeId }))!.reachability!.byCountry.find(
        (c) => c.country === country,
      )!;
    // IR: globalping once reached the edge. RU: globalping only ever saw a
    // DEGRADED path (one success, one failure): a `mixed` verdict, so
    // `lastReachableAt` is never stamped and only `lastOkAt` records it.
    await finish('globalping', 'IR', [
      { ok: true, asn: 'AS1' },
      { ok: true, asn: 'AS2' },
    ]);
    await finish('globalping', 'RU', [
      { ok: true, asn: 'AS1' },
      { ok: false, asn: 'AS2' },
    ]);
    const rows = await t.run((ctx) => ctx.db.query('probeReachability').collect());
    const ru = rows.find((r) => r.country === 'RU')!;
    expect(ru.verdict).toBe('mixed');
    expect(ru.lastReachableAt).toBeUndefined();
    expect(ru.lastOkAt).toBeDefined();
    // Now the source that holds the history is switched off and its rows age
    // past the freshness window, while a DIFFERENT, enabled source reports the
    // block. The history view is unfiltered, so the transition still arms.
    await t.run(async (ctx) => {
      await upsertSettingRow(ctx, 'edge.probe.sources.globalping', 'false');
      for (const r of await ctx.db.query('probeReachability').collect())
        await ctx.db.patch(r._id, { updatedAt: Date.now() - 31 * 60_000 });
    });
    for (const country of ['IR', 'RU'])
      await finish('checkhost', country, [
        { ok: false, asn: 'AS8' },
        { ok: false, asn: 'AS9' },
      ]);
    expect(await of('IR')).toMatchObject({ verdict: 'unreachable', wasReachable: true });
    expect(await of('RU')).toMatchObject({ verdict: 'unreachable', wasReachable: true });
    // A country that was never reached at all is still not evidence.
    await finish('checkhost', 'CN', [
      { ok: false, asn: 'AS8' },
      { ok: false, asn: 'AS9' },
    ]);
    expect(await of('CN')).toMatchObject({ verdict: 'unreachable', wasReachable: false });
  });

  test('a hostname (L7) edge is probed by NAME over TLS: one run, no family, rolled up on its own path', async () => {
    const gp = fakeGlobalpingHttp();
    __setGlobalpingFactory(() => gp);
    const { t, edgeId } = await seed({ countries: ['IR'] });
    await t.run((ctx) =>
      ctx.db.patch(edgeId, { addresses: { hostname: 'front.example' }, layer: 'l7' }),
    );
    const { runIds } = await t.mutation(internal.probes.requestProbes, {
      target: { kind: 'edge', ref: edgeId },
      trigger: 'manual',
      sources: ['globalping'],
    });
    expect(runIds).toHaveLength(1); // one name, one port: no per-family fan-out
    const run = (await t.run((ctx) => ctx.db.get(runIds[0])))!;
    expect(run).toMatchObject({
      target: 'front.example:443',
      addressKind: 'name',
      probeProtocol: 'tls',
      requestedFamily: 'any',
    });
    expect(run.ipVersion).toBeUndefined();
    await drainRuns(t);
    // Globalping was asked for an http measurement against the name.
    expect(gp.requests[0]).toMatchObject({
      type: 'http',
      target: 'front.example',
      measurementOptions: { protocol: 'HTTPS', port: 443 },
    });
    const rows = await t.run((ctx) => ctx.db.query('probeReachability').collect());
    const row = rows.find((r) => r.source === 'globalping')!;
    expect(row.ipVersion).toBeUndefined();
    expect(row).toMatchObject({ addressKind: 'name', probeProtocol: 'tls', verdict: 'reachable' });
    const admin = (
      await t.query(internal.probes.listRuns, {
        target: { kind: 'edge', ref: edgeId },
      })
    ).find((r) => r.source === 'globalping')!;
    expect(admin).toMatchObject({ ipVersion: null, addressKind: 'name', probeProtocol: 'tls' });
    // Rows from an earlier LITERAL life of the same edge stay their own path:
    // the country verdict follows the v4 rows and the name path is reported
    // alongside as `nameVerdict`.
    await t.run((ctx) =>
      ctx.db.insert('probeReachability', {
        targetKind: 'edge',
        targetRef: edgeId,
        country: 'IR',
        source: 'globalping',
        ipVersion: 4,
        addressKind: 'ip',
        port: 443,
        okCount: 0,
        failCount: 2,
        failNetworks: ['AS1', 'AS2'],
        verdict: 'unreachable',
        updatedAt: Date.now(),
      }),
    );
    await t.mutation(internal.probes.requestProbes, {
      target: { kind: 'edge', ref: edgeId },
      trigger: 'manual',
      sources: ['globalping'],
    });
    await drainRuns(t);
    const ir = (await t.query(internal.edges.get, { id: edgeId }))!.reachability!.byCountry.find(
      (c) => c.country === 'IR',
    )!;
    expect(ir.verdict).toBe('unreachable');
    expect(ir.nameVerdict).toBe('reachable');
  });

  test('a custom target can opt into tls/https; changing the protocol resets its history', async () => {
    __setGlobalpingFactory(() => fakeGlobalpingHttp());
    const { t } = await seed({ countries: ['IR'] });
    const created = await t.mutation(internal.probeTargets.create, {
      label: 'Front',
      address: 'decoy.example',
      port: 8443,
      probeProtocol: 'https',
    });
    expect((await t.query(internal.probeTargets.list, {}))[0].probeProtocol).toBe('https');
    const target = { kind: 'custom' as const, ref: created.id };
    await t.mutation(internal.probes.requestProbes, {
      target,
      trigger: 'manual',
      sources: ['globalping'],
    });
    await drainRuns(t);
    const runs = await t.query(internal.probes.listRuns, { target });
    expect(runs[0]).toMatchObject({ addressKind: 'name', probeProtocol: 'https' });
    const rollups = () =>
      t.run((ctx) =>
        ctx.db
          .query('probeReachability')
          .withIndex('by_target_country', (q) =>
            q.eq('targetKind', 'custom').eq('targetRef', created.id),
          )
          .collect(),
      );
    expect((await rollups()).length).toBeGreaterThan(0);
    // A different protocol is a different measurement: the old verdicts go.
    await t.mutation(internal.probeTargets.update, { id: created.id, probeProtocol: 'tcp' });
    expect(await rollups()).toEqual([]);
    await expect(
      t.mutation(internal.probeTargets.update, { id: created.id, probeProtocol: 'quic' as never }),
    ).rejects.toThrow();
  });
});
