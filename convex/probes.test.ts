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
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { __setGlobalpingFactory } from './probeOps';
import type { GlobalpingLike } from './lib/edges/probes/globalping';

const modules = import.meta.glob('./**/*.*s');

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  __setGlobalpingFactory(null);
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
  await t.mutation(internal.protocolProfiles.create, {
    slug: 'prof-u',
    name: 'P',
    provider: 'upcloud',
    targetAddress: 'target.example',
    serverNames: ['a.example'],
  });
  const { id: relayId } = await t.mutation(internal.relays.upsertBySlug, {
    slug: 'node-one',
    backendServerSlug: 'panel-a',
    nodeHostname: 'node-one',
    originAddress: '203.0.113.10',
  });
  const { id: slotId } = await t.mutation(internal.relaySlots.upsert, {
    relayId,
    slotKey: 'u',
    profileSlug: 'prof-u',
    inboundTag: 'VLESS_RELAY_U',
    configProfileUuid: '11111111-1111-4111-8111-111111111111',
    configProfileInboundUuid: '22222222-2222-4222-8222-222222222222',
    originPort: 443,
  });
  const { edgeId } = await t.mutation(internal.relays.adoptEdge, {
    relayId,
    slotId,
    ipv4: EDGE,
    publish: true,
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
      slotId: (await t.run((ctx) => ctx.db.get(edgeId)))!.slotId,
      ipv4: '198.51.100.10',
      ipv6: '2001:db8::10',
      publish: true,
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
      'localhost',
      'LOCALHOST',
      'panel.localhost',
      'printer.local',
      'db.internal',
    ]) {
      await expect(
        t.mutation(internal.probeTargets.create, { label: 'x', address }),
      ).rejects.toThrow(/public/);
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
});
