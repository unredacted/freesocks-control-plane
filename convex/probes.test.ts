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
    void edgeId;
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
    // Address change resets the custom target's history; delete removes its rollups.
    await t.mutation(internal.probeTargets.update, { id: created.id, address: 'decoy-b.example' });
    expect((await t.query(internal.probeTargets.list, {}))[0].reachability.updatedAt).toBeNull();
    await t.mutation(internal.probeTargets.remove, { id: created.id });
    const rows = await t.run((ctx) =>
      ctx.db
        .query('probeReachability')
        .withIndex('by_target_country', (q) =>
          q.eq('targetKind', 'custom').eq('targetRef', created.id),
        )
        .collect(),
    );
    expect(rows).toEqual([]);
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
});
