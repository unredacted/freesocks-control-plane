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
import { __setGlobalpingFactory } from './relayProbeOps';
import type { GlobalpingLike } from './lib/relays/probes/globalping';

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
    await upsertSettingRow(ctx, 'relay.probe.enabled', JSON.stringify(opts.probeEnabled ?? true));
    await upsertSettingRow(
      ctx,
      'relay.probe.countries',
      JSON.stringify(opts.countries ?? ['IR', 'RU']),
    );
    // check-host / ripe atlas off: this test drives globalping + internal only.
    await upsertSettingRow(ctx, 'relay.probe.sources.checkhost', 'false');
  });
  await t.mutation(internal.relayProfiles.create, {
    slug: 'prof-u',
    name: 'P',
    provider: 'upcloud',
    targetAddress: 'target.example',
    serverNames: ['a.example'],
  });
  const { id: originId } = await t.mutation(internal.relayOrigins.upsertBySlug, {
    slug: 'node-one',
    backendServerSlug: 'panel-a',
    nodeHostname: 'node-one',
    originAddress: '203.0.113.10',
  });
  const { id: slotId } = await t.mutation(internal.relaySlots.upsert, {
    originId,
    slotKey: 'u',
    profileSlug: 'prof-u',
    inboundTag: 'VLESS_RELAY_U',
    configProfileUuid: '11111111-1111-4111-8111-111111111111',
    configProfileInboundUuid: '22222222-2222-4222-8222-222222222222',
    originPort: 443,
  });
  const { edgeId } = await t.mutation(internal.relayOrigins.adoptEdge, {
    originId,
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
  return { t, originId, edgeId: edgeId as Id<'relayEdges'> };
}

async function drainRuns(t: ReturnType<typeof convexTest>) {
  for (let i = 0; i < 60; i++) {
    await vi.runAllTimersAsync();
    await t.finishInProgressScheduledFunctions();
    const pending = await t.run(async (ctx) => {
      const rows = await ctx.db.query('relayProbeRuns').collect();
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
    const { runIds } = await t.mutation(internal.relayProbes.requestProbes, {
      edgeId,
      trigger: 'manual',
    });
    expect(runIds).toHaveLength(2); // globalping + internal, v4 only
    await drainRuns(t);
    const runs = await t.query(internal.relayProbes.listByEdge, { edgeId });
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
    const rows = await t.run((ctx) => ctx.db.query('relayEdgeReachability').collect());
    const by = Object.fromEntries(rows.map((r) => [`${r.source}:${r.country}`, r.verdict]));
    expect(by).toEqual({
      'globalping:IR': 'unreachable',
      'globalping:RU': 'reachable',
      'internal:XX': 'reachable',
    });
    // Edge summary across sources.
    const edge = (await t.query(internal.relayEdges.get, { id: edgeId }))!;
    const summary = Object.fromEntries(
      edge.reachability!.byCountry.map((c) => [c.country, c.verdict]),
    );
    expect(summary).toEqual({ IR: 'unreachable', RU: 'reachable', XX: 'reachable' });
    // Verdict audits carry only ids/codes.
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    const verdicts = audit.filter((a) => a.action === 'relay.probe.verdict');
    expect(verdicts.length).toBeGreaterThan(0);
    expect(JSON.stringify(audit)).not.toContain(EDGE);
    const matrix = await t.query(internal.relayProbes.reachabilityForOrigin, {
      originId: edge.originId,
    });
    expect(matrix.countries).toEqual(['IR', 'RU']);
    expect(matrix.edges[0].byCountry.find((c) => c.country === 'IR')?.verdict).toBe('unreachable');
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
    await t.mutation(internal.relayProbes.requestProbes, {
      edgeId,
      trigger: 'manual',
      sources: ['globalping'],
    });
    await drainRuns(t);
    const edge = (await t.query(internal.relayEdges.get, { id: edgeId }))!;
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
    await t.mutation(internal.relayProbes.requestProbes, { edgeId, trigger: 'manual' });
    await drainRuns(t);
    const runs = await t.query(internal.relayProbes.listByEdge, { edgeId });
    expect(runs.find((r) => r.source === 'globalping')?.status).toBe('failed');
    expect(runs.find((r) => r.source === 'internal')?.status).toBe('finished');
    const edge = (await t.query(internal.relayEdges.get, { id: edgeId }))!;
    expect(edge.reachability!.byCountry).toEqual([
      expect.objectContaining({ country: 'XX', verdict: 'unreachable' }),
    ]);
  });

  test('cron: due edges are probed within the hourly budget; disabled config probes nothing', async () => {
    const gp = fakeGlobalping(() => 'ok');
    __setGlobalpingFactory(() => gp);
    const { t, edgeId } = await seed();
    const r1 = await t.action(internal.relayProbes.run, {});
    expect(r1.requested).toBe(2);
    await drainRuns(t);
    // Not due again inside the interval.
    const r2 = await t.action(internal.relayProbes.run, {});
    expect(r2.requested).toBe(0);
    // Budget exhausted → skipped, not requested.
    await t.run((ctx) => upsertSettingRow(ctx, 'relay.probe.hourlyBudget', '1'));
    await t.run(async (ctx) => {
      // Make the edge due again by aging its runs.
      for (const run of await ctx.db.query('relayProbeRuns').collect()) {
        await ctx.db.patch(run._id, { requestedAt: run.requestedAt - 16 * 60_000 });
      }
    });
    const r3 = await t.action(internal.relayProbes.run, {});
    expect(r3.requested).toBe(0);
    expect(r3.skipped).toBe(1);
    await t.run((ctx) => upsertSettingRow(ctx, 'relay.probe.enabled', 'false'));
    const r4 = await t.action(internal.relayProbes.run, {});
    expect(r4).toMatchObject({ requested: 0, skipped: 0 });
    void edgeId;
  });

  test('stuck runs time out after the ceiling', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, edgeId } = await seed();
    const runId = await t.run((ctx) =>
      ctx.db.insert('relayProbeRuns', {
        edgeId,
        source: 'checkhost',
        target: `${EDGE}:443`,
        ipVersion: 4,
        status: 'running',
        trigger: 'cron',
        requestedAt: Date.now() - 11 * 60_000,
        results: [],
      }),
    );
    const r = await t.mutation(internal.relayProbes.sweepStuck, { now: Date.now() });
    expect(r.timedOut).toBe(1);
    expect((await t.run((ctx) => ctx.db.get(runId)))!.status).toBe('timeout');
  });
});
