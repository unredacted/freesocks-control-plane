/// <reference types="vite/client" />
/**
 * Test block evidence (convex/edgeSimulations.ts): the opt-in gate, the start
 * refusals, the detector overlay (nothing fake written anywhere), atomic
 * consumption with the rotation it starts, and the admin surface (view,
 * attention, HTTP, status). The full replace a simulation drives through the
 * rotation machine is in edgeRotations.test.ts.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { signValue } from './lib/cookies';
import { throttlePolicyFor } from './httpEdges';
import {
  adoptL4Edge,
  createAccount,
  insertPanelServer,
  realityListener,
  registerRelay,
} from './lib/edges/testing/fixtures';
import { scheduledWork } from './lib/edges/testing/scheduled';

const modules = import.meta.glob('./**/*.*s');
const scheduled = scheduledWork();
const ADMIN_SIGN_KEY = 'test-admin-sign';

beforeEach(() => {
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', ADMIN_SIGN_KEY);
  vi.stubEnv('EDGE_SIMULATOR_ALLOW', 'simulate-blocks');
});
afterEach(async () => {
  await scheduled.end();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

const EDGE_A = '198.51.100.1';
const EDGE_B = '198.51.100.2';
const SPARE = '198.51.100.3';

/** Two published L4 edges and (optionally) a tested spare; automation and probes on. */
async function seed(opts: { spare?: boolean; automation?: boolean } = {}) {
  const t = scheduled.track(convexTest(schema, modules));
  await insertPanelServer(t);
  const { relayId, listenerId } = await registerRelay(t, {
    listeners: [realityListener({ tlsNames: ['a.example'] })],
  });
  const a = await adoptL4Edge(t, relayId, listenerId, { ipv4: EDGE_A, publish: true });
  const b = await adoptL4Edge(t, relayId, listenerId, { ipv4: EDGE_B, publish: true });
  let spare: Id<'edges'> | null = null;
  if (opts.spare !== false) {
    const accountId = await createAccount(t, {
      provider: 'upcloud',
      name: 'acct-u',
      qualified: true,
    });
    spare = (await adoptL4Edge(t, relayId, listenerId, { ipv4: SPARE, publish: false, accountId }))
      .edgeId as Id<'edges'>;
  }
  await t.run(async (ctx) => {
    await upsertSettingRow(ctx, 'edge.probe.enabled', 'true');
    if (opts.automation !== false) {
      await upsertSettingRow(ctx, 'edge.enabled', 'true');
      await upsertSettingRow(ctx, 'edge.autoRotate', 'true');
      await ctx.db.patch(relayId, { autoRotate: true });
    }
  });
  return {
    t,
    relayId,
    listenerId,
    edgeA: a.edgeId as Id<'edges'>,
    edgeB: b.edgeId as Id<'edges'>,
    spare,
  };
}

type T = Awaited<ReturnType<typeof seed>>['t'];
const rotations = (t: T) => t.run((ctx) => ctx.db.query('edgeRotations').collect());
const simulation = (t: T, id: string) =>
  t.run((ctx) => ctx.db.get(id as Id<'edgeBlockSimulations'>));

describe('test block evidence: the gate and the start refusals', () => {
  test('refused without the opt-in (ENVIRONMENT=production included); accepted with it or in development', async () => {
    const s = await seed();
    vi.stubEnv('EDGE_SIMULATOR_ALLOW', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    await expect(
      s.t.mutation(internal.edgeSimulations.start, { edgeId: s.edgeA, country: 'IR' }),
    ).rejects.toThrow(/simulator_disabled/);
    vi.stubEnv('ENVIRONMENT', 'development');
    const dev = await s.t.mutation(internal.edgeSimulations.start, {
      edgeId: s.edgeA,
      country: 'IR',
    });
    expect(dev.ok).toBe(true);
    vi.stubEnv('ENVIRONMENT', 'production');
    vi.stubEnv('EDGE_SIMULATOR_ALLOW', 'simulate-blocks');
    const opted = await s.t.mutation(internal.edgeSimulations.start, {
      edgeId: s.edgeB,
      country: 'ir',
    });
    const row = (await simulation(s.t, opted.simulationId))!;
    // The country is normalised, the reporters default to twice the detector minimum.
    expect(row).toMatchObject({ edgeId: s.edgeB, country: 'IR', reporters: 8 });
    expect(row.expiresAt - row.startedAt).toBe(60 * 60_000);
  });

  test('only a published edge, with probes on, in a country edges are checked from, one per edge, three at once', async () => {
    const s = await seed();
    await expect(
      s.t.mutation(internal.edgeSimulations.start, { edgeId: s.spare!, country: 'IR' }),
    ).rejects.toThrow(/not_published/);
    await expect(
      s.t.mutation(internal.edgeSimulations.start, { edgeId: s.edgeA, country: 'FR' }),
    ).rejects.toThrow(/simulation_country/);
    for (const bad of [{ reporters: 0 }, { reporters: 51 }, { minutes: 10 }, { minutes: 361 }])
      await expect(
        s.t.mutation(internal.edgeSimulations.start, { edgeId: s.edgeA, country: 'IR', ...bad }),
      ).rejects.toThrow(/validation/);
    await s.t.mutation(internal.edgeSimulations.start, { edgeId: s.edgeA, country: 'IR' });
    await expect(
      s.t.mutation(internal.edgeSimulations.start, { edgeId: s.edgeA, country: 'RU' }),
    ).rejects.toThrow(/simulation_active/);
    // Two more live elsewhere (written directly: the cap counts the deployment).
    await s.t.run(async (ctx) => {
      for (let i = 0; i < 2; i++)
        await ctx.db.insert('edgeBlockSimulations', {
          relayId: s.relayId,
          edgeId: s.spare!,
          country: 'RU',
          reporters: 8,
          startedAt: Date.now(),
          expiresAt: Date.now() + 60 * 60_000,
        });
    });
    await expect(
      s.t.mutation(internal.edgeSimulations.start, { edgeId: s.edgeB, country: 'IR' }),
    ).rejects.toThrow(/simulation_limit/);
    // Probes off: the probe side of the evidence would never be fresh.
    const off = await seed();
    await off.t.run((ctx) => upsertSettingRow(ctx, 'edge.probe.enabled', 'false'));
    await expect(
      off.t.mutation(internal.edgeSimulations.start, { edgeId: off.edgeA, country: 'IR' }),
    ).rejects.toThrow(/simulation_needs_probes/);
  });
});

describe('test block evidence: review fixes', () => {
  test('refused on an origin the detector does not look at: disabled, or being deleted', async () => {
    const s = await seed();
    await s.t.run((ctx) => ctx.db.patch(s.relayId, { enabled: false }));
    await expect(
      s.t.mutation(internal.edgeSimulations.start, { edgeId: s.edgeA, country: 'IR' }),
    ).rejects.toThrow(/simulation_origin_off/);
    await s.t.run((ctx) => ctx.db.patch(s.relayId, { enabled: true, deleting: true }));
    await expect(
      s.t.mutation(internal.edgeSimulations.start, { edgeId: s.edgeA, country: 'IR' }),
    ).rejects.toThrow(/simulation_origin_off/);
  });

  test('expired rows a stalled sweep left open never hide a live one from the limits', async () => {
    const s = await seed();
    const now = Date.now();
    const row = (edgeId: Id<'edges'>, expiresAt: number) => ({
      relayId: s.relayId,
      edgeId,
      country: 'IR',
      reporters: 8,
      startedAt: now - 2 * 60 * 60_000,
      expiresAt,
    });
    await s.t.run(async (ctx) => {
      // Older-expiring open rows first in index order, then the live one.
      for (let i = 0; i < 6; i++)
        await ctx.db.insert('edgeBlockSimulations', row(s.edgeA, now - 60_000 - i));
      await ctx.db.insert('edgeBlockSimulations', row(s.edgeA, now + 60 * 60_000));
    });
    await expect(
      s.t.mutation(internal.edgeSimulations.start, { edgeId: s.edgeA, country: 'RU' }),
    ).rejects.toThrow(/simulation_active/);
    await s.t.run(async (ctx) => {
      for (let i = 0; i < 60; i++)
        await ctx.db.insert('edgeBlockSimulations', row(s.spare!, now - 60_000 - i));
      for (let i = 0; i < 2; i++)
        await ctx.db.insert('edgeBlockSimulations', row(s.spare!, now + 60 * 60_000));
    });
    await expect(
      s.t.mutation(internal.edgeSimulations.start, { edgeId: s.edgeB, country: 'IR' }),
    ).rejects.toThrow(/simulation_limit/);
    // The sweep closes 50 expired ones (its bound) and the two live ones on the
    // unpublished spare (their edge is not in use); the live one on edgeA stays.
    const swept = await s.t.mutation(internal.edgeSimulations.sweep, { now: Date.now() });
    expect(swept.ended).toBe(52);
    const live = await s.t.run((ctx) =>
      ctx.db
        .query('edgeBlockSimulations')
        .withIndex('by_live', (q) => q.eq('endedAt', undefined).gt('expiresAt', Date.now()))
        .collect(),
    );
    expect(live.map((r) => r.edgeId)).toEqual([s.edgeA]);
  });

  test('ending a test block is never held back by the probe quota; starting one is', () => {
    expect(throttlePolicyFor(['edges', 'e1', 'simulate-block'])).toBe('admin.edges.probe');
    expect(throttlePolicyFor(['edges', 'e1', 'simulate-block', 'end'])).toBeNull();
  });
});

describe('test block evidence: the detector', () => {
  test('the overlay suspects and starts the replace, consuming the simulation; nothing fake is written anywhere', async () => {
    const s = await seed();
    const { simulationId } = await s.t.mutation(internal.edgeSimulations.start, {
      edgeId: s.edgeA,
      country: 'IR',
    });
    const report = await s.t.action(internal.edgeDetector.run, {});
    expect(report.rotated).toBe(1);
    const origin = (await s.t.query(internal.relays.get, { id: s.relayId }))!;
    expect(origin.suspicion).toMatchObject({
      state: 'suspected',
      hintLevel: 'corroborated',
      simulated: true,
      veto: null,
    });
    const [r] = await rotations(s.t);
    expect(r).toMatchObject({
      kind: 'replace',
      trigger: 'detector',
      burn: true,
      targetEdgeId: s.edgeA,
      reason: 'detector:reports:simulated',
      simulationId,
      affectedCountries: ['IR'],
    });
    expect(await simulation(s.t, simulationId)).toMatchObject({
      endReason: 'consumed',
      rotationId: r._id,
    });
    const audits = await s.t.run((ctx) => ctx.db.query('auditLog').collect());
    const suspected = audits.find((x) => x.action === 'edge.block_suspected')!;
    expect(suspected.payload).toMatchObject({ simulated: true });
    expect(audits.map((x) => x.action)).toEqual(
      expect.arrayContaining(['edge.block_simulation.started', 'edge.block_simulation.ended']),
    );
    // The real inputs never saw the test.
    const real = await s.t.run(async (ctx) => ({
      reports: (await ctx.db.query('issueReports').collect()).length,
      runs: (await ctx.db.query('probeRuns').collect()).length,
      reach: (await ctx.db.query('probeReachability').collect()).length,
      samples: (await ctx.db.query('relaySamples').collect()).length,
    }));
    expect(real).toEqual({ reports: 0, runs: 0, reach: 0, samples: 0 });
    // The next pass starts nothing: the simulation is consumed.
    expect((await s.t.action(internal.edgeDetector.run, {})).rotated).toBe(0);
    expect(await rotations(s.t)).toHaveLength(1);
  });

  test('consumption is atomic with the start: a rotation that ends early never lets the same simulation start another', async () => {
    const s = await seed();
    const { simulationId } = await s.t.mutation(internal.edgeSimulations.start, {
      edgeId: s.edgeA,
      country: 'IR',
    });
    // The start commits with the consumption, then the action dies (nothing
    // else runs): the rotation exists and the simulation is already consumed.
    const { rotationId } = await s.t.mutation(internal.edgeSimulations.startSimulatedRotation, {
      simulationId: simulationId as Id<'edgeBlockSimulations'>,
      relayId: s.relayId,
      targetEdgeId: s.edgeA,
      reason: 'detector:reports:simulated',
      affectedCountries: ['IR'],
    });
    expect(await simulation(s.t, simulationId)).toMatchObject({
      endReason: 'consumed',
      rotationId,
    });
    // The rotation then fails with no cooldown (an inconclusive L7 proof does that).
    await s.t.run(async (ctx) => {
      await ctx.db.patch(rotationId, { phase: 'failed', outcome: 'qualification_inconclusive' });
      await ctx.db.patch(s.relayId, { activeRotationId: undefined, cooldownUntil: undefined });
    });
    expect((await s.t.action(internal.edgeDetector.run, {})).rotated).toBe(0);
    expect(await rotations(s.t)).toHaveLength(1);
  });

  test('two starts for one simulation create one rotation; an ended simulation starts none', async () => {
    const s = await seed();
    const { simulationId } = await s.t.mutation(internal.edgeSimulations.start, {
      edgeId: s.edgeA,
      country: 'IR',
    });
    const args = {
      simulationId: simulationId as Id<'edgeBlockSimulations'>,
      relayId: s.relayId,
      targetEdgeId: s.edgeA,
      reason: 'detector:reports:simulated',
      affectedCountries: ['IR'],
    };
    const both = await Promise.allSettled([
      s.t.mutation(internal.edgeSimulations.startSimulatedRotation, args),
      s.t.mutation(internal.edgeSimulations.startSimulatedRotation, args),
    ]);
    expect(both.filter((x) => x.status === 'fulfilled')).toHaveLength(1);
    expect(
      String((both.find((x) => x.status === 'rejected') as PromiseRejectedResult).reason),
    ).toMatch(/simulation_ended|already running/);
    expect(await rotations(s.t)).toHaveLength(1);
    // Ended between the evaluation and the start: refused, nothing created.
    const t2 = await seed();
    const sim2 = await t2.t.mutation(internal.edgeSimulations.start, {
      edgeId: t2.edgeA,
      country: 'IR',
    });
    await t2.t.mutation(internal.edgeSimulations.end, { edgeId: t2.edgeA });
    await expect(
      t2.t.mutation(internal.edgeSimulations.startSimulatedRotation, {
        ...args,
        simulationId: sim2.simulationId as Id<'edgeBlockSimulations'>,
        relayId: t2.relayId,
        targetEdgeId: t2.edgeA,
      }),
    ).rejects.toThrow(/simulation_ended/);
    expect(await rotations(t2.t)).toHaveLength(0);
  });

  test('a refused start (no tested spare) rolls back: no rotation, the simulation stays live, the refusal is on the suspicion', async () => {
    const s = await seed({ spare: false });
    const { simulationId } = await s.t.mutation(internal.edgeSimulations.start, {
      edgeId: s.edgeA,
      country: 'IR',
    });
    expect((await s.t.action(internal.edgeDetector.run, {})).rotated).toBe(0);
    expect(await rotations(s.t)).toHaveLength(0);
    expect((await simulation(s.t, simulationId))!.endedAt).toBeUndefined();
    const origin = (await s.t.query(internal.relays.get, { id: s.relayId }))!;
    expect(origin.suspicion?.lastRotateError).toBe('edge.no_verified_spare');
    const attention = await s.t.query(internal.edgeOperator.attention, {});
    expect(attention.items.map((i: { kind: string }) => i.kind)).toEqual(
      expect.arrayContaining(['needs_test', 'block_simulated', 'block_suspected']),
    );
  });

  test('without automation the simulation still raises suspicion, vetoed; removing the opt-in ends it at the next pass', async () => {
    const s = await seed({ automation: false });
    const { simulationId } = await s.t.mutation(internal.edgeSimulations.start, {
      edgeId: s.edgeA,
      country: 'IR',
    });
    expect((await s.t.action(internal.edgeDetector.run, {})).rotated).toBe(0);
    expect((await s.t.query(internal.relays.get, { id: s.relayId }))!.suspicion).toMatchObject({
      state: 'suspected',
      veto: 'edge_disabled',
      simulated: true,
    });
    vi.stubEnv('EDGE_SIMULATOR_ALLOW', '');
    await s.t.action(internal.edgeDetector.run, {});
    expect(await simulation(s.t, simulationId)).toMatchObject({ endReason: 'disabled' });
    const after = (await s.t.query(internal.relays.get, { id: s.relayId }))!;
    expect(after.suspicion?.simulated).toBeUndefined();
    expect(after.suspicion?.score).toBe(0);
  });
});

describe('test block evidence: the admin surface', () => {
  async function adminCookie(t: T) {
    const adminUserId = await t.run((ctx) =>
      ctx.db.insert('adminUsers', {
        username: 'op',
        displayName: 'Op',
        isActive: true,
        updatedAt: Date.now(),
      }),
    );
    const sid = `asid-${Math.random().toString(36).slice(2)}`;
    await t.mutation(internal.sessions.create, {
      sid,
      kind: 'admin',
      adminUserId,
      ttlMs: 3_600_000,
    });
    return `fs_admin_session=${await signValue(sid, ADMIN_SIGN_KEY)}`;
  }

  test('the routes start, show and end a test block; refused with 403 without the opt-in; the status says whether it is on', async () => {
    const s = await seed();
    const cookie = await adminCookie(s.t);
    const call = (method: string, path: string, body?: unknown) =>
      s.t.fetch(`/api/v1/admin/edges/${path}`, {
        method,
        headers: { cookie, 'content-type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    const started = await call('POST', `edges/${s.edgeA}/simulate-block`, {
      country: 'IR',
      minutes: 30,
    });
    expect(started.status).toBe(200);
    const view = await (await call('GET', `relays/${s.relayId}/simulations`)).json();
    expect(view.available).toBe(true);
    expect(view.live).toEqual([
      expect.objectContaining({ edgeId: s.edgeA, country: 'IR', reporters: 8 }),
    ]);
    const attention = await s.t.query(internal.edgeOperator.attention, {});
    expect(
      attention.items.find((i: { kind: string }) => i.kind === 'block_simulated'),
    ).toMatchObject({
      action: 'open_relay',
      edgeId: s.edgeA,
      facts: { count: 1, countries: ['IR'] },
    });
    const ended = await call('POST', `edges/${s.edgeA}/simulate-block/end`, {});
    expect(await ended.json()).toEqual({ ok: true, ended: 1 });
    const after = await (await call('GET', `relays/${s.relayId}/simulations`)).json();
    expect(after.live).toEqual([]);
    expect(after.recent[0]).toMatchObject({ edgeId: s.edgeA, endReason: 'ended' });
    const status = await s.t.query(internal.adminApi.statusSummary, {});
    expect(status.testTools).toEqual({ blockSimulator: true });
    vi.stubEnv('EDGE_SIMULATOR_ALLOW', '');
    const refused = await call('POST', `edges/${s.edgeA}/simulate-block`, { country: 'IR' });
    expect(refused.status).toBe(403);
    expect((await (await call('GET', `relays/${s.relayId}/simulations`)).json()).available).toBe(
      false,
    );
    expect((await s.t.query(internal.adminApi.statusSummary, {})).testTools).toEqual({
      blockSimulator: false,
    });
  });
});
