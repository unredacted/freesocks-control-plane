/// <reference types="vite/client" />
/**
 * A Scaleway edge built through the real rotation machine against a load
 * balancer that applies every change for a while after the call answers
 * (lib/edges/testing/fakeScaleway.ts, docs/edges.md § "Scaleway settling"):
 * every step waits for a `ready` LB before and after its change, so nothing
 * the LB accepted is lost and the address answers. Fixtures only (RFC 5737,
 * `*.example`).
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import {
  createAccount,
  insertPanelServer,
  realityListener,
  registerRelay,
} from './lib/edges/testing/fixtures';
import { defaultLocationRow } from './lib/edges/testing/reads';
import { fakeScaleway } from './lib/edges/testing/fakeScaleway';
import { __setScalewayApiFactory, __setScalewayPause } from './lib/edges/providers/scaleway';

const modules = import.meta.glob('./**/*.*s');
const PROJECT = '66666666-7777-4888-8999-000000000000';

afterEach(() => {
  __setScalewayApiFactory(null);
  __setScalewayPause(null);
  vi.useRealTimers();
});

/** A node with a REALITY transport and a tested, trusted Scaleway account building multi-cloud LBs. */
async function world() {
  const t = convexTest(schema, modules);
  await insertPanelServer(t);
  const accountId = await createAccount(t, {
    provider: 'scaleway',
    name: 'acct-s',
    qualified: true,
    settings: { accessKey: 'SCWXXXXXXXXXXXXXXXXX', zone: 'fr-par-1', projectId: PROJECT },
    credentials: { secretKey: '11111111-2222-4333-8444-555555555555' },
  });
  await t.mutation(internal.edgeProviderAccounts.recordTest, { id: accountId, ok: true });
  const r = await registerRelay(t, { listeners: [realityListener()] });
  const locationId = (await defaultLocationRow(t, accountId))!._id;
  await t.run((ctx) =>
    ctx.db.patch(locationId, { regionalParams: JSON.stringify({ type: 'LB-GP-L' }) }),
  );
  return { t, relayId: r.relayId, listenerId: r.listenerId, locationId };
}

async function drain(t: ReturnType<typeof convexTest>, rotationId: Id<'edgeRotations'>) {
  for (let i = 0; i < 400; i++) {
    await vi.runAllTimersAsync();
    await t.finishInProgressScheduledFunctions();
    const r = await t.query(internal.edgeRotations.get, { id: rotationId });
    if (r && ['done', 'failed', 'rolled_back', 'quarantined', 'cancelled'].includes(r.phase))
      return r;
  }
  throw new Error('drain: the rotation did not settle');
}

describe('a Scaleway edge through the rotation machine', () => {
  test('every step waits for a ready load balancer: nothing is lost, the address answers', async () => {
    vi.useFakeTimers();
    const fake = fakeScaleway({ applyReads: 3 });
    __setScalewayApiFactory(() => fake.api as never);
    __setScalewayPause(async () => {});
    const { t, relayId, listenerId, locationId } = await world();
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'provision',
      trigger: 'manual',
      publishOnDone: false,
      listenerId,
      requestedLocationId: locationId,
    });
    const r = await drain(t, rotationId);
    expect(r.phase).toBe('done');
    expect(fake.lost()).toEqual([]);
    expect(fake.answers()).toBe(true);
    // Each create went out right after a READY read.
    for (const create of ['createBackend', 'createFrontend'])
      expect(fake.calls[fake.calls.indexOf(create) - 1]).toBe('getLb:ready');
    const edge = (await t.run((ctx) => ctx.db.get(r.toEdgeId!)))!;
    expect(edge.steps.map((s) => [s.stepId, s.state])).toEqual([
      ['ip4', 'done'],
      ['ip6', 'done'],
      ['lb', 'done'],
      ['backend', 'done'],
      ['frontend', 'done'],
    ]);
    // Each settling step was polled, and its resource recorded once.
    expect(r.events.map((e) => e.detail)).toEqual(
      expect.arrayContaining([
        'step lb requested',
        'step backend requested',
        'step frontend requested',
      ]),
    );
    expect(edge.resources.map((x) => x.kind)).toEqual(['ip', 'ipv6', 'lb', 'backend', 'frontend']);
    expect(edge.addresses).toMatchObject({ v4: '198.51.100.80', v6: '2001:db8::80' });
  });

  test('a load balancer that goes into error stops the run on lb_unusable and keeps what was built', async () => {
    vi.useFakeTimers();
    const fake = fakeScaleway({ applyReads: 1 });
    __setScalewayApiFactory(() => fake.api as never);
    __setScalewayPause(async () => {});
    const { t, relayId, listenerId, locationId } = await world();
    const create = fake.api.createLb;
    fake.api.createLb = async (req: { name: string }) => {
      const lb = await create(req);
      fake.force('error');
      return lb;
    };
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'provision',
      trigger: 'manual',
      publishOnDone: false,
      listenerId,
      requestedLocationId: locationId,
    });
    const r = await drain(t, rotationId);
    expect(r.phase).toBe('failed');
    expect(r.outcome).toBe('lb_unusable');
    const edge = (await t.run((ctx) => ctx.db.get(r.toEdgeId!)))!;
    expect(edge.failure).toMatchObject({ step: 'lb', code: 'lb_unusable' });
    expect(edge.status).toBe('needs_operator');
    expect(edge.resources.map((x) => x.kind)).toContain('lb');
    expect(fake.calls).not.toContain('createBackend');
  });
});
