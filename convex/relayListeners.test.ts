/// <reference types="vite/client" />
/**
 * Relay listeners as an admin edits them: the admin-owned upsert (never
 * pruned by the role), retire refusals (edge in use, FCP Host present, a
 * running rotation), server-name retire / reactivate with the epoch bumps and
 * the ≥1-active-name rule, the fleet-wide ONE-transaction name retirement,
 * the drain-elapsed epoch bump and the template-edge bookkeeping.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import {
  FIXTURE_CONFIG_PROFILE,
  adoptL4Edge,
  realityListener,
  registerRelay,
  seedEdgeFixture,
  shadowsocksListener,
  wsListener,
} from './lib/edges/testing/fixtures';

const modules = import.meta.glob('./**/*.*s');

type T = TestConvex<typeof schema>;

async function seed() {
  const t = convexTest(schema, modules);
  return seedEdgeFixture(t);
}

const epochOf = async (t: T, relayId: Id<'relays'>) =>
  (await t.query(internal.relays.get, { id: relayId }))!.publicationEpoch;
const row = (t: T, id: Id<'relayListeners'>) => t.run((ctx) => ctx.db.get(id));
const mirrorRefreshes = (t: T) =>
  t.run(
    async (ctx) =>
      (await ctx.db.system.query('_scheduled_functions').collect()).filter(
        (r) => r.name === 'storage:refreshActiveMirrors',
      ).length,
  );
const audits = (t: T, action: string) =>
  t.run(async (ctx) =>
    (await ctx.db.query('auditLog').collect()).filter((a) => a.action === action),
  );
const names = (l: { tlsNames?: Array<{ name: string; status: string }> } | null) =>
  Object.fromEntries((l?.tlsNames ?? []).map((n) => [n.name, n.status]));

async function fakeRotation(t: T, relayId: Id<'relays'>) {
  const rotationId = await t.run((ctx) =>
    ctx.db.insert('edgeRotations', {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      burn: false,
      force: false,
      phase: 'provisioning',
      stepVersion: 1,
      cancelRequested: false,
      hostPlan: [],
      flipAttempts: 0,
      rollbackAttempts: 0,
      pollAttempts: 0,
      events: [],
      startedAt: Date.now(),
      updatedAt: Date.now(),
    }),
  );
  await t.run((ctx) => ctx.db.patch(relayId, { activeRotationId: rotationId }));
  return rotationId;
}

describe('relayListeners: admin upsert', () => {
  test('creates an admin-owned listener with the derived remark; re-sending it is a no-op; the role neither prunes nor edits it', async () => {
    const { t, relayId } = await seed();
    const e0 = await epochOf(t, relayId);
    const created = await t.mutation(internal.relayListeners.upsert, {
      relayId,
      spec: wsListener() as never,
    });
    expect(created).toMatchObject({
      created: true,
      changed: true,
      templateHostRemark: 'node-one-relay-w',
    });
    const l = (await row(t, created.id))!;
    expect(l).toMatchObject({
      listenerKey: 'w',
      source: 'admin',
      protocol: 'vless',
      streamTransport: 'ws',
      security: 'tls',
      transport: 'tcp',
      originPort: 443,
      matchRule: { kind: 'remark', remark: 'node-one-relay-w' },
      transportParams: { path: '/ws' },
      enabled: true,
      deployed: true,
      retired: false,
      revision: 1,
    });
    expect(l.configHash).toMatch(/^[0-9a-f]{16}$/);
    expect(await epochOf(t, relayId)).toBe(e0 + 1);
    expect((await audits(t, 'relay.listener.upsert'))[0].payload).toEqual({
      relaySlug: 'node-one',
      listenerKey: 'w',
      created: true,
    });
    // Identical spec: nothing moves.
    const again = await t.mutation(internal.relayListeners.upsert, {
      relayId,
      spec: wsListener() as never,
    });
    expect(again).toMatchObject({ id: created.id, created: false, changed: false });
    expect((await row(t, created.id))!.revision).toBe(1);
    expect(await epochOf(t, relayId)).toBe(e0 + 1);
    // A changed spec is an update.
    const upd = await t.mutation(internal.relayListeners.upsert, {
      relayId,
      spec: wsListener({ transportParams: { path: '/ws2' } }) as never,
    });
    expect(upd).toMatchObject({ created: false, changed: true });
    expect((await row(t, created.id))!.revision).toBe(2);
    // The role's registration (which prunes ITS listeners) leaves the admin row alone ...
    const role = await registerRelay(t, { listeners: [realityListener()] });
    expect(role.changed).toBe(false);
    expect((await row(t, created.id))!.retired).toBe(false);
    // ... and cannot take it over.
    await expect(
      registerRelay(t, { listeners: [realityListener(), wsListener()] }),
    ).rejects.toThrow(/listener_key_owned/);
    // Nor can the admin form take over the role's key.
    await expect(
      t.mutation(internal.relayListeners.upsert, { relayId, spec: realityListener() as never }),
    ).rejects.toThrow(/listener_key_owned/);
    // Validation errors surface with their codes.
    await expect(
      t.mutation(internal.relayListeners.upsert, {
        relayId,
        spec: shadowsocksListener({ security: 'tls' }) as never,
      }),
    ).rejects.toThrow(/invalid_combination/);
    await expect(
      t.mutation(internal.relayListeners.upsert, {
        relayId: 'relays:missing' as never,
        spec: shadowsocksListener() as never,
      }),
    ).rejects.toThrow();
    const list = await t.query(internal.relayListeners.listByRelay, { relayId });
    expect(list.map((x) => x.listenerKey)).toEqual(['a', 'w']);
    expect(list[1]).toMatchObject({
      source: 'admin',
      host: null,
      legacyHosts: [],
      templateEdgeId: null,
      label: 'VLESS over WebSocket (TLS)',
    });
  });
});

describe('relayListeners: retire + enable', () => {
  test('retire: no-op for a missing/retired key; refused while an edge uses it, while an FCP Host is present, or while a rotation runs', async () => {
    const { t, relayId, listenerId } = await seed();
    expect(
      await t.mutation(internal.relayListeners.retire, { relayId, listenerKey: 'nope' }),
    ).toEqual({ ok: true });
    const { edgeId } = await adoptL4Edge(t, relayId, listenerId, { publish: false });
    await expect(
      t.mutation(internal.relayListeners.retire, { relayId, listenerKey: 'a' }),
    ).rejects.toThrow(/listener_in_use/);
    await t.mutation(internal.edges.patchEdge, { edgeId, status: 'destroyed' });
    await t.run((ctx) =>
      ctx.db.patch(listenerId, { host: { state: 'present', uuid: 'h-1', ownership: 'fcp' } }),
    );
    await expect(
      t.mutation(internal.relayListeners.retire, { relayId, listenerKey: 'a' }),
    ).rejects.toThrow(/host_present/);
    // An operator-owned (adopted) Host does not block.
    await t.run((ctx) =>
      ctx.db.patch(listenerId, { host: { state: 'present', uuid: 'h-1', ownership: 'adopted' } }),
    );
    const rotationId = await fakeRotation(t, relayId);
    await expect(
      t.mutation(internal.relayListeners.retire, { relayId, listenerKey: 'a' }),
    ).rejects.toThrow(/rotation_running/);
    await t.run((ctx) => ctx.db.patch(rotationId, { phase: 'done' }));
    const e0 = await epochOf(t, relayId);
    const m0 = await mirrorRefreshes(t);
    expect(await t.mutation(internal.relayListeners.retire, { relayId, listenerKey: 'a' })).toEqual(
      { ok: true },
    );
    expect((await row(t, listenerId))!).toMatchObject({
      retired: true,
      deployed: false,
      revision: 2,
    });
    expect(await epochOf(t, relayId)).toBe(e0 + 1);
    expect(await mirrorRefreshes(t)).toBe(m0 + 1);
    expect((await audits(t, 'relay.listener.retire'))[0].payload).toEqual({
      relaySlug: 'node-one',
      listenerKey: 'a',
    });
    // Already retired: no-op.
    expect(await t.mutation(internal.relayListeners.retire, { relayId, listenerKey: 'a' })).toEqual(
      { ok: true },
    );
    expect(await epochOf(t, relayId)).toBe(e0 + 1);
    // Quarantine blocks it too.
    const w = await t.mutation(internal.relayListeners.upsert, {
      relayId,
      spec: wsListener() as never,
    });
    await t.run((ctx) =>
      ctx.db.patch(relayId, { quarantine: { rotationId, since: Date.now(), reason: 'test' } }),
    );
    await expect(
      t.mutation(internal.relayListeners.retire, { relayId, listenerKey: 'w' }),
    ).rejects.toThrow(/quarantined/);
    expect((await row(t, w.id))!.retired).toBe(false);
  });

  test('setEnabled: same value is a no-op; a flip bumps revision + epoch and is audited with the flag', async () => {
    const { t, relayId, listenerId } = await seed();
    const e0 = await epochOf(t, relayId);
    expect(
      await t.mutation(internal.relayListeners.setEnabled, { id: listenerId, enabled: true }),
    ).toEqual({ ok: true });
    expect(await epochOf(t, relayId)).toBe(e0);
    await t.mutation(internal.relayListeners.setEnabled, { id: listenerId, enabled: false });
    expect((await row(t, listenerId))!).toMatchObject({ enabled: false, revision: 2 });
    expect(await epochOf(t, relayId)).toBe(e0 + 1);
    expect((await audits(t, 'relay.listener.update'))[0].payload).toEqual({
      relaySlug: 'node-one',
      listenerKey: 'a',
      enabled: false,
    });
    await fakeRotation(t, relayId);
    await expect(
      t.mutation(internal.relayListeners.setEnabled, { id: listenerId, enabled: true }),
    ).rejects.toThrow(/rotation_running/);
    await expect(
      t.mutation(internal.relayListeners.setEnabled, {
        id: 'relayListeners:missing' as never,
        enabled: true,
      }),
    ).rejects.toThrow();
  });
});

describe('relayListeners: server names', () => {
  test('retireName / reactivateName bump the epoch when they change something; a listener keeps ≥1 active name unless L7-only', async () => {
    const { t, relayId, listenerId } = await seed();
    const e0 = await epochOf(t, relayId);
    expect(
      await t.mutation(internal.relayListeners.retireName, {
        id: listenerId,
        names: ['A.Example.'],
      }),
    ).toEqual({ ok: true, retired: 1 });
    let l = (await row(t, listenerId))!;
    expect(l.tlsNames![0]).toMatchObject({
      name: 'a.example',
      status: 'retired',
      retiredBy: 'admin',
    });
    expect(l.tlsNames![0].drainUntil).toBeGreaterThan(Date.now());
    expect(l.revision).toBe(2);
    expect(await epochOf(t, relayId)).toBe(e0 + 1);
    // Retiring an already-retired or unknown name changes nothing.
    expect(
      await t.mutation(internal.relayListeners.retireName, {
        id: listenerId,
        names: ['a.example', 'nope.example', 'bad name'],
      }),
    ).toEqual({ ok: true, retired: 0 });
    expect(await epochOf(t, relayId)).toBe(e0 + 1);
    // The last active name cannot go.
    await expect(
      t.mutation(internal.relayListeners.retireName, { id: listenerId, names: ['b.example'] }),
    ).rejects.toThrow(/at least one active/);
    expect(
      await t.mutation(internal.relayListeners.reactivateName, {
        id: listenerId,
        names: ['a.example'],
      }),
    ).toEqual({ ok: true, reactivated: 1 });
    l = (await row(t, listenerId))!;
    expect(l.tlsNames![0]).toEqual({ name: 'a.example', status: 'active' });
    expect(l.revision).toBe(3);
    expect(await epochOf(t, relayId)).toBe(e0 + 2);
    // Reactivating an active name changes nothing.
    expect(
      await t.mutation(internal.relayListeners.reactivateName, {
        id: listenerId,
        names: ['a.example'],
      }),
    ).toEqual({ ok: true, reactivated: 0 });
    expect(await epochOf(t, relayId)).toBe(e0 + 2);
    const retireAudit = (await audits(t, 'relay.listener.name.retire')).map((a) => a.payload);
    expect(retireAudit[0]).toEqual({ relaySlug: 'node-one', listenerKey: 'a', count: 1 });
    expect((await audits(t, 'relay.listener.name.reactivate'))[0].payload).toEqual({
      relaySlug: 'node-one',
      listenerKey: 'a',
      count: 1,
    });
    // An L7-only listener (plaintext origin behind the front) may retire every name: the hostname is the name.
    const l7 = await t.mutation(internal.relayListeners.upsert, {
      relayId,
      spec: wsListener({
        tlsNames: ['only.example'],
        originTransport: {
          scheme: 'http',
          certPublic: false,
          certNames: [],
          acceptsHostHeader: 'any',
        },
      }) as never,
    });
    expect(
      await t.mutation(internal.relayListeners.retireName, { id: l7.id, names: ['only.example'] }),
    ).toEqual({ ok: true, retired: 1 });
    // A running rotation refuses both.
    await fakeRotation(t, relayId);
    await expect(
      t.mutation(internal.relayListeners.retireName, { id: listenerId, names: ['b.example'] }),
    ).rejects.toThrow(/rotation_running/);
    await expect(
      t.mutation(internal.relayListeners.reactivateName, { id: listenerId, names: ['a.example'] }),
    ).rejects.toThrow(/rotation_running/);
  });

  test('retireNameEverywhere retires the name on every relay in ONE transaction; a rotating relay refuses the whole call', async () => {
    const { t, relayId, listenerId } = await seed();
    const two = await registerRelay(t, {
      slug: 'node-two',
      nodeName: 'node-two',
      originAddress: '203.0.113.11',
      listeners: [
        realityListener({ tlsNames: ['a.example', 'z.example'] }),
        shadowsocksListener(), // no names: untouched
        realityListener({
          listenerKey: 'r',
          tlsNames: ['other.example'],
          panelBinding: {
            inboundTag: 'VLESS_RELAY_R',
            configProfileUuid: FIXTURE_CONFIG_PROFILE,
            configProfileInboundUuid: '99999999-9999-4999-8999-999999999999',
          },
        }),
      ],
    });
    // A retired listener carrying the name is skipped.
    const three = await registerRelay(t, {
      slug: 'node-three',
      nodeName: 'node-three',
      originAddress: '203.0.113.12',
      listeners: [realityListener({ tlsNames: ['a.example', 'q.example'] })],
    });
    await t.mutation(internal.relayListeners.retire, { relayId: three.relayId, listenerKey: 'a' });
    await expect(
      t.mutation(internal.relayListeners.retireNameEverywhere, { name: 'not a name' }),
    ).rejects.toThrow(/invalid server name/);
    const e1 = await epochOf(t, relayId);
    const e2 = await epochOf(t, two.relayId);
    const e3 = await epochOf(t, three.relayId);
    // Relay two rotates: nothing is retired anywhere.
    const rotationId = await fakeRotation(t, two.relayId);
    await expect(
      t.mutation(internal.relayListeners.retireNameEverywhere, { name: 'a.example' }),
    ).rejects.toThrow(/rotation_running/);
    expect(names(await row(t, listenerId))['a.example']).toBe('active');
    expect(names(await row(t, two.listenerIds.a))['a.example']).toBe('active');
    expect(await epochOf(t, relayId)).toBe(e1);
    await t.run((ctx) => ctx.db.patch(rotationId, { phase: 'done' }));
    const r = await t.mutation(internal.relayListeners.retireNameEverywhere, { name: 'A.EXAMPLE' });
    expect(r).toEqual({ ok: true, retired: 2, listeners: 2 });
    expect(names(await row(t, listenerId))).toEqual({
      'a.example': 'retired',
      'b.example': 'active',
    });
    expect(names(await row(t, two.listenerIds.a))).toEqual({
      'a.example': 'retired',
      'z.example': 'active',
    });
    expect(names(await row(t, two.listenerIds.r))).toEqual({ 'other.example': 'active' });
    expect(names(await row(t, three.listenerIds.a))['a.example']).toBe('active'); // retired listener: skipped
    expect(await epochOf(t, relayId)).toBe(e1 + 1);
    expect(await epochOf(t, two.relayId)).toBe(e2 + 1);
    expect(await epochOf(t, three.relayId)).toBe(e3); // its only carrier is retired: untouched
    const everywhere = (await audits(t, 'relay.listener.name.retire')).find(
      (a) => (a.payload as { everywhere?: boolean }).everywhere,
    );
    expect(everywhere?.payload).toEqual({ count: 2, everywhere: true });
    // Nothing left to retire: zero, no bump.
    expect(
      await t.mutation(internal.relayListeners.retireNameEverywhere, { name: 'a.example' }),
    ).toEqual({
      ok: true,
      retired: 0,
      listeners: 0,
    });
    expect(await epochOf(t, relayId)).toBe(e1 + 1);
    // Atomic under the ≥1-active rule too: a listener whose ONLY active name is
    // the burned one refuses the call, and no other relay loses the name.
    const four = await registerRelay(t, {
      slug: 'node-four',
      nodeName: 'node-four',
      originAddress: '203.0.113.13',
      listeners: [realityListener({ tlsNames: ['z.example'] })],
    });
    await expect(
      t.mutation(internal.relayListeners.retireNameEverywhere, { name: 'z.example' }),
    ).rejects.toThrow(/at least one active/);
    expect(names(await row(t, two.listenerIds.a))['z.example']).toBe('active');
    expect(names(await row(t, four.listenerIds.a))['z.example']).toBe('active');
  });

  test('onNameDrainElapsed bumps the epoch (+ mirrors) only once a named retirement’s drain has elapsed', async () => {
    const { t, relayId, listenerId } = await seed();
    await t.mutation(internal.relayListeners.retireName, { id: listenerId, names: ['a.example'] });
    const scheduled = await t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect());
    const drain = scheduled.find((s) => s.name === 'relayListeners:onNameDrainElapsed');
    expect(drain).toBeDefined();
    expect(drain!.args[0]).toEqual({ id: listenerId, names: ['a.example'] });
    const e0 = await epochOf(t, relayId);
    const m0 = await mirrorRefreshes(t);
    // Too early: the drain is still running.
    await t.mutation(internal.relayListeners.onNameDrainElapsed, {
      id: listenerId,
      names: ['a.example'],
    });
    expect(await epochOf(t, relayId)).toBe(e0);
    // An unrelated name, or a reactivated one, never bumps.
    await t.run(async (ctx) => {
      const l = (await ctx.db.get(listenerId))!;
      await ctx.db.patch(listenerId, {
        tlsNames: l.tlsNames!.map((n) =>
          n.name === 'a.example' ? { ...n, drainUntil: Date.now() - 1 } : n,
        ),
      });
    });
    await t.mutation(internal.relayListeners.onNameDrainElapsed, {
      id: listenerId,
      names: ['b.example'],
    });
    expect(await epochOf(t, relayId)).toBe(e0);
    // Elapsed: members stop receiving the retired name.
    await t.mutation(internal.relayListeners.onNameDrainElapsed, {
      id: listenerId,
      names: ['a.example'],
    });
    expect(await epochOf(t, relayId)).toBe(e0 + 1);
    expect(await mirrorRefreshes(t)).toBe(m0 + 1);
    // A deleted listener is a quiet no-op.
    await t.run((ctx) => ctx.db.delete(listenerId));
    expect(
      await t.mutation(internal.relayListeners.onNameDrainElapsed, {
        id: listenerId,
        names: ['a.example'],
      }),
    ).toBeNull();
  });
});

describe('relayListeners: template edge', () => {
  test('setTemplateEdge records / clears the edge a listener’s Host points at', async () => {
    const { t, relayId, listenerId } = await seed();
    const { edgeId } = await adoptL4Edge(t, relayId, listenerId);
    await t.mutation(internal.relayListeners.setTemplateEdge, {
      id: listenerId,
      edgeId: edgeId as Id<'edges'>,
    });
    expect((await row(t, listenerId))!.templateEdgeId).toBe(edgeId);
    expect((await t.query(internal.relayListeners.get, { id: listenerId }))!.templateEdgeId).toBe(
      edgeId,
    );
    await t.mutation(internal.relayListeners.setTemplateEdge, { id: listenerId, edgeId: null });
    expect((await row(t, listenerId))!.templateEdgeId).toBeUndefined();
  });
});
