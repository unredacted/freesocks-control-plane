/// <reference types="vite/client" />
/**
 * The backend-Host state machine for FCP-owned listener Hosts (convex/hostOps.ts):
 * persisted intent before any call, discovery that matches on remark AND
 * transport AND address:port, the settle floor before an empty listing means
 * `absent`, read-back-only delete confirmation, and the reconcile pass.
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { jsonRes, mockFetch } from './lib/edges/testing/mockFetch';
import {
  FIXTURE_INBOUND,
  FIXTURE_ORIGIN,
  realityListener,
  seedEdgeFixture,
} from './lib/edges/testing/fixtures';

const modules = import.meta.glob('./**/*.*s');

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

const REMARK = 'node-one-relay-a';
const EDGE = '198.51.100.50';
const HOST_UUID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const NOW = 1_800_000_000_000;

const TARGET = { address: EDGE, port: 443, sni: 'a.example', host: null };

interface BackendAddress {
  uuid: string;
  remark: string;
  address: string;
  port: number;
  sni?: string | null;
  host?: string | null;
  inbound: { configProfileUuid: string; configProfileInboundUuid: string } | null;
}

function panelHost(over: Partial<BackendAddress> = {}): BackendAddress {
  return {
    uuid: HOST_UUID,
    remark: REMARK,
    address: EDGE,
    port: 443,
    sni: 'a.example',
    host: null,
    inbound: {
      configProfileUuid: '11111111-1111-4111-8111-111111111111',
      configProfileInboundUuid: FIXTURE_INBOUND,
    },
    ...over,
  };
}

/** The discovery-call shape `applyDiscovery` takes (what `listPanelHosts` produces). */
function seen(h: BackendAddress) {
  return {
    uuid: h.uuid,
    remark: h.remark,
    address: h.address,
    port: h.port,
    sni: h.sni ?? null,
    host: h.host ?? null,
    inboundUuid: h.inbound?.configProfileInboundUuid ?? null,
  };
}

/**
 * A fake backend with a mutable Host table. POST mints a uuid (or fails when
 * asked), DELETE removes (or fails / is ignored when asked), GET lists.
 */
function fakePanel(
  initial: BackendAddress[] = [],
  opts: { createFails?: boolean; deleteFails?: boolean; deleteIgnored?: boolean } = {},
) {
  const hosts = [...initial];
  let minted = 0;
  const stub = mockFetch((c) => {
    if (new URL(c.url).hostname !== 'panel.example') throw new Error(`unexpected ${c.url}`);
    if (c.path === '/api/hosts' && c.method === 'GET') return jsonRes({ response: hosts });
    if (c.path === '/api/hosts' && c.method === 'POST') {
      if (opts.createFails) return jsonRes({ message: 'boom' }, 500);
      const b = c.body as {
        remark: string;
        address: string;
        port: number;
        sni?: string;
        host?: string;
        inbound: BackendAddress['inbound'];
      };
      const uuid = `cccccccc-cccc-4ccc-8ccc-${String(++minted).padStart(12, '0')}`;
      hosts.push({
        uuid,
        remark: b.remark,
        address: b.address,
        port: b.port,
        sni: b.sni ?? null,
        host: b.host ?? null,
        inbound: b.inbound,
      });
      return jsonRes({ response: { uuid } });
    }
    const del = c.path.match(/^\/api\/hosts\/([^/]+)$/);
    if (del && c.method === 'DELETE') {
      if (opts.deleteFails) return jsonRes({ message: 'boom' }, 500);
      const i = hosts.findIndex((h) => h.uuid === del[1]);
      if (i < 0) return jsonRes({ message: 'not found' }, 404);
      if (!opts.deleteIgnored) hosts.splice(i, 1);
      return new Response(null, { status: 204 });
    }
    return jsonRes({ message: 'not found' }, 404);
  });
  const calls = () => stub.calls.map((c) => `${c.method} ${c.path}`);
  return { stub, hosts, calls };
}

async function seed() {
  const t = convexTest(schema, modules);
  return seedEdgeFixture(t, { listeners: [realityListener()] });
}

async function listener(t: ReturnType<typeof convexTest>, id: Id<'relayListeners'>) {
  return (await t.run((ctx) => ctx.db.get(id)))!;
}

async function auditActions(t: ReturnType<typeof convexTest>) {
  return (await t.run((ctx) => ctx.db.query('auditLog').collect())).map((a) => a.action);
}

describe('hostOps: create', () => {
  test('claimCreate persists the full intent and the op BEFORE any call; a second claim is refused while the op is unsettled', async () => {
    vi.useFakeTimers({ now: NOW });
    const { t, listenerId, serverId } = await seed();
    const claim = await t.mutation(internal.hostOps.claimCreate, { listenerId, target: TARGET });
    expect(claim.claimed).toBe(true);
    if (!claim.claimed) throw new Error('unreachable');
    expect(claim.backendServerId).toBe(serverId);
    expect(claim.intended).toEqual({
      remark: REMARK,
      address: EDGE,
      port: 443,
      sni: 'a.example',
      host: null,
      inboundUuid: FIXTURE_INBOUND,
    });
    const l = await listener(t, listenerId);
    expect(l.host).toMatchObject({
      state: 'creating',
      ownership: 'fcp',
      intended: claim.intended,
      op: {
        kind: 'create',
        opId: claim.opId,
        claimedAt: NOW,
        expiresAt: NOW + 60_000,
        attempts: 1,
      },
    });
    // Unsettled (not yet expired): refused, naming the op.
    expect(await t.mutation(internal.hostOps.claimCreate, { listenerId, target: TARGET })).toEqual({
      claimed: false,
      state: 'unresolved',
      opId: claim.opId,
    });
    // Expired but still unsettled: STILL refused (nothing writes until it is re-observed).
    vi.setSystemTime(NOW + 10 * 60_000);
    expect(await t.mutation(internal.hostOps.claimCreate, { listenerId, target: TARGET })).toEqual({
      claimed: false,
      state: 'unresolved',
      opId: claim.opId,
    });
  });

  test('settleCreated → present / fcp, op cleared, audited; a stale opId is ignored', async () => {
    const { t, listenerId } = await seed();
    const claim = await t.mutation(internal.hostOps.claimCreate, { listenerId, target: TARGET });
    if (!claim.claimed) throw new Error('unreachable');
    expect(
      await t.mutation(internal.hostOps.settleCreated, { listenerId, opId: 'other', uuid: 'x' }),
    ).toEqual({ ok: false });
    expect(
      await t.mutation(internal.hostOps.settleCreated, {
        listenerId,
        opId: claim.opId,
        uuid: HOST_UUID,
      }),
    ).toEqual({ ok: true });
    const l = await listener(t, listenerId);
    expect(l.host).toMatchObject({ state: 'present', uuid: HOST_UUID, ownership: 'fcp' });
    expect(l.host!.op).toBeUndefined();
    expect(l.host!.intended).toBeDefined();
    expect(await auditActions(t)).toContain('relay.host.created');
    // A present Host is not re-created.
    expect(await t.mutation(internal.hostOps.claimCreate, { listenerId, target: TARGET })).toEqual({
      claimed: false,
      state: 'present',
      uuid: HOST_UUID,
    });
  });

  test('markUnresolved parks the listener but KEEPS the op (fenced by opId)', async () => {
    const { t, listenerId } = await seed();
    const claim = await t.mutation(internal.hostOps.claimCreate, { listenerId, target: TARGET });
    if (!claim.claimed) throw new Error('unreachable');
    await t.mutation(internal.hostOps.markUnresolved, { listenerId, opId: 'other' });
    expect((await listener(t, listenerId)).host!.state).toBe('creating');
    await t.mutation(internal.hostOps.markUnresolved, { listenerId, opId: claim.opId });
    const l = await listener(t, listenerId);
    expect(l.host).toMatchObject({ state: 'unresolved', op: { opId: claim.opId, kind: 'create' } });
    expect(l.host!.intended).toBeDefined();
  });

  test('claimCreate refuses an origin whose Hosts FCP does not own, and a listener without a backend Host', async () => {
    const { t, relayId, listenerId } = await seed();
    await t.run((ctx) => ctx.db.patch(relayId, { hostMode: 'operator' }));
    await expect(
      t.mutation(internal.hostOps.claimCreate, { listenerId, target: TARGET }),
    ).rejects.toThrow(/host_mode_unsupported/);
    await t.run((ctx) => ctx.db.patch(relayId, { hostMode: 'fcp' }));
    await t.run((ctx) => ctx.db.patch(listenerId, { matchRule: { kind: 'address' } }));
    await expect(
      t.mutation(internal.hostOps.claimCreate, { listenerId, target: TARGET }),
    ).rejects.toThrow(/host_not_applicable/);
  });
});

describe('hostOps: applyDiscovery after an uncertain create', () => {
  async function unresolvedCreate(
    t: ReturnType<typeof convexTest>,
    listenerId: Id<'relayListeners'>,
  ) {
    const claim = await t.mutation(internal.hostOps.claimCreate, { listenerId, target: TARGET });
    if (!claim.claimed) throw new Error('unreachable');
    await t.mutation(internal.hostOps.markUnresolved, { listenerId, opId: claim.opId });
    return claim.opId;
  }

  test('exactly one Host matching remark AND transport AND address:port settles the create as present', async () => {
    const { t, listenerId } = await seed();
    const opId = await unresolvedCreate(t, listenerId);
    const r = await t.mutation(internal.hostOps.applyDiscovery, {
      listenerId,
      opId,
      hosts: [
        // Same remark, another transport: the role's Host for a different listener, not ours.
        seen(
          panelHost({
            uuid: 'other-inbound',
            inbound: {
              configProfileUuid: 'p',
              configProfileInboundUuid: '99999999-9999-4999-8999-999999999999',
            },
          }),
        ),
        // Same remark + transport, another port: not the intended tuple.
        seen(panelHost({ uuid: 'other-port', port: 8443 })),
        // Same remark + transport, another address: not ours either.
        seen(panelHost({ uuid: 'other-address', address: '198.51.100.99' })),
        seen(panelHost()),
      ],
    });
    expect(r).toEqual({ state: 'present' });
    const l = await listener(t, listenerId);
    expect(l.host).toMatchObject({ state: 'present', uuid: HOST_UUID, ownership: 'fcp' });
    expect(l.host!.op).toBeUndefined();
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.find((a) => a.action === 'relay.host.created')?.payload).toMatchObject({
      relaySlug: 'node-one',
      listenerKey: 'a',
      discovered: true,
    });
  });

  test('a remark-only match is never enough: one intended Host among remark twins is still exactly one', async () => {
    const { t, listenerId } = await seed();
    const opId = await unresolvedCreate(t, listenerId);
    const r = await t.mutation(internal.hostOps.applyDiscovery, {
      listenerId,
      opId,
      hosts: [seen(panelHost({ uuid: 'twin', inbound: null })), seen(panelHost())],
    });
    expect(r).toEqual({ state: 'present' });
    expect((await listener(t, listenerId)).host!.uuid).toBe(HOST_UUID);
  });

  test('several matching Hosts → ambiguous (needs the operator); a create is then refused', async () => {
    const { t, listenerId } = await seed();
    const opId = await unresolvedCreate(t, listenerId);
    const r = await t.mutation(internal.hostOps.applyDiscovery, {
      listenerId,
      opId,
      hosts: [seen(panelHost()), seen(panelHost({ uuid: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' }))],
    });
    expect(r).toEqual({ state: 'ambiguous' });
    const l = await listener(t, listenerId);
    expect(l.host!.state).toBe('ambiguous');
    expect(l.host!.op).toBeUndefined();
    expect(await t.mutation(internal.hostOps.claimCreate, { listenerId, target: TARGET })).toEqual({
      claimed: false,
      state: 'ambiguous',
    });
  });

  test('an empty listing right after the claim never authorises a retry: unresolved until the settle floor AND two quiet looks', async () => {
    vi.useFakeTimers({ now: NOW });
    const { t, listenerId } = await seed();
    const opId = await unresolvedCreate(t, listenerId);
    // Look 1, right away: quiet, nothing else.
    expect(
      await t.mutation(internal.hostOps.applyDiscovery, { listenerId, opId, hosts: [] }),
    ).toEqual({
      state: 'unresolved',
    });
    let l = await listener(t, listenerId);
    expect(l.host).toMatchObject({ state: 'unresolved', op: { opId, lastLookAt: NOW } });
    expect(l.host!.intended).toBeDefined();
    // Look 2, still inside the floor: two looks are not enough on their own.
    vi.setSystemTime(NOW + 30_000);
    expect(
      await t.mutation(internal.hostOps.applyDiscovery, { listenerId, opId, hosts: [] }),
    ).toEqual({
      state: 'unresolved',
    });
    expect((await listener(t, listenerId)).host!.op?.opId).toBe(opId);
    // A create is refused throughout.
    expect(await t.mutation(internal.hostOps.claimCreate, { listenerId, target: TARGET })).toEqual({
      claimed: false,
      state: 'unresolved',
      opId,
    });
    // Past the floor AND a second look: absent, op and intent cleared.
    vi.setSystemTime(NOW + 2 * 60_000 + 1);
    expect(
      await t.mutation(internal.hostOps.applyDiscovery, { listenerId, opId, hosts: [] }),
    ).toEqual({
      state: 'absent',
    });
    l = await listener(t, listenerId);
    expect(l.host).toEqual({ state: 'absent' });
    // Now a create may run again.
    const again = await t.mutation(internal.hostOps.claimCreate, { listenerId, target: TARGET });
    expect(again.claimed).toBe(true);
  });

  test('the floor alone is not enough either: the FIRST look past it is still a quiet look', async () => {
    vi.useFakeTimers({ now: NOW });
    const { t, listenerId } = await seed();
    const opId = await unresolvedCreate(t, listenerId);
    vi.setSystemTime(NOW + 10 * 60_000);
    expect(
      await t.mutation(internal.hostOps.applyDiscovery, { listenerId, opId, hosts: [] }),
    ).toEqual({
      state: 'unresolved',
    });
    expect(
      await t.mutation(internal.hostOps.applyDiscovery, { listenerId, opId, hosts: [] }),
    ).toEqual({
      state: 'absent',
    });
  });

  test('a look for a stale opId changes nothing', async () => {
    const { t, listenerId } = await seed();
    await unresolvedCreate(t, listenerId);
    const r = await t.mutation(internal.hostOps.applyDiscovery, {
      listenerId,
      opId: 'stale',
      hosts: [seen(panelHost())],
    });
    expect(r).toEqual({ state: 'unresolved' });
    expect((await listener(t, listenerId)).host!.state).toBe('unresolved');
  });
});

describe('hostOps: delete', () => {
  async function presentHost(
    t: ReturnType<typeof convexTest>,
    listenerId: Id<'relayListeners'>,
    ownership: 'fcp' | 'adopted' = 'fcp',
  ) {
    await t.run((ctx) =>
      ctx.db.patch(listenerId, {
        host: {
          state: 'present',
          uuid: HOST_UUID,
          ownership,
          intended: {
            remark: REMARK,
            address: EDGE,
            port: 443,
            sni: 'a.example',
            host: null,
            inboundUuid: FIXTURE_INBOUND,
          },
        },
        updatedAt: Date.now(),
      }),
    );
  }

  test('a delete is confirmed ONLY by a read-back in which the uuid is gone; finding it keeps the op', async () => {
    const { t, listenerId } = await seed();
    await presentHost(t, listenerId);
    const claim = await t.mutation(internal.hostOps.claimDelete, { listenerId });
    expect(claim.claimed).toBe(true);
    if (!claim.claimed) throw new Error('unreachable');
    expect(claim.uuid).toBe(HOST_UUID);
    expect((await listener(t, listenerId)).host).toMatchObject({
      state: 'deleting',
      op: { kind: 'delete', opId: claim.opId },
    });
    // The Host is still there (a DELETE that 2xx'd but has not landed, or a lost call).
    expect(
      await t.mutation(internal.hostOps.applyDiscovery, {
        listenerId,
        opId: claim.opId,
        hosts: [seen(panelHost())],
      }),
    ).toEqual({ state: 'present' });
    let l = await listener(t, listenerId);
    expect(l.host).toMatchObject({ state: 'present', uuid: HOST_UUID, op: { opId: claim.opId } });
    expect(await auditActions(t)).not.toContain('relay.host.deleted');
    // Gone from the read-back: absent, everything cleared, audited.
    expect(
      await t.mutation(internal.hostOps.applyDiscovery, {
        listenerId,
        opId: claim.opId,
        hosts: [seen(panelHost({ uuid: 'unrelated', remark: 'node-one-relay-z' }))],
      }),
    ).toEqual({ state: 'absent' });
    l = await listener(t, listenerId);
    expect(l.host).toEqual({ state: 'absent' });
    expect(await auditActions(t)).toContain('relay.host.deleted');
  });

  test('an ADOPTED Host is released, never deleted', async () => {
    const { t, listenerId } = await seed();
    await presentHost(t, listenerId, 'adopted');
    const claim = await t.mutation(internal.hostOps.claimDelete, { listenerId });
    expect(claim).toEqual({ claimed: false, state: 'absent' });
    expect((await listener(t, listenerId)).host).toEqual({ state: 'absent' });
    const actions = await auditActions(t);
    expect(actions).toContain('relay.host.released');
    expect(actions).not.toContain('relay.host.deleted');
    // Through the action: no backend call at all.
    const world = fakePanel([panelHost()]);
    await presentHost(t, listenerId, 'adopted');
    expect(await t.action(internal.hostOps.deleteListenerHost, { listenerId })).toEqual({
      state: 'absent',
    });
    expect(world.calls()).toEqual([]);
    expect(world.hosts).toHaveLength(1);
  });

  test('claimDelete is a no-op for an absent Host and refused while a create is unsettled', async () => {
    const { t, listenerId } = await seed();
    expect(await t.mutation(internal.hostOps.claimDelete, { listenerId })).toEqual({
      claimed: false,
      state: 'absent',
    });
    const claim = await t.mutation(internal.hostOps.claimCreate, { listenerId, target: TARGET });
    if (!claim.claimed) throw new Error('unreachable');
    await t.mutation(internal.hostOps.markUnresolved, { listenerId, opId: claim.opId });
    expect(await t.mutation(internal.hostOps.claimDelete, { listenerId })).toEqual({
      claimed: false,
      state: 'unresolved',
    });
  });
});

describe('hostOps: the actions against a backend', () => {
  test('ensureListenerHost creates the Host through POST /api/hosts with the persisted intent, then answers present only after seeing it on the backend', async () => {
    const world = fakePanel();
    const { t, listenerId } = await seed();
    const r = await t.action(internal.hostOps.ensureListenerHost, { listenerId, target: TARGET });
    expect(r.state).toBe('present');
    expect(r.uuid).toBeDefined();
    expect(world.calls()).toEqual(['POST /api/hosts']);
    const post = world.stub.calls[0].body as Record<string, unknown>;
    expect(post).toMatchObject({
      remark: REMARK,
      address: EDGE,
      port: 443,
      sni: 'a.example',
      // null = clear, sent as '' (the backend's string-typed DTO).
      host: '',
      isDisabled: false,
      inbound: {
        configProfileUuid: '11111111-1111-4111-8111-111111111111',
        configProfileInboundUuid: FIXTURE_INBOUND,
      },
    });
    expect(world.hosts).toHaveLength(1);
    expect((await listener(t, listenerId)).host).toMatchObject({
      state: 'present',
      uuid: r.uuid,
      ownership: 'fcp',
    });
    const again = await t.action(internal.hostOps.ensureListenerHost, {
      listenerId,
      target: TARGET,
    });
    expect(again).toEqual({ state: 'present', uuid: r.uuid });
    // Verified against the live listing (a read), never re-created.
    expect(world.calls()).toEqual(['POST /api/hosts', 'GET /api/hosts']);
  });

  test('a Host the ledger calls present but the backend lost is re-created, not reported present from the database', async () => {
    const world = fakePanel();
    const { t, listenerId } = await seed();
    const first = await t.action(internal.hostOps.ensureListenerHost, {
      listenerId,
      target: TARGET,
    });
    expect(first.state).toBe('present');
    // Deleted out of band on the backend.
    world.hosts.length = 0;
    const again = await t.action(internal.hostOps.ensureListenerHost, {
      listenerId,
      target: TARGET,
    });
    expect(again.state).toBe('present');
    expect(again.uuid).toBeDefined();
    expect(world.hosts).toHaveLength(1);
    expect(world.calls()).toEqual(['POST /api/hosts', 'GET /api/hosts', 'POST /api/hosts']);
    const audits = await t.run(async (ctx) =>
      (await ctx.db.query('auditLog').collect()).map((a) => a.action),
    );
    expect(audits).toContain('relay.host.lost');
  });

  test('a lost uuid with exactly one Host on the listener remark and transport takes its place; several park it ambiguous', async () => {
    const world = fakePanel();
    const { t, listenerId } = await seed();
    await t.action(internal.hostOps.ensureListenerHost, { listenerId, target: TARGET });
    // Re-created out of band under a new uuid.
    world.hosts.length = 0;
    world.hosts.push(panelHost());
    const one = await t.action(internal.hostOps.ensureListenerHost, { listenerId, target: TARGET });
    expect(one).toEqual({ state: 'present', uuid: HOST_UUID });
    expect(world.calls().filter((c) => c === 'POST /api/hosts')).toHaveLength(1);
    // Now two candidates and the known uuid gone: nobody guesses.
    world.hosts.length = 0;
    world.hosts.push(
      { ...panelHost(), uuid: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' },
      { ...panelHost(), uuid: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' },
    );
    const many = await t.action(internal.hostOps.ensureListenerHost, {
      listenerId,
      target: TARGET,
    });
    expect(many.state).toBe('ambiguous');
    expect(world.calls().filter((c) => c === 'POST /api/hosts')).toHaveLength(1);
  });

  test('a failed POST parks the listener unresolved; the next ensure RE-OBSERVES (never re-creates) and adopts what the backend did create', async () => {
    const world = fakePanel([], { createFails: true });
    const { t, listenerId } = await seed();
    const r = await t.action(internal.hostOps.ensureListenerHost, { listenerId, target: TARGET });
    expect(r.state).toBe('unresolved');
    expect((await listener(t, listenerId)).host).toMatchObject({
      state: 'unresolved',
      op: { kind: 'create' },
    });
    // The backend actually created it before answering 500.
    world.hosts.push(panelHost());
    const r2 = await t.action(internal.hostOps.ensureListenerHost, { listenerId, target: TARGET });
    expect(r2).toEqual({ state: 'present', uuid: HOST_UUID });
    expect(world.calls()).toEqual(['POST /api/hosts', 'GET /api/hosts']);
    expect((await listener(t, listenerId)).host).toMatchObject({
      state: 'present',
      uuid: HOST_UUID,
      ownership: 'fcp',
    });
  });

  test('a failed POST followed by an empty listing stays unresolved: no second POST', async () => {
    const world = fakePanel([], { createFails: true });
    const { t, listenerId } = await seed();
    await t.action(internal.hostOps.ensureListenerHost, { listenerId, target: TARGET });
    const r2 = await t.action(internal.hostOps.ensureListenerHost, { listenerId, target: TARGET });
    expect(r2.state).toBe('unresolved');
    const r3 = await t.action(internal.hostOps.ensureListenerHost, { listenerId, target: TARGET });
    expect(r3.state).toBe('unresolved');
    expect(world.calls()).toEqual(['POST /api/hosts', 'GET /api/hosts', 'GET /api/hosts']);
  });

  test('deleteListenerHost: DELETE then a read-back; only the read-back decides', async () => {
    const { t, listenerId } = await seed();
    const present = () =>
      t.run((ctx) =>
        ctx.db.patch(listenerId, {
          host: { state: 'present', uuid: HOST_UUID, ownership: 'fcp' },
          updatedAt: Date.now(),
        }),
      );
    // The DELETE lands: gone on read-back → absent.
    let world = fakePanel([panelHost()]);
    await present();
    expect(await t.action(internal.hostOps.deleteListenerHost, { listenerId })).toEqual({
      state: 'absent',
    });
    expect(world.calls()).toEqual([`DELETE /api/hosts/${HOST_UUID}`, 'GET /api/hosts']);
    expect((await listener(t, listenerId)).host).toEqual({ state: 'absent' });
    // The DELETE 2xx'd but the backend still lists it: present, op kept, not confirmed.
    world = fakePanel([panelHost()], { deleteIgnored: true });
    await present();
    expect(await t.action(internal.hostOps.deleteListenerHost, { listenerId })).toEqual({
      state: 'present',
    });
    const l = await listener(t, listenerId);
    expect(l.host).toMatchObject({ state: 'present', uuid: HOST_UUID, op: { kind: 'delete' } });
    // The DELETE throws: still decided by the read-back (here: still there).
    world = fakePanel([panelHost()], { deleteFails: true });
    await present();
    expect(await t.action(internal.hostOps.deleteListenerHost, { listenerId })).toEqual({
      state: 'present',
    });
    expect(world.calls()).toEqual([`DELETE /api/hosts/${HOST_UUID}`, 'GET /api/hosts']);
  });
});

describe('hostOps: pendingListeners + reconcileHosts', () => {
  test('nothing pending: an empty list, a no-op pass, no backend call', async () => {
    const world = fakePanel();
    const { t } = await seed();
    expect(await t.query(internal.hostOps.pendingListeners, {})).toEqual([]);
    expect(await t.action(internal.hostOps.reconcileHosts, {})).toEqual({ looked: 0, deleted: 0 });
    expect(world.calls()).toEqual([]);
  });

  test('an EXPIRED unresolved create gets a discovery look; a live one and a present live Host do not', async () => {
    vi.useFakeTimers({ now: NOW });
    const world = fakePanel([panelHost()]);
    const { t, listenerId, serverId } = await seed();
    const claim = await t.mutation(internal.hostOps.claimCreate, { listenerId, target: TARGET });
    if (!claim.claimed) throw new Error('unreachable');
    await t.mutation(internal.hostOps.markUnresolved, { listenerId, opId: claim.opId });
    // Not expired yet: nothing pending.
    expect(await t.query(internal.hostOps.pendingListeners, {})).toEqual([]);
    vi.setSystemTime(NOW + 61_000);
    expect(await t.query(internal.hostOps.pendingListeners, {})).toEqual([
      { kind: 'discover', listenerId, opId: claim.opId, backendServerId: serverId },
    ]);
    expect(await t.action(internal.hostOps.reconcileHosts, {})).toEqual({ looked: 1, deleted: 0 });
    expect(world.calls()).toEqual(['GET /api/hosts']);
    // The look found the Host: present, and nothing is pending any more.
    expect((await listener(t, listenerId)).host).toMatchObject({
      state: 'present',
      uuid: HOST_UUID,
    });
    expect(await t.query(internal.hostOps.pendingListeners, {})).toEqual([]);
  });

  test('a RETIRED listener with an FCP-owned present Host is deleted, confirmed only by read-back', async () => {
    const world = fakePanel([panelHost()], { deleteIgnored: true });
    const { t, listenerId } = await seed();
    await t.run((ctx) =>
      ctx.db.patch(listenerId, {
        host: { state: 'present', uuid: HOST_UUID, ownership: 'fcp' },
        retired: true,
        deployed: false,
        updatedAt: Date.now(),
      }),
    );
    expect(await t.query(internal.hostOps.pendingListeners, {})).toEqual([
      { kind: 'delete', listenerId },
    ]);
    // Pass 1: the DELETE is accepted but the backend still lists the Host: not deleted.
    expect(await t.action(internal.hostOps.reconcileHosts, {})).toEqual({ looked: 0, deleted: 0 });
    expect(world.calls()).toEqual([`DELETE /api/hosts/${HOST_UUID}`, 'GET /api/hosts']);
    expect((await listener(t, listenerId)).host).toMatchObject({
      state: 'present',
      op: { kind: 'delete' },
    });
    // Pass 2: the backend lets go: gone on read-back → absent, counted.
    world.hosts.splice(0, 1);
    expect(await t.action(internal.hostOps.reconcileHosts, {})).toEqual({ looked: 0, deleted: 1 });
    expect((await listener(t, listenerId)).host).toEqual({ state: 'absent' });
    expect(await t.query(internal.hostOps.pendingListeners, {})).toEqual([]);
  });

  test('a deleting origin has its FCP Hosts removed; an operator-managed origin is never touched; an adopted Host is released', async () => {
    const world = fakePanel([panelHost()]);
    const { t, relayId, listenerId } = await seed();
    await t.run((ctx) =>
      ctx.db.patch(listenerId, {
        host: { state: 'present', uuid: HOST_UUID, ownership: 'fcp' },
        updatedAt: Date.now(),
      }),
    );
    // Operator-managed: FCP does not own the Hosts, so nothing is pending.
    await t.run((ctx) => ctx.db.patch(relayId, { hostMode: 'operator' }));
    expect(await t.query(internal.hostOps.pendingListeners, {})).toEqual([]);
    // The origin is being deleted: its FCP Host goes.
    await t.run((ctx) => ctx.db.patch(relayId, { hostMode: 'fcp', deleting: true }));
    expect(await t.query(internal.hostOps.pendingListeners, {})).toEqual([
      { kind: 'delete', listenerId },
    ]);
    expect(await t.action(internal.hostOps.reconcileHosts, {})).toEqual({ looked: 0, deleted: 1 });
    expect(world.hosts).toEqual([]);
    // An adopted Host on a deleting origin: released, no DELETE.
    world.hosts.push(panelHost());
    await t.run((ctx) =>
      ctx.db.patch(listenerId, {
        host: { state: 'present', uuid: HOST_UUID, ownership: 'adopted' },
        updatedAt: Date.now(),
      }),
    );
    expect(await t.query(internal.hostOps.pendingListeners, {})).toEqual([]);
    const before = world.calls().length;
    await t.action(internal.hostOps.reconcileHosts, {});
    expect(world.calls().length).toBe(before);
    expect(world.hosts).toHaveLength(1);
  });
});
