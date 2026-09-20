/// <reference types="vite/client" />
/**
 * Server-name rollouts and acceptance receipts.
 *
 *  - a rollout writes the backend through the operations ledger and hands members
 *    NOTHING: the backend listing a name is not a node accepting it;
 *  - a receipt (an operator's authenticated session with a test link) is the
 *    only thing that activates a name, and only on the node that proved it;
 *  - a WITNESS (a name this transport never listed) proves the whole generation
 *    on that node; a name that was listed before proves only itself;
 *  - a receipt is void after an expiry, a newer generation, a profile that
 *    moved, or a change to the edge's endpoint confirmation, and needs a
 *    verified edge to begin with;
 *  - names an origin still hands out, or that are still draining, stay on the
 *    backend whatever the family says;
 *  - activating proven names does not stale the endpoint confirmation.
 *
 * Fixtures use RFC 5737 addresses and `*.example` names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import {
  FIXTURE_CONFIG_PROFILE as PROFILE,
  FIXTURE_INBOUND as INBOUND,
  adoptL4Edge,
  insertPanelServer,
  markBackendSetUp,
  realityListener,
  registerRelay,
} from './lib/edges/testing/fixtures';
import { verificationCurrent } from './lib/edges/verification';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;
const TAG = 'VLESS_RELAY_A';

beforeEach(() => {
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

interface Panel {
  names: string[];
  node: { lastStatusChange: string };
  patches: number;
  /** Profile reads answer 500 from the next PATCH on, until cleared (the run's own look fails). */
  failReadsAfterPatch: boolean;
  failReads: boolean;
}

function installPanel(): Panel {
  const panel: Panel = {
    names: ['a.example', 'b.example'],
    node: { lastStatusChange: 't0' },
    patches: 0,
    failReadsAfterPatch: false,
    failReads: false,
  };
  const config = () => ({
    inbounds: [
      {
        tag: TAG,
        port: 443,
        protocol: 'vless',
        settings: { clients: [], decryption: 'none' },
        streamSettings: {
          network: 'tcp',
          security: 'reality',
          realitySettings: {
            target: 'target.example:443',
            serverNames: panel.names,
            privateKey: 'PRIVATE_KEY_VALUE',
            shortIds: ['deadbeef00112233'],
          },
        },
      },
    ],
  });
  const json = (o: unknown) =>
    new Response(JSON.stringify({ response: o }), {
      headers: { 'content-type': 'application/json' },
    });
  const profile = () => ({
    uuid: PROFILE,
    name: 'Default',
    config: config(),
    inbounds: [{ uuid: INBOUND, tag: TAG }],
  });
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL, init: RequestInit = {}) => {
      const path = new URL(typeof input === 'string' ? input : input.toString()).pathname;
      if ((init.method ?? 'GET').toUpperCase() === 'PATCH') {
        const body = JSON.parse(init.body as string);
        panel.names = body.config.inbounds[0].streamSettings.realitySettings.serverNames;
        panel.patches++;
        if (panel.failReadsAfterPatch) panel.failReads = true;
        return json({});
      }
      if (panel.failReads && path.startsWith('/api/config-profiles'))
        return new Response('', { status: 500 });
      if (path === '/api/nodes')
        return json([
          {
            uuid: 'n-1',
            name: 'node-one',
            isConnected: true,
            isDisabled: false,
            lastStatusChange: panel.node.lastStatusChange,
            configProfile: {
              activeConfigProfileUuid: PROFILE,
              activeInbounds: [{ uuid: INBOUND, tag: TAG }],
            },
          },
        ]);
      if (path === '/api/hosts') return json([]);
      if (path === '/api/internal-squads') return json({ internalSquads: [] });
      if (path === '/api/config-profiles') return json({ configProfiles: [profile()] });
      if (path === `/api/config-profiles/${PROFILE}`) return json(profile());
      return json({});
    }),
  );
  return panel;
}

async function seed(familyNames = ['fresh-1.example', 'fresh-2.example']) {
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
  const panel = installPanel();
  await t.action(internal.backendObserve.refresh, { backendServerId: serverId });
  await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': true } });
  await markBackendSetUp(t, serverId);
  await t.mutation(internal.sniFamilies.patchConfig, { patch: { enabled: true } });
  const { relayId, listenerIds } = await registerRelay(t, { listeners: [realityListener()] });
  const listenerId = listenerIds.a as Id<'relayListeners'>;
  const { edgeId } = await adoptL4Edge(t, relayId, listenerId, { publish: true });
  await t.mutation(internal.sniFamilies.create, {
    slug: 'fam',
    label: 'Fam',
    targetAddress: 'target.example',
    targetPort: 443,
  });
  await t.mutation(internal.sniFamilies.importNames, { slug: 'fam', lines: familyNames });
  // Qualified against the target.
  for (const n of (await t.query(internal.sniFamilies.dueForQualification, {})).names)
    await t.mutation(internal.sniFamilies.recordQualification, {
      id: n.id,
      ok: true,
      tlsVersion: 'TLSv1.3',
    });
  const { id } = await t.mutation(internal.sniFamilies.bind, {
    slug: 'fam',
    backendSlug: 'panel-a',
    inboundTag: TAG,
  });
  return {
    t,
    panel,
    serverId,
    relayId,
    listenerId,
    edgeId: edgeId as Id<'edges'>,
    bindingId: id as Id<'sniInboundBindings'>,
  };
}

const activeNames = async (t: T, listenerId: Id<'relayListeners'>) =>
  ((await t.run((ctx) => ctx.db.get(listenerId)))!.tlsNames ?? [])
    .filter((n) => n.status === 'active')
    .map((n) => n.name);

/** Issue a receipt without building the link (the link builder has its own suite). */
async function receipt(t: T, rolloutId: Id<'sniRollouts'>, edgeId: Id<'edges'>, sni?: string) {
  const c = await t.query(internal.sniRollouts.receiptContext, { rolloutId, edgeId, sni });
  const receiptId = await t.mutation(internal.sniRollouts.recordReceipt, {
    rolloutId,
    generation: c.generation,
    relayId: c.relayId,
    listenerId: c.listenerId,
    edgeId,
    sni: c.sni,
    isWitness: c.isWitness,
    expectedToken: c.expectedToken,
    endpoint: c.binding.endpoint,
    listenerRevision: c.binding.listenerRevision,
    configHash: c.binding.configHash,
  });
  return { receiptId, ...c };
}

describe('rollout', () => {
  test('the plan keeps what an origin hands out, adds the qualified family names, and finds a witness', async () => {
    const { t, bindingId } = await seed();
    const p = await t.query(internal.sniRollouts.plan, { bindingId });
    expect(p).toMatchObject({
      generation: 1,
      names: ['a.example', 'b.example', 'fresh-1.example', 'fresh-2.example'],
      added: ['fresh-1.example', 'fresh-2.example'],
      removed: [],
      witness: 'fresh-1.example',
      changed: true,
    });
  });

  test('the backend is written, and members are handed NOTHING', async () => {
    const { t, panel, bindingId, listenerId } = await seed();
    const out = await t.action(internal.sniRollouts.start, { bindingId });
    expect(out).toMatchObject({ phase: 'panel_confirmed', added: 2, removed: 0 });
    expect(panel.patches).toBe(1);
    expect(panel.names).toEqual(['a.example', 'b.example', 'fresh-1.example', 'fresh-2.example']);
    // The backend lists them. No node has proven anything: the origin hands out what it did before.
    expect(await activeNames(t, listenerId)).toEqual(['a.example', 'b.example']);
    const status = await t.query(internal.sniRollouts.status, { rolloutId: out.rolloutId! });
    // Only the family's usable names are counted: a.example and b.example were
    // on the transport before the family and no receipt can activate them.
    expect(status.nodes).toMatchObject([
      { relaySlug: 'node-one', listenerKey: 'a', proven: 0, pending: 2, generationProven: false },
    ]);
    // The live addresses a test link can be built through, by name and state only.
    expect(status.nodes[0]!.edges).toMatchObject([{ status: 'active' }]);
    expect(Object.keys(status.nodes[0]!.edges[0]!).sort()).toEqual(['id', 'name', 'status']);
    // Rolling out again with nothing new is a no-op: no write, no node work.
    expect((await t.action(internal.sniRollouts.start, { bindingId })).phase).toBe(
      'nothing_to_change',
    );
    expect(panel.patches).toBe(1);
  });

  test("the rollout follows the ledger from a LATER look when the run's own read-back failed", async () => {
    const { t, panel, bindingId } = await seed();
    panel.failReadsAfterPatch = true;
    const out = await t.action(internal.sniRollouts.start, { bindingId });
    // The PATCH landed; the look right after it could not read the profile.
    expect(out).toMatchObject({ phase: 'writing', added: 2 });
    expect(panel.patches).toBe(1);
    const before = await t.query(internal.sniRollouts.status, { rolloutId: out.rolloutId! });
    expect(before.phase).toBe('writing');
    await expect(
      t.query(internal.sniRollouts.receiptContext, {
        rolloutId: out.rolloutId!,
        edgeId: (await t.run((ctx) => ctx.db.query('edges').first()))!._id,
      }),
    ).rejects.toThrow(/rollout_not_confirmed/);
    // The backend is readable again; the scheduled reconcile settles the op...
    panel.failReads = false;
    panel.node.lastStatusChange = 't1';
    await t.action(internal.backendWrites.reconcile, {});
    // ...and the rollout followed it, without anyone starting it again.
    const after = await t.query(internal.sniRollouts.status, { rolloutId: out.rolloutId! });
    expect(after.phase).toBe('panel_confirmed');
    expect((await t.run((ctx) => ctx.db.get(bindingId)))!.panelConfirmedGeneration).toBe(1);
    expect(panel.patches).toBe(1);
  });

  test('a name an origin still hands out, or that is still draining, stays on the backend', async () => {
    const { t, panel, bindingId, listenerId } = await seed();
    await t.action(internal.sniRollouts.start, { bindingId });
    // b.example is retired on the origin but still inside its drain.
    panel.node.lastStatusChange = 't1';
    await t.action(internal.backendWrites.reconcile, {});
    await t.mutation(internal.relayListeners.retireName, { id: listenerId, names: ['b.example'] });
    const p = await t.query(internal.sniRollouts.plan, { bindingId });
    expect(p.names).toContain('b.example');
    expect(p.removed).toEqual([]);
    // Once the drain is over nothing holds it any more, and the next rollout drops it.
    await t.run(async (ctx) => {
      const l = (await ctx.db.get(listenerId))!;
      await ctx.db.patch(listenerId, {
        tlsNames: l.tlsNames!.map((n) =>
          n.name === 'b.example' ? { ...n, drainUntil: Date.now() - 1 } : n,
        ),
      });
    });
    expect((await t.query(internal.sniRollouts.plan, { bindingId })).removed).toEqual([
      'b.example',
    ]);
  });
});

describe('acceptance', () => {
  test('a WITNESS receipt proves the generation on that node: every new name reaches its members', async () => {
    const { t, bindingId, listenerId, edgeId, relayId } = await seed();
    const { rolloutId } = await t.action(internal.sniRollouts.start, { bindingId });
    const epoch0 = (await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch;
    const rc = await receipt(t, rolloutId!, edgeId);
    expect(rc).toMatchObject({ sni: 'fresh-1.example', isWitness: true });
    const out = await t.mutation(internal.sniRollouts.confirmReceipt, { receiptId: rc.receiptId });
    expect(out).toEqual({ ok: true, activated: 2, witness: true });
    expect(await activeNames(t, listenerId)).toEqual([
      'a.example',
      'b.example',
      'fresh-1.example',
      'fresh-2.example',
    ]);
    const l = (await t.run((ctx) => ctx.db.get(listenerId)))!;
    // A growing list gets the growth-stable selection; the renders move on...
    expect(l.sniPick).toBe('hrw1');
    expect((await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch).toBe(epoch0 + 1);
    // ...and the operator's endpoint confirmation still stands: acceptance was PROVEN.
    expect(l.revision).toBe(1);
    const edge = (await t.run((ctx) => ctx.db.get(edgeId)))!;
    expect(verificationCurrent(edge as never, l as never)).toBe(true);
    // The same link cannot be used twice.
    await expect(
      t.mutation(internal.sniRollouts.confirmReceipt, { receiptId: rc.receiptId }),
    ).rejects.toThrow(/already used/);
  });

  test('moving a listener onto the growth-stable selection is an epoch bump and an audited change, even with nothing new to activate', async () => {
    const { t, bindingId, listenerId, edgeId, relayId } = await seed();
    const { rolloutId } = await t.action(internal.sniRollouts.start, { bindingId });
    const epoch0 = (await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch;
    expect((await t.run((ctx) => ctx.db.get(listenerId)))!.sniPick).toBeUndefined();
    // a.example is already active on the listener: the receipt activates nothing...
    const rc = await receipt(t, rolloutId!, edgeId, 'a.example');
    const out = await t.mutation(internal.sniRollouts.confirmReceipt, { receiptId: rc.receiptId });
    expect(out).toEqual({ ok: true, activated: 0, witness: false });
    // ...yet every member's name selection changed, so the renders must move on
    // and the change must be on the record, as `setSniPick` would write it.
    expect((await t.run((ctx) => ctx.db.get(listenerId)))!.sniPick).toBe('hrw1');
    expect((await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch).toBe(epoch0 + 1);
    const audits = (await t.run((ctx) => ctx.db.query('auditLog').collect())).filter(
      (a) => a.action === 'relay.listener.sni_pick',
    );
    expect(audits.map((a) => a.payload)).toEqual([
      { relaySlug: 'node-one', listenerKey: 'a', version: 'hrw1' },
    ]);
    // A second receipt on the same listener changes the selection no further.
    const rc2 = await receipt(t, rolloutId!, edgeId, 'b.example');
    await t.mutation(internal.sniRollouts.confirmReceipt, { receiptId: rc2.receiptId });
    expect((await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch).toBe(epoch0 + 1);
  });

  test('a name the transport listed BEFORE proves only itself', async () => {
    // old-seen.example was on the transport when the family was bound.
    const t0 = convexTest(schema, modules);
    void t0;
    const { t, panel, bindingId, listenerId, edgeId } = await seed([
      'a.example',
      'returning.example',
    ]);
    // Make "returning.example" a name with history: it was listed once, then dropped.
    await t.run(async (ctx) => {
      const b = (await ctx.db.get(bindingId))!;
      await ctx.db.insert('sniInboundNameHistory', {
        backendServerId: b.backendServerId,
        inboundUuid: b.inboundUuid,
        name: 'returning.example',
        firstSeenGeneration: 0,
      });
    });
    void panel;
    const { rolloutId } = await t.action(internal.sniRollouts.start, { bindingId });
    const rc = await receipt(t, rolloutId!, edgeId);
    // No witness: a node stuck on an older config might accept this name too.
    expect(rc).toMatchObject({ sni: 'returning.example', isWitness: false });
    const out = await t.mutation(internal.sniRollouts.confirmReceipt, { receiptId: rc.receiptId });
    expect(out).toMatchObject({ activated: 1, witness: false });
    expect(await activeNames(t, listenerId)).toEqual([
      'a.example',
      'b.example',
      'returning.example',
    ]);
  });

  test('an unverified edge cannot carry a proof', async () => {
    const { t, bindingId, relayId, listenerId } = await seed();
    const { rolloutId } = await t.action(internal.sniRollouts.start, { bindingId });
    const { edgeId: untested } = await adoptL4Edge(t, relayId, listenerId, {
      ipv4: '198.51.100.9',
      verified: false,
    });
    await expect(
      t.query(internal.sniRollouts.receiptContext, {
        rolloutId: rolloutId!,
        edgeId: untested as Id<'edges'>,
      }),
    ).rejects.toThrow(/unverified_endpoint/);
  });

  test('a receipt is void after an expiry, a newer generation, a moved profile, or a changed endpoint', async () => {
    const { t, bindingId, edgeId, listenerId } = await seed();
    const { rolloutId } = await t.action(internal.sniRollouts.start, { bindingId });
    const confirm = (receiptId: Id<'sniAcceptanceReceipts'>) =>
      t.mutation(internal.sniRollouts.confirmReceipt, { receiptId });

    const expired = await receipt(t, rolloutId!, edgeId);
    await t.run((ctx) => ctx.db.patch(expired.receiptId, { expiresAt: Date.now() - 1 }));
    await expect(confirm(expired.receiptId)).rejects.toThrow(/receipt_expired/);

    const moved = await receipt(t, rolloutId!, edgeId);
    const profile = (await t.run((ctx) => ctx.db.query('panelProfiles').collect()))[0];
    await t.run((ctx) => ctx.db.patch(profile._id, { changeToken: 'someone-else-wrote' }));
    await expect(confirm(moved.receiptId)).rejects.toThrow(/profile_moved/);
    await t.run((ctx) => ctx.db.patch(profile._id, { changeToken: moved.expectedToken }));

    const stale = await receipt(t, rolloutId!, edgeId);
    // The listener changed materially after the link was made: the endpoint needs a retest.
    await t.run(async (ctx) => {
      const l = (await ctx.db.get(listenerId))!;
      await ctx.db.patch(listenerId, { revision: l.revision + 1 });
    });
    await expect(confirm(stale.receiptId)).rejects.toThrow(/binding_changed/);
    // Nothing reached members through any of them.
    expect(await activeNames(t, listenerId)).toEqual(['a.example', 'b.example']);
  });

  test('a newer generation supersedes a waiting receipt', async () => {
    const { t, panel, bindingId, edgeId } = await seed();
    const first = await t.action(internal.sniRollouts.start, { bindingId });
    const rc = await receipt(t, first.rolloutId!, edgeId);
    panel.node.lastStatusChange = 't1';
    await t.action(internal.backendWrites.reconcile, {});
    await t.mutation(internal.sniFamilies.importNames, { slug: 'fam', lines: ['fresh-3.example'] });
    for (const n of (await t.query(internal.sniFamilies.dueForQualification, {})).names)
      await t.mutation(internal.sniFamilies.recordQualification, { id: n.id, ok: true });
    const second = await t.action(internal.sniRollouts.start, { bindingId });
    expect(second.phase).toBe('panel_confirmed');
    await expect(
      t.mutation(internal.sniRollouts.confirmReceipt, { receiptId: rc.receiptId }),
    ).rejects.toThrow(/superseded/);
    expect(
      (await t.query(internal.sniRollouts.status, { rolloutId: first.rolloutId! })).phase,
    ).toBe('superseded');
  });

  test('a name that stopped qualifying is not activated, even by a witness proof', async () => {
    const { t, bindingId, listenerId, edgeId } = await seed();
    const { rolloutId } = await t.action(internal.sniRollouts.start, { bindingId });
    await t.mutation(internal.sniFamilies.setNames, {
      slug: 'fam',
      names: ['fresh-2.example'],
      action: 'burn',
    });
    const rc = await receipt(t, rolloutId!, edgeId);
    await t.mutation(internal.sniRollouts.confirmReceipt, { receiptId: rc.receiptId });
    expect(await activeNames(t, listenerId)).toEqual(['a.example', 'b.example', 'fresh-1.example']);
  });
});
