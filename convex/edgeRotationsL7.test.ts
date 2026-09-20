// @vitest-environment node
/// <reference types="vite/client" />
/**
 * The rotation machine over an L7 (CDN) edge: provision → verify (with the
 * authenticated front qualification) → publish → Host flip, plus the rules that
 * only exist for that layer: the frozen intent, the automatic-selection gate
 * and the qualification binding.
 *
 * The node environment is required because the front qualification's action is
 * a `"use node"` module (it speaks TLS and HTTP/2); the session itself is
 * replaced by a stub, so nothing here opens a socket.
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { z } from 'zod';
import { jsonRes, mockFetch } from './lib/edges/testing/mockFetch';
import { __setEdgeProviderForTests } from './lib/edges/providers/registry';
import { __setFrontChecker } from './frontQualifyOps';
import type { EdgeProvider, EdgeSpec, Ledger, LedgerResource } from './lib/edges/providers/types';
import {
  FIXTURE_CONFIG_PROFILE,
  insertPanelServer,
  registerRelay,
  wsListener,
  type ListenerSpecFixture,
} from './lib/edges/testing/fixtures';

const modules = import.meta.glob('./**/*.*s');

const ORIGIN = 'node-one.origin.example';
const HOST_UUID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const INBOUND = '22222222-2222-4222-8222-222222222222';
const QUALIFY_UUID = '99999999-9999-4999-8999-999999999999';
const ZONE = 'example.org';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  __setEdgeProviderForTests('cloudflare', null);
  __setFrontChecker(null);
});

/**
 * A fake L7 adapter: one DNS record, then a hostname. It records what the
 * machine asked it for, which is what these tests are about; the vendor's own
 * wire format is pinned by its contract tests, not here.
 */
function fakeL7() {
  const seen: Array<{ call: string; hostname?: string; originPort?: number }> = [];
  let minted: string | null = null;
  const provider = {
    id: 'cloudflare',
    templateSchema: z.object({}).passthrough(),
    templateFields: [],
    defaultTemplate: {},
    testCredentials: async () => ({ ok: true }),
    planProvision: (_cfg: unknown, spec: EdgeSpec) => {
      seen.push({ call: 'plan', hostname: spec.hostname });
      return [
        {
          id: 'dns',
          kind: 'create_dns_record',
          resourceName: spec.name,
          discoverability: 'by_name',
        },
      ];
    },
    runStep: async (_cfg: unknown, _step: unknown, spec: EdgeSpec) => {
      seen.push({
        call: 'runStep',
        hostname: spec.hostname,
        originPort: spec.listeners[0]?.members[0]?.port,
      });
      minted = spec.hostname ?? null;
      return {
        status: 'done',
        resources: [{ kind: 'dns_record', resourceId: 'rec-1', ownership: 'created' }],
        addresses: { hostname: spec.hostname },
      };
    },
    discover: async () => ({ status: 'unresolved' }),
    describe: async (_cfg: unknown, ledger: Ledger) => {
      seen.push({ call: 'describe' });
      const present = ledger.resources.some(
        (r: LedgerResource) => r.deleteState !== 'confirmed_gone',
      );
      return {
        state: present && minted ? 'active' : 'pending',
        addresses: minted ? { hostname: minted } : {},
        health: 'unknown',
        readiness: { dns: 'ready', certificate: 'ready' },
      };
    },
    inspect: async () => ({ summary: { addresses: {}, members: [], listeners: [] }, raw: {} }),
    inventory: async () => ({ loadBalancers: [], ips: [], flavors: [] }),
    planDestroy: (_cfg: unknown, ledger: Ledger) =>
      ledger.resources.filter((r: LedgerResource) => r.deleteState !== 'confirmed_gone'),
    runDestroy: async () => ({ status: 'confirmed_gone' }),
  } as unknown as EdgeProvider;
  __setEdgeProviderForTests('cloudflare', provider);
  return { seen };
}

/** A backend that stores the full Host tuple, so the flip is observable. */
function fakePanel() {
  const hosts = [
    {
      uuid: HOST_UUID,
      remark: 'node-one-relay-w',
      address: '198.51.100.1',
      port: 443,
      sni: 'a.example',
      host: '',
      inbound: {
        configProfileUuid: FIXTURE_CONFIG_PROFILE,
        configProfileInboundUuid: INBOUND,
      },
    },
  ];
  mockFetch((c) => {
    if (c.path === '/api/hosts' && c.method === 'GET') return jsonRes({ response: hosts });
    if (c.path === '/api/hosts' && c.method === 'PATCH') {
      const b = c.body as {
        uuid: string;
        address: string;
        port: number;
        sni?: string;
        host?: string;
      };
      const h = hosts.find((x) => x.uuid === b.uuid);
      if (h) {
        h.address = b.address;
        h.port = b.port;
        if (b.sni !== undefined) h.sni = b.sni;
        if (b.host !== undefined) h.host = b.host;
      }
      return jsonRes({ response: h ?? null });
    }
    return jsonRes({ message: 'not found' }, 404);
  });
  return hosts;
}

const originTransport = {
  scheme: 'https' as const,
  certPublic: true,
  certNames: [ORIGIN],
  acceptsHostHeader: 'any' as const,
};

/** The VLESS-over-WebSocket listener `w` behind the HTTPS origin (remark `node-one-origin-w`). */
function listenerW(over: Partial<ListenerSpecFixture> = {}): ListenerSpecFixture {
  return wsListener({
    listenerKey: 'w',
    tlsNames: ['a.example'],
    originTransport,
    transportParams: { path: '/ws' },
    panelBinding: {
      inboundTag: 'VLESS_RELAY_W',
      configProfileUuid: FIXTURE_CONFIG_PROFILE,
      configProfileInboundUuid: INBOUND,
    },
    ...over,
  });
}

/** Register (or re-register) node-one with one listener body, the way the role does. */
async function register(t: ReturnType<typeof convexTest>, listeners: ListenerSpecFixture[]) {
  return registerRelay(t, { originAddress: ORIGIN, listeners });
}

async function seed(opts: { autoSelect?: boolean; zoneSslMode?: string } = {}) {
  const t = convexTest(schema, modules);
  await insertPanelServer(t);
  await t.run(async (ctx) => {
    for (const [key, value] of [
      ['edge.enabled', 'true'],
      ['edge.l7.autoSelect', opts.autoSelect ? 'true' : 'false'],
    ] as const) {
      await ctx.db.insert('appSettings', { key, value, updatedAt: Date.now() });
    }
  });
  const { id: accountId } = await t.mutation(internal.edgeProviderAccounts.create, {
    provider: 'cloudflare',
    name: 'acct-cf',
    settings: { zoneId: 'a'.repeat(32), zoneName: ZONE },
    credentials: { apiToken: 'cf' },
  });
  await t.mutation(internal.edgeProviderAccounts.setQualified, { id: accountId, qualified: true });
  // The zone's encryption mode is what the credential test OBSERVED; planning
  // refuses without it (`zone_mode_unknown`), never guesses one.
  await t.run((ctx) =>
    ctx.db.patch(accountId, {
      observedSettings: JSON.stringify({ zoneSslMode: opts.zoneSslMode ?? 'full' }),
      observedAt: Date.now(),
    }),
  );
  const { relayId, listenerId } = await register(t, [listenerW()]);
  // The credential the qualification session authenticates with.
  await t.run((ctx) => ctx.db.patch(relayId, { qualificationUserId: QUALIFY_UUID }));
  return { t, accountId, relayId, listenerId };
}

async function drain(t: ReturnType<typeof convexTest>, rotationId: Id<'edgeRotations'>) {
  for (let i = 0; i < 400; i++) {
    await vi.runAllTimersAsync();
    await t.finishInProgressScheduledFunctions();
    const r = await t.query(internal.edgeRotations.get, { id: rotationId });
    if (r && ['done', 'failed', 'rolled_back', 'quarantined', 'cancelled'].includes(r.phase)) {
      await vi.runAllTimersAsync();
      await t.finishInProgressScheduledFunctions();
      return;
    }
  }
  throw new Error('drain: the rotation did not settle');
}

/** An adopted, published L7 (or L4) front on the origin's listener. */
async function insertPublishedFront(
  t: ReturnType<typeof convexTest>,
  relayId: Id<'relays'>,
  listenerId: Id<'relayListeners'>,
  over: Record<string, unknown> = {},
) {
  return t.run((ctx) =>
    ctx.db.insert('edges', {
      relayId,
      listenerId,
      managed: false,
      name: 'adopted-x',
      steps: [],
      resources: [],
      listeners: [],
      addresses: { hostname: 'old.example.org' },
      layer: 'l7',
      publication: 'published',
      poolIndex: 0,
      status: 'active',
      statusChangedAt: Date.now(),
      health: 'unknown',
      destroyAttempts: 0,
      updatedAt: Date.now(),
      ...over,
    }),
  );
}

describe('edgeRotations: an L7 edge end to end', () => {
  test('provision → qualify → publish → flip writes the hostname into address, SNI and Host', async () => {
    vi.useFakeTimers();
    const adapter = fakeL7();
    const hosts = fakePanel();
    __setFrontChecker(async (args) => {
      // The session is handed the minted hostname and the listener's protocol
      // triple + transport parameters, never a guess.
      expect(args.proto).toEqual({ protocol: 'vless', streamTransport: 'ws', security: 'tls' });
      expect(args.params.path).toBe('/ws');
      expect(args.uuid).toBe(QUALIFY_UUID);
      return { ok: true, steps: [], checkedAt: Date.now() };
    });
    const { t, relayId, listenerId } = await seed();
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'provision',
      trigger: 'manual',
      listenerId,
      publishOnDone: true,
    });
    await drain(t, rotationId);

    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(r.phase).toBe('done');
    expect(r.outcome).toBe('published');
    const edge = (await t.query(internal.edges.get, { id: r.toEdgeId! }))!;
    expect(edge.layer).toBe('l7');
    expect(edge.listenerId).toBe(listenerId);
    expect(edge.addresses.hostname).toMatch(new RegExp(`^[a-z0-9]+\\.${ZONE}$`));
    expect(edge.addresses.v4).toBeUndefined();
    expect(edge.publication).toBe('published');
    expect(edge.poolIndex).toBe(0);
    // The proof is stored against exactly what was published: the hostname and
    // the listener's protocol / revision / transport parameters.
    expect(edge.frontQualification?.ok).toBe(true);
    expect(edge.frontQualification?.binding).toMatchObject({
      hostname: edge.addresses.hostname,
      listenerId,
      protocol: 'vless',
      streamTransport: 'ws',
      security: 'tls',
    });
    expect(edge.readiness).toMatchObject({ dns: 'ready', certificate: 'ready', front: 'ready' });
    // The flip wrote the WHOLE tuple: behind a CDN the hostname is the address,
    // the SNI and the Host header.
    expect(hosts[0]).toMatchObject({
      address: edge.addresses.hostname,
      port: 443,
      sni: edge.addresses.hostname,
      host: edge.addresses.hostname,
    });
    // The listener records the Host the plan found (adopted: the role made it)
    // and its template edge is the new front.
    const listener = (await t.run((ctx) => ctx.db.get(listenerId)))!;
    expect(listener.host).toMatchObject({
      state: 'present',
      uuid: HOST_UUID,
      ownership: 'adopted',
    });
    expect(listener.templateEdgeId).toBe(edge._id);
    // The adapter was driven with the hostname from the frozen intent.
    expect(adapter.seen.find((s) => s.call === 'runStep')?.hostname).toBe(edge.addresses.hostname);
    // What the node role reads: the hostname is the address, the SNI and the
    // Host header, and the listener's own names are not offered (they are never
    // sent behind a front).
    const view = (await t.query(internal.edgeAdmin.relayBySlugView, { slug: 'node-one' }))!;
    expect(view.relay).toMatchObject({ hostMode: 'fcp', delivery: 'edge-required' });
    expect(view.publishedEndpoints).toHaveLength(1);
    expect(view.publishedEndpoints[0]).toMatchObject({
      listenerKey: 'w',
      poolIndex: 0,
      layer: 'l7',
      port: 443,
      addresses: { hostname: edge.addresses.hostname },
      sni: edge.addresses.hostname,
      hostHeader: edge.addresses.hostname,
    });

    // An expired proof takes the endpoint OUT of the role-usable list: the role
    // keeps waiting instead of configuring a front nobody has passed through.
    await t.run((ctx) =>
      ctx.db.patch(edge._id, {
        frontQualification: { ...edge.frontQualification!, expiresAt: Date.now() - 1 },
      }),
    );
    const stale = (await t.query(internal.edgeAdmin.relayBySlugView, { slug: 'node-one' }))!;
    expect(stale.publishedEndpoints).toEqual([]);
  });

  test('an L7 edge whose front qualification FAILS is never published', async () => {
    vi.useFakeTimers();
    fakeL7();
    fakePanel();
    __setFrontChecker(async () => ({
      // A CDN error page instead of the transport: not a front, whatever DNS says.
      ok: false,
      code: 'front_error',
      steps: [],
      checkedAt: Date.now(),
    }));
    const { t, relayId, listenerId } = await seed();
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'provision',
      trigger: 'manual',
      listenerId,
      publishOnDone: true,
    });
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(r.phase).toBe('failed');
    expect(r.outcome).toBe('front_unqualified');
    const origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.publishedEdgeIds).toEqual([]);
  });

  test('the intent is FROZEN: the account may move mid-rotation and the edge does not', async () => {
    vi.useFakeTimers();
    const adapter = fakeL7();
    fakePanel();
    __setFrontChecker(async () => ({ ok: true, steps: [], checkedAt: Date.now() }));
    const { t, accountId, relayId, listenerId } = await seed();
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'provision',
      trigger: 'manual',
      listenerId,
      publishOnDone: false,
    });
    // One step: enough to plan and freeze the intent.
    await t.action(internal.edgeRotations.step, { rotationId });
    const planned = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    const frozen = JSON.parse(
      (await t.query(internal.edges.get, { id: planned.toEdgeId! }))!.provisionIntent!,
    ) as { hostname: string; zoneId: string; zoneName: string };
    expect(frozen.zoneName).toBe(ZONE);
    // The operator repoints the account at another zone while the run is in
    // flight. Nothing about this edge may follow: its records live in the old one.
    await t.run((ctx) =>
      ctx.db.patch(accountId, {
        settings: { type: 'cloudflare', zoneId: 'b'.repeat(32), zoneName: 'moved.example' },
        updatedAt: Date.now(),
      }),
    );
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(r.phase).toBe('done');
    const edge = (await t.query(internal.edges.get, { id: r.toEdgeId! }))!;
    expect(edge.addresses.hostname).toBe(frozen.hostname);
    expect(JSON.parse(edge.provisionIntent!).zoneName).toBe(ZONE);
    // Every provider call after the edit still used the frozen hostname.
    expect(
      adapter.seen
        .filter((s) => s.hostname !== undefined)
        .every((s) => s.hostname === frozen.hostname),
    ).toBe(true);
  });

  test('a stale binding is not a qualification: a listener re-registration expires the proof', async () => {
    vi.useFakeTimers();
    fakeL7();
    fakePanel();
    __setFrontChecker(async () => ({ ok: true, steps: [], checkedAt: Date.now() }));
    const { t, relayId, listenerId } = await seed();
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'provision',
      trigger: 'manual',
      listenerId,
      publishOnDone: false,
    });
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    const edgeId = r.toEdgeId!;
    const before = (await t.run((ctx) => ctx.db.get(listenerId)))!.revision;
    expect((await t.query(internal.edges.get, { id: edgeId }))!.frontQualification?.ok).toBe(true);
    // The node role redeploys the transport on a different path: what the proof
    // exercised is no longer what a member would speak. (Not a rebind: the
    // standby may stay bound; the listener's revision moves.)
    const reg = await register(t, [listenerW({ transportParams: { path: '/other' } })]);
    expect(reg.changed).toBe(true);
    expect((await t.run((ctx) => ctx.db.get(listenerId)))!.revision).toBeGreaterThan(before);
    // No Host flip is owed on an operator-managed origin, so the direct publish
    // reaches the publishability check, which refuses the stale proof.
    await t.mutation(internal.relays.update, { id: relayId, hostMode: 'operator' });
    await expect(t.mutation(internal.relays.publishEdge, { relayId, edgeId })).rejects.toThrow(
      /front_qualification_stale/,
    );
  });
});

describe('edgeRotations: the L7 automatic-selection gate', () => {
  test('a detector replacement for an L7-only listener is vetoed while the gate is off', async () => {
    fakeL7();
    fakePanel();
    __setFrontChecker(async () => ({ ok: true, steps: [], checkedAt: Date.now() }));
    const { t, relayId } = await seed();
    // A plaintext origin makes the listener L7-only: an L4 forwarder cannot add
    // the TLS the front terminated, so there is no L4 fallback to route to.
    // (Port + transport change = a rebind; nothing is bound to `w` yet.)
    const { listenerId } = await register(t, [
      listenerW({
        originPort: 80,
        tlsNames: [],
        originTransport: {
          scheme: 'http',
          certPublic: false,
          certNames: [],
          acceptsHostHeader: 'any',
        },
      }),
    ]);
    const edgeId = await insertPublishedFront(t, relayId, listenerId);
    await t.run((ctx) => ctx.db.patch(relayId, { publishedEdgeIds: [edgeId], autoRotate: true }));
    await t.run(async (ctx) => {
      const row = await ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.eq('key', 'edge.autoRotate'))
        .unique();
      if (!row)
        await ctx.db.insert('appSettings', {
          key: 'edge.autoRotate',
          value: 'true',
          updatedAt: Date.now(),
        });
    });
    await expect(
      t.mutation(internal.edgeRotations.start, {
        relayId,
        kind: 'replace',
        trigger: 'detector',
        targetEdgeId: edgeId,
      }),
    ).rejects.toThrow(/l7_auto_select_disabled/);
    // An operator's own request is never gated by it.
    await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: edgeId,
    });
  });

  test('the daily bound stops repeated same-provider L7 replacements', async () => {
    fakeL7();
    fakePanel();
    const { t, relayId, listenerId } = await seed({ autoSelect: true });
    const edgeId = await insertPublishedFront(t, relayId, listenerId);
    const today = new Date().toISOString().slice(0, 10);
    await t.run((ctx) =>
      ctx.db.patch(relayId, {
        publishedEdgeIds: [edgeId],
        autoRotate: true,
        // The default bound is two per origin per day.
        l7ReplacementsDayKey: today,
        l7ReplacementsToday: 2,
      }),
    );
    await t.run(async (ctx) => {
      await ctx.db.insert('appSettings', {
        key: 'edge.autoRotate',
        value: 'true',
        updatedAt: Date.now(),
      });
    });
    await expect(
      t.mutation(internal.edgeRotations.start, {
        relayId,
        kind: 'replace',
        trigger: 'detector',
        targetEdgeId: edgeId,
      }),
    ).rejects.toThrow(/l7_replacement_cap/);
    // `force` is the operator's override, as everywhere else.
    await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'detector',
      targetEdgeId: edgeId,
      force: true,
    });
  });

  /** A published L7 (or L4) front on the origin, as the detector's target. */
  async function publishedFront(
    t: ReturnType<typeof convexTest>,
    relayId: Id<'relays'>,
    listenerId: Id<'relayListeners'>,
    over: Record<string, unknown> = {},
  ) {
    const edgeId = await insertPublishedFront(t, relayId, listenerId, {
      provider: 'cloudflare',
      name: 'adopted-old',
      listeners: [{ edgePort: 443, originAddress: ORIGIN, originPort: 443 }],
      ...over,
    });
    await t.run(async (ctx) => {
      await ctx.db.patch(relayId, { publishedEdgeIds: [edgeId], autoRotate: true });
      await ctx.db.insert('appSettings', {
        key: 'edge.autoRotate',
        value: 'true',
        updatedAt: Date.now(),
      });
    });
    return edgeId;
  }

  test('a SUCCESSFUL same-provider L7 replacement counts against the daily bound too', async () => {
    vi.useFakeTimers();
    fakeL7();
    fakePanel();
    __setFrontChecker(async () => ({ ok: true, steps: [], checkedAt: Date.now() }));
    const { t, relayId, listenerId } = await seed({ autoSelect: true });
    const oldEdge = await publishedFront(t, relayId, listenerId);
    // The affected-country evidence is waived here (audited); everything else
    // about the replacement is the ordinary detector path.
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'detector',
      targetEdgeId: oldEdge,
      forceGeoEvidence: true,
    });
    await drain(t, rotationId);
    const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect([r.phase, r.outcome]).toEqual(['done', 'published']);
    const to = (await t.query(internal.edges.get, { id: r.toEdgeId! }))!;
    expect(to.provider).toBe('cloudflare');
    // A new hostname on the SAME CDN is not a new frontend address, so the
    // successful replacement is bounded exactly like a blocked one.
    const origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.l7ReplacementsToday).toBe(1);
    expect(origin.l7ReplacementsDayKey).toBe(new Date().toISOString().slice(0, 10));
    vi.useRealTimers();
  });

  test('a replacement that CHANGED layer, or one the operator asked for, is not counted', async () => {
    vi.useFakeTimers();
    fakeL7();
    fakePanel();
    __setFrontChecker(async () => ({ ok: true, steps: [], checkedAt: Date.now() }));
    const { t, relayId, listenerId } = await seed({ autoSelect: true });
    // An L4 forwarder replaced by a front IS a new frontend address.
    const oldEdge = await publishedFront(t, relayId, listenerId, {
      layer: 'l4',
      addresses: { v4: '198.51.100.9' },
      provider: undefined,
    });
    const first = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'detector',
      targetEdgeId: oldEdge,
      forceGeoEvidence: true,
    });
    await drain(t, first.rotationId);
    expect((await t.query(internal.edgeRotations.get, { id: first.rotationId }))!.phase).toBe(
      'done',
    );
    let origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.l7ReplacementsToday ?? 0).toBe(0);
    // And an operator's own rotation is never rationed.
    await t.run((ctx) => ctx.db.patch(relayId, { cooldownUntil: undefined, rotationsToday: 0 }));
    const second = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      targetEdgeId: origin.publishedEdgeIds[0]!,
    });
    await drain(t, second.rotationId);
    expect((await t.query(internal.edgeRotations.get, { id: second.rotationId }))!.phase).toBe(
      'done',
    );
    origin = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(origin.l7ReplacementsToday ?? 0).toBe(0);
    vi.useRealTimers();
  });
});

describe('edgeRotations: affected-country evidence must be FRESH', () => {
  /** The stored per-country verdicts, with the freshness the gate reads. */
  test('a verdict older than the freshness window reports `stale`, never its old value', async () => {
    const { t, relayId, listenerId } = await seed();
    const edgeId = await insertPublishedFront(t, relayId, listenerId, {
      publication: 'unpublished',
      poolIndex: undefined,
    });
    const weeksAgo = Date.now() - 21 * 24 * 60 * 60_000;
    await t.run((ctx) =>
      ctx.db.patch(edgeId, {
        reachability: {
          byCountry: [
            {
              country: 'IR',
              verdict: 'reachable',
              okVantages: 3,
              failVantages: 0,
              lastAt: weeksAgo,
            },
            {
              country: 'RU',
              verdict: 'reachable',
              okVantages: 3,
              failVantages: 0,
              lastAt: Date.now(),
            },
          ],
          updatedAt: weeksAgo,
        },
      }),
    );
    const verdicts = await t.query(internal.edgeRotations.edgeReachability, {
      edgeId,
      countries: ['IR', 'RU', 'CN'],
    });
    expect(verdicts).toEqual([
      { country: 'IR', verdict: 'stale', lastAt: weeksAgo },
      { country: 'RU', verdict: 'reachable', lastAt: expect.any(Number) },
      { country: 'CN', verdict: 'absent', lastAt: null },
    ]);
  });

  test('a detector replacement never passes on a stale `reachable`; a fresh one lets it through', async () => {
    // Drive the same run twice: once with the new hostname's only evidence
    // weeks old, once fresh. Nothing but the freshness differs.
    for (const fresh of [false, true]) {
      vi.useFakeTimers();
      fakeL7();
      fakePanel();
      __setFrontChecker(async () => ({ ok: true, steps: [], checkedAt: Date.now() }));
      const { t, relayId, listenerId } = await seed({ autoSelect: true });
      await t.run(async (ctx) => {
        for (const [key, value] of [
          ['edge.autoRotate', 'true'],
          ['edge.probe.enabled', 'true'],
          // Short enough that the gate's wait is observable step by step.
          ['edge.pollSeconds', '5'],
          ['edge.l7.qualifyTimeoutMinutes', '2'],
        ] as const) {
          await ctx.db.insert('appSettings', { key, value, updatedAt: Date.now() });
        }
      });
      const oldEdge = await insertPublishedFront(t, relayId, listenerId, {
        name: 'adopted-old',
        listeners: [{ edgePort: 443, originAddress: ORIGIN, originPort: 443 }],
      });
      await t.run((ctx) =>
        ctx.db.patch(relayId, {
          publishedEdgeIds: [oldEdge],
          autoRotate: true,
          suspicion: {
            state: 'suspected',
            hintLevel: 'probes',
            score: 1,
            reportScore: 0,
            loadScore: 0,
            probeScore: 1,
            scope: 'regional',
            countries: [{ code: 'IR', count: 3 }],
            edgeEvidence: [{ edgeId: oldEdge, source: 'probes', countries: ['IR'] }],
            firstSeenAt: Date.now(),
            lastEvalAt: Date.now(),
            quietEvals: 0,
            baselineWarm: true,
            veto: null,
          },
        }),
      );
      const { rotationId } = await t.mutation(internal.edgeRotations.start, {
        relayId,
        kind: 'replace',
        trigger: 'detector',
        targetEdgeId: oldEdge,
      });
      // As soon as the run has minted its new edge, give that hostname the only
      // country verdict it will ever have: `reachable`, but measured weeks ago
      // in the first pass and just now in the second.
      const stamped = new Set<string>();
      for (let i = 0; i < 300; i++) {
        // Step the clock rather than draining every timer at once: the stamp
        // below has to land WHILE the run is waiting on the gate.
        await vi.advanceTimersByTimeAsync(2_000);
        await t.finishInProgressScheduledFunctions();
        const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
        const newEdge = r.toEdgeId ?? r.createdEdgeId ?? null;
        if (newEdge && !stamped.has(newEdge as string)) {
          stamped.add(newEdge as string);
          const at = fresh ? Date.now() : Date.now() - 21 * 24 * 60 * 60_000;
          await t.run((ctx) =>
            ctx.db.patch(newEdge, {
              reachability: {
                byCountry: [
                  {
                    country: 'IR',
                    verdict: 'reachable',
                    okVantages: 3,
                    failVantages: 0,
                    lastAt: at,
                  },
                ],
                updatedAt: at,
              },
            }),
          );
        }
        if (['done', 'failed', 'rolled_back', 'quarantined', 'cancelled'].includes(r.phase)) break;
      }
      const r = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
      const origin = (await t.query(internal.relays.get, { id: relayId }))!;
      // The verdict really was stamped on the NEW hostname: without this the
      // assertions below would hold for a run that simply never measured it.
      expect(stamped.size).toBe(1);
      if (fresh) {
        expect([r.phase, r.outcome]).toEqual(['done', 'published']);
        expect(origin.publishedEdgeIds[0]).toBe(r.toEdgeId);
      } else {
        // The gate never accepted the stale verdict, so the replacement did not
        // reach members; it asked for a fresh round instead.
        expect(r.phase).not.toBe('done');
        expect(origin.publishedEdgeIds[0]).toBe(oldEdge);
        const runs = await t.run((ctx) => ctx.db.query('probeRuns').collect());
        expect(runs.some((x) => x.targetRef === (r.toEdgeId as string))).toBe(true);
      }
      vi.useRealTimers();
    }
  }, 20_000);
});

describe('edgeReconcile: a published front whose proof failed is re-proven soon', () => {
  test('the failed proof expires within a few poll intervals and the next tick re-runs the session', async () => {
    fakeL7();
    fakePanel();
    let sessions = 0;
    __setFrontChecker(async () => {
      sessions++;
      return { ok: false, code: 'front_error', steps: [], checkedAt: Date.now() };
    });
    const { t, accountId, relayId, listenerId } = await seed();
    const edgeId = await t.run((ctx) =>
      ctx.db.insert('edges', {
        relayId,
        listenerId,
        accountId,
        provider: 'cloudflare',
        managed: true,
        name: 'fcp-relay-node-one-1',
        steps: [],
        resources: [
          {
            stepId: 'dns',
            kind: 'dns_record',
            resourceId: 'rec-1',
            ownership: 'created' as const,
            deleteState: 'present' as const,
          },
        ],
        listeners: [{ edgePort: 443, originAddress: ORIGIN, originPort: 443 }],
        addresses: { hostname: `front.${ZONE}` },
        layer: 'l7',
        provisionIntent: JSON.stringify({
          hostname: `front.${ZONE}`,
          zoneId: 'a'.repeat(32),
          zoneName: ZONE,
          originTransport,
          originPort: 443,
          zoneSslMode: 'full',
          templateHash: 'h1',
          templateParams: {},
        }),
        publication: 'published',
        poolIndex: 0,
        status: 'active',
        statusChangedAt: Date.now(),
        health: 'unknown',
        destroyAttempts: 0,
        updatedAt: Date.now(),
      }),
    );
    await t.run((ctx) => ctx.db.patch(relayId, { publishedEdgeIds: [edgeId] }));
    await t.action(internal.edgeReconcile.run, {});
    expect(sessions).toBe(1);
    const edge = (await t.run((ctx) => ctx.db.get(edgeId)))!;
    expect(edge.frontQualification!.ok).toBe(false);
    // A few poll intervals, not a whole qualification TTL: the very next tick
    // past that point re-runs the session instead of leaving the pool carrying
    // an unverified front for an hour.
    const q = edge.frontQualification!;
    expect(q.expiresAt - q.checkedAt).toBeLessThanOrEqual(60 * 60_000);
    await t.run((ctx) =>
      ctx.db.patch(edgeId, { lastHealthAt: 0, frontQualification: { ...q, expiresAt: 1 } }),
    );
    await t.action(internal.edgeReconcile.run, {});
    expect(sessions).toBe(2);
  });
});
