/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { parseMaintenance } from './lib/edges/maintenance';
import { realityListener, registerRelay, seedEdgeFixture } from './lib/edges/testing/fixtures';
import { wipeAllowedIn } from './seedEdgesReset';

const modules = import.meta.glob('./**/*.*s');

const ORIGINAL_ENV = process.env.ENVIRONMENT;
afterEach(() => {
  if (ORIGINAL_ENV === undefined) delete process.env.ENVIRONMENT;
  else process.env.ENVIRONMENT = ORIGINAL_ENV;
});

async function seed() {
  const t = convexTest(schema, modules);
  const { accountId, relayId, listenerId } = await seedEdgeFixture(t);
  return { t, accountId, relayId, listenerId };
}

describe('edge maintenance gate', () => {
  test('parseMaintenance tolerates garbage and clamps the reason', () => {
    expect(parseMaintenance(undefined)).toEqual({ frozen: false, since: null, reason: null });
    expect(parseMaintenance('{not json')).toEqual({ frozen: false, since: null, reason: null });
    const long = 'x'.repeat(500);
    expect(parseMaintenance(JSON.stringify({ frozen: true, since: 5, reason: long }))).toEqual({
      frozen: true,
      since: 5,
      reason: 'x'.repeat(200),
    });
  });

  test('freeze refuses every admission entry point and audits once', async () => {
    const { t, relayId, listenerId } = await seed();
    const { edgeId } = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      listenerId,
      ipv4: '198.51.100.7',
    });
    const before = await t.mutation(internal.edgeMaintenance.freeze, { reason: 'reset drain' });
    expect(before.frozen).toBe(true);
    // Idempotent: a second freeze does not re-audit.
    await t.mutation(internal.edgeMaintenance.freeze, {});
    const audits = await t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .collect()
        .then((rows) => rows.filter((r) => r.action === 'admin.edge.maintenance')),
    );
    expect(audits).toHaveLength(1);
    expect(audits[0]?.payload).toEqual({ frozen: true, reason: 'reset drain' });

    const refused = /edge\.maintenance|maintenance/;
    await expect(
      t.mutation(internal.edgeRotations.start, {
        relayId,
        kind: 'provision',
        trigger: 'manual',
      }),
    ).rejects.toThrow(refused);
    await expect(
      registerRelay(t, { slug: 'node-two', nodeName: 'node-two', originAddress: '203.0.113.11' }),
    ).rejects.toThrow(refused);
    await expect(
      t.mutation(internal.relays.create, {
        slug: 'node-three',
        origin: { kind: 'manual' },
        originAddress: '203.0.113.12',
      }),
    ).rejects.toThrow(refused);
    await expect(
      t.mutation(internal.relayListeners.upsert, {
        relayId,
        spec: realityListener({
          listenerKey: 'b',
          originPort: 8443,
          panelBinding: {
            inboundTag: 'VLESS_RELAY_B',
            configProfileUuid: '11111111-1111-4111-8111-111111111111',
            configProfileInboundUuid: '33333333-3333-4333-8333-333333333333',
          },
        }),
      }),
    ).rejects.toThrow(refused);
    await expect(
      t.mutation(internal.relays.adoptEdge, { relayId, listenerId, ipv4: '198.51.100.8' }),
    ).rejects.toThrow(refused);
    await expect(t.mutation(internal.relays.publishEdge, { relayId, edgeId })).rejects.toThrow(
      refused,
    );
    await expect(
      t.mutation(internal.edgeProviderAccounts.create, {
        provider: 'gcore',
        name: 'acct-b',
        settings: { projectId: 1, regionId: 2 },
        credentials: { apiKey: 'k2' },
      }),
    ).rejects.toThrow(refused);
    await expect(
      t.mutation(internal.edgeTemplates.create, {
        provider: 'gcore',
        name: 'tpl',
        params: {},
      }),
    ).rejects.toThrow(refused);
    await expect(
      t.mutation(internal.probes.requestMany, { targets: [{ kind: 'relay', ref: relayId }] }),
    ).rejects.toThrow(refused);
  });

  test('freeze still admits completion paths: unpublish, relay delete, thaw', async () => {
    const { t, relayId, listenerId } = await seed();
    const { edgeId } = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      listenerId,
      ipv4: '198.51.100.7',
      publish: true,
    });
    await t.mutation(internal.edgeMaintenance.freeze, {});
    await t.mutation(internal.relays.unpublishEdge, { relayId, edgeId });
    const del = await t.mutation(internal.relays.requestDelete, {
      id: relayId,
      force: true,
      disposition: 'restore-direct',
    });
    expect(del.ok).toBe(true);
    const fin = await t.mutation(internal.relays.finalizeDelete, { id: relayId });
    expect(fin.removed).toBe(true);
    const thawed = await t.mutation(internal.edgeMaintenance.thaw, {});
    expect(thawed.frozen).toBe(false);
    // Admission works again.
    const again = await registerRelay(t);
    expect(again.created).toBe(true);
  });
});

describe('seedEdgesReset', () => {
  test('wipeAllowedIn is an allowlist', () => {
    expect(wipeAllowedIn('development')).toBe(true);
    expect(wipeAllowedIn('beta')).toBe(true);
    expect(wipeAllowedIn('production')).toBe(false);
    expect(wipeAllowedIn('Beta')).toBe(false);
    expect(wipeAllowedIn(undefined)).toBe(false);
    expect(wipeAllowedIn('')).toBe(false);
  });

  test('status reports every blocker and empties once the drain is done', async () => {
    const { t, relayId, listenerId } = await seed();
    // An observe-only edge holds nothing at a provider and never blocks.
    await t.mutation(internal.relays.adoptEdge, { relayId, listenerId, ipv4: '198.51.100.7' });
    await t.run(async (ctx) => {
      await ctx.db.patch(relayId, {
        qualificationUserId: 'q-user',
        qualificationRemovalPending: ['old-user'],
      });
    });
    const s1 = await t.query(internal.seedEdgesReset.status, {});
    expect(s1.frozen).toBe(false);
    expect(s1.blockers.join('\n')).toMatch(/not frozen/);
    expect(s1.blockers.join('\n')).toMatch(/credential still active.*node-one/);
    expect(s1.blockers.join('\n')).toMatch(/removal still owed.*node-one/);
    expect(s1.edgesOpen).toEqual([]);

    await t.mutation(internal.edgeMaintenance.freeze, {});
    await t.run(async (ctx) => {
      await ctx.db.patch(relayId, {
        qualificationUserId: undefined,
        qualificationRemovalPending: [],
      });
    });
    const s2 = await t.query(internal.seedEdgesReset.status, {});
    expect(s2.blockers).toEqual([]);
  });

  test('wipe refuses a wrong confirm, a non-allowlisted environment and open blockers', async () => {
    const { t } = await seed();
    process.env.ENVIRONMENT = 'beta';
    await expect(t.action(internal.seedEdgesReset.wipe, { confirm: 'nope' })).rejects.toThrow(
      /confirm/,
    );
    process.env.ENVIRONMENT = 'production';
    await expect(t.action(internal.seedEdgesReset.wipe, { confirm: 'wipe-edges' })).rejects.toThrow(
      /allowed only/,
    );
    delete process.env.ENVIRONMENT;
    await expect(t.action(internal.seedEdgesReset.wipe, { confirm: 'wipe-edges' })).rejects.toThrow(
      /allowed only/,
    );
    process.env.ENVIRONMENT = 'beta';
    // Not frozen yet -> blocked.
    await expect(t.action(internal.seedEdgesReset.wipe, { confirm: 'wipe-edges' })).rejects.toThrow(
      /not safe to wipe.*not frozen/,
    );
    const rows = await t.run((ctx) => ctx.db.query('relays').collect());
    expect(rows).toHaveLength(1);
  });

  test('wipe deletes the edge tables, keeps operator data and turns the switches off', async () => {
    const { t, relayId, listenerId, accountId } = await seed();
    await t.mutation(internal.relays.adoptEdge, { relayId, listenerId, ipv4: '198.51.100.7' });
    await t.mutation(internal.edgeTemplates.ensureDefaults, {});
    await t.mutation(internal.probeTargets.create, {
      label: 'custom',
      address: '198.51.100.99',
      port: 443,
    });
    await t.run(async (ctx) => {
      await ctx.db.insert('probeReachability', {
        targetKind: 'relay',
        targetRef: relayId,
        country: 'IR',
        source: 'internal',
        okCount: 1,
        failCount: 0,
        verdict: 'reachable',
        updatedAt: Date.now(),
      });
      await ctx.db.insert('probeReachability', {
        targetKind: 'custom',
        targetRef: 'custom-1',
        country: 'IR',
        source: 'internal',
        okCount: 1,
        failCount: 0,
        verdict: 'reachable',
        updatedAt: Date.now(),
      });
      for (const key of ['edge.enabled', 'edge.render.enabled'])
        await ctx.db.insert('appSettings', { key, value: 'true', updatedAt: Date.now() });
    });
    await t.mutation(internal.edgeMaintenance.freeze, {});
    process.env.ENVIRONMENT = 'development';
    const r = await t.action(internal.seedEdgesReset.wipe, { confirm: 'wipe-edges' });
    expect(r.deleted.relays).toBe(1);
    expect(r.deleted.edges).toBe(1);
    expect(r.deleted.relayListeners).toBe(1);
    expect(r.deleted.edgeDeliveryBindings).toBe(1);
    expect(r.deleted.probeReachability).toBe(1);
    expect(Object.keys(r.deleted).sort()).toEqual(
      [
        'edgeRotations',
        'edges',
        'relayListeners',
        'relays',
        'edgeDeliveryBindings',
        'externalLocks',
        'relaySamples',
        'probeRuns',
        'probeReachability',
      ].sort(),
    );
    const after = await t.run(async (ctx) => ({
      relays: await ctx.db.query('relays').collect(),
      edges: await ctx.db.query('edges').collect(),
      listeners: await ctx.db.query('relayListeners').collect(),
      bindings: await ctx.db.query('edgeDeliveryBindings').collect(),
      accounts: await ctx.db.query('edgeProviderAccounts').collect(),
      templates: await ctx.db.query('edgeTemplates').collect(),
      probeTargets: await ctx.db.query('probeTargets').collect(),
      reach: await ctx.db.query('probeReachability').collect(),
      settings: await ctx.db.query('appSettings').collect(),
      audits: (await ctx.db.query('auditLog').collect()).map((a) => a.action),
    }));
    expect(after.relays).toEqual([]);
    expect(after.edges).toEqual([]);
    expect(after.listeners).toEqual([]);
    expect(after.bindings).toEqual([]);
    expect(after.accounts.map((a) => a._id)).toEqual([accountId]);
    expect(after.templates.length).toBeGreaterThan(0);
    expect(after.probeTargets).toHaveLength(1);
    expect(after.reach.map((x) => x.targetKind)).toEqual(['custom']);
    const setting = (k: string) => after.settings.find((s) => s.key === k)?.value;
    expect(setting('edge.enabled')).toBe('false');
    expect(setting('edge.render.enabled')).toBe('false');
    expect(setting('edge.autoRotate')).toBe('false');
    expect(setting('edge.l7.autoSelect')).toBe('false');
    expect(after.audits).toContain('admin.edge.reset');
  });
});
