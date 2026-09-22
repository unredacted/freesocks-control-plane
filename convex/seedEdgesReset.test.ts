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
const ORIGINAL_ALLOW = process.env.EDGE_RESET_ALLOW;
afterEach(() => {
  if (ORIGINAL_ENV === undefined) delete process.env.ENVIRONMENT;
  else process.env.ENVIRONMENT = ORIGINAL_ENV;
  if (ORIGINAL_ALLOW === undefined) delete process.env.EDGE_RESET_ALLOW;
  else process.env.EDGE_RESET_ALLOW = ORIGINAL_ALLOW;
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

  test('freeze still admits completion paths: unpublish, origin delete, thaw', async () => {
    const { t, relayId, listenerId } = await seed();
    const { edgeId } = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      listenerId,
      ipv4: '198.51.100.7',
      publish: true,
      verified: true,
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

describe('edge maintenance gate: every admin configuration write and single-target probe', () => {
  test('qualification flips, account / template deletes and cron or detector probes are refused; a qualification probe is not', async () => {
    const { t, relayId, listenerId, accountId } = await seed();
    const { edgeId } = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      listenerId,
      ipv4: '198.51.100.7',
    });
    await t.mutation(internal.edgeTemplates.ensureDefaults, {});
    const templateId = await t.run(
      async (ctx) => (await ctx.db.query('edgeTemplates').first())!._id,
    );
    await t.mutation(internal.edgeMaintenance.freeze, {});
    const refused = /maintenance/;
    await expect(
      t.mutation(internal.edgeProviderAccounts.setQualified, { id: accountId, qualified: true }),
    ).rejects.toThrow(refused);
    await expect(
      t.mutation(internal.edgeProviderAccounts.remove, { id: accountId }),
    ).rejects.toThrow(refused);
    await expect(t.mutation(internal.edgeTemplates.remove, { id: templateId })).rejects.toThrow(
      refused,
    );
    const target = { kind: 'edge' as const, ref: edgeId as string };
    for (const trigger of ['cron', 'detector', 'manual'] as const)
      await expect(t.mutation(internal.probes.requestProbes, { target, trigger })).rejects.toThrow(
        refused,
      );
    // A qualification probe belongs to a rotation already in flight (completion):
    // whatever it answers, it is not the maintenance refusal.
    const q = await t
      .mutation(internal.probes.requestProbes, { target, trigger: 'qualification' })
      .then(
        () => 'admitted',
        (e: unknown) => String(e),
      );
    expect(q).not.toMatch(refused);
  });
});

describe('seedEdgesReset', () => {
  test('wipeAllowedIn: development always, anything else only with the explicit opt-in', () => {
    expect(wipeAllowedIn({ ENVIRONMENT: 'development' })).toBe(true);
    // A beta stack runs ENVIRONMENT=production like prod: the opt-in decides, not the name.
    expect(wipeAllowedIn({ ENVIRONMENT: 'production' })).toBe(false);
    expect(wipeAllowedIn({ ENVIRONMENT: 'production', EDGE_RESET_ALLOW: 'wipe-edges' })).toBe(true);
    expect(wipeAllowedIn({ ENVIRONMENT: 'production', EDGE_RESET_ALLOW: 'true' })).toBe(false);
    expect(wipeAllowedIn({ ENVIRONMENT: 'beta' })).toBe(false);
    expect(wipeAllowedIn({})).toBe(false);
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

  test('wipe refuses a wrong confirm, a deployment that did not opt in, and open blockers', async () => {
    const { t } = await seed();
    process.env.ENVIRONMENT = 'production';
    process.env.EDGE_RESET_ALLOW = 'wipe-edges';
    await expect(t.action(internal.seedEdgesReset.wipe, { confirm: 'nope' })).rejects.toThrow(
      /confirm/,
    );
    delete process.env.EDGE_RESET_ALLOW;
    await expect(t.action(internal.seedEdgesReset.wipe, { confirm: 'wipe-edges' })).rejects.toThrow(
      /EDGE_RESET_ALLOW/,
    );
    process.env.EDGE_RESET_ALLOW = 'wipe-edges';
    // Not frozen yet -> blocked.
    await expect(t.action(internal.seedEdgesReset.wipe, { confirm: 'wipe-edges' })).rejects.toThrow(
      /not safe to wipe.*not frozen/,
    );
    const rows = await t.run((ctx) => ctx.db.query('relays').collect());
    expect(rows).toHaveLength(1);
  });

  test('every destructive batch enforces the guards itself: a direct wipeBatch bypasses nothing', async () => {
    const { t } = await seed();
    const direct = (confirm: string) =>
      t.mutation(internal.seedEdgesReset.wipeBatch, { table: 'relays', confirm });
    process.env.ENVIRONMENT = 'production';
    await expect(direct('wipe-edges')).rejects.toThrow(/EDGE_RESET_ALLOW/);
    process.env.EDGE_RESET_ALLOW = 'wipe-edges';
    await expect(direct('nope')).rejects.toThrow(/confirm/);
    await expect(direct('wipe-edges')).rejects.toThrow(/not frozen/);
    await expect(
      t.mutation(internal.seedEdgesReset.disableSwitches, { confirm: 'wipe-edges' }),
    ).rejects.toThrow(/not frozen/);
    expect(await t.run((ctx) => ctx.db.query('relays').collect())).toHaveLength(1);
  });

  test('a managed edge beyond any listing cap still blocks the wipe', async () => {
    const { t, relayId, listenerId } = await seed();
    await t.mutation(internal.relays.adoptEdge, { relayId, listenerId, ipv4: '198.51.100.7' });
    const template = await t.run(async (ctx) => (await ctx.db.query('edges').first())!);
    await t.run(async (ctx) => {
      const { _id, _creationTime, ...row } = template;
      void _id;
      void _creationTime;
      // 520 imported (observe-only) edges first, then ONE managed edge after them.
      for (let i = 0; i < 520; i++) await ctx.db.insert('edges', { ...row, managed: false });
      await ctx.db.insert('edges', { ...row, managed: true });
    });
    await t.mutation(internal.edgeMaintenance.freeze, {});
    const st = await t.query(internal.seedEdgesReset.status, {});
    expect(st.edgesOpenCount).toBe(1);
    expect(st.blockers.join(' ')).toMatch(/1 managed edge\(s\) not destroyed/);
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
