/// <reference types="vite/client" />
/**
 * Operations safety (docs/edges.md § "Operations safety"): the fleet brake and
 * the fleet's daily cap on automatic rotation, provider API failures and
 * billable-but-idle resources made visible, a stuck rotation, a disabled
 * client family, the operator alerts (new items once, codes and counts only)
 * and "Serve this node directly again".
 *
 * Fixtures use RFC 5737 addresses and `*.example` names only.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { ATTENTION_KINDS } from '../src/shared/contracts/edgeCodes';
import { ATTENTION_RANK, STUCK_ROTATION_MS } from './edgeOperator';
import { collectStartBlockers } from './edgeRotations';
import { apiFailureCode } from './edgeProviderOps';
import { EdgeProviderError } from './lib/edges/providers/http';
import { __setEdgeProviderForTests, edgeProviderFor } from './lib/edges/providers/registry';
import { EDGE_DEFAULTS } from './lib/edgeConfig';
import {
  FLEET_BRAKE_MIN_SUSPECTED,
  countFleetRotation,
  fleetBrakeEngages,
  writeFleetBrake,
} from './lib/edges/fleet';
import { alertMessage, alertWorthy } from './alerts';
import {
  FIXTURE_NODE,
  FIXTURE_ORIGIN,
  adoptL4Edge,
  createAccount,
  seedEdgeFixture,
} from './lib/edges/testing/fixtures';

const modules = import.meta.glob('./**/*.*s');

beforeEach(() => {
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.useRealTimers();
  __setEdgeProviderForTests('gcore', null);
});

type T = ReturnType<typeof convexTest>;

const attentionOf = async (t: T) => (await t.query(internal.edgeOperator.attention, {})).items;

async function automation(t: T) {
  await t.run(async (ctx) => {
    await upsertSettingRow(ctx, 'edge.enabled', 'true');
    await upsertSettingRow(ctx, 'edge.autoRotate', 'true');
  });
}

describe('the attention ranking', () => {
  test('the server ranks exactly the shared kinds, each once', () => {
    expect([...ATTENTION_RANK].sort()).toEqual([...ATTENTION_KINDS].sort());
    expect(new Set(ATTENTION_RANK).size).toBe(ATTENTION_RANK.length);
  });
});

describe('the fleet brake', () => {
  test('probe-only automatic rotation is off by default', () => {
    expect(EDGE_DEFAULTS.detect.allowProbeOnlyAutoRotate).toBe(false);
  });

  test('engages past the threshold with enough suspected origins, never for a small fleet', () => {
    const pct = 30;
    expect(fleetBrakeEngages({ suspected: 3, evaluated: 5, thresholdPct: pct })).toBe(true);
    expect(fleetBrakeEngages({ suspected: 3, evaluated: 10, thresholdPct: pct })).toBe(false);
    // One of one origin is 100 %, but one burned address is not a mass block.
    expect(
      fleetBrakeEngages({
        suspected: FLEET_BRAKE_MIN_SUSPECTED - 1,
        evaluated: 2,
        thresholdPct: pct,
      }),
    ).toBe(false);
    expect(fleetBrakeEngages({ suspected: 0, evaluated: 0, thresholdPct: pct })).toBe(false);
  });

  test('a pass records it (audited on each transition), the attention shows it, a detector start is refused and a manual one is not', async () => {
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t);
    const e1 = await adoptL4Edge(t, fx.relayId, fx.listenerId, { publish: true });
    await automation(t);
    await t.run((ctx) => ctx.db.patch(fx.relayId, { autoRotate: true }));
    const now = Date.now();
    expect(
      await t.mutation(internal.edgeDetector.recordFleetBrake, { suspected: 4, evaluated: 6, now }),
    ).toMatchObject({ engaged: true });
    // A second engaged pass is not a transition.
    await t.mutation(internal.edgeDetector.recordFleetBrake, { suspected: 5, evaluated: 6, now });
    const brake = (await attentionOf(t)).find((i) => i.kind === 'fleet_brake')!;
    expect(brake).toMatchObject({
      severity: 'critical',
      facts: { suspected: 5, evaluated: 6, threshold: 30 },
      action: 'open_settings',
    });
    expect(alertWorthy(brake)).toBe(true);
    const blockers = (trigger: 'detector' | 'manual') =>
      t.run(async (ctx) =>
        (
          await collectStartBlockers(ctx, {
            relayId: fx.relayId,
            kind: 'replace',
            trigger,
            targetEdgeId: e1.edgeId as Id<'edges'>,
          })
        ).blockers.map((b) => b.code),
      );
    expect(await blockers('detector')).toContain('edge.fleet_brake');
    expect(await blockers('manual')).not.toContain('edge.fleet_brake');
    // Back under the threshold: released, audited once more.
    expect(
      await t.mutation(internal.edgeDetector.recordFleetBrake, { suspected: 1, evaluated: 6, now }),
    ).toMatchObject({ engaged: false });
    expect(await blockers('detector')).not.toContain('edge.fleet_brake');
    expect((await attentionOf(t)).some((i) => i.kind === 'fleet_brake')).toBe(false);
    const audits = await t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .filter((q) => q.eq(q.field('action'), 'edge.fleet_brake'))
        .collect(),
    );
    expect(audits.map((a) => (a.payload as { engaged: boolean }).engaged)).toEqual([true, false]);
  });

  test('the fleet daily cap holds detector starts once reached and shows on the attention list', async () => {
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t);
    const e1 = await adoptL4Edge(t, fx.relayId, fx.listenerId, { publish: true });
    await automation(t);
    await t.run(async (ctx) => {
      await ctx.db.patch(fx.relayId, { autoRotate: true });
      await upsertSettingRow(ctx, 'edge.detect.fleetRotationsPerDay', '2');
    });
    const detector = () =>
      t.run(async (ctx) =>
        (
          await collectStartBlockers(ctx, {
            relayId: fx.relayId,
            kind: 'replace',
            trigger: 'detector',
            targetEdgeId: e1.edgeId as Id<'edges'>,
          })
        ).blockers.map((b) => b.code),
      );
    expect(await detector()).not.toContain('edge.fleet_daily_cap');
    await t.run(async (ctx) => {
      await countFleetRotation(ctx.db, Date.now());
      await countFleetRotation(ctx.db, Date.now());
    });
    expect(await detector()).toContain('edge.fleet_daily_cap');
    expect((await attentionOf(t)).find((i) => i.kind === 'fleet_rotation_cap')).toMatchObject({
      severity: 'warning',
      facts: { used: 2, cap: 2 },
    });
    // A new UTC day starts the count again.
    await t.run((ctx) =>
      writeFleetBrake(ctx.db, {
        engaged: false,
        since: null,
        suspected: 0,
        evaluated: 0,
        threshold: 30,
        updatedAt: null,
      }),
    );
    vi.useFakeTimers({ now: Date.now() + 24 * 60 * 60_000 });
    expect(await detector()).not.toContain('edge.fleet_daily_cap');
  });
});

describe('provider failures are visible', () => {
  const err = (meta: Partial<ConstructorParameters<typeof EdgeProviderError>[1]>) =>
    new EdgeProviderError('x', {
      provider: 'gcore',
      step: 'describe',
      retryable: false,
      timedOut: false,
      ...meta,
    });

  test('only the provider side counts: timeouts, network, 5xx, refused credentials, throttling, unreadable answers', () => {
    expect(apiFailureCode(err({ timedOut: true }))).toBe('timeout');
    expect(apiFailureCode(err({}))).toBe('network');
    expect(apiFailureCode(err({ status: 503 }))).toBe('503');
    expect(apiFailureCode(err({ status: 401 }))).toBe('401');
    expect(apiFailureCode(err({ status: 429 }))).toBe('429');
    expect(apiFailureCode(err({ status: 200, code: 'schema_mismatch' }))).toBe('schema_mismatch');
    // An adapter's own word for an answer it could not read counts the same way.
    expect(apiFailureCode(err({ code: 'plan_list_unreadable' }))).toBe('plan_list_unreadable');
    // A refusal the caller handles is not the API failing.
    expect(apiFailureCode(err({ status: 404 }))).toBeNull();
    expect(apiFailureCode(err({ status: 409, code: 'conflict' }))).toBeNull();
    expect(apiFailureCode(new Error('plain'))).toBeNull();
  });

  test('three failing calls in a row raise account_api_failing; the next good call clears it', async () => {
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t);
    const real = edgeProviderFor('gcore');
    let failing = true;
    __setEdgeProviderForTests('gcore', {
      ...real,
      describe: async () => {
        if (failing)
          throw new EdgeProviderError('gcore 503 on describe', {
            provider: 'gcore',
            step: 'describe',
            status: 503,
            retryable: true,
            timedOut: false,
          });
        return { state: 'present', addresses: {}, health: 'online', resources: [] } as never;
      },
    });
    const ledger = { steps: [], resources: [] };
    for (let i = 0; i < 3; i++)
      await expect(
        t.action(internal.edgeProviderOps.describe, { accountId: fx.accountId, ledger }),
      ).rejects.toThrow();
    const item = (await attentionOf(t)).find((i) => i.kind === 'account_api_failing')!;
    expect(item).toMatchObject({
      severity: 'critical',
      accountId: fx.accountId,
      code: '503',
      facts: { failures: 3 },
      action: 'open_account',
    });
    // The account's row version is left alone (credential rotations compare it).
    failing = false;
    await t.action(internal.edgeProviderOps.describe, { accountId: fx.accountId, ledger });
    const acct = (await t.run((ctx) => ctx.db.get(fx.accountId)))!;
    expect(acct.apiFailures).toBe(0);
    expect((await attentionOf(t)).some((i) => i.kind === 'account_api_failing')).toBe(false);
    // A disabled account's failing API stays visible (its live edges still need it).
    failing = true;
    for (let i = 0; i < 3; i++)
      await expect(
        t.action(internal.edgeProviderOps.describe, { accountId: fx.accountId, ledger }),
      ).rejects.toThrow();
    await t.run((ctx) => ctx.db.patch(fx.accountId, { enabled: false }));
    expect((await attentionOf(t)).some((i) => i.kind === 'account_api_failing')).toBe(true);
    failing = false;
    await t.run((ctx) => ctx.db.patch(fx.accountId, { enabled: true }));
  });

  test('a live edge whose health has not been refreshed for long is health_stale on its account', async () => {
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t);
    const e1 = await adoptL4Edge(t, fx.relayId, fx.listenerId, { publish: true });
    await t.run((ctx) =>
      ctx.db.patch(e1.edgeId as Id<'edges'>, {
        managed: true,
        accountId: fx.accountId,
        lastHealthAt: Date.now() - 3 * 60 * 60_000,
      }),
    );
    expect((await attentionOf(t)).find((i) => i.kind === 'health_stale')).toMatchObject({
      severity: 'warning',
      accountId: fx.accountId,
      facts: { edges: 1 },
    });
  });

  test('a daily budget of 0 (no limit) is refused outside development', async () => {
    const t = convexTest(schema, modules);
    await expect(createAccount(t, { name: 'acct-z', dailyAllocationBudget: 0 })).rejects.toThrow(
      /only in development/,
    );
    vi.stubEnv('ENVIRONMENT', 'development');
    const id = await createAccount(t, { name: 'acct-z', dailyAllocationBudget: 0 });
    expect((await attentionOf(t)).some((i) => i.kind === 'account_budget_unlimited')).toBe(false);
    // An older row with no limit is pointed out outside development.
    vi.unstubAllEnvs();
    expect((await attentionOf(t)).find((i) => i.kind === 'account_budget_unlimited')).toMatchObject(
      {
        severity: 'warning',
        accountId: id,
        action: 'open_account',
      },
    );
    // It keeps no limit only until its next edit, which must set one;
    // switching it off alone always works.
    await expect(
      t.mutation(internal.edgeProviderAccounts.update, { id, priority: 3 }),
    ).rejects.toThrow(/only in development/);
    await t.mutation(internal.edgeProviderAccounts.update, { id, enabled: false });
    await t.mutation(internal.edgeProviderAccounts.update, {
      id,
      priority: 3,
      dailyAllocationBudget: 5,
    });
    expect((await t.run((ctx) => ctx.db.get(id)))!.dailyAllocationBudget).toBe(5);
  });

  test('a quarantined origin keeps paying for its edges: billable_idle', async () => {
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t);
    const e1 = await adoptL4Edge(t, fx.relayId, fx.listenerId, { publish: true });
    await t.run(async (ctx) => {
      await ctx.db.patch(e1.edgeId as Id<'edges'>, { managed: true, accountId: fx.accountId });
      const rotationId = await ctx.db.insert('edgeRotations', {
        relayId: fx.relayId,
        kind: 'replace',
        trigger: 'manual',
        burn: false,
        force: false,
        phase: 'quarantined',
        stepVersion: 1,
        cancelRequested: false,
        hostPlan: [],
        flipAttempts: 0,
        rollbackAttempts: 0,
        pollAttempts: 0,
        events: [],
        startedAt: Date.now(),
        updatedAt: Date.now(),
      });
      await ctx.db.patch(fx.relayId, {
        quarantine: { rotationId, since: Date.now(), reason: 'host_uncertain' },
      });
    });
    expect((await attentionOf(t)).find((i) => i.kind === 'billable_idle')).toMatchObject({
      severity: 'warning',
      code: 'quarantine',
      facts: { edges: 1 },
      action: 'resolve_quarantine',
    });
  });
});

describe('stuck work and dark members', () => {
  test('a rotation running past the stuck mark is critical attention', async () => {
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t);
    const rotationId = await t.run(async (ctx) => {
      const id = await ctx.db.insert('edgeRotations', {
        relayId: fx.relayId,
        kind: 'provision',
        trigger: 'reconcile',
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
        startedAt: Date.now() - STUCK_ROTATION_MS - 60_000,
        updatedAt: Date.now(),
      });
      await ctx.db.patch(fx.relayId, { activeRotationId: id });
      return id;
    });
    expect((await attentionOf(t)).find((i) => i.kind === 'rotation_stuck')).toMatchObject({
      severity: 'critical',
      rotationId,
      code: 'provisioning',
      action: 'open_relay',
    });
  });

  test('a client family switched off while a node is edge-required is attention', async () => {
    const t = convexTest(schema, modules);
    await seedEdgeFixture(t);
    await t.run(async (ctx) => {
      await upsertSettingRow(ctx, 'edge.render.enabled', 'true');
      await upsertSettingRow(
        ctx,
        'edge.render.clients.v2rayng',
        JSON.stringify({ enabled: false }),
      );
    });
    expect((await attentionOf(t)).find((i) => i.kind === 'family_rule_disabled')).toMatchObject({
      severity: 'warning',
      facts: { families: ['v2rayng'] },
    });
  });
});

describe('operator alerts', () => {
  async function quarantine(t: T, relayId: Id<'relays'>) {
    await t.run(async (ctx) => {
      const rotationId = await ctx.db.insert('edgeRotations', {
        relayId,
        kind: 'replace',
        trigger: 'manual',
        burn: false,
        force: false,
        phase: 'quarantined',
        stepVersion: 1,
        cancelRequested: false,
        hostPlan: [],
        flipAttempts: 0,
        rollbackAttempts: 0,
        pollAttempts: 0,
        events: [],
        startedAt: Date.now(),
        updatedAt: Date.now(),
      });
      await ctx.db.patch(relayId, {
        quarantine: { rotationId, since: Date.now(), reason: 'flip_unconfirmed' },
      });
    });
  }

  function receiver(status = 200) {
    const posts: Array<{ url: string; auth: string | null; body: Record<string, unknown> }> = [];
    let answer = status;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL, init: RequestInit = {}) => {
        const headers = new Headers(init.headers);
        posts.push({
          url: String(input),
          auth: headers.get('authorization'),
          body: JSON.parse(String(init.body)),
        });
        return new Response('{}', { status: answer });
      }),
    );
    return { posts, answer: (s: number) => (answer = s) };
  }

  test('the config refuses what it cannot use and never shows a secret', async () => {
    const t = convexTest(schema, modules);
    await expect(t.mutation(internal.alerts.setConfig, { enabled: true })).rejects.toThrow(
      /webhook URL/,
    );
    await expect(
      t.mutation(internal.alerts.setConfig, { url: 'http://alerts.example.org' }),
    ).rejects.toThrow(/url is not valid/);
    await expect(
      t.mutation(internal.alerts.setConfig, { url: 'https://127.0.0.1/hook' }),
    ).rejects.toThrow(/url is not valid/);
    await t.mutation(internal.alerts.setConfig, {
      enabled: true,
      url: 'https://alerts.example.org/',
      topic: 'secret-topic-1',
      token: 'tk_secret',
    });
    const view = await t.query(internal.alerts.view, {});
    expect(view).toMatchObject({
      enabled: true,
      urlSet: true,
      urlOrigin: 'https://alerts.example.org',
      topicSet: true,
      tokenSet: true,
    });
    expect(JSON.stringify(view)).not.toMatch(/secret-topic|tk_secret/);
    // A field left out keeps its value; an empty string clears it.
    await t.mutation(internal.alerts.setConfig, { token: '' });
    expect(await t.query(internal.alerts.view, {})).toMatchObject({
      tokenSet: false,
      topicSet: true,
    });
    const audit = await t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .filter((q) => q.eq(q.field('action'), 'admin.alerts.change'))
        .collect(),
    );
    expect(JSON.stringify(audit)).not.toMatch(/secret-topic|tk_secret|alerts\.example/);
  });

  test('a new critical item is sent once, as kinds and counts; a recurrence alerts again; a failed post is retried', async () => {
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t);
    await t.mutation(internal.alerts.setConfig, {
      enabled: true,
      url: 'https://alerts.example.org',
      topic: 'ops-topic',
      token: 'tk_1',
    });
    const r = receiver();
    // The fixture node is bound with nothing published: its members are dark.
    expect(await t.action(internal.alerts.dispatch, {})).toMatchObject({ sent: 1 });
    expect(String(r.posts[0].body.message)).toContain('members_dark (empty_pool): 1');
    // Still on the list: not sent again.
    expect(await t.action(internal.alerts.dispatch, {})).toMatchObject({ sent: 0 });
    expect(r.posts).toHaveLength(1);
    // A new item: only it is sent.
    await quarantine(t, fx.relayId);
    expect(await t.action(internal.alerts.dispatch, {})).toMatchObject({ sent: 1, error: null });
    expect(r.posts).toHaveLength(2);
    expect(r.posts[1]).toMatchObject({
      url: 'https://alerts.example.org',
      auth: 'Bearer tk_1',
      body: { topic: 'ops-topic', priority: 5 },
    });
    expect(String(r.posts[1].body.message)).toContain('quarantine (flip_unconfirmed): 1');
    expect(String(r.posts[1].body.message)).not.toContain('members_dark');
    // Never a name, an address or an id.
    const sent = JSON.stringify(r.posts.map((p) => p.body));
    expect(sent).not.toContain(FIXTURE_NODE);
    expect(sent).not.toContain(FIXTURE_ORIGIN);
    expect(sent).not.toContain(fx.relayId);
    // Cleared, then back: it alerts again.
    await t.run((ctx) => ctx.db.patch(fx.relayId, { quarantine: undefined }));
    await t.action(internal.alerts.dispatch, {});
    await quarantine(t, fx.relayId);
    r.answer(500);
    expect(await t.action(internal.alerts.dispatch, {})).toMatchObject({ sent: 0, error: '500' });
    expect((await t.query(internal.alerts.view, {})).lastError).toBe('500');
    r.answer(200);
    expect(await t.action(internal.alerts.dispatch, {})).toMatchObject({ sent: 1, error: null });
    expect(r.posts).toHaveLength(4);
  });

  test('turning alerts back on sends what is open once more: nothing was reconciled while off', async () => {
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t);
    await t.mutation(internal.alerts.setConfig, {
      enabled: true,
      url: 'https://alerts.example.org',
    });
    const r = receiver();
    await quarantine(t, fx.relayId);
    await t.action(internal.alerts.dispatch, {});
    const sentBefore = r.posts.length;
    // Off: the quarantine clears and comes back meanwhile, unseen.
    await t.mutation(internal.alerts.setConfig, { enabled: false });
    await t.run((ctx) => ctx.db.patch(fx.relayId, { quarantine: undefined }));
    await quarantine(t, fx.relayId);
    await t.action(internal.alerts.dispatch, {});
    expect(r.posts).toHaveLength(sentBefore);
    // On again: it is reported.
    await t.mutation(internal.alerts.setConfig, { enabled: true });
    await t.action(internal.alerts.dispatch, {});
    expect(r.posts).toHaveLength(sentBefore + 1);
    expect(String(r.posts.at(-1)!.body.message)).toContain('quarantine');
  });

  test('disabled: nothing is read or sent', async () => {
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t);
    await quarantine(t, fx.relayId);
    const r = receiver();
    expect(await t.action(internal.alerts.dispatch, {})).toMatchObject({ enabled: false, sent: 0 });
    expect(r.posts).toHaveLength(0);
  });

  test('a suspected block alerts only while FCP is holding back a replacement', () => {
    const held = (code: string | null) =>
      alertWorthy({ kind: 'block_suspected', severity: 'warning', code });
    for (const code of [
      'edge_disabled',
      'auto_rotate_off',
      'probe_only_disallowed',
      'cooldown',
      'daily_cap',
      'fleet_daily_cap',
      'hosts_unmanaged',
      'open_lane_budget',
    ])
      expect(held(code)).toBe(true);
    // FCP is acting, a setup run owns it, an outage or evidence judgement, a
    // steering hold, or a hold that alerts on its own: no alert from this item.
    for (const code of [
      null,
      'rotation_active',
      'setup_owned',
      'not_live',
      'no_edge_evidence',
      'node_offline',
      'edge_outage',
      'protocol_level_block',
      'country_scoped',
      'country_wide',
      'fleet_brake',
      'quarantined',
    ])
      expect(held(code)).toBe(false);
    // The veto codes say nothing for any other warning.
    expect(
      alertWorthy({ kind: 'spare_untested', severity: 'warning', code: 'edge_disabled' }),
    ).toBe(false);
  });

  test('a held block is sent once as its kind and veto, and not again while it stays held', async () => {
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t);
    await t.mutation(internal.alerts.setConfig, {
      enabled: true,
      url: 'https://alerts.example.org',
    });
    const r = receiver();
    // Whatever the fixture raises on its own goes out first.
    await t.action(internal.alerts.dispatch, {});
    const before = r.posts.length;
    const suspect = (veto: string) =>
      t.run((ctx) =>
        ctx.db.patch(fx.relayId, {
          suspicion: {
            state: 'suspected',
            hintLevel: 'probes',
            score: 0.75,
            reportScore: 0,
            loadScore: 0.5,
            probeScore: 1,
            scope: 'regional',
            countries: [],
            edgeEvidence: [],
            firstSeenAt: Date.now(),
            lastEvalAt: Date.now(),
            quietEvals: 0,
            baselineWarm: true,
            veto,
          },
        }),
      );
    // FCP is replacing it: nothing to tell.
    await suspect('rotation_active');
    expect(await t.action(internal.alerts.dispatch, {})).toMatchObject({ sent: 0 });
    // Automation is off: FCP will not act, so the operator hears it.
    await suspect('edge_disabled');
    expect(await t.action(internal.alerts.dispatch, {})).toMatchObject({ sent: 1, error: null });
    expect(r.posts).toHaveLength(before + 1);
    expect(r.posts.at(-1)!.body).toMatchObject({ priority: 4, tags: ['warning'] });
    expect(String(r.posts.at(-1)!.body.message)).toContain('block_suspected (edge_disabled): 1');
    const sent = JSON.stringify(r.posts.at(-1)!.body);
    expect(sent).not.toContain(FIXTURE_NODE);
    expect(sent).not.toContain(fx.relayId);
    // Still suspected, now held by the daily cap: the same item, not sent again.
    await suspect('daily_cap');
    expect(await t.action(internal.alerts.dispatch, {})).toMatchObject({ sent: 0 });
    expect(r.posts).toHaveLength(before + 1);
  });

  test('the message drops a code that is not a short identifier', () => {
    const m = alertMessage(
      [
        { id: 'a', kind: 'quarantine', severity: 'critical', code: 'rotation_timeout during x' },
        { id: 'b', kind: 'node_ready_to_protect', severity: 'warning', code: null },
      ],
      '',
    );
    expect(m.message).toContain('quarantine: 1');
    expect(m.message).toContain('node_ready_to_protect: 1');
    expect(m.message).not.toContain('during');
    expect(m).not.toHaveProperty('topic');
  });
});

describe('serve this node directly again', () => {
  test('refused for a node that is not edge-required, then runs the release_requirement workflow once bound', async () => {
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t);
    // The fixture origin is bound (edge-required) from its creation.
    const res = await t.mutation(internal.edgeRestore.serveDirect, { relayId: fx.relayId });
    expect(res).toEqual({ ok: true, phase: 'freeze' });
    const relay = (await t.run((ctx) => ctx.db.get(fx.relayId)))!;
    expect(relay.restore).toMatchObject({ purpose: 'release_requirement', phase: 'freeze' });
    // A second one waits for the first.
    await expect(
      t.mutation(internal.edgeRestore.serveDirect, { relayId: fx.relayId }),
    ).rejects.toThrow(/restore/);
  });

  test('refused while quarantined, while a setup run owns the origin, and with nothing to restore', async () => {
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t);
    await t.run((ctx) => ctx.db.patch(fx.relayId, { setupOwned: true }));
    await expect(
      t.mutation(internal.edgeRestore.serveDirect, { relayId: fx.relayId }),
    ).rejects.toThrow(/setup owns/);
    await t.run(async (ctx) => {
      await ctx.db.patch(fx.relayId, { setupOwned: false });
      const rotationId = await ctx.db.insert('edgeRotations', {
        relayId: fx.relayId,
        kind: 'replace',
        trigger: 'manual',
        burn: false,
        force: false,
        phase: 'quarantined',
        stepVersion: 1,
        cancelRequested: false,
        hostPlan: [],
        flipAttempts: 0,
        rollbackAttempts: 0,
        pollAttempts: 0,
        events: [],
        startedAt: Date.now(),
        updatedAt: Date.now(),
      });
      await ctx.db.patch(fx.relayId, {
        quarantine: { rotationId, since: Date.now(), reason: 'host_uncertain' },
      });
    });
    await expect(
      t.mutation(internal.edgeRestore.serveDirect, { relayId: fx.relayId }),
    ).rejects.toThrow(/quarantined/);
    await t.run(async (ctx) => {
      await ctx.db.patch(fx.relayId, { quarantine: undefined });
      for (const b of await ctx.db.query('edgeDeliveryBindings').collect())
        await ctx.db.patch(b._id, { state: 'released' });
    });
    await expect(
      t.mutation(internal.edgeRestore.serveDirect, { relayId: fx.relayId }),
    ).rejects.toThrow(/already receive its direct address/);
  });
});
