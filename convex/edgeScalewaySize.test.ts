/**
 * A Scaleway load balancer size that takes only Scaleway's own servers is
 * refused before anything billable is created (lib/edges/sizeCheck.ts,
 * docs/edges.md § "Scaleway sizes"): the rule itself, the protect sheet's
 * place and pick checks, a set that names such a place, a rotation that names
 * it, automatic selection and preflight. Fixtures only (RFC 5737, `*.example`).
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import {
  FIXTURE_CONFIG_PROFILE,
  FIXTURE_INBOUND,
  createAccount,
  insertPanelServer,
  realityListener,
  registerRelay,
} from './lib/edges/testing/fixtures';
import { defaultLocationRow } from './lib/edges/testing/reads';
import {
  SIZE_NOT_MULTICLOUD,
  scalewaySizeIsMulticloud,
  sizeProblemOf,
} from './lib/edges/sizeCheck';
import { sizeProblemOfLocation } from './edgeLocations';
import { selectionContext } from './edgeRotations';
import { __setPlanOpsForTests, refuseSet, setOfPicks } from './edgeSetupPlan';
import { resolveEdgeConfig } from './lib/edgeConfig';
import type { BackendTransport } from './lib/backends/types';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;

const PROJECT = '66666666-7777-4888-8999-000000000000';
const NODE_UUID = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const inboundA: BackendTransport = {
  tag: 'VLESS_RELAY_A',
  configProfileUuid: FIXTURE_CONFIG_PROFILE,
  configProfileInboundUuid: FIXTURE_INBOUND,
  protocol: 'vless',
  port: 443,
  network: 'tcp',
  security: 'reality',
  reality: { target: 'target.example:443', serverNames: ['a.example'] },
  active: true,
};

afterEach(() => __setPlanOpsForTests(null));

describe('the rule (lib/edges/sizeCheck.ts)', () => {
  test('with no size list: only the documented multi-cloud sizes, in any case', () => {
    expect(sizeProblemOf('scaleway', { type: 'LB-S' }, null)).toBe(SIZE_NOT_MULTICLOUD);
    expect(sizeProblemOf('scaleway', { type: 'LB-GP-M' }, undefined)).toBe(SIZE_NOT_MULTICLOUD);
    expect(sizeProblemOf('scaleway', { type: 'lb-gp-l' }, null)).toBeNull();
    expect(sizeProblemOf('scaleway', { type: 'LB-GP-XL' }, null)).toBeNull();
    // A size nobody listed cannot be proven: refused.
    expect(sizeProblemOf('scaleway', { type: 'LB-NEW' }, null)).toBe(SIZE_NOT_MULTICLOUD);
    // A snapshot that cannot be read is no list at all.
    expect(sizeProblemOf('scaleway', { type: 'LB-GP-L' }, '{not json')).toBeNull();
    // Other providers have no such rule.
    expect(sizeProblemOf('gcore', { type: 'LB-S' }, null)).toBeNull();
  });

  test("the location's size list decides: its flag, else the label an older pull gave it", () => {
    const snapshot = (flavors: unknown[]) =>
      JSON.stringify({ loadBalancers: [], ips: [], flavors });
    // The provider's own flag wins over the documented list, either way.
    expect(
      sizeProblemOf(
        'scaleway',
        { type: 'LB-NEW' },
        snapshot([{ id: 'LB-NEW', label: 'LB-NEW (multi-cloud)', multicloud: true }]),
      ),
    ).toBeNull();
    expect(
      sizeProblemOf(
        'scaleway',
        { type: 'LB-GP-L' },
        snapshot([{ id: 'LB-GP-L', label: 'LB-GP-L', multicloud: false }]),
      ),
    ).toBe(SIZE_NOT_MULTICLOUD);
    // A pull from before the flag was kept: the label says it.
    expect(
      scalewaySizeIsMulticloud('lb-gp-l', [{ id: 'LB-GP-L', label: 'LB-GP-L (multi-cloud)' }]),
    ).toBe(true);
    expect(scalewaySizeIsMulticloud('LB-S', [{ id: 'LB-S', label: 'LB-S' }])).toBe(false);
    // Not on the list: the documented sizes.
    expect(scalewaySizeIsMulticloud('LB-GP-XL', [{ id: 'LB-S', label: 'LB-S' }])).toBe(true);
  });
});

/** A node with a REALITY transport and a tested, trusted Scaleway account (its location names a project). */
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
  return { t, accountId, relayId: r.relayId, listenerId: r.listenerId, locationId };
}

/** The location builds with `type` (its regional value). */
const sizeAt = (t: T, id: Id<'edgeLocations'>, type: string) =>
  t.run((ctx) => ctx.db.patch(id, { regionalParams: JSON.stringify({ type }) }));

async function refusal(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (err) {
    return String((err as { data?: { code?: string } }).data?.code ?? err);
  }
  return 'no refusal';
}

describe('a Scaleway place whose size takes only Scaleway servers', () => {
  test('the place reads `size_not_multicloud` until it builds with a multi-cloud size', async () => {
    const { t, accountId, locationId } = await world();
    const problem = () =>
      t.run(async (ctx) =>
        sizeProblemOfLocation(ctx, (await ctx.db.get(accountId))!, (await ctx.db.get(locationId))!),
      );
    // The default template's size (LB-S, kept as it is).
    expect(await problem()).toBe(SIZE_NOT_MULTICLOUD);
    await sizeAt(t, locationId, 'LB-GP-L');
    expect(await problem()).toBeNull();
    // The location's size list says LB-GP-L is not multi-cloud after all: believed.
    await t.run((ctx) =>
      ctx.db.patch(locationId, {
        inventorySnapshot: JSON.stringify({
          loadBalancers: [],
          ips: [],
          flavors: [{ id: 'LB-GP-L', label: 'LB-GP-L', multicloud: false }],
        }),
      }),
    );
    expect(await problem()).toBe(SIZE_NOT_MULTICLOUD);
  });

  test('the protect sheet offers the place only once it builds with a multi-cloud size', async () => {
    const t = convexTest(schema, modules);
    const serverId = await insertPanelServer(t);
    const accountId = await createAccount(t, {
      provider: 'scaleway',
      name: 'acct-s',
      settings: { accessKey: 'SCWXXXXXXXXXXXXXXXXX', zone: 'fr-par-1', projectId: PROJECT },
      credentials: { secretKey: '11111111-2222-4333-8444-555555555555' },
    });
    await t.mutation(internal.edgeProviderAccounts.recordTest, { id: accountId, ok: true });
    await t.run((ctx) =>
      ctx.db.insert('backendNodeInventory', {
        backendServerId: serverId,
        nodeUuid: NODE_UUID,
        name: 'node-one',
        usersOnline: 0,
        online: true,
        lastStatsAt: Date.now(),
        address: '203.0.113.10',
        port: 443,
      }),
    );
    __setPlanOpsForTests({ listNodeInbounds: async () => [inboundA], listHosts: async () => [] });
    const offered = async () => {
      const plan = await t.action(internal.edgeSetupPlan.plan, {
        backendServerId: serverId,
        nodeUuid: NODE_UUID,
      });
      return plan.accounts.find((a) => a.id === (accountId as string))!;
    };
    const before = await offered();
    expect(before.locations?.map((l) => [l.compatible, l.reasons])).toEqual([
      [false, [SIZE_NOT_MULTICLOUD]],
    ]);
    await sizeAt(t, (await defaultLocationRow(t, accountId))!._id, 'LB-GP-L');
    const after = await offered();
    expect(after.locations?.map((l) => [l.compatible, l.reasons])).toEqual([[true, []]]);
  });

  test("a pick is checked with the node's own size option (`checkPicks`)", async () => {
    const { t, locationId } = await world();
    const check = (options: Record<string, unknown>) =>
      t.query(internal.edgeSetupPlan.checkPicks, {
        picks: [{ locationId, options }],
        realityL4: true,
      });
    const refused = (await check({}))[0]!;
    expect(refused).toMatchObject({ ok: false, code: `edge.${SIZE_NOT_MULTICLOUD}` });
    expect(refused.ok === false && refused.issues[0]).toContain(
      'This size only accepts servers hosted at Scaleway. Pick a multi-cloud size (L or XL).',
    );
    expect((await check({ type: 'LB-GP-XL' }))[0]!.ok).toBe(true);
    // A multi-cloud place, and a node that asks for the small size there.
    await sizeAt(t, locationId, 'LB-GP-L');
    expect((await check({}))[0]!.ok).toBe(true);
    expect((await check({ type: 'LB-S' }))[0]).toMatchObject({
      ok: false,
      code: `edge.${SIZE_NOT_MULTICLOUD}`,
    });
  });

  test('a set naming such a place is refused in its own words', () => {
    const set = setOfPicks(
      ['x1'],
      [
        {
          id: 'acct-s',
          name: 'acct-s',
          provider: 'scaleway',
          layer: 'l4',
          compatible: false,
          reasons: [SIZE_NOT_MULTICLOUD],
          locations: [
            {
              id: 'x1',
              label: 'fr-par-1',
              placeKey: 'fr-par-1',
              isDefault: true,
              qualified: true,
              compatible: false,
              reasons: [SIZE_NOT_MULTICLOUD],
            },
          ],
          carries: ['a'],
        },
      ],
      [
        {
          listenerKey: 'a',
          sourceTag: 'A',
          listenerSpec: {},
          layers: ['l4'],
          frontable: true,
          formats: { links: true, singbox: true, clash: true },
          needsName: false,
        },
      ],
      [],
    );
    expect(set.problems).toContainEqual({ locationId: 'x1', reason: SIZE_NOT_MULTICLOUD });
    expect(() => refuseSet(set)).toThrow(/Scaleway/);
    let code = '';
    try {
      refuseSet(set);
    } catch (e) {
      code = (e as { data: { code: string } }).data.code;
    }
    expect(code).toBe(`edge.${SIZE_NOT_MULTICLOUD}`);
  });

  test('a rotation naming it is refused at its start, and preflight says why', async () => {
    const { t, relayId, listenerId, locationId } = await world();
    const start = () =>
      refusal(
        t.mutation(internal.edgeRotations.start, {
          relayId,
          kind: 'provision',
          trigger: 'manual',
          publishOnDone: false,
          listenerId,
          requestedLocationId: locationId,
        }),
      );
    expect(await start()).toBe(`edge.${SIZE_NOT_MULTICLOUD}`);
    const pre = await t.query(internal.edgeOperator.preflight, {
      relayId,
      kind: 'provision',
      listenerKey: 'a',
      locationId,
      publish: false,
    });
    expect(pre.blockers.map((b) => b.code)).toContain(SIZE_NOT_MULTICLOUD);
    await sizeAt(t, locationId, 'LB-GP-L');
    expect(await start()).not.toBe(`edge.${SIZE_NOT_MULTICLOUD}`);
  });

  test('selection never chooses it, named or automatic', async () => {
    const { t, relayId, listenerId, locationId } = await world();
    const select = (rotation: Parameters<typeof selectionContext>[1]) =>
      t.run(async (ctx) =>
        selectionContext(
          ctx,
          rotation,
          (await ctx.db.get(relayId))!,
          null,
          await resolveEdgeConfig(ctx.db),
        ),
      );
    const named = await select({
      kind: 'provision',
      trigger: 'manual',
      listenerId,
      requestedLocationId: locationId,
    });
    expect(named.accountFailure).toBe(SIZE_NOT_MULTICLOUD);
    const automatic = await select({ kind: 'provision', trigger: 'manual', listenerId });
    expect(automatic.account).toBeNull();
    expect(automatic.accountFailure).toBe(SIZE_NOT_MULTICLOUD);
    await sizeAt(t, locationId, 'LB-GP-XL');
    const picked = await select({ kind: 'provision', trigger: 'manual', listenerId });
    expect(picked.accountFailure ?? null).toBeNull();
    expect(picked.account?.locationId).toBe(locationId);
  });
});
