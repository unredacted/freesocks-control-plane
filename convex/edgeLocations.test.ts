/// <reference types="vite/client" />
/**
 * Edge locations (docs/edges.md § "Provider accounts and locations"): an
 * account is credentials; a location is where its edges live. Each edge
 * freezes its location's placement, so a describe or a destroy acts in the
 * edge's own region; trust is taken per location; a region-specific template
 * value is the location's own.
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { jsonRes, mockFetch } from './lib/edges/testing/mockFetch';
import { createAccount, seedEdgeFixture } from './lib/edges/testing/fixtures';
import { defaultLocationRow, insertPlanned } from './lib/edges/testing/reads';
import { resolveTemplateFor } from './edgeTemplates';

const modules = import.meta.glob('./**/*.*s');

afterEach(() => vi.unstubAllGlobals());

type T = ReturnType<typeof convexTest>;

const lbLedger = {
  steps: [],
  resources: [
    {
      stepId: 'lb',
      kind: 'lb',
      resourceId: 'lb-1',
      ownership: 'created' as const,
      deleteState: 'present' as const,
    },
  ],
};

async function locationsOf(t: T, accountId: Id<'edgeProviderAccounts'>) {
  return t.query(internal.edgeLocations.listForAccount, { accountId });
}

/** A second location for a gcore account, written straight through the mutation (no discovery). */
async function addGcoreLocation(t: T, accountId: Id<'edgeProviderAccounts'>, regionId: number) {
  const r = await t.mutation(internal.edgeLocations.create, {
    accountId,
    placement: { projectId: 11, regionId },
    label: `Region ${regionId}`,
  });
  return r.id as Id<'edgeLocations'>;
}

describe('an account is credentials; a location is where its edges live', () => {
  test('the old single-location shape becomes the default location; a credentials-only L4 account has none; a CDN account always one', async () => {
    const t = convexTest(schema, modules);
    const legacy = await createAccount(t, { provider: 'upcloud', name: 'legacy' });
    const locs = await locationsOf(t, legacy);
    expect(locs).toHaveLength(1);
    expect(locs[0]).toMatchObject({
      placeKey: 'de-fra1',
      locationKey: 'upcloud:de-fra1',
      placement: { zone: 'de-fra1' },
      isDefault: true,
      qualified: false,
    });
    const bare = await createAccount(t, { provider: 'upcloud', name: 'bare', settings: {} });
    expect(await locationsOf(t, bare)).toEqual([]);
    const cdn = await createAccount(t, { provider: 'cloudflare', name: 'cdn' });
    expect(await locationsOf(t, cdn)).toEqual([
      expect.objectContaining({ placeKey: 'anycast', placement: {}, isDefault: true }),
    ]);
    // A CDN has one location per account: no second one.
    await expect(
      t.mutation(internal.edgeLocations.create, { accountId: cdn, placement: {} }),
    ).rejects.toThrow(/location_not_geographic/);
    // The same placement twice is the same location.
    const again = await t.mutation(internal.edgeLocations.create, {
      accountId: legacy,
      placement: { zone: 'de-fra1' },
    });
    expect(again).toEqual({ id: locs[0].id, created: false });
  });

  test('a location that would provision without a required regional value is refused', async () => {
    const t = convexTest(schema, modules);
    // The template names no flavor (the compiled default is empty) and OVH needs one.
    const accountId = await createAccount(t, {
      provider: 'ovh',
      name: 'ovh',
      settings: { applicationKey: 'ak', endpoint: 'ovh-eu' },
    });
    const placement = { serviceName: 'svc', regionName: 'REG2', networkId: 'n', subnetId: 's' };
    await expect(
      t.mutation(internal.edgeLocations.create, { accountId, placement }),
    ).rejects.toThrow(/template_value_required/);
    const made = await t.mutation(internal.edgeLocations.create, {
      accountId,
      placement,
      regionalParams: { flavorId: 'flavor-small' },
    });
    expect(made.created).toBe(true);
    // Clearing its own value later is refused the same way.
    await expect(
      t.mutation(internal.edgeLocations.update, {
        id: made.id as Id<'edgeLocations'>,
        regionalParams: {},
      }),
    ).rejects.toThrow(/template_value_required/);
  });

  test('a new location is offered by the provider to this key, labelled by it, and created once', async () => {
    const t = convexTest(schema, modules);
    const accountId = await createAccount(t, { provider: 'upcloud', name: 'up', settings: {} });
    const stub = mockFetch((c) =>
      c.path.endsWith('/1.3/zone')
        ? jsonRes({
            zones: {
              zone: [
                { id: 'de-fra1', description: 'Zone one' },
                { id: 'nl-ams1', description: 'Zone two' },
              ],
            },
          })
        : jsonRes({}, 404),
    );
    const made = await t.action(internal.edgeProviderOps.createLocation, {
      accountId,
      placement: { zone: 'nl-ams1' },
      costNote: 'about 10 a month',
    });
    expect(made.created).toBe(true);
    const locs = await locationsOf(t, accountId);
    expect(locs).toEqual([
      expect.objectContaining({
        id: made.id,
        label: 'Zone two',
        placeKey: 'nl-ams1',
        isDefault: true,
        costNote: 'about 10 a month',
      }),
    ]);
    expect(stub.calls.some((c) => c.path.endsWith('/1.3/zone'))).toBe(true);
    expect(
      await t.action(internal.edgeProviderOps.createLocation, {
        accountId,
        placement: { zone: 'nl-ams1' },
      }),
    ).toEqual({ id: made.id, created: false });
    // A zone the key is not offered is refused; so is one the listing could not confirm.
    await expect(
      t.action(internal.edgeProviderOps.createLocation, {
        accountId,
        placement: { zone: 'fi-hel2' },
      }),
    ).rejects.toThrow(/location_not_offered/);
    stub.route(() => jsonRes({ error: 'down' }, 500));
    await expect(
      t.action(internal.edgeProviderOps.createLocation, {
        accountId,
        placement: { zone: 'de-fra1' },
      }),
    ).rejects.toThrow(/location_unchecked/);
    expect(await locationsOf(t, accountId)).toHaveLength(1);
  });
});

describe('trust is per location', () => {
  test('a location is trusted on its own; an account edit untrusts every location; a rotation keeps them', async () => {
    const t = convexTest(schema, modules);
    const accountId = await createAccount(t, { provider: 'gcore', name: 'g' });
    const a = (await defaultLocationRow(t, accountId))!._id;
    const b = await addGcoreLocation(t, accountId, 33);
    await t.mutation(internal.edgeLocations.setQualified, { id: b, qualified: true });
    let locs = await locationsOf(t, accountId);
    expect(locs.find((l) => l.id === a)?.qualified).toBe(false);
    expect(locs.find((l) => l.id === b)?.qualified).toBe(true);
    // The account reads as trusted: one of its locations is.
    expect(
      (await t.query(internal.edgeProviderAccounts.getForAdmin, { id: accountId }))?.qualified,
    ).toBe(true);
    await t.mutation(internal.edgeLocations.setQualified, { id: a, qualified: true });
    // A credential EDIT was never trusted anywhere: every location goes.
    const r = await t.mutation(internal.edgeProviderAccounts.update, {
      id: accountId,
      credentials: { apiKey: 'k2' },
    });
    expect(r.requalify).toBe(2);
    locs = await locationsOf(t, accountId);
    expect(locs.every((l) => !l.qualified)).toBe(true);
    // A manual untrust holds one location only.
    await t.mutation(internal.edgeLocations.setQualified, { id: b, qualified: false });
    expect((await t.run((c) => c.db.get(b)))!.autoQualifyHold).toBe(true);
    expect((await t.run((c) => c.db.get(a)))!.autoQualifyHold).toBeUndefined();
  });

  test("a location's own flavor lays over the template: an empty overlay keeps the template hash, a flavor of its own moves it and untrusts the location", async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.edgeTemplates.ensureDefaults, {});
    const accountId = await createAccount(t, { provider: 'gcore', name: 'g' });
    const loc = (await defaultLocationRow(t, accountId))!;
    const effective = (l: typeof loc) =>
      t.run(async (ctx) => {
        const acct = (await ctx.db.get(accountId))!;
        return resolveTemplateFor(ctx, 'gcore', null, null, acct._id, l);
      });
    const base = await effective(loc);
    const tpl = (await t.query(internal.edgeTemplates.list, { provider: 'gcore' })).find(
      (x) => x.isDefault,
    )!;
    expect(base.hash).toBe(tpl.paramsHash);
    await t.mutation(internal.edgeLocations.setQualified, { id: loc._id, qualified: true });
    // Only the regional keys survive; anything else is dropped.
    await t.mutation(internal.edgeLocations.update, {
      id: loc._id,
      regionalParams: { flavor: 'lb1-2-4', vipMode: 'private' },
    });
    const moved = (await t.run((c) => c.db.get(loc._id)))!;
    expect(JSON.parse(moved.regionalParams!)).toEqual({ flavor: 'lb1-2-4' });
    expect(moved.qualified).toBe(false);
    const overlaid = await effective(moved);
    expect(overlaid.params.flavor).toBe('lb1-2-4');
    expect(overlaid.params.vipMode).toBe('public');
    expect(overlaid.hash).not.toBe(base.hash);
    expect(overlaid.id).toBe(base.id);
  });
});

describe('every edge freezes its location', () => {
  test("describe and destroy act in the edge's own region, never the account's default", async () => {
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t, { qualified: true });
    // A credentials-only account with two locations: the edge lives in the second.
    const accountId = await createAccount(t, { provider: 'gcore', name: 'bare', settings: {} });
    const first = await addGcoreLocation(t, accountId, 22);
    const second = await addGcoreLocation(t, accountId, 33);
    expect((await t.run((c) => c.db.get(accountId)))!.defaultLocationId).toBe(first);
    const { id: edgeId } = await insertPlanned(t, {
      relayId: fx.relayId,
      listenerId: fx.listenerId,
      accountId,
      locationId: second,
      templateHash: 'h',
      listeners: [{ edgePort: 443, originAddress: '192.0.2.10', originPort: 443 }],
      steps: [],
    });
    const edge = (await t.run((c) => c.db.get(edgeId)))!;
    expect(edge).toMatchObject({
      locationId: second,
      placeKey: '33',
      placement: { type: 'gcore', projectId: 11, regionId: 33 },
      templateHash: 'h',
    });
    const stub = mockFetch(() =>
      jsonRes({ id: 'lb-1', provisioning_status: 'ACTIVE', vip_address: '198.51.100.9' }),
    );
    await t
      .action(internal.edgeProviderOps.describe, { accountId, ledger: lbLedger, edgeId })
      .catch(() => null);
    const paths = stub.calls.map((c) => c.path);
    expect(paths.length).toBeGreaterThan(0);
    expect(paths.every((p) => p.includes('/11/33'))).toBe(true);
    stub.calls.length = 0;
    await t
      .action(internal.edgeProviderOps.runDestroy, {
        accountId,
        resource: lbLedger.resources[0],
        ledger: lbLedger,
        edgeId,
      })
      .catch(() => null);
    expect(stub.calls.some((c) => c.method === 'DELETE' && c.path.includes('/11/33/'))).toBe(true);
    expect(stub.calls.some((c) => c.path.includes('/11/22'))).toBe(false);
  });

  test("a location's own cap bounds its inserts beside the account's", async () => {
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t, { qualified: true });
    const capped = await addGcoreLocation(t, fx.accountId, 33);
    await t.mutation(internal.edgeLocations.update, { id: capped, maxLiveEdges: 1 });
    const insert = (locationId: Id<'edgeLocations'>) =>
      insertPlanned(t, {
        relayId: fx.relayId,
        listenerId: fx.listenerId,
        accountId: fx.accountId,
        locationId,
        templateHash: 'h',
        listeners: [],
        steps: [],
      });
    await insert(capped);
    await expect(insert(capped)).rejects.toThrow(/location_capacity/);
    // The account's other location still has room.
    const dflt = (await defaultLocationRow(t, fx.accountId))!._id;
    await expect(insert(dflt)).resolves.toBeTruthy();
  });
});

describe('selection picks a trusted location', () => {
  test('automatic work uses a trusted location only; a named one may be untrusted for a spare', async () => {
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t, { qualified: true });
    const trusted = (await defaultLocationRow(t, fx.accountId))!._id;
    const other = await addGcoreLocation(t, fx.accountId, 33);
    const preflight = (extra: Record<string, unknown> = {}) =>
      t.query(internal.edgeOperator.preflight, {
        relayId: fx.relayId,
        kind: 'provision',
        publish: false,
        ...extra,
      } as never);
    let pf = await preflight();
    expect(pf.wouldSelect).toMatchObject({ accountId: fx.accountId, locationId: trusted });
    // Trust moves to the other location: automatic selection follows it.
    await t.mutation(internal.edgeLocations.setQualified, { id: trusted, qualified: false });
    await t.mutation(internal.edgeLocations.setQualified, { id: other, qualified: true });
    pf = await preflight();
    expect(pf.wouldSelect).toMatchObject({ locationId: other });
    // Nothing trusted: the automatic pick fails; the operator may still name one.
    await t.mutation(internal.edgeLocations.setQualified, { id: other, qualified: false });
    pf = await preflight();
    expect(pf.blockers.map((b: { code: string }) => b.code)).toContain('no_qualified_account');
    const listener = (await t.run((c) => c.db.get(fx.listenerId)))!;
    // The explicit (bootstrap) path needs a tested account, not a trusted location.
    await t.mutation(internal.edgeProviderAccounts.recordTest, { id: fx.accountId, ok: true });
    pf = await preflight({
      kind: 'test-provision',
      listenerKey: listener.listenerKey,
      locationId: other,
    });
    expect(pf.wouldSelect).toMatchObject({ locationId: other });
    expect(pf.warnings.map((w: { code: string }) => w.code)).toContain('account_unqualified');
  });
});

describe('removing a location', () => {
  test('refused while an edge lives there, a node names it or an open run picked it; the default moves to the next', async () => {
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t, { qualified: true });
    const first = (await defaultLocationRow(t, fx.accountId))!._id;
    const second = await addGcoreLocation(t, fx.accountId, 33);
    const { id: edgeId } = await insertPlanned(t, {
      relayId: fx.relayId,
      listenerId: fx.listenerId,
      accountId: fx.accountId,
      locationId: first,
      templateHash: 'h',
      listeners: [],
      steps: [],
    });
    await expect(t.mutation(internal.edgeLocations.remove, { id: first })).rejects.toThrow(
      /location_in_use/,
    );
    await t.run((c) => c.db.patch(edgeId, { status: 'destroyed' }));
    await t.run((c) =>
      c.db.patch(fx.relayId, { providerSet: [{ locationId: first, addedAt: Date.now() }] }),
    );
    await expect(t.mutation(internal.edgeLocations.remove, { id: first })).rejects.toThrow(
      /location_in_use/,
    );
    await t.run((c) => c.db.patch(fx.relayId, { providerSet: [] }));
    // A setup run that picked it before creating its first edge holds it too.
    const now = Date.now();
    const runId = await t.run((c) =>
      c.db.insert('edgeSetupRuns', {
        relaySlug: 'node-one',
        backendServerId: fx.serverId,
        nodeName: 'node-one',
        nodeUuid: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
        picks: [{ locationId: first, accountId: fx.accountId }],
        plan: '{}',
        planHash: 'h',
        planRevision: 1,
        approvedHideUuids: [],
        stage: 'provision',
        state: 'running',
        generation: 1,
        stepVersion: 1,
        listeners: [],
        stageEnteredAt: now,
        events: [],
        startedAt: now,
        updatedAt: now,
      }),
    );
    await expect(t.mutation(internal.edgeLocations.remove, { id: first })).rejects.toThrow(
      /location_in_use/,
    );
    await t.run((c) => c.db.patch(runId, { state: 'cancelled' }));
    await t.mutation(internal.edgeLocations.remove, { id: first });
    expect((await t.run((c) => c.db.get(fx.accountId)))!.defaultLocationId).toBe(second);
    const audit = await t.run((c) => c.db.query('auditLog').collect());
    expect(audit.find((a) => a.action === 'edge.location.removed')?.payload).toEqual({
      name: 'acct-a',
      provider: 'gcore',
      placeKey: '22',
    });
  });
});

describe('a credential test needs no location', () => {
  test('gcore lists the projects, scaleway lists in the first zone: no region is guessed', async () => {
    const t = convexTest(schema, modules);
    const gcore = await createAccount(t, { provider: 'gcore', name: 'g', settings: {} });
    const scw = await createAccount(t, {
      provider: 'scaleway',
      name: 's',
      settings: { accessKey: 'SCWXXXXXXXXXXXXXXXXX' },
      credentials: { secretKey: '11111111-2222-4333-8444-555555555555' },
    });
    const stub = mockFetch((c) =>
      c.path === '/cloud/v1/projects'
        ? jsonRes({ count: 0, results: [] })
        : c.path.startsWith('/lb/v1/zones/')
          ? jsonRes({ lbs: [], total_count: 0 })
          : jsonRes({}, 404),
    );
    expect(await t.action(internal.edgeProviderOps.testCredentials, { accountId: gcore })).toEqual({
      ok: true,
      code: undefined,
      detail: undefined,
    });
    expect(stub.calls.map((c) => c.path)).toEqual(['/cloud/v1/projects']);
    stub.calls.length = 0;
    expect((await t.action(internal.edgeProviderOps.testCredentials, { accountId: scw })).ok).toBe(
      true,
    );
    expect(stub.calls.map((c) => c.path)).toEqual(['/lb/v1/zones/fr-par-1/lbs']);
  });
});

describe('a location named after its bare region id', () => {
  test('gets the name its provider lists for that region; a named one is left alone', async () => {
    const t = convexTest(schema, modules);
    const accountId = await createAccount(t, { provider: 'gcore', name: 'g' });
    const row = (await defaultLocationRow(t, accountId))!;
    // A migrated account had no region name to copy: the id is the label.
    await t.run((c) => c.db.patch(row._id, { label: row.placeKey }));
    mockFetch((c) =>
      c.path.startsWith('/cloud/v1/regions')
        ? jsonRes({
            count: 1,
            results: [{ id: Number(row.placeKey), display_name: 'Region Two', state: 'ACTIVE' }],
          })
        : jsonRes({}, 404),
    );
    expect(await t.action(internal.edgeProviderOps.relabelLocations, {})).toEqual({ named: 1 });
    expect((await defaultLocationRow(t, accountId))!.label).toBe('Region Two');
    // Asked again, nothing is left to name.
    expect(await t.action(internal.edgeProviderOps.relabelLocations, {})).toEqual({ named: 0 });
  });
});
