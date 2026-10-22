/// <reference types="vite/client" />
/**
 * An account is its credentials; its locations are picked where a node's
 * addresses are chosen (docs/edges.md § "Provider accounts and locations").
 * A load balancer account added with nothing but its credentials passes its
 * test and lists the regions its key reaches; the protect plan and a node's
 * provider card offer those regions; picking one creates the location then,
 * its project (and OVH's network and subnet) completed from what the key
 * reaches, untrusted until its first tested address. Fixtures only (RFC 5737,
 * `*.example`).
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { jsonRes, mockFetch, type Captured } from './lib/edges/testing/mockFetch';
import {
  FIXTURE_CONFIG_PROFILE,
  FIXTURE_INBOUND,
  createAccount,
  insertPanelServer,
  seedEdgeFixture,
} from './lib/edges/testing/fixtures';
import { __setPlanOpsForTests } from './edgeSetupPlan';
import { regionOffersOf } from './edgeProviderCatalog';
import type { BackendTransport } from './lib/backends/types';
import { completePlacement, networkDefault, projectDefault } from './lib/edges/placementDefaults';
import { setupVetoNow } from './lib/edges/scoring';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;

afterEach(() => {
  vi.unstubAllGlobals();
  __setPlanOpsForTests(null);
});

const locationsOf = (t: T, accountId: Id<'edgeProviderAccounts'>) =>
  t.query(internal.edgeLocations.listForAccount, { accountId });
const catalogRegions = async (t: T, accountId: Id<'edgeProviderAccounts'>) =>
  (
    (await t.query(internal.edgeProviderCatalog.view, { accountId })).kinds.regions?.items ?? []
  ).map((r) => r.id);

// --- the provider APIs, as far as these tests reach them -----------------------------------------

const gcoreApi = (c: Captured) => {
  if (c.path === '/cloud/v1/projects')
    return jsonRes({
      count: 2,
      results: [
        { id: 11, name: 'first' },
        { id: 12, name: 'second' },
      ],
    });
  if (c.path === '/cloud/v1/regions')
    return jsonRes({
      count: 2,
      results: [
        { id: 22, display_name: 'Region one', state: 'ACTIVE' },
        { id: 33, display_name: 'Region two', state: 'ACTIVE' },
      ],
    });
  if (c.path.startsWith('/cloud/v1/loadbalancers/')) return jsonRes({ count: 0, results: [] });
  if (c.path.startsWith('/cloud/v1/networks/')) return jsonRes({ count: 0, results: [] });
  if (c.path.startsWith('/cloud/v1/subnets/')) return jsonRes({ count: 0, results: [] });
  if (c.path.startsWith('/cloud/v1/lbflavors/')) return jsonRes({ count: 0, results: [] });
  return jsonRes({}, 404);
};
const upcloudApi = (c: Captured) =>
  c.path === '/1.3/account'
    ? jsonRes({ account: { username: 'u' } })
    : c.path === '/1.3/zone'
      ? jsonRes({
          zones: {
            zone: [
              { id: 'de-fra1', description: 'Zone one' },
              { id: 'nl-ams1', description: 'Zone two' },
            ],
          },
        })
      : jsonRes({}, 404);
const scalewayApi = (c: Captured) =>
  c.path.startsWith('/lb/v1/zones/')
    ? jsonRes({ lbs: [], total_count: 0 })
    : c.path.startsWith('/iam/')
      ? jsonRes({
          access_key: 'SCWXXXXXXXXXXXXXXXXX',
          default_project_id: '66666666-7777-4888-8999-000000000000',
        })
      : jsonRes({}, 404);
/** OVH with one project; GRA9 has a private network with a subnet there, SBG5 has none. */
const ovhApi = (c: Captured) => {
  const p = c.path.replace(/^\/1\.0/, '');
  if (p === '/auth/time') return jsonRes(1_700_000_000);
  if (p === '/cloud/project') return jsonRes(['svc-a']);
  if (p === '/cloud/project/svc-a') return jsonRes({ description: 'Prod' });
  if (p === '/cloud/project/svc-a/region') return jsonRes(['GRA9', 'SBG5']);
  if (p === '/cloud/project/svc-a/network/private')
    return jsonRes([{ id: 'pn-1', name: 'vrack-a', regions: [{ region: 'GRA9' }] }]);
  if (p === '/cloud/project/svc-a/network/private/pn-1/subnet')
    return jsonRes([{ id: 'sn-1', cidr: '10.1.0.0/24', ipPools: [{ region: 'GRA9' }] }]);
  if (p.endsWith('/loadbalancing/flavor')) return jsonRes([]);
  return jsonRes({}, 404);
};

/** Each L4 provider's account as the account form now adds it: credentials and identifiers only. */
const CREDENTIALS_ONLY = {
  gcore: { settings: {}, credentials: { apiKey: 'k' }, api: gcoreApi, regions: ['22', '33'] },
  upcloud: {
    settings: {},
    credentials: { token: 't' },
    api: upcloudApi,
    regions: ['de-fra1', 'nl-ams1'],
  },
  scaleway: {
    settings: { accessKey: 'SCWXXXXXXXXXXXXXXXXX' },
    credentials: { secretKey: '11111111-2222-4333-8444-555555555555' },
    api: scalewayApi,
    regions: ['fr-par-1', 'fr-par-2', 'nl-ams-1'],
  },
  ovh: {
    settings: { applicationKey: 'ak', endpoint: 'ovh-eu' },
    credentials: { applicationSecret: 'as', consumerKey: 'ck' },
    api: ovhApi,
    regions: ['GRA9', 'SBG5'],
  },
} as const;

describe('a load balancer account of credentials alone', () => {
  test.each(Object.keys(CREDENTIALS_ONLY) as Array<keyof typeof CREDENTIALS_ONLY>)(
    '%s: no location, its test passes, and it lists the regions its key reaches',
    async (provider) => {
      const t = convexTest(schema, modules);
      const fx = CREDENTIALS_ONLY[provider];
      const id = await createAccount(t, {
        provider,
        name: `bare-${provider}`,
        settings: { ...fx.settings },
        credentials: { ...fx.credentials },
      });
      expect(await locationsOf(t, id)).toEqual([]);
      mockFetch(fx.api);
      const res = await t.action(internal.edgeProviderOps.testCredentials, { accountId: id });
      expect(res.ok).toBe(true);
      const row = (await t.run((c) => c.db.get(id)))!;
      expect(row.lastTestOkAt).toBeGreaterThan(0);
      expect(row.lastTestError).toBeUndefined();
      await t.action(internal.edgeProviderOps.refreshCatalog, { accountId: id, force: true });
      expect(await catalogRegions(t, id)).toEqual(expect.arrayContaining([...fx.regions]));
      // Still no location: one is made when a region is picked.
      expect(await locationsOf(t, id)).toEqual([]);
    },
  );
});

/** OVH with two projects: an account working in the second one lists ITS regions. */
const ovhTwoProjects = (c: Captured) => {
  const p = c.path.replace(/^\/1\.0/, '');
  if (p === '/auth/time') return jsonRes(1_700_000_000);
  if (p === '/cloud/project') return jsonRes(['svc-a', 'svc-b']);
  if (p === '/cloud/project/svc-a' || p === '/cloud/project/svc-b') return jsonRes({});
  if (p === '/cloud/project/svc-a/region') return jsonRes(['GRA9', 'SBG5']);
  if (p === '/cloud/project/svc-b/region') return jsonRes(['BHS5', 'WAW1']);
  if (p === '/cloud/project/svc-b/network/private')
    return jsonRes([
      { id: 'pn-9', name: 'vrack-b', regions: [{ region: 'BHS5' }, { region: 'WAW1' }] },
    ]);
  if (p === '/cloud/project/svc-b/network/private/pn-9/subnet')
    return jsonRes([
      { id: 'sn-9', cidr: '10.9.0.0/24', ipPools: [{ region: 'BHS5' }, { region: 'WAW1' }] },
    ]);
  if (p.endsWith('/loadbalancing/flavor')) return jsonRes([]);
  return jsonRes({}, 404);
};

describe('the regions offered are the ones of the project a pick creates in', () => {
  const catalogOffers = async (t: T, accountId: Id<'edgeProviderAccounts'>) =>
    (
      (await t.query(internal.edgeProviderCatalog.view, { accountId })).kinds.regions?.items ?? []
    ).map((r) => [r.id, r.facts?.project]);

  test("an account working in another project lists that project's regions, each naming it", async () => {
    const t = convexTest(schema, modules);
    const id = await createAccount(t, {
      provider: 'ovh',
      name: 'o',
      settings: { applicationKey: 'ak', endpoint: 'ovh-eu' },
      credentials: { applicationSecret: 'as', consumerKey: 'ck' },
    });
    mockFetch(ovhTwoProjects);
    // No location yet: the key's first project.
    await t.action(internal.edgeProviderOps.refreshCatalog, { accountId: id, force: true });
    expect(await catalogOffers(t, id)).toEqual([
      ['GRA9', 'svc-a'],
      ['SBG5', 'svc-a'],
    ]);
    // Working in the second project: its regions, not the first project's.
    await t.mutation(internal.edgeLocations.create, {
      accountId: id,
      placement: { serviceName: 'svc-b', regionName: 'BHS5', networkId: 'pn-9', subnetId: 'sn-9' },
      regionalParams: { flavorId: 'flavor-small' },
    });
    await t.action(internal.edgeProviderOps.refreshCatalog, { accountId: id, force: true });
    expect(await catalogOffers(t, id)).toEqual([
      ['BHS5', 'svc-b'],
      ['WAW1', 'svc-b'],
    ]);
    // A pick names the project it was offered in: the location is made there.
    const made = await t.action(internal.edgeProviderOps.createLocation, {
      accountId: id,
      placement: { regionName: 'WAW1', serviceName: 'svc-b' },
      fill: true,
      regionalParams: { flavorId: 'flavor-small' },
    });
    expect((await locationsOf(t, id)).find((l) => l.id === made.id)).toMatchObject({
      placement: { serviceName: 'svc-b', regionName: 'WAW1', networkId: 'pn-9', subnetId: 'sn-9' },
    });
  });

  test("gcore regions name the project they were probed in; the plan's offer carries it", async () => {
    const t = convexTest(schema, modules);
    const id = await createAccount(t, {
      provider: 'gcore',
      name: 'g',
      settings: {},
      credentials: { apiKey: 'k' },
    });
    const stub = mockFetch(gcoreApi);
    await t.action(internal.edgeProviderOps.refreshCatalog, { accountId: id, force: true });
    expect(await catalogOffers(t, id)).toEqual([
      ['22', '11'],
      ['33', '11'],
    ]);
    // Its locations all in the second project: the probes ask in it.
    await t.mutation(internal.edgeLocations.create, {
      accountId: id,
      placement: { projectId: 12, regionId: 22 },
    });
    stub.calls.length = 0;
    await t.action(internal.edgeProviderOps.refreshCatalog, { accountId: id, force: true });
    expect(await catalogOffers(t, id)).toEqual([
      ['22', '12'],
      ['33', '12'],
    ]);
    const probes = stub.calls.filter((c) => c.path.startsWith('/cloud/v1/loadbalancers/'));
    expect(probes.length).toBeGreaterThan(0);
    for (const c of probes) expect(c.path).toMatch(/^\/cloud\/v1\/loadbalancers\/12\//);
    const offers = await t.run(async (ctx) =>
      regionOffersOf(ctx.db, (await ctx.db.get(id))!, ['22']),
    );
    expect(offers).toEqual([{ id: '33', label: 'Region two', project: '12' }]);
  });
});

describe('a region picked creates its location, completed from what the key reaches', () => {
  test("gcore: the key's first project, or the one the account's locations already use", async () => {
    const t = convexTest(schema, modules);
    const id = await createAccount(t, {
      provider: 'gcore',
      name: 'g',
      settings: {},
      credentials: { apiKey: 'k' },
    });
    mockFetch(gcoreApi);
    const made = await t.action(internal.edgeProviderOps.createLocation, {
      accountId: id,
      placement: { regionId: 22 },
      fill: true,
    });
    expect(made.created).toBe(true);
    const [first] = await locationsOf(t, id);
    expect(first).toMatchObject({
      id: made.id,
      label: 'Region one',
      placeKey: '22',
      placement: { projectId: 11, regionId: 22 },
      qualified: false,
    });
    // The account's own project wins over the key's first one.
    await t.run((c) =>
      c.db.patch(made.id as Id<'edgeLocations'>, {
        placement: { type: 'gcore', projectId: 12, regionId: 22 } as never,
      }),
    );
    const second = await t.action(internal.edgeProviderOps.createLocation, {
      accountId: id,
      placement: { regionId: 33 },
      fill: true,
    });
    const row = (await locationsOf(t, id)).find((l) => l.id === second.id)!;
    expect(row.placement).toMatchObject({ projectId: 12, regionId: 33 });
    expect(row.qualified).toBe(false);
    // The form's "Change options" opens on the same completion, with the lists.
    const opts = await t.action(internal.edgeProviderOps.locationOptions, {
      accountId: id,
      placement: { regionId: 33 },
      defaults: true,
    });
    expect(opts.defaults).toEqual({ projectId: 12, regionId: 33 });
    expect(opts.missing).toEqual([]);
    expect(opts.projects?.map((p) => p.id)).toEqual(['11', '12']);
  });

  test('ovh: the project, and the private network and subnet that serve the region', async () => {
    const t = convexTest(schema, modules);
    const id = await createAccount(t, {
      provider: 'ovh',
      name: 'o',
      settings: { applicationKey: 'ak', endpoint: 'ovh-eu' },
      credentials: { applicationSecret: 'as', consumerKey: 'ck' },
    });
    mockFetch(ovhApi);
    // The balancer size is the region's own choice, never guessed: with a
    // template that names none, the pick asks for it (the form opens).
    await expect(
      t.action(internal.edgeProviderOps.createLocation, {
        accountId: id,
        placement: { regionName: 'GRA9' },
        fill: true,
      }),
    ).rejects.toThrow(/template_value_required/);
    const made = await t.action(internal.edgeProviderOps.createLocation, {
      accountId: id,
      placement: { regionName: 'GRA9' },
      fill: true,
      regionalParams: { flavorId: 'flavor-small' },
    });
    const [loc] = await locationsOf(t, id);
    expect(loc).toMatchObject({
      id: made.id,
      placeKey: 'GRA9',
      placement: { serviceName: 'svc-a', regionName: 'GRA9', networkId: 'pn-1', subnetId: 'sn-1' },
      qualified: false,
    });
    // A region no network of the key serves: the form must ask, nothing is made.
    await expect(
      t.action(internal.edgeProviderOps.createLocation, {
        accountId: id,
        placement: { regionName: 'SBG5' },
        fill: true,
        regionalParams: { flavorId: 'flavor-small' },
      }),
    ).rejects.toThrow(/location_options_needed/);
    const opts = await t.action(internal.edgeProviderOps.locationOptions, {
      accountId: id,
      placement: { regionName: 'SBG5' },
      defaults: true,
    });
    expect(opts.defaults).toEqual({ serviceName: 'svc-a', regionName: 'SBG5' });
    expect(opts.missing).toEqual(['networkId', 'subnetId']);
    expect(await locationsOf(t, id)).toHaveLength(1);
  });

  test('upcloud and scaleway: the region is the whole place; a region the key is not offered is refused', async () => {
    const t = convexTest(schema, modules);
    const up = await createAccount(t, {
      provider: 'upcloud',
      name: 'u',
      settings: {},
      credentials: { token: 't' },
    });
    mockFetch(upcloudApi);
    const made = await t.action(internal.edgeProviderOps.createLocation, {
      accountId: up,
      placement: { zone: 'nl-ams1' },
      fill: true,
    });
    expect((await locationsOf(t, up))[0]).toMatchObject({
      id: made.id,
      label: 'Zone two',
      placement: { zone: 'nl-ams1' },
    });
    await expect(
      t.action(internal.edgeProviderOps.createLocation, {
        accountId: up,
        placement: { zone: 'fi-hel2' },
        fill: true,
      }),
    ).rejects.toThrow(/location_not_offered/);
    const scw = await createAccount(t, {
      provider: 'scaleway',
      name: 's',
      settings: { accessKey: 'SCWXXXXXXXXXXXXXXXXX' },
      credentials: { secretKey: '11111111-2222-4333-8444-555555555555' },
    });
    mockFetch(scalewayApi);
    const z = await t.action(internal.edgeProviderOps.createLocation, {
      accountId: scw,
      placement: { zone: 'nl-ams-1' },
      fill: true,
    });
    // No Project id: the key's default project is used (the credential test reads it).
    expect((await locationsOf(t, scw))[0]).toMatchObject({
      id: z.id,
      placement: { zone: 'nl-ams-1' },
    });
  });
});

// --- the protect plan and a node's provider card -------------------------------------------------

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

async function planFor(t: T, serverId: Id<'backendServers'>, picks: string[] = []) {
  return t.action(internal.edgeSetupPlan.plan, {
    backendServerId: serverId,
    nodeUuid: NODE_UUID,
    ...(picks.length > 0 ? { picks } : {}),
  });
}

describe('the protect plan offers the regions an account reaches', () => {
  test('an account with no location is offered by its regions; a pick makes the location', async () => {
    const t = convexTest(schema, modules);
    const serverId = await insertPanelServer(t);
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
    __setPlanOpsForTests({
      listNodeInbounds: async () => [inboundA],
      listHosts: async () => [],
    });
    const id = await createAccount(t, {
      provider: 'upcloud',
      name: 'bare',
      settings: {},
      credentials: { token: 't' },
    });
    await t.mutation(internal.edgeProviderAccounts.recordTest, { id, ok: true });
    // Never listed: nothing to pick yet, the location form is the way on.
    const before = (await planFor(t, serverId)).accounts.find((a) => a.id === id)!;
    expect(before.compatible).toBe(false);
    expect(before.reasons).toContain('no_location');
    expect(before.regions).toEqual([]);
    // Listed: the account is offered by its regions.
    mockFetch(upcloudApi);
    await t.action(internal.edgeProviderOps.refreshCatalog, { accountId: id, force: true });
    const listed = (await planFor(t, serverId)).accounts.find((a) => a.id === id)!;
    expect(listed).toMatchObject({
      compatible: true,
      reasons: [],
      locations: [],
      regions: [
        { id: 'de-fra1', label: 'Zone one' },
        { id: 'nl-ams1', label: 'Zone two' },
      ],
    });
    // The pick: its location is made, then picked like any other.
    const made = await t.action(internal.edgeProviderOps.createLocation, {
      accountId: id,
      placement: { zone: 'nl-ams1' },
      fill: true,
    });
    const plan = await planFor(t, serverId, [made.id]);
    const after = plan.accounts.find((a) => a.id === id)!;
    expect(after.locations).toEqual([
      expect.objectContaining({ id: made.id, compatible: true, qualified: false }),
    ]);
    expect(after.regions).toEqual([{ id: 'de-fra1', label: 'Zone one' }]);
    expect(plan.set?.picks.map((p) => p.locationId)).toEqual([made.id]);
    expect(plan.set?.problems).toEqual([]);
  });

  test("a node's provider card offers them too, and names a location outside its set", async () => {
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t, { qualified: true, provider: 'upcloud' });
    await t.mutation(internal.edgeProviderAccounts.recordTest, { id: fx.accountId, ok: true });
    const [home] = await locationsOf(t, fx.accountId);
    await t.mutation(internal.edgeProviderCatalog.record, {
      accountId: fx.accountId,
      lists: [
        {
          kind: 'regions',
          items: [
            { id: 'de-fra1', label: 'Zone one' },
            { id: 'nl-ams1', label: 'Zone two' },
          ],
        },
      ],
      errors: [],
    });
    const view0 = await t.query(internal.edgeProviderSets.view, { relayId: fx.relayId });
    // The account's own place is a location already: only the other region is offered.
    expect(view0!.regions).toEqual([
      expect.objectContaining({ accountId: fx.accountId, regionId: 'nl-ams1', label: 'Zone two' }),
    ]);
    // A re-protect that failed left a spare in a location its set never took.
    const other = await t.mutation(internal.edgeLocations.create, {
      accountId: fx.accountId,
      placement: { zone: 'nl-ams1' },
      label: 'Zone two',
    });
    await t.run((c) =>
      c.db.patch(fx.relayId, {
        providerSet: [{ locationId: home!.id as Id<'edgeLocations'>, addedAt: Date.now() }],
      }),
    );
    await t.mutation(internal.relays.adoptEdge, {
      relayId: fx.relayId,
      listenerId: fx.listenerId,
      ipv4: '198.51.100.31',
      verified: true,
      accountId: fx.accountId,
      locationId: other.id as Id<'edgeLocations'>,
    });
    const view = await t.query(internal.edgeProviderSets.view, { relayId: fx.relayId });
    expect(view!.picks.map((p) => p.locationId)).toEqual([home!.id]);
    expect(view!.outside).toEqual([
      expect.objectContaining({ locationId: other.id, label: 'Zone two', inUse: 0, spare: 1 }),
    ]);
    // It is no region to offer any more: it is a location, offered to add.
    expect(view!.regions).toEqual([]);
    expect(view!.available.map((a) => a.locationId)).toContain(other.id);
  });
});

// --- "Owned by a setup run" after the run stopped ------------------------------------------------

describe("a setup veto reads the setup as it stands, not the detector's last pass", () => {
  test('setupVetoNow', () => {
    expect(setupVetoNow('setup_owned', { setupOwned: false, runLive: null })).toBeNull();
    expect(setupVetoNow('setup_owned', { setupOwned: true, runLive: false })).toBe('not_live');
    expect(setupVetoNow('not_live', { setupOwned: true, runLive: true })).toBe('setup_owned');
    expect(setupVetoNow('setup_owned', { setupOwned: true, runLive: null })).toBe('setup_owned');
    expect(setupVetoNow('cooldown', { setupOwned: false, runLive: false })).toBe('cooldown');
    expect(setupVetoNow(null, { setupOwned: true, runLive: true })).toBeNull();
  });

  test('the origin read drops "Owned by a setup run" once the run failed', async () => {
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t, { qualified: true, provider: 'upcloud' });
    const relay = (await t.run((c) => c.db.get(fx.relayId)))!;
    const suspicion = {
      state: 'clear' as const,
      hintLevel: 'none' as const,
      score: 0,
      reportScore: 0,
      loadScore: 0,
      probeScore: 0,
      scope: null,
      countries: [],
      edgeEvidence: [],
      firstSeenAt: null,
      lastEvalAt: Date.now(),
      quietEvals: 0,
      baselineWarm: false,
      veto: 'setup_owned',
    };
    // The detector's pass saw a run working; a re-protect that failed then
    // handed the origin back (setupOwned cleared) before any pass came.
    await t.run((c) => c.db.patch(fx.relayId, { suspicion, setupOwned: undefined }));
    const read = () => t.query(internal.edgeOperator.relayLookup, { slug: relay.slug });
    expect((await read())!.suspicion?.veto).toBeNull();
    expect((await read())!.setupOwned).toBe(false);
    // A first protection that failed keeps its origin owned: it is not live.
    await t.run(async (c) => {
      await c.db.patch(fx.relayId, {
        setupOwned: true,
        origin: { kind: 'panel-node', backendServerId: fx.serverId, nodeName: 'node-one' },
        backendServerId: fx.serverId,
        nodeName: 'node-one',
      } as never);
    });
    expect((await read())!.suspicion?.veto).toBe('not_live');
    const list = await t.query(internal.relays.listForAdmin, {});
    expect(list.find((r) => r.id === (fx.relayId as string))!.suspicion?.veto).toBe('not_live');
  });
});

describe('placement defaults (pure)', () => {
  test('the project the account uses, else the first listed; none listed and none used is missing', () => {
    const projects = [
      { id: '11', label: 'a' },
      { id: '12', label: 'b' },
    ];
    expect(projectDefault('gcore', projects, [])).toBe('11');
    expect(projectDefault('gcore', projects, [{ projectId: 12 }, { projectId: 12 }])).toBe('12');
    // Two projects in use: no single answer, the key's first.
    expect(projectDefault('gcore', projects, [{ projectId: 11 }, { projectId: 12 }])).toBe('11');
    // A project the key no longer lists is not reused.
    expect(projectDefault('gcore', projects, [{ projectId: 99 }])).toBe('11');
    // The listing failed: the account's own still stands.
    expect(projectDefault('ovh', undefined, [{ serviceName: 'svc-a' }])).toBe('svc-a');
    expect(projectDefault('upcloud', projects, [])).toBeNull();
    expect(completePlacement('gcore', { regionId: '22' }, {})).toEqual({
      placement: { regionId: 22 },
      missing: ['projectId'],
    });
  });

  test("OVH's network: the chosen one's first subnet, else the first network with a subnet", () => {
    const networks = [
      { id: 'pn-0', label: 'empty', subnets: [] },
      { id: 'pn-1', label: 'a', subnets: [{ id: 'sn-1', label: '10.1.0.0/24' }] },
    ];
    expect(networkDefault(networks)).toEqual({ networkId: 'pn-1', subnetId: 'sn-1' });
    expect(networkDefault(networks, 'pn-0')).toBeNull();
    expect(
      completePlacement(
        'ovh',
        { regionName: 'GRA9', serviceName: 'svc-a', networkId: 'pn-1' },
        { networks },
      ),
    ).toEqual({
      placement: { regionName: 'GRA9', serviceName: 'svc-a', networkId: 'pn-1', subnetId: 'sn-1' },
      missing: [],
    });
    // What was chosen is never replaced.
    expect(
      completePlacement(
        'gcore',
        { regionId: 22, projectId: 12 },
        { projects: [{ id: '11', label: 'a' }] },
      ).placement,
    ).toEqual({ regionId: 22, projectId: 12 });
  });
});
