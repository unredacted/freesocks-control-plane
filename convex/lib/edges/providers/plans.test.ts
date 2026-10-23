/**
 * Every load balancer adapter's price source (`EdgeProvider.plans`,
 * docs/edges.md § "Plans and prices"), against fake answers shaped like the
 * documented ones and two recorded public catalogs (trimmed, read 2026-10-22):
 *
 *  - Gcore: the flavor list with `include_prices=true`; the v2 price preview
 *    for a flavor the list does not price;
 *  - UpCloud: the account's price list for the zone, else the pricing page's
 *    dated table. Its fixtures follow UpCloud's recorded answers: the plan
 *    list is a bare array (the `development` and `production-small` rows as
 *    upcloud-go-api records them in `getloadbalancerplans.yaml`), the price
 *    list is `prices.zone[]` with `{ amount, price }` items in cents an hour
 *    (trimmed from its `getpricezones.yaml`, zone names replaced). UpCloud
 *    does not document a load balancer plan's price key:
 *    `managed_load_balancer_<plan>` is FCP's assumption, and the reader takes
 *    every spelling of it;
 *  - OVHcloud: the flavor list joined by name to the public cloud catalog
 *    (micro-cents);
 *  - Scaleway: the public product catalog, else the zone's size list priced
 *    from the dated table.
 *
 * Nothing secret reaches a plan, and no price source creates anything.
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { gcoreProvider } from './gcore';
import {
  UPCLOUD_BILLED_HOURS_PER_MONTH,
  UPCLOUD_LB_PRICES,
  upcloudPlanListOf,
  upcloudProvider,
  upcloudZonePricesOf,
} from './upcloud';
import { EdgeProviderError } from './http';
import {
  __resetOvhCatalogCache,
  __resetOvhSkewCache,
  ovhLbCatalogOf,
  ovhPlanOf,
  ovhProvider,
  ovhTrafficOf,
} from './ovh';
import {
  SCALEWAY_LB_PRICES,
  __setScalewayApiFactory,
  __setScalewayCatalogFactory,
  scalewayIpv4PriceOf,
  scalewayOffersOf,
  scalewayProvider,
  scalewayTablePlans,
} from './scaleway';
import type { GcoreConfig, OvhConfig, ScalewayConfig, UpcloudConfig } from './types';
import { jsonRes, mockFetch } from '../testing/mockFetch';
import { EDGE_PROVIDERS } from './registry';
import { edgeLayerOf } from './capabilities';
import { EDGE_PROVIDER_IDS } from '../../edgeProviderIds';
import ovhCatalog from './fixtures/pricing/ovh_public_cloud_catalog_lb.json';
import scalewayCatalog from './fixtures/pricing/scaleway_catalog_lb_zone.json';
import upcloudPlansFixture from './fixtures/pricing/upcloud_load_balancer_plans.json';
import upcloudPriceFixture from './fixtures/pricing/upcloud_price.json';

afterEach(() => {
  vi.unstubAllGlobals();
  __setScalewayApiFactory(null);
  __setScalewayCatalogFactory(null);
});
beforeEach(() => {
  __resetOvhSkewCache();
  __resetOvhCatalogCache();
});

const notFound = () => jsonRes({ message: 'not found' }, 404);

describe('gcore: the priced flavor list, the price preview for what it hides', () => {
  const cfg: GcoreConfig = {
    type: 'gcore',
    apiKey: 'SECRET_GCORE_KEY',
    projectId: 11,
    regionId: 22,
  };

  test('every flavor priced from `include_prices=true`; a hidden price asks the v2 preview', async () => {
    const stub = mockFetch((c) => {
      if (c.path === '/cloud/v1/lbflavors/11/22' && c.method === 'GET')
        return jsonRes({
          count: 2,
          results: [
            {
              flavor_id: 'lb1-1-2',
              flavor_name: 'lb1-1-2',
              ram: 2048,
              vcpus: 1,
              price_per_hour: 0.0208,
              price_per_month: 15,
              currency_code: 'EUR',
              price_status: 'show',
            },
            {
              flavor_id: 'lb1-2-4',
              flavor_name: 'lb1-2-4',
              ram: 4096,
              vcpus: 2,
              price_per_hour: null,
              price_per_month: null,
              currency_code: null,
              price_status: 'hide',
            },
          ],
        });
      if (c.path === '/cloud/v2/pricing/11/22/loadbalancers' && c.method === 'POST')
        return jsonRes({
          currency_code: 'EUR',
          per_hour: { flavor: 0.0416, external_ip: 0.004, floating_ip: 0 },
          per_month: { flavor: 30, external_ip: 2.88, floating_ip: 0 },
          price_status: 'show',
          total_price_per_hour: 0.05,
          total_price_per_month: 39.6,
          price_without_discount_per_month: 39.6,
          discount_percent: 0,
          tax_percent: 20,
        });
      return notFound();
    });
    const plans = await gcoreProvider.plans!(cfg);
    expect(plans).toEqual([
      {
        size: 'lb1-1-2',
        label: 'lb1-1-2 (1 vCPU, 2 GiB)',
        perHour: 0.0208,
        perMonth: 15,
        currency: 'EUR',
        traffic: { kind: 'unknown' },
        bandwidthMbps: null,
        acceptsOutsideNode: null,
        source: 'api',
      },
      expect.objectContaining({ size: 'lb1-2-4', perHour: 0.0416, perMonth: 30, currency: 'EUR' }),
    ]);
    expect(stub.calls[0]!.query).toBe('?include_prices=true');
    expect(stub.calls[0]!.headers.authorization).toBe('APIKey SECRET_GCORE_KEY');
    // Only the hidden flavor is previewed, and the preview names it alone.
    const previews = stub.calls.filter((c) => c.method === 'POST');
    expect(previews.map((c) => c.body)).toEqual([{ flavor: 'lb1-2-4' }]);
    expect(JSON.stringify(plans)).not.toContain('SECRET_GCORE_KEY');
  });

  test('a preview that fails or hides too leaves the flavor unpriced; a failed list throws', async () => {
    mockFetch((c) => {
      if (c.path === '/cloud/v1/lbflavors/11/22')
        return jsonRes({ results: [{ flavor_name: 'lb1-1-2', price_status: 'error' }] });
      return jsonRes({ price_status: 'hide', currency_code: null }, 200);
    });
    expect((await gcoreProvider.plans!(cfg))[0]).toMatchObject({
      size: 'lb1-1-2',
      perHour: null,
      perMonth: null,
      currency: null,
    });
    mockFetch(() => jsonRes({ message: 'down' }, 503));
    await expect(gcoreProvider.plans!(cfg)).rejects.toThrow(/503/);
  });
});

describe('upcloud: the price list for the zone, else the pricing page', () => {
  const cfg: UpcloudConfig = { type: 'upcloud', token: 'SECRET_UC_TOKEN', zone: 'zz-zone1' };
  /** A plan's monthly price: UpCloud bills an hourly price for at most 672 hours a month. */
  const monthly = (centsAnHour: number) =>
    Math.round((centsAnHour / 100) * UPCLOUD_BILLED_HOURS_PER_MONTH * 100) / 100;

  /** The account's own answers: its username, then its details (the billing currency). */
  const account = (currency: string | null) => (c: { path: string }) =>
    c.path === '/1.3/account'
      ? jsonRes({ account: { username: 'uc-user', credits: 0 } })
      : c.path === '/1.3/account/details/uc-user'
        ? currency === null
          ? jsonRes({ error: { error_code: 'ACCOUNT_FORBIDDEN' } }, 403)
          : jsonRes({ account: { username: 'uc-user', country: 'ZZZ', currency } })
        : null;

  /** UpCloud as the recorded fixtures answer it, with any route overridden. */
  const upcloud =
    (over: { plans?: unknown; price?: unknown; currency?: string | null } = {}) =>
    (c: { path: string }) => {
      if (c.path === '/1.3/load-balancer/plans') return jsonRes(over.plans ?? upcloudPlansFixture);
      if (c.path === '/1.3/price') return jsonRes(over.price ?? upcloudPriceFixture);
      return account(over.currency === undefined ? 'EUR' : over.currency)(c) ?? notFound();
    };

  test('every plan of the recorded answers is priced from its zone, a month being 672 hours', async () => {
    const stub = mockFetch(upcloud());
    const plans = await upcloudProvider.plans!(cfg);
    expect(plans.map((p) => p.size)).toEqual([
      'development',
      'production-small',
      'production-medium',
      'essentials',
    ]);
    expect(plans[0]).toEqual({
      size: 'development',
      label: 'development (1 node, 1,000 sessions each)',
      perHour: 0.014881,
      perMonth: 10,
      currency: 'EUR',
      traffic: { kind: 'unlimited' },
      bandwidthMbps: null,
      acceptsOutsideNode: null,
      source: 'api',
    });
    // The pricing page's monthly figures, read back from cents an hour.
    expect(plans.map((p) => [p.size, p.perMonth, p.source])).toEqual([
      ['development', 10, 'api'],
      ['production-small', 30, 'api'],
      ['production-medium', 75, 'api'],
      ['essentials', 0, 'api'],
    ]);
    expect(plans[1]!.label).toBe('production-small (2 nodes, 50,000 sessions each)');
    // The plan list is read page by page, and nothing is written.
    const listed = stub.calls.filter((c) => c.path === '/1.3/load-balancer/plans');
    expect(listed.map((c) => c.query)).toEqual(['?limit=100&offset=0']);
    expect(stub.calls.every((c) => c.method === 'GET')).toBe(true);
    expect(JSON.stringify(plans)).not.toContain('SECRET_UC_TOKEN');
  });

  test("only the location's zone prices it: another zone's list never does", async () => {
    mockFetch(upcloud());
    const plans = await upcloudProvider.plans!({ ...cfg, zone: 'zz-zone2' });
    expect(plans.map((p) => [p.size, p.perMonth, p.currency, p.source])).toEqual([
      ['development', monthly(1.6369), 'EUR', 'api'],
      ['production-small', monthly(4.9107), 'EUR', 'api'],
      // Not named in this zone's list: the pricing page's dated table.
      [
        'production-medium',
        UPCLOUD_LB_PRICES.monthly['production-medium'],
        UPCLOUD_LB_PRICES.currency,
        'catalog',
      ],
      ['essentials', UPCLOUD_LB_PRICES.monthly.essentials, UPCLOUD_LB_PRICES.currency, 'catalog'],
    ]);
    expect(plans[0]!.perMonth).toBe(11);
    // A zone the list does not hold at all: the table for every plan.
    mockFetch(upcloud());
    const elsewhere = await upcloudProvider.plans!({ ...cfg, zone: 'zz-zone9' });
    expect(elsewhere.every((p) => p.source === 'catalog')).toBe(true);
    expect(elsewhere.find((p) => p.size === 'production-small')?.perMonth).toBe(30);
  });

  test('a plan in neither the list nor the table has no known price, and the read still answers', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    mockFetch(
      upcloud({
        plans: [
          ...upcloudPlansFixture,
          { name: 'something-new', per_server_max_sessions: 1000, server_number: 1 },
        ],
      }),
    );
    const plans = await upcloudProvider.plans!(cfg);
    expect(plans.find((p) => p.size === 'something-new')).toEqual({
      size: 'something-new',
      label: 'something-new (1 node, 1,000 sessions each)',
      perHour: null,
      perMonth: null,
      currency: null,
      traffic: { kind: 'unlimited' },
      bandwidthMbps: null,
      acceptsOutsideNode: null,
      source: 'api',
    });
    expect(plans.filter((p) => p.perMonth !== null)).toHaveLength(4);
    // The log names the plan and the zone's other item keys, never a price or the key.
    expect(warn).toHaveBeenCalledTimes(1);
    const said = String(warn.mock.calls[0]![0]);
    expect(said).toContain('something-new');
    expect(said).toContain('ipv4_address');
    expect(said).not.toContain('server_plan_');
    expect(said).not.toContain('SECRET_UC_TOKEN');
    expect(said).not.toMatch(/\d\.\d/);
    warn.mockRestore();
  });

  test('a price list whose currency cannot be read is not used: the table answers', async () => {
    mockFetch(upcloud({ currency: null }));
    const plans = await upcloudProvider.plans!(cfg);
    expect(plans.find((p) => p.size === 'production-small')).toMatchObject({
      perMonth: 30,
      currency: 'EUR',
      source: 'catalog',
      catalogAsOf: UPCLOUD_LB_PRICES.asOf,
    });
  });

  test('a price list that cannot be read, or is not the documented shape, falls back to the table', async () => {
    mockFetch((c) =>
      c.path === '/1.3/load-balancer/plans' ? jsonRes(upcloudPlansFixture) : jsonRes({}, 401),
    );
    const plans = await upcloudProvider.plans!(cfg);
    expect(plans.every((p) => p.source === 'catalog')).toBe(true);
    for (const price of [{}, { prices: { zone: 'not a list' } }, []]) {
      mockFetch(upcloud({ price }));
      const read = await upcloudProvider.plans!(cfg);
      expect(read.find((p) => p.size === 'development')).toMatchObject({
        perMonth: 10,
        source: 'catalog',
      });
    }
  });

  test('a plan list that is not a list of named plans fails the read with plan_list_unreadable', async () => {
    // The shape this adapter once expected: UpCloud answers a bare array.
    for (const plans of [{ plans: upcloudPlansFixture }, [{ per_server_max_sessions: 1 }]]) {
      mockFetch(upcloud({ plans }));
      const err = await upcloudProvider.plans!(cfg).then(
        () => null,
        (e: unknown) => e,
      );
      expect(err).toBeInstanceOf(EdgeProviderError);
      expect((err as EdgeProviderError).meta).toMatchObject({
        provider: 'upcloud',
        step: 'plans',
        code: 'plan_list_unreadable',
        retryable: false,
      });
    }
    expect(() => upcloudPlanListOf({ plans: [] })).toThrow(/not a list/);
    expect(() => upcloudPlanListOf([{ name: 'development' }, { name: '' }])).toThrow(
      /plan 2 has no name/,
    );
  });

  test('the plan list keeps fields UpCloud adds and reads past its first page', async () => {
    expect(
      upcloudPlanListOf([
        { name: 'development', server_number: '1', per_server_max_sessions: null, zones: [] },
      ]),
    ).toEqual([
      { name: 'development', server_number: null, per_server_max_sessions: null, zones: [] },
    ]);
    const many = Array.from({ length: 130 }, (_, i) => ({ name: `plan-${i}` }));
    const stub = mockFetch((c) => {
      if (c.path !== '/1.3/load-balancer/plans') return upcloud()(c);
      const q = new URLSearchParams(c.query);
      const offset = Number(q.get('offset') ?? 0);
      return jsonRes(many.slice(offset, offset + Math.min(Number(q.get('limit') ?? 10), 100)));
    });
    expect(await upcloudProvider.plans!(cfg)).toHaveLength(130);
    expect(
      stub.calls.filter((c) => c.path === '/1.3/load-balancer/plans').map((c) => c.query),
    ).toEqual(['?limit=100&offset=0', '?limit=100&offset=100']);
  });

  test('the inventory lists the plans as sizes, and an unreadable list leaves none', async () => {
    mockFetch((c) => (c.path === '/1.3/load-balancer' ? jsonRes([]) : upcloud()(c)));
    expect((await upcloudProvider.inventory(cfg)).flavors).toEqual(
      upcloudPlansFixture.map((p) => ({ id: p.name, label: p.name })),
    );
    mockFetch((c) =>
      c.path === '/1.3/load-balancer' ? jsonRes([]) : upcloud({ plans: { plans: [] } })(c),
    );
    expect((await upcloudProvider.inventory(cfg)).flavors).toEqual([]);
  });

  test('the zone price reader: every spelling of the product key, units, and items skipped', () => {
    const read = upcloudZonePricesOf(
      {
        prices: {
          currency: 'usd',
          zone: [
            'not a zone',
            { description: 'no name' },
            {
              name: 'zz-zone1',
              load_balancer_development: { amount: 1, price: 1.5 },
              'LoadBalancer_Production-Small': { amount: 2, price: 9 },
              'managed_load_balancer_plan_production-medium': { amount: 1, price: 11 },
              managed_load_balancer_essentials: { price: 'free' },
              'server_plan_1xCPU-1GB': { amount: 1, price: 1.0416 },
              managed_kubernetes_control_plane: { amount: 1, price: 4 },
              ipv4_address: { amount: 1, price: 0.336 },
            },
          ],
        },
      },
      'zz-zone1',
    );
    expect(read).toEqual({
      currency: 'USD',
      plans: new Map([
        ['development', 0.015],
        ['production_small', 0.045],
        ['production_medium', 0.11],
      ]),
      otherKeys: ['ipv4_address', 'managed_kubernetes_control_plane'],
    });
    expect(upcloudZonePricesOf(upcloudPriceFixture, 'zz-zone9')).toEqual({
      currency: null,
      plans: null,
      otherKeys: [],
    });
    expect(upcloudZonePricesOf({ prices: [] }, 'zz-zone1')).toBeNull();
    expect(upcloudZonePricesOf('<html>', 'zz-zone1')).toBeNull();
  });
});

describe('ovh: the public cloud catalog, joined to the region’s flavors by name', () => {
  const cfg: OvhConfig = {
    type: 'ovh',
    applicationKey: 'ak',
    applicationSecret: 'SECRET_OVH_AS',
    consumerKey: 'SECRET_OVH_CK',
    endpoint: 'ovh-eu',
    serviceName: 'svc',
    regionName: 'ZZ1',
    networkId: 'net',
    subnetId: 'sub',
  };

  test('the recorded catalog: hourly and monthly prices in micro-cents, bandwidth per size', () => {
    const c = ovhLbCatalogOf(ovhCatalog as never);
    expect(c.currency).toBe('EUR');
    expect(c.sizes.small).toEqual({ perHour: 0.0083, perMonth: 6, bandwidthMbps: 200 });
    expect(c.sizes.medium).toEqual({ perHour: 0.0208, perMonth: 15, bandwidthMbps: 500 });
    expect(c.sizes.large).toEqual({ perHour: 0.0556, perMonth: 40, bandwidthMbps: 2000 });
    expect(c.sizes.xl).toEqual({ perHour: 0.2083, perMonth: 150, bandwidthMbps: 4000 });
    // The floating IP each balancer gets: priced apart, never a size.
    expect(Object.keys(c.sizes).sort()).toEqual(['large', 'medium', 'small', 'xl']);
    expect(c.floatingIp).toEqual({ perHour: 0.0027, perMonth: 1.8 });
  });

  test('traffic: included, but past 1 TB a month in the Asia-Pacific regions', () => {
    expect(ovhTrafficOf('GRA11')).toEqual({ kind: 'unlimited' });
    expect(ovhTrafficOf('SGP1')).toEqual({ kind: 'included', includedGb: 1000 });
    expect(ovhTrafficOf('AP-SOUTH-MUM-1')).toEqual({ kind: 'included', includedGb: 1000 });
  });

  test('plans: the flavor ids priced by name with the floating IP added; the catalog read once, without the keys', async () => {
    const stub = mockFetch((c) => {
      if (c.path.endsWith('/auth/time')) return jsonRes(1_700_000_000);
      if (c.path === '/1.0/me') return jsonRes({ ovhSubsidiary: 'FR' });
      if (c.path === '/1.0/order/catalog/public/cloud') return jsonRes(ovhCatalog);
      if (c.path === '/1.0/cloud/project/svc/region/ZZ1/loadbalancing/flavor')
        return jsonRes([
          { id: 'f-small', name: 'small', region: 'ZZ1' },
          { id: 'f-large', name: 'large', region: 'ZZ1' },
          { id: 'f-odd', name: 'odd', region: 'ZZ1' },
        ]);
      return notFound();
    });
    const plans = await ovhProvider.plans!(cfg);
    expect(plans).toEqual([
      {
        size: 'f-small',
        label: 'small',
        perHour: 0.011,
        perMonth: 7.8,
        currency: 'EUR',
        traffic: { kind: 'unlimited' },
        bandwidthMbps: 200,
        acceptsOutsideNode: null,
        source: 'api',
      },
      expect.objectContaining({ size: 'f-large', perHour: 0.0583, perMonth: 41.8 }),
      expect.objectContaining({ size: 'f-odd', perHour: null, currency: null }),
    ]);
    const catalogCall = stub.calls.find((c) => c.path === '/1.0/order/catalog/public/cloud')!;
    expect(catalogCall.query).toBe('?ovhSubsidiary=FR');
    // The public catalog is asked without the account's signature.
    expect(Object.keys(catalogCall.headers).some((h) => h.startsWith('x-ovh'))).toBe(false);
    await ovhProvider.plans!(cfg);
    expect(stub.calls.filter((c) => c.path === '/1.0/order/catalog/public/cloud')).toHaveLength(1);
  });

  test('a key that may not read /me is priced in its endpoint’s subsidiary', async () => {
    const stub = mockFetch((c) => {
      if (c.path.endsWith('/auth/time')) return jsonRes(1_700_000_000);
      if (c.path === '/1.0/me') return jsonRes({ message: 'forbidden' }, 403);
      if (c.path === '/1.0/order/catalog/public/cloud') return jsonRes(ovhCatalog);
      return jsonRes([{ id: 'f-small', name: 'small' }]);
    });
    const plans = await ovhProvider.plans!({ ...cfg, endpoint: 'ovh-ca' });
    expect(plans[0]).toMatchObject({ currency: 'EUR', perHour: 0.011 });
    expect(stub.calls.find((c) => c.path.endsWith('/catalog/public/cloud'))!.url).toContain(
      'ca.api.ovh.com/1.0/order/catalog/public/cloud?ovhSubsidiary=CA',
    );
  });

  test('a failing catalog read waits for the flavor list: nothing is left running', async () => {
    let flavorsAnswered = false;
    mockFetch(async (c) => {
      if (c.path.endsWith('/auth/time')) return jsonRes(1_700_000_000);
      if (c.path === '/1.0/order/catalog/public/cloud') return jsonRes({ message: 'down' }, 503);
      if (c.path.endsWith('/loadbalancing/flavor')) {
        await new Promise((r) => setTimeout(r, 20));
        flavorsAnswered = true;
        return jsonRes([{ id: 'f-small', name: 'small' }]);
      }
      return notFound();
    });
    await expect(ovhProvider.plans!(cfg)).rejects.toThrow(/503/);
    expect(flavorsAnswered).toBe(true);
  });

  test('a flavor the catalog does not name has no price', () => {
    expect(
      ovhPlanOf({ id: 'x', name: 'tiny' }, { currency: 'EUR', sizes: {}, floatingIp: null }, 'ZZ1'),
    ).toMatchObject({ perHour: null, perMonth: null, currency: null });
    // A catalog with no floating IP: the balancer's own price alone.
    expect(
      ovhPlanOf(
        { id: 'f', name: 'small' },
        {
          currency: 'EUR',
          sizes: { small: { perHour: 0.0083, perMonth: 6, bandwidthMbps: 200 } },
          floatingIp: null,
        },
        'ZZ1',
      ),
    ).toMatchObject({ perHour: 0.0083, perMonth: 6 });
  });
});

describe('scaleway: the public product catalog, else the dated table', () => {
  const cfg: ScalewayConfig = {
    type: 'scaleway',
    accessKey: 'SCWXXXXXXXXXXXXXXXXX',
    secretKey: 'SECRET_SCW_KEY',
    zone: 'fr-par-1',
  };

  test('the recorded catalog: each offer’s hourly price, bandwidth and multi-cloud flag', () => {
    const offers = scalewayOffersOf(scalewayCatalog as never, 'fr-par-1');
    expect(offers.map((o) => [o.type, o.perHour, o.bandwidthMbps, o.multicloud])).toEqual([
      ['LB-GP-L', 0.094, 1000, true],
      ['LB-GP-M', 0.054, 500, false],
      ['LB-GP-XL', 0.941, 4000, true],
      ['LB-S', 0.023, 200, false],
    ]);
    expect(offers.every((o) => o.currency === 'EUR')).toBe(true);
    // Another zone's products are not this location's.
    expect(scalewayOffersOf(scalewayCatalog as never, 'zz-zone-9')).toEqual([]);
    // The "Load Balancer IP": what each IPv4 an edge allocates costs an hour.
    expect(scalewayIpv4PriceOf(scalewayCatalog as never, 'fr-par-1')).toBe(0.005);
  });

  test('plans from the catalog with the IPv4 each edge allocates, asked without credentials', async () => {
    const stub = mockFetch((c) =>
      c.path === '/product-catalog/v2alpha1/public-catalog/products'
        ? jsonRes(scalewayCatalog)
        : notFound(),
    );
    const plans = await scalewayProvider.plans!(cfg);
    expect(plans.find((p) => p.size === 'LB-GP-L')).toEqual({
      size: 'LB-GP-L',
      label: 'LB-GP-L',
      perHour: 0.099,
      perMonth: null,
      currency: 'EUR',
      traffic: { kind: 'unlimited' },
      bandwidthMbps: 1000,
      acceptsOutsideNode: true,
      source: 'api',
    });
    expect(plans.find((p) => p.size === 'LB-S')).toMatchObject({ acceptsOutsideNode: false });
    const call = stub.calls[0]!;
    expect(call.query).toContain('product_types=load_balancer');
    expect(call.query).toContain('zone=fr-par-1');
    expect(Object.keys(call.headers)).not.toContain('x-auth-token');
  });

  test('the catalog failing: the zone’s size list priced from the table (its own flags win)', async () => {
    __setScalewayCatalogFactory(() => ({
      loadBalancerOffers: async (): Promise<never> => {
        throw new Error('alpha API gone');
      },
    }));
    const list = (items: unknown[]) =>
      Object.assign(Promise.resolve({}), { all: async () => items });
    __setScalewayApiFactory(
      () =>
        ({
          listLbTypes: vi.fn(() =>
            list([
              { name: 'LB-S', bandwidth: 200_000_000, multicloud: false },
              { name: 'LB-GP-L', bandwidth: 1_000_000_000, multicloud: true },
            ]),
          ),
        }) as never,
    );
    const plans = await scalewayProvider.plans!(cfg);
    expect(plans).toEqual([
      expect.objectContaining({
        size: 'LB-S',
        perHour: 0.028,
        acceptsOutsideNode: false,
        source: 'catalog',
        catalogAsOf: SCALEWAY_LB_PRICES.asOf,
      }),
      expect.objectContaining({ size: 'LB-GP-L', perHour: 0.099, acceptsOutsideNode: true }),
    ]);
  });

  test('with no size list either, every size of the table', () => {
    expect(scalewayTablePlans(null).map((p) => [p.size, p.acceptsOutsideNode])).toEqual([
      ['LB-S', false],
      ['LB-GP-M', false],
      ['LB-GP-L', true],
      ['LB-GP-XL', true],
    ]);
    // A size the table does not know is listed, unpriced.
    expect(scalewayTablePlans([{ name: 'LB-NEW' }])[0]).toMatchObject({
      perHour: null,
      currency: null,
    });
  });
});

describe('which adapters price', () => {
  test('every load balancer adapter has a price source; no CDN adapter is ever auto-priced', () => {
    for (const id of EDGE_PROVIDER_IDS) {
      const priced = typeof EDGE_PROVIDERS[id].plans === 'function';
      expect([id, priced]).toEqual([id, edgeLayerOf(id) === 'l4']);
    }
  });
});
