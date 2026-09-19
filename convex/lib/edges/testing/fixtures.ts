/**
 * Shared convex-test fixtures for the edges area (generic-relay model). Every
 * value is RFC 5737 / RFC 3849 / `*.example`; nothing here names a real
 * deployment. Tests import `seedEdgeFixture` and reach for the ids they need.
 *
 *   backend server `panel-a` (remnawave) -> account `acct-a` (gcore, unqualified
 *   by default) -> relay `node-one` (panel-node origin, listener `a`:
 *   vless/raw/reality on 443 with two names and a target).
 */
import type { TestConvex } from 'convex-test';
import { internal } from '../../../_generated/api';
import type { Id } from '../../../_generated/dataModel';
import type schema from '../../../schema';

type T = TestConvex<typeof schema>;

export const FIXTURE_PANEL_SLUG = 'panel-a';
export const FIXTURE_RELAY_SLUG = 'node-one';
export const FIXTURE_NODE = 'node-one';
export const FIXTURE_ORIGIN = '203.0.113.10';
export const FIXTURE_INBOUND = '22222222-2222-4222-8222-222222222222';
export const FIXTURE_CONFIG_PROFILE = '11111111-1111-4111-8111-111111111111';

export interface ListenerSpecFixture {
  listenerKey: string;
  protocol: 'vless' | 'trojan' | 'shadowsocks' | 'hysteria2' | 'tuic';
  streamTransport: 'raw' | 'ws' | 'httpupgrade' | 'grpc' | 'xhttp' | 'udp';
  security: 'none' | 'tls' | 'reality';
  originPort: number;
  tlsNames?: string[];
  realityTarget?: { address: string; port: number };
  transportParams?: {
    path?: string;
    host?: string;
    serviceName?: string;
    upgradeToken?: string;
    mode?: string;
  };
  originTransport?: {
    scheme: 'http' | 'https';
    certPublic: boolean;
    certNames: string[];
    acceptsHostHeader: 'any' | 'names';
  };
  panelBinding?: {
    inboundTag: string;
    configProfileUuid: string;
    configProfileInboundUuid: string;
  };
  matchRule?: { kind: 'remark'; remark: string } | { kind: 'address' } | { kind: 'whole-body' };
  providerScope?: {
    provider: 'gcore' | 'upcloud' | 'scaleway' | 'ovh' | 'cloudflare' | 'fastly';
    accountId?: Id<'edgeProviderAccounts'>;
  };
  deployed?: boolean;
}

/** The default REALITY listener the old "slot a on profile prof-a" fixture described. */
export function realityListener(overrides: Partial<ListenerSpecFixture> = {}): ListenerSpecFixture {
  return {
    listenerKey: 'a',
    protocol: 'vless',
    streamTransport: 'raw',
    security: 'reality',
    originPort: 443,
    tlsNames: ['a.example', 'b.example'],
    realityTarget: { address: 'target.example', port: 443 },
    panelBinding: {
      inboundTag: 'VLESS_RELAY_A',
      configProfileUuid: FIXTURE_CONFIG_PROFILE,
      configProfileInboundUuid: FIXTURE_INBOUND,
    },
    ...overrides,
  };
}

/** A VLESS-over-WebSocket listener behind an HTTPS origin (L4 and L7 frontable). */
export function wsListener(overrides: Partial<ListenerSpecFixture> = {}): ListenerSpecFixture {
  return {
    listenerKey: 'w',
    protocol: 'vless',
    streamTransport: 'ws',
    security: 'tls',
    originPort: 443,
    tlsNames: ['ws.example'],
    transportParams: { path: '/ws' },
    originTransport: {
      scheme: 'https',
      certPublic: true,
      certNames: ['ws.example'],
      acceptsHostHeader: 'any',
    },
    panelBinding: {
      inboundTag: 'VLESS_WS',
      configProfileUuid: FIXTURE_CONFIG_PROFILE,
      configProfileInboundUuid: '33333333-3333-4333-8333-333333333333',
    },
    ...overrides,
  };
}

/** A Shadowsocks listener (no names, no target; address/port rewrite only). */
export function shadowsocksListener(
  overrides: Partial<ListenerSpecFixture> = {},
): ListenerSpecFixture {
  return {
    listenerKey: 's',
    protocol: 'shadowsocks',
    streamTransport: 'raw',
    security: 'none',
    originPort: 8388,
    panelBinding: {
      inboundTag: 'SS_IN',
      configProfileUuid: FIXTURE_CONFIG_PROFILE,
      configProfileInboundUuid: '44444444-4444-4444-8444-444444444444',
    },
    ...overrides,
  };
}

export async function insertPanelServer(
  t: T,
  opts: { slug?: string; backend?: 'remnawave' | 'outline' } = {},
): Promise<Id<'backendServers'>> {
  const slug = opts.slug ?? FIXTURE_PANEL_SLUG;
  const backend = opts.backend ?? 'remnawave';
  return t.run((ctx) =>
    ctx.db.insert('backendServers', {
      backend,
      name: slug,
      slug,
      config:
        backend === 'remnawave'
          ? { type: 'remnawave', baseUrl: 'https://panel.example', apiToken: 'tok' }
          : { type: 'outline', apiUrl: 'https://outline.example/secret', websocketEnabled: false },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: Date.now(),
    }),
  );
}

export async function createAccount(
  t: T,
  opts: {
    provider?: 'gcore' | 'upcloud' | 'scaleway' | 'ovh' | 'cloudflare' | 'fastly';
    name?: string;
    qualified?: boolean;
    maxLiveEdges?: number;
    dailyAllocationBudget?: number;
    settings?: Record<string, unknown>;
    credentials?: Record<string, unknown>;
  } = {},
): Promise<Id<'edgeProviderAccounts'>> {
  const provider = opts.provider ?? 'gcore';
  const defaults: Record<
    string,
    { settings: Record<string, unknown>; credentials: Record<string, unknown> }
  > = {
    gcore: { settings: { projectId: 11, regionId: 22 }, credentials: { apiKey: 'k' } },
    upcloud: { settings: { zone: 'de-fra1' }, credentials: { token: 't' } },
    scaleway: {
      settings: { accessKey: 'SCWXXXXXXXXXXXXXXXXX', zone: 'fr-par-1' },
      credentials: { secretKey: 'sk' },
    },
    ovh: {
      settings: {
        applicationKey: 'ak',
        endpoint: 'ovh-eu',
        serviceName: 'svc',
        regionName: 'REG',
        networkId: 'net',
        subnetId: 'sub',
      },
      credentials: { applicationSecret: 'as', consumerKey: 'ck' },
    },
    cloudflare: {
      settings: { zoneId: 'a'.repeat(32), zoneName: 'example.org' },
      credentials: { apiToken: 'cf' },
    },
    fastly: {
      settings: { dnsAccountId: '', certificateAuthority: 'certainly' },
      credentials: { apiToken: 'fs' },
    },
  };
  const { id } = await t.mutation(internal.edgeProviderAccounts.create, {
    provider,
    name: opts.name ?? `acct-${provider}`,
    settings: (opts.settings ?? defaults[provider].settings) as never,
    credentials: (opts.credentials ?? defaults[provider].credentials) as never,
    ...(opts.maxLiveEdges !== undefined ? { maxLiveEdges: opts.maxLiveEdges } : {}),
    ...(opts.dailyAllocationBudget !== undefined
      ? { dailyAllocationBudget: opts.dailyAllocationBudget }
      : {}),
  });
  if (opts.qualified)
    await t.mutation(internal.edgeProviderAccounts.setQualified, { id, qualified: true });
  return id;
}

/** Register a relay the way the node role does: origin + listeners in one PUT. */
export async function registerRelay(
  t: T,
  opts: {
    slug?: string;
    backendSlug?: string;
    nodeName?: string;
    originAddress?: string;
    listeners?: ListenerSpecFixture[];
    kind?: 'panel-node' | 'backend-server' | 'manual';
    source?: 'role' | 'admin';
    hostModeRequest?: 'operator';
  } = {},
) {
  const kind = opts.kind ?? 'panel-node';
  const backendSlug = opts.backendSlug ?? FIXTURE_PANEL_SLUG;
  const origin =
    kind === 'panel-node'
      ? { kind: 'panel-node' as const, backendSlug, nodeName: opts.nodeName ?? FIXTURE_NODE }
      : kind === 'backend-server'
        ? { kind: 'backend-server' as const, backendSlug }
        : { kind: 'manual' as const };
  const listeners = opts.listeners ?? [realityListener()];
  const r = await t.mutation(internal.relays.registerBySlug, {
    slug: opts.slug ?? FIXTURE_RELAY_SLUG,
    origin,
    originAddress: opts.originAddress ?? FIXTURE_ORIGIN,
    listeners: listeners.map((l) =>
      kind === 'panel-node' ? l : { ...l, panelBinding: undefined },
    ) as never,
    source: opts.source ?? 'role',
    ...(opts.hostModeRequest ? { hostModeRequest: opts.hostModeRequest } : {}),
  });
  const rows = await t.run((ctx) =>
    ctx.db
      .query('relayListeners')
      .withIndex('by_relay', (q) => q.eq('relayId', r.id))
      .collect(),
  );
  const listenerIds = Object.fromEntries(rows.map((l) => [l.listenerKey, l._id])) as Record<
    string,
    Id<'relayListeners'>
  >;
  return {
    relayId: r.id,
    created: r.created,
    changed: r.changed,
    listenerIds,
    listenerId: listenerIds[listeners[0].listenerKey],
  };
}

export interface EdgeFixture {
  t: T;
  serverId: Id<'backendServers'>;
  accountId: Id<'edgeProviderAccounts'>;
  relayId: Id<'relays'>;
  /** The first listener (key `a` by default). */
  listenerId: Id<'relayListeners'>;
  listenerIds: Record<string, Id<'relayListeners'>>;
}

/**
 * The standard fixture: panel + one gcore account + one panel-node relay with
 * the REALITY listener. `qualified` marks the account qualified.
 */
export async function seedEdgeFixture(
  t: T,
  opts: {
    qualified?: boolean;
    maxLiveEdges?: number;
    dailyAllocationBudget?: number;
    listeners?: ListenerSpecFixture[];
    provider?: 'gcore' | 'upcloud' | 'scaleway' | 'ovh' | 'cloudflare' | 'fastly';
  } = {},
): Promise<EdgeFixture> {
  const serverId = await insertPanelServer(t);
  const accountId = await createAccount(t, {
    provider: opts.provider ?? 'gcore',
    name: 'acct-a',
    qualified: opts.qualified,
    maxLiveEdges: opts.maxLiveEdges,
    dailyAllocationBudget: opts.dailyAllocationBudget,
  });
  const r = await registerRelay(t, { listeners: opts.listeners });
  return {
    t,
    serverId,
    accountId,
    relayId: r.relayId,
    listenerId: r.listenerId,
    listenerIds: r.listenerIds,
  };
}

/**
 * Observe-only import of an L4 edge at `ipv4` on the relay's listener
 * (published when asked). By default the import carries the operator's
 * statement that the address already serves (`verified`, recorded as a
 * `named_connection` verification), which the publication gate needs for an
 * L4 edge; pass `verified: false` to import an UNTESTED spare.
 */
export async function adoptL4Edge(
  t: T,
  relayId: Id<'relays'>,
  listenerId: Id<'relayListeners'>,
  opts: {
    ipv4?: string;
    port?: number;
    publish?: boolean;
    verified?: boolean;
    accountId?: Id<'edgeProviderAccounts'> | null;
  } = {},
) {
  return t.mutation(internal.relays.adoptEdge, {
    relayId,
    listenerId,
    ipv4: opts.ipv4 ?? '198.51.100.7',
    port: opts.port,
    publish: opts.publish,
    verified: opts.verified ?? true,
    ...(opts.accountId ? { accountId: opts.accountId } : {}),
  });
}

/**
 * The operator's tick on an L4 edge: fetch the binding the way the CMS does
 * and echo it back. Returns the confirmation result.
 */
export async function verifyL4Edge(t: T, edgeId: Id<'edges'>) {
  const b = await t.query(internal.edgeVerification.binding, { edgeId });
  if (!b) throw new Error('verifyL4Edge: no binding (edge without an address?)');
  return t.mutation(internal.edgeVerification.confirm, {
    edgeId,
    endpoint: b.endpoint,
    listenerRevision: b.listenerRevision,
    configHash: b.configHash,
    method: 'test_link',
  });
}
