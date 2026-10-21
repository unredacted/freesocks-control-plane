/// <reference types="vite/client" />
/**
 * The "use node" provider actions through convex-test with a stubbed fetch:
 * failures must cross the action boundary as `ConvexError` data (a plain
 * Error's `meta` does not survive `ctx.runAction`), a udp transport is refused
 * before any provider call, and credential rotation keeps the qualification
 * only after the NEW credentials pass the provider test.
 */
import { convexTest } from 'convex-test';
import { ConvexError } from 'convex/values';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { z } from 'zod';
import { jsonRes, mockFetch } from './lib/edges/testing/mockFetch';
import { __setEdgeProviderForTests, edgeProviderFor } from './lib/edges/providers/registry';
import type { EdgeProviderOpsFailure } from './edgeProviderOps';
import { certificateRefusalOf } from './edgeProviderAccounts';
import type { Id } from './_generated/dataModel';
import { insertPanelServer, registerRelay, wsListener } from './lib/edges/testing/fixtures';

const WS = { protocol: 'vless', streamTransport: 'ws', security: 'tls' } as const;
const GRPC = { protocol: 'vless', streamTransport: 'grpc', security: 'tls' } as const;

const modules = import.meta.glob('./**/*.*s');

afterEach(() => vi.unstubAllGlobals());

const spec = {
  name: 'fcp-relay-o1-00000000',
  listeners: [{ edgePort: 443, members: [{ address: '198.51.100.7', port: 443 }] }],
};
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

function newT() {
  return convexTest(schema, modules);
}

async function gcoreAccount(t: ReturnType<typeof newT>) {
  const { id } = await t.mutation(internal.edgeProviderAccounts.create, {
    provider: 'gcore',
    name: 'acct-g',
    settings: { projectId: 11, regionId: 22 },
    credentials: { apiKey: 'SECRET_GCORE_KEY' },
  });
  return id;
}

async function ovhAccount(t: ReturnType<typeof newT>) {
  const { id } = await t.mutation(internal.edgeProviderAccounts.create, {
    provider: 'ovh',
    name: 'acct-o',
    settings: {
      applicationKey: 'AK1',
      endpoint: 'ovh-eu',
      serviceName: 'svc',
      regionName: 'GRA9',
      networkId: 'n',
      subnetId: 's',
    },
    credentials: { applicationSecret: 'AS1', consumerKey: 'CK1' },
  });
  return id;
}

function dataOf(err: unknown): EdgeProviderOpsFailure {
  expect(err).toBeInstanceOf(ConvexError);
  return (err as ConvexError<EdgeProviderOpsFailure>).data;
}

describe('edgeProviderOps: failures cross the action boundary as ConvexError data', () => {
  test('a provider error keeps code/status/retryable/provider/step; never the key, body or host', async () => {
    const t = newT();
    const accountId = await gcoreAccount(t);
    mockFetch(() =>
      jsonRes(
        { code: 'auth_failed', message: 'bad key SECRET_GCORE_KEY at https://api.gcore.com/x' },
        401,
      ),
    );
    let err: unknown;
    try {
      await t.action(internal.edgeProviderOps.describe, { accountId, ledger: lbLedger });
    } catch (e) {
      err = e;
    }
    const data = dataOf(err);
    expect(data).toMatchObject({
      code: 'auth_failed',
      status: 401,
      retryable: false,
      timedOut: false,
      provider: 'gcore',
      step: 'describe',
    });
    const blob = `${JSON.stringify(data)} ${(err as Error).message}`;
    expect(blob).not.toContain('SECRET_GCORE_KEY');
    expect(blob).not.toContain('api.gcore.com');
    expect(blob).not.toContain('bad key');
    // A 5xx is retryable and, without a body code, carries the status as its code.
    mockFetch(() => new Response('upstream down', { status: 503 }));
    try {
      await t.action(internal.edgeProviderOps.describe, { accountId, ledger: lbLedger });
    } catch (e) {
      err = e;
    }
    expect(dataOf(err)).toMatchObject({ code: '503', status: 503, retryable: true });
  });

  test('a missing account is `account_missing` (no provider id is invented)', async () => {
    const t = newT();
    const accountId = await gcoreAccount(t);
    await t.run((ctx) => ctx.db.delete(accountId));
    let err: unknown;
    try {
      await t.action(internal.edgeProviderOps.describe, { accountId, ledger: lbLedger });
    } catch (e) {
      err = e;
    }
    const data = dataOf(err);
    expect(data).toMatchObject({ code: 'account_missing', retryable: false });
    expect(data.provider).toBeUndefined();
  });

  test('a udp listener is refused before any provider call; tcp/absent plans normally', async () => {
    const t = newT();
    const accountId = await gcoreAccount(t);
    const stub = mockFetch(() => jsonRes({ tasks: ['t-1'] }));
    const udpSpec = {
      ...spec,
      listeners: [{ ...spec.listeners[0], transport: 'udp' as const }],
    };
    let err: unknown;
    try {
      await t.action(internal.edgeProviderOps.planProvision, {
        accountId,
        spec: udpSpec,
        templateParams: {},
      });
    } catch (e) {
      err = e;
    }
    expect(dataOf(err)).toMatchObject({ code: 'transport_unsupported', provider: 'gcore' });
    const [step] = await t.action(internal.edgeProviderOps.planProvision, {
      accountId,
      spec: { ...spec, listeners: [{ ...spec.listeners[0], transport: 'tcp' as const }] },
      templateParams: {},
    });
    expect(step.kind).toBe('create_lb');
    try {
      await t.action(internal.edgeProviderOps.runStep, {
        accountId,
        spec: udpSpec,
        templateParams: {},
        step,
        ledger: { steps: [], resources: [] },
      });
    } catch (e) {
      err = e;
    }
    expect(dataOf(err)).toMatchObject({ code: 'transport_unsupported' });
    expect(stub.calls).toHaveLength(0);
  });

  test('invalid template params surface as template_invalid naming paths only', async () => {
    const t = newT();
    const accountId = await gcoreAccount(t);
    mockFetch(() => jsonRes({ tasks: ['t-1'] }));
    let err: unknown;
    try {
      await t.action(internal.edgeProviderOps.planProvision, {
        accountId,
        spec,
        templateParams: { ipFamily: 'ipv6', flavor: 'leak-me' },
      });
    } catch (e) {
      err = e;
    }
    const data = dataOf(err);
    expect(data.code).toBe('template_invalid');
    expect(String(data.message)).toContain('ipFamily');
    expect(String(data.message)).not.toContain('leak-me');
  });
});

describe('edgeProviderOps.rotateCredentials', () => {
  /**
   * OVH: the clock, then whatever `rest` answers (default: the account-level
   * credential test, the project listing, succeeds, and so does the read in
   * each location: an empty load balancer listing).
   */
  const ovhOk = (
    rest: (path: string) => Response = (path) =>
      path.endsWith('/cloud/project')
        ? jsonRes(['svc'])
        : path.includes('/loadbalancing/') || path.endsWith('/floatingip')
          ? jsonRes([])
          : jsonRes({ description: 'p' }),
  ) => mockFetch((c) => (c.path.endsWith('/auth/time') ? jsonRes(1_700_000_000) : rest(c.path)));

  test('a passing test applies the new secret + identifier, keeps the qualification, audits booleans only', async () => {
    const t = newT();
    const id = await ovhAccount(t);
    await t.mutation(internal.edgeProviderAccounts.setQualified, { id, qualified: true });
    const stub = ovhOk();
    const res = await t.action(internal.edgeProviderOps.rotateCredentials, {
      accountId: id,
      credentials: { applicationSecret: 'AS2', consumerKey: '' }, // blank keeps CK1
      identifiers: { applicationKey: 'AK2', regionName: 'MOVED' }, // regionName is not an identifier: dropped
    });
    expect(res).toEqual({
      ok: true,
      qualified: true,
      credentialsChanged: true,
      identifiersChanged: true,
    });
    // The provider test (the project listing) ran with the NEW credentials.
    const probe = stub.calls.find((c) => c.path.endsWith('/cloud/project'))!;
    expect(probe.headers['x-ovh-application']).toBe('AK2');
    expect(probe.headers['x-ovh-consumer']).toBe('CK1');
    const secret = await t.query(internal.edgeProviderAccounts.getWithSecret, { id });
    expect(secret?.credentials).toEqual({
      type: 'ovh',
      applicationSecret: 'AS2',
      consumerKey: 'CK1',
    });
    // The account is credentials only: the region stays on its location.
    expect(secret?.settings).toEqual({ type: 'ovh', applicationKey: 'AK2', endpoint: 'ovh-eu' });
    const view = await t.query(internal.edgeProviderAccounts.getForAdmin, { id });
    expect(view).toMatchObject({ qualified: true, lastTestError: null });
    expect(view?.lastTestOkAt).toBeTruthy();
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    const row = audit.find((a) => a.action === 'edge.provider_account.credentials_rotated')!;
    expect(row.payload).toEqual({
      name: 'acct-o',
      provider: 'ovh',
      credentialsChanged: true,
      identifiersChanged: true,
      qualifiedKept: true,
    });
    const blob = JSON.stringify(audit);
    for (const s of ['AS1', 'AS2', 'CK1', 'AK1', 'AK2']) expect(blob).not.toContain(`"${s}"`);
  });

  test('the apply step is compare-and-set: a row that moved during the provider test is refused, nothing stored', async () => {
    const t = newT();
    const id = await ovhAccount(t);
    const secret = (await t.query(internal.edgeProviderAccounts.getWithSecret, { id }))!;
    // Simulate a concurrent edit landing between the test and the apply.
    await t.run((ctx) => ctx.db.patch(id, { updatedAt: secret.updatedAt + 1 }));
    await expect(
      t.mutation(internal.edgeProviderAccounts.applyCredentialRotation, {
        id,
        credentials: { type: 'ovh', applicationSecret: 'AS9', consumerKey: 'CK9' },
        settings: { ...secret.settings, applicationKey: 'AK9' },
        expectedUpdatedAt: secret.updatedAt,
        actorAdminId: undefined,
      }),
    ).rejects.toMatchObject({ data: { code: 'conflict' } });
    const after = (await t.query(internal.edgeProviderAccounts.getWithSecret, { id }))!;
    expect(after.credentials).toEqual({
      type: 'ovh',
      applicationSecret: 'AS1',
      consumerKey: 'CK1',
    });
    expect(after.settings).toMatchObject({ applicationKey: 'AK1' });
    // The apply stores the EXACT tested set (no re-merge against the row).
    await t.mutation(internal.edgeProviderAccounts.applyCredentialRotation, {
      id,
      credentials: { type: 'ovh', applicationSecret: 'AS9', consumerKey: 'CK9' },
      settings: { ...secret.settings, applicationKey: 'AK9' },
      expectedUpdatedAt: after.updatedAt,
      actorAdminId: undefined,
    });
    const stored = (await t.query(internal.edgeProviderAccounts.getWithSecret, { id }))!;
    expect(stored.credentials).toEqual({
      type: 'ovh',
      applicationSecret: 'AS9',
      consumerKey: 'CK9',
    });
    expect(stored.settings).toEqual({ type: 'ovh', applicationKey: 'AK9', endpoint: 'ovh-eu' });
  });

  test('a failing test changes nothing (stored credentials, identifier, qualification) and reports the code', async () => {
    const t = newT();
    const id = await ovhAccount(t);
    await t.mutation(internal.edgeProviderAccounts.setQualified, { id, qualified: true });
    ovhOk(() => jsonRes({ class: 'Client::Forbidden', message: 'bad AS2' }, 403));
    const res = await t.action(internal.edgeProviderOps.rotateCredentials, {
      accountId: id,
      credentials: { applicationSecret: 'AS2', consumerKey: 'CK2' },
      identifiers: { applicationKey: 'AK2' },
    });
    // The provider echoed the (3-character) secret: too short to replace safely,
    // so the answer is withheld and only the code is reported.
    expect(res).toMatchObject({ ok: false, code: 'Client::Forbidden' });
    expect(JSON.stringify(res)).not.toContain('AS2');
    expect((res as { detail?: string }).detail).toBeUndefined();
    const secret = await t.query(internal.edgeProviderAccounts.getWithSecret, { id });
    expect(secret?.credentials).toEqual({
      type: 'ovh',
      applicationSecret: 'AS1',
      consumerKey: 'CK1',
    });
    expect(secret?.settings).toMatchObject({ applicationKey: 'AK1' });
    expect((await t.query(internal.edgeProviderAccounts.getForAdmin, { id }))?.qualified).toBe(
      true,
    );
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.some((a) => a.action === 'edge.provider_account.credentials_rotated')).toBe(false);
  });

  test('a key that passes the account test but cannot read a location in use is refused, nothing changed', async () => {
    const t = newT();
    const id = await ovhAccount(t);
    await t.mutation(internal.edgeProviderAccounts.setQualified, { id, qualified: true });
    // The project listing passes; the read in the account's location is refused.
    const stub = ovhOk((path) =>
      path.endsWith('/cloud/project')
        ? jsonRes(['svc'])
        : path.endsWith('/loadbalancing/loadbalancer')
          ? jsonRes({ class: 'Client::Forbidden', message: 'not this project' }, 403)
          : jsonRes([]),
    );
    const res = await t.action(internal.edgeProviderOps.rotateCredentials, {
      accountId: id,
      credentials: { applicationSecret: 'AS2', consumerKey: 'CK2' },
    });
    expect(res).toMatchObject({ ok: false, code: 'location_unreachable' });
    expect((res as { detail?: string }).detail).toMatch(/\(Client::Forbidden\)$/);
    expect(stub.calls.some((c) => c.path.endsWith('/loadbalancing/loadbalancer'))).toBe(true);
    // The location read is three parallel calls: the refused one ends the
    // rotation while the other two are still in flight. They land on this
    // stub, not on whatever `fetch` is once the test is over.
    await vi.waitFor(() =>
      expect(
        stub.calls.filter((c) => /\/(floatingip|loadbalancing\/flavor)$/.test(c.path)),
      ).toHaveLength(2),
    );
    const secret = await t.query(internal.edgeProviderAccounts.getWithSecret, { id });
    expect(secret?.credentials).toEqual({
      type: 'ovh',
      applicationSecret: 'AS1',
      consumerKey: 'CK1',
    });
    expect((await t.query(internal.edgeProviderAccounts.getForAdmin, { id }))?.qualified).toBe(
      true,
    );
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.some((a) => a.action === 'edge.provider_account.credentials_rotated')).toBe(false);
  });

  test('the ordinary update path still drops the qualification on a credential change', async () => {
    const t = newT();
    const id = await ovhAccount(t);
    await t.mutation(internal.edgeProviderAccounts.setQualified, { id, qualified: true });
    await t.mutation(internal.edgeProviderAccounts.update, {
      id,
      credentials: { applicationSecret: 'AS2', consumerKey: '' },
    });
    expect((await t.query(internal.edgeProviderAccounts.getForAdmin, { id }))?.qualified).toBe(
      false,
    );
  });
});

describe('edgeProviderOps: contract + layer refusals', () => {
  test('pollStep on an adapter with no poller is a CONTRACT VIOLATION, never a fabricated done', async () => {
    const t = newT();
    // UpCloud is synchronous: it has no `pollStep`. Answering `done` with an
    // empty ledger would mark an allocating step complete while the resource it
    // created stayed unrecorded, undeletable and billable.
    const { id: accountId } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'upcloud',
      name: 'acct-u',
      settings: { zone: 'de-fra1' },
      credentials: { token: 'ucl' },
    });
    mockFetch(() => jsonRes({}));
    try {
      await t.action(internal.edgeProviderOps.pollStep, {
        accountId,
        step: { id: 'lb', kind: 'create_lb', resourceName: 'x', discoverability: 'by_name' },
        opRef: 'op-1',
        ledger: { steps: [], resources: [] },
      });
      throw new Error('expected a refusal');
    } catch (err) {
      expect(err).toBeInstanceOf(ConvexError);
      expect((err as ConvexError<EdgeProviderOpsFailure>).data.code).toBe('contract_violation');
    }
  });

  test('a protocol the provider cannot carry is refused before any call', async () => {
    const t = newT();
    const { id: dnsId } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'cloudflare',
      name: 'acct-cf',
      settings: { zoneId: 'a'.repeat(32), zoneName: 'example.org' },
      credentials: { apiToken: 'cf' },
    });
    const { id: fastlyId } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'fastly',
      name: 'acct-fastly',
      settings: { dnsAccountId: dnsId, certificateAuthority: 'certainly' },
      credentials: { apiToken: 'f' },
    });
    const calls: string[] = [];
    mockFetch((c) => {
      calls.push(c.url);
      return jsonRes({});
    });
    const l7Spec = {
      ...spec,
      hostname: 'front.example.org',
      originTransport: {
        scheme: 'https' as const,
        certPublic: true,
        certNames: ['origin.example'],
        acceptsHostHeader: 'any' as const,
      },
    };
    await expect(
      t.action(internal.edgeProviderOps.planProvision, {
        accountId: fastlyId,
        spec: l7Spec,
        templateParams: {},
        proto: GRPC,
      }),
    ).rejects.toThrow(/protocol_not_carried/);
    expect(calls).toEqual([]);
  });

  test('an L7 spec without its hostname or origin transport is refused before any call', async () => {
    const t = newT();
    const { id: cfId } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'cloudflare',
      name: 'acct-cf',
      settings: { zoneId: 'a'.repeat(32), zoneName: 'example.org' },
      credentials: { apiToken: 'cf' },
    });
    mockFetch(() => jsonRes({}));
    await expect(
      t.action(internal.edgeProviderOps.planProvision, {
        accountId: cfId,
        spec,
        templateParams: {},
        proto: WS,
      }),
    ).rejects.toThrow(/hostname_missing/);
    await expect(
      t.action(internal.edgeProviderOps.planProvision, {
        accountId: cfId,
        spec: { ...spec, hostname: 'front.example.org' },
        templateParams: {},
        proto: WS,
      }),
    ).rejects.toThrow(/origin_transport_missing/);
  });

  test('a provider that needs a DNS account refuses to act without a usable one', async () => {
    const t = newT();
    const { id: dnsId } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'cloudflare',
      name: 'acct-cf',
      settings: { zoneId: 'a'.repeat(32), zoneName: 'example.org' },
      credentials: { apiToken: 'cf' },
    });
    const { id: fastlyId } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'fastly',
      name: 'acct-fastly',
      settings: { dnsAccountId: dnsId, certificateAuthority: 'certainly' },
      credentials: { apiToken: 'f' },
    });
    // The DNS account disappears under it.
    await t.run((ctx) => ctx.db.delete(dnsId));
    mockFetch(() => jsonRes({}));
    await expect(
      t.action(internal.edgeProviderOps.describe, {
        accountId: fastlyId,
        ledger: { steps: [], resources: [] },
      }),
    ).rejects.toThrow(/dns_account_missing/);
  });

  test('a DISABLED DNS account still serves existing edges (reconcile and destroy keep working)', async () => {
    const t = newT();
    const { id: dnsId } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'cloudflare',
      name: 'acct-cf',
      settings: { zoneId: 'a'.repeat(32), zoneName: 'example.org' },
      credentials: { apiToken: 'cf' },
    });
    const { id: fastlyId } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'fastly',
      name: 'acct-fastly',
      settings: { dnsAccountId: dnsId, certificateAuthority: 'certainly' },
      credentials: { apiToken: 'f' },
    });
    await t.mutation(internal.edgeProviderAccounts.update, { id: dnsId, enabled: false });
    mockFetch((c) =>
      // Enough of a Fastly answer for `describe` to resolve the config first.
      c.url.includes('/service/') ? jsonRes({}, 404) : jsonRes({}),
    );
    // Disabling stops NEW allocations, not the config resolution: the adapter
    // runs and answers about the edge, instead of the load being refused.
    expect(
      await t.action(internal.edgeProviderOps.describe, {
        accountId: fastlyId,
        ledger: { steps: [], resources: [] },
      }),
    ).toMatchObject({ state: 'pending' });
  });
});

describe('edgeProviderOps: an existing edge is driven by its FROZEN intent', () => {
  afterEach(() => __setEdgeProviderForTests('fastly', null));

  /** A fastly stand-in that records the config each call was handed. */
  function recordingFastly() {
    const seen: Array<Record<string, unknown>> = [];
    __setEdgeProviderForTests('fastly', {
      id: 'fastly',
      templateSchema: z.object({}).passthrough(),
      templateFields: [],
      defaultTemplate: {},
      testCredentials: async () => ({ ok: true }),
      planProvision: () => [],
      runStep: async () => ({ status: 'done', resources: [] }),
      discover: async () => ({ status: 'unresolved' }),
      describe: async (cfg: Record<string, unknown>) => {
        seen.push(cfg);
        return { state: 'active', addresses: {}, health: 'unknown' };
      },
      inspect: async () => ({ summary: { addresses: [], members: [], listeners: [] }, raw: {} }),
      inventory: async () => ({ loadBalancers: [], ips: [], flavors: [] }),
      planDestroy: () => [],
      runDestroy: async () => ({ status: 'confirmed_gone' }),
    } as unknown as Parameters<typeof __setEdgeProviderForTests>[1]);
    return seen;
  }

  test('a settings edit after planning cannot move a live edge to another TLS subscription', async () => {
    const t = newT();
    const { id: dnsId } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'cloudflare',
      name: 'acct-cf',
      settings: { zoneId: 'a'.repeat(32), zoneName: 'example.org' },
      credentials: { apiToken: 'cf' },
    });
    const { id: fastlyId } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'fastly',
      name: 'acct-fastly',
      settings: {
        dnsAccountId: dnsId,
        certificateAuthority: 'certainly',
        tlsConfigurationId: 'tls-old',
      },
      credentials: { apiToken: 'f' },
    });
    const seen = recordingFastly();
    // An edge planned against the OLD subscription.
    await insertPanelServer(t);
    const { relayId, listenerId } = await registerRelay(t, {
      slug: 'o1',
      nodeName: 'o1',
      originAddress: '198.51.100.7',
      listeners: [
        wsListener({
          tlsNames: ['ws.example'],
          originTransport: {
            scheme: 'https',
            certPublic: true,
            certNames: ['origin.example'],
            acceptsHostHeader: 'any',
          },
        }),
      ],
    });
    const edgeId = await t.run((ctx) =>
      ctx.db.insert('edges', {
        relayId,
        listenerId,
        accountId: fastlyId,
        provider: 'fastly',
        managed: true,
        name: 'fcp-relay-o1-1',
        steps: [],
        resources: [],
        listeners: [{ edgePort: 443, originAddress: '198.51.100.7', originPort: 443 }],
        addresses: { hostname: 'front.example.org' },
        layer: 'l7',
        provisionIntent: JSON.stringify({
          hostname: 'front.example.org',
          zoneId: 'a'.repeat(32),
          zoneName: 'example.org',
          dnsAccountId: dnsId,
          certificateAuthority: 'certainly',
          tlsConfigurationId: 'tls-old',
          originTransport: {
            scheme: 'https',
            certPublic: true,
            certNames: ['origin.example'],
            acceptsHostHeader: 'any',
          },
          originPort: 443,
          zoneSslMode: 'full',
          templateHash: 'h',
          templateParams: {},
        }),
        publication: 'unpublished',
        status: 'active',
        statusChangedAt: Date.now(),
        health: 'unknown',
        destroyAttempts: 0,
        updatedAt: Date.now(),
      }),
    );
    // The operator repoints the ACCOUNT at another subscription and CA.
    await t.run((ctx) =>
      ctx.db.patch(fastlyId, {
        settings: {
          type: 'fastly',
          dnsAccountId: dnsId,
          certificateAuthority: 'lets-encrypt',
          tlsConfigurationId: 'tls-new',
        },
        updatedAt: Date.now(),
      }),
    );
    await t.action(internal.edgeProviderOps.describe, {
      accountId: fastlyId,
      ledger: { steps: [], resources: [] },
      edgeId,
    });
    // Acting on THIS edge uses what its intent froze, not the account's now.
    expect(seen[0]).toMatchObject({
      certificateAuthority: 'certainly',
      tlsConfigurationId: 'tls-old',
    });
    // Planning a NEW edge (no edgeId) follows the account's current settings.
    await t.action(internal.edgeProviderOps.describe, {
      accountId: fastlyId,
      ledger: { steps: [], resources: [] },
    });
    expect(seen[1]).toMatchObject({
      certificateAuthority: 'lets-encrypt',
      tlsConfigurationId: 'tls-new',
    });
  });
});

describe('edgeProviderOps: L7 plan-time refusals', () => {
  const l7Spec = (over: Record<string, unknown> = {}) => ({
    ...spec,
    hostname: 'front.example.org',
    originTransport: {
      scheme: 'https' as const,
      certPublic: true,
      certNames: ['origin.example'],
      acceptsHostHeader: 'any' as const,
    },
    ...over,
  });

  async function cloudflareAccount(t: ReturnType<typeof newT>) {
    const { id } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'cloudflare',
      name: 'acct-cf',
      settings: { zoneId: 'a'.repeat(32), zoneName: 'example.org' },
      credentials: { apiToken: 'cf' },
    });
    return id;
  }

  test('a Host header the origin would reject is refused before any call', async () => {
    const t = newT();
    const cfId = await cloudflareAccount(t);
    const calls: string[] = [];
    mockFetch((c) => {
      calls.push(c.url);
      return jsonRes({});
    });
    await expect(
      t.action(internal.edgeProviderOps.planProvision, {
        accountId: cfId,
        spec: l7Spec({
          originTransport: {
            scheme: 'https',
            certPublic: true,
            certNames: ['origin.example'],
            acceptsHostHeader: 'names',
          },
        }),
        templateParams: {},
        proto: WS,
        zoneSslMode: 'full',
      }),
    ).rejects.toThrow(/host_header_rejected/);
    expect(calls).toEqual([]);
  });

  test('a zone encryption mode that cannot carry the origin transport is refused at plan time', async () => {
    const t = newT();
    const cfId = await cloudflareAccount(t);
    mockFetch(() => jsonRes({}));
    // `flexible` dials the origin over plain HTTP; this origin speaks HTTPS.
    await expect(
      t.action(internal.edgeProviderOps.planProvision, {
        accountId: cfId,
        spec: l7Spec(),
        templateParams: {},
        proto: WS,
        zoneSslMode: 'flexible',
      }),
    ).rejects.toThrow(/origin_tls_mismatch/);
    // A privately issued origin certificate cannot survive `strict`.
    await expect(
      t.action(internal.edgeProviderOps.planProvision, {
        accountId: cfId,
        spec: l7Spec({
          originTransport: {
            scheme: 'https',
            certPublic: false,
            certNames: ['origin.example'],
            acceptsHostHeader: 'any',
          },
        }),
        templateParams: {},
        proto: WS,
        zoneSslMode: 'strict',
      }),
    ).rejects.toThrow(/origin_tls_mismatch/);
  });

  test('the zone encryption mode only refuses the CDN that PROXIES the zone', async () => {
    const t = newT();
    const cfId = await cloudflareAccount(t);
    const { id: fastlyId } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'fastly',
      name: 'acct-fastly',
      settings: { dnsAccountId: cfId, certificateAuthority: 'certainly' },
      credentials: { apiToken: 'f' },
    });
    mockFetch(() => jsonRes({}));
    // A plaintext origin, and a DNS zone set to the strictest mode. The zone
    // only holds this front's unproxied CNAMEs, so its mode says nothing about
    // how the front dials the origin: the plan goes through.
    const httpOrigin = l7Spec({
      listeners: [{ edgePort: 443, members: [{ address: '198.51.100.7', port: 80 }] }],
      originTransport: {
        scheme: 'http',
        certPublic: false,
        certNames: [],
        acceptsHostHeader: 'any',
      },
    });
    const steps = await t.action(internal.edgeProviderOps.planProvision, {
      accountId: fastlyId,
      spec: httpOrigin,
      templateParams: {},
      proto: WS,
      zoneSslMode: 'strict',
    });
    expect(steps.length).toBeGreaterThan(0);
    // The same origin behind the zone's own proxy is still refused.
    await expect(
      t.action(internal.edgeProviderOps.planProvision, {
        accountId: cfId,
        spec: httpOrigin,
        templateParams: {},
        proto: WS,
        zoneSslMode: 'strict',
      }),
    ).rejects.toThrow(/origin_tls_mismatch/);
  });

  test('the observed zone mode reaches the zone proxy adapter as a template param', async () => {
    const t = newT();
    const cfId = await cloudflareAccount(t);
    mockFetch(() => jsonRes({}));
    // `flexible` dials port 80; an origin on 443 therefore needs an Origin Rule.
    // Without the mode the adapter would refuse with `zone_mode_unknown`, so
    // the extra step proves the mode survived the template schema.
    const steps = await t.action(internal.edgeProviderOps.planProvision, {
      accountId: cfId,
      spec: l7Spec(),
      templateParams: {},
      proto: WS,
      zoneSslMode: 'full',
    });
    expect(steps.map((s) => s.kind)).toEqual(['create_dns_record']);
    const flexible = await t.action(internal.edgeProviderOps.planProvision, {
      accountId: cfId,
      spec: l7Spec({
        listeners: [{ edgePort: 443, members: [{ address: '198.51.100.7', port: 80 }] }],
        originTransport: {
          scheme: 'http',
          certPublic: false,
          certNames: [],
          acceptsHostHeader: 'any',
        },
      }),
      templateParams: {},
      proto: WS,
      zoneSslMode: 'flexible',
    });
    expect(flexible.map((s) => s.kind)).toEqual(['create_dns_record']);
  });

  test('an adapter with no adoption inspection refuses the import instead of guessing', async () => {
    const t = newT();
    const cfId = await cloudflareAccount(t);
    mockFetch(() => jsonRes({}));
    __setEdgeProviderForTests('cloudflare', {
      ...edgeProviderFor('cloudflare'),
      inspectForAdoption: undefined,
    } as never);
    try {
      await expect(
        t.action(internal.edgeProviderOps.inspectForAdoption, {
          accountId: cfId,
          resourceId: 'rec-1',
          hostname: 'front.example.org',
        }),
      ).rejects.toThrow(/adoption_unsupported/);
    } finally {
      __setEdgeProviderForTests('cloudflare', null);
    }
  });
});

describe('edgeProviderOps: the inventory pull refreshes what was observed', () => {
  afterEach(() => __setEdgeProviderForTests('cloudflare', null));

  test('an inventory refresh re-reads the zone facts; a failing test never fails the pull', async () => {
    const t = newT();
    const { id: cfId } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'cloudflare',
      name: 'acct-cf',
      settings: { zoneId: 'a'.repeat(32), zoneName: 'example.org' },
      credentials: { apiToken: 'cf' },
    });
    let mode = 'flexible';
    let testThrows = false;
    __setEdgeProviderForTests('cloudflare', {
      ...edgeProviderFor('cloudflare'),
      inventory: async () => ({ loadBalancers: [], ips: [], flavors: [] }),
      testCredentials: async () => {
        if (testThrows) throw new Error('zone read failed');
        return { ok: true, observed: { zoneSslMode: mode } };
      },
    } as never);
    await t.action(internal.edgeProviderOps.inventory, { accountId: cfId });
    expect(
      (await t.query(internal.edgeProviderAccounts.getForAdmin, { id: cfId }))!.observedSettings,
    ).toEqual({ zoneSslMode: 'flexible' });
    // The operator changes the zone's mode at the provider: the next pull sees it.
    mode = 'full';
    await t.action(internal.edgeProviderOps.inventory, { accountId: cfId });
    expect(
      (await t.query(internal.edgeProviderAccounts.getForAdmin, { id: cfId }))!.observedSettings,
    ).toEqual({ zoneSslMode: 'full' });
    // The inventory is what was asked for: a failing test does not lose it.
    testThrows = true;
    expect(await t.action(internal.edgeProviderOps.inventory, { accountId: cfId })).toMatchObject({
      loadBalancers: [],
    });
  });

  test('a credential rotation refreshes the observed zone facts like a test does', async () => {
    const t = newT();
    const { id: cfId } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'cloudflare',
      name: 'acct-cf',
      settings: { zoneId: 'a'.repeat(32), zoneName: 'example.org' },
      credentials: { apiToken: 'cf' },
    });
    let mode = 'flexible';
    __setEdgeProviderForTests('cloudflare', {
      ...edgeProviderFor('cloudflare'),
      testCredentials: async () => ({ ok: true, observed: { zoneSslMode: mode } }),
    } as never);
    await t.action(internal.edgeProviderOps.testCredentials, { accountId: cfId });
    expect(
      (await t.query(internal.edgeProviderAccounts.getForAdmin, { id: cfId }))!.observedSettings,
    ).toEqual({ zoneSslMode: 'flexible' });
    // The zone mode moved at the provider; the rotation's passing test sees it,
    // so planning must not keep freezing the stale mode.
    mode = 'strict';
    const res = await t.action(internal.edgeProviderOps.rotateCredentials, {
      accountId: cfId,
      credentials: { apiToken: 'cf2' },
    });
    expect(res).toMatchObject({ ok: true, credentialsChanged: true });
    expect(
      (await t.query(internal.edgeProviderAccounts.getForAdmin, { id: cfId }))!.observedSettings,
    ).toEqual({ zoneSslMode: 'strict' });
  });
});

describe('edgeProviderOps: an existing edge acts only where it was placed', () => {
  test("a describe reaches the edge's own region; a placed edge without a placement is refused before any call", async () => {
    const t = newT();
    const accountId = await gcoreAccount(t);
    await insertPanelServer(t);
    const { relayId, listenerId } = await registerRelay(t, {
      slug: 'o1',
      nodeName: 'o1',
      originAddress: '198.51.100.7',
      listeners: [wsListener({ tlsNames: ['ws.example'] })],
    });
    // Planned in another region of the account than its first location.
    const edgeId = await t.run((ctx) =>
      ctx.db.insert('edges', {
        relayId,
        listenerId,
        accountId,
        provider: 'gcore',
        placement: { type: 'gcore', projectId: 11, regionId: 77 },
        placeKey: '77',
        managed: true,
        name: 'fcp-relay-o1-1',
        steps: [],
        resources: lbLedger.resources,
        listeners: [{ edgePort: 443, originAddress: '198.51.100.7', originPort: 443 }],
        addresses: { v4: '198.51.100.9' },
        layer: 'l4',
        publication: 'unpublished',
        status: 'active',
        statusChangedAt: Date.now(),
        health: 'unknown',
        destroyAttempts: 0,
        updatedAt: Date.now(),
      }),
    );
    const stub = mockFetch(() => jsonRes({}, 404));
    await t
      .action(internal.edgeProviderOps.describe, { accountId, ledger: lbLedger, edgeId })
      .catch(() => null);
    expect(stub.calls.length).toBeGreaterThan(0);
    expect(stub.calls.every((c) => c.path.includes('/11/77'))).toBe(true);
    // Without its own placement the call is refused: it never falls back to a region.
    await t.run((ctx) => ctx.db.patch(edgeId, { placement: undefined }));
    const before = stub.calls.length;
    let err: unknown;
    try {
      await t.action(internal.edgeProviderOps.describe, { accountId, ledger: lbLedger, edgeId });
    } catch (e) {
      err = e;
    }
    expect(dataOf(err)).toMatchObject({ code: 'placement_missing', retryable: false });
    expect(stub.calls.length).toBe(before);
  });
});

describe('edgeProviderOps: how an edge was built is frozen with it (Fastly domains and certificates)', () => {
  afterEach(() => __setEdgeProviderForTests('fastly', null));

  /** A fastly stand-in that records the config each call was handed, with optional overrides. */
  function standIn(over: Record<string, unknown> = {}) {
    const seen: Array<Record<string, unknown>> = [];
    __setEdgeProviderForTests('fastly', {
      id: 'fastly',
      templateSchema: z.object({}).passthrough(),
      templateFields: [],
      defaultTemplate: {},
      testCredentials: async () => ({ ok: true }),
      planProvision: () => [],
      runStep: async () => ({ status: 'done', resources: [] }),
      discover: async () => ({ status: 'unresolved' }),
      describe: async (cfg: Record<string, unknown>) => {
        seen.push({ ...cfg });
        return { state: 'active', addresses: {}, health: 'unknown' };
      },
      inspect: async () => ({ summary: { addresses: [], members: [], listeners: [] }, raw: {} }),
      inventory: async () => ({ loadBalancers: [], ips: [], flavors: [] }),
      planDestroy: () => [],
      runDestroy: async () => ({ status: 'confirmed_gone' }),
      ...over,
    } as unknown as Parameters<typeof __setEdgeProviderForTests>[1]);
    return seen;
  }

  async function fastlyAccount(t: ReturnType<typeof newT>, settings: Record<string, unknown> = {}) {
    const { id: dnsId } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'cloudflare',
      name: 'acct-cf',
      settings: { zoneId: 'a'.repeat(32), zoneName: 'example.org' },
      credentials: { apiToken: 'cf' },
    });
    const { id } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'fastly',
      name: 'acct-fastly',
      settings: { dnsAccountId: dnsId, certificateAuthority: 'certainly', ...settings },
      credentials: { apiToken: 'f' },
    });
    return { id, dnsId };
  }

  async function edgeWithIntent(
    t: ReturnType<typeof newT>,
    accountId: Id<'edgeProviderAccounts'>,
    dnsId: string,
    intent: Record<string, unknown>,
  ) {
    await insertPanelServer(t);
    const { relayId, listenerId } = await registerRelay(t, {
      slug: 'o1',
      nodeName: 'o1',
      originAddress: '198.51.100.7',
      listeners: [wsListener({ tlsNames: ['ws.example'] })],
    });
    return t.run((ctx) =>
      ctx.db.insert('edges', {
        relayId,
        listenerId,
        accountId,
        provider: 'fastly',
        managed: true,
        name: 'fcp-relay-o1-1',
        steps: [],
        resources: [],
        listeners: [{ edgePort: 443, originAddress: '198.51.100.7', originPort: 443 }],
        addresses: { hostname: 'front.example.org' },
        layer: 'l7',
        provisionIntent: JSON.stringify({
          hostname: 'front.example.org',
          zoneId: 'a'.repeat(32),
          zoneName: 'example.org',
          dnsAccountId: dnsId,
          certificateAuthority: 'certainly',
          originTransport: {
            scheme: 'https',
            certPublic: true,
            certNames: ['origin.example'],
            acceptsHostHeader: 'any',
          },
          originPort: 443,
          templateHash: 'h',
          templateParams: {},
          ...intent,
        }),
        publication: 'unpublished',
        status: 'active',
        statusChangedAt: Date.now(),
        health: 'unknown',
        destroyAttempts: 0,
        updatedAt: Date.now(),
      }),
    );
  }

  test('a new account shares one wildcard; an edge from before keeps its classic domain and its own certificate', async () => {
    const t = newT();
    const { id: accountId, dnsId } = await fastlyAccount(t, { tlsConfigurationId: 'tls-now' });
    const row = (await t.run((ctx) => ctx.db.get(accountId)))!;
    expect((row.settings as { certificateScope?: string }).certificateScope).toBe('wildcard');
    const seen = standIn();
    // An edge planned before versionless domains, a TLS configuration or a scope existed.
    const old = await edgeWithIntent(t, accountId, dnsId, {});
    mockFetch(() => jsonRes({}));
    await t.action(internal.edgeProviderOps.describe, {
      accountId,
      ledger: { steps: [], resources: [] },
      edgeId: old,
    });
    expect(seen[0]).toMatchObject({ domainModel: 'classic' });
    // What the intent did NOT name stays unnamed: the account's choices now never reach it.
    expect(seen[0]).not.toHaveProperty('tlsConfigurationId');
    expect(seen[0]).not.toHaveProperty('certificateScope');
    // Planning a new edge (no edgeId): today's way, and the account's settings.
    await t.action(internal.edgeProviderOps.describe, {
      accountId,
      ledger: { steps: [], resources: [] },
    });
    expect(seen[1]).toMatchObject({
      domainModel: 'versionless',
      certificateScope: 'wildcard',
      tlsConfigurationId: 'tls-now',
    });
  });

  test('an edge planned now keeps the versionless domain and the wildcard it froze', async () => {
    const t = newT();
    const { id: accountId, dnsId } = await fastlyAccount(t);
    const seen = standIn();
    const edgeId = await edgeWithIntent(t, accountId, dnsId, {
      domainModel: 'versionless',
      certificateScope: 'wildcard',
    });
    // The account switches back to one certificate per front: the edge does not move.
    await t.run((ctx) =>
      ctx.db.patch(accountId, {
        settings: {
          type: 'fastly',
          dnsAccountId: dnsId,
          certificateAuthority: 'certainly',
          certificateScope: 'per_host',
        },
      }),
    );
    mockFetch(() => jsonRes({}));
    await t.action(internal.edgeProviderOps.describe, {
      accountId,
      ledger: { steps: [], resources: [] },
      edgeId,
    });
    expect(seen[0]).toMatchObject({ domainModel: 'versionless', certificateScope: 'wildcard' });
  });

  test('a CAA refusal is recorded as the test result, and does not count as the provider failing', async () => {
    const t = newT();
    const { id: accountId } = await fastlyAccount(t);
    standIn({
      testCredentials: async () => ({
        ok: false,
        code: 'caa_forbids_ca',
        detail: 'the CAA records at example.org do not allow certainly.com',
        observed: { caa: 'forbids', caaIssuer: 'certainly.com', caaCertificate: 'wildcard' },
      }),
    });
    mockFetch(() => jsonRes({}));
    for (let i = 0; i < 4; i++)
      expect(await t.action(internal.edgeProviderOps.testCredentials, { accountId })).toMatchObject(
        {
          ok: false,
          code: 'caa_forbids_ca',
        },
      );
    const row = (await t.run((ctx) => ctx.db.get(accountId)))!;
    expect(row.lastTestError).toBe('caa_forbids_ca');
    expect(row.apiFailures ?? 0).toBe(0);
    expect(JSON.parse(row.observedSettings!)).toMatchObject({ caa: 'forbids' });
  });

  test('the shared certificate is read at the provider and kept on the account, with its users', async () => {
    const t = newT();
    const { id: accountId, dnsId } = await fastlyAccount(t);
    let status: Record<string, unknown> | null = {
      name: '*.example.org',
      subscriptionId: 'WILD1',
      state: 'processing',
      code: 'tls_caa_conflict',
    };
    standIn({ sharedCertificate: async () => status });
    await edgeWithIntent(t, accountId, dnsId, {
      domainModel: 'versionless',
      certificateScope: 'wildcard',
    });
    mockFetch(() => jsonRes({}));
    // Not issued yet: the reconcile cron reads it every pass.
    expect(
      await t.query(internal.edgeProviderAccounts.listForSharedCertificates, { now: Date.now() }),
    ).toEqual([accountId]);
    await t.action(internal.edgeProviderOps.refreshSharedCertificate, { accountId });
    let admin = (await t.query(internal.edgeProviderAccounts.getForAdmin, { id: accountId }))!;
    expect(admin.sharedCertificate).toMatchObject({
      name: '*.example.org',
      state: 'processing',
      code: 'tls_caa_conflict',
      edges: 1,
    });
    const attention = await t.query(internal.edgeOperator.attention, {});
    expect(attention.items.find((i) => i.kind === 'certificate_waiting')).toMatchObject({
      accountId,
      code: 'tls_caa_conflict',
      action: 'open_account',
    });
    // Issued: read again only after the recheck interval.
    status = {
      name: '*.example.org',
      subscriptionId: 'WILD1',
      state: 'issued',
      notAfter: '2026-11-19T10:12:00.000Z',
    };
    await t.action(internal.edgeProviderOps.refreshSharedCertificate, { accountId });
    admin = (await t.query(internal.edgeProviderAccounts.getForAdmin, { id: accountId }))!;
    expect(admin.sharedCertificate).toMatchObject({
      state: 'issued',
      code: null,
      notAfter: '2026-11-19T10:12:00.000Z',
    });
    expect(
      await t.query(internal.edgeProviderAccounts.listForSharedCertificates, { now: Date.now() }),
    ).toEqual([]);
    expect(
      await t.query(internal.edgeProviderAccounts.listForSharedCertificates, {
        now: Date.now() + 31 * 60_000,
      }),
    ).toEqual([accountId]);
    // A failed one refuses new fronts of the account.
    status = {
      name: '*.example.org',
      subscriptionId: 'WILD1',
      state: 'failed',
      code: 'tls_failed',
    };
    await t.action(internal.edgeProviderOps.refreshSharedCertificate, { accountId });
    const row = (await t.run((ctx) => ctx.db.get(accountId)))!;
    expect(certificateRefusalOf(row)).toBe('shared_certificate_failed');
    // An account that no longer shares one is cleared.
    status = null;
    await t.action(internal.edgeProviderOps.refreshSharedCertificate, { accountId });
    admin = (await t.query(internal.edgeProviderAccounts.getForAdmin, { id: accountId }))!;
    expect(admin.sharedCertificate).toBeNull();
  });
});
