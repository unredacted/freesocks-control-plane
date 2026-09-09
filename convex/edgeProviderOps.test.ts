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
import { jsonRes, mockFetch } from './lib/edges/testing/mockFetch';
import type { EdgeProviderOpsFailure } from './edgeProviderOps';

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
  /** OVH: the clock, then whatever `rest` answers (default: the project read succeeds). */
  const ovhOk = (rest: (path: string) => Response = () => jsonRes({ description: 'p' })) =>
    mockFetch((c) => (c.path.endsWith('/auth/time') ? jsonRes(1_700_000_000) : rest(c.path)));

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
    // The provider test ran with the NEW credentials.
    const probe = stub.calls.find((c) => !c.path.endsWith('/auth/time'))!;
    expect(probe.headers['x-ovh-application']).toBe('AK2');
    expect(probe.headers['x-ovh-consumer']).toBe('CK1');
    const secret = await t.query(internal.edgeProviderAccounts.getWithSecret, { id });
    expect(secret?.credentials).toEqual({
      type: 'ovh',
      applicationSecret: 'AS2',
      consumerKey: 'CK1',
    });
    expect(secret?.settings).toMatchObject({ applicationKey: 'AK2', regionName: 'GRA9' });
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
    expect(stored.settings).toMatchObject({ applicationKey: 'AK9', regionName: 'GRA9' });
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
    expect(res).toEqual({ ok: false, code: 'Client::Forbidden' });
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
