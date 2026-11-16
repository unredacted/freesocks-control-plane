// @vitest-environment node
/**
 * The EdgeOne adapter on a fake Tencent account (testing/fakeEdgeOne.ts),
 * driven through the real SDK wrapper (its readers and error reduction): both
 * ways a zone gets its records (EdgeOne's own DNS, a DNS account), the free
 * certificate's wait for the name to point at EdgeOne, lost answers, a missing
 * CAM grant, a plan refusal, the location check and the destroy walk.
 */
import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import {
  __setEdgeOneCaaLookup,
  __setEdgeOneDnsClientFactory,
  edgeOneDomainSpec,
  edgeOneProvider,
} from './edgeone';
import { __setEdgeOneApiFactory, edgeOneSdkApi } from './edgeone/sdk';
import { fakeEdgeOne, type FakeEdgeOne, type FakeZone } from '../testing/fakeEdgeOne';
import { fakeDnsZone } from '../testing/fakeCloudFront';
import type {
  ChildResource,
  EdgeOneConfig,
  EdgeSpec,
  Ledger,
  ResourceStep,
  StepOutcome,
} from './types';
import type { EdgeOneTemplateParams } from './templates';

const ZONE_ID = 'zone-2abcdef01234';
const ZONE = 'example.org';
const HOST = 'k3m7q9zbx2wd.example.org';
const ORIGIN = 'node-7.origin.example.net';
const SECRET = 'SECRET_TENCENT_KEY_0123456789';

const ns: EdgeOneConfig = {
  type: 'edgeone',
  secretId: 'AKIDfcptestkey01',
  secretKey: SECRET,
  zoneId: ZONE_ID,
  zoneName: ZONE,
};
const dnsZone = {
  apiToken: 'SECRET_CF_TOKEN',
  zoneId: '0123456789abcdef0123456789abcdef',
  zoneName: ZONE,
  accountId: 'dnsacct1',
};
const viaAccount: EdgeOneConfig = {
  ...ns,
  dnsAccountId: 'dnsacct1',
  dnsZoneId: dnsZone.zoneId,
  dns: dnsZone,
};

const spec: EdgeSpec = {
  name: 'fcp-relay-o1-deadbeef',
  hostname: HOST,
  listeners: [{ edgePort: 443, members: [{ address: ORIGIN, port: 443 }] }],
  originTransport: {
    scheme: 'https',
    certPublic: true,
    certNames: ['*.origin.example.net'],
    acceptsHostHeader: 'any',
  },
};
const tpl = edgeOneProvider.templateSchema.parse({});

const zone = (over: Partial<FakeZone> = {}): FakeZone => ({
  ZoneId: ZONE_ID,
  ZoneName: ZONE,
  Type: 'full',
  Status: 'active',
  ActiveStatus: 'active',
  Area: 'overseas',
  ...over,
});

let fake: FakeEdgeOne;
function account(init: Parameters<typeof fakeEdgeOne>[0] = {}): FakeEdgeOne {
  fake = fakeEdgeOne({ zones: [zone()], ...init });
  __setEdgeOneApiFactory((cfg, diagnostic) => edgeOneSdkApi(cfg, diagnostic, fake.client));
  return fake;
}

beforeEach(() => {
  __setEdgeOneCaaLookup(async () => []);
});
afterEach(() => {
  __setEdgeOneApiFactory(null);
  __setEdgeOneDnsClientFactory(null);
  __setEdgeOneCaaLookup(null);
});

/** Fold a step outcome into the ledger the way the orchestrator's mutation does. */
function apply(ledger: Ledger, step: ResourceStep, out: StepOutcome): Ledger {
  const known = new Set(ledger.resources.map((r) => `${r.kind}:${r.resourceId}`));
  const fresh: ChildResource[] = ('resources' in out ? out.resources : []).filter(
    (r) => !known.has(`${r.kind}:${r.resourceId}`),
  );
  return {
    steps: [
      ...ledger.steps.filter((s) => s.stepId !== step.id),
      {
        stepId: step.id,
        kind: step.kind,
        resourceName: step.resourceName,
        state:
          out.status === 'done' ? 'done' : out.status === 'requested' ? 'requested' : 'unresolved',
        attempt: 1,
        ...(out.status === 'requested' ? { opRef: out.opRef } : {}),
      },
    ],
    resources: [
      ...ledger.resources,
      ...fresh.map((r) => ({
        stepId: step.id,
        kind: r.kind,
        resourceId: r.resourceId,
        ownership: r.ownership,
        deleteState: 'present' as const,
        ...(r.meta ? { meta: JSON.stringify(r.meta) } : {}),
      })),
    ],
  };
}

/** Run every planned step to `done` (polling a waiting one), or stop at the first other answer. */
async function provision(
  cfg: EdgeOneConfig,
  s: EdgeSpec = spec,
  t: EdgeOneTemplateParams = tpl,
  between?: (step: ResourceStep, out: StepOutcome) => void,
): Promise<{ ledger: Ledger; last: StepOutcome; waits: string[] }> {
  let ledger: Ledger = { steps: [], resources: [] };
  let last: StepOutcome = { status: 'done', resources: [] };
  const waits: string[] = [];
  for (const step of edgeOneProvider.planProvision(cfg, s, t)) {
    last = await edgeOneProvider.runStep(cfg, step, s, t, ledger);
    ledger = apply(ledger, step, last);
    for (let i = 0; last.status === 'requested' && i < 8; i++) {
      if (last.code) waits.push(`${step.id}:${last.code}`);
      between?.(step, last);
      last = await edgeOneProvider.pollStep!(cfg, step, last.opRef, ledger);
      ledger = apply(ledger, step, last);
    }
    if (last.status !== 'done') break;
  }
  return { ledger, last, waits };
}

/** Destroy in the adapter's order, running each delete until it is confirmed gone. */
async function destroyAll(cfg: EdgeOneConfig, ledger: Ledger): Promise<string[]> {
  const order: string[] = [];
  let live = ledger;
  for (let pass = 0; pass < 6; pass++) {
    const plan = edgeOneProvider.planDestroy(cfg, live);
    if (plan.length === 0) break;
    const r = plan[0]!;
    order.push(r.kind);
    let out = await edgeOneProvider.runDestroy(cfg, r, live);
    for (let i = 0; out.status !== 'confirmed_gone' && i < 4; i++)
      out = await edgeOneProvider.runDestroy(cfg, r, live);
    expect(out.status, r.kind).toBe('confirmed_gone');
    live = {
      ...live,
      resources: live.resources.map((x) =>
        x === r ? { ...x, deleteState: 'confirmed_gone' as const } : x,
      ),
    };
  }
  return order;
}

describe('edgeone: a zone EdgeOne hosts (NS access)', () => {
  test('creates the domain, switches on the record EdgeOne added, waits for the certificate, and tears it all down', async () => {
    account();
    const { ledger, last } = await provision(ns);
    expect(last.status).toBe('done');
    expect(ledger.resources.map((r) => r.kind)).toEqual([
      'acceleration_domain',
      'dns_record',
      'tls_subscription',
    ]);
    // The domain dials the node over TLS on its port, with the front name as Host.
    const d = fake.state.domains[0]!;
    expect(d.OriginDetail).toEqual({ OriginType: 'IP_DOMAIN', Origin: ORIGIN, HostHeader: HOST });
    expect([d.OriginProtocol, d.HttpsOriginPort]).toEqual(['HTTPS', 443]);
    expect(d.Certificate.Mode).toBe('eofreecert');
    // EdgeOne's own record, switched on; FCP wrote none of its own.
    expect(fake.state.records).toEqual([
      expect.objectContaining({ Name: HOST, Content: d.Cname, Status: 'enable', auto: true }),
    ]);
    expect(fake.state.calls).not.toContain('CreateDnsRecord');

    expect(await edgeOneProvider.describe(ns, ledger)).toMatchObject({
      state: 'active',
      addresses: { hostname: HOST },
      readiness: { dns: 'ready', certificate: 'ready' },
      health: 'unknown',
    });
    for (const step of edgeOneProvider.planProvision(ns, spec, tpl))
      expect((await edgeOneProvider.discover(ns, step, spec, ledger, 1)).status, step.id).toBe(
        'found',
      );

    expect(await destroyAll(ns, ledger)).toEqual([
      'acceleration_domain',
      'tls_subscription',
      'dns_record',
    ]);
    expect(fake.state.domains).toEqual([]);
    expect(fake.state.records).toEqual([]);
    expect(await edgeOneProvider.describe(ns, ledger)).toMatchObject({ state: 'gone' });
  });

  test('writes the CNAME itself when EdgeOne added none, and removes it after the domain', async () => {
    account({ autoRecord: false });
    const { ledger, last } = await provision(ns);
    expect(last.status).toBe('done');
    expect(fake.state.calls).toContain('CreateDnsRecord');
    expect(fake.state.records).toEqual([expect.objectContaining({ Name: HOST, Status: 'enable' })]);
    await destroyAll(ns, ledger);
    expect(fake.state.records).toEqual([]);
  });

  test('a record EdgeOne lists by its label under the zone is the same name', async () => {
    account();
    const { ledger } = await provision(ns);
    // The same record, as an API that names records by label would list it.
    fake.state.records[0]!.Name = HOST.slice(0, -(ZONE.length + 1));
    expect((await edgeOneProvider.describe(ns, ledger)).readiness).toMatchObject({ dns: 'ready' });
  });

  test('a record at the name that points elsewhere is somebody else’s: the run stops', async () => {
    account({ autoRecord: false });
    fake.state.records.push({
      RecordId: 'rec-x',
      ZoneId: ZONE_ID,
      Name: HOST,
      Type: 'CNAME',
      Content: 'elsewhere.example.net',
      Status: 'enable',
      TTL: 300,
    });
    const { last } = await provision(ns);
    expect(last).toMatchObject({ status: 'partial', refused: true, code: 'dns_record_exists' });
    expect(fake.state.records).toHaveLength(1);
  });
});

describe('edgeone: a zone connected by CNAME', () => {
  test('writes the CNAME through the DNS account and asks for the certificate once the name points at EdgeOne', async () => {
    account({ zones: [zone({ Type: 'partial' })] });
    const dns = fakeDnsZone(dnsZone);
    __setEdgeOneDnsClientFactory(() => dns);
    let resolving = false;
    fake.state.resolves = () => resolving;
    const { ledger, last, waits } = await provision(viaAccount, spec, tpl, (step) => {
      // The public resolver catches up while the certificate step waits.
      if (step.id === 'tls') resolving = true;
    });
    expect(last.status).toBe('done');
    expect(waits).toContain('tls:tls_challenge_missing');
    const d = fake.state.domains[0]!;
    expect(dns.rows).toEqual([
      expect.objectContaining({ type: 'CNAME', name: HOST, content: d.Cname, comment: spec.name }),
    ]);
    // EdgeOne's own DNS is never touched for such a zone.
    expect(fake.state.calls).not.toContain('DescribeDnsRecords');

    // The DNS account's record leaves first, then the domain.
    expect(await destroyAll(viaAccount, ledger)).toEqual([
      'dns_record',
      'acceleration_domain',
      'tls_subscription',
    ]);
    expect(dns.rows).toEqual([]);
    expect(fake.state.domains).toEqual([]);
  });

  test('a record at the name that FCP did not write is never adopted', async () => {
    account({ zones: [zone({ Type: 'partial' })] });
    const dns = fakeDnsZone(dnsZone, [
      {
        id: 'r1',
        type: 'CNAME',
        name: HOST,
        content: 'other.example.net',
        proxied: false,
        comment: 'not ours',
      },
    ]);
    __setEdgeOneDnsClientFactory(() => dns);
    const { last } = await provision(viaAccount);
    expect(last).toMatchObject({ status: 'partial', refused: true, code: 'dns_record_exists' });
  });
});

describe('edgeone: refusals, lost answers and discovery', () => {
  test('a plan limit stops the run with plan_limit, naming the action', async () => {
    account();
    fake.state.failNext.set('CreateAccelerationDomain', 'LimitExceeded.PackNotAllow');
    const { last } = await provision(ns);
    expect(last).toMatchObject({
      status: 'partial',
      refused: true,
      code: 'plan_limit',
      httpStatus: 400,
    });
    expect((last as { detail?: string }).detail).toContain(
      'LimitExceeded.PackNotAllow on teo:CreateAccelerationDomain',
    );
    expect(fake.state.domains).toEqual([]);
  });

  test('an unsupported plan, an expired one and a sold-out region are plan limits too', async () => {
    for (const code of [
      'OperationDenied.UnsupportedPlan',
      'OperationDenied.PlanHasBeenExpired',
      'ResourcesSoldOut.L7LackOfResources',
      'LimitExceeded',
    ]) {
      account();
      fake.state.failNext.set('CreateAccelerationDomain', code);
      const { last } = await provision(ns);
      expect(last, code).toMatchObject({ status: 'partial', refused: true, code: 'plan_limit' });
    }
  });

  test('a missing CAM grant on a create is a 403 refusal naming the action', async () => {
    account();
    fake.state.denied.add('CreateAccelerationDomain');
    const { last } = await provision(ns);
    expect(last).toMatchObject({ refused: true, code: 'permission_missing', httpStatus: 403 });
    expect((last as { detail?: string }).detail).toContain('teo:CreateAccelerationDomain');
  });

  test('a busy zone is not a refusal: the call throws for a retry', async () => {
    account();
    fake.state.failNext.set('CreateAccelerationDomain', 'OperationDenied.ResourceLockedTemporary');
    const step = edgeOneProvider.planProvision(ns, spec, tpl)[0]!;
    await expect(
      edgeOneProvider.runStep(ns, step, spec, tpl, { steps: [], resources: [] }),
    ).rejects.toMatchObject({ meta: { code: 'provider_busy', status: 409 } });
  });

  test('a create whose answer was lost is found by its name and origin, never made twice', async () => {
    account();
    fake.state.loseNext.add('CreateAccelerationDomain');
    const step = edgeOneProvider.planProvision(ns, spec, tpl)[0]!;
    const out = await edgeOneProvider.runStep(ns, step, spec, tpl, { steps: [], resources: [] });
    expect(out).toMatchObject({
      status: 'done',
      resources: [{ kind: 'acceleration_domain', resourceId: HOST, ownership: 'adopted' }],
    });
    expect(fake.state.domains).toHaveLength(1);
    expect(fake.state.calls.filter((c) => c === 'CreateAccelerationDomain')).toHaveLength(1);
  });

  test('discovery: absent is authoritative; a same-name domain dialing elsewhere is ambiguous', async () => {
    account();
    const step = edgeOneProvider.planProvision(ns, spec, tpl)[0]!;
    const empty: Ledger = { steps: [], resources: [] };
    expect(await edgeOneProvider.discover(ns, step, spec, empty, 1)).toEqual({
      status: 'confirmed_absent',
    });
    fake.handle('CreateAccelerationDomain', {
      ZoneId: ZONE_ID,
      DomainName: HOST,
      OriginInfo: { OriginType: 'IP_DOMAIN', Origin: 'someone-else.example.net' },
    });
    const d = await edgeOneProvider.discover(ns, step, spec, empty, 1);
    expect(d.status).toBe('ambiguous');
  });

  test("a zone serving another area than the template's is refused before anything is built", async () => {
    account({ zones: [zone({ Area: 'global' })] });
    const { last } = await provision(ns);
    expect(last).toMatchObject({ status: 'partial', refused: true, code: 'zone_area_mismatch' });
    expect(fake.state.domains).toEqual([]);
    // A template that asks for the zone's area builds there.
    account({ zones: [zone({ Area: 'global' })] });
    expect((await provision(ns, spec, { ...tpl, serviceArea: 'global' })).last.status).toBe('done');
  });

  test('a zone that reports no service area is refused too', async () => {
    account({ zones: [zone({ Area: undefined as never })] });
    const { last } = await provision(ns);
    expect(last).toMatchObject({ status: 'partial', refused: true, code: 'zone_area_mismatch' });
    expect(fake.state.domains).toEqual([]);
  });

  test('discovery: our CNAME pointing at an old target is not done, and the step moves it', async () => {
    account({ zones: [zone({ Type: 'partial' })] });
    const dns = fakeDnsZone(dnsZone);
    __setEdgeOneDnsClientFactory(() => dns);
    fake.state.resolves = () => true;
    const { ledger } = await provision(viaAccount);
    const dnsStep = edgeOneProvider
      .planProvision(viaAccount, spec, tpl)
      .find((x) => x.kind === 'create_dns_record')!;
    dns.rows[0]!.content = 'old-target.example.net';
    expect(await edgeOneProvider.discover(viaAccount, dnsStep, spec, ledger, 1)).toEqual({
      status: 'confirmed_absent',
    });
    expect((await edgeOneProvider.runStep(viaAccount, dnsStep, spec, tpl, ledger)).status).toBe(
      'done',
    );
    expect(dns.rows).toEqual([
      expect.objectContaining({ content: fake.state.domains[0]!.Cname, comment: spec.name }),
    ]);
  });

  test('a failed certificate stops the wait with tls_failed', async () => {
    account();
    const { ledger } = await provision(ns);
    fake.state.domains[0]!.Certificate.List[0]!.Status = 'failed';
    const awaitStep = edgeOneProvider
      .planProvision(ns, spec, tpl)
      .find((s) => s.kind === 'await_tls')!;
    expect(await edgeOneProvider.pollStep!(ns, awaitStep, HOST, ledger)).toMatchObject({
      status: 'partial',
      code: 'tls_failed',
    });
    expect(await edgeOneProvider.describe(ns, ledger)).toMatchObject({
      state: 'error',
      code: 'tls_failed',
    });
  });
});

describe('edgeone: the origin', () => {
  test("the node's own name as Host, on its own port, over plain HTTP", () => {
    const plain: EdgeSpec = {
      ...spec,
      listeners: [{ edgePort: 443, members: [{ address: ORIGIN, port: 8080 }] }],
      originTransport: { ...spec.originTransport!, scheme: 'http' },
    };
    expect(edgeOneDomainSpec(ns, plain, { ...tpl, overrideHost: 'origin' })).toEqual({
      zoneId: ZONE_ID,
      name: HOST,
      origin: ORIGIN,
      hostHeader: ORIGIN,
      originProtocol: 'HTTP',
      httpPort: 8080,
      httpsPort: 443,
      ipv6Status: 'follow',
    });
  });

  test('refused before any call: a port EdgeOne is not taken to dial, an address as the Host', () => {
    const at = (address: string, port: number): EdgeSpec => ({
      ...spec,
      listeners: [{ edgePort: 443, members: [{ address, port }] }],
    });
    // Any port 1-65535 (Tencent's data types); nothing outside it.
    expect(edgeOneProvider.planProvision(ns, at(ORIGIN, 808), tpl)).toHaveLength(4);
    expect(edgeOneProvider.planProvision(ns, at(ORIGIN, 22), tpl)).toHaveLength(4);
    for (const port of [0, 65536])
      expect(() => edgeOneProvider.planProvision(ns, at(ORIGIN, port), tpl), String(port)).toThrow(
        expect.objectContaining({
          meta: expect.objectContaining({ code: 'origin_port_unsupported' }),
        }),
      );
    expect(() =>
      edgeOneProvider.planProvision(ns, at('198.51.100.7', 443), {
        ...tpl,
        overrideHost: 'origin',
      }),
    ).toThrow(
      expect.objectContaining({ meta: expect.objectContaining({ code: 'origin_not_a_name' }) }),
    );
    // An address is fine as the origin when the front name is the Host.
    expect(edgeOneProvider.planProvision(ns, at('198.51.100.7', 443), tpl)).toHaveLength(4);
  });
});

describe('edgeone: the account and its locations', () => {
  test('the credential test lists the zones; a missing grant names the action', async () => {
    account();
    expect(await edgeOneProvider.testCredentials(ns)).toMatchObject({ ok: true });
    fake.state.denied.add('DescribeZones');
    const res = await edgeOneProvider.testCredentials(ns);
    expect(res).toMatchObject({ ok: false, code: 'permission_missing' });
    expect(res.detail).toContain('teo:DescribeZones');
    expect(JSON.stringify(res)).not.toContain(SECRET);
  });

  test('a rejected key is token_rejected; a location-less test reads zones only', async () => {
    account();
    fake.state.failNext.set('DescribeZones', 'AuthFailure.SecretIdNotFound');
    expect(await edgeOneProvider.testCredentials(ns)).toMatchObject({
      ok: false,
      code: 'token_rejected',
    });
    const { zoneId: _z, zoneName: _n, ...bare } = ns;
    fake.state.calls.length = 0;
    expect(await edgeOneProvider.testCredentials(bare as EdgeOneConfig)).toMatchObject({
      ok: true,
    });
    expect(fake.state.calls).toEqual(['DescribeZones']);
  });

  test('the zone list carries each zone’s access mode and area', async () => {
    account({
      zones: [zone(), zone({ ZoneId: 'zone-other0001', ZoneName: 'other.org', Type: 'partial' })],
    });
    expect(await edgeOneProvider.discoverOptions!({ ...ns })).toEqual({
      zones: [
        { id: ZONE_ID, label: ZONE, facts: { status: 'active', access: 'ns', area: 'overseas' } },
        {
          id: 'zone-other0001',
          label: 'other.org',
          facts: { status: 'active', access: 'cname', area: 'overseas' },
        },
      ],
    });
  });

  test('a location check records the zone and its WebSocket switch, and refuses a mismatched DNS account', async () => {
    account({ webSocket: { [ZONE_ID]: { Switch: 'on', Timeout: 120 } } });
    expect(await edgeOneProvider.checkLocation!(ns)).toMatchObject({
      ok: true,
      label: ZONE,
      observed: {
        zoneAccess: 'ns',
        zoneArea: 'overseas',
        edgeoneWebSocket: 'on',
        edgeoneWebSocketTimeout: '120',
        caa: 'no_records',
      },
    });
    __setEdgeOneDnsClientFactory(() => fakeDnsZone(dnsZone));
    expect(await edgeOneProvider.checkLocation!(viaAccount)).toMatchObject({
      ok: false,
      code: 'zone_dns_at_edgeone',
    });
    account({ zones: [zone({ Type: 'partial' })] });
    expect(await edgeOneProvider.checkLocation!(ns)).toMatchObject({
      ok: false,
      code: 'zone_needs_dns_account',
    });
    expect(await edgeOneProvider.checkLocation!(viaAccount)).toMatchObject({ ok: true });
  });

  test('a zone with WebSocket off is usable and says why a quiet tunnel closes', async () => {
    account();
    const res = await edgeOneProvider.checkLocation!(ns);
    expect(res).toMatchObject({ ok: true, observed: { edgeoneWebSocket: 'off' } });
    expect(res.detail).toMatch(/15 s/);
  });

  test('a paused zone, an inactive one and CAA records that allow neither authority are refused', async () => {
    account({ zones: [zone({ Paused: true, ActiveStatus: 'paused' })] });
    expect(await edgeOneProvider.checkLocation!(ns)).toMatchObject({
      ok: false,
      code: 'zone_paused',
    });
    account({ zones: [zone({ Status: 'pending' })] });
    expect(await edgeOneProvider.checkLocation!(ns)).toMatchObject({
      ok: false,
      code: 'zone_not_active',
    });
    account();
    __setEdgeOneCaaLookup(async (name) =>
      name === ZONE ? [{ flags: 0, tag: 'issue', value: 'certainly.com' }] : [],
    );
    expect(await edgeOneProvider.checkLocation!(ns)).toMatchObject({
      ok: false,
      code: 'caa_forbids_ca',
    });
    // Allowing one of EdgeOne's two authorities is not enough: it picks either.
    __setEdgeOneCaaLookup(async (name) =>
      name === ZONE ? [{ flags: 0, tag: 'issue', value: 'trustasia.com' }] : [],
    );
    expect(await edgeOneProvider.checkLocation!(ns)).toMatchObject({
      ok: false,
      code: 'caa_forbids_ca',
    });
    __setEdgeOneCaaLookup(async (name) =>
      name === ZONE
        ? [
            { flags: 0, tag: 'issue', value: 'trustasia.com' },
            { flags: 0, tag: 'issue', value: 'letsencrypt.org' },
          ]
        : [],
    );
    expect(await edgeOneProvider.checkLocation!(ns)).toMatchObject({ ok: true });
  });

  test('a zone not in effect yet (ActiveStatus) is not active', async () => {
    account({ zones: [zone({ ActiveStatus: 'inactive' })] });
    expect(await edgeOneProvider.checkLocation!(ns)).toMatchObject({
      ok: false,
      code: 'zone_not_active',
    });
  });

  test("CAA is judged under the zone's validation: DNS where EdgeOne hosts it, HTTP by CNAME", async () => {
    __setEdgeOneCaaLookup(async (name) =>
      name === ZONE
        ? [
            { flags: 0, tag: 'issue', value: 'letsencrypt.org; validationmethods=http-01' },
            { flags: 0, tag: 'issue', value: 'trustasia.com; validationmethods=http-01' },
          ]
        : [],
    );
    account();
    expect(await edgeOneProvider.checkLocation!(ns)).toMatchObject({
      ok: false,
      code: 'caa_forbids_ca',
    });
    account({ zones: [zone({ Type: 'partial' })] });
    __setEdgeOneDnsClientFactory(() => fakeDnsZone(dnsZone));
    expect(await edgeOneProvider.checkLocation!(viaAccount)).toMatchObject({ ok: true });
  });

  test('a zone EdgeOne hosts needs its records read: a key that may not is refused before any front', async () => {
    account();
    fake.state.denied.add('DescribeDnsRecords');
    const check = await edgeOneProvider.checkLocation!(ns);
    expect(check).toMatchObject({ ok: false, code: 'permission_missing' });
    expect(check.detail).toContain('teo:DescribeDnsRecords');
    expect(await edgeOneProvider.testCredentials(ns)).toMatchObject({
      ok: false,
      code: 'permission_missing',
    });
    // A zone connected by CNAME never reads EdgeOne's records.
    account({ zones: [zone({ Type: 'partial' })] });
    fake.state.denied.add('DescribeDnsRecords');
    __setEdgeOneDnsClientFactory(() => fakeDnsZone(dnsZone));
    expect(await edgeOneProvider.checkLocation!(viaAccount)).toMatchObject({ ok: true });
    expect(await edgeOneProvider.testCredentials(viaAccount)).toMatchObject({ ok: true });
  });

  test('a zone the key does not see is unreadable, not an outage', async () => {
    account({ zones: [] });
    expect(await edgeOneProvider.checkLocation!(ns)).toMatchObject({
      ok: false,
      code: 'zone_unreadable',
    });
  });

  test('inventory lists the zone’s domains with what they dial', async () => {
    account();
    await provision(ns);
    expect(await edgeOneProvider.inventory(ns)).toEqual({
      loadBalancers: [
        {
          id: HOST,
          name: HOST,
          status: 'online',
          addresses: { hostname: HOST },
          hostnames: [HOST],
          content: ORIGIN,
        },
      ],
      ips: [],
      flavors: [],
    });
  });
});
