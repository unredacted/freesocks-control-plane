// @vitest-environment node
/**
 * CloudFront adapter contract, on a fake AWS account (testing/fakeCloudFront.ts)
 * that keeps CloudFront's and ACM's documented rules: CallerReference and
 * alias uniqueness, ETags, disable before delete, one validation record per
 * name, a certificate in use is not deleted. The SDK's own wire format is
 * pinned by wireContract.test.ts; here the subject is what the adapter asks
 * for and in what order, and what it never asks for.
 */
import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import {
  CLOUDFRONT_ALWAYS_SENT,
  CLOUDFRONT_CACHING_DISABLED_POLICY_ID,
  CLOUDFRONT_DESTROY_ORDER,
  CLOUDFRONT_WEBSOCKET_HEADERS,
  __setCloudFrontCaaLookup,
  __setCloudFrontDnsClientFactory,
  certificateIdempotencyToken,
  cloudFrontAcmMarker,
  cloudFrontDestroyKey,
  cloudFrontDistributionConfig,
  cloudFrontOriginRequestPolicyConfig,
  cloudFrontProvider,
  effectiveCloudFrontParams,
} from './cloudfront';
import { __setCloudFrontApiFactory } from './cloudfront/sdk';
import { EDGE_PROVIDER_CAPABILITIES } from './capabilities';
import { CloudFrontTemplate, CLOUDFRONT_TEMPLATE_FIELDS } from './templates';
import { defaultsOf } from './options';
import {
  FAKE_AWS_ACCOUNT,
  FakeCloudFrontAccount,
  fakeDnsZone,
  type FakeDnsZone,
} from '../testing/fakeCloudFront';
import type { CaaRecord } from '../caa';
import type {
  CloudFrontConfig,
  DestroyOutcome,
  EdgeSpec,
  Ledger,
  LedgerResource,
  ResourceStep,
  StepOutcome,
} from './types';

const ZONE = 'fronts.example.org';
const HOSTNAME = `k3m7q9zbx2wd.${ZONE}`;
const ORIGIN = 'node-one.origin.example';
const SECRET = 'SECRET-aws-0123456789abcdefghijklmnop';

const cfg: CloudFrontConfig = {
  type: 'cloudfront',
  accessKeyId: 'AKIAEXAMPLEEXAMPLE00',
  secretAccessKey: SECRET,
  certificateScope: 'wildcard',
  dns: {
    apiToken: 'SECRET_CF_TOKEN_0123456789',
    zoneId: '0'.repeat(32),
    zoneName: ZONE,
    accountId: 'dns-acct',
  },
};

function specOf(over: Partial<EdgeSpec> = {}, name = 'fcp-relay-node-one-0123abcd'): EdgeSpec {
  return {
    name,
    hostname: HOSTNAME,
    listeners: [{ edgePort: 443, members: [{ address: ORIGIN, port: 443 }] }],
    originTransport: {
      scheme: 'https',
      certPublic: true,
      certNames: [ORIGIN],
      acceptsHostHeader: 'names',
    },
    ...over,
  };
}

const tpl = CloudFrontTemplate.parse({});

let aws: FakeCloudFrontAccount;
let dns: FakeDnsZone;
let caa: Record<string, CaaRecord[]>;

beforeEach(() => {
  aws = new FakeCloudFrontAccount();
  dns = fakeDnsZone(cfg.dns!);
  aws.dns = dns;
  caa = {};
  __setCloudFrontApiFactory((_cfg, diagnostic) => aws.api(diagnostic));
  __setCloudFrontDnsClientFactory(() => dns);
  __setCloudFrontCaaLookup(async (name) => caa[name] ?? []);
});

afterEach(() => {
  __setCloudFrontApiFactory(null);
  __setCloudFrontDnsClientFactory(null);
  __setCloudFrontCaaLookup(null);
});

// --- a small orchestrator: what the rotation's settle and the reconcile walk do ------------

function settle(ledger: Ledger, step: ResourceStep, out: StepOutcome | { resources: [] }) {
  for (const r of out.resources) {
    if (ledger.resources.some((x) => x.kind === r.kind && x.resourceId === r.resourceId)) continue;
    ledger.resources.push({
      stepId: step.id,
      kind: r.kind,
      resourceId: r.resourceId,
      ownership: r.ownership,
      deleteState: 'present',
      ...(r.meta ? { meta: JSON.stringify(r.meta) } : {}),
    });
  }
  const s = ledger.steps.find((x) => x.stepId === step.id);
  const state = 'status' in out && out.status === 'requested' ? 'requested' : 'done';
  if (s) s.state = state;
  else
    ledger.steps.push({
      stepId: step.id,
      kind: step.kind,
      resourceName: step.resourceName,
      state,
      attempt: 1,
      startedAt: Date.now(),
    });
}

async function runToDone(
  step: ResourceStep,
  spec: EdgeSpec,
  ledger: Ledger,
  t: Record<string, unknown> = tpl,
): Promise<StepOutcome> {
  let out = await cloudFrontProvider.runStep(cfg, step, spec, t as never, ledger);
  for (let i = 0; out.status === 'requested' && i < 20; i++) {
    settle(ledger, step, out);
    out = await cloudFrontProvider.pollStep!(cfg, step, out.opRef, ledger);
  }
  return out;
}

/** Every planned step, polled until done, like a rotation's provision. */
async function provision(spec = specOf(), t: Record<string, unknown> = tpl): Promise<Ledger> {
  const ledger: Ledger = { steps: [], resources: [] };
  for (const step of cloudFrontProvider.planProvision(cfg, spec, t as never)) {
    const out = await runToDone(step, spec, ledger, t);
    expect(out.status, step.id).toBe('done');
    settle(ledger, step, out);
  }
  return ledger;
}

function stepOfKind(kind: string, spec = specOf()): ResourceStep {
  return cloudFrontProvider.planProvision(cfg, spec, tpl).find((s) => s.kind === kind)!;
}

/**
 * One reconcile destroy pass (edgeReconcile `destroyStep`): walk the plan in
 * kind order, confirm a requested delete (re-issuing it when the read-back
 * says it never landed), read an issued one back at once (an async-delete
 * provider), and stop at the first resource still going away.
 */
async function destroyPass(ledger: Ledger): Promise<boolean> {
  for (;;) {
    const plan = cloudFrontProvider
      .planDestroy(cfg, ledger)
      .filter((r) => r.deleteState !== 'confirmed_gone');
    if (plan.length === 0) return true;
    const target = plan[0]!;
    const row = ledger.resources.find((r) => r === target)!;
    let out: DestroyOutcome =
      target.deleteState === 'delete_requested'
        ? await cloudFrontProvider.confirmDestroyed!(cfg, target, ledger)
        : await cloudFrontProvider.runDestroy(cfg, target, ledger);
    if (target.deleteState !== 'delete_requested' && out.status === 'delete_requested') {
      const back = await cloudFrontProvider.confirmDestroyed!(
        cfg,
        { ...target, deleteState: 'delete_requested' },
        ledger,
      );
      if (back.status === 'confirmed_gone') out = back;
    }
    row.deleteState =
      out.status === 'confirmed_gone'
        ? 'confirmed_gone'
        : out.status === 'delete_requested'
          ? 'delete_requested'
          : out.status === 'still_present'
            ? 'present'
            : row.deleteState;
    if (row.deleteState !== 'confirmed_gone') return false;
  }
}

async function destroyAll(ledger: Ledger, maxPasses = 20): Promise<number> {
  for (let pass = 1; pass <= maxPasses; pass++) if (await destroyPass(ledger)) return pass;
  throw new Error('destroy did not finish');
}

const ofKind = (ledger: Ledger, kind: string) => ledger.resources.filter((r) => r.kind === kind);
const metaOfRow = (r: LedgerResource) => JSON.parse(r.meta ?? '{}') as Record<string, unknown>;

// --- plan ----------------------------------------------------------------------------------

describe('cloudfront: plan', () => {
  test('six steps, each a single call discoverable by name, certificate first and the traffic name last', () => {
    const steps = cloudFrontProvider.planProvision(cfg, specOf(), tpl);
    expect(steps.map((s) => [s.id, s.kind, s.resourceName])).toEqual([
      ['tls', 'create_tls_subscription', `*.${ZONE}`],
      ['acme', 'create_dns_acme', `*.${ZONE}`],
      ['await-tls', 'await_tls', `*.${ZONE}`],
      ['distribution', 'create_service', 'fcp-relay-node-one-0123abcd'],
      ['deploy', 'activate_version', 'fcp-relay-node-one-0123abcd'],
      ['dns', 'create_dns_record', HOSTNAME],
    ]);
    expect(steps.every((s) => s.discoverability === 'by_name')).toBe(true);
  });

  test.each([
    ['an IP address', { address: '198.51.100.7', port: 443 }, {}, 'origin_not_a_name'],
    [
      'a privileged port other than 80 and 443',
      { address: ORIGIN, port: 22 },
      {},
      'origin_port_unsupported',
    ],
    ['port 1023', { address: ORIGIN, port: 1023 }, {}, 'origin_port_unsupported'],
    [
      'a private certificate',
      { address: ORIGIN, port: 443 },
      { certPublic: false },
      'origin_cert_not_public',
    ],
    [
      'a name its certificate does not cover',
      { address: ORIGIN, port: 443 },
      { certNames: ['other.example'] },
      'origin_cert_name_uncovered',
    ],
  ])('refuses %s before any call', (_label, member, transport, code) => {
    const base = specOf();
    const spec = specOf({
      listeners: [{ edgePort: 443, members: [member] }],
      originTransport: { ...base.originTransport!, ...transport },
    });
    expect(() => cloudFrontProvider.planProvision(cfg, spec, tpl)).toThrow(
      expect.objectContaining({ meta: expect.objectContaining({ code }) }),
    );
    expect(aws.calls).toEqual([]);
  });

  test('takes 80, 443 and any port from 1024 up, over TLS or not', () => {
    for (const [scheme, port] of [
      ['https', 443],
      ['https', 8443],
      ['http', 80],
      ['http', 2052],
      ['https', 65535],
    ] as const) {
      const base = specOf();
      const spec = specOf({
        listeners: [{ edgePort: 443, members: [{ address: ORIGIN, port }] }],
        originTransport: { ...base.originTransport!, scheme },
      });
      expect(() => cloudFrontProvider.planProvision(cfg, spec, tpl)).not.toThrow();
    }
  });

  test('the capability row: WebSocket only, records through a DNS account, the origin as Host', () => {
    const caps = EDGE_PROVIDER_CAPABILITIES.cloudfront;
    expect(caps).toMatchObject({
      layer: 'l7',
      role: 'edge',
      addressKind: 'hostname',
      l7Transports: ['ws'],
      needsDnsAccount: true,
      providesDns: false,
      originPortMode: 'web-or-high',
      originHostHeader: 'origin',
      sharedCertificates: true,
      asyncOps: true,
      asyncDelete: true,
      idleTimeoutConfigurable: false,
      memberHealth: false,
    });
    expect(caps.typicalProvisionMs).toBeGreaterThanOrEqual(5 * 60_000);
  });
});

// --- the whole lifecycle -----------------------------------------------------------------

describe('cloudfront: a front from nothing', () => {
  test('certificate, its validation record, issuance, distribution, deployment, traffic name', async () => {
    const spec = specOf();
    const ledger = await provision(spec);
    // One wildcard for the zone, DNS-validated, requested with the edge's token.
    expect(aws.certificates).toHaveLength(1);
    const cert = aws.certificates[0]!;
    expect(cert).toMatchObject({ domainName: `*.${ZONE}`, status: 'ISSUED' });
    const sub = ofKind(ledger, 'tls_subscription')[0]!;
    expect(sub).toMatchObject({ resourceId: cert.arn, ownership: 'created' });
    expect(metaOfRow(sub)).toMatchObject({ shared: true, wildcard: true, hostname: `*.${ZONE}` });
    // ACM's validation record, marked as this AWS account's.
    const acme = dns.rows.find((r) => r.name === cert.record.name.replace(/\.$/, ''))!;
    expect(acme).toMatchObject({
      type: 'CNAME',
      content: cert.record.value.replace(/\.$/, ''),
      proxied: false,
      comment: `fcp-cert:${FAKE_AWS_ACCOUNT}:${cert.arn.split('/')[1]}`,
    });
    expect(
      metaOfRow(ofKind(ledger, 'dns_record').find((r) => metaOfRow(r).role === 'acme')!),
    ).toMatchObject({ shared: true });
    // The distribution, deployed, and the traffic name pointing at it.
    const d = aws.distributions[0]!;
    expect(d.status).toBe('Deployed');
    expect(ofKind(ledger, 'distribution')[0]).toMatchObject({
      resourceId: d.id,
      ownership: 'created',
    });
    const traffic = dns.rows.find((r) => r.name === HOSTNAME)!;
    expect(traffic).toMatchObject({ type: 'CNAME', content: d.domainName, comment: spec.name });
    // The policy is shared, created by this first front.
    const policy = ofKind(ledger, 'origin_request_policy')[0]!;
    expect(policy).toMatchObject({ resourceId: aws.policies[0]!.id, ownership: 'created' });
    expect(metaOfRow(policy)).toMatchObject({ shared: true, name: 'fcp-ws-1' });

    const described = await cloudFrontProvider.describe(cfg, ledger);
    expect(described).toMatchObject({
      state: 'active',
      addresses: { hostname: HOSTNAME },
      health: 'unknown',
      readiness: { dns: 'ready', certificate: 'ready' },
    });
  });

  test('a second front of the zone reuses the certificate, its record and the policy, and waits for nothing', async () => {
    await provision(specOf());
    aws.calls.length = 0;
    const second = specOf({ hostname: `zz9q8w7e6r5t.${ZONE}` }, 'fcp-relay-node-two-89abcdef');
    const ledger: Ledger = { steps: [], resources: [] };
    for (const step of cloudFrontProvider.planProvision(cfg, second, tpl)) {
      const out = await cloudFrontProvider.runStep(cfg, step, second, tpl, ledger);
      if (step.kind === 'activate_version') {
        expect(out.status).toBe('requested');
        settle(ledger, step, out);
        continue;
      }
      expect(out.status, step.id).toBe('done');
      settle(ledger, step, out);
    }
    expect(aws.calls).not.toContain('requestCertificate');
    expect(aws.calls).not.toContain('createOriginRequestPolicy');
    expect(aws.certificates).toHaveLength(1);
    expect(aws.policies).toHaveLength(1);
    expect(ofKind(ledger, 'tls_subscription')[0]!.ownership).toBe('adopted');
    expect(ofKind(ledger, 'origin_request_policy')[0]!.ownership).toBe('adopted');
    // One validation record for the name, still the first one.
    expect(dns.rows.filter((r) => r.name.startsWith('_'))).toHaveLength(1);
    expect(aws.usersOfPolicy(aws.policies[0]!.id)).toBe(2);
  });
});

// --- the shared certificate ----------------------------------------------------------------

describe('cloudfront: the shared ACM certificate', () => {
  test('a lost request is found by name, and a repeated one answers the same certificate', async () => {
    const spec = specOf();
    const tls = stepOfKind('create_tls_subscription');
    aws.failures.set('requestCertificate', 'lost');
    const ledger: Ledger = { steps: [], resources: [] };
    await expect(cloudFrontProvider.runStep(cfg, tls, spec, tpl, ledger)).rejects.toMatchObject({
      meta: { timedOut: true },
    });
    expect(aws.certificates).toHaveLength(1);
    const found = await cloudFrontProvider.discover(cfg, tls, spec, ledger, 1);
    expect(found).toMatchObject({
      status: 'found',
      resources: [{ kind: 'tls_subscription', resourceId: aws.certificates[0]!.arn }],
    });
    // ACM's own guarantee the step leans on: the same token, the same certificate.
    const token = certificateIdempotencyToken(spec.name, `*.${ZONE}`);
    expect(token).toMatch(/^\w{1,32}$/);
    expect(
      await aws.api().requestCertificate({ domainName: `*.${ZONE}`, idempotencyToken: token }),
    ).toBe(aws.certificates[0]!.arn);
    expect(aws.certificates).toHaveLength(1);
  });

  test('an imported certificate, one another service manages and an expired one are never reused', async () => {
    aws.addCertificate({ domainName: `*.${ZONE}`, type: 'IMPORTED' });
    aws.addCertificate({ domainName: `*.${ZONE}`, managedBy: 'CLOUDFRONT' });
    aws.addCertificate({ domainName: `*.${ZONE}`, status: 'EXPIRED' });
    const out = await cloudFrontProvider.runStep(
      cfg,
      stepOfKind('create_tls_subscription'),
      specOf(),
      tpl,
      { steps: [], resources: [] },
    );
    expect(out).toMatchObject({ status: 'done', resources: [{ ownership: 'created' }] });
    expect(aws.calls).toContain('requestCertificate');
  });

  test('several candidates are never guessed between', async () => {
    aws.addCertificate({ domainName: `*.${ZONE}` });
    aws.addCertificate({ domainName: `*.${ZONE}`, status: 'PENDING_VALIDATION' });
    const tls = stepOfKind('create_tls_subscription');
    await expect(
      cloudFrontProvider.runStep(cfg, tls, specOf(), tpl, { steps: [], resources: [] }),
    ).rejects.toMatchObject({ meta: { code: 'shared_certificate_ambiguous' } });
    const d = await cloudFrontProvider.discover(
      cfg,
      tls,
      specOf(),
      { steps: [], resources: [] },
      1,
    );
    expect(d.status).toBe('ambiguous');
    expect(aws.calls).not.toContain('requestCertificate');
  });

  test('a failed certificate is reported, not silently replaced; a CAA refusal says so', async () => {
    const cert = aws.addCertificate({
      domainName: `*.${ZONE}`,
      status: 'FAILED',
      failureReason: 'CAA_ERROR',
    });
    const ledger = { steps: [], resources: [] } as Ledger;
    settle(
      ledger,
      stepOfKind('create_tls_subscription'),
      await cloudFrontProvider.runStep(
        cfg,
        stepOfKind('create_tls_subscription'),
        specOf(),
        tpl,
        ledger,
      ),
    );
    expect(ofKind(ledger, 'tls_subscription')[0]!.resourceId).toBe(cert.arn);
    const out = await cloudFrontProvider.runStep(
      cfg,
      stepOfKind('await_tls'),
      specOf(),
      tpl,
      ledger,
    );
    expect(out).toEqual({ status: 'partial', resources: [], code: 'tls_caa_conflict' });
    cert.failureReason = 'NO_AVAILABLE_CONTACTS';
    expect(
      await cloudFrontProvider.runStep(cfg, stepOfKind('await_tls'), specOf(), tpl, ledger),
    ).toMatchObject({ status: 'partial', code: 'tls_failed' });
    expect((await cloudFrontProvider.sharedCertificate!(cfg, {}))!).toMatchObject({
      state: 'failed',
      code: 'tls_failed',
    });
  });

  test('a wait whose validation record is missing says so', async () => {
    aws.dns = undefined; // nothing issues it
    const cert = aws.addCertificate({ domainName: `*.${ZONE}`, status: 'PENDING_VALIDATION' });
    const ledger: Ledger = { steps: [], resources: [] };
    settle(ledger, stepOfKind('create_tls_subscription'), {
      status: 'done',
      resources: [{ kind: 'tls_subscription', resourceId: cert.arn, ownership: 'adopted' }],
    });
    const out = await cloudFrontProvider.runStep(
      cfg,
      stepOfKind('await_tls'),
      specOf(),
      tpl,
      ledger,
    );
    expect(out).toEqual({
      status: 'requested',
      opRef: cert.arn,
      resources: [],
      code: 'tls_challenge_missing',
    });
  });

  test("the validation record: ACM's value already there is used as it is, a foreign one with another value stops the step", async () => {
    const cert = aws.addCertificate({ domainName: `*.${ZONE}`, status: 'PENDING_VALIDATION' });
    const ledger: Ledger = { steps: [], resources: [] };
    settle(ledger, stepOfKind('create_tls_subscription'), {
      status: 'done',
      resources: [{ kind: 'tls_subscription', resourceId: cert.arn, ownership: 'adopted' }],
    });
    const name = cert.record.name.replace(/\.$/, '');
    // Somebody else's record at ACM's name with another value: never touched.
    dns.rows.push({
      id: 'theirs',
      type: 'CNAME',
      name,
      content: 'elsewhere.example',
      proxied: false,
    });
    const acme = stepOfKind('create_dns_acme');
    await expect(
      cloudFrontProvider.runStep(cfg, acme, specOf(), tpl, ledger),
    ).rejects.toMatchObject({ meta: { code: 'acme_name_in_use' } });
    expect(dns.deleted).toEqual([]);
    // The same record holding ACM's value: it validates, so it is used (as a
    // candidate: it was not written by this account's FCP, so never deleted).
    dns.rows[0]!.content = cert.record.value.replace(/\.$/, '');
    const out = await cloudFrontProvider.runStep(cfg, acme, specOf(), tpl, ledger);
    expect(out).toMatchObject({
      status: 'done',
      resources: [
        { kind: 'dns_record', resourceId: 'theirs', meta: { candidate: true, shared: true } },
      ],
    });
  });

  test("our own account's record with a stale value is replaced, and only ours", async () => {
    const cert = aws.addCertificate({ domainName: `*.${ZONE}`, status: 'PENDING_VALIDATION' });
    const ledger: Ledger = { steps: [], resources: [] };
    settle(ledger, stepOfKind('create_tls_subscription'), {
      status: 'done',
      resources: [{ kind: 'tls_subscription', resourceId: cert.arn, ownership: 'adopted' }],
    });
    const name = cert.record.name.replace(/\.$/, '');
    dns.rows.push({
      id: 'ours-old',
      type: 'CNAME',
      name,
      content: 'edited.by.hand.example',
      proxied: false,
      comment: `fcp-cert:${FAKE_AWS_ACCOUNT}:gone-certificate`,
    });
    const out = await cloudFrontProvider.runStep(
      cfg,
      stepOfKind('create_dns_acme'),
      specOf(),
      tpl,
      ledger,
    );
    expect(out.status).toBe('done');
    expect(dns.deleted).toEqual(['ours-old']);
    expect(dns.rows.find((r) => r.name === name)).toMatchObject({
      content: cert.record.value.replace(/\.$/, ''),
      comment: cloudFrontAcmMarker(cert.arn),
    });
  });

  test('the account page reads its state: absent, pending, issued, renewing, expiring', async () => {
    expect(await cloudFrontProvider.sharedCertificate!(cfg, {})).toEqual({
      name: `*.${ZONE}`,
      state: 'absent',
    });
    aws.dns = undefined;
    const cert = aws.addCertificate({ domainName: `*.${ZONE}`, status: 'PENDING_VALIDATION' });
    expect(await cloudFrontProvider.sharedCertificate!(cfg, {})).toMatchObject({
      subscriptionId: cert.arn,
      state: 'pending',
      code: 'tls_challenge_missing',
    });
    cert.status = 'ISSUED';
    cert.notAfter = new Date(Date.now() + 90 * 86_400_000).toISOString();
    expect(await cloudFrontProvider.sharedCertificate!(cfg, {})).toEqual({
      name: `*.${ZONE}`,
      subscriptionId: cert.arn,
      state: 'issued',
      notAfter: cert.notAfter,
    });
    cert.renewalStatus = 'PENDING_AUTO_RENEWAL';
    expect((await cloudFrontProvider.sharedCertificate!(cfg, {}))!.state).toBe('renewing');
    cert.renewalStatus = undefined;
    cert.notAfter = new Date(Date.now() + 2 * 86_400_000).toISOString();
    expect((await cloudFrontProvider.sharedCertificate!(cfg, {}))!.code).toBe(
      'certificate_expiring',
    );
  });

  test('removal deletes only a certificate an edge ordered, never one in use, and only our record', async () => {
    const ledger = await provision();
    const arn = aws.certificates[0]!.arn;
    const record = aws.certificates[0]!.record.name.replace(/\.$/, '');
    dns.rows.push({
      id: 'foreign',
      type: 'CNAME',
      name: `x.${ZONE}`,
      content: 'y.example',
      proxied: false,
      comment: 'fcp-cert:999999999999:other',
    });
    expect(await cloudFrontProvider.removeSharedCertificate!(cfg, { ordered: [] })).toEqual({
      removed: false,
      code: 'shared_certificate_not_ours',
    });
    const ordered = [`tls_subscription:${arn}`];
    // A distribution still serves it: ACM refuses, nothing is removed.
    expect(await cloudFrontProvider.removeSharedCertificate!(cfg, { ordered })).toEqual({
      removed: false,
      code: 'shared_certificate_in_use',
    });
    await destroyAll(ledger);
    expect(await cloudFrontProvider.removeSharedCertificate!(cfg, { ordered })).toEqual({
      removed: true,
    });
    expect(aws.certificates).toEqual([]);
    expect(dns.rows.some((r) => r.name === record)).toBe(false);
    expect(dns.rows.some((r) => r.id === 'foreign')).toBe(true);
  });
});

// --- what reaches the node --------------------------------------------------------------------

/**
 * CloudFront's origin request, as its documentation builds it from a viewer
 * request and the origin request policy: a whitelist policy forwards the viewer
 * headers it names (and the CloudFront-* headers it names), and CloudFront adds
 * X-Forwarded-For (the viewer's address, appended), X-Amz-Cf-Id, Via, its own
 * User-Agent and the origin's own name as Host, whatever the policy says.
 */
function originRequestHeaders(
  viewer: Record<string, string>,
  viewerAddress: string,
  policy: ReturnType<typeof cloudFrontOriginRequestPolicyConfig>,
): Record<string, string> {
  const out: Record<string, string> = {};
  const allowed = new Set((policy.HeadersConfig?.Headers?.Items ?? []).map((h) => h.toLowerCase()));
  expect(policy.HeadersConfig?.HeaderBehavior).toBe('whitelist');
  for (const [k, v] of Object.entries(viewer)) if (allowed.has(k.toLowerCase())) out[k] = v;
  if (allowed.has('cloudfront-viewer-address'))
    out['CloudFront-Viewer-Address'] = `${viewerAddress}:51234`;
  const xff = viewer['X-Forwarded-For'];
  out['X-Forwarded-For'] = xff ? `${xff}, ${viewerAddress}` : viewerAddress;
  out['X-Amz-Cf-Id'] = 'abcdEXAMPLE==';
  out['Via'] = '1.1 abcdef.cloudfront.net (CloudFront)';
  out['User-Agent'] = 'Amazon CloudFront';
  out['Host'] = ORIGIN;
  return out;
}

const MEMBER = '203.0.113.77';
/** A WebSocket upgrade with every address header a client could forge. */
const UPGRADE = {
  'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
  'Sec-WebSocket-Version': '13',
  'Sec-WebSocket-Protocol': 'early-data',
  'X-Real-IP': '192.0.2.1',
  'True-Client-IP': '192.0.2.2',
  Forwarded: 'for=192.0.2.3',
  'X-Forwarded-For': '192.0.2.4',
  'CloudFront-Viewer-Address': '192.0.2.5:1',
  'Fastly-Client-IP': '192.0.2.6',
  'CF-Connecting-IP': '192.0.2.7',
};

describe('cloudfront: the member address never reaches the node through the policy', () => {
  test('the policy is a whitelist of the WebSocket handshake headers, nothing that carries an address', () => {
    const policy = cloudFrontOriginRequestPolicyConfig('ws', 1);
    expect(policy).toMatchObject({
      Name: 'fcp-ws-1',
      HeadersConfig: { HeaderBehavior: 'whitelist' },
      CookiesConfig: { CookieBehavior: 'none' },
    });
    expect(policy.HeadersConfig!.Headers!.Items).toEqual([...CLOUDFRONT_WEBSOCKET_HEADERS]);
    expect(policy.HeadersConfig!.Headers!.Quantity).toBe(CLOUDFRONT_WEBSOCKET_HEADERS.length);
    for (const h of policy.HeadersConfig!.Headers!.Items!) expect(h).toMatch(/^Sec-WebSocket-/);
  });

  test("the node sees no member address but CloudFront's own X-Forwarded-For, which the node removes", () => {
    const seen = originRequestHeaders(
      UPGRADE,
      MEMBER,
      cloudFrontOriginRequestPolicyConfig('ws', 1),
    );
    const carrying = Object.entries(seen).filter(
      ([, v]) => v.includes(MEMBER) || /192\.0\.2\./.test(v),
    );
    // Only CloudFront's own header carries an address: documented as always
    // sent, never removable by a policy, and stripped by the node's Caddy.
    expect(carrying.map(([k]) => k)).toEqual(['X-Forwarded-For']);
    expect(CLOUDFRONT_ALWAYS_SENT).toContain('X-Forwarded-For');
    for (const forged of [
      'X-Real-IP',
      'True-Client-IP',
      'Forwarded',
      'Fastly-Client-IP',
      'CF-Connecting-IP',
    ])
      expect(seen[forged]).toBeUndefined();
    expect(seen['CloudFront-Viewer-Address']).toBeUndefined();
    // The handshake itself gets through.
    expect(seen['Sec-WebSocket-Key']).toBe(UPGRADE['Sec-WebSocket-Key']);
    expect(seen['Host']).toBe(ORIGIN);
  });

  test('with forwardClientAddress on, a second policy adds CloudFront-Viewer-Address and nothing else', () => {
    const on = cloudFrontOriginRequestPolicyConfig('ws-address', 1);
    expect(on.Name).toBe('fcp-ws-address-1');
    expect(on.HeadersConfig!.Headers!.Items).toEqual([
      ...CLOUDFRONT_WEBSOCKET_HEADERS,
      'CloudFront-Viewer-Address',
    ]);
    const seen = originRequestHeaders(UPGRADE, MEMBER, on);
    expect(seen['CloudFront-Viewer-Address']).toBe(`${MEMBER}:51234`);
    expect(seen['X-Real-IP']).toBeUndefined();
  });

  test('every distribution uses FCP policy, the uncached policy, and no function or custom header', async () => {
    const ledger = await provision();
    const d = aws.distributions[0]!.config;
    const policyId = ofKind(ledger, 'origin_request_policy')[0]!.resourceId;
    expect(d.DefaultCacheBehavior).toMatchObject({
      OriginRequestPolicyId: policyId,
      CachePolicyId: CLOUDFRONT_CACHING_DISABLED_POLICY_ID,
      LambdaFunctionAssociations: { Quantity: 0 },
      FunctionAssociations: { Quantity: 0 },
    });
    expect(d.Origins!.Items![0]!.CustomHeaders).toEqual({ Quantity: 0 });
    // The account's policy is FCP's whitelist, never a managed all-viewer one.
    const p = aws.policies.find((x) => x.id === policyId)!;
    expect(p.config.HeadersConfig?.HeaderBehavior).toBe('whitelist');
    expect(p.config.HeadersConfig?.Headers?.Items).not.toContain('CloudFront-Viewer-Address');
  });

  test('a front whose options pass the address on gets the other policy; the default one is untouched', async () => {
    await provision();
    const withAddress = specOf({ hostname: `aaaabbbbcccc.${ZONE}` }, 'fcp-relay-node-two-89abcdef');
    const l = await provision(withAddress, { ...tpl, forwardClientAddress: true });
    const id = ofKind(l, 'origin_request_policy')[0]!.resourceId;
    expect(aws.policies.find((p) => p.id === id)!.config.Name).toBe('fcp-ws-address-1');
    expect(aws.usersOfPolicy(aws.policies.find((p) => p.config.Name === 'fcp-ws-1')!.id)).toBe(1);
  });
});

// --- the distribution ---------------------------------------------------------------------

describe('cloudfront: the distribution', () => {
  test('what it is built as (the defaults FCP sends)', () => {
    const c = cloudFrontDistributionConfig(specOf(), tpl, 'arn:cert', 'orp-1');
    expect(c).toMatchObject({
      CallerReference: 'fcp-relay-node-one-0123abcd',
      Comment: 'fcp-relay-node-one-0123abcd',
      Enabled: true,
      Aliases: { Quantity: 1, Items: [HOSTNAME] },
      PriceClass: 'PriceClass_All',
      HttpVersion: 'http1.1',
      IsIPV6Enabled: true,
      Logging: { Enabled: false },
      ViewerCertificate: {
        ACMCertificateArn: 'arn:cert',
        SSLSupportMethod: 'sni-only',
        MinimumProtocolVersion: 'TLSv1.2_2021',
        CloudFrontDefaultCertificate: false,
      },
      DefaultCacheBehavior: {
        ViewerProtocolPolicy: 'https-only',
        AllowedMethods: { Items: ['GET', 'HEAD'] },
        Compress: false,
      },
    });
    expect(c.Origins!.Items![0]).toMatchObject({
      Id: 'origin',
      DomainName: ORIGIN,
      ConnectionAttempts: 3,
      ConnectionTimeout: 10,
      CustomOriginConfig: {
        HTTPPort: 80,
        HTTPSPort: 443,
        OriginProtocolPolicy: 'https-only',
        OriginSslProtocols: { Quantity: 1, Items: ['TLSv1.2'] },
        OriginReadTimeout: 30,
        OriginKeepaliveTimeout: 5,
      },
    });
  });

  test("every option reaches its field; a plaintext origin's port is its HTTP port", () => {
    const base = specOf();
    const c = cloudFrontDistributionConfig(
      specOf({
        listeners: [{ edgePort: 443, members: [{ address: ORIGIN, port: 8080 }] }],
        originTransport: { ...base.originTransport!, scheme: 'http' },
      }),
      {
        ...tpl,
        priceClass: 'PriceClass_100',
        ipv6: false,
        viewerHttpVersion: 'http2',
        viewerMinTlsVersion: 'TLSv1.3_2025',
        originMinTlsVersion: 'TLSv1.1',
        originConnectTimeoutS: 4,
        originConnectAttempts: 1,
        originReadTimeoutS: 60,
        originKeepaliveTimeoutS: 30,
      },
      'arn:cert',
      'orp-1',
    );
    expect(c).toMatchObject({
      PriceClass: 'PriceClass_100',
      IsIPV6Enabled: false,
      HttpVersion: 'http2',
      ViewerCertificate: { MinimumProtocolVersion: 'TLSv1.3_2025' },
    });
    expect(c.Origins!.Items![0]).toMatchObject({
      ConnectionAttempts: 1,
      ConnectionTimeout: 4,
      CustomOriginConfig: {
        HTTPPort: 8080,
        HTTPSPort: 443,
        OriginProtocolPolicy: 'http-only',
        OriginSslProtocols: { Items: ['TLSv1.1', 'TLSv1.2'] },
        OriginReadTimeout: 60,
        OriginKeepaliveTimeout: 30,
      },
    });
  });

  test('every option the template leaves unset takes its declared default', () => {
    const effective = effectiveCloudFrontParams(tpl);
    for (const [k, v] of Object.entries(defaultsOf(CLOUDFRONT_TEMPLATE_FIELDS)))
      expect(effective[k as keyof typeof effective], k).toEqual(v);
  });

  test('a lost create answer is found by its comment, and a re-run never makes a second distribution', async () => {
    const spec = specOf();
    const ledger: Ledger = { steps: [], resources: [] };
    for (const kind of ['create_tls_subscription', 'create_dns_acme', 'await_tls']) {
      const step = stepOfKind(kind);
      settle(ledger, step, await runToDone(step, spec, ledger));
    }
    const create = stepOfKind('create_service');
    aws.failures.set('createDistribution', 'lost');
    await expect(cloudFrontProvider.runStep(cfg, create, spec, tpl, ledger)).rejects.toMatchObject({
      meta: { timedOut: true },
    });
    const d = aws.distributions[0]!;
    expect(await cloudFrontProvider.discover(cfg, create, spec, ledger, 1)).toMatchObject({
      status: 'found',
      resources: [
        { kind: 'origin_request_policy', meta: { shared: true } },
        { kind: 'distribution', resourceId: d.id, ownership: 'adopted' },
      ],
    });
    // Even a blind re-run: the same CallerReference is refused, then adopted.
    const again = await cloudFrontProvider.runStep(cfg, create, spec, tpl, ledger);
    expect(again).toMatchObject({
      status: 'done',
      resources: expect.arrayContaining([expect.objectContaining({ resourceId: d.id })]),
    });
    expect(aws.distributions).toHaveLength(1);
    expect(aws.calls.filter((c) => c === 'createDistribution')).toHaveLength(2);
  });

  test('a distribution under another name is never taken over; absent is safe to act on', async () => {
    const spec = specOf();
    const create = stepOfKind('create_service');
    expect(
      await cloudFrontProvider.discover(cfg, create, spec, { steps: [], resources: [] }, 1),
    ).toEqual({ status: 'confirmed_absent' });
    await provision(specOf({ hostname: `other1234567.${ZONE}` }, spec.name));
    // Same comment, another name: somebody else's (or a stale twin), never adopted.
    expect(
      (await cloudFrontProvider.discover(cfg, create, spec, { steps: [], resources: [] }, 1))
        .status,
    ).toBe('ambiguous');
  });

  test('an alias another distribution serves is a refusal that ends the run, with the reason', async () => {
    await provision();
    aws.calls.length = 0;
    const twin = specOf({}, 'fcp-relay-node-one-ffffffff');
    const ledger: Ledger = { steps: [], resources: [] };
    for (const kind of ['create_tls_subscription', 'create_dns_acme', 'await_tls']) {
      const step = stepOfKind(kind, twin);
      settle(ledger, step, await runToDone(step, twin, ledger));
    }
    const out = await cloudFrontProvider.runStep(
      cfg,
      stepOfKind('create_service', twin),
      twin,
      tpl,
      ledger,
    );
    expect(out).toMatchObject({ status: 'partial', refused: true, code: 'alias_in_use' });
    expect((out as { detail?: string }).detail).toMatch(/CNAMEAlreadyExists/);
  });

  test('a full policy (100 distributions) gives way to the next; one edited by hand is never used', async () => {
    const api = aws.api();
    // `fcp-ws-1` edited by hand to forward X-Forwarded-For: skipped, kept.
    await api.createOriginRequestPolicy({
      ...cloudFrontOriginRequestPolicyConfig('ws', 1),
      HeadersConfig: {
        HeaderBehavior: 'whitelist',
        Headers: { Quantity: 2, Items: ['Sec-WebSocket-Key', 'X-Forwarded-For'] },
      },
    });
    // `fcp-ws-2` full.
    const full = await api.createOriginRequestPolicy(cloudFrontOriginRequestPolicyConfig('ws', 2));
    for (let i = 0; i < 100; i++)
      aws.distributions.push({
        id: `EFULL${i}`,
        arn: `arn:x:${i}`,
        domainName: `full${i}.cloudfront.net`,
        config: { DefaultCacheBehavior: { OriginRequestPolicyId: full.id } } as never,
        status: 'Deployed',
        etag: 'x',
        reads: 0,
      });
    const ledger = await provision();
    const used = ofKind(ledger, 'origin_request_policy')[0]!;
    expect(metaOfRow(used).name).toBe('fcp-ws-3');
    expect(aws.policies.map((p) => p.config.Name)).toEqual(['fcp-ws-1', 'fcp-ws-2', 'fcp-ws-3']);
  });

  test('the deployment wait: in progress is a wait, deployed finishes, disabled by hand stops the run', async () => {
    const spec = specOf();
    const ledger: Ledger = { steps: [], resources: [] };
    for (const kind of [
      'create_tls_subscription',
      'create_dns_acme',
      'await_tls',
      'create_service',
    ]) {
      const step = stepOfKind(kind);
      settle(ledger, step, await runToDone(step, spec, ledger));
    }
    aws.deployAfterReads = 3;
    const deploy = stepOfKind('activate_version');
    const first = await cloudFrontProvider.runStep(cfg, deploy, spec, tpl, ledger);
    expect(first).toEqual({ status: 'requested', opRef: aws.distributions[0]!.id, resources: [] });
    expect((await cloudFrontProvider.discover(cfg, deploy, spec, ledger, 1)).status).toBe(
      'confirmed_absent',
    );
    expect(
      await cloudFrontProvider.pollStep!(
        cfg,
        deploy,
        first.status === 'requested' ? first.opRef : '',
        ledger,
      ),
    ).toEqual({ status: 'done', resources: [], addresses: { hostname: HOSTNAME } });
    aws.distributions[0]!.config.Enabled = false;
    expect(
      await cloudFrontProvider.pollStep!(cfg, deploy, aws.distributions[0]!.id, ledger),
    ).toMatchObject({
      status: 'partial',
      refused: true,
      code: 'distribution_disabled',
    });
  });

  test("the traffic record carries the template's record options", async () => {
    const ledger = await provision(specOf(), { ...tpl, dnsTtl: 300, dnsTags: { team: 'edges' } });
    expect(dns.rows.find((r) => r.name === HOSTNAME)).toMatchObject({
      ttl: 300,
      tags: ['team:edges'],
    });
    expect(
      ofKind(ledger, 'dns_record')
        .map((r) => metaOfRow(r).role)
        .sort(),
    ).toEqual(['acme', 'traffic']);
  });
});

// --- reading -------------------------------------------------------------------------------------

describe('cloudfront: describe, inspect, inventory, import', () => {
  test('describe: pending until deployed, certified and named; gone once deleted', async () => {
    expect(await cloudFrontProvider.describe(cfg, { steps: [], resources: [] })).toMatchObject({
      state: 'pending',
      code: 'no_service_yet',
    });
    const ledger = await provision();
    // The traffic record edited away from the distribution: not ready.
    const traffic = dns.rows.find((r) => r.name === HOSTNAME)!;
    traffic.content = 'elsewhere.example';
    expect((await cloudFrontProvider.describe(cfg, ledger)).readiness).toEqual({
      dns: 'pending',
      certificate: 'ready',
    });
    traffic.content = aws.distributions[0]!.domainName;
    expect((await cloudFrontProvider.describe(cfg, ledger)).state).toBe('active');
    aws.distributions.length = 0;
    expect((await cloudFrontProvider.describe(cfg, ledger)).state).toBe('gone');
  });

  test('inspect and inventory report the origin, its port and every name served', async () => {
    const ledger = await provision();
    const view = await cloudFrontProvider.inspect(cfg, ledger);
    expect(view.summary).toMatchObject({
      status: 'Deployed',
      addresses: { hostname: HOSTNAME },
      members: [{ address: ORIGIN, port: 443 }],
      listeners: [{ port: 443, protocol: 'https' }],
    });
    expect(JSON.stringify(view.raw)).not.toContain(SECRET);
    const inv = await cloudFrontProvider.inventory(cfg);
    expect(inv.loadBalancers).toEqual([
      expect.objectContaining({
        id: aws.distributions[0]!.id,
        name: 'fcp-relay-node-one-0123abcd',
        hostnames: [HOSTNAME],
        content: ORIGIN,
      }),
    ]);
  });

  test('import: one name only, the wildcard recorded as shared, the traffic record found', async () => {
    await provision();
    const d = aws.distributions[0]!;
    await expect(
      cloudFrontProvider.inspectForAdoption!(cfg, d.id, `nope.${ZONE}`),
    ).rejects.toMatchObject({ meta: { code: 'hostname_mismatch' } });
    const got = await cloudFrontProvider.inspectForAdoption!(cfg, d.id, HOSTNAME.toUpperCase());
    expect(got).toMatchObject({
      hostname: HOSTNAME,
      hostnames: [HOSTNAME],
      shared: false,
      content: ORIGIN,
    });
    expect(
      got.resources.map((r) => [r.kind, (r.meta as { shared?: boolean } | undefined)?.shared]),
    ).toEqual([
      ['origin_request_policy', true],
      ['distribution', undefined],
      ['tls_subscription', true],
      ['dns_record', undefined],
    ]);
    d.config.Aliases = { Quantity: 2, Items: [HOSTNAME, `second.${ZONE}`] };
    await expect(cloudFrontProvider.inspectForAdoption!(cfg, d.id, HOSTNAME)).rejects.toMatchObject(
      {
        meta: { code: 'distribution_shared' },
      },
    );
  });
});

// --- destroy ---------------------------------------------------------------------------------------

describe('cloudfront: destroy', () => {
  test('in kind order: the traffic name, the distribution, then what is shared (left in place)', async () => {
    const ledger = await provision();
    expect(cloudFrontProvider.planDestroy(cfg, ledger).map(cloudFrontDestroyKey)).toEqual([
      'dns_record:traffic',
      'distribution',
      'tls_subscription',
      'dns_record:acme',
      'origin_request_policy',
    ]);
    expect([...CLOUDFRONT_DESTROY_ORDER]).toEqual([
      'dns_record:traffic',
      'distribution',
      'tls_subscription',
      'dns_record:acme',
      'origin_request_policy',
    ]);
  });

  test('disable with the ETag read, wait for deployment, delete with the new ETag; shared things stay', async () => {
    const ledger = await provision();
    const d = aws.distributions[0]!;
    const cert = aws.certificates[0]!;
    const acmeName = cert.record.name.replace(/\.$/, '');
    aws.deployAfterReads = 3;
    aws.calls.length = 0;
    const passes = await destroyAll(ledger);
    // Disable first (IfMatch the version read), then delete only once deployed.
    const order = aws.calls.filter((c) =>
      ['updateDistribution', 'deleteDistribution', 'getDistributionConfig'].includes(c),
    );
    expect(order).toEqual(['getDistributionConfig', 'updateDistribution', 'deleteDistribution']);
    expect(passes).toBeGreaterThan(1);
    expect(aws.distributions).toEqual([]);
    expect(dns.rows.some((r) => r.name === HOSTNAME)).toBe(false);
    // The zone's certificate, its validation record and the policy are left for the next front.
    expect(aws.certificates).toEqual([cert]);
    expect(dns.rows.some((r) => r.name === acmeName)).toBe(true);
    expect(aws.policies).toHaveLength(1);
    expect(aws.calls).not.toContain('deleteCertificate');
    expect(ledger.resources.every((r) => r.deleteState === 'confirmed_gone')).toBe(true);
    void d;
  });

  test('a delete racing an edit is refused on its ETag and the next pass recovers', async () => {
    const ledger = await provision();
    const d = aws.distributions[0]!;
    const row = ofKind(ledger, 'distribution')[0]!;
    expect(await cloudFrontProvider.runDestroy(cfg, row, ledger)).toEqual({
      status: 'delete_requested',
    });
    // Somebody edits it between our read and our delete: the ETag moves.
    d.status = 'Deployed';
    const stale = d.etag;
    aws.failures.set('deleteDistribution', { name: 'PreconditionFailed', status: 412 });
    await expect(cloudFrontProvider.runDestroy(cfg, row, ledger)).rejects.toMatchObject({
      meta: { code: 'precondition_failed', status: 412 },
    });
    expect(d.etag).toBe(stale);
    expect(await cloudFrontProvider.runDestroy(cfg, row, ledger)).toEqual({
      status: 'delete_requested',
    });
    expect(aws.distributions).toEqual([]);
    expect(await cloudFrontProvider.confirmDestroyed!(cfg, row, ledger)).toEqual({
      status: 'confirmed_gone',
    });
  });

  test('a candidate discovery could not prove is ours is never destroyed', async () => {
    const ledger = await provision();
    ledger.resources.push({
      stepId: 'dns',
      kind: 'dns_record',
      resourceId: 'theirs',
      ownership: 'adopted',
      deleteState: 'present',
      meta: JSON.stringify({ role: 'traffic', candidate: true, recordId: 'theirs' }),
    });
    expect(cloudFrontProvider.planDestroy(cfg, ledger).some((r) => r.resourceId === 'theirs')).toBe(
      false,
    );
  });
});

// --- account and location -----------------------------------------------------------------------

describe('cloudfront: credential test and location check', () => {
  test('the credential test reads certificates, distributions and policies', async () => {
    await provision();
    expect(await cloudFrontProvider.testCredentials(cfg)).toEqual({
      ok: true,
      detail: 'certificates=1; distributions=1; fcp_policies=1',
    });
    aws.failures.set('listCertificates', { name: 'AccessDeniedException', status: 400 });
    const denied = await cloudFrontProvider.testCredentials(cfg);
    expect(denied).toMatchObject({ ok: false, code: 'access_denied_exception' });
    expect(denied.detail).toMatch(/AccessDeniedException/);
    aws.failures.set('listCertificates', { name: 'InvalidClientTokenId', status: 403 });
    expect(await cloudFrontProvider.testCredentials(cfg)).toMatchObject({
      ok: false,
      code: 'invalid_client_token_id',
    });
  });

  test("the location check reads the zone and its CAA for Amazon's wildcard", async () => {
    expect(await cloudFrontProvider.checkLocation!(cfg)).toMatchObject({
      ok: true,
      label: ZONE,
      observed: {
        zoneStatus: 'active',
        caa: 'no_records',
        caaIssuer: 'amazon.com',
        caaCertificate: 'wildcard',
      },
    });
    caa[ZONE] = [
      { flags: 0, tag: 'issue', value: 'awstrust.com' },
      { flags: 0, tag: 'issuewild', value: 'letsencrypt.org' },
    ];
    const refused = await cloudFrontProvider.checkLocation!(cfg);
    expect(refused).toMatchObject({ ok: false, code: 'caa_forbids_ca' });
    expect(await cloudFrontProvider.certificatePreflight!(cfg)).toMatchObject({
      ok: false,
      code: 'caa_forbids_ca',
    });
    caa[ZONE] = [{ flags: 0, tag: 'issuewild', value: 'amazontrust.com' }];
    expect(await cloudFrontProvider.certificatePreflight!(cfg)).toEqual({ ok: true });
    expect(
      await cloudFrontProvider.checkLocation!({
        ...cfg,
        dns: { ...cfg.dns!, zoneName: 'other.example' },
      }),
    ).toMatchObject({ ok: false, code: 'zone_name_mismatch' });
  });
});

describe('cloudfront: errors', () => {
  test('carry no secret, no origin and no front name', async () => {
    const errors: unknown[] = [];
    await provision();
    for (const op of ['createDistribution', 'getDistribution', 'describeCertificate'] as const)
      aws.failures.set(op, { name: 'InvalidArgument', status: 400 });
    const twin = specOf({}, 'fcp-relay-node-one-ffffffff');
    const ledger: Ledger = { steps: [], resources: [] };
    try {
      await cloudFrontProvider.runStep(cfg, stepOfKind('await_tls', twin), twin, tpl, {
        steps: [],
        resources: [
          {
            stepId: 'tls',
            kind: 'tls_subscription',
            resourceId: aws.certificates[0]!.arn,
            ownership: 'adopted',
            deleteState: 'present',
          },
        ],
      });
    } catch (e) {
      errors.push(e);
    }
    try {
      await cloudFrontProvider.describe(cfg, {
        ...ledger,
        resources: [
          {
            stepId: 'distribution',
            kind: 'distribution',
            resourceId: aws.distributions[0]!.id,
            ownership: 'created',
            deleteState: 'present',
          },
        ],
      });
    } catch (e) {
      errors.push(e);
    }
    expect(errors).toHaveLength(2);
    for (const e of errors) {
      const text = `${String(e)} ${JSON.stringify(e)} ${JSON.stringify((e as { meta?: unknown }).meta)}`;
      expect(text).not.toContain(SECRET);
      expect(text).not.toContain(ORIGIN);
      expect(text).not.toContain(HOSTNAME);
      expect((e as { meta: { code?: string } }).meta.code).toBe('invalid_argument');
    }
  });
});
