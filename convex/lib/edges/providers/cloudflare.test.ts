/**
 * Cloudflare adapter contract. The real `cloudflare@7.1.0` SDK drives every
 * call; the recording fetch stub observes them at the HTTP layer, so paths,
 * methods, query serialization, bodies, the auth header and the absence of
 * retries are pinned against what Cloudflare actually receives.
 */
import { afterEach, describe, expect, test, vi } from 'vitest';
import { errorBlob, jsonRes, mockFetch, type Captured, type Handler } from '../testing/mockFetch';
import { EDGE_PROVIDER_CAPABILITIES } from './capabilities';
import type { CloudflareConfig, EdgeSpec, Ledger, LedgerResource } from './types';
import {
  CloudflareTemplate,
  cloudflareOriginRule,
  cloudflareProvider,
  cloudflareRecordBody,
  defaultOriginPort,
  originRuleNeeded,
  originRuleTargetsHost,
  recordComment,
  zoneSslModeOf,
  __setCloudflareApiFactory,
} from './cloudflare';
import tokenVerify from './fixtures/cloudflare/token_verify.json';
import zoneGet from './fixtures/cloudflare/zone_get.json';
import zonesList from './fixtures/cloudflare/zones_list.json';
import settingSsl from './fixtures/cloudflare/setting_ssl.json';
import settingWebsockets from './fixtures/cloudflare/setting_websockets.json';
import recordCreated from './fixtures/cloudflare/dns_record_created.json';
import recordsList from './fixtures/cloudflare/dns_records_list.json';
import recordsListEmpty from './fixtures/cloudflare/dns_records_list_empty.json';
import certPacks from './fixtures/cloudflare/certificate_packs_list.json';
import originPhase from './fixtures/cloudflare/ruleset_origin_phase.json';
import originPhaseEmpty from './fixtures/cloudflare/ruleset_origin_phase_empty.json';
import ruleCreated from './fixtures/cloudflare/ruleset_rule_created.json';
import notFound from './fixtures/cloudflare/error_record_not_found.json';
import rateLimited from './fixtures/cloudflare/error_rate_limited.json';

afterEach(() => {
  vi.unstubAllGlobals();
  __setCloudflareApiFactory(null);
});

/** Fixtures carry a `_source` header for reviewers; the wire body never does. */
function wire(fixture: Record<string, unknown>): Record<string, unknown> {
  const copy = { ...fixture };
  delete copy._source;
  return copy;
}

const ZONE = '023e105f4ecef8ad9ca31a8372d0c353';
const HOSTNAME = 'k7m2x9qp4n3f.example.net';
const ORIGIN = '198.51.100.7';
const NAME = 'fcp-relay-o1-0badf00d';
const RULESET = '3c0b456bc2aa443089c5f40defb5fdc9';
const RULE_ID = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
const RECORD_ID = '372e67954025e0ba6aaa6d586b9e0b59';

const cfg: CloudflareConfig = {
  type: 'cloudflare',
  apiToken: 'SECRET_CF',
  zoneId: ZONE,
  zoneName: 'example.net',
  accountId: 'acct_1',
};

/** The template as the CMS stores it: the zone mode is NOT one of its fields. */
const bareTpl = CloudflareTemplate.parse({});

/**
 * The zone encryption mode reaches the adapter as an EXTRA rendered template
 * param (the orchestrator observes it at credential-test time and freezes it
 * into the edge's provisionIntent), not as a schema field, so it is added on
 * top of the parsed template.
 */
function withMode(mode: string, over: Record<string, unknown> = {}) {
  return { ...bareTpl, ...over, zoneSslMode: mode };
}

/** The thrown value of a synchronous call (the pure refusals throw rather than reject). */
function errorOf(fn: () => unknown): unknown {
  try {
    fn();
    return undefined;
  } catch (e) {
    return e;
  }
}

/** The default for every test that is not about the mode itself. */
const tpl = withMode('full');

function specFor(originPort = 443, over: Partial<EdgeSpec> = {}): EdgeSpec {
  return {
    name: NAME,
    hostname: HOSTNAME,
    listeners: [{ edgePort: 443, members: [{ address: ORIGIN, port: originPort }] }],
    ...over,
  };
}

const emptyLedger: Ledger = { steps: [], resources: [] };

function ledgerWith(...resources: LedgerResource[]): Ledger {
  return { steps: [], resources };
}

const recordResource: LedgerResource = {
  stepId: 'dns',
  kind: 'dns_record',
  resourceId: RECORD_ID,
  ownership: 'created',
  deleteState: 'present',
  meta: JSON.stringify({ name: HOSTNAME, zoneId: ZONE, type: 'A' }),
};
const ruleResource: LedgerResource = {
  stepId: 'rule',
  kind: 'origin_rule',
  resourceId: RULE_ID,
  ownership: 'created',
  deleteState: 'present',
  meta: JSON.stringify({ rulesetId: RULESET }),
};

/** A router over the Cloudflare paths this adapter touches. */
function route(over: Partial<Record<string, Handler>> = {}): Handler {
  return (call, index) => {
    const p = call.path;
    for (const [fragment, handler] of Object.entries(over)) {
      if (p.includes(fragment) && handler) return handler(call, index);
    }
    if (p.endsWith('/user/tokens/verify')) return jsonRes(wire(tokenVerify));
    if (p.endsWith('/settings/ssl')) return jsonRes(wire(settingSsl));
    if (p.endsWith('/settings/websockets')) return jsonRes(wire(settingWebsockets));
    if (p.endsWith('/ssl/certificate_packs')) return jsonRes(wire(certPacks));
    if (p.endsWith('/rulesets/phases/http_request_origin/entrypoint'))
      return jsonRes(wire(call.method === 'PUT' ? ruleCreated : originPhase));
    if (p.includes('/rulesets/') && p.endsWith('/rules')) return jsonRes(wire(ruleCreated));
    if (p.includes('/dns_records/')) return jsonRes(wire(recordCreated));
    if (p.endsWith('/dns_records'))
      return jsonRes(wire(call.method === 'POST' ? recordCreated : recordsList));
    if (p.endsWith(`/zones/${ZONE}`)) return jsonRes(wire(zoneGet));
    if (p.endsWith('/zones')) return jsonRes(wire(zonesList));
    return jsonRes({ result: null, success: false, errors: [{ code: 7003 }] }, 404);
  };
}

// --- pure surface -------------------------------------------------------------------

describe('cloudflare: port model', () => {
  test('the effective default origin port follows the zone encryption mode', () => {
    expect(defaultOriginPort('flexible')).toBe(80);
    expect(defaultOriginPort('full')).toBe(443);
    expect(defaultOriginPort('strict')).toBe(443);
  });

  test('origin port matrix decides whether an Origin Rule is planned', () => {
    const matrix: Array<[number, 'flexible' | 'full' | 'strict', boolean]> = [
      [443, 'full', false],
      [443, 'strict', false],
      [8443, 'full', true],
      [10443, 'full', true],
      [80, 'flexible', false],
      [8080, 'flexible', true],
      [443, 'flexible', true],
    ];
    for (const [port, mode, needed] of matrix) {
      expect(originRuleNeeded(port, mode)).toBe(needed);
      const steps = cloudflareProvider.planProvision(cfg, specFor(port), withMode(mode));
      expect(steps.map((s) => s.kind)).toEqual(
        needed ? ['create_dns_record', 'create_origin_rule'] : ['create_dns_record'],
      );
      expect(steps.every((s) => s.discoverability === 'by_name')).toBe(true);
    }
  });

  test('an absent zone mode is refused, never inferred from the origin scheme', () => {
    // The live zone setting is not readable from a pure plan, and guessing it
    // would decide both the effective origin port and whether the origin leg is
    // encrypted at all. A plaintext-HTTP origin is NOT a licence to assume
    // `flexible`.
    const httpSpec = specFor(80, {
      originTransport: {
        scheme: 'http',
        certPublic: false,
        certNames: [],
        acceptsHostHeader: 'any',
      },
    });
    const stub = mockFetch(route());
    expect(() => zoneSslModeOf(httpSpec, bareTpl)).toThrow(/zone_mode_unknown/);
    expect(() => zoneSslModeOf(specFor(443), bareTpl)).toThrow(/zone_mode_unknown/);
    expect(() => cloudflareProvider.planProvision(cfg, httpSpec, bareTpl)).toThrow(
      /zone_mode_unknown/,
    );
    // An unusable value is no better than a missing one.
    expect(() => zoneSslModeOf(specFor(443), withMode('off'))).toThrow(/zone_mode_unknown/);
    // Refused without any I/O at all.
    expect(stub.calls).toHaveLength(0);
  });

  test('the zone mode and the slot origin transport must agree, or the plan is refused', () => {
    const transports = {
      http: { scheme: 'http', certPublic: false, certNames: [], acceptsHostHeader: 'any' },
      httpsPublic: {
        scheme: 'https',
        certPublic: true,
        certNames: ['*.origin.example'],
        acceptsHostHeader: 'any',
      },
      httpsPrivate: {
        scheme: 'https',
        certPublic: false,
        certNames: ['node7.internal'],
        acceptsHostHeader: 'any',
      },
    } as const;
    const matrix: Array<[keyof typeof transports, 'flexible' | 'full' | 'strict', boolean]> = [
      // a plaintext origin needs `flexible`: every other mode dials 443 over TLS
      ['http', 'flexible', true],
      ['http', 'full', false],
      ['http', 'strict', false],
      // an https origin needs an encrypted mode; `flexible` would dial port 80
      ['httpsPublic', 'flexible', false],
      ['httpsPublic', 'full', true],
      ['httpsPublic', 'strict', true],
      // `strict` validates the origin certificate: a private one cannot sit there
      ['httpsPrivate', 'full', true],
      ['httpsPrivate', 'strict', false],
    ];
    for (const [transport, mode, ok] of matrix) {
      const port = transport === 'http' ? 80 : 443;
      const spec = specFor(port, { originTransport: transports[transport] as never });
      if (ok) expect(zoneSslModeOf(spec, withMode(mode))).toBe(mode);
      else expect(() => zoneSslModeOf(spec, withMode(mode))).toThrow(/origin_tls_mismatch/);
    }
    // A slot that declares no transport at all is not second-guessed.
    expect(zoneSslModeOf(specFor(443), withMode('strict'))).toBe('strict');
  });

  test('a refused mode never quotes the hostname, the origin or the zone', () => {
    const spec = specFor(80, {
      originTransport: {
        scheme: 'http',
        certPublic: false,
        certNames: [],
        acceptsHostHeader: 'any',
      },
    });
    for (const [thrown, code] of [
      [errorOf(() => zoneSslModeOf(spec, bareTpl)), 'zone_mode_unknown'],
      [errorOf(() => zoneSslModeOf(spec, withMode('full'))), 'origin_tls_mismatch'],
    ] as const) {
      const blob = errorBlob(thrown);
      expect(blob).toContain(code);
      for (const secret of ['SECRET_CF', HOSTNAME, ORIGIN, 'example.net'])
        expect(blob).not.toContain(secret);
    }
  });

  test('a template that forbids the override refuses the slot at plan time (no I/O)', () => {
    const strictTpl = withMode('full', { allowOriginPortOverride: false });
    const stub = mockFetch(route());
    expect(() => cloudflareProvider.planProvision(cfg, specFor(8443), strictTpl)).toThrow(
      /origin_port_override_disabled/,
    );
    // The default-port case is still fine with overrides disabled.
    expect(cloudflareProvider.planProvision(cfg, specFor(443), strictTpl)).toHaveLength(1);
    expect(stub.calls).toHaveLength(0);
  });
});

describe('cloudflare: request bodies', () => {
  test('the DNS body is a proxied record typed by the origin address family', () => {
    expect(cloudflareRecordBody(cfg, specFor(), tpl)).toEqual({
      zone_id: ZONE,
      type: 'A',
      name: HOSTNAME,
      content: ORIGIN,
      proxied: true,
      ttl: 1,
      comment: `fcp:${NAME}`,
    });
    const v6 = specFor(443, {
      listeners: [{ edgePort: 443, members: [{ address: '2001:db8::7', port: 443 }] }],
    });
    expect(cloudflareRecordBody(cfg, v6, tpl).type).toBe('AAAA');
    const byName = specFor(443, {
      listeners: [{ edgePort: 443, members: [{ address: 'node7.origin.example', port: 443 }] }],
    });
    expect(cloudflareRecordBody(cfg, byName, tpl).type).toBe('CNAME');
  });

  test('a spec without a hostname is refused, and so is a hostname outside the zone', () => {
    const noHost = specFor();
    delete noHost.hostname;
    expect(() => cloudflareRecordBody(cfg, noHost, tpl)).toThrow(/hostname_missing/);
    expect(() =>
      cloudflareRecordBody(cfg, specFor(443, { hostname: 'a.b.example.net' }), tpl),
    ).toThrow(/hostname_not_in_zone/);
    expect(() =>
      cloudflareRecordBody(cfg, specFor(443, { hostname: 'x.other.test' }), tpl),
    ).toThrow(/hostname_not_in_zone/);
  });

  test('the comment marker fits the 100-char cap by truncating the PREFIX, never the spec name', () => {
    const long = 'x'.repeat(80);
    const comment = recordComment(long, NAME);
    expect(comment.length).toBeLessThanOrEqual(100);
    expect(comment.endsWith(`:${NAME}`)).toBe(true);
    expect(recordComment('fcp', NAME)).toBe(`fcp:${NAME}`);
  });

  test('the origin rule routes by host to the override port and is keyed by ref', () => {
    expect(cloudflareOriginRule(specFor(8443), 8443)).toEqual({
      action: 'route',
      action_parameters: { origin: { port: 8443 } },
      expression: `(http.host eq "${HOSTNAME}")`,
      description: NAME,
      ref: NAME,
      enabled: true,
    });
    // The adoption matcher reads back exactly what the generator writes, and
    // nothing else: a longer sibling label is a different host.
    const expression = cloudflareOriginRule(specFor(8443), 8443).expression;
    expect(originRuleTargetsHost(expression, HOSTNAME)).toBe(true);
    expect(originRuleTargetsHost(expression, `ba.${HOSTNAME}`)).toBe(false);
    expect(originRuleTargetsHost(`(http.host eq "ba.${HOSTNAME}")`, HOSTNAME)).toBe(false);
    expect(originRuleTargetsHost(undefined, HOSTNAME)).toBe(false);
  });
});

// --- steps --------------------------------------------------------------------------

describe('cloudflare: runStep', () => {
  test('create_dns_record posts the proxied record and publishes the hostname', async () => {
    const stub = mockFetch(route());
    const steps = cloudflareProvider.planProvision(cfg, specFor(), tpl);
    const out = await cloudflareProvider.runStep(cfg, steps[0]!, specFor(), tpl, emptyLedger);
    expect(out).toEqual({
      status: 'done',
      resources: [
        {
          kind: 'dns_record',
          resourceId: RECORD_ID,
          ownership: 'created',
          meta: { name: HOSTNAME, zoneId: ZONE, type: 'A' },
        },
      ],
      addresses: { hostname: HOSTNAME },
    });
    const call = stub.calls[0] as Captured;
    expect(call.method).toBe('POST');
    expect(call.path).toBe(`/client/v4/zones/${ZONE}/dns_records`);
    expect(call.body).toMatchObject({ proxied: true, ttl: 1, comment: `fcp:${NAME}` });
    expect(call.headers.authorization).toBe('Bearer SECRET_CF');
  });

  test('create_origin_rule adds one rule to the existing entry point ruleset', async () => {
    const stub = mockFetch(route());
    const spec = specFor(8443);
    const steps = cloudflareProvider.planProvision(cfg, spec, tpl);
    const out = await cloudflareProvider.runStep(
      cfg,
      steps[1]!,
      spec,
      tpl,
      ledgerWith(recordResource),
    );
    expect(out).toEqual({
      status: 'done',
      resources: [
        {
          kind: 'origin_rule',
          resourceId: RULE_ID,
          ownership: 'created',
          meta: { rulesetId: RULESET },
        },
      ],
    });
    expect(stub.calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      `GET /client/v4/zones/${ZONE}/rulesets/phases/http_request_origin/entrypoint`,
      `POST /client/v4/zones/${ZONE}/rulesets/${RULESET}/rules`,
    ]);
    expect((stub.calls[1] as Captured).body).toEqual({
      action: 'route',
      action_parameters: { origin: { port: 8443 } },
      expression: `(http.host eq "${HOSTNAME}")`,
      description: NAME,
      ref: NAME,
      enabled: true,
    });
  });

  test('a zone with no origin ruleset yet is bootstrapped through the phase entry point', async () => {
    const stub = mockFetch(
      route({
        '/rulesets/phases/http_request_origin/entrypoint': (call) =>
          call.method === 'GET' ? jsonRes(wire(notFound), 404) : jsonRes(wire(ruleCreated)),
      }),
    );
    const spec = specFor(8443);
    const steps = cloudflareProvider.planProvision(cfg, spec, tpl);
    const out = await cloudflareProvider.runStep(cfg, steps[1]!, spec, tpl, emptyLedger);
    expect(out).toMatchObject({ status: 'done', resources: [{ resourceId: RULE_ID }] });
    expect(stub.calls.map((c) => c.method)).toEqual(['GET', 'PUT']);
    expect((stub.calls[1] as Captured).body).toEqual({
      name: 'default',
      rules: [
        {
          action: 'route',
          action_parameters: { origin: { port: 8443 } },
          expression: `(http.host eq "${HOSTNAME}")`,
          description: NAME,
          ref: NAME,
          enabled: true,
        },
      ],
    });
  });

  test('a ruleset answer that does not contain our ref is partial, never a fabricated resource', async () => {
    mockFetch(
      route({
        '/rules': () => jsonRes(wire(originPhaseEmpty)),
      }),
    );
    const spec = specFor(8443);
    const steps = cloudflareProvider.planProvision(cfg, spec, tpl);
    const out = await cloudflareProvider.runStep(cfg, steps[1]!, spec, tpl, emptyLedger);
    expect(out).toEqual({ status: 'partial', resources: [], code: 'rule_not_returned' });
  });
});

// --- discovery -----------------------------------------------------------------------

describe('cloudflare: discovery', () => {
  const dnsStep = {
    id: 'dns',
    kind: 'create_dns_record',
    resourceName: NAME,
    discoverability: 'by_name',
  } as const;
  const ruleStep = {
    id: 'rule',
    kind: 'create_origin_rule',
    resourceName: `${NAME}-rule`,
    discoverability: 'by_name',
  } as const;

  test('a record with our comment marker and our origin content is adopted, in ONE request', async () => {
    const stub = mockFetch(route());
    const out = await cloudflareProvider.discover(cfg, dnsStep, specFor(), emptyLedger, 1);
    expect(out).toEqual({
      status: 'found',
      resources: [
        {
          kind: 'dns_record',
          resourceId: RECORD_ID,
          ownership: 'adopted',
          meta: { name: HOSTNAME, zoneId: ZONE, type: 'A' },
        },
      ],
      addresses: { hostname: HOSTNAME },
    });
    expect(stub.calls).toHaveLength(1);
    expect(new URLSearchParams((stub.calls[0] as Captured).query).get('name.exact')).toBe(HOSTNAME);
  });

  test('an empty listing is confirmed_absent on the first look (the listing is authoritative)', async () => {
    mockFetch(route({ '/dns_records': () => jsonRes(wire(recordsListEmpty)) }));
    expect(await cloudflareProvider.discover(cfg, dnsStep, specFor(), emptyLedger, 1)).toEqual({
      status: 'confirmed_absent',
    });
    expect(EDGE_PROVIDER_CAPABILITIES.cloudflare.discoverySettleMs).toBe(0);
  });

  test('our hostname carrying a FOREIGN comment is ambiguous, never adopted', async () => {
    const foreign = structuredClone(wire(recordsList)) as { result: Array<{ comment: string }> };
    foreign.result[0]!.comment = 'someone-else:their-edge';
    mockFetch(route({ '/dns_records': () => jsonRes(foreign) }));
    const out = await cloudflareProvider.discover(cfg, dnsStep, specFor(), emptyLedger, 1);
    expect(out).toMatchObject({ status: 'ambiguous', candidates: [{ resourceId: RECORD_ID }] });
  });

  test('our comment but a FOREIGN content is ambiguous too (the record fronts something else)', async () => {
    const foreign = structuredClone(wire(recordsList)) as { result: Array<{ content: string }> };
    foreign.result[0]!.content = '203.0.113.99';
    mockFetch(route({ '/dns_records': () => jsonRes(foreign) }));
    const out = await cloudflareProvider.discover(cfg, dnsStep, specFor(), emptyLedger, 1);
    expect(out).toMatchObject({ status: 'ambiguous' });
  });

  test('an adopted record is recognised by its ledger id even without our comment', async () => {
    const foreign = structuredClone(wire(recordsList)) as { result: Array<{ comment: string }> };
    foreign.result[0]!.comment = 'operator-managed';
    mockFetch(route({ '/dns_records': () => jsonRes(foreign) }));
    const out = await cloudflareProvider.discover(
      cfg,
      dnsStep,
      specFor(),
      ledgerWith(recordResource),
      1,
    );
    expect(out).toMatchObject({ status: 'found', resources: [{ resourceId: RECORD_ID }] });
  });

  test('lost response recovery: the create throws after the record exists, discovery adopts it', async () => {
    const stub = mockFetch((call) =>
      call.method === 'POST' ? jsonRes(wire(rateLimited), 429) : jsonRes(wire(recordsList)),
    );
    const steps = cloudflareProvider.planProvision(cfg, specFor(), tpl);
    await expect(
      cloudflareProvider.runStep(cfg, steps[0]!, specFor(), tpl, emptyLedger),
    ).rejects.toThrow();
    // Exactly one POST: no SDK retry allocated a second record.
    expect(stub.calls.filter((c) => c.method === 'POST')).toHaveLength(1);
    const out = await cloudflareProvider.discover(cfg, dnsStep, specFor(), emptyLedger, 1);
    expect(out).toMatchObject({ status: 'found', resources: [{ resourceId: RECORD_ID }] });
    expect(stub.calls.filter((c) => c.method === 'POST')).toHaveLength(1);
  });

  test('the origin rule is discovered by ref; a missing phase or ref is confirmed_absent', async () => {
    mockFetch(route());
    expect(await cloudflareProvider.discover(cfg, ruleStep, specFor(8443), emptyLedger, 1)).toEqual(
      {
        status: 'found',
        resources: [
          {
            kind: 'origin_rule',
            resourceId: RULE_ID,
            ownership: 'adopted',
            meta: { rulesetId: RULESET },
          },
        ],
      },
    );
    mockFetch(route({ '/rulesets/phases': () => jsonRes(wire(notFound), 404) }));
    expect(await cloudflareProvider.discover(cfg, ruleStep, specFor(8443), emptyLedger, 1)).toEqual(
      {
        status: 'confirmed_absent',
      },
    );
    mockFetch(route({ '/rulesets/phases': () => jsonRes(wire(originPhaseEmpty)) }));
    expect(await cloudflareProvider.discover(cfg, ruleStep, specFor(8443), emptyLedger, 1)).toEqual(
      {
        status: 'confirmed_absent',
      },
    );
  });
});

// --- describe / inspect / inventory ---------------------------------------------------

describe('cloudflare: describe readiness matrix', () => {
  test('proxied record + an active pack covering the wildcard is active and ready', async () => {
    mockFetch(route());
    const out = await cloudflareProvider.describe(cfg, ledgerWith(recordResource));
    expect(out).toEqual({
      state: 'active',
      addresses: { hostname: HOSTNAME },
      health: 'unknown',
      readiness: { dns: 'ready', certificate: 'ready' },
    });
  });

  test('no pack covering the hostname keeps the edge pending, not failed', async () => {
    const packs = structuredClone(wire(certPacks)) as { result: Array<{ hosts: string[] }> };
    packs.result[0]!.hosts = ['other.test'];
    mockFetch(route({ '/ssl/certificate_packs': () => jsonRes(packs) }));
    const out = await cloudflareProvider.describe(cfg, ledgerWith(recordResource));
    expect(out).toMatchObject({
      state: 'pending',
      readiness: { dns: 'ready', certificate: 'pending' },
    });
  });

  test('a certificate read the token cannot make is unknown, never a failure', async () => {
    mockFetch(route({ '/ssl/certificate_packs': () => jsonRes(wire(notFound), 403) }));
    const out = await cloudflareProvider.describe(cfg, ledgerWith(recordResource));
    expect(out).toMatchObject({ state: 'pending', readiness: { certificate: 'unknown' } });
  });

  test('an UNPROXIED record is an error (it would hand members the origin address)', async () => {
    const rec = structuredClone(wire(recordCreated)) as { result: { proxied: boolean } };
    rec.result.proxied = false;
    mockFetch(route({ '/dns_records/': () => jsonRes(rec) }));
    const out = await cloudflareProvider.describe(cfg, ledgerWith(recordResource));
    expect(out).toMatchObject({
      state: 'error',
      code: 'unproxied',
      readiness: { dns: 'pending' },
      health: 'unknown',
    });
  });

  test('a deleted record is gone; an empty ledger is pending', async () => {
    mockFetch(route({ '/dns_records/': () => jsonRes(wire(notFound), 404) }));
    expect(await cloudflareProvider.describe(cfg, ledgerWith(recordResource))).toEqual({
      state: 'gone',
      addresses: {},
      health: 'unknown',
    });
    expect(await cloudflareProvider.describe(cfg, emptyLedger)).toMatchObject({
      state: 'pending',
      code: 'no_record_yet',
    });
  });

  test('health is never claimed: memberHealth is false for this provider', async () => {
    mockFetch(route());
    expect((await cloudflareProvider.describe(cfg, ledgerWith(recordResource))).health).toBe(
      'unknown',
    );
    expect(EDGE_PROVIDER_CAPABILITIES.cloudflare.memberHealth).toBe(false);
  });
});

describe('cloudflare: inspect + inventory', () => {
  test('inspect reports the record, both zone settings and the certificate state without secrets', async () => {
    const stub = mockFetch(route());
    const out = await cloudflareProvider.inspect(cfg, ledgerWith(recordResource, ruleResource));
    expect(out.summary).toEqual({
      status: 'proxied',
      addresses: { hostname: HOSTNAME },
      members: [{ address: ORIGIN, port: 8443 }],
      listeners: [{ port: 443, protocol: 'https' }],
    });
    expect(out.raw).toMatchObject({
      settings: { ssl: 'full', websockets: 'on' },
      certificate: { state: 'ready' },
      originRule: { id: RULE_ID, ref: NAME, port: 8443 },
    });
    expect(JSON.stringify(out.raw)).not.toContain('SECRET_CF');
    expect(stub.calls.some((c) => c.path.endsWith('/settings/websockets'))).toBe(true);
    expect(stub.calls.some((c) => c.path.endsWith('/settings/ssl'))).toBe(true);
  });

  test('without an origin rule the member port is the zone mode default', async () => {
    mockFetch(route());
    const out = await cloudflareProvider.inspect(cfg, ledgerWith(recordResource));
    expect(out.summary.members).toEqual([{ address: ORIGIN, port: 443 }]);
  });

  test('inventory pages by hand over proxied records and reports hostnames', async () => {
    const page1 = structuredClone(wire(recordsList)) as {
      result: Array<Record<string, unknown>>;
      result_info: Record<string, unknown>;
    };
    page1.result = Array.from({ length: 100 }, (_, i) => ({
      ...(page1.result[0] as Record<string, unknown>),
      id: `rec-${i}`,
      name: `h${i}.example.net`,
    }));
    const stub = mockFetch(
      route({
        '/dns_records': (call) => {
          const page = new URLSearchParams(call.query).get('page');
          return jsonRes(page === '1' ? page1 : wire(recordsList));
        },
      }),
    );
    const inv = await cloudflareProvider.inventory(cfg);
    expect(stub.calls).toHaveLength(2);
    const q = new URLSearchParams((stub.calls[0] as Captured).query);
    expect(q.get('per_page')).toBe('100');
    expect(q.get('page')).toBe('1');
    expect(q.get('proxied')).toBe('true');
    expect(inv.loadBalancers).toHaveLength(101);
    expect(inv.loadBalancers.at(-1)).toEqual({
      id: RECORD_ID,
      name: HOSTNAME,
      addresses: { hostname: HOSTNAME },
      content: ORIGIN,
      hostnames: [HOSTNAME],
      status: 'proxied',
    });
    expect(inv.ips).toEqual([]);
    expect(inv.flavors).toEqual([]);
  });
});

// --- adoption -------------------------------------------------------------------------

describe('cloudflare: inspectForAdoption', () => {
  test('an existing record is described as the children an import records', async () => {
    const stub = mockFetch(route());
    const seen = await cloudflareProvider.inspectForAdoption!(cfg, RECORD_ID, HOSTNAME);
    expect(seen).toEqual({
      resources: [
        {
          kind: 'dns_record',
          resourceId: RECORD_ID,
          ownership: 'adopted',
          meta: { name: HOSTNAME, zoneId: ZONE, type: 'A' },
        },
        {
          kind: 'origin_rule',
          resourceId: RULE_ID,
          ownership: 'adopted',
          meta: { rulesetId: RULESET, port: 8443 },
        },
      ],
      hostname: HOSTNAME,
      hostnames: [HOSTNAME],
      // A DNS record serves exactly one name: a Cloudflare edge is never shared.
      shared: false,
      content: ORIGIN,
    });
    // Two reads, no writes: an import changes nothing at the provider.
    expect(stub.calls.map((c) => c.method)).toEqual(['GET', 'GET']);
    expect(stub.calls[0]!.path).toBe(`/client/v4/zones/${ZONE}/dns_records/${RECORD_ID}`);
  });

  test('a zone whose origin rules do not name the hostname adopts the record alone', async () => {
    mockFetch(route({ '/rulesets/phases': () => jsonRes(wire(originPhaseEmpty)) }));
    const seen = await cloudflareProvider.inspectForAdoption!(cfg, RECORD_ID, HOSTNAME);
    expect(seen.resources.map((r) => r.kind)).toEqual(['dns_record']);

    // ...and neither does a rule that routes somebody else's hostname.
    const foreign = structuredClone(wire(originPhase)) as {
      result: { rules: Array<{ expression: string }> };
    };
    foreign.result.rules[0]!.expression = '(http.host eq "other.example.net")';
    mockFetch(route({ '/rulesets/phases': () => jsonRes(foreign) }));
    expect(
      (await cloudflareProvider.inspectForAdoption!(cfg, RECORD_ID, HOSTNAME)).resources,
    ).toHaveLength(1);

    // A zone with no entry point ruleset at all is not an error either.
    mockFetch(route({ '/rulesets/phases': () => jsonRes(wire(notFound), 404) }));
    expect(
      (await cloudflareProvider.inspectForAdoption!(cfg, RECORD_ID, HOSTNAME)).resources,
    ).toHaveLength(1);
  });

  test('an UNPROXIED record is refused: nothing fronts a DNS-only name', async () => {
    const rec = structuredClone(wire(recordCreated)) as { result: { proxied: boolean } };
    rec.result.proxied = false;
    mockFetch(route({ '/dns_records/': () => jsonRes(rec) }));
    // A DNS-only record answers with the origin's own address, so importing it
    // would publish the node itself as an "edge".
    await expect(cloudflareProvider.inspectForAdoption!(cfg, RECORD_ID, HOSTNAME)).rejects.toThrow(
      /record_not_proxied/,
    );
  });

  test('an origin rule is adopted by an EXACT hostname match, never by substring', async () => {
    // A rule for a host whose name CONTAINS the imported one belongs to that
    // other host; adopting it would delete its port override on destroy.
    const sibling = structuredClone(wire(originPhase)) as {
      result: { rules: Array<{ expression: string }> };
    };
    sibling.result.rules[0]!.expression = `(http.host eq "ba.${HOSTNAME}")`;
    mockFetch(route({ '/rulesets/phases': () => jsonRes(sibling) }));
    expect(
      (await cloudflareProvider.inspectForAdoption!(cfg, RECORD_ID, HOSTNAME)).resources.map(
        (r) => r.kind,
      ),
    ).toEqual(['dns_record']);

    // A rule that merely mentions the name in a comparison against ANOTHER
    // field is not a match either.
    const mention = structuredClone(wire(originPhase)) as {
      result: { rules: Array<{ expression: string }> };
    };
    mention.result.rules[0]!.expression = `(http.request.uri.path contains "${HOSTNAME}")`;
    mockFetch(route({ '/rulesets/phases': () => jsonRes(mention) }));
    expect(
      (await cloudflareProvider.inspectForAdoption!(cfg, RECORD_ID, HOSTNAME)).resources,
    ).toHaveLength(1);

    // The operand is compared as a hostname: case and a trailing dot still match.
    const noisy = structuredClone(wire(originPhase)) as {
      result: { rules: Array<{ expression: string }> };
    };
    noisy.result.rules[0]!.expression = `(http.host eq "${HOSTNAME.toUpperCase()}.")`;
    mockFetch(route({ '/rulesets/phases': () => jsonRes(noisy) }));
    expect(
      (await cloudflareProvider.inspectForAdoption!(cfg, RECORD_ID, HOSTNAME)).resources.map(
        (r) => r.kind,
      ),
    ).toEqual(['dns_record', 'origin_rule']);
  });

  test('a record that is gone, or serves another name, is refused with a short code', async () => {
    mockFetch(route({ '/dns_records/': () => jsonRes(wire(notFound), 404) }));
    await expect(cloudflareProvider.inspectForAdoption!(cfg, RECORD_ID, HOSTNAME)).rejects.toThrow(
      /not_found/,
    );

    mockFetch(route());
    await expect(
      cloudflareProvider.inspectForAdoption!(cfg, RECORD_ID, 'someone-else.example.net'),
    ).rejects.toThrow(/hostname_mismatch/);
    // The name comparison is the normalised one (trailing dot, case).
    await expect(
      cloudflareProvider.inspectForAdoption!(cfg, RECORD_ID, `${HOSTNAME.toUpperCase()}.`),
    ).resolves.toMatchObject({ hostname: HOSTNAME });
  });

  test('an adoption refusal carries no hostname, origin address or token', async () => {
    mockFetch(route());
    const err = await cloudflareProvider.inspectForAdoption!(
      cfg,
      RECORD_ID,
      'someone-else.example.net',
    ).catch((e: unknown) => e);
    const blob = errorBlob(err);
    expect(blob).toContain('hostname_mismatch');
    for (const secret of ['SECRET_CF', HOSTNAME, ORIGIN, 'someone-else', 'example.net'])
      expect(blob).not.toContain(secret);
  });
});

// --- destroy --------------------------------------------------------------------------

describe('cloudflare: destroy', () => {
  test('the rule goes before the record, and both deletes are idempotent', async () => {
    const ledger = ledgerWith(recordResource, ruleResource);
    const order = cloudflareProvider.planDestroy(cfg, ledger);
    expect(order.map((r) => r.kind)).toEqual(['origin_rule', 'dns_record']);

    const stub = mockFetch(route());
    expect(await cloudflareProvider.runDestroy(cfg, ruleResource, ledger)).toEqual({
      status: 'confirmed_gone',
    });
    expect(await cloudflareProvider.runDestroy(cfg, recordResource, ledger)).toEqual({
      status: 'confirmed_gone',
    });
    expect(stub.calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      `DELETE /client/v4/zones/${ZONE}/rulesets/${RULESET}/rules/${RULE_ID}`,
      `DELETE /client/v4/zones/${ZONE}/dns_records/${RECORD_ID}`,
    ]);
  });

  test('a 404 on either delete is confirmed_gone (already removed)', async () => {
    mockFetch(() => jsonRes(wire(notFound), 404));
    const ledger = ledgerWith(recordResource, ruleResource);
    expect(await cloudflareProvider.runDestroy(cfg, ruleResource, ledger)).toEqual({
      status: 'confirmed_gone',
    });
    expect(await cloudflareProvider.runDestroy(cfg, recordResource, ledger)).toEqual({
      status: 'confirmed_gone',
    });
  });

  test('an unknown kind, or a rule with no ruleset in meta, is unresolved and never assumed gone', async () => {
    const stub = mockFetch(route());
    const ledger = ledgerWith(recordResource);
    expect(
      await cloudflareProvider.runDestroy(cfg, { ...ruleResource, meta: undefined }, ledger),
    ).toEqual({ status: 'unresolved' });
    expect(
      await cloudflareProvider.runDestroy(cfg, { ...recordResource, kind: 'mystery' }, ledger),
    ).toEqual({ status: 'unresolved' });
    expect(stub.calls).toHaveLength(0);
    // Synchronous deletes: no confirmDestroyed for this provider.
    expect(cloudflareProvider.confirmDestroyed).toBeUndefined();
    expect(EDGE_PROVIDER_CAPABILITIES.cloudflare.asyncDelete).toBe(false);
    expect(EDGE_PROVIDER_CAPABILITIES.cloudflare.asyncOps).toBe(false);
    expect(cloudflareProvider.pollStep).toBeUndefined();
  });
});

// --- account plumbing -------------------------------------------------------------------

describe('cloudflare: credentials + discovery options', () => {
  test('testCredentials verifies the token, the zone and the two soft preconditions', async () => {
    const stub = mockFetch(route());
    const res = await cloudflareProvider.testCredentials(cfg);
    expect(res.ok).toBe(true);
    expect(res.detail).toContain('ssl_full');
    expect(res.detail).toContain('websockets_on');
    expect(res.detail).toContain('plan_free');
    expect(stub.calls.map((c) => c.path)).toEqual([
      '/client/v4/user/tokens/verify',
      `/client/v4/zones/${ZONE}`,
      `/client/v4/zones/${ZONE}/settings/ssl`,
      `/client/v4/zones/${ZONE}/settings/websockets`,
    ]);
  });

  test('websockets off is a soft code, not a refusal (the operator may still use grpc)', async () => {
    const off = structuredClone(wire(settingWebsockets)) as { result: { value: string } };
    off.result.value = 'off';
    mockFetch(route({ '/settings/websockets': () => jsonRes(off) }));
    const res = await cloudflareProvider.testCredentials(cfg);
    expect(res.ok).toBe(true);
    expect(res.detail).toContain('websockets_off');
    expect(res.observed).toEqual({ zoneSslMode: 'full', websockets: 'off' });
  });

  test('the two settings travel as `observed`, which is what planning is later given', async () => {
    for (const mode of ['flexible', 'full', 'strict'] as const) {
      const ssl = structuredClone(wire(settingSsl)) as { result: { value: string } };
      ssl.result.value = mode;
      mockFetch(route({ '/settings/ssl': () => jsonRes(ssl) }));
      const res = await cloudflareProvider.testCredentials(cfg);
      expect(res.observed).toEqual({ zoneSslMode: mode, websockets: 'on' });
      // The observed mode is exactly what `zoneSslModeOf` accepts as a param.
      expect(zoneSslModeOf(specFor(443), withMode(res.observed!.zoneSslMode))).toBe(mode);
    }
    // A refusal still reports what it saw, so the operator sees the mode too.
    const off = structuredClone(wire(settingSsl)) as { result: { value: string } };
    off.result.value = 'off';
    mockFetch(route({ '/settings/ssl': () => jsonRes(off) }));
    expect((await cloudflareProvider.testCredentials(cfg)).observed).toEqual({
      zoneSslMode: 'off',
      websockets: 'on',
    });
  });

  test('a setting the token cannot read leaves the mode OUT rather than guessing one', async () => {
    mockFetch(
      route({
        '/settings/ssl': () => jsonRes(wire(notFound), 403),
        '/settings/websockets': () => jsonRes(wire(notFound), 403),
      }),
    );
    const res = await cloudflareProvider.testCredentials(cfg);
    expect(res.ok).toBe(true);
    // No zoneSslMode at all: an edge planned from this account is refused with
    // zone_mode_unknown instead of being built against an unread setting.
    expect(res.observed).toEqual({ websockets: 'off' });
    expect(() => zoneSslModeOf(specFor(443), withMode(res.observed!.zoneSslMode ?? ''))).toThrow(
      /zone_mode_unknown/,
    );
  });

  test('every ssl mode but `off` is usable; `off` is refused', async () => {
    for (const mode of ['flexible', 'full', 'strict']) {
      const ssl = structuredClone(wire(settingSsl)) as { result: { value: string } };
      ssl.result.value = mode;
      mockFetch(route({ '/settings/ssl': () => jsonRes(ssl) }));
      const res = await cloudflareProvider.testCredentials(cfg);
      expect(res).toMatchObject({ ok: true });
      expect(res.detail).toContain(`ssl_${mode}`);
    }
    const off = structuredClone(wire(settingSsl)) as { result: { value: string } };
    off.result.value = 'off';
    mockFetch(route({ '/settings/ssl': () => jsonRes(off) }));
    expect(await cloudflareProvider.testCredentials(cfg)).toMatchObject({
      ok: false,
      code: 'zone_ssl_off',
    });
  });

  test('a paused or non-active zone, and an inactive token, are refused with a short code', async () => {
    const paused = structuredClone(wire(zoneGet)) as {
      result: { paused: boolean; status: string };
    };
    paused.result.paused = true;
    mockFetch(route({ [`/zones/${ZONE}`]: () => jsonRes(paused) }));
    expect(await cloudflareProvider.testCredentials(cfg)).toMatchObject({ code: 'zone_paused' });

    const pending = structuredClone(wire(zoneGet)) as { result: { status: string } };
    pending.result.status = 'pending';
    mockFetch(route({ [`/zones/${ZONE}`]: () => jsonRes(pending) }));
    expect(await cloudflareProvider.testCredentials(cfg)).toMatchObject({
      code: 'zone_not_active',
    });

    const stale = structuredClone(wire(tokenVerify)) as { result: { status: string } };
    stale.result.status = 'expired';
    mockFetch(route({ '/user/tokens/verify': () => jsonRes(stale) }));
    expect(await cloudflareProvider.testCredentials(cfg)).toEqual({
      ok: false,
      code: 'token_not_active',
    });
  });

  test('a rejected token reports the provider answer without the token', async () => {
    mockFetch(() =>
      jsonRes(
        {
          result: null,
          success: false,
          errors: [{ code: 1000, message: 'Invalid API Token SECRET_CF' }],
        },
        403,
      ),
    );
    const res = await cloudflareProvider.testCredentials(cfg);
    expect(res).toEqual({ ok: false, code: '1000', detail: '1000 Invalid API Token [redacted]' });
    expect(JSON.stringify(res)).not.toContain('SECRET_CF');
  });

  test('discoverOptions lists zones; a failure becomes a per-list code, never a throw', async () => {
    const stub = mockFetch(route());
    expect(await cloudflareProvider.discoverOptions?.({ apiToken: 'SECRET_CF' })).toEqual({
      zones: [
        { id: ZONE, label: 'example.net' },
        { id: '7c1a1e4f9d2b4f8a9c3d5e6f7a8b9c0d', label: 'example.org' },
      ],
    });
    expect((stub.calls[0] as Captured).path).toBe('/client/v4/zones');
    expect(await cloudflareProvider.discoverOptions?.({})).toEqual({});
    mockFetch(() => jsonRes(wire(rateLimited), 429));
    const failed = await cloudflareProvider.discoverOptions?.({ apiToken: 'SECRET_CF' });
    expect(failed?.errors).toEqual({ zones: '10000' });
    // The provider's words ride along for the admin, never the token.
    expect(failed?.errorDetails?.zones).toBeDefined();
    expect(JSON.stringify(failed)).not.toContain('SECRET_CF');
  });

  test('listRegions offers the account zones', async () => {
    mockFetch(route());
    expect(await cloudflareProvider.listRegions?.(cfg)).toEqual([
      { id: ZONE, label: 'example.net' },
      { id: '7c1a1e4f9d2b4f8a9c3d5e6f7a8b9c0d', label: 'example.org' },
    ]);
  });
});

describe('cloudflare: capability cross-check + error hygiene', () => {
  test('the capability row matches what the adapter observably does', () => {
    const caps = EDGE_PROVIDER_CAPABILITIES.cloudflare;
    expect(caps.layer).toBe('l7');
    expect(caps.addressKind).toBe('hostname');
    expect(caps.providesDns).toBe(true);
    expect(caps.needsDnsAccount).toBe(false);
    expect(caps.originPortMode).toBe('default-or-override');
    expect([...caps.l7Transports]).toEqual(['ws', 'httpupgrade', 'grpc', 'xhttp']);
  });

  test('an L7 describe reports a hostname and never an IP literal', async () => {
    mockFetch(route());
    const out = await cloudflareProvider.describe(cfg, ledgerWith(recordResource));
    expect(out.addresses.hostname).toBe(HOSTNAME);
    expect(out.addresses.v4).toBeUndefined();
    expect(out.addresses.v6).toBeUndefined();
  });

  test('no thrown error carries the token, the zone name, the origin address or a body', async () => {
    mockFetch(() =>
      jsonRes(
        {
          result: null,
          success: false,
          errors: [
            {
              code: 81053,
              message: `A record for ${HOSTNAME} pointing at ${ORIGIN} already exists`,
            },
          ],
        },
        400,
      ),
    );
    const steps = cloudflareProvider.planProvision(cfg, specFor(), tpl);
    const err = await cloudflareProvider
      .runStep(cfg, steps[0]!, specFor(), tpl, emptyLedger)
      .catch((e: unknown) => e);
    const blob = errorBlob(err);
    for (const secret of [
      'SECRET_CF',
      'example.net',
      ORIGIN,
      'already exists',
      'api.cloudflare.com',
    ])
      expect(blob).not.toContain(secret);
    expect(blob).toContain('81053');
  });
});
