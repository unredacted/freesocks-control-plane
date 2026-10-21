// @vitest-environment node
/**
 * Fastly adapter contract. Everything that touches HTTP drives the REAL `fastly`
 * SDK (superagent, hence the node environment) against an in-process recorder,
 * so the request shapes asserted here are the ones the SDK actually puts on the
 * wire; the response fixtures under ./fixtures/fastly cite the Fastly reference
 * they were taken from, so a hand-written adapter and a hand-written mock cannot
 * quietly agree on a shape the API never produces.
 *
 * The DNS writer is an in-memory fake injected through the adapter's factory
 * seam, so these tests never load the Cloudflare SDK.
 */
import { createServer, type Server } from 'node:http';
import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { errorBlob } from '../testing/mockFetch';
import { acmeChallengeName } from '../hostname';
import type {
  ChildResource,
  EdgeSpec,
  FastlyConfig,
  Ledger,
  LedgerResource,
  ResourceStep,
  StepOutcome,
} from './types';
import type { DnsClient, DnsCreateArgs, DnsRecord, DnsRecordType } from './dns/types';
import { __setFastlyBasePath, fastlyApiFor } from './fastly/sdk';
import type { CaaRecord } from '../caa';
import {
  FASTLY_DESTROY_ORDER,
  FASTLY_WS_UPGRADE_VCL,
  CERTIFICATE_EXPIRY_WARN_MS,
  TLS_WARNING_GRACE_MS,
  __setFastlyCaaLookup,
  __setFastlyDnsClientFactory,
  fastlyBackendBody,
  fastlyDestroyKey,
  fastlyOriginTlsName,
  fastlyProvider,
  fastlySnippetBody,
  fastlyTlsSubscriptionBody,
  highestDraftVersion,
  managedDnsChallenge,
  parseDomainCheck,
  parseTlsChallenges,
  parseTrafficCname,
  planSharedTeardown,
  sharedAcmeMarker,
  sharedTeardownStep,
  tlsAuthorizationCode,
  type SharedTeardownState,
} from './fastly';

// --- in-process recorder -------------------------------------------------------------

interface Call {
  method: string;
  path: string;
  query: Record<string, string>;
  headers: Record<string, string | undefined>;
  body: unknown;
}
type Reply = { status: number; body?: unknown; contentType?: string };
type Route = (call: Call, index: number) => Reply;
interface Recorder {
  calls: Call[];
  base: string;
  close: () => Promise<void>;
}

function fixture(name: string): unknown {
  const raw = JSON.parse(
    readFileSync(new URL(`./fixtures/fastly/${name}`, import.meta.url), 'utf8'),
  ) as Record<string, unknown>;
  if ('_body' in raw) return raw._body;
  const { _source: _ignored, ...rest } = raw;
  return rest;
}

async function startRecorder(route: Route): Promise<Recorder> {
  const calls: Call[] = [];
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      const url = new URL(req.url ?? '/', 'http://recorder.invalid');
      const query: Record<string, string> = {};
      url.searchParams.forEach((v, k) => (query[k] = v));
      const contentType = String(req.headers['content-type'] ?? '');
      let body: unknown;
      if (raw.length > 0) {
        if (contentType.includes('json')) {
          try {
            body = JSON.parse(raw);
          } catch {
            body = raw;
          }
        } else if (contentType.includes('x-www-form-urlencoded')) {
          body = Object.fromEntries(new URLSearchParams(raw).entries());
        } else body = raw;
      }
      const call: Call = {
        method: req.method ?? 'GET',
        path: url.pathname,
        query,
        headers: req.headers as Record<string, string | undefined>,
        body,
      };
      calls.push(call);
      const reply = route(call, calls.length - 1);
      const payload = reply.body === undefined ? '' : JSON.stringify(reply.body);
      res.writeHead(reply.status, {
        'content-type': reply.contentType ?? 'application/json',
        'content-length': Buffer.byteLength(payload),
      });
      res.end(payload);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  return {
    calls,
    base: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

// --- fixtures of our own -------------------------------------------------------------

const HOST = 'k3m7q9zb.example.org';
const ORIGIN = 'node-7.origin.example.net';
const SVC = 'SU1Z0isxPaozGVKXdv0eY';
const SUB = 'C0cuTFmLzMCiyMcOZuLEZ1';
const DM = 'DMDOM01kq7v3xzwYb9pRn';
/** The Fastly customer `current-customer.json` names (the shared ACME marker's owner). */
const CUSTOMER = 'x4xCwxxJxGCx123Rgqjx8k';
const ACME_TARGET = '6a8mtt5uzzsw2qsl.fastly-validations.com';
const TRAFFIC_TARGET = 'j.sni.global.fastly.net';

const cfg: FastlyConfig = {
  type: 'fastly',
  apiToken: 'SECRET_FASTLY_TOKEN',
  certificateAuthority: 'certainly',
  dns: {
    apiToken: 'SECRET_CF_TOKEN',
    zoneId: '0123456789abcdef0123456789abcdef',
    zoneName: 'example.org',
    accountId: 'dnsacct1',
  },
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
const tpl = fastlyProvider.templateSchema.parse({});

// --- in-memory DNS client -------------------------------------------------------------

interface FakeDns extends DnsClient {
  rows: DnsRecord[];
  deleted: string[];
}
function fakeDns(seed: DnsRecord[] = []): FakeDns {
  const rows = [...seed];
  const deleted: string[] = [];
  let next = seed.length + 1;
  const client: FakeDns = {
    rows,
    deleted,
    zoneId: cfg.dns!.zoneId,
    zoneName: cfg.dns!.zoneName,
    accountId: cfg.dns!.accountId,
    async createRecord(args: DnsCreateArgs) {
      const rec: DnsRecord = { id: `rec${next++}`, ...args };
      rows.push(rec);
      return rec;
    },
    async findRecordsByName(name: string, type?: DnsRecordType) {
      return rows.filter((r) => r.name === name && (!type || r.type === type));
    },
    async getRecord(id: string) {
      return rows.find((r) => r.id === id) ?? null;
    },
    async deleteRecord(id: string) {
      deleted.push(id);
      const i = rows.findIndex((r) => r.id === id);
      if (i >= 0) rows.splice(i, 1);
    },
    async listCaa() {
      return [];
    },
  };
  __setFastlyDnsClientFactory(() => client);
  return client;
}

// --- default provider behaviour --------------------------------------------------------

const ok = (name: string): Reply => ({ status: 200, body: fixture(name) });
const api = (name: string): Reply => ({
  status: 200,
  body: fixture(name),
  contentType: 'application/vnd.api+json',
});
const NOT_FOUND: Reply = { status: 404, body: { msg: 'Record not found' } };

function defaultReply(c: Call): Reply {
  const p = c.path;
  const m = c.method;
  if (m === 'POST' && p === '/service') return ok('service-create.json');
  if (m === 'GET' && p === '/service/search') return ok('service-search.json');
  if (m === 'GET' && p === `/service/${SVC}/details`) return ok('service-detail-active.json');
  if (m === 'GET' && p === '/service') return ok('service-list.json');
  if (m === 'GET' && p === `/service/${SVC}/domain`) return ok('service-domains.json');
  if (m === 'DELETE' && p === `/service/${SVC}`) return { status: 200, body: { status: 'ok' } };
  if (m === 'GET' && p === `/service/${SVC}/version`) return ok('version-list.json');
  if (m === 'PUT' && /\/version\/\d+\/clone$/.test(p)) return ok('version-clone.json');
  if (m === 'GET' && /\/version\/\d+\/validate$/.test(p)) return ok('version-validate-ok.json');
  if (m === 'PUT' && /\/version\/\d+\/activate$/.test(p)) return ok('version-activate.json');
  if (m === 'PUT' && /\/version\/\d+\/deactivate$/.test(p)) return ok('version-activate.json');
  if (m === 'PUT' && /\/version\/\d+$/.test(p)) return ok('version-clone.json');
  if (m === 'POST' && /\/backend$/.test(p)) return ok('backend-create.json');
  if (m === 'GET' && /\/backend\/origin$/.test(p)) return ok('backend-create.json');
  if (m === 'GET' && /\/backend$/.test(p))
    return { status: 200, body: [fixture('backend-create.json')] };
  if (m === 'POST' && /\/snippet$/.test(p)) return ok('snippet-create.json');
  if (m === 'GET' && /\/snippet\/ws-upgrade$/.test(p)) return ok('snippet-create.json');
  if (m === 'POST' && /\/domain$/.test(p)) return ok('domain-create.json');
  if (m === 'GET' && p.endsWith(`/domain/${HOST}/check`)) return ok('domain-check-ok.json');
  if (m === 'GET' && p.endsWith(`/domain/${HOST}`)) return ok('domain-create.json');
  if (m === 'DELETE' && p.endsWith(`/domain/${HOST}`))
    return { status: 200, body: { status: 'ok' } };
  if (m === 'GET' && /\/domain$/.test(p))
    return { status: 200, body: [fixture('domain-create.json')] };
  // Versionless domains: none linked yet, unless a test routes otherwise.
  if (m === 'GET' && p === '/domain-management/v1/domains') return ok('dm-domains-empty.json');
  if (m === 'POST' && p === '/domain-management/v1/domains') return ok('dm-domain-create.json');
  if (p === `/domain-management/v1/domains/${DM}`)
    return m === 'DELETE' ? { status: 204 } : ok('dm-domain-create.json');
  if (p === `/enabled-products/v1/websockets/services/${SVC}`)
    return m === 'DELETE' ? { status: 204 } : ok('websockets-enabled.json');
  if (m === 'POST' && p === '/tls/subscriptions') return api('tls-subscription-create.json');
  if (m === 'GET' && p === '/tls/subscriptions') return api('tls-subscriptions-list.json');
  if (m === 'GET' && p === `/tls/subscriptions/${SUB}`)
    return api(
      c.query.include ? 'tls-subscription-authorizations.json' : 'tls-subscription-issued.json',
    );
  if (m === 'DELETE' && p === `/tls/subscriptions/${SUB}`) return { status: 204 };
  if (m === 'GET' && p === '/tls/configurations') return api('tls-configurations.json');
  if (p === '/tokens/self') return ok('token-self.json');
  if (p === '/current_customer') return ok('current-customer.json');
  return NOT_FOUND;
}

let rec: Recorder | undefined;
// No CAA record anywhere unless a test says otherwise (the suite refuses real DNS).
beforeEach(() => __setFastlyCaaLookup(async () => []));
afterEach(async () => {
  __setFastlyBasePath(null);
  __setFastlyDnsClientFactory(null);
  __setFastlyCaaLookup(null);
  await rec?.close();
  rec = undefined;
});

async function serve(route: Route = defaultReply): Promise<Recorder> {
  rec = await startRecorder(route);
  __setFastlyBasePath(rec.base);
  return rec;
}

/** Fold a step outcome into a ledger the way the orchestrator's mutation does. */
function apply(ledger: Ledger, step: ResourceStep, out: StepOutcome): Ledger {
  const resources: ChildResource[] = 'resources' in out ? out.resources : [];
  return {
    steps: [
      ...ledger.steps,
      {
        stepId: step.id,
        kind: step.kind,
        resourceName: step.resourceName,
        state:
          out.status === 'done' ? 'done' : out.status === 'requested' ? 'requested' : 'unresolved',
        attempt: 1,
      },
    ],
    resources: [
      ...ledger.resources,
      ...resources.map((r) => ({
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

/** Run the whole plan and return the ledger it produced. */
async function provision(): Promise<Ledger> {
  let ledger: Ledger = { steps: [], resources: [] };
  for (const step of fastlyProvider.planProvision(cfg, spec, tpl)) {
    const out = await fastlyProvider.runStep(cfg, step, spec, tpl, ledger);
    ledger = apply(ledger, step, out);
    if (out.status === 'requested') {
      const polled = await fastlyProvider.pollStep!(cfg, step, out.opRef, ledger);
      ledger = apply(ledger, step, polled);
    }
  }
  return ledger;
}

// --- plan-time refusals ----------------------------------------------------------------

describe('fastly: what it refuses before any provider call', () => {
  const cases: Array<[string, Partial<EdgeSpec>, string]> = [
    ['no origin transport at all', { originTransport: undefined }, 'origin_transport_missing'],
    [
      'an https origin with a private certificate',
      {
        originTransport: {
          scheme: 'https',
          certPublic: false,
          certNames: [],
          acceptsHostHeader: 'any',
        },
      },
      'origin_cert_not_public',
    ],
    [
      'an https origin on a port other than 443',
      { listeners: [{ edgePort: 443, members: [{ address: ORIGIN, port: 8443 }] }] },
      'origin_port_unsupported',
    ],
    [
      'an http origin on a port other than 80',
      {
        originTransport: {
          scheme: 'http',
          certPublic: false,
          certNames: [],
          acceptsHostHeader: 'any',
        },
      },
      'origin_port_unsupported',
    ],
    ['no hostname', { hostname: undefined }, 'hostname_missing'],
  ];
  test.each(cases)('%s is refused with %s', (_label, patch, code) => {
    const bad: EdgeSpec = { ...spec, ...patch } as EdgeSpec;
    try {
      fastlyProvider.planProvision(cfg, bad, tpl);
      throw new Error('expected a refusal');
    } catch (e) {
      expect((e as { meta?: { code?: string } }).meta?.code).toBe(code);
      expect(errorBlob(e)).not.toContain(ORIGIN);
    }
  });

  test('an http origin on 80 is accepted and dials the origin without TLS', () => {
    const http: EdgeSpec = {
      ...spec,
      listeners: [{ edgePort: 443, members: [{ address: ORIGIN, port: 80 }] }],
      originTransport: {
        scheme: 'http',
        certPublic: false,
        certNames: [],
        acceptsHostHeader: 'any',
      },
    };
    expect(fastlyProvider.planProvision(cfg, http, tpl)).toHaveLength(10);
    expect(fastlyBackendBody(http, tpl).use_ssl).toBe(false);
  });

  test('the plan is ten uniquely named, discoverable steps in dependency order', () => {
    const steps = fastlyProvider.planProvision(cfg, spec, tpl);
    expect(steps.map((s) => s.kind)).toEqual([
      'create_service',
      'create_backend',
      'create_snippet',
      'create_domain',
      'enable_product',
      'activate_version',
      'create_tls_subscription',
      'create_dns_acme',
      'await_tls',
      'create_dns_record',
    ]);
    expect(new Set(steps.map((s) => s.id)).size).toBe(steps.length);
    for (const s of steps) expect(s.discoverability).toBe('by_name');
  });
});

// --- pure wire bodies ---------------------------------------------------------------------

describe('fastly: request bodies', () => {
  test('the backend names its port and TLS name explicitly (plus a marker comment)', () => {
    expect(fastlyBackendBody(spec, tpl)).toEqual({
      name: 'origin',
      address: ORIGIN,
      // Never left to the API: it defaults to 80 even with use_ssl.
      port: 443,
      use_ssl: true,
      // The origin address is the name its certificate covers.
      ssl_cert_hostname: ORIGIN,
      ssl_sni_hostname: ORIGIN,
      override_host: HOST,
      comment: spec.name,
    });
  });

  test('the TLS name is a name the certificate covers, never a wildcard, and absent without TLS', () => {
    const byIp: EdgeSpec = {
      ...spec,
      listeners: [{ edgePort: 443, members: [{ address: '198.51.100.7', port: 443 }] }],
      originTransport: {
        ...spec.originTransport!,
        certNames: ['*.origin.example.net', 'origin.example.net'],
      },
    };
    expect(fastlyOriginTlsName(byIp)).toBe('origin.example.net');
    expect(fastlyBackendBody(byIp, tpl)).toMatchObject({
      address: '198.51.100.7',
      port: 443,
      ssl_sni_hostname: 'origin.example.net',
    });
    const onlyWildcard: EdgeSpec = {
      ...byIp,
      originTransport: { ...spec.originTransport!, certNames: ['*.origin.example.net'] },
    };
    expect(fastlyOriginTlsName(onlyWildcard)).toBeUndefined();
    expect(fastlyBackendBody(onlyWildcard, tpl)).not.toHaveProperty('ssl_sni_hostname');
    const http: EdgeSpec = {
      ...spec,
      listeners: [{ edgePort: 443, members: [{ address: ORIGIN, port: 80 }] }],
      originTransport: {
        scheme: 'http',
        certPublic: false,
        certNames: [],
        acceptsHostHeader: 'any',
      },
    };
    const body = fastlyBackendBody(http, tpl);
    expect(body).toMatchObject({ port: 80, use_ssl: false });
    expect(body).not.toHaveProperty('ssl_cert_hostname');
    expect(body).not.toHaveProperty('ssl_sni_hostname');
  });

  test('overrideHost `origin` sends the origin its own name instead of the fronted one', () => {
    const t = fastlyProvider.templateSchema.parse({ overrideHost: 'origin' });
    expect(fastlyBackendBody(spec, t).override_host).toBe(ORIGIN);
  });

  test('the snippet is the upgrade guard, string-typed as the API wants', () => {
    expect(fastlySnippetBody()).toEqual({
      name: 'ws-upgrade',
      type: 'recv',
      content: FASTLY_WS_UPGRADE_VCL,
      priority: '100',
      dynamic: '0',
    });
  });

  test('the TLS subscription names the domain, the CA and (only when set) the configuration', () => {
    expect(fastlyTlsSubscriptionBody(HOST, 'certainly', 'TLSCONFIG01')).toEqual({
      data: {
        type: 'tls_subscription',
        attributes: { certificate_authority: 'certainly' },
        relationships: {
          tls_domains: { data: [{ type: 'tls_domain', id: HOST }] },
          tls_configuration: { data: { type: 'tls_configuration', id: 'TLSCONFIG01' } },
        },
      },
    });
    const withoutConfig = fastlyTlsSubscriptionBody(HOST, 'lets-encrypt');
    expect(
      (withoutConfig.data as { relationships: Record<string, unknown> }).relationships,
    ).not.toHaveProperty('tls_configuration');
  });
});

// --- pure response readers ------------------------------------------------------------------

describe('fastly: response readers', () => {
  test('the managed-dns challenge is the one FCP can satisfy', () => {
    const doc = fixture('tls-subscription-authorizations.json');
    expect(parseTlsChallenges(doc).map((c) => c.type)).toEqual([
      'managed-dns',
      'managed-http-cname',
    ]);
    expect(managedDnsChallenge(doc)).toMatchObject({
      record_name: acmeChallengeName(HOST),
      values: [ACME_TARGET],
    });
    expect(parseTlsChallenges({})).toEqual([]);
  });

  test('the domain check is a positional triple, and only the third element means ready', () => {
    expect(parseDomainCheck(fixture('domain-check-ok.json'))).toEqual({
      cname: 'k3m7q9zb.example.org.global.prod.fastly.net',
      ok: true,
    });
    expect(parseDomainCheck(fixture('domain-check-pending.json')).ok).toBe(false);
    expect(parseDomainCheck([fixture('domain-check-ok.json')]).ok).toBe(true);
    expect(parseDomainCheck(null).ok).toBe(false);
  });

  test('the traffic CNAME is the included dns_record id, never a hard-coded name', () => {
    const doc = fixture('tls-configurations.json') as never;
    expect(parseTrafficCname(doc)).toBe(TRAFFIC_TARGET);
    expect(parseTrafficCname(doc, 'TLSCONFIG02')).toBe('c.sni.global.fastly.net');
    expect(parseTrafficCname({ data: [] } as never)).toBeUndefined();
  });

  test('the draft version is the highest unlocked, inactive one', () => {
    expect(
      highestDraftVersion([
        { number: 1, active: true, locked: true },
        { number: 2, active: false, locked: true },
        { number: 3, active: false, locked: false },
      ])?.number,
    ).toBe(3);
    expect(highestDraftVersion([{ number: 1, active: true, locked: true }])).toBeUndefined();
  });
});

// --- provisioning ---------------------------------------------------------------------------

describe('fastly: provisioning', () => {
  test('every step targets the ONE persisted draft version and records its resource', async () => {
    const r = await serve();
    fakeDns();
    const ledger = await provision();

    const service = ledger.resources.find((x) => x.kind === 'service')!;
    expect(service.resourceId).toBe(SVC);
    expect(JSON.parse(service.meta!)).toEqual({ version: 1, name: spec.name });
    expect(ledger.resources.map((x) => x.kind)).toEqual([
      'service',
      'backend',
      'snippet',
      'domain',
      'ws_product',
      'active_version',
      'tls_subscription',
      'dns_record',
      'dns_record',
    ]);

    const paths = r.calls.map((c) => `${c.method} ${c.path}`);
    expect(paths).toEqual([
      'POST /service',
      `POST /service/${SVC}/version/1/backend`,
      `POST /service/${SVC}/version/1/snippet`,
      `POST /service/${SVC}/version/1/domain`,
      `PUT /enabled-products/v1/websockets/services/${SVC}`,
      `GET /service/${SVC}/version/1/validate`,
      `PUT /service/${SVC}/version/1/activate`,
      'POST /tls/subscriptions',
      `GET /tls/subscriptions/${SUB}`,
      `GET /tls/subscriptions/${SUB}`,
      `GET /tls/subscriptions/${SUB}`,
      'GET /tls/configurations',
    ]);
    // The ACME read, the wait's first look and its poll all ask for the
    // authorizations: a wait reports what holds it up.
    for (const i of [8, 9, 10]) expect(r.calls[i].query).toEqual({ include: 'tls_authorizations' });
    expect(r.calls[11].query).toEqual({ include: 'dns_records', 'page[size]': '100' });
  });

  test('the two DNS records are the ACME challenge and the traffic CNAME, both marked as ours', async () => {
    await serve();
    const dns = fakeDns();
    const ledger = await provision();
    expect(dns.rows).toEqual([
      {
        id: 'rec1',
        type: 'CNAME',
        name: acmeChallengeName(HOST),
        content: ACME_TARGET,
        proxied: false,
        comment: spec.name,
      },
      {
        id: 'rec2',
        type: 'CNAME',
        name: HOST,
        content: TRAFFIC_TARGET,
        proxied: false,
        comment: spec.name,
      },
    ]);
    const roles = ledger.resources
      .filter((x) => x.kind === 'dns_record')
      .map((x) => JSON.parse(x.meta!));
    expect(roles).toEqual([
      {
        dnsAccountId: 'dnsacct1',
        zoneId: cfg.dns!.zoneId,
        recordId: 'rec1',
        name: acmeChallengeName(HOST),
        role: 'acme',
      },
      {
        dnsAccountId: 'dnsacct1',
        zoneId: cfg.dns!.zoneId,
        recordId: 'rec2',
        name: HOST,
        role: 'traffic',
      },
    ]);
  });

  test('certificate issuance is polled, not waited on: pending stays requested, issued finishes', async () => {
    let state = 'processing';
    await serve((c) =>
      c.path === `/tls/subscriptions/${SUB}`
        ? api(
            state === 'issued'
              ? 'tls-subscription-issued.json'
              : 'tls-subscription-authorizations.json',
          )
        : defaultReply(c),
    );
    // The validation record is in place: nothing but time holds the wait up.
    fakeDns([
      {
        id: 'acme1',
        type: 'CNAME',
        name: acmeChallengeName(HOST),
        content: ACME_TARGET,
        proxied: false,
        comment: spec.name,
      },
    ]);
    const ledger: Ledger = {
      steps: [],
      resources: [
        {
          stepId: 'tls',
          kind: 'tls_subscription',
          resourceId: SUB,
          ownership: 'created',
          deleteState: 'present',
          meta: JSON.stringify({ hostname: HOST }),
        },
        {
          stepId: 'domain',
          kind: 'domain',
          resourceId: HOST,
          ownership: 'created',
          deleteState: 'present',
        },
      ],
    };
    const step = fastlyProvider.planProvision(cfg, spec, tpl).find((s) => s.kind === 'await_tls')!;
    const started = await fastlyProvider.runStep(cfg, step, spec, tpl, ledger);
    expect(started).toEqual({ status: 'requested', opRef: SUB, resources: [] });
    expect(await fastlyProvider.pollStep!(cfg, step, SUB, ledger)).toMatchObject({
      status: 'requested',
    });
    state = 'issued';
    expect(await fastlyProvider.pollStep!(cfg, step, SUB, ledger)).toEqual({
      status: 'done',
      resources: [],
      addresses: { hostname: HOST },
    });
  });

  test('a failed subscription is a partial outcome with a code, never a thrown body', async () => {
    await serve((c) =>
      c.path === `/tls/subscriptions/${SUB}`
        ? api('tls-subscription-failed.json')
        : defaultReply(c),
    );
    const step = fastlyProvider.planProvision(cfg, spec, tpl).find((s) => s.kind === 'await_tls')!;
    expect(
      await fastlyProvider.pollStep!(cfg, step, SUB, { steps: [], resources: [] }),
    ).toMatchObject({ status: 'partial', code: 'tls_failed' });
  });

  test('a version that does not validate is partial, so activation is never attempted', async () => {
    const r = await serve((c) =>
      /\/validate$/.test(c.path) ? ok('version-validate-error.json') : defaultReply(c),
    );
    const ledger = apply(
      { steps: [], resources: [] },
      {
        id: 'service',
        kind: 'create_service',
        resourceName: spec.name,
        discoverability: 'by_name',
      },
      {
        status: 'done',
        resources: [
          {
            kind: 'service',
            resourceId: SVC,
            ownership: 'created',
            meta: { version: 1, name: spec.name },
          },
        ],
      },
    );
    const step = fastlyProvider
      .planProvision(cfg, spec, tpl)
      .find((s) => s.kind === 'activate_version')!;
    expect(await fastlyProvider.runStep(cfg, step, spec, tpl, ledger)).toEqual({
      status: 'partial',
      resources: [],
      code: 'version_invalid',
    });
    expect(r.calls.some((c) => c.path.endsWith('/activate'))).toBe(false);
  });

  test('an account without the WebSockets entitlement is refused with a code, not a body', async () => {
    await serve((c) =>
      c.path.startsWith('/enabled-products/')
        ? { status: 403, body: { msg: 'Forbidden', detail: `service ${SVC} at ${ORIGIN}` } }
        : defaultReply(c),
    );
    const ledger = apply(
      { steps: [], resources: [] },
      {
        id: 'service',
        kind: 'create_service',
        resourceName: spec.name,
        discoverability: 'by_name',
      },
      {
        status: 'done',
        resources: [
          {
            kind: 'service',
            resourceId: SVC,
            ownership: 'created',
            meta: { version: 1, name: spec.name },
          },
        ],
      },
    );
    const step = fastlyProvider
      .planProvision(cfg, spec, tpl)
      .find((s) => s.kind === 'enable_product')!;
    const err = await fastlyProvider.runStep(cfg, step, spec, tpl, ledger).catch((e) => e);
    expect(err.meta.code).toBe('websockets_not_entitled');
    expect(errorBlob(err)).not.toContain(ORIGIN);
    expect(errorBlob(err)).not.toContain('SECRET_FASTLY_TOKEN');
  });
});

// --- discovery -------------------------------------------------------------------------------

describe('fastly: discovery answers the four outcomes', () => {
  test('a lost create response is resolved by a read, and no second service is allocated', async () => {
    const r = await serve();
    fakeDns();
    const step = fastlyProvider.planProvision(cfg, spec, tpl)[0];
    const found = await fastlyProvider.discover(cfg, step, spec, { steps: [], resources: [] }, 1);
    expect(found).toEqual({
      status: 'found',
      resources: [
        {
          kind: 'service',
          resourceId: SVC,
          ownership: 'adopted',
          // The draft version is chosen ONCE, here: version 2 (1 is locked).
          meta: { version: 2, name: spec.name },
        },
      ],
    });
    expect(r.calls.every((c) => c.method === 'GET')).toBe(true);
  });

  test('a service with no unlocked draft is ambiguous, never silently edited', async () => {
    await serve((c) =>
      c.path === '/service/search'
        ? {
            status: 200,
            body: {
              id: SVC,
              name: spec.name,
              versions: [{ number: 1, active: true, locked: true }],
            },
          }
        : defaultReply(c),
    );
    const step = fastlyProvider.planProvision(cfg, spec, tpl)[0];
    expect(
      await fastlyProvider.discover(cfg, step, spec, { steps: [], resources: [] }, 1),
    ).toMatchObject({ status: 'ambiguous' });
  });

  test('an absent service is confirmed absent (404 from the name search)', async () => {
    await serve((c) => (c.path === '/service/search' ? NOT_FOUND : defaultReply(c)));
    const step = fastlyProvider.planProvision(cfg, spec, tpl)[0];
    expect(await fastlyProvider.discover(cfg, step, spec, { steps: [], resources: [] }, 1)).toEqual(
      {
        status: 'confirmed_absent',
      },
    );
  });

  const serviceLedger: Ledger = {
    steps: [],
    resources: [
      {
        stepId: 'service',
        kind: 'service',
        resourceId: SVC,
        ownership: 'created',
        deleteState: 'present',
        meta: JSON.stringify({ version: 1, name: 'fcp-relay-o1-deadbeef' }),
      },
      {
        stepId: 'tls',
        kind: 'tls_subscription',
        resourceId: SUB,
        ownership: 'created',
        deleteState: 'present',
        meta: JSON.stringify({ hostname: HOST }),
      },
    ],
  };

  test.each([
    ['create_backend', 'backend', 'origin'],
    ['create_snippet', 'snippet', 'ws-upgrade'],
    ['create_domain', 'domain', HOST],
    ['enable_product', 'ws_product', SVC],
    ['activate_version', 'active_version', '1'],
    ['create_tls_subscription', 'tls_subscription', SUB],
  ])('%s discovers its own resource by name', async (kind, resourceKind, resourceId) => {
    await serve();
    const step = fastlyProvider.planProvision(cfg, spec, tpl).find((s) => s.kind === kind)!;
    const res = await fastlyProvider.discover(cfg, step, spec, serviceLedger, 1);
    expect(res.status).toBe('found');
    expect(res.status === 'found' && res.resources[0]).toMatchObject({
      kind: resourceKind,
      resourceId,
      ownership: 'adopted',
    });
  });

  test.each([
    ['create_backend'],
    ['create_snippet'],
    ['create_domain'],
    ['enable_product'],
    ['create_tls_subscription'],
  ])('%s proves absence when the provider says the object is not there', async (kind) => {
    await serve((c) => {
      if (/\/(backend\/origin|snippet\/ws-upgrade)$/.test(c.path)) return NOT_FOUND;
      if (c.path.endsWith(`/domain/${HOST}`)) return NOT_FOUND;
      if (c.path.startsWith('/enabled-products/')) return NOT_FOUND;
      if (c.path === '/tls/subscriptions') return api('tls-subscriptions-empty.json');
      return defaultReply(c);
    });
    const step = fastlyProvider.planProvision(cfg, spec, tpl).find((s) => s.kind === kind)!;
    expect(await fastlyProvider.discover(cfg, step, spec, serviceLedger, 1)).toEqual({
      status: 'confirmed_absent',
    });
  });

  test('a version that is not the active one is confirmed absent, so activation is retried', async () => {
    await serve((c) =>
      c.path === `/service/${SVC}/details`
        ? { status: 200, body: { id: SVC, active_version: { number: 7 } } }
        : defaultReply(c),
    );
    const step = fastlyProvider
      .planProvision(cfg, spec, tpl)
      .find((s) => s.kind === 'activate_version')!;
    expect(await fastlyProvider.discover(cfg, step, spec, serviceLedger, 1)).toEqual({
      status: 'confirmed_absent',
    });
  });

  /** A `GET /tls/subscriptions` answer built from (id, domains, CA, configuration). */
  function subscriptionsDoc(
    subs: Array<{ id: string; domains: string[]; ca?: string; configuration?: string }>,
  ) {
    return {
      status: 200,
      contentType: 'application/vnd.api+json',
      body: {
        data: subs.map((x) => ({
          id: x.id,
          type: 'tls_subscription',
          attributes: { state: 'issued', certificate_authority: x.ca ?? 'certainly' },
          relationships: {
            tls_domains: { data: x.domains.map((d) => ({ id: d, type: 'tls_domain' })) },
            ...(x.configuration
              ? {
                  tls_configuration: {
                    data: { id: x.configuration, type: 'tls_configuration' },
                  },
                }
              : {}),
          },
        })),
        meta: { current_page: 1, per_page: 20, record_count: subs.length, total_pages: 1 },
      },
    };
  }

  const tlsStep = () =>
    fastlyProvider.planProvision(cfg, spec, tpl).find((s) => s.kind === 'create_tls_subscription')!;

  test('a subscription is adopted only when it is the ONLY one covering the hostname and matches the intent', async () => {
    // Exactly one, issued by the certificate authority this edge was planned
    // with: proven enough to adopt.
    await serve((c) =>
      c.method === 'GET' && c.path === '/tls/subscriptions'
        ? subscriptionsDoc([{ id: SUB, domains: [HOST] }])
        : defaultReply(c),
    );
    expect(await fastlyProvider.discover(cfg, tlsStep(), spec, serviceLedger, 1)).toEqual({
      status: 'found',
      resources: [
        {
          kind: 'tls_subscription',
          resourceId: SUB,
          ownership: 'adopted',
          meta: { hostname: HOST },
        },
      ],
    });
  });

  test('several subscriptions covering the hostname are ambiguous, never the first one', async () => {
    await serve((c) =>
      c.method === 'GET' && c.path === '/tls/subscriptions'
        ? subscriptionsDoc([
            { id: 'sub-other', domains: [HOST, 'someone-else.example.org'] },
            { id: SUB, domains: [HOST] },
          ])
        : defaultReply(c),
    );
    const res = await fastlyProvider.discover(cfg, tlsStep(), spec, serviceLedger, 1);
    expect(res.status).toBe('ambiguous');
    expect(res.status === 'ambiguous' && res.candidates.map((x) => x.resourceId)).toEqual([
      'sub-other',
      SUB,
    ]);
    // Not proven ours: a destroy never deletes a certificate it recorded this way.
    const ledger = apply({ steps: [], resources: [] }, tlsStep(), {
      status: 'done',
      resources: res.status === 'ambiguous' ? res.candidates : [],
    });
    expect(fastlyProvider.planDestroy(cfg, ledger)).toEqual([]);
  });

  test('a subscription whose CA or TLS configuration is not the frozen one is ambiguous', async () => {
    // Same hostname, another certificate authority: somebody else's.
    await serve((c) =>
      c.method === 'GET' && c.path === '/tls/subscriptions'
        ? subscriptionsDoc([{ id: 'sub-foreign', domains: [HOST], ca: 'lets-encrypt' }])
        : defaultReply(c),
    );
    expect(await fastlyProvider.discover(cfg, tlsStep(), spec, serviceLedger, 1)).toMatchObject({
      status: 'ambiguous',
      candidates: [{ resourceId: 'sub-foreign' }],
    });
    // With a TLS configuration in the intent, the configuration must match too.
    const pinned = { ...cfg, tlsConfigurationId: 'tls-1' };
    await serve((c) =>
      c.method === 'GET' && c.path === '/tls/subscriptions'
        ? subscriptionsDoc([{ id: SUB, domains: [HOST], configuration: 'tls-other' }])
        : defaultReply(c),
    );
    expect(await fastlyProvider.discover(pinned, tlsStep(), spec, serviceLedger, 1)).toMatchObject({
      status: 'ambiguous',
    });
    await serve((c) =>
      c.method === 'GET' && c.path === '/tls/subscriptions'
        ? subscriptionsDoc([{ id: SUB, domains: [HOST], configuration: 'tls-1' }])
        : defaultReply(c),
    );
    expect(await fastlyProvider.discover(pinned, tlsStep(), spec, serviceLedger, 1)).toMatchObject({
      status: 'found',
    });
  });

  test('a listing that covers only OTHER hostnames proves this subscription absent', async () => {
    await serve((c) =>
      c.method === 'GET' && c.path === '/tls/subscriptions'
        ? subscriptionsDoc([{ id: 'sub-other', domains: ['someone-else.example.org'] }])
        : defaultReply(c),
    );
    expect(await fastlyProvider.discover(cfg, tlsStep(), spec, serviceLedger, 1)).toEqual({
      status: 'confirmed_absent',
    });
  });

  test('a DNS record with a foreign comment is ambiguous, never adopted, never deleted', async () => {
    await serve();
    const dns = fakeDns([
      {
        id: 'foreign1',
        type: 'CNAME',
        name: HOST,
        content: 'someone-else.example.net',
        proxied: false,
        comment: 'managed by hand',
      },
    ]);
    const step = fastlyProvider
      .planProvision(cfg, spec, tpl)
      .find((s) => s.kind === 'create_dns_record')!;
    const res = await fastlyProvider.discover(cfg, step, spec, serviceLedger, 1);
    expect(res).toMatchObject({ status: 'ambiguous' });
    // Recorded for the operator as a candidate: a destroy of the parked edge
    // (the operator's "destroy, the ledger is trusted") leaves it alone.
    const candidates = (res as { candidates: ChildResource[] }).candidates;
    expect(candidates[0]!.meta).toMatchObject({ candidate: true, role: 'traffic' });
    const ledger = apply(serviceLedger, step, { status: 'done', resources: candidates });
    expect(fastlyProvider.planDestroy(cfg, ledger).map((r) => r.kind)).not.toContain('dns_record');
    const record = ledger.resources.find((r) => r.kind === 'dns_record')!;
    expect(await fastlyProvider.runDestroy(cfg, record, ledger)).toEqual({
      status: 'confirmed_gone',
    });
    expect(await fastlyProvider.confirmDestroyed!(cfg, record, ledger)).toEqual({
      status: 'confirmed_gone',
    });
    expect(dns.deleted).toEqual([]);
  });

  test('our own DNS record is adopted by its comment marker', async () => {
    await serve();
    fakeDns([
      {
        id: 'rec9',
        type: 'CNAME',
        name: HOST,
        content: TRAFFIC_TARGET,
        proxied: false,
        comment: spec.name,
      },
    ]);
    const step = fastlyProvider
      .planProvision(cfg, spec, tpl)
      .find((s) => s.kind === 'create_dns_record')!;
    const res = await fastlyProvider.discover(cfg, step, spec, serviceLedger, 1);
    expect(res).toMatchObject({
      status: 'found',
      addresses: { hostname: HOST },
      resources: [{ kind: 'dns_record', resourceId: 'rec9', ownership: 'adopted' }],
    });
  });
});

// --- describe / inspect / inventory / credentials ----------------------------------------------

describe('fastly: live views', () => {
  test('active means the version is live, DNS checks out and the certificate is issued', async () => {
    await serve();
    fakeDns();
    const ledger = await provision();
    expect(await fastlyProvider.describe(cfg, ledger)).toEqual({
      state: 'active',
      addresses: { hostname: HOST },
      health: 'unknown',
      readiness: { dns: 'ready', certificate: 'ready' },
    });
  });

  test('a pending DNS check keeps the edge pending but still reports the hostname', async () => {
    await serve((c) =>
      c.path.endsWith('/check') ? ok('domain-check-pending.json') : defaultReply(c),
    );
    fakeDns();
    const ledger = await provision();
    const d = await fastlyProvider.describe(cfg, ledger);
    expect(d).toMatchObject({
      state: 'pending',
      addresses: { hostname: HOST },
      readiness: { dns: 'pending', certificate: 'ready' },
    });
  });

  test('a failed certificate is an error with a code', async () => {
    // Only the plain read reports failure; the challenge read still answers, so
    // provisioning gets as far as the DNS records.
    await serve((c) =>
      c.path === `/tls/subscriptions/${SUB}` && !c.query.include
        ? api('tls-subscription-failed.json')
        : defaultReply(c),
    );
    fakeDns();
    const ledger = await provision();
    expect(await fastlyProvider.describe(cfg, ledger)).toMatchObject({
      state: 'error',
      code: 'tls_failed',
      readiness: { certificate: 'failed' },
    });
  });

  test('a deleted service is gone', async () => {
    await serve((c) => (c.path === `/service/${SVC}/details` ? NOT_FOUND : defaultReply(c)));
    fakeDns();
    const ledger = await provision();
    expect(await fastlyProvider.describe(cfg, ledger)).toEqual({
      state: 'gone',
      addresses: {},
      health: 'unknown',
    });
  });

  test('inspect shows the service, its domains and its backends without any secret', async () => {
    await serve();
    fakeDns();
    const ledger = await provision();
    const res = await fastlyProvider.inspect(cfg, ledger);
    expect(res.summary).toMatchObject({
      status: 'active',
      addresses: { hostname: HOST },
      members: [{ address: ORIGIN, port: 443 }],
      listeners: [{ port: 443, protocol: 'https' }],
    });
    expect(JSON.stringify(res.raw)).not.toContain('SECRET_FASTLY_TOKEN');
    expect(JSON.stringify(res.raw)).toContain(SUB);
  });

  test('inventory lists every service with ALL its hostnames and the origin it fronts', async () => {
    await serve();
    const inv = await fastlyProvider.inventory(cfg);
    expect(inv.loadBalancers[0]).toEqual({
      id: SVC,
      name: 'fcp-relay-o1-deadbeef',
      status: 'active',
      addresses: { hostname: HOST },
      hostnames: [HOST],
      content: ORIGIN,
    });
    expect(inv.ips).toEqual([]);
  });

  test('credentials need the global scope, and the pricing plan is recorded', async () => {
    await serve();
    expect(await fastlyProvider.testCredentials(cfg)).toEqual({
      ok: true,
      detail: 'scope=global; pricing_plan=enterprise',
      // The zone has no CAA record at all: any certificate authority may issue.
      observed: { caa: 'no_records', caaIssuer: 'certainly.com', caaCertificate: 'per_host' },
    });
  });

  test('a narrow token is refused with token_scope', async () => {
    await serve((c) =>
      c.path === '/tokens/self' ? ok('token-self-narrow.json') : defaultReply(c),
    );
    expect(await fastlyProvider.testCredentials(cfg)).toMatchObject({
      ok: false,
      code: 'token_scope',
    });
  });

  test('the account form offers the TLS configurations, default one marked', async () => {
    await serve();
    expect(await fastlyProvider.discoverOptions!({ ...cfg })).toEqual({
      tlsConfigurations: [
        { id: 'TLSCONFIG01', label: 'Default TLS configuration (default)' },
        { id: 'TLSCONFIG02', label: 'Customer TLS configuration' },
      ],
    });
  });

  test('a failing discovery surfaces a code and the provider answer, never the token', async () => {
    await serve((c) =>
      c.path === '/tls/configurations'
        ? { status: 403, body: { msg: 'Forbidden', detail: `bad ${cfg.apiToken}` } }
        : defaultReply(c),
    );
    const res = await fastlyProvider.discoverOptions!({ ...cfg });
    expect(res.errors).toEqual({ tlsConfigurations: 'forbidden' });
    expect(res.errorDetails?.tlsConfigurations).toContain('Forbidden');
    expect(JSON.stringify(res)).not.toContain(cfg.apiToken);
  });
});

// --- destroy ----------------------------------------------------------------------------------

describe('fastly: destroy', () => {
  test('the order is traffic record, subscription, ACME record, version, service, children, product', async () => {
    await serve();
    fakeDns();
    const ledger = await provision();
    const keys = fastlyProvider.planDestroy(cfg, ledger).map(fastlyDestroyKey);
    expect(keys).toEqual([
      'dns_record:traffic',
      'tls_subscription',
      'dns_record:acme',
      'active_version',
      'service',
      'backend',
      'snippet',
      'domain',
      'ws_product',
    ]);
    expect(keys).toEqual(FASTLY_DESTROY_ORDER.filter((k) => keys.includes(k)));
  });

  test('a partially provisioned edge destroys only what the ledger recorded', async () => {
    const r = await serve();
    const dns = fakeDns();
    // Provisioning stopped after the domain: no product, no version, no TLS, no DNS.
    let ledger: Ledger = { steps: [], resources: [] };
    for (const step of fastlyProvider.planProvision(cfg, spec, tpl).slice(0, 4)) {
      ledger = apply(ledger, step, await fastlyProvider.runStep(cfg, step, spec, tpl, ledger));
    }
    const plan = fastlyProvider.planDestroy(cfg, ledger);
    expect(plan.map(fastlyDestroyKey)).toEqual(['service', 'backend', 'snippet', 'domain']);
    r.calls.length = 0;
    for (const resource of plan) await fastlyProvider.runDestroy(cfg, resource, ledger);
    expect(r.calls.map((c) => `${c.method} ${c.path}`)).toEqual([`DELETE /service/${SVC}`]);
    expect(dns.deleted).toEqual([]);
  });

  test('a full teardown deletes each owned resource once, and the product goes last', async () => {
    const r = await serve();
    const dns = fakeDns();
    const ledger = await provision();
    r.calls.length = 0;
    const outcomes: string[] = [];
    for (const resource of fastlyProvider.planDestroy(cfg, ledger)) {
      const out = await fastlyProvider.runDestroy(cfg, resource, ledger);
      outcomes.push(`${fastlyDestroyKey(resource)}=${out.status}`);
    }
    expect(outcomes).toEqual([
      'dns_record:traffic=delete_requested',
      'tls_subscription=delete_requested',
      'dns_record:acme=delete_requested',
      'active_version=delete_requested',
      'service=delete_requested',
      'backend=unresolved',
      'snippet=unresolved',
      'domain=unresolved',
      'ws_product=delete_requested',
    ]);
    expect(dns.deleted).toEqual(['rec2', 'rec1']);
    expect(r.calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      `DELETE /tls/subscriptions/${SUB}`,
      `GET /service/${SVC}/details`,
      `PUT /service/${SVC}/version/1/deactivate`,
      `DELETE /service/${SVC}`,
      `DELETE /enabled-products/v1/websockets/services/${SVC}`,
    ]);
    // The subscription delete must force, or an enabled domain blocks it.
    expect(r.calls[0].query).toEqual({ force: 'true' });
  });

  test('confirmation reads each resource back rather than trusting the delete', async () => {
    // Provision under the normal provider, then answer as a provider that has
    // actually deleted everything.
    let gone = false;
    await serve((c) => {
      if (!gone) return defaultReply(c);
      if (c.path === '/service/search') return NOT_FOUND;
      if (c.path === '/tls/subscriptions') return api('tls-subscriptions-empty.json');
      if (c.path === `/service/${SVC}/details`)
        return { status: 200, body: { id: SVC, active_version: null } };
      if (c.path.startsWith('/enabled-products/')) return NOT_FOUND;
      return NOT_FOUND;
    });
    const dns = fakeDns();
    const ledger = await provision();
    gone = true;
    dns.rows.length = 0;
    const seen: string[] = [];
    for (const resource of fastlyProvider.planDestroy(cfg, ledger)) {
      const out = await fastlyProvider.confirmDestroyed!(cfg, resource, ledger);
      seen.push(`${fastlyDestroyKey(resource)}=${out.status}`);
    }
    expect(seen.every((s) => s.endsWith('=confirmed_gone'))).toBe(true);
  });

  test('a resource that is still there is reported still_present, not gone', async () => {
    await serve();
    const dns = fakeDns();
    const ledger = await provision();
    const traffic = ledger.resources.find(
      (x) => x.kind === 'dns_record' && JSON.parse(x.meta!).role === 'traffic',
    )!;
    expect(dns.rows).toHaveLength(2);
    expect(await fastlyProvider.confirmDestroyed!(cfg, traffic, ledger)).toEqual({
      status: 'still_present',
    });
    const service = ledger.resources.find((x) => x.kind === 'service')!;
    expect(await fastlyProvider.confirmDestroyed!(cfg, service, ledger)).toEqual({
      status: 'still_present',
    });
  });

  test('a service that is readable but flagged deleted counts as gone', async () => {
    await serve((c) =>
      c.path === '/service/search'
        ? { status: 200, body: { id: SVC, name: spec.name, deleted_at: '2026-09-16T12:00:00Z' } }
        : defaultReply(c),
    );
    fakeDns();
    const ledger = await provision();
    const service = ledger.resources.find((x) => x.kind === 'service')!;
    expect(await fastlyProvider.confirmDestroyed!(cfg, service, ledger)).toEqual({
      status: 'confirmed_gone',
    });
  });
});

// --- shared teardown ---------------------------------------------------------------------------

/** An adopted edge: FCP owns one domain on a service somebody else also uses. */
function sharedLedger(): Ledger {
  return {
    steps: [],
    resources: [
      {
        stepId: 'service',
        kind: 'service',
        resourceId: SVC,
        ownership: 'adopted',
        deleteState: 'present',
        meta: JSON.stringify({ version: 4, activeVersion: 4, name: 'legacy front', shared: true }),
      },
      {
        stepId: 'domain',
        kind: 'domain',
        resourceId: HOST,
        ownership: 'adopted',
        deleteState: 'present',
      },
      {
        stepId: 'dns',
        kind: 'dns_record',
        resourceId: 'rec2',
        ownership: 'created',
        deleteState: 'present',
        meta: JSON.stringify({
          recordId: 'rec2',
          name: HOST,
          role: 'traffic',
          zoneId: 'z',
          dnsAccountId: 'dnsacct1',
        }),
      },
    ],
  };
}

/** `sharedLedger()` plus a TLS subscription with the given sharing marker. */
function sharedLedgerWithSubscription(subscriptionShared: boolean): Ledger {
  const ledger = sharedLedger();
  ledger.resources.push({
    stepId: 'tls',
    kind: 'tls_subscription',
    resourceId: SUB,
    ownership: 'adopted',
    deleteState: 'present',
    meta: JSON.stringify({ hostname: HOST, shared: subscriptionShared }),
  });
  return ledger;
}

describe('fastly: a TLS subscription on a shared service', () => {
  test('a subscription dedicated to OUR hostname is destroyed even though the service is shared', async () => {
    const ledger = sharedLedgerWithSubscription(false);
    // The certificate is not part of the service: leaving it behind would keep
    // renewing (and paying for) a certificate for a hostname nobody serves.
    expect(fastlyProvider.planDestroy(cfg, ledger).map(fastlyDestroyKey)).toEqual([
      'dns_record:traffic',
      'tls_subscription',
      'domain',
    ]);
    const r = await serve();
    fakeDns();
    const sub = ledger.resources.find((x) => x.kind === 'tls_subscription')!;
    expect(await fastlyProvider.runDestroy(cfg, sub, ledger)).toEqual({
      status: 'delete_requested',
    });
    expect(r.calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      `DELETE /tls/subscriptions/${SUB}`,
    ]);
  });

  test('a subscription that also covers other hostnames is left alone', async () => {
    const ledger = sharedLedgerWithSubscription(true);
    expect(fastlyProvider.planDestroy(cfg, ledger).map(fastlyDestroyKey)).toEqual([
      'dns_record:traffic',
      'domain',
    ]);
    const r = await serve();
    fakeDns();
    const sub = ledger.resources.find((x) => x.kind === 'tls_subscription')!;
    // Deleting it would drop somebody else's certificate.
    expect(await fastlyProvider.runDestroy(cfg, sub, ledger)).toEqual({
      status: 'confirmed_gone',
    });
    expect(r.calls).toEqual([]);
  });
});

describe('fastly: shared teardown of an adopted domain', () => {
  test('a shared service is never deleted: only the domain and our DNS records are planned', async () => {
    const ledger = sharedLedger();
    expect(fastlyProvider.planDestroy(cfg, ledger).map(fastlyDestroyKey)).toEqual([
      'dns_record:traffic',
      'domain',
    ]);
    await serve();
    fakeDns([
      {
        id: 'rec2',
        type: 'CNAME',
        name: HOST,
        content: TRAFFIC_TARGET,
        proxied: false,
        comment: spec.name,
      },
    ]);
    const domain = ledger.resources.find((x) => x.kind === 'domain')!;
    // The domain is removed by the persisted workflow below, not by runDestroy.
    expect(await fastlyProvider.runDestroy(cfg, domain, ledger)).toEqual({ status: 'unresolved' });
    const service: LedgerResource = ledger.resources[0];
    expect(await fastlyProvider.runDestroy(cfg, service, ledger)).toEqual({
      status: 'confirmed_gone',
    });
  });

  test('the happy path walks clone, remove, validate, activate, confirm', async () => {
    let active = 4;
    let domains = [HOST, 'kept.example.org'];
    const r = await serve((c) => {
      if (c.path === `/service/${SVC}/version`)
        return {
          status: 200,
          body: [
            { number: 4, active: active === 4, locked: true, created_at: '2026-09-16T09:00:00Z' },
            ...(active === 5
              ? [{ number: 5, active: true, locked: true, comment: 'fcp:legacy front:op1' }]
              : []),
          ],
        };
      if (/\/version\/4\/clone$/.test(c.path)) return { status: 200, body: { number: 5 } };
      if (c.method === 'PUT' && /\/version\/5$/.test(c.path))
        return { status: 200, body: { number: 5 } };
      if (c.method === 'DELETE' && c.path.endsWith(`/domain/${HOST}`)) {
        domains = domains.filter((d) => d !== HOST);
        return { status: 200, body: { status: 'ok' } };
      }
      if (/\/version\/5\/validate$/.test(c.path)) return ok('version-validate-ok.json');
      if (/\/version\/5\/activate$/.test(c.path)) {
        active = 5;
        return { status: 200, body: { number: 5, active: true } };
      }
      if (c.path === `/service/${SVC}/details`)
        return { status: 200, body: { id: SVC, active_version: { number: active } } };
      if (c.method === 'GET' && /\/version\/5\/domain$/.test(c.path))
        return { status: 200, body: domains.map((d) => ({ name: d })) };
      return defaultReply(c);
    });

    let state = planSharedTeardown(sharedLedger(), 'op1', Date.parse('2026-09-16T10:00:00Z'))!;
    expect(state).toMatchObject({ phase: 'clone', fromVersion: 4, marker: 'fcp:legacy front:op1' });
    const phases: string[] = [];
    for (let i = 0; i < 6 && state.phase !== 'done'; i++) {
      state = await sharedTeardownStep(cfg, state);
      phases.push(state.phase);
    }
    expect(phases).toEqual(['remove_domain', 'validate', 'activate', 'confirm', 'done']);
    expect(state.workVersion).toBe(5);
    // The clone is marked immediately so a lost response is recognisable.
    expect(
      r.calls.filter((c) => c.method === 'PUT' && /\/version\/5$/.test(c.path))[0].body,
    ).toEqual({
      comment: 'fcp:legacy front:op1',
    });
    expect(domains).toEqual(['kept.example.org']);
  });

  test('a lost clone response is recovered by our marker, and never cloned twice', async () => {
    const r = await serve((c) => {
      if (c.path === `/service/${SVC}/version`)
        return {
          status: 200,
          body: [
            { number: 4, active: true, locked: true, created_at: '2026-09-16T09:00:00Z' },
            {
              number: 5,
              active: false,
              locked: false,
              comment: 'fcp:legacy front:op1',
              created_at: '2026-09-16T10:00:05Z',
            },
          ],
        };
      return defaultReply(c);
    });
    const state = planSharedTeardown(sharedLedger(), 'op1', Date.parse('2026-09-16T10:00:00Z'))!;
    const next = await sharedTeardownStep(cfg, state);
    expect(next).toMatchObject({ phase: 'remove_domain', workVersion: 5 });
    expect(r.calls.some((c) => c.path.endsWith('/clone'))).toBe(false);
  });

  test('an unmarked draft made inside the op window is ambiguous, never adopted or re-cloned', async () => {
    const r = await serve((c) => {
      if (c.path === `/service/${SVC}/version`)
        return {
          status: 200,
          body: [
            { number: 4, active: true, locked: true, created_at: '2026-09-16T09:00:00Z' },
            {
              number: 5,
              active: false,
              locked: false,
              comment: 'operator experiment',
              created_at: '2026-09-16T10:00:05Z',
            },
          ],
        };
      return defaultReply(c);
    });
    const state = planSharedTeardown(sharedLedger(), 'op1', Date.parse('2026-09-16T10:00:00Z'))!;
    expect(await sharedTeardownStep(cfg, state)).toMatchObject({
      phase: 'needs_operator',
      code: 'shared_teardown_ambiguous',
    });
    expect(r.calls.some((c) => c.path.endsWith('/clone'))).toBe(false);
  });

  test('a draft from BEFORE the op window is somebody else`s and does not block the clone', async () => {
    const r = await serve((c) => {
      if (c.path === `/service/${SVC}/version`)
        return {
          status: 200,
          body: [
            { number: 4, active: true, locked: true, created_at: '2026-09-16T09:00:00Z' },
            {
              number: 5,
              active: false,
              locked: false,
              comment: 'old draft',
              created_at: '2026-09-15T00:00:00Z',
            },
          ],
        };
      if (/\/version\/4\/clone$/.test(c.path)) return { status: 200, body: { number: 6 } };
      if (c.method === 'PUT' && /\/version\/6$/.test(c.path))
        return { status: 200, body: { number: 6 } };
      return defaultReply(c);
    });
    const state = planSharedTeardown(sharedLedger(), 'op1', Date.parse('2026-09-16T10:00:00Z'))!;
    expect(await sharedTeardownStep(cfg, state)).toMatchObject({
      phase: 'remove_domain',
      workVersion: 6,
    });
    expect(r.calls.filter((c) => c.path.endsWith('/clone'))).toHaveLength(1);
  });

  test('activation refuses when the active version drifted away from the clone source', async () => {
    const r = await serve((c) =>
      c.path === `/service/${SVC}/details`
        ? { status: 200, body: { id: SVC, active_version: { number: 9 } } }
        : defaultReply(c),
    );
    const state: SharedTeardownState = {
      phase: 'activate',
      serviceId: SVC,
      hostname: HOST,
      fromVersion: 4,
      workVersion: 5,
      marker: 'fcp:legacy front:op1',
      opWindowStart: 0,
    };
    const err = await sharedTeardownStep(cfg, state).catch((e) => e);
    expect(err.meta.code).toBe('service_version_drift');
    expect(errorBlob(err)).not.toContain(HOST);
    expect(r.calls.some((c) => c.path.endsWith('/activate'))).toBe(false);
  });

  test('a lost activation response is confirmed by reading the service, not by activating again', async () => {
    const r = await serve((c) => {
      if (c.path === `/service/${SVC}/details`)
        return { status: 200, body: { id: SVC, active_version: { number: 5 } } };
      if (c.method === 'GET' && /\/version\/5\/domain$/.test(c.path))
        return { status: 200, body: [{ name: 'kept.example.org' }] };
      return defaultReply(c);
    });
    let state: SharedTeardownState = {
      phase: 'activate',
      serviceId: SVC,
      hostname: HOST,
      fromVersion: 4,
      workVersion: 5,
      marker: 'fcp:legacy front:op1',
      opWindowStart: 0,
    };
    state = await sharedTeardownStep(cfg, state);
    expect(state.phase).toBe('confirm');
    state = await sharedTeardownStep(cfg, state);
    expect(state.phase).toBe('done');
    expect(r.calls.some((c) => c.path.endsWith('/activate'))).toBe(false);
  });

  test('a domain still present on the activated version needs an operator', async () => {
    await serve((c) => {
      if (c.path === `/service/${SVC}/details`)
        return { status: 200, body: { id: SVC, active_version: { number: 5 } } };
      if (c.method === 'GET' && /\/version\/5\/domain$/.test(c.path))
        return { status: 200, body: [{ name: HOST }] };
      return defaultReply(c);
    });
    const state: SharedTeardownState = {
      phase: 'confirm',
      serviceId: SVC,
      hostname: HOST,
      fromVersion: 4,
      workVersion: 5,
      marker: 'm',
      opWindowStart: 0,
    };
    expect(await sharedTeardownStep(cfg, state)).toMatchObject({
      phase: 'needs_operator',
      code: 'shared_teardown_incomplete',
    });
  });

  test('an exclusively owned service has no shared teardown', async () => {
    await serve();
    fakeDns();
    const ledger = await provision();
    expect(planSharedTeardown(ledger, 'op1')).toBeNull();
  });
});

// --- adoption -------------------------------------------------------------------------------

describe('fastly: inspectForAdoption', () => {
  /** The DNS rows an already-running front has in the referenced zone. */
  function seededDns() {
    return fakeDns([
      {
        id: 'rec-traffic',
        type: 'CNAME',
        name: HOST,
        content: TRAFFIC_TARGET,
        proxied: false,
        comment: 'operator-managed',
      },
      {
        id: 'rec-acme',
        type: 'CNAME',
        name: acmeChallengeName(HOST),
        content: ACME_TARGET,
        proxied: false,
        comment: 'operator-managed',
      },
    ]);
  }

  test('an exclusively owned service is described with its real ids, version and origin', async () => {
    const r = await serve();
    seededDns();
    const seen = await fastlyProvider.inspectForAdoption!(cfg, SVC, HOST);
    expect(seen.resources).toEqual([
      {
        kind: 'service',
        resourceId: SVC,
        ownership: 'adopted',
        meta: { name: 'fcp-relay-o1-deadbeef', version: 1, activeVersion: 1, shared: false },
      },
      { kind: 'domain', resourceId: HOST, ownership: 'adopted' },
      {
        kind: 'tls_subscription',
        resourceId: SUB,
        ownership: 'adopted',
        meta: { hostname: HOST, shared: false },
      },
      { kind: 'ws_product', resourceId: SVC, ownership: 'adopted' },
      {
        kind: 'dns_record',
        resourceId: 'rec-traffic',
        ownership: 'adopted',
        meta: {
          dnsAccountId: 'dnsacct1',
          zoneId: cfg.dns!.zoneId,
          recordId: 'rec-traffic',
          name: HOST,
          role: 'traffic',
        },
      },
      {
        kind: 'dns_record',
        resourceId: 'rec-acme',
        ownership: 'adopted',
        meta: {
          dnsAccountId: 'dnsacct1',
          zoneId: cfg.dns!.zoneId,
          recordId: 'rec-acme',
          name: acmeChallengeName(HOST),
          role: 'acme',
        },
      },
    ]);
    expect(seen).toMatchObject({
      hostname: HOST,
      hostnames: [HOST],
      shared: false,
      content: ORIGIN,
    });
    // Everything is read from the ACTIVE version, and nothing is written.
    expect(r.calls.every((c) => c.method === 'GET')).toBe(true);
    expect(r.calls.some((c) => c.path === `/service/${SVC}/version/1/domain`)).toBe(true);
    expect(r.calls.some((c) => c.query['filter[tls_domains.id]'] === HOST)).toBe(true);
  });

  test('a service serving other hostnames is SHARED (FCP may never delete it)', async () => {
    await serve((c) =>
      c.method === 'GET' && /\/version\/1\/domain$/.test(c.path)
        ? { status: 200, body: [{ name: HOST }, { name: 'shop.example.org' }] }
        : defaultReply(c),
    );
    seededDns();
    const seen = await fastlyProvider.inspectForAdoption!(cfg, SVC, HOST);
    expect(seen.shared).toBe(true);
    expect(seen.hostnames).toEqual([HOST, 'shop.example.org']);
    expect(seen.resources[0].meta).toMatchObject({ shared: true });
  });

  test('a certificate covering other domains marks the subscription (and the edge) shared', async () => {
    await serve((c) =>
      c.method === 'GET' && c.path === '/tls/subscriptions'
        ? {
            status: 200,
            contentType: 'application/vnd.api+json',
            body: {
              data: [
                {
                  id: SUB,
                  type: 'tls_subscription',
                  attributes: { state: 'issued' },
                  relationships: {
                    tls_domains: {
                      data: [
                        { id: HOST, type: 'tls_domain' },
                        { id: 'shop.example.org', type: 'tls_domain' },
                      ],
                    },
                  },
                },
              ],
            },
          }
        : defaultReply(c),
    );
    seededDns();
    const seen = await fastlyProvider.inspectForAdoption!(cfg, SVC, HOST);
    // One domain on the service, but a certificate somebody else also depends on.
    expect(seen.hostnames).toEqual([HOST]);
    expect(seen.shared).toBe(true);
    const sub = seen.resources.find((x) => x.kind === 'tls_subscription')!;
    expect(sub.meta).toEqual({ hostname: HOST, shared: true });
  });

  test('no subscription, or several, leaves the certificate unowned rather than guessed', async () => {
    for (const body of [
      { data: [] },
      {
        data: [
          {
            id: SUB,
            type: 'tls_subscription',
            relationships: { tls_domains: { data: [{ id: HOST, type: 'tls_domain' }] } },
          },
          {
            id: 'C1other',
            type: 'tls_subscription',
            relationships: { tls_domains: { data: [{ id: HOST, type: 'tls_domain' }] } },
          },
        ],
      },
    ]) {
      await serve((c) =>
        c.method === 'GET' && c.path === '/tls/subscriptions'
          ? { status: 200, contentType: 'application/vnd.api+json', body }
          : defaultReply(c),
      );
      seededDns();
      const seen = await fastlyProvider.inspectForAdoption!(cfg, SVC, HOST);
      expect(seen.resources.map((x) => x.kind)).not.toContain('tls_subscription');
      await rec!.close();
      rec = undefined;
    }
  });

  test('the WebSockets product is recorded only when it is already on', async () => {
    await serve((c) =>
      c.path === `/enabled-products/v1/websockets/services/${SVC}` ? NOT_FOUND : defaultReply(c),
    );
    seededDns();
    const seen = await fastlyProvider.inspectForAdoption!(cfg, SVC, HOST);
    expect(seen.resources.map((x) => x.kind)).not.toContain('ws_product');

    // A server fault is not an answer about the product: it travels.
    await rec!.close();
    rec = undefined;
    await serve((c) =>
      c.path === `/enabled-products/v1/websockets/services/${SVC}`
        ? { status: 503, body: { msg: 'Service Unavailable' } }
        : defaultReply(c),
    );
    seededDns();
    await expect(fastlyProvider.inspectForAdoption!(cfg, SVC, HOST)).rejects.toThrow();
  });

  test('a hostname the service does not serve, and a service with no active version, are refused', async () => {
    await serve((c) =>
      c.method === 'GET' && /\/version\/1\/domain$/.test(c.path)
        ? { status: 200, body: [{ name: 'kept.example.org' }] }
        : defaultReply(c),
    );
    seededDns();
    const mismatch = await fastlyProvider.inspectForAdoption!(cfg, SVC, HOST).catch(
      (e: unknown) => e,
    );
    expect((mismatch as { meta: { code?: string } }).meta.code).toBe('hostname_mismatch');
    // ...and the refusal quotes neither the hostname nor the origin nor a token.
    const blob = errorBlob(mismatch);
    for (const secret of ['SECRET_FASTLY_TOKEN', 'SECRET_CF_TOKEN', HOST, ORIGIN])
      expect(blob).not.toContain(secret);

    await rec!.close();
    rec = undefined;
    await serve((c) =>
      c.path === `/service/${SVC}/details`
        ? { status: 200, body: { id: SVC, name: 'draft only', versions: [{ number: 1 }] } }
        : defaultReply(c),
    );
    seededDns();
    const inactive = await fastlyProvider.inspectForAdoption!(cfg, SVC, HOST).catch(
      (e: unknown) => e,
    );
    expect((inactive as { meta: { code?: string } }).meta.code).toBe('service_not_active');
  });

  test('the DNS records are optional: a front whose zone has none is still adoptable', async () => {
    await serve();
    fakeDns();
    const seen = await fastlyProvider.inspectForAdoption!(cfg, SVC, HOST);
    expect(seen.resources.map((x) => x.kind)).toEqual([
      'service',
      'domain',
      'tls_subscription',
      'ws_product',
    ]);
  });
});

describe('fastly: the shared-teardown driver', () => {
  test('the provider exposes the same workflow as a generic driver', async () => {
    const driver = fastlyProvider.sharedTeardown!;
    expect(driver.plan(sharedLedger(), 'op1', Date.parse('2026-09-16T10:00:00Z'))).toMatchObject({
      phase: 'clone',
      serviceId: SVC,
      hostname: HOST,
      fromVersion: 4,
      marker: 'fcp:legacy front:op1',
    });

    await serve();
    fakeDns();
    // An exclusively owned service has no shared teardown at all.
    expect(driver.plan(await provision(), 'op1')).toBeNull();
  });

  test('the driver advances one phase per call and leaves a finished state alone', async () => {
    const driver = fastlyProvider.sharedTeardown!;
    await serve((c) => {
      if (c.path === `/service/${SVC}/version`)
        return {
          status: 200,
          body: [{ number: 4, active: true, locked: true, created_at: '2026-09-16T09:00:00Z' }],
        };
      if (/\/version\/4\/clone$/.test(c.path)) return { status: 200, body: { number: 5 } };
      return defaultReply(c);
    });
    let state = driver.plan(sharedLedger(), 'op1', Date.parse('2026-09-16T10:00:00Z'))!;
    state = await driver.step(cfg, state);
    // The extra, adapter-specific fields survive the round trip through the
    // generic state the caller persists.
    expect(state).toMatchObject({
      phase: 'remove_domain',
      workVersion: 5,
      hostname: HOST,
      fromVersion: 4,
      marker: 'fcp:legacy front:op1',
    });

    const done = { ...state, phase: 'done' };
    expect(await driver.step(cfg, done)).toEqual(done);
    // A phase nobody wrote is parked for an operator, never re-cloned.
    expect(await driver.step(cfg, { ...state, phase: 'nonsense' })).toMatchObject({
      phase: 'needs_operator',
    });
  });
});

// --- error hygiene -------------------------------------------------------------------------------

describe('fastly: nothing provider-shaped reaches an error', () => {
  test('a 500 on an allocating call is thrown once and quotes no secret, host or origin', async () => {
    const r = await serve(() => ({
      status: 500,
      body: {
        msg: 'Internal Server Error',
        detail: `service for ${HOST} backed by ${ORIGIN} failed`,
        title: 'Internal Server Error',
      },
    }));
    const step = fastlyProvider.planProvision(cfg, spec, tpl)[0];
    const err = await fastlyProvider
      .runStep(cfg, step, spec, tpl, { steps: [], resources: [] })
      .catch((e) => e);
    expect(err.meta).toMatchObject({ provider: 'fastly', status: 500, retryable: true });
    // Exactly one request: retrying an allocating POST is discovery's job.
    expect(r.calls).toHaveLength(1);
    const blob = errorBlob(err);
    for (const secret of ['SECRET_FASTLY_TOKEN', 'SECRET_CF_TOKEN', HOST, ORIGIN, 'failed'])
      expect(blob).not.toContain(secret);
  });

  test('a DNS step without a resolved DNS account refuses instead of guessing a zone', async () => {
    await serve();
    __setFastlyDnsClientFactory(null);
    const step = fastlyProvider
      .planProvision(cfg, spec, tpl)
      .find((s) => s.kind === 'create_dns_record')!;
    const { dns: _dropped, ...noDns } = cfg;
    const err = await fastlyProvider
      .runStep(noDns as FastlyConfig, step, spec, tpl, { steps: [], resources: [] })
      .catch((e) => e);
    expect(err.meta.code).toBe('dns_account_missing');
  });
});

// --- the CAA preflight of the credential test -----------------------------------------------

describe('fastly: the credential test checks the zone lets the CA issue', () => {
  const issue = (value: string): CaaRecord => ({ flags: 0, tag: 'issue', value });
  const issuewild = (value: string): CaaRecord => ({ flags: 0, tag: 'issuewild', value });
  /** A zone's CAA records by name, and every name the walk asked for. */
  function caaZone(table: Record<string, CaaRecord[]>): string[] {
    const asked: string[] = [];
    __setFastlyCaaLookup(async (name) => {
      asked.push(name);
      return table[name] ?? [];
    });
    return asked;
  }

  test('records that name only another CA refuse the test with a code, naming the CA to allow', async () => {
    await serve();
    caaZone({ 'example.org': [issue('letsencrypt.org')] });
    const res = await fastlyProvider.testCredentials(cfg);
    expect(res).toEqual({
      ok: false,
      code: 'caa_forbids_ca',
      detail: 'the CAA records at example.org do not allow certainly.com',
      observed: {
        caa: 'forbids',
        caaIssuer: 'certainly.com',
        caaCertificate: 'per_host',
        caaAt: 'example.org',
      },
    });
    expect(JSON.stringify(res)).not.toContain(cfg.apiToken);
  });

  test('a record allowing the CA passes, and says where it was decided', async () => {
    await serve();
    caaZone({ 'example.org': [issue('certainly.com')] });
    expect(await fastlyProvider.testCredentials(cfg)).toMatchObject({
      ok: true,
      observed: { caa: 'allows', caaAt: 'example.org' },
    });
  });

  test('records above the zone decide when the zone has none (the CA climbs too)', async () => {
    await serve();
    const asked = caaZone({ 'example.org': [issue(';')] });
    const sub = { ...cfg, dns: { ...cfg.dns!, zoneName: 'fronts.example.org' } };
    expect(await fastlyProvider.testCredentials(sub)).toMatchObject({
      ok: false,
      code: 'caa_forbids_ca',
    });
    expect(asked).toEqual([
      '_fcp-caa-check.fronts.example.org',
      'fronts.example.org',
      'example.org',
    ]);
  });

  test('a zone wildcard that answers for a new front decides, as the CA would see it', async () => {
    await serve();
    // `*.example.org CNAME elsewhere`: the resolver follows it for any new
    // name, so the probe label gets the CNAME target's CAA records.
    const asked = caaZone({ '_fcp-caa-check.example.org': [issue('letsencrypt.org')] });
    expect(await fastlyProvider.testCredentials(cfg)).toMatchObject({
      ok: false,
      code: 'caa_forbids_ca',
      observed: { caaAt: '_fcp-caa-check.example.org' },
    });
    expect(asked).toEqual(['_fcp-caa-check.example.org']);
  });

  test('a record naming the CA but binding an account, or another validation method, refuses', async () => {
    await serve();
    caaZone({
      'example.org': [issue('certainly.com; accounturi=https://acme.example.net/acct/1')],
    });
    expect(await fastlyProvider.testCredentials(cfg)).toMatchObject({ code: 'caa_forbids_ca' });
    caaZone({ 'example.org': [issue('certainly.com; validationmethods=http-01')] });
    expect(await fastlyProvider.testCredentials(cfg)).toMatchObject({ code: 'caa_forbids_ca' });
    caaZone({ 'example.org': [issue('certainly.com; validationmethods=http-01,dns-01')] });
    expect(await fastlyProvider.testCredentials(cfg)).toMatchObject({ ok: true });
  });

  test('a wildcard account is checked against issuewild', async () => {
    await serve();
    caaZone({ 'example.org': [issue('certainly.com'), issuewild('letsencrypt.org')] });
    const wild = { ...cfg, certificateScope: 'wildcard' as const };
    expect(await fastlyProvider.testCredentials(wild)).toMatchObject({
      ok: false,
      code: 'caa_forbids_ca',
      detail:
        'the CAA records at example.org do not allow certainly.com for a wildcard (issuewild)',
      observed: { caaCertificate: 'wildcard' },
    });
    // The same zone lets the CA issue one certificate per front.
    expect(await fastlyProvider.testCredentials(cfg)).toMatchObject({ ok: true });
  });

  test('a lookup that fails is recorded as unchecked and never refuses', async () => {
    await serve();
    __setFastlyCaaLookup(async () => {
      throw new Error('SERVFAIL');
    });
    expect(await fastlyProvider.testCredentials(cfg)).toMatchObject({
      ok: true,
      observed: { caa: 'unchecked' },
    });
  });
});

// --- what a waiting certificate reports ----------------------------------------------------

describe('fastly: a waiting certificate says what holds it up', () => {
  const awaitStep = () =>
    fastlyProvider.planProvision(cfg, spec, tpl).find((s) => s.kind === 'await_tls')!;
  const subLedger = (startedAt?: number): Ledger => ({
    steps: [
      {
        stepId: 'await-tls',
        kind: 'await_tls',
        resourceName: HOST,
        state: 'requested',
        attempt: 1,
        ...(startedAt !== undefined ? { startedAt } : {}),
      },
    ],
    resources: [
      {
        stepId: 'tls',
        kind: 'tls_subscription',
        resourceId: SUB,
        ownership: 'created',
        deleteState: 'present',
        meta: JSON.stringify({ hostname: HOST }),
      },
    ],
  });
  const acmeRecord = (content = ACME_TARGET): DnsRecord => ({
    id: 'acme1',
    type: 'CNAME',
    name: acmeChallengeName(HOST),
    content,
    proxied: false,
    comment: spec.name,
  });
  /** An authorization document carrying these warnings / this state. */
  const authDoc = (warnings: unknown[], state = 'pending') => ({
    data: { id: SUB, type: 'tls_subscription', attributes: { state: 'processing' } },
    included: [{ id: 'A1', type: 'tls_authorization', attributes: { state, warnings } }],
  });

  test('warnings map to a fixed code by their type, and their words are never read', () => {
    const words = 'records at example.org name only another CA';
    expect(tlsAuthorizationCode(authDoc([{ type: 'CAA', instructions: words }]))).toBe(
      'tls_caa_conflict',
    );
    expect(
      tlsAuthorizationCode(authDoc([{ type: 'conflicting-records', instructions: words }])),
    ).toBe('tls_challenge_conflict');
    expect(tlsAuthorizationCode(authDoc([], 'failed'))).toBe('tls_authorization_failed');
    // Most specific first.
    expect(
      tlsAuthorizationCode(authDoc([{ type: 'other' }, { type: 'caa_record' }], 'failed')),
    ).toBe('tls_caa_conflict');
    // An unnamed warning only when the caller asks for one.
    expect(tlsAuthorizationCode(authDoc([{ type: 'dns' }]))).toBeUndefined();
    expect(tlsAuthorizationCode(authDoc([{ type: 'dns' }]), { generic: true })).toBe(
      'tls_authorization_warning',
    );
    expect(tlsAuthorizationCode({ data: {} })).toBeUndefined();
  });

  test('a CAA conflict is reported while the poll waits, as a code only', async () => {
    await serve((c) =>
      c.path === `/tls/subscriptions/${SUB}`
        ? api('tls-subscription-caa-warning.json')
        : defaultReply(c),
    );
    fakeDns([acmeRecord()]);
    const out = await fastlyProvider.pollStep!(cfg, awaitStep(), SUB, subLedger());
    expect(out).toEqual({
      status: 'requested',
      opRef: SUB,
      resources: [],
      code: 'tls_caa_conflict',
    });
    expect(JSON.stringify(out)).not.toContain('example.org');
    expect(rec!.calls[0].query).toEqual({ include: 'tls_authorizations' });
  });

  test('a validation record that is missing, or holds another value, is reported', async () => {
    await serve();
    fakeDns();
    expect(await fastlyProvider.pollStep!(cfg, awaitStep(), SUB, subLedger())).toMatchObject({
      status: 'requested',
      code: 'tls_challenge_missing',
    });
    fakeDns([acmeRecord('elsewhere.example.net')]);
    expect(await fastlyProvider.pollStep!(cfg, awaitStep(), SUB, subLedger())).toMatchObject({
      code: 'tls_challenge_missing',
    });
    fakeDns([acmeRecord(`${ACME_TARGET.toUpperCase()}.`)]);
    expect(await fastlyProvider.pollStep!(cfg, awaitStep(), SUB, subLedger())).toEqual({
      status: 'requested',
      opRef: SUB,
      resources: [],
    });
  });

  test('a DNS API that does not answer says nothing about the record', async () => {
    await serve();
    const dns = fakeDns();
    dns.findRecordsByName = async () => {
      throw new Error('dns api down');
    };
    expect(await fastlyProvider.pollStep!(cfg, awaitStep(), SUB, subLedger())).toEqual({
      status: 'requested',
      opRef: SUB,
      resources: [],
    });
  });

  test('an unnamed warning is reported only once the wait is long', async () => {
    const doc = authDoc([{ type: 'something_new', instructions: 'see example.org' }]);
    await serve((c) =>
      c.path === `/tls/subscriptions/${SUB}`
        ? { status: 200, body: doc, contentType: 'application/vnd.api+json' }
        : defaultReply(c),
    );
    fakeDns([acmeRecord()]);
    const now = Date.now();
    expect(
      await fastlyProvider.pollStep!(cfg, awaitStep(), SUB, subLedger(now - 60_000)),
    ).not.toHaveProperty('code');
    expect(
      await fastlyProvider.pollStep!(cfg, awaitStep(), SUB, subLedger(now - TLS_WARNING_GRACE_MS)),
    ).toMatchObject({ code: 'tls_authorization_warning' });
  });
});

// --- versionless domains ---------------------------------------------------------------------

describe('fastly: a new edge gets a versionless domain', () => {
  const cfgV: FastlyConfig = { ...cfg, domainModel: 'versionless' };

  async function provisionV(): Promise<Ledger> {
    let ledger: Ledger = { steps: [], resources: [] };
    for (const step of fastlyProvider.planProvision(cfgV, spec, tpl)) {
      const out = await fastlyProvider.runStep(cfgV, step, spec, tpl, ledger);
      ledger = apply(ledger, step, out);
      if (out.status === 'requested')
        ledger = apply(ledger, step, await fastlyProvider.pollStep!(cfgV, step, out.opRef, ledger));
    }
    return ledger;
  }

  test('the domain is created on its own, linked to the service, never on a version', async () => {
    const r = await serve();
    fakeDns();
    const ledger = await provisionV();
    expect(ledger.resources.map((x) => x.kind)).toEqual([
      'service',
      'backend',
      'snippet',
      'versionless_domain',
      'ws_product',
      'active_version',
      'tls_subscription',
      'dns_record',
      'dns_record',
    ]);
    const domain = ledger.resources.find((x) => x.kind === 'versionless_domain')!;
    expect(domain.resourceId).toBe(DM);
    expect(JSON.parse(domain.meta!)).toEqual({ fqdn: HOST, serviceId: SVC });
    const create = r.calls.find((c) => c.path === '/domain-management/v1/domains')!;
    expect(create.method).toBe('POST');
    expect(create.body).toEqual({ fqdn: HOST, service_id: SVC, description: spec.name });
    expect(r.calls.some((c) => /\/version\/\d+\/domain/.test(c.path))).toBe(false);
  });

  test('discovery finds it by its exact name, linked to THIS service only', async () => {
    const step = fastlyProvider
      .planProvision(cfgV, spec, tpl)
      .find((s) => s.kind === 'create_domain')!;
    const ledger = apply({ steps: [], resources: [] }, step, {
      status: 'done',
      resources: [{ kind: 'service', resourceId: SVC, ownership: 'created', meta: { version: 1 } }],
    });
    let listing = 'dm-domains-empty.json';
    const r = await serve((c) =>
      c.path === '/domain-management/v1/domains' ? ok(listing) : defaultReply(c),
    );
    expect(await fastlyProvider.discover(cfgV, step, spec, ledger, 1)).toEqual({
      status: 'confirmed_absent',
    });
    expect(r.calls[0].query).toMatchObject({ fqdn: HOST, fqdn_match: 'exact' });
    listing = 'dm-domains-list.json';
    expect(await fastlyProvider.discover(cfgV, step, spec, ledger, 1)).toMatchObject({
      status: 'found',
      resources: [{ kind: 'versionless_domain', resourceId: DM }],
    });
    // The same name on another service is somebody else's.
    const other = apply({ steps: [], resources: [] }, step, {
      status: 'done',
      resources: [
        { kind: 'service', resourceId: 'OTHERSVC', ownership: 'created', meta: { version: 1 } },
      ],
    });
    expect(await fastlyProvider.discover(cfgV, step, spec, other, 1)).toMatchObject({
      status: 'ambiguous',
    });
  });

  test('its DNS readiness is the link and the traffic record, with no version check', async () => {
    let linkedTo = SVC;
    const r = await serve((c) =>
      c.path === `/domain-management/v1/domains/${DM}`
        ? {
            status: 200,
            body: { ...(fixture('dm-domain-create.json') as object), service_id: linkedTo },
          }
        : defaultReply(c),
    );
    const dns = fakeDns();
    const ledger = await provisionV();
    r.calls.length = 0;
    expect(await fastlyProvider.describe(cfgV, ledger)).toMatchObject({
      state: 'active',
      readiness: { dns: 'ready', certificate: 'ready' },
      addresses: { hostname: HOST },
    });
    expect(r.calls.some((c) => c.path.endsWith('/check'))).toBe(false);
    // The traffic record is read back: pointed elsewhere, or gone, is not ready.
    const traffic = dns.rows.find((x) => x.name === HOST)!;
    traffic.content = 'elsewhere.example.net';
    expect(await fastlyProvider.describe(cfgV, ledger)).toMatchObject({
      state: 'pending',
      readiness: { dns: 'pending' },
    });
    dns.rows.splice(dns.rows.indexOf(traffic), 1);
    expect(await fastlyProvider.describe(cfgV, ledger)).toMatchObject({
      readiness: { dns: 'pending' },
    });
    dns.rows.push({ ...traffic, content: TRAFFIC_TARGET });
    linkedTo = 'OTHERSVC';
    expect(await fastlyProvider.describe(cfgV, ledger)).toMatchObject({
      state: 'pending',
      readiness: { dns: 'pending' },
    });
  });

  test('destroy deletes it by id once its certificate is gone, before the service', async () => {
    let deleted = false;
    const r = await serve((c) =>
      deleted && c.path.startsWith('/domain-management/') ? NOT_FOUND : defaultReply(c),
    );
    fakeDns();
    const ledger = await provisionV();
    const plan = fastlyProvider.planDestroy(cfgV, ledger);
    expect(plan.map(fastlyDestroyKey)).toEqual([
      'dns_record:traffic',
      'tls_subscription',
      'dns_record:acme',
      'versionless_domain',
      'active_version',
      'service',
      'backend',
      'snippet',
      'ws_product',
    ]);
    r.calls.length = 0;
    const domain = plan.find((x) => x.kind === 'versionless_domain')!;
    expect(await fastlyProvider.runDestroy(cfgV, domain, ledger)).toEqual({
      status: 'delete_requested',
    });
    expect(r.calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      `DELETE /domain-management/v1/domains/${DM}`,
    ]);
    expect(await fastlyProvider.confirmDestroyed!(cfgV, domain, ledger)).toEqual({
      status: 'still_present',
    });
    deleted = true;
    expect(await fastlyProvider.confirmDestroyed!(cfgV, domain, ledger)).toEqual({
      status: 'confirmed_gone',
    });
  });

  test('an edge built with a classic domain is described and destroyed the classic way', async () => {
    // The adapter reads the LEDGER: a classic edge stays classic whatever the config says.
    const r = await serve();
    fakeDns();
    const ledger = await provision();
    r.calls.length = 0;
    await fastlyProvider.describe(cfgV, ledger);
    expect(r.calls.some((c) => c.path.endsWith(`/domain/${HOST}/check`))).toBe(true);
    expect(r.calls.some((c) => c.path.startsWith('/domain-management/'))).toBe(false);
    r.calls.length = 0;
    for (const resource of fastlyProvider.planDestroy(cfgV, ledger))
      await fastlyProvider.runDestroy(cfgV, resource, ledger);
    expect(r.calls.some((c) => c.path.startsWith('/domain-management/'))).toBe(false);
  });

  test('on a shared service the versionless domain is one delete, with no version workflow', () => {
    const ledger: Ledger = {
      steps: [],
      resources: [
        {
          stepId: 'service',
          kind: 'service',
          resourceId: SVC,
          ownership: 'adopted',
          deleteState: 'present',
          meta: JSON.stringify({
            version: 4,
            activeVersion: 4,
            name: 'legacy front',
            shared: true,
          }),
        },
        {
          stepId: 'domain',
          kind: 'versionless_domain',
          resourceId: DM,
          ownership: 'adopted',
          deleteState: 'present',
          meta: JSON.stringify({ fqdn: HOST, serviceId: SVC }),
        },
      ],
    };
    expect(planSharedTeardown(ledger, 'op-1')).toBeNull();
    expect(fastlyProvider.planDestroy(cfgV, ledger).map(fastlyDestroyKey)).toEqual([
      'versionless_domain',
    ]);
  });

  test('an import finds a versionless hostname too, and records it as such', async () => {
    await serve((c) => {
      if (c.method === 'GET' && c.path === '/domain-management/v1/domains')
        return c.query.service_id === SVC
          ? ok('dm-domains-list.json')
          : ok('dm-domains-empty.json');
      if (c.method === 'GET' && /\/version\/\d+\/domain$/.test(c.path))
        return { status: 200, body: [] };
      return defaultReply(c);
    });
    fakeDns();
    const adopted = await fastlyProvider.inspectForAdoption!(cfgV, SVC, HOST);
    expect(adopted).toMatchObject({ hostname: HOST, hostnames: [HOST], shared: false });
    expect(adopted.resources.find((x) => x.kind === 'versionless_domain')).toMatchObject({
      resourceId: DM,
      ownership: 'adopted',
    });
  });
});

// --- one wildcard certificate shared by the account -------------------------------------------

describe('fastly: one wildcard certificate per account and zone', () => {
  const WILD = 'WILDsub0example0org01';
  const WILD_ACME = 'w1ld9mtt5uzzsw2q.fastly-validations.com';
  const cfgW: FastlyConfig = { ...cfg, domainModel: 'versionless', certificateScope: 'wildcard' };
  const HOST2 = 'p9x2v4kd.example.org';
  const spec2: EdgeSpec = { ...spec, name: 'fcp-relay-o2-feedface', hostname: HOST2 };

  /** A provider that holds the wildcard once ordered, and issues it when told to. */
  function wildcardProvider() {
    const state = { ordered: false, issued: false };
    const route: Route = (c) => {
      if (c.method === 'GET' && c.path === '/tls/subscriptions')
        return c.query['filter[tls_domains.id]'] === '*.example.org' && state.ordered
          ? api('tls-subscriptions-wildcard-list.json')
          : api('tls-subscriptions-empty.json');
      if (c.method === 'POST' && c.path === '/tls/subscriptions') {
        state.ordered = true;
        return api('tls-subscription-wildcard-create.json');
      }
      if (c.method === 'GET' && c.path === `/tls/subscriptions/${WILD}`)
        return api(
          state.issued
            ? 'tls-subscription-wildcard-issued.json'
            : 'tls-subscription-wildcard-pending.json',
        );
      if (c.method === 'GET' && c.path === '/domain-management/v1/domains')
        return ok('dm-domains-empty.json');
      if (c.method === 'POST' && c.path === '/domain-management/v1/domains')
        return {
          status: 200,
          body: {
            ...(fixture('dm-domain-create.json') as object),
            fqdn: (c.body as { fqdn: string }).fqdn,
          },
        };
      return defaultReply(c);
    };
    return { state, route };
  }

  async function provisionW(
    s: EdgeSpec,
    issueAfterOrder?: () => void,
  ): Promise<{ ledger: Ledger; polls: number }> {
    let ledger: Ledger = { steps: [], resources: [] };
    let polls = 0;
    for (const step of fastlyProvider.planProvision(cfgW, s, tpl)) {
      const out = await fastlyProvider.runStep(cfgW, step, s, tpl, ledger);
      ledger = apply(ledger, step, out);
      if (out.status === 'requested') {
        issueAfterOrder?.();
        polls++;
        ledger = apply(ledger, step, await fastlyProvider.pollStep!(cfgW, step, out.opRef, ledger));
      }
    }
    return { ledger, polls };
  }

  test('the certificate steps name the zone wildcard and its challenge', () => {
    const steps = fastlyProvider.planProvision(cfgW, spec, tpl);
    expect(
      steps.filter((x) => ['tls', 'acme', 'await-tls'].includes(x.id)).map((x) => x.resourceName),
    ).toEqual(['*.example.org', '_acme-challenge.example.org', '*.example.org']);
  });

  test('two edges share ONE subscription and ONE ACME record; the second never waits', async () => {
    const p = wildcardProvider();
    const r = await serve(p.route);
    const dns = fakeDns();

    // The first edge orders the wildcard and waits for it.
    const a = await provisionW(spec, () => (p.state.issued = true));
    expect(a.polls).toBe(1);
    const order = r.calls.filter((c) => c.method === 'POST' && c.path === '/tls/subscriptions');
    expect(order).toHaveLength(1);
    expect(order[0].body).toMatchObject({
      data: {
        relationships: { tls_domains: { data: [{ type: 'tls_domain', id: '*.example.org' }] } },
      },
    });
    const sub = a.ledger.resources.find((x) => x.kind === 'tls_subscription')!;
    expect(sub.resourceId).toBe(WILD);
    expect(JSON.parse(sub.meta!)).toEqual({
      hostname: '*.example.org',
      shared: true,
      wildcard: true,
    });
    expect(dns.rows.filter((x) => x.name === '_acme-challenge.example.org')).toEqual([
      expect.objectContaining({ content: WILD_ACME, comment: sharedAcmeMarker(CUSTOMER, WILD) }),
    ]);

    // The second edge finds both and finishes the wait at its first look.
    r.calls.length = 0;
    const b = await provisionW(spec2);
    expect(b.polls).toBe(0);
    expect(
      r.calls.filter((c) => c.method === 'POST' && c.path === '/tls/subscriptions'),
    ).toHaveLength(0);
    expect(dns.rows.filter((x) => x.name === '_acme-challenge.example.org')).toHaveLength(1);
    const bSub = b.ledger.resources.find((x) => x.kind === 'tls_subscription')!;
    expect(bSub).toMatchObject({ resourceId: WILD, ownership: 'adopted' });
    const bAcme = b.ledger.resources.find(
      (x) => x.kind === 'dns_record' && JSON.parse(x.meta!).role === 'acme',
    )!;
    expect(JSON.parse(bAcme.meta!)).toMatchObject({ shared: true });
    // Each edge still has its own front name.
    expect(dns.rows.filter((x) => x.name === HOST2)).toHaveLength(1);

    // Destroying the first edge leaves the shared certificate and its record.
    r.calls.length = 0;
    for (const resource of fastlyProvider.planDestroy(cfgW, a.ledger)) {
      const out = await fastlyProvider.runDestroy(cfgW, resource, a.ledger);
      if (resource.kind === 'tls_subscription' || JSON.parse(resource.meta ?? '{}').role === 'acme')
        expect(out).toEqual({ status: 'confirmed_gone' });
    }
    expect(r.calls.some((c) => c.method === 'DELETE' && c.path.startsWith('/tls/'))).toBe(false);
    expect(dns.rows.filter((x) => x.name === '_acme-challenge.example.org')).toHaveLength(1);
    expect(dns.rows.some((x) => x.name === HOST)).toBe(false);
    // ... and the second edge still describes as active through it.
    expect(await fastlyProvider.describe(cfgW, b.ledger)).toMatchObject({
      readiness: { certificate: 'ready' },
    });
    // Confirmation never waits on a shared resource.
    expect(await fastlyProvider.confirmDestroyed!(cfgW, bSub, b.ledger)).toEqual({
      status: 'confirmed_gone',
    });
  });

  test('a lost order response is recognised by name, and never ordered twice', async () => {
    const p = wildcardProvider();
    p.state.ordered = true;
    const r = await serve(p.route);
    fakeDns();
    const step = fastlyProvider
      .planProvision(cfgW, spec, tpl)
      .find((x) => x.kind === 'create_tls_subscription')!;
    expect(
      await fastlyProvider.discover(cfgW, step, spec, { steps: [], resources: [] }, 1),
    ).toMatchObject({
      status: 'found',
      resources: [{ kind: 'tls_subscription', resourceId: WILD }],
    });
    expect(r.calls[0].query['filter[tls_domains.id]']).toBe('*.example.org');
    p.state.ordered = false;
    expect(
      await fastlyProvider.discover(cfgW, step, spec, { steps: [], resources: [] }, 1),
    ).toEqual({
      status: 'confirmed_absent',
    });
  });

  test('a wildcard another CA issued is not ours to reuse', async () => {
    const other = fixture('tls-subscriptions-wildcard-list.json') as {
      data: Array<{ attributes: Record<string, unknown> }>;
    };
    other.data[0]!.attributes.certificate_authority = 'lets-encrypt';
    await serve((c) =>
      c.method === 'GET' && c.path === '/tls/subscriptions'
        ? { status: 200, body: other, contentType: 'application/vnd.api+json' }
        : defaultReply(c),
    );
    fakeDns();
    const step = fastlyProvider
      .planProvision(cfgW, spec, tpl)
      .find((x) => x.kind === 'create_tls_subscription')!;
    const err = (await fastlyProvider
      .runStep(cfgW, step, spec, tpl, { steps: [], resources: [] })
      .catch((e: unknown) => e)) as { meta?: { code?: string } };
    expect(err.meta?.code).toBe('shared_certificate_ambiguous');
    expect(
      await fastlyProvider.discover(cfgW, step, spec, { steps: [], resources: [] }, 1),
    ).toMatchObject({
      status: 'ambiguous',
    });
  });

  test('a record FCP did not write at the challenge name is never taken over', async () => {
    const p = wildcardProvider();
    p.state.ordered = true;
    await serve(p.route);
    fakeDns([
      {
        id: 'theirs',
        type: 'CNAME',
        name: '_acme-challenge.example.org',
        content: 'acme.example.net',
        proxied: false,
        comment: 'their own client',
      },
    ]);
    const steps = fastlyProvider.planProvision(cfgW, spec, tpl);
    const tls = steps.find((x) => x.kind === 'create_tls_subscription')!;
    const acme = steps.find((x) => x.kind === 'create_dns_acme')!;
    const ledger = apply(
      { steps: [], resources: [] },
      tls,
      await fastlyProvider.runStep(cfgW, tls, spec, tpl, { steps: [], resources: [] }),
    );
    const err = (await fastlyProvider
      .runStep(cfgW, acme, spec, tpl, ledger)
      .catch((e: unknown) => e)) as {
      meta?: { code?: string };
    };
    expect(err.meta?.code).toBe('acme_name_in_use');
    expect(await fastlyProvider.discover(cfgW, acme, spec, ledger, 1)).toMatchObject({
      status: 'ambiguous',
      candidates: [{ resourceId: 'theirs' }],
    });
  });

  test('a wildcard on another TLS configuration than the effective one is not reused', async () => {
    const other = fixture('tls-subscriptions-wildcard-list.json') as {
      data: Array<{ relationships: Record<string, unknown> }>;
    };
    // The account names no configuration, so its fronts use the DEFAULT one
    // (TLSCONFIG01, whose CNAME the traffic record points at); this
    // subscription is on the other one.
    other.data[0]!.relationships.tls_configuration = {
      data: { type: 'tls_configuration', id: 'TLSCONFIG02' },
    };
    await serve((c) =>
      c.method === 'GET' && c.path === '/tls/subscriptions'
        ? { status: 200, body: other, contentType: 'application/vnd.api+json' }
        : defaultReply(c),
    );
    fakeDns();
    const step = fastlyProvider
      .planProvision(cfgW, spec, tpl)
      .find((x) => x.kind === 'create_tls_subscription')!;
    expect(
      await fastlyProvider.discover(cfgW, step, spec, { steps: [], resources: [] }, 1),
    ).toMatchObject({ status: 'ambiguous' });
    // Named explicitly, the same configuration is ours.
    const named: FastlyConfig = { ...cfgW, tlsConfigurationId: 'TLSCONFIG02' };
    expect(
      await fastlyProvider.discover(named, step, spec, { steps: [], resources: [] }, 1),
    ).toMatchObject({ status: 'found' });
  });

  /** The ledger right after the wildcard step found or ordered `subId`. */
  function afterTls(subId: string): Ledger {
    return {
      steps: [],
      resources: [
        {
          stepId: 'tls',
          kind: 'tls_subscription',
          resourceId: subId,
          ownership: 'created',
          deleteState: 'present',
          meta: JSON.stringify({ hostname: '*.example.org', shared: true, wildcard: true }),
        },
      ],
    };
  }
  const challengeRecord = (comment: string, id = 'old1'): DnsRecord => ({
    id,
    type: 'CNAME',
    name: '_acme-challenge.example.org',
    content: 'stale.fastly-validations.com',
    proxied: false,
    comment,
  });

  test('another customer’s record at the challenge name is a candidate that is never deleted', async () => {
    const p = wildcardProvider();
    p.state.ordered = true;
    await serve(p.route);
    const dns = fakeDns([challengeRecord('fcp-cert:SOMEONEELSE:THEIRSUB')]);
    const acme = fastlyProvider
      .planProvision(cfgW, spec, tpl)
      .find((x) => x.kind === 'create_dns_acme')!;
    const found = await fastlyProvider.discover(cfgW, acme, spec, afterTls(WILD), 1);
    expect(found).toMatchObject({ status: 'ambiguous' });
    const candidates = (found as { candidates: ChildResource[] }).candidates;
    expect(candidates[0]!.meta).toMatchObject({ candidate: true, shared: true });
    // The orchestrator records the candidate; an operator's destroy then
    // never plans it, and a direct destroy leaves it in place.
    const ledger = apply(afterTls(WILD), acme, { status: 'done', resources: candidates });
    const record = ledger.resources.find((x) => x.kind === 'dns_record')!;
    expect(fastlyProvider.planDestroy(cfgW, ledger)).not.toContainEqual(record);
    expect(await fastlyProvider.runDestroy(cfgW, record, ledger)).toEqual({
      status: 'confirmed_gone',
    });
    expect(dns.deleted).toEqual([]);
  });

  test('our own record for a subscription that is gone is replaced; one for a live subscription is not', async () => {
    const p = wildcardProvider();
    p.state.ordered = true;
    let oldExists = false;
    await serve((c) =>
      c.method === 'GET' && c.path === '/tls/subscriptions/OLDSUB'
        ? oldExists
          ? api('tls-subscription-failed.json')
          : NOT_FOUND
        : p.route(c, 0),
    );
    const dns = fakeDns([challengeRecord(sharedAcmeMarker(CUSTOMER, 'OLDSUB'))]);
    const acme = fastlyProvider
      .planProvision(cfgW, spec, tpl)
      .find((x) => x.kind === 'create_dns_acme')!;
    // The old subscription was deleted at the provider: discovery says absent,
    // and the step swaps the record for one naming the new subscription.
    expect(await fastlyProvider.discover(cfgW, acme, spec, afterTls(WILD), 1)).toEqual({
      status: 'confirmed_absent',
    });
    const out = await fastlyProvider.runStep(cfgW, acme, spec, tpl, afterTls(WILD));
    expect(out.status).toBe('done');
    expect(dns.deleted).toEqual(['old1']);
    expect(dns.rows.filter((x) => x.name === '_acme-challenge.example.org')).toEqual([
      expect.objectContaining({ content: WILD_ACME, comment: sharedAcmeMarker(CUSTOMER, WILD) }),
    ]);
    // While our older subscription still exists, its record is left alone.
    oldExists = true;
    const dns2 = fakeDns([challengeRecord(sharedAcmeMarker(CUSTOMER, 'OLDSUB'))]);
    expect(await fastlyProvider.discover(cfgW, acme, spec, afterTls(WILD), 1)).toMatchObject({
      status: 'ambiguous',
    });
    const err = (await fastlyProvider
      .runStep(cfgW, acme, spec, tpl, afterTls(WILD))
      .catch((e: unknown) => e)) as { meta?: { code?: string } };
    expect(err.meta?.code).toBe('acme_name_in_use');
    expect(dns2.deleted).toEqual([]);
  });

  test('our record pointing at another validation target is replaced with the current one', async () => {
    const p = wildcardProvider();
    p.state.ordered = true;
    await serve(p.route);
    const dns = fakeDns([
      {
        ...challengeRecord(sharedAcmeMarker(CUSTOMER, WILD), 'acme1'),
        content: 'edited-by-hand.example.net',
      },
    ]);
    const acme = fastlyProvider
      .planProvision(cfgW, spec, tpl)
      .find((x) => x.kind === 'create_dns_acme')!;
    expect(await fastlyProvider.discover(cfgW, acme, spec, afterTls(WILD), 1)).toEqual({
      status: 'confirmed_absent',
    });
    expect((await fastlyProvider.runStep(cfgW, acme, spec, tpl, afterTls(WILD))).status).toBe(
      'done',
    );
    expect(dns.deleted).toEqual(['acme1']);
    expect(dns.rows.filter((x) => x.name === '_acme-challenge.example.org')).toEqual([
      expect.objectContaining({ content: WILD_ACME, comment: sharedAcmeMarker(CUSTOMER, WILD) }),
    ]);
  });

  test('an unused wildcard is removed with OUR records only; one ordered differently is refused', async () => {
    const p = wildcardProvider();
    p.state.ordered = true;
    p.state.issued = true;
    const r = await serve((c) =>
      c.method === 'GET' && c.path === '/tls/subscriptions/OLDSUB' ? NOT_FOUND : p.route(c, 0),
    );
    const dns = fakeDns([
      { ...challengeRecord(sharedAcmeMarker(CUSTOMER, WILD), 'ours'), content: WILD_ACME },
      challengeRecord(sharedAcmeMarker(CUSTOMER, 'OLDSUB'), 'stale'),
      challengeRecord('fcp-cert:SOMEONEELSE:THEIRS', 'theirs'),
    ]);
    // A per-host account still sees the wildcard it left behind, to remove it.
    expect(await fastlyProvider.sharedCertificate!(cfg)).toMatchObject({
      name: '*.example.org',
      state: 'issued',
    });
    expect(await fastlyProvider.removeSharedCertificate!(cfg)).toEqual({ removed: true });
    expect(
      r.calls.filter((c) => c.method === 'DELETE').map((c) => [c.path, c.query.force]),
    ).toEqual([[`/tls/subscriptions/${WILD}`, 'true']]);
    expect(dns.deleted.sort()).toEqual(['ours', 'stale']);
    expect(dns.rows.map((x) => x.id)).toEqual(['theirs']);
    // Nothing left to see on a per-host account.
    p.state.ordered = false;
    expect(await fastlyProvider.sharedCertificate!(cfg)).toBeNull();

    // A wildcard another CA issued is not this account's to delete.
    const other = fixture('tls-subscriptions-wildcard-list.json') as {
      data: Array<{ attributes: Record<string, unknown> }>;
    };
    other.data[0]!.attributes.certificate_authority = 'lets-encrypt';
    await serve((c) =>
      c.method === 'GET' && c.path === '/tls/subscriptions'
        ? { status: 200, body: other, contentType: 'application/vnd.api+json' }
        : defaultReply(c),
    );
    expect(await fastlyProvider.removeSharedCertificate!(cfgW)).toEqual({
      removed: false,
      code: 'shared_certificate_ambiguous',
    });
  });

  test('a renewal reports what holds it up, and one that is late is raised by itself', async () => {
    const renewing = (extra: Record<string, unknown>) => {
      const doc = fixture('tls-subscription-wildcard-issued.json') as {
        data: { attributes: Record<string, unknown> };
        included: Array<{ type: string; attributes: Record<string, unknown> }>;
      };
      doc.data.attributes.state = extra.state ?? 'renewing';
      const auth = doc.included.find((x) => x.type === 'tls_authorization')!;
      if (extra.warnings) auth.attributes.warnings = extra.warnings;
      const cert = doc.included.find((x) => x.type === 'tls_certificate')!;
      if (extra.notAfter) cert.attributes.not_after = extra.notAfter;
      return doc;
    };
    let doc = renewing({ warnings: [{ type: 'caa', instructions: 'see example.org' }] });
    const p = wildcardProvider();
    p.state.ordered = true;
    await serve((c) =>
      c.method === 'GET' && c.path === `/tls/subscriptions/${WILD}`
        ? { status: 200, body: doc, contentType: 'application/vnd.api+json' }
        : p.route(c, 0),
    );
    fakeDns([
      {
        id: 'acme1',
        type: 'CNAME',
        name: '_acme-challenge.example.org',
        content: WILD_ACME,
        proxied: false,
        comment: sharedAcmeMarker(CUSTOMER, WILD),
      },
    ]);
    const far = new Date(Date.now() + 20 * 86_400_000).toISOString();
    const near = new Date(Date.now() + 3 * 86_400_000).toISOString();
    doc = renewing({ warnings: [{ type: 'caa' }], notAfter: far });
    expect(await fastlyProvider.sharedCertificate!(cfgW)).toMatchObject({
      state: 'renewing',
      code: 'tls_caa_conflict',
    });
    // An ordinary renewal, far from expiry: nothing to raise.
    doc = renewing({ notAfter: far });
    expect(await fastlyProvider.sharedCertificate!(cfgW)).not.toHaveProperty('code');
    // Issued but within a week of expiry: the renewal is late.
    doc = renewing({ state: 'issued', notAfter: near });
    expect(await fastlyProvider.sharedCertificate!(cfgW)).toMatchObject({
      state: 'issued',
      code: 'certificate_expiring',
    });
    expect(CERTIFICATE_EXPIRY_WARN_MS).toBe(7 * 86_400_000);
  });

  test('the account reads its shared certificate: absent, waiting with a code, issued until a date', async () => {
    const p = wildcardProvider();
    await serve(p.route);
    fakeDns();
    expect(await fastlyProvider.sharedCertificate!(cfgW)).toEqual({
      name: '*.example.org',
      state: 'absent',
    });
    p.state.ordered = true;
    // Waiting, and its validation record is not in the zone yet.
    expect(await fastlyProvider.sharedCertificate!(cfgW)).toEqual({
      name: '*.example.org',
      subscriptionId: WILD,
      state: 'processing',
      code: 'tls_challenge_missing',
    });
    p.state.issued = true;
    expect(await fastlyProvider.sharedCertificate!(cfgW)).toEqual({
      name: '*.example.org',
      subscriptionId: WILD,
      state: 'issued',
      notAfter: '2026-11-19T10:12:00.000Z',
    });
    expect(rec!.calls.at(-1)!.query).toEqual({ include: 'tls_authorizations,tls_certificates' });
    // A per-host account sees the wildcard only while one exists (to remove
    // it); with none at all it has no shared certificate.
    expect(await fastlyProvider.sharedCertificate!(cfg)).toMatchObject({ state: 'issued' });
    p.state.ordered = false;
    expect(await fastlyProvider.sharedCertificate!(cfg)).toBeNull();
  });
});

// --- what the front dials ------------------------------------------------------------------

describe('fastly: the front dials the origin on its own port', () => {
  /**
   * A provider that KEEPS the backend it was given, with the API's own
   * defaults for what the request left out: `port` 80 (whatever `use_ssl`
   * says) and no TLS name. The front then dials exactly what is stored.
   */
  function backendKeepingProvider() {
    let stored: Record<string, unknown> | null = null;
    const route: Route = (c) => {
      if (c.method === 'POST' && /\/backend$/.test(c.path)) {
        const b = c.body as Record<string, string>;
        stored = {
          name: b.name,
          address: b.address,
          hostname: b.address,
          port: b.port !== undefined ? Number(b.port) : 80,
          use_ssl: b.use_ssl === 'true',
          ssl_cert_hostname: b.ssl_cert_hostname ?? null,
          ssl_sni_hostname: b.ssl_sni_hostname ?? null,
          override_host: b.override_host ?? null,
          comment: b.comment ?? null,
        };
        return { status: 200, body: stored };
      }
      if (c.method === 'GET' && /\/backend$/.test(c.path))
        return { status: 200, body: stored ? [stored] : [] };
      if (c.method === 'GET' && /\/backend\/origin$/.test(c.path))
        return stored ? { status: 200, body: stored } : NOT_FOUND;
      return defaultReply(c);
    };
    return { route, stored: () => stored };
  }

  /** Where a front with this backend opens its connection, and how. */
  function frontDials(b: Record<string, unknown>) {
    return {
      host: b.address,
      port: b.port,
      tls: b.use_ssl === true,
      sni: b.use_ssl === true ? (b.ssl_sni_hostname ?? null) : null,
    };
  }

  test('an https origin is dialled on 443 with TLS, presenting and verifying its own name', async () => {
    const p = backendKeepingProvider();
    await serve(p.route);
    fakeDns();
    const ledger = await provision();
    expect(frontDials(p.stored()!)).toEqual({ host: ORIGIN, port: 443, tls: true, sni: ORIGIN });
    expect(p.stored()!.ssl_cert_hostname).toBe(ORIGIN);
    // What inspect reports is the port the provider holds, not one derived from TLS.
    const seen = await fastlyProvider.inspect(cfg, ledger);
    expect(seen.summary.members).toEqual([{ address: ORIGIN, port: 443 }]);
  });

  test('a backend created without its port is dialled on 80, which the inspect read shows', async () => {
    // The regression this guards against: the body without `port` lands on 80.
    const p = backendKeepingProvider();
    const r = await serve(p.route);
    const { port: _dropped, ...withoutPort } = fastlyBackendBody(spec, tpl);
    await fastlyApiFor(cfg).createBackend(SVC, 1, withoutPort as never);
    expect(frontDials(p.stored()!)).toMatchObject({ port: 80, tls: true });
    const ledger: Ledger = {
      steps: [],
      resources: [
        {
          stepId: 'service',
          kind: 'service',
          resourceId: SVC,
          ownership: 'created',
          deleteState: 'present',
          meta: JSON.stringify({ version: 1, name: spec.name }),
        },
      ],
    };
    const seen = await fastlyProvider.inspect(cfg, ledger);
    expect(seen.summary.members).toEqual([{ address: ORIGIN, port: 80 }]);
    expect(r.calls.length).toBeGreaterThan(0);
  });
});
