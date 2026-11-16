'use node';
/**
 * Test helper: an in-memory Tencent Cloud account with EdgeOne zones, answering
 * the SDK client's actions with Tencent's own request and response shapes.
 * Not a test file itself.
 *
 * Two front-ends share one store: `client`, a stand-in for the SDK client the
 * wrapper (`edgeOneSdkApi`) drives, so the adapter tests run the wrapper's
 * readers and error reduction; and `route`, an HTTP route for the recorder,
 * so the wire contract test runs the REAL SDK against the same account.
 *
 * It keeps the rules the adapter depends on, as Tencent documents them:
 *  - a new acceleration domain is `process`, then `online` after a few reads;
 *  - in a zone EdgeOne hosts (`full`), a new domain gets a CNAME record that
 *    is switched off (`autoRecord`), deleted with the domain;
 *  - the free certificate is refused (`HostStatusNotAllowApplyCertificate`)
 *    until the name resolves to EdgeOne: an enabled record in a hosted zone,
 *    or the outside resolver (`resolves`) for a zone connected by CNAME; it is
 *    `applying`, then `deployed` after a few reads;
 *  - an action the CAM policy leaves out answers `UnauthorizedOperation.CamUnauthorized`
 *    naming it; an injected code answers once (`failNext`); a lost answer
 *    applies the call and then fails like a dropped connection (`loseNext`).
 */
import type { RecorderReply, RecordedCall } from './httpRecorder';

export interface FakeZone {
  ZoneId: string;
  ZoneName: string;
  Type: 'full' | 'partial';
  Status: string;
  ActiveStatus?: string;
  Paused?: boolean;
  Area: string;
}

interface FakeDomain {
  ZoneId: string;
  DomainName: string;
  DomainStatus: string;
  Cname: string;
  OriginDetail: { OriginType: string; Origin: string; HostHeader?: string };
  OriginProtocol: string;
  HttpOriginPort: number;
  HttpsOriginPort: number;
  IPv6Status: string;
  Certificate: { Mode: string; List: Array<{ CertId: string; Type: string; Status: string }> };
  reads: number;
  certReads: number;
}

interface FakeRecord {
  RecordId: string;
  ZoneId: string;
  Name: string;
  Type: string;
  Content: string;
  Status: 'enable' | 'disable';
  TTL: number;
  /** EdgeOne added it for a domain (removed with the domain). */
  auto?: boolean;
}

export interface FakeEdgeOneState {
  zones: FakeZone[];
  domains: FakeDomain[];
  records: FakeRecord[];
  webSocket: Record<string, { Switch: string; Timeout?: number }>;
  /** A hosted zone adds a switched-off CNAME for a new domain (Tencent's NS-access behaviour). */
  autoRecord: boolean;
  /** Reads before a new domain is `online`, and before a certificate is `deployed`. */
  readsToOnline: number;
  readsToDeployed: number;
  /** Actions the CAM policy does not allow. */
  denied: Set<string>;
  /** One answer per action: a Tencent error code, given once. */
  failNext: Map<string, string>;
  /** Apply the action, then drop the answer (once). */
  loseNext: Set<string>;
  /** CNAME access: whether the public resolver sends the name to EdgeOne. */
  resolves: (name: string) => boolean;
  /** Every action called, in order. */
  calls: string[];
}

class FakeTencentError extends Error {
  constructor(
    public code: string | undefined,
    message: string,
    public requestId = 'req-fake',
  ) {
    super(message);
    this.name = 'TencentCloudSDKHttpException';
  }
}

const norm = (n: string) => n.trim().toLowerCase().replace(/\.$/, '');

function filterValue(req: Record<string, unknown>, name: string): string | undefined {
  const filters = (req.Filters ?? []) as Array<{ Name: string; Values: string[] }>;
  return filters.find((f) => f.Name === name)?.Values[0];
}

function page<T>(items: T[], req: Record<string, unknown>): T[] {
  const offset = Number(req.Offset ?? 0);
  const limit = Number(req.Limit ?? 20);
  return items.slice(offset, offset + limit);
}

export interface FakeEdgeOne {
  state: FakeEdgeOneState;
  /** Answer one action with Tencent's response object (without the `Response` wrapper). */
  handle(action: string, req: Record<string, unknown>): Record<string, unknown>;
  /** The SDK client stand-in (`edgeOneSdkApi(cfg, diagnostic, fake.client)`). */
  client: never;
  /** The recorder route (Tencent API 3.0 over HTTP: `POST /`, `X-TC-Action`). */
  route: (call: RecordedCall) => RecorderReply;
}

export function fakeEdgeOne(init: Partial<FakeEdgeOneState> = {}): FakeEdgeOne {
  const state: FakeEdgeOneState = {
    zones: [],
    domains: [],
    records: [],
    webSocket: {},
    autoRecord: true,
    readsToOnline: 2,
    readsToDeployed: 2,
    denied: new Set(),
    failNext: new Map(),
    loseNext: new Set(),
    resolves: () => false,
    calls: [],
    ...init,
  };
  let nextId = 1;
  const zoneOf = (id: unknown) => {
    const z = state.zones.find((x) => x.ZoneId === id);
    if (!z) throw new FakeTencentError('ResourceUnavailable.ZoneNotFound', 'zone not found');
    return z;
  };
  const resolvesToEdgeOne = (d: FakeDomain) => {
    const zone = zoneOf(d.ZoneId);
    if (zone.Type === 'partial') return state.resolves(d.DomainName);
    return state.records.some(
      (r) => r.Name === d.DomainName && r.Content === d.Cname && r.Status === 'enable',
    );
  };
  const view = (d: FakeDomain) => {
    const { reads: _r, certReads: _c, ...out } = d;
    return out;
  };

  function handle(action: string, req: Record<string, unknown>): Record<string, unknown> {
    state.calls.push(action);
    if (state.denied.has(action))
      throw new FakeTencentError(
        'UnauthorizedOperation.CamUnauthorized',
        `you are not authorized to perform operation (teo:${action})`,
      );
    const injected = state.failNext.get(action);
    if (injected) {
      state.failNext.delete(action);
      throw new FakeTencentError(injected, `${injected} (fake answer)`);
    }
    switch (action) {
      case 'DescribeZones': {
        const id = filterValue(req, 'zone-id');
        const zones = state.zones.filter((z) => !id || z.ZoneId === id);
        return { TotalCount: zones.length, Zones: page(zones, req) };
      }
      case 'DescribeL7AccSetting': {
        const z = zoneOf(req.ZoneId);
        return {
          ZoneSetting: {
            ZoneName: z.ZoneName,
            ZoneConfig: {
              WebSocket: state.webSocket[z.ZoneId] ?? { Switch: 'off' },
              ClientIPHeader: { Switch: 'off' },
            },
          },
        };
      }
      case 'DescribeAccelerationDomains': {
        zoneOf(req.ZoneId);
        const name = filterValue(req, 'domain-name');
        const found = state.domains.filter(
          (d) => d.ZoneId === req.ZoneId && (!name || d.DomainName === norm(name)),
        );
        for (const d of found) {
          d.reads++;
          if (d.DomainStatus === 'process' && d.reads >= state.readsToOnline)
            d.DomainStatus = 'online';
          const cert = d.Certificate.List[0];
          if (cert && cert.Status === 'applying' && ++d.certReads >= state.readsToDeployed)
            cert.Status = 'deployed';
        }
        return { TotalCount: found.length, AccelerationDomains: page(found, req).map(view) };
      }
      case 'CreateAccelerationDomain': {
        const zone = zoneOf(req.ZoneId);
        const name = norm(String(req.DomainName));
        if (!name.endsWith(`.${zone.ZoneName}`))
          throw new FakeTencentError('InvalidParameterValue.DomainNotMatchZone', 'not in zone');
        if (state.domains.some((d) => d.DomainName === name))
          throw new FakeTencentError('ResourceInUse', 'the domain exists');
        const origin = req.OriginInfo as {
          OriginType: string;
          Origin: string;
          HostHeader?: string;
        };
        const d: FakeDomain = {
          ZoneId: zone.ZoneId,
          DomainName: name,
          DomainStatus: 'process',
          Cname: `${name}.eo.dnse4.com`,
          OriginDetail: { ...origin },
          OriginProtocol: String(req.OriginProtocol ?? 'FOLLOW'),
          HttpOriginPort: Number(req.HttpOriginPort ?? 80),
          HttpsOriginPort: Number(req.HttpsOriginPort ?? 443),
          IPv6Status: String(req.IPv6Status ?? 'follow'),
          Certificate: { Mode: 'disable', List: [] },
          reads: 0,
          certReads: 0,
        };
        state.domains.push(d);
        if (zone.Type === 'full' && state.autoRecord)
          state.records.push({
            RecordId: `rec-${nextId++}`,
            ZoneId: zone.ZoneId,
            Name: name,
            Type: 'CNAME',
            Content: d.Cname,
            Status: 'disable',
            TTL: 300,
            auto: true,
          });
        return {};
      }
      case 'DeleteAccelerationDomains': {
        const names = (req.DomainNames as string[]).map(norm);
        const gone = state.domains.filter(
          (d) => d.ZoneId === req.ZoneId && names.includes(d.DomainName),
        );
        if (gone.length === 0)
          throw new FakeTencentError('ResourceUnavailable.DomainNotFound', 'domain not found');
        state.domains = state.domains.filter((d) => !gone.includes(d));
        state.records = state.records.filter(
          (r) => !(r.auto && gone.some((d) => d.DomainName === r.Name && d.Cname === r.Content)),
        );
        return {};
      }
      case 'ModifyHostsCertificate': {
        const hosts = (req.Hosts as string[]).map(norm);
        for (const h of hosts) {
          const d = state.domains.find((x) => x.ZoneId === req.ZoneId && x.DomainName === h);
          if (!d) throw new FakeTencentError('ResourceUnavailable.HostNotFound', 'host not found');
          if (!resolvesToEdgeOne(d))
            throw new FakeTencentError(
              'InvalidParameter.HostStatusNotAllowApplyCertificate',
              'the CNAME is not switched to EdgeOne',
            );
          d.Certificate = {
            Mode: String(req.Mode),
            List: [{ CertId: `teo-free-${nextId++}`, Type: 'managed', Status: 'applying' }],
          };
        }
        return {};
      }
      case 'DescribeDnsRecords': {
        zoneOf(req.ZoneId);
        const name = filterValue(req, 'name');
        const rows = state.records.filter(
          (r) => r.ZoneId === req.ZoneId && (!name || r.Name.includes(norm(name))),
        );
        return {
          TotalCount: rows.length,
          DnsRecords: page(rows, req).map(({ auto: _a, ...r }) => r),
        };
      }
      case 'CreateDnsRecord': {
        const zone = zoneOf(req.ZoneId);
        const name = norm(String(req.Name));
        if (state.records.some((r) => r.ZoneId === zone.ZoneId && r.Name === name))
          throw new FakeTencentError('InvalidParameterValue.ConflictRecord', 'record exists');
        const id = `rec-${nextId++}`;
        state.records.push({
          RecordId: id,
          ZoneId: zone.ZoneId,
          Name: name,
          Type: String(req.Type),
          Content: norm(String(req.Content)),
          Status: 'enable',
          TTL: Number(req.TTL ?? 300),
        });
        return { RecordId: id };
      }
      case 'ModifyDnsRecordsStatus': {
        for (const id of (req.RecordsToEnable as string[] | undefined) ?? []) {
          const r = state.records.find((x) => x.RecordId === id);
          if (r) r.Status = 'enable';
        }
        return {};
      }
      case 'DeleteDnsRecords': {
        const ids = req.RecordIds as string[];
        if (state.records.some((r) => ids.includes(r.RecordId) && r.auto))
          throw new FakeTencentError(
            'OperationDenied',
            'a record EdgeOne added goes with its domain',
          );
        state.records = state.records.filter((r) => !ids.includes(r.RecordId));
        return {};
      }
      default:
        throw new FakeTencentError('InvalidAction', `unknown action ${action}`);
    }
  }

  function answer(action: string, req: Record<string, unknown>): Promise<Record<string, unknown>> {
    try {
      const out = handle(action, req);
      if (state.loseNext.has(action)) {
        state.loseNext.delete(action);
        // A dropped connection: the SDK's exception carries no code.
        return Promise.reject(
          new FakeTencentError(undefined, 'request failed, reason: socket hang up'),
        );
      }
      return Promise.resolve({ ...out, RequestId: 'req-fake' });
    } catch (e) {
      return Promise.reject(e);
    }
  }

  const client = new Proxy(
    {},
    {
      get: (_t, action: string) => (req: Record<string, unknown>) => answer(action, req),
    },
  ) as never;

  function route(call: RecordedCall): RecorderReply {
    const action = String(call.headers['x-tc-action'] ?? '');
    try {
      const out = handle(action, (call.body ?? {}) as Record<string, unknown>);
      return { status: 200, body: { Response: { ...out, RequestId: 'req-fake' } } };
    } catch (e) {
      const err = e as FakeTencentError;
      return {
        status: 200,
        body: {
          Response: { Error: { Code: err.code, Message: err.message }, RequestId: 'req-fake' },
        },
      };
    }
  }

  return { state, handle, client, route };
}
