'use node';
/**
 * Cloudflare Spectrum with a Worker origin (L4), on the official SDK
 * (`cloudflare@7.3.0`, through the one client factory in dns/cloudflareDns.ts).
 *
 * One edge is two resources:
 *  1. a relay Worker (`create_worker`): FCP's fixed module, which pipes each
 *     inbound TCP connection to the node untouched. The node's address and
 *     port travel as plain-text bindings. It lives in the account of the
 *     location's zone (Cloudflare requires the Worker and the zone to share an
 *     account), read from the zone when the edge is made and kept in the
 *     ledger. Observability and Logpush are off: no record of a member.
 *  2. a Spectrum application (`create_lb`, ledger kind `lb`) on the zone: `tcp/<edge port>`,
 *     `traffic_type: worker`, its origin the Worker's tag, a CNAME under the
 *     zone named from the edge's name (never published).
 *
 * Addresses: Cloudflare picks a unique anycast IPv4 and IPv6 for the
 * application and may change them; its docs say to read them over DNS, so
 * `describe` resolves the application's name through Cloudflare's resolver
 * (authoritative for the zone) every time, and the edge is `active` once an
 * IPv4 answers. A Pro or Business zone takes no TLS options: the bytes pass
 * through, so a REALITY or TLS listener works unchanged.
 *
 * Limits the adapter cannot lift: one port per application, TCP only, one
 * Worker-origin application per zone (capability `edgesPerLocation`; a second
 * is refused with Cloudflare error 11034), and a Free zone is refused.
 *
 * Creates and deletes answer at once. The Worker upload is a PUT by name, so
 * re-running it is harmless; the application POST is discovered by its DNS
 * name before any retry. No member health is on the wire (`memberHealth`
 * false): a live application is `unknown`, never `online`.
 *
 * Sources: developers.cloudflare.com/spectrum/how-to/route-tcp-traffic-to-a-worker/,
 * /spectrum/reference/configuration-options/, /workers/runtime-apis/handlers/connect/
 * and /api/resources/spectrum/subresources/apps/methods/create/, read 2026-11-21.
 */
import { Resolver } from 'node:dns/promises';
import type {
  ChildResource,
  CredentialTestResult,
  DiscoverResult,
  Discovery,
  EdgeDescription,
  EdgeProvider,
  EdgeSpec,
  LedgerResource,
  LocationCheckResult,
  ResourceStep,
  SpectrumConfig,
  StepOutcome,
} from './types';
import { firstResource, metaOf, orderByKind, stepOf } from './types';
import { discoveryMaySettle } from './capabilities';
import { EdgeProviderError, credentialTestFailure, noteDiscoverError, refusedCreate } from './http';
import {
  cfCall,
  cloudflareClient,
  isCloudflareNotFound,
  verifyCloudflareToken,
} from './dns/cloudflareDns';
import { listZones } from './cloudflare';
import { labelFromSeed } from '../hostname';
import {
  SpectrumTemplate,
  SPECTRUM_TEMPLATE_FIELDS,
  type SpectrumTemplateParams,
} from './templates';

export { SpectrumTemplate, SPECTRUM_TEMPLATE_FIELDS } from './templates';
export type { SpectrumTemplateParams } from './templates';

// --- the relay Worker ------------------------------------------------------------------

/** The module's file name in the upload (`main_module`). */
export const SPECTRUM_WORKER_MODULE = 'relay.mjs';
/**
 * The Workers runtime date the relay is written against. The `connect()`
 * handler needs no compatibility flag; bump the date deliberately.
 */
export const SPECTRUM_WORKER_COMPATIBILITY_DATE = '2026-11-19';

/**
 * The relay: both directions piped, half-close kept (a client's FIN reaches
 * the node while the node may still answer), both sockets closed when either
 * side ends or resets. It reads nothing and logs nothing (it never touches
 * `socket.opened.remoteAddress`). The node's address is the `ORIGIN_HOST`
 * binding, its port `ORIGIN_PORT`.
 */
export const SPECTRUM_RELAY_WORKER = `import { connect } from "cloudflare:sockets";

export default {
  async connect(socket, env) {
    const origin = connect(
      { hostname: env.ORIGIN_HOST, port: Number(env.ORIGIN_PORT) },
      { secureTransport: "off", allowHalfOpen: true },
    );
    try {
      await Promise.all([
        socket.readable.pipeTo(origin.writable),
        origin.readable.pipeTo(socket.writable),
      ]);
    } catch {
      // One side reset: fall through and close both.
    } finally {
      try { origin.close(); } catch {}
      try { socket.close(); } catch {}
    }
  },
};
`;

// --- helpers ---------------------------------------------------------------------------

const PROVIDER = 'cloudflareSpectrum';

function fail(step: string, message: string, code: string): EdgeProviderError {
  return new EdgeProviderError(`spectrum ${message} on ${step}`, {
    provider: PROVIDER,
    step,
    code,
    retryable: false,
    timedOut: false,
  });
}

/**
 * Origin ports a Worker may not connect to (Cloudflare refuses outbound TCP
 * to port 25), so an edge in front of one would take connections and fail
 * every one of them.
 */
const WORKER_BLOCKED_PORTS = new Set([25]);

/**
 * The one listener an application carries (one port per application), refused
 * before anything is made when it cannot work.
 */
function onlyListener(spec: EdgeSpec, step: string) {
  const l = spec.listeners[0];
  if (spec.listeners.length !== 1 || !l || l.members.length !== 1)
    throw fail(step, 'needs exactly one listener with one member', 'spectrum_one_port');
  if (l.transport === 'udp') throw fail(step, 'carries TCP only', 'udp_unsupported');
  const member = l.members[0]!;
  if (WORKER_BLOCKED_PORTS.has(member.port))
    throw fail(step, `a Worker cannot connect to port ${member.port}`, 'origin_port_blocked');
  return { edgePort: l.edgePort, member };
}

/** Characters in the application's DNS label. */
const APP_LABEL_LENGTH = 12;

/**
 * The application's DNS name under the zone, from the edge's name (stable, so
 * it is the discovery key; the edge's name itself carries the node's slug and
 * is never put in DNS). Never published: members get the addresses.
 */
export function spectrumAppName(
  cfg: Pick<SpectrumConfig, 'zoneName'>,
  spec: Pick<EdgeSpec, 'name'>,
): string {
  return `${labelFromSeed(spec.name, APP_LABEL_LENGTH)}.${cfg.zoneName.toLowerCase().replace(/\.$/, '')}`;
}

/** The account the location's zone belongs to: where its Worker must live. */
async function zoneAccountId(cfg: SpectrumConfig, step: string): Promise<string> {
  const zone = await cfCall(step, () => cloudflareClient(cfg).zones.get({ zone_id: cfg.zoneId }), [
    cfg.apiToken,
  ]);
  const id = zone.account?.id;
  if (!id) throw fail(step, 'zone names no account', 'zone_account_unknown');
  return id;
}

/** The Worker upload's metadata (exported for tests). */
export function spectrumWorkerMetadata(
  member: { address: string; port: number },
  tpl: Pick<SpectrumTemplateParams, 'cpuLimitMs'>,
) {
  return {
    main_module: SPECTRUM_WORKER_MODULE,
    compatibility_date: SPECTRUM_WORKER_COMPATIBILITY_DATE,
    bindings: [
      { type: 'plain_text' as const, name: 'ORIGIN_HOST', text: member.address },
      { type: 'plain_text' as const, name: 'ORIGIN_PORT', text: String(member.port) },
    ],
    // No stored logs or traces of a connection: the Worker prints nothing, and
    // neither does the platform for it.
    observability: { enabled: false },
    logpush: false,
    ...(tpl.cpuLimitMs ? { limits: { cpu_ms: tpl.cpuLimitMs } } : {}),
  };
}

/**
 * The Worker upload as Cloudflare documents it (exported for tests): a JSON
 * part named `metadata`, and the module as a part named by its file name.
 */
export function spectrumWorkerUpload(
  member: { address: string; port: number },
  tpl: Pick<SpectrumTemplateParams, 'cpuLimitMs'>,
): FormData {
  const form = new FormData();
  form.append(
    'metadata',
    new Blob([JSON.stringify(spectrumWorkerMetadata(member, tpl))], { type: 'application/json' }),
  );
  form.append(
    SPECTRUM_WORKER_MODULE,
    new Blob([SPECTRUM_RELAY_WORKER], { type: 'application/javascript+module' }),
    SPECTRUM_WORKER_MODULE,
  );
  return form;
}

/**
 * The create-application body (exported for tests): exactly the four fields a
 * Pro or Business Worker application takes (Cloudflare's "settings by plan":
 * no `edge_ips`, `tls` or other Enterprise field, even unset). Cloudflare
 * gives it an IPv4 and an IPv6 of its own choosing.
 */
export function spectrumAppBody(
  cfg: SpectrumConfig,
  name: string,
  edgePort: number,
  workerTag: string,
) {
  return {
    zone_id: cfg.zoneId,
    dns: { type: 'CNAME' as const, name },
    protocol: `tcp/${edgePort}`,
    traffic_type: 'worker' as const,
    origin_worker_id: workerTag,
  };
}

/**
 * What the application says of its Worker origin (`origin_worker_status`,
 * not in the SDK's types yet): `available`, `not_found` or `unknown`. Absent
 * when Cloudflare does not report it.
 */
function originWorkerStatusOf(app: unknown): string | undefined {
  const v = (app as { origin_worker_status?: unknown } | null)?.origin_worker_status;
  return typeof v === 'string' ? v : undefined;
}

// --- addresses over DNS -------------------------------------------------------------------

/** How an application's addresses are looked up (a test replaces it). */
export interface SpectrumResolver {
  resolve4(name: string): Promise<string[]>;
  resolve6(name: string): Promise<string[]>;
}

function cloudflareResolver(): SpectrumResolver {
  // Cloudflare's own resolver answers for a zone it hosts without waiting on
  // another resolver's cache.
  const r = new Resolver({ timeout: 3_000, tries: 2 });
  r.setServers(['1.1.1.1', '1.0.0.1', '[2606:4700:4700::1111]']);
  return r;
}

let resolverFactory: () => SpectrumResolver = cloudflareResolver;

/** Test seam: replace the resolver (null restores Cloudflare's). */
export function __setSpectrumResolver(f: (() => SpectrumResolver) | null): void {
  resolverFactory = f ?? cloudflareResolver;
}

/** Answers that mean "no such record (yet)", not a failed lookup. */
const NO_RECORD = new Set(['ENODATA', 'ENOTFOUND', 'ENONAME']);

async function lookup(fn: () => Promise<string[]>): Promise<string | undefined> {
  try {
    return (await fn()).sort()[0];
  } catch (e) {
    const code = (e as { code?: unknown })?.code;
    if (typeof code === 'string' && NO_RECORD.has(code)) return undefined;
    throw fail(
      'describe',
      `address lookup failed (${String(code ?? 'error')})`,
      'dns_lookup_failed',
    );
  }
}

/**
 * The application's current addresses, as DNS answers for its name. Both
 * families are asked: an IPv4-only application answers no AAAA.
 */
export async function spectrumAddressesOf(name: string): Promise<{ v4?: string; v6?: string }> {
  const r = resolverFactory();
  const [v4, v6] = await Promise.all([
    lookup(() => r.resolve4(name)),
    lookup(() => r.resolve6(name)),
  ]);
  return { ...(v4 ? { v4 } : {}), ...(v6 ? { v6 } : {}) };
}

// --- listings ----------------------------------------------------------------------------

interface ListedApp {
  id: string;
  name: string;
  protocol?: string;
  trafficType?: string;
  createdOn?: string;
}

/** Applications asked for a page, and the most pages read (a zone holds a handful). */
const APP_PAGE = 50;
const APP_PAGES_MAX = 20;

/**
 * Every Spectrum application of the zone, page by page: a page shorter than
 * asked is the last. Bounded, so a provider that keeps answering never loops.
 */
async function listApps(cfg: SpectrumConfig, step: string): Promise<ListedApp[]> {
  const client = cloudflareClient(cfg);
  const out: ListedApp[] = [];
  for (let page = 1; page <= APP_PAGES_MAX; page++) {
    const res = await cfCall(
      step,
      () => client.spectrum.apps.list({ zone_id: cfg.zoneId, page, per_page: APP_PAGE }),
      [cfg.apiToken],
    );
    for (const a of res.result as Array<{
      id?: string;
      dns?: { name?: string };
      protocol?: string;
      traffic_type?: string;
      created_on?: string;
    }>) {
      if (!a.id) continue;
      out.push({
        id: a.id,
        name: (a.dns?.name ?? '').toLowerCase(),
        protocol: a.protocol,
        trafficType: a.traffic_type,
        createdOn: a.created_on,
      });
    }
    if (res.result.length < APP_PAGE) return out;
  }
  return out;
}

async function findWorker(
  cfg: SpectrumConfig,
  accountId: string,
  name: string,
  step: string,
): Promise<{ tag?: string } | null> {
  return cfCall(step, async () => {
    // One answer lists every Worker of the account (the list is not paged).
    const res = await cloudflareClient(cfg).workers.scripts.list({ account_id: accountId });
    const hit = res.result.find((w) => w.id === name);
    return hit ? { ...(hit.tag ? { tag: hit.tag } : {}) } : null;
  }, [cfg.apiToken]);
}

function ledgerIncomplete(step: string, what: string): EdgeProviderError {
  return fail(step, `ledger has no ${what}`, 'ledger_incomplete');
}

// --- the adapter -------------------------------------------------------------------------

export const spectrumProvider: EdgeProvider<SpectrumConfig, SpectrumTemplateParams> = {
  id: 'cloudflareSpectrum',
  templateSchema: SpectrumTemplate,
  templateFields: SPECTRUM_TEMPLATE_FIELDS,
  defaultTemplate: SpectrumTemplate.parse({}),

  /**
   * The token works, is active and reaches at least one zone, and can read
   * the Workers of that zone's account (the relay is uploaded there). Which
   * zone holds an application is a location's.
   */
  async testCredentials(cfg): Promise<CredentialTestResult> {
    const detail: string[] = [];
    let listing: ReturnType<typeof listZones> | undefined;
    const listOnce = () => (listing ??= listZones(cfg.apiToken, 'test', 1));
    try {
      const token = await verifyCloudflareToken(cfg, async () => {
        try {
          return (await listOnce()).zones[0]?.accountId || cfg.accountId || undefined;
        } catch (e) {
          if (cfg.accountId) return cfg.accountId;
          if (e instanceof EdgeProviderError && e.meta.retryable) throw e;
          return undefined;
        }
      });
      if (token.status !== 'active') return { ok: false, code: 'token_not_active' };
      detail.push(`token_${token.kind}`);
      const { zones } = await listOnce();
      if (zones.length === 0) return { ok: false, code: 'no_zones', detail: 'zones_none' };
      detail.push(`zones_${zones.length}`);
      const accountId = zones[0]?.accountId || cfg.accountId;
      if (accountId) {
        // Reading the account's Workers is what uploading one needs first.
        await cfCall(
          'test',
          () => cloudflareClient(cfg).workers.scripts.list({ account_id: accountId }),
          [cfg.apiToken],
        );
        detail.push('workers_readable');
      }
      return { ok: true, detail: detail.join(' ') };
    } catch (e) {
      return credentialTestFailure(e);
    }
  },

  /** A location is a zone: the token alone lists them. */
  async discoverOptions(partial): Promise<DiscoverResult> {
    const apiToken = typeof partial.apiToken === 'string' ? partial.apiToken : '';
    if (!apiToken) return {};
    try {
      const { zones, truncated } = await listZones(apiToken, 'zones');
      return {
        zones: zones.map((z) => ({
          id: z.id,
          label: z.name,
          facts: {
            status: z.paused ? 'paused' : z.status,
            ...(z.accountId ? { account: z.accountId } : {}),
          },
        })),
        ...(truncated ? { truncated: ['zones'] } : {}),
      };
    } catch (e) {
      const out: DiscoverResult = {};
      noteDiscoverError(out, 'zones', e);
      return out;
    }
  },

  /**
   * One location is one zone: the token reads it, it is active and not
   * paused, its name is still the one the location holds, and it is not on
   * the Free plan (which takes no Worker application). What it already holds
   * is reported, never refused: a zone's one Worker application may be this
   * location's own edge.
   */
  async checkLocation(cfg): Promise<LocationCheckResult> {
    const zone = await cfCall(
      'location',
      () => cloudflareClient(cfg).zones.get({ zone_id: cfg.zoneId }),
      [cfg.apiToken],
    );
    const name = String(zone.name ?? '')
      .toLowerCase()
      .replace(/\.$/, '');
    const plan = (zone.plan as { legacy_id?: string } | undefined)?.legacy_id;
    const observed: Record<string, string> = {
      ...(plan ? { zonePlan: plan } : {}),
      zoneStatus: zone.paused === true ? 'paused' : String(zone.status ?? 'unknown'),
    };
    const detail: string[] = [];
    const out = (code?: string): LocationCheckResult => ({
      ok: !code,
      ...(code ? { code } : {}),
      detail: detail.join(' '),
      observed,
      label: name,
      zoneName: name,
    });
    if (cfg.zoneName && name !== cfg.zoneName.toLowerCase().replace(/\.$/, ''))
      return out('zone_name_mismatch');
    if (zone.paused === true) return out('zone_paused');
    if (zone.status !== 'active') return out('zone_not_active');
    if (plan === 'free') return out('zone_plan_free');
    const workerApps = (await listApps(cfg, 'location')).filter(
      (a) => a.trafficType === 'worker',
    ).length;
    detail.push(`worker_apps_${workerApps}`);
    return out();
  },

  /** Pure: the Worker, then the application that forwards to it. */
  planProvision(_cfg, spec): ResourceStep[] {
    return [
      { id: 'worker', kind: 'create_worker', resourceName: spec.name, discoverability: 'by_name' },
      { id: 'app', kind: 'create_lb', resourceName: spec.name, discoverability: 'by_name' },
    ];
  },

  async runStep(cfg, step, spec, tpl, ledger): Promise<StepOutcome> {
    switch (step.kind) {
      case 'create_worker': {
        const { member } = onlyListener(spec, step.id);
        let accountId: string;
        let res: { tag?: string | null; handlers?: string[] | null };
        try {
          accountId = await zoneAccountId(cfg, step.id);
          const client = cloudflareClient(cfg);
          const form = spectrumWorkerUpload(member, tpl);
          // The SDK's own `workers.scripts.update` cannot send this: it forces
          // `Content-Type: application/javascript` over the multipart body
          // (Cloudflare then parses the whole body as one script: "Uncaught
          // SyntaxError ... at worker.js:1:4") and flattens `metadata` into
          // nested form fields. The raw request keeps the client's base URL
          // and auth, and `fetch` sets the multipart type and boundary.
          const answer = await cfCall(
            step.id,
            () =>
              client.put<{ result?: { tag?: string | null } | null }>(
                `/accounts/${accountId}/workers/scripts/${encodeURIComponent(step.resourceName)}`,
                { body: form },
              ),
            [cfg.apiToken],
          );
          res = answer?.result ?? {};
        } catch (e) {
          const refused = refusedCreate(e, 'create_refused');
          if (refused) return refused;
          throw e;
        }
        const tag =
          res.tag ?? (await findWorker(cfg, accountId, step.resourceName, step.id))?.tag ?? null;
        if (!tag) throw fail(step.id, 'worker has no tag', 'worker_tag_unknown');
        return {
          status: 'done',
          resources: [
            {
              kind: 'worker',
              resourceId: step.resourceName,
              ownership: 'created',
              meta: { accountId, tag, origin: `${member.address}:${member.port}` },
            },
          ],
        };
      }
      case 'create_lb': {
        const { edgePort } = onlyListener(spec, step.id);
        const worker = firstResource(ledger, 'worker');
        const tag = worker ? metaOf(worker).tag : undefined;
        if (!worker || typeof tag !== 'string') throw ledgerIncomplete(step.id, 'worker');
        const name = spectrumAppName(cfg, spec);
        let app: { id: string };
        try {
          app = await cfCall(
            step.id,
            () =>
              cloudflareClient(cfg).spectrum.apps.create(spectrumAppBody(cfg, name, edgePort, tag)),
            [cfg.apiToken],
          );
        } catch (e) {
          const refused = refusedCreate(e, 'create_refused');
          if (refused) return refused;
          throw e;
        }
        return {
          status: 'done',
          resources: [{ kind: 'lb', resourceId: app.id, ownership: 'created', meta: { name } }],
        };
      }
      default:
        throw fail(step.id, `unknown step kind ${step.kind}`, 'unknown_step');
    }
  },

  async discover(cfg, step, spec, ledger, attempt): Promise<Discovery> {
    const absent = (): Discovery =>
      discoveryMaySettle('cloudflareSpectrum', attempt, stepOf(ledger, step.id)?.startedAt)
        ? { status: 'confirmed_absent' }
        : { status: 'unresolved' };
    switch (step.kind) {
      case 'create_worker': {
        const accountId = await zoneAccountId(cfg, step.id);
        const hit = await findWorker(cfg, accountId, step.resourceName, step.id);
        if (!hit) return absent();
        // A Worker without a tag cannot be an application's origin: upload it again.
        if (!hit.tag) return { status: 'confirmed_absent' };
        const { member } = onlyListener(spec, step.id);
        return {
          status: 'found',
          resources: [
            {
              kind: 'worker',
              resourceId: step.resourceName,
              ownership: 'adopted',
              meta: { accountId, tag: hit.tag, origin: `${member.address}:${member.port}` },
            },
          ],
        };
      }
      case 'create_lb': {
        const apps = await listApps(cfg, step.id);
        const name = spectrumAppName(cfg, spec);
        const hits = apps.filter((a) => a.name === name);
        if (hits.length === 0) return absent();
        const candidates: ChildResource[] = hits.map((a) => ({
          kind: 'lb',
          resourceId: a.id,
          ownership: 'adopted',
          meta: { name: a.name },
        }));
        return hits.length === 1
          ? { status: 'found', resources: candidates }
          : { status: 'ambiguous', candidates };
      }
      default:
        return { status: 'confirmed_absent' };
    }
  },

  async describe(cfg, ledger): Promise<EdgeDescription> {
    const app = firstResource(ledger, 'lb');
    if (!app) return { state: 'pending', addresses: {}, health: 'unknown', code: 'no_app_yet' };
    let got: { dns?: { name?: string } | null };
    try {
      got = await cfCall(
        'describe',
        () => cloudflareClient(cfg).spectrum.apps.get(app.resourceId, { zone_id: cfg.zoneId }),
        [cfg.apiToken],
      );
    } catch (e) {
      if (isCloudflareNotFound(e)) return { state: 'gone', addresses: {}, health: 'unknown' };
      throw e;
    }
    const name = got.dns?.name ?? String(metaOf(app).name ?? '');
    if (!name) return { state: 'pending', addresses: {}, health: 'unknown', code: 'app_unnamed' };
    const addresses = await spectrumAddressesOf(name);
    // An application whose Worker is gone takes connections and fails every
    // one: never active, whatever its name resolves to.
    const origin = originWorkerStatusOf(got);
    if (origin === 'not_found')
      return { state: 'error', addresses, health: 'offline', code: 'worker_origin_missing' };
    if (origin !== undefined && origin !== 'available')
      return { state: 'pending', addresses, health: 'unknown', code: 'worker_origin_unknown' };
    // An IPv4 is what publishing needs; until DNS answers one the edge waits.
    return addresses.v4
      ? { state: 'active', addresses, health: 'unknown' }
      : { state: 'pending', addresses, health: 'unknown', code: 'addresses_not_resolved' };
  },

  async inspect(cfg, ledger) {
    const app = firstResource(ledger, 'lb');
    if (!app) throw ledgerIncomplete('inspect', 'application');
    const got = await cfCall(
      'inspect',
      () => cloudflareClient(cfg).spectrum.apps.get(app.resourceId, { zone_id: cfg.zoneId }),
      [cfg.apiToken],
    );
    const name = got.dns?.name ?? String(metaOf(app).name ?? '');
    const addresses = name ? await spectrumAddressesOf(name) : {};
    const worker = firstResource(ledger, 'worker');
    const origin = worker ? String(metaOf(worker).origin ?? '') : '';
    const sep = origin.lastIndexOf(':');
    const port = Number(origin.slice(sep + 1));
    const protocol = typeof got.protocol === 'string' ? got.protocol : '';
    const edgePort = Number(protocol.split('/')[1]);
    return {
      summary: {
        status: 'traffic_type' in got ? String(got.traffic_type) : undefined,
        region: 'anycast',
        createdAt: got.created_on,
        addresses,
        members: sep > 0 && Number.isInteger(port) ? [{ address: origin.slice(0, sep), port }] : [],
        listeners: Number.isInteger(edgePort) ? [{ port: edgePort, protocol: 'tcp' }] : [],
      },
      raw: got,
    };
  },

  /** A location's inventory: the zone's Spectrum applications (no addresses to own, no sizes). */
  async inventory(cfg) {
    const apps = await listApps(cfg, 'inventory');
    return {
      loadBalancers: apps.map((a) => ({
        id: a.id,
        name: a.name,
        ...(a.trafficType ? { status: a.trafficType } : {}),
        addresses: {},
        ...(a.createdOn ? { createdAt: a.createdOn } : {}),
      })),
      ips: [],
      flavors: [],
    };
  },

  /**
   * One size and no list price: what an edge costs is the zone's plan (Pro or
   * Business, a flat fee a month), Cloudflare's Spectrum add-on, whose price
   * is not published, and Workers usage (requests and CPU time, with no charge
   * for traffic). The operator sets the cost on the location.
   */
  async plans() {
    return [
      {
        size: 'worker-application',
        label: 'Spectrum application with a Worker origin',
        perHour: null,
        perMonth: null,
        currency: null,
        traffic: { kind: 'unknown' as const },
        bandwidthMbps: null,
        acceptsOutsideNode: true,
        source: 'catalog' as const,
        catalogAsOf: '2026-11-21',
      },
    ];
  },

  planDestroy: (_cfg, ledger): LedgerResource[] => orderByKind(ledger, SPECTRUM_DESTROY_ORDER),

  /**
   * Both deletes are synchronous and idempotent: a 404 is the confirmation.
   * The application goes first (it references the Worker). A kind this
   * adapter never creates stays `unresolved`.
   */
  async runDestroy(cfg, r) {
    try {
      if (r.kind === 'lb') {
        await cfCall(
          'destroy',
          () => cloudflareClient(cfg).spectrum.apps.delete(r.resourceId, { zone_id: cfg.zoneId }),
          [cfg.apiToken],
        );
        return { status: 'confirmed_gone' };
      }
      if (r.kind === 'worker') {
        const accountId = metaOf(r).accountId;
        if (typeof accountId !== 'string' || !accountId) return { status: 'unresolved' };
        await cfCall(
          'destroy',
          () =>
            cloudflareClient(cfg).workers.scripts.delete(r.resourceId, {
              account_id: accountId,
              force: true,
            }),
          [cfg.apiToken],
        );
        return { status: 'confirmed_gone' };
      }
    } catch (e) {
      if (isCloudflareNotFound(e)) return { status: 'confirmed_gone' };
      throw e;
    }
    return { status: 'unresolved' };
  },
};

/** The application references the Worker: it goes first. */
const SPECTRUM_DESTROY_ORDER = ['lb', 'worker'] as const;
