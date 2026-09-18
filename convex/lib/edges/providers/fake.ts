/**
 * DEV-ONLY fake edge provider: lets the whole setup flow (account → template →
 * relay → provision → qualify → publish → render) be walked locally without any
 * cloud credentials. Enabled ONLY when BOTH `ENVIRONMENT=development` and
 * `DEV_FAKE_EDGE_PROVIDER=true` are set on the deployment (the lib/backends/
 * mock.ts double gate); the registry then hands the fake out in place of ONE
 * real adapter per layer (`upcloud` for L4, `cloudflare` for L7), so the schema
 * unions, capability rows and provider ids stay untouched and nothing about the
 * fake can leak into a production bundle path. The fake never appears in
 * `EDGE_PROVIDER_IDS` and never in the wire contracts.
 *
 * Deterministic: addresses are RFC 5737 / RFC 3849 literals derived from the
 * resource name, hostnames live under `edge.example`. Every "call" records
 * itself in `calls` (in memory) so tests and the live view have something to
 * show. Creates are instant; a `slowMs` knob (env `DEV_FAKE_EDGE_SLOW_MS`)
 * delays them to exercise the async paths.
 */
import type { EdgeProviderId } from '../../edgeProviderIds';
import type {
  Discovery,
  DestroyOutcome,
  EdgeDescription,
  EdgeProvider,
  EdgeProviderConfig,
  EdgeSpec,
  InspectResult,
  Inventory,
  Ledger,
  LedgerResource,
  ResourceStep,
  StepOutcome,
} from './types';
import type { EdgeLayer } from './capabilities';

export const FAKE_L4_SHADOW: EdgeProviderId = 'upcloud';
export const FAKE_L7_SHADOW: EdgeProviderId = 'cloudflare';

export function fakeEdgeProviderEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.ENVIRONMENT === 'development' && env.DEV_FAKE_EDGE_PROVIDER === 'true';
}

/** The ids the fake shadows when enabled. */
export function fakeShadowedIds(env: NodeJS.ProcessEnv = process.env): EdgeProviderId[] {
  return fakeEdgeProviderEnabled(env) ? [FAKE_L4_SHADOW, FAKE_L7_SHADOW] : [];
}

function fnv1a32(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/** A stable RFC 5737 (TEST-NET-2) literal for a resource name. */
export function fakeV4For(name: string): string {
  return `198.51.100.${(fnv1a32(name) % 250) + 2}`;
}
/** A stable RFC 3849 literal for a resource name. */
export function fakeV6For(name: string): string {
  return `2001:db8:fa4e::${(fnv1a32(name) % 0xfffe) + 1}`;
}

export interface FakeCall {
  at: number;
  op: string;
  name?: string;
}

export interface FakeState {
  calls: FakeCall[];
  /** Resource name → live record. */
  resources: Map<
    string,
    { kind: string; id: string; addresses: { v4?: string; v6?: string; hostname?: string } }
  >;
}

const STATE: FakeState = { calls: [], resources: new Map() };

/** Test/dev seam: inspect or reset the fake's in-memory state. */
export function __fakeEdgeState(): FakeState {
  return STATE;
}
export function __resetFakeEdgeState(): void {
  STATE.calls.length = 0;
  STATE.resources.clear();
}

function record(op: string, name?: string) {
  STATE.calls.push({ at: Date.now(), op, name });
  if (STATE.calls.length > 200) STATE.calls.splice(0, STATE.calls.length - 200);
}

/**
 * Build the fake for one shadowed adapter. The template schema, field
 * descriptors and defaults are the REAL adapter's, so the CMS form and the
 * template validation behave exactly as they would with the real provider.
 */
export function fakeEdgeProvider<Cfg extends EdgeProviderConfig, Tpl>(
  real: EdgeProvider<Cfg, Tpl>,
  layer: EdgeLayer,
): EdgeProvider<Cfg, Tpl> {
  const kind = layer === 'l7' ? 'create_dns_record' : 'create_lb';
  const childKind = layer === 'l7' ? 'dns_record' : 'lb';
  const addressesFor = (spec: EdgeSpec) =>
    layer === 'l7'
      ? { hostname: spec.hostname ?? `${spec.name}.edge.example` }
      : { v4: fakeV4For(spec.name), v6: fakeV6For(spec.name) };
  const live = (ledger: Ledger) => {
    const r = ledger.resources.find(
      (x) => x.kind === childKind && x.deleteState !== 'confirmed_gone',
    );
    return r ? STATE.resources.get(r.resourceId) : undefined;
  };
  return {
    id: real.id,
    templateSchema: real.templateSchema,
    templateFields: real.templateFields,
    defaultTemplate: real.defaultTemplate,
    async testCredentials() {
      record('testCredentials');
      return layer === 'l7'
        ? { ok: true, observed: { zoneSslMode: 'full', zoneWebsockets: 'on' } }
        : { ok: true };
    },
    async discoverOptions() {
      record('discoverOptions');
      return layer === 'l7'
        ? {
            zones: [{ id: 'zone1234', label: 'edge.example' }],
            tlsConfigurations: [{ id: 'tls-1', label: 'default' }],
          }
        : {
            projects: [{ id: 'proj-1', label: 'Fake project' }],
            regions: [{ id: 'zone-1', label: 'Fake region' }],
          };
    },
    planProvision(_cfg, spec) {
      record('planProvision', spec.name);
      return [
        { id: 's1', kind, resourceName: spec.name, discoverability: 'by_name' },
      ] as ResourceStep[];
    },
    async runStep(_cfg, step, spec): Promise<StepOutcome> {
      record('runStep', spec.name);
      const slow = Number(process.env.DEV_FAKE_EDGE_SLOW_MS ?? '0');
      if (slow > 0) await new Promise((r) => setTimeout(r, Math.min(slow, 10_000)));
      const id = `fake-${childKind}-${fnv1a32(spec.name).toString(16)}`;
      const addresses = addressesFor(spec);
      STATE.resources.set(id, { kind: childKind, id, addresses });
      return {
        status: 'done',
        resources: [
          {
            kind: childKind,
            resourceId: id,
            ownership: 'created',
            meta: { name: step.resourceName },
          },
        ],
        addresses,
      };
    },
    async discover(_cfg, _step, spec): Promise<Discovery> {
      record('discover', spec.name);
      const id = `fake-${childKind}-${fnv1a32(spec.name).toString(16)}`;
      const r = STATE.resources.get(id);
      if (!r) return { status: 'confirmed_absent' };
      return {
        status: 'found',
        resources: [{ kind: childKind, resourceId: id, ownership: 'created' }],
        addresses: r.addresses,
      };
    },
    async describe(_cfg, ledger): Promise<EdgeDescription> {
      record('describe');
      const r = live(ledger);
      if (!r) return { state: 'gone', addresses: {}, health: 'unknown', code: 'not_found' };
      return {
        state: 'active',
        addresses: r.addresses,
        health: layer === 'l7' ? 'unknown' : 'online',
        ...(layer === 'l7' ? { readiness: { dns: 'ready', certificate: 'ready' } } : {}),
      };
    },
    async inspect(_cfg, ledger): Promise<InspectResult> {
      record('inspect');
      const r = live(ledger);
      return {
        summary: {
          status: r ? 'ready' : 'gone',
          operatingStatus: r ? 'online' : 'gone',
          flavor: 'fake',
          region: 'fake-region',
          addresses: r?.addresses ?? {},
          members: [],
          listeners: [{ port: 443, protocol: 'tcp' }],
        },
        raw: { fake: true, calls: STATE.calls.length },
      };
    },
    async inventory(): Promise<Inventory> {
      record('inventory');
      return {
        loadBalancers: [...STATE.resources.values()].map((r) => ({
          id: r.id,
          name: r.id,
          status: 'ready',
          addresses: r.addresses,
        })),
        ips: [],
        flavors: [{ id: 'fake', label: 'Fake flavor' }],
      };
    },
    planDestroy(_cfg, ledger) {
      return ledger.resources.filter((r) => r.deleteState !== 'confirmed_gone');
    },
    async runDestroy(_cfg, r: LedgerResource): Promise<DestroyOutcome> {
      record('runDestroy', r.resourceId);
      STATE.resources.delete(r.resourceId);
      return { status: 'confirmed_gone' };
    },
  };
}
