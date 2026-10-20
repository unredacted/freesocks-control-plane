/**
 * The provider facts the admin console needs to render an edge, mirrored from
 * `convex/lib/edges/providers/capabilities.ts` (the SPA cannot import convex/).
 * Presentation only: what to call a provider, whether its edges are addressed
 * by IP literal or by hostname, and which HTTP transports an L7 front carries.
 * Every decision that costs money or changes state is still the server's.
 *
 * `edgeProviderMeta.test.ts` pins the record against EDGE_PROVIDER_IDS so a new
 * provider id fails to compile until it has an entry here too.
 */
import {
  type EdgeLayer,
  type EdgeProviderId,
  type ListenerStreamTransport,
} from '../../shared/contracts/edges';

export type EdgeAddressKind = 'ip' | 'hostname';
/**
 * What an account of the provider is for (`role` in capabilities.ts): `edge`
 * fronts member traffic, `dns` holds the records FCP writes for L7 fronts and
 * fronts nothing unless Settings lets DNS accounts front.
 */
export type EdgeProviderRole = 'edge' | 'dns';

export interface EdgeProviderMeta {
  /** What an operator calls the provider (the id stays the wire value). */
  label: string;
  layer: EdgeLayer;
  role: EdgeProviderRole;
  addressKind: EdgeAddressKind;
  /** HTTP-carried protocols this front can carry; empty for an L4 forwarder. */
  l7Transports: readonly ListenerStreamTransport[];
  /** The account needs a DNS account of another provider (Fastly → Cloudflare). */
  needsDnsAccount: boolean;
  /** The account can host DNS records for other providers' edges. */
  providesDns: boolean;
}

const L4 = {
  layer: 'l4',
  role: 'edge',
  addressKind: 'ip',
  l7Transports: [],
  needsDnsAccount: false,
  providesDns: false,
} as const satisfies Omit<EdgeProviderMeta, 'label'>;

export const EDGE_PROVIDER_META: Record<EdgeProviderId, EdgeProviderMeta> = {
  gcore: { ...L4, label: 'Gcore' },
  upcloud: { ...L4, label: 'UpCloud' },
  scaleway: { ...L4, label: 'Scaleway' },
  ovh: { ...L4, label: 'OVHcloud' },
  cloudflare: {
    label: 'Cloudflare',
    layer: 'l7',
    role: 'dns',
    addressKind: 'hostname',
    l7Transports: ['ws', 'httpupgrade', 'grpc', 'xhttp'],
    needsDnsAccount: false,
    providesDns: true,
  },
  fastly: {
    label: 'Fastly',
    layer: 'l7',
    role: 'edge',
    addressKind: 'hostname',
    l7Transports: ['ws'],
    needsDnsAccount: true,
    providesDns: false,
  },
};

/** What a DNS account does, in one sentence (picker, account form, badges). */
export const DNS_ACCOUNT_BLURB =
  'A DNS account holds the records FCP writes for L7 fronts (their certificate challenge and traffic name), never member traffic.';

/** The provider picker's groups, in order: what each kind of account is for. */
export type ProviderGroupId = 'l4' | 'l7' | 'dns';

export interface ProviderGroup {
  id: ProviderGroupId;
  title: string;
  /** One sentence: what an account of this group does. */
  blurb: string;
  providers: EdgeProviderId[];
}

/** Which picker group a provider sits in: its role first, then its layer. */
export function providerGroupOf(id: EdgeProviderId): ProviderGroupId {
  const m = EDGE_PROVIDER_META[id];
  return m.role === 'dns' ? 'dns' : m.layer;
}

/**
 * L4 edge providers, L7 edge providers, DNS providers. A DNS provider is listed
 * ONLY as one (its own layer is what it would front with, if ever allowed).
 * More DNS-only providers are a future group member, not a new group.
 */
export function providerGroups(ids: readonly EdgeProviderId[]): ProviderGroup[] {
  const groups: ProviderGroup[] = [
    {
      id: 'l4',
      title: 'L4 edge providers',
      blurb: 'Load balancers that forward member connections to the node by address.',
      providers: [],
    },
    {
      id: 'l7',
      title: 'L7 edge providers',
      blurb:
        'CDN fronts that carry HTTP transports by hostname. They need a DNS account for their names.',
      providers: [],
    },
    {
      id: 'dns',
      title: 'DNS providers',
      blurb: DNS_ACCOUNT_BLURB,
      providers: [],
    },
  ];
  for (const id of ids) groups.find((g) => g.id === providerGroupOf(id))!.providers.push(id);
  return groups;
}

/** The DNS providers FCP supports today, by name ("Cloudflare"). */
export function dnsProviderNames(ids: readonly EdgeProviderId[]): string[] {
  return ids
    .filter((id) => EDGE_PROVIDER_META[id].role === 'dns')
    .map((id) => EDGE_PROVIDER_META[id].label);
}

/**
 * One line for an edge's addresses: the fronted hostname when there is one,
 * otherwise the IP literals. `-` when the edge has no address yet.
 */
export function addressLine(
  addresses: { v4?: string | null; v6?: string | null; hostname?: string | null },
  separator = ' · ',
): string {
  if (addresses.hostname) return addresses.hostname;
  const parts = [addresses.v4, addresses.v6].filter((x): x is string => !!x);
  return parts.length > 0 ? parts.join(separator) : '-';
}
