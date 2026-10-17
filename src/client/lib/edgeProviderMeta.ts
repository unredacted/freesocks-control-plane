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

export interface EdgeProviderMeta {
  /** What an operator calls the provider (the id stays the wire value). */
  label: string;
  layer: EdgeLayer;
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
    addressKind: 'hostname',
    l7Transports: ['ws', 'httpupgrade', 'grpc', 'xhttp'],
    needsDnsAccount: false,
    providesDns: true,
  },
  fastly: {
    label: 'Fastly',
    layer: 'l7',
    addressKind: 'hostname',
    l7Transports: ['ws'],
    needsDnsAccount: true,
    providesDns: false,
  },
};

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
