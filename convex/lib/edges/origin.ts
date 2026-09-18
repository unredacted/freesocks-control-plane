/**
 * Relay ORIGIN helpers (pure). A relay's origin is one of three kinds:
 *
 *   panel-node      a node on a Remnawave-style panel FCP knows: FCP can pin
 *                   subscriptions to it and, when the backend has Host
 *                   management, own its client-facing Hosts (`hostMode: fcp`).
 *   backend-server  a whole backend server (an Outline instance): FCP renders
 *                   its subscriptions by address rewrite; there is no Host.
 *   manual          an address the operator described by hand: FCP provisions,
 *                   publishes, probes and rotates edges for it and hands the
 *                   operator a connection plan; nothing FCP serves maps to it.
 */
import type { Id } from '../../_generated/dataModel';
import type { BackendCapabilities } from '../backends/capabilities';

export type RelayOrigin =
  | {
      kind: 'panel-node';
      backendServerId: Id<'backendServers'>;
      nodeName: string;
      nodeUuid?: string;
    }
  | { kind: 'backend-server'; backendServerId: Id<'backendServers'> }
  | { kind: 'manual' };

export type RelayOriginKind = RelayOrigin['kind'];
export type HostMode = 'fcp' | 'operator' | 'none';

export function originBackendServerId(o: RelayOrigin): Id<'backendServers'> | undefined {
  return o.kind === 'manual' ? undefined : o.backendServerId;
}

export function originNodeName(o: RelayOrigin): string | undefined {
  return o.kind === 'panel-node' ? o.nodeName : undefined;
}

/**
 * Who writes the client-facing Hosts. Only a panel node on a backend with Host
 * management can hand them to FCP; every other kind has no Host at all.
 */
export function deriveHostMode(o: RelayOrigin, caps: BackendCapabilities | null): HostMode {
  if (o.kind === 'panel-node' && caps?.hostManagement) return 'fcp';
  return 'none';
}

/** Whether a requested hostMode is possible for this origin. */
export function hostModeAllowed(o: RelayOrigin, caps: BackendCapabilities | null, m: HostMode) {
  if (m === 'none') return deriveHostMode(o, caps) === 'none';
  return o.kind === 'panel-node' && !!caps?.hostManagement;
}

/** Whether subscriptions can render for this origin (a body FCP serves maps to it). */
export function originRenders(o: RelayOrigin): boolean {
  return o.kind !== 'manual';
}

/** Whether the detector has a node-online / load signal for this origin. */
export function originHasNodeSignal(o: RelayOrigin, caps: BackendCapabilities | null): boolean {
  return o.kind === 'panel-node' && !!caps?.nodeInventory;
}

/** Audit-safe description: kind + which backend, never the address. */
export function describeOrigin(o: RelayOrigin): {
  kind: RelayOriginKind;
  backendServerId?: string;
} {
  const id = originBackendServerId(o);
  return id ? { kind: o.kind, backendServerId: id as string } : { kind: o.kind };
}

/** Two origins name the same place (the one-relay-per-node / per-server rule). */
export function sameOriginKey(a: RelayOrigin, b: RelayOrigin): boolean {
  if (a.kind !== b.kind) return false;
  if (a.kind === 'manual') return false;
  if (a.kind === 'panel-node' && b.kind === 'panel-node')
    return a.backendServerId === b.backendServerId && a.nodeName === b.nodeName;
  return originBackendServerId(a) === originBackendServerId(b);
}
