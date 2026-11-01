/**
 * Transport candidates with the origin probe applied (docs/edges.md § "Listener
 * catalogue", discovery): `GET origins/transport-candidates?backendServerId=&nodeUuid=`
 * lists the node's transports (`backends.listNodeInbounds`), maps them to listener
 * candidates (`mapTransportsToListeners`), then probes every HTTP-transport
 * candidate's origin (edgeOriginProbeOps.ts) and fills `originTransport` where
 * the probe succeeded, recomputing `layers`. Everything else stays L4-only and
 * carries the probe's reason. Read-only: nothing is registered here.
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import { capabilitiesOf } from './lib/backends/capabilities';
import {
  mapTransportsToListeners,
  type TransportCandidate,
  type UnsupportedInbound,
} from './lib/edges/inboundMapping';
import { listenerLayers, type OriginTransport } from './lib/edges/layers';
import type { OriginProbeOutcome } from './lib/edges/originProbe';
import { protocolIsHttpTransport } from './lib/edges/protocols';
import { listenersOf } from './relayListeners';
import { enrolledOriginOf, withVerifiedIngress } from './nodeIntents';
import { websocketNodeOf } from './lib/edges/websocketNode';

export interface ProbedInboundCandidate extends TransportCandidate {
  originTransport: OriginTransport | null;
  /** The probe's verdict for an HTTP-transport candidate; null when none was needed. */
  probe: { ok: boolean; reason: string | null } | null;
}

export interface InboundCandidatesResult {
  node: { nodeUuid: string; name: string; address: string | null };
  originAddress: string;
  relaySlug: string | null;
  candidates: ProbedInboundCandidate[];
  unsupported: UnsupportedInbound[];
  probedAt: string;
}

export const nodeContext = internalQuery({
  args: { backendServerId: v.id('backendServers'), nodeUuid: v.string() },
  handler: async (ctx, { backendServerId, nodeUuid }) => {
    const server = await ctx.db.get(backendServerId);
    if (!server) throw new ConvexError({ code: 'backend.not_found', message: 'Backend not found' });
    if (!capabilitiesOf(server.backend).inboundDiscovery)
      throw new ConvexError({
        code: 'backend.inbounds_unsupported',
        message: 'This backend does not list node transports',
      });
    const rows = await ctx.db
      .query('backendNodeInventory')
      .withIndex('by_server', (q) => q.eq('backendServerId', backendServerId))
      .collect();
    const node = rows.find((r) => r.nodeUuid === nodeUuid) ?? null;
    if (!node)
      throw new ConvexError({
        code: 'edge.node_unknown',
        message: 'The node is not in the backend inventory; refresh the node list first',
      });
    // An existing origin on the node names the origin address and the keys already taken.
    const relay = await ctx.db
      .query('relays')
      .withIndex('by_node', (q) =>
        q.eq('backendServerId', backendServerId).eq('nodeName', node.name),
      )
      .first();
    const existingKeys = relay
      ? (await listenersOf(ctx, relay._id)).filter((l) => !l.retired).map((l) => l.listenerKey)
      : [];
    // An enrolled node's origin and ingress come from its intent (the
    // backend's node row holds the management address).
    const enrolled = await enrolledOriginOf(ctx, backendServerId, node.name);
    const originAddress = relay?.originAddress ?? enrolled?.originAddress ?? node.address ?? null;
    if (!originAddress)
      throw new ConvexError({
        code: 'edge.node_address_unknown',
        message: 'The backend reports no address for this node',
      });
    return {
      node: { nodeUuid: node.nodeUuid, name: node.name, address: node.address ?? null },
      originAddress,
      existingKeys,
      relaySlug: relay?.slug ?? null,
      ingress: enrolled?.ingress ?? null,
      enrolled: enrolled ? { acceptsAnyHost: enrolled.acceptsAnyHost } : null,
      websocketNode: await websocketNodeOf(ctx.db, {
        kind: 'panel-node',
        backendServerId,
        nodeName: node.name,
      }),
    };
  },
});

/** The HTTP-transport candidates the origin probe must look at (pure; shared with the setup plan). */
export function originProbeTargets(
  candidates: readonly TransportCandidate[],
  originAddress: string,
) {
  return candidates
    .filter((cand) => protocolIsHttpTransport(cand.listenerSpec))
    .map((cand) => ({
      listenerKey: cand.listenerSpec.listenerKey,
      originAddress,
      originPort: cand.listenerSpec.originPort,
      streamTransport: cand.listenerSpec.streamTransport,
      security: cand.listenerSpec.security,
      tlsNames: cand.listenerSpec.tlsNames ?? [],
      // A WebSocket / HTTP Upgrade transport's Host answer is asked at its own
      // path, with its own upgrade token.
      ...(cand.listenerSpec.transportParams?.path
        ? { path: cand.listenerSpec.transportParams.path }
        : {}),
      ...(cand.listenerSpec.transportParams?.upgradeToken
        ? { upgradeToken: cand.listenerSpec.transportParams.upgradeToken }
        : {}),
    }));
}

/**
 * Fold the probe outcomes back into the candidates: `originTransport` on the
 * spec where the probe succeeded and the layers recomputed from it (pure;
 * shared with the setup plan so a WS / HTTP-upgrade / gRPC origin can be
 * offered an L7 account through the guided flow too). A WebSocket node's
 * HTTP transports are never L4-frontable (lib/edges/websocketNode.ts), and
 * `originAddress` (what fronts dial) decides whether a node that answers only
 * for its own names can be sent that name (lib/edges/layers.ts).
 */
export function applyOriginProbes(
  candidates: readonly TransportCandidate[],
  outcomes: readonly OriginProbeOutcome[],
  opts: { websocketNode?: boolean; originAddress?: string } = {},
): ProbedInboundCandidate[] {
  const byKey = new Map(outcomes.map((o) => [o.listenerKey, o]));
  return candidates.map((cand) => {
    const o = byKey.get(cand.listenerSpec.listenerKey) ?? null;
    const originTransport = o?.originTransport ?? null;
    const spec = originTransport ? { ...cand.listenerSpec, originTransport } : cand.listenerSpec;
    return {
      ...cand,
      listenerSpec: spec,
      originTransport,
      probe: o ? { ok: !!o.originTransport, reason: o.reason ?? null } : null,
      layers: listenerLayers(
        {
          protocol: spec.protocol,
          streamTransport: spec.streamTransport,
          security: spec.security,
          tlsNames: (spec.tlsNames ?? []).map((name) => ({ name, status: 'active' as const })),
          originTransport,
        },
        { websocketNode: opts.websocketNode, originAddress: opts.originAddress },
      ),
    };
  });
}

export const inboundCandidates = internalAction({
  args: { backendServerId: v.id('backendServers'), nodeUuid: v.string() },
  handler: async (ctx, { backendServerId, nodeUuid }): Promise<InboundCandidatesResult> => {
    const c = await ctx.runQuery(internal.edgeOriginProbe.nodeContext, {
      backendServerId,
      nodeUuid,
    });
    const inbounds = await ctx.runAction(internal.backends.listNodeInbounds, {
      backendServerId,
      nodeUuid,
    });
    const mapped = await mapTransportsToListeners(inbounds, {
      existingKeys: c.existingKeys,
      origin: { kind: 'panel-node', backendServerId, nodeName: c.node.name, nodeUuid },
      ingress: c.ingress,
    });
    const targets = originProbeTargets(mapped.candidates, c.originAddress);
    const outcomes: OriginProbeOutcome[] =
      targets.length > 0 ? await ctx.runAction(internal.edgeOriginProbeOps.probe, { targets }) : [];
    const candidates = applyOriginProbes(
      mapped.candidates,
      withVerifiedIngress(outcomes, c.enrolled),
      { websocketNode: c.websocketNode, originAddress: c.originAddress },
    );
    return {
      node: c.node,
      originAddress: c.originAddress,
      relaySlug: c.relaySlug,
      candidates,
      unsupported: mapped.unsupported,
      probedAt: new Date().toISOString(),
    };
  },
});
