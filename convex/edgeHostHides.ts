// STUB: merged with agent H (the hide ledger owns this module; only `observe`
// is provided here so the rehearsal can take its before/after Host listings).
/**
 * `observe`: a fresh listing of the panel Hosts that matter for one relay's
 * node (its FCP relay Hosts and the Hosts of its listeners' inbounds, with
 * their `isDisabled` bits), hashed so two listings can be compared for
 * identity. The rehearsal (edgeRehearsal.ts) takes one BEFORE and one AFTER
 * and repeats when they differ.
 */
import { v } from 'convex/values';
import { internalAction, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import { capabilitiesOf } from './lib/backends/capabilities';
import { sha256Hex } from './lib/crypto';
import { relayRemarkRegex, sameAddress } from './lib/edges/hosts';
import { listenersOf } from './relayListeners';

export interface DirectHost {
  uuid: string;
  remark: string;
  inboundUuid: string;
  address: string;
  port: number;
  sni: string | null;
  host: string | null;
  isDisabled: boolean;
}

export interface HostObservation {
  listingHash: string;
  observedAt: number;
  direct: { covered: DirectHost[]; uncovered: DirectHost[] };
}

export const observeContext = internalQuery({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay || !relay.backendServerId) return null;
    const server = await ctx.db.get(relay.backendServerId);
    // A backend without Hosts (Outline) has nothing to observe.
    if (!server || !capabilitiesOf(server.backend).hostManagement) return null;
    const listeners = (await listenersOf(ctx, relayId)).filter((l) => !l.retired);
    return {
      backendServerId: relay.backendServerId,
      nodeName: relay.nodeName ?? null,
      originAddress: relay.originAddress,
      inboundUuids: listeners
        .map((l) => l.panelBinding?.configProfileInboundUuid.toLowerCase() ?? '')
        .filter(Boolean),
      fcpUuids: listeners.map((l) => l.host?.uuid ?? '').filter(Boolean),
      legacyUuids: listeners.flatMap((l) => (l.legacyHosts ?? []).map((h) => h.uuid)),
    };
  },
});

export const observe = internalAction({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }): Promise<HostObservation> => {
    const c = await ctx.runQuery(internal.edgeHostHides.observeContext, { relayId });
    const observedAt = Date.now();
    if (!c) return { listingHash: 'none', observedAt, direct: { covered: [], uncovered: [] } };
    const hosts = await ctx.runAction(internal.backends.listHosts, {
      backendServerId: c.backendServerId,
    });
    const remarkRe = c.nodeName ? relayRemarkRegex(c.nodeName) : null;
    const inbounds = new Set(c.inboundUuids);
    const relevant = hosts.filter((h) => {
      const ib = (h.inbound?.configProfileInboundUuid ?? '').toLowerCase();
      return (remarkRe?.test(h.remark) ?? false) || inbounds.has(ib);
    });
    const lines = relevant
      .map((h) => `${h.uuid}|${h.remark}|${h.address}|${h.port}|${h.isDisabled ? 1 : 0}`)
      .sort();
    const uncovered: DirectHost[] = relevant
      .filter(
        (h) =>
          !h.isDisabled &&
          !(remarkRe?.test(h.remark) ?? false) &&
          !c.fcpUuids.includes(h.uuid) &&
          !c.legacyUuids.includes(h.uuid) &&
          sameAddress(h.address, c.originAddress),
      )
      .map((h) => ({
        uuid: h.uuid,
        remark: h.remark,
        inboundUuid: h.inbound?.configProfileInboundUuid ?? '',
        address: h.address,
        port: h.port,
        sni: h.sni ?? null,
        host: h.host ?? null,
        isDisabled: h.isDisabled,
      }));
    return {
      listingHash: await sha256Hex(lines.join('\n')),
      observedAt,
      direct: { covered: [], uncovered },
    };
  },
});
