'use node';
/**
 * `POST sni/transports/manage` (docs/edges.md "A transport's names"). A dry run
 * resolves the transport's target the way qualification does (every answer
 * public) and suggests the one network holding the target and every address
 * in use on the transport: a family on a network fails every name whose
 * target is off it, so no network is suggested from the addresses alone.
 *
 * The real call is one mutation (`sniTransports.manage`: a family, bound, the
 * transport's names taken in), then, with finding names on, one read of the
 * target's certificate so suggestions arrive (`sniHuntOps.readCert`, the same
 * single handshake as its own route). Nothing reaches the backend here.
 */
import { v } from 'convex/values';
import { internalAction } from './_generated/server';
import { internal } from './_generated/api';
import { suggestNetwork } from './lib/edges/sni/delivery';
import { dialAddress } from './sniQualifyOps';
import { onNetworkOf } from './sniTransports';

interface ManageDeps {
  lookup?: (name: string) => Promise<string[]>;
}
let deps: ManageDeps = {};

/** Test seam: the resolver the dry run uses. */
export function __setManageDepsForTests(d: ManageDeps | null): void {
  deps = d ?? {};
}

type CertRead = { ok: true; listed: number } | { ok: false; code?: string | null };

export const manage = internalAction({
  args: {
    backendSlug: v.string(),
    transportUuid: v.string(),
    dryRun: v.optional(v.boolean()),
    family: v.optional(v.string()),
    network: v.optional(v.union(v.string(), v.null())),
    label: v.optional(v.string()),
    requireH2: v.optional(v.boolean()),
    nodeUuid: v.optional(v.string()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a): Promise<Record<string, unknown>> => {
    if (a.dryRun) {
      const c = await ctx.runQuery(internal.sniTransports.manageContext, {
        backendSlug: a.backendSlug,
        transportUuid: a.transportUuid,
      });
      const at = await dialAddress(c.target.address, deps.lookup);
      const network = at.ok ? suggestNetwork(at.all, c.addresses, c.networks, onNetworkOf) : null;
      return {
        dryRun: true,
        coverSite: c.coverSite,
        resolved: at.ok,
        network: network ? { slug: network.slug, label: network.label } : null,
        label: `${c.tag} names`,
      };
    }
    const done = await ctx.runMutation(internal.sniTransports.manage, {
      backendSlug: a.backendSlug,
      transportUuid: a.transportUuid,
      ...(a.family ? { family: a.family } : {}),
      ...(a.network !== undefined ? { network: a.network } : {}),
      ...(a.label !== undefined ? { label: a.label } : {}),
      ...(a.requireH2 !== undefined ? { requireH2: a.requireH2 } : {}),
      ...(a.nodeUuid ? { nodeUuid: a.nodeUuid } : {}),
      ...(a.actorAdminId ? { actorAdminId: a.actorAdminId } : {}),
    });
    // Suggestions come from the target's own certificate first.
    const { hunt } = await ctx.runQuery(internal.sniFamilies.configView, {});
    let cert: CertRead | null = null;
    if (hunt.enabled)
      try {
        cert = (await ctx.runAction(internal.sniHuntOps.readCert, {
          slug: done.family,
          ...(a.actorAdminId ? { actorAdminId: a.actorAdminId } : {}),
        })) as CertRead;
      } catch {
        // The names are managed either way; the certificate can be read again from the list.
        cert = { ok: false, code: null };
      }
    return { dryRun: false, ...done, cert };
  },
});
