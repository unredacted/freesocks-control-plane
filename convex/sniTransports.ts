/**
 * A backend's REALITY transports and their names, as a node's page shows them
 * (docs/edges.md "A transport's names"): for each transport, whether FCP
 * manages its names, where each name stands on its way to members
 * (`lib/edges/sni/delivery.ts`), what each node behind it lacks, and the
 * switches that hold a step back. And managing a transport's names in one call:
 * a family with the transport's own target, bound with the names it lists now.
 *
 * Reads and writes nothing a family page or a binding does not already; the
 * steps after it (rollout, test link, receipt) are the existing routes.
 * Audit payloads carry slugs and counts only, never a hostname.
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery, type QueryCtx } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { parseRealityTarget } from './lib/edges/inboundMapping';
import { onNetwork, hasPrefixes } from './lib/edges/networks';
import { sameTarget } from './lib/edges/sni/family';
import {
  countDeliveries,
  familySlugForTransport,
  nameDelivery,
  nodeCounts,
  placeFromNode,
  type DeliveryName,
} from './lib/edges/sni/delivery';
import { verificationCurrent } from './lib/edges/verification';
import { verificationListenersOf } from './lib/edges/verificationContext';
import { resolveServerConfig } from './lib/serverConfig';
import { resolveSniConfig, resolveSniHuntConfig } from './lib/sniConfig';
import { bindFamily, insertFamily } from './sniFamilies';
import { fcpWrites } from './backendSetup';
import { familyUsable } from './lib/edges/sni/hunt/store';
import { hostPort } from './lib/edges/ip';

const refuse = (code: string, message: string): never => {
  throw new ConvexError({ code, message });
};
const actor = { actorAdminId: v.optional(v.id('adminUsers')) };

async function serverBySlug(db: QueryCtx['db'], slug: string) {
  const s = await db
    .query('backendServers')
    .withIndex('by_slug', (q) => q.eq('slug', slug))
    .unique();
  return s ?? refuse('not_found', 'Backend server not found');
}

/** Non-retired listeners of the backend, with their origin, grouped by transport. */
async function listenersByTransport(db: QueryCtx['db'], serverId: Id<'backendServers'>) {
  const out = new Map<string, { relay: Doc<'relays'>; listener: Doc<'relayListeners'> }[]>();
  for (const relay of await db
    .query('relays')
    .withIndex('by_backend_server', (q) => q.eq('backendServerId', serverId))
    .collect())
    for (const listener of await db
      .query('relayListeners')
      .withIndex('by_relay', (q) => q.eq('relayId', relay._id))
      .collect()) {
      const uuid = listener.panelBinding?.configProfileInboundUuid;
      if (listener.retired || !uuid) continue;
      out.set(uuid, [...(out.get(uuid) ?? []), { relay, listener }]);
    }
  return out;
}

const deliveryName = (n: Doc<'sniNames'>): DeliveryName => ({
  name: n.name,
  status: n.status,
  qualification: n.qualification.state,
});

/** The newest rollout of a binding, and the names a test can prove with it. */
async function newestRollout(db: QueryCtx['db'], bindingId: Id<'sniInboundBindings'>) {
  const rollouts = await db
    .query('sniRollouts')
    .withIndex('by_binding', (q) => q.eq('bindingId', bindingId))
    .collect();
  const r = rollouts.sort((x, y) => y.generation - x.generation)[0] ?? null;
  return {
    rollout: r,
    provable: new Set(r?.phase === 'panel_confirmed' ? r.names : []),
  };
}

/**
 * `GET sni/transports?backend=<slug>`: every REALITY transport of the backend
 * as Servers last read it, with its names' standing and what each node behind
 * it (each protected listener) lacks.
 */
export const status = internalQuery({
  args: { backendSlug: v.string() },
  handler: async (ctx, { backendSlug }) => {
    const server = await serverBySlug(ctx.db, backendSlug);
    const sni = await resolveSniConfig(ctx.db);
    const hunt = await resolveSniHuntConfig(ctx.db);
    const servers = await resolveServerConfig(ctx.db);
    const setup = await ctx.db
      .query('panelSetups')
      .withIndex('by_server', (q) => q.eq('backendServerId', server._id))
      .first();
    const profiles = await ctx.db
      .query('panelProfiles')
      .withIndex('by_server', (q) => q.eq('backendServerId', server._id))
      .collect();
    const panelNodes = await ctx.db
      .query('panelNodes')
      .withIndex('by_server', (q) => q.eq('backendServerId', server._id))
      .collect();
    const bindings = await ctx.db
      .query('sniInboundBindings')
      .withIndex('by_server_inbound', (q) => q.eq('backendServerId', server._id))
      .collect();
    const byTransport = await listenersByTransport(ctx.db, server._id);
    // Families no transport uses, for "use the existing list" (few: one per target).
    let unbound: { f: Doc<'sniFamilies'>; names: number }[] | null = null;
    const unboundFamilies = async () => {
      if (unbound) return unbound;
      unbound = [];
      for (const f of await ctx.db.query('sniFamilies').collect()) {
        if (!f.enabled) continue;
        const b = await ctx.db
          .query('sniInboundBindings')
          .withIndex('by_family', (q) => q.eq('familyId', f._id))
          .first();
        if (b) continue;
        const names = await ctx.db
          .query('sniNames')
          .withIndex('by_family_seq', (q) => q.eq('familyId', f._id))
          .collect();
        unbound.push({ f, names: names.filter((n) => n.status !== 'burned').length });
      }
      return unbound;
    };

    const transports = [];
    for (const p of profiles)
      for (const i of p.inbounds) {
        if (i.security !== 'reality' || !i.reality) continue;
        const target = parseRealityTarget(i.reality.target);
        const binding = bindings.find((b) => b.inboundUuid === i.inboundUuid) ?? null;
        const family = binding ? await ctx.db.get(binding.familyId) : null;
        const listeners = byTransport.get(i.inboundUuid) ?? [];
        const handedOut = listeners.map(
          ({ listener }) =>
            new Set(
              (listener.tlsNames ?? []).filter((n) => n.status === 'active').map((n) => n.name),
            ),
        );
        const names = family
          ? (
              await ctx.db
                .query('sniNames')
                .withIndex('by_family_seq', (q) => q.eq('familyId', family._id))
                .collect()
            ).map(deliveryName)
          : [];
        const { rollout, provable } = binding
          ? await newestRollout(ctx.db, binding._id)
          : { rollout: null, provable: new Set<string>() };
        const facts = {
          bound: !!binding,
          onBackend: new Set(i.reality.serverNames),
          provable,
          nodes: handedOut,
        };
        // Each node behind the transport: what its members get, what a test adds,
        // and the addresses a test link can go through (a current endpoint confirmation).
        const nodes = [];
        for (const [k, { relay, listener }] of listeners.entries()) {
          const [verifiable] = await verificationListenersOf(ctx.db, relay, [listener]);
          const edges = await ctx.db
            .query('edges')
            .withIndex('by_relay_status', (q) => q.eq('relayId', relay._id))
            .collect();
          const origin = relay.origin.kind === 'panel-node' ? relay.origin : null;
          const node = origin
            ? (panelNodes.find((n) =>
                origin.nodeUuid ? n.nodeUuid === origin.nodeUuid : n.name === origin.nodeName,
              ) ?? null)
            : null;
          nodes.push({
            relaySlug: relay.slug,
            nodeUuid: node?.nodeUuid ?? origin?.nodeUuid ?? null,
            nodeName: node?.name ?? origin?.nodeName ?? relay.slug,
            ...(family ? nodeCounts(names, provable, handedOut[k]!) : { inUse: 0, waitingTest: 0 }),
            testable: edges
              .filter(
                (e) =>
                  e.listenerId === listener._id &&
                  (e.status === 'active' || e.status === 'verifying') &&
                  verificationCurrent(e, verifiable!),
              )
              .map((e) => ({ edgeId: e._id as string, name: e.name })),
          });
        }
        const sameCoverSite = family
          ? []
          : (await unboundFamilies())
              .filter(({ f }) => sameTarget(target, f.target))
              .map(({ f, names }) => ({ slug: f.slug, label: f.label, names }));
        transports.push({
          transportUuid: i.inboundUuid,
          tag: i.tag,
          profileUuid: p.profileUuid,
          profileName: p.name,
          port: i.port,
          coverSite: target ? hostPort(target.address, target.port) : null,
          listed: i.reality.serverNames.length,
          profileNodes: panelNodes
            .filter((n) => n.configProfileUuid === p.profileUuid)
            .map((n) => ({ nodeUuid: n.nodeUuid, name: n.name })),
          list: family
            ? {
                slug: family.slug,
                label: family.label,
                enabled: family.enabled,
                bindingId: binding!._id as string,
                counts: countDeliveries(names.map((n) => nameDelivery(n, facts).state)),
                // The overview's number (every scope of the family, exact counts).
                suggestions: await familyUsable(ctx.db, family._id),
              }
            : null,
          send: rollout
            ? {
                rolloutId: rollout._id as string,
                generation: rollout.generation,
                phase: rollout.phase,
              }
            : null,
          nodes,
          sameCoverSite,
        });
      }
    transports.sort((a, b) => a.tag.localeCompare(b.tag) || (a.port ?? 0) - (b.port ?? 0));
    return {
      switches: {
        names: sni.enabled,
        findNames: hunt.enabled,
        backendChanges: servers.manage.enabled,
        // Established once (or adopted): what the backend ledger writes against.
        backendSetUp: fcpWrites(setup),
      },
      transports,
    };
  },
});

/** What managing a transport's names needs to know before it starts (the dry run's facts). */
export const manageContext = internalQuery({
  args: { backendSlug: v.string(), transportUuid: v.string() },
  handler: async (ctx, a) => {
    const server = await serverBySlug(ctx.db, a.backendSlug);
    const i = await transportOf(ctx.db, server._id, a.transportUuid);
    if (i.security !== 'reality' || !i.reality)
      return refuse('servers.not_reality', 'Only a REALITY transport takes a server-name family');
    const target = parseRealityTarget(i.reality.target);
    if (!target)
      return refuse('edge.sni.bad_target', 'The transport has no target that FCP can check');
    // Every address in use on the transport (a network suggestion must hold them all).
    const addresses: string[] = [];
    for (const { relay, listener } of (await listenersByTransport(ctx.db, server._id)).get(
      a.transportUuid,
    ) ?? [])
      for (const e of await ctx.db
        .query('edges')
        .withIndex('by_relay_publication', (q) =>
          q.eq('relayId', relay._id).eq('publication', 'published'),
        )
        .collect())
        if (e.listenerId === listener._id)
          for (const ip of [e.addresses.v4, e.addresses.v6]) if (ip) addresses.push(ip);
    const networks = [];
    for (const n of await ctx.db.query('edgeNetworks').take(200))
      if (hasPrefixes(n.prefixes))
        networks.push({ slug: n.slug, label: n.label, prefixes: n.prefixes });
    return {
      tag: i.tag,
      target,
      coverSite: hostPort(target.address, target.port),
      addresses,
      networks,
    };
  },
});

async function transportOf(
  db: QueryCtx['db'],
  serverId: Id<'backendServers'>,
  transportUuid: string,
) {
  for (const p of await db
    .query('panelProfiles')
    .withIndex('by_server', (q) => q.eq('backendServerId', serverId))
    .collect())
    for (const i of p.inbounds) if (i.inboundUuid === transportUuid) return i;
  return refuse(
    'servers.unknown_inbound',
    'That transport is not on this backend. Refresh Servers',
  );
}

/** Whether every address lies on the network (exported for the dry run). */
export const onNetworkOf = (ip: string, n: { prefixes: Doc<'edgeNetworks'>['prefixes'] }) =>
  onNetwork(ip, n.prefixes);

/**
 * Manage a transport's names with FCP, in one transaction: a new family with
 * the transport's own target (or an existing one with that target no
 * transport uses), bound with the names the transport lists now taken in. A
 * refusal leaves nothing behind. Writes nothing to the backend: the names are
 * qualified, and reach a node only through the usual rollout and test.
 *
 * A family on a network whose place for the timing checks is not set takes
 * the node's: its country, and the city its backend's location is named after.
 */
export const manage = internalMutation({
  args: {
    backendSlug: v.string(),
    transportUuid: v.string(),
    // An existing family with the same target, instead of a new one.
    family: v.optional(v.string()),
    network: v.optional(v.union(v.string(), v.null())),
    label: v.optional(v.string()),
    requireH2: v.optional(v.boolean()),
    // The node whose page asked: its place is the network's, when unset.
    nodeUuid: v.optional(v.string()),
    ...actor,
  },
  handler: async (ctx, a) => {
    if (!(await resolveSniConfig(ctx.db)).enabled)
      refuse('edge.sni.disabled', 'Server-name families are switched off');
    const server = await serverBySlug(ctx.db, a.backendSlug);
    const i = await transportOf(ctx.db, server._id, a.transportUuid);
    if (i.security !== 'reality' || !i.reality)
      return refuse('servers.not_reality', 'Only a REALITY transport takes a server-name family');
    const target = parseRealityTarget(i.reality.target);
    if (!target)
      return refuse('edge.sni.bad_target', 'The transport has no target that FCP can check');
    let f: Doc<'sniFamilies'>;
    let created = false;
    if (a.family) {
      const found = await ctx.db
        .query('sniFamilies')
        .withIndex('by_slug', (q) => q.eq('slug', a.family!))
        .unique();
      if (!found) return refuse('not_found', 'No such family');
      // Only a family no transport uses: another transport's would take these names too.
      const used = await ctx.db
        .query('sniInboundBindings')
        .withIndex('by_family', (q) => q.eq('familyId', found._id))
        .first();
      if (used)
        return refuse('edge.sni.family_in_use', 'Another transport already uses this family');
      f = found;
    } else {
      // A short id from the tag, unique among families.
      const base = familySlugForTransport(i.tag);
      let slug = base;
      for (let n = 2; ; n++) {
        const taken = await ctx.db
          .query('sniFamilies')
          .withIndex('by_slug', (q) => q.eq('slug', slug))
          .unique();
        if (!taken) break;
        slug = `${base}-${n}`;
      }
      f = await insertFamily(ctx, {
        slug,
        label: a.label?.trim() || `${i.tag} names`,
        targetAddress: target.address,
        targetPort: target.port,
        requireH2: a.requireH2 ?? false,
        ...(a.network ? { network: a.network } : {}),
        ...(a.actorAdminId ? { actorAdminId: a.actorAdminId } : {}),
      });
      created = true;
    }
    const bound = await bindFamily(ctx, f, server, {
      inboundTag: i.tag,
      inboundUuid: i.inboundUuid,
      importNames: true,
      ...(a.actorAdminId ? { actorAdminId: a.actorAdminId } : {}),
    });
    // Where the network's nodes are, for timing names from there: the node's own place.
    let placeSet = false;
    if (f.networkId) {
      const network = await ctx.db.get(f.networkId);
      if (network && !network.hunt?.place) {
        // The node that asked, else only a country every node running it agrees on.
        const running = (
          await ctx.db
            .query('panelNodes')
            .withIndex('by_server', (q) => q.eq('backendServerId', server._id))
            .collect()
        ).filter((n) => n.activeInboundUuids.includes(i.inboundUuid));
        const asked = a.nodeUuid ? running.find((n) => n.nodeUuid === a.nodeUuid) : undefined;
        const countries = new Set(running.map((n) => n.countryCode?.toUpperCase() ?? ''));
        const country = asked
          ? asked.countryCode
          : countries.size === 1
            ? [...countries][0]
            : undefined;
        const place = placeFromNode(country, server.locationLabel);
        if (place) {
          await ctx.db.patch(network._id, {
            hunt: { enabled: network.hunt?.enabled ?? false, place, placeFrom: 'node' },
            updatedAt: Date.now(),
          });
          placeSet = true;
        }
      }
    }
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'edge.sni.transport.manage',
      targetType: 'sni_family',
      payload: {
        slug: f.slug,
        backendSlug: server.slug,
        inboundTag: i.tag,
        created,
        imported: bound.imported?.added ?? 0,
        placeSet,
      },
    });
    return {
      family: f.slug,
      created,
      bindingId: bound.id,
      imported: bound.imported ?? { added: 0, lines: [] },
      placeSet,
    };
  },
});
