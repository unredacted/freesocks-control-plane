/**
 * Admin reads for server management (Admin -> Servers) plus its two switches.
 * Every read is served from the `panel*` caches `panelObserve` fills, so the
 * page shows what ALREADY exists on a panel without making a panel call, and
 * nothing here can return a secret: the caches hold none.
 *
 * The central view is the TREE of one instance: each node with the config
 * profile it runs, the inbounds it serves, the Hosts members are handed for
 * those inbounds and the squads that grant them.
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { Doc } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { writeAuditLog } from './lib/audit';
import { capabilitiesOf } from './lib/backends/capabilities';
import { poolFromConfig } from './lib/remnawavePlacement';
import { flattenServerConfig, resolveServerConfig, serverConfigWrites } from './lib/serverConfig';

const iso = (ms: number | undefined) => (ms ? new Date(ms).toISOString() : null);

export const observeEnabled = internalQuery({
  args: {},
  handler: async (ctx) => (await resolveServerConfig(ctx.db)).manage.observe,
});

export const configView = internalQuery({
  args: {},
  handler: async (ctx) => ({ config: flattenServerConfig(await resolveServerConfig(ctx.db)) }),
});

export const patchConfig = internalMutation({
  args: { patch: v.any(), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { patch, actorAdminId }) => {
    const p = (patch && typeof patch === 'object' ? patch : {}) as Record<string, unknown>;
    const { writes, changedKeys } = serverConfigWrites(p);
    for (const w of writes) await upsertSettingRow(ctx, w.key, w.value, actorAdminId);
    if (changedKeys.length > 0)
      await writeAuditLog(ctx, {
        actorType: 'admin',
        actorId: actorAdminId ?? undefined,
        action: 'servers.config.update',
        targetType: 'app_settings',
        payload: { changedKeys },
      });
    return { changedKeys };
  },
});

function mapState(s: Doc<'panelObserveState'> | null) {
  return {
    observedAt: iso(s?.observedAt),
    attemptedAt: iso(s?.attemptedAt),
    ok: s ? s.ok : null,
    errorCode: s?.errorCode ?? null,
    counts: s?.counts ?? null,
  };
}

/** Every instance with whether it can be observed and how its last look went. */
export const summary = internalQuery({
  args: {},
  handler: async (ctx) => {
    const [servers, states, cfg] = await Promise.all([
      ctx.db.query('backendServers').collect(),
      ctx.db.query('panelObserveState').collect(),
      resolveServerConfig(ctx.db),
    ]);
    const stateBy = new Map(states.map((s) => [s.backendServerId as string, s]));
    return {
      config: flattenServerConfig(cfg),
      instances: servers
        .sort((a, b) => a.slug.localeCompare(b.slug))
        .map((s) => ({
          id: s._id as string,
          slug: s.slug,
          name: s.name,
          backend: s.backend,
          isActive: s.isActive,
          observable: capabilitiesOf(s.backend).panelObservation,
          ...mapState(stateBy.get(s._id as string) ?? null),
        })),
    };
  },
});

export const instanceBySlug = internalQuery({
  args: { slug: v.string() },
  handler: async (ctx, { slug }) => {
    const s = await ctx.db
      .query('backendServers')
      .withIndex('by_slug', (q) => q.eq('slug', slug))
      .unique();
    if (!s) throw new ConvexError({ code: 'not_found', message: 'Backend server not found' });
    return { id: s._id, slug: s.slug, name: s.name, backend: s.backend };
  },
});

function mapInbound(i: Doc<'panelProfiles'>['inbounds'][number]) {
  return {
    tag: i.tag,
    inboundUuid: i.inboundUuid,
    protocol: i.protocol,
    port: i.port,
    listen: i.listen ?? null,
    network: i.network,
    security: i.security,
    serverNames: i.reality?.serverNames ?? null,
    realityTarget: i.reality?.target ?? null,
    tlsServerName: i.tlsServerName ?? null,
    path: i.path ?? null,
    serviceName: i.serviceName ?? null,
    realityPublicKey: i.realityAuth?.publicKey ?? null,
    realityPublicKeyMismatch: i.realityAuth?.publicKeyMismatch ?? false,
  };
}

function mapHost(h: Doc<'panelHosts'>) {
  return {
    hostUuid: h.hostUuid,
    remark: h.remark,
    address: h.address,
    port: h.port,
    sni: h.sni ?? null,
    host: h.host ?? null,
    path: h.path ?? null,
    alpn: h.alpn ?? null,
    fingerprint: h.fingerprint ?? null,
    securityLayer: h.securityLayer ?? null,
    isDisabled: h.isDisabled,
    isHidden: h.isHidden,
    tag: h.tag ?? null,
    viewPosition: h.viewPosition ?? null,
    configProfileUuid: h.configProfileUuid ?? null,
    inboundUuid: h.configProfileInboundUuid ?? null,
    nodeUuids: h.nodeUuids,
  };
}

/**
 * One instance as a tree: node -> profile -> served inbounds -> Hosts + squads.
 * A Host pinned to specific nodes appears under those only; an unpinned one
 * under every node serving its inbound. What hangs off no node (a profile no
 * node runs, a Host on an inbound no node serves) is returned as `unattached`,
 * because that is exactly what an operator needs to notice.
 */
export const tree = internalQuery({
  args: { slug: v.string() },
  handler: async (ctx, { slug }) => {
    const server = await ctx.db
      .query('backendServers')
      .withIndex('by_slug', (q) => q.eq('slug', slug))
      .unique();
    if (!server) throw new ConvexError({ code: 'not_found', message: 'Backend server not found' });
    const sid = server._id;
    const [nodes, profiles, hosts, squads, state] = await Promise.all([
      ctx.db
        .query('panelNodes')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .collect(),
      ctx.db
        .query('panelProfiles')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .collect(),
      ctx.db
        .query('panelHosts')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .collect(),
      ctx.db
        .query('panelSquads')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .collect(),
      ctx.db
        .query('panelObserveState')
        .withIndex('by_server', (q) => q.eq('backendServerId', server._id))
        .unique(),
    ]);
    const profileBy = new Map(profiles.map((p) => [p.profileUuid, p]));
    const usedProfiles = new Set<string>();
    const placedHosts = new Set<string>();
    const tagOf = new Map<string, string>();
    for (const p of profiles) for (const i of p.inbounds) tagOf.set(i.inboundUuid, i.tag);

    const nodeViews = nodes
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((n) => {
        const profile = n.configProfileUuid ? profileBy.get(n.configProfileUuid) : undefined;
        if (profile) usedProfiles.add(profile.profileUuid);
        const active = new Set(n.activeInboundUuids);
        const inbounds = (profile?.inbounds ?? [])
          .filter((i) => active.has(i.inboundUuid))
          .map((i) => {
            const mine = hosts.filter(
              (h) =>
                h.configProfileInboundUuid === i.inboundUuid &&
                (h.nodeUuids.length === 0 || h.nodeUuids.includes(n.nodeUuid)),
            );
            for (const h of mine) placedHosts.add(h.hostUuid);
            return {
              ...mapInbound(i),
              hosts: mine
                .sort((a, b) => (a.viewPosition ?? 0) - (b.viewPosition ?? 0))
                .map(mapHost),
              squads: squads
                .filter((sq) => sq.inboundUuids.includes(i.inboundUuid))
                .map((sq) => ({ squadUuid: sq.squadUuid, name: sq.name })),
            };
          });
        return {
          nodeUuid: n.nodeUuid,
          name: n.name,
          address: n.address ?? null,
          port: n.port ?? null,
          countryCode: n.countryCode ?? null,
          online: n.online,
          isDisabled: n.isDisabled,
          usersOnline: n.usersOnline,
          tags: n.tags,
          profile: profile
            ? {
                profileUuid: profile.profileUuid,
                name: profile.name,
                inboundCount: profile.inbounds.length,
                changedAt: iso(profile.tokenChangedAt),
              }
            : null,
          inbounds,
        };
      });

    return {
      instance: { id: server._id as string, slug: server.slug, name: server.name },
      observable: capabilitiesOf(server.backend).panelObservation,
      state: mapState(state),
      nodes: nodeViews,
      profiles: profiles
        .sort((a, b) => a.name.localeCompare(b.name))
        .map((p) => ({
          profileUuid: p.profileUuid,
          name: p.name,
          shapeHash: p.shapeHash,
          changedAt: iso(p.tokenChangedAt),
          nodeCount: nodes.filter((n) => n.configProfileUuid === p.profileUuid).length,
          inbounds: p.inbounds.map(mapInbound),
        })),
      squads: squads
        .sort((a, b) => a.name.localeCompare(b.name))
        .map((sq) => ({
          squadUuid: sq.squadUuid,
          name: sq.name,
          membersCount: sq.membersCount ?? null,
          inboundTags: sq.inboundUuids.map((u) => tagOf.get(u) ?? null),
          inboundUuids: sq.inboundUuids,
        })),
      hosts: hosts.sort((a, b) => (a.viewPosition ?? 0) - (b.viewPosition ?? 0)).map(mapHost),
      unattached: {
        profiles: profiles.filter((p) => !usedProfiles.has(p.profileUuid)).map((p) => p.name),
        hosts: hosts.filter((h) => !placedHosts.has(h.hostUuid)).map((h) => h.remark),
      },
    };
  },
});

/**
 * Who feels a change to these inbounds of a profile: the nodes the panel will
 * re-apply it to, and the relays whose listeners are bound to them.
 */
export const profileBlastRadius = internalQuery({
  args: {
    backendServerId: v.id('backendServers'),
    profileUuid: v.string(),
    inboundUuids: v.array(v.string()),
  },
  handler: async (ctx, { backendServerId: sid, profileUuid, inboundUuids }) => {
    const nodes = (
      await ctx.db
        .query('panelNodes')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .collect()
    ).filter((n) => !n.isDisabled && n.configProfileUuid === profileUuid);
    const wanted = new Set(inboundUuids);
    const relays = await ctx.db
      .query('relays')
      .withIndex('by_backend_server', (q) => q.eq('backendServerId', sid))
      .collect();
    const affected: { relaySlug: string; listenerKeys: string[]; publishedEdges: number }[] = [];
    for (const r of relays) {
      const listeners = (
        await ctx.db
          .query('relayListeners')
          .withIndex('by_relay', (q) => q.eq('relayId', r._id))
          .collect()
      ).filter(
        (l) =>
          !l.retired && !!l.panelBinding && wanted.has(l.panelBinding.configProfileInboundUuid),
      );
      if (listeners.length > 0)
        affected.push({
          relaySlug: r.slug,
          listenerKeys: listeners.map((l) => l.listenerKey),
          publishedEdges: r.publishedEdgeIds.length,
        });
    }
    return { restartsNodes: nodes.map((n) => n.name), affectedRelays: affected };
  },
});

/**
 * Check the squad pools operators pasted into mode placements against the
 * squads the panel really has. A pool is write-only over HTTP (it is never
 * echoed), so this answers in COUNTS and squad names, never the pasted uuids:
 * a uuid the panel lacks issues keys nobody can use, and a squad without an
 * inbound issues keys that connect to nothing.
 */
export const validatePlacements = internalQuery({
  args: { slug: v.string() },
  handler: async (ctx, { slug }) => {
    const server = await ctx.db
      .query('backendServers')
      .withIndex('by_slug', (q) => q.eq('slug', slug))
      .unique();
    if (!server) throw new ConvexError({ code: 'not_found', message: 'Backend server not found' });
    const sid = server._id;
    const [squads, placements, state] = await Promise.all([
      ctx.db
        .query('panelSquads')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .collect(),
      ctx.db
        .query('modePlacements')
        .withIndex('by_backend', (q) => q.eq('backend', server.backend))
        .collect(),
      ctx.db
        .query('panelObserveState')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .unique(),
    ]);
    const known = new Map(squads.map((sq) => [sq.squadUuid, sq]));
    return {
      observedAt: iso(state?.observedAt),
      modes: placements
        .map((p) => {
          const pool = poolFromConfig(p.config);
          const present = pool.filter((u) => known.has(u));
          return {
            modeSlug: p.modeSlug,
            squads: pool.length,
            // Several instances can share a backend type: a uuid missing HERE
            // may live on another panel, so this is a count to look into, not
            // a verdict.
            unknownHere: pool.length - present.length,
            withoutInbounds: present
              .map((u) => known.get(u)!)
              .filter((sq) => sq.inboundUuids.length === 0)
              .map((sq) => sq.name),
          };
        })
        .sort((a, b) => a.modeSlug.localeCompare(b.modeSlug)),
    };
  },
});
