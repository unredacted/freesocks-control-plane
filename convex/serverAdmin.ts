/**
 * Admin reads for server management (Admin -> Servers) plus its two switches.
 * Every read is served from the `backend*` caches `panelObserve` fills, so the
 * page shows what ALREADY exists on a backend without making a backend call, and
 * nothing here can return a secret: the caches hold none.
 *
 * The central view is the TREE of one instance: each node with the config
 * profile it runs, the transports it serves, the Hosts members are handed for
 * those transports and the mode groups that grant them.
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { Doc } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { writeAuditLog } from './lib/audit';
import { capabilitiesOf } from './lib/backends/capabilities';
import { poolFromConfig } from './lib/remnawavePlacement';
import { flattenServerConfig, resolveServerConfig, serverConfigWrites } from './lib/serverConfig';
import { modeRefOf } from './panelIntents';

const iso = (ms: number | undefined) => (ms ? new Date(ms).toISOString() : null);

export const observeEnabled = internalQuery({
  args: {},
  handler: async (ctx) => (await resolveServerConfig(ctx.db)).manage.observe,
});

/** The write-off switch, re-read by resumed workflows before any provider side effect. */
export const manageEnabled = internalQuery({
  args: {},
  handler: async (ctx) => (await resolveServerConfig(ctx.db)).manage.enabled,
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
    // Stored under the backend's own words; the view speaks ours.
    counts: s?.counts
      ? {
          nodes: s.counts.nodes,
          profiles: s.counts.profiles,
          addresses: s.counts.hosts,
          modeGroups: s.counts.squads,
        }
      : null,
  };
}

/**
 * The enrolled nodes of an instance (docs/servers.md "Node lifecycle"): what
 * the Servers page shows beside each node row and on its page. Never a
 * secret: stages, dispositions, revisions, the origin name, the retirement.
 */
export const intentsView = internalQuery({
  args: { backendServerId: v.id('backendServers') },
  handler: async (ctx, { backendServerId }) => {
    const intents = await ctx.db
      .query('panelNodeIntents')
      .withIndex('by_server', (q) => q.eq('backendServerId', backendServerId))
      .collect();
    const out = [];
    for (const i of intents) {
      const retirement = i.retirementId ? await ctx.db.get(i.retirementId) : null;
      const run = i.activation.currentRunId ? await ctx.db.get(i.activation.currentRunId) : null;
      out.push({
        id: i._id as string,
        name: i.name,
        mode: await modeRefOf(ctx, i),
        state: i.state,
        code: i.code ?? null,
        stage: i.activation.stage,
        disposition: i.delivery.disposition,
        machineRevision: i.machineRevision,
        appliedRevision: i.appliedRevision ?? null,
        nodeUuid: i.nodeUuid ?? null,
        addressUuids: i.addressUuids ?? [],
        adopted: !!i.adopted,
        origin: { hostname: i.origin.hostname ?? null, dns: i.origin.dns },
        maintenance: !!i.maintenance,
        run: run
          ? { id: run._id as string, state: run.state, stage: run.stage, code: run.code ?? null }
          : null,
        retirement: retirement ? { stage: retirement.stage, code: retirement.code ?? null } : null,
        registeredAt: new Date(i.registeredAt).toISOString(),
        updatedAt: new Date(i.updatedAt).toISOString(),
      });
    }
    return out;
  },
});

/** Every instance with whether it can be observed and how its last look went. */
export const summary = internalQuery({
  args: {},
  handler: async (ctx) => {
    const [servers, states, setups, cfg] = await Promise.all([
      ctx.db.query('backendServers').collect(),
      ctx.db.query('panelObserveState').collect(),
      ctx.db.query('panelSetups').collect(),
      resolveServerConfig(ctx.db),
    ]);
    const stateBy = new Map(states.map((s) => [s.backendServerId as string, s]));
    const setupBy = new Map(setups.map((s) => [s.backendServerId as string, s]));
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
          writable: capabilitiesOf(s.backend).panelWrites,
          // Whether FCP has set this backend up (or adopted it): the one condition for writing it.
          setUp: setupBy.get(s._id as string)?.state === 'ready',
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
    transportUuid: i.inboundUuid,
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
    addressUuid: h.hostUuid,
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
    transportUuid: h.configProfileInboundUuid ?? null,
    nodeUuids: h.nodeUuids,
  };
}

/**
 * One instance as a tree: node -> profile -> served transports -> Hosts + mode groups.
 * A Host pinned to specific nodes appears under those only; an unpinned one
 * under every node serving its transport. What hangs off no node (a profile no
 * node runs, a Host on a transport no node serves) is returned as `unattached`,
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
        const transports = (profile?.inbounds ?? [])
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
              addresses: mine
                .sort((a, b) => (a.viewPosition ?? 0) - (b.viewPosition ?? 0))
                .map(mapHost),
              modeGroups: squads
                .filter((sq) => sq.inboundUuids.includes(i.inboundUuid))
                .map((sq) => ({ groupUuid: sq.squadUuid, name: sq.name })),
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
                transportCount: profile.inbounds.length,
                changedAt: iso(profile.tokenChangedAt),
              }
            : null,
          transports,
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
          foreignEditAt: iso(p.foreignEditAt),
          nodeCount: nodes.filter((n) => n.configProfileUuid === p.profileUuid).length,
          transports: p.inbounds.map(mapInbound),
        })),
      modeGroups: squads
        .sort((a, b) => a.name.localeCompare(b.name))
        .map((sq) => ({
          groupUuid: sq.squadUuid,
          name: sq.name,
          membersCount: sq.membersCount ?? null,
          transportTags: sq.inboundUuids.map((u) => tagOf.get(u) ?? null),
          transportUuids: sq.inboundUuids,
        })),
      addresses: hosts.sort((a, b) => (a.viewPosition ?? 0) - (b.viewPosition ?? 0)).map(mapHost),
      unattached: {
        profiles: profiles.filter((p) => !usedProfiles.has(p.profileUuid)).map((p) => p.name),
        addresses: hosts.filter((h) => !placedHosts.has(h.hostUuid)).map((h) => h.remark),
      },
    };
  },
});

/**
 * Who feels a change to these transports of a profile: the nodes the backend will
 * re-apply it to, and the origins whose listeners are bound to them.
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
 * Check the mode group pools operators pasted into mode placements against the
 * mode groups the backend really has. A pool is write-only over HTTP (it is never
 * echoed), so this answers in COUNTS and mode group names, never the pasted uuids:
 * a uuid the backend lacks issues keys nobody can use, and a mode group without an
 * transport issues keys that connect to nothing.
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
            modeGroups: pool.length,
            // Several instances can share a backend type: a uuid missing HERE
            // may live on another backend, so this is a count to look into, not
            // a verdict.
            unknownHere: pool.length - present.length,
            withoutTransports: present
              .map((u) => known.get(u)!)
              .filter((sq) => sq.inboundUuids.length === 0)
              .map((sq) => sq.name),
          };
        })
        .sort((a, b) => a.modeSlug.localeCompare(b.modeSlug)),
    };
  },
});
