/**
 * Admin reads for server management (Admin -> Servers) plus its two switches.
 * Every read is served from the `backend*` caches `backendObserve` fills, so the
 * page shows what ALREADY exists on a backend without making a backend call, and
 * nothing here can return a secret: the caches hold none.
 *
 * The central view is the TREE of one instance: each node with the config
 * profile it runs, the transports it serves, the Hosts members are handed for
 * those transports and the mode groups that grant them.
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { DatabaseReader } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id, TableNames } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { writeAuditLog } from './lib/audit';
import { capabilitiesOf } from './lib/backends/capabilities';
import { resolveModeCatalog } from './lib/connectionModes';
import { poolFromConfig } from './lib/remnawavePlacement';
import { flattenServerConfig, resolveServerConfig, serverConfigWrites } from './lib/serverConfig';
import { modeRefOf } from './nodeIntents';

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
    const { modes: catalog } = await resolveModeCatalog(ctx.db);
    const out = [];
    for (const i of intents) {
      const retirement = i.retirementId ? await ctx.db.get(i.retirementId) : null;
      const run = i.activation.currentRunId ? await ctx.db.get(i.activation.currentRunId) : null;
      // The guided setup run protecting this node right now (fronted nodes).
      const protection =
        (
          await ctx.db
            .query('edgeSetupRuns')
            .withIndex('by_origin', (q) =>
              q.eq('backendServerId', backendServerId).eq('nodeName', i.name),
            )
            .collect()
        ).find((r) => r.state === 'running' || r.state === 'waiting' || r.state === 'needs_you') ??
        null;
      out.push({
        id: i._id as string,
        name: i.name,
        machineName: i.machineName ?? null,
        mode: await modeRefOf(ctx, i),
        // Members can pick the mode this node serves (off: nobody gets the node).
        modeEnabled: catalog.find((m) => m.id === i.mode)?.enabled ?? false,
        state: i.state,
        code: i.code ?? null,
        stage: i.activation.stage,
        disposition: i.delivery.disposition,
        machineRevision: i.machineRevision,
        appliedRevision: i.appliedRevision ?? null,
        // When the node role last reported in (each run starts with a report).
        roleSeenAt: new Date(i.observed.at).toISOString(),
        nodeUuid: i.nodeUuid ?? null,
        addressUuids: i.addressUuids ?? [],
        adopted: !!i.adopted,
        origin: { hostname: i.origin.hostname ?? null, dns: i.origin.dns },
        maintenance: !!i.maintenance,
        run: run
          ? { id: run._id as string, state: run.state, stage: run.stage, code: run.code ?? null }
          : null,
        protection: protection
          ? {
              runId: protection._id as string,
              stage: protection.stage,
              state: protection.state,
              need: protection.need?.code ?? null,
            }
          : null,
        // Where the ladder is, and since when it waits there (the page words the steps).
        retirement: retirement
          ? {
              stage: retirement.stage,
              code: retirement.code ?? null,
              step: retirement.step ?? null,
              requestedBy: retirement.requestedBy,
              // It waited for an admin's decision (or got one): only then is that a step.
              decision: retirement.events.some(
                (e) => e.code === 'needs_admin' || e.code === 'decided',
              ),
              requestedAt: new Date(retirement.createdAt).toISOString(),
              since: new Date(
                retirement.events[retirement.events.length - 1]?.at ?? retirement.updatedAt,
              ).toISOString(),
            }
          : null,
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
          writable: capabilitiesOf(s.backend).backendWrites,
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

/**
 * The enrolled node `intentId` names, only if it belongs to the backend `slug`
 * names (null otherwise, including for a malformed id). Every intent route goes
 * through this: a valid id under another backend's path is not found.
 */
export const intentOnServer = internalQuery({
  args: { slug: v.string(), intentId: v.string() },
  handler: async (ctx, { slug, intentId }) => {
    const server = await ctx.db
      .query('backendServers')
      .withIndex('by_slug', (q) => q.eq('slug', slug))
      .unique();
    const id = ctx.db.normalizeId('panelNodeIntents', intentId);
    if (!server || !id) return null;
    const intent = await ctx.db.get(id);
    return intent && intent.backendServerId === server._id ? id : null;
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

// --- removing a backend server: its server-management rows go with it ---------------------------

/**
 * What keeps a backend server from being removed (docs/servers.md "Removing a
 * backend server"): a node FCP manages on it that is not retired (retire it
 * from its page first: its addresses, origin and members' delivery are the
 * retirement's to undo), an origin Edges still protects on it (a whole-server
 * one has no node: its edges are provider resources only its removal tears
 * down), a setup run or a rename running now, or a backend write still open.
 * Null when nothing does: what is left is FCP's record of the backend,
 * removed with it (`purgeRemovedBackend`).
 */
export async function removalBlocker(
  db: DatabaseReader,
  sid: Id<'backendServers'>,
): Promise<{ code: string; message: string } | null> {
  const intents = await db
    .query('panelNodeIntents')
    .withIndex('by_server', (q) => q.eq('backendServerId', sid))
    .collect();
  const managed = intents.filter((i) => i.state !== 'retired');
  if (managed.length > 0)
    return {
      code: 'server.has_nodes',
      message: `FCP manages ${managed.length === 1 ? 'a node' : `${managed.length} nodes`} on this backend (${managed
        .slice(0, 3)
        .map((i) => i.name)
        .join(', ')}). Retire ${managed.length === 1 ? 'it' : 'them'} from Servers first`,
    };
  const origins = await db
    .query('relays')
    .withIndex('by_backend_server', (q) => q.eq('backendServerId', sid))
    .take(4);
  if (origins.length > 0)
    return {
      code: 'server.has_origins',
      message: `Edges still protect ${origins.length === 1 ? 'an origin' : 'origins'} on this backend (${origins
        .slice(0, 3)
        .map((r) => r.slug)
        .join(', ')}). Remove ${origins.length === 1 ? 'its' : 'their'} protection in Edges first`,
    };
  const setup = await db
    .query('panelSetups')
    .withIndex('by_server', (q) => q.eq('backendServerId', sid))
    .unique();
  if (setup?.claim && setup.claim.expiresAt > Date.now())
    return { code: 'server.setup_running', message: 'This backend is being set up right now' };
  const renaming = await db
    .query('panelNodeRenames')
    .withIndex('by_server', (q) => q.eq('backendServerId', sid))
    .filter((q) => q.eq(q.field('state'), 'running'))
    .first();
  if (renaming)
    return { code: 'server.rename_running', message: 'A node of this backend is being renamed' };
  const open = await db
    .query('panelOps')
    .withIndex('by_open', (q) => q.eq('open', true).eq('backendServerId', sid))
    .first();
  if (open)
    return {
      code: 'server.op_running',
      message: 'A change to this backend is still being made. Try again once it is done',
    };
  return null;
}

/** A dry run reads at most this many rows of each table; a purge deletes at most this many per call. */
const PURGE_READ_CAP = 1000;
const PURGE_BATCH = 400;

/**
 * Every server-management row of a backend, per table, rows that point at
 * another one first (activation runs and retirements before their node,
 * rollouts before their binding, requirements before their port change).
 * At most `cap` per table.
 */
async function rowsOfBackend(
  db: DatabaseReader,
  sid: Id<'backendServers'>,
  cap: number,
): Promise<Array<[TableNames, Id<TableNames>[]]>> {
  const ids = (rows: { _id: Id<TableNames> }[]) => rows.map((r) => r._id);
  const intents = await db
    .query('panelNodeIntents')
    .withIndex('by_server', (q) => q.eq('backendServerId', sid))
    .take(cap);
  const bindings = await db
    .query('sniInboundBindings')
    .withIndex('by_server_inbound', (q) => q.eq('backendServerId', sid))
    .take(cap);
  const runs: Id<TableNames>[] = [];
  const retirements: Id<TableNames>[] = [];
  for (const i of intents) {
    if (runs.length < cap)
      runs.push(
        ...ids(
          await db
            .query('panelActivationRuns')
            .withIndex('by_intent', (q) => q.eq('intentId', i._id))
            .take(cap - runs.length),
        ),
      );
    if (retirements.length < cap)
      retirements.push(
        ...ids(
          await db
            .query('panelRetirements')
            .withIndex('by_intent', (q) => q.eq('intentId', i._id))
            .take(cap - retirements.length),
        ),
      );
  }
  const rollouts: Id<TableNames>[] = [];
  for (const b of bindings)
    if (rollouts.length < cap)
      rollouts.push(
        ...ids(
          await db
            .query('sniRollouts')
            .withIndex('by_binding', (q) => q.eq('bindingId', b._id))
            .take(cap - rollouts.length),
        ),
      );
  return [
    // A guided setup run's history names an activation run: it goes first.
    [
      'edgeSetupRuns',
      ids(
        await db
          .query('edgeSetupRuns')
          .withIndex('by_origin', (q) => q.eq('backendServerId', sid))
          .take(cap),
      ),
    ],
    [
      'edgeDeliveryBindings',
      ids(
        await db
          .query('edgeDeliveryBindings')
          .withIndex('by_server', (q) => q.eq('backendServerId', sid))
          .take(cap),
      ),
    ],
    ['panelActivationRuns', runs],
    ['panelRetirements', retirements],
    ['sniRollouts', rollouts],
    [
      'panelPortRequirements',
      ids(
        await db
          .query('panelPortRequirements')
          .withIndex('by_server_node', (q) => q.eq('backendServerId', sid))
          .take(cap),
      ),
    ],
    [
      'panelNodeAliases',
      ids(
        await db
          .query('panelNodeAliases')
          .withIndex('by_server', (q) => q.eq('backendServerId', sid))
          .take(cap),
      ),
    ],
    [
      'panelNodeRenames',
      ids(
        await db
          .query('panelNodeRenames')
          .withIndex('by_server', (q) => q.eq('backendServerId', sid))
          .take(cap),
      ),
    ],
    [
      'panelMaintenanceHolds',
      ids(
        await db
          .query('panelMaintenanceHolds')
          .withIndex('by_server', (q) => q.eq('backendServerId', sid))
          .take(cap),
      ),
    ],
    [
      'panelPortChanges',
      ids(
        await db
          .query('panelPortChanges')
          .withIndex('by_server', (q) => q.eq('backendServerId', sid))
          .take(cap),
      ),
    ],
    [
      'panelOwnership',
      ids(
        await db
          .query('panelOwnership')
          .withIndex('by_server_kind_identity', (q) => q.eq('backendServerId', sid))
          .take(cap),
      ),
    ],
    [
      'backendObligations',
      ids(
        await db
          .query('backendObligations')
          .withIndex('by_server_kind_identity', (q) => q.eq('backendServerId', sid))
          .take(cap),
      ),
    ],
    [
      'panelClaims',
      ids(
        await db
          .query('panelClaims')
          .withIndex('by_server_key', (q) => q.eq('backendServerId', sid))
          .take(cap),
      ),
    ],
    [
      'panelOps',
      ids(
        await db
          .query('panelOps')
          .withIndex('by_server', (q) => q.eq('backendServerId', sid))
          .take(cap),
      ),
    ],
    [
      'sniInboundNameHistory',
      ids(
        await db
          .query('sniInboundNameHistory')
          .withIndex('by_inbound_name', (q) => q.eq('backendServerId', sid))
          .take(cap),
      ),
    ],
    [
      'panelNodes',
      ids(
        await db
          .query('panelNodes')
          .withIndex('by_server', (q) => q.eq('backendServerId', sid))
          .take(cap),
      ),
    ],
    [
      'panelHosts',
      ids(
        await db
          .query('panelHosts')
          .withIndex('by_server', (q) => q.eq('backendServerId', sid))
          .take(cap),
      ),
    ],
    [
      'panelProfiles',
      ids(
        await db
          .query('panelProfiles')
          .withIndex('by_server', (q) => q.eq('backendServerId', sid))
          .take(cap),
      ),
    ],
    [
      'panelSquads',
      ids(
        await db
          .query('panelSquads')
          .withIndex('by_server', (q) => q.eq('backendServerId', sid))
          .take(cap),
      ),
    ],
    [
      'backendNodeInventory',
      ids(
        await db
          .query('backendNodeInventory')
          .withIndex('by_server', (q) => q.eq('backendServerId', sid))
          .take(cap),
      ),
    ],
    [
      'remnawaveNodeStats',
      ids(
        await db
          .query('remnawaveNodeStats')
          .withIndex('by_server', (q) => q.eq('backendServerId', sid))
          .take(cap),
      ),
    ],
    [
      'panelObserveState',
      ids(
        await db
          .query('panelObserveState')
          .withIndex('by_server', (q) => q.eq('backendServerId', sid))
          .take(cap),
      ),
    ],
    ['panelNodeIntents', ids(intents)],
    ['sniInboundBindings', ids(bindings)],
    [
      'panelSetups',
      ids(
        await db
          .query('panelSetups')
          .withIndex('by_server', (q) => q.eq('backendServerId', sid))
          .take(cap),
      ),
    ],
  ];
}

/**
 * Remove what FCP kept about a backend server that is gone: its setup, nodes,
 * renames and aliases, port changes, activation runs, retirements, holds,
 * ownership, ledger, caches, the guided setup runs and delivery bindings its
 * removed origins left, and the server-name binding and history its
 * transports had (a family rollout reads a binding). A dry run unless
 * `dryRun: false`: it counts and changes nothing. A real run deletes a batch
 * and comes back for the next until nothing is left. Refused while the
 * backend server is still there. Removing a backend server runs it; a backend
 * an earlier release removed is cleared by hand, through the deployer
 * (docs/beta-deploy.md "One-off functions"), after `removedBackends` named it.
 */
export const purgeRemovedBackend = internalMutation({
  args: { backendServerId: v.id('backendServers'), dryRun: v.optional(v.boolean()) },
  handler: async (ctx, { backendServerId: sid, dryRun }) => {
    if (await ctx.db.get(sid))
      throw new ConvexError({
        code: 'server.still_there',
        message: 'That backend server is still there. Remove it first',
      });
    const dry = dryRun !== false;
    const rows = await rowsOfBackend(ctx.db, sid, dry ? PURGE_READ_CAP : PURGE_BATCH);
    const found = Object.fromEntries(
      rows.filter(([, ids]) => ids.length > 0).map(([table, ids]) => [table, ids.length]),
    );
    if (dry)
      return {
        dryRun: true as const,
        rows: found,
        capped: rows.some(([, ids]) => ids.length >= PURGE_READ_CAP),
      };
    let budget = PURGE_BATCH;
    let deleted = 0;
    for (const [, ids] of rows)
      for (const id of ids) {
        if (budget <= 0) break;
        await ctx.db.delete(id);
        budget--;
        deleted++;
      }
    const total = rows.reduce((n, [, ids]) => n + ids.length, 0);
    const more = total > deleted || rows.some(([, ids]) => ids.length >= PURGE_BATCH);
    if (more)
      await ctx.scheduler.runAfter(0, internal.serverAdmin.purgeRemovedBackend, {
        backendServerId: sid,
        dryRun: false,
      });
    if (deleted > 0)
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'admin.backend_server.purge',
        targetType: 'backend_server',
        targetId: sid,
        payload: { rows: deleted, more },
      });
    return { dryRun: false as const, rows: found, deleted, more };
  },
});

/**
 * Backend servers that are gone while FCP still keeps server-management rows
 * for them (an earlier release removed the backend row alone). Each is one
 * `purgeRemovedBackend` away from clean.
 */
export const removedBackends = internalQuery({
  args: {},
  handler: async (ctx) => {
    const sids = new Set<Id<'backendServers'>>();
    for (const r of await ctx.db.query('panelSetups').collect()) sids.add(r.backendServerId);
    for (const r of await ctx.db.query('panelObserveState').collect()) sids.add(r.backendServerId);
    for (const r of await ctx.db.query('panelNodeIntents').collect()) sids.add(r.backendServerId);
    for (const r of await ctx.db.query('sniInboundBindings').collect()) sids.add(r.backendServerId);
    for (const r of await ctx.db.query('edgeDeliveryBindings').collect())
      sids.add(r.backendServerId);
    for (const r of await ctx.db.query('panelOwnership').take(PURGE_READ_CAP))
      sids.add(r.backendServerId);
    const gone: Id<'backendServers'>[] = [];
    for (const sid of sids) if (!(await ctx.db.get(sid))) gone.push(sid);
    return gone;
  },
});
