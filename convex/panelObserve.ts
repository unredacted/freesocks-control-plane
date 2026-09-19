/**
 * Panel observation for server management: read a panel's nodes, config
 * profiles, Hosts and squads, and cache the NON-SECRET projection so Admin can
 * show what already exists before anything is written. READ-ONLY toward the
 * panel, and the sole writer of the `panel*` cache tables.
 *
 * Runs at the tail of the backend healthcheck when `servers.manage.observe` is
 * on (`observeInstance`), and on demand (`refresh`). A failure is recorded as a
 * code word on `panelObserveState`, never as the provider's message, and never
 * marks the instance unhealthy.
 */
import { writeAuditLog } from './lib/audit';
import { adoptObservedReservations } from './panelReservations';
import { ConvexError, v } from 'convex/values';
import type { ActionCtx } from './_generated/server';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { capabilitiesOf } from './lib/backends/capabilities';
import { PROVIDERS, type BackendConfig } from './lib/backends/registry';
import type {
  PanelObservation,
  PanelObservedHost,
  PanelObservedInbound,
  PanelObservedSquad,
} from './lib/backends/types';
import { panelDigestKey } from './lib/panel/key';

const nullableString = v.union(v.string(), v.null());

const observedInbound = v.object({
  tag: v.string(),
  inboundUuid: v.string(),
  protocol: v.string(),
  port: v.union(v.number(), v.null()),
  listen: v.optional(v.string()),
  network: v.string(),
  security: v.string(),
  reality: v.optional(v.object({ target: nullableString, serverNames: v.array(v.string()) })),
  tlsServerName: v.optional(nullableString),
  path: v.optional(nullableString),
  serviceName: v.optional(nullableString),
  realityAuth: v.optional(
    v.object({ digest: nullableString, publicKey: nullableString, publicKeyMismatch: v.boolean() }),
  ),
});

type StoredInbound = Doc<'panelProfiles'>['inbounds'][number];

/** The provider's inbound projection, flattened to the stored shape. Pure. */
export function toStoredInbound(i: PanelObservedInbound): StoredInbound {
  const out: StoredInbound = {
    tag: i.tag,
    inboundUuid: i.configProfileInboundUuid,
    protocol: i.protocol,
    port: i.port,
    network: i.network,
    security: i.security,
  };
  if (i.listen) out.listen = i.listen;
  if (i.reality) out.reality = i.reality;
  if (i.tls) out.tlsServerName = i.tls.serverName;
  const path = i.ws?.path ?? i.httpupgrade?.path ?? i.xhttp?.path;
  if (path !== undefined) out.path = path;
  if (i.grpc) out.serviceName = i.grpc.serviceName;
  if (i.realityAuth) out.realityAuth = i.realityAuth;
  return out;
}

const opt = <T>(x: T | null): T | undefined => (x === null ? undefined : x);

type Db = import('./_generated/server').MutationCtx['db'];

/**
 * Replace an instance's cached Hosts with what was just read: rows the panel
 * still lists are replaced in place, rows it no longer lists are deleted. The
 * one mapping from the provider's Host shape to the stored row, shared with the
 * ledger's post-settle refresh (`panelLedger.syncCache`).
 */
export async function upsertObservedHosts(
  ctx: { db: Db },
  sid: Id<'backendServers'>,
  hosts: readonly PanelObservedHost[],
  now: number,
) {
  const rows = await ctx.db
    .query('panelHosts')
    .withIndex('by_server', (q) => q.eq('backendServerId', sid))
    .collect();
  const by = new Map(rows.map((r) => [r.hostUuid, r]));
  for (const h of hosts) {
    const row = {
      backendServerId: sid,
      hostUuid: h.hostUuid,
      remark: h.remark,
      address: h.address,
      port: h.port,
      sni: opt(h.sni),
      host: opt(h.host),
      path: opt(h.path),
      alpn: opt(h.alpn),
      fingerprint: opt(h.fingerprint),
      securityLayer: opt(h.securityLayer),
      isDisabled: h.isDisabled,
      isHidden: h.isHidden,
      tag: opt(h.tag),
      viewPosition: opt(h.viewPosition),
      configProfileUuid: opt(h.configProfileUuid),
      configProfileInboundUuid: opt(h.configProfileInboundUuid),
      nodeUuids: h.nodeUuids,
      observedAt: now,
    };
    const prev = by.get(h.hostUuid);
    if (prev) await ctx.db.replace(prev._id, row);
    else await ctx.db.insert('panelHosts', row);
    by.delete(h.hostUuid);
  }
  for (const gone of by.values()) await ctx.db.delete(gone._id);
}

/** The same for squads. */
export async function upsertObservedSquads(
  ctx: { db: Db },
  sid: Id<'backendServers'>,
  squads: readonly PanelObservedSquad[],
  now: number,
) {
  const rows = await ctx.db
    .query('panelSquads')
    .withIndex('by_server', (q) => q.eq('backendServerId', sid))
    .collect();
  const by = new Map(rows.map((r) => [r.squadUuid, r]));
  for (const sq of squads) {
    const row = {
      backendServerId: sid,
      squadUuid: sq.squadUuid,
      name: sq.name,
      inboundUuids: sq.inboundUuids,
      membersCount: opt(sq.membersCount),
      observedAt: now,
    };
    const prev = by.get(sq.squadUuid);
    if (prev) await ctx.db.replace(prev._id, row);
    else await ctx.db.insert('panelSquads', row);
    by.delete(sq.squadUuid);
  }
  for (const gone of by.values()) await ctx.db.delete(gone._id);
}

export const record = internalMutation({
  args: {
    backendServerId: v.id('backendServers'),
    // FCP itself just edited profiles outside the ledger (the logging harden):
    // a moved token is a new baseline, not somebody else's edit.
    ownEdit: v.optional(v.boolean()),
    digestKeyId: v.string(),
    nodes: v.array(
      v.object({
        nodeUuid: v.string(),
        name: v.string(),
        address: nullableString,
        port: v.union(v.number(), v.null()),
        countryCode: nullableString,
        online: v.boolean(),
        isDisabled: v.boolean(),
        usersOnline: v.number(),
        configProfileUuid: nullableString,
        activeInboundUuids: v.array(v.string()),
        tags: v.array(v.string()),
      }),
    ),
    profiles: v.array(
      v.object({
        profileUuid: v.string(),
        name: v.string(),
        shapeHash: v.string(),
        changeToken: v.string(),
        inbounds: v.array(observedInbound),
      }),
    ),
    hosts: v.array(
      v.object({
        hostUuid: v.string(),
        remark: v.string(),
        address: v.string(),
        port: v.number(),
        sni: nullableString,
        host: nullableString,
        path: nullableString,
        alpn: nullableString,
        fingerprint: nullableString,
        securityLayer: nullableString,
        isDisabled: v.boolean(),
        isHidden: v.boolean(),
        tag: nullableString,
        viewPosition: v.union(v.number(), v.null()),
        configProfileUuid: nullableString,
        configProfileInboundUuid: nullableString,
        nodeUuids: v.array(v.string()),
      }),
    ),
    squads: v.array(
      v.object({
        squadUuid: v.string(),
        name: v.string(),
        inboundUuids: v.array(v.string()),
        membersCount: v.union(v.number(), v.null()),
      }),
    ),
  },
  handler: async (ctx, a) => {
    const now = Date.now();
    const sid = a.backendServerId;

    const nodeRows = await ctx.db
      .query('panelNodes')
      .withIndex('by_server', (q) => q.eq('backendServerId', sid))
      .collect();
    const nodeBy = new Map(nodeRows.map((r) => [r.nodeUuid, r]));
    for (const n of a.nodes) {
      const row = {
        backendServerId: sid,
        nodeUuid: n.nodeUuid,
        name: n.name,
        address: opt(n.address),
        port: opt(n.port),
        countryCode: opt(n.countryCode),
        online: n.online,
        isDisabled: n.isDisabled,
        usersOnline: n.usersOnline,
        configProfileUuid: opt(n.configProfileUuid),
        activeInboundUuids: n.activeInboundUuids,
        tags: n.tags,
        observedAt: now,
      };
      const prev = nodeBy.get(n.nodeUuid);
      if (prev) await ctx.db.replace(prev._id, row);
      else await ctx.db.insert('panelNodes', row);
      nodeBy.delete(n.nodeUuid);
    }
    for (const gone of nodeBy.values()) await ctx.db.delete(gone._id);

    const profileRows = await ctx.db
      .query('panelProfiles')
      .withIndex('by_server', (q) => q.eq('backendServerId', sid))
      .collect();
    const profileBy = new Map(profileRows.map((r) => [r.profileUuid, r]));
    // Every token a change made from FCP said the profile would end up with.
    // An edit that lands on one of them is ours, whenever it is first seen.
    const expectedTokens = new Set<string>();
    if (!a.ownEdit)
      for (const op of await ctx.db
        .query('panelOps')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .order('desc')
        .take(200)) {
        if (op.kind !== 'profile') continue;
        try {
          const token = (JSON.parse(op.postcondition) as { expectedToken?: unknown }).expectedToken;
          if (typeof token === 'string') expectedTokens.add(token);
        } catch {
          // An unreadable postcondition expects nothing.
        }
      }
    for (const p of a.profiles) {
      const prev = profileBy.get(p.profileUuid);
      // A token made with another key is a new baseline, not a change.
      const moved =
        !!prev && prev.digestKeyId === a.digestKeyId && prev.changeToken !== p.changeToken;
      const row = {
        backendServerId: sid,
        profileUuid: p.profileUuid,
        name: p.name,
        shapeHash: p.shapeHash,
        changeToken: p.changeToken,
        digestKeyId: a.digestKeyId,
        tokenChangedAt: moved ? now : prev?.tokenChangedAt,
        foreignEditAt:
          moved && !a.ownEdit && !expectedTokens.has(p.changeToken) ? now : prev?.foreignEditAt,
        inbounds: p.inbounds,
        observedAt: now,
      };
      if (prev) await ctx.db.replace(prev._id, row);
      else await ctx.db.insert('panelProfiles', row);
      profileBy.delete(p.profileUuid);
    }
    for (const gone of profileBy.values()) await ctx.db.delete(gone._id);

    await upsertObservedHosts(ctx, sid, a.hosts, now);
    await upsertObservedSquads(ctx, sid, a.squads, now);

    // A reserved identity that now exists was made by the run that reserved it.
    await adoptObservedReservations(ctx, sid);

    await stampState(ctx, sid, {
      attemptedAt: now,
      observedAt: now,
      ok: true,
      counts: {
        nodes: a.nodes.length,
        profiles: a.profiles.length,
        hosts: a.hosts.length,
        squads: a.squads.length,
      },
    });
    return null;
  },
});

async function stampState(
  ctx: { db: import('./_generated/server').MutationCtx['db'] },
  backendServerId: Id<'backendServers'>,
  patch: Omit<Doc<'panelObserveState'>, '_id' | '_creationTime' | 'backendServerId'>,
) {
  const prev = await ctx.db
    .query('panelObserveState')
    .withIndex('by_server', (q) => q.eq('backendServerId', backendServerId))
    .unique();
  if (prev) await ctx.db.replace(prev._id, { backendServerId, ...patch });
  else await ctx.db.insert('panelObserveState', { backendServerId, ...patch });
}

/** A failed look keeps the last good snapshot and its time; only the verdict moves. */
export const recordFailure = internalMutation({
  args: { backendServerId: v.id('backendServers'), errorCode: v.string() },
  handler: async (ctx, { backendServerId, errorCode }) => {
    const prev = await ctx.db
      .query('panelObserveState')
      .withIndex('by_server', (q) => q.eq('backendServerId', backendServerId))
      .unique();
    await stampState(ctx, backendServerId, {
      attemptedAt: Date.now(),
      observedAt: prev?.observedAt,
      ok: false,
      errorCode,
      counts: prev?.counts,
    });
    return null;
  },
});

/** Drop an instance's cache (the instance was removed, or lost the capability). */
export const clear = internalMutation({
  args: { backendServerId: v.id('backendServers') },
  handler: async (ctx, { backendServerId }) => {
    for (const table of [
      'panelNodes',
      'panelProfiles',
      'panelHosts',
      'panelSquads',
      'panelObserveState',
    ] as const) {
      const rows = await ctx.db
        .query(table)
        .withIndex('by_server', (q) => q.eq('backendServerId', backendServerId))
        .collect();
      for (const r of rows) await ctx.db.delete(r._id);
    }
    return null;
  },
});

function toRecordArgs(o: PanelObservation) {
  return {
    nodes: o.nodes,
    profiles: o.profiles.map((p) => ({ ...p, inbounds: p.inbounds.map(toStoredInbound) })),
    hosts: o.hosts,
    squads: o.squads,
  };
}

/**
 * Observe ONE instance and record the outcome. Never throws: the healthcheck
 * calls it in its own best-effort slot. Returns whether the look succeeded.
 */
export async function observeInstance(
  ctx: ActionCtx,
  server: { _id: Id<'backendServers'>; backend: Doc<'backendServers'>['backend']; config: unknown },
  opts: { ownEdit?: boolean } = {},
): Promise<boolean> {
  const provider = PROVIDERS[server.backend];
  if (!provider.observePanel) return false;
  try {
    const { key, keyId } = await panelDigestKey();
    const seen = await provider.observePanel(server.config as BackendConfig, key);
    await ctx.runMutation(internal.panelObserve.record, {
      backendServerId: server._id,
      digestKeyId: keyId,
      ownEdit: opts.ownEdit,
      ...toRecordArgs(seen),
    });
    return true;
  } catch {
    // The provider's message is never persisted (a panel can say anything).
    await ctx.runMutation(internal.panelObserve.recordFailure, {
      backendServerId: server._id,
      errorCode: 'servers.observe_failed',
    });
    return false;
  }
}

/** Observe one instance now (Admin -> Servers, "Refresh"). A failure is reported to the caller. */
/** An operator has seen that a profile was edited elsewhere, and looked at it. */
export const acknowledgeForeignEdit = internalMutation({
  args: {
    backendServerId: v.id('backendServers'),
    profileUuid: v.string(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const row = await ctx.db
      .query('panelProfiles')
      .withIndex('by_server_uuid', (q) =>
        q.eq('backendServerId', a.backendServerId).eq('profileUuid', a.profileUuid),
      )
      .unique();
    if (!row) throw new ConvexError({ code: 'not_found', message: 'No such profile' });
    if (row.foreignEditAt === undefined) return { ok: true as const };
    await ctx.db.patch(row._id, { foreignEditAt: undefined });
    const server = await ctx.db.get(a.backendServerId);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'servers.profile.foreign_edit_seen',
      targetType: 'backend_server',
      targetId: a.backendServerId,
      payload: { backendSlug: server?.slug ?? '', label: row.name },
    });
    return { ok: true as const };
  },
});

export const refresh = internalAction({
  args: { backendServerId: v.id('backendServers'), ownEdit: v.optional(v.boolean()) },
  handler: async (ctx, { backendServerId, ownEdit }): Promise<{ ok: true }> => {
    const server = await ctx.runQuery(internal.backendServers.getById, { id: backendServerId });
    if (!server) throw new ConvexError({ code: 'not_found', message: 'Backend server not found' });
    if (!capabilitiesOf(server.backend).panelObservation)
      throw new ConvexError({
        code: 'servers.unsupported_backend',
        message: 'This backend type has nothing to observe',
      });
    if (!(await observeInstance(ctx, server, { ownEdit })))
      throw new ConvexError({
        code: 'backend.panel_read_failed',
        message: 'The panel could not be read',
      });
    return { ok: true };
  },
});

// --- reads ---------------------------------------------------------------------------------------

export const snapshot = internalQuery({
  args: { backendServerId: v.id('backendServers') },
  handler: async (ctx, { backendServerId }) => {
    const sid = backendServerId;
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
        .withIndex('by_server', (q) => q.eq('backendServerId', backendServerId))
        .unique(),
    ]);
    return { nodes, profiles, hosts, squads, state };
  },
});

export const states = internalQuery({
  args: {},
  handler: (ctx) => ctx.db.query('panelObserveState').collect(),
});
