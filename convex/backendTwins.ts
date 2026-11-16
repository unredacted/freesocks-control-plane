/**
 * A mode's ENCRYPTED TWIN on a backend (docs/backends.md "VLESS Encryption",
 * docs/servers.md "A mode's encrypted twin").
 *
 * A WebSocket mode behind a CDN is not end to end: the CDN holds the VLESS
 * stream in the clear. Its nodes can serve the same mode a second time, with
 * VLESS Encryption inside the stream, on another loopback port and path
 * behind the same front server, so the same fronts reach it. An inbound that
 * runs the layer refuses every app that does not speak it, so the mode's own
 * transport is never switched: the twin is a SECOND transport of the profile,
 * added with "Add a transport" (its server key is made in that attempt), and
 * this module makes it the mode's:
 *
 *  - `attach` checks the transport against the last look at the backend (a
 *    loopback WebSocket transport of the setup's profile, running a VLESS
 *    Encryption FCP's own sessions can speak, on a port and path of its own),
 *    puts it into the mode's group beside the mode's transport (a ledger op:
 *    members of the mode then hold a credential for it), and records it on
 *    the setup;
 *  - `detach` takes it out of the group and off the setup, refused while a
 *    node still serves it.
 *
 * Nothing here turns the twin on for a node, writes an address for it or
 * hands it to a member: a group that carries a transport no node serves and
 * no Host names gives members nothing new.
 */
import { ConvexError, v } from 'convex/values';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { internalMutation, type MutationCtx } from './_generated/server';
import { writeAuditLog } from './lib/audit';
import { resolveServerConfig } from './lib/serverConfig';
import { fcpWrites, groupCarriesMode, setupReady, type SetupMode } from './backendSetup';
import { twinProblem, type TwinProblem } from './lib/backend/modeTwin';

const refuse = (code: string, message: string): never => {
  throw new ConvexError({ code, message });
};

const WORDS: Record<TwinProblem, string> = {
  'servers.twin_unsupported': 'Only a WebSocket mode behind a CDN takes an encrypted twin',
  'servers.twin_present': 'This mode already has an encrypted twin. Take it away first',
  'servers.twin_transport_unknown':
    'That transport is not on this backend’s profile. Refresh, then try again',
  'servers.twin_transport_taken': 'That transport already belongs to a mode',
  'servers.twin_not_websocket':
    'The twin has to be a loopback WebSocket transport like the mode’s own',
  'servers.twin_not_encrypted':
    'That transport does not run VLESS Encryption. Add one with "Encrypt inside the connection"',
  'servers.twin_encryption_unreadable':
    'FCP cannot read that transport’s VLESS Encryption on the profile. Refresh, then try again',
  'servers.twin_encryption_unsupported':
    'FCP cannot check a transport with that VLESS Encryption (the random appearance, or several keys)',
  'servers.twin_same_route':
    'The twin needs a port and a path of its own: the node’s front server tells the two apart by them',
};

const actor = { actorAdminId: v.optional(v.id('adminUsers')) };

async function context(ctx: MutationCtx, backendServerId: Id<'backendServers'>, slug: string) {
  if (!(await resolveServerConfig(ctx.db)).manage.enabled)
    refuse('servers.manage_disabled', 'Server changes are switched off in Servers settings');
  const server = await ctx.db.get(backendServerId);
  if (!server) return refuse('not_found', 'Backend server not found');
  const row = await ctx.db
    .query('panelSetups')
    .withIndex('by_server', (q) => q.eq('backendServerId', backendServerId))
    .unique();
  if (!setupReady(row) || !fcpWrites(row))
    return refuse('servers.panel_not_set_up', 'The backend is not set up');
  if (row.claim && row.claim.expiresAt > Date.now())
    refuse('servers.setup_running', 'This backend’s setup is running. Try again when it is done');
  const mode = row.modes.find((m) => m.slug === slug);
  if (!mode || !mode.transport || !mode.groupUuid)
    return refuse('servers.mode_unknown', `This backend has no mode "${slug}"`);
  const profile = row.profileUuid
    ? await ctx.db
        .query('panelProfiles')
        .withIndex('by_server_uuid', (q) =>
          q.eq('backendServerId', backendServerId).eq('profileUuid', row.profileUuid!),
        )
        .unique()
    : null;
  const group = await ctx.db
    .query('panelSquads')
    .withIndex('by_server_uuid', (q) =>
      q.eq('backendServerId', backendServerId).eq('squadUuid', mode.groupUuid!),
    )
    .unique();
  if (!group)
    return refuse('not_found', 'That mode’s group is not on this backend. Refresh and retry');
  return { server, row, mode, inbounds: profile?.inbounds ?? [], group };
}

async function saveMode(ctx: MutationCtx, row: Doc<'panelSetups'>, next: SetupMode) {
  await ctx.db.patch(row._id, {
    modes: (row.modes ?? []).map((m) => (m.slug === next.slug ? next : m)),
    updatedAt: Date.now(),
  });
}

/**
 * Make a transport of the profile the mode's encrypted twin. Answers the
 * ledger op that puts it into the mode's group (null when the group already
 * carries it): the caller runs it.
 */
export const attach = internalMutation({
  args: {
    backendServerId: v.id('backendServers'),
    slug: v.string(),
    transportTag: v.string(),
    ...actor,
  },
  handler: async (ctx, a): Promise<{ opId: Id<'panelOps'> | null }> => {
    const c = await context(ctx, a.backendServerId, a.slug);
    const tag = a.transportTag.trim();
    const problem = twinProblem({
      mode: c.mode,
      modes: c.row.modes,
      inbounds: c.inbounds,
      tag,
    });
    if (problem) refuse(problem, WORDS[problem]);
    const inbound = c.inbounds.find((i) => i.tag === tag);
    // Asked again for the twin it has (an op that did not settle): the record
    // stands, and only the group is looked at again.
    const twin: NonNullable<SetupMode['twin']> =
      c.mode.twin ??
      (inbound
        ? {
            tag,
            uuid: inbound.inboundUuid,
            ...(inbound.listen ? { listen: inbound.listen } : {}),
            port: inbound.port!,
            path: inbound.path!,
          }
        : refuse('servers.twin_transport_unknown', WORDS['servers.twin_transport_unknown']));
    const next: SetupMode = { ...c.mode, twin };
    // The group: the mode's transport and the twin, nothing else. A group that
    // holds anything else has drifted, and is not rewritten from here.
    let opId: Id<'panelOps'> | null = null;
    if (!groupCarriesMode(c.group.inboundUuids, next)) {
      if (!groupCarriesMode(c.group.inboundUuids, c.mode))
        refuse(
          `servers.setup_mode_drifted:${c.mode.slug}`,
          `The group of mode ${c.mode.name} changed on the backend. Look at it under Mode groups first`,
        );
      opId = (
        await ctx.runMutation(internal.backendWrites.requestModeGroupUpdate, {
          backendServerId: a.backendServerId,
          squadUuid: c.group.squadUuid,
          inboundUuids: [c.mode.transport!.uuid, twin.uuid],
          actorAdminId: a.actorAdminId,
        })
      ).opId;
    }
    await saveMode(ctx, c.row, next);
    await writeAuditLog(ctx, {
      actorType: a.actorAdminId ? 'admin' : 'system',
      actorId: a.actorAdminId ?? undefined,
      action: 'admin.servers.mode_twin.attach',
      targetType: 'backend_server',
      targetId: a.backendServerId,
      payload: {
        backendSlug: c.server.slug,
        mode: c.mode.slug,
        tag,
        port: twin.port,
        auth: inbound?.vlessEncryption?.auth ?? null,
      },
    });
    return { opId };
  },
});

/** Take a mode's encrypted twin away: out of its group and off the setup. The transport stays on the profile. */
export const detach = internalMutation({
  args: { backendServerId: v.id('backendServers'), slug: v.string(), ...actor },
  handler: async (ctx, a): Promise<{ opId: Id<'panelOps'> | null }> => {
    const c = await context(ctx, a.backendServerId, a.slug);
    const twin = c.mode.twin;
    if (!twin) return refuse('servers.twin_absent', 'This mode has no encrypted twin');
    // A node that serves it has members' entries pointing at it.
    const nodes = await ctx.db
      .query('panelNodes')
      .withIndex('by_server', (q) => q.eq('backendServerId', a.backendServerId))
      .collect();
    if (nodes.some((n) => n.activeInboundUuids.includes(twin.uuid)))
      refuse(
        'servers.twin_in_use',
        'A node still serves the encrypted twin. Turn it off there first',
      );
    const { twin: _gone, ...rest } = c.mode;
    void _gone;
    const next: SetupMode = rest;
    let opId: Id<'panelOps'> | null = null;
    if (!groupCarriesMode(c.group.inboundUuids, next))
      opId = (
        await ctx.runMutation(internal.backendWrites.requestModeGroupUpdate, {
          backendServerId: a.backendServerId,
          squadUuid: c.group.squadUuid,
          inboundUuids: [c.mode.transport!.uuid],
          actorAdminId: a.actorAdminId,
        })
      ).opId;
    await saveMode(ctx, c.row, next);
    await writeAuditLog(ctx, {
      actorType: a.actorAdminId ? 'admin' : 'system',
      actorId: a.actorAdminId ?? undefined,
      action: 'admin.servers.mode_twin.detach',
      targetType: 'backend_server',
      targetId: a.backendServerId,
      payload: { backendSlug: c.server.slug, mode: c.mode.slug, tag: twin.tag },
    });
    return { opId };
  },
});
