/**
 * The node role's reservations: how the role and FCP avoid both creating, or
 * one recreating what the other removed.
 *
 * Before the role creates an ABSENT node, Host, inbound, squad or profile on an
 * instance FCP manages, it reserves that identity here. One mutation decides:
 * a tombstoned identity (removed on purpose) is refused, an identity FCP is
 * creating right now is refused, anything else becomes `reserved`. While a
 * reservation is open FCP does not create that identity either
 * (`servers.reservation_open`, enforced in `panelWrites`).
 *
 * A reservation closes in exactly three ways, never by a timeout:
 *  - the role settles it (`created` with the panel uuid, or
 *    `rejected_pre_mutation`: the panel refused before doing anything);
 *  - FCP OBSERVES the object on the panel (the role's answer was lost): it is
 *    adopted as owned;
 *  - the same attested recovery an op with an unknown outcome needs.
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery, type MutationCtx } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { claimKey, hostIdentity } from './lib/panel/ops';

const refuse = (code: string, message: string): never => {
  throw new ConvexError({ code, message });
};

export const reservationKind = v.union(
  v.literal('node'),
  v.literal('host'),
  v.literal('inbound'),
  v.literal('squad'),
  v.literal('profile'),
);
type Kind = Doc<'panelOwnership'>['kind'];

/** The claim an FCP create of the same identity would hold right now. */
function createClaimKey(kind: Kind, identity: string): string | null {
  if (kind === 'node') return `nodename:${identity.toLowerCase()}`;
  if (kind === 'squad') return claimKey.squadName(identity);
  if (kind === 'host') return claimKey.hostIdentity(identity);
  return null;
}

async function rowsOfKind(ctx: MutationCtx, sid: Id<'backendServers'>, kind: Kind) {
  return ctx.db
    .query('panelOwnership')
    .withIndex('by_server_kind_identity', (q) => q.eq('backendServerId', sid).eq('kind', kind))
    .collect();
}

/** What the last look at the panel holds under this identity, if anything. */
async function observedUuid(
  ctx: MutationCtx,
  sid: Id<'backendServers'>,
  kind: Kind,
  identity: string,
): Promise<string | null> {
  if (kind === 'node') {
    const rows = await ctx.db
      .query('panelNodes')
      .withIndex('by_server', (q) => q.eq('backendServerId', sid))
      .collect();
    return rows.find((n) => n.name === identity)?.nodeUuid ?? null;
  }
  if (kind === 'squad') {
    const rows = await ctx.db
      .query('panelSquads')
      .withIndex('by_server', (q) => q.eq('backendServerId', sid))
      .collect();
    return rows.find((s) => s.name === identity)?.squadUuid ?? null;
  }
  if (kind === 'host') {
    const rows = await ctx.db
      .query('panelHosts')
      .withIndex('by_server', (q) => q.eq('backendServerId', sid))
      .collect();
    // Host attributes are not unique: two matches are not an adoption.
    const hits = rows.filter(
      (h) =>
        h.configProfileInboundUuid !== undefined &&
        hostIdentity({
          remark: h.remark,
          inboundUuid: h.configProfileInboundUuid,
          address: h.address,
          port: h.port,
        }) === identity,
    );
    return hits.length === 1 ? hits[0].hostUuid : null;
  }
  const profiles = await ctx.db
    .query('panelProfiles')
    .withIndex('by_server', (q) => q.eq('backendServerId', sid))
    .collect();
  if (kind === 'profile') return profiles.find((p) => p.name === identity)?.profileUuid ?? null;
  // Inbound tags are unique panel-wide (measured).
  for (const p of profiles) {
    const hit = p.inbounds.find((i) => i.tag === identity);
    if (hit) return hit.inboundUuid;
  }
  return null;
}

const hostSpec = v.object({
  remark: v.string(),
  inboundUuid: v.string(),
  address: v.string(),
  port: v.number(),
});

export const reserve = internalMutation({
  args: {
    backendServerId: v.id('backendServers'),
    roleOpId: v.string(),
    kind: reservationKind,
    // A name (node, squad, profile), an inbound tag, or for a Host its parts.
    identity: v.optional(v.string()),
    host: v.optional(hostSpec),
    tokenId: v.optional(v.id('apiTokens')),
  },
  handler: async (ctx, a) => {
    const sid = a.backendServerId;
    if (!/^[A-Za-z0-9._:-]{8,80}$/.test(a.roleOpId))
      refuse('validation', 'roleOpId is 8 to 80 plain characters');
    const identity = a.kind === 'host' ? (a.host ? hostIdentity(a.host) : '') : (a.identity ?? '');
    if (!identity || identity.length > 400) refuse('validation', 'An identity is required');

    const mine = await ctx.db
      .query('panelOwnership')
      .withIndex('by_reservation', (q) => q.eq('reservation.roleOpId', a.roleOpId))
      .first();
    if (mine) {
      // The same call again (the role retried its request): the same answer.
      if (mine.backendServerId === sid && mine.kind === a.kind && mine.identity === identity)
        return { ok: true as const, roleOpId: a.roleOpId, state: mine.state };
      refuse('servers.reservation_conflict', 'This roleOpId already reserves something else');
    }

    const rows = (await rowsOfKind(ctx, sid, a.kind)).filter((r) => r.lookup.includes(identity));
    if (rows.some((r) => r.state === 'tombstoned'))
      refuse('servers.tombstoned', 'This was removed on purpose and is not to be created again');
    if (rows.some((r) => r.state === 'reserved'))
      refuse('servers.reservation_open', 'Another run has reserved this and has not settled it');
    if (rows.some((r) => r.state === 'owned') || (await observedUuid(ctx, sid, a.kind, identity)))
      refuse('servers.exists', 'This already exists on the panel: look it up instead of creating');
    const key = createClaimKey(a.kind, identity);
    if (key) {
      const claim = await ctx.db
        .query('panelClaims')
        .withIndex('by_server_key', (q) => q.eq('backendServerId', sid).eq('key', key))
        .unique();
      if (claim) refuse('servers.op_running', 'This is being created from the admin right now');
    }

    const now = Date.now();
    await ctx.db.insert('panelOwnership', {
      backendServerId: sid,
      kind: a.kind,
      identity,
      lookup: [identity],
      state: 'reserved',
      reservation: { roleOpId: a.roleOpId, at: now, tokenId: a.tokenId },
      since: now,
      updatedAt: now,
    });
    return { ok: true as const, roleOpId: a.roleOpId, state: 'reserved' as const };
  },
});

export const settle = internalMutation({
  args: {
    backendServerId: v.id('backendServers'),
    roleOpId: v.string(),
    outcome: v.union(v.literal('created'), v.literal('rejected_pre_mutation')),
    panelUuid: v.optional(v.string()),
  },
  handler: async (ctx, a) => {
    const row = await ctx.db
      .query('panelOwnership')
      .withIndex('by_reservation', (q) => q.eq('reservation.roleOpId', a.roleOpId))
      .first();
    if (!row || row.backendServerId !== a.backendServerId)
      return refuse('not_found', 'No such reservation');
    if (a.outcome === 'rejected_pre_mutation') {
      // Nothing was made, so nothing is owned and nothing is remembered.
      await ctx.db.delete(row._id);
      return { ok: true as const, state: 'released' as const };
    }
    if (!a.panelUuid || a.panelUuid.length > 80)
      return refuse('validation', 'A created object is settled with its panel uuid');
    await ctx.db.patch(row._id, {
      state: 'owned',
      panelUuid: a.panelUuid,
      reservation: undefined,
      updatedAt: Date.now(),
    });
    return { ok: true as const, state: 'owned' as const };
  },
});

/**
 * After a look at the panel: a reserved identity that now EXISTS was created
 * by the run that reserved it (nobody else may create it), whatever became of
 * that run's answer. Called from the observation's own mutation.
 */
export async function adoptObservedReservations(ctx: MutationCtx, sid: Id<'backendServers'>) {
  for (const kind of ['node', 'host', 'inbound', 'squad', 'profile'] as const) {
    const open = (await rowsOfKind(ctx, sid, kind)).filter((r) => r.state === 'reserved');
    for (const row of open) {
      const uuid = await observedUuid(ctx, sid, kind, row.identity);
      if (!uuid) continue;
      await ctx.db.patch(row._id, {
        state: 'owned',
        panelUuid: uuid,
        reservation: undefined,
        updatedAt: Date.now(),
      });
    }
  }
}

/** Refuse an FCP create of an identity a role run holds. */
export async function assertNotReserved(
  ctx: MutationCtx,
  sid: Id<'backendServers'>,
  kind: Kind,
  identity: string,
) {
  const rows = await rowsOfKind(ctx, sid, kind);
  if (rows.some((r) => r.state === 'reserved' && r.lookup.includes(identity)))
    refuse(
      'servers.reservation_open',
      'The node role has reserved this and has not said how that ended',
    );
}

/**
 * The attested exit for a reservation whose run never answered and whose
 * object never appeared: the same named conditions an op's unknown outcome needs.
 */
export const recover = internalMutation({
  args: {
    backendServerId: v.id('backendServers'),
    roleOpId: v.string(),
    credentialsRevoked: v.boolean(),
    noInFlightExecutor: v.boolean(),
    queueDrained: v.boolean(),
    freshReadAt: v.number(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const row = await ctx.db
      .query('panelOwnership')
      .withIndex('by_reservation', (q) => q.eq('reservation.roleOpId', a.roleOpId))
      .first();
    if (!row || row.backendServerId !== a.backendServerId)
      return refuse('not_found', 'No such reservation');
    if (!a.credentialsRevoked || !a.noInFlightExecutor || !a.queueDrained)
      return refuse(
        'servers.recovery_incomplete',
        'Every condition must hold before an unknown outcome can be released',
      );
    const server = await ctx.db.get(row.backendServerId);
    await ctx.db.delete(row._id);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'servers.reservation.recover',
      targetType: 'backend_server',
      targetId: row.backendServerId,
      payload: { backendSlug: server?.slug ?? '', kind: row.kind },
    });
    return { ok: true as const };
  },
});

export const list = internalQuery({
  args: { backendServerId: v.id('backendServers') },
  handler: async (ctx, { backendServerId }) => {
    const out: { roleOpId: string; kind: Kind; label: string; at: number }[] = [];
    for (const kind of ['node', 'host', 'inbound', 'squad', 'profile'] as const) {
      const rows = await ctx.db
        .query('panelOwnership')
        .withIndex('by_server_kind_identity', (q) =>
          q.eq('backendServerId', backendServerId).eq('kind', kind),
        )
        .collect();
      for (const r of rows)
        if (r.state === 'reserved' && r.reservation)
          out.push({
            roleOpId: r.reservation.roleOpId,
            kind,
            // A Host identity is its parts: show the remark only.
            label: kind === 'host' ? String(JSON.parse(r.identity)[0]) : r.identity,
            at: r.reservation.at,
          });
    }
    return out;
  },
});
