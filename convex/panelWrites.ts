/**
 * Server-management writes: Hosts and internal mode groups. Every write is a
 * `request*` mutation (validate against what FCP knows, then claim through the
 * ledger) followed by `run` (send ONCE, then look). The mutation refuses
 * anything that belongs to the edges machinery or that would strand members;
 * the ledger decides when a claim may be released (panelLedger.ts).
 *
 * What queues node work on the backend (measured against the backend's source and
 * the managed-node harness): changing a mode group's transports and deleting a mode group
 * re-apply the affected config profiles to their nodes; creating or renaming a
 * mode group, and every Host write, do not. The first kind also claims those
 * profiles and nodes and holds the claims until the nodes show the work ran.
 */
import { ConvexError, v } from 'convex/values';
import type { ActionCtx, MutationCtx } from './_generated/server';
import { internalAction, internalMutation } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { runWithCronOutcome } from './cronHeartbeat';
import { PROVIDERS, type BackendConfig } from './lib/backends/registry';
import type {
  PanelHostCreate,
  PanelHostFields,
  PanelNodeFields,
  ProfilePatchPreview,
} from './lib/backends/types';
import {
  callResultOf,
  claimKey,
  classifyRequest,
  hostIdentity,
  hostLock,
  hostsMatchingIdentity,
  looksLikeRelayRemark,
} from './lib/panel/ops';
import { poolFromConfig } from './lib/remnawavePlacement';
import { parseRealityTarget } from './lib/edges/inboundMapping';
import { assertNoRotationOrQuarantine } from './lib/edges/relayGuards';
import { panelDigestKey } from './lib/panel/key';
import { PatchRefused, checkPatchOps, type PatchOp } from './lib/panel/patchOps';
import { closeForSharedChange } from './panelIntents';
import { claimOp } from './panelLedger';
import { observeInstance } from './panelObserve';

const refuse = (code: string, message: string): never => {
  throw new ConvexError({ code, message });
};

const nullable = v.union(v.string(), v.null());
const hostFields = {
  remark: v.optional(v.string()),
  address: v.optional(v.string()),
  port: v.optional(v.number()),
  sni: v.optional(nullable),
  host: v.optional(nullable),
  path: v.optional(nullable),
  alpn: v.optional(nullable),
  fingerprint: v.optional(nullable),
  securityLayer: v.optional(nullable),
  isDisabled: v.optional(v.boolean()),
  isHidden: v.optional(v.boolean()),
  tag: v.optional(nullable),
  inboundUuid: v.optional(v.string()),
  nodeUuids: v.optional(v.array(v.string())),
};
const actor = { actorAdminId: v.optional(v.id('adminUsers')) };

const ALPN = new Set(['h3', 'h2', 'http/1.1', 'h2,http/1.1', 'h3,h2,http/1.1', 'h3,h2']);
const FINGERPRINTS = new Set([
  'chrome',
  'firefox',
  'safari',
  'ios',
  'android',
  'edge',
  'qq',
  'random',
  'randomized',
]);
const SECURITY_LAYERS = new Set(['DEFAULT', 'TLS', 'NONE']);

function checkHostFields(f: {
  remark?: string;
  address?: string;
  port?: number;
  alpn?: string | null;
  fingerprint?: string | null;
  securityLayer?: string | null;
}) {
  if (f.remark !== undefined && (f.remark.trim().length < 1 || f.remark.length > 40))
    refuse('validation', 'A remark is 1 to 40 characters');
  if (f.address !== undefined && f.address.trim().length < 2)
    refuse('validation', 'An address is required');
  if (f.port !== undefined && (!Number.isInteger(f.port) || f.port < 1 || f.port > 65535))
    refuse('validation', 'A port is 1 to 65535');
  if (f.alpn && !ALPN.has(f.alpn)) refuse('validation', 'Unknown ALPN value');
  if (f.fingerprint && !FINGERPRINTS.has(f.fingerprint))
    refuse('validation', 'Unknown fingerprint value');
  if (f.securityLayer && !SECURITY_LAYERS.has(f.securityLayer))
    refuse('validation', 'Unknown security layer');
}

/** The profile a transport uuid belongs to, from the observation cache. */
async function inboundBinding(ctx: MutationCtx, sid: Id<'backendServers'>, inboundUuid: string) {
  const profiles = await ctx.db
    .query('panelProfiles')
    .withIndex('by_server', (q) => q.eq('backendServerId', sid))
    .collect();
  const profile = profiles.find((p) => p.inbounds.some((i) => i.inboundUuid === inboundUuid));
  if (!profile)
    return refuse(
      'servers.unknown_inbound',
      'That transport is not on this backend. Refresh and retry',
    );
  return { configProfileUuid: profile.profileUuid, configProfileInboundUuid: inboundUuid };
}

/** Which Hosts the edges machinery owns on this instance. */
async function hostLockRefs(ctx: MutationCtx, sid: Id<'backendServers'>) {
  const relays = await ctx.db
    .query('relays')
    .withIndex('by_backend_server', (q) => q.eq('backendServerId', sid))
    .collect();
  const listenerHostUuids = new Set<string>();
  const legacyHostUuids = new Set<string>();
  const hideLedgerUuids = new Set<string>();
  for (const r of relays) {
    const listeners = await ctx.db
      .query('relayListeners')
      .withIndex('by_relay', (q) => q.eq('relayId', r._id))
      .collect();
    for (const l of listeners) {
      if (l.host?.uuid) listenerHostUuids.add(l.host.uuid);
      for (const h of l.legacyHosts ?? []) legacyHostUuids.add(h.uuid);
    }
    const hides = await ctx.db
      .query('edgeHostHides')
      .withIndex('by_relay', (q) => q.eq('relayId', r._id))
      .collect();
    for (const h of hides) if (h.state !== 'released') hideLedgerUuids.add(h.hostUuid);
  }
  return { listenerHostUuids, legacyHostUuids, hideLedgerUuids };
}

async function nodeNames(ctx: MutationCtx, sid: Id<'backendServers'>) {
  const nodes = await ctx.db
    .query('panelNodes')
    .withIndex('by_server', (q) => q.eq('backendServerId', sid))
    .collect();
  return nodes.map((n) => n.name);
}

async function cachedHost(ctx: MutationCtx, sid: Id<'backendServers'>, hostUuid: string) {
  const row = await ctx.db
    .query('panelHosts')
    .withIndex('by_server_uuid', (q) => q.eq('backendServerId', sid).eq('hostUuid', hostUuid))
    .unique();
  return row ?? refuse('not_found', 'That Host is not on this backend. Refresh and retry');
}

async function assertHostEditable(ctx: MutationCtx, sid: Id<'backendServers'>, hostUuid: string) {
  const lock = hostLock(hostUuid, await hostLockRefs(ctx, sid));
  if (lock)
    refuse(
      'servers.host_edge_owned',
      'This Host belongs to an edge. Change it from the origin it serves',
    );
}

/** A deliberately removed item is not recreated by name. */
async function assertNotTombstoned(
  ctx: MutationCtx,
  sid: Id<'backendServers'>,
  kind: 'host' | 'squad' | 'node',
  identity: string,
  allow: boolean,
) {
  // A role run holding this identity is not overridden by "I want it back".
  if (allow) return;
  const rows = await ctx.db
    .query('panelOwnership')
    .withIndex('by_server_kind_identity', (q) => q.eq('backendServerId', sid).eq('kind', kind))
    .collect();
  if (rows.some((r) => r.state === 'tombstoned' && r.lookup.includes(identity)))
    refuse(
      'servers.tombstoned',
      'This was removed on purpose. Confirm that you want it back to create it again',
    );
}

// --- Hosts ---------------------------------------------------------------------------------------------

export const requestAddressCreate = internalMutation({
  args: {
    backendServerId: v.id('backendServers'),
    ...hostFields,
    remark: v.string(),
    address: v.string(),
    port: v.number(),
    inboundUuid: v.string(),
    /** Recreate something that was removed on purpose. */
    restore: v.optional(v.boolean()),
    ...actor,
  },
  handler: async (ctx, a) => {
    checkHostFields(a);
    const sid = a.backendServerId;
    if (looksLikeRelayRemark(a.remark, await nodeNames(ctx, sid)))
      refuse('servers.relay_remark', 'Remarks ending in -origin belong to edges. Pick another');
    const inbound = await inboundBinding(ctx, sid, a.inboundUuid);
    const identity = hostIdentity({
      remark: a.remark,
      inboundUuid: a.inboundUuid,
      address: a.address,
      port: a.port,
    });
    await assertNotTombstoned(ctx, sid, 'host', identity, a.restore === true);
    const { backendServerId: _s, actorAdminId, inboundUuid: _i, restore: _r, ...fields } = a;
    const spec: PanelHostCreate = { ...fields, inbound };
    const opId = await claimOp(ctx, {
      backendServerId: sid,
      kind: 'host',
      verb: 'create',
      label: a.remark,
      identity,
      claimKeys: [claimKey.hostIdentity(identity)],
      intent: spec,
      postcondition: {},
      actorAdminId,
    });
    return { opId };
  },
});

export const requestAddressUpdate = internalMutation({
  args: { backendServerId: v.id('backendServers'), hostUuid: v.string(), ...hostFields, ...actor },
  handler: async (ctx, a) => {
    checkHostFields(a);
    const sid = a.backendServerId;
    const current = await cachedHost(ctx, sid, a.hostUuid);
    await assertHostEditable(ctx, sid, a.hostUuid);
    if (a.remark !== undefined && a.remark !== current.remark) {
      if (looksLikeRelayRemark(a.remark, await nodeNames(ctx, sid)))
        refuse('servers.relay_remark', 'Remarks ending in -origin belong to edges. Pick another');
    }
    const { backendServerId: _s, hostUuid, actorAdminId, inboundUuid, ...rest } = a;
    const fields: PanelHostFields = { ...rest };
    const expected: Record<string, unknown> = { ...rest };
    // The postcondition is what a later read must SHOW, not what was asked. A
    // cleared security layer is sent as the backend's own default word (the
    // enumeration has no "unset"), and the backend reads it back as that word;
    // expecting null here would never be observed and the claim never released.
    if (expected.securityLayer === null) expected.securityLayer = 'DEFAULT';
    if (inboundUuid !== undefined) {
      fields.inbound = await inboundBinding(ctx, sid, inboundUuid);
      expected.configProfileInboundUuid = inboundUuid;
    }
    if (Object.keys(expected).length === 0) refuse('validation', 'Nothing to change');
    const opId = await claimOp(ctx, {
      backendServerId: sid,
      kind: 'host',
      verb: 'update',
      label: current.remark,
      objectUuid: hostUuid,
      claimKeys: [claimKey.host(hostUuid)],
      intent: fields,
      postcondition: expected,
      actorAdminId,
    });
    return { opId };
  },
});

export const requestAddressDelete = internalMutation({
  args: { backendServerId: v.id('backendServers'), hostUuid: v.string(), ...actor },
  handler: async (ctx, a) => {
    const current = await cachedHost(ctx, a.backendServerId, a.hostUuid);
    await assertHostEditable(ctx, a.backendServerId, a.hostUuid);
    const opId = await claimOp(ctx, {
      backendServerId: a.backendServerId,
      kind: 'host',
      verb: 'delete',
      label: current.remark,
      objectUuid: a.hostUuid,
      identity: hostIdentity({
        remark: current.remark,
        inboundUuid: current.configProfileInboundUuid ?? '',
        address: current.address,
        port: current.port,
      }),
      claimKeys: [claimKey.host(a.hostUuid)],
      intent: {},
      postcondition: {},
      actorAdminId: a.actorAdminId,
    });
    return { opId };
  },
});

export const requestAddressReorder = internalMutation({
  args: { backendServerId: v.id('backendServers'), hostUuids: v.array(v.string()), ...actor },
  handler: async (ctx, a) => {
    const rows = await ctx.db
      .query('panelHosts')
      .withIndex('by_server', (q) => q.eq('backendServerId', a.backendServerId))
      .collect();
    const known = new Set(rows.map((r) => r.hostUuid));
    const unique = new Set(a.hostUuids);
    if (unique.size !== a.hostUuids.length || unique.size !== known.size)
      refuse('validation', 'The order must list every Host of this backend exactly once');
    for (const u of unique) if (!known.has(u)) refuse('validation', 'Unknown Host in the order');
    const order = a.hostUuids.map((hostUuid, i) => ({ hostUuid, viewPosition: i + 1 }));
    const opId = await claimOp(ctx, {
      backendServerId: a.backendServerId,
      kind: 'host',
      verb: 'reorder',
      label: `${order.length} Hosts`,
      claimKeys: [claimKey.hostOrder()],
      intent: { order },
      postcondition: { order },
      actorAdminId: a.actorAdminId,
    });
    return { opId };
  },
});

// --- mode groups --------------------------------------------------------------------------------------------

async function cachedSquad(ctx: MutationCtx, sid: Id<'backendServers'>, squadUuid: string) {
  const row = await ctx.db
    .query('panelSquads')
    .withIndex('by_server_uuid', (q) => q.eq('backendServerId', sid).eq('squadUuid', squadUuid))
    .unique();
  return row ?? refuse('not_found', 'That mode group is not on this backend. Refresh and retry');
}

/** The mode groups operators put into mode placements (members are issued into them). */
async function placedSquads(ctx: MutationCtx, sid: Id<'backendServers'>) {
  const server = await ctx.db.get(sid);
  const rows = await ctx.db
    .query('modePlacements')
    .withIndex('by_backend', (q) => q.eq('backend', server!.backend))
    .collect();
  return new Set(rows.flatMap((r) => poolFromConfig(r.config)));
}

/**
 * The profiles that own any of `inboundUuids`, and the enabled nodes on them:
 * what the backend re-applies when a mode group's transports change or it is deleted.
 */
async function affectedByInbounds(
  ctx: MutationCtx,
  sid: Id<'backendServers'>,
  inboundUuids: readonly string[],
) {
  const wanted = new Set(inboundUuids);
  const profiles = (
    await ctx.db
      .query('panelProfiles')
      .withIndex('by_server', (q) => q.eq('backendServerId', sid))
      .collect()
  ).filter((p) => p.inbounds.some((i) => wanted.has(i.inboundUuid)));
  const profileUuids = new Set(profiles.map((p) => p.profileUuid));
  const nodes = (
    await ctx.db
      .query('panelNodes')
      .withIndex('by_server', (q) => q.eq('backendServerId', sid))
      .collect()
  ).filter((n) => !n.isDisabled && n.configProfileUuid && profileUuids.has(n.configProfileUuid));
  return {
    claimKeys: [
      ...[...profileUuids].map(claimKey.profile),
      ...nodes.map((n) => claimKey.node(n.nodeUuid)),
    ],
    nodeUuids: nodes.map((n) => n.nodeUuid),
  };
}

const SQUAD_NAME = /^[A-Za-z0-9_-]{2,20}$/;

export const requestModeGroupCreate = internalMutation({
  args: {
    backendServerId: v.id('backendServers'),
    name: v.string(),
    inboundUuids: v.array(v.string()),
    restore: v.optional(v.boolean()),
    ...actor,
  },
  handler: async (ctx, a) => {
    if (!SQUAD_NAME.test(a.name))
      refuse('validation', 'A mode group name is 2 to 20 letters, digits, dashes or underscores');
    const sid = a.backendServerId;
    for (const u of a.inboundUuids) await inboundBinding(ctx, sid, u);
    const existing = await ctx.db
      .query('panelSquads')
      .withIndex('by_server', (q) => q.eq('backendServerId', sid))
      .collect();
    if (existing.some((s) => s.name === a.name))
      refuse('servers.squad_name_taken', 'A mode group with that name already exists');
    await assertNotTombstoned(ctx, sid, 'squad', a.name, a.restore === true);
    // A NEW mode group has no members, so the backend queues no node work for it.
    const opId = await claimOp(ctx, {
      backendServerId: sid,
      kind: 'squad',
      verb: 'create',
      label: a.name,
      identity: a.name,
      claimKeys: [claimKey.squadName(a.name)],
      intent: { name: a.name, inboundUuids: a.inboundUuids },
      postcondition: {},
      actorAdminId: a.actorAdminId,
    });
    return { opId };
  },
});

export const requestModeGroupUpdate = internalMutation({
  args: {
    backendServerId: v.id('backendServers'),
    squadUuid: v.string(),
    name: v.optional(v.string()),
    inboundUuids: v.optional(v.array(v.string())),
    ...actor,
  },
  handler: async (ctx, a) => {
    const sid = a.backendServerId;
    const current = await cachedSquad(ctx, sid, a.squadUuid);
    if (a.name === undefined && a.inboundUuids === undefined)
      refuse('validation', 'Nothing to change');
    if (a.name !== undefined && !SQUAD_NAME.test(a.name))
      refuse('validation', 'A mode group name is 2 to 20 letters, digits, dashes or underscores');
    const claimKeys = [claimKey.squad(a.squadUuid)];
    const expected: Record<string, unknown> = {};
    let asyncNodeUuids: string[] | undefined;
    if (a.name !== undefined) {
      expected.name = a.name;
      claimKeys.push(claimKey.squadName(a.name));
    }
    if (a.inboundUuids !== undefined) {
      for (const u of a.inboundUuids) await inboundBinding(ctx, sid, u);
      if (a.inboundUuids.length === 0 && (await placedSquads(ctx, sid)).has(a.squadUuid))
        refuse(
          'servers.squad_in_placement',
          'Members are issued into this mode group. Take it out of the connection modes first',
        );
      expected.inboundUuids = a.inboundUuids;
      // The backend re-applies the profiles of BOTH the old and the new transports.
      const affected = await affectedByInbounds(ctx, sid, [
        ...current.inboundUuids,
        ...a.inboundUuids,
      ]);
      claimKeys.push(...affected.claimKeys);
      asyncNodeUuids = affected.nodeUuids;
    }
    const opId = await claimOp(ctx, {
      backendServerId: sid,
      kind: 'squad',
      verb: 'update',
      label: current.name,
      objectUuid: a.squadUuid,
      claimKeys,
      intent: { name: a.name, inboundUuids: a.inboundUuids },
      postcondition: expected,
      asyncNodeUuids,
      actorAdminId: a.actorAdminId,
    });
    return { opId };
  },
});

export const requestModeGroupDelete = internalMutation({
  args: { backendServerId: v.id('backendServers'), squadUuid: v.string(), ...actor },
  handler: async (ctx, a) => {
    const sid = a.backendServerId;
    const current = await cachedSquad(ctx, sid, a.squadUuid);
    if ((await placedSquads(ctx, sid)).has(a.squadUuid))
      refuse(
        'servers.squad_in_placement',
        'Members are issued into this mode group. Take it out of the connection modes first',
      );
    if ((current.membersCount ?? 0) > 0)
      refuse('servers.squad_has_members', 'This mode group still has members');
    // Deleting re-applies the profiles it referenced, members or not.
    const affected = await affectedByInbounds(ctx, sid, current.inboundUuids);
    const opId = await claimOp(ctx, {
      backendServerId: sid,
      kind: 'squad',
      verb: 'delete',
      label: current.name,
      objectUuid: a.squadUuid,
      identity: current.name,
      claimKeys: [claimKey.squad(a.squadUuid), ...affected.claimKeys],
      intent: {},
      postcondition: {},
      asyncNodeUuids: affected.nodeUuids,
      actorAdminId: a.actorAdminId,
    });
    return { opId };
  },
});

// --- nodes --------------------------------------------------------------------------------------------

async function cachedNode(ctx: MutationCtx, sid: Id<'backendServers'>, nodeUuid: string) {
  const row = await ctx.db
    .query('panelNodes')
    .withIndex('by_server_uuid', (q) => q.eq('backendServerId', sid).eq('nodeUuid', nodeUuid))
    .unique();
  return row ?? refuse('not_found', 'That node is not on this backend. Refresh and retry');
}

/** The origins whose origin is this backend node. */
async function relaysOfNode(ctx: MutationCtx, sid: Id<'backendServers'>, nodeName: string) {
  const relays = await ctx.db
    .query('relays')
    .withIndex('by_backend_server', (q) => q.eq('backendServerId', sid))
    .collect();
  return relays.filter((r) => r.origin.kind === 'panel-node' && r.origin.nodeName === nodeName);
}

/**
 * A node an origin stands in front of is part of a published path: its address is
 * what edges forward to, its transports are what listeners are bound to. Moving,
 * stopping or removing it from here would strand members behind edges that
 * still look healthy, so those changes are refused; they belong to a migration
 * that also moves the origin.
 */
async function assertNotRelayOrigin(ctx: MutationCtx, sid: Id<'backendServers'>, nodeName: string) {
  const relays = await relaysOfNode(ctx, sid, nodeName);
  if (relays.length > 0)
    refuse(
      'servers.node_relay_origin',
      `${relays[0].slug} protects this node. Remove that protection before changing the node itself`,
    );
}

/**
 * A node's NAME is an identifier well beyond the backend: origins, delivery
 * requirements, the node role's token boundary and members' pinned keys all
 * refer to it. Renaming a node any of them refers to is refused.
 */
async function assertRenameSafe(ctx: MutationCtx, sid: Id<'backendServers'>, nodeName: string) {
  const referenced = async (): Promise<string | null> => {
    if ((await relaysOfNode(ctx, sid, nodeName)).length > 0) return 'an origin';
    const binding = await ctx.db
      .query('edgeDeliveryBindings')
      .withIndex('by_server_node', (q) => q.eq('backendServerId', sid).eq('nodeName', nodeName))
      .first();
    if (binding) return 'a delivery requirement';
    const pinned = await ctx.db
      .query('subscriptions')
      .withIndex('by_backend_server_pinned', (q) =>
        q.eq('backendServerId', sid).eq('pinnedNode', nodeName),
      )
      .first();
    if (pinned) return 'members whose keys are pinned to it';
    const tokens = await ctx.db.query('apiTokens').collect();
    if (tokens.some((t) => t.edgeRegistration?.nodeNames?.includes(nodeName)))
      return 'an automation token';
    return null;
  };
  const by = await referenced();
  if (by)
    refuse(
      'servers.node_rename_referenced',
      `This node's name is used by ${by}. It cannot be renamed here`,
    );
}

/** Transport uuids must all belong to the profile, as Servers last read it. */
async function checkProfileInbounds(
  ctx: MutationCtx,
  sid: Id<'backendServers'>,
  profileUuid: string,
  inboundUuids: readonly string[],
) {
  const profile = await ctx.db
    .query('panelProfiles')
    .withIndex('by_server_uuid', (q) => q.eq('backendServerId', sid).eq('profileUuid', profileUuid))
    .unique();
  if (!profile)
    return refuse('not_found', 'That profile is not on this backend. Refresh and retry');
  const known = new Set(profile.inbounds.map((i) => i.inboundUuid));
  for (const u of inboundUuids)
    if (!known.has(u))
      refuse('servers.unknown_inbound', 'An transport does not belong to that profile');
  if (inboundUuids.length === 0) refuse('validation', 'A node serves at least one transport');
}

const NODE_NAME = /^[A-Za-z0-9 ._-]{3,30}$/;

export const requestNodeCreate = internalMutation({
  args: {
    backendServerId: v.id('backendServers'),
    name: v.string(),
    address: v.string(),
    port: v.optional(v.number()),
    countryCode: v.optional(v.string()),
    configProfileUuid: v.string(),
    activeInboundUuids: v.array(v.string()),
    restore: v.optional(v.boolean()),
    ...actor,
  },
  handler: async (ctx, a) => {
    const sid = a.backendServerId;
    if (!NODE_NAME.test(a.name)) refuse('validation', 'A node name is 3 to 30 plain characters');
    if (a.address.trim().length < 2) refuse('validation', 'An address is required');
    if (a.port !== undefined && (!Number.isInteger(a.port) || a.port < 1 || a.port > 65535))
      refuse('validation', 'A port is 1 to 65535');
    await checkProfileInbounds(ctx, sid, a.configProfileUuid, a.activeInboundUuids);
    const nodes = await ctx.db
      .query('panelNodes')
      .withIndex('by_server', (q) => q.eq('backendServerId', sid))
      .collect();
    if (nodes.some((n) => n.name === a.name))
      refuse('servers.node_name_taken', 'A node with that name already exists');
    await assertNotTombstoned(ctx, sid, 'node', a.name, a.restore === true);
    const { backendServerId: _s, actorAdminId, restore: _r, ...spec } = a;
    // The backend ROW only. Installing the node and giving it its secret is the
    // node role's job, against the backend directly.
    const opId = await claimOp(ctx, {
      backendServerId: sid,
      kind: 'node',
      verb: 'create',
      label: a.name,
      identity: a.name,
      claimKeys: [`nodename:${a.name.toLowerCase()}`],
      intent: spec,
      postcondition: {},
      actorAdminId,
    });
    return { opId };
  },
});

export const requestNodeUpdate = internalMutation({
  args: {
    backendServerId: v.id('backendServers'),
    nodeUuid: v.string(),
    name: v.optional(v.string()),
    address: v.optional(v.string()),
    port: v.optional(v.number()),
    countryCode: v.optional(v.string()),
    configProfileUuid: v.optional(v.string()),
    activeInboundUuids: v.optional(v.array(v.string())),
    ...actor,
  },
  handler: async (ctx, a) => {
    const sid = a.backendServerId;
    const node = await cachedNode(ctx, sid, a.nodeUuid);
    const fields: PanelNodeFields = {};
    const expected: Record<string, unknown> = {};
    const claimKeys = [claimKey.node(a.nodeUuid)];
    if (a.name !== undefined && a.name !== node.name) {
      if (!NODE_NAME.test(a.name)) refuse('validation', 'A node name is 3 to 30 plain characters');
      await assertRenameSafe(ctx, sid, node.name);
      fields.name = a.name;
      expected.name = a.name;
      claimKeys.push(`nodename:${a.name.toLowerCase()}`);
    }
    if (a.countryCode !== undefined) {
      if (!/^[A-Za-z]{2}$/.test(a.countryCode)) refuse('validation', 'A country is two letters');
      fields.countryCode = a.countryCode.toUpperCase();
      expected.countryCode = fields.countryCode;
    }
    // These make the backend restart the node (measured); a name or country does not.
    let restarts = false;
    if (a.address !== undefined && a.address !== node.address) {
      if (a.address.trim().length < 2) refuse('validation', 'An address is required');
      fields.address = a.address;
      expected.address = a.address;
      restarts = true;
    }
    if (a.port !== undefined && a.port !== node.port) {
      if (!Number.isInteger(a.port) || a.port < 1 || a.port > 65535)
        refuse('validation', 'A port is 1 to 65535');
      fields.port = a.port;
      expected.port = a.port;
      restarts = true;
    }
    if (a.configProfileUuid !== undefined || a.activeInboundUuids !== undefined) {
      const profileUuid = a.configProfileUuid ?? node.configProfileUuid;
      const inbounds = a.activeInboundUuids ?? node.activeInboundUuids;
      if (!profileUuid) return refuse('validation', 'A profile is required');
      await checkProfileInbounds(ctx, sid, profileUuid, inbounds);
      fields.profile = { configProfileUuid: profileUuid, activeInboundUuids: inbounds };
      expected.configProfileUuid = profileUuid;
      expected.activeInboundUuids = inbounds;
      claimKeys.push(claimKey.profile(profileUuid));
      restarts = true;
    }
    if (Object.keys(expected).length === 0) refuse('validation', 'Nothing to change');
    if (restarts) await assertNotRelayOrigin(ctx, sid, node.name);
    const opId = await claimOp(ctx, {
      backendServerId: sid,
      kind: 'node',
      verb: 'update',
      label: node.name,
      objectUuid: a.nodeUuid,
      claimKeys,
      intent: fields,
      postcondition: expected,
      asyncNodeUuids: restarts ? [a.nodeUuid] : undefined,
      actorAdminId: a.actorAdminId,
    });
    return { opId, restartsNode: restarts };
  },
});

/** enable / disable / restart. The backend queues each; none is a no-op, so state is checked first. */
export const requestNodeAction = internalMutation({
  args: {
    backendServerId: v.id('backendServers'),
    nodeUuid: v.string(),
    action: v.union(v.literal('enable'), v.literal('disable'), v.literal('restart')),
    ...actor,
  },
  handler: async (ctx, a) => {
    const sid = a.backendServerId;
    const node = await cachedNode(ctx, sid, a.nodeUuid);
    if (a.action === 'disable') await assertNotRelayOrigin(ctx, sid, node.name);
    // A repeat enqueues backend work for nothing (measured): refuse instead of sending.
    if (a.action === 'enable' && !node.isDisabled)
      refuse('servers.already', 'This node is already on');
    if (a.action === 'disable' && node.isDisabled)
      refuse('servers.already', 'This node is already off');
    if (a.action === 'restart' && node.isDisabled)
      refuse('servers.node_off', 'This node is turned off');
    const opId = await claimOp(ctx, {
      backendServerId: sid,
      kind: 'node',
      verb: a.action,
      label: node.name,
      objectUuid: a.nodeUuid,
      claimKeys: [claimKey.node(a.nodeUuid)],
      intent: {},
      // A restart names no field: the backend row looks the same before and
      // after, so only the node's own clock settles it.
      postcondition: a.action === 'restart' ? {} : { isDisabled: a.action === 'disable' },
      asyncNodeUuids: [a.nodeUuid],
      actorAdminId: a.actorAdminId,
    });
    return { opId };
  },
});

/**
 * Two different things, named as such:
 *
 *  - "Stop and remove" (the default): the node must ALREADY be off, as a
 *    settled step of its own. The backend deletes the row before it tells the
 *    node to stop, so a row disappearing proves nothing about the process.
 *  - "Remove from backend" (`removeOnly`): the row goes; the process on the
 *    server may keep running and serving until someone stops it there.
 */
export const requestNodeDelete = internalMutation({
  args: {
    backendServerId: v.id('backendServers'),
    nodeUuid: v.string(),
    removeOnly: v.optional(v.boolean()),
    ...actor,
  },
  handler: async (ctx, a) => {
    const sid = a.backendServerId;
    const node = await cachedNode(ctx, sid, a.nodeUuid);
    await assertNotRelayOrigin(ctx, sid, node.name);
    if (!a.removeOnly && !node.isDisabled)
      refuse(
        'servers.node_still_on',
        'Turn the node off first and wait for that to finish, or choose to remove it from the backend only',
      );
    const opId = await claimOp(ctx, {
      backendServerId: sid,
      kind: 'node',
      verb: 'delete',
      label: node.name,
      objectUuid: a.nodeUuid,
      identity: node.name,
      claimKeys: [claimKey.node(a.nodeUuid)],
      intent: { removeOnly: a.removeOnly === true },
      postcondition: {},
      actorAdminId: a.actorAdminId,
    });
    return { opId };
  },
});

// --- config profiles --------------------------------------------------------------------------------

const patchOp = v.union(
  v.object({
    op: v.literal('setRealityServerNames'),
    inboundTag: v.string(),
    names: v.array(v.string()),
  }),
  v.object({ op: v.literal('setRealityTarget'), inboundTag: v.string(), target: v.string() }),
);

/**
 * Claim a typed profile edit that was just previewed against the live backend.
 * Everything that could strand members or fight another workflow is refused
 * HERE, before anything is sent:
 *
 *  - a server name that a bound origin listener still hands out (or that is
 *    still draining there) may not be removed: retire it on the origin first;
 *  - an origin that is rotating, restoring, quarantined or mid-setup holds still;
 *  - the profile, every enabled node on it and every affected origin are claimed
 *    together, and the origin claims are what rotations, restores, registrations
 *    and setup runs refuse against (`assertNoRelayPanelClaim`).
 */
export const requestProfilePatch = internalMutation({
  args: {
    backendServerId: v.id('backendServers'),
    profileUuid: v.string(),
    ops: v.array(patchOp),
    /** From the preview the operator confirmed. */
    baseToken: v.string(),
    expectedToken: v.string(),
    inboundUuids: v.record(v.string(), v.string()),
    /** Set by the server-name rollout only; no HTTP route can pass it. */
    sniRollout: v.optional(v.boolean()),
    /**
     * The treatment of enrolled-less nodes the edit reaches: held closed until
     * released, or acknowledged as changing in place. Required when any exist.
     */
    unmanaged: v.optional(v.union(v.literal('hold'), v.literal('acknowledge'))),
    ...actor,
  },
  handler: async (ctx, a) => {
    const sid = a.backendServerId;
    let ops: PatchOp[];
    try {
      ops = checkPatchOps(a.ops as PatchOp[]);
    } catch (e) {
      if (e instanceof PatchRefused) return refuse(e.code, e.message);
      throw e;
    }
    const cached = await ctx.db
      .query('panelProfiles')
      .withIndex('by_server_uuid', (q) =>
        q.eq('backendServerId', sid).eq('profileUuid', a.profileUuid),
      )
      .unique();
    if (!cached)
      return refuse('not_found', 'That profile is not on this backend. Refresh and retry');
    if (a.baseToken === a.expectedToken) refuse('validation', 'Nothing to change');

    const touched = new Map<string, string>();
    for (const op of ops) {
      const uuid = a.inboundUuids[op.inboundTag];
      if (!uuid) return refuse('servers.unknown_inbound', `No inbound is tagged ${op.inboundTag}`);
      touched.set(op.inboundTag, uuid);
    }
    const touchedUuids = new Set(touched.values());

    // A family-managed transport has ONE author of its allowlist and target: the
    // rollout, which hands names to members only after each node proved it
    // accepts them. A manual edit would bypass exactly that.
    if (!a.sniRollout)
      for (const uuid of touchedUuids) {
        const managed = await ctx.db
          .query('sniInboundBindings')
          .withIndex('by_server_inbound', (q) =>
            q.eq('backendServerId', sid).eq('inboundUuid', uuid),
          )
          .unique();
        if (managed)
          refuse(
            'servers.inbound_sni_managed',
            'A server-name family manages this transport. Change its names in the family',
          );
      }

    // Origins whose listeners are bound to a touched transport.
    const relays = await ctx.db
      .query('relays')
      .withIndex('by_backend_server', (q) => q.eq('backendServerId', sid))
      .collect();
    const now = Date.now();
    const affected: Id<'relays'>[] = [];
    for (const relay of relays) {
      const listeners = (
        await ctx.db
          .query('relayListeners')
          .withIndex('by_relay', (q) => q.eq('relayId', relay._id))
          .collect()
      ).filter(
        (l) =>
          !l.retired &&
          !!l.panelBinding &&
          touchedUuids.has(l.panelBinding.configProfileInboundUuid),
      );
      if (listeners.length === 0) continue;
      await assertNoRotationOrQuarantine(ctx.db, relay);
      const runs = await ctx.db
        .query('edgeSetupRuns')
        .withIndex('by_relay', (q) => q.eq('relayId', relay._id))
        .collect();
      if (
        runs.some((r) => r.state === 'running' || r.state === 'waiting' || r.state === 'needs_you')
      )
        refuse('servers.relay_setup_running', `A guided setup is still running on ${relay.slug}`);
      for (const op of ops) {
        if (op.op !== 'setRealityServerNames') continue;
        const keep = new Set(op.names);
        for (const l of listeners) {
          if (l.panelBinding!.configProfileInboundUuid !== touched.get(op.inboundTag)) continue;
          const stranded = (l.tlsNames ?? []).filter(
            (n) =>
              !keep.has(n.name) &&
              (n.status === 'active' || (n.drainUntil !== undefined && n.drainUntil > now)),
          );
          if (stranded.length > 0)
            refuse(
              'servers.name_in_use',
              `${relay.slug} still hands out ${stranded[0].name}. Retire it on the relay and let it drain first`,
            );
        }
      }
      affected.push(relay._id);
    }

    const nodes = (
      await ctx.db
        .query('panelNodes')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .collect()
    ).filter((n) => !n.isDisabled && n.configProfileUuid === a.profileUuid);

    const targets: Record<string, { address: string; port: number }> = {};
    for (const op of ops)
      if (op.op === 'setRealityTarget') targets[op.inboundTag] = parseRealityTarget(op.target)!;

    // An edit (never a rollout: names reach members by per-node receipts) is
    // applied in place under every node on the touched transports: the
    // maintenance transition over its blast radius comes BEFORE the claim.
    if (!a.sniRollout)
      await closeForSharedChange(ctx, {
        backendServerId: sid,
        transportUuids: [...touchedUuids],
        reason: 'profile',
        unmanaged: a.unmanaged,
        actorAdminId: a.actorAdminId,
      });

    const opId = await claimOp(ctx, {
      backendServerId: sid,
      kind: 'profile',
      verb: 'patch',
      label: cached.name,
      objectUuid: a.profileUuid,
      claimKeys: [
        claimKey.profile(a.profileUuid),
        ...nodes.map((n) => claimKey.node(n.nodeUuid)),
        ...affected.map((r) => `relay:${r}`),
      ],
      intent: { ops, baseToken: a.baseToken },
      postcondition: {
        expectedToken: a.expectedToken,
        inboundUuids: a.inboundUuids,
        targets,
        relayIds: affected,
      },
      asyncNodeUuids: nodes.map((n) => n.nodeUuid),
      actorAdminId: a.actorAdminId,
    });
    return { opId, restartsNodes: nodes.length, affectedRelays: affected.length };
  },
});

// --- run: send once, then look -------------------------------------------------------------------------

async function writesFor(ctx: ActionCtx, backendServerId: Id<'backendServers'>) {
  const server = await ctx.runQuery(internal.backendServers.getById, { id: backendServerId });
  if (!server) throw new ConvexError({ code: 'not_found', message: 'Backend server not found' });
  const writes = PROVIDERS[server.backend].panelWrites;
  if (!writes)
    throw new ConvexError({
      code: 'servers.unsupported_backend',
      message: 'This backend type cannot be managed here',
    });
  return { writes, config: server.config as BackendConfig };
}

/** One look at the backend for this op; never throws (a failed look changes nothing). */
async function look(ctx: ActionCtx, opId: Id<'panelOps'>): Promise<boolean> {
  const op = await ctx.runQuery(internal.panelLedger.getForRun, { opId });
  if (!op || !op.open) return false;
  try {
    const { writes, config } = await writesFor(ctx, op.backendServerId);
    const hosts = op.kind === 'host' ? await writes.readHosts(config) : undefined;
    const squads = op.kind === 'squad' ? await writes.readSquads(config) : undefined;
    let profile: { changeToken: string; inboundUuids: Record<string, string> } | undefined;
    if (op.kind === 'profile') {
      const seen = await writes.readProfile(config, op.objectUuid!, (await panelDigestKey()).key);
      profile = {
        changeToken: seen.changeToken,
        inboundUuids: Object.fromEntries(
          seen.inbounds.map((i) => [i.tag, i.configProfileInboundUuid]),
        ),
      };
    }
    const nodes =
      op.asyncEffect === 'pending' || op.kind === 'node'
        ? (await writes.readNodeStatus(config)).map((n) => ({
            nodeUuid: n.nodeUuid,
            lastStatusChange: n.lastStatusChange,
            isDisabled: n.isDisabled,
            // A node op is settled against the node row itself.
            ...(op.kind === 'node'
              ? {
                  name: n.name,
                  address: n.address,
                  port: n.port,
                  countryCode: n.countryCode,
                  configProfileUuid: n.configProfileUuid,
                  activeInboundUuids: n.activeInboundUuids,
                }
              : {}),
          }))
        : undefined;
    const out = await ctx.runMutation(internal.panelLedger.applyLook, {
      opId,
      hosts,
      squads,
      profile,
      nodes,
    });
    // A server-name rollout that owns this op follows what the look decided,
    // from whichever look it was (the run's, the cron's, an operator's).
    if (op.kind === 'profile') await ctx.runMutation(internal.sniRollouts.syncByOp, { opId });
    // A settled profile edit is shown at once, not at the next scheduled read.
    if (!out.open && op.kind === 'profile') {
      const server = await ctx.runQuery(internal.backendServers.getById, {
        id: op.backendServerId,
      });
      if (server) await observeInstance(ctx, server);
    }
    return out.open;
  } catch {
    return true;
  }
}

/**
 * Execute a claimed op: look first (a create whose identity already exists is
 * adopted and nothing is sent), record the ONE attempt, send it, classify the
 * answer, then look. Safe to call again: a second call never sends.
 */
export const run = internalAction({
  args: { opId: v.id('panelOps') },
  handler: async (ctx, { opId }): Promise<{ open: boolean }> => {
    const op = await ctx.runQuery(internal.panelLedger.getForRun, { opId });
    if (!op || !op.open) return { open: false };
    if (op.request !== 'pending' || op.attemptId) return { open: await look(ctx, opId) };
    const { writes, config } = await writesFor(ctx, op.backendServerId);
    const intent = JSON.parse(op.intent);

    if (op.verb === 'create') {
      // Discovery BEFORE the send: the backend enforces no uniqueness.
      let matches = 0;
      let match: string | undefined;
      if (op.kind === 'host') {
        const found = hostsMatchingIdentity(await writes.readHosts(config), op.identity ?? '');
        matches = found.length;
        match = found[0]?.hostUuid;
      } else if (op.kind === 'node') {
        const found = (await writes.readNodeStatus(config)).filter((n) => n.name === op.identity);
        matches = found.length;
        match = found[0]?.nodeUuid;
      } else {
        const found = (await writes.readSquads(config)).filter((s) => s.name === op.identity);
        matches = found.length;
        match = found[0]?.squadUuid;
      }
      if (matches > 0) {
        await ctx.runMutation(internal.panelLedger.settleWithoutSending, {
          opId,
          outcome: matches === 1 ? 'adopted' : 'duplicate',
          objectUuid: match,
        });
        return { open: false };
      }
    }

    const asyncNodes =
      op.asyncEffect === 'pending'
        ? (await writes.readNodeStatus(config))
            .filter((n) => (op.asyncNodes ?? []).some((a) => a.nodeUuid === n.nodeUuid))
            .map((n) => ({ nodeUuid: n.nodeUuid, before: n.lastStatusChange }))
        : undefined;
    const sent = await ctx.runMutation(internal.panelLedger.markSent, {
      opId,
      attemptId: crypto.randomUUID(),
      asyncNodes,
    });
    if (!sent.send) return { open: await look(ctx, opId) };

    let objectUuid: string | undefined;
    let outcome: ReturnType<typeof classifyRequest>;
    let errorCode: string | undefined;
    try {
      if (op.kind === 'profile') {
        const sent = await writes.applyProfilePatch(
          config,
          op.objectUuid!,
          intent.ops,
          intent.baseToken,
          (await panelDigestKey()).key,
        );
        if (!sent.sent) {
          // Someone else changed the profile since the preview (or there is
          // nothing to do): the PATCH was never made.
          await ctx.runMutation(internal.panelLedger.recordOutcome, {
            opId,
            request: 'rejected_pre_mutation',
            errorCode: `servers.${sent.reason}`,
          });
          await ctx.runMutation(internal.sniRollouts.syncByOp, { opId });
          return { open: false };
        }
      } else if (op.kind === 'node') {
        const uuid = op.objectUuid!;
        if (op.verb === 'create') objectUuid = (await writes.createNode(config, intent)).nodeUuid;
        else if (op.verb === 'update') await writes.updateNode(config, uuid, intent);
        else if (op.verb === 'enable') await writes.setNodeEnabled(config, uuid, true);
        else if (op.verb === 'disable') await writes.setNodeEnabled(config, uuid, false);
        else if (op.verb === 'restart') await writes.restartNode(config, uuid);
        else await writes.deleteNode(config, uuid);
      } else if (op.kind === 'host') {
        if (op.verb === 'create')
          objectUuid = (await writes.createAddress(config, intent)).hostUuid;
        else if (op.verb === 'update') await writes.updateAddress(config, op.objectUuid!, intent);
        else if (op.verb === 'delete') await writes.deleteAddress(config, op.objectUuid!);
        else await writes.reorderAddresses(config, intent.order);
      } else if (op.verb === 'create')
        objectUuid = (await writes.createModeGroup(config, intent)).squadUuid;
      else if (op.verb === 'update') await writes.updateModeGroup(config, op.objectUuid!, intent);
      else await writes.deleteModeGroup(config, op.objectUuid!);
      outcome = classifyRequest({ kind: 'ok' });
    } catch (err) {
      // The message is never read: only a status or a connect code.
      const result = callResultOf(err);
      outcome = classifyRequest(result);
      errorCode =
        outcome === 'rejected_pre_mutation' ? 'servers.panel_refused' : 'servers.outcome_unknown';
    }
    await ctx.runMutation(internal.panelLedger.recordOutcome, {
      opId,
      request: outcome as 'rejected_pre_mutation' | 'acknowledged' | 'uncertain',
      objectUuid,
      errorCode,
    });
    if (outcome === 'rejected_pre_mutation') {
      if (op.kind === 'profile') await ctx.runMutation(internal.sniRollouts.syncByOp, { opId });
      return { open: false };
    }
    return { open: await look(ctx, opId) };
  },
});

/**
 * What a typed profile edit WOULD do, read from the live backend: the non-secret
 * before/after, and who feels it. Writes nothing. The tokens it returns are
 * what `requestProfilePatch` then conditions the write on.
 */
export type ProfilePatchPreviewView = ProfilePatchPreview & {
  ops: PatchOp[];
  restartsNodes: string[];
  affectedRelays: { relaySlug: string; listenerKeys: string[]; publishedEdges: number }[];
};

export const previewProfilePatch = internalAction({
  args: { backendServerId: v.id('backendServers'), profileUuid: v.string(), ops: v.any() },
  handler: async (ctx, { backendServerId, profileUuid, ops }): Promise<ProfilePatchPreviewView> => {
    const { writes, config } = await writesFor(ctx, backendServerId);
    try {
      const checked = checkPatchOps(ops as PatchOp[]);
      const preview = await writes.previewProfilePatch(
        config,
        profileUuid,
        checked,
        (await panelDigestKey()).key,
      );
      const blast = await ctx.runQuery(internal.serverAdmin.profileBlastRadius, {
        backendServerId,
        profileUuid,
        inboundUuids: preview.touchedTags.map((t) => preview.inboundUuids[t]).filter(Boolean),
      });
      return { ...preview, ops: checked, ...blast };
    } catch (e) {
      if (e instanceof PatchRefused) throw new ConvexError({ code: e.code, message: e.message });
      if (e instanceof ConvexError) throw e;
      // A backend fault while reading a profile: status and path only ever reach here.
      throw new ConvexError({
        code: 'backend.panel_read_failed',
        message: 'The backend could not be read',
      });
    }
  },
});

export const observe = internalAction({
  args: { opId: v.id('panelOps') },
  handler: async (ctx, { opId }): Promise<{ open: boolean }> => ({ open: await look(ctx, opId) }),
});

/** Recovery of an unknown outcome: a FRESH read first, then the attested release. */
export const recoverOp = internalAction({
  args: {
    opId: v.id('panelOps'),
    credentialsRevoked: v.boolean(),
    noInFlightExecutor: v.boolean(),
    queueDrained: v.boolean(),
    note: v.optional(v.string()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a): Promise<{ ok: true; settledByLook: boolean }> => {
    // The fresh read may simply settle it: then no attestation is needed.
    if (!(await look(ctx, a.opId))) return { ok: true, settledByLook: true };
    await ctx.runMutation(internal.panelLedger.recover, { ...a, freshReadAt: Date.now() });
    return { ok: true, settledByLook: false };
  },
});

/**
 * Every five minutes: release ops that never sent, mark interrupted ones as
 * unknown, and look again at everything still open. It never sends anything.
 */
export const reconcile = internalAction({
  args: {},
  handler: async (ctx): Promise<{ looked: number; stillOpen: number }> =>
    runWithCronOutcome(ctx, 'panel-reconcile', async () => {
      const { toLook, released } = await ctx.runMutation(internal.panelLedger.sweepInterrupted, {
        olderThanMs: 2 * 60_000,
      });
      // An op released as never sent may have been a rollout's write.
      for (const opId of released) await ctx.runMutation(internal.sniRollouts.syncByOp, { opId });
      let stillOpen = 0;
      for (const opId of toLook) if (await look(ctx, opId)) stillOpen++;
      return { looked: toLook.length, stillOpen };
    }),
});
