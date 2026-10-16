/**
 * Renaming a node (docs/servers.md "Renaming a node"). A node's name is an
 * identifier well beyond the backend row: origins, delivery bindings, the
 * node role's routes and token, members' pins, holds, port requirements and
 * the remarks of the Hosts FCP writes all carry it. A rename is therefore a
 * resumable workflow, one step at a time, every backend write through the
 * ledger (send once, settle by looking):
 *
 *  1. `backend`: the backend row is renamed (a node op). In the transaction
 *     that SEES the new name, every FCP row keyed by the name moves with it
 *     (`bridgeNodeRename`, lib/backend/nodeRename.ts) and the old name becomes
 *     an alias (`panelNodeAliases`), so a lookup by it still answers.
 *  2. `hosts`: every Host on the backend whose remark is one of FCP's forms for
 *     the old name (a direct node's `<node> | <name>`, an origin listener's
 *     `<node>-relay-<key>`) is found by READING the listing, never from FCP's
 *     records alone, and re-remarked through the ledger one at a time. Nothing
 *     else about a Host changes, so members keep connecting; the renderer
 *     matches a listener's old remark too until its Host carries the new one.
 *  3. `subscriptions`: members' pins move to the new name, a page at a time
 *     (a lagging pin resolves through the alias meanwhile).
 *
 * While it runs, the node's origins are fenced (`relays.renaming`): no
 * rotation, restore, registration, setup run or listener write starts. A step
 * whose backend write has an open outcome parks; `backend-reconcile` resumes
 * it. A rename refused before the backend row moved changes nothing.
 *
 * The only writer of `panelNodeRenames` (and, with lib/backend/nodeRename.ts,
 * of `panelNodeAliases`).
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { ActionCtx, MutationCtx, QueryCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { PROVIDERS, type BackendConfig } from './lib/backends/registry';
import { CLAIM_LEASE_MS } from './lib/backend/fencing';
import { claimKey } from './lib/backend/ops';
import { HOST_REMARK_MAX } from './lib/backend/hostRemark';
import {
  bridgeNodeRename,
  longestListenerRemark,
  originNameOf,
  renamedRemark,
} from './lib/backend/nodeRename';
import { assertNoRotationOrQuarantine } from './lib/edges/relayGuards';
import { assertNoPanelClaim, assertWritable, claimOp } from './backendLedger';

const refuse = (code: string, message: string): never => {
  throw new ConvexError({ code, message });
};

type Rename = Doc<'panelNodeRenames'>;

/** No attempt holds the rename, or the one that did let its lease run out. */
const leaseFree = (r: Pick<Rename, 'claim'>, now: number): boolean =>
  !r.claim || r.claim.expiresAt <= now;

const NODE_NAME = /^[A-Za-z0-9 ._-]{3,30}$/;
/** An origin keeps its node's name as a DNS label: a node with an origin is renamed to one. */
const ORIGIN_NAME = /^[a-z0-9][a-z0-9-]{0,62}$/;
/** Subscriptions moved per transaction (each is one read and at most one write). */
const DRAIN_PAGE = 200;

function codeOf(err: unknown): string | null {
  return err instanceof ConvexError && typeof (err.data as { code?: unknown })?.code === 'string'
    ? (err.data as { code: string }).code
    : null;
}

async function audit(
  ctx: MutationCtx,
  r: Rename,
  action: string,
  extra: Record<string, unknown> = {},
  actorAdminId?: Id<'adminUsers'>,
) {
  const server = await ctx.db.get(r.backendServerId);
  await writeAuditLog(ctx, {
    actorType: actorAdminId ? 'admin' : 'system',
    actorId: actorAdminId,
    action,
    targetType: 'panel_node_rename',
    targetId: r._id,
    payload: { backendSlug: server?.slug ?? '', from: r.from, to: r.to, ...extra },
  });
}

// --- request ----------------------------------------------------------------------------------------

/**
 * Ask for a rename. Everything that could leave something behind is refused
 * HERE, before anything is sent:
 *  - a name another node has, had (a former name stays reserved: a pin or the
 *    role may still use it) or that was removed on purpose;
 *  - a node that is retiring, has work in flight, or is being renamed;
 *  - an origin in front of the node that is rotating, restoring, quarantined
 *    or mid-setup, whose Hosts the operator owns (the remarks are theirs), or
 *    whose new name is not a DNS label (origins keep it as one) or would make a
 *    Host remark longer than the backend allows.
 */
export const request = internalMutation({
  args: {
    backendServerId: v.id('backendServers'),
    nodeUuid: v.string(),
    name: v.string(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const sid = a.backendServerId;
    await assertWritable(ctx, sid);
    const to = a.name.trim();
    if (!NODE_NAME.test(to)) refuse('validation', 'A node name is 3 to 30 plain characters');
    const node = await ctx.db
      .query('panelNodes')
      .withIndex('by_server_uuid', (q) => q.eq('backendServerId', sid).eq('nodeUuid', a.nodeUuid))
      .unique();
    if (!node) return refuse('not_found', 'That node is not on this backend. Refresh and retry');
    const from = node.name;
    if (from === to) return refuse('validation', 'Nothing to change');

    const [nodes, intents, aliases, renames] = await Promise.all([
      ctx.db
        .query('panelNodes')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .collect(),
      ctx.db
        .query('panelNodeIntents')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .collect(),
      ctx.db
        .query('panelNodeAliases')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .collect(),
      ctx.db
        .query('panelNodeRenames')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .collect(),
    ]);
    const lower = to.toLowerCase();
    if (
      nodes.some((n) => n.nodeUuid !== a.nodeUuid && n.name.toLowerCase() === lower) ||
      intents.some((i) => i.nodeUuid !== a.nodeUuid && i.name.toLowerCase() === lower) ||
      aliases.some((x) => x.formerName.toLowerCase() === lower)
    )
      refuse('servers.node_name_taken', 'A node has, or had, that name. Pick another one');
    const tombstoned = (
      await ctx.db
        .query('panelOwnership')
        .withIndex('by_server_kind_identity', (q) =>
          q.eq('backendServerId', sid).eq('kind', 'node'),
        )
        .collect()
    ).some((o) => o.state === 'tombstoned' && o.lookup.includes(to));
    if (tombstoned)
      refuse('servers.tombstoned', 'A node of that name was removed on purpose. Pick another one');
    if (renames.some((r) => r.state === 'running' && r.nodeUuid === a.nodeUuid))
      refuse('servers.node_rename_running', 'This node is already being renamed');
    // A name another running rename is about to give its node is taken already.
    if (renames.some((r) => r.state === 'running' && r.to.toLowerCase() === lower))
      refuse('servers.node_name_taken', 'Another node is being renamed to that name');
    // Nothing else may be changing the node's backend row.
    await assertNoPanelClaim(ctx.db, sid, [claimKey.node(a.nodeUuid)]);
    const now = Date.now();
    const intent = intents.find((i) => i.nodeUuid === a.nodeUuid || i.name === from) ?? null;
    if (intent && (intent.state === 'retiring' || intent.state === 'retired'))
      refuse('servers.node_retiring', 'This node is being retired');
    if (intent?.claim && intent.claim.expiresAt > now)
      refuse('servers.op_running', 'The node is still being brought in line. Try again shortly');

    const relays = (
      await ctx.db
        .query('relays')
        .withIndex('by_backend_server', (q) => q.eq('backendServerId', sid))
        .collect()
    ).filter((r) => r.origin.kind === 'panel-node' && r.origin.nodeName === originNameOf(from));
    for (const relay of relays) {
      if (relay.hostMode === 'operator')
        refuse(
          'servers.node_rename_foreign_hosts',
          `${relay.slug} uses Hosts the operator writes. Their remarks name the node, and FCP does not change them`,
        );
      if (to !== lower || !ORIGIN_NAME.test(to))
        refuse(
          'servers.node_name_origin',
          `${relay.slug} keeps this node's name as a DNS label: lower-case letters, digits and dashes`,
        );
      await assertNoRotationOrQuarantine(ctx.db, relay);
      const runs = await ctx.db
        .query('edgeSetupRuns')
        .withIndex('by_relay', (q) => q.eq('relayId', relay._id))
        .collect();
      if (
        runs.some((r) => r.state === 'running' || r.state === 'waiting' || r.state === 'needs_you')
      )
        refuse('servers.relay_setup_running', `A guided setup is still running on ${relay.slug}`);
      const listeners = (
        await ctx.db
          .query('relayListeners')
          .withIndex('by_relay', (q) => q.eq('relayId', relay._id))
          .collect()
      ).filter((l) => !l.retired);
      if (
        listeners.some((l) => (l.legacyHosts ?? []).length > 0 || l.host?.ownership === 'adopted')
      )
        refuse(
          'servers.node_rename_foreign_hosts',
          `${relay.slug} serves Hosts adopted from the operator. Their remarks are theirs, and FCP does not change them`,
        );
      if (
        longestListenerRemark(
          listeners.map((l) => l.listenerKey),
          to,
        ) > HOST_REMARK_MAX
      )
        refuse(
          'servers.node_name_too_long',
          `With this name a Host remark of ${relay.slug} is longer than the backend allows`,
        );
    }

    const renameId = await ctx.db.insert('panelNodeRenames', {
      backendServerId: sid,
      nodeUuid: a.nodeUuid,
      from,
      to,
      intentId: intent?._id,
      relayIds: relays.map((r) => r._id),
      state: 'running',
      step: 'backend',
      actorAdminId: a.actorAdminId,
      createdAt: now,
      updatedAt: now,
    });
    for (const relay of relays)
      await ctx.db.patch(relay._id, { renaming: { renameId, since: now }, updatedAt: now });
    const r = (await ctx.db.get(renameId))!;
    await audit(ctx, r, 'servers.node.rename_started', {}, a.actorAdminId);
    await lease(ctx, r);
    return { renameId };
  },
});

/** Take the lease and schedule the run, unless an attempt already holds it. */
async function lease(ctx: MutationCtx, r: Rename): Promise<boolean> {
  const now = Date.now();
  if (r.state !== 'running' || !leaseFree(r, now)) return false;
  const attemptId = crypto.randomUUID();
  await ctx.db.patch(r._id, { claim: { attemptId, expiresAt: now + CLAIM_LEASE_MS } });
  await ctx.scheduler.runAfter(0, internal.backendNodeRenames.run, {
    renameId: r._id,
    attemptId,
  });
  return true;
}

export const resume = internalMutation({
  args: { renameId: v.id('panelNodeRenames') },
  handler: async (ctx, { renameId }) => {
    const r = await ctx.db.get(renameId);
    return r ? lease(ctx, r) : false;
  },
});

// --- the steps (fenced by the attempt) --------------------------------------------------------------

const fence = { renameId: v.id('panelNodeRenames'), attemptId: v.string() };

async function held(
  ctx: { db: QueryCtx['db'] },
  f: { renameId: Id<'panelNodeRenames'>; attemptId: string },
) {
  const r = await ctx.db.get(f.renameId);
  return r && r.state === 'running' && r.claim?.attemptId === f.attemptId ? r : null;
}

export const getForRun = internalQuery({
  args: fence,
  handler: (ctx, f) => held(ctx, f),
});

/** Let go of the lease: the step waits on something that settles by itself (the sweep resumes it). */
export const park = internalMutation({
  args: { ...fence, code: v.optional(v.string()) },
  handler: async (ctx, { code, ...f }) => {
    const r = await held(ctx, f);
    if (r) await ctx.db.patch(r._id, { claim: undefined, code, updatedAt: Date.now() });
  },
});

/** Step 1: the backend row, as a node op whose observation moves FCP's rows (the bridge). */
export const claimBackend = internalMutation({
  args: fence,
  handler: async (ctx, f): Promise<{ opId: Id<'panelOps'> } | { code: string }> => {
    const r = await held(ctx, f);
    if (!r || r.step !== 'backend' || r.opId) return { code: 'servers.claim_not_held' };
    // Checked again right before the write: the name may have been taken since
    // the request (a create, an adoption, an enrollment), and a backend that
    // takes duplicate names would then hold two nodes of one name.
    const lower = r.to.toLowerCase();
    const sid = r.backendServerId;
    const taken =
      (
        await ctx.db
          .query('panelNodes')
          .withIndex('by_server', (q) => q.eq('backendServerId', sid))
          .collect()
      ).some((n) => n.nodeUuid !== r.nodeUuid && n.name.toLowerCase() === lower) ||
      (
        await ctx.db
          .query('panelNodeIntents')
          .withIndex('by_server', (q) => q.eq('backendServerId', sid))
          .collect()
      ).some((i) => i._id !== r.intentId && i.name.toLowerCase() === lower);
    if (taken) return { code: 'servers.node_name_taken' };
    try {
      const opId = await claimOp(ctx, {
        backendServerId: r.backendServerId,
        kind: 'node',
        verb: 'update',
        label: r.from,
        objectUuid: r.nodeUuid,
        claimKeys: [claimKey.node(r.nodeUuid), `nodename:${r.to.toLowerCase()}`],
        intent: { name: r.to },
        // `renameId` is not a field of the row: the look matches `name` and
        // hands the observation to the rename's bridge.
        postcondition: { name: r.to, renameId: r._id },
        actorAdminId: r.actorAdminId,
      });
      await ctx.db.patch(r._id, { opId, code: undefined, updatedAt: Date.now() });
      return { opId };
    } catch (err) {
      const code = codeOf(err);
      if (!code) throw err;
      return { code };
    }
  },
});

/**
 * Step 1 ended without the bridge having run: refused before any change (the
 * rename is over, nothing moved), or settled by a recorded recovery, in which
 * case a fresh read decides whether the backend row carries the new name.
 */
export const settleBackend = internalMutation({
  args: { ...fence, seenName: v.union(v.string(), v.null()) },
  handler: async (ctx, { seenName, ...f }) => {
    const r = await held(ctx, f);
    if (!r || r.step !== 'backend' || !r.opId) return null;
    const op = await ctx.db.get(r.opId);
    if (!op || op.open) return null;
    if (seenName === r.to) {
      await bridgeNodeRename(ctx, r._id, r.opId);
      return null;
    }
    await finishFailed(ctx, r, op.errorCode ?? 'servers.panel_refused');
    return null;
  },
});

async function finishFailed(ctx: MutationCtx, r: Rename, code: string) {
  const now = Date.now();
  await ctx.db.patch(r._id, { state: 'failed', code, claim: undefined, updatedAt: now });
  for (const id of r.relayIds) {
    const relay = await ctx.db.get(id);
    if (relay?.renaming?.renameId === r._id)
      await ctx.db.patch(id, { renaming: undefined, updatedAt: now });
  }
  await audit(ctx, r, 'servers.node.rename_failed', { code });
}

/** Refused before the backend row moved: the rename is over and nothing changed. */
export const fail = internalMutation({
  args: { ...fence, code: v.string() },
  handler: async (ctx, { code, ...f }) => {
    const r = await held(ctx, f);
    if (r && r.step === 'backend') await finishFailed(ctx, r, code);
  },
});

/** Step 2: one Host's remark through the ledger. The rename owns the origin (it is fenced). */
export const claimHostRemark = internalMutation({
  args: { ...fence, hostUuid: v.string(), remark: v.string(), was: v.string() },
  handler: async (ctx, { hostUuid, remark, was, ...f }) => {
    const r = await held(ctx, f);
    if (!r || r.step !== 'hosts' || r.opId) return { code: 'servers.claim_not_held' };
    try {
      const opId = await claimOp(ctx, {
        backendServerId: r.backendServerId,
        kind: 'host',
        verb: 'update',
        label: was,
        objectUuid: hostUuid,
        claimKeys: [claimKey.host(hostUuid)],
        intent: { remark },
        postcondition: { remark },
        actorAdminId: r.actorAdminId,
      });
      await ctx.db.patch(r._id, { opId, code: undefined, updatedAt: Date.now() });
      return { opId };
    } catch (err) {
      const code = codeOf(err);
      if (!code) throw err;
      return { code };
    }
  },
});

/** The Host op of step 2 is settled (seen, refused, or recovered): the next look decides what is left. */
export const hostSettled = internalMutation({
  args: fence,
  handler: async (ctx, f) => {
    const r = await held(ctx, f);
    if (!r || r.step !== 'hosts' || !r.opId) return null;
    const op = await ctx.db.get(r.opId);
    if (!op || op.open) return null;
    // Refused before any change (a permission, a validation): sending the same
    // write again would be refused again. It waits for an operator's retry.
    const refused =
      op.request === 'rejected_pre_mutation' && op.objectUuid
        ? [
            ...(r.refusedHosts ?? []),
            {
              hostUuid: op.objectUuid,
              remark: op.label,
              code: op.errorCode ?? 'servers.panel_refused',
            },
          ]
        : r.refusedHosts;
    await ctx.db.patch(r._id, { opId: undefined, refusedHosts: refused, updatedAt: Date.now() });
    return null;
  },
});

export const hostsDone = internalMutation({
  args: fence,
  handler: async (ctx, f) => {
    const r = await held(ctx, f);
    if (r && r.step === 'hosts' && !r.opId)
      await ctx.db.patch(r._id, {
        step: 'subscriptions',
        cursor: undefined,
        updatedAt: Date.now(),
      });
  },
});

/**
 * Step 3: one page of the backend's subscriptions. A pin (and the node a key
 * is kept off) under the old name, in either of its forms, moves to the new
 * one. Bounded per transaction; the cursor carries over a crash.
 */
export const drainPage = internalMutation({
  args: fence,
  handler: async (ctx, f): Promise<{ done: boolean; moved: number }> => {
    const r = await held(ctx, f);
    if (!r || r.step !== 'subscriptions') return { done: true, moved: 0 };
    const map = new Map([
      [r.from, r.to],
      [originNameOf(r.from), originNameOf(r.to)],
    ]);
    const page = await ctx.db
      .query('subscriptions')
      .withIndex('by_backend_server', (q) => q.eq('backendServerId', r.backendServerId))
      .paginate({ numItems: DRAIN_PAGE, cursor: r.cursor ?? null });
    let moved = 0;
    for (const sub of page.page) {
      const patch: Partial<Doc<'subscriptions'>> = {};
      if (sub.pinnedNode && map.has(sub.pinnedNode)) patch.pinnedNode = map.get(sub.pinnedNode);
      if (sub.excludeNode && map.has(sub.excludeNode)) patch.excludeNode = map.get(sub.excludeNode);
      if (Object.keys(patch).length > 0) {
        await ctx.db.patch(sub._id, patch);
        moved++;
      }
    }
    const now = Date.now();
    if (page.isDone) {
      await ctx.db.patch(r._id, { step: 'done', cursor: undefined, updatedAt: now });
      return { done: true, moved };
    }
    await ctx.db.patch(r._id, { cursor: page.continueCursor, updatedAt: now });
    return { done: false, moved };
  },
});

/** Done: the fence goes, and an enrolled node is reconciled under its new name. */
export const finish = internalMutation({
  args: fence,
  handler: async (ctx, f) => {
    const r = await held(ctx, f);
    if (!r || r.step !== 'done') return null;
    const now = Date.now();
    await ctx.db.patch(r._id, { state: 'done', claim: undefined, code: undefined, updatedAt: now });
    for (const id of r.relayIds) {
      const relay = await ctx.db.get(id);
      if (relay?.renaming?.renameId === r._id)
        await ctx.db.patch(id, { renaming: undefined, updatedAt: now });
    }
    if (r.intentId)
      await ctx.scheduler.runAfter(0, internal.nodeIntents.reconcileNow, { intentId: r.intentId });
    await audit(ctx, r, 'servers.node.renamed');
    return null;
  },
});

async function writesOf(ctx: ActionCtx, backendServerId: Id<'backendServers'>) {
  const server = await ctx.runQuery(internal.backendServers.getById, { id: backendServerId });
  const writes = server ? PROVIDERS[server.backend].backendWrites : undefined;
  if (!server || !writes)
    throw new ConvexError({ code: 'servers.unsupported_backend', message: 'Unsupported' });
  return { writes, config: server.config as BackendConfig };
}

/**
 * One attempt at the rename: step by step until a step waits on something
 * (an open op, a busy item), then the lease is let go and the sweep resumes.
 */
export const run = internalAction({
  args: fence,
  handler: async (ctx, f): Promise<null> => {
    for (let guard = 0; guard < 200; guard++) {
      const r = await ctx.runQuery(internal.backendNodeRenames.getForRun, f);
      if (!r) return null;
      const park = (code?: string) =>
        ctx.runMutation(internal.backendNodeRenames.park, { ...f, code });

      if (r.step === 'backend' || r.step === 'hosts') {
        if (r.opId) {
          const op = await ctx.runQuery(internal.backendLedger.getForRun, { opId: r.opId });
          if (op?.open) {
            const { open } = await ctx.runAction(internal.backendWrites.observe, { opId: r.opId });
            if (open) {
              await park('servers.op_running');
              return null;
            }
          }
          if (r.step === 'hosts') {
            await ctx.runMutation(internal.backendNodeRenames.hostSettled, f);
            continue;
          }
          // The op settled; a seen rename already moved the step (the bridge).
          const now = await ctx.runQuery(internal.backendNodeRenames.getForRun, f);
          if (now && now.step === 'backend') {
            const { writes, config } = await writesOf(ctx, r.backendServerId);
            const row = (await writes.readNodeStatus(config)).find(
              (n) => n.nodeUuid === r.nodeUuid,
            );
            await ctx.runMutation(internal.backendNodeRenames.settleBackend, {
              ...f,
              seenName: row?.name ?? null,
            });
          }
          continue;
        }
        if (r.step === 'backend') {
          const claimed = await ctx.runMutation(internal.backendNodeRenames.claimBackend, f);
          if ('code' in claimed) {
            if (claimed.code === 'servers.op_running' || claimed.code === 'servers.op_uncertain') {
              await park(claimed.code);
              return null;
            }
            if (claimed.code === 'servers.claim_not_held') return null;
            await ctx.runMutation(internal.backendNodeRenames.fail, { ...f, code: claimed.code });
            return null;
          }
          await ctx.runAction(internal.backendWrites.run, { opId: claimed.opId });
          continue;
        }
        // hosts: what still carries an old remark, read from the backend itself.
        const { writes, config } = await writesOf(ctx, r.backendServerId);
        const hosts = await writes.readHosts(config);
        const refused = new Set((r.refusedHosts ?? []).map((x) => x.hostUuid));
        const pending = hosts
          .map((h) => ({ h, remark: renamedRemark(h.remark, h.sni, r.from, r.to) }))
          .filter((x) => x.remark !== null && x.remark !== x.h.remark);
        const next = pending.find((x) => !refused.has(x.h.hostUuid));
        if (!next) {
          // Only Hosts the backend refused are left: the rename holds here,
          // its old remarks still matched, until an operator retries.
          if (pending.length > 0) {
            await park('servers.rename_host_refused');
            return null;
          }
          await ctx.runMutation(internal.backendNodeRenames.hostsDone, f);
          continue;
        }
        const claimed = await ctx.runMutation(internal.backendNodeRenames.claimHostRemark, {
          ...f,
          hostUuid: next.h.hostUuid,
          remark: next.remark!,
          was: next.h.remark,
        });
        if ('code' in claimed) {
          // A Host busy with another change (or one whose outcome is unknown):
          // try again later; nothing was sent.
          if (claimed.code !== 'servers.claim_not_held') await park(claimed.code);
          return null;
        }
        await ctx.runAction(internal.backendWrites.run, { opId: claimed.opId });
        continue;
      }
      if (r.step === 'subscriptions') {
        await ctx.runMutation(internal.backendNodeRenames.drainPage, f);
        continue;
      }
      await ctx.runMutation(internal.backendNodeRenames.finish, f);
      return null;
    }
    // A very large drain: the next attempt carries on from the cursor.
    await ctx.runMutation(internal.backendNodeRenames.park, { ...f });
    return null;
  },
});

/** Running renames whose lease is free: resumed from `backend-reconcile`. */
export const stale = internalQuery({
  args: { now: v.number() },
  handler: async (ctx, { now }) =>
    (
      await ctx.db
        .query('panelNodeRenames')
        .withIndex('by_state', (q) => q.eq('state', 'running'))
        .collect()
    )
      // One waiting on an operator (a refused Host remark) is not resumed by the clock.
      .filter((r) => leaseFree(r, now) && (r.refusedHosts ?? []).length === 0)
      .map((r) => r._id),
});

/**
 * An operator retries a rename that holds on Host remarks the backend refused
 * (once whatever refused them is fixed): those Hosts are tried again, once.
 */
export const retry = internalMutation({
  args: { renameId: v.id('panelNodeRenames'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { renameId, actorAdminId }) => {
    const r = await ctx.db.get(renameId);
    if (!r) return refuse('not_found', 'No such rename');
    if (r.state !== 'running')
      refuse('servers.node_rename_not_running', 'This rename is not running any more');
    await ctx.db.patch(r._id, { refusedHosts: undefined, code: undefined, updatedAt: Date.now() });
    await audit(ctx, r, 'servers.node.rename_retried', {}, actorAdminId);
    await lease(ctx, (await ctx.db.get(r._id))!);
    return { ok: true as const };
  },
});

/** On `backend-reconcile`: resume what an interrupted or parked attempt left running. */
export const sweep = internalAction({
  args: {},
  handler: async (ctx): Promise<number> => {
    const ids = await ctx.runQuery(internal.backendNodeRenames.stale, { now: Date.now() });
    for (const renameId of ids)
      await ctx.runMutation(internal.backendNodeRenames.resume, { renameId });
    return ids.length;
  },
});

// --- views ------------------------------------------------------------------------------------------

export function mapRename(r: Rename) {
  return {
    id: r._id as string,
    nodeUuid: r.nodeUuid,
    from: r.from,
    to: r.to,
    state: r.state,
    step: r.step,
    code: r.code ?? null,
    refusedHosts: (r.refusedHosts ?? []).map((h) => ({ remark: h.remark, code: h.code })),
    createdAt: new Date(r.createdAt).toISOString(),
    updatedAt: new Date(r.updatedAt).toISOString(),
  };
}

export const listForServer = internalQuery({
  args: { backendServerId: v.id('backendServers') },
  handler: async (ctx, { backendServerId }) =>
    (
      await ctx.db
        .query('panelNodeRenames')
        .withIndex('by_server', (q) => q.eq('backendServerId', backendServerId))
        .order('desc')
        .take(20)
    ).map(mapRename),
});

export const view = internalQuery({
  args: { renameId: v.id('panelNodeRenames') },
  handler: async (ctx, { renameId }) => {
    const r = await ctx.db.get(renameId);
    if (!r) return refuse('not_found', 'No such rename');
    return mapRename(r);
  },
});

/** The rename must belong to the backend the path names. */
export const onServer = internalQuery({
  args: { backendServerId: v.id('backendServers'), renameId: v.string() },
  handler: async (ctx, { backendServerId, renameId }) => {
    const id = ctx.db.normalizeId('panelNodeRenames', renameId);
    const r = id ? await ctx.db.get(id) : null;
    return r && r.backendServerId === backendServerId ? r._id : null;
  },
});
