/**
 * Node activation (docs/servers.md "Node lifecycle"): from `machine_ready` to
 * `live` without a member ever seeing the node before the delivery commit.
 *
 *  - A DIRECT node is proven with an isolated test link built from the
 *    node's own test credential and the transport's live parameters, and the
 *    operator's tick is bound to the exact endpoint, revisions and parameters
 *    it tested (`confirmDirect` recomputes the binding from live rows).
 *  - The review card hashes the delivery SHAPE; approval creates one
 *    activation run with an immutable candidate snapshot of its own.
 *  - The run enables the direct Host (a candidate resource, filtered from
 *    members by the gate), rehearses the backend's real bodies in every client
 *    family, and the commit mutation re-validates everything and promotes the
 *    candidate: `intent.approved`, the committed resources, `live`.
 *  - A FRONTED node's run stops at `publish`: Autopilot publishes under the
 *    publication guard and its go-live delegates to `promoteCandidate`.
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { ActionCtx, MutationCtx, QueryCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { PROVIDERS, type BackendConfig } from './lib/backends/registry';
import { randomHex } from './lib/crypto';
import {
  evidenceHolds,
  publicationAdmitted,
  publicationFits,
  reviewHashOf,
  type Evidence,
  type PublicationShape,
  type ReviewListener,
  type ReviewShape,
  type Revisions,
  type Stage,
} from './lib/backend/activation';
import type { VectorActivation } from './lib/edges/setupRuns';
import { panelDigestKey } from './lib/backend/key';
import {
  REHEARSAL_USER_AGENTS,
  bodyHasEndpoint,
  type RehearsalFamily,
} from './lib/backend/rehearsal';
import { QUALIFICATION_TRAFFIC_LIMIT_BYTES } from './relayQualification';
import { TEST_CREDENTIAL_TAG, testCredentialUsername } from './edgeTestCredentials';
import {
  isDirect,
  modeEntry,
  nodeGateFor,
  modeSlug,
  originAddressOf,
  originHostnameOf,
  transportFor,
} from './nodeIntents';
import { bumpGateVersion, setupReady, type Setup } from './backendSetup';
import { relayForBackendNode, scheduleMirrorRefresh } from './relays';
import { isCandidateEdge, type NodeGate } from './lib/backend/deliveryGate';

const refuse = (code: string, message: string): never => {
  throw new ConvexError({ code, message });
};

type Intent = Doc<'panelNodeIntents'>;
type Run = Doc<'panelActivationRuns'>;

async function setupOf(ctx: { db: QueryCtx['db'] }, sid: Id<'backendServers'>) {
  const row = await ctx.db
    .query('panelSetups')
    .withIndex('by_server', (q) => q.eq('backendServerId', sid))
    .unique();
  if (!setupReady(row))
    return refuse('servers.panel_not_set_up', 'Set up this backend in Servers first');
  return row;
}

function revisionsOf(intent: Intent): Revisions {
  return {
    machineRevision: intent.machineRevision,
    configRevision: intent.configRevision ?? '',
    authRevision: intent.authRevision,
    deliveryRevision: intent.deliveryRevision ?? '',
  };
}

// --- the review (pure over rows) --------------------------------------------------------------------

async function reviewShapeOf(
  ctx: { db: QueryCtx['db'] },
  intent: Intent,
  setup: Setup,
): Promise<ReviewShape> {
  const hostname = originHostnameOf(intent, setup);
  const originAddress = originAddressOf(intent, hostname);
  const mode = modeEntry(setup, modeSlug(intent));
  const transport = transportFor(setup, modeSlug(intent));
  const direct = isDirect(mode.shape);
  const listeners: ReviewListener[] = direct
    ? []
    : (await frontedListenersOf(ctx, intent)).map((l) => ({
        listenerKey: l.listenerKey,
        accountId: l.accountId,
        templateHash: l.templateHash,
      }));
  // A direct node's addresses follow the names its transport lists today.
  const names = direct ? await liveNamesOf(ctx, intent, transport.uuid) : [];
  return {
    mode: mode.slug,
    modeShape: mode.shape,
    ingress: intent.settings.ingress ?? null,
    configRevision: intent.configRevision ?? '',
    authRevision: intent.authRevision ?? null,
    listeners,
    subscriptionTemplates: Object.fromEntries(setup.templates.map((t) => [t.family, t.hash])),
    addressTuples: names.map((sni) => ({ address: originAddress, port: transport.port, sni })),
  };
}

/**
 * Every required listener of a fronted node, sorted by key, with the edge
 * that fronts it: the candidate the open setup run holds for it, else the
 * listener's published template edge. The review lists each one (never one
 * representative edge), so a change of account or template on ANY listener
 * is a new review.
 */
async function frontedListenersOf(
  ctx: { db: QueryCtx['db'] },
  intent: Intent,
): Promise<
  Array<
    ReviewListener & {
      layer: 'l4' | 'l7';
      edge: Doc<'edges'> | null;
      templateEdgeId: Id<'edges'> | null;
    }
  >
> {
  const relay = await relayForBackendNode(ctx.db, intent.backendServerId, intent.name);
  if (!relay || relay.origin.kind !== 'panel-node' || relay.origin.nodeName !== intent.name)
    return [];
  const run = await openSetupRunOf(ctx, intent);
  const listeners = (
    await ctx.db
      .query('relayListeners')
      .withIndex('by_relay', (q) => q.eq('relayId', relay._id))
      .collect()
  )
    .filter((l) => !l.retired)
    .sort((a, b) => a.listenerKey.localeCompare(b.listenerKey));
  const out = [];
  for (const l of listeners) {
    const entry = run?.listeners.find((x) => x.listenerKey === l.listenerKey);
    const edgeId = entry?.edgeId ?? l.templateEdgeId;
    const edge = edgeId ? await ctx.db.get(edgeId) : null;
    out.push({
      listenerKey: l.listenerKey,
      accountId: edge?.accountId ? String(edge.accountId) : null,
      templateHash: edge?.templateHash ?? null,
      layer: entry?.layer ?? edge?.layer ?? ('l4' as const),
      edge,
      templateEdgeId: l.templateEdgeId ?? null,
    });
  }
  return out;
}

/** The names a REALITY transport lists on the backend right now (its family's rollouts move them). */
async function liveNamesOf(
  ctx: { db: QueryCtx['db'] },
  intent: Intent,
  transportUuid: string,
): Promise<string[]> {
  const profiles = await ctx.db
    .query('panelProfiles')
    .withIndex('by_server', (q) => q.eq('backendServerId', intent.backendServerId))
    .collect();
  for (const p of profiles) {
    const ib = p.inbounds.find((i) => i.inboundUuid === transportUuid);
    if (ib) return ib.reality?.serverNames ?? [];
  }
  return [];
}

export const review = internalQuery({
  args: { intentId: v.id('panelNodeIntents') },
  handler: async (ctx, { intentId }) => {
    const intent = await ctx.db.get(intentId);
    if (!intent) return refuse('not_found', 'No such node');
    const setup = await setupOf(ctx, intent.backendServerId);
    const shape = await reviewShapeOf(ctx, intent, setup);
    const reviewHash = await reviewHashOf(shape);
    const direct = isDirect(modeEntry(setup, modeSlug(intent)).shape);
    const standbys = direct ? null : await standbysOf(ctx, intent);
    const blockers = await activationBlockers(ctx, intent, setup, direct, standbys);
    return {
      shape,
      reviewHash,
      blockers,
      stage: intent.activation.stage,
      // Shown, never hashed: the addresses a fronted approval releases.
      display: { standbys: direct ? [] : await standbyDisplayOf(ctx, intent) },
    };
  },
});

/** What the review card shows of a fronted node's candidates: one line per required listener. */
async function standbyDisplayOf(ctx: { db: QueryCtx['db'] }, intent: Intent) {
  const out = [];
  for (const l of await frontedListenersOf(ctx, intent)) {
    const e = l.edge;
    const host = e ? (e.addresses.v4 ?? e.addresses.hostname ?? e.addresses.v6 ?? null) : null;
    const port = e?.listeners[0]?.edgePort ?? null;
    const account = e?.accountId ? await ctx.db.get(e.accountId) : null;
    out.push({
      listenerKey: l.listenerKey,
      layer: l.layer,
      endpoint: host ? (port ? `${host}:${port}` : host) : null,
      accountName: account?.name ?? null,
      provider: e?.provider ?? null,
    });
  }
  return out;
}

// --- a fronted node's candidates: the standbys of its Autopilot run ---------------------------------

const OPEN_SETUP_RUN = new Set(['running', 'waiting', 'needs_you']);

/** The guided setup run protecting this node right now (one per node by construction). */
async function openSetupRunOf(
  ctx: { db: QueryCtx['db'] },
  intent: Intent,
): Promise<Doc<'edgeSetupRuns'> | null> {
  return (
    (
      await ctx.db
        .query('edgeSetupRuns')
        .withIndex('by_origin', (q) =>
          q.eq('backendServerId', intent.backendServerId).eq('nodeName', intent.name),
        )
        .collect()
    ).find((r) => OPEN_SETUP_RUN.has(r.state)) ?? null
  );
}

interface Standbys {
  /** null = verified now. */
  code: string | null;
  listenerKeys: string[];
  /** The open setup run whose standbys these are (absent = none). */
  runId?: Id<'edgeSetupRuns'>;
  edgeIds: Id<'edges'>[];
}

/**
 * A front or origin node's candidates are the listeners of the Autopilot run
 * protecting it, each with a live, verified standby (an L7 proof; an L4
 * revision-bound confirmation) before that run reaches publish and waits for
 * this approval. `code` null = verified now.
 */
async function standbysOf(ctx: { db: QueryCtx['db'] }, intent: Intent): Promise<Standbys> {
  const run = await openSetupRunOf(ctx, intent);
  if (!run) return { code: 'servers.standbys_missing', listenerKeys: [], edgeIds: [] };
  const listenerKeys = run.listeners.map((l) => l.listenerKey).sort();
  const edgeIds = run.listeners.map((l) => l.edgeId).filter((e): e is Id<'edges'> => !!e);
  if (run.listeners.length === 0 || run.listeners.some((l) => !l.edgeId || l.verify !== 'verified'))
    return { code: 'servers.standbys_unverified', listenerKeys, runId: run._id, edgeIds };
  return { code: null, listenerKeys, runId: run._id, edgeIds };
}

/**
 * The stage an approval starts from, or null when the node's stage cannot be
 * approved. A fronted node whose standbys hold NOW is approvable from
 * `machine_ready` (its first approval) and from `live` (a re-approval of a
 * live node, members keep the committed delivery meanwhile).
 */
function approvalStageOf(intent: Intent, direct: boolean, standbys: Standbys | null): Stage | null {
  const stage = intent.activation.stage;
  if (stage === 'candidates_verified' || stage === 'awaiting_approval') return stage;
  if (!direct && standbys && !standbys.code && (stage === 'machine_ready' || stage === 'live'))
    return 'candidates_verified';
  return null;
}

/**
 * Candidate Hosts on a LIVE node (docs/servers.md "Node lifecycle"). A
 * direct node's body passes to members as the backend serves it, so an
 * address enabled for a candidate cannot be kept out of it; a fronted node's
 * listener without a committed template edge gets a new Host or a new Host
 * pointer. Either needs the gate closed first: maintenance, then a fresh
 * activation. Null when the approval keeps to what members already have.
 */
async function liveIsolationBlocker(
  ctx: { db: QueryCtx['db'] },
  intent: Intent,
  direct: boolean,
): Promise<string | null> {
  if (intent.delivery.disposition !== 'live' || !intent.approved) return null;
  const committed = intent.approved.committed;
  if (direct) {
    const extra = (intent.addressUuids ?? []).some((u) => !committed.hostUuids.includes(u));
    return extra ? 'servers.maintenance_required' : null;
  }
  const gate = await nodeGateFor(ctx, intent.backendServerId, intent.name);
  for (const l of await frontedListenersOf(ctx, intent)) {
    if (pointerMoves(gate, l.templateEdgeId)) return 'servers.maintenance_required';
  }
  return null;
}

/**
 * Whether a candidate on this listener of a LIVE node would need a new Host
 * or a moved Host pointer: the listener has no template edge, or its template
 * is itself a candidate (members are not served through it yet). A template
 * an automatic replacement moved stays fine: what members get is what counts.
 */
function pointerMoves(gate: NodeGate, templateEdgeId: Id<'edges'> | null): boolean {
  return !templateEdgeId || isCandidateEdge(gate, templateEdgeId as string);
}

/** What keeps a node from being approved, as code words (the first is what `approve` refuses with). */
async function activationBlockers(
  ctx: { db: QueryCtx['db'] },
  intent: Intent,
  setup: Setup,
  direct: boolean,
  standbys: Standbys | null,
): Promise<string[]> {
  const out: string[] = [];
  const revs = revisionsOf(intent);
  const has = (k: string) =>
    intent.activation.evidence.some((e) => e.kind === k && evidenceHolds(e, revs));
  if (!has('machine_ready')) out.push('servers.machine_not_ready');
  if (direct && !has('direct_confirmed')) out.push('servers.direct_unconfirmed');
  // An adopted node whose edge FCP does not run yet has no standbys to show.
  // Every other fronted approval is driven by its open setup run: without
  // one, nothing would publish the candidate.
  if (!direct && !intent.adopted?.externallyFronted && standbys?.code) out.push(standbys.code);
  const mode = modeEntry(setup, modeSlug(intent));
  if (mode.placement !== 'bound') out.push('servers.placement_skipped');
  if (mode.family === 'unbound' || mode.family === 'target_mismatch')
    out.push('servers.family_unbound');
  if (setup.templates.some((t) => t.state !== 'matched')) out.push('servers.template_drifted');
  if (setup.privacy === 'drifted') out.push('servers.privacy_drifted');
  if (intent.maintenance) out.push('servers.maintenance_open');
  if (intent.state === 'retiring' || intent.state === 'retired') out.push('servers.node_retiring');
  const isolation = await liveIsolationBlocker(ctx, intent, direct);
  if (isolation) out.push(isolation);
  if (!approvalStageOf(intent, direct, standbys)) out.push('servers.stage');
  return out;
}

// --- the test credential a direct node owns ----------------------------------------------------------

async function credentialContextOf(ctx: QueryCtx, intentId: Id<'panelNodeIntents'>) {
  const intent = await ctx.db.get(intentId);
  if (!intent) return null;
  const server = await ctx.db.get(intent.backendServerId);
  if (!server) return null;
  const setup = await setupOf(ctx, intent.backendServerId);
  const now = Date.now();
  const rows = await ctx.db
    .query('edgeTestCredentials')
    .withIndex('by_intent', (q) => q.eq('nodeIntentId', intentId))
    .collect();
  const reusable =
    rows.find(
      (r) =>
        r.removal === 'pending' &&
        r.expiresAt > now + 60_000 &&
        !!r.backendUserId &&
        !!r.backendShortId &&
        !!r.subscriptionUrl,
    ) ?? null;
  // An issuance whose answer was lost: the row holds no backend identity.
  const unresolved = rows.find((r) => r.removal === 'pending' && !r.backendUserId) ?? null;
  const hostname = originHostnameOf(intent, setup);
  return {
    intent,
    server: { _id: server._id, backend: server.backend, config: server.config, slug: server.slug },
    setup,
    mode: modeEntry(setup, modeSlug(intent)),
    transport: transportFor(setup, modeSlug(intent)),
    groupUuid: modeEntry(setup, modeSlug(intent)).groupUuid ?? null,
    originAddress: originAddressOf(intent, hostname),
    reusable: reusable
      ? {
          id: reusable._id,
          backendUserId: reusable.backendUserId!,
          backendShortId: reusable.backendShortId!,
          subscriptionUrl: reusable.subscriptionUrl!,
        }
      : null,
    unresolved: unresolved
      ? { id: unresolved._id, username: unresolved.username, expiresAt: unresolved.expiresAt }
      : null,
  };
}
type CredentialCtx = NonNullable<Awaited<ReturnType<typeof credentialContextOf>>>;

export const credentialContext = internalQuery({
  args: { intentId: v.id('panelNodeIntents') },
  handler: (ctx, { intentId }) => credentialContextOf(ctx, intentId),
});

async function ensureIntentCredential(
  ctx: ActionCtx,
  c: {
    intent: Intent;
    server: { _id: Id<'backendServers'>; backend: Doc<'backendServers'>['backend'] };
    groupUuid: string | null;
    reusable: {
      id: Id<'edgeTestCredentials'>;
      backendUserId: string;
      backendShortId: string;
      subscriptionUrl: string;
    } | null;
    unresolved: { id: Id<'edgeTestCredentials'>; username: string; expiresAt: number } | null;
  },
) {
  if (c.reusable) return c.reusable;
  if (c.unresolved) {
    // Discovery by name settles the lost issuance before anything is minted
    // again: found = adopted (and reused while it lasts), absent = it never
    // landed. A backend without lookup keeps the block for the operator.
    let found: { backendUserId: string; backendShortId: string; subscriptionUrl: string } | null;
    try {
      found = await ctx.runAction(internal.backends.findUserByUsername, {
        backendServerId: c.server._id,
        username: c.unresolved.username,
      });
    } catch (err) {
      const code = err instanceof ConvexError ? (err.data as { code?: string })?.code : undefined;
      if (code === 'backend.lookup_unsupported')
        return refuse(
          'servers.credential_unresolved',
          'A test credential of this node has an unknown outcome on the backend',
        );
      throw err;
    }
    if (found) {
      const adopted = {
        backendUserId: found.backendUserId,
        backendShortId: found.backendShortId,
        subscriptionUrl: found.subscriptionUrl,
      };
      await ctx.runMutation(internal.edgeTestCredentials.markIssued, {
        id: c.unresolved.id,
        ...adopted,
      });
      if (c.unresolved.expiresAt > Date.now() + 60_000) return { id: c.unresolved.id, ...adopted };
      // Expired meanwhile: the sweep removes it now that it has an id.
    } else {
      await ctx.runMutation(internal.edgeTestCredentials.dropUnissued, { id: c.unresolved.id });
    }
  }
  if (!c.groupUuid) refuse('servers.panel_not_set_up', 'The mode has no group on the backend');
  const username = testCredentialUsername(c.intent.name, 'test_link', randomHex(4));
  const id = await ctx.runMutation(internal.edgeTestCredentials.insertPending, {
    nodeIntentId: c.intent._id,
    backendServerId: c.server._id,
    username,
    purpose: 'test_link',
  });
  let issued;
  try {
    issued = await ctx.runAction(internal.backends.issueUser, {
      backend: c.server.backend,
      pinServerId: c.server._id,
      spec: {
        username,
        trafficLimitBytes: QUALIFICATION_TRAFFIC_LIMIT_BYTES,
        expireAt: null,
        tag: TEST_CREDENTIAL_TAG,
        description: 'FCP node activation test (automated, temporary)',
        placement: c.groupUuid,
      },
    });
  } catch (err) {
    if (err instanceof ConvexError)
      await ctx.runMutation(internal.edgeTestCredentials.dropUnissued, { id });
    throw err;
  }
  await ctx.runMutation(internal.edgeTestCredentials.markIssued, {
    id,
    backendUserId: issued.backendUserId,
    backendShortId: issued.backendShortId,
    subscriptionUrl: issued.subscriptionUrl,
  });
  return {
    id,
    backendUserId: issued.backendUserId,
    backendShortId: issued.backendShortId,
    subscriptionUrl: issued.subscriptionUrl,
  };
}

// --- the direct test link and its confirmation ----------------------------------------------------

export interface DirectTestBinding {
  intentId: string;
  inboundUuid: string;
  endpoint: string;
  machineRevision: number;
  configRevision: string;
  authRevision: string | null;
  params: { sni: string; fingerprint: string; shortIdRef: number; publicKey: string };
  credentialRef: string;
  issuedAt: string;
}

export const buildDirectTestLink = internalAction({
  args: { intentId: v.id('panelNodeIntents') },
  handler: async (ctx, { intentId }): Promise<{ link: string; binding: DirectTestBinding }> => {
    const c = (await ctx.runQuery(internal.nodeActivation.credentialContext, {
      intentId,
    })) as CredentialCtx | null;
    if (!c) throw new ConvexError({ code: 'not_found', message: 'No such node' });
    if (!isDirect(c.mode.shape) || c.mode.shape.transport !== 'reality')
      throw new ConvexError({
        code: 'validation',
        message: 'Only a direct REALITY node has a direct test link',
      });
    const writes = PROVIDERS[c.server.backend].backendWrites;
    if (!writes)
      throw new ConvexError({ code: 'servers.unsupported_backend', message: 'Unsupported' });
    const config = c.server.config as BackendConfig;
    const cred = await ensureIntentCredential(ctx, c);
    const reality = c.transport;
    const params = await writes.readInboundForTest(
      config,
      c.setup.profileUuid!,
      reality.tag,
      (await panelDigestKey()).key,
    );
    if (!params)
      throw new ConvexError({
        code: 'servers.inbound_missing',
        message: 'The REALITY transport is gone',
      });
    const { protocolUuid } = await writes.userCredential(config, cred.backendUserId);
    if (!protocolUuid)
      throw new ConvexError({
        code: 'servers.credential_unavailable',
        message: 'No protocol credential',
      });
    const sni = params.serverNames[0] ?? '';
    const endpoint = `${c.originAddress}:${params.port ?? reality.port}`;
    const q = new URLSearchParams({
      encryption: 'none',
      security: 'reality',
      type: 'tcp',
      sni,
      fp: 'chrome',
      pbk: params.publicKey,
      sid: params.shortId,
    });
    const link = `vless://${protocolUuid}@${endpoint}?${q.toString()}#${encodeURIComponent(`FCP test ${c.intent.name}`)}`;
    const binding: DirectTestBinding = {
      intentId: intentId as string,
      inboundUuid: params.inboundUuid,
      endpoint,
      machineRevision: c.intent.machineRevision,
      configRevision: `${params.changeToken}:${params.inboundUuid}`,
      authRevision: params.authDigest,
      params: { sni, fingerprint: 'chrome', shortIdRef: 0, publicKey: params.publicKey },
      credentialRef: cred.id as string,
      issuedAt: new Date().toISOString(),
    };
    return { link, binding };
  },
});

/** The operator's tick: every value of the binding is recomputed from live rows and must agree. */
export const confirmDirect = internalMutation({
  args: {
    intentId: v.id('panelNodeIntents'),
    binding: v.object({
      inboundUuid: v.string(),
      endpoint: v.string(),
      machineRevision: v.number(),
      configRevision: v.string(),
      authRevision: v.union(v.string(), v.null()),
      params: v.object({
        sni: v.string(),
        fingerprint: v.string(),
        shortIdRef: v.number(),
        publicKey: v.string(),
      }),
      credentialRef: v.string(),
    }),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const intent = await ctx.db.get(a.intentId);
    if (!intent) return refuse('not_found', 'No such node');
    const setup = await setupOf(ctx, intent.backendServerId);
    if (!isDirect(modeEntry(setup, modeSlug(intent)).shape))
      refuse('validation', 'Only a direct node is confirmed this way');
    const reality = transportFor(setup, modeSlug(intent));
    const hostname = originHostnameOf(intent, setup);
    const names = await liveNamesOf(ctx, intent, reality.uuid);
    const live = {
      inboundUuid: reality.uuid,
      endpoint: `${originAddressOf(intent, hostname)}:${reality.port}`,
      machineRevision: intent.machineRevision,
      configRevision: intent.configRevision ?? '',
      authRevision: intent.authRevision ?? null,
      sni: names[0] ?? reality.serverNames?.[0] ?? '',
      publicKey: reality.publicKey ?? '',
    };
    const b = a.binding;
    const same =
      b.inboundUuid === live.inboundUuid &&
      b.endpoint === live.endpoint &&
      b.machineRevision === live.machineRevision &&
      b.configRevision === live.configRevision &&
      b.authRevision === live.authRevision &&
      b.params.sni === live.sni &&
      b.params.publicKey === live.publicKey;
    if (!same)
      refuse(
        'servers.confirmation_stale',
        'What you tested is not what the node serves now. Build a new test link',
      );
    const cred = await ctx.db.get(b.credentialRef as Id<'edgeTestCredentials'>);
    if (!cred || cred.nodeIntentId !== intent._id)
      refuse('servers.confirmation_stale', 'The test credential is not this node’s');
    const now = Date.now();
    const evidence: Evidence[] = [
      ...intent.activation.evidence.filter((e) => e.kind !== 'direct_confirmed'),
      {
        kind: 'direct_confirmed',
        machineRevision: live.machineRevision,
        configRevision: live.configRevision,
        authRevision: live.authRevision ?? undefined,
        at: now,
        detail: live.endpoint,
      },
    ];
    const stage =
      intent.activation.stage === 'machine_ready' ? 'candidates_verified' : intent.activation.stage;
    await ctx.db.patch(intent._id, {
      activation: { ...intent.activation, evidence, stage },
      updatedAt: now,
    });
    const server = await ctx.db.get(intent.backendServerId);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'servers.node.direct_confirmed',
      targetType: 'panel_node_intent',
      targetId: intent._id,
      payload: { backendSlug: server?.slug ?? '', name: intent.name },
    });
    return { stage };
  },
});

// --- approval: one run with an immutable candidate ----------------------------------------------

export const approve = internalMutation({
  args: {
    intentId: v.id('panelNodeIntents'),
    reviewHash: v.string(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const intent = await ctx.db.get(a.intentId);
    if (!intent) return refuse('not_found', 'No such node');
    const setup = await setupOf(ctx, intent.backendServerId);
    const direct = isDirect(modeEntry(setup, modeSlug(intent)).shape);
    const standbys = direct ? null : await standbysOf(ctx, intent);
    const blockers = await activationBlockers(ctx, intent, setup, direct, standbys);
    if (blockers.length > 0) refuse(blockers[0]!, 'The node is not ready for approval');
    const now = Date.now();
    let evidence = intent.activation.evidence;
    if (!direct && standbys && !standbys.code) {
      // The standbys hold now: recorded as evidence bound to the revisions
      // (the commit re-checks it), and the ladder reaches candidates_verified.
      evidence = [
        ...evidence.filter((e) => e.kind !== 'standbys_verified'),
        {
          kind: 'standbys_verified',
          ...revisionsOf(intent),
          at: now,
          detail: standbys.listenerKeys.join(','),
        },
      ];
    }
    const shape = await reviewShapeOf(ctx, intent, setup);
    const reviewHash = await reviewHashOf(shape);
    if (reviewHash !== a.reviewHash)
      refuse('servers.review_stale', 'The review changed since you read it. Read it again');
    // Any older run of this node is superseded: it never commits. Its
    // candidates stay isolated from members (the gate counts every
    // uncommitted run's resources) until this run commits or they are released.
    for (const r of await ctx.db
      .query('panelActivationRuns')
      .withIndex('by_intent', (q) => q.eq('intentId', intent._id))
      .collect())
      if (r.state === 'running' || r.state === 'blocked' || r.state === 'review')
        await ctx.db.patch(r._id, { state: 'superseded', updatedAt: now });
    // A fronted approval names the standbys of the open setup run: they are
    // this run's candidates from now on (members never see one before the
    // commit), except an edge members already hold under the committed approval.
    const committedEdges = new Set(intent.approved?.committed.edgeIds ?? []);
    const setupRunId = standbys?.runId;
    const runId = await ctx.db.insert('panelActivationRuns', {
      backendServerId: intent.backendServerId,
      intentId: intent._id,
      ...(setupRunId ? { setupRunId } : {}),
      generation: intent.generation,
      stepVersion: 1,
      state: 'running',
      stage: direct ? 'hosts' : 'publish',
      candidate: {
        machineRevision: intent.machineRevision,
        configRevision: intent.configRevision ?? '',
        authRevision: intent.authRevision,
        deliveryRevision: intent.deliveryRevision ?? '',
        reviewHash,
        review: JSON.stringify(shape),
        approval: { byAdminId: a.actorAdminId, at: now },
      },
      resources: {
        hostUuids: direct ? [...(intent.addressUuids ?? [])] : [],
        edgeIds: direct
          ? []
          : (standbys?.edgeIds ?? []).filter((e) => !committedEdges.has(e as string)),
      },
      events: [{ at: now, code: 'approved' }],
      createdAt: now,
      updatedAt: now,
    });
    await ctx.db.patch(intent._id, {
      activation: {
        ...intent.activation,
        evidence,
        stage: 'activating',
        currentRunId: runId,
        reviewHash,
      },
      delivery: {
        ...intent.delivery,
        disposition: intent.delivery.disposition === 'live' ? 'live' : 'activating',
      },
      updatedAt: now,
    });
    await bumpGateVersion(ctx, intent.backendServerId);
    const server = await ctx.db.get(intent.backendServerId);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'servers.node.approved',
      targetType: 'panel_node_intent',
      targetId: intent._id,
      payload: { backendSlug: server?.slug ?? '', name: intent.name, mode: modeSlug(intent) },
    });
    if (direct)
      await ctx.scheduler.runAfter(0, internal.nodeActivation.runDirect, {
        runId,
        stepVersion: 1,
      });
    else if (setupRunId) {
      // The setup run waiting at publish is woken for THIS approval: the link
      // is ownership (stable across retries), the generation read here fences
      // the wake against an attempt that moved on meanwhile.
      const setupRun = (await ctx.db.get(setupRunId))!;
      await ctx.db.patch(setupRunId, { activationRunId: runId, updatedAt: now });
      await ctx.scheduler.runAfter(0, internal.edgeSetupRuns.wakeForApproval, {
        setupRunId,
        activationRunId: runId,
        generation: setupRun.generation,
      });
    }
    return { runId };
  },
});

/** A revision change under a node supersedes its running activation (called by the settings patch). */
export async function supersedeRuns(ctx: MutationCtx, intentId: Id<'panelNodeIntents'>) {
  const now = Date.now();
  for (const r of await ctx.db
    .query('panelActivationRuns')
    .withIndex('by_intent', (q) => q.eq('intentId', intentId))
    .collect())
    if (r.state === 'running' || r.state === 'blocked' || r.state === 'review')
      await ctx.db.patch(r._id, { state: 'superseded', updatedAt: now });
}

// --- the direct run: enable the Host, rehearse, commit ----------------------------------------------

async function runContextOf(ctx: QueryCtx, runId: Id<'panelActivationRuns'>, stepVersion: number) {
  const run = await ctx.db.get(runId);
  if (!run || run.stepVersion !== stepVersion || run.state !== 'running') return null;
  const intent = await ctx.db.get(run.intentId);
  if (!intent || intent.activation.currentRunId !== runId) return null;
  const server = await ctx.db.get(intent.backendServerId);
  if (!server) return null;
  const setup = await setupOf(ctx, intent.backendServerId);
  const wanted = new Set(intent.addressUuids ?? []);
  const addresses = (
    await ctx.db
      .query('panelHosts')
      .withIndex('by_server', (q) => q.eq('backendServerId', intent.backendServerId))
      .collect()
  ).filter((h) => wanted.has(h.hostUuid));
  const hostname = originHostnameOf(intent, setup);
  return {
    run,
    intent,
    server: { _id: server._id, backend: server.backend, config: server.config, slug: server.slug },
    setup,
    transport: transportFor(setup, modeSlug(intent)),
    addresses,
    originAddress: originAddressOf(intent, hostname),
  };
}
type RunContext = NonNullable<Awaited<ReturnType<typeof runContextOf>>>;

export const runContext = internalQuery({
  args: { runId: v.id('panelActivationRuns'), stepVersion: v.number() },
  handler: (ctx, { runId, stepVersion }) => runContextOf(ctx, runId, stepVersion),
});

export const step = internalMutation({
  args: {
    runId: v.id('panelActivationRuns'),
    stepVersion: v.number(),
    stage: v.optional(
      v.union(
        v.literal('hosts'),
        v.literal('publish'),
        v.literal('rehearse'),
        v.literal('commit'),
        v.literal('done'),
      ),
    ),
    state: v.optional(v.union(v.literal('running'), v.literal('blocked'), v.literal('failed'))),
    code: v.optional(v.string()),
    rehearsal: v.optional(
      v.object({ ok: v.boolean(), families: v.array(v.string()), detail: v.optional(v.string()) }),
    ),
    schedule: v.optional(v.boolean()),
  },
  handler: async (ctx, a) => {
    const run = await ctx.db.get(a.runId);
    if (!run || run.stepVersion !== a.stepVersion || run.state !== 'running')
      return { ok: false as const };
    const now = Date.now();
    const next = run.stepVersion + 1;
    await ctx.db.patch(a.runId, {
      stepVersion: next,
      ...(a.stage ? { stage: a.stage } : {}),
      ...(a.state ? { state: a.state } : {}),
      ...(a.code !== undefined ? { code: a.code } : {}),
      ...(a.rehearsal ? { rehearsal: { ...a.rehearsal, at: now } } : {}),
      events: [...run.events, { at: now, code: a.code ?? a.stage ?? a.state ?? 'step' }],
      updatedAt: now,
    });
    if (a.state === 'blocked' || a.state === 'failed') await parkAfterBlock(ctx, run);
    if (a.schedule)
      await ctx.scheduler.runAfter(0, internal.nodeActivation.runDirect, {
        runId: a.runId,
        stepVersion: next,
      });
    return { ok: true as const, stepVersion: next };
  },
});

/**
 * A run that blocked or failed parks the node where it can be approved
 * again: the run keeps its record, the intent drops it as current, and a
 * node that was only `activating` is `staged` again (a live node keeps its
 * committed delivery). The next approval supersedes this run and starts a
 * fresh one; nothing of the candidate is served meanwhile.
 */
async function parkAfterBlock(ctx: MutationCtx, run: Run): Promise<void> {
  const intent = await ctx.db.get(run.intentId);
  if (!intent || intent.activation.currentRunId !== run._id) return;
  const now = Date.now();
  await ctx.db.patch(intent._id, {
    activation: {
      ...intent.activation,
      stage:
        intent.activation.stage === 'activating' ? 'awaiting_approval' : intent.activation.stage,
      currentRunId: undefined,
    },
    delivery: {
      ...intent.delivery,
      disposition:
        intent.delivery.disposition === 'activating' ? 'staged' : intent.delivery.disposition,
    },
    updatedAt: now,
  });
  await bumpGateVersion(ctx, intent.backendServerId);
}

export const runDirect = internalAction({
  args: { runId: v.id('panelActivationRuns'), stepVersion: v.number() },
  handler: async (ctx, { runId, stepVersion }): Promise<null> => {
    const c = (await ctx.runQuery(internal.nodeActivation.runContext, {
      runId,
      stepVersion,
    })) as RunContext | null;
    if (!c) return null;
    const block = (code: string) =>
      ctx.runMutation(internal.nodeActivation.step, {
        runId,
        stepVersion,
        state: 'blocked',
        code,
      });
    try {
      if (c.run.stage === 'hosts') {
        // The candidate addresses: enabled now, kept from members by the
        // closed gate until the commit. A LIVE node's gate is open, and a
        // direct body cannot be filtered, so a new address waits for maintenance.
        if (c.addresses.length === 0) return block('servers.host_missing').then(() => null);
        const committed = c.intent.approved?.committed.hostUuids ?? [];
        if (
          c.intent.delivery.disposition === 'live' &&
          c.addresses.some((h) => !committed.includes(h.hostUuid))
        )
          return block('servers.maintenance_required').then(() => null);
        for (const h of c.addresses) {
          if (!h.isDisabled) continue;
          const { opId } = await ctx.runMutation(internal.backendWrites.requestAddressUpdate, {
            backendServerId: c.server._id,
            hostUuid: h.hostUuid,
            isDisabled: false,
          });
          const r = await ctx.runAction(internal.backendWrites.run, { opId });
          if (r.open) return block('servers.op_running').then(() => null);
        }
        await ctx.runMutation(internal.nodeActivation.step, {
          runId,
          stepVersion,
          stage: 'rehearse',
          schedule: true,
        });
        return null;
      }
      if (c.run.stage === 'rehearse') {
        const cred = (await ctx.runQuery(internal.nodeActivation.credentialContext, {
          intentId: c.intent._id,
        })) as CredentialCtx | null;
        if (!cred?.reusable) return block('servers.credential_unavailable').then(() => null);
        const publicKey = c.transport.publicKey ?? '';
        const families: RehearsalFamily[] = ['links', 'singbox', 'clash'];
        const failed: string[] = [];
        // EVERY candidate address, with the name it is there to serve: a body
        // that carries one of a node's addresses says nothing about the rest,
        // and the commit promotes all of them.
        const expected = c.addresses.map((h) => ({
          address: h.address,
          port: h.port,
          publicKey,
          sni: h.sni ?? null,
          label: h.sni ?? h.address,
        }));
        for (const family of families) {
          const fetched = await ctx.runAction(internal.backends.fetchSubscriptionContent, {
            backend: c.server.backend,
            backendServerId: c.server._id,
            backendShortId: cred.reusable.backendShortId,
            subscriptionUrl: cred.reusable.subscriptionUrl,
            userAgent: REHEARSAL_USER_AGENTS[family],
            unpinned: true,
          });
          for (const e of expected) {
            const verdict = bodyHasEndpoint(family, fetched.content, e);
            if (!verdict.found)
              failed.push(
                `${family}:${e.label}:${
                  verdict.keyMismatch ? 'key' : verdict.sniMismatch ? 'sni' : 'absent'
                }`,
              );
          }
        }
        const ok = failed.length === 0;
        const s = await ctx.runMutation(internal.nodeActivation.step, {
          runId,
          stepVersion,
          rehearsal: { ok, families, detail: failed.join(',') || undefined },
          ...(ok
            ? { stage: 'commit' as const }
            : { state: 'blocked' as const, code: 'servers.rehearsal_failed' }),
        });
        if (!ok || !s.ok) {
          // A failed rehearsal closes what it opened: every address goes back to disabled.
          for (const h of c.addresses) {
            const { opId } = await ctx.runMutation(internal.backendWrites.requestAddressUpdate, {
              backendServerId: c.server._id,
              hostUuid: h.hostUuid,
              isDisabled: true,
            });
            await ctx.runAction(internal.backendWrites.run, { opId });
          }
          return null;
        }
        await ctx.runMutation(internal.nodeActivation.commit, {
          runId,
          stepVersion: s.stepVersion,
        });
        return null;
      }
      return null;
    } catch (err) {
      const code =
        err instanceof ConvexError && typeof (err.data as { code?: unknown })?.code === 'string'
          ? (err.data as { code: string }).code
          : 'servers.activation_failed';
      await block(code);
      return null;
    }
  },
});

// --- the delivery commit ------------------------------------------------------------------------------

/**
 * Promote a run's immutable candidate: the ONE transaction in which a node
 * becomes live. Every check reads current rows; Autopilot's go-live calls
 * this for an enrolled node inside its own mutation.
 */
export async function promoteCandidate(
  ctx: MutationCtx,
  run: Run,
  extra: { edgeIds?: string[] } = {},
): Promise<{ ok: true } | { ok: false; code: string }> {
  const intent = await ctx.db.get(run.intentId);
  if (!intent) return { ok: false, code: 'not_found' };
  if (intent.activation.currentRunId !== run._id)
    return { ok: false, code: 'servers.run_superseded' };
  if (run.state !== 'running') return { ok: false, code: 'servers.run_not_running' };
  if (intent.state === 'retiring' || intent.state === 'retired')
    return { ok: false, code: 'servers.node_retiring' };
  if (intent.maintenance) return { ok: false, code: 'servers.maintenance_open' };
  const setup = await ctx.db
    .query('panelSetups')
    .withIndex('by_server', (q) => q.eq('backendServerId', intent.backendServerId))
    .unique();
  if (!setupReady(setup)) return { ok: false, code: 'servers.panel_not_set_up' };
  // The candidate is what was approved: recomputed from the snapshot's own values.
  const cand = run.candidate;
  const revs: Revisions = {
    machineRevision: cand.machineRevision,
    configRevision: cand.configRevision,
    authRevision: cand.authRevision,
    deliveryRevision: cand.deliveryRevision,
  };
  const now = revisionsOf(intent);
  if (
    now.machineRevision !== revs.machineRevision ||
    now.configRevision !== revs.configRevision ||
    (now.authRevision ?? null) !== (revs.authRevision ?? null) ||
    now.deliveryRevision !== revs.deliveryRevision
  )
    return { ok: false, code: 'servers.revision_moved' };
  const shape = await reviewShapeOf(ctx, intent, setup);
  if ((await reviewHashOf(shape)) !== cand.reviewHash)
    return { ok: false, code: 'servers.review_stale' };
  const has = (k: string) =>
    intent.activation.evidence.some((e) => e.kind === k && evidenceHolds(e, revs));
  if (!has('machine_ready')) return { ok: false, code: 'servers.machine_not_ready' };
  if (isDirect(modeEntry(setup, modeSlug(intent)).shape)) {
    if (!has('direct_confirmed')) return { ok: false, code: 'servers.direct_unconfirmed' };
    if (!run.rehearsal?.ok) return { ok: false, code: 'servers.rehearsal_missing' };
  } else if (!has('standbys_verified') && !intent.adopted?.externallyFronted)
    return { ok: false, code: 'servers.standbys_unverified' };
  const open = (
    await ctx.db
      .query('backendObligations')
      .withIndex('by_owner', (q) => q.eq('ownerKind', 'intent').eq('ownerId', intent._id))
      .collect()
  ).some((o) => o.state === 'pending' || o.state === 'sent' || o.state === 'unresolved');
  if (open) return { ok: false, code: 'servers.obligation_unresolved' };
  const at = Date.now();
  // What members are served from now on: this run's set, plus every edge of
  // the previous commit still published (a replacement joins the pool beside
  // the committed edges; the replace or unpublish that retires them is its own
  // decision), so a later approval never mistakes a served edge for a candidate.
  const kept: string[] = [];
  for (const id of intent.approved?.committed.edgeIds ?? []) {
    const e = await ctx.db.get(id as Id<'edges'>);
    if (e && e.publication === 'published' && e.status === 'active') kept.push(id);
  }
  const committed = {
    hostUuids: run.resources.hostUuids,
    edgeIds: [...new Set([...kept, ...run.resources.edgeIds, ...(extra.edgeIds ?? [])])],
  };
  await ctx.db.patch(run._id, {
    state: 'committed',
    stage: 'done',
    resources: committed,
    events: [...run.events, { at, code: 'committed' }],
    updatedAt: at,
  });
  await ctx.db.patch(intent._id, {
    approved: {
      machineRevision: cand.machineRevision,
      configRevision: cand.configRevision,
      authRevision: cand.authRevision,
      deliveryRevision: cand.deliveryRevision,
      reviewHash: cand.reviewHash,
      approvedAt: cand.approval?.at ?? at,
      byAdminId: cand.approval?.byAdminId,
      committed,
    },
    delivery: {
      ...intent.delivery,
      disposition: 'live',
      acceptingAssignments: true,
      lastLiveAt: at,
      exposure: { ...intent.delivery.exposure, everLive: true, hosts: committed.hostUuids },
    },
    activation: { ...intent.activation, stage: 'live', currentRunId: undefined },
    state: 'ready',
    code: undefined,
    updatedAt: at,
  });
  await bumpGateVersion(ctx, intent.backendServerId);
  await scheduleMirrorRefresh(ctx);
  const server = await ctx.db.get(intent.backendServerId);
  await writeAuditLog(ctx, {
    actorType: 'system',
    action: 'servers.node.live',
    targetType: 'panel_node_intent',
    targetId: intent._id,
    payload: { backendSlug: server?.slug ?? '', name: intent.name, mode: modeSlug(intent) },
  });
  return { ok: true };
}

export const commit = internalMutation({
  args: { runId: v.id('panelActivationRuns'), stepVersion: v.number() },
  handler: async (ctx, { runId, stepVersion }) => {
    const run = await ctx.db.get(runId);
    if (!run || run.stepVersion !== stepVersion) return { ok: false as const, code: 'stale' };
    const r = await promoteCandidate(ctx, run);
    if (!r.ok) await blockActivation(ctx, run, r.code);
    return r;
  },
});

/**
 * Block a running activation and park the node where it can be approved
 * again (`awaiting_approval`; a live node keeps its committed delivery). The
 * run keeps its record and its candidates stay isolated; the next approval
 * supersedes it. A run that is no longer running is left as it is.
 */
export async function blockActivation(ctx: MutationCtx, run: Run, code: string): Promise<void> {
  const fresh = await ctx.db.get(run._id);
  if (!fresh || fresh.state !== 'running') return;
  const now = Date.now();
  await ctx.db.patch(run._id, {
    state: 'blocked',
    code,
    stepVersion: fresh.stepVersion + 1,
    events: [...fresh.events, { at: now, code }],
    updatedAt: now,
  });
  await parkAfterBlock(ctx, fresh);
}

/** The activating run of an enrolled node, for Autopilot's publish and go-live (null = none). */
export async function activatingRunFor(
  ctx: { db: QueryCtx['db'] },
  backendServerId: Id<'backendServers'>,
  nodeName: string,
): Promise<{ intent: Intent; run: Run | null } | null> {
  const intent = await ctx.db
    .query('panelNodeIntents')
    .withIndex('by_server_name', (q) =>
      q.eq('backendServerId', backendServerId).eq('name', nodeName),
    )
    .unique();
  if (!intent) return null;
  const run = intent.activation.currentRunId
    ? await ctx.db.get(intent.activation.currentRunId)
    : null;
  return { intent, run: run && run.state === 'running' ? run : null };
}

/** Record an edge an activating run published as one of its candidate resources. */
export async function recordCandidateEdge(ctx: MutationCtx, run: Run, edgeId: Id<'edges'>) {
  const fresh = (await ctx.db.get(run._id)) ?? run;
  if (fresh.resources.edgeIds.includes(edgeId)) return;
  await ctx.db.patch(run._id, {
    resources: { ...fresh.resources, edgeIds: [...fresh.resources.edgeIds, edgeId] },
    updatedAt: Date.now(),
  });
}

/** The review a node's committed delivery was approved under (null: none on record, e.g. adopted). */
async function committedReviewOf(
  ctx: { db: QueryCtx['db'] },
  intent: Intent,
): Promise<ReviewShape | null> {
  if (!intent.approved) return null;
  const runs = (
    await ctx.db
      .query('panelActivationRuns')
      .withIndex('by_intent', (q) => q.eq('intentId', intent._id))
      .collect()
  )
    .filter(
      (r) => r.state === 'committed' && r.candidate.reviewHash === intent.approved!.reviewHash,
    )
    .sort((a, b) => b.updatedAt - a.updatedAt);
  if (!runs[0]) return null;
  try {
    return JSON.parse(runs[0].candidate.review) as ReviewShape;
  } catch {
    return null;
  }
}

export type PublicationAdmission =
  | { kind: 'unmanaged' }
  | { kind: 'committed' }
  | { kind: 'candidate'; run: Run }
  | { kind: 'refused'; code: string };

/**
 * The approval one edge publication needs (docs/servers.md "Node lifecycle"),
 * compared with the publication itself: `unmanaged` for a node FCP does not
 * manage; `candidate` when the node's one running activation approved this
 * shape (listener, account, template) and the node's gate keeps it from
 * members until the commit; `committed` when the node is live with no
 * activation running, nothing moved since the commit (revisions: machine,
 * ingress, transport, auth) and the publication fits the committed review: a
 * replacement address within the approved shape reuses that approval. Any
 * other account, template, listener or revision needs a new review:
 * `refused`. The publish pre-check of a setup run and the rotation start gate
 * both call this.
 */
export async function publicationAdmission(
  ctx: { db: QueryCtx['db'] },
  backendServerId: Id<'backendServers'>,
  nodeName: string,
  pub: PublicationShape,
): Promise<PublicationAdmission> {
  const intent = await ctx.db
    .query('panelNodeIntents')
    .withIndex('by_server_name', (q) =>
      q.eq('backendServerId', backendServerId).eq('name', nodeName),
    )
    .unique();
  if (!intent) return { kind: 'unmanaged' };
  if (intent.maintenance) return { kind: 'refused', code: 'servers.maintenance_open' };
  if (intent.state === 'retiring' || intent.state === 'retired')
    return { kind: 'refused', code: 'servers.node_retiring' };
  const disposition = intent.delivery.disposition;
  const run = intent.activation.currentRunId
    ? await ctx.db.get(intent.activation.currentRunId)
    : null;
  if (run && run.state === 'running') {
    const admitted = publicationAdmitted({
      disposition,
      underMaintenance: false,
      matchesCommitted: false,
      matchesApprovedCandidate: true,
    });
    if (admitted !== 'candidate') return { kind: 'refused', code: 'servers.node_not_approved' };
    let approved: ReviewShape | null = null;
    try {
      approved = JSON.parse(run.candidate.review) as ReviewShape;
    } catch {
      approved = null;
    }
    if (!publicationFits(approved, pub)) return { kind: 'refused', code: 'servers.review_stale' };
    // On a LIVE node a candidate must not need a new Host or Host pointer.
    if (disposition === 'live' && (await isolationBreaks(ctx, intent, pub.listenerKey)))
      return { kind: 'refused', code: 'servers.maintenance_required' };
    return { kind: 'candidate', run };
  }
  if (
    publicationAdmitted({
      disposition,
      underMaintenance: false,
      matchesCommitted: true,
      matchesApprovedCandidate: false,
    }) !== 'committed' ||
    !intent.approved
  )
    return { kind: 'refused', code: 'servers.node_not_approved' };
  const a = intent.approved;
  const now = revisionsOf(intent);
  if (
    now.machineRevision !== a.machineRevision ||
    now.configRevision !== a.configRevision ||
    (now.authRevision ?? null) !== (a.authRevision ?? null) ||
    now.deliveryRevision !== a.deliveryRevision
  )
    return { kind: 'refused', code: 'servers.node_not_approved' };
  // The committed approval's shape; a review stored before the per-listener
  // shape (or an adopted node's, which has none) is read as the shape members
  // are served through now: each listener's template edge.
  const committedShape = await committedReviewOf(ctx, intent);
  const shape = committedShape?.listeners
    ? committedShape
    : { listeners: await servedListenersOf(ctx, intent) };
  if (!publicationFits(shape, pub)) return { kind: 'refused', code: 'servers.node_not_approved' };
  return { kind: 'committed' };
}

/** Each listener of a fronted node with the account and template of its template edge (what is served). */
async function servedListenersOf(
  ctx: { db: QueryCtx['db'] },
  intent: Intent,
): Promise<ReviewListener[]> {
  const out: ReviewListener[] = [];
  for (const l of await frontedListenersOf(ctx, intent)) {
    const e = l.templateEdgeId ? await ctx.db.get(l.templateEdgeId) : null;
    out.push({
      listenerKey: l.listenerKey,
      accountId: e?.accountId ? String(e.accountId) : null,
      templateHash: e?.templateHash ?? null,
    });
  }
  return out;
}

/** Whether publishing on this listener of a live node would add or move a committed Host pointer. */
async function isolationBreaks(
  ctx: { db: QueryCtx['db'] },
  intent: Intent,
  listenerKey: string,
): Promise<boolean> {
  const gate = await nodeGateFor(ctx, intent.backendServerId, intent.name);
  const l = (await frontedListenersOf(ctx, intent)).find((x) => x.listenerKey === listenerKey);
  return pointerMoves(gate, l?.templateEdgeId ?? null);
}

/**
 * The activation candidate an origin's rehearsal renders for (the setup
 * vector carries it): the node's running activation run and the revisions it
 * approved; null for an origin that is not an enrolled node with one.
 */
export async function activationVectorFor(
  ctx: { db: QueryCtx['db'] },
  relay: Doc<'relays'>,
): Promise<VectorActivation | null> {
  if (relay.origin.kind !== 'panel-node' || !relay.backendServerId) return null;
  const act = await activatingRunFor(ctx, relay.backendServerId, relay.origin.nodeName);
  if (!act?.run) return null;
  const c = act.run.candidate;
  return {
    runId: act.run._id as string,
    machineRevision: c.machineRevision,
    configRevision: c.configRevision,
    authRevision: c.authRevision ?? null,
    deliveryRevision: c.deliveryRevision,
  };
}

export { transportFor };
