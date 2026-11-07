/**
 * A node serving an EXTRA mode beside its own (docs/servers.md "A node serving
 * an extra mode"): today a Hysteria 2 transport (QUIC, UDP 443) on a direct
 * REALITY node (TCP 443). Each extra mode has its own staged lifecycle,
 * evidence and address, so nothing about it ever closes the node's own mode:
 *
 *   waiting_firewall  An admin asked for it. The (port, protocol) is listed for
 *                     the node's firewall (`firewall.ports`, `pending`), and
 *                     nothing else happens until the node role's applied
 *                     report names exactly that (port, protocol), or, for a
 *                     node no role runs (adopted), an admin confirms it. A role
 *                     that predates protocols never confirms UDP.
 *   activating        The node reconcile turns the transport on for the node
 *                     (its active set = its own transport + the extra ones).
 *                     This run writes the node's address for it, DISABLED, with
 *                     the certificate pin and the per-client rewrites that make
 *                     every format verify by pin (lib/backend/hostMapper.ts),
 *                     then enables it and rehearses: the backend's bodies for
 *                     the mode's own test credential must carry the address,
 *                     pinned, in every format (lib/hysteriaPins.ts), and, where
 *                     the check service is configured, a real sing-box client
 *                     must connect through it with the stored public-key pin.
 *                     A failure turns the address off again.
 *   serving           The address is on, bound to `evidence.revision`
 *                     (lib/backend/extraModes.ts `extraRevision`): a new
 *                     certificate, server name, Salamander or Salamander
 *                     password, port, address or Host field closes ONLY this
 *                     mode (address off, back to activating) until a new
 *                     rehearsal passes.
 *   removing          Address off, then deleted, then the transport is dropped
 *                     from the node.
 *
 * The extra mode's group holds only its own transport; members reach the
 * node's own transport through a second group (convex/lib/placement.ts).
 */
import { ConvexError, v } from 'convex/values';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import {
  internalAction,
  internalMutation,
  internalQuery,
  type ActionCtx,
  type MutationCtx,
  type QueryCtx,
} from './_generated/server';
import { writeAuditLog } from './lib/audit';
import { randomHex } from './lib/crypto';
import { capabilitiesOf } from './lib/backends/capabilities';
import { resolveServerConfig } from './lib/serverConfig';
import { modeOf, setupReady, type Setup, type SetupMode } from './backendSetup';
import { originAddressOf, originHostnameOf } from './nodeIntents';
import { observeInstance } from './backendObserve';
import { inboundPortProtocol } from './lib/edges/inboundMapping';
import {
  desiredExtraHost,
  extraHostDiff,
  extraModeProblem,
  extraRevision,
  type ExtraModeState,
} from './lib/backend/extraModes';
import { REHEARSAL_USER_AGENTS, type RehearsalFamily } from './lib/backend/rehearsal';
import { hysteriaEndpointVerified, scanHysteria } from './lib/hysteriaPins';
import { decodeLinkList } from './lib/edges/render/links';
import { ownsAddress } from './lib/backend/hostRemark';
import { clientCheckService, runEngineCheck } from './lib/edges/clientCheck/client';
import { outboundsForLink } from './lib/edges/clientCheck/outbound';
import { QUALIFICATION_TRAFFIC_LIMIT_BYTES } from './relayQualification';
import { TEST_CREDENTIAL_TAG, testCredentialUsername } from './edgeTestCredentials';

type Intent = Doc<'panelNodeIntents'>;
type ExtraMode = NonNullable<Intent['extraModes']>[number];

const refuse = (code: string, message: string): never => {
  throw new ConvexError({ code, message });
};

/** One run of one mode at a time; a run that died is taken over once this runs out. */
const LEASE_MS = 5 * 60_000;

const WORDS: Record<string, string> = {
  'servers.mode_unknown': 'This backend is not set up for that mode yet',
  'servers.extra_mode_present': 'The node already serves that mode',
  'servers.extra_mode_unsupported':
    'Only a direct Hysteria 2 transport can be served beside a node’s own mode',
  'servers.extra_mode_node_not_direct': 'Only a node members reach at its own address can serve it',
  'servers.extra_mode_fallback_missing':
    'That mode’s backup is another mode than the one this node serves',
  'servers.extra_mode_certificate':
    'FCP cannot read that transport’s certificate on the profile. Refresh, then try again',
  'servers.port_taken': 'The node already listens on that port for the same protocol',
  'servers.extra_mode_name_collision':
    'The Hysteria server name is one of the node’s REALITY names. Give it its own name',
  'servers.unsupported_transport': 'This backend type cannot serve a UDP transport',
};

// --- reads -----------------------------------------------------------------------------------------

async function readySetupOf(ctx: { db: QueryCtx['db'] }, sid: Id<'backendServers'>) {
  const row = await ctx.db
    .query('panelSetups')
    .withIndex('by_server', (q) => q.eq('backendServerId', sid))
    .unique();
  return setupReady(row) ? row : null;
}

async function profileInboundsOf(ctx: { db: QueryCtx['db'] }, setup: Setup) {
  if (!setup.profileUuid) return [];
  const profile = await ctx.db
    .query('panelProfiles')
    .withIndex('by_server_uuid', (q) =>
      q.eq('backendServerId', setup.backendServerId).eq('profileUuid', setup.profileUuid!),
    )
    .unique();
  return profile?.inbounds ?? [];
}

/** Why `slug` may not be served by this node beside its own mode, or null. */
async function problemOf(
  ctx: { db: QueryCtx['db'] },
  intent: Intent,
  setup: Setup,
  slug: string,
): Promise<string | null> {
  const primary = modeOf(setup, intent.mode);
  if (!primary?.transport) return 'servers.mode_unknown';
  const extra = modeOf(setup, slug);
  const inbounds = await profileInboundsOf(ctx, setup);
  const pIn = inbounds.find((i) => i.inboundUuid === primary.transport!.uuid);
  const xIn = extra?.transport
    ? inbounds.find((i) => i.inboundUuid === extra.transport!.uuid)
    : null;
  const opening = (i: typeof pIn) =>
    i && i.port !== null ? { port: i.port, protocol: inboundPortProtocol(i) } : null;
  const mode = await ctx.db
    .query('connectionModes')
    .withIndex('by_slug', (q) => q.eq('slug', slug))
    .unique();
  return extraModeProblem({
    primary,
    extra,
    served: (intent.extraModes ?? []).map((m) => m.slug),
    otherOpenings: (intent.extraModes ?? []).map((m) => m.firewall),
    primaryOpening: opening(pIn),
    extraOpening: xIn?.hysteriaAuth?.pinHex ? opening(xIn) : null,
    primaryNames: pIn?.reality?.serverNames ?? primary.transport.serverNames ?? [],
    extraName: xIn?.hysteriaAuth?.serverName ?? null,
    fallbackModeSlug:
      (mode as (Doc<'connectionModes'> & { fallbackModeSlug?: string }) | null)?.fallbackModeSlug ??
      null,
  });
}

async function server(ctx: { db: QueryCtx['db'] }, intent: Intent) {
  const s = await ctx.db.get(intent.backendServerId);
  if (!s) return refuse('not_found', 'Backend server not found');
  return s;
}

function entryOf(intent: Intent, slug: string): ExtraMode {
  const e = (intent.extraModes ?? []).find((m) => m.slug === slug);
  if (!e) return refuse('not_found', 'The node does not serve that mode');
  return e;
}

async function patchEntry(
  ctx: MutationCtx,
  intent: Intent,
  slug: string,
  next: ExtraMode | null,
): Promise<void> {
  const rest = (intent.extraModes ?? []).filter((m) => m.slug !== slug);
  const list = next ? (intent.extraModes ?? []).map((m) => (m.slug === slug ? next : m)) : rest;
  await ctx.db.patch(intent._id, {
    extraModes: list.length > 0 ? list : undefined,
    updatedAt: Date.now(),
  });
}

async function audit(
  ctx: MutationCtx,
  intent: Intent,
  action: string,
  payload: Record<string, unknown>,
  actorAdminId?: Id<'adminUsers'>,
) {
  const s = await ctx.db.get(intent.backendServerId);
  await writeAuditLog(ctx, {
    actorType: actorAdminId ? 'admin' : 'system',
    actorId: actorAdminId ?? undefined,
    action,
    targetType: 'panel_node_intent',
    targetId: intent._id,
    payload: { backendSlug: s?.slug ?? '', name: intent.name, ...payload },
  });
}

/** Ask the node reconcile (the active transport set) and this mode's run to look again. */
async function kickBoth(ctx: MutationCtx, intentId: Id<'panelNodeIntents'>) {
  await ctx.scheduler.runAfter(0, internal.nodeIntents.reconcileNow, { intentId });
}

// --- admin -----------------------------------------------------------------------------------------

/** Ask a node to serve `slug` beside its own mode. Staged: nothing is sent until its firewall is confirmed. */
export const add = internalMutation({
  args: {
    intentId: v.id('panelNodeIntents'),
    slug: v.string(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const intent = await ctx.db.get(a.intentId);
    if (!intent) return refuse('not_found', 'No such node');
    if (intent.state === 'retiring' || intent.state === 'retired')
      refuse('servers.node_retiring', 'This node is being retired');
    if (!(await resolveServerConfig(ctx.db)).manage.enabled)
      refuse('servers.manage_disabled', 'Server changes are switched off in Servers settings');
    const s = await server(ctx, intent);
    if (!capabilitiesOf(s.backend).udpTransports)
      refuse('servers.unsupported_transport', WORDS['servers.unsupported_transport']!);
    const setup = await readySetupOf(ctx, intent.backendServerId);
    if (!setup) return refuse('servers.panel_not_set_up', 'The backend is not set up');
    const problem = await problemOf(ctx, intent, setup, a.slug);
    if (problem) refuse(problem, WORDS[problem] ?? problem);
    const extra = modeOf(setup, a.slug)!;
    const inbound = (await profileInboundsOf(ctx, setup)).find(
      (i) => i.inboundUuid === extra.transport!.uuid,
    )!;
    const now = Date.now();
    const entry: ExtraMode = {
      slug: a.slug,
      state: 'waiting_firewall',
      firewall: {
        port: inbound.port!,
        protocol: inboundPortProtocol(inbound),
        // No role runs an adopted machine: an admin confirms its firewall.
        confirmedBy: intent.adopted ? 'operator' : 'role',
      },
      byAdminId: a.actorAdminId,
      since: now,
      updatedAt: now,
    };
    await ctx.db.patch(intent._id, {
      extraModes: [...(intent.extraModes ?? []), entry],
      updatedAt: now,
    });
    await audit(
      ctx,
      intent,
      'admin.servers.extra_mode.add',
      { mode: a.slug, port: entry.firewall.port, protocol: entry.firewall.protocol },
      a.actorAdminId,
    );
    return { state: entry.state };
  },
});

/** An admin confirms the firewall of a node no role runs (adopted) lets the extra mode's port in. */
export const acknowledgeFirewall = internalMutation({
  args: {
    intentId: v.id('panelNodeIntents'),
    slug: v.string(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const intent = await ctx.db.get(a.intentId);
    if (!intent) return refuse('not_found', 'No such node');
    const e = entryOf(intent, a.slug);
    if (e.state !== 'waiting_firewall') return { state: e.state };
    if (e.firewall.confirmedBy === 'role')
      refuse(
        'servers.firewall_role_confirms',
        'The node role confirms this node itself, when it has opened the port',
      );
    const now = Date.now();
    await patchEntry(ctx, intent, a.slug, {
      ...e,
      state: 'activating',
      code: undefined,
      firewall: { ...e.firewall, confirmedAt: now },
      updatedAt: now,
    });
    await audit(
      ctx,
      intent,
      'servers.node.extra_mode_firewall',
      { mode: a.slug, by: 'operator', port: e.firewall.port, protocol: e.firewall.protocol },
      a.actorAdminId,
    );
    await kickBoth(ctx, intent._id);
    return { state: 'activating' as const };
  },
});

/** Stop serving `slug`: address off and removed, then the transport. Nothing to undo while it waits. */
export const remove = internalMutation({
  args: {
    intentId: v.id('panelNodeIntents'),
    slug: v.string(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const intent = await ctx.db.get(a.intentId);
    if (!intent) return refuse('not_found', 'No such node');
    const e = entryOf(intent, a.slug);
    const now = Date.now();
    if (e.state === 'waiting_firewall' && !e.hostUuid) await patchEntry(ctx, intent, a.slug, null);
    else
      await patchEntry(ctx, intent, a.slug, {
        ...e,
        state: 'removing',
        code: undefined,
        // A run holding the mode now may end on what it read before: it runs
        // again when it releases, so the removal is never left waiting.
        rerun: e.lease && e.lease.expiresAt > now ? true : e.rerun,
        updatedAt: now,
      });
    await audit(ctx, intent, 'admin.servers.extra_mode.remove', { mode: a.slug }, a.actorAdminId);
    if (e.state !== 'waiting_firewall' || e.hostUuid)
      await ctx.scheduler.runAfter(0, internal.nodeExtraModes.run, { intentId: intent._id });
    return { state: e.state === 'waiting_firewall' ? null : ('removing' as const) };
  },
});

/** After a node reconcile: run every extra mode that has work. */
export const kick = internalMutation({
  args: { intentId: v.id('panelNodeIntents') },
  handler: async (ctx, { intentId }) => {
    const intent = await ctx.db.get(intentId);
    if (!intent) return false;
    const now = Date.now();
    const active = (intent.extraModes ?? []).filter((m) => m.state !== 'waiting_firewall');
    const due = active.some((m) => !(m.lease && m.lease.expiresAt > now));
    // A mode a run holds now looks again when that run ends: what this kick
    // reports (a transport just turned on) may be after the run's look.
    const busy = active.filter((m) => m.lease && m.lease.expiresAt > now && !m.rerun);
    if (busy.length > 0)
      await ctx.db.patch(intent._id, {
        extraModes: intent.extraModes!.map((m) =>
          busy.some((b) => b.slug === m.slug) ? { ...m, rerun: true } : m,
        ),
      });
    if (due) await ctx.scheduler.runAfter(0, internal.nodeExtraModes.run, { intentId });
    return due;
  },
});

// --- the run ---------------------------------------------------------------------------------------

export const claim = internalMutation({
  args: { intentId: v.id('panelNodeIntents'), slug: v.string() },
  handler: async (ctx, { intentId, slug }) => {
    const intent = await ctx.db.get(intentId);
    const e = intent?.extraModes?.find((m) => m.slug === slug);
    const now = Date.now();
    if (!intent || !e || e.state === 'waiting_firewall') return null;
    if (e.lease && e.lease.expiresAt > now) return null;
    const attemptId = crypto.randomUUID();
    await patchEntry(ctx, intent, slug, {
      ...e,
      lease: { attemptId, expiresAt: now + LEASE_MS },
    });
    return attemptId;
  },
});

/** The longest a failed run waits before the next try (backoff doubles up to it). */
const RETRY_MAX_MS = 60 * 60_000;

const recordPatch = v.object({
  state: v.optional(
    v.union(
      v.literal('waiting_firewall'),
      v.literal('activating'),
      v.literal('serving'),
      v.literal('removing'),
    ),
  ),
  // The opening the node's firewall must let in now (the transport moved).
  firewall: v.optional(
    v.object({
      port: v.number(),
      protocol: v.union(v.literal('tcp'), v.literal('udp')),
      confirmedBy: v.union(v.literal('role'), v.literal('operator')),
    }),
  ),
  // The run failed: try again after a backoff (no role report or reconcile
  // may ever come for an adopted node).
  retry: v.optional(v.boolean()),
  code: v.optional(v.union(v.string(), v.null())),
  hostUuid: v.optional(v.union(v.string(), v.null())),
  evidence: v.optional(
    v.union(
      v.object({
        revision: v.string(),
        at: v.number(),
        checked: v.union(v.literal('client'), v.literal('rehearsal')),
      }),
      v.null(),
    ),
  ),
  drop: v.optional(v.boolean()),
  release: v.optional(v.boolean()),
});

/** What a run learned, recorded only while it still holds the mode's lease. */
export const record = internalMutation({
  args: {
    intentId: v.id('panelNodeIntents'),
    slug: v.string(),
    attemptId: v.string(),
    patch: recordPatch,
    audit: v.optional(v.object({ action: v.string(), detail: v.optional(v.string()) })),
  },
  handler: async (ctx, a) => {
    const intent = await ctx.db.get(a.intentId);
    const e = intent?.extraModes?.find((m) => m.slug === a.slug);
    if (!intent || !e || e.lease?.attemptId !== a.attemptId) return { ok: false };
    // An admin's removal while the run worked wins over the run's own state.
    const state: ExtraModeState = e.state === 'removing' ? 'removing' : (a.patch.state ?? e.state);
    if (a.patch.drop) {
      await patchEntry(ctx, intent, a.slug, null);
    } else {
      const p = a.patch;
      const retries = p.retry ? (e.retries ?? 0) + 1 : state === 'serving' ? undefined : e.retries;
      // A write still settling or a look that lags clears in seconds; anything
      // else (a refused rehearsal, the node offline) is tried a minute on.
      const settling = p.code === 'servers.op_running' || p.code === 'servers.observe_lag';
      if (p.retry && retries)
        await ctx.scheduler.runAfter(
          Math.min(RETRY_MAX_MS, (settling ? 5_000 : 60_000) * 2 ** Math.min(retries - 1, 10)),
          internal.nodeExtraModes.run,
          { intentId: intent._id },
        );
      await patchEntry(ctx, intent, a.slug, {
        ...e,
        state,
        ...(p.firewall ? { firewall: { ...p.firewall } } : {}),
        retries,
        code: p.code === undefined ? e.code : (p.code ?? undefined),
        hostUuid: p.hostUuid === undefined ? e.hostUuid : (p.hostUuid ?? undefined),
        evidence: p.evidence === undefined ? e.evidence : (p.evidence ?? undefined),
        lease: p.release ? undefined : e.lease,
        rerun: p.release ? undefined : e.rerun,
        updatedAt: Date.now(),
      });
      if (p.release && e.rerun)
        await ctx.scheduler.runAfter(0, internal.nodeExtraModes.run, { intentId: intent._id });
    }
    if (a.audit)
      await audit(ctx, intent, a.audit.action, {
        mode: a.slug,
        ...(a.audit.detail ? { code: a.audit.detail } : {}),
      });
    // The transport follows the state: on for activating/serving, off once removed.
    if (a.patch.drop || (a.patch.state && a.patch.state !== e.state))
      await ctx.scheduler.runAfter(0, internal.nodeIntents.reconcileNow, { intentId: intent._id });
    return { ok: true };
  },
});

/** Everything one run reads. */
export const context = internalQuery({
  args: { intentId: v.id('panelNodeIntents') },
  handler: async (ctx, { intentId }) => {
    const intent = await ctx.db.get(intentId);
    if (!intent || !intent.extraModes?.length) return null;
    // A retiring node's addresses, the extra ones included, are the retirement's.
    if (intent.state === 'retiring' || intent.state === 'retired') return null;
    const s = await ctx.db.get(intent.backendServerId);
    const setup = await readySetupOf(ctx, intent.backendServerId);
    if (!s || !setup) return null;
    const node = intent.nodeUuid
      ? await ctx.db
          .query('panelNodes')
          .withIndex('by_server_uuid', (q) =>
            q.eq('backendServerId', intent.backendServerId).eq('nodeUuid', intent.nodeUuid!),
          )
          .unique()
      : null;
    const hosts = await ctx.db
      .query('panelHosts')
      .withIndex('by_server', (q) => q.eq('backendServerId', intent.backendServerId))
      .collect();
    const creds = await ctx.db
      .query('edgeTestCredentials')
      .withIndex('by_intent', (q) => q.eq('nodeIntentId', intentId))
      .collect();
    const now = Date.now();
    return {
      intent,
      server: { _id: s._id, backend: s.backend, config: s.config, slug: s.slug },
      modes: Object.fromEntries(
        intent.extraModes.map((m) => [m.slug, modeOf(setup, m.slug) ?? null]),
      ) as Record<string, SetupMode | null>,
      node,
      inbounds: await profileInboundsOf(ctx, setup),
      hosts,
      originAddress: originAddressOf(intent, originHostnameOf(intent, setup)),
      credentials: Object.fromEntries(
        intent.extraModes.map((m) => {
          const own = creds.filter((r) => r.modeSlug === m.slug && r.removal === 'pending');
          const reusable = own.find(
            (r) =>
              r.expiresAt > now + 60_000 &&
              !!r.backendUserId &&
              !!r.backendShortId &&
              !!r.subscriptionUrl,
          );
          const unresolved = own.find((r) => !r.backendUserId);
          return [
            m.slug,
            {
              reusable: reusable
                ? {
                    backendShortId: reusable.backendShortId!,
                    subscriptionUrl: reusable.subscriptionUrl!,
                  }
                : null,
              unresolved: unresolved ? { id: unresolved._id, username: unresolved.username } : null,
            },
          ];
        }),
      ),
    };
  },
});
type RunContext = NonNullable<Awaited<ReturnType<typeof loadContext>>>;
async function loadContext(ctx: ActionCtx, intentId: Id<'panelNodeIntents'>) {
  return ctx.runQuery(internal.nodeExtraModes.context, { intentId });
}

class Stop extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

function codeOf(err: unknown, fallback: string): string {
  if (err instanceof Stop) return err.code;
  return err instanceof ConvexError && typeof (err.data as { code?: unknown })?.code === 'string'
    ? (err.data as { code: string }).code
    : fallback;
}

/** One backend write through the ledger, sent and looked at; never two at once. */
async function write(ctx: ActionCtx, make: () => Promise<{ opId: Id<'panelOps'> }>): Promise<void> {
  const { opId } = await make();
  const r = await ctx.runAction(internal.backendWrites.run, { opId });
  if (r.open) throw new Stop('servers.op_running');
}

/** The mode's own test credential: in the extra mode's group, never the node's own. */
async function credentialFor(
  ctx: ActionCtx,
  c: RunContext,
  slug: string,
  groupUuid: string,
): Promise<{ backendShortId: string; subscriptionUrl: string }> {
  const have = c.credentials[slug];
  if (have?.reusable) return have.reusable;
  if (have?.unresolved) {
    const found = await ctx.runAction(internal.backends.findUserByUsername, {
      backendServerId: c.server._id,
      username: have.unresolved.username,
    });
    if (found) {
      await ctx.runMutation(internal.edgeTestCredentials.markIssued, {
        id: have.unresolved.id,
        backendUserId: found.backendUserId,
        backendShortId: found.backendShortId,
        subscriptionUrl: found.subscriptionUrl,
      });
      return { backendShortId: found.backendShortId, subscriptionUrl: found.subscriptionUrl };
    }
    await ctx.runMutation(internal.edgeTestCredentials.dropUnissued, { id: have.unresolved.id });
  }
  const username = testCredentialUsername(c.intent.name, 'test_link', randomHex(4));
  const id = await ctx.runMutation(internal.edgeTestCredentials.insertPending, {
    nodeIntentId: c.intent._id,
    backendServerId: c.server._id,
    username,
    purpose: 'test_link',
    modeSlug: slug,
  });
  let issued;
  try {
    issued = await ctx.runAction(internal.backends.issueUser, {
      backend: c.server.backend,
      pinServerId: c.server._id,
      ownCheck: true,
      spec: {
        username,
        trafficLimitBytes: QUALIFICATION_TRAFFIC_LIMIT_BYTES,
        expireAt: null,
        tag: TEST_CREDENTIAL_TAG,
        description: 'FCP node extra-mode check (automated, temporary)',
        placement: groupUuid,
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
  return { backendShortId: issued.backendShortId, subscriptionUrl: issued.subscriptionUrl };
}

const FAMILIES: RehearsalFamily[] = ['links', 'singbox', 'clash'];

/**
 * The rehearsal of one address: every family's body for the mode's own
 * credential carries it, pinned; and, where the check service runs, a real
 * sing-box client connects through it with the stored public-key pin.
 */
async function rehearse(
  ctx: ActionCtx,
  c: RunContext,
  cred: { backendShortId: string; subscriptionUrl: string },
  e: { address: string; port: number; sni: string },
  pins: { pinHex: string; spkiB64: string },
): Promise<{ ok: true; checked: 'client' | 'rehearsal' } | { ok: false; detail: string }> {
  const expected = { pinHex: [pins.pinHex], spkiB64: [pins.spkiB64] };
  const failed: string[] = [];
  let linksBody = '';
  for (const family of FAMILIES) {
    const fetched = await ctx.runAction(internal.backends.fetchSubscriptionContent, {
      backend: c.server.backend,
      backendServerId: c.server._id,
      backendShortId: cred.backendShortId,
      subscriptionUrl: cred.subscriptionUrl,
      userAgent: REHEARSAL_USER_AGENTS[family],
      unpinned: true,
    });
    if (family === 'links') linksBody = fetched.content;
    const verdict = hysteriaEndpointVerified(fetched.content, expected, e);
    if (!verdict.found) failed.push(`${family}:${verdict.trust ?? 'absent'}`);
  }
  if (failed.length > 0) return { ok: false, detail: failed.join(',') };
  const svc = clientCheckService(process.env);
  if (!svc) return { ok: true, checked: 'rehearsal' };
  // The entry of THIS address (every node of the group shares the certificate
  // and the port): a check through another node proves nothing about this one.
  const scan = scanHysteria(linksBody, expected);
  const bare = (a: string) =>
    a
      .trim()
      .toLowerCase()
      .replace(/^\[|\]$/g, '');
  const entry = scan.entries.find(
    (x) =>
      x.trust === 'pinned' &&
      x.port === e.port &&
      bare(x.address) === bare(e.address) &&
      bare(x.sni ?? '') === bare(e.sni),
  );
  const line = entry ? decodeLinkList(linksBody)?.lines[Number(entry.ref)] : undefined;
  const outbound = line
    ? outboundsForLink(line, { hysteriaSpkiB64: [pins.spkiB64] })?.outbounds['sing-box']
    : undefined;
  if (!outbound) return { ok: false, detail: 'client:no_outbound' };
  const r = await runEngineCheck(svc, { engine: 'sing-box', outbound, reality: false });
  if (!r.ok) return { ok: false, detail: `client:${r.code}` };
  if (!r.value.ok) return { ok: false, detail: `client:${r.value.code}` };
  return { ok: true, checked: 'client' };
}

async function step(
  ctx: ActionCtx,
  intentId: Id<'panelNodeIntents'>,
  slug: string,
  attemptId: string,
) {
  const rec = (
    patch: {
      state?: 'waiting_firewall' | 'activating' | 'serving' | 'removing';
      code?: string | null;
      hostUuid?: string | null;
      evidence?: { revision: string; at: number; checked: 'client' | 'rehearsal' } | null;
      firewall?: {
        port: number;
        protocol: 'tcp' | 'udp';
        confirmedBy: 'role' | 'operator';
      };
      retry?: boolean;
      drop?: boolean;
    },
    auditAction?: { action: string; detail?: string },
  ) =>
    ctx.runMutation(internal.nodeExtraModes.record, {
      intentId,
      slug,
      attemptId,
      patch,
      ...(auditAction ? { audit: auditAction } : {}),
    });
  let c = await loadContext(ctx, intentId);
  if (!c) return;
  const reload = async () => {
    await observeInstance(ctx, c!.server);
    c = (await loadContext(ctx, intentId))!;
    if (!c) throw new Stop('not_found');
  };
  // A fresh look first: the node reconcile that turned the transport on may
  // have parked before it read the backend again (a node write still settling).
  await reload();
  const entry = () => c!.intent.extraModes!.find((m) => m.slug === slug)!;
  const hostOf = () => {
    const uuid = entry().hostUuid;
    return uuid ? (c!.hosts.find((h) => h.hostUuid === uuid) ?? null) : null;
  };
  // The node's own actor: the retirement waits for every open write under it.
  const actorRun = `node:${intentId}`;
  const setDisabled = (hostUuid: string, isDisabled: boolean) =>
    write(ctx, () =>
      ctx.runMutation(internal.backendWrites.requestAddressUpdate, {
        backendServerId: c!.server._id,
        hostUuid,
        isDisabled,
        actorRun,
      }),
    );
  /** Turn an address off and SEE it off: a refused write is never taken for one. */
  const close = async (hostUuid: string) => {
    await setDisabled(hostUuid, true);
    await reload();
    const h = c!.hosts.find((x) => x.hostUuid === hostUuid);
    if (h && !h.isDisabled) throw new Stop('servers.extra_mode_close_failed');
  };
  // The address FCP keeps on the mode's transport: by the uuid recorded, or (a
  // create whose answer was lost) under FCP's remark for this node.
  const transportOf = () => c!.modes[slug]?.transport?.uuid ?? '';
  const ownHost = () =>
    hostOf() ??
    c!.hosts.find(
      (h) => h.configProfileInboundUuid === transportOf() && ownsAddress(c!.intent.name, h.remark),
    ) ??
    null;

  if (entry().state === 'removing') {
    const host = ownHost();
    if (host) {
      if (!host.isDisabled) await close(host.hostUuid);
      await write(ctx, () =>
        ctx.runMutation(internal.backendWrites.requestAddressDelete, {
          backendServerId: c!.server._id,
          hostUuid: host.hostUuid,
          actorRun,
        }),
      );
      await reload();
      if (c.hosts.some((h) => h.hostUuid === host.hostUuid)) throw new Stop('servers.observe_lag');
    }
    await rec({ drop: true }, { action: 'servers.node.extra_mode_removed' });
    return;
  }

  // What the address needs before anything is written. A serving mode that
  // lost one of these (its transport turned off, its certificate unreadable)
  // closes before the run stops.
  const setupMode = c.modes[slug];
  const transportUuid = setupMode?.transport?.uuid ?? '';
  const inbound = c.inbounds.find((i) => i.inboundUuid === transportUuid);
  const auth = inbound?.hysteriaAuth;
  const missing =
    !setupMode?.transport || !setupMode.groupUuid
      ? 'servers.mode_unknown'
      : !c.node || !c.node.activeInboundUuids.includes(transportUuid)
        ? 'servers.extra_mode_transport_off'
        : !inbound ||
            inbound.port === null ||
            !auth?.pinHex ||
            !auth.spkiB64 ||
            !auth.serverName ||
            !auth.digest
          ? 'servers.extra_mode_certificate'
          : null;
  if (missing) {
    const open = hostOf();
    if (entry().state === 'serving') {
      if (open && !open.isDisabled) await close(open.hostUuid);
      await rec(
        { state: 'activating', evidence: null, code: missing },
        { action: 'servers.node.extra_mode_closed', detail: missing },
      );
    }
    throw new Stop(missing);
  }
  if (
    !setupMode?.groupUuid ||
    !inbound ||
    inbound.port === null ||
    !auth?.pinHex ||
    !auth.spkiB64 ||
    !auth.serverName ||
    !auth.digest
  )
    throw new Stop('servers.extra_mode_certificate');
  // The firewall was confirmed for one (port, protocol): a transport that moved
  // since needs the new one let in first. The mode waits for it again, its
  // address off, before anything is turned on there.
  const opening = { port: inbound.port, protocol: inboundPortProtocol(inbound) };
  const confirmed = entry().firewall;
  if (confirmed.port !== opening.port || confirmed.protocol !== opening.protocol) {
    const open = ownHost();
    if (open && !open.isDisabled) await close(open.hostUuid);
    await rec(
      {
        state: 'waiting_firewall',
        evidence: null,
        code: 'servers.extra_mode_port_moved',
        firewall: { ...opening, confirmedBy: confirmed.confirmedBy },
      },
      { action: 'servers.node.extra_mode_closed', detail: 'servers.extra_mode_port_moved' },
    );
    return;
  }
  const want = desiredExtraHost({
    nodeName: c.intent.name,
    originAddress: c.originAddress,
    port: inbound.port,
    auth: { serverName: auth.serverName, pinHex: auth.pinHex, spkiB64: auth.spkiB64 },
  });
  const revision = extraRevision({ transportUuid, authDigest: auth.digest, host: want });

  // The address: found by the uuid recorded for it, or (a create whose answer
  // was lost) under its remark on the transport.
  let host =
    hostOf() ??
    c.hosts.find((h) => h.remark === want.remark && h.configProfileInboundUuid === transportUuid) ??
    null;
  if (host && host.hostUuid !== entry().hostUuid) await rec({ hostUuid: host.hostUuid });
  const serving = entry().state === 'serving';

  // Serving and still what was rehearsed: nothing to do.
  if (serving && host && !host.isDisabled && entry().evidence?.revision === revision) {
    if (entry().code) await rec({ code: null });
    return;
  }
  // Serving, but something it was proven under moved: this mode alone closes.
  if (serving) {
    if (host && !host.isDisabled) await close(host.hostUuid);
    await rec(
      { state: 'activating', evidence: null, code: 'servers.extra_mode_drifted' },
      { action: 'servers.node.extra_mode_closed', detail: 'servers.extra_mode_drifted' },
    );
    await reload();
    host = hostOf();
  }

  if (!host) {
    await write(ctx, () =>
      ctx.runMutation(internal.backendWrites.requestAddressCreate, {
        backendServerId: c!.server._id,
        remark: want.remark,
        address: want.address,
        port: want.port,
        sni: want.sni,
        alpn: want.alpn,
        securityLayer: want.securityLayer,
        pinnedPeerCertSha256: want.pinnedPeerCertSha256,
        mapper: want.mapper,
        isDisabled: true,
        inboundUuid: transportUuid,
        actorRun,
      }),
    );
    await reload();
    host =
      c.hosts.find(
        (h) => h.remark === want.remark && h.configProfileInboundUuid === transportUuid,
      ) ?? null;
    if (!host) throw new Stop('servers.observe_lag');
    await rec({ hostUuid: host.hostUuid });
  } else {
    const diff = extraHostDiff(host, want);
    if (diff) {
      if (!host.isDisabled) await close(host.hostUuid);
      await write(ctx, () =>
        ctx.runMutation(internal.backendWrites.requestAddressUpdate, {
          backendServerId: c!.server._id,
          hostUuid: host!.hostUuid,
          ...diff,
          actorRun,
        }),
      );
      await reload();
      host = hostOf();
      if (!host || extraHostDiff(host, want)) throw new Stop('servers.observe_lag');
    }
  }

  if (!c.node?.online) throw new Stop('servers.node_offline');
  if (host.isDisabled) {
    await setDisabled(host.hostUuid, false);
    await reload();
  }
  const cred = await credentialFor(ctx, c, slug, setupMode.groupUuid);
  const verdict = await rehearse(
    ctx,
    c,
    cred,
    { address: want.address, port: want.port, sni: want.sni },
    { pinHex: auth.pinHex, spkiB64: auth.spkiB64 },
  );
  if (!verdict.ok) {
    // Never left on unproven: the address goes off again, seen off.
    await close(host.hostUuid);
    await rec(
      { code: 'servers.rehearsal_failed', retry: true },
      { action: 'servers.node.extra_mode_rehearsal_failed', detail: verdict.detail.slice(0, 120) },
    );
    return;
  }
  await rec(
    {
      state: 'serving',
      code: null,
      evidence: { revision, at: Date.now(), checked: verdict.checked },
    },
    { action: 'servers.node.extra_mode_serving', detail: verdict.checked },
  );
}

/** Run every extra mode of a node that has work, one at a time, each under its own lease. */
export const run = internalAction({
  args: { intentId: v.id('panelNodeIntents') },
  handler: async (ctx, { intentId }): Promise<null> => {
    const c = await loadContext(ctx, intentId);
    if (!c) return null;
    if (!(await ctx.runQuery(internal.serverAdmin.manageEnabled, {}))) return null;
    for (const m of c.intent.extraModes ?? []) {
      if (m.state === 'waiting_firewall') continue;
      const attemptId = await ctx.runMutation(internal.nodeExtraModes.claim, {
        intentId,
        slug: m.slug,
      });
      if (!attemptId) continue;
      try {
        await step(ctx, intentId, m.slug, attemptId);
      } catch (err) {
        const code = codeOf(err, 'servers.extra_mode_failed');
        await ctx
          .runMutation(internal.nodeExtraModes.record, {
            intentId,
            slug: m.slug,
            attemptId,
            patch: { code, retry: true },
          })
          .catch(() => undefined);
      } finally {
        await ctx
          .runMutation(internal.nodeExtraModes.record, {
            intentId,
            slug: m.slug,
            attemptId,
            patch: { release: true },
          })
          .catch(() => undefined);
      }
    }
    return null;
  },
});
