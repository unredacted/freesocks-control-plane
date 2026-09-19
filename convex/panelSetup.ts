/**
 * "Set up this panel" (docs/servers.md "Setting up a panel"): one durable,
 * fenced workflow per backend server that makes a panel the shape the node
 * purposes rely on. The profile (created from the template, or an existing
 * one adopted only when compatible; keys never touched), its three inbounds,
 * the three squads and their mode placements, the subscription templates,
 * and the handoff that makes FCP the panel's only writer.
 *
 * Every step is idempotent and re-enterable: the row records the step it is
 * on, the sweep resumes an expired lease, and the one external create (the
 * profile) is an obligation persisted before the call. The REALITY keys are
 * generated inside the claimed attempt right before that call and exist
 * nowhere else.
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { capabilitiesOf } from './lib/backends/capabilities';
import { PROVIDERS, type BackendConfig } from './lib/backends/registry';
import { resolveModeCatalog } from './lib/connectionModes';
import { CLAIM_LEASE_MS, claimAvailable, desiredHashOf, fenceHolds } from './lib/panel/fencing';
import { callResultOf, classifyRequest } from './lib/panel/ops';
import { checkProfileCompatibility } from './lib/panel/profileCompat';
import {
  BOOTSTRAP_DEFAULTS,
  buildBootstrapProfile,
  checkBootstrapInput,
  type BootstrapProfileInput,
} from './lib/panel/profileTemplate';
import { generateRealityKey } from './lib/panel/realityKeys';
import {
  SUBSCRIPTION_TEMPLATES,
  TEMPLATE_FAMILIES,
  desiredTemplateBody,
  templateDrift,
  templateHash,
} from './lib/panel/subscriptionTemplates';
import { resolveServerConfig } from './lib/serverConfig';
import { observeInstance } from './panelObserve';

const refuse = (code: string, message: string): never => {
  throw new ConvexError({ code, message });
};

/** The role contract version FCP itself reports when it is the panel's only writer. */
export const FCP_WRITER_CONTRACT_VERSION = 2;

const realityInput = v.object({
  target: v.object({ address: v.string(), port: v.number() }),
  serverNames: v.array(v.string()),
  minClientVer: v.optional(v.string()),
});
export const setupInput = v.object({
  profileName: v.string(),
  cdn: v.object({ path: v.string(), port: v.number() }),
  reality: realityInput,
  relay: v.object({ ...realityInput.fields, acceptProxyProtocol: v.boolean() }),
  squads: v.object({ fronted: v.string(), reality: v.string(), relay: v.string() }),
  originDns: v.union(v.object({ accountId: v.string() }), v.null()),
});
type SetupInput = {
  profileName: string;
  cdn: { path: string; port: number };
  reality: BootstrapProfileInput['reality'];
  relay: BootstrapProfileInput['relay'];
  squads: { fronted: string; reality: string; relay: string };
  originDns: { accountId: string } | null;
};

const fence = {
  setupId: v.id('panelSetups'),
  generation: v.number(),
  attemptId: v.string(),
};
type Fence = { setupId: Id<'panelSetups'>; generation: number; attemptId: string };

const SQUAD_NAME = /^[A-Za-z0-9_-]{2,20}$/;
/** Which squad feeds which connection mode (the role's topology, kept). */
export const SQUAD_MODES = {
  fronted: 'freedom-ws',
  reality: 'privacy-reality',
  relay: 'freedom-reality',
} as const;

async function setupRow(ctx: { db: { query: DbQuery } }, sid: Id<'backendServers'>) {
  return ctx.db
    .query('panelSetups')
    .withIndex('by_server', (q) => q.eq('backendServerId', sid))
    .unique();
}
type DbQuery = import('./_generated/server').QueryCtx['db']['query'];

// --- start / takeover ----------------------------------------------------------------------------

export const start = internalMutation({
  args: {
    backendServerId: v.id('backendServers'),
    input: setupInput,
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const sid = a.backendServerId;
    const cfg = await resolveServerConfig(ctx.db);
    if (!cfg.manage.enabled)
      refuse('servers.manage_disabled', 'Server changes are switched off in Servers settings');
    const server = await ctx.db.get(sid);
    if (!server) return refuse('not_found', 'Backend server not found');
    if (!capabilitiesOf(server.backend).panelSetup)
      refuse('servers.unsupported_backend', 'This backend type cannot be set up here');
    const input = a.input as SetupInput;
    const bad = checkBootstrapInput(input);
    if (bad) refuse('validation', `The setup input is not usable (${bad})`);
    for (const name of Object.values(input.squads))
      if (!SQUAD_NAME.test(name)) refuse('validation', 'A squad name is 2 to 20 plain characters');
    if (new Set(Object.values(input.squads)).size !== 3)
      refuse('validation', 'The three squads need three different names');
    let originDns: Doc<'panelSetups'>['originDns'] = null;
    if (input.originDns) {
      const acct = await ctx.db.get(input.originDns.accountId as Id<'edgeProviderAccounts'>);
      const settings = acct?.settings as { zoneId?: string; zoneName?: string } | undefined;
      if (!acct || acct.provider !== 'cloudflare' || !settings?.zoneId || !settings.zoneName)
        refuse('validation', 'Origin names need a Cloudflare account with a zone');
      originDns = {
        accountId: acct!._id,
        zoneId: settings!.zoneId!,
        zoneName: settings!.zoneName!,
      };
    }
    const desiredHash = await desiredHashOf(input);
    const now = Date.now();
    let row = await setupRow(ctx, sid);
    if (row && !claimAvailable(row, now))
      refuse('servers.setup_running', 'The panel is being set up right now');
    if (!row) {
      const id = await ctx.db.insert('panelSetups', {
        backendServerId: sid,
        desired: JSON.stringify(input),
        desiredHash,
        generation: 1,
        state: 'pending',
        profileName: input.profileName,
        squads: {
          fronted: { name: input.squads.fronted },
          reality: { name: input.squads.reality },
          relay: { name: input.squads.relay },
        },
        placements: [],
        templates: [],
        originDns,
        gateVersion: 0,
        createdAt: now,
        updatedAt: now,
      });
      row = (await ctx.db.get(id))!;
    } else if (row.desiredHash !== desiredHash) {
      await ctx.db.patch(row._id, {
        desired: JSON.stringify(input),
        desiredHash,
        generation: row.generation + 1,
        state: 'pending',
        step: undefined,
        code: undefined,
        profileName: input.profileName,
        squads: {
          fronted: { name: input.squads.fronted, uuid: row.squads.fronted.uuid },
          reality: { name: input.squads.reality, uuid: row.squads.reality.uuid },
          relay: { name: input.squads.relay, uuid: row.squads.relay.uuid },
        },
        originDns,
        updatedAt: now,
      });
      row = (await ctx.db.get(row._id))!;
    } else if (row.state === 'ready') {
      return { setupId: row._id, generation: row.generation, state: row.state, started: false };
    }
    const attemptId = crypto.randomUUID();
    await ctx.db.patch(row._id, {
      claim: { attemptId, expiresAt: now + CLAIM_LEASE_MS },
      state: 'pending',
      code: undefined,
      updatedAt: now,
    });
    await ctx.scheduler.runAfter(0, internal.panelSetup.run, {
      setupId: row._id,
      generation: row.generation,
      attemptId,
    });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'servers.setup.started',
      targetType: 'backend_server',
      targetId: sid,
      payload: { backendSlug: server.slug, generation: row.generation },
    });
    return {
      setupId: row._id,
      generation: row.generation,
      state: 'pending' as const,
      started: true,
    };
  },
});

/**
 * An existing panel becomes FCP's to write: the operator attests that no
 * v1 role still writes to it. Refused while a v1 reservation is open.
 */
export const takeover = internalMutation({
  args: { backendServerId: v.id('backendServers'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, a) => {
    const sid = a.backendServerId;
    const server = await ctx.db.get(sid);
    if (!server) return refuse('not_found', 'Backend server not found');
    const reserved = (
      await ctx.db
        .query('panelOwnership')
        .withIndex('by_server_kind_identity', (q) => q.eq('backendServerId', sid))
        .collect()
    ).filter((r) => r.state === 'reserved');
    if (reserved.length > 0)
      refuse(
        'servers.reservation_open',
        'A node role run still holds a reservation on this panel. Settle it first',
      );
    await writeHandoff(ctx, sid, 'fcp-takeover');
    const row = await setupRow(ctx, sid);
    if (row)
      await ctx.db.patch(row._id, {
        handoff: 'taken_over',
        state: row.state === 'needs_takeover' ? 'pending' : row.state,
        code: undefined,
        updatedAt: Date.now(),
      });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'servers.setup.takeover',
      targetType: 'backend_server',
      targetId: sid,
      payload: { backendSlug: server.slug },
    });
    return { ok: true as const };
  },
});

async function writeHandoff(
  ctx: { db: import('./_generated/server').MutationCtx['db'] },
  sid: Id<'backendServers'>,
  by: string,
) {
  const prev = await ctx.db
    .query('panelHandoff')
    .withIndex('by_server', (q) => q.eq('backendServerId', sid))
    .unique();
  const row = {
    backendServerId: sid,
    roleContractVersion: FCP_WRITER_CONTRACT_VERSION,
    reportedAt: Date.now(),
    reportedBy: by,
  };
  if (prev) await ctx.db.replace(prev._id, row);
  else await ctx.db.insert('panelHandoff', row);
}

// --- what the run reads and records ---------------------------------------------------------------------

export const loadForRun = internalQuery({
  args: fence,
  handler: async (ctx, f) => {
    const row = await ctx.db.get(f.setupId);
    if (!row || !fenceHolds(row, f)) return null;
    const sid = row.backendServerId;
    const server = await ctx.db.get(sid);
    if (!server) return null;
    const [nodes, hosts, profiles, squads, ownership, handoff] = await Promise.all([
      ctx.db
        .query('panelNodes')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .collect(),
      ctx.db
        .query('panelHosts')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .collect(),
      ctx.db
        .query('panelProfiles')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .collect(),
      ctx.db
        .query('panelSquads')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .collect(),
      ctx.db
        .query('panelOwnership')
        .withIndex('by_server_kind_identity', (q) => q.eq('backendServerId', sid))
        .collect(),
      ctx.db
        .query('panelHandoff')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .unique(),
    ]);
    const { modes } = await resolveModeCatalog(ctx.db);
    return {
      row,
      input: JSON.parse(row.desired) as SetupInput,
      server: {
        _id: server._id,
        backend: server.backend,
        config: server.config,
        slug: server.slug,
      },
      snapshot: {
        nodes: nodes.length,
        hosts: hosts.length,
        profiles: profiles.map((p) => ({
          profileUuid: p.profileUuid,
          name: p.name,
          inbounds: p.inbounds.map((i) => ({
            ...i,
            configProfileUuid: p.profileUuid,
            configProfileInboundUuid: i.inboundUuid,
            reality: i.reality,
            ws: i.path !== undefined ? { path: i.path ?? null, host: null } : undefined,
          })),
        })),
        squads: squads.map((s) => ({
          squadUuid: s.squadUuid,
          name: s.name,
          inboundUuids: s.inboundUuids,
        })),
        openReservations: ownership.filter((o) => o.state === 'reserved').length,
        handoff: handoff ? { version: handoff.roleContractVersion } : null,
        knownModes: modes.map((m) => m.id),
      },
    };
  },
});

const stepPatch = v.object({
  step: v.optional(v.string()),
  profileUuid: v.optional(v.string()),
  inbounds: v.optional(v.any()),
  squads: v.optional(v.any()),
  placements: v.optional(v.any()),
  templates: v.optional(v.any()),
  privacy: v.optional(v.union(v.literal('ok'), v.literal('drifted'))),
  handoff: v.optional(v.union(v.literal('fresh'), v.literal('taken_over'))),
});

export const recordStep = internalMutation({
  args: { ...fence, patch: stepPatch },
  handler: async (ctx, { patch, ...f }) => {
    const row = await ctx.db.get(f.setupId);
    if (!row || !fenceHolds(row, f)) return { ok: false as const };
    const now = Date.now();
    await ctx.db.patch(f.setupId, {
      ...(patch as Partial<Doc<'panelSetups'>>),
      claim: { attemptId: f.attemptId, expiresAt: now + CLAIM_LEASE_MS },
      updatedAt: now,
    });
    return { ok: true as const };
  },
});

export const recordHandoff = internalMutation({
  args: fence,
  handler: async (ctx, f) => {
    const row = await ctx.db.get(f.setupId);
    if (!row || !fenceHolds(row, f)) return { ok: false as const };
    await writeHandoff(ctx, row.backendServerId, 'fcp-setup');
    await ctx.db.patch(f.setupId, { handoff: 'fresh', updatedAt: Date.now() });
    return { ok: true as const };
  },
});

export const finish = internalMutation({
  args: {
    ...fence,
    state: v.union(
      v.literal('pending'),
      v.literal('needs_takeover'),
      v.literal('ready'),
      v.literal('failed'),
    ),
    code: v.optional(v.string()),
    step: v.optional(v.string()),
  },
  handler: async (ctx, { state, code, step, ...f }) => {
    const row = await ctx.db.get(f.setupId);
    if (!row || !fenceHolds(row, f)) return { ok: false as const };
    await ctx.db.patch(f.setupId, {
      state,
      code,
      ...(step !== undefined ? { step } : {}),
      claim: undefined,
      updatedAt: Date.now(),
    });
    const server = await ctx.db.get(row.backendServerId);
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'servers.setup.finished',
      targetType: 'backend_server',
      targetId: row.backendServerId,
      payload: {
        backendSlug: server?.slug ?? '',
        state,
        code: code ?? null,
        step: row.step ?? null,
      },
    });
    return { ok: true as const };
  },
});

// --- the delivery gate version lives on the setup row -------------------------------------------

export const gateVersionOf = internalQuery({
  args: { backendServerId: v.id('backendServers') },
  handler: async (ctx, { backendServerId }) =>
    (await setupRow(ctx, backendServerId))?.gateVersion ?? 0,
});

/** Bump the panel-wide gate version (every disposition or resource-set change). */
export async function bumpGateVersion(
  ctx: { db: import('./_generated/server').MutationCtx['db'] },
  sid: Id<'backendServers'>,
): Promise<number> {
  const row = await setupRow(ctx, sid);
  if (!row) return 0;
  const next = row.gateVersion + 1;
  await ctx.db.patch(row._id, { gateVersion: next, updatedAt: Date.now() });
  return next;
}

export const bumpGate = internalMutation({
  args: { backendServerId: v.id('backendServers') },
  handler: (ctx, { backendServerId }) => bumpGateVersion(ctx, backendServerId),
});

// --- the run ------------------------------------------------------------------------------------------

type Loaded = NonNullable<Awaited<ReturnType<typeof loadForRunHandler>>>;
async function loadForRunHandler(ctx: ActionCtx, f: Fence) {
  return ctx.runQuery(internal.panelSetup.loadForRun, f);
}

export const run = internalAction({
  args: fence,
  handler: async (ctx, f): Promise<null> => {
    let c = await loadForRunHandler(ctx, f);
    if (!c) return null;
    const sid = c.server._id;
    const record = (patch: Record<string, unknown>) =>
      ctx.runMutation(internal.panelSetup.recordStep, { ...f, patch });
    const finish = (
      state: 'pending' | 'needs_takeover' | 'ready' | 'failed',
      code?: string,
      step?: string,
    ) => ctx.runMutation(internal.panelSetup.finish, { ...f, state, code, step });
    const reload = async (): Promise<Loaded> => {
      const next = await loadForRunHandler(ctx, f);
      if (!next) throw new Fenced();
      return next;
    };
    const provider = PROVIDERS[c.server.backend];
    const writes = provider.panelWrites;
    if (!writes) {
      await finish('failed', 'servers.unsupported_backend');
      return null;
    }
    const config = c.server.config as BackendConfig;
    const input = c.input;
    try {
      // 1. A fresh look at the panel: everything below reads the cache.
      await record({ step: 'observe' });
      if (!(await observeInstance(ctx, c.server))) {
        await finish('failed', 'servers.observe_failed', 'observe');
        return null;
      }
      c = await reload();

      // 2. Handoff: automatic only for a demonstrably fresh panel.
      await record({ step: 'handoff' });
      if (!c.snapshot.handoff) {
        const fresh =
          c.snapshot.nodes === 0 && c.snapshot.hosts === 0 && c.snapshot.openReservations === 0;
        if (!fresh) {
          await finish('needs_takeover', 'servers.handoff_needs_takeover', 'handoff');
          return null;
        }
        await ctx.runMutation(internal.panelSetup.recordHandoff, f);
      }

      // 3. The profile: adopt a compatible one, else create from the template.
      await record({ step: 'profile' });
      let profile = c.snapshot.profiles.find((p) => p.name === input.profileName) ?? null;
      if (!profile) {
        const blocking = await ctx.runQuery(internal.panelObligations.blockingFor, {
          backendServerId: sid,
          kind: 'profile.create',
          identity: input.profileName,
        });
        if (blocking) {
          // The same attempt's discovery just ran (the fresh look above) and
          // found nothing: the outcome is still unknown. Never a second create.
          await finish('pending', 'servers.obligation_unresolved', 'profile');
          return null;
        }
        const opened = await ctx.runMutation(internal.panelObligations.open, {
          backendServerId: sid,
          ownerKind: 'setup',
          ownerId: f.setupId,
          ownerGeneration: f.generation,
          attemptId: f.attemptId,
          kind: 'profile.create',
          identity: input.profileName,
          verb: 'create',
          ownership: 'shared',
          intent: JSON.stringify({ name: input.profileName }),
        });
        if (!opened.ok) {
          await finish('pending', 'servers.obligation_unresolved', 'profile');
          return null;
        }
        const outcome = await createProfile(writes, config, input, opened.id, ctx);
        if (outcome !== 'created') {
          await finish(
            outcome === 'refused' ? 'failed' : 'pending',
            outcome === 'refused' ? 'servers.panel_refused' : 'servers.obligation_unresolved',
            'profile',
          );
          return null;
        }
        await observeInstance(ctx, c.server);
        c = await reload();
        profile = c.snapshot.profiles.find((p) => p.name === input.profileName) ?? null;
        if (!profile) {
          await finish('pending', 'servers.observe_lag', 'profile');
          return null;
        }
      }
      const compat = checkProfileCompatibility(profile);
      if (!compat.ok) {
        await finish(
          'failed',
          `servers.profile_incompatible:${compat.issue.tag}:${compat.issue.field}`,
          'profile',
        );
        return null;
      }
      const e = compat.effective;
      const asReality = (k: 'reality' | 'relay') => {
        const r = e[k];
        if (r.kind === 'cdn') throw new Error('unreachable');
        return {
          uuid: r.inboundUuid,
          tag: r.tag,
          port: r.port,
          serverNames: r.serverNames,
          target: r.target,
          publicKey: r.publicKey,
        };
      };
      const cdn = e.cdn.kind === 'cdn' ? e.cdn : null;
      if (!cdn) throw new Error('unreachable');
      let privacy: 'ok' | 'drifted' = 'ok';
      if (provider.hardenLogging) {
        const report = await provider.hardenLogging(config, { dryRun: true });
        const p = report.profiles.find((x) => x.uuid === profile!.profileUuid);
        privacy = p && p.changed ? 'drifted' : 'ok';
      }
      await record({
        profileUuid: profile.profileUuid,
        inbounds: {
          cdn: {
            uuid: cdn.inboundUuid,
            tag: cdn.tag,
            listen: cdn.listen,
            port: cdn.port,
            path: cdn.path,
          },
          reality: asReality('reality'),
          relay: asReality('relay'),
        },
        privacy,
      });

      // 4. Squads: three, each carrying its inbound; through the ledger.
      await record({ step: 'squads' });
      const squadInbound = {
        fronted: cdn.inboundUuid,
        reality: asReality('reality').uuid,
        relay: asReality('relay').uuid,
      };
      const squads: Doc<'panelSetups'>['squads'] = {
        fronted: { name: input.squads.fronted },
        reality: { name: input.squads.reality },
        relay: { name: input.squads.relay },
      };
      for (const kind of ['fronted', 'reality', 'relay'] as const) {
        const name = input.squads[kind];
        const inboundUuid = squadInbound[kind];
        let sq = c.snapshot.squads.find((s) => s.name === name) ?? null;
        if (!sq) {
          const { opId } = await ctx.runMutation(internal.panelWrites.requestSquadCreate, {
            backendServerId: sid,
            name,
            inboundUuids: [inboundUuid],
          });
          const r = await ctx.runAction(internal.panelWrites.run, { opId });
          if (r.open) {
            await finish('pending', 'servers.op_running', 'squads');
            return null;
          }
          await observeInstance(ctx, c.server);
          c = await reload();
          sq = c.snapshot.squads.find((s) => s.name === name) ?? null;
          if (!sq) {
            await finish('pending', 'servers.observe_lag', 'squads');
            return null;
          }
        } else if (!sq.inboundUuids.includes(inboundUuid)) {
          const { opId } = await ctx.runMutation(internal.panelWrites.requestSquadUpdate, {
            backendServerId: sid,
            squadUuid: sq.squadUuid,
            inboundUuids: [...sq.inboundUuids, inboundUuid],
          });
          const r = await ctx.runAction(internal.panelWrites.run, { opId });
          if (r.open) {
            await finish('pending', 'servers.op_running', 'squads');
            return null;
          }
        }
        squads[kind] = { name, uuid: sq.squadUuid };
      }
      await record({ squads });

      // 5. Placements: each squad into its mode's pool; unknown modes are recorded, not bound.
      await record({ step: 'placements' });
      const modes: Record<string, { addSquadUuids: string[] }> = {};
      const placements: { mode: string; state: 'bound' | 'skipped' }[] = [];
      for (const kind of ['fronted', 'reality', 'relay'] as const) {
        const mode = SQUAD_MODES[kind];
        const uuid = squads[kind].uuid!;
        if (c.snapshot.knownModes.includes(mode)) {
          modes[mode] = { addSquadUuids: [uuid] };
          placements.push({ mode, state: 'bound' });
        } else placements.push({ mode, state: 'skipped' });
      }
      if (Object.keys(modes).length > 0)
        await ctx.runMutation(internal.connectionModes.setModePlacements, {
          backend: c.server.backend,
          patch: { modes },
        });
      await record({ placements });

      // 6. Subscription templates: reconcile on drift; a refused write blocks activation later.
      await record({ step: 'templates' });
      const listed = await writes.listSubscriptionTemplates(config);
      const templates: {
        family: string;
        hash: string;
        state: 'matched' | 'drifted' | 'refused';
      }[] = [];
      for (const family of TEMPLATE_FAMILIES) {
        const ref = listed.find((t) => t.templateType === family);
        if (!ref) continue;
        const desired = SUBSCRIPTION_TEMPLATES[family];
        const hash = await templateHash(desired);
        let live = await writes.readSubscriptionTemplate(config, ref.uuid);
        if (!templateDrift(live, desired)) {
          templates.push({ family, hash, state: 'matched' });
          continue;
        }
        try {
          await writes.updateSubscriptionTemplate(config, ref.uuid, desiredTemplateBody(desired));
          live = await writes.readSubscriptionTemplate(config, ref.uuid);
          templates.push({
            family,
            hash,
            state: templateDrift(live, desired) ? 'drifted' : 'matched',
          });
        } catch (err) {
          const r = callResultOf(err);
          const refused = r.kind === 'http' && (r.status === 401 || r.status === 403);
          templates.push({ family, hash, state: refused ? 'refused' : 'drifted' });
        }
      }
      await record({ templates });

      await finish('ready', undefined, 'done');
      return null;
    } catch (err) {
      if (err instanceof Fenced) return null;
      const code =
        err instanceof ConvexError && typeof (err.data as { code?: unknown })?.code === 'string'
          ? (err.data as { code: string }).code
          : 'servers.setup_failed';
      await finish('failed', code);
      return null;
    }
  },
});

class Fenced extends Error {}

/**
 * The one external create: keys generated here, the config built here, the
 * call made once. Returns what happened without ever returning the config.
 */
async function createProfile(
  writes: NonNullable<(typeof PROVIDERS)[keyof typeof PROVIDERS]['panelWrites']>,
  config: BackendConfig,
  input: SetupInput,
  obligationId: Id<'panelObligations'>,
  ctx: ActionCtx,
): Promise<'created' | 'refused' | 'unresolved'> {
  const mark = (
    state: 'sent' | 'unresolved' | 'confirmed' | 'failed',
    extra: { resourceRef?: string; code?: string } = {},
  ) => ctx.runMutation(internal.panelObligations.mark, { id: obligationId, state, ...extra });
  const body = buildBootstrapProfile(input, {
    reality: { privateKey: generateRealityKey().privateKey, shortIds: BOOTSTRAP_DEFAULTS.shortIds },
    relay: { privateKey: generateRealityKey().privateKey, shortIds: BOOTSTRAP_DEFAULTS.shortIds },
  });
  await mark('sent');
  try {
    const made = await writes.createProfile(config, { name: input.profileName, config: body });
    await mark('confirmed', { resourceRef: made.profileUuid });
    return 'created';
  } catch (err) {
    if (classifyRequest(callResultOf(err)) === 'rejected_pre_mutation') {
      await mark('failed', { code: 'servers.panel_refused' });
      return 'refused';
    }
    await mark('unresolved', { code: 'servers.outcome_unknown' });
    return 'unresolved';
  }
}

// --- the view ---------------------------------------------------------------------------------------

export const view = internalQuery({
  args: { backendServerId: v.id('backendServers') },
  handler: async (ctx, { backendServerId }) => {
    const row = await setupRow(ctx, backendServerId);
    if (!row)
      return {
        exists: false,
        state: null,
        step: null,
        code: null,
        generation: 0,
        running: false,
        profile: null,
        inbounds: null,
        squads: [],
        placements: [],
        templates: [],
        privacy: null,
        originDns: null,
        handoff: null,
        updatedAt: null,
      };
    const target = (t: { address: string; port: number }) => `${t.address}:${t.port}`;
    return {
      exists: true,
      state: row.state,
      step: row.step ?? null,
      code: row.code ?? null,
      generation: row.generation,
      running: !!row.claim && row.claim.expiresAt > Date.now(),
      profile: { name: row.profileName, uuid: row.profileUuid ?? null },
      inbounds: row.inbounds
        ? {
            cdn: {
              tag: row.inbounds.cdn.tag,
              listen: row.inbounds.cdn.listen,
              port: row.inbounds.cdn.port,
              path: row.inbounds.cdn.path,
            },
            reality: {
              tag: row.inbounds.reality.tag,
              port: row.inbounds.reality.port,
              serverNames: row.inbounds.reality.serverNames,
              target: target(row.inbounds.reality.target),
            },
            relay: {
              tag: row.inbounds.relay.tag,
              port: row.inbounds.relay.port,
              serverNames: row.inbounds.relay.serverNames,
              target: target(row.inbounds.relay.target),
            },
          }
        : null,
      squads: (['fronted', 'reality', 'relay'] as const).map((k) => ({
        kind: k,
        name: row.squads[k].name,
        bound: !!row.squads[k].uuid,
      })),
      placements: row.placements,
      templates: row.templates.map((t) => ({ family: t.family, state: t.state })),
      privacy: row.privacy ?? null,
      originDns: row.originDns
        ? { accountId: row.originDns.accountId, zoneName: row.originDns.zoneName }
        : null,
      handoff: row.handoff ?? null,
      updatedAt: new Date(row.updatedAt).toISOString(),
    };
  },
});

/** The setup row a node intent reads its inbounds and origin zone from; null until ready. */
export const readyFor = internalQuery({
  args: { backendServerId: v.id('backendServers') },
  handler: async (ctx, { backendServerId }) => {
    const row = await setupRow(ctx, backendServerId);
    return row && row.state === 'ready' && row.inbounds && row.profileUuid ? row : null;
  },
});
