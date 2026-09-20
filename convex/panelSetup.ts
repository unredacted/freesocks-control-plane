/**
 * "Set up this backend" (docs/servers.md "Setting up a backend"): one durable,
 * fenced workflow per backend server that makes a backend the shape its
 * modes rely on. The profile (created from the template, or an existing one
 * adopted only when compatible; keys never touched), one transport per mode,
 * each REALITY transport bound to its server-name family, each mode's group
 * (found under its name or a name an earlier setup gave it and renamed in
 * place), the mode placements, and the subscription templates.
 *
 * A backend that already has nodes or addresses is ADOPTED: the operator's
 * typed confirmation is the one attestation; nothing is created beside what
 * exists, and nothing a member holds changes.
 *
 * Every step is idempotent and re-enterable: the row records the step it is
 * on, the sweep resumes an expired lease, and the one external create (the
 * profile) is an obligation persisted before the call. The REALITY keys are
 * generated inside the claimed attempt right before that call and exist
 * nowhere else.
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { ActionCtx, QueryCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { capabilitiesOf } from './lib/backends/capabilities';
import { PROVIDERS, type BackendConfig } from './lib/backends/registry';
import { resolveModeCatalog } from './lib/connectionModes';
import { sameTarget } from './lib/edges/sni/family';
import { CLAIM_LEASE_MS, claimAvailable, desiredHashOf, fenceHolds } from './lib/panel/fencing';
import { callResultOf, classifyRequest } from './lib/panel/ops';
import { checkProfileCompatibility, type EffectiveTransport } from './lib/panel/profileCompat';
import {
  PROFILE_DEFAULTS,
  buildProfile,
  checkModeDefinitions,
  isReality,
  transportTagOf,
  type ModeShape,
  type ModeTemplateInput,
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

const shapeValidator = v.object({
  transport: v.union(v.literal('reality'), v.literal('xhttp-reality'), v.literal('ws')),
  fronting: v.union(v.literal('direct'), v.literal('edge-l4'), v.literal('edge-l7')),
});
const modeInput = v.object({
  slug: v.string(),
  name: v.string(),
  shape: shapeValidator,
  familySlug: v.optional(v.string()),
  acceptProxyProtocol: v.boolean(),
  ws: v.optional(v.object({ path: v.string(), port: v.number() })),
});
export const setupInput = v.object({
  profileName: v.string(),
  modes: v.array(modeInput),
  originDns: v.union(v.object({ accountId: v.string() }), v.null()),
  adopt: v.boolean(),
});
type ModeInput = {
  slug: string;
  name: string;
  shape: ModeShape;
  familySlug?: string;
  acceptProxyProtocol: boolean;
  ws?: { path: string; port: number };
};
type SetupInput = {
  profileName: string;
  modes: ModeInput[];
  originDns: { accountId: string } | null;
  adopt: boolean;
};

/** Group names an earlier setup gave the same modes; found and renamed in place. */
const LEGACY_GROUP_NAMES: Readonly<Record<string, readonly string[]>> = {
  'privacy-reality': ['FreeSocks-Reality'],
  'freedom-reality': ['FreeSocks-Relay'],
  'freedom-ws': ['FreeSocks-Fronted', 'FreeSocks-Fastly'],
};

const fence = {
  setupId: v.id('panelSetups'),
  generation: v.number(),
  attemptId: v.string(),
};
type Fence = { setupId: Id<'panelSetups'>; generation: number; attemptId: string };

type SetupRow = Doc<'panelSetups'>;
export type SetupMode = NonNullable<SetupRow['modes']>[number];
/**
 * A setup row of the CURRENT shape. `modes` and `adopted` are optional in the
 * schema only so a row from the release before modes can be pushed (see the
 * transitional notes there); every consumer goes through `setupReady`, which
 * refuses such a row, so the fields are present here.
 */
export type Setup = SetupRow & { modes: SetupMode[]; adopted: boolean };

async function setupRow(ctx: { db: { query: DbQuery } }, sid: Id<'backendServers'>) {
  return ctx.db
    .query('panelSetups')
    .withIndex('by_server', (q) => q.eq('backendServerId', sid))
    .unique();
}
type DbQuery = import('./_generated/server').QueryCtx['db']['query'];

/** The setup row's entry for a mode slug. */
export function modeOf(setup: Setup, slug: string): SetupMode | undefined {
  return setup.modes.find((m) => m.slug === slug);
}

/** The modes a row carries, whatever its vintage (a pre-modes row has none). */
const modesOf = (row: SetupRow): SetupMode[] => row.modes ?? [];

/** The mode entries a fresh row starts with: definitions only, nothing found yet. */
function freshModes(input: SetupInput, prev: readonly SetupMode[] = []): SetupMode[] {
  return input.modes.map((m) => {
    const before = prev.find((p) => p.slug === m.slug);
    return {
      slug: m.slug,
      name: m.name,
      shape: m.shape,
      familySlug: m.familySlug,
      acceptProxyProtocol: m.acceptProxyProtocol,
      ws: m.ws,
      tag: before?.tag ?? transportTagOf(m.name),
      groupUuid: before?.groupUuid,
      renamedFrom: before?.renamedFrom,
      placement: 'pending',
      transport: undefined,
      family: isReality(m.shape) ? 'unbound' : 'none',
    };
  });
}

// --- start ----------------------------------------------------------------------------------------

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
    if (!/^[A-Za-z0-9 ._-]{1,60}$/.test(input.profileName))
      refuse('validation', 'A profile name is 1 to 60 plain characters');
    const bad = checkModeDefinitions(input.modes);
    if (bad) refuse('servers.modes_invalid', `The modes are not usable (${bad})`);
    const { modes: catalog } = await resolveModeCatalog(ctx.db);
    const known = new Set(catalog.map((m) => m.id));
    for (const m of input.modes) {
      if (!known.has(m.slug))
        refuse('servers.mode_unknown', `No connection mode "${m.slug}" exists. Add it first`);
      if (!isReality(m.shape)) continue;
      const family = await ctx.db
        .query('sniFamilies')
        .withIndex('by_slug', (q) => q.eq('slug', m.familySlug!))
        .unique();
      if (!family || !family.enabled)
        refuse('servers.family_missing', `Mode ${m.name} names a family that does not exist`);
    }
    let originDns: Setup['originDns'] = null;
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
    // A backend with nodes or addresses on it is adopted, never quietly set up.
    const [nodes, addresses] = await Promise.all([
      ctx.db
        .query('panelNodes')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .first(),
      ctx.db
        .query('panelHosts')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .first(),
    ]);
    const existing = !!nodes || !!addresses;
    let row = await setupRow(ctx, sid);
    if (existing && !input.adopt && !row?.adopted)
      refuse(
        'servers.adopt_required',
        'This backend already has nodes or addresses. Adopt it (typed) to make FCP its writer',
      );
    const desiredHash = await desiredHashOf(input);
    const now = Date.now();
    if (row && !claimAvailable(row, now))
      refuse('servers.setup_running', 'The backend is being set up right now');
    if (!row) {
      const id = await ctx.db.insert('panelSetups', {
        backendServerId: sid,
        desired: JSON.stringify(input),
        desiredHash,
        generation: 1,
        state: 'pending',
        profileName: input.profileName,
        modes: freshModes(input),
        templates: [],
        originDns,
        adopted: existing,
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
        modes: freshModes(input, modesOf(row)),
        originDns,
        adopted: row.adopted === true || existing,
        // A row from before modes is replaced, not merged (see schema.ts).
        inbounds: undefined,
        squads: undefined,
        placements: undefined,
        handoff: undefined,
        updatedAt: now,
      });
      row = (await ctx.db.get(row._id))!;
    } else if (row.state === 'ready' && !setupNeedsRefresh(row)) {
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
      payload: { backendSlug: server.slug, generation: row.generation, adopt: row.adopted },
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
 * A ready row that still records a blocker (drifted privacy after a
 * hardening, a drifted or refused template, a skipped placement, an unbound
 * family) is re-run on request so the blocker can clear: the run adopts
 * everything it finds and recomputes those fields from the backend.
 */
function setupNeedsRefresh(row: SetupRow): boolean {
  return (
    row.privacy === 'drifted' ||
    row.templates.some((t) => t.state !== 'matched') ||
    modesOf(row).some((m) => m.placement !== 'bound' || m.family === 'unbound' || !m.transport)
  );
}

// --- what the run reads and records ---------------------------------------------------------------------

async function loadSetupContext(ctx: QueryCtx, f: Fence) {
  const row = await ctx.db.get(f.setupId);
  if (!row || !fenceHolds(row, f)) return null;
  const sid = row.backendServerId;
  const server = await ctx.db.get(sid);
  if (!server) return null;
  const [profiles, groups] = await Promise.all([
    ctx.db
      .query('panelProfiles')
      .withIndex('by_server', (q) => q.eq('backendServerId', sid))
      .collect(),
    ctx.db
      .query('panelSquads')
      .withIndex('by_server', (q) => q.eq('backendServerId', sid))
      .collect(),
  ]);
  const { modes } = await resolveModeCatalog(ctx.db);
  // Every family a REALITY mode names: its target and the names usable today.
  const families: Record<
    string,
    { slug: string; target: { address: string; port: number }; names: string[] }
  > = {};
  for (const m of modesOf(row)) {
    if (!m.familySlug || families[m.familySlug]) continue;
    const family = await ctx.db
      .query('sniFamilies')
      .withIndex('by_slug', (q) => q.eq('slug', m.familySlug!))
      .unique();
    if (!family) continue;
    const names = (
      await ctx.db
        .query('sniNames')
        .withIndex('by_family_seq', (q) => q.eq('familyId', family._id))
        .collect()
    )
      .filter((n) => n.status === 'active' && n.qualification.state === 'ok')
      .map((n) => n.name);
    families[m.familySlug] = {
      slug: family.slug,
      target: { address: family.target.address, port: family.target.port },
      names,
    };
  }
  const bindings = await ctx.db
    .query('sniInboundBindings')
    .withIndex('by_server_inbound', (q) => q.eq('backendServerId', sid))
    .collect();
  // Which family each already-bound transport answers to: a transport bound to
  // ANOTHER family is that family's allowlist, and its rollouts would keep
  // moving this mode's names.
  const boundFamilies: Record<string, string> = {};
  for (const b of bindings) {
    const fam = await ctx.db.get(b.familyId);
    if (fam) boundFamilies[b.inboundUuid] = fam.slug;
  }
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
      profiles: profiles.map((p) => ({
        profileUuid: p.profileUuid,
        name: p.name,
        inbounds: p.inbounds.map((i) => ({
          ...i,
          configProfileUuid: p.profileUuid,
          configProfileInboundUuid: i.inboundUuid,
          reality: i.reality,
          ws:
            i.network === 'ws' && i.path !== undefined
              ? { path: i.path ?? null, host: null }
              : undefined,
          xhttp:
            i.network === 'xhttp' ? { path: i.path ?? null, host: null, mode: null } : undefined,
        })),
      })),
      groups: groups.map((s) => ({
        groupUuid: s.squadUuid,
        name: s.name,
        transportUuids: s.inboundUuids,
      })),
      knownModes: modes.map((m) => m.id),
      families,
      boundFamilies,
    },
  };
}

export const loadForRun = internalQuery({
  args: fence,
  handler: (ctx, f) => loadSetupContext(ctx, f),
});

const stepPatch = v.object({
  step: v.optional(v.string()),
  profileUuid: v.optional(v.string()),
  modes: v.optional(v.any()),
  templates: v.optional(v.any()),
  privacy: v.optional(v.union(v.literal('ok'), v.literal('drifted'))),
});

export const recordStep = internalMutation({
  args: { ...fence, patch: stepPatch },
  handler: async (ctx, { patch, ...f }) => {
    const row = await ctx.db.get(f.setupId);
    if (!row || !fenceHolds(row, f)) return { ok: false as const };
    const now = Date.now();
    await ctx.db.patch(f.setupId, {
      ...(patch as Partial<Setup>),
      claim: { attemptId: f.attemptId, expiresAt: now + CLAIM_LEASE_MS },
      updatedAt: now,
    });
    return { ok: true as const };
  },
});

export const finish = internalMutation({
  args: {
    ...fence,
    state: v.union(v.literal('pending'), v.literal('ready'), v.literal('failed')),
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

export const recordGroupRename = internalMutation({
  args: { ...fence, from: v.string(), to: v.string() },
  handler: async (ctx, { from, to, ...f }) => {
    const row = await ctx.db.get(f.setupId);
    if (!row || !fenceHolds(row, f)) return null;
    const server = await ctx.db.get(row.backendServerId);
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'servers.setup.group_renamed',
      targetType: 'backend_server',
      targetId: row.backendServerId,
      payload: { backendSlug: server?.slug ?? '', from, to },
    });
    return null;
  },
});

// --- the delivery gate version lives on the setup row -------------------------------------------

export const gateVersionOf = internalQuery({
  args: { backendServerId: v.id('backendServers') },
  handler: async (ctx, { backendServerId }) =>
    (await setupRow(ctx, backendServerId))?.gateVersion ?? 0,
});

/** Bump the backend-wide gate version (every disposition or resource-set change). */
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

type Loaded = NonNullable<Awaited<ReturnType<typeof loadSetupContext>>>;
async function loadForRunHandler(ctx: ActionCtx, f: Fence): Promise<Loaded | null> {
  return (await ctx.runQuery(internal.panelSetup.loadForRun, f)) as Loaded | null;
}

/** The transport entry a setup row records for an effective transport. */
function transportRecord(e: EffectiveTransport): NonNullable<SetupMode['transport']> {
  return e.kind === 'ws'
    ? { uuid: e.uuid, listen: e.listen, port: e.port, path: e.path }
    : {
        uuid: e.uuid,
        port: e.port,
        path: e.path ?? undefined,
        serverNames: e.serverNames,
        target: e.target,
        publicKey: e.publicKey,
      };
}

export const run = internalAction({
  args: fence,
  handler: async (ctx, f): Promise<null> => {
    const first = await loadForRunHandler(ctx, f);
    if (!first) return null;
    let c: Loaded = first;
    const sid = c.server._id;
    const record = (patch: Record<string, unknown>) =>
      ctx.runMutation(internal.panelSetup.recordStep, { ...f, patch });
    const finish = (state: 'pending' | 'ready' | 'failed', code?: string, step?: string) =>
      ctx.runMutation(internal.panelSetup.finish, { ...f, state, code, step });
    const reload = async (): Promise<Loaded> => {
      const next = await loadForRunHandler(ctx, f);
      if (!next) throw new Fenced();
      return next;
    };
    // The write-off switch is re-read before every provider write this run
    // makes outside the ledger: a run scheduled or resumed after the switch
    // was turned off parks instead of writing.
    const writable = async (step: string): Promise<boolean> => {
      if (await ctx.runQuery(internal.serverAdmin.manageEnabled, {})) return true;
      await finish('pending', 'servers.manage_disabled', step);
      return false;
    };
    const provider = PROVIDERS[c.server.backend];
    const writes = provider.panelWrites;
    if (!writes) {
      await finish('failed', 'servers.unsupported_backend');
      return null;
    }
    const config = c.server.config as BackendConfig;
    const input = c.input;
    let modes: SetupMode[] = modesOf(c.row).map((m) => ({ ...m }));
    const save = () => record({ modes });
    try {
      // 1. A fresh look at the backend: everything below reads the cache.
      await record({ step: 'observe' });
      if (!(await observeInstance(ctx, c.server))) {
        await finish('failed', 'servers.observe_failed', 'observe');
        return null;
      }
      c = await reload();

      // 2. Every REALITY mode's family must have a usable name today; a
      //    created transport is born with exactly those names.
      await record({ step: 'families' });
      for (const m of modes) {
        if (!isReality(m.shape)) continue;
        const fam = c.snapshot.families[m.familySlug!];
        if (!fam) {
          await finish('failed', 'servers.family_missing', 'families');
          return null;
        }
        if (fam.names.length === 0) {
          await finish('failed', 'servers.family_empty', 'families');
          return null;
        }
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
        if (!(await writable('profile'))) {
          await ctx.runMutation(internal.panelObligations.mark, {
            id: opened.id,
            state: 'failed',
            code: 'servers.manage_disabled',
          });
          return null;
        }
        const template: ModeTemplateInput[] = modes.map((m) =>
          m.shape.transport === 'ws'
            ? {
                slug: m.slug,
                name: m.name,
                shape: m.shape as { transport: 'ws'; fronting: ModeShape['fronting'] },
                ws: m.ws ?? { path: PROFILE_DEFAULTS.ws.path, port: PROFILE_DEFAULTS.ws.port },
              }
            : {
                slug: m.slug,
                name: m.name,
                shape: m.shape as {
                  transport: 'reality' | 'xhttp-reality';
                  fronting: ModeShape['fronting'];
                },
                acceptProxyProtocol: m.acceptProxyProtocol,
                reality: {
                  target: c.snapshot.families[m.familySlug!]!.target,
                  serverNames: c.snapshot.families[m.familySlug!]!.names,
                },
              },
        );
        const outcome = await createProfile(
          writes,
          config,
          input.profileName,
          template,
          opened.id,
          ctx,
        );
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
      const compat = checkProfileCompatibility(profile, modes);
      if (!compat.ok) {
        await finish(
          'failed',
          `servers.profile_incompatible:${compat.issue.tag}:${compat.issue.field}`,
          'profile',
        );
        return null;
      }
      let privacy: 'ok' | 'drifted' = 'ok';
      if (provider.hardenLogging) {
        const report = await provider.hardenLogging(config, { dryRun: true });
        const p = report.profiles.find((x) => x.uuid === profile!.profileUuid);
        privacy = p && p.changed ? 'drifted' : 'ok';
      }
      modes = modes.map((m) => {
        const e = compat.effective[m.slug]!;
        return { ...m, tag: e.tag, transport: transportRecord(e) };
      });
      await record({ profileUuid: profile.profileUuid, privacy, modes });

      // 4. Families bound to their transports: the one authoritative allowlist
      //    of each REALITY transport (rollouts carry later changes).
      await record({ step: 'bind' });
      for (const m of modes) {
        if (!isReality(m.shape) || !m.transport) continue;
        const fam = c.snapshot.families[m.familySlug!]!;
        // Already bound: only THIS family's binding counts. A binding to
        // another family owns the transport's allowlist and its rollouts would
        // keep moving these names, so an admin unbinds it first.
        const bound = c.snapshot.boundFamilies[m.transport.uuid];
        if (bound !== undefined) {
          if (bound !== fam.slug) {
            m.family = 'bound_elsewhere';
            await save();
            await finish('failed', `servers.family_bound_elsewhere:${bound}`, 'bind');
            return null;
          }
          m.family = 'bound';
          continue;
        }
        if (!sameTarget(m.transport.target ?? null, fam.target)) {
          m.family = 'target_mismatch';
          await save();
          await finish('failed', 'servers.family_target_mismatch', 'bind');
          return null;
        }
        await ctx.runMutation(internal.sniFamilies.bind, {
          slug: fam.slug,
          backendSlug: c.server.slug,
          inboundTag: m.tag,
          inboundUuid: m.transport.uuid,
        });
        m.family = 'bound';
      }
      await save();

      // 5. Groups: each mode's, found under its name or a name an earlier
      //    setup gave it (renamed in place: ids and assignments survive);
      //    created only when nothing exists; carrying the mode's transport.
      await record({ step: 'groups' });
      for (const m of modes) {
        const transportUuid = m.transport!.uuid;
        let group =
          c.snapshot.groups.find((g) => g.name === m.name) ??
          (m.groupUuid ? c.snapshot.groups.find((g) => g.groupUuid === m.groupUuid) : undefined) ??
          null;
        if (!group) {
          const legacy = (LEGACY_GROUP_NAMES[m.slug] ?? [])
            .map((n) => c.snapshot.groups.find((g) => g.name === n))
            .find((g) => !!g);
          if (legacy) {
            const { opId } = await ctx.runMutation(internal.panelWrites.requestSquadUpdate, {
              backendServerId: sid,
              squadUuid: legacy.groupUuid,
              name: m.name,
            });
            const r = await ctx.runAction(internal.panelWrites.run, { opId });
            if (r.open) {
              await finish('pending', 'servers.op_running', 'groups');
              return null;
            }
            await ctx.runMutation(internal.panelSetup.recordGroupRename, {
              ...f,
              from: legacy.name,
              to: m.name,
            });
            m.renamedFrom = legacy.name;
            await observeInstance(ctx, c.server);
            c = await reload();
            group = c.snapshot.groups.find((g) => g.groupUuid === legacy.groupUuid) ?? null;
          }
        }
        if (!group) {
          const { opId } = await ctx.runMutation(internal.panelWrites.requestSquadCreate, {
            backendServerId: sid,
            name: m.name,
            inboundUuids: [transportUuid],
          });
          const r = await ctx.runAction(internal.panelWrites.run, { opId });
          if (r.open) {
            await finish('pending', 'servers.op_running', 'groups');
            return null;
          }
          await observeInstance(ctx, c.server);
          c = await reload();
          group = c.snapshot.groups.find((g) => g.name === m.name) ?? null;
          if (!group) {
            await finish('pending', 'servers.observe_lag', 'groups');
            return null;
          }
        } else if (group.transportUuids.length !== 1 || group.transportUuids[0] !== transportUuid) {
          // A mode grants exactly ONE transport, so the group carries exactly
          // it: a transport an earlier release left in the group would keep
          // granting members a second way in.
          const { opId } = await ctx.runMutation(internal.panelWrites.requestSquadUpdate, {
            backendServerId: sid,
            squadUuid: group.groupUuid,
            inboundUuids: [transportUuid],
          });
          const r = await ctx.runAction(internal.panelWrites.run, { opId });
          if (r.open) {
            await finish('pending', 'servers.op_running', 'groups');
            return null;
          }
        }
        m.groupUuid = group.groupUuid;
        await save();
      }

      // 6. Placements: each group into its mode's pool; an unknown mode is recorded, not bound.
      await record({ step: 'placements' });
      const patch: Record<string, { addSquadUuids: string[] }> = {};
      for (const m of modes) {
        if (c.snapshot.knownModes.includes(m.slug)) {
          patch[m.slug] = { addSquadUuids: [m.groupUuid!] };
          m.placement = 'bound';
        } else m.placement = 'skipped';
      }
      if (Object.keys(patch).length > 0)
        await ctx.runMutation(internal.connectionModes.setModePlacements, {
          backend: c.server.backend,
          patch: { modes: patch },
        });
      await save();

      // 7. Subscription templates: reconcile on drift; a refused write blocks activation later.
      await record({ step: 'templates' });
      if (!(await writable('templates'))) return null;
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
      await record({ modes }).catch(() => undefined);
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
  profileName: string,
  modes: readonly ModeTemplateInput[],
  obligationId: Id<'panelObligations'>,
  ctx: ActionCtx,
): Promise<'created' | 'refused' | 'unresolved'> {
  const mark = (
    state: 'sent' | 'unresolved' | 'confirmed' | 'failed',
    extra: { resourceRef?: string; code?: string } = {},
  ) => ctx.runMutation(internal.panelObligations.mark, { id: obligationId, state, ...extra });
  const keys = Object.fromEntries(
    modes
      .filter((m) => m.shape.transport !== 'ws')
      .map((m) => [
        m.slug,
        { privateKey: generateRealityKey().privateKey, shortIds: PROFILE_DEFAULTS.shortIds },
      ]),
  );
  const body = buildProfile(modes, keys);
  await mark('sent');
  try {
    const made = await writes.createProfile(config, { name: profileName, config: body });
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
        modes: [],
        templates: [],
        privacy: null,
        originDns: null,
        adopted: false,
        updatedAt: null,
      };
    return {
      exists: true,
      state: row.state,
      step: row.step ?? null,
      code: row.code ?? null,
      generation: row.generation,
      running: !!row.claim && row.claim.expiresAt > Date.now(),
      profile: { name: row.profileName, uuid: row.profileUuid ?? null },
      modes: modesOf(row).map((m) => ({
        slug: m.slug,
        name: m.name,
        shape: m.shape,
        familySlug: m.familySlug ?? null,
        tag: m.tag,
        group: { uuid: m.groupUuid ?? null, renamedFrom: m.renamedFrom ?? null },
        placement: m.placement,
        transport: m.transport
          ? {
              port: m.transport.port,
              path: m.transport.path ?? null,
              serverNames: m.transport.serverNames ?? [],
              target: m.transport.target
                ? `${m.transport.target.address}:${m.transport.target.port}`
                : null,
            }
          : null,
        family: m.family,
      })),
      templates: row.templates.map((t) => ({ family: t.family, state: t.state })),
      privacy: row.privacy ?? null,
      originDns: row.originDns
        ? { accountId: row.originDns.accountId, zoneName: row.originDns.zoneName }
        : null,
      adopted: row.adopted === true,
      updatedAt: new Date(row.updatedAt).toISOString(),
    };
  },
});

/** Whether a setup row can serve node intents: ready, with every mode's transport and group. */
export function setupReady(row: SetupRow | null): row is Setup {
  return (
    !!row &&
    row.state === 'ready' &&
    !!row.profileUuid &&
    // A row from before modes is not set up: the operator sets the backend up
    // again (which adopts what is there) and the migration removes the row.
    !!row.modes &&
    row.modes.length > 0 &&
    row.modes.every((m) => !!m.transport && !!m.groupUuid)
  );
}

/** The setup row a node intent reads its transports and origin zone from; null until ready. */
export const readyFor = internalQuery({
  args: { backendServerId: v.id('backendServers') },
  handler: async (ctx, { backendServerId }) => {
    const row = await setupRow(ctx, backendServerId);
    return setupReady(row) ? row : null;
  },
});

// --- the one-shot migration off contract v1 ---------------------------------------------------------

/**
 * ONE-SHOT operator migration for the modes release (run once per deployment,
 * right after the deploy; docs/servers.md "Moving to modes"):
 *
 *  - `panelHandoff` rows go: the v1 role's declaration means nothing now.
 *  - A v1 reservation on a `panelOwnership` row is settled to `owned`: no role
 *    holds one any more (contract v1 is gone), and nothing may stay reserved.
 *  - A `panelSetups` row written before modes is removed with everything it
 *    fenced (its intents, their activation runs, retirements, obligations and
 *    holds). Such a row describes three fixed inbounds and squads, a shape
 *    that no longer exists; the operator sets the backend up again, which
 *    ADOPTS what is there, and adopts each live node. Nothing on the backend
 *    and nothing a member holds is touched here: these are FCP's own rows.
 *  - A `panelNodeIntents` row with no mode goes the same way even where its
 *    setup row is current (it was enrolled by purpose).
 *
 * Idempotent: a second run finds nothing. Once every deployment has run it,
 * the TRANSITIONAL fields in schema.ts go (see the notes there).
 */
export const migrateContractV2 = internalMutation({
  args: {},
  handler: async (ctx) => {
    let handoffs = 0;
    for (const h of await ctx.db.query('panelHandoff').collect()) {
      await ctx.db.delete(h._id);
      handoffs++;
    }
    let reservations = 0;
    for (const o of await ctx.db.query('panelOwnership').collect()) {
      if (o.state !== 'reserved' && !o.reservation) continue;
      await ctx.db.patch(o._id, {
        ...(o.state === 'reserved' ? { state: 'owned' as const } : {}),
        reservation: undefined,
        updatedAt: Date.now(),
      });
      reservations++;
    }
    const dropIntent = async (id: Id<'panelNodeIntents'>) => {
      for (const r of await ctx.db
        .query('panelActivationRuns')
        .withIndex('by_intent', (q) => q.eq('intentId', id))
        .collect())
        await ctx.db.delete(r._id);
      const intent = await ctx.db.get(id);
      if (intent?.retirementId) await ctx.db.delete(intent.retirementId);
      await ctx.db.delete(id);
    };
    const legacySetups = (await ctx.db.query('panelSetups').collect()).filter((r) => !r.modes);
    const legacyServers = new Set(legacySetups.map((r) => r.backendServerId));
    let intents = 0;
    for (const i of await ctx.db.query('panelNodeIntents').collect()) {
      if (i.mode !== undefined && !legacyServers.has(i.backendServerId)) continue;
      await dropIntent(i._id);
      intents++;
    }
    for (const sid of legacyServers) {
      for (const h of await ctx.db
        .query('panelMaintenanceHolds')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .collect())
        await ctx.db.delete(h._id);
      for (const o of (await ctx.db.query('panelObligations').collect()).filter(
        (o) => o.backendServerId === sid,
      ))
        await ctx.db.delete(o._id);
    }
    for (const r of legacySetups) await ctx.db.delete(r._id);
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'servers.contract.migrated',
      targetType: 'system',
      payload: { handoffs, reservations, setups: legacySetups.length, intents },
    });
    return { handoffs, reservations, setups: legacySetups.length, intents };
  },
});
