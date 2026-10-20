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
 *
 * Once a backend is ready, the sweep runs the templates step alone whenever
 * its templates are not what FCP ships, and hourly to catch a change made on
 * the backend (`resyncTemplates`): a release that changes a template reaches
 * every backend without a new setup.
 *
 * A backend FCP has set up (or adopted) is CHANGED, never set up afresh
 * (`checkChange`): what its nodes and members rely on stays, the origin-name
 * zone changes in place, and an added mode runs the setup again.
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
import { CLAIM_LEASE_MS, claimAvailable, desiredHashOf, fenceHolds } from './lib/backend/fencing';
import { callResultOf, classifyRequest } from './lib/backend/ops';
import { checkProfileCompatibility, type EffectiveTransport } from './lib/backend/profileCompat';
import {
  PROFILE_DEFAULTS,
  buildProfile,
  checkModeDefinitions,
  isReality,
  transportTagOf,
  type ModeShape,
  type ModeTemplateInput,
} from './lib/backend/profileTemplate';
import { generateRealityKey } from './lib/backend/realityKeys';
import {
  SUBSCRIPTION_TEMPLATES,
  TEMPLATE_FAMILIES,
  desiredTemplateBody,
  shippedTemplateHashes,
  stageShippedTemplates,
  templateDrift,
  templateHash,
  templatesOutdated,
} from './lib/backend/subscriptionTemplates';
import { resolveServerConfig } from './lib/serverConfig';
import { observeInstance } from './backendObserve';

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

/** What a mode is set up as: everything a node of it and its members rely on. */
const definitionOf = (m: {
  name: string;
  shape: ModeShape;
  familySlug?: string;
  acceptProxyProtocol: boolean;
  ws?: { path: string; port: number };
}) =>
  JSON.stringify([
    m.name,
    m.shape.transport,
    m.shape.fronting,
    m.familySlug ?? null,
    m.acceptProxyProtocol,
    m.ws?.path ?? null,
    m.ws?.port ?? null,
  ]);

/**
 * The mode entries a new generation starts with. A mode already set up as it
 * is keeps what was found for it (its transport, group, placement and
 * family) while the run looks again, so its nodes are read the same
 * meanwhile; any other mode starts from its definition only.
 */
function freshModes(input: SetupInput, prev: readonly SetupMode[] = []): SetupMode[] {
  return input.modes.map((m) => {
    const before = prev.find((p) => p.slug === m.slug);
    const kept = before && definitionOf(before) === definitionOf(m) ? before : null;
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
      placement: kept?.placement ?? 'pending',
      transport: kept?.transport,
      family: kept?.family ?? (isReality(m.shape) ? 'unbound' : 'none'),
    };
  });
}

/**
 * Whether FCP is this backend's writer: it set the backend up (the row has
 * been ready) or an admin adopted it. The nodes and addresses such a backend
 * has are FCP's own (enrolled, added from here) or are handled one node at a
 * time (Adopt as an enrolled node, holds), and no setup step touches a node or
 * an address, so a change of its setup asks for no adoption. A row that never
 * got to ready proves nothing: what is on the backend may be anybody's.
 */
export function fcpWrites(row: SetupRow | null): boolean {
  return !!row && (row.adopted || row.state === 'ready' || row.readyAt !== undefined);
}

/** A cached profile in the shape the compatibility check reads. */
function observedProfile(p: Doc<'panelProfiles'>) {
  return {
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
      xhttp: i.network === 'xhttp' ? { path: i.path ?? null, host: null, mode: null } : undefined,
    })),
  };
}

type OriginDns = Setup['originDns'];
type Change = { kind: 'none' } | { kind: 'origin' } | { kind: 'modes'; added: ModeInput[] };

/**
 * What a new setup request changes on a backend FCP writes (docs/servers.md
 * "Changing a backend's setup"), refused when it would move something a node
 * or a member relies on. Nodes run the profile, and members hold each mode's
 * transport, group and family, so the profile name and every mode already set
 * up (its group name, shape, family, PROXY protocol, WebSocket path and port)
 * stay exactly as they are; such a mode is never removed. A mode that never
 * got its transport and group (a run that added it stopped) is not set up:
 * it may be changed or taken out again. The origin-name zone may change while
 * no node has a name in it (another account holding the same zone is always
 * fine). A mode may be added once the profile has a usable transport for it
 * (Add a transport), checked here against the last look at the backend, and
 * again by the run.
 */
async function checkChange(
  ctx: { db: QueryCtx['db'] },
  row: SetupRow,
  input: SetupInput,
  originDns: OriginDns,
): Promise<Change> {
  const prev = JSON.parse(row.desired) as SetupInput;
  if (input.profileName !== prev.profileName)
    refuse(
      'servers.setup_profile_kept',
      `This backend keeps its profile ${prev.profileName}: its nodes run it`,
    );
  const setUp = new Set(row.modes.filter((m) => m.transport && m.groupUuid).map((m) => m.slug));
  for (const p of prev.modes) {
    if (!setUp.has(p.slug)) continue;
    const next = input.modes.find((m) => m.slug === p.slug);
    if (!next || definitionOf(next) !== definitionOf(p))
      refuse(
        `servers.setup_mode_kept:${p.slug}`,
        `Mode ${p.name} stays as it is set up: nodes and members rely on it. Add a new mode instead`,
      );
  }
  const before = row.originDns ?? null;
  if (before && before.zoneId !== originDns?.zoneId) {
    const named = (
      await ctx.db
        .query('panelNodeIntents')
        .withIndex('by_server_name', (q) => q.eq('backendServerId', row.backendServerId))
        .collect()
    ).some((i) => i.state !== 'retired' && i.settings.originHostnameSource === 'managed');
    if (named)
      refuse(
        'servers.origin_zone_in_use',
        `WebSocket nodes have origin names under ${before.zoneName}. Keep that zone, or retire them first`,
      );
  }
  // The modes as a set (another order changes nothing).
  const modesKey = (ms: readonly ModeInput[]) =>
    JSON.stringify(
      [...ms].sort((x, y) => x.slug.localeCompare(y.slug)).map((m) => [m.slug, definitionOf(m)]),
    );
  const added = input.modes.filter((m) => !setUp.has(m.slug));
  if (modesKey(input.modes) !== modesKey(prev.modes)) {
    // A run would find every set-up mode as it is, and stops at one whose
    // group drifted on the backend: said now, from the last look.
    const groups = await ctx.db
      .query('panelSquads')
      .withIndex('by_server', (q) => q.eq('backendServerId', row.backendServerId))
      .collect();
    for (const m of row.modes) {
      if (!setUp.has(m.slug)) continue;
      const g = groups.find((x) => x.squadUuid === m.groupUuid);
      if (!g || g.inboundUuids.join() !== m.transport!.uuid)
        refuse(
          `servers.setup_mode_drifted:${m.slug}`,
          `The group of mode ${m.name} changed on the backend. Look at it under Mode groups first`,
        );
    }
    const cached = row.profileUuid
      ? await ctx.db
          .query('panelProfiles')
          .withIndex('by_server_uuid', (q) =>
            q.eq('backendServerId', row.backendServerId).eq('profileUuid', row.profileUuid!),
          )
          .unique()
      : null;
    if (cached) {
      const compat = checkProfileCompatibility(observedProfile(cached), added);
      if (!compat.ok)
        refuse(
          `servers.setup_transport_missing:${compat.issue.tag}:${compat.issue.field}`,
          `The profile has no usable transport ${compat.issue.tag} for the new mode yet. Add it first`,
        );
    }
    return { kind: 'modes', added };
  }
  const zoneKey = (z: OriginDns) => (z ? `${z.accountId}|${z.zoneId}|${z.zoneName}` : null);
  return zoneKey(before) !== zoneKey(originDns) ? { kind: 'origin' } : { kind: 'none' };
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
    if (!capabilitiesOf(server.backend).backendSetup)
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
    // A backend with nodes or addresses on it is adopted, never quietly set
    // up; one FCP already writes has nothing left to adopt (`fcpWrites`).
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
    const writer = fcpWrites(row);
    if (existing && !input.adopt && !writer)
      refuse(
        'servers.adopt_required',
        'This backend already has nodes or addresses. Adopt it (typed) to make FCP its writer',
      );
    const desiredHash = await desiredHashOf(input);
    const now = Date.now();
    if (row && !claimAvailable(row, now))
      refuse('servers.setup_running', 'The backend is being set up right now');
    // A backend FCP writes is changed, never set up afresh.
    const change =
      row && writer && row.desiredHash !== desiredHash
        ? await checkChange(ctx, row, input, originDns)
        : null;
    if (row && change && change.kind !== 'none')
      await writeAuditLog(ctx, {
        actorType: 'admin',
        actorId: a.actorAdminId ?? undefined,
        action: 'servers.setup.changed',
        targetType: 'backend_server',
        targetId: sid,
        payload: {
          backendSlug: server.slug,
          generation: row.generation + 1,
          change: change.kind,
          originZone: originDns?.zoneName ?? null,
          addedModes: change.kind === 'modes' ? change.added.map((m) => m.slug).join(',') : '',
        },
      });
    if (row && change?.kind === 'origin' && row.state === 'ready') {
      // Only the origin-name zone: no step of the setup reads it, so nothing on
      // the backend is looked at or written and the row stays ready. Nodes
      // read it when they are next reconciled.
      await ctx.db.patch(row._id, {
        desired: JSON.stringify(input),
        desiredHash,
        generation: row.generation + 1,
        originDns,
        readyAt: row.readyAt ?? now,
        updatedAt: now,
      });
      await ctx.scheduler.runAfter(0, internal.nodeIntents.afterSetupReady, {
        backendServerId: sid,
      });
      return {
        setupId: row._id,
        generation: row.generation + 1,
        state: 'ready' as const,
        started: false,
      };
    }
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
    } else if (row.desiredHash !== desiredHash && change?.kind !== 'none') {
      await ctx.db.patch(row._id, {
        desired: JSON.stringify(input),
        desiredHash,
        generation: row.generation + 1,
        state: 'pending',
        step: undefined,
        code: undefined,
        profileName: input.profileName,
        modes: freshModes(input, row.modes),
        originDns,
        // Nodes FCP enrolled on a backend it writes do not make it adopted.
        adopted: row.adopted || (existing && !writer),
        readyAt: row.readyAt ?? (row.state === 'ready' ? now : undefined),
        updatedAt: now,
      });
      row = (await ctx.db.get(row._id))!;
    } else if (row.state === 'ready' && !setupNeedsRefresh(row)) {
      // The same setup, or a change that changes nothing (the modes in another order).
      return { setupId: row._id, generation: row.generation, state: row.state, started: false };
    }
    const attemptId = crypto.randomUUID();
    await ctx.db.patch(row._id, {
      claim: { attemptId, expiresAt: now + CLAIM_LEASE_MS },
      state: 'pending',
      code: undefined,
      readyAt: row.readyAt ?? (row.state === 'ready' ? now : undefined),
      updatedAt: now,
    });
    await ctx.scheduler.runAfter(0, internal.backendSetup.run, {
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
    row.modes.some((m) => m.placement !== 'bound' || m.family === 'unbound' || !m.transport)
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
  for (const m of row.modes) {
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
      profiles: profiles.map(observedProfile),
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
  templatesCheckedAt: v.optional(v.number()),
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
    const now = Date.now();
    await ctx.db.patch(f.setupId, {
      state,
      code,
      ...(step !== undefined ? { step } : {}),
      // From the first ready on, FCP is this backend's writer (`fcpWrites`).
      ...(state === 'ready' && row.readyAt === undefined ? { readyAt: now } : {}),
      claim: undefined,
      updatedAt: now,
    });
    // Nodes kept waiting while the setup ran (and, with a zone, WebSocket
    // nodes waiting for an origin name) go on now, never before.
    if (state === 'ready')
      await ctx.scheduler.runAfter(0, internal.nodeIntents.afterSetupReady, {
        backendServerId: row.backendServerId,
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

// --- the run ------------------------------------------------------------------------------------------

type Loaded = NonNullable<Awaited<ReturnType<typeof loadSetupContext>>>;
async function loadForRunHandler(ctx: ActionCtx, f: Fence): Promise<Loaded | null> {
  return (await ctx.runQuery(internal.backendSetup.loadForRun, f)) as Loaded | null;
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
      ctx.runMutation(internal.backendSetup.recordStep, { ...f, patch });
    const finish = (state: 'pending' | 'ready' | 'failed', code?: string, step?: string) =>
      ctx.runMutation(internal.backendSetup.finish, { ...f, state, code, step });
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
    const writes = provider.backendWrites;
    if (!writes) {
      await finish('failed', 'servers.unsupported_backend');
      return null;
    }
    const config = c.server.config as BackendConfig;
    const input = c.input;
    let modes: SetupMode[] = c.row.modes.map((m) => ({ ...m }));
    const save = () => record({ modes });
    // On a backend FCP writes, the modes already set up are only looked at:
    // nodes and members rely on their groups and placements, so this run never
    // writes them (a group that drifted stops it instead). Everything else
    // (a first setup, an adoption, a mode added) is made or repaired.
    const established = new Set(
      c.row.readyAt !== undefined
        ? c.row.modes
            .filter((m) => m.transport && m.groupUuid && m.placement === 'bound')
            .map((m) => m.slug)
        : [],
    );
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
        const blocking = await ctx.runQuery(internal.backendObligations.blockingFor, {
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
        const opened = await ctx.runMutation(internal.backendObligations.open, {
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
          await ctx.runMutation(internal.backendObligations.mark, {
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
        if (established.has(m.slug)) {
          const kept = c.snapshot.groups.find((g) => g.groupUuid === m.groupUuid);
          if (!kept || kept.transportUuids.join() !== transportUuid) {
            await save();
            await finish('failed', `servers.setup_mode_drifted:${m.slug}`, 'groups');
            return null;
          }
          continue;
        }
        let group =
          c.snapshot.groups.find((g) => g.name === m.name) ??
          (m.groupUuid ? c.snapshot.groups.find((g) => g.groupUuid === m.groupUuid) : undefined) ??
          null;
        if (!group) {
          const legacy = (LEGACY_GROUP_NAMES[m.slug] ?? [])
            .map((n) => c.snapshot.groups.find((g) => g.name === n))
            .find((g) => !!g);
          if (legacy) {
            const { opId } = await ctx.runMutation(internal.backendWrites.requestModeGroupUpdate, {
              backendServerId: sid,
              squadUuid: legacy.groupUuid,
              name: m.name,
            });
            const r = await ctx.runAction(internal.backendWrites.run, { opId });
            if (r.open) {
              await finish('pending', 'servers.op_running', 'groups');
              return null;
            }
            await ctx.runMutation(internal.backendSetup.recordGroupRename, {
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
          const { opId } = await ctx.runMutation(internal.backendWrites.requestModeGroupCreate, {
            backendServerId: sid,
            name: m.name,
            inboundUuids: [transportUuid],
          });
          const r = await ctx.runAction(internal.backendWrites.run, { opId });
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
          const { opId } = await ctx.runMutation(internal.backendWrites.requestModeGroupUpdate, {
            backendServerId: sid,
            squadUuid: group.groupUuid,
            inboundUuids: [transportUuid],
          });
          const r = await ctx.runAction(internal.backendWrites.run, { opId });
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
        if (established.has(m.slug)) continue;
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
      const reconciled = await reconcileTemplates(writes, config, () => writable('templates'));
      if (!reconciled) return null;
      await record({ templates: reconciled.templates, templatesCheckedAt: Date.now() });

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
  writes: NonNullable<(typeof PROVIDERS)[keyof typeof PROVIDERS]['backendWrites']>,
  config: BackendConfig,
  profileName: string,
  modes: readonly ModeTemplateInput[],
  obligationId: Id<'backendObligations'>,
  ctx: ActionCtx,
): Promise<'created' | 'refused' | 'unresolved'> {
  const mark = (
    state: 'sent' | 'unresolved' | 'confirmed' | 'failed',
    extra: { resourceRef?: string; code?: string } = {},
  ) => ctx.runMutation(internal.backendObligations.mark, { id: obligationId, state, ...extra });
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

// --- subscription templates ---------------------------------------------------------------------------

type BackendWrites = NonNullable<(typeof PROVIDERS)[keyof typeof PROVIDERS]['backendWrites']>;
type TemplateRecord = SetupRow['templates'][number];
const templateRecord = v.object({
  family: v.string(),
  hash: v.string(),
  state: v.union(v.literal('matched'), v.literal('drifted'), v.literal('refused')),
});

/**
 * Install every template FCP ships that the backend has, where the live one
 * differs: what each ended as, under the hash of what FCP ships, and the
 * families the backend accepted a write for. `mayWrite` is asked before every
 * write: when it says no, nothing more is written and the answer is null.
 */
async function reconcileTemplates(
  writes: BackendWrites,
  config: BackendConfig,
  mayWrite: () => Promise<boolean>,
): Promise<{ templates: TemplateRecord[]; written: string[] } | null> {
  const listed = await writes.listSubscriptionTemplates(config);
  const templates: TemplateRecord[] = [];
  const written: string[] = [];
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
    if (!(await mayWrite())) return null;
    try {
      await writes.updateSubscriptionTemplate(config, ref.uuid, desiredTemplateBody(desired));
      written.push(family);
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
  return { templates, written };
}

/** How often a ready backend's live templates are looked at even when the record says matched. */
export const TEMPLATE_RECHECK_MS = 60 * 60_000;

/**
 * Whether a ready row's templates are due: not matched at what FCP ships, or
 * not looked at live for an hour (a backend upgrade or an edit on the backend
 * changes them without FCP seeing it).
 */
function templatesDueNow(row: SetupRow, shipped: Record<string, string>, now: number): boolean {
  return (
    templatesOutdated(row.templates, shipped) ||
    now - (row.templatesCheckedAt ?? 0) >= TEMPLATE_RECHECK_MS
  );
}

const templatesKey = (ts: readonly TemplateRecord[]) =>
  ts.map((t) => `${t.family}:${t.hash}:${t.state}`).join(',');

/** Ready backends whose templates are due, with no attempt holding them. */
export const templatesDue = internalQuery({
  args: { now: v.number() },
  handler: async (ctx, { now }): Promise<Id<'panelSetups'>[]> => {
    const shipped = await shippedTemplateHashes();
    return (await ctx.db.query('panelSetups').collect())
      .filter(
        (s) => s.state === 'ready' && claimAvailable(s, now) && templatesDueNow(s, shipped, now),
      )
      .map((s) => s._id);
  },
});

/**
 * Take a ready backend's setup lease for one template re-sync: a setup run
 * cannot start meanwhile (`servers.setup_running`), and the row stays ready.
 * A template FCP ships differently is recorded under its new hash, not
 * matched, BEFORE anything is written: the review hash moves and activation
 * holds (`servers.template_drifted`) until the outcome is recorded, so no node
 * is approved or goes live against the old template while the write is in
 * flight.
 */
export const claimTemplates = internalMutation({
  args: { setupId: v.id('panelSetups') },
  handler: async (
    ctx,
    { setupId },
  ): Promise<{ fence: Fence; backend: string; config: unknown } | null> => {
    const row = await ctx.db.get(setupId);
    const now = Date.now();
    if (!row || row.state !== 'ready' || !claimAvailable(row, now)) return null;
    const shipped = await shippedTemplateHashes();
    if (!templatesDueNow(row, shipped, now)) return null;
    const server = await ctx.db.get(row.backendServerId);
    if (!server) return null;
    const attemptId = crypto.randomUUID();
    await ctx.db.patch(setupId, {
      templates: stageShippedTemplates(row.templates, shipped),
      claim: { attemptId, expiresAt: now + CLAIM_LEASE_MS },
      updatedAt: now,
    });
    return {
      fence: { setupId, generation: row.generation, attemptId },
      backend: server.backend,
      config: server.config,
    };
  },
});

/**
 * Record a template re-sync (fenced) and release the lease. No answer from the
 * backend, or server changes switched off on the way, records nothing: what
 * the claim staged stays, and the next sweep tries again.
 */
export const finishTemplates = internalMutation({
  args: {
    ...fence,
    templates: v.optional(v.array(templateRecord)),
    written: v.optional(v.array(v.string())),
  },
  handler: async (ctx, { templates, written = [], ...f }) => {
    const row = await ctx.db.get(f.setupId);
    if (!row || !fenceHolds(row, f)) return null;
    const now = Date.now();
    await ctx.db.patch(f.setupId, {
      ...(templates ? { templates, templatesCheckedAt: now } : {}),
      claim: undefined,
      updatedAt: now,
    });
    // Audited when something was written or the outcome moved, so a write the
    // backend keeps refusing is not logged every sweep.
    if (
      templates &&
      (written.length > 0 || templatesKey(templates) !== templatesKey(row.templates))
    ) {
      const server = await ctx.db.get(row.backendServerId);
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'servers.setup.templates_installed',
        targetType: 'backend_server',
        targetId: row.backendServerId,
        payload: {
          backendSlug: server?.slug ?? '',
          templates: templates.map((t) => `${t.family}:${t.state}`).join(','),
          written: written.join(','),
        },
      });
    }
    return null;
  },
});

/**
 * On `backend-bootstrap-sweep`: keep every set-up backend's subscription
 * templates on what FCP ships. A backend is due when a template is not matched
 * at today's hash (a release changed one, or an earlier write failed), and
 * hourly otherwise, since the backend can change them without FCP seeing it.
 * Only the templates step runs, never the rest of the setup, and only what
 * differs is written. With server changes switched off it writes nothing; the
 * switch is read again before every write.
 */
export const resyncTemplates = internalAction({
  args: {},
  handler: async (ctx): Promise<number> => {
    const due: Id<'panelSetups'>[] = await ctx.runQuery(internal.backendSetup.templatesDue, {
      now: Date.now(),
    });
    const mayWrite = (): Promise<boolean> => ctx.runQuery(internal.serverAdmin.manageEnabled, {});
    let done = 0;
    for (const setupId of due) {
      if (!(await mayWrite())) break;
      const claimed = (await ctx.runMutation(internal.backendSetup.claimTemplates, {
        setupId,
      })) as { fence: Fence; backend: string; config: unknown } | null;
      if (!claimed) continue;
      const writes = PROVIDERS[claimed.backend as keyof typeof PROVIDERS]?.backendWrites;
      let reconciled: { templates: TemplateRecord[]; written: string[] } | null = null;
      try {
        if (writes)
          reconciled = await reconcileTemplates(writes, claimed.config as BackendConfig, mayWrite);
      } catch {
        // The list or a read went unanswered: the next sweep tries again.
      }
      await ctx.runMutation(internal.backendSetup.finishTemplates, {
        ...claimed.fence,
        templates: reconciled?.templates,
        written: reconciled?.written,
      });
      if (reconciled) done++;
    }
    return done;
  },
});

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
        established: false,
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
      modes: row.modes.map((m) => ({
        slug: m.slug,
        name: m.name,
        shape: m.shape,
        familySlug: m.familySlug ?? null,
        acceptProxyProtocol: m.acceptProxyProtocol,
        ws: m.ws ?? null,
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
      adopted: row.adopted,
      established: fcpWrites(row),
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
    row.modes.length > 0 &&
    row.modes.every((m) => !!m.transport && !!m.groupUuid)
  );
}
