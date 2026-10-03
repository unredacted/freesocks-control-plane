/**
 * Admin HTTP surface for server management: `/api/v1/admin/servers/*`. Same
 * shape as the edges surface (one prefix route per verb feeding a dispatcher,
 * so the HPKE policy is a clean per-verb prefix rule in envelope.ts): GET
 * reveals, POST seals both legs, PATCH seals the body. The responses carry node
 * and Host addresses, the same class of data the edges routes seal.
 *
 * Scopes: `admin:settings:*` for `config`, `admin:servers:read` for every
 * other route here. This surface is READ-ONLY toward the backend: `refresh`
 * re-reads one backend (throttled, it is the only route that makes a backend call)
 * and `placements/validate` only computes over stored rows.
 *
 * `{slug}` is the backend server's slug. Responses are the shapes in
 * src/shared/contracts/servers.ts.
 */
import type { HttpRouter } from 'convex/server';
import { httpAction } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import type { Id } from './_generated/dataModel';
import { internal } from './_generated/api';
import {
  makeFail,
  nodeWithinBoundary,
  notFound,
  registrationBoundaryOf,
  throttle,
  unauth,
} from './lib/adminHttp';
import { sealed } from './lib/hpke';
import { errorJson, json, readJson, resolveAdmin, type AdminAuth } from './lib/http';
import type { z } from 'zod';
import {
  AddressPatch,
  AddressWrite,
  BackendSetupInput,
  DirectTestConfirm,
  ModeGroupPatch,
  ModeGroupWrite,
  NodeAppliedReport,
  NodeRegistration,
  ProfilePatchApply,
  ProfilePatchPreviewRequest,
  type ProfilePatchOp,
  type ProfilePatchPreview,
} from '../src/shared/contracts/servers';
import { findLegacyField, LEGACY, type LegacySpec } from './lib/legacyFields';
import type { PatchOp } from './lib/backend/patchOps';
import type { ProfilePatchPreviewView } from './backendWrites';

const PREFIX = '/api/v1/admin/servers/';

type Handler = (
  ctx: ActionCtx,
  parts: string[],
  admin: AdminAuth,
  body: Record<string, unknown>,
  query: URLSearchParams,
) => Promise<Response>;

function statusFromCode(code: string): number {
  if (code === 'not_found') return 404;
  if (code === 'servers.manage_disabled') return 403;
  // The backend could not be read: an upstream fault, not a refusal.
  if (code === 'backend.panel_read_failed') return 502;
  if (code === 'conflict' || code.startsWith('servers.')) return 409;
  return 400;
}

const fail = makeFail('servers', statusFromCode);

/** POSTs that read or compute only: the read scope, like every GET. */
function isReadOnlyPost(parts: string[]): boolean {
  if (parts.length === 2 && parts[1] === 'refresh') return true;
  if (parts.length === 3 && parts[1] === 'placements' && parts[2] === 'validate') return true;
  // A preview reads the profile and computes; it writes nothing.
  if (parts.length === 4 && parts[1] === 'profiles' && parts[3] === 'preview') return true;
  // Looking at the backend again for an open op changes nothing on the backend.
  return parts.length === 4 && parts[1] === 'ops' && parts[3] === 'observe';
}

/**
 * `config` is a settings surface. Reads need `admin:servers:read`. A WRITE to a
 * backend needs `admin:servers:manage`, which is deliberately not
 * `admin:servers:write`: the node role's token holds that one. The role's
 * handoff report is the one write it may make here (it changes no backend).
 */
/** `{slug}/nodes/by-name/{name}[/verb]`: the node role's own routes (docs/servers.md "Node lifecycle"). */
export function isByNameRoute(parts: string[]): boolean {
  return parts.length >= 4 && parts[1] === 'nodes' && parts[2] === 'by-name' && !!parts[3];
}

export function scopeFor(parts: string[], method: string): string | string[] {
  // Exactly `/config`: a longer path starting with `config` is a backend slug's
  // route and takes that route's own scope, never the settings one.
  if (parts.length === 1 && parts[0] === 'config')
    return method === 'GET' ? 'admin:settings:read' : 'admin:settings:write';
  // The role's routes: its fleet token, or a register token confined to its boundary.
  if (isByNameRoute(parts))
    return method === 'GET'
      ? ['admin:servers:read', 'admin:edges:register', 'admin:servers:manage']
      : ['admin:servers:write', 'admin:edges:register', 'admin:servers:manage'];
  if (method === 'GET' || (method === 'POST' && isReadOnlyPost(parts))) return 'admin:servers:read';
  return 'admin:servers:manage';
}

function segments(req: Request): string[] | null {
  const url = new URL(req.url);
  const rest = url.pathname.startsWith(PREFIX) ? url.pathname.slice(PREFIX.length) : '';
  try {
    return rest.split('/').filter(Boolean).map(decodeURIComponent);
  } catch {
    return null;
  }
}

function wrap(handler: Handler, sealedRoute: boolean) {
  const inner = async (ctx: ActionCtx, req: Request): Promise<Response> => {
    const parts = segments(req);
    if (!parts) return errorJson('validation', 'Malformed path encoding', 400);
    const method = req.method.toUpperCase();
    const admin = await resolveAdmin(ctx, req, scopeFor(parts, method));
    if (!admin) return unauth();
    // Whatever reaches a backend is throttled per actor: reads and writes apart.
    const readOnly = method === 'GET' || (method === 'POST' && isReadOnlyPost(parts));
    // Of the role's routes only `bootstrap` reaches the backend (the node secret);
    // enrollment and reports are records, reconciled from FCP's own actions.
    const byName = isByNameRoute(parts);
    const reachesPanel = readOnly
      ? method === 'POST' && parts[1] !== 'placements'
      : byName
        ? parts[4] === 'bootstrap'
        : parts[0] !== 'config' && parts[3] !== 'acknowledge';
    if (reachesPanel) {
      const limited = await throttle(
        ctx,
        req,
        admin,
        readOnly ? 'admin.servers.panel-read' : 'admin.servers.panel-write',
      );
      if (limited) return limited;
    }
    let body: Record<string, unknown> = {};
    if (method !== 'GET' && method !== 'DELETE')
      body = await readJson<Record<string, unknown>>(req);
    try {
      if (byName) return await byNameHandler(ctx, parts, admin, body, method);
      return await handler(ctx, parts, admin, body, new URL(req.url).searchParams);
    } catch (err) {
      return fail(err);
    }
  };
  return sealedRoute ? sealed(inner) : httpAction(inner);
}

/**
 * The node role's routes on `{slug}/nodes/by-name/{name}`: PUT enrolls or
 * reports observations, GET reads the node's own view, POST bootstrap serves
 * the machine configuration and the node secret, POST applied and POST wiped
 * are the role's reports, DELETE asks for retirement. A register-scoped token
 * is confined to its boundary; nothing here is an admin decision.
 */
async function byNameHandler(
  ctx: ActionCtx,
  parts: string[],
  admin: AdminAuth,
  body: Record<string, unknown>,
  method: string,
): Promise<Response> {
  const [slug, , , name, verb, extra] = parts;
  if (!slug || !name || extra) return notFound();
  const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug });
  const boundary = await registrationBoundaryOf(
    ctx,
    admin,
    method === 'GET' ? 'admin:servers:read' : 'admin:servers:write',
  );
  if (!nodeWithinBoundary(boundary, instance.id, name))
    return errorJson('servers.registration_boundary', 'This token may not act for that node', 403);
  const view = async () => {
    const out = await ctx.runQuery(internal.nodeIntents.roleViewByName, {
      backendServerId: instance.id,
      name,
    });
    return out ? json(out) : notFound();
  };
  if (method === 'GET' && !verb) return view();
  if (method === 'PUT' && !verb) {
    const parsed = NodeRegistration.safeParse(body);
    if (!parsed.success) return errorJson('validation', 'The registration body is not usable', 400);
    await ctx.runMutation(internal.nodeIntents.enroll, {
      backendServerId: instance.id,
      name,
      label: parsed.data.label,
      mode: parsed.data.mode,
      contractVersion: parsed.data.roleContractVersion,
      observed: parsed.data.observed,
      tokenId: admin.tokenId ?? undefined,
    });
    return view();
  }
  if (method === 'DELETE' && !verb) {
    const intent = await ctx.runQuery(internal.nodeIntents.byName, {
      backendServerId: instance.id,
      name,
    });
    if (!intent) return notFound();
    await ctx.runMutation(internal.nodeIntents.requestRetirement, {
      intentId: intent._id,
      requestedBy: 'role',
    });
    return view();
  }
  if (method !== 'POST') return notFound();
  const intent = await ctx.runQuery(internal.nodeIntents.byName, {
    backendServerId: instance.id,
    name,
  });
  if (!intent) return notFound();
  if (verb === 'bootstrap') {
    // The one answer that carries a secret: never persisted by FCP, never audited.
    return json(await ctx.runAction(internal.nodeIntents.bootstrap, { intentId: intent._id }));
  }
  if (verb === 'applied') {
    const parsed = NodeAppliedReport.safeParse(body);
    if (!parsed.success) return errorJson('validation', 'The applied report is not usable', 400);
    await ctx.runMutation(internal.nodeIntents.applied, {
      intentId: intent._id,
      appliedRevision: parsed.data.appliedRevision,
      certificateReady: parsed.data.caddy?.certificateReady,
      nodeStarted: parsed.data.nodeStarted,
    });
    return view();
  }
  if (verb === 'wiped') {
    await ctx.runMutation(internal.nodeIntents.markWiped, { intentId: intent._id });
    return view();
  }
  return notFound();
}

const actorOf = (admin: AdminAuth) => ({ actorAdminId: admin.adminUserId ?? undefined });

/**
 * A write body, parsed. Obsolete renamed fields are refused BY NAME on the raw
 * input (zod would strip them silently), then the contract schema projects the
 * accepted fields. The internal mutations keep the stored names; the mapping
 * from the contract's words happens here, at the boundary.
 */
function parseWrite<T>(
  schema: z.ZodType<T>,
  body: unknown,
  legacy: LegacySpec,
): { ok: true; data: T } | { ok: false; res: Response } {
  const old = findLegacyField(body, legacy);
  if (old)
    return {
      ok: false,
      res: errorJson('validation', `${old} is no longer accepted (renamed in the admin API)`, 400),
    };
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    const where = parsed.error.issues[0]?.path.join('.') ?? '';
    return {
      ok: false,
      res: errorJson(
        'validation',
        `The request body is not usable${where ? `: ${where}` : ''}`,
        400,
      ),
    };
  }
  return { ok: true, data: parsed.data };
}

const toPatchOps = (ops: readonly ProfilePatchOp[]): PatchOp[] =>
  ops.map((o) =>
    o.op === 'setRealityServerNames'
      ? { op: o.op, inboundTag: o.transportTag, names: o.names }
      : { op: o.op, inboundTag: o.transportTag, target: o.target },
  );

/** The preview in the contract's words (`transport*`, never the backend's `inbound*`). */
function previewToContract(p: ProfilePatchPreviewView): ProfilePatchPreview {
  const { inboundUuids, changes, ops, ...rest } = p;
  return {
    ...rest,
    transportUuids: inboundUuids,
    changes: changes.map(({ inboundTag, ...c }) => ({ ...c, transportTag: inboundTag })),
    ops: ops.map((o) =>
      o.op === 'setRealityServerNames'
        ? { op: o.op, transportTag: o.inboundTag, names: o.names }
        : { op: o.op, transportTag: o.inboundTag, target: o.target },
    ),
  };
}

/** The mutation validated and claimed; now send once and look, and answer the op. */
async function runOp(ctx: ActionCtx, opId: Id<'panelOps'>) {
  await ctx.runAction(internal.backendWrites.run, { opId });
  return json(await ctx.runQuery(internal.backendLedger.view, { opId }));
}

/** An address write in the contract's words, as the internal mutation's (stored) field names. */
function hostFieldsOf(w: AddressPatch): Record<string, unknown> {
  const { transportUuid, ...rest } = w;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(rest)) if (v !== undefined) out[k] = v;
  if (transportUuid !== undefined) out.inboundUuid = transportUuid;
  return out;
}

const getHandler: Handler = async (ctx, parts) => {
  const [a, b, c] = parts;
  if (!a || (a === 'summary' && !b))
    return json(await ctx.runQuery(internal.serverAdmin.summary, {}));
  if (a === 'config' && !b) return json(await ctx.runQuery(internal.serverAdmin.configView, {}));
  if (b === 'tree' && !c) return json(await ctx.runQuery(internal.serverAdmin.tree, { slug: a }));
  if (a && b === 'ops' && !c) {
    const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
    return json({
      ops: await ctx.runQuery(internal.backendLedger.listForServer, {
        backendServerId: instance.id,
      }),
    });
  }
  if (a && b === 'setup' && !c) {
    const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
    return json(await ctx.runQuery(internal.backendSetup.view, { backendServerId: instance.id }));
  }
  // The enrolled nodes of an instance, and one node's review card.
  if (a && b === 'nodes' && c === 'intents' && !parts[4]) {
    const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
    return json({
      intents: await ctx.runQuery(internal.serverAdmin.intentsView, {
        backendServerId: instance.id,
      }),
      holds: await ctx.runQuery(internal.nodeIntents.holdsView, {
        backendServerId: instance.id,
      }),
    });
  }
  if (a && b === 'nodes' && c === 'intents' && parts[3] && parts[4] === 'review' && !parts[5]) {
    const intentId = await ctx.runQuery(internal.serverAdmin.intentOnServer, {
      slug: a,
      intentId: parts[3],
    });
    if (!intentId) return notFound();
    return json(await ctx.runQuery(internal.nodeActivation.review, { intentId }));
  }
  return notFound();
};

const postHandler: Handler = async (ctx, parts, admin, body) => {
  const [a, b, c, d] = parts;
  if (a && b === 'profiles' && c && d === 'acknowledge') {
    const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
    return json(
      await ctx.runMutation(internal.backendObserve.acknowledgeForeignEdit, {
        backendServerId: instance.id,
        profileUuid: c,
        ...actorOf(admin),
      }),
    );
  }
  if (a && b === 'profiles' && c && (d === 'preview' || d === 'apply')) {
    const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
    if (d === 'preview') {
      const w = parseWrite(ProfilePatchPreviewRequest, body, LEGACY.profilePreview);
      if (!w.ok) return w.res;
      const view = await ctx.runAction(internal.backendWrites.previewProfilePatch, {
        backendServerId: instance.id,
        profileUuid: c,
        ops: toPatchOps(w.data.ops),
      });
      return json(previewToContract(view));
    }
    // Apply takes what the preview answered, verbatim: the write is conditioned
    // on the profile still having THAT token.
    const w = parseWrite(ProfilePatchApply, body, LEGACY.profileApply);
    if (!w.ok) return w.res;
    const { opId } = await ctx.runMutation(internal.backendWrites.requestProfilePatch, {
      backendServerId: instance.id,
      profileUuid: c,
      ops: toPatchOps(w.data.ops),
      baseToken: w.data.baseToken,
      expectedToken: w.data.expectedToken,
      inboundUuids: w.data.transportUuids,
      unmanaged: w.data.unmanaged,
      ...actorOf(admin),
    });
    return runOp(ctx, opId);
  }
  // Adopting a node that already serves members, as it is (docs/servers.md "Adopting a backend").
  if (a && b === 'nodes' && c === 'adopt' && !d) {
    const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
    return json(
      await ctx.runMutation(internal.nodeIntents.adoptNode, {
        backendServerId: instance.id,
        nodeUuid: String(body.nodeUuid ?? ''),
        mode: String(body.mode ?? ''),
        externallyFronted: body.externallyFronted === true,
        ...actorOf(admin),
      }),
    );
  }
  // Releasing the hold a shared change put on nodes FCP does not manage.
  if (a && b === 'holds' && c && d === 'release')
    return json(
      await ctx.runMutation(internal.nodeIntents.releaseHold, {
        holdId: c as Id<'panelMaintenanceHolds'>,
        ...actorOf(admin),
      }),
    );
  // Node activation (docs/servers.md "Node lifecycle"): the isolated direct
  // test link, its bound confirmation, and the approval of a review. Before
  // the generic node writes: `nodes/intents/{id}/{verb}` is not a node uuid.
  if (a && b === 'nodes' && c === 'intents' && d) {
    const [, , , intentIdRaw, verb, extra] = parts;
    if (!verb || extra) return notFound();
    // The node must belong to the backend the path names.
    const intentId = await ctx.runQuery(internal.serverAdmin.intentOnServer, {
      slug: a,
      intentId: intentIdRaw ?? '',
    });
    if (!intentId) return notFound();
    if (verb === 'test-link') {
      const { link, binding } = await ctx.runAction(internal.nodeActivation.buildDirectTestLink, {
        intentId,
      });
      const { inboundUuid, ...rest } = binding;
      return json({ link, binding: { ...rest, transportUuid: inboundUuid } });
    }
    if (verb === 'confirm') {
      const w = parseWrite(DirectTestConfirm, body, LEGACY.directConfirm);
      if (!w.ok) return w.res;
      const { transportUuid, ...binding } = w.data.binding;
      return json(
        await ctx.runMutation(internal.nodeActivation.confirmDirect, {
          intentId,
          binding: { ...binding, inboundUuid: transportUuid },
          ...actorOf(admin),
        }),
      );
    }
    if (verb === 'approve')
      return json(
        await ctx.runMutation(internal.nodeActivation.approve, {
          intentId,
          reviewHash: String(body.reviewHash ?? ''),
          ...actorOf(admin),
        }),
      );
    if (verb === 'retire') {
      // With a disposition this is the admin's decision; without, a request.
      const disposition = body.disposition;
      if (disposition === 'keep-dark' || disposition === 'migrate')
        return json(
          await ctx.runMutation(internal.nodeRetirement.decide, {
            intentId,
            disposition,
            targetIntentId:
              typeof body.targetIntentId === 'string'
                ? (body.targetIntentId as Id<'panelNodeIntents'>)
                : undefined,
            ...actorOf(admin),
          }),
        );
      return json(
        await ctx.runMutation(internal.nodeIntents.requestRetirement, {
          intentId,
          requestedBy: 'admin',
        }),
      );
    }
    // A node FCP bootstrapped reports its own wipe (POST …/wiped, role token);
    // for an adopted node, whose machine the role never runs, an admin confirms
    // the machine is gone and the retirement closes.
    if (verb === 'wiped')
      return json(
        await ctx.runMutation(internal.nodeIntents.markWiped, {
          intentId,
          byAdminId: admin.adminUserId ?? undefined,
        }),
      );
    if (verb === 'maintenance')
      return json(
        await ctx.runMutation(internal.nodeIntents.finishMaintenance, {
          intentId,
          ...actorOf(admin),
        }),
      );
    if (verb === 'settings')
      return json(
        await ctx.runMutation(internal.nodeIntents.patchSettings, {
          intentId,
          patch: body.patch as never,
          maintenance: body.maintenance === true,
          ...actorOf(admin),
        }),
      );
    return notFound();
  }
  if (a && b === 'nodes') {
    const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
    if (!c) {
      const { opId } = await ctx.runMutation(internal.backendWrites.requestNodeCreate, {
        backendServerId: instance.id,
        name: String(body.name ?? ''),
        address: String(body.address ?? ''),
        port: typeof body.port === 'number' ? body.port : undefined,
        countryCode: typeof body.countryCode === 'string' ? body.countryCode : undefined,
        configProfileUuid: String(body.configProfileUuid ?? ''),
        activeInboundUuids: Array.isArray(body.activeInboundUuids)
          ? body.activeInboundUuids.map(String)
          : [],
        restore: body.restore === true,
        ...actorOf(admin),
      });
      return runOp(ctx, opId);
    }
    if (d === 'enable' || d === 'disable' || d === 'restart') {
      const { opId } = await ctx.runMutation(internal.backendWrites.requestNodeAction, {
        backendServerId: instance.id,
        nodeUuid: c,
        action: d,
        ...actorOf(admin),
      });
      return runOp(ctx, opId);
    }
    return notFound();
  }
  if (a && (b === 'addresses' || b === 'modeGroups' || b === 'ops')) {
    const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
    const sid = instance.id;
    if (b === 'addresses' && !c) {
      const w = parseWrite(AddressWrite, body, LEGACY.addressCreate);
      if (!w.ok) return w.res;
      const { restore, ...fields } = w.data;
      const { opId } = await ctx.runMutation(internal.backendWrites.requestAddressCreate, {
        backendServerId: sid,
        ...(hostFieldsOf(fields) as {
          remark: string;
          address: string;
          port: number;
          inboundUuid: string;
        }),
        restore: restore === true,
        ...actorOf(admin),
      });
      return runOp(ctx, opId);
    }
    if (b === 'addresses' && c === 'reorder' && !d) {
      const { opId } = await ctx.runMutation(internal.backendWrites.requestAddressReorder, {
        backendServerId: sid,
        hostUuids: Array.isArray(body.hostUuids) ? body.hostUuids.map(String) : [],
        ...actorOf(admin),
      });
      return runOp(ctx, opId);
    }
    if (b === 'modeGroups' && !c) {
      const w = parseWrite(ModeGroupWrite, body, LEGACY.modeGroup);
      if (!w.ok) return w.res;
      const { opId } = await ctx.runMutation(internal.backendWrites.requestModeGroupCreate, {
        backendServerId: sid,
        name: w.data.name,
        inboundUuids: w.data.transportUuids,
        restore: w.data.restore === true,
        ...actorOf(admin),
      });
      return runOp(ctx, opId);
    }
    if (b === 'ops' && c && d === 'observe') {
      const opId = c as Id<'panelOps'>;
      await ctx.runAction(internal.backendWrites.observe, { opId });
      return json(await ctx.runQuery(internal.backendLedger.view, { opId }));
    }
    if (b === 'ops' && c && d === 'recover') {
      const opId = c as Id<'panelOps'>;
      await ctx.runAction(internal.backendWrites.recoverOp, {
        opId,
        credentialsRevoked: body.credentialsRevoked === true,
        noInFlightExecutor: body.noInFlightExecutor === true,
        queueDrained: body.queueDrained === true,
        note: typeof body.note === 'string' ? body.note : undefined,
        ...actorOf(admin),
      });
      return json(await ctx.runQuery(internal.backendLedger.view, { opId }));
    }
    return notFound();
  }
  if (a && b === 'refresh' && !c) {
    const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
    await ctx.runAction(internal.backendObserve.refresh, { backendServerId: instance.id });
    return json(await ctx.runQuery(internal.serverAdmin.tree, { slug: a }));
  }
  // Setting up a backend (docs/servers.md): start, resume, or adopt an existing one (typed).
  if (a && b === 'setup' && !c) {
    const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
    const parsed = BackendSetupInput.safeParse(body);
    if (!parsed.success) return errorJson('validation', 'The setup input is not usable', 400);
    await ctx.runMutation(internal.backendSetup.start, {
      backendServerId: instance.id,
      input: parsed.data,
      ...actorOf(admin),
    });
    return json(await ctx.runQuery(internal.backendSetup.view, { backendServerId: instance.id }));
  }
  if (a && b === 'placements' && c === 'validate')
    return json(await ctx.runQuery(internal.serverAdmin.validatePlacements, { slug: a }));
  return notFound();
};

const patchHandler: Handler = async (ctx, parts, admin, body) => {
  const [a, b, c, d] = parts;
  if (a && b === 'nodes' && c && !d) {
    const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
    const { opId } = await ctx.runMutation(internal.backendWrites.requestNodeUpdate, {
      backendServerId: instance.id,
      nodeUuid: c,
      name: typeof body.name === 'string' ? body.name : undefined,
      address: typeof body.address === 'string' ? body.address : undefined,
      port: typeof body.port === 'number' ? body.port : undefined,
      countryCode: typeof body.countryCode === 'string' ? body.countryCode : undefined,
      configProfileUuid:
        typeof body.configProfileUuid === 'string' ? body.configProfileUuid : undefined,
      activeInboundUuids: Array.isArray(body.activeInboundUuids)
        ? body.activeInboundUuids.map(String)
        : undefined,
      ...actorOf(admin),
    });
    return runOp(ctx, opId);
  }
  if (a && c && !d && b === 'addresses') {
    const w = parseWrite(AddressPatch, body, LEGACY.addressPatch);
    if (!w.ok) return w.res;
    const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
    const { opId } = await ctx.runMutation(internal.backendWrites.requestAddressUpdate, {
      backendServerId: instance.id,
      hostUuid: c,
      ...hostFieldsOf(w.data),
      ...actorOf(admin),
    });
    return runOp(ctx, opId);
  }
  if (a && c && !d && b === 'modeGroups') {
    const w = parseWrite(ModeGroupPatch, body, LEGACY.modeGroup);
    if (!w.ok) return w.res;
    const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
    const { opId } = await ctx.runMutation(internal.backendWrites.requestModeGroupUpdate, {
      backendServerId: instance.id,
      squadUuid: c,
      name: w.data.name,
      inboundUuids: w.data.transportUuids,
      ...actorOf(admin),
    });
    return runOp(ctx, opId);
  }
  if (parts.length === 1 && parts[0] === 'config')
    return json(
      await ctx.runMutation(internal.serverAdmin.patchConfig, {
        patch: body,
        actorAdminId: admin.adminUserId ?? undefined,
      }),
    );
  return notFound();
};

const deleteHandler: Handler = async (ctx, parts, admin, _body, query) => {
  const [a, b, c, d] = parts;
  if (a && b === 'nodes' && c && !d) {
    const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
    const { opId } = await ctx.runMutation(internal.backendWrites.requestNodeDelete, {
      backendServerId: instance.id,
      nodeUuid: c,
      // "Remove from backend" only; the default is "stop and remove".
      removeOnly: query.get('removeOnly') === '1',
      ...actorOf(admin),
    });
    return runOp(ctx, opId);
  }
  if (!a || !c || d || (b !== 'addresses' && b !== 'modeGroups')) return notFound();
  const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
  const { opId } =
    b === 'addresses'
      ? await ctx.runMutation(internal.backendWrites.requestAddressDelete, {
          backendServerId: instance.id,
          hostUuid: c,
          ...actorOf(admin),
        })
      : await ctx.runMutation(internal.backendWrites.requestModeGroupDelete, {
          backendServerId: instance.id,
          squadUuid: c,
          ...actorOf(admin),
        });
  return runOp(ctx, opId);
};

/** `PUT` carries only the node role's enrollment (dispatched by `byNameHandler` before this). */
const putHandler: Handler = async () => notFound();

export function registerServerRoutes(http: HttpRouter): void {
  http.route({ pathPrefix: PREFIX, method: 'GET', handler: wrap(getHandler, true) });
  http.route({ pathPrefix: PREFIX, method: 'POST', handler: wrap(postHandler, true) });
  http.route({ pathPrefix: PREFIX, method: 'PATCH', handler: wrap(patchHandler, true) });
  http.route({ pathPrefix: PREFIX, method: 'PUT', handler: wrap(putHandler, true) });
  http.route({ pathPrefix: PREFIX, method: 'DELETE', handler: wrap(deleteHandler, false) });
}
