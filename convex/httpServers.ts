/**
 * Admin HTTP surface for server management: `/api/v1/admin/servers/*`. Same
 * shape as the edges surface (one prefix route per verb feeding a dispatcher,
 * so the HPKE policy is a clean per-verb prefix rule in envelope.ts): GET
 * reveals, POST seals both legs, PATCH seals the body. The responses carry node
 * and Host addresses, the same class of data the edges routes seal.
 *
 * Scopes: `admin:settings:*` for `config`, `admin:servers:read` for every
 * other route here. This surface is READ-ONLY toward the panel: `refresh`
 * re-reads one panel (throttled, it is the only route that makes a panel call)
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
import {
  NodeAppliedReport,
  NodeRegistration,
  PanelSetupInput,
} from '../src/shared/contracts/servers';

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
  // The panel could not be read: an upstream fault, not a refusal.
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
  // Looking at the panel again for an open op changes nothing on the panel.
  return parts.length === 4 && parts[1] === 'ops' && parts[3] === 'observe';
}

/**
 * `config` is a settings surface. Reads need `admin:servers:read`. A WRITE to a
 * panel needs `admin:servers:manage`, which is deliberately not
 * `admin:servers:write`: the node role's token holds that one. The role's
 * handoff report is the one write it may make here (it changes no panel).
 */
/** `{slug}/nodes/by-name/{name}[/verb]`: the node role's own routes (docs/servers.md "Node lifecycle"). */
export function isByNameRoute(parts: string[]): boolean {
  return parts.length >= 4 && parts[1] === 'nodes' && parts[2] === 'by-name' && !!parts[3];
}

export function scopeFor(parts: string[], method: string): string | string[] {
  if (parts[0] === 'config')
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
    // Whatever reaches a panel is throttled per actor: reads and writes apart.
    const readOnly = method === 'GET' || (method === 'POST' && isReadOnlyPost(parts));
    // Of the role's routes only `bootstrap` reaches the panel (the node secret);
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
    const out = await ctx.runQuery(internal.panelIntents.roleViewByName, {
      backendServerId: instance.id,
      name,
    });
    return out ? json(out) : notFound();
  };
  if (method === 'GET' && !verb) return view();
  if (method === 'PUT' && !verb) {
    const parsed = NodeRegistration.safeParse(body);
    if (!parsed.success) return errorJson('validation', 'The registration body is not usable', 400);
    await ctx.runMutation(internal.panelIntents.enroll, {
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
    const intent = await ctx.runQuery(internal.panelIntents.byName, {
      backendServerId: instance.id,
      name,
    });
    if (!intent) return notFound();
    await ctx.runMutation(internal.panelIntents.requestRetirement, {
      intentId: intent._id,
      requestedBy: 'role',
    });
    return view();
  }
  if (method !== 'POST') return notFound();
  const intent = await ctx.runQuery(internal.panelIntents.byName, {
    backendServerId: instance.id,
    name,
  });
  if (!intent) return notFound();
  if (verb === 'bootstrap') {
    // The one answer that carries a secret: never persisted by FCP, never audited.
    return json(await ctx.runAction(internal.panelIntents.bootstrap, { intentId: intent._id }));
  }
  if (verb === 'applied') {
    const parsed = NodeAppliedReport.safeParse(body);
    if (!parsed.success) return errorJson('validation', 'The applied report is not usable', 400);
    await ctx.runMutation(internal.panelIntents.applied, {
      intentId: intent._id,
      appliedRevision: parsed.data.appliedRevision,
      certificateReady: parsed.data.caddy?.certificateReady,
      nodeStarted: parsed.data.nodeStarted,
    });
    return view();
  }
  if (verb === 'wiped') {
    await ctx.runMutation(internal.panelIntents.markWiped, { intentId: intent._id });
    return view();
  }
  return notFound();
}

const actorOf = (admin: AdminAuth) => ({ actorAdminId: admin.adminUserId ?? undefined });

/** The mutation validated and claimed; now send once and look, and answer the op. */
async function runOp(ctx: ActionCtx, opId: Id<'panelOps'>) {
  await ctx.runAction(internal.panelWrites.run, { opId });
  return json(await ctx.runQuery(internal.panelLedger.view, { opId }));
}

const HOST_FIELDS = [
  'remark',
  'address',
  'port',
  'sni',
  'host',
  'path',
  'alpn',
  'fingerprint',
  'securityLayer',
  'isDisabled',
  'isHidden',
  'tag',
  'inboundUuid',
  'nodeUuids',
] as const;
/** Only the known Host fields travel on; an unknown key is dropped, never forwarded. */
function hostFieldsOf(body: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of HOST_FIELDS) if (body[k] !== undefined) out[k] = body[k];
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
      ops: await ctx.runQuery(internal.panelLedger.listForServer, { backendServerId: instance.id }),
    });
  }
  if (a && b === 'setup' && !c) {
    const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
    return json(await ctx.runQuery(internal.panelSetup.view, { backendServerId: instance.id }));
  }
  // The enrolled nodes of an instance, and one node's review card.
  if (a && b === 'nodes' && c === 'intents' && !parts[4]) {
    const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
    return json({
      intents: await ctx.runQuery(internal.serverAdmin.intentsView, {
        backendServerId: instance.id,
      }),
      holds: await ctx.runQuery(internal.panelIntents.holdsView, {
        backendServerId: instance.id,
      }),
    });
  }
  if (a && b === 'nodes' && c === 'intents' && parts[4] === 'review')
    return json(
      await ctx.runQuery(internal.panelActivation.review, {
        intentId: parts[3] as Id<'panelNodeIntents'>,
      }),
    );
  return notFound();
};

const postHandler: Handler = async (ctx, parts, admin, body) => {
  const [a, b, c, d] = parts;
  if (a && b === 'profiles' && c && d === 'acknowledge') {
    const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
    return json(
      await ctx.runMutation(internal.panelObserve.acknowledgeForeignEdit, {
        backendServerId: instance.id,
        profileUuid: c,
        ...actorOf(admin),
      }),
    );
  }
  if (a && b === 'profiles' && c && (d === 'preview' || d === 'apply')) {
    const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
    if (d === 'preview')
      return json(
        await ctx.runAction(internal.panelWrites.previewProfilePatch, {
          backendServerId: instance.id,
          profileUuid: c,
          ops: body.ops,
        }),
      );
    // Apply takes what the preview answered, verbatim: the write is conditioned
    // on the profile still having THAT token.
    const { opId } = await ctx.runMutation(internal.panelWrites.requestProfilePatch, {
      backendServerId: instance.id,
      profileUuid: c,
      ops: body.ops as never,
      baseToken: String(body.baseToken ?? ''),
      expectedToken: String(body.expectedToken ?? ''),
      inboundUuids: (body.inboundUuids ?? {}) as Record<string, string>,
      unmanaged:
        body.unmanaged === 'hold' || body.unmanaged === 'acknowledge' ? body.unmanaged : undefined,
      ...actorOf(admin),
    });
    return runOp(ctx, opId);
  }
  // Adopting a node that already serves members, as it is (docs/servers.md "Adopting a backend").
  if (a && b === 'nodes' && c === 'adopt' && !d) {
    const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
    return json(
      await ctx.runMutation(internal.panelIntents.adoptNode, {
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
      await ctx.runMutation(internal.panelIntents.releaseHold, {
        holdId: c as Id<'panelMaintenanceHolds'>,
        ...actorOf(admin),
      }),
    );
  // Node activation (docs/servers.md "Node lifecycle"): the isolated direct
  // test link, its bound confirmation, and the approval of a review. Before
  // the generic node writes: `nodes/intents/{id}/{verb}` is not a node uuid.
  if (a && b === 'nodes' && c === 'intents' && d) {
    const [, , , , intentIdRaw, verb] = parts;
    const intentId = intentIdRaw as Id<'panelNodeIntents'>;
    if (verb === 'test-link')
      return json(await ctx.runAction(internal.panelActivation.buildDirectTestLink, { intentId }));
    if (verb === 'confirm')
      return json(
        await ctx.runMutation(internal.panelActivation.confirmDirect, {
          intentId,
          binding: body.binding as never,
          ...actorOf(admin),
        }),
      );
    if (verb === 'approve')
      return json(
        await ctx.runMutation(internal.panelActivation.approve, {
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
          await ctx.runMutation(internal.panelRetirement.decide, {
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
        await ctx.runMutation(internal.panelIntents.requestRetirement, {
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
        await ctx.runMutation(internal.panelIntents.markWiped, {
          intentId,
          byAdminId: admin.adminUserId ?? undefined,
        }),
      );
    if (verb === 'maintenance')
      return json(
        await ctx.runMutation(internal.panelIntents.finishMaintenance, {
          intentId,
          ...actorOf(admin),
        }),
      );
    if (verb === 'settings')
      return json(
        await ctx.runMutation(internal.panelIntents.patchSettings, {
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
      const { opId } = await ctx.runMutation(internal.panelWrites.requestNodeCreate, {
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
      const { opId } = await ctx.runMutation(internal.panelWrites.requestNodeAction, {
        backendServerId: instance.id,
        nodeUuid: c,
        action: d,
        ...actorOf(admin),
      });
      return runOp(ctx, opId);
    }
    return notFound();
  }
  if (a && (b === 'hosts' || b === 'squads' || b === 'ops')) {
    const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
    const sid = instance.id;
    if (b === 'hosts' && !c) {
      const { opId } = await ctx.runMutation(internal.panelWrites.requestHostCreate, {
        backendServerId: sid,
        ...(hostFieldsOf(body) as {
          remark: string;
          address: string;
          port: number;
          inboundUuid: string;
        }),
        restore: body.restore === true,
        ...actorOf(admin),
      });
      return runOp(ctx, opId);
    }
    if (b === 'hosts' && c === 'reorder' && !d) {
      const { opId } = await ctx.runMutation(internal.panelWrites.requestHostReorder, {
        backendServerId: sid,
        hostUuids: Array.isArray(body.hostUuids) ? body.hostUuids.map(String) : [],
        ...actorOf(admin),
      });
      return runOp(ctx, opId);
    }
    if (b === 'squads' && !c) {
      const { opId } = await ctx.runMutation(internal.panelWrites.requestSquadCreate, {
        backendServerId: sid,
        name: String(body.name ?? ''),
        inboundUuids: Array.isArray(body.inboundUuids) ? body.inboundUuids.map(String) : [],
        restore: body.restore === true,
        ...actorOf(admin),
      });
      return runOp(ctx, opId);
    }
    if (b === 'ops' && c && d === 'observe') {
      const opId = c as Id<'panelOps'>;
      await ctx.runAction(internal.panelWrites.observe, { opId });
      return json(await ctx.runQuery(internal.panelLedger.view, { opId }));
    }
    if (b === 'ops' && c && d === 'recover') {
      const opId = c as Id<'panelOps'>;
      await ctx.runAction(internal.panelWrites.recoverOp, {
        opId,
        credentialsRevoked: body.credentialsRevoked === true,
        noInFlightExecutor: body.noInFlightExecutor === true,
        queueDrained: body.queueDrained === true,
        note: typeof body.note === 'string' ? body.note : undefined,
        ...actorOf(admin),
      });
      return json(await ctx.runQuery(internal.panelLedger.view, { opId }));
    }
    return notFound();
  }
  if (a && b === 'refresh' && !c) {
    const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
    await ctx.runAction(internal.panelObserve.refresh, { backendServerId: instance.id });
    return json(await ctx.runQuery(internal.serverAdmin.tree, { slug: a }));
  }
  // Setting up a backend (docs/servers.md): start, resume, or adopt an existing one (typed).
  if (a && b === 'setup' && !c) {
    const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
    const parsed = PanelSetupInput.safeParse(body);
    if (!parsed.success) return errorJson('validation', 'The setup input is not usable', 400);
    await ctx.runMutation(internal.panelSetup.start, {
      backendServerId: instance.id,
      input: parsed.data,
      ...actorOf(admin),
    });
    return json(await ctx.runQuery(internal.panelSetup.view, { backendServerId: instance.id }));
  }
  if (a && b === 'placements' && c === 'validate')
    return json(await ctx.runQuery(internal.serverAdmin.validatePlacements, { slug: a }));
  return notFound();
};

const patchHandler: Handler = async (ctx, parts, admin, body) => {
  const [a, b, c, d] = parts;
  if (a && b === 'nodes' && c && !d) {
    const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
    const { opId } = await ctx.runMutation(internal.panelWrites.requestNodeUpdate, {
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
  if (a && c && !d && (b === 'hosts' || b === 'squads')) {
    const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
    const { opId } =
      b === 'hosts'
        ? await ctx.runMutation(internal.panelWrites.requestHostUpdate, {
            backendServerId: instance.id,
            hostUuid: c,
            ...hostFieldsOf(body),
            ...actorOf(admin),
          })
        : await ctx.runMutation(internal.panelWrites.requestSquadUpdate, {
            backendServerId: instance.id,
            squadUuid: c,
            name: typeof body.name === 'string' ? body.name : undefined,
            inboundUuids: Array.isArray(body.inboundUuids)
              ? body.inboundUuids.map(String)
              : undefined,
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
    const { opId } = await ctx.runMutation(internal.panelWrites.requestNodeDelete, {
      backendServerId: instance.id,
      nodeUuid: c,
      // "Remove from panel" only; the default is "stop and remove".
      removeOnly: query.get('removeOnly') === '1',
      ...actorOf(admin),
    });
    return runOp(ctx, opId);
  }
  if (!a || !c || d || (b !== 'hosts' && b !== 'squads')) return notFound();
  const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
  const { opId } =
    b === 'hosts'
      ? await ctx.runMutation(internal.panelWrites.requestHostDelete, {
          backendServerId: instance.id,
          hostUuid: c,
          ...actorOf(admin),
        })
      : await ctx.runMutation(internal.panelWrites.requestSquadDelete, {
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
