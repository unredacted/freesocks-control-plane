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
import { makeFail, notFound, throttle, unauth } from './lib/adminHttp';
import { sealed } from './lib/hpke';
import { errorJson, json, readJson, resolveAdmin, type AdminAuth } from './lib/http';

const PREFIX = '/api/v1/admin/servers/';

type Handler = (
  ctx: ActionCtx,
  parts: string[],
  admin: AdminAuth,
  body: Record<string, unknown>,
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
  // Looking at the panel again for an open op changes nothing on the panel.
  return parts.length === 4 && parts[1] === 'ops' && parts[3] === 'observe';
}

/**
 * `config` is a settings surface. Reads need `admin:servers:read`. A WRITE to a
 * panel needs `admin:servers:manage`, which is deliberately not
 * `admin:servers:write`: the node role's token holds that one. The role's
 * handoff report is the one write it may make here (it changes no panel).
 */
export function scopeFor(parts: string[], method: string): string | string[] {
  if (parts[0] === 'config')
    return method === 'GET' ? 'admin:settings:read' : 'admin:settings:write';
  if (method === 'GET' || (method === 'POST' && isReadOnlyPost(parts))) return 'admin:servers:read';
  if (method === 'PUT' && parts.length === 2 && parts[1] === 'handoff')
    return ['admin:servers:write', 'admin:servers:manage'];
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
    const reachesPanel = readOnly
      ? method === 'POST' && parts[1] !== 'placements'
      : parts[0] !== 'config' && parts[1] !== 'handoff';
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
      return await handler(ctx, parts, admin, body);
    } catch (err) {
      return fail(err);
    }
  };
  return sealedRoute ? sealed(inner) : httpAction(inner);
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
  return notFound();
};

const postHandler: Handler = async (ctx, parts, admin, body) => {
  const [a, b, c, d] = parts;
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
  if (a && b === 'placements' && c === 'validate')
    return json(await ctx.runQuery(internal.serverAdmin.validatePlacements, { slug: a }));
  return notFound();
};

const patchHandler: Handler = async (ctx, parts, admin, body) => {
  const [a, b, c, d] = parts;
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

const deleteHandler: Handler = async (ctx, parts, admin) => {
  const [a, b, c, d] = parts;
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

/** The node role declares that it follows the ownership protocol for this instance. */
const putHandler: Handler = async (ctx, parts, admin, body) => {
  const [a, b, c] = parts;
  if (!a || b !== 'handoff' || c) return notFound();
  const version = Number(body.roleContractVersion);
  if (!Number.isInteger(version) || version < 1)
    return errorJson('validation', 'roleContractVersion must be a positive integer', 400);
  const instance = await ctx.runQuery(internal.serverAdmin.instanceBySlug, { slug: a });
  return json(
    await ctx.runMutation(internal.panelLedger.reportHandoff, {
      backendServerId: instance.id,
      roleContractVersion: version,
      reportedBy: admin.tokenId ? 'token' : 'admin',
    }),
  );
};

export function registerServerRoutes(http: HttpRouter): void {
  http.route({ pathPrefix: PREFIX, method: 'GET', handler: wrap(getHandler, true) });
  http.route({ pathPrefix: PREFIX, method: 'POST', handler: wrap(postHandler, true) });
  http.route({ pathPrefix: PREFIX, method: 'PATCH', handler: wrap(patchHandler, true) });
  http.route({ pathPrefix: PREFIX, method: 'PUT', handler: wrap(putHandler, true) });
  http.route({ pathPrefix: PREFIX, method: 'DELETE', handler: wrap(deleteHandler, false) });
}
