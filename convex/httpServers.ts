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

/** `config` is a settings surface; everything else here only reads server state. */
export function scopeFor(parts: string[], method: string): string {
  if (parts[0] === 'config')
    return method === 'GET' ? 'admin:settings:read' : 'admin:settings:write';
  return 'admin:servers:read';
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
    // The one route that reaches a panel.
    if (method === 'POST' && parts.length === 2 && parts[1] === 'refresh') {
      const limited = await throttle(ctx, req, admin, 'admin.servers.panel-read');
      if (limited) return limited;
    }
    let body: Record<string, unknown> = {};
    if (method !== 'GET') body = await readJson<Record<string, unknown>>(req);
    try {
      return await handler(ctx, parts, admin, body);
    } catch (err) {
      return fail(err);
    }
  };
  return sealedRoute ? sealed(inner) : httpAction(inner);
}

const getHandler: Handler = async (ctx, parts) => {
  const [a, b, c] = parts;
  if (!a || (a === 'summary' && !b))
    return json(await ctx.runQuery(internal.serverAdmin.summary, {}));
  if (a === 'config' && !b) return json(await ctx.runQuery(internal.serverAdmin.configView, {}));
  if (b === 'tree' && !c) return json(await ctx.runQuery(internal.serverAdmin.tree, { slug: a }));
  return notFound();
};

const postHandler: Handler = async (ctx, parts) => {
  const [a, b, c] = parts;
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
  if (parts.length === 1 && parts[0] === 'config')
    return json(
      await ctx.runMutation(internal.serverAdmin.patchConfig, {
        patch: body,
        actorAdminId: admin.adminUserId ?? undefined,
      }),
    );
  return notFound();
};

export function registerServerRoutes(http: HttpRouter): void {
  http.route({ pathPrefix: PREFIX, method: 'GET', handler: wrap(getHandler, true) });
  http.route({ pathPrefix: PREFIX, method: 'POST', handler: wrap(postHandler, true) });
  http.route({ pathPrefix: PREFIX, method: 'PATCH', handler: wrap(patchHandler, true) });
}
