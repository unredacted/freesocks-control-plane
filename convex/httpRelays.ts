/**
 * Admin HTTP surface for relay edges: `/api/v1/admin/relays/*`. One prefix
 * route per verb feeds a small dispatcher, so the HPKE policy is a clean
 * per-verb prefix rule (envelope.ts): GET reveals, POST seals both legs,
 * PATCH/PUT seal the body, DELETE carries nothing. Scopes: `admin:settings:*`
 * for the config namespace, `admin:servers:*` for everything else. Responses
 * are the shapes in src/shared/contracts/relays.ts.
 */
import { ConvexError } from 'convex/values';
import type { HttpRouter } from 'convex/server';
import { httpAction } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Id, TableNames } from './_generated/dataModel';
import { sealed } from './lib/e2ee';
import { errorJson, json, readJson, resolveAdmin, type AdminAuth } from './lib/http';
import type { InspectResult, Inventory } from './lib/relays/providers/types';

const PREFIX = '/api/v1/admin/relays/';

type Handler = (
  ctx: ActionCtx,
  req: Request,
  parts: string[],
  admin: AdminAuth,
  body: Record<string, unknown>,
  query: URLSearchParams,
) => Promise<Response>;

function statusFromCode(code: string): number {
  if (code === 'not_found') return 404;
  if (code === 'conflict' || code.startsWith('relay.')) return 409;
  if (code === 'validation') return 400;
  return 400;
}

function fail(err: unknown): Response {
  if (err instanceof ConvexError) {
    const data = err.data as { code?: string; message?: string };
    const code = data.code ?? 'error';
    return errorJson(code, data.message ?? 'Request failed', statusFromCode(code));
  }
  console.error(`[relays] unhandled error: ${err instanceof Error ? err.message : String(err)}`);
  return errorJson('admin.error', 'The request could not be completed.', 400);
}

const notFound = () => errorJson('not_found', 'Not found', 404);
const unauth = () => errorJson('auth.unauthenticated', 'Authentication required', 401);

function segments(req: Request): { parts: string[]; query: URLSearchParams } {
  const url = new URL(req.url);
  const rest = url.pathname.startsWith(PREFIX) ? url.pathname.slice(PREFIX.length) : '';
  return {
    parts: rest.split('/').filter(Boolean).map(decodeURIComponent),
    query: url.searchParams,
  };
}

/** Config routes need the settings scope; everything else the servers scope. */
function scopeFor(parts: string[], write: boolean): string {
  const ns = parts[0] === 'config' ? 'settings' : 'servers';
  return `admin:${ns}:${write ? 'write' : 'read'}`;
}

function wrap(write: boolean, handler: Handler, sealedRoute: boolean) {
  const inner = async (ctx: ActionCtx, req: Request): Promise<Response> => {
    const { parts, query } = segments(req);
    const admin = await resolveAdmin(ctx, req, scopeFor(parts, write));
    if (!admin) return unauth();
    let body: Record<string, unknown> = {};
    if (req.method !== 'GET' && req.method !== 'DELETE') {
      body = await readJson<Record<string, unknown>>(req);
    }
    try {
      return await handler(ctx, req, parts, admin, body, query);
    } catch (err) {
      return fail(err);
    }
  };
  return sealedRoute ? sealed(inner) : httpAction(inner);
}

const id = <T extends TableNames>(s: string | undefined) => (s ?? '') as Id<T>;
const actor = (admin: AdminAuth) => ({ actorAdminId: admin.adminUserId ?? undefined });

// --- GET ----------------------------------------------------------------------------------------

const getHandler: Handler = async (ctx, _req, parts, _admin, _body, query) => {
  const [a, b, c, d, e] = parts;
  if (!a || a === 'summary') return json(await ctx.runQuery(internal.relayAdmin.summary, {}));
  if (a === 'config') return json(await ctx.runQuery(internal.relayAdmin.configView, {}));
  if (a === 'providers') {
    if (!b) {
      const [accounts, credentialFields] = await Promise.all([
        ctx.runQuery(internal.relayProviderAccounts.listForAdmin, {}),
        ctx.runQuery(internal.relayAdmin.credentialFields, {}),
      ]);
      return json({ accounts, credentialFields });
    }
    if (c === 'inventory') {
      const inv = await ctx.runQuery(internal.relayProviderAccounts.getInventory, {
        id: id<'relayProviderAccounts'>(b),
      });
      return json(inv ?? { inventory: null, inventoryAt: null });
    }
    if (!c) {
      const acct = await ctx.runQuery(internal.relayProviderAccounts.getForAdmin, {
        id: id<'relayProviderAccounts'>(b),
      });
      return acct ? json(acct) : notFound();
    }
    return notFound();
  }
  if (a === 'templates' && !b) {
    const [templates, schemas] = await Promise.all([
      ctx.runQuery(internal.relayEdgeTemplates.list, {}),
      ctx.runQuery(internal.relayEdgeTemplates.describeSchemas, {}),
    ]);
    return json({ templates, schemas });
  }
  if (a === 'profiles' && !b) return json(await ctx.runQuery(internal.relayProfiles.list, {}));
  if (a === 'origins') {
    if (!b) return json(await ctx.runQuery(internal.relayOrigins.listForAdmin, {}));
    if (b === 'by-slug' && c) {
      const view = await ctx.runQuery(internal.relayAdmin.originBySlugView, { slug: c });
      if (!view) return notFound();
      if (d === 'slots' && e) {
        const slot = view.slots.find((s) => s.slotKey === e);
        return slot ? json(slot) : notFound();
      }
      if (!d) return json(view);
      return notFound();
    }
    if (c === 'endpoints') {
      const r = await ctx.runQuery(internal.relayAdmin.endpoints, {
        originId: id<'relayOrigins'>(b),
      });
      return r ? json(r) : notFound();
    }
    if (c === 'slots') {
      return json(
        await ctx.runQuery(internal.relaySlots.listByOrigin, { originId: id<'relayOrigins'>(b) }),
      );
    }
    if (c === 'rotations') {
      return json(
        await ctx.runQuery(internal.relayRotations.listByOrigin, {
          originId: id<'relayOrigins'>(b),
        }),
      );
    }
    return notFound();
  }
  if (a === 'edges') {
    if (!b) {
      const originId = query.get('originId');
      if (!originId) return errorJson('validation', 'originId is required', 400);
      return json(
        await ctx.runQuery(internal.relayEdges.listByOriginForAdmin, {
          originId: id<'relayOrigins'>(originId),
        }),
      );
    }
    if (c === 'live')
      return json(
        await ctx.runQuery(internal.relayAdmin.liveView, { edgeId: id<'relayEdges'>(b) }),
      );
    if (!c) {
      const detail = await ctx.runQuery(internal.relayAdmin.edgeDetail, {
        edgeId: id<'relayEdges'>(b),
      });
      return detail ? json(detail) : notFound();
    }
    return notFound();
  }
  if (a === 'rotations') {
    if (!b) {
      const originId = query.get('originId');
      if (!originId) return errorJson('validation', 'originId is required', 400);
      return json(
        await ctx.runQuery(internal.relayRotations.listByOrigin, {
          originId: id<'relayOrigins'>(originId),
          take: Number(query.get('take') ?? 20) || 20,
        }),
      );
    }
    const r = await ctx.runQuery(internal.relayRotations.getForAdmin, {
      id: id<'relayRotations'>(b),
    });
    return r ? json(r) : notFound();
  }
  if (a === 'probes' && !b) {
    const edgeId = query.get('edgeId');
    if (!edgeId) return errorJson('validation', 'edgeId is required', 400);
    return json(
      await ctx.runQuery(internal.relayProbes.listByEdge, {
        edgeId: id<'relayEdges'>(edgeId),
        take: Number(query.get('take') ?? 20) || 20,
      }),
    );
  }
  if (a === 'reachability' && !b) {
    const originId = query.get('originId');
    if (!originId) return errorJson('validation', 'originId is required', 400);
    return json(
      await ctx.runQuery(internal.relayProbes.reachabilityForOrigin, {
        originId: id<'relayOrigins'>(originId),
      }),
    );
  }
  return notFound();
};

// --- POST ----------------------------------------------------------------------------------------

async function refreshInventory(
  ctx: ActionCtx,
  accountId: Id<'relayProviderAccounts'>,
): Promise<Response> {
  const inventory: Inventory = await ctx.runAction(internal.relayProviderOps.inventory, {
    accountId,
  });
  await ctx.runMutation(internal.relayProviderAccounts.recordInventory, {
    id: accountId,
    inventory: JSON.stringify(inventory),
  });
  const view = await ctx.runQuery(internal.relayProviderAccounts.getInventory, { id: accountId });
  return json(view ?? { inventory, inventoryAt: new Date().toISOString() });
}

const postHandler: Handler = async (ctx, _req, parts, admin, body) => {
  const [a, b, c, d] = parts;
  const act = actor(admin);
  if (a === 'providers') {
    if (!b)
      return json(
        await ctx.runMutation(internal.relayProviderAccounts.create, { ...body, ...act } as never),
      );
    if (b === 'test-credentials') {
      const accountId = id<'relayProviderAccounts'>(String(body.accountId ?? ''));
      const res = await ctx.runAction(internal.relayProviderOps.testCredentials, { accountId });
      await ctx.runMutation(internal.relayProviderAccounts.recordTest, {
        id: accountId,
        ok: res.ok,
        code: res.code,
      });
      let regions: Array<{ id: string; label: string }> = [];
      if (res.ok) {
        try {
          regions = await ctx.runAction(internal.relayProviderOps.listRegions, { accountId });
        } catch {
          regions = [];
        }
      }
      return json({ ok: res.ok, code: res.code ?? null, regions });
    }
    if (c === 'inventory' && d === 'refresh')
      return refreshInventory(ctx, id<'relayProviderAccounts'>(b));
    if (c === 'qualify') {
      return json(
        await ctx.runMutation(internal.relayProviderAccounts.setQualified, {
          id: id<'relayProviderAccounts'>(b),
          qualified: body.qualified !== false,
          templateHash: typeof body.templateHash === 'string' ? body.templateHash : undefined,
          ...act,
        }),
      );
    }
    return notFound();
  }
  if (a === 'templates') {
    if (!b)
      return json(
        await ctx.runMutation(internal.relayEdgeTemplates.create, { ...body, ...act } as never),
      );
    if (b === 'validate')
      return json(await ctx.runQuery(internal.relayEdgeTemplates.validate, body as never));
    return notFound();
  }
  if (a === 'profiles') {
    if (!b)
      return json(
        await ctx.runMutation(internal.relayProfiles.create, { ...body, ...act } as never),
      );
    const pid = id<'relayCamouflageProfiles'>(b);
    if (c === 'qualify')
      return json(
        await ctx.runMutation(internal.relayProfiles.recordQualification, {
          ...body,
          id: pid,
          ...act,
        } as never),
      );
    if (c === 'retire-sni')
      return json(
        await ctx.runMutation(internal.relayProfiles.retireSni, {
          id: pid,
          snis: snis(body),
          ...act,
        }),
      );
    if (c === 'reactivate-sni')
      return json(
        await ctx.runMutation(internal.relayProfiles.reactivateSni, {
          id: pid,
          snis: snis(body),
          ...act,
        }),
      );
    return notFound();
  }
  if (a === 'origins') {
    if (!b)
      return json(
        await ctx.runMutation(internal.relayOrigins.create, { ...body, ...act } as never),
      );
    const originId = id<'relayOrigins'>(b);
    switch (c) {
      case 'adopt':
        return json(
          await ctx.runMutation(internal.relayOrigins.adoptEdge, {
            ...body,
            originId,
            ...act,
          } as never),
        );
      case 'provision':
        return json(
          await ctx.runMutation(internal.relayRotations.start, {
            originId,
            kind: 'provision',
            trigger: 'manual',
            publishOnDone: body.publish !== false,
            slotId:
              typeof body.slotId === 'string' ? id<'relayOriginSlots'>(body.slotId) : undefined,
            ...act,
          }),
        );
      case 'rotate':
      case 'burn':
        return json(
          await ctx.runMutation(internal.relayRotations.start, {
            originId,
            kind: 'replace',
            trigger: 'manual',
            burn: c === 'burn',
            force: body.force === true,
            targetEdgeId: id<'relayEdges'>(String(body.edgeId ?? '')),
            ...act,
          }),
        );
      case 'publish':
        return json(
          await ctx.runMutation(internal.relayRotations.start, {
            originId,
            kind: 'publish',
            trigger: 'manual',
            toEdgeId: id<'relayEdges'>(String(body.edgeId ?? '')),
            ...act,
          }),
        );
      case 'cancel': {
        const origin = await ctx.runQuery(internal.relayOrigins.get, { id: originId });
        if (!origin?.activeRotationId)
          return errorJson('relay.no_rotation', 'No rotation is running', 409);
        return json(
          await ctx.runMutation(internal.relayRotations.requestCancel, {
            rotationId: origin.activeRotationId,
            ...act,
          }),
        );
      }
      case 'resolve-quarantine':
        return json(
          await ctx.runMutation(internal.relayRotations.resolveQuarantine, {
            originId,
            keep: body.keep === 'previous' ? 'previous' : 'current',
            ...act,
          }),
        );
      case 'probe': {
        const edges = await ctx.runQuery(internal.relayAdmin.publishedEdgeIds, { originId });
        const runIds: string[] = [];
        for (const edgeId of edges) {
          const r = await ctx.runMutation(internal.relayProbes.requestProbes, {
            edgeId,
            trigger: 'manual',
          });
          runIds.push(...r.runIds);
        }
        return json({ runIds });
      }
      default:
        return notFound();
    }
  }
  if (a === 'edges' && b) {
    const edgeId = id<'relayEdges'>(b);
    if (c === 'live' && d === 'refresh') {
      const edge = await ctx.runQuery(internal.relayEdges.get, { id: edgeId });
      if (!edge) return notFound();
      if (!edge.accountId)
        return errorJson(
          'relay.unmanaged',
          'An adopted edge has no provider account to inspect',
          409,
        );
      const res: InspectResult = await ctx.runAction(internal.relayProviderOps.inspect, {
        accountId: edge.accountId,
        ledger: { steps: edge.steps, resources: edge.resources },
      });
      await ctx.runMutation(internal.relayAdmin.recordLive, {
        edgeId,
        snapshot: JSON.stringify(res),
        ...act,
      });
      return json(await ctx.runQuery(internal.relayAdmin.liveView, { edgeId }));
    }
    const edge = await ctx.runQuery(internal.relayEdges.get, { id: edgeId });
    if (!edge) return notFound();
    switch (c) {
      case 'publish':
        // Pool index 0 on a Host-managed origin needs the flip → rotation machine.
        return json(
          body.direct === true
            ? await ctx.runMutation(internal.relayOrigins.publishEdge, {
                originId: edge.originId,
                edgeId,
                poolIndex: typeof body.poolIndex === 'number' ? body.poolIndex : undefined,
                ...act,
              })
            : await ctx.runMutation(internal.relayRotations.start, {
                originId: edge.originId,
                kind: 'publish',
                trigger: 'manual',
                toEdgeId: edgeId,
                ...act,
              }),
        );
      case 'unpublish':
        return json(
          await ctx.runMutation(internal.relayOrigins.unpublishEdge, {
            originId: edge.originId,
            edgeId,
            keepActive: body.keepActive === true,
            ...act,
          }),
        );
      case 'retry-destroy':
        return json(
          await ctx.runMutation(internal.relayReconcileMutations.retryDestroy, { edgeId, ...act }),
        );
      case 'resolve-operator': {
        const action = body.action;
        if (action !== 'destroy' && action !== 'forget' && action !== 'reactivate') {
          return errorJson('validation', 'action must be destroy, forget or reactivate', 400);
        }
        return json(
          await ctx.runMutation(internal.relayAdmin.resolveOperator, { edgeId, action, ...act }),
        );
      }
      case 'probe':
        return json(
          await ctx.runMutation(internal.relayProbes.requestProbes, { edgeId, trigger: 'manual' }),
        );
      default:
        return notFound();
    }
  }
  if (a === 'render' && b === 'preview') {
    return json(
      await ctx.runQuery(internal.relayAdmin.renderPreview, {
        originId: id<'relayOrigins'>(String(body.originId ?? '')),
        family: String(body.family ?? 'other'),
        sampleKey: typeof body.sampleKey === 'string' ? body.sampleKey : undefined,
      }),
    );
  }
  return notFound();
};

function snis(body: Record<string, unknown>): string[] {
  const raw = body.snis ?? body.sni;
  if (Array.isArray(raw)) return raw.map(String);
  return typeof raw === 'string' ? [raw] : [];
}

// --- PATCH ------------------------------------------------------------------------------------------

const patchHandler: Handler = async (ctx, _req, parts, admin, body) => {
  const [a, b, c] = parts;
  const act = actor(admin);
  if (a === 'config' && !b)
    return json(await ctx.runMutation(internal.relayAdmin.patchConfig, { patch: body, ...act }));
  if (c) return notFound();
  if (a === 'providers' && b)
    return json(
      await ctx.runMutation(internal.relayProviderAccounts.update, {
        ...body,
        id: id<'relayProviderAccounts'>(b),
        ...act,
      } as never),
    );
  if (a === 'templates' && b)
    return json(
      await ctx.runMutation(internal.relayEdgeTemplates.update, {
        ...body,
        id: id<'relayEdgeTemplates'>(b),
        ...act,
      } as never),
    );
  if (a === 'profiles' && b)
    return json(
      await ctx.runMutation(internal.relayProfiles.update, {
        ...body,
        id: id<'relayCamouflageProfiles'>(b),
        ...act,
      } as never),
    );
  if (a === 'origins' && b)
    return json(
      await ctx.runMutation(internal.relayOrigins.update, {
        ...body,
        id: id<'relayOrigins'>(b),
        ...act,
      } as never),
    );
  return notFound();
};

// --- PUT (IaC upserts) -----------------------------------------------------------------------------

const putHandler: Handler = async (ctx, _req, parts, admin, body) => {
  const [a, b, c, d, e] = parts;
  const act = actor(admin);
  if (a !== 'origins' || b !== 'by-slug' || !c) return notFound();
  if (!d) {
    await ctx.runMutation(internal.relayOrigins.upsertBySlug, {
      ...body,
      slug: c,
      ...act,
    } as never);
    const view = await ctx.runQuery(internal.relayAdmin.originBySlugView, { slug: c });
    return view ? json(view) : notFound();
  }
  if (d === 'slots' && e) {
    const origin = await ctx.runQuery(internal.relayOrigins.getBySlug, { slug: c });
    if (!origin) return notFound();
    return json(
      await ctx.runMutation(internal.relaySlots.upsert, {
        ...body,
        originId: origin._id,
        slotKey: e,
        ...act,
      } as never),
    );
  }
  return notFound();
};

// --- DELETE --------------------------------------------------------------------------------------------

const deleteHandler: Handler = async (ctx, _req, parts, admin) => {
  const [a, b, c, d, e] = parts;
  const act = actor(admin);
  if (a === 'providers' && b && !c)
    return json(
      await ctx.runMutation(internal.relayProviderAccounts.remove, {
        id: id<'relayProviderAccounts'>(b),
        ...act,
      }),
    );
  if (a === 'templates' && b && !c)
    return json(
      await ctx.runMutation(internal.relayEdgeTemplates.remove, {
        id: id<'relayEdgeTemplates'>(b),
        ...act,
      }),
    );
  if (a === 'profiles' && b && !c)
    return json(
      await ctx.runMutation(internal.relayProfiles.remove, {
        id: id<'relayCamouflageProfiles'>(b),
        ...act,
      }),
    );
  if (a === 'edges' && b && !c)
    return json(
      await ctx.runMutation(internal.relayAdmin.deleteEdge, {
        edgeId: id<'relayEdges'>(b),
        ...act,
      }),
    );
  if (a === 'origins' && b) {
    if (b === 'by-slug' && c) {
      const origin = await ctx.runQuery(internal.relayOrigins.getBySlug, { slug: c });
      if (!origin) return json({ ok: true, deleted: true });
      if (d === 'slots' && e)
        return json(
          await ctx.runMutation(internal.relaySlots.retire, {
            originId: origin._id,
            slotKey: e,
            ...act,
          }),
        );
      if (!d)
        return json(
          await ctx.runMutation(internal.relayOrigins.requestDelete, { id: origin._id, ...act }),
        );
      return notFound();
    }
    if (!c)
      return json(
        await ctx.runMutation(internal.relayOrigins.requestDelete, {
          id: id<'relayOrigins'>(b),
          ...act,
        }),
      );
  }
  return notFound();
};

export function registerRelayRoutes(http: HttpRouter): void {
  http.route({ pathPrefix: PREFIX, method: 'GET', handler: wrap(false, getHandler, true) });
  http.route({ pathPrefix: PREFIX, method: 'POST', handler: wrap(true, postHandler, true) });
  http.route({ pathPrefix: PREFIX, method: 'PATCH', handler: wrap(true, patchHandler, true) });
  http.route({ pathPrefix: PREFIX, method: 'PUT', handler: wrap(true, putHandler, true) });
  http.route({ pathPrefix: PREFIX, method: 'DELETE', handler: wrap(true, deleteHandler, false) });
}
