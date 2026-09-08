/**
 * Admin HTTP surface for edges (the L4 load balancers in front of relays): `/api/v1/admin/edges/*`. One prefix
 * route per verb feeds a small dispatcher, so the HPKE policy is a clean
 * per-verb prefix rule (envelope.ts): GET reveals, POST seals both legs,
 * PATCH/PUT seal the body, DELETE carries nothing. Scopes: `admin:settings:*`
 * for the config namespace, `admin:servers:*` for everything else; the two
 * POSTs that only compute (`render/preview`, `templates/validate`) need the
 * READ scope. The POSTs that reach a cloud provider / spend probe credits are
 * rate-limited per actor (`admin.edges.provider-call` / `admin.edges.probe`).
 * Responses are the shapes in src/shared/contracts/edges.ts.
 */
import { ConvexError } from 'convex/values';
import type { HttpRouter } from 'convex/server';
import { httpAction } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Id, TableNames } from './_generated/dataModel';
import { sealed } from './lib/e2ee';
import { sha256Hex } from './lib/crypto';
import {
  errorJson,
  ipHashSubject,
  json,
  newRequestId,
  readJson,
  resolveAdmin,
  resolveClientIp,
  type AdminAuth,
} from './lib/http';
import type { RateLimitPolicyKey } from './lib/rateLimitPolicy';
import type { InspectResult, Inventory } from './lib/edges/providers/types';
import { parseTargetKey } from './probes';

const PREFIX = '/api/v1/admin/edges/';

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
  if (code === 'conflict' || code.startsWith('edge.')) return 409;
  if (code === 'validation') return 400;
  return 400;
}

function fail(err: unknown): Response {
  if (err instanceof ConvexError) {
    const data = err.data as { code?: string; message?: string };
    const code = data.code ?? 'error';
    return errorJson(code, data.message ?? 'Request failed', statusFromCode(code));
  }
  // Never log the message of a non-ConvexError: Convex's ArgumentValidationError
  // text embeds the offending argument VALUES (addresses, credentials, ids the
  // caller typed). The class name + a request id is enough to correlate.
  const requestId = newRequestId();
  const kind = err instanceof Error ? err.constructor.name || err.name : typeof err;
  console.error(`[edges] unhandled error kind=${kind} requestId=${requestId}`);
  return errorJson('admin.error', 'The request could not be completed.', 400, { requestId });
}

const notFound = () => errorJson('not_found', 'Not found', 404);
const unauth = () => errorJson('auth.unauthenticated', 'Authentication required', 401);

/** First segments that are collections of their own; anything else is an edge id. */
const RESERVED = new Set([
  'summary',
  'config',
  'providers',
  'templates',
  'profiles',
  'relays',
  'rotations',
  'probes',
  'render',
  'edges',
]);

/**
 * Path → segments. Decoding happens BEFORE the scope check (a percent-encoded
 * `config` must still resolve to the settings scope) and returns null on a
 * malformed escape so the caller answers 400 instead of throwing (which was a
 * 500 on the unsealed DELETE route).
 */
function segments(req: Request): { parts: string[]; query: URLSearchParams } | null {
  const url = new URL(req.url);
  const rest = url.pathname.startsWith(PREFIX) ? url.pathname.slice(PREFIX.length) : '';
  let parts: string[];
  try {
    parts = rest.split('/').filter(Boolean).map(decodeURIComponent);
  } catch {
    return null;
  }
  // The edge collection sits at the prefix root: `list` lists, `<id>/…` addresses one edge.
  if (parts[0] === 'list') parts = ['edges'];
  else if (parts[0] && !RESERVED.has(parts[0])) parts = ['edges', ...parts];
  return { parts, query: url.searchParams };
}

/** POSTs that only compute over stored state (no write, no provider call): read scope. */
function isReadOnlyPost(parts: string[]): boolean {
  return (
    parts.length === 2 &&
    ((parts[0] === 'render' && parts[1] === 'preview') ||
      (parts[0] === 'templates' && parts[1] === 'validate'))
  );
}

/** Config routes need the settings scope; everything else the servers scope. */
export function scopeFor(parts: string[], method: string): string {
  const ns = parts[0] === 'config' ? 'settings' : 'servers';
  const write = method !== 'GET' && !(method === 'POST' && isReadOnlyPost(parts));
  return `admin:${ns}:${write ? 'write' : 'read'}`;
}

/**
 * Which POSTs are throttled, and under which policy. `provider-call` = a live
 * call to a cloud provider / the panel (or a CPU-bound preview render);
 * `probe` = measurement runs that spend third-party credits.
 */
export function throttlePolicyFor(parts: string[]): RateLimitPolicyKey | null {
  const [a, b, c, d] = parts;
  if (a === 'providers' && (b === 'discover' || b === 'test-credentials') && !c) {
    return 'admin.edges.provider-call';
  }
  if (a === 'providers' && b && c === 'inventory' && d === 'refresh') {
    return 'admin.edges.provider-call';
  }
  // Credential rotation tests the new secret against the provider first.
  if (a === 'providers' && b && c === 'rotate-credentials' && !d) {
    return 'admin.edges.provider-call';
  }
  if (a === 'relays' && b === 'node-candidates' && c === 'refresh') {
    return 'admin.edges.provider-call';
  }
  if (a === 'edges' && b && c === 'live' && d === 'refresh') return 'admin.edges.provider-call';
  if (a === 'render' && b === 'preview') return 'admin.edges.provider-call';
  if (a === 'edges' && b && c === 'probe') return 'admin.edges.probe';
  if (a === 'relays' && b && c === 'probe') return 'admin.edges.probe';
  if (a === 'probes' && !b) return 'admin.edges.probe';
  return null;
}

/**
 * Per-actor rate-limit subject: the admin id for a cookie session, a hash of
 * the bearer token for an `fsv1_` caller, else the (hashed) client IP. The
 * token plaintext is never the subject (bucket names land in the DB).
 */
async function actorSubject(req: Request, admin: AdminAuth): Promise<string> {
  if (admin.adminUserId) return `admin:${admin.adminUserId}`;
  const m = /^Bearer\s+(\S+)$/i.exec((req.headers.get('authorization') ?? '').trim());
  if (m) return `tok:${(await sha256Hex(m[1])).slice(0, 32)}`;
  const ip = resolveClientIp(req);
  return ip ? `ip:${await ipHashSubject(ip)}` : 'unknown';
}

async function throttle(
  ctx: ActionCtx,
  req: Request,
  admin: AdminAuth,
  policyKey: RateLimitPolicyKey,
): Promise<Response | null> {
  const rl = await ctx.runMutation(internal.rateLimits.enforce, {
    policyKey,
    subject: await actorSubject(req, admin),
  });
  if (rl.allowed) return null;
  return errorJson('rate_limit.exceeded', 'Too many requests. Please slow down.', 429, {
    retryAfterMs: rl.retryAfterMs,
  });
}

function wrap(handler: Handler, sealedRoute: boolean) {
  const inner = async (ctx: ActionCtx, req: Request): Promise<Response> => {
    const seg = segments(req);
    if (!seg) return errorJson('validation', 'Malformed path encoding', 400);
    const { parts, query } = seg;
    const method = req.method.toUpperCase();
    const admin = await resolveAdmin(ctx, req, scopeFor(parts, method));
    if (!admin) return unauth();
    if (method === 'POST') {
      const policyKey = throttlePolicyFor(parts);
      if (policyKey) {
        const limited = await throttle(ctx, req, admin, policyKey);
        if (limited) return limited;
      }
    }
    let body: Record<string, unknown> = {};
    if (method !== 'GET' && method !== 'DELETE') {
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
  if (!a || a === 'summary') return json(await ctx.runQuery(internal.edgeAdmin.summary, {}));
  if (a === 'config') return json(await ctx.runQuery(internal.edgeAdmin.configView, {}));
  if (a === 'providers') {
    if (!b) {
      const [accounts, credentialFields] = await Promise.all([
        ctx.runQuery(internal.edgeProviderAccounts.listForAdmin, {}),
        ctx.runQuery(internal.edgeAdmin.credentialFields, {}),
      ]);
      return json({ accounts, credentialFields });
    }
    if (c === 'inventory') {
      const inv = await ctx.runQuery(internal.edgeProviderAccounts.getInventory, {
        id: id<'edgeProviderAccounts'>(b),
      });
      return json(inv ?? { inventory: null, inventoryAt: null });
    }
    if (!c) {
      const acct = await ctx.runQuery(internal.edgeProviderAccounts.getForAdmin, {
        id: id<'edgeProviderAccounts'>(b),
      });
      return acct ? json(acct) : notFound();
    }
    return notFound();
  }
  if (a === 'templates' && !b) {
    // Read-only: provisioning falls back to the compiled adapter defaults when
    // no row exists (edgeTemplates.resolveTemplateFor); seeding rows is the
    // explicit `POST templates/ensure-defaults` (write scope).
    const [templates, schemas] = await Promise.all([
      ctx.runQuery(internal.edgeTemplates.list, {}),
      ctx.runQuery(internal.edgeTemplates.describeSchemas, {}),
    ]);
    return json({ templates, schemas });
  }
  if (a === 'profiles' && !b) return json(await ctx.runQuery(internal.protocolProfiles.list, {}));
  if (a === 'relays') {
    if (!b) return json(await ctx.runQuery(internal.relays.listForAdmin, {}));
    if (b === 'node-candidates' && !c) {
      const serverId = query.get('backendServerId');
      if (!serverId) return errorJson('validation', 'backendServerId is required', 400);
      return json(
        await ctx.runQuery(internal.edgeAdmin.nodeCandidates, {
          backendServerId: id<'backendServers'>(serverId),
        }),
      );
    }
    if (b === 'by-slug' && c) {
      const view = await ctx.runQuery(internal.edgeAdmin.relayBySlugView, { slug: c });
      if (!view) return notFound();
      if (d === 'slots' && e) {
        const slot = view.slots.find((s) => s.slotKey === e);
        return slot ? json(slot) : notFound();
      }
      if (!d) return json(view);
      return notFound();
    }
    if (c === 'endpoints') {
      const r = await ctx.runQuery(internal.edgeAdmin.endpoints, {
        relayId: id<'relays'>(b),
      });
      return r ? json(r) : notFound();
    }
    if (c === 'slots') {
      return json(
        await ctx.runQuery(internal.relaySlots.listByRelay, { relayId: id<'relays'>(b) }),
      );
    }
    if (c === 'rotations') {
      return json(
        await ctx.runQuery(internal.edgeRotations.listByRelay, {
          relayId: id<'relays'>(b),
        }),
      );
    }
    return notFound();
  }
  if (a === 'edges') {
    if (!b) {
      const relayId = query.get('relayId');
      if (!relayId) return errorJson('validation', 'relayId is required', 400);
      return json(
        await ctx.runQuery(internal.edges.listByRelayForAdmin, {
          relayId: id<'relays'>(relayId),
        }),
      );
    }
    if (c === 'live')
      return json(await ctx.runQuery(internal.edgeAdmin.liveView, { edgeId: id<'edges'>(b) }));
    if (!c) {
      const detail = await ctx.runQuery(internal.edgeAdmin.edgeDetail, {
        edgeId: id<'edges'>(b),
      });
      return detail ? json(detail) : notFound();
    }
    return notFound();
  }
  if (a === 'rotations') {
    if (!b) {
      const relayId = query.get('relayId');
      if (!relayId) return errorJson('validation', 'relayId is required', 400);
      return json(
        await ctx.runQuery(internal.edgeRotations.listByRelay, {
          relayId: id<'relays'>(relayId),
          take: Number(query.get('take') ?? 20) || 20,
        }),
      );
    }
    const r = await ctx.runQuery(internal.edgeRotations.getForAdmin, {
      id: id<'edgeRotations'>(b),
    });
    return r ? json(r) : notFound();
  }
  if (a === 'probes') {
    if (!b) {
      // Run history of one target: ?target=<kind>:<ref>
      const target = parseTargetKey(query.get('target') ?? '');
      if (!target) return errorJson('validation', 'target (<kind>:<ref>) is required', 400);
      return json({
        runs: await ctx.runQuery(internal.probes.listRuns, {
          target,
          take: Number(query.get('take') ?? 20) || 20,
        }),
      });
    }
    if (b === 'matrix' && !c) return json(await ctx.runQuery(internal.probes.matrix, {}));
    if (b === 'summary' && !c) {
      // ?window=<ms> ending now, or ?from=<ms>[&to=<ms>] (the query clamps the span).
      const windowMs = Number(query.get('window') ?? '');
      const fromMs = Number(query.get('from') ?? '');
      const toMs = Number(query.get('to') ?? '');
      return json(
        await ctx.runQuery(internal.probes.summary, {
          ...(Number.isFinite(fromMs) && fromMs > 0
            ? { sinceMs: fromMs, ...(Number.isFinite(toMs) && toMs > 0 ? { untilMs: toMs } : {}) }
            : { windowMs: Number.isFinite(windowMs) && windowMs > 0 ? windowMs : 7 * 86_400_000 }),
        }),
      );
    }
    if (b === 'targets' && !c)
      return json({ targets: await ctx.runQuery(internal.probeTargets.list, {}) });
    if (b === 'audit' && !c)
      return json({
        entries: await ctx.runQuery(internal.probes.auditFeed, {
          take: Number(query.get('take') ?? 50) || 50,
        }),
      });
    return notFound();
  }
  return notFound();
};

// --- POST ----------------------------------------------------------------------------------------

async function refreshInventory(
  ctx: ActionCtx,
  accountId: Id<'edgeProviderAccounts'>,
): Promise<Response> {
  const inventory: Inventory = await ctx.runAction(internal.edgeProviderOps.inventory, {
    accountId,
  });
  await ctx.runMutation(internal.edgeProviderAccounts.recordInventory, {
    id: accountId,
    inventory: JSON.stringify(inventory),
  });
  const view = await ctx.runQuery(internal.edgeProviderAccounts.getInventory, { id: accountId });
  return json(view ?? { inventory, inventoryAt: new Date().toISOString() });
}

const postHandler: Handler = async (ctx, _req, parts, admin, body) => {
  const [a, b, c, d] = parts;
  const act = actor(admin);
  if (a === 'providers') {
    if (!b) {
      const created = (await ctx.runMutation(internal.edgeProviderAccounts.create, {
        ...body,
        ...act,
      } as never)) as { id: Id<'edgeProviderAccounts'> };
      // A new account is inventoried right away so its existing load balancers
      // show up in the relay import picker without a manual pull (fail-soft:
      // a scheduled action; bad credentials just leave the snapshot empty).
      await ctx.scheduler.runAfter(0, internal.edgeProviderOps.inventory, {
        accountId: created.id,
      });
      return json(created);
    }
    if (b === 'discover') {
      return json(
        await ctx.runAction(internal.edgeProviderOps.discoverOptions, {
          provider: String(body.provider ?? ''),
          credentials: body.credentials ?? {},
          settings: body.settings ?? {},
          accountId:
            typeof body.accountId === 'string' && body.accountId
              ? id<'edgeProviderAccounts'>(body.accountId)
              : undefined,
        }),
      );
    }
    if (b === 'test-credentials') {
      const accountId = id<'edgeProviderAccounts'>(String(body.accountId ?? ''));
      const res = await ctx.runAction(internal.edgeProviderOps.testCredentials, { accountId });
      await ctx.runMutation(internal.edgeProviderAccounts.recordTest, {
        id: accountId,
        ok: res.ok,
        code: res.code,
      });
      let regions: Array<{ id: string; label: string }> = [];
      if (res.ok) {
        try {
          regions = await ctx.runAction(internal.edgeProviderOps.listRegions, { accountId });
        } catch {
          regions = [];
        }
      }
      return json({ ok: res.ok, code: res.code ?? null, regions });
    }
    if (c === 'inventory' && d === 'refresh')
      return refreshInventory(ctx, id<'edgeProviderAccounts'>(b));
    if (c === 'qualify') {
      // The effective template hash is computed server-side; a client-sent one is ignored.
      return json(
        await ctx.runMutation(internal.edgeProviderAccounts.setQualified, {
          id: id<'edgeProviderAccounts'>(b),
          qualified: body.qualified !== false,
          ...act,
        }),
      );
    }
    if (c === 'rotate-credentials' && !d) {
      // New secret (+ its non-secret identifiers) → tested against the provider,
      // applied only on a pass, qualification kept. The body is sealed in transit
      // (POST under the prefix); nothing of it is logged.
      return json(
        await ctx.runAction(internal.edgeProviderOps.rotateCredentials, {
          accountId: id<'edgeProviderAccounts'>(b),
          credentials: body.credentials ?? {},
          identifiers: body.identifiers ?? undefined,
          ...act,
        }),
      );
    }
    return notFound();
  }
  if (a === 'templates') {
    if (!b)
      return json(
        await ctx.runMutation(internal.edgeTemplates.create, { ...body, ...act } as never),
      );
    if (b === 'validate')
      return json(await ctx.runQuery(internal.edgeTemplates.validate, body as never));
    if (b === 'ensure-defaults' && !c)
      return json(await ctx.runMutation(internal.edgeTemplates.ensureDefaults, {}));
    return notFound();
  }
  if (a === 'profiles') {
    if (!b)
      return json(
        await ctx.runMutation(internal.protocolProfiles.create, { ...body, ...act } as never),
      );
    const pid = id<'protocolProfiles'>(b);
    if (c === 'qualify')
      return json(
        await ctx.runMutation(internal.protocolProfiles.recordQualification, {
          ...body,
          id: pid,
          ...act,
        } as never),
      );
    if (c === 'retire-sni')
      return json(
        await ctx.runMutation(internal.protocolProfiles.retireSni, {
          id: pid,
          snis: snis(body),
          ...act,
        }),
      );
    if (c === 'reactivate-sni')
      return json(
        await ctx.runMutation(internal.protocolProfiles.reactivateSni, {
          id: pid,
          snis: snis(body),
          ...act,
        }),
      );
    return notFound();
  }
  if (a === 'relays') {
    if (!b)
      return json(await ctx.runMutation(internal.relays.create, { ...body, ...act } as never));
    if (b === 'node-candidates' && c === 'refresh') {
      const serverId = id<'backendServers'>(String(body.backendServerId ?? ''));
      const r = await ctx.runAction(internal.backendNodes.refreshNodeInventory, {
        backendServerId: serverId,
      });
      return json({
        ...r,
        ...(await ctx.runQuery(internal.edgeAdmin.nodeCandidates, { backendServerId: serverId })),
      });
    }
    const relayId = id<'relays'>(b);
    switch (c) {
      case 'adopt':
        return json(
          await ctx.runMutation(internal.relays.adoptEdge, {
            ...body,
            relayId,
            ...act,
          } as never),
        );
      case 'provision':
        return json(
          await ctx.runMutation(internal.edgeRotations.start, {
            relayId,
            kind: 'provision',
            trigger: 'manual',
            publishOnDone: body.publish !== false,
            slotId: typeof body.slotId === 'string' ? id<'relaySlots'>(body.slotId) : undefined,
            ...act,
          }),
        );
      case 'rotate':
      case 'burn':
        return json(
          await ctx.runMutation(internal.edgeRotations.start, {
            relayId,
            kind: 'replace',
            trigger: 'manual',
            burn: c === 'burn',
            force: body.force === true,
            targetEdgeId: id<'edges'>(String(body.edgeId ?? '')),
            ...act,
          }),
        );
      case 'publish':
        return json(
          await ctx.runMutation(internal.edgeRotations.start, {
            relayId,
            kind: 'publish',
            trigger: 'manual',
            toEdgeId: id<'edges'>(String(body.edgeId ?? '')),
            ...act,
          }),
        );
      case 'cancel': {
        const origin = await ctx.runQuery(internal.relays.get, { id: relayId });
        if (!origin?.activeRotationId)
          return errorJson('edge.no_rotation', 'No rotation is running', 409);
        return json(
          await ctx.runMutation(internal.edgeRotations.requestCancel, {
            rotationId: origin.activeRotationId,
            ...act,
          }),
        );
      }
      case 'resolve-quarantine':
        return json(
          await ctx.runMutation(internal.edgeRotations.resolveQuarantine, {
            relayId,
            keep: body.keep === 'previous' ? 'previous' : 'current',
            ...act,
          }),
        );
      case 'probe': {
        // Every published edge of the relay (+ the node itself when it opted in).
        const relay = await ctx.runQuery(internal.relays.get, { id: relayId });
        if (!relay) return notFound();
        const edges = await ctx.runQuery(internal.edgeAdmin.publishedEdgeIdsOf, { relayId });
        const targets: Array<{ kind: 'edge' | 'relay' | 'custom'; ref: string }> = edges.map(
          (e) => ({ kind: 'edge', ref: e as string }),
        );
        if (relay.probeNode) targets.push({ kind: 'relay', ref: relayId as string });
        if (targets.length === 0) return json({ runIds: [], skipped: [] });
        return json(await ctx.runMutation(internal.probes.requestMany, { targets, ...act }));
      }
      default:
        return notFound();
    }
  }
  if (a === 'edges' && b) {
    const edgeId = id<'edges'>(b);
    if (c === 'live' && d === 'refresh') {
      const edge = await ctx.runQuery(internal.edges.get, { id: edgeId });
      if (!edge) return notFound();
      if (!edge.accountId)
        return errorJson(
          'edge.unmanaged',
          'An adopted edge has no provider account to inspect',
          409,
        );
      const res: InspectResult = await ctx.runAction(internal.edgeProviderOps.inspect, {
        accountId: edge.accountId,
        ledger: { steps: edge.steps, resources: edge.resources },
      });
      await ctx.runMutation(internal.edgeAdmin.recordLive, {
        edgeId,
        snapshot: JSON.stringify(res),
        ...act,
      });
      return json(await ctx.runQuery(internal.edgeAdmin.liveView, { edgeId }));
    }
    const edge = await ctx.runQuery(internal.edges.get, { id: edgeId });
    if (!edge) return notFound();
    switch (c) {
      case 'publish':
        // Pool index 0 on a Host-managed origin needs the flip → rotation machine.
        return json(
          body.direct === true
            ? await ctx.runMutation(internal.relays.publishEdge, {
                relayId: edge.relayId,
                edgeId,
                poolIndex: typeof body.poolIndex === 'number' ? body.poolIndex : undefined,
                ...act,
              })
            : await ctx.runMutation(internal.edgeRotations.start, {
                relayId: edge.relayId,
                kind: 'publish',
                trigger: 'manual',
                toEdgeId: edgeId,
                ...act,
              }),
        );
      case 'unpublish':
        return json(
          await ctx.runMutation(internal.relays.unpublishEdge, {
            relayId: edge.relayId,
            edgeId,
            keepActive: body.keepActive === true,
            ...act,
          }),
        );
      case 'retry-destroy':
        return json(
          await ctx.runMutation(internal.edgeReconcileMutations.retryDestroy, { edgeId, ...act }),
        );
      case 'resolve-operator': {
        const action = body.action;
        if (action !== 'destroy' && action !== 'forget' && action !== 'reactivate') {
          return errorJson('validation', 'action must be destroy, forget or reactivate', 400);
        }
        return json(
          await ctx.runMutation(internal.edgeAdmin.resolveOperator, { edgeId, action, ...act }),
        );
      }
      case 'probe': {
        // Through requestMany so the operator's request is audited with the
        // actor (requestProbes takes no actor arg). One target: a skip is an error.
        const r = await ctx.runMutation(internal.probes.requestMany, {
          targets: [{ kind: 'edge', ref: edgeId as string }],
          ...act,
        });
        if (r.runIds.length === 0 && r.skipped.length > 0) {
          const code = r.skipped[0].split(': ').pop() ?? 'error';
          return errorJson(code, 'The probe could not be requested', statusFromCode(code));
        }
        return json({ runIds: r.runIds });
      }
      default:
        return notFound();
    }
  }
  if (a === 'probes') {
    if (!b) {
      // Probe several targets now: { targets: ["edge:<id>", ...] | [{kind, ref}], sources? }
      const raw = Array.isArray(body.targets) ? body.targets : [];
      const targets = raw
        .map((t) => (typeof t === 'string' ? parseTargetKey(t) : t))
        .filter(
          (t): t is { kind: 'edge' | 'relay' | 'custom'; ref: string } =>
            !!t && typeof t === 'object' && 'kind' in t && 'ref' in t,
        );
      if (targets.length === 0) return errorJson('validation', 'targets is required', 400);
      return json(
        await ctx.runMutation(internal.probes.requestMany, {
          targets,
          sources: Array.isArray(body.sources) ? (body.sources as never) : undefined,
          ...act,
        }),
      );
    }
    if (b === 'targets' && !c)
      return json(
        await ctx.runMutation(internal.probeTargets.create, { ...body, ...act } as never),
      );
    return notFound();
  }
  if (a === 'render' && b === 'preview') {
    return json(
      await ctx.runQuery(internal.edgeAdmin.renderPreview, {
        relayId: id<'relays'>(String(body.relayId ?? '')),
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
    return json(await ctx.runMutation(internal.edgeAdmin.patchConfig, { patch: body, ...act }));
  if (a === 'probes' && b === 'targets' && c && !parts[3])
    return json(
      await ctx.runMutation(internal.probeTargets.update, {
        ...body,
        id: id<'probeTargets'>(c),
        ...act,
      } as never),
    );
  if (c) return notFound();
  if (a === 'providers' && b) {
    const res = await ctx.runMutation(internal.edgeProviderAccounts.update, {
      ...body,
      id: id<'edgeProviderAccounts'>(b),
      ...act,
    } as never);
    if (body.credentials !== undefined || body.settings !== undefined) {
      await ctx.scheduler.runAfter(0, internal.edgeProviderOps.inventory, {
        accountId: id<'edgeProviderAccounts'>(b),
      });
    }
    return json(res);
  }
  if (a === 'templates' && b)
    return json(
      await ctx.runMutation(internal.edgeTemplates.update, {
        ...body,
        id: id<'edgeTemplates'>(b),
        ...act,
      } as never),
    );
  if (a === 'profiles' && b)
    return json(
      await ctx.runMutation(internal.protocolProfiles.update, {
        ...body,
        id: id<'protocolProfiles'>(b),
        ...act,
      } as never),
    );
  if (a === 'relays' && b)
    return json(
      await ctx.runMutation(internal.relays.update, {
        ...body,
        id: id<'relays'>(b),
        ...act,
      } as never),
    );
  return notFound();
};

// --- PUT (IaC upserts) -----------------------------------------------------------------------------

const putHandler: Handler = async (ctx, _req, parts, admin, body) => {
  const [a, b, c, d, e] = parts;
  const act = actor(admin);
  if (a !== 'relays' || b !== 'by-slug' || !c) return notFound();
  if (!d) {
    await ctx.runMutation(internal.relays.upsertBySlug, {
      ...body,
      slug: c,
      ...act,
    } as never);
    const view = await ctx.runQuery(internal.edgeAdmin.relayBySlugView, { slug: c });
    return view ? json(view) : notFound();
  }
  if (d === 'slots' && e) {
    const origin = await ctx.runQuery(internal.relays.getBySlug, { slug: c });
    if (!origin) return notFound();
    return json(
      await ctx.runMutation(internal.relaySlots.upsert, {
        ...body,
        relayId: origin._id,
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
      await ctx.runMutation(internal.edgeProviderAccounts.remove, {
        id: id<'edgeProviderAccounts'>(b),
        ...act,
      }),
    );
  if (a === 'templates' && b && !c)
    return json(
      await ctx.runMutation(internal.edgeTemplates.remove, {
        id: id<'edgeTemplates'>(b),
        ...act,
      }),
    );
  if (a === 'profiles' && b && !c)
    return json(
      await ctx.runMutation(internal.protocolProfiles.remove, {
        id: id<'protocolProfiles'>(b),
        ...act,
      }),
    );
  if (a === 'edges' && b && !c)
    return json(
      await ctx.runMutation(internal.edgeAdmin.deleteEdge, {
        edgeId: id<'edges'>(b),
        ...act,
      }),
    );
  if (a === 'probes' && b === 'targets' && c && !d)
    return json(
      await ctx.runMutation(internal.probeTargets.remove, { id: id<'probeTargets'>(c), ...act }),
    );
  if (a === 'relays' && b) {
    if (b === 'by-slug' && c) {
      const origin = await ctx.runQuery(internal.relays.getBySlug, { slug: c });
      if (!origin) return json({ ok: true, deleted: true });
      if (d === 'slots' && e)
        return json(
          await ctx.runMutation(internal.relaySlots.retire, {
            relayId: origin._id,
            slotKey: e,
            ...act,
          }),
        );
      if (!d)
        return json(
          await ctx.runMutation(internal.relays.requestDelete, { id: origin._id, ...act }),
        );
      return notFound();
    }
    if (!c)
      return json(
        await ctx.runMutation(internal.relays.requestDelete, {
          id: id<'relays'>(b),
          ...act,
        }),
      );
  }
  return notFound();
};

export function registerEdgeRoutes(http: HttpRouter): void {
  http.route({ pathPrefix: PREFIX, method: 'GET', handler: wrap(getHandler, true) });
  http.route({ pathPrefix: PREFIX, method: 'POST', handler: wrap(postHandler, true) });
  http.route({ pathPrefix: PREFIX, method: 'PATCH', handler: wrap(patchHandler, true) });
  http.route({ pathPrefix: PREFIX, method: 'PUT', handler: wrap(putHandler, true) });
  http.route({ pathPrefix: PREFIX, method: 'DELETE', handler: wrap(deleteHandler, false) });
}
