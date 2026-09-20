/**
 * Admin HTTP surface for edges (the L4 load balancers in front of origins): `/api/v1/admin/edges/*`. One prefix
 * route per verb feeds a small dispatcher, so the HPKE policy is a clean
 * per-verb prefix rule (envelope.ts): GET reveals, POST seals both legs,
 * PATCH/PUT seal the body, DELETE carries nothing. Scopes: `admin:settings:*`
 * for the config namespace, `admin:servers:*` for everything else; the two
 * POSTs that only compute (`render/preview`, `templates/validate`) need the
 * READ scope. The POSTs that reach a cloud provider / spend probe credits are
 * rate-limited per actor (`admin.edges.provider-call` / `admin.edges.probe`).
 * Responses are the shapes in src/shared/contracts/edges.ts.
 */
import type { HttpRouter } from 'convex/server';
import { httpAction } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Id, TableNames } from './_generated/dataModel';
import { sealed } from './lib/hpke';
import { makeFail, notFound, throttle, unauth } from './lib/adminHttp';
import { errorJson, json, readJson, resolveAdmin, type AdminAuth } from './lib/http';
import type { RateLimitPolicyKey } from './lib/rateLimitPolicy';
import type { InspectResult, Inventory } from './lib/edges/providers/types';
import { parseTargetKey } from './probes';
import { assertWithinBoundary, type RegistrationBoundary } from './relays';

const PREFIX = '/api/v1/admin/edges/';

type Handler = (
  ctx: ActionCtx,
  req: Request,
  parts: string[],
  admin: EdgeAdminAuth,
  body: Record<string, unknown>,
  query: URLSearchParams,
) => Promise<Response>;

function statusFromCode(code: string): number {
  if (code === 'not_found') return 404;
  // A register-scoped token reaching outside its boundary is a permission refusal.
  if (code === 'edge.registration_boundary') return 403;
  // The backend (or a step that depends on it) failed: an upstream fault, not a refusal.
  if (code === 'backend.panel_read_failed' || code === 'edge.plan_step_failed') return 502;
  if (code === 'conflict' || code.startsWith('edge.')) return 409;
  // The hourly probe budget is a quota: answer like a rate limit.
  if (code === 'probe.budget_exhausted') return 429;
  if (code === 'validation') return 400;
  return 400;
}

const fail = makeFail('edges', statusFromCode);

/**
 * First segments that are collections of their own; anything else is an edge
 * id. `profiles` (the removed protocol-profile collection) stays reserved so a
 * stale caller gets a clean 404 instead of an invalid-edge-id error.
 */
const RESERVED = new Set([
  'summary',
  'config',
  'providers',
  'templates',
  'listeners',
  'profiles',
  'relays',
  'rotations',
  'probes',
  'render',
  'edges',
  'attention',
  'setup-status',
  'maintenance',
  'delivery-bindings',
  'automation',
  'setup-runs',
  'sni',
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
  if (parts.length === 1 && parts[0] === 'setup-status') return true;
  if (parts.length === 4 && parts[0] === 'sni' && parts[1] === 'bindings' && parts[3] === 'plan')
    return true;
  if (parts.length === 3 && parts[0] === 'relays' && parts[2] === 'preflight') return true;
  return (
    parts.length === 2 &&
    ((parts[0] === 'render' && parts[1] === 'preview') ||
      (parts[0] === 'templates' && parts[1] === 'validate'))
  );
}

/** The node role's registration routes: `origins/by-slug/{slug}[/listeners/{key}]`. */
export function isRegistrationRoute(parts: string[]): boolean {
  return parts[0] === 'relays' && parts[1] === 'by-slug' && !!parts[2];
}

/**
 * Config routes need the settings scope; everything else the servers scope.
 * The registration routes ALSO accept `admin:edges:register` (any-of), whose
 * callers are additionally confined to their token's registration boundary.
 */
export function scopeFor(parts: string[], method: string): string | string[] {
  // The automation switch writes `edge.*` config: the settings scope, like `config`.
  const ns =
    parts[0] === 'config' ||
    parts[0] === 'automation' ||
    (parts[0] === 'sni' && parts[1] === 'config')
      ? 'settings'
      : 'servers';
  const write = method !== 'GET' && !(method === 'POST' && isReadOnlyPost(parts));
  const full = `admin:${ns}:${write ? 'write' : 'read'}`;
  if (isRegistrationRoute(parts) && method !== 'POST' && method !== 'PATCH')
    return ['admin:edges:register', full];
  return full;
}

/**
 * Which POSTs are throttled, and under which policy. `provider-call` = a live
 * call to a cloud provider / the backend (or a CPU-bound preview render);
 * `probe` = measurement runs that spend third-party credits.
 */
export function throttlePolicyFor(parts: string[]): RateLimitPolicyKey | null {
  const [a, b, c, d] = parts;
  // Qualifying server names opens sockets from the control plane.
  if (a === 'sni' && b === 'qualify' && !c) return 'admin.edges.provider-call';
  // A rollout writes a backend profile; a test link fetches a credential body.
  if (
    a === 'sni' &&
    (b === 'bindings' || b === 'rollouts') &&
    (d === 'rollout' || d === 'test-link')
  )
    return 'admin.edges.provider-call';
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
  // The test link fetches the credential body and lists the backend Hosts.
  if (a === 'edges' && b && c === 'test-link' && !d) return 'admin.edges.provider-call';
  if (a === 'relays' && b === 'node-candidates' && c === 'refresh') {
    return 'admin.edges.provider-call';
  }
  // Importing a front inspects the provider resource first: an outbound call.
  if (a === 'relays' && b && c === 'adopt' && !d) return 'admin.edges.provider-call';
  // The quarantine resolver's live column lists the backend's Hosts.
  if (a === 'relays' && b && c === 'quarantine' && d === 'inspect')
    return 'admin.edges.provider-call';
  if (a === 'edges' && b && c === 'live' && d === 'refresh') return 'admin.edges.provider-call';
  // An authenticated session through the front: an outbound call like any other.
  if (a === 'edges' && b && c === 'qualify' && !d) return 'admin.edges.provider-call';
  if (a === 'render' && b === 'preview') return 'admin.edges.provider-call';
  if (a === 'edges' && b && c === 'probe') return 'admin.edges.probe';
  if (a === 'relays' && b && c === 'probe') return 'admin.edges.probe';
  // Minting the L7 qualification credential creates a backend user.
  if (a === 'relays' && b && c === 'qualification-credential' && !d)
    return 'admin.edges.provider-call';
  if (a === 'probes' && !b) return 'admin.edges.probe';
  // The setup plan lists the node's transports and Hosts from the backend.
  if (a === 'setup-runs' && b === 'plan' && !c) return 'admin.edges.provider-call';
  return null;
}

/**
 * The GETs that reach a backend or open sockets from the control plane (the
 * transport-candidates origin probe, the test link's credential body + Host
 * listing): throttled under the same policy as the provider-calling POSTs.
 */
export function throttlePolicyForGet(parts: string[]): RateLimitPolicyKey | null {
  const [a, b, c, d] = parts;
  if (a === 'relays' && b === 'inbound-candidates' && !c) return 'admin.edges.provider-call';
  return null;
}

function wrap(handler: Handler, sealedRoute: boolean) {
  const inner = async (ctx: ActionCtx, req: Request): Promise<Response> => {
    const seg = segments(req);
    if (!seg) return errorJson('validation', 'Malformed path encoding', 400);
    const { parts, query } = seg;
    const method = req.method.toUpperCase();
    const required = scopeFor(parts, method);
    const admin: EdgeAdminAuth | null = await resolveAdmin(ctx, req, required);
    if (!admin) return unauth();
    // A bearer caller admitted ONLY by the register scope is confined to its
    // token's registration boundary on every registration verb.
    if (isRegistrationRoute(parts) && admin.tokenId && admin.tokenScopes) {
      const fullScope = Array.isArray(required) ? required[1] : required;
      if (!admin.tokenScopes.includes(fullScope)) {
        const boundary = await ctx.runQuery(internal.apiTokens.registrationBoundary, {
          tokenId: admin.tokenId,
        });
        // A register token without a boundary may register nothing.
        admin.boundary = boundary ?? { backendServerIds: [] };
      }
    }
    if (method === 'POST' || method === 'GET') {
      const policyKey = method === 'POST' ? throttlePolicyFor(parts) : throttlePolicyForGet(parts);
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

/** AdminAuth plus the registration boundary of a register-scoped token (undefined = unbounded). */
type EdgeAdminAuth = AdminAuth & { boundary?: RegistrationBoundary };

/** Refuse a bounded caller outside its boundary for an EXISTING origin (GET / DELETE / PUT update). */
async function assertRelayWithinBoundary(ctx: ActionCtx, slug: string, admin: EdgeAdminAuth) {
  if (!admin.boundary) return;
  const relay = await ctx.runQuery(internal.relays.getBySlug, { slug });
  if (relay) assertWithinBoundary(relay.origin, admin.boundary);
}

// --- GET ----------------------------------------------------------------------------------------

const getHandler: Handler = async (ctx, _req, parts, _admin, _body, query) => {
  const [a, b, c, d, e] = parts;
  if (!a || a === 'summary') return json(await ctx.runQuery(internal.edgeAdmin.summary, {}));
  // Server-name families (docs/edges.md "Server-name families").
  if (a === 'sni') {
    if (b === 'config' && !c) return json(await ctx.runQuery(internal.sniFamilies.configView, {}));
    if (b === 'families' && !c) return json(await ctx.runQuery(internal.sniFamilies.list, {}));
    if (b === 'families' && c && !d)
      return json(await ctx.runQuery(internal.sniFamilies.detail, { slug: c }));
    if (b === 'rollouts' && c && !d)
      return json(
        await ctx.runQuery(internal.sniRollouts.status, { rolloutId: id<'sniRollouts'>(c) }),
      );
    return notFound();
  }
  if (a === 'config') return json(await ctx.runQuery(internal.edgeAdmin.configView, {}));
  if (a === 'attention' && !b) return json(await ctx.runQuery(internal.edgeOperator.attention, {}));
  if (a === 'setup-status' && !b) {
    const relaySlug = query.get('relay') ?? undefined;
    return json(
      await ctx.runQuery(internal.edgeOperator.setupStatus, {
        ...(relaySlug ? { relaySlug } : {}),
      }),
    );
  }
  if (a === 'maintenance' && !b) return json(await maintenanceView(ctx));
  if (a === 'delivery-bindings' && !b)
    return json(await ctx.runQuery(internal.edgeOperator.deliveryBindings, {}));
  if (a === 'setup-runs') {
    if (!b) return json(await ctx.runQuery(internal.edgeSetupRuns.listForAdmin, {}));
    if (!c) {
      const run = await ctx.runQuery(internal.edgeSetupRuns.getForAdmin, {
        id: id<'edgeSetupRuns'>(b),
      });
      return run ? json(run) : notFound();
    }
    return notFound();
  }
  if (a === 'providers') {
    if (b === 'usage' && !c)
      return json(await ctx.runQuery(internal.edgeOperator.providersUsage, {}));
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
  if (a === 'relays') {
    if (!b) return json(await ctx.runQuery(internal.relays.listForAdmin, {}));
    if (b === 'lookup' && !c) {
      // The CMS's full admin view by slug (servers:read only; never the register scope).
      const slug = query.get('slug');
      if (!slug) return errorJson('validation', 'slug is required', 400);
      const r = await ctx.runQuery(internal.edgeOperator.relayLookup, { slug });
      return r ? json(r) : notFound();
    }
    if (b === 'node-candidates' && !c) {
      const serverId = query.get('backendServerId');
      if (!serverId) return errorJson('validation', 'backendServerId is required', 400);
      return json(
        await ctx.runQuery(internal.edgeAdmin.nodeCandidates, {
          backendServerId: id<'backendServers'>(serverId),
        }),
      );
    }
    if (b === 'inbound-candidates' && !c) {
      // Discovery with the origin probe applied (throttled: a backend call plus sockets).
      const serverId = query.get('backendServerId');
      const nodeUuid = query.get('nodeUuid');
      if (!serverId || !nodeUuid)
        return errorJson('validation', 'backendServerId and nodeUuid are required', 400);
      return json(
        await ctx.runAction(internal.edgeOriginProbe.inboundCandidates, {
          backendServerId: id<'backendServers'>(serverId),
          nodeUuid,
        }),
      );
    }
    if (b === 'by-slug' && c) {
      await assertRelayWithinBoundary(ctx, c, _admin);
      const view = await ctx.runQuery(internal.edgeAdmin.relayBySlugView, { slug: c });
      if (!view) return notFound();
      if (d === 'listeners' && e) {
        const l = view.listeners.find((x) => x.listenerKey === e);
        return l ? json(l) : notFound();
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
    if (c === 'listeners' && !d) {
      const r = await ctx.runQuery(internal.edgeAdmin.relayListenersView, {
        relayId: id<'relays'>(b),
      });
      return r ? json(r) : notFound();
    }
    if (c === 'rotations') {
      return json(
        await ctx.runQuery(internal.edgeRotations.listByRelay, {
          relayId: id<'relays'>(b),
        }),
      );
    }
    if (c === 'timeline' && !d)
      return json(
        await ctx.runQuery(internal.edgeOperator.timeline, {
          relayId: id<'relays'>(b),
          take: Number(query.get('take') ?? 100) || 100,
        }),
      );
    if (c === 'quarantine' && !d)
      return json(
        await ctx.runQuery(internal.edgeOperator.quarantineView, { relayId: id<'relays'>(b) }),
      );
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
    if (c === 'verification-binding' && !d) {
      // What the operator is about to test, exactly as `POST .../verify` must
      // echo it back (the test-link builder reuses this).
      const b2 = await ctx.runQuery(internal.edgeVerification.binding, { edgeId: id<'edges'>(b) });
      return b2 ? json(b2) : notFound();
    }
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

async function maintenanceView(ctx: ActionCtx) {
  const m = await ctx.runQuery(internal.edgeMaintenance.state, {});
  return {
    frozen: m.frozen,
    reason: m.reason,
    since: m.since ? new Date(m.since).toISOString() : null,
  };
}

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
  const [a, b, c, d, e] = parts;
  const act = actor(admin);
  if (a === 'sni') {
    if (b === 'families' && !c)
      return json(
        await ctx.runMutation(internal.sniFamilies.create, {
          slug: String(body.slug ?? ''),
          label: String(body.label ?? ''),
          targetAddress: String(body.targetAddress ?? ''),
          targetPort: Number(body.targetPort ?? 443),
          requireH2: body.requireH2 === true,
          ...act,
        }),
      );
    if (b === 'families' && c && d === 'names' && !e)
      return json(
        await ctx.runMutation(internal.sniFamilies.importNames, {
          slug: c,
          lines: Array.isArray(body.lines)
            ? body.lines.map(String)
            : String(body.text ?? '').split(/\r?\n/),
          ...act,
        }),
      );
    const NAME_ACTIONS = ['retire', 'reactivate', 'burn', 'recheck'] as const;
    const action = NAME_ACTIONS.find((x) => x === e);
    if (b === 'families' && c && d === 'names' && action)
      return json(
        await ctx.runMutation(internal.sniFamilies.setNames, {
          slug: c,
          names: snis(body),
          action,
          ...act,
        }),
      );
    // An operator's judgement of names in one curated country.
    if (b === 'families' && c && d === 'names' && e === 'country')
      return json(
        await ctx.runMutation(internal.sniFamilies.setCountry, {
          slug: c,
          names: snis(body),
          country: String(body.country ?? ''),
          state:
            body.state === 'proven' || body.state === 'blocked' ? body.state : ('unknown' as const),
          ...act,
        }),
      );
    if (b === 'families' && c && d === 'bind' && !e)
      return json(
        await ctx.runMutation(internal.sniFamilies.bind, {
          slug: c,
          backendSlug: String(body.backendSlug ?? ''),
          inboundTag: String(body.inboundTag ?? ''),
          ...act,
        }),
      );
    if (b === 'qualify' && !c) return json(await ctx.runAction(internal.sniQualifyOps.run, {}));
    if (b === 'bindings' && c && d === 'plan' && !e)
      return json(
        await ctx.runQuery(internal.sniRollouts.plan, { bindingId: id<'sniInboundBindings'>(c) }),
      );
    if (b === 'bindings' && c && d === 'rollout' && !e)
      return json(
        await ctx.runAction(internal.sniRollouts.start, {
          bindingId: id<'sniInboundBindings'>(c),
          ...act,
        }),
      );
    if (b === 'rollouts' && c && d === 'test-link' && !e)
      return json(
        await ctx.runAction(internal.sniRollouts.issueReceipt, {
          rolloutId: id<'sniRollouts'>(c),
          edgeId: id<'edges'>(String(body.edgeId ?? '')),
          sni: typeof body.sni === 'string' ? body.sni : undefined,
          ...act,
        }),
      );
    if (b === 'receipts' && c && d === 'confirm' && !e)
      return json(
        await ctx.runMutation(internal.sniRollouts.confirmReceipt, {
          receiptId: id<'sniAcceptanceReceipts'>(c),
          ...act,
        }),
      );
    return notFound();
  }
  if (a === 'setup-status' && !b) {
    // A draft: the wizard's intended origin + listeners before the origin exists (read-only).
    return json(
      await ctx.runQuery(internal.edgeOperator.setupStatus, {
        draft: (body.draft ?? body) as never,
      }),
    );
  }
  if (a === 'maintenance' && (b === 'freeze' || b === 'thaw') && !c) {
    if (b === 'freeze')
      await ctx.runMutation(internal.edgeMaintenance.freeze, {
        reason: typeof body.reason === 'string' ? body.reason : undefined,
        ...act,
      });
    else await ctx.runMutation(internal.edgeMaintenance.thaw, { ...act });
    return json(await maintenanceView(ctx));
  }
  if (a === 'delivery-bindings' && b && c === 'release' && !d)
    return json(
      await ctx.runMutation(internal.relays.releaseDeliveryBinding, {
        id: id<'edgeDeliveryBindings'>(b),
        ...act,
      }),
    );
  // The one automation switch (settings scope): `{on: boolean}`.
  if (a === 'automation' && !b) {
    if (typeof body.on !== 'boolean') return errorJson('validation', 'on must be a boolean', 400);
    return json(await ctx.runMutation(internal.edgeAdmin.setAutomation, { on: body.on, ...act }));
  }
  // Guided setup runs: plan (read-only over the backend), create, and the three
  // operator verbs on a run (cancel / retry / continue).
  if (a === 'setup-runs') {
    if (b === 'plan' && !c) {
      return json(
        await ctx.runAction(internal.edgeSetupPlan.plan, {
          backendServerId: id<'backendServers'>(String(body.backendServerId ?? '')),
          nodeUuid: String(body.nodeUuid ?? ''),
        }),
      );
    }
    if (!b) {
      const uuids = Array.isArray(body.approvedHideUuids)
        ? body.approvedHideUuids.filter((x): x is string => typeof x === 'string')
        : [];
      return json(
        await ctx.runAction(internal.edgeSetupPlan.create, {
          backendServerId: id<'backendServers'>(String(body.backendServerId ?? '')),
          nodeUuid: String(body.nodeUuid ?? ''),
          accountId: id<'edgeProviderAccounts'>(String(body.accountId ?? '')),
          planHash: String(body.planHash ?? ''),
          approvedHideUuids: uuids,
          ...(body.keepDirect === true ? { keepDirect: true } : {}),
          ...act,
        }),
      );
    }
    const runId = id<'edgeSetupRuns'>(b);
    if (c === 'cancel' && !d)
      return json(await ctx.runAction(internal.edgeSetupRuns.cancel, { runId, ...act }));
    if (c === 'retry' && !d) {
      return json(
        await ctx.runMutation(internal.edgeSetupRuns.retry, {
          runId,
          ...(body.tryAnotherAddress === true ? { tryAnotherAddress: true } : {}),
          ...(body.acceptPartial === true ? { acceptPartial: true } : {}),
          ...(typeof body.accountId === 'string' && body.accountId
            ? { accountId: id<'edgeProviderAccounts'>(body.accountId) }
            : {}),
          ...act,
        }),
      );
    }
    if (c === 'continue' && !d) {
      const confirmations = Array.isArray(body.confirmations)
        ? body.confirmations.map((x) => {
            const o = (x ?? {}) as Record<string, unknown>;
            return {
              edgeId: id<'edges'>(String(o.edgeId ?? '')),
              endpoint: String(o.endpoint ?? ''),
              listenerRevision: Number(o.listenerRevision ?? -1),
              configHash: String(o.configHash ?? ''),
            };
          })
        : undefined;
      const uuids = Array.isArray(body.approvedHideUuids)
        ? body.approvedHideUuids.filter((x): x is string => typeof x === 'string')
        : undefined;
      return json(
        await ctx.runMutation(internal.edgeSetupRuns.resume, {
          runId,
          ...(confirmations ? { confirmations } : {}),
          ...(uuids ? { approvedHideUuids: uuids } : {}),
          ...(body.keepDirect === true ? { keepDirect: true } : {}),
          ...act,
        }),
      );
    }
    return notFound();
  }
  if (a === 'providers') {
    if (!b) {
      const created = (await ctx.runMutation(internal.edgeProviderAccounts.create, {
        ...body,
        ...act,
      } as never)) as { id: Id<'edgeProviderAccounts'> };
      // A new account is inventoried right away so its existing load balancers
      // show up in the origin import picker without a manual pull (fail-soft:
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
      // The action records the outcome itself (code, provider answer, observed facts).
      const res = await ctx.runAction(internal.edgeProviderOps.testCredentials, { accountId });
      let regions: Array<{ id: string; label: string }> = [];
      if (res.ok) {
        try {
          regions = await ctx.runAction(internal.edgeProviderOps.listRegions, { accountId });
        } catch {
          regions = [];
        }
      }
      return json({ ok: res.ok, code: res.code ?? null, detail: res.detail ?? null, regions });
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
  if (a === 'listeners') {
    // Fleet-wide retirement of a burned name: ONE transaction over every listener.
    if (b === 'retire-name' && !c)
      return json(
        await ctx.runMutation(internal.relayListeners.retireNameEverywhere, {
          name: String(body.name ?? ''),
          ...act,
        }),
      );
    const lid = id<'relayListeners'>(b);
    if (c === 'retire-name')
      return json(
        await ctx.runMutation(internal.relayListeners.retireName, {
          id: lid,
          names: snis(body),
          ...act,
        }),
      );
    if (c === 'reactivate-name')
      return json(
        await ctx.runMutation(internal.relayListeners.reactivateName, {
          id: lid,
          names: snis(body),
          ...act,
        }),
      );
    if (c === 'sni-pick') {
      // The field is REQUIRED: `null` means "back to the legacy PRF", which
      // reshuffles nearly every member's name, so an empty body or a missing
      // field must never be read as that.
      if (!('version' in body))
        return errorJson('validation', "version is required: 'hrw1' or null", 400);
      const version = body.version;
      if (version !== null && version !== 'hrw1')
        return errorJson('validation', "version must be 'hrw1' or null", 400);
      return json(
        await ctx.runMutation(internal.relayListeners.setSniPick, { id: lid, version, ...act }),
      );
    }
    if (c === 'enable' || c === 'disable')
      return json(
        await ctx.runMutation(internal.relayListeners.setEnabled, {
          id: lid,
          enabled: c === 'enable',
          ...act,
        }),
      );
    return notFound();
  }
  if (a === 'relays') {
    if (!b) {
      // `deferBinding` / `setupOwned` are internal (a guided setup run); a request body never sets them.
      const { deferBinding: _defer, setupOwned: _owned, ...rest } = body;
      return json(await ctx.runMutation(internal.relays.create, { ...rest, ...act } as never));
    }
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
    if (c === 'listeners' && d && e === 'adopt-host')
      return json(
        await ctx.runAction(internal.hostOps.adoptListenerHost, {
          relayId,
          listenerKey: d,
          hostUuid: String(body.hostUuid ?? ''),
          ...act,
        }),
      );
    if (c === 'quarantine' && d === 'inspect')
      return json(await ctx.runAction(internal.edgeOperator.quarantineInspect, { relayId }));
    if (c === 'preflight' && !d) {
      const kind = String(body.kind ?? '');
      if (!['provision', 'publish', 'replace', 'test-provision'].includes(kind))
        return errorJson(
          'validation',
          'kind must be provision, publish, replace or test-provision',
          400,
        );
      return json(
        await ctx.runQuery(internal.edgeOperator.preflight, {
          relayId,
          kind: kind as 'provision' | 'publish' | 'replace' | 'test-provision',
          edgeId:
            typeof body.edgeId === 'string' && body.edgeId ? id<'edges'>(body.edgeId) : undefined,
          listenerKey: typeof body.listenerKey === 'string' ? body.listenerKey : undefined,
          accountId:
            typeof body.accountId === 'string' && body.accountId
              ? id<'edgeProviderAccounts'>(body.accountId)
              : undefined,
          templateId:
            typeof body.templateId === 'string' && body.templateId
              ? id<'edgeTemplates'>(body.templateId)
              : undefined,
          trigger: triggerOf(body.trigger),
        }),
      );
    }
    if (c === 'test-provision' && !d) {
      // The explicit bootstrap provision: a named, tested account (unqualified
      // allowed) on a named listener; never published.
      const listenerKey = String(body.listenerKey ?? '');
      const listeners = await ctx.runQuery(internal.relayListeners.listByRelay, { relayId });
      const l = listeners.find((x) => x.listenerKey === listenerKey && !x.retired);
      if (!l) return errorJson('edge.listener_not_found', 'Unknown listener', 404);
      if (typeof body.accountId !== 'string' || !body.accountId)
        return errorJson('validation', 'accountId is required', 400);
      return json(
        await ctx.runMutation(internal.edgeRotations.start, {
          relayId,
          kind: 'provision',
          trigger: 'manual',
          publishOnDone: false,
          listenerId: id<'relayListeners'>(l.id),
          requestedAccountId: id<'edgeProviderAccounts'>(body.accountId),
          requestedTemplateId:
            typeof body.templateId === 'string' && body.templateId
              ? id<'edgeTemplates'>(body.templateId)
              : undefined,
          allowUnqualified: true,
          ...act,
        }),
      );
    }
    switch (c) {
      case 'rebalance':
        // Coverage at the cap: unpublish ONE duplicate back to standby so
        // upkeep can publish the uncovered listener. Never automatic.
        return json(await ctx.runMutation(internal.relays.rebalance, { relayId, ...act }));
      case 'require-edges':
        // The only path besides a setup run's go-live to the deferred binding:
        // the SAME activation policy (untested L4 endpoints come back as
        // pending instead of binding; then rehearsal + go-live).
        return json(
          await ctx.runMutation(internal.edgeSetupRuns.requireEdges, {
            relayId,
            ...(typeof body.accountId === 'string' && body.accountId
              ? { accountId: id<'edgeProviderAccounts'>(body.accountId) }
              : {}),
            ...act,
          }),
        );
      case 'qualification-credential':
        // Mint (or re-mint) the backend account the L7 front qualification
        // authenticates with; the credential never leaves the server.
        return json(await ctx.runAction(internal.relayQualification.mint, { relayId, ...act }));
      case 'adopt': {
        // Importing a HOSTNAME front from a provider account: ask the adapter
        // what the resource really is FIRST (its real child ids and versions,
        // every hostname it serves, what it dials, whether it is shared). The
        // mutation then has an ownership proof and everything discovery,
        // qualification and a partial destroy will need; without it the import
        // would be an unqualifiable row.
        const accountId =
          typeof body.accountId === 'string' && body.accountId
            ? id<'edgeProviderAccounts'>(body.accountId)
            : null;
        const resourceId = typeof body.resourceId === 'string' ? body.resourceId.trim() : '';
        const hostname = typeof body.hostname === 'string' ? body.hostname.trim() : '';
        let inspected: {
          resources: Array<{ kind: string; resourceId: string; meta?: string }>;
          inspection: { hostnames: string[]; shared: boolean; content?: string };
        } | null = null;
        if (accountId && resourceId && hostname) {
          const insp = await ctx.runAction(internal.edgeProviderOps.inspectForAdoption, {
            accountId,
            resourceId,
            hostname,
          });
          inspected = {
            resources: insp.resources.map((r) => ({
              kind: r.kind,
              resourceId: r.resourceId,
              // The ledger stores `meta` as JSON, exactly as every step outcome does.
              ...(r.meta ? { meta: JSON.stringify(r.meta) } : {}),
            })),
            inspection: {
              hostnames: insp.hostnames,
              shared: insp.shared,
              ...(insp.content ? { content: insp.content } : {}),
            },
          };
        }
        // `resourceId` addresses the PROVIDER call above, not the mutation.
        const { resourceId: _picked, ...rest } = body;
        return json(
          await ctx.runMutation(internal.relays.adoptEdge, {
            ...rest,
            ...(inspected ?? {}),
            relayId,
            ...act,
          } as never),
        );
      }
      case 'listeners':
        // An admin-owned listener (never pruned by the role's registration).
        return json(
          await ctx.runMutation(internal.relayListeners.upsert, {
            relayId,
            spec: body as never,
            ...act,
          }),
        );
      case 'provision':
        return json(
          await ctx.runMutation(internal.edgeRotations.start, {
            relayId,
            kind: 'provision',
            trigger: 'manual',
            publishOnDone: body.publish !== false,
            listenerId:
              typeof body.listenerId === 'string'
                ? id<'relayListeners'>(body.listenerId)
                : undefined,
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
            // Waives ONLY the affected-country evidence gate; the transport
            // proof, the TLS chain and every binding check still apply.
            forceGeoEvidence: body.forceGeoEvidence === true,
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
            forceGeoEvidence: body.forceGeoEvidence === true,
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
            reason: typeof body.reason === 'string' ? body.reason.slice(0, 200) : undefined,
            ...act,
          }),
        );
      case 'probe': {
        // Every published edge of the origin (+ the node itself when it opted in).
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
                forceGeoEvidence: body.forceGeoEvidence === true,
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
      case 'test-link':
        if (d === 'release') {
          // The card closed or finished: the temporary credential behind the
          // link expires now instead of at its TTL (scoped to the edge's origin).
          if (typeof body.credentialId !== 'string')
            return errorJson('validation', 'credentialId is required', 400);
          await ctx.runMutation(internal.edgeTestCredentials.releaseForEdge, {
            edgeId,
            credentialId: id<'edgeTestCredentials'>(body.credentialId),
          });
          return json({ ok: true });
        }
        // The isolated test link: the candidate connection only, plus the same
        // binding `GET .../verification-binding` shows. A POST under the write
        // scope, not a GET: building it may mint the test credential (a backend
        // user, or a temporary Outline key) and record it. Throttled like the
        // other provider-calling POSTs.
        return json(await ctx.runAction(internal.edgeTestLinks.build, { edgeId }));
      case 'qualify':
        // Run the authenticated end-to-end session through this L7 front now and
        // store the verdict with the configuration it proved.
        return json(await ctx.runAction(internal.frontQualifyOps.run, { edgeId }));
      case 'verify': {
        // The operator's per-endpoint confirmation of an L4 edge: the body
        // echoes the binding `GET .../verification-binding` showed; the
        // mutation recomputes it and refuses a mismatch (`edge.verification_stale`).
        const method = body.method === 'named_connection' ? 'named_connection' : 'test_link';
        if (
          typeof body.endpoint !== 'string' ||
          typeof body.listenerRevision !== 'number' ||
          typeof body.configHash !== 'string'
        )
          return errorJson(
            'validation',
            'endpoint, listenerRevision and configHash are required',
            400,
          );
        return json(
          await ctx.runMutation(internal.edgeVerification.confirm, {
            edgeId,
            endpoint: body.endpoint,
            listenerRevision: body.listenerRevision,
            configHash: body.configHash,
            method,
            ...act,
          }),
        );
      }
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

function triggerOf(v: unknown): 'manual' | 'detector' | 'api' | 'reconcile' | undefined {
  return v === 'manual' || v === 'detector' || v === 'api' || v === 'reconcile' ? v : undefined;
}

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
  if (a === 'sni' && b === 'config' && !c)
    return json(await ctx.runMutation(internal.sniFamilies.patchConfig, { patch: body, ...act }));
  if (a === 'sni' && b === 'families' && c && !parts[3])
    return json(
      await ctx.runMutation(internal.sniFamilies.update, {
        slug: c,
        label: typeof body.label === 'string' ? body.label : undefined,
        enabled: typeof body.enabled === 'boolean' ? body.enabled : undefined,
        requireH2: typeof body.requireH2 === 'boolean' ? body.requireH2 : undefined,
        ...act,
      }),
    );
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
  const [a, b, c, d] = parts;
  const act = actor(admin);
  if (a !== 'relays' || b !== 'by-slug' || !c || d) return notFound();
  // ONE idempotent body: origin + every listener the caller owns (docs/edges.md
  // § "Node role contract"). A bounded token is confined to its boundary for
  // the existing row AND the body's origin (the mutation checks both).
  const result = await ctx.runMutation(internal.relays.registerBySlug, {
    ...body,
    slug: c,
    listeners: Array.isArray(body.listeners) ? body.listeners : [],
    source: admin.adminUserId ? 'admin' : 'role',
    ...(admin.boundary ? { boundary: admin.boundary } : {}),
    ...act,
  } as never);
  const view = await ctx.runQuery(internal.edgeAdmin.relayBySlugView, { slug: c });
  return view ? json({ ...view, registration: result }) : notFound();
};

// --- DELETE --------------------------------------------------------------------------------------------

const deleteHandler: Handler = async (ctx, _req, parts, admin, _body, query) => {
  const [a, b, c, d, e] = parts;
  const act = actor(admin);
  if (a === 'sni' && b === 'families' && c && !d)
    return json(await ctx.runMutation(internal.sniFamilies.remove, { slug: c, ...act }));
  if (a === 'sni' && b === 'bindings' && c && !d)
    return json(
      await ctx.runMutation(internal.sniFamilies.unbind, {
        bindingId: id<'sniInboundBindings'>(c),
        ...act,
      }),
    );
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
      await assertRelayWithinBoundary(ctx, c, admin);
      const origin = await ctx.runQuery(internal.relays.getBySlug, { slug: c });
      if (!origin) return json({ ok: true, deleted: true });
      if (d === 'listeners' && e)
        return json(
          await ctx.runMutation(internal.relayListeners.retire, {
            relayId: origin._id,
            listenerKey: e,
            ...act,
          }),
        );
      if (!d)
        // The node role decommissions the node: raw delivery returns unless it says otherwise.
        return json(
          await ctx.runMutation(internal.relays.requestDelete, {
            id: origin._id,
            disposition: dispositionOf(query) ?? 'restore-direct',
            ...act,
          }),
        );
      return notFound();
    }
    if (c === 'listeners' && d && !e)
      return json(
        await ctx.runMutation(internal.relayListeners.retire, {
          relayId: id<'relays'>(b),
          listenerKey: d,
          ...act,
        }),
      );
    if (c === 'qualification-credential' && !d)
      return json(
        await ctx.runAction(internal.relayQualification.revoke, {
          relayId: id<'relays'>(b),
          ...act,
        }),
      );
    if (!c)
      // The CMS says what happens to members of the origin (edge.delivery_disposition_required otherwise).
      return json(
        await ctx.runMutation(internal.relays.requestDelete, {
          id: id<'relays'>(b),
          disposition: dispositionOf(query),
          force: query.get('force') === 'true',
          ...act,
        }),
      );
  }
  return notFound();
};

function dispositionOf(query: URLSearchParams): 'restore-direct' | 'keep-dark' | undefined {
  const d = query.get('disposition');
  return d === 'restore-direct' || d === 'keep-dark' ? d : undefined;
}

export function registerEdgeRoutes(http: HttpRouter): void {
  http.route({ pathPrefix: PREFIX, method: 'GET', handler: wrap(getHandler, true) });
  http.route({ pathPrefix: PREFIX, method: 'POST', handler: wrap(postHandler, true) });
  http.route({ pathPrefix: PREFIX, method: 'PATCH', handler: wrap(patchHandler, true) });
  http.route({ pathPrefix: PREFIX, method: 'PUT', handler: wrap(putHandler, true) });
  http.route({ pathPrefix: PREFIX, method: 'DELETE', handler: wrap(deleteHandler, false) });
}
