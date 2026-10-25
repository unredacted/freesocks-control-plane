/**
 * FCP's own client check (docs/edges.md § "FCP's own client check"): a real
 * client engine connects through an L4 address with FCP's check credential and
 * fetches an egress-IP page; the verdict says whether members would get through
 * it, out of THIS node.
 *
 * The check uses exactly what a human test uses, the address's one-entry test
 * link (edgeTestLinks.build, with its own temporary Outline key), turned into
 * each engine's outbound (lib/edges/clientCheck/outbound.ts) and run by the
 * `edge-client-check` service (docker/edge-client-check/server.ts) over a signed
 * call. Each engine's session is judged against a CONTROL address members
 * already use for the same transport (lib/edges/clientCheck/verdict.ts), so the
 * node's own refusals are never blamed on the address.
 *
 * What is kept: the verdict per address (`edges.clientCheck`, codes and engine
 * versions only) and the service's last health answer (`appState`
 * `edge:clientCheck`). Never an address, an egress IP, a link or an engine's
 * output.
 */
import { ConvexError, v } from 'convex/values';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import {
  internalAction,
  internalMutation,
  internalQuery,
  type ActionCtx,
  type DatabaseReader,
  type MutationCtx,
} from './_generated/server';
import {
  CLIENT_CHECK_ENGINES,
  type ClientCheckEngine,
  type ClientCheckUncheckedCode,
  type ClientCheckVerdict,
} from '../src/shared/contracts/edgeCodes';
import { writeAuditLog } from './lib/audit';
import { readStateJson, writeStateJson } from './lib/appStateJson';
import {
  clientCheckService,
  fetchHealth,
  runEngineCheck,
  type ClientCheckService,
  type ServiceAnswer,
} from './lib/edges/clientCheck/client';
import { outboundsForLink, type LinkOutbounds } from './lib/edges/clientCheck/outbound';
import { CLIENT_CHECK_CALL_MS } from './lib/edges/clientCheck/protocol';
import {
  judge,
  needsControl,
  type EngineRun,
  type EngineVerdict,
} from './lib/edges/clientCheck/verdict';
import { edgeClientCheckV } from './lib/edges/clientCheck/validators';
import { canonicalIp } from './lib/edges/ip';
import { edgeLayerOf } from './lib/edges/providers/capabilities';
import { liveEdgesOfRelay } from './lib/edges/relayGuards';
import {
  bindingMatches,
  verificationBinding,
  verificationCurrent,
  type VerificationEdgeLike,
  type VerificationListenerLike,
} from './lib/edges/verification';
import { resolveEdgeConfig, type EdgeConfig } from './lib/edgeConfig';
import { locationTicked } from './lib/edges/tickedLocation';
import { verificationListenerOf } from './lib/edges/verificationContext';
import { nodeAddressesOf } from './nodeIntents';

export const CLIENT_CHECK_HEALTH_KEY = 'edge:clientCheck';
/** How often a busy service is asked again within one check, and how long apart. */
const BUSY_RETRIES = 5;
const BUSY_WAIT_MS = 3_000;
/**
 * The whole check (links, every engine through the address and the control,
 * busy waits) ends within this, well inside a self-hosted action's 120 s. A
 * call that would not fit is not made: the check answers `out_of_time`.
 */
export const CLIENT_CHECK_BUDGET_MS = 90_000;
/** Below this much time left a session is not started (one session's own bounds). */
const MIN_CALL_MS = 22_000;

export interface ClientCheckHealthRecord {
  at: number;
  ok: boolean;
  code: ClientCheckUncheckedCode | null;
  engines: Array<{ engine: ClientCheckEngine; version: string | null }>;
  egressHost: string | null;
}

/** What a check returns to its caller. `checked: false` says nothing about the address. */
export type ClientCheckOutcome =
  | { checked: false; code: ClientCheckUncheckedCode; detail?: string }
  | {
      checked: true;
      at: number;
      verdict: ClientCheckVerdict;
      ok: boolean;
      engines: EngineVerdict[];
      control: boolean;
      /** The configuration the session proved (the test link's binding). */
      binding: {
        endpoint: string;
        listenerKey: string;
        listenerRevision: number;
        configHash: string;
      };
      /** The check confirmed the address for publication (a ticked location, the switch on). */
      confirmed: boolean;
    };

const REALITY_FAMILY_ENGINE: Record<string, ClientCheckEngine> = { singbox: 'sing-box' };

/**
 * What a check of `edgeId` needs to know besides the link: the layer, what the
 * node's egress may be, which engines the REALITY verdict already says the
 * transport refuses, and the control address (a published, active address of
 * the same transport whose confirmation is current, an operator's tick first;
 * else `controlEdgeId` when the caller names one, as a replacement names its
 * target).
 */
export const context = internalQuery({
  args: { edgeId: v.id('edges'), controlEdgeId: v.optional(v.id('edges')) },
  handler: async (ctx, { edgeId, controlEdgeId }) => {
    const edge = await ctx.db.get(edgeId);
    if (!edge) return null;
    const relay = await ctx.db.get(edge.relayId);
    const listener = await ctx.db.get(edge.listenerId);
    if (!relay || !listener) return null;
    const vl = await verificationListenerOf(ctx.db, listener);
    // Every address the node is known by: the origin address, an enrolled
    // node's direct addresses and the names it was found under (another family).
    const expectedEgress = [relay.originAddress, ...(await nodeAddressesOf(ctx, relay))]
      .map((a) => canonicalIp(a))
      .filter((a): a is string => !!a);
    const expectedRefusals = [
      ...new Set(
        (relay.realityClients?.refusals ?? [])
          .filter((r) => r.listenerKey === listener.listenerKey)
          .flatMap((r) => r.refuses)
          .map((f) => REALITY_FAMILY_ENGINE[f])
          .filter((e): e is ClientCheckEngine => !!e),
      ),
    ];
    const controls = (await liveEdgesOfRelay(ctx.db, relay._id)).filter(
      (e) =>
        e._id !== edge._id &&
        e.listenerId === edge.listenerId &&
        e.status === 'active' &&
        e.publication === 'published' &&
        (e.layer ?? edgeLayerOf(e.provider)) === 'l4' &&
        verificationCurrent(e, vl),
    );
    controls.sort(
      (a, b) =>
        Number(b.verification?.by === 'admin') - Number(a.verification?.by === 'admin') ||
        (a.poolIndex ?? 99) - (b.poolIndex ?? 99),
    );
    const named =
      controlEdgeId && controlEdgeId !== edge._id ? await ctx.db.get(controlEdgeId) : null;
    return {
      relayId: relay._id,
      relaySlug: relay.slug,
      layer: edge.layer ?? edgeLayerOf(edge.provider),
      expectedEgress,
      expectedRefusals,
      controlEdgeId: controls[0]?._id ?? (named && named.relayId === relay._id ? named._id : null),
    };
  },
});

export const record = internalMutation({
  args: {
    edgeId: v.id('edges'),
    result: edgeClientCheckV,
    /** The test link's binding: what the sessions proved (the confirmation binds to it). */
    binding: v.optional(
      v.object({
        endpoint: v.string(),
        listenerKey: v.string(),
        listenerRevision: v.number(),
        configHash: v.string(),
      }),
    ),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { edgeId, result, binding, actorAdminId }) => {
    const edge = await ctx.db.get(edgeId);
    if (!edge) return { confirmed: false };
    await ctx.db.patch(edgeId, { clientCheck: result, updatedAt: Date.now() });
    const relay = await ctx.db.get(edge.relayId);
    await writeAuditLog(ctx, {
      actorType: actorAdminId ? 'admin' : 'system',
      actorId: actorAdminId ?? undefined,
      action: 'edge.client_check',
      targetType: 'edge',
      targetId: edgeId,
      payload: {
        relaySlug: relay?.slug ?? '',
        edgeId,
        verdict: result.verdict,
        by: result.by,
        control: result.control,
        // `sing-box:ok xray:reality_refused`: codes only.
        engines: result.engines.map((e) => `${e.engine}:${e.code}`).join(' '),
      },
    });
    return { confirmed: binding ? await confirmByCheck(ctx, edge, result, binding) : false };
  },
});

/**
 * A passing check confirms the address for publication (docs/edges.md §
 * "Replacing a blocked address without a spare") only where FCP's own check may
 * stand in for the owner's tick: the switch is on (`edge.clientCheck.enabled`),
 * the address is L4 and in a location the owner ticked an address in, and the
 * sessions proved the configuration it holds now. An owner's own current tick
 * is never replaced. The record binds like a tick (stale the same way).
 */
async function confirmByCheck(
  ctx: MutationCtx,
  edge: Doc<'edges'>,
  result: Doc<'edges'>['clientCheck'] & object,
  binding: { endpoint: string; listenerKey: string; listenerRevision: number; configHash: string },
): Promise<boolean> {
  if (!result.ok) return false;
  if (!(await resolveEdgeConfig(ctx.db)).clientCheck.enabled) return false;
  if ((edge.layer ?? edgeLayerOf(edge.provider)) === 'l7') return false;
  if (edge.status !== 'active' && edge.status !== 'verifying') return false;
  const location = edge.locationId ? await ctx.db.get(edge.locationId) : null;
  if (!locationTicked(location)) return false;
  const raw = await ctx.db.get(edge.listenerId);
  if (!raw || raw.retired) return false;
  const listener = await verificationListenerOf(ctx.db, raw);
  const current = verificationBinding(edge, listener);
  if (!bindingMatches(current, binding)) return false;
  if (edge.verification?.by === 'admin' && verificationCurrent(edge, listener)) return false;
  const now = Date.now();
  await ctx.db.patch(edge._id, {
    verification: {
      rung: 'verified',
      by: 'system',
      at: now,
      method: 'client_check',
      ...current!,
      ...(listener.authRevision ? { authRevision: listener.authRevision } : {}),
      engines: result.engines
        .filter((e) => e.code === 'ok')
        .map((e) => ({ engine: e.engine, version: e.engineVersion })),
    },
    updatedAt: now,
  });
  const relay = await ctx.db.get(edge.relayId);
  await writeAuditLog(ctx, {
    actorType: 'system',
    action: 'edge.verified',
    targetType: 'edge',
    targetId: edge._id,
    payload: {
      relaySlug: relay?.slug ?? '',
      edgeId: edge._id,
      listenerKey: listener.listenerKey,
      method: 'client_check',
    },
  });
  return true;
}

export const recordHealth = internalMutation({
  args: {
    ok: v.boolean(),
    code: v.union(v.string(), v.null()),
    engines: v.array(v.object({ engine: v.string(), version: v.union(v.string(), v.null()) })),
    egressHost: v.union(v.string(), v.null()),
  },
  handler: async (ctx, a) => {
    await writeStateJson(ctx.db, CLIENT_CHECK_HEALTH_KEY, { at: Date.now(), ...a });
    return null;
  },
});

/** A health answer older than this says nothing (the reconcile asks every 5 minutes). */
export const CLIENT_CHECK_HEALTH_FRESH_MS = 30 * 60_000;

export type ClientCheckReadiness = 'ready' | 'off' | 'not_configured' | 'unhealthy';

/**
 * Whether FCP may count on its own client check now (a replace with no tested
 * spare relies on it): the switch is on, the deployment has the service, and
 * the service answered its last health check, recently.
 */
export async function clientCheckReadiness(
  db: DatabaseReader,
  cfg: Pick<EdgeConfig, 'clientCheck'>,
  now: number = Date.now(),
): Promise<ClientCheckReadiness> {
  if (!cfg.clientCheck.enabled) return 'off';
  if (!clientCheckService(process.env)) return 'not_configured';
  const h = await readStateJson<ClientCheckHealthRecord>(db, CLIENT_CHECK_HEALTH_KEY);
  if (!h || !h.ok || now - h.at > CLIENT_CHECK_HEALTH_FRESH_MS) return 'unhealthy';
  return 'ready';
}

/**
 * Whether the service could be counted on if the switch were on: configured,
 * and its last health answer recent and healthy (`clientCheckReadiness`
 * without the switch). The automation switch asks it before letting spares go.
 */
export async function clientCheckServiceReady(
  db: DatabaseReader,
  now: number = Date.now(),
): Promise<boolean> {
  return (await clientCheckReadiness(db, { clientCheck: { enabled: true } }, now)) === 'ready';
}

/**
 * The address's latest check, taken against the configuration it holds now,
 * found the ADDRESS at fault (not the node, not the checker). A spare like that
 * is not picked for a replace again until a later check passes, so a failed
 * gate does not make every later replace retry the same known-bad address.
 */
export function clientCheckFailedNow(
  edge: Pick<Doc<'edges'>, 'clientCheck'> & VerificationEdgeLike,
  listener: VerificationListenerLike | undefined,
): boolean {
  const c = edge.clientCheck;
  if (!c || c.ok || !listener) return false;
  if (c.verdict !== 'address_failed' && c.verdict !== 'egress_mismatch') return false;
  const b = verificationBinding(edge, listener);
  return !!b && b.configHash === c.configHash && b.listenerRevision === c.listenerRevision;
}

/** The admin view: whether the deployment has the service, and its last health answer. */
export const status = internalQuery({
  args: {},
  handler: async (ctx) => ({
    configured: clientCheckService(process.env) !== null,
    health: await readStateJson<ClientCheckHealthRecord>(ctx.db, CLIENT_CHECK_HEALTH_KEY),
  }),
});

/** Ask the service how it is (the reconcile pass and the admin's refresh); stored for attention. */
export const refreshHealth = internalAction({
  args: {},
  handler: async (ctx): Promise<ClientCheckHealthRecord | null> => {
    const svc = clientCheckService(process.env);
    if (!svc) return null;
    const h = await fetchHealth(svc);
    const rec = h.ok
      ? { ok: true, code: null, engines: h.value.engines, egressHost: h.value.egressHost }
      : { ok: false, code: h.code, engines: [], egressHost: null };
    await ctx.runMutation(internal.edgeClientCheck.recordHealth, rec);
    return { at: Date.now(), ...rec };
  },
});

type Link =
  | {
      ok: true;
      link: string;
      binding: {
        endpoint: string;
        listenerKey: string;
        listenerRevision: number;
        configHash: string;
      };
      credentialId: string | null;
    }
  | { ok: false; detail: string };

export type ClientCheckLink = Link;
type LinkBuilder = (ctx: ActionCtx, edgeId: Id<'edges'>) => Promise<Link>;
let linkBuilder: LinkBuilder = buildLink;

/**
 * Test seam: build the check's link without a backend (a rotation test has no
 * panel serving credential bodies). The real builder is the test link's.
 */
export function __setClientCheckLinks(f: LinkBuilder | null): void {
  linkBuilder = f ?? buildLink;
}

function linkFor(ctx: ActionCtx, edgeId: Id<'edges'>): Promise<Link> {
  return linkBuilder(ctx, edgeId);
}

async function buildLink(ctx: ActionCtx, edgeId: Id<'edges'>): Promise<Link> {
  try {
    const r = await ctx.runAction(internal.edgeTestLinks.build, { edgeId, clientCheck: true });
    return { ok: true, link: r.link, binding: r.binding, credentialId: r.credentialId };
  } catch (err) {
    // A link that cannot be built (no entry, the account used up) means "could
    // not check", never a failed address.
    const code =
      err instanceof ConvexError ? String((err.data as { code?: string }).code ?? '') : '';
    return { ok: false, detail: code || 'error' };
  }
}

async function runEngines(
  svc: ClientCheckService,
  conv: LinkOutbounds,
  engines: readonly ClientCheckEngine[],
  deadline: number,
): Promise<ServiceAnswer<EngineRun[]>> {
  const runs: EngineRun[] = [];
  const call = async (engine: ClientCheckEngine, outbound: Record<string, unknown>) => {
    const left = deadline - Date.now();
    if (left < MIN_CALL_MS) return { ok: false as const, code: 'out_of_time' as const };
    return runEngineCheck(
      svc,
      { engine, outbound, reality: conv.reality },
      fetch,
      Math.min(CLIENT_CHECK_CALL_MS, left),
    );
  };
  for (const engine of engines) {
    const outbound = conv.outbounds[engine];
    if (!outbound) continue;
    let answer = await call(engine, outbound);
    // One session runs at a time on the service: wait for a concurrent check,
    // while the budget still holds a session after the wait.
    for (
      let i = 0;
      i < BUSY_RETRIES &&
      !answer.ok &&
      answer.code === 'busy' &&
      deadline - Date.now() >= MIN_CALL_MS + BUSY_WAIT_MS;
      i++
    ) {
      await new Promise((r) => setTimeout(r, BUSY_WAIT_MS));
      answer = await call(engine, outbound);
    }
    if (!answer.ok) return answer;
    runs.push({
      engine,
      ok: answer.value.ok,
      code: answer.value.code,
      egressIp: answer.value.egressIp,
      engineVersion: answer.value.engineVersion,
    });
  }
  return { ok: true, value: runs };
}

/**
 * One check of an L4 address, recorded on the edge. `by` says who asked (the
 * operator's button, or FCP's own work); `controlEdgeId` is the control to fall
 * back to when the address's transport has no other confirmed address in use.
 */
export async function runClientCheck(
  ctx: ActionCtx,
  a: {
    edgeId: Id<'edges'>;
    by: 'admin' | 'system';
    controlEdgeId?: Id<'edges'>;
    actorAdminId?: Id<'adminUsers'>;
  },
): Promise<ClientCheckOutcome> {
  const svc = clientCheckService(process.env);
  if (!svc) return { checked: false, code: 'not_configured' };
  const deadline = Date.now() + CLIENT_CHECK_BUDGET_MS;
  const c = await ctx.runQuery(internal.edgeClientCheck.context, {
    edgeId: a.edgeId,
    ...(a.controlEdgeId ? { controlEdgeId: a.controlEdgeId } : {}),
  });
  if (!c) throw new ConvexError({ code: 'not_found', message: 'Edge not found' });
  if (c.layer === 'l7') return { checked: false, code: 'not_l4' };
  const issued: Array<{ edgeId: Id<'edges'>; credentialId: string }> = [];
  try {
    const link = await linkFor(ctx, a.edgeId);
    if (!link.ok) return { checked: false, code: 'link_unavailable', detail: link.detail };
    if (link.credentialId) issued.push({ edgeId: a.edgeId, credentialId: link.credentialId });
    const conv = outboundsForLink(link.link);
    const engines = CLIENT_CHECK_ENGINES.filter((e) => !!conv?.outbounds[e]);
    if (!conv || engines.length === 0) return { checked: false, code: 'no_engine' };
    const runs = await runEngines(svc, conv, engines, deadline);
    if (!runs.ok) return { checked: false, code: runs.code };
    let control: EngineRun[] | null = null;
    if (needsControl(runs.value, c.expectedEgress) && c.controlEdgeId) {
      const cl = await linkFor(ctx, c.controlEdgeId);
      if (cl.ok) {
        if (cl.credentialId)
          issued.push({ edgeId: c.controlEdgeId, credentialId: cl.credentialId });
        const cc = outboundsForLink(cl.link);
        if (cc) {
          const r = await runEngines(svc, cc, engines, deadline);
          if (!r.ok) return { checked: false, code: r.code };
          control = r.value;
        }
      }
    }
    const j = judge({
      candidate: runs.value,
      control,
      expectedEgress: c.expectedEgress,
      expectedRefusals: c.expectedRefusals,
    });
    const at = Date.now();
    const binding = {
      endpoint: link.binding.endpoint,
      listenerKey: link.binding.listenerKey,
      listenerRevision: link.binding.listenerRevision,
      configHash: link.binding.configHash,
    };
    const recorded = await ctx.runMutation(internal.edgeClientCheck.record, {
      edgeId: a.edgeId,
      binding,
      ...(a.actorAdminId ? { actorAdminId: a.actorAdminId } : {}),
      result: {
        at,
        verdict: j.verdict,
        ok: j.ok,
        engines: j.engines,
        control: control !== null,
        by: a.by,
        listenerRevision: link.binding.listenerRevision,
        configHash: link.binding.configHash,
      },
    });
    return {
      checked: true,
      at,
      verdict: j.verdict,
      ok: j.ok,
      engines: j.engines,
      control: control !== null,
      binding,
      confirmed: recorded.confirmed,
    };
  } finally {
    // A temporary Outline key lives only for the check.
    for (const k of issued) {
      try {
        await ctx.runMutation(internal.edgeTestCredentials.releaseForEdge, {
          edgeId: k.edgeId,
          credentialId: k.credentialId as Id<'edgeTestCredentials'>,
        });
      } catch {
        // The sweep removes it at its TTL anyway.
      }
    }
  }
}

/**
 * Before deploying a build from before the client check: its schema has no
 * `edges.clientCheck`, no `client_check` test-credential purpose, and none of
 * the fields of replacing without a spare (`edges.replacementOf`, a
 * `client_check` verification and its `engines`, `relays.autoReplaceHolds`,
 * `edgeRotations.clientCheckGate`), so a push is refused while any row holds
 * one. An address FCP's check confirmed keeps serving: its confirmation is kept
 * as a `named_connection`. Walks the edges, the rotations (then the origins'
 * holds) and the temporary keys (handed to the `test_link` purpose; the sweep
 * still removes them), a page per run, the rest scheduled. Run with no
 * arguments; run it again if the push is still refused.
 */
export const clearForRollback = internalMutation({
  args: {
    cursor: v.optional(v.union(v.string(), v.null())),
    phase: v.optional(
      v.union(v.literal('edges'), v.literal('rotations'), v.literal('credentials')),
    ),
  },
  handler: async (ctx, { cursor, phase }) => {
    let cleared = 0;
    type Phase = 'edges' | 'rotations' | 'credentials';
    const next = (args: { phase: Phase; cursor?: string }) =>
      ctx.scheduler.runAfter(0, internal.edgeClientCheck.clearForRollback, args);
    const at = phase ?? 'edges';
    if (at === 'edges') {
      const page = await ctx.db.query('edges').paginate({ cursor: cursor ?? null, numItems: 200 });
      for (const e of page.page) {
        const rec = e.verification;
        const fromCheck = rec?.method === 'client_check';
        if (e.clientCheck === undefined && e.replacementOf === undefined && !fromCheck) continue;
        await ctx.db.patch(e._id, {
          clientCheck: undefined,
          replacementOf: undefined,
          ...(fromCheck
            ? { verification: { ...rec!, method: 'named_connection' as const, engines: undefined } }
            : {}),
        });
        cleared++;
      }
      await next(
        page.isDone ? { phase: 'rotations' } : { phase: 'edges', cursor: page.continueCursor },
      );
      return { cleared, done: false };
    }
    if (at === 'rotations') {
      const page = await ctx.db
        .query('edgeRotations')
        .paginate({ cursor: cursor ?? null, numItems: 200 });
      for (const r of page.page)
        if (r.clientCheckGate !== undefined) {
          await ctx.db.patch(r._id, { clientCheckGate: undefined });
          cleared++;
        }
      if (!page.isDone) {
        await next({ phase: 'rotations', cursor: page.continueCursor });
        return { cleared, done: false };
      }
      // Origins are operator-scale: their holds go in one pass.
      for (const relay of await ctx.db.query('relays').collect())
        if (relay.autoReplaceHolds !== undefined)
          await ctx.db.patch(relay._id, { autoReplaceHolds: undefined });
      await next({ phase: 'credentials' });
      return { cleared, done: false };
    }
    const page = await ctx.db
      .query('edgeTestCredentials')
      .paginate({ cursor: cursor ?? null, numItems: 200 });
    for (const row of page.page)
      if (row.purpose === 'client_check') {
        await ctx.db.patch(row._id, { purpose: 'test_link' });
        cleared++;
      }
    if (!page.isDone) {
      await next({ phase: 'credentials', cursor: page.continueCursor });
      return { cleared, done: false };
    }
    return { cleared, done: true };
  },
});

/** `POST edges/{id}/client-check`: the operator's check of one address. */
export const check = internalAction({
  args: { edgeId: v.id('edges'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: (ctx, { edgeId, actorAdminId }): Promise<ClientCheckOutcome> =>
    runClientCheck(ctx, { edgeId, by: 'admin', ...(actorAdminId ? { actorAdminId } : {}) }),
});
