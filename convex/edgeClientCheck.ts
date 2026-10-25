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
import type { Id } from './_generated/dataModel';
import {
  internalAction,
  internalMutation,
  internalQuery,
  type ActionCtx,
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
import { verificationCurrent } from './lib/edges/verification';
import { verificationListenerOf } from './lib/edges/verificationContext';

export const CLIENT_CHECK_HEALTH_KEY = 'edge:clientCheck';
/** How often a busy service is asked again within one check, and how long apart. */
const BUSY_RETRIES = 5;
const BUSY_WAIT_MS = 3_000;

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
    const expectedEgress = [relay.originAddress, ...(relay.nodeAddresses ?? [])]
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
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { edgeId, result, actorAdminId }) => {
    const edge = await ctx.db.get(edgeId);
    if (!edge) return null;
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
    return null;
  },
});

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

async function linkFor(ctx: ActionCtx, edgeId: Id<'edges'>): Promise<Link> {
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
): Promise<ServiceAnswer<EngineRun[]>> {
  const runs: EngineRun[] = [];
  for (const engine of engines) {
    const outbound = conv.outbounds[engine];
    if (!outbound) continue;
    let answer = await runEngineCheck(svc, { engine, outbound, reality: conv.reality });
    // One session runs at a time on the service: wait for a concurrent check.
    for (let i = 0; i < BUSY_RETRIES && !answer.ok && answer.code === 'busy'; i++) {
      await new Promise((r) => setTimeout(r, BUSY_WAIT_MS));
      answer = await runEngineCheck(svc, { engine, outbound, reality: conv.reality });
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
    const runs = await runEngines(svc, conv, engines);
    if (!runs.ok) return { checked: false, code: runs.code };
    let control: EngineRun[] | null = null;
    if (needsControl(runs.value, c.expectedEgress) && c.controlEdgeId) {
      const cl = await linkFor(ctx, c.controlEdgeId);
      if (cl.ok) {
        if (cl.credentialId)
          issued.push({ edgeId: c.controlEdgeId, credentialId: cl.credentialId });
        const cc = outboundsForLink(cl.link);
        if (cc) {
          const r = await runEngines(svc, cc, engines);
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
    await ctx.runMutation(internal.edgeClientCheck.record, {
      edgeId: a.edgeId,
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
      binding: {
        endpoint: link.binding.endpoint,
        listenerKey: link.binding.listenerKey,
        listenerRevision: link.binding.listenerRevision,
        configHash: link.binding.configHash,
      },
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
 * `edges.clientCheck` and no `client_check` test-credential purpose, so a push
 * is refused while any row holds one. Clears the verdicts (a page per run, the
 * rest scheduled) and hands the temporary keys of checks to the `test_link`
 * purpose (equally temporary; the sweep still removes them). Run with no
 * arguments; run it again if the push is still refused.
 */
export const clearForRollback = internalMutation({
  args: { cursor: v.optional(v.union(v.string(), v.null())) },
  handler: async (ctx, { cursor }) => {
    const page = await ctx.db.query('edges').paginate({ cursor: cursor ?? null, numItems: 200 });
    let cleared = 0;
    for (const e of page.page)
      if (e.clientCheck !== undefined) {
        await ctx.db.patch(e._id, { clientCheck: undefined });
        cleared++;
      }
    if (!page.isDone) {
      await ctx.scheduler.runAfter(0, internal.edgeClientCheck.clearForRollback, {
        cursor: page.continueCursor,
      });
      return { cleared, done: false };
    }
    let keys = 0;
    for (const row of await ctx.db.query('edgeTestCredentials').take(1000))
      if (row.purpose === 'client_check') {
        await ctx.db.patch(row._id, { purpose: 'test_link' });
        keys++;
      }
    return { cleared, keys, done: true };
  },
});

/** `POST edges/{id}/client-check`: the operator's check of one address. */
export const check = internalAction({
  args: { edgeId: v.id('edges'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: (ctx, { edgeId, actorAdminId }): Promise<ClientCheckOutcome> =>
    runClientCheck(ctx, { edgeId, by: 'admin', ...(actorAdminId ? { actorAdminId } : {}) }),
});
