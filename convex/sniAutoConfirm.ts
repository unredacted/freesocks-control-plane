/**
 * FCP's own test of a send (docs/edges.md "FCP's own test of a send"): once the
 * backend is seen to hold a rollout's names, FCP's client check proves them on
 * each node the way an operator's "Test one name" does, and a pass is that
 * node's receipt. Switch `edge.sni.autoConfirm`, off by default: off, nothing
 * here runs and a receipt comes only from a person.
 *
 * The test is the operator's, run by real engines:
 *
 *   - the same receipt (`sniRollouts.receiptContextOf`): the newest rollout,
 *     confirmed on the backend, through an L4 address of that node whose
 *     endpoint confirmation is current (an operator's tick first; a check's
 *     only while it stands for publication), presenting the witness when there
 *     is one (one test proves the whole send), else one waiting name;
 *   - the same test link (`edgeTestLinks.build` with the name), with the
 *     check's own credential, run by every engine the client-check service
 *     holds (sing-box, Xray, Mihomo);
 *   - judged against a control that tells the name from the node: the same
 *     address with a name members get now (`edgeClientCheck.checkWithControl`).
 *     An engine the node refuses whatever the name (sing-box against an Xray
 *     that wants an ML-KEM key share) is not the name's doing. The control's
 *     egress proves nothing here (it went the same way): a session must come
 *     out of one of the node's own addresses;
 *   - confirmed by the same function as an operator's tick
 *     (`sniRollouts.acceptReceipt`, every guard again from the live rows), as
 *     the system: audit `edge.sni.names.accepted` with `by: client_check`.
 *
 * A test that does not pass changes nothing for members: the receipt is
 * `failed` with the verdict or the code, the node's page says why, and the
 * operator's "Test one name" stays where it was. It is tried again on the
 * `sni-qualify` cron's cadence, at most `AUTO_MAX_FAILURES` times per send and
 * node. A node with no such address stays manual (its page says so): the check
 * never dials a node's own address.
 */
import { ConvexError, v, type Infer } from 'convex/values';
import { internal } from './_generated/api';
import type { Doc } from './_generated/dataModel';
import {
  internalAction,
  internalMutation,
  internalQuery,
  type MutationCtx,
} from './_generated/server';
import {
  CLIENT_CHECK_BUDGET_MS,
  checkWithControl,
  clientCheckServiceReady,
} from './edgeClientCheck';
import { writeAuditLog } from './lib/audit';
import { clientCheckService } from './lib/edges/clientCheck/client';
import { clientCheckEngineVerdictV, clientCheckVerdictV } from './lib/edges/clientCheck/validators';
import { edgeLayerOf } from './lib/edges/providers/capabilities';
import { liveEdgesOfRelay } from './lib/edges/relayGuards';
import {
  AUTO_PER_SWEEP,
  AUTO_RECEIPT_TTL_MS,
  AUTO_STAGGER_MS,
  autoTestDue,
} from './lib/edges/sni/autoTest';
import { clientConfirmationStands } from './lib/edges/tickedLocation';
import { verificationCurrent } from './lib/edges/verification';
import { verificationListenerOf } from './lib/edges/verificationContext';
import { resolveSniConfig } from './lib/sniConfig';
import { acceptReceipt, boundListeners, receiptContextOf } from './sniRollouts';

/**
 * Rollouts one page of a sweep looks at. A sweep walks every send still
 * confirmed on its backend (one per binding at most: a newer send supersedes
 * the last) a page at a time, the next page scheduled, until it has started
 * its tests or seen them all.
 */
const SWEEP_PAGE = 25;

/**
 * The address a test goes through: an L4 address of the listener that is in
 * use, whose endpoint confirmation is current and stands for publication (a
 * check's confirmation only while its switch is on and its location ticked),
 * an operator's tick first. Null: the node has none, and stays manual.
 */
async function testAddress(
  ctx: { db: MutationCtx['db'] },
  relay: Doc<'relays'>,
  listener: Doc<'relayListeners'>,
): Promise<Doc<'edges'> | null> {
  const vl = await verificationListenerOf(ctx.db, listener);
  const out: Doc<'edges'>[] = [];
  for (const e of await liveEdgesOfRelay(ctx.db, relay._id))
    if (
      e.listenerId === listener._id &&
      e.status === 'active' &&
      (e.layer ?? edgeLayerOf(e.provider)) === 'l4' &&
      verificationCurrent(e, vl) &&
      (await clientConfirmationStands(ctx.db, e))
    )
      out.push(e);
  out.sort(
    (a, b) =>
      Number(b.verification?.by === 'admin') - Number(a.verification?.by === 'admin') ||
      Number(b.publication === 'published') - Number(a.publication === 'published') ||
      (a.poolIndex ?? 99) - (b.poolIndex ?? 99),
  );
  return out[0] ?? null;
}

/**
 * Start FCP's test of every send that waits on a node (the `sni-qualify` cron,
 * and once per send a minute after the backend is seen to hold it): one
 * receipt per node that is due (`autoTestDue`), then its run, the runs
 * `AUTO_STAGGER_MS` apart (the service runs one session at a time), at most
 * `AUTO_PER_SWEEP` per sweep. A node it started is not due again for minutes,
 * so the next sweep reaches the ones after it. Nothing while either switch is
 * off, the send's name list is off, or the service is not set up and answering.
 */
export const sweep = internalMutation({
  args: {
    rolloutId: v.optional(v.id('sniRollouts')),
    // The next page of a sweep, and the tests it has started so far.
    cursor: v.optional(v.string()),
    started: v.optional(v.number()),
  },
  handler: async (ctx, { rolloutId, cursor, started: before }) => {
    const cfg = await resolveSniConfig(ctx.db);
    if (!cfg.enabled || !cfg.autoConfirm) return { started: 0, why: 'off' as const };
    if (!clientCheckService(process.env)) return { started: 0, why: 'not_configured' as const };
    if (!(await clientCheckServiceReady(ctx.db))) return { started: 0, why: 'unhealthy' as const };
    const now = Date.now();
    let next: string | null = null;
    let rollouts: Doc<'sniRollouts'>[];
    if (rolloutId)
      rollouts = [await ctx.db.get(rolloutId)].filter((r): r is Doc<'sniRollouts'> => !!r);
    else {
      const page = await ctx.db
        .query('sniRollouts')
        .withIndex('by_phase_updated', (q) => q.eq('phase', 'panel_confirmed'))
        .paginate({ cursor: cursor ?? null, numItems: SWEEP_PAGE });
      rollouts = page.page;
      if (!page.isDone) next = page.continueCursor;
    }
    let started = before ?? 0;
    for (const r of rollouts) {
      if (started >= AUTO_PER_SWEEP) break;
      if (r.phase !== 'panel_confirmed') continue;
      const b = await ctx.db.get(r.bindingId);
      if (!b || b.generation !== r.generation) continue;
      // A name list switched off sends nothing new: no test either.
      if (!(await ctx.db.get(b.familyId))?.enabled) continue;
      // The family's usable names of the send: a receipt activates nothing else.
      const usable = new Set(
        (
          await ctx.db
            .query('sniNames')
            .withIndex('by_family_seq', (q) => q.eq('familyId', b.familyId))
            .collect()
        )
          .filter((n) => n.status === 'active' && n.qualification.state === 'ok')
          .map((n) => n.name),
      );
      const receipts = (
        await ctx.db
          .query('sniAcceptanceReceipts')
          .withIndex('by_rollout', (q) => q.eq('rolloutId', r._id))
          .collect()
      ).filter((x) => x.evidenceKind === 'client_check');
      for (const { relay, listener } of await boundListeners(ctx, b)) {
        if (started >= AUTO_PER_SWEEP) break;
        const mine = receipts.filter((x) => x.listenerId === listener._id);
        // A run that died leaves its receipt `issued`: it lapses here.
        for (const x of mine)
          if (x.state === 'issued' && now > x.expiresAt)
            await ctx.db.patch(x._id, {
              state: 'expired',
              check: { at: now, verdict: null, code: 'lapsed', engines: [], control: false },
            });
        const active = new Set(
          (listener.tlsNames ?? []).filter((n) => n.status === 'active').map((n) => n.name),
        );
        const pending = r.names.filter((n) => usable.has(n) && !active.has(n));
        if (pending.length === 0) continue;
        if (!autoTestDue(mine, now)) continue;
        const edge = await testAddress(ctx, relay, listener);
        if (!edge) continue;
        const sni = r.witness && pending.includes(r.witness) ? r.witness : pending[0]!;
        let c: Awaited<ReturnType<typeof receiptContextOf>>;
        try {
          c = await receiptContextOf(ctx.db, { rolloutId: r._id, edgeId: edge._id, sni });
        } catch (err) {
          if (err instanceof ConvexError) continue;
          throw err;
        }
        const receiptId = await ctx.db.insert('sniAcceptanceReceipts', {
          rolloutId: r._id,
          generation: c.generation,
          relayId: c.relayId,
          listenerId: c.listenerId,
          edgeId: edge._id,
          sni: c.sni,
          isWitness: c.isWitness,
          expectedToken: c.expectedToken,
          endpoint: c.binding.endpoint,
          listenerRevision: c.binding.listenerRevision,
          configHash: c.binding.configHash,
          evidenceKind: 'client_check',
          state: 'issued',
          issuedAt: now,
          expiresAt: now + AUTO_RECEIPT_TTL_MS,
        });
        await ctx.scheduler.runAfter(started * AUTO_STAGGER_MS, internal.sniAutoConfirm.run, {
          receiptId,
        });
        started++;
      }
    }
    if (next !== null && started < AUTO_PER_SWEEP)
      await ctx.scheduler.runAfter(0, internal.sniAutoConfirm.sweep, { cursor: next, started });
    return { started: started - (before ?? 0), why: null };
  },
});

/** The receipt a run tests, while it is still FCP's and still open. */
export const runContext = internalQuery({
  args: { receiptId: v.id('sniAcceptanceReceipts') },
  handler: async (ctx, { receiptId }) => {
    const rc = await ctx.db.get(receiptId);
    if (!rc || rc.evidenceKind !== 'client_check' || rc.state !== 'issued') return null;
    if (Date.now() > rc.expiresAt) return null;
    return { edgeId: rc.edgeId, sni: rc.sni };
  },
});

const bindingV = v.object({
  endpoint: v.string(),
  listenerKey: v.string(),
  listenerRevision: v.number(),
  configHash: v.string(),
});

const resultV = v.union(
  v.object({ checked: v.literal(false), code: v.string(), detail: v.optional(v.string()) }),
  v.object({
    checked: v.literal(true),
    verdict: clientCheckVerdictV,
    ok: v.boolean(),
    engines: v.array(clientCheckEngineVerdictV),
    control: v.boolean(),
    binding: bindingV,
  }),
);

/**
 * One test of a send's name on one node: the receipt's test link through its
 * address, by every engine the service holds, against the same address with a
 * name members get now. Records the outcome on the receipt (`settle`).
 */
export const run = internalAction({
  args: { receiptId: v.id('sniAcceptanceReceipts') },
  handler: async (ctx, { receiptId }): Promise<{ state: string | null }> => {
    const rc = await ctx.runQuery(internal.sniAutoConfirm.runContext, { receiptId });
    if (!rc) return { state: null };
    const settle = (result: Infer<typeof resultV>) =>
      ctx.runMutation(internal.sniAutoConfirm.settle, { receiptId, result });
    const svc = clientCheckService(process.env);
    if (!svc) return settle({ checked: false, code: 'not_configured' });
    const deadline = Date.now() + CLIENT_CHECK_BUDGET_MS;
    const c = await ctx.runQuery(internal.edgeClientCheck.context, { edgeId: rc.edgeId });
    if (!c) return settle({ checked: false, code: 'link_unavailable', detail: 'not_found' });
    if (c.layer === 'l7') return settle({ checked: false, code: 'not_l4' });
    const j = await checkWithControl(ctx, {
      svc,
      deadline,
      engines: c.engines,
      expectedEgress: c.expectedEgress,
      expectedRefusals: c.expectedRefusals,
      candidate: { edgeId: rc.edgeId, opts: { candidateSni: rc.sni } },
      // The same address: it tells the name from the node's own refusals, and
      // says nothing about where the address leads (a misrouted address takes
      // both sessions to the same wrong node), so the egress must be the node's.
      control: { edgeId: rc.edgeId },
      controlEgress: false,
    });
    return settle(
      j.checked
        ? {
            checked: true,
            verdict: j.verdict,
            ok: j.ok,
            engines: j.engines,
            control: j.control,
            binding: j.binding,
          }
        : { checked: false, code: j.code, ...(j.detail ? { detail: j.detail } : {}) },
    );
  },
});

/**
 * A run's outcome. A pass confirms the receipt through `acceptReceipt` (every
 * guard of an operator's tick, again, from the live rows) only while both
 * switches are still on and the sessions proved the configuration the receipt
 * is bound to; anything else leaves it for a person and says why.
 */
export const settle = internalMutation({
  args: { receiptId: v.id('sniAcceptanceReceipts'), result: resultV },
  handler: async (ctx, { receiptId, result }): Promise<{ state: string | null }> => {
    const rc = await ctx.db.get(receiptId);
    if (!rc || rc.evidenceKind !== 'client_check' || rc.state !== 'issued')
      return { state: rc?.state ?? null };
    const now = Date.now();
    const check = result.checked
      ? {
          at: now,
          verdict: result.verdict,
          code: null,
          engines: result.engines.map((e) => ({
            engine: e.engine,
            code: e.code,
            engineVersion: e.engineVersion,
          })),
          control: result.control,
        }
      : {
          at: now,
          verdict: null,
          // `link_unavailable` carries the link's refusal (`edge.test_account_used_up`).
          code: result.detail ? `${result.code}:${result.detail}` : result.code,
          engines: [],
          control: false,
        };
    const engines = check.engines.map((e) => `${e.engine}:${e.code}`).join(' ');
    const relay = await ctx.db.get(rc.relayId);
    const listener = await ctx.db.get(rc.listenerId);
    const noted = async (
      state: 'failed' | 'superseded' | 'expired',
      outcome: 'failed' | 'could_not_check' | 'voided',
      code: string | null,
    ) => {
      await ctx.db.patch(rc._id, { state, check: { ...check, code: code ?? check.code } });
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'edge.sni.names.tested',
        targetType: 'relay_listener',
        targetId: rc.listenerId,
        payload: {
          relaySlug: relay?.slug ?? '',
          listenerKey: listener?.listenerKey ?? '',
          generation: rc.generation,
          outcome,
          verdict: check.verdict ?? '',
          code: code ?? check.code ?? '',
          engines,
        },
      });
      return { state };
    };
    if (!result.checked) return noted('failed', 'could_not_check', null);
    if (!result.ok)
      return noted(
        'failed',
        result.verdict === 'node_unreachable' ? 'could_not_check' : 'failed',
        null,
      );
    // The sessions proved the configuration the link was built from: the receipt's, or nothing.
    if (
      result.binding.endpoint !== rc.endpoint ||
      result.binding.listenerRevision !== rc.listenerRevision ||
      result.binding.configHash !== rc.configHash
    )
      return noted('superseded', 'voided', 'edge.sni.binding_changed');
    const cfg = await resolveSniConfig(ctx.db);
    if (!cfg.enabled || !cfg.autoConfirm) return noted('superseded', 'voided', 'switched_off');
    // The name list switched off while the test ran: it sends nothing new.
    const rollout = await ctx.db.get(rc.rolloutId);
    const binding = rollout ? await ctx.db.get(rollout.bindingId) : null;
    const family = binding ? await ctx.db.get(binding.familyId) : null;
    if (binding && !family?.enabled) return noted('superseded', 'voided', 'list_off');
    const out = await acceptReceipt(ctx, rc, { kind: 'client_check', engines });
    if (!out.ok) return noted(out.state ?? 'superseded', 'voided', out.code);
    // A person proved it first: theirs stands, this one writes nothing.
    if (out.already) return noted('superseded', 'voided', 'already_proven');
    await ctx.db.patch(rc._id, { check });
    // A name that proves only itself: the node's next waiting name is tested next.
    if (!rc.isWitness)
      await ctx.scheduler.runAfter(AUTO_STAGGER_MS, internal.sniAutoConfirm.sweep, {
        rolloutId: rc.rolloutId,
      });
    return { state: 'confirmed' };
  },
});

/**
 * Before deploying a build from before FCP's own test of a send: its schema has
 * no `client_check` receipts, no `failed` state and no `check`, so a push is
 * refused while any row holds one. FCP's receipts are deleted (what they
 * activated stays on the listeners; an operator's receipts are untouched), a
 * page per run, the rest scheduled. Run with no arguments; run it again if the
 * push is still refused.
 */
export const clearForRollback = internalMutation({
  args: { cursor: v.optional(v.union(v.string(), v.null())) },
  handler: async (ctx, { cursor }) => {
    const page = await ctx.db
      .query('sniAcceptanceReceipts')
      .paginate({ cursor: cursor ?? null, numItems: 200 });
    let cleared = 0;
    for (const rc of page.page)
      if (rc.evidenceKind === 'client_check' || rc.state === 'failed' || rc.check !== undefined) {
        await ctx.db.delete(rc._id);
        cleared++;
      }
    if (!page.isDone)
      await ctx.scheduler.runAfter(0, internal.sniAutoConfirm.clearForRollback, {
        cursor: page.continueCursor,
      });
    return { cleared, done: page.isDone };
  },
});
