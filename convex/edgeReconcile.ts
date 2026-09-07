/**
 * Relay reconcile cron (`edge-reconcile`): the recovery loop that makes the
 * rotation machine safe to interrupt anywhere.
 *
 *  1. re-kick rotations whose next step went stale (a crashed action);
 *  2. settle edges with an unknown external outcome — an expired op claim or an
 *     `unresolved` step — by DISCOVERING (never by re-running the step);
 *  3. non-destructive health refresh for live managed edges; a published edge
 *     the provider no longer has is dropped from the pool (drift audit);
 *  4. drained / failed / cancelled edges become destroy runs; each child
 *     resource walks `present → delete_requested → confirmed_gone` under a
 *     claim, reverse allocation order; the edge is `destroyed` only when every
 *     child is confirmed gone; the attempt cap parks it as `needs_operator`;
 *  5. pool upkeep (config-gated): publish a compatible standby into a free pool
 *     slot, or start a provision to reach `desiredPublished` / `standbyPerRelay`;
 *  6. finish origin deletes once every managed edge is destroyed.
 *
 * Every provider call runs under an edge op claim; every DB change is a
 * mutation in relayEdges / relayOrigins / relayRotations.
 */
import { v } from 'convex/values';
import { internalAction } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc } from './_generated/dataModel';
import { runWithCronOutcome } from './cronHeartbeat';
import { edgeMs, type EdgeConfig } from './lib/edgeConfig';
import { isDiscoverable } from './edges';
import { publishedCount } from './lib/edges/pool';
import type {
  Discovery,
  EdgeDescription,
  DestroyOutcome,
  ResourceStep,
} from './lib/edges/providers/types';

type Edge = Doc<'edges'>;

const MAX_DISCOVER_ATTEMPTS = 3;

export interface ReconcileReport {
  rekicked: number;
  settled: number;
  described: number;
  dropped: number;
  destroying: number;
  destroyed: number;
  started: number;
  published: number;
  finalizedDeletes: number;
  errors: number;
}

function errText(err: unknown): string {
  const meta = (err as { meta?: { code?: string } }).meta;
  return (meta?.code ?? (err instanceof Error ? err.message : String(err))).slice(0, 120);
}

function specOf(edge: Edge) {
  return {
    name: edge.name,
    listeners: edge.listeners.map((l) => ({
      edgePort: l.edgePort,
      members: [{ address: l.originAddress, port: l.originPort }],
    })),
  };
}

function ledgerOf(edge: Edge) {
  return { steps: edge.steps, resources: edge.resources };
}

function stepOf(s: Edge['steps'][number]): ResourceStep {
  return {
    id: s.stepId,
    kind: s.kind as ResourceStep['kind'],
    resourceName: s.resourceName,
    discoverability: s.discoverability ?? 'by_name',
  };
}

export const run = internalAction({
  args: {},
  handler: async (ctx): Promise<ReconcileReport> =>
    runWithCronOutcome(ctx, 'edge-reconcile', () => reconcile(ctx)),
});

export async function reconcile(ctx: ActionCtx): Promise<ReconcileReport> {
  const report: ReconcileReport = {
    rekicked: 0,
    settled: 0,
    described: 0,
    dropped: 0,
    destroying: 0,
    destroyed: 0,
    started: 0,
    published: 0,
    finalizedDeletes: 0,
    errors: 0,
  };
  const cfg = await ctx.runQuery(internal.edgeReconcileMutations.configSnapshot, {});
  const now = Date.now();

  // 0. Record the action runtime's Node version (dashboard; the deploy guard enforces the floor).
  try {
    const info = await ctx.runAction(internal.edgeProviderOps.runtimeInfo, {});
    await ctx.runMutation(internal.edgeReconcileMutations.recordRuntime, {
      nodeVersion: info.nodeVersion,
    });
  } catch (err) {
    console.warn(`[relay-reconcile] runtimeInfo unavailable: ${errText(err)}`);
  }

  // 1. Re-kick stale rotations.
  const stale = await ctx.runQuery(internal.edgeRotations.listStale, { now });
  for (const rotationId of stale) {
    await ctx.runMutation(internal.edgeRotations.rekick, { rotationId });
    report.rekicked++;
  }

  const edges = await ctx.runQuery(internal.edges.listLive, {});
  const origins = await ctx.runQuery(internal.relays.listAll, {});
  const rotatingOrigins = new Set(
    origins.filter((o) => o.activeRotationId).map((o) => o._id as string),
  );

  for (const edge of edges) {
    if (!edge.managed || !edge.accountId) {
      // Observe-only edges: nothing to discover, describe or destroy. A failed/
      // cancelled adopted row is simply forgotten.
      if (['failed', 'cancelled', 'destroying'].includes(edge.status)) {
        await ctx.runMutation(internal.edges.patchEdge, {
          edgeId: edge._id,
          status: 'destroyed',
        });
        report.destroyed++;
      }
      continue;
    }
    const inRotation = rotatingOrigins.has(edge.relayId as string);
    try {
      // 2. Settle unknown outcomes (outside a running rotation, which does this itself).
      if (!inRotation && isDiscoverable(edge, now)) {
        await settleEdge(ctx, cfg, edge, report);
        continue;
      }
      // 4. Destroy runs.
      if (edge.status === 'destroying') {
        await destroyStep(ctx, cfg, edge, report);
        continue;
      }
      if (edge.status === 'draining' && edge.drainUntil !== undefined && edge.drainUntil <= now) {
        await ctx.runMutation(internal.edges.patchEdge, {
          edgeId: edge._id,
          status: 'destroying',
        });
        report.destroying++;
        continue;
      }
      if ((edge.status === 'failed' || edge.status === 'cancelled') && !inRotation) {
        // Only once every step is settled (done or confirmed absent): unresolved
        // steps went through settleEdge above.
        if (
          !edge.steps.some((s) =>
            ['requested', 'unresolved', 'ambiguous', 'needs_operator'].includes(s.state),
          )
        ) {
          await ctx.runMutation(internal.edges.patchEdge, {
            edgeId: edge._id,
            status: 'destroying',
          });
          report.destroying++;
        }
        continue;
      }
      // 3. Health refresh for live edges (non-destructive).
      if (['active', 'standby', 'draining'].includes(edge.status) && !inRotation) {
        const staleHealth = (edge.lastHealthAt ?? 0) + edgeMs.poll(cfg) * 10 <= now;
        if (!staleHealth) continue;
        const desc: EdgeDescription = await ctx.runAction(internal.edgeProviderOps.describe, {
          accountId: edge.accountId,
          ledger: ledgerOf(edge),
        });
        await ctx.runMutation(internal.edges.recordDescribe, {
          edgeId: edge._id,
          state: desc.state,
          addresses: desc.addresses,
          health: desc.health,
          resources: desc.resources,
        });
        report.described++;
        if (desc.state === 'gone' && edge.publication !== 'unpublished') {
          const r = await ctx.runMutation(internal.relays.dropFromPool, {
            relayId: edge.relayId,
            edgeId: edge._id,
            reason: 'provider_gone',
          });
          if (r.ok && r.dropped) report.dropped++;
        }
      }
    } catch (err) {
      report.errors++;
      console.warn(`[relay-reconcile] edge ${edge._id}: ${errText(err)}`);
    }
  }

  // 5. Pool upkeep + 6. origin deletes.
  let starts = 0;
  for (const origin of origins) {
    try {
      if (origin.deleting) {
        const r = await ctx.runMutation(internal.relays.finalizeDelete, { id: origin._id });
        if (r.removed) report.finalizedDeletes++;
        continue;
      }
      if (!origin.enabled || origin.quarantine || origin.activeRotationId) continue;
      if (starts >= cfg.maxReconcileStartsPerTick) continue;
      const originEdges = edges.filter((e) => e.relayId === origin._id);
      const publishedNow = publishedCount(origin.publishedEdgeIds);
      const standbys = originEdges.filter(
        (e) => e.status === 'active' && e.publication === 'unpublished' && !!e.addresses.v4,
      );
      if (publishedNow < origin.desiredPublished) {
        if (cfg.autoPublishStandby && standbys.length > 0) {
          const res = await ctx.runMutation(internal.edgeReconcileMutations.publishStandby, {
            relayId: origin._id,
            candidates: standbys.map((e) => e._id),
          });
          if (res.published) {
            report.published++;
            continue;
          }
          if (res.rotationId) {
            report.started++;
            starts++;
            continue;
          }
        }
        if (cfg.autoProvisionToDesired) {
          await ctx.runMutation(internal.edgeRotations.start, {
            relayId: origin._id,
            kind: 'provision',
            trigger: 'reconcile',
            publishOnDone: true,
          });
          report.started++;
          starts++;
          continue;
        }
      } else if (cfg.autoProvisionToDesired && standbys.length < origin.standbyPerRelay) {
        await ctx.runMutation(internal.edgeRotations.start, {
          relayId: origin._id,
          kind: 'provision',
          trigger: 'reconcile',
          publishOnDone: false,
        });
        report.started++;
        starts++;
      }
    } catch (err) {
      report.errors++;
      console.warn(`[relay-reconcile] origin ${origin.slug}: ${errText(err)}`);
    }
  }
  return report;
}

/** Discover the first unsettled step (or the expired op's target) and record what is there. */
async function settleEdge(ctx: ActionCtx, cfg: EdgeConfig, edge: Edge, report: ReconcileReport) {
  const accountId = edge.accountId!;
  const now = Date.now();
  // An expired claim on a destroy step: the delete may or may not have landed → confirm.
  if (edge.currentOp && edge.currentOp.expiresAt < now && edge.currentOp.kind === 'destroy_step') {
    const target = edge.resources.find((r) => r.resourceId === edge.currentOp!.target);
    const cl = await ctx.runMutation(internal.edges.claimOp, {
      edgeId: edge._id,
      kind: 'discover',
      target: edge.currentOp.target,
      claimMs: edgeMs.opClaim(cfg),
    });
    if (!cl.ok) return;
    if (!target) {
      await ctx.runMutation(internal.edges.settleOp, { edgeId: edge._id, opId: cl.opId });
      return;
    }
    const out: DestroyOutcome = await ctx.runAction(internal.edgeProviderOps.confirmDestroyed, {
      accountId,
      resource: target,
      ledger: ledgerOf(edge),
    });
    await ctx.runMutation(internal.edges.settleOp, {
      edgeId: edge._id,
      opId: cl.opId,
      resourceDeleteState: [
        {
          resourceId: target.resourceId,
          deleteState:
            out.status === 'confirmed_gone'
              ? 'confirmed_gone'
              : out.status === 'delete_requested'
                ? 'delete_requested'
                : target.deleteState,
        },
      ],
    });
    report.settled++;
    return;
  }
  const pending =
    edge.steps.find((s) => s.state === 'requested' || s.state === 'unresolved') ??
    (edge.currentOp ? edge.steps.find((s) => s.stepId === edge.currentOp!.target) : undefined);
  if (!pending) {
    // Only an expired non-destroy op with nothing pending: release it.
    if (edge.currentOp) {
      const cl = await ctx.runMutation(internal.edges.claimOp, {
        edgeId: edge._id,
        kind: 'discover',
        target: edge.currentOp.target,
        claimMs: edgeMs.opClaim(cfg),
      });
      if (cl.ok)
        await ctx.runMutation(internal.edges.settleOp, { edgeId: edge._id, opId: cl.opId });
    }
    return;
  }
  const cl = await ctx.runMutation(internal.edges.claimOp, {
    edgeId: edge._id,
    kind: 'discover',
    target: pending.stepId,
    claimMs: edgeMs.opClaim(cfg),
  });
  if (!cl.ok) return;
  // Discovery attempts live on the step, not the claim: every pass settles and
  // clears the claim, and adapters need ≥2 quiet looks before `confirmed_absent`.
  const discoverAttempt = (pending.discoverAttempts ?? 0) + 1;
  let disc: Discovery;
  try {
    disc = await ctx.runAction(internal.edgeProviderOps.discover, {
      accountId,
      spec: specOf(edge),
      step: stepOf(pending),
      ledger: ledgerOf(edge),
      attempt: discoverAttempt,
    });
  } catch (err) {
    await ctx.runMutation(internal.edges.settleOp, { edgeId: edge._id, opId: cl.opId });
    throw err;
  }
  const failedRun = edge.status === 'failed' || edge.status === 'cancelled';
  if (disc.status === 'found') {
    await ctx.runMutation(internal.edges.settleOp, {
      edgeId: edge._id,
      opId: cl.opId,
      stepPatch: { stepId: pending.stepId, state: 'done', opRef: null, finished: true },
      addResources: disc.resources,
      addresses: disc.addresses,
    });
  } else if (disc.status === 'confirmed_absent') {
    // Nothing exists for this step. A failed run marks it done-with-nothing so the
    // destroy can proceed; a live run may retry (the rotation machine owns retries).
    await ctx.runMutation(internal.edges.settleOp, {
      edgeId: edge._id,
      opId: cl.opId,
      stepPatch: failedRun
        ? { stepId: pending.stepId, state: 'done', opRef: null, finished: true }
        : { stepId: pending.stepId, state: 'pending', opRef: null, attempt: pending.attempt + 1 },
    });
    if (!failedRun && pending.attempt + 1 > MAX_DISCOVER_ATTEMPTS) {
      await ctx.runMutation(internal.edges.patchEdge, {
        edgeId: edge._id,
        status: 'failed',
        failure: { step: pending.stepId, code: 'step_retries_exhausted' },
      });
    }
  } else if (disc.status === 'ambiguous') {
    await ctx.runMutation(internal.edges.settleOp, {
      edgeId: edge._id,
      opId: cl.opId,
      stepPatch: { stepId: pending.stepId, state: 'ambiguous' },
      addResources: disc.candidates.map((c) => ({ ...c, ownership: 'adopted' as const })),
      status: 'needs_operator',
    });
  } else {
    await ctx.runMutation(internal.edges.settleOp, {
      edgeId: edge._id,
      opId: cl.opId,
      stepPatch: {
        stepId: pending.stepId,
        state: pending.state,
        discoverAttempts: discoverAttempt,
      },
    });
    if ((pending.startedAt ?? edge._creationTime) + edgeMs.discoveryTimeout(cfg) < now) {
      await ctx.runMutation(internal.edges.patchEdge, {
        edgeId: edge._id,
        status: 'needs_operator',
        stepStates: [{ stepId: pending.stepId, state: 'needs_operator' }],
      });
    }
  }
  report.settled++;
}

/** One destroy pass: confirm requested deletes, then request the next present resource (reverse order). */
async function destroyStep(ctx: ActionCtx, cfg: EdgeConfig, edge: Edge, report: ReconcileReport) {
  const accountId = edge.accountId!;
  if (edge.destroyAttempts >= cfg.maxDestroyAttempts) {
    await ctx.runMutation(internal.edgeReconcileMutations.destroyExhausted, { edgeId: edge._id });
    return;
  }
  const ledger = ledgerOf(edge);
  const plan =
    edge.resources.length > 0
      ? ((await ctx.runAction(internal.edgeProviderOps.planDestroy, {
          accountId,
          ledger,
        })) as Edge['resources'])
      : [];
  const remaining = plan.filter((r) => r.deleteState !== 'confirmed_gone');
  if (remaining.length === 0) {
    await ctx.runMutation(internal.edgeReconcileMutations.markDestroyed, { edgeId: edge._id });
    report.destroyed++;
    return;
  }
  const target = remaining[0];
  const cl = await ctx.runMutation(internal.edges.claimOp, {
    edgeId: edge._id,
    kind: 'destroy_step',
    target: target.resourceId,
    claimMs: edgeMs.opClaim(cfg),
  });
  if (!cl.ok) return;
  let out: DestroyOutcome;
  try {
    out =
      target.deleteState === 'delete_requested'
        ? await ctx.runAction(internal.edgeProviderOps.confirmDestroyed, {
            accountId,
            resource: target,
            ledger,
          })
        : await ctx.runAction(internal.edgeProviderOps.runDestroy, {
            accountId,
            resource: target,
            ledger,
          });
  } catch (err) {
    // Unknown outcome: keep the claim's target; the next pass confirms (not re-deletes).
    await ctx.runMutation(internal.edges.settleOp, {
      edgeId: edge._id,
      opId: cl.opId,
      resourceDeleteState: [{ resourceId: target.resourceId, deleteState: 'delete_requested' }],
      failure: { step: 'destroy', code: errText(err) },
    });
    await ctx.runMutation(internal.edges.patchEdge, {
      edgeId: edge._id,
      destroyAttemptsDelta: 1,
    });
    throw err;
  }
  await ctx.runMutation(internal.edges.settleOp, {
    edgeId: edge._id,
    opId: cl.opId,
    resourceDeleteState: [
      {
        resourceId: target.resourceId,
        deleteState: out.status === 'confirmed_gone' ? 'confirmed_gone' : 'delete_requested',
      },
    ],
  });
  await ctx.runMutation(internal.edges.patchEdge, {
    edgeId: edge._id,
    destroyAttemptsDelta: 1,
  });
  if (out.status === 'confirmed_gone' && remaining.length === 1) {
    await ctx.runMutation(internal.edgeReconcileMutations.markDestroyed, { edgeId: edge._id });
    report.destroyed++;
  }
}
