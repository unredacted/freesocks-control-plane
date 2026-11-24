/**
 * A node's machine settings moved: the next machine revision, shared by the
 * node intents (an admin's settings change, a name given once a zone exists)
 * and the backend setup (a zone move that renames the nodes nothing relies
 * on, in the same transaction as the setup change). Activation evidence for
 * the old revisions is kept only where it still applies, and every activation
 * run of the old revisions is superseded so none of them can commit.
 */
import type { MutationCtx } from '../../_generated/server';
import type { Doc } from '../../_generated/dataModel';
import { retainEvidence, stageAfterChange, type Revisions } from './activation';
import { desiredHashOf } from './fencing';

type Intent = Doc<'panelNodeIntents'>;

export function revisionsOf(intent: Intent): Revisions {
  return {
    machineRevision: intent.machineRevision,
    configRevision: intent.configRevision ?? '',
    authRevision: intent.authRevision,
    deliveryRevision: intent.deliveryRevision ?? '',
  };
}

export async function revisedForSettings(
  ctx: Pick<MutationCtx, 'db'>,
  intent: Intent,
  settings: Intent['settings'],
  now: number,
): Promise<Partial<Intent>> {
  const machineRevision = intent.machineRevision + 1;
  const evidence = retainEvidence(intent.activation.evidence, {
    ...revisionsOf(intent),
    machineRevision,
  });
  // A revision moved: no activation run of the old revisions may commit.
  for (const r of await ctx.db
    .query('panelActivationRuns')
    .withIndex('by_intent', (q) => q.eq('intentId', intent._id))
    .collect())
    if (r.state === 'running' || r.state === 'blocked' || r.state === 'review')
      await ctx.db.patch(r._id, { state: 'superseded', updatedAt: now });
  return {
    settings,
    machineRevision,
    activation: {
      ...intent.activation,
      evidence,
      stage: stageAfterChange(intent.activation.stage, evidence),
      reviewHash: undefined,
      currentRunId: undefined,
    },
    desiredHash: await desiredHashOf({ observed: intent.observed, settings }),
    generation: intent.generation + 1,
    updatedAt: now,
  };
}
