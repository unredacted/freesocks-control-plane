/**
 * A guided setup run's plain stages (pure; unit-tested). The status of an
 * origin (one sentence and one dot per node, the fleet headline) is NOT judged
 * here any more: it is the server's one projection
 * (convex/lib/edges/originStatus.ts), worded by ../lib/statusWords.ts.
 *
 * Exports:
 *   Dot                           the status dot colours (the shared `StatusDot`)
 *   runIsLive(run)                a run that is still going (not terminal)
 *   plainStage(stage)             machine stage -> 1..4 (done -> 5)
 *   PLAIN_STAGES                  the four stage labels, in order
 */
import type { SetupRunAdmin, StatusDot } from '../../../../../shared/contracts/edges';
import type { SetupRunStage } from '../../../../../shared/contracts/edgeCodes';
import { SETUP_RUN_PLAIN_STAGES, SETUP_RUN_STAGE_STEP } from '../../../../lib/edgeCodes';

export type Dot = StatusDot;

const TERMINAL = new Set<SetupRunAdmin['state']>(['done', 'done_unbound', 'failed', 'cancelled']);
export const runIsLive = (run: Pick<SetupRunAdmin, 'state'>): boolean => !TERMINAL.has(run.state);

export const PLAIN_STAGES = SETUP_RUN_PLAIN_STAGES;

/** The machine's ten stages folded onto the four the operator sees (`done` = 5, past the last). */
export const plainStage = (stage: SetupRunStage): number => SETUP_RUN_STAGE_STEP[stage];
