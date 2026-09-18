/**
 * Titles and one-line descriptions of the nine guided-setup steps, and the
 * projection of the server's steps onto the shared Stepper (pure; unit-tested).
 * The server decides status, blockers and the current step; this file only
 * names things.
 *
 * Exports:
 *   STEP_COPY                         id -> { title, description } (the shared edgeCodes titles and hints)
 *   stepperSteps(steps)               SetupStep[] -> StepperStep[] (with a blocker / warning note)
 *   resolveShownStep(status, peek)    which step body to render (a valid `?step` peek, else the current one)
 *   isSetupStepId(v)
 */
import { SETUP_STEP_IDS, type SetupStepId } from '@shared/contracts/edgeCodes';
import type { SetupStatusResponse, SetupStep } from '@shared/contracts/edges';
import { SETUP_STEP_HINTS, SETUP_STEP_TITLES } from '@client/lib/edgeCodes';
import type { StepperStep } from '../lib/types';

export const STEP_COPY: Record<SetupStepId, { title: string; description: string }> =
  Object.fromEntries(
    SETUP_STEP_IDS.map((id) => [
      id,
      { title: SETUP_STEP_TITLES[id], description: SETUP_STEP_HINTS[id] },
    ]),
  ) as Record<SetupStepId, { title: string; description: string }>;

export function isSetupStepId(v: unknown): v is SetupStepId {
  return typeof v === 'string' && (SETUP_STEP_IDS as readonly string[]).includes(v);
}

const plural = (n: number, one: string): string => `${n} ${one}${n === 1 ? '' : 's'}`;

export function stepNote(step: Pick<SetupStep, 'status' | 'blockers' | 'warnings'>): string {
  if (step.status === 'done' || step.status === 'skipped')
    return step.warnings.length > 0 ? plural(step.warnings.length, 'warning') : '';
  if (step.blockers.length > 0) return plural(step.blockers.length, 'blocker');
  return step.warnings.length > 0 ? plural(step.warnings.length, 'warning') : '';
}

export function stepperSteps(steps: readonly SetupStep[]): StepperStep[] {
  return steps.map((s) => {
    const note = stepNote(s);
    return {
      id: s.id,
      title: STEP_COPY[s.id].title,
      description: STEP_COPY[s.id].description,
      status: s.status,
      ...(note ? { note } : {}),
    };
  });
}

export function resolveShownStep(
  status: Pick<SetupStatusResponse, 'steps' | 'currentStep'>,
  peek: string | null | undefined,
): SetupStepId | null {
  if (isSetupStepId(peek) && status.steps.some((s) => s.id === peek)) return peek;
  return status.currentStep;
}
