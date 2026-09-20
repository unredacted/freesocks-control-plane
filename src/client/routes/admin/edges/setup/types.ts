/** Props every guided-setup step body receives. The server's step is the only source of status. */
import type { OriginAdmin, SetupStatusResponse, SetupStep } from '@shared/contracts/edges';
import type { IssueLinkContext } from './issueActions';

export interface StepBodyProps {
  step: SetupStep;
  status: SetupStatusResponse;
  /** The origin row once it exists (null while the wizard works from a draft). */
  relay: OriginAdmin | null;
  linkCtx: IssueLinkContext;
}

export const factString = (facts: Record<string, unknown>, key: string): string | null => {
  const v = facts[key];
  return typeof v === 'string' && v !== '' ? v : null;
};
export const factNumber = (facts: Record<string, unknown>, key: string): number | null => {
  const v = facts[key];
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
};
export const factBool = (facts: Record<string, unknown>, key: string): boolean | null => {
  const v = facts[key];
  return typeof v === 'boolean' ? v : null;
};
