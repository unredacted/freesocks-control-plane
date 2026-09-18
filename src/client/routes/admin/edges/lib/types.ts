/**
 * Shared prop types for the Edges components. Data shapes come from the zod
 * contracts (`z.infer`); only view-only shapes are declared here.
 */
import type { z } from 'zod';
import type { AuditEntry } from '../../../../../shared/contracts/admin';
import type {
  PreflightIssue,
  RelayPoolEntry,
  SetupBlocker,
  TimelineResponse,
} from '../../../../../shared/contracts/edges';
import type { SetupStepStatus } from '../../../../../shared/contracts/edgeCodes';
import type { Tone } from '../../../../lib/edgeCodes';

export type { Tone };
export type PoolEntry = z.infer<typeof RelayPoolEntry>;
export type TimelineEntry = z.infer<typeof TimelineResponse>['entries'][number];
export type TimelineSubject = TimelineEntry['subject'];
/** Timeline accepts plain audit rows too (a rotation's audit trail has no `subject`). */
export type TimelineRow = AuditEntry & { subject?: TimelineSubject };

/** A blocker or warning as the server reports it (setup steps carry `subject`, preflight does not). */
export type CodeIssue =
  | z.infer<typeof SetupBlocker>
  | z.infer<typeof PreflightIssue>
  | { code: string; subject?: string | null; detail?: string | null };

/** One KeyValue row. `value` is rendered as text (booleans in words); empty values show a dash. */
export interface KeyValueRow {
  label: string;
  value: unknown;
  /** Show a copy button (strings and numbers only). */
  copy?: boolean;
  /** Monospace (ids, addresses, hashes). */
  mono?: boolean;
  /** Render the value as a Badge in this tone instead of plain text. */
  tone?: Tone;
  /** Small muted text under the value. */
  hint?: string;
}

/** One Stepper step. `status` reuses the guided-setup vocabulary. */
export interface StepperStep {
  id: string;
  title: string;
  description?: string;
  status: SetupStepStatus;
  /** A short count or note shown at the right of the title ("2 blockers"). */
  note?: string;
}
