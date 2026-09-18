/**
 * Pure helpers for the guided setup run machine (convex/edgeSetupRuns.ts):
 * stage order, terminal states, the bounded event log, the version vector
 * stage 8 compares against stage 7, the plan hash and the relay slug a node
 * gets. No db, no clock.
 */
import {
  SETUP_RUN_STAGES,
  type SetupRunStage,
  type SetupRunState,
} from '../../../src/shared/contracts/edgeCodes';
import { sha256Hex } from '../crypto';

export { SETUP_RUN_STAGES };

export const MAX_RUN_EVENTS = 50;
/** Stage 8 refuses a Host observation older than this (the final listing of stage 7). */
export const MAX_OBSERVATION_AGE_MS = 60_000;
/** Stage 7 repeats the rehearsal at most this many times when the Host listing moved under it. */
export const MAX_REHEARSAL_ATTEMPTS = 3;

export interface RunEvent {
  at: number;
  level: 'info' | 'warn' | 'error';
  code: string;
  detail?: string;
}

export function appendRunEvent(events: readonly RunEvent[], ev: RunEvent): RunEvent[] {
  const out = [...events, { ...ev, detail: ev.detail?.slice(0, 200) }];
  return out.length > MAX_RUN_EVENTS ? out.slice(out.length - MAX_RUN_EVENTS) : out;
}

export const TERMINAL_RUN_STATES: readonly SetupRunState[] = [
  'done',
  'done_unbound',
  'failed',
  'cancelled',
];

export function isTerminalRunState(s: string): boolean {
  return (TERMINAL_RUN_STATES as readonly string[]).includes(s);
}

export function stageIndex(stage: SetupRunStage): number {
  return SETUP_RUN_STAGES.indexOf(stage);
}

/** The stage after `stage` in the fixed order; null after `done`. */
export function nextStage(stage: SetupRunStage): SetupRunStage | null {
  const i = stageIndex(stage);
  return i >= 0 && i + 1 < SETUP_RUN_STAGES.length ? SETUP_RUN_STAGES[i + 1] : null;
}

/** Stages 1..4b: a cancel deletes the relay (nothing was published). */
export function cancelDeletesRelay(stage: SetupRunStage): boolean {
  return stageIndex(stage) < stageIndex('publish');
}

/** Stages 5..7: a cancel runs the restore workflow (published edges stay). */
export function cancelRestores(stage: SetupRunStage): boolean {
  const i = stageIndex(stage);
  return i >= stageIndex('publish') && i < stageIndex('go_live');
}

/** The version vector stage 7 records and stage 8 re-derives. */
export interface SetupVector {
  listenerRevisions: Record<string, number>;
  renderConfigHash: string;
  publicationEpoch: number;
  qualificationEvidenceIds: string[];
}

export function vectorsEqual(a: SetupVector, b: SetupVector): boolean {
  if (a.renderConfigHash !== b.renderConfigHash) return false;
  if (a.publicationEpoch !== b.publicationEpoch) return false;
  const ak = Object.keys(a.listenerRevisions).sort();
  const bk = Object.keys(b.listenerRevisions).sort();
  if (ak.length !== bk.length || ak.some((k, i) => k !== bk[i])) return false;
  if (ak.some((k) => a.listenerRevisions[k] !== b.listenerRevisions[k])) return false;
  const ae = [...a.qualificationEvidenceIds].sort();
  const be = [...b.qualificationEvidenceIds].sort();
  return ae.length === be.length && ae.every((x, i) => x === be[i]);
}

/** Stable JSON: sorted keys, `undefined` dropped. */
export function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o)
      .filter((k) => o[k] !== undefined)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(v);
}

/**
 * The plan hash a `POST setup-runs` must echo: sha256 over the canonical
 * required listener specs + the direct-Host identities + the account ids the
 * plan offered. Anything else on the snapshot (labels, reasons) is free to move.
 */
export async function planHashOf(input: {
  listenerSpecs: readonly unknown[];
  directHosts: ReadonlyArray<{ uuid: string; covered: boolean }>;
  accountIds: readonly string[];
}): Promise<string> {
  return sha256Hex(
    canonicalJson({
      listeners: input.listenerSpecs,
      directHosts: [...input.directHosts]
        .map((h) => ({ uuid: h.uuid, covered: h.covered }))
        .sort((a, b) => a.uuid.localeCompare(b.uuid)),
      accounts: [...input.accountIds].sort(),
    }),
  );
}

/** One discovered inbound in the plan snapshot (the required set is the frontable ones). */
export interface SetupPlanInbound {
  listenerKey: string;
  sourceTag: string;
  /** The registration-shaped listener spec (no `originTransport`). */
  listenerSpec: unknown;
  layers: Array<'l4' | 'l7'>;
  frontable: boolean;
  formats: { links: boolean; singbox: boolean; clash: boolean };
  needsName: boolean;
  /** Why it is not frontable (an `INBOUND_UNSUPPORTED_CODES` reason or a layer exclusion). */
  reason?: string;
  detail?: string;
}

export interface SetupPlanDirectHost {
  uuid: string;
  remark: string;
  inboundUuid: string;
  covered: boolean;
}

export interface SetupPlanAccount {
  id: string;
  name: string;
  provider: string;
  layer: 'l4' | 'l7';
  compatible: boolean;
  reasons: string[];
}

/** The read-only plan `POST setup-runs/plan` returns and `POST setup-runs` persists (JSON on the run). */
export interface SetupPlanSnapshot {
  backendServerId: string;
  backend: string;
  nodeUuid: string;
  nodeName: string;
  originAddress: string;
  relaySlug: string;
  inbounds: SetupPlanInbound[];
  /** Listener keys of the frontable inbounds (cap 8). */
  requiredListeners: string[];
  tooManyInbounds: boolean;
  directHosts: SetupPlanDirectHost[];
  accounts: SetupPlanAccount[];
  renderGlobal: { willEnable: boolean; affectedRelays: string[] };
  familiesDisabled: string[];
  /** No subscription is pinned to the node (the rehearsal uses the credential's own body). */
  emptyNode: boolean;
  /** A relay a previous run left `setupOwned` (the new run resumes at its recorded stage). */
  existingRelay: { id: string; slug: string; setupStage: string | null } | null;
  /** A non-terminal run already owns this origin. */
  activeRunId: string | null;
}

const SLUG_MAX = 40;

/** The relay slug a node gets: its name, lowercased and slug-safe (`[a-z0-9][a-z0-9-]{1,62}`). */
export function slugForNode(nodeName: string): string {
  let s = nodeName
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .replace(/-{2,}/g, '-')
    .slice(0, SLUG_MAX)
    .replace(/-+$/g, '');
  if (s.length < 2) s = `node-${s}`.replace(/-+$/g, '');
  if (!/^[a-z0-9]/.test(s)) s = `n${s}`;
  return s;
}
