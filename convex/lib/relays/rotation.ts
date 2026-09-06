/**
 * Pure helpers for the rotation machine (convex/relayRotations.ts): phase
 * bookkeeping, the weighted progress bar, the bounded live log, and the
 * selection rules (compatible standby first, then a qualified account with
 * capacity + budget).
 */

export const ROTATION_PHASES = [
  'select',
  'provisioning',
  'verifying',
  'publishing',
  'host_flipping',
  'confirming',
  'finalizing',
  'rolling_back',
  'done',
  'failed',
  'rolled_back',
  'quarantined',
  'cancelled',
] as const;
export type RotationPhase = (typeof ROTATION_PHASES)[number];

export const TERMINAL_PHASES: readonly RotationPhase[] = [
  'done',
  'failed',
  'rolled_back',
  'quarantined',
  'cancelled',
];
export function isTerminalPhase(p: string): boolean {
  return (TERMINAL_PHASES as readonly string[]).includes(p);
}

/** Phases during which a cancel simply stops the run (nothing published yet). */
export const CANCELLABLE_PHASES: readonly RotationPhase[] = ['select', 'provisioning', 'verifying'];
/** Phases during which a cancel means "roll back what was published". */
export const ROLLBACK_ON_CANCEL_PHASES: readonly RotationPhase[] = ['publishing', 'host_flipping'];

export interface RotationEvent {
  at: number;
  level: 'info' | 'warn' | 'error';
  code: string;
  detail?: string;
}
export const MAX_EVENTS = 60;

export function appendEvent(events: readonly RotationEvent[], ev: RotationEvent): RotationEvent[] {
  const out = [...events, { ...ev, detail: ev.detail?.slice(0, 200) }];
  return out.length > MAX_EVENTS ? out.slice(out.length - MAX_EVENTS) : out;
}

// --- progress ---------------------------------------------------------------------------

/** Weighted phase budget (percent). Provisioning is split evenly over the edge steps. */
const WEIGHTS = { select: 5, provisioning: 60, verifying: 15, publishing: 10, host: 10 } as const;

export interface ProgressInput {
  phase: string;
  /** Provisioning ledger states of the new edge, if any. */
  stepStates?: readonly string[];
  /** Whether this rotation includes a template-Host flip at all. */
  needsHostFlip: boolean;
}

export function progressPercent(input: ProgressInput): number {
  const p = input.phase;
  if (p === 'done') return 100;
  if (isTerminalPhase(p)) return 0;
  const hostBudget = input.needsHostFlip ? WEIGHTS.host : 0;
  // Without a flip the remaining weight is re-spread so "publishing" ends at 100.
  const scale = 100 / (100 - (WEIGHTS.host - hostBudget));
  let acc = 0;
  const done = (w: number) => (acc += w);
  if (p === 'select') return 0;
  done(WEIGHTS.select);
  if (p === 'provisioning') {
    const states = input.stepStates ?? [];
    const finished = states.filter((s) => s === 'done').length;
    const frac = states.length === 0 ? 0 : finished / states.length;
    return Math.round((acc + WEIGHTS.provisioning * frac) * scale);
  }
  done(WEIGHTS.provisioning);
  if (p === 'verifying') return Math.round(acc * scale);
  done(WEIGHTS.verifying);
  if (p === 'publishing') return Math.round(acc * scale);
  done(WEIGHTS.publishing);
  if (p === 'host_flipping') return Math.round((acc + hostBudget * 0.5) * scale);
  if (p === 'confirming') return Math.round((acc + hostBudget * 0.8) * scale);
  if (p === 'finalizing' || p === 'rolling_back')
    return Math.min(99, Math.round((acc + hostBudget) * scale));
  return 0;
}

// --- selection ---------------------------------------------------------------------------

export interface StandbyCandidate {
  id: string;
  slotId: string;
  provider: string | null;
  status: string;
  publication: string;
  health: string;
  hasV4: boolean;
}

/**
 * A compatible standby: active + unpublished, on the SAME slot (same profile,
 * same inbound), with an IPv4. Prefers a provider not already published.
 */
export function pickStandby(
  candidates: readonly StandbyCandidate[],
  slotId: string,
  publishedProviders: readonly string[],
  excludeEdgeId: string | null,
  requireOnline: boolean,
): StandbyCandidate | null {
  const ok = candidates.filter(
    (c) =>
      c.id !== excludeEdgeId &&
      c.slotId === slotId &&
      c.status === 'active' &&
      c.publication === 'unpublished' &&
      c.hasV4 &&
      (!requireOnline || c.health === 'online'),
  );
  if (ok.length === 0) return null;
  const distinct = ok.find((c) => !c.provider || !publishedProviders.includes(c.provider));
  return distinct ?? ok[0];
}

export interface AccountCandidate {
  id: string;
  provider: string;
  qualified: boolean;
  priority: number;
  dailyAllocationBudget: number;
  allocationsToday: number;
  maxLiveEdges: number;
  liveEdges: number;
}

export type AccountPickFailure =
  | 'no_account_for_provider'
  | 'no_qualified_account'
  | 'accounts_exhausted';

/** Qualified account of the provider with capacity + budget; lowest priority number first, then fewest live edges. */
export function pickAccount(
  accounts: readonly AccountCandidate[],
  provider: string,
): { ok: true; account: AccountCandidate } | { ok: false; code: AccountPickFailure } {
  const ofProvider = accounts.filter((a) => a.provider === provider);
  if (ofProvider.length === 0) return { ok: false, code: 'no_account_for_provider' };
  const qualified = ofProvider.filter((a) => a.qualified);
  if (qualified.length === 0) return { ok: false, code: 'no_qualified_account' };
  const usable = qualified
    .filter((a) => a.liveEdges < a.maxLiveEdges && a.allocationsToday < a.dailyAllocationBudget)
    .sort((a, b) => a.priority - b.priority || a.liveEdges - b.liveEdges);
  if (usable.length === 0) return { ok: false, code: 'accounts_exhausted' };
  return { ok: true, account: usable[0] };
}

export interface SlotCandidate {
  slotId: string;
  slotKey: string;
  provider: string;
  deployed: boolean;
  retired: boolean;
  profileEnabled: boolean;
  activeSnis: number;
}

/**
 * Pick the slot for a fresh provision (no target): eligible slots only, then a
 * provider not yet published (when preferred), then the origin's preference,
 * then stable slotKey order.
 */
export function pickSlot(
  slots: readonly SlotCandidate[],
  publishedProviders: readonly string[],
  preferDistinct: boolean,
  providerPreference: string | null,
): SlotCandidate | null {
  const eligible = slots
    .filter((s) => s.deployed && !s.retired && s.profileEnabled && s.activeSnis > 0)
    .sort((a, b) => a.slotKey.localeCompare(b.slotKey));
  if (eligible.length === 0) return null;
  if (preferDistinct) {
    const fresh = eligible.filter((s) => !publishedProviders.includes(s.provider));
    if (fresh.length > 0) {
      return fresh.find((s) => s.provider === providerPreference) ?? fresh[0];
    }
  }
  return eligible.find((s) => s.provider === providerPreference) ?? eligible[0];
}
