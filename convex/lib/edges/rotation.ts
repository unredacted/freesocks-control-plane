/**
 * Pure helpers for the rotation machine (convex/edgeRotations.ts): phase
 * bookkeeping, the weighted progress bar, the bounded live log, and the
 * selection rules (compatible standby first, then a trusted location of an
 * account with capacity + budget).
 */

import { protocolUsesSni, type ListenerProto } from './protocols';
import {
  edgeLayerOf,
  protocolCarriedBy,
  providerHealthSatisfies,
  type EdgeLayer,
} from './providers/capabilities';
import type { EdgeProviderId } from '../edgeProviderIds';
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
  /** Provisioning account (null for adopted, observe-only edges). */
  accountId?: string | null;
  /** Its location and `<provider>:<placeKey>` (absent for edges without one). */
  locationId?: string | null;
  locationKey?: string | null;
  status: string;
  publication: string;
  health: string;
  /** Has the address of ITS OWN layer's kind (an L7 hostname, an L4 IPv4). */
  hasAddress: boolean;
}

export interface StandbyPickOptions {
  /**
   * The failure domain to move away from (a replace's target): another
   * provider first, then another location, then anything.
   */
  avoid?: { provider: string | null; locationKey: string | null } | null;
  /** Locations automatic work may not use (cooling, outside the node's set). */
  skipLocations?: ReadonlySet<string>;
  /** An explicit spare: that one or nothing. */
  spareEdgeId?: string | null;
}

/**
 * A compatible standby: active + unpublished, on the SAME slot (same profile,
 * same transport), with a publishable address, and from the profile's account when
 * the profile is account-scoped. With `avoid` (a replace): a provider other
 * than the target's first, then another location, then any; otherwise a
 * provider not already published.
 */
export function pickStandby(
  candidates: readonly StandbyCandidate[],
  slotId: string,
  publishedProviders: readonly string[],
  excludeEdgeId: string | null,
  requireOnline: boolean,
  requiredAccountId: string | null = null,
  opts: StandbyPickOptions = {},
): StandbyCandidate | null {
  const ok = candidates.filter(
    (c) =>
      c.id !== excludeEdgeId &&
      c.slotId === slotId &&
      c.status === 'active' &&
      c.publication === 'unpublished' &&
      c.hasAddress &&
      providerHealthSatisfies(c.provider, c.health, requireOnline) &&
      (!requiredAccountId || !c.accountId || c.accountId === requiredAccountId) &&
      (opts.spareEdgeId ? c.id === opts.spareEdgeId : true) &&
      !(c.locationId && opts.skipLocations?.has(c.locationId) && c.id !== opts.spareEdgeId),
  );
  if (ok.length === 0) return null;
  const avoid = opts.avoid;
  if (avoid) {
    return (
      ok.find((c) => !c.provider || !avoid.provider || c.provider !== avoid.provider) ??
      ok.find((c) => !c.locationKey || !avoid.locationKey || c.locationKey !== avoid.locationKey) ??
      ok[0]!
    );
  }
  const distinct = ok.find((c) => !c.provider || !publishedProviders.includes(c.provider));
  return distinct ?? ok[0]!;
}

/**
 * A pick of the node's provider set as selection ranks it for one listener
 * (docs/edges.md § "Provider sets"): what it would add, then set order, then
 * the fewest live edges.
 */
export interface SetLocationCandidate extends AccountCandidate {
  /** Index in the node's set (the deterministic tie-break). */
  setOrder: number;
  /** Publishing an edge here would lower the coverage deficit. */
  lowersDeficit: boolean;
  /** No edge of this provider is published for the listener yet. */
  providerNew: boolean;
  /** No edge of this location key is published for the listener yet. */
  locationKeyNew: boolean;
}

/**
 * Selection with a set: the trusted, usable picks (any pick when the request
 * allows an untrusted location), ranked by what they add: lowers the deficit,
 * a provider not yet published for the listener, a location not yet
 * published, set order, fewest live edges.
 */
export function pickLocation(
  candidates: readonly SetLocationCandidate[],
  opts: { allowUnqualified?: boolean } = {},
): { ok: true; account: SetLocationCandidate } | { ok: false; code: AccountPickFailure } {
  if (candidates.length === 0) return { ok: false, code: 'no_account_for_provider' };
  const trusted = candidates.filter((a) => opts.allowUnqualified || a.qualified);
  if (trusted.length === 0) return { ok: false, code: 'no_qualified_account' };
  const usable = trusted
    .filter(
      (a) =>
        a.liveEdges < a.maxLiveEdges &&
        (a.locationMaxLiveEdges == null || (a.locationLiveEdges ?? 0) < a.locationMaxLiveEdges) &&
        (a.dailyAllocationBudget === 0 || a.allocationsToday < a.dailyAllocationBudget),
    )
    .sort(
      (a, b) =>
        Number(b.lowersDeficit) - Number(a.lowersDeficit) ||
        Number(b.providerNew) - Number(a.providerNew) ||
        Number(b.locationKeyNew) - Number(a.locationKeyNew) ||
        a.setOrder - b.setOrder ||
        a.liveEdges - b.liveEdges,
    );
  if (usable.length === 0) return { ok: false, code: 'accounts_exhausted' };
  return { ok: true, account: usable[0]! };
}

/**
 * Whether AUTOMATIC selection may pick an L7 account at all. Until the node
 * role registers the slots' origin transport and the HTTP-transport profiles,
 * and a qualification run has passed, L7 edges are provisioned and published by
 * hand only: an automatic pick could publish a front nobody has proven.
 * A manual operator action is never gated by this.
 */
export function l7SelectionAllowed(cfg: { l7: { autoSelect: boolean } }): boolean {
  return cfg.l7.autoSelect === true;
}

/**
 * Filter provider accounts to the ones that can actually front this slot: the
 * layers the complete client-to-origin chain allows (`slotLayers`), the
 * protocol the provider can carry, and (for automatic selection) the L7 gate.
 * Reads capabilities, never provider ids.
 */
export function accountsForSlot<T extends { provider: string }>(
  accounts: readonly T[],
  opts: {
    layers: readonly EdgeLayer[];
    proto: ListenerProto;
    /** The listener's origin port: an L7 provider may dial a transport on fixed ports only. */
    originPort?: number;
    /** false = automatic selection with the L7 gate off: L7 accounts are excluded. */
    allowL7: boolean;
  },
): T[] {
  return accounts.filter((a) => {
    const layer = edgeLayerOf(a.provider);
    if (!opts.layers.includes(layer)) return false;
    if (layer === 'l7' && !opts.allowL7) return false;
    return protocolCarriedBy(a.provider as EdgeProviderId, opts.proto, opts.originPort);
  });
}

/**
 * One place selection may create an edge in: a LOCATION of an account. `id`
 * is the account (its budget, its live cap, its priority); `qualified` is the
 * location's trust; the location's own cap applies too when it set one.
 */
export interface AccountCandidate {
  id: string;
  locationId: string | null;
  provider: string;
  qualified: boolean;
  priority: number;
  dailyAllocationBudget: number;
  allocationsToday: number;
  maxLiveEdges: number;
  liveEdges: number;
  /** The location's own live-edge cap (null / absent = none) and its live count. */
  locationMaxLiveEdges?: number | null;
  locationLiveEdges?: number;
}

export type AccountPickFailure =
  | 'no_account_for_provider'
  | 'no_qualified_account'
  | 'accounts_exhausted'
  /** Every pick of the node's set that could carry it cools (D6). */
  | 'set_picks_cooling';

/**
 * A trusted location of the provider whose account has capacity + budget (and
 * the location room under its own cap); lowest account priority first, then
 * fewest live edges on the account, then in the location.
 */
export function pickAccount(
  accounts: readonly AccountCandidate[],
  provider: string,
): { ok: true; account: AccountCandidate } | { ok: false; code: AccountPickFailure } {
  const ofProvider = accounts.filter((a) => a.provider === provider);
  if (ofProvider.length === 0) return { ok: false, code: 'no_account_for_provider' };
  const qualified = ofProvider.filter((a) => a.qualified);
  if (qualified.length === 0) return { ok: false, code: 'no_qualified_account' };
  // dailyAllocationBudget 0 = unlimited (the same rule `reserveAllocation` applies).
  const usable = qualified
    .filter(
      (a) =>
        a.liveEdges < a.maxLiveEdges &&
        (a.locationMaxLiveEdges == null || (a.locationLiveEdges ?? 0) < a.locationMaxLiveEdges) &&
        (a.dailyAllocationBudget === 0 || a.allocationsToday < a.dailyAllocationBudget),
    )
    .sort(
      (a, b) =>
        a.priority - b.priority ||
        a.liveEdges - b.liveEdges ||
        (a.locationLiveEdges ?? 0) - (b.locationLiveEdges ?? 0),
    );
  if (usable.length === 0) return { ok: false, code: 'accounts_exhausted' };
  return { ok: true, account: usable[0] };
}

export interface SlotCandidate {
  slotId: string;
  slotKey: string;
  /** What the listener speaks; SNI-presenting listeners need an active server name. */
  proto: ListenerProto;
  /** Provider the slot's profile is bound to ('' = any provider). */
  provider: string;
  deployed: boolean;
  retired: boolean;
  profileEnabled: boolean;
  activeSnis: number;
}

/** A slot is publishable when deployed with an enabled profile that still has a name to present. */
export function slotEligible(s: SlotCandidate): boolean {
  if (!s.deployed || s.retired || !s.profileEnabled) return false;
  return !protocolUsesSni(s.proto) || s.activeSnis > 0;
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
  const eligible = slots.filter(slotEligible).sort((a, b) => a.slotKey.localeCompare(b.slotKey));
  if (eligible.length === 0) return null;
  if (preferDistinct) {
    // A provider-free slot ('') can always host a distinct provider.
    const fresh = eligible.filter(
      (s) => s.provider === '' || !publishedProviders.includes(s.provider),
    );
    if (fresh.length > 0) {
      return fresh.find((s) => s.provider === providerPreference) ?? fresh[0];
    }
  }
  return eligible.find((s) => s.provider === providerPreference) ?? eligible[0];
}

/**
 * Account pick for a slot that is not bound to one provider: the best qualified
 * account across providers, preferring one not yet published on the origin
 * (when distinct providers are preferred), then the origin's preference.
 */
export function pickAccountAny(
  accounts: readonly AccountCandidate[],
  publishedProviders: readonly string[],
  preferDistinct: boolean,
  providerPreference: string | null,
): { ok: true; account: AccountCandidate } | { ok: false; code: AccountPickFailure } {
  const providers = [...new Set(accounts.map((a) => a.provider))];
  if (providers.length === 0) return { ok: false, code: 'no_account_for_provider' };
  const ranked = [...providers].sort((a, b) => {
    const pa =
      (preferDistinct && publishedProviders.includes(a) ? 2 : 0) +
      (a === providerPreference ? 0 : 1);
    const pb =
      (preferDistinct && publishedProviders.includes(b) ? 2 : 0) +
      (b === providerPreference ? 0 : 1);
    return pa - pb || a.localeCompare(b);
  });
  let failure: AccountPickFailure = 'no_qualified_account';
  for (const p of ranked) {
    const r = pickAccount(accounts, p);
    if (r.ok) return r;
    if (r.code === 'accounts_exhausted') failure = 'accounts_exhausted';
  }
  return { ok: false, code: failure };
}
