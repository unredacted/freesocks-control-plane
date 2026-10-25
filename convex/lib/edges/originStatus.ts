/**
 * One origin's status, judged ONCE on the server (pure: no db, no clock). Every
 * admin page (the Edges home, the node page, All origins, the Servers node
 * page) reads the projection the attention query builds from this module
 * (`origins[]`, `fleet`) and the per-origin Delivery card reads `setup-status`'s
 * `delivery`; the CMS only turns the codes into words (docs/edges.md § "Admin
 * section").
 *
 * Exports:
 *   ATTENTION_RANK              every attention kind, most urgent first (the attention
 *                               query sorts by it; the status picks its item by it)
 *   attentionRankOf(kind)       index in ATTENTION_RANK (unknown kinds rank last)
 *   membersDarkCode(facts)      the `members_dark` rule: why a bound origin's members get
 *                               nothing (`empty_pool` | `relay_disabled` | `render_disabled`),
 *                               or why a node's binding left by a departed origin does (`relay_missing`)
 *   deliveryOf(facts)           what members get: manual | direct | serving | degraded | dark
 *   originStatusOf(facts)       the one status of an origin (kind, dot, code, run, counts)
 *   fleetStatusOf(statuses)     the fleet headline judgement
 *   worstHealthOf(pool) / layersOf(pool)
 */
import type { AttentionKind } from '../../../src/shared/contracts/edgeCodes';
import {
  SETUP_RUN_STAGE_STEP,
  type SetupRunStage,
  type SetupRunState,
} from '../../../src/shared/contracts/edgeCodes';
import type {
  FleetStatus,
  OriginDelivery,
  OriginStatus,
  StatusDot,
} from '../../../src/shared/contracts/edges';
import { isTerminalRunState } from './setupRuns';

/**
 * The server's ranking of every attention kind, most urgent first. The shared
 * vocabulary (`ATTENTION_KINDS`) only appends; a test pins that this list holds
 * exactly the same kinds.
 */
export const ATTENTION_RANK = [
  'quarantine',
  'fleet_brake',
  'needs_operator',
  'account_api_failing',
  'rotation_stuck',
  'host_unresolved',
  'members_dark',
  'delivery_refusals',
  'freedom_node_withheld',
  'direct_host_reappeared',
  'reality_refuses_clients',
  'client_refused',
  'node_awaiting_approval',
  'go_live_pending',
  'setup_run_failed',
  'needs_test',
  'certificate_waiting',
  'rotation_failed',
  'node_ready_to_protect',
  'node_mode_disabled',
  'qualification_lapsed',
  'retest_needed',
  'block_simulated',
  'block_suspected',
  'edge_unreachable',
  'new_edge_blocked_in',
  'edge_off_network',
  'country_wide_failure',
  'probe_source_failing',
  'fleet_rotation_cap',
  'client_check_unavailable',
  'family_rule_disabled',
  'billable_idle',
  'account_spend_cap',
  'health_stale',
  'pool_rebalance',
  'spare_untested',
  'pool_below_desired',
  'reduced_resilience',
  'pick_cooling',
  'account_budget_unlimited',
  'account_unqualified',
  'account_untested',
  'test_key_cleanup',
  'restore_in_progress',
  'front_host_unused',
  'maintenance_frozen',
] as const satisfies readonly AttentionKind[];

export function attentionRankOf(kind: string): number {
  const i = (ATTENTION_RANK as readonly string[]).indexOf(kind);
  return i === -1 ? ATTENTION_RANK.length : i;
}

// --- delivery ------------------------------------------------------------------------------------

export type OriginKind = 'panel-node' | 'backend-server' | 'manual';

export interface DeliveryFacts {
  originKind: OriginKind;
  /** An active delivery binding covers the origin AND names it: its members are served edges only. */
  bound: boolean;
  /**
   * An active binding covers the origin's node but names an origin that no
   * longer exists (one deleted `keep-dark`): members are answered
   * `relay_missing`, whatever this origin publishes.
   */
  foreignBinding?: boolean;
  /** Published edges (the pool's non-empty slots). */
  published: number;
  enabled: boolean;
  /** `edge.render.enabled` (the setup-status rendering step's `renderEnabled` fact). */
  renderEnabled: boolean;
  /**
   * The setup-status rendering step's blockers, where the sample render ran
   * (relay scope only). Omitted everywhere else, so `degraded` is only ever
   * judged by the per-origin setup status.
   */
  renderBlockers?: ReadonlyArray<{ code: string; detail: string | null }> | null;
}

export type MembersDarkCode = 'empty_pool' | 'relay_disabled' | 'render_disabled' | 'relay_missing';

/**
 * The `members_dark` rule (the attention item of the same name): a bound
 * origin whose members get no subscription body, and why; or a node whose
 * binding still names a departed origin (`relay_missing`, the 503 members get).
 * Null when the origin is not bound (and no foreign binding covers it) or can serve.
 */
export function membersDarkCode(
  f: Pick<DeliveryFacts, 'bound' | 'foreignBinding' | 'published' | 'enabled' | 'renderEnabled'>,
): MembersDarkCode | null {
  if (!f.bound) return f.foreignBinding ? 'relay_missing' : null;
  if (f.published === 0) return 'empty_pool';
  if (!f.enabled) return 'relay_disabled';
  if (!f.renderEnabled) return 'render_disabled';
  return null;
}

/** Rendering blockers that leave a bound origin serving, with a problem (first one wins). */
export const SOFT_RENDER_BLOCKERS = [
  'preview_not_applied',
  'entry_mismatch',
  'mirrors_unvalidated',
] as const;

/**
 * What members of one origin get right now: `manual` (nothing FCP serves maps
 * to it), `dark` (the `members_dark` rule: bound and nothing can be served, or
 * the node's binding names a departed origin), `direct` (no delivery binding:
 * the node's own address; a guided origin's binding is deferred until
 * go-live), `degraded` (bound and serving, but the
 * sample render hit a soft problem; `preview_not_applied` carries the sample
 * render's delivery reason as its detail), else `serving`.
 */
export function deliveryOf(f: DeliveryFacts): OriginDelivery {
  if (f.originKind === 'manual') return { kind: 'manual', code: null };
  const dark = membersDarkCode(f);
  if (dark) return { kind: 'dark', code: dark };
  if (!f.bound) return { kind: 'direct', code: null };
  const soft = (f.renderBlockers ?? []).find((b) =>
    (SOFT_RENDER_BLOCKERS as readonly string[]).includes(b.code),
  );
  if (soft) {
    const code = soft.code === 'preview_not_applied' && soft.detail ? soft.detail : soft.code;
    return { kind: 'degraded', code };
  }
  return { kind: 'serving', code: null };
}

// --- pool ----------------------------------------------------------------------------------------

export interface PoolEntryFacts {
  health: string;
  layer: 'l4' | 'l7';
}

const HEALTH_RANK: Record<string, number> = { offline: 3, degraded: 2, unknown: 1, online: 0 };
const healthRank = (h: string) => HEALTH_RANK[h] ?? 1;

/** The worst health of the published pool (offline > degraded > unknown > online); null when empty. */
export function worstHealthOf(pool: readonly PoolEntryFacts[]): string | null {
  if (pool.length === 0) return null;
  let worst = pool[0].health;
  for (const p of pool) if (healthRank(p.health) > healthRank(worst)) worst = p.health;
  return worst;
}

/** The layers of the published pool, L4 first. */
export function layersOf(pool: readonly PoolEntryFacts[]): Array<'l4' | 'l7'> {
  const seen = new Set(pool.map((p) => p.layer));
  return (['l4', 'l7'] as const).filter((l) => seen.has(l));
}

// --- origin status -------------------------------------------------------------------------------

export interface StatusRunFacts {
  id: string;
  /** The run row's `kind` (absent = a first protection). */
  kind?: string | null;
  stage: SetupRunStage;
  state: SetupRunState;
  need?: { code: string } | null;
}

export interface StatusAttentionFacts {
  kind: string;
  severity: 'critical' | 'warning' | 'info';
  code: string | null;
}

export interface OriginStatusFacts {
  originKind: OriginKind;
  enabled: boolean;
  quarantined: boolean;
  /** A restore workflow is running (protection being removed). */
  restore: boolean;
  deleting: boolean;
  bindingDeferred: boolean;
  setupOwned: boolean;
  published: number;
  /** Health and layer of each published edge. */
  pool: readonly PoolEntryFacts[];
  /** Active unpublished edges (spares). */
  standbys: number;
  bound: boolean;
  foreignBinding?: boolean;
  renderEnabled: boolean;
  /** The origin's guided setup run, if any; a terminal run is ignored. */
  run: StatusRunFacts | null;
  /** The origin's newest guided setup run when it failed (no live run): its sheet has Try again. */
  failedRun?: {
    id: string;
    kind?: string | null;
    stage: SetupRunStage;
    code: string | null;
  } | null;
  /** The enrolled node is fronted: its mode gives members no direct address. */
  fronted?: boolean;
  /** The attention items that name this origin (any order, any severity). */
  attention: readonly StatusAttentionFacts[];
}

type Kind = OriginStatus['kind'];

/**
 * Items that only restate the origin's own state, mapped to that state: they
 * never turn it into a generic `needs-you`. Members dark for an empty pool IS
 * the empty pool (`unprotected`); a pending go-live IS `not-live`; a pool short
 * of anything published is `not-live` for a guided origin before go-live and
 * `unprotected` otherwise. Null = the item is its own reason (`needs-you`).
 */
function restatedKind(item: StatusAttentionFacts, f: OriginStatusFacts): Kind | null {
  if (item.kind === 'members_dark' && item.code === 'empty_pool') return 'unprotected';
  if (item.kind === 'go_live_pending') return 'not-live';
  if (item.kind === 'pool_below_desired' && f.published === 0)
    return f.bindingDeferred || f.setupOwned ? 'not-live' : 'unprotected';
  return null;
}

const KIND_DOT: Partial<Record<Kind, StatusDot>> = {
  unprotected: 'red',
  'not-live': 'amber',
};

/**
 * The one status of an origin. Judged in this order (the first that applies):
 *  1. a live (non-terminal) guided setup run: `needs-you` amber (code = the
 *     run's need) while it waits on the operator, else `setting-up` blue;
 *  2. deleting / a restore running: `removing` grey (code `restore` / `deleting`);
 *  3. quarantined: `paused` red;
 *  4. the most urgent critical / warning attention item naming the origin
 *     (ATTENTION_RANK): `needs-you`, red for critical, amber for warning,
 *     code = its kind (an item that only restates the origin's state reports
 *     that state instead, see `restatedKind`);
 *  5. switched off: `off` grey;
 *  6. binding deferred or setup-owned: `not-live` amber;
 *  7. nothing published: `unprotected` red;
 *  8. a published edge offline: `needs-you` red, code `offline`;
 *  9. else `protected` green.
 */
export function originStatusOf(f: OriginStatusFacts): OriginStatus {
  const offline = f.pool.filter((p) => p.health === 'offline').length;
  const base = {
    code: null,
    runId: null,
    runKind: null,
    step: null,
    published: f.published,
    standbys: f.standbys,
    offline,
    worstHealth: worstHealthOf(f.pool),
    layers: layersOf(f.pool),
    attention: f.attention.length > 0,
    delivery: deliveryOf(f),
    failedRunId: null,
    fronted: f.fronted ?? false,
  } satisfies Omit<OriginStatus, 'kind' | 'dot'>;
  const is = (kind: Kind, dot: StatusDot, code: string | null = null): OriginStatus => ({
    ...base,
    failedRunId: f.deleting || f.restore ? null : (f.failedRun?.id ?? null),
    kind,
    dot,
    code,
  });

  const run = f.run && !isTerminalRunState(f.run.state) ? f.run : null;
  if (run) {
    const withRun = {
      ...base,
      runId: run.id,
      runKind: run.kind === 'reprotect' ? ('reprotect' as const) : ('protect' as const),
      step: SETUP_RUN_STAGE_STEP[run.stage],
    };
    if (run.state === 'needs_you')
      return { ...withRun, kind: 'needs-you', dot: 'amber', code: run.need?.code ?? null };
    return { ...withRun, kind: 'setting-up', dot: 'blue' };
  }
  if (f.deleting || f.restore) return is('removing', 'grey', f.restore ? 'restore' : 'deleting');
  if (f.quarantined) return is('paused', 'red');
  let urgent: StatusAttentionFacts | null = null;
  for (const a of f.attention) {
    if (a.severity !== 'critical' && a.severity !== 'warning') continue;
    if (!urgent || attentionRankOf(a.kind) < attentionRankOf(urgent.kind)) urgent = a;
  }
  if (urgent) {
    const restated = restatedKind(urgent, f);
    if (restated) return is(restated, KIND_DOT[restated] ?? 'amber');
    return is('needs-you', urgent.severity === 'critical' ? 'red' : 'amber', urgent.kind);
  }
  if (!f.enabled) return is('off', 'grey');
  if (f.bindingDeferred || f.setupOwned) return is('not-live', 'amber');
  if (f.published === 0) return is('unprotected', 'red');
  if (offline > 0) return is('needs-you', 'red', 'offline');
  return is('protected', 'green');
}

// --- fleet ---------------------------------------------------------------------------------------

/**
 * The fleet in one judgement, what matters most first: `empty` (no origin),
 * `needs-you` (needs-you + paused + unprotected), `setting-up`, `not-live`,
 * `protected` (every origin), else `partial` (some are off or being removed;
 * green when any is protected). `count` = the origins in the winning state
 * (for `partial`: the ones not protected).
 */
export function fleetStatusOf(statuses: ReadonlyArray<Pick<OriginStatus, 'kind'>>): FleetStatus {
  const total = statuses.length;
  const n = (...kinds: Kind[]) => statuses.filter((s) => kinds.includes(s.kind)).length;
  const protectedCount = n('protected');
  const out = (kind: FleetStatus['kind'], dot: StatusDot, count: number): FleetStatus => ({
    kind,
    dot,
    count,
    total,
    protected: protectedCount,
  });
  if (total === 0) return out('empty', 'grey', 0);
  const needs = n('needs-you', 'paused', 'unprotected');
  if (needs > 0) return out('needs-you', 'amber', needs);
  const setting = n('setting-up');
  if (setting > 0) return out('setting-up', 'blue', setting);
  const notLive = n('not-live');
  if (notLive > 0) return out('not-live', 'amber', notLive);
  if (protectedCount === total) return out('protected', 'green', total);
  return out('partial', protectedCount > 0 ? 'green' : 'grey', total - protectedCount);
}
