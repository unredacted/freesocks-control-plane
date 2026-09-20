/**
 * The simple screens' status logic (pure; unit-tested): one sentence and one
 * dot per protected node, one sentence for the fleet, and the four plain stages
 * of a guided setup run.
 *
 * Exports:
 *   nodeStatus(row, ctx)          -> NodeStatus for one origin row
 *   fleetSentence(statuses)       -> the home's headline
 *   runIsLive(run)                a run that is still going (not terminal)
 *   plainStage(stage)             machine stage -> 1..4 (done -> 5)
 *   PLAIN_STAGES                  the four stage labels, in order
 *   liveRunFor(runs, slug)        the live run of an origin, if any
 */
import type { z } from 'zod';
import type {
  AttentionItem,
  EdgeSummary,
  OriginAdmin,
  SetupRunAdmin,
} from '../../../../../shared/contracts/edges';
import type { SetupRunStage } from '../../../../../shared/contracts/edgeCodes';
import { codeLabel } from '../../../../lib/edgeCodes';

export type OriginRow = z.infer<typeof EdgeSummary>['relays'][number];
export type Dot = 'green' | 'amber' | 'red' | 'blue' | 'grey';

export interface NodeStatus {
  kind:
    | 'protected'
    | 'setting-up'
    | 'needs-you'
    | 'not-live'
    | 'removing'
    | 'paused'
    | 'off'
    | 'unprotected';
  dot: Dot;
  /** One plain sentence. */
  sentence: string;
  /** The plain stage (1..4) while a run is live. */
  step?: number;
}

const TERMINAL = new Set<SetupRunAdmin['state']>(['done', 'done_unbound', 'failed', 'cancelled']);
export const runIsLive = (run: Pick<SetupRunAdmin, 'state'>): boolean => !TERMINAL.has(run.state);

export const PLAIN_STAGES = [
  'Creating the address',
  'Checking from outside',
  'Checking it works',
  'Going live',
] as const;

/** The machine's ten stages folded onto the four the operator sees (`done` = 5, past the last). */
export function plainStage(stage: SetupRunStage): number {
  switch (stage) {
    case 'prepare':
    case 'credential':
    case 'provision':
      return 1;
    case 'verify':
      return 2;
    case 'try_it':
    case 'publish':
      return 3;
    case 'hide_direct_hosts':
    case 'rehearse':
    case 'go_live':
      return 4;
    case 'done':
      return 5;
  }
}

export function liveRunFor(runs: readonly SetupRunAdmin[], slug: string): SetupRunAdmin | null {
  return runs.find((r) => r.relaySlug === slug && runIsLive(r)) ?? null;
}

export interface StatusContext {
  attention: readonly AttentionItem[];
  runs: readonly SetupRunAdmin[];
}

type RelayLike = Pick<
  OriginAdmin,
  | 'slug'
  | 'enabled'
  | 'quarantine'
  | 'restore'
  | 'deleting'
  | 'bindingDeferred'
  | 'setupOwned'
  | 'publishedCount'
>;

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

export function nodeStatus(
  row: { relay: RelayLike; pool: ReadonlyArray<{ health: string }>; standbys: number },
  ctx: StatusContext,
): NodeStatus {
  const r = row.relay;
  const run = liveRunFor(ctx.runs, r.slug);
  if (run) {
    const step = plainStage(run.stage);
    if (run.state === 'needs_you') {
      return {
        kind: 'needs-you',
        dot: 'amber',
        sentence: `Setting up, step ${step} of 4. It needs you.`,
        step,
      };
    }
    return { kind: 'setting-up', dot: 'blue', sentence: `Setting up, step ${step} of 4.`, step };
  }
  if (r.deleting || r.restore) {
    return {
      kind: 'removing',
      dot: 'grey',
      sentence: r.restore ? 'Removing protection.' : 'Being removed.',
    };
  }
  if (r.quarantine) {
    return { kind: 'paused', dot: 'red', sentence: 'Paused for safety. It needs you.' };
  }
  const urgent = ctx.attention.find(
    (a) => a.relaySlug === r.slug && (a.severity === 'critical' || a.severity === 'warning'),
  );
  if (urgent) {
    return {
      kind: 'needs-you',
      dot: urgent.severity === 'critical' ? 'red' : 'amber',
      sentence: `${codeLabel(urgent.kind)}. It needs you.`,
    };
  }
  if (!r.enabled) {
    return { kind: 'off', dot: 'grey', sentence: 'Protection is switched off (Advanced).' };
  }
  if (r.bindingDeferred || r.setupOwned) {
    return {
      kind: 'not-live',
      dot: 'amber',
      sentence:
        r.publishedCount > 0
          ? 'Address ready, not live yet. Members still use the direct address.'
          : 'Not protected yet. Members use the direct address.',
    };
  }
  if (r.publishedCount === 0) {
    return { kind: 'unprotected', dot: 'red', sentence: 'No address in use. Members get nothing.' };
  }
  const offline = row.pool.filter((p) => p.health === 'offline').length;
  if (offline > 0) {
    return {
      kind: 'needs-you',
      dot: 'red',
      sentence: `${plural(offline, 'address is', 'addresses are')} offline.`,
    };
  }
  const spare = row.standbys > 0 ? `, ${plural(row.standbys, 'spare', 'spares')}` : '';
  return {
    kind: 'protected',
    dot: 'green',
    sentence: `Protected. ${plural(r.publishedCount, 'address', 'addresses')} in use${spare}.`,
  };
}

/** The home's headline: what matters most, then the count. */
export function fleetSentence(statuses: readonly NodeStatus[]): { text: string; dot: Dot } {
  const n = statuses.length;
  if (n === 0) return { text: 'No node is protected yet.', dot: 'grey' };
  const needs = statuses.filter(
    (s) => s.kind === 'needs-you' || s.kind === 'paused' || s.kind === 'unprotected',
  ).length;
  if (needs > 0) return { text: `${plural(needs, 'node needs', 'nodes need')} you.`, dot: 'amber' };
  const setting = statuses.filter((s) => s.kind === 'setting-up').length;
  if (setting > 0) return { text: `Setting up ${plural(setting, 'node', 'nodes')}.`, dot: 'blue' };
  const notLive = statuses.filter((s) => s.kind === 'not-live').length;
  if (notLive > 0)
    return { text: `${plural(notLive, 'node is', 'nodes are')} not live yet.`, dot: 'amber' };
  const protectedCount = statuses.filter((s) => s.kind === 'protected').length;
  if (protectedCount === n)
    return {
      text: n === 1 ? 'Your node is protected.' : `All ${n} nodes protected.`,
      dot: 'green',
    };
  return {
    text: `${protectedCount} of ${plural(n, 'node', 'nodes')} protected.`,
    dot: protectedCount > 0 ? 'green' : 'grey',
  };
}
