/**
 * All origins' derivations (pure; unit-tested). The JUDGEMENTS (delivery,
 * worst health, layers, whether an origin needs attention) are the server's
 * one status projection (the attention response's `origins[]`,
 * convex/lib/edges/originStatus.ts); this module only filters by them, counts
 * them into tiles and words them. Figures the `EdgeSummary` contract does not
 * carry (published per layer, standbys, probe budget) are counted from the
 * summary rows.
 *
 * Exports:
 *   OVERVIEW_FILTERS / OVERVIEW_LAYERS, parseFilter, parseLayer
 *   statusIndex(origins)           slug -> the server's OriginStatus
 *   matchesFilter(row, filter, status), matchesLayer(status, layer), filterRelays(rows, ...)
 *   fleetTiles(summary, statuses, probe) -> FleetTile[]
 *   DELIVERY_LABELS / DELIVERY_TONES     the server's delivery kinds in words
 *   ORIGIN_KIND_LABELS, suspicionChip(row)
 */
import type { z } from 'zod';
import type {
  EdgeSummary,
  OriginDelivery,
  OriginStatus,
  OriginStatusRow,
  RelayPoolSummary,
} from '../../../../../shared/contracts/edges';
import { codeLabel, type Tone } from '../../../../lib/edgeCodes';

export type OriginRow = z.infer<typeof RelayPoolSummary>;

export const OVERVIEW_FILTERS = ['all', 'attention', 'dark', 'quarantined', 'unpublished'] as const;
export type OverviewFilter = (typeof OVERVIEW_FILTERS)[number];
export const OVERVIEW_LAYERS = ['all', 'l4', 'l7'] as const;
export type OverviewLayer = (typeof OVERVIEW_LAYERS)[number];

export const FILTER_LABELS: Record<OverviewFilter, string> = {
  all: 'All origins',
  attention: 'Needs attention',
  dark: 'Members dark',
  quarantined: 'Quarantined',
  unpublished: 'Nothing published',
};
export const LAYER_FILTER_LABELS: Record<OverviewLayer, string> = {
  all: 'Any layer',
  l4: 'L4 only',
  l7: 'L7 only',
};

export const parseFilter = (raw: string | null | undefined): OverviewFilter =>
  (OVERVIEW_FILTERS as readonly string[]).includes(raw ?? '') ? (raw as OverviewFilter) : 'all';
export const parseLayer = (raw: string | null | undefined): OverviewLayer =>
  (OVERVIEW_LAYERS as readonly string[]).includes(raw ?? '') ? (raw as OverviewLayer) : 'all';

/** The server's status of each origin, by slug. */
export function statusIndex(
  origins: readonly OriginStatusRow[] | undefined,
): ReadonlyMap<string, OriginStatus> {
  return new Map((origins ?? []).map((o) => [o.relaySlug, o.status]));
}

export const ORIGIN_KIND_LABELS: Record<OriginRow['relay']['origin']['kind'], string> = {
  'panel-node': 'Backend node',
  'backend-server': 'Backend server',
  manual: 'Manual origin',
};

export const DELIVERY_LABELS: Record<OriginDelivery['kind'], string> = {
  manual: 'Nothing to deliver',
  direct: 'Direct address',
  serving: 'Serving',
  degraded: 'Serving, with a problem',
  dark: 'Members dark',
};
export const DELIVERY_TONES: Record<OriginDelivery['kind'], Tone> = {
  manual: 'muted',
  direct: 'muted',
  serving: 'success',
  degraded: 'warning',
  dark: 'danger',
};

/** A row the server has no status for yet (the attention response is loading) matches only `all`. */
export function matchesFilter(
  row: OriginRow,
  filter: OverviewFilter,
  status: OriginStatus | undefined,
): boolean {
  switch (filter) {
    case 'all':
      return true;
    case 'attention':
      return (status?.attention ?? false) || row.needsOperator > 0;
    case 'dark':
      return status?.delivery.kind === 'dark';
    case 'quarantined':
      return row.relay.quarantine !== null;
    case 'unpublished':
      return (status?.published ?? row.relay.publishedCount) === 0;
  }
}
export function matchesLayer(status: OriginStatus | undefined, layer: OverviewLayer): boolean {
  return layer === 'all' || (status?.layers ?? []).includes(layer);
}
export function filterRelays(
  rows: readonly OriginRow[],
  filter: OverviewFilter,
  layer: OverviewLayer,
  statuses: ReadonlyMap<string, OriginStatus>,
): OriginRow[] {
  return rows.filter((r) => {
    const status = statuses.get(r.relay.slug);
    return matchesFilter(r, filter, status) && matchesLayer(status, layer);
  });
}

/** The detector chip of a row: a veto wins over a suspicion; null = nothing to say. */
export function suspicionChip(row: OriginRow): { label: string; tone: Tone; hint: string } | null {
  const s = row.relay.suspicion;
  if (!s) return null;
  if (s.veto) {
    return {
      label: `Held back: ${codeLabel(s.veto)}`,
      tone: 'info',
      hint: 'The detector saw a signal but this reason stops it from acting.',
    };
  }
  if (s.state !== 'suspected') return null;
  const where =
    s.scope === 'regional' && s.countries.length > 0
      ? ` in ${s.countries
          .slice(0, 4)
          .map((c) => c.code)
          .join(', ')}`
      : '';
  const evidence =
    s.hintLevel === 'corroborated'
      ? 'reports and probes agree'
      : s.hintLevel === 'probes'
        ? 'probes only'
        : s.hintLevel === 'reports'
          ? 'member reports only'
          : 'weak evidence';
  return {
    label: `Block suspected${where}`,
    tone: 'warning',
    hint: `Evidence: ${evidence}.`,
  };
}

export interface FleetTile {
  id:
    | 'relays'
    | 'published-l4'
    | 'published-l7'
    | 'standbys'
    | 'rotating'
    | 'quarantined'
    | 'needs-operator'
    | 'dark'
    | 'probe-budget';
  label: string;
  value: string;
  hint: string;
  /** A problem tile is toned when its count is non-zero. */
  tone: Tone;
  /** The filter a click applies; only set while the problem count is non-zero. */
  filter: OverviewFilter | null;
}

export interface ProbeBudget {
  /** Probe runs in the last hour (probe summary), when known. */
  usedLastHour: number | null;
  /** `probe.hourlyBudget` (0 = no external probes allowed), when known. */
  hourlyBudget: number | null;
  enabled: boolean | null;
}

export function fleetTiles(
  summary: EdgeSummary,
  statuses: ReadonlyMap<string, OriginStatus>,
  probe: ProbeBudget,
): FleetTile[] {
  let l4 = 0;
  let l7 = 0;
  let standbys = 0;
  for (const r of summary.relays) {
    standbys += r.standbys;
    for (const p of r.pool) {
      if (p.layer === 'l7') l7++;
      else l4++;
    }
  }
  const dark = [...statuses.values()].filter((st) => st.delivery.kind === 'dark').length;
  const c = summary.counts;
  const problem = (n: number, tone: Tone): Tone => (n > 0 ? tone : 'neutral');

  let budgetValue = 'Unknown';
  let budgetHint = 'Probe runs in the last hour against the hourly budget.';
  let budgetTone: Tone = 'neutral';
  if (probe.enabled === false) {
    budgetValue = 'Off';
    budgetHint = 'Probes are switched off in the settings.';
    budgetTone = 'muted';
  } else if (probe.hourlyBudget !== null) {
    const used = probe.usedLastHour;
    budgetValue = used === null ? `of ${probe.hourlyBudget}` : `${used} of ${probe.hourlyBudget}`;
    budgetHint = 'Probe runs in the last hour against the hourly budget.';
    if (used !== null && probe.hourlyBudget > 0) {
      const ratio = used / probe.hourlyBudget;
      budgetTone = ratio >= 1 ? 'danger' : ratio >= 0.8 ? 'warning' : 'neutral';
    }
  }

  return [
    {
      id: 'relays',
      label: 'Relays',
      value: String(c.relays),
      hint: 'Origins registered with the control plane.',
      tone: 'neutral',
      filter: null,
    },
    {
      id: 'published-l4',
      label: 'Published L4',
      value: String(l4),
      hint: 'Load balancer edges members connect to right now.',
      tone: 'neutral',
      filter: null,
    },
    {
      id: 'published-l7',
      label: 'Published L7',
      value: String(l7),
      hint: 'CDN fronts members connect to right now.',
      tone: 'neutral',
      filter: null,
    },
    {
      id: 'standbys',
      label: 'Standbys',
      value: String(standbys),
      hint: 'Ready edges kept in reserve, not handed to members.',
      tone: 'neutral',
      filter: null,
    },
    {
      id: 'rotating',
      label: 'Rotations running',
      value: String(c.rotating),
      hint: 'Provision, publish or replace runs in progress.',
      tone: c.rotating > 0 ? 'info' : 'neutral',
      filter: null,
    },
    {
      id: 'quarantined',
      label: 'Quarantined',
      value: String(c.quarantined),
      hint: 'Origins frozen after a run could not roll back cleanly.',
      tone: problem(c.quarantined, 'danger'),
      filter: c.quarantined > 0 ? 'quarantined' : null,
    },
    {
      id: 'needs-operator',
      label: 'Needs operator',
      value: String(c.needsOperator),
      hint: 'Edges the automation gave up on and left for you to decide.',
      tone: problem(c.needsOperator, 'warning'),
      filter: c.needsOperator > 0 ? 'attention' : null,
    },
    {
      id: 'dark',
      label: 'Members dark',
      value: String(dark),
      hint: 'Origins whose members currently get no subscription.',
      tone: problem(dark, 'danger'),
      filter: dark > 0 ? 'dark' : null,
    },
    {
      id: 'probe-budget',
      label: 'Probe budget',
      value: budgetValue,
      hint: budgetHint,
      tone: budgetTone,
      filter: null,
    },
  ];
}
