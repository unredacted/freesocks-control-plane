/**
 * Overview derivations (pure; unit-tested). Everything the dashboard shows that
 * the `EdgeSummary` contract does not carry as a figure is derived HERE from the
 * summary's origin rows and the attention list, never invented.
 *
 * Exports:
 *   OVERVIEW_FILTERS / OVERVIEW_LAYERS, parseFilter, parseLayer
 *   relayLayers(row), worstHealth(row), deliveryState(row, darkSlugs)
 *   darkRelaySlugs(items), attentionRelaySlugs(items)
 *   matchesFilter(row, filter, ctx), matchesLayer(row, layer), filterRelays(rows, ...)
 *   fleetTiles(summary, items, probe) -> FleetTile[]
 *   ORIGIN_KIND_LABELS, suspicionChip(row)
 */
import type { z } from 'zod';
import type {
  AttentionItem as AttentionItemSchema,
  EdgeLayer,
  EdgeSummary,
  RelayPoolSummary,
} from '../../../../../shared/contracts/edges';
import { codeLabel, type Tone } from '../../../../lib/edgeCodes';

export type RelayRow = z.infer<typeof RelayPoolSummary>;
export type AttentionItem = z.infer<typeof AttentionItemSchema>;

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

export const ORIGIN_KIND_LABELS: Record<RelayRow['relay']['origin']['kind'], string> = {
  'panel-node': 'Backend node',
  'backend-server': 'Backend server',
  manual: 'Manual origin',
};

/** The layers of the origin's PUBLISHED pool, L4 first. */
export function relayLayers(row: RelayRow): EdgeLayer[] {
  const seen = new Set<EdgeLayer>(row.pool.map((p) => p.layer));
  return (['l4', 'l7'] as const).filter((l) => seen.has(l));
}

const HEALTH_RANK: Record<string, number> = { offline: 3, degraded: 2, unknown: 1, online: 0 };
/** The worst health among the published edges; null when nothing is published. */
export function worstHealth(row: RelayRow): string | null {
  if (row.pool.length === 0) return null;
  let worst = row.pool[0]!.health;
  for (const p of row.pool) {
    if ((HEALTH_RANK[p.health] ?? 1) > (HEALTH_RANK[worst] ?? 1)) worst = p.health;
  }
  return worst;
}

/** Origins the server reports as leaving members without a usable subscription. */
export function darkRelaySlugs(items: readonly AttentionItem[]): Set<string> {
  const out = new Set<string>();
  for (const i of items) if (i.kind === 'members_dark' && i.relaySlug) out.add(i.relaySlug);
  return out;
}
/** Origins with at least one attention item of any kind. */
export function attentionRelaySlugs(items: readonly AttentionItem[]): Set<string> {
  const out = new Set<string>();
  for (const i of items) if (i.relaySlug) out.add(i.relaySlug);
  return out;
}

export type DeliveryState = 'dark' | 'serving' | 'idle';
/**
 * dark = the server says members of this origin get no subscription body;
 * serving = at least one edge is published; idle = nothing published and no
 * member depends on it yet.
 */
export function deliveryState(row: RelayRow, dark: ReadonlySet<string>): DeliveryState {
  if (dark.has(row.relay.slug)) return 'dark';
  return row.relay.publishedCount > 0 ? 'serving' : 'idle';
}
export const DELIVERY_LABELS: Record<DeliveryState, string> = {
  dark: 'Members dark',
  serving: 'Serving',
  idle: 'Nothing published',
};
export const DELIVERY_TONES: Record<DeliveryState, Tone> = {
  dark: 'danger',
  serving: 'success',
  idle: 'muted',
};

export interface FilterContext {
  dark: ReadonlySet<string>;
  attention: ReadonlySet<string>;
}
export function matchesFilter(row: RelayRow, filter: OverviewFilter, ctx: FilterContext): boolean {
  switch (filter) {
    case 'all':
      return true;
    case 'attention':
      return ctx.attention.has(row.relay.slug) || row.needsOperator > 0;
    case 'dark':
      return ctx.dark.has(row.relay.slug);
    case 'quarantined':
      return row.relay.quarantine !== null;
    case 'unpublished':
      return row.relay.publishedCount === 0;
  }
}
export function matchesLayer(row: RelayRow, layer: OverviewLayer): boolean {
  return layer === 'all' || row.pool.some((p) => p.layer === layer);
}
export function filterRelays(
  rows: readonly RelayRow[],
  filter: OverviewFilter,
  layer: OverviewLayer,
  ctx: FilterContext,
): RelayRow[] {
  return rows.filter((r) => matchesFilter(r, filter, ctx) && matchesLayer(r, layer));
}

/** The detector chip of a row: a veto wins over a suspicion; null = nothing to say. */
export function suspicionChip(row: RelayRow): { label: string; tone: Tone; hint: string } | null {
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
  items: readonly AttentionItem[],
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
  const dark = darkRelaySlugs(items).size;
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
