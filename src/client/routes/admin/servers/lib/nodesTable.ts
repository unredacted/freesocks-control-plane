/**
 * The Nodes table (pure; unit-tested in nodesTable.test.ts): ONE row per node
 * of every backend, plus every origin that is not a backend node row (added by
 * hand, or a backend node the panel no longer lists), joined with the edges
 * that front it.
 *
 * Inputs are what the page already reads: each backend's tree and enrolled
 * nodes (serversApi), the edge summary rows and the server's status of each
 * origin (edgesApi). Every judgement stays the server's: the node's own words
 * (words.ts `nodeWords`, `stageWords`) and the origin's (edges statusWords
 * `originSentence`); this module only picks the most urgent one, counts
 * addresses and filters.
 *
 * URL state of the page (`/admin/servers/nodes`):
 *   ?show=     all | attention | fronted | direct | retiring | by-hand,
 *              and with technical columns: dark | quarantined | unpublished
 *   ?layer=    all | l4 | l7 (technical columns only)
 *   ?backend=  one backend's slug (the Backend chip)
 *   ?columns=technical   the Technical columns (the old All origins table)
 *
 * Exports:
 *   NODE_FILTERS, TECH_FILTERS, FILTER_LABELS, parseShow, parseLayer
 *   buildNodeRows(input) -> NodeRow[]
 *   rowMatches(row, show, layer), searchMatches(row, query), filterNodeRows(rows, f)
 *   filterCounts(rows) -> count per filter
 *   addressesWords(origin, status) -> "3 fronted, 1 spare" / "Direct" / ...
 *   pickStatus(candidates) -> the most urgent { dot, sentence }
 *   waitsForWipe(intent), tableState(queries), setupsStopped(before, now)
 *   rowHref(row) -> the node's page, or the origin's own page
 *
 * The old All origins query becomes the Nodes query in ../../edges/lib/routes.ts
 * (`originsToNodesSearch`), next to `edgesPaths.overview`.
 */
import type { NodeIntentView, NodeView } from '../../../../../shared/contracts/servers';
import type { OriginStatus, RelayPoolSummary } from '../../../../../shared/contracts/edges';
import type { z } from 'zod';
import { originSentence } from '../../edges/lib/statusWords';
import { edgesPaths } from '../../edges/lib/routes';
import { nodeMatches } from './nodeFilter';
import { serversPaths } from './routes';
import { machineNameShown } from './machineName';
import { nodeWords, stageWords } from './words';

export type OriginRow = z.infer<typeof RelayPoolSummary>;
export type RowDot = 'green' | 'amber' | 'red' | 'blue' | 'grey';

export const NODE_FILTERS = [
  'all',
  'attention',
  'fronted',
  'direct',
  'retiring',
  'by-hand',
] as const;
/** Filters shown only with the technical columns (the old All origins filters). */
export const TECH_FILTERS = ['dark', 'quarantined', 'unpublished'] as const;
export type NodeFilter = (typeof NODE_FILTERS)[number] | (typeof TECH_FILTERS)[number];
export const LAYERS = ['all', 'l4', 'l7'] as const;
export type LayerFilter = (typeof LAYERS)[number];

export const FILTER_LABELS: Record<NodeFilter, string> = {
  all: 'All',
  attention: 'Action needed',
  fronted: 'Fronted',
  direct: 'Direct',
  retiring: 'Retiring',
  'by-hand': 'Added by hand',
  dark: 'Members dark',
  quarantined: 'Quarantined',
  unpublished: 'Nothing published',
};
export const LAYER_LABELS: Record<LayerFilter, string> = {
  all: 'Any layer',
  l4: 'L4 only',
  l7: 'L7 only',
};

export function parseShow(raw: string | null | undefined, technical: boolean): NodeFilter {
  const v = raw ?? '';
  if ((NODE_FILTERS as readonly string[]).includes(v)) return v as NodeFilter;
  if (technical && (TECH_FILTERS as readonly string[]).includes(v)) return v as NodeFilter;
  return 'all';
}
export const parseLayer = (raw: string | null | undefined, technical: boolean): LayerFilter =>
  technical && (LAYERS as readonly string[]).includes(raw ?? '') ? (raw as LayerFilter) : 'all';

export interface NodeRow {
  /** Stable per row. */
  key: string;
  /** node: a backend node row; retiring: an enrolled node whose panel row is gone; origin: an origin with no node row. */
  kind: 'node' | 'retiring' | 'origin';
  /** An origin that is not a backend node (a manual address or a whole server). */
  byHand: boolean;
  name: string;
  /** The machine name, when it says more than the name. */
  machine: string | null;
  backend: { slug: string; name: string } | null;
  nodeUuid: string | null;
  countryCode: string | null;
  modes: string[];
  usersOnline: number | null;
  origin: OriginRow | null;
  status: OriginStatus | null;
  dot: RowDot;
  sentence: string;
  /** Something here waits for someone. */
  attention: boolean;
  retiring: boolean;
  /** An enrolled node with no intent yet: it can be adopted. */
  adoptable: boolean;
  /** The live (or stopped first) guided setup run, whose progress the row can open. */
  runId: string | null;
}

export interface BackendInput {
  instance: { id: string; slug: string; name: string };
  nodes: readonly NodeView[];
  intents: readonly NodeIntentView[];
  /** Node uuids the backend's Action needed names (words.ts `needsYou`). */
  attentionNodes?: ReadonlySet<string>;
  /** Whether an offline reading of this node is its restart for a change. */
  restarting?: (node: NodeView, intent: NodeIntentView | null) => boolean;
}

export interface BuildInput {
  backends: readonly BackendInput[];
  origins: readonly OriginRow[];
  statuses: ReadonlyMap<string, OriginStatus>;
  /**
   * Backends (by id) the page does not show (the Backend chip keeps another
   * one): their nodes' origins are left out, never listed as stray origins.
   */
  hiddenBackendIds?: ReadonlySet<string>;
}

/**
 * An adopted node whose retirement waits at the wipe: nothing reports a wipe
 * the role never runs, so it waits for the admin's "The machine is gone".
 */
export function waitsForWipe(
  intent: Pick<NodeIntentView, 'adopted' | 'retirement'> | null,
): boolean {
  return !!intent?.adopted && intent.retirement?.stage === 'ready_to_wipe';
}

/**
 * What the Nodes table can show: `loading` until every query it reads has
 * answered once, then `error` (naming the first that failed, so the page can
 * offer Retry for it) or `ready`. A failed origin status read is an error, not
 * an empty status: without it every fronted row would lose its sentence and
 * Action needed its origin problems.
 */
export function tableState<K extends string>(
  queries: ReadonlyArray<readonly [K, { isPending: boolean; isError: boolean }]>,
): { kind: 'loading' } | { kind: 'error'; failed: K } | { kind: 'ready' } {
  const failed = queries.find(([, q]) => q.isError);
  if (failed) return { kind: 'error', failed: failed[0] };
  if (queries.some(([, q]) => q.isPending)) return { kind: 'loading' };
  return { kind: 'ready' };
}

/** The backends whose setup run was running before and is not now (each needs a fresh read). */
export function setupsStopped(
  before: ReadonlyMap<string, boolean>,
  now: ReadonlyMap<string, boolean>,
): string[] {
  return [...before].filter(([slug, was]) => was && !now.get(slug)).map(([slug]) => slug);
}

const RANK: Record<RowDot, number> = { red: 4, amber: 3, blue: 2, grey: 1, green: 0 };

/**
 * The most urgent of several { dot, sentence }: the worst dot wins, the
 * earlier one on a tie. With nothing but green, the first.
 */
export function pickStatus(
  candidates: ReadonlyArray<{ dot: RowDot; sentence: string } | null | undefined>,
): { dot: RowDot; sentence: string } {
  let best: { dot: RowDot; sentence: string } | null = null;
  for (const c of candidates) {
    if (!c) continue;
    if (!best || RANK[c.dot] > RANK[best.dot]) best = c;
  }
  return best ?? { dot: 'grey', sentence: '' };
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** The Addresses cell: how members reach the node. */
export function addressesWords(origin: OriginRow | null, status: OriginStatus | null): string {
  if (!origin) return 'Direct';
  const published = status?.published ?? origin.relay.publishedCount;
  const spares = status?.standbys ?? origin.standbys;
  const offline = status?.offline ?? 0;
  if (published === 0 && spares === 0) return 'None yet';
  const parts = [`${published} fronted`];
  if (spares > 0) parts.push(plural(spares, 'spare', 'spares'));
  if (offline > 0) parts.push(`${offline} offline`);
  return parts.join(', ');
}

function runOf(status: OriginStatus | null): string | null {
  if (!status) return null;
  return (
    status.runId ??
    (status.kind === 'needs-you' && status.code === 'setup_run_failed' ? status.failedRunId : null)
  );
}

function originStatusWords(status: OriginStatus | null): { dot: RowDot; sentence: string } | null {
  return status ? { dot: status.dot, sentence: originSentence(status) } : null;
}

function originAttention(origin: OriginRow | null, status: OriginStatus | null): boolean {
  return (status?.attention ?? false) || (origin?.needsOperator ?? 0) > 0;
}

/** The modes a node serves: its enrolled mode and extra modes, else its mode groups. */
function modesOf(node: NodeView | null, intent: NodeIntentView | null): string[] {
  if (intent) {
    const extra = intent.extraModes.filter((m) => m.state === 'serving').map((m) => m.slug);
    return [intent.mode.name, ...extra.filter((s) => s !== intent.mode.slug)];
  }
  const names = new Set<string>();
  for (const t of node?.transports ?? []) for (const g of t.modeGroups) names.add(g.name);
  return [...names];
}

export function buildNodeRows(input: BuildInput): NodeRow[] {
  const rows: NodeRow[] = [];
  const claimed = new Set<string>();
  const statusOf = (o: OriginRow | null) => (o ? (input.statuses.get(o.relay.slug) ?? null) : null);

  for (const b of input.backends) {
    const backend = { slug: b.instance.slug, name: b.instance.name };
    const originsHere = input.origins.filter(
      (o) =>
        o.relay.origin.kind === 'panel-node' && o.relay.origin.backendServerId === b.instance.id,
    );
    const originFor = (uuid: string | null, name: string): OriginRow | null =>
      originsHere.find((o) => {
        const ref = o.relay.origin;
        if (ref.kind !== 'panel-node' || claimed.has(o.relay.id)) return false;
        return ref.nodeUuid ? ref.nodeUuid === uuid : ref.nodeName === name;
      }) ?? null;
    const intentOf = (n: { nodeUuid: string; name: string }) =>
      b.intents.find((i) => i.nodeUuid === n.nodeUuid || i.name === n.name) ?? null;

    for (const node of b.nodes) {
      const intent = intentOf(node);
      const origin = originFor(node.nodeUuid, node.name);
      if (origin) claimed.add(origin.relay.id);
      const status = statusOf(origin);
      const restarting = b.restarting?.(node, intent) ?? false;
      const w = nodeWords(node, { restarting });
      const stage = intent ? stageWords(intent) : null;
      const picked = pickStatus([
        stage && stage.dot !== 'green' ? stage : null,
        originStatusWords(status),
        w,
      ]);
      const retiring = !!intent?.retirement && intent.retirement.stage !== 'retired';
      rows.push({
        key: `node:${b.instance.slug}:${node.nodeUuid}`,
        kind: 'node',
        byHand: false,
        name: node.name,
        machine: machineNameShown(node.name, intent?.machineName),
        backend,
        nodeUuid: node.nodeUuid,
        countryCode: node.countryCode,
        modes: modesOf(node, intent),
        usersOnline: node.usersOnline,
        origin,
        status,
        dot: picked.dot,
        sentence: picked.sentence,
        attention:
          picked.dot === 'red' ||
          picked.dot === 'amber' ||
          waitsForWipe(intent) ||
          (b.attentionNodes?.has(node.nodeUuid) ?? false) ||
          originAttention(origin, status),
        retiring,
        adoptable: !intent,
        runId: runOf(status),
      });
    }

    // Retiring removes a node's panel row before its machine is wiped: such a
    // node is listed until it is retired, so its steps stay reachable.
    for (const intent of b.intents) {
      if (!intent.retirement || intent.retirement.stage === 'retired') continue;
      if (b.nodes.some((n) => n.nodeUuid === intent.nodeUuid || n.name === intent.name)) continue;
      const origin = originFor(intent.nodeUuid, intent.name);
      if (origin) claimed.add(origin.relay.id);
      const status = statusOf(origin);
      const st = stageWords(intent);
      rows.push({
        key: `retiring:${b.instance.slug}:${intent.id}`,
        kind: 'retiring',
        byHand: false,
        name: intent.name,
        machine: machineNameShown(intent.name, intent.machineName),
        backend,
        nodeUuid: intent.nodeUuid,
        countryCode: null,
        modes: modesOf(null, intent),
        usersOnline: null,
        origin,
        status,
        dot: st.dot,
        sentence: st.sentence,
        attention: st.dot === 'amber' || st.dot === 'red' || waitsForWipe(intent),
        retiring: true,
        adoptable: false,
        runId: null,
      });
    }
  }

  // Every other origin: added by hand, or a backend node no tree lists (yet).
  for (const origin of input.origins) {
    if (claimed.has(origin.relay.id)) continue;
    const ref = origin.relay.origin;
    if (ref.kind === 'panel-node' && input.hiddenBackendIds?.has(ref.backendServerId)) continue;
    const status = statusOf(origin);
    const words = originStatusWords(status);
    const backendRow =
      ref.kind === 'panel-node'
        ? (input.backends.find((b) => b.instance.id === ref.backendServerId)?.instance ?? null)
        : null;
    rows.push({
      key: `origin:${origin.relay.id}`,
      kind: 'origin',
      byHand: ref.kind !== 'panel-node',
      name: origin.relay.label ?? (ref.kind === 'panel-node' ? ref.nodeName : origin.relay.slug),
      machine: null,
      backend: backendRow ? { slug: backendRow.slug, name: backendRow.name } : null,
      nodeUuid: ref.kind === 'panel-node' ? ref.nodeUuid : null,
      countryCode: origin.relay.locationCode,
      modes: [],
      usersOnline: null,
      origin,
      status,
      dot: words?.dot ?? 'grey',
      sentence: words?.sentence ?? '',
      attention: words?.dot === 'red' || words?.dot === 'amber' || originAttention(origin, status),
      retiring: false,
      adoptable: false,
      runId: runOf(status),
    });
  }
  return rows;
}

/** Whether a row passes the filter chip and the layer filter. */
export function rowMatches(row: NodeRow, show: NodeFilter, layer: LayerFilter = 'all'): boolean {
  if (layer !== 'all' && !(row.status?.layers ?? []).includes(layer)) return false;
  switch (show) {
    case 'all':
      return true;
    case 'attention':
      return row.attention;
    case 'fronted':
      return !row.byHand && row.origin !== null;
    case 'direct':
      return !row.byHand && row.origin === null;
    case 'retiring':
      return row.retiring;
    case 'by-hand':
      return row.byHand;
    case 'dark':
      return row.status?.delivery.kind === 'dark';
    case 'quarantined':
      return (row.origin?.relay.quarantine ?? null) !== null;
    case 'unpublished':
      return (
        row.origin !== null && (row.status?.published ?? row.origin.relay.publishedCount) === 0
      );
  }
}

/** The search box: the node name, its machine name, or its origin's slug or label. */
export function searchMatches(row: NodeRow, query: string): boolean {
  if (!query.trim()) return true;
  return (
    nodeMatches(query, row.name, row.machine) ||
    nodeMatches(query, row.origin?.relay.slug ?? '', row.origin?.relay.label ?? null)
  );
}

export interface RowFilter {
  show: NodeFilter;
  layer?: LayerFilter;
  query?: string;
  /** One backend's slug; rows of no backend (added by hand) stay. */
  backend?: string | null;
}

export function filterNodeRows(rows: readonly NodeRow[], f: RowFilter): NodeRow[] {
  return rows.filter(
    (r) =>
      (!f.backend || !r.backend || r.backend.slug === f.backend) &&
      rowMatches(r, f.show, f.layer) &&
      searchMatches(r, f.query ?? ''),
  );
}

/** How many rows each filter chip would show. */
export function filterCounts(rows: readonly NodeRow[]): Record<NodeFilter, number> {
  const out = {} as Record<NodeFilter, number>;
  for (const f of [...NODE_FILTERS, ...TECH_FILTERS])
    out[f] = rows.filter((r) => rowMatches(r, f)).length;
  return out;
}

/** Where a row leads: the node's page, or the origin's own page (added by hand, or a node no tree lists). */
export function rowHref(row: NodeRow): string | null {
  if (row.kind !== 'origin' && row.nodeUuid)
    return serversPaths.node(row.nodeUuid, { backend: row.backend?.slug });
  if (row.origin) return edgesPaths.node(row.origin.relay.slug);
  return null;
}
