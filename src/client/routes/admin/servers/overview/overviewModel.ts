/**
 * The Servers Overview (`/admin/servers`) as data (pure; unit-tested in
 * overviewModel.test.ts). The page loads what the other tabs already load and
 * this module merges it, so nothing new is asked of the server:
 *
 *   mergeAttention(input)     ONE ranked Action needed list from edge attention
 *                             (the server's ranking kept), each backend's own
 *                             rows (holds, setup, key mismatches, edits made on
 *                             the backend, port changes, changes of unknown
 *                             outcome, nodes not enrolled), SNI lists that need
 *                             you, countries where a node has no working address,
 *                             and provider accounts at their cost cap.
 *   statusSentence(input)     the one status sentence and its dot.
 *   overviewTiles(input)      the four tiles: Nodes, Countries, Spend, Probes.
 *   mergeActivity(input)      one timeline from every fronted node's timeline
 *                             and every backend's recent changes, newest first.
 *   freedomSummary(preview)   what "Freedom only through edges" holds back.
 *   backendNodeCounts(tree), unadoptedCount(nodes, intents), atRiskCount(origins),
 *   oldestRead(times)         the per-source figures the page and BackendFeed feed in.
 *
 * Words follow docs/servers.md: plain, short, "fronted", "Action needed",
 * never "names" for SNIs, no dashes.
 */
import type { AttentionItem, FleetStatus, FreedomPreview } from '@shared/contracts/edges';
import { plainAuditActionLabel, type Tone } from '@client/lib/edgeCodes';
import { collapseRepeats } from '@client/lib/collapseRepeats';
import { edgesPaths } from '../../edges/lib/routes';
import { countryLabel } from '../../edges/countries/words';
import { money } from '../../edges/lib/planWords';
import type { NamesAttention } from '../../edges/names/lib/transportWords';
import { serversPaths } from '../lib/routes';
import {
  ago,
  opRepeatKey,
  opTitle,
  opWords,
  portChangeTitle,
  portChangeWords,
  type AttentionRow,
  type Dot,
  type OpLike,
  type PortChangeLike,
} from '../lib/words';

// --- Action needed ---------------------------------------------------------------------------------

export type Severity = 'critical' | 'warning' | 'info';
const RANK: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };

/** What a row is about, shown as a small chip before its sentence. */
export interface Chip {
  kind: 'backend' | 'node' | 'sni' | 'country' | 'provider';
  label: string;
}

/** The one button of a row: a link, or one of the two server calls the Overview runs itself. */
export type RowAction =
  | { kind: 'link'; label: string; href: string }
  | { kind: 'release'; label: string; slug: string; holdId: string }
  | { kind: 'seen'; label: string; slug: string; profileUuid: string };

export type OverviewRow =
  /** An edge attention item: AttentionList draws it and runs its action. */
  | { key: string; source: 'edge'; severity: Severity; item: AttentionItem }
  | {
      key: string;
      source: 'servers' | 'snis' | 'country' | 'provider';
      severity: Severity;
      chip: Chip | null;
      text: string;
      action: RowAction | null;
    };

/** A port change as the backend lists it (`PortChangeView`, the fields read here). */
export type PortChangeInput = PortChangeLike & { id: string; updatedAt: string };

/** One backend server, with what its own queries said (ServersHome reads the same ones). */
export interface BackendInput {
  slug: string;
  name: string;
  /** Changes from here are on, the backend can be written to, and it is set up. */
  canWrite: boolean;
  /** `manage.enabled`. */
  manageOn: boolean;
  /** The node role reported that it follows the ownership protocol. */
  setUp: boolean;
  /** `setupWords(setup)`: the setup row, or null when there is nothing to do. */
  setupRow: string | null;
  holds: readonly { id: string; heldNodeNames: readonly string[]; since: string }[];
  /** `needsYou(tree)`. */
  needs: readonly AttentionRow[];
  /** `namesNeedsYou(transports)`. */
  names: readonly NamesAttention[];
  portChanges: readonly PortChangeInput[];
  ops: readonly (OpLike & { id: string })[];
  /** Nodes that serve members but are not enrolled, while the backend is set up to adopt them. */
  unadopted: number;
  /** Its last panel read failed (or its tree could not be fetched): node status may be stale. */
  readFailed: boolean;
}

/** A country on the censored-country list (`countries/summary`, the fields read here). */
export interface CountryInput {
  country: string;
  totals: { originsAtRisk: number; addresses: { blocked: number }; names: { blocked: number } };
  meantFor: { locations: number; blocked: number };
}

/** A provider account (`providers`, the fields read here). */
export interface ProviderInput {
  id: string;
  name: string;
  enabled: boolean;
  cost: {
    currency: string | null;
    monthlyCap: number | null;
    spend: {
      totals: readonly { currency: string; monthly: number }[];
      unpriced: number;
      monthly: number;
      atCap: boolean;
    };
  } | null;
}

export interface AttentionInput {
  edge: readonly AttentionItem[];
  backends: readonly BackendInput[];
  countries: readonly CountryInput[];
  providers: readonly ProviderInput[];
  now: number;
}

const DAY = 24 * 3600_000;
/** A cap this close is worth a heads-up before it stops new addresses. */
export const NEAR_CAP = 0.9;

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

function backendRows(b: BackendInput, multi: boolean, now: number): OverviewRow[] {
  const chip: Chip | null = multi ? { kind: 'backend', label: b.name } : null;
  const nodesHref = serversPaths.nodes(multi ? { backend: b.slug } : {});
  const open = { kind: 'link', label: 'Open', href: nodesHref } as const;
  const out: OverviewRow[] = [];
  const row = (
    key: string,
    severity: Severity,
    text: string,
    action: RowAction | null,
    source: 'servers' | 'snis' = 'servers',
    rowChip: Chip | null = chip,
  ) => out.push({ key: `${b.slug}:${key}`, source, severity, chip: rowChip, text, action });

  if (b.readFailed)
    row(
      'read-failed',
      'critical',
      'The panel could not be read, so its node status may be out of date.',
      { ...open },
    );
  for (const h of b.holds)
    row(
      `hold:${h.id}`,
      'warning',
      `${h.heldNodeNames.join(', ')} ${h.heldNodeNames.length === 1 ? 'is' : 'are'} held closed since a profile change ${ago(now - Date.parse(h.since))}. Check ${h.heldNodeNames.length === 1 ? 'it' : 'them'} yourself, then release the hold.`,
      b.canWrite ? { kind: 'release', label: 'Release', slug: b.slug, holdId: h.id } : { ...open },
    );
  if (b.manageOn && b.setupRow) row('setup', 'warning', b.setupRow, { ...open, label: 'Set up' });
  else if (b.manageOn && !b.setUp)
    row(
      'not-set-up',
      'warning',
      'Changes are on but refused until this backend is set up. Set it up first.',
      { ...open, label: 'Set up' },
    );
  for (const n of b.needs) {
    if (n.key.startsWith('edit:'))
      row(
        n.key,
        'warning',
        n.text,
        b.canWrite
          ? { kind: 'seen', label: 'Seen it', slug: b.slug, profileUuid: n.key.slice(5) }
          : { ...open },
      );
    else
      row(
        n.key,
        n.key.startsWith('key:') ? 'critical' : 'warning',
        n.text,
        n.nodeUuid
          ? {
              kind: 'link',
              label: 'Open node',
              href: serversPaths.node(n.nodeUuid, { backend: b.slug }),
            }
          : { ...open },
      );
  }
  for (const op of b.ops)
    if (op.state === 'outcome_unknown')
      row(`op:${op.id}`, 'critical', `${opTitle(op)}: ${opWords(op).sentence}`, {
        ...open,
        label: 'Settle it',
      });
  for (const c of b.portChanges) {
    const forYou = c.nodes.filter((n) => n.state === 'waiting' && n.confirmedBy === 'operator');
    if (c.state === 'waiting' && forYou.length > 0)
      row(
        `port:${c.id}`,
        'warning',
        `${portChangeTitle(c)}: open the port on ${plural(forYou.length, 'node')} no role reports for, then confirm it.`,
        { ...open },
      );
    else if (
      (c.state === 'recovered' || c.state === 'refused') &&
      now - Date.parse(c.updatedAt) < DAY
    )
      row(
        `port:${c.id}`,
        c.state === 'recovered' ? 'warning' : 'info',
        `${portChangeTitle(c)}. ${portChangeWords(c).sentence}`,
        { ...open },
      );
  }
  if (b.unadopted > 0)
    row(
      'unadopted',
      'info',
      `${plural(b.unadopted, 'node serves', 'nodes serve')} members without being enrolled. Adopt ${b.unadopted === 1 ? 'it' : 'them'} so FCP can look after ${b.unadopted === 1 ? 'it' : 'them'}.`,
      { ...open },
    );
  for (const n of b.names) {
    const action: RowAction | null = n.nodeUuid
      ? {
          kind: 'link',
          label: 'Open node',
          href: serversPaths.node(n.nodeUuid, { backend: b.slug }),
        }
      : n.family
        ? { kind: 'link', label: 'Open the SNI list', href: edgesPaths.family(n.family) }
        : null;
    row(
      n.key,
      n.key.startsWith('names-failing:') || n.key.startsWith('names-blocked:') ? 'warning' : 'info',
      n.text,
      action,
      'snis',
      { kind: 'sni', label: 'SNIs' },
    );
  }
  return out;
}

function countryRows(countries: readonly CountryInput[]): OverviewRow[] {
  const out: OverviewRow[] = [];
  for (const c of countries) {
    const chip: Chip = { kind: 'country', label: countryLabel(c.country) };
    const action: RowAction = {
      kind: 'link',
      label: 'Open country',
      href: edgesPaths.country(c.country),
    };
    const atRisk = c.totals.originsAtRisk;
    if (atRisk > 0)
      out.push({
        key: `country:${c.country}:at-risk`,
        source: 'country',
        severity: 'critical',
        chip,
        text:
          atRisk === 1
            ? 'One node has no working address there.'
            : `${atRisk} nodes have no working address there.`,
        action,
      });
    else if (c.meantFor.blocked > 0)
      out.push({
        key: `country:${c.country}:location`,
        source: 'country',
        severity: 'warning',
        chip,
        text:
          c.meantFor.blocked === 1
            ? 'A location set for it is blocked there.'
            : `${c.meantFor.blocked} locations set for it are blocked there.`,
        action,
      });
  }
  return out;
}

function providerRows(providers: readonly ProviderInput[]): OverviewRow[] {
  const out: OverviewRow[] = [];
  for (const p of providers) {
    const c = p.cost;
    if (!p.enabled || !c || c.monthlyCap === null || c.monthlyCap <= 0 || !c.currency) continue;
    const chip: Chip = { kind: 'provider', label: p.name };
    const action: RowAction = {
      kind: 'link',
      label: 'Open account',
      href: edgesPaths.provider(p.id),
    };
    const of = `about ${money(c.spend.monthly, c.currency)} a month of its ${money(c.monthlyCap, c.currency)} cap`;
    if (c.spend.atCap)
      out.push({
        key: `provider:${p.id}:cap`,
        source: 'provider',
        severity: 'warning',
        chip,
        text: `At its cost cap (${of}). It makes no new address until the cap is raised.`,
        action,
      });
    else if (c.spend.monthly >= c.monthlyCap * NEAR_CAP)
      out.push({
        key: `provider:${p.id}:near-cap`,
        source: 'provider',
        severity: 'info',
        chip,
        text: `Close to its cost cap: ${of}.`,
        action,
      });
  }
  return out;
}

/**
 * Every source in one list, most urgent first. The server's ranking of edge
 * attention is kept: rows of one severity stay in source order (edge
 * attention, backends, countries, providers), so a sort never reorders them.
 */
export function mergeAttention(input: AttentionInput): OverviewRow[] {
  const multi = input.backends.length > 1;
  const all: OverviewRow[] = [
    ...input.edge.map((item): OverviewRow => ({
      key: `edge:${item.id}`,
      source: 'edge',
      severity: item.severity,
      item,
    })),
    ...input.backends.flatMap((b) => backendRows(b, multi, input.now)),
    ...countryRows(input.countries),
    ...providerRows(input.providers),
  ];
  return all
    .map((row, i) => ({ row, i }))
    .sort((a, b) => RANK[a.row.severity] - RANK[b.row.severity] || a.i - b.i)
    .map(({ row }) => row);
}

// --- status sentence --------------------------------------------------------------------------------

// --- per-source helpers (BackendFeed and the page) -------------------------------------------------

/**
 * Nodes switched on, and how many are online, from one backend's tree. Null
 * when the tree is not read yet or its last panel read failed: cached
 * `online` flags are not current then, so they are never counted.
 */
export function backendNodeCounts(
  tree: {
    state: { ok: boolean | null };
    nodes: readonly { online: boolean; isDisabled: boolean }[];
  } | null,
): { online: number; total: number } | null {
  if (!tree || tree.state.ok === false) return null;
  const on = tree.nodes.filter((n) => !n.isDisabled);
  return { online: on.filter((n) => n.online).length, total: on.length };
}

/** Nodes switched on that serve members without being enrolled (no intent by uuid or name). */
export function unadoptedCount(
  nodes: readonly { nodeUuid: string; name: string; isDisabled: boolean }[],
  intents: readonly { nodeUuid: string | null; name: string }[],
): number {
  return nodes.filter(
    (n) => !n.isDisabled && !intents.some((i) => i.nodeUuid === n.nodeUuid || i.name === n.name),
  ).length;
}

/**
 * Fronted nodes: origins with an address in use, whatever their warnings (a
 * warning is "at risk" or Action needed, never "not fronted"). An origin being
 * removed, switched off or with nothing in use is not counted.
 */
export function frontedCount(
  origins: readonly { status: { kind: string; published: number } }[],
): number {
  return origins.filter(
    (o) =>
      o.status.published > 0 &&
      o.status.kind !== 'removing' &&
      o.status.kind !== 'off' &&
      o.status.kind !== 'unprotected',
  ).length;
}

/** Fronted nodes with no working address: a fronted origin whose status dot is red. */
export function atRiskCount(
  origins: readonly { status: { fronted: boolean; dot: string } }[],
): number {
  return origins.filter((o) => o.status.fronted && o.status.dot === 'red').length;
}

/**
 * When the oldest data shown was read (ms), from every source that has data;
 * 0 while none has. "Updated N s ago" uses it, so it never claims fresher data.
 */
export function oldestRead(times: readonly number[]): number {
  const read = times.filter((t) => t > 0);
  return read.length > 0 ? Math.min(...read) : 0;
}

export interface StatusInput {
  /** Nodes switched on across every backend, and how many are online; null before any backend answered. */
  nodes: { online: number; total: number } | null;
  /** The edge fleet status (the attention response), null before it answered. */
  fleet: Pick<FleetStatus, 'protected' | 'total'> | null;
  rows: readonly Pick<OverviewRow, 'severity'>[];
  /** A source of Action needed could not be read: the dot is never green then. */
  incomplete?: boolean;
  /** A backend's panel read failed, so its nodes are not counted. */
  nodesUnread?: boolean;
}

/** "6 nodes online, 4 fronted. 2 things need you." and its dot. */
export function statusSentence(s: StatusInput): { dot: Dot; text: string } {
  const parts: string[] = [];
  // A loaded empty fleet is "0 fronted", not "not known".
  const fronted = s.fleet ? s.fleet.protected : null;
  if (s.nodes && s.nodes.total > 0) {
    const n = s.nodes;
    const online =
      n.online === n.total
        ? `${plural(n.total, 'node')} online`
        : `${n.online} of ${plural(n.total, 'node')} online`;
    parts.push(fronted !== null ? `${online}, ${fronted} fronted.` : `${online}.`);
  } else if (s.fleet && s.fleet.total > 0) {
    parts.push(`${plural(s.fleet.protected, 'node')} fronted.`);
  } else if (s.nodesUnread) {
    parts.push('Node status could not be read.');
  } else {
    parts.push('No nodes yet.');
  }
  const count = s.rows.length;
  parts.push(
    count === 0 ? 'Nothing needs you.' : `${plural(count, 'thing needs', 'things need')} you.`,
  );
  const empty = !(s.nodes && s.nodes.total > 0) && !(s.fleet && s.fleet.total > 0);
  let dot: Dot = 'green';
  if (
    s.rows.some((r) => r.severity === 'critical') ||
    (s.nodes && s.nodes.total > 0 && s.nodes.online === 0)
  )
    dot = 'red';
  else if (count > 0 || s.incomplete || (s.nodes && s.nodes.online < s.nodes.total)) dot = 'amber';
  else if (empty) dot = 'grey';
  return { dot, text: parts.join(' ') };
}

// --- tiles ------------------------------------------------------------------------------------------

export interface Tile {
  id: 'nodes' | 'countries' | 'spend' | 'probes';
  label: string;
  value: string;
  hint: string;
  tone: Tone;
  href: string;
}

export interface TilesInput {
  nodes: { online: number; total: number } | null;
  fleet: Pick<FleetStatus, 'protected' | 'total'> | null;
  /** Fronted nodes whose status dot is red (no working address). */
  atRisk: number | null;
  countries: readonly CountryInput[] | null;
  providers: readonly ProviderInput[] | null;
  probe: { usedLastHour: number | null; hourlyBudget: number | null; enabled: boolean | null };
}

const q = (n: number | null | undefined) => (n === null || n === undefined ? '?' : String(n));

/** Amounts per currency, never added across currencies. */
function sumByCurrency(pairs: Iterable<[string, number]>): Map<string, number> {
  const out = new Map<string, number>();
  for (const [cur, n] of pairs) out.set(cur, (out.get(cur) ?? 0) + n);
  return out;
}

function spendTile(providers: readonly ProviderInput[] | null): Omit<Tile, 'id' | 'href'> {
  const label = 'Spend a month';
  if (!providers)
    return { label, value: '?', hint: 'Estimated from live addresses.', tone: 'muted' };
  // A switched-off account still pays for its live addresses, so its spend
  // counts; only switched-on accounts' caps do, as only they make new ones.
  const priced = providers.filter((p) => p.cost);
  const enabled = priced.filter((p) => p.enabled);
  const spend = sumByCurrency(
    priced.flatMap((p) =>
      p.cost!.spend.totals.map((t): [string, number] => [t.currency, t.monthly]),
    ),
  );
  const caps = sumByCurrency(
    enabled
      .filter((p) => p.cost!.monthlyCap !== null && p.cost!.currency)
      .map((p): [string, number] => [p.cost!.currency!, p.cost!.monthlyCap!]),
  );
  const unpriced = priced.reduce((a, p) => a + p.cost!.spend.unpriced, 0);
  const atCap = enabled.some((p) => p.cost!.spend.atCap);
  const currencies = [...new Set([...spend.keys(), ...caps.keys()])].sort();
  if (currencies.length === 0)
    return {
      label,
      value: unpriced > 0 ? 'Not known' : 'None',
      hint:
        unpriced > 0
          ? `${plural(unpriced, 'address', 'addresses')} without a known price.`
          : 'No live address costs anything now.',
      tone: 'muted',
    };
  const value = currencies
    .map((cur) => {
      const s = money(spend.get(cur) ?? 0, cur);
      const cap = caps.get(cur);
      return cap !== undefined ? `${s} / ${money(cap, cur)}` : s;
    })
    .join(' + ');
  const capWords =
    caps.size > 0
      ? 'Estimated from live addresses, against the caps.'
      : 'Estimated from live addresses. No cap is set.';
  return {
    label,
    value,
    hint:
      unpriced > 0
        ? `${capWords} ${plural(unpriced, 'address', 'addresses')} without a price.`
        : capWords,
    tone: atCap ? 'warning' : 'neutral',
  };
}

function probeTile(p: TilesInput['probe']): Omit<Tile, 'id' | 'href'> {
  const label = 'Probe budget';
  if (p.enabled === false)
    return { label, value: 'Off', hint: 'Probes are switched off in the settings.', tone: 'muted' };
  if (p.hourlyBudget === null)
    return { label, value: '?', hint: 'Probe runs in the last hour.', tone: 'muted' };
  if (p.hourlyBudget <= 0)
    return {
      label,
      value: 'None',
      hint: 'The hourly budget allows no probe runs.',
      tone: 'warning',
    };
  if (p.usedLastHour === null)
    return {
      label,
      value: `of ${p.hourlyBudget}`,
      hint: 'Probe runs in the last hour.',
      tone: 'muted',
    };
  const ratio = p.usedLastHour / p.hourlyBudget;
  return {
    label,
    value: `${Math.round(ratio * 100)}%`,
    hint: `${p.usedLastHour} of ${p.hourlyBudget} probe runs used in the last hour.`,
    tone: ratio >= 1 ? 'danger' : ratio >= 0.8 ? 'warning' : 'neutral',
  };
}

/** The four tiles. A figure not loaded yet reads "?". */
export function overviewTiles(t: TilesInput): Tile[] {
  const fronted = t.fleet ? t.fleet.protected : null;
  const blocked = t.countries
    ? t.countries.filter(
        (c) =>
          c.totals.originsAtRisk > 0 ||
          c.totals.addresses.blocked > 0 ||
          c.totals.names.blocked > 0,
      ).length
    : null;
  return [
    {
      id: 'nodes',
      label: 'Nodes',
      value: `${q(t.nodes?.online)} · ${q(fronted)} · ${q(t.atRisk)}`,
      hint: 'Online · fronted · at risk',
      tone: (t.atRisk ?? 0) > 0 ? 'danger' : 'neutral',
      href: serversPaths.nodes(),
    },
    {
      id: 'countries',
      label: 'Countries',
      value: t.countries ? `${blocked} of ${t.countries.length}` : '?',
      hint: 'With a block now',
      tone: (blocked ?? 0) > 0 ? 'warning' : 'neutral',
      href: edgesPaths.countries(),
    },
    { id: 'spend', ...spendTile(t.providers), href: edgesPaths.providers() },
    { id: 'probes', ...probeTile(t.probe), href: edgesPaths.probes() },
  ];
}

// --- recent activity --------------------------------------------------------------------------------

/** An audit row of a fronted node's timeline (`TimelineResponse.entries`, the fields read here). */
export interface TimelineEntryInput {
  id: string;
  action: string;
  payload: unknown;
  createdAt: string;
  subject?: string;
}

export interface ActivityInput {
  timelines: readonly {
    slug: string;
    /** The node's name as the Overview shows it. */
    name: string;
    href: string;
    entries: readonly TimelineEntryInput[];
  }[];
  backends: readonly {
    slug: string;
    name: string;
    ops: readonly (OpLike & {
      id: string;
      open: boolean;
      createdAt: string;
      settledAt: string | null;
    })[];
  }[];
  max?: number;
}

export interface ActivityEntry {
  key: string;
  /** ISO time. */
  at: string;
  /** Whose activity it is: a node, or a backend for its changes. */
  who: string;
  text: string;
  href: string | null;
  dot: Dot | null;
}

/**
 * Check results (outside probes, results from countries) are left out: they
 * come every few minutes and have their own pages (Probes, Countries).
 */
const QUIET_ACTION = /^(probe\.|edge\.country\.)/;

/** One timeline, newest first: runs and replacements from the nodes, changes from the backends. */
export function mergeActivity(input: ActivityInput): ActivityEntry[] {
  const out: ActivityEntry[] = [];
  for (const t of input.timelines)
    for (const e of t.entries) {
      if (e.subject === 'probe' || QUIET_ACTION.test(e.action)) continue;
      out.push({
        key: `t:${t.slug}:${e.id}`,
        at: e.createdAt,
        who: t.name,
        text: plainAuditActionLabel(e.action, e.payload),
        href: t.href,
        dot: null,
      });
    }
  const multi = input.backends.length > 1;
  for (const b of input.backends)
    for (const g of collapseRepeats(b.ops, opRepeatKey)) {
      const op = g.item;
      const w = opWords(op);
      out.push({
        key: `o:${b.slug}:${op.id}`,
        at: op.settledAt ?? op.createdAt,
        who: multi ? b.name : 'Backend',
        text: `${opTitle(op)}${g.count > 1 ? ` (${g.count} times)` : ''}. ${w.sentence}`,
        href: serversPaths.nodes(multi ? { backend: b.slug } : {}),
        dot: w.dot,
      });
    }
  out.sort((a, b) => Date.parse(b.at) - Date.parse(a.at) || a.key.localeCompare(b.key));
  return out.slice(0, input.max ?? 10);
}

// --- Freedom delivery -------------------------------------------------------------------------------

/** What "Freedom only through edges" holds back, in one or two sentences (the confirm dialog). */
export function freedomSummary(p: Pick<FreedomPreview, 'on' | 'approximate' | 'totals'>): string {
  const { withheldNodes, affectedMembers, cutOffMembers } = p.totals;
  if (withheldNodes === 0) return 'Every node of a freedom mode is fronted.';
  const nodes = `${plural(withheldNodes, 'node')} ${p.on ? (withheldNodes === 1 ? 'is' : 'are') : 'would be'} held back from freedom members.`;
  if (affectedMembers === 0) return `${nodes} No member is on them now.`;
  const moved = affectedMembers - cutOffMembers;
  const parts = [
    ...(moved > 0
      ? [`${plural(moved, 'member moves', 'members move')} to a fronted node at their next refresh`]
      : []),
    ...(cutOffMembers > 0
      ? [
          `${plural(cutOffMembers, 'member gets', 'members get')} nothing until their node is fronted`,
        ]
      : []),
  ];
  return `${nodes} ${parts.join(', and ')}.${p.approximate ? ' At least, as the count stopped early.' : ''}`;
}
