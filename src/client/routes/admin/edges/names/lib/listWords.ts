/**
 * One name list as one list (docs/edges.md "The page"; pure, unit-tested):
 * its names and the names found for it, each with ONE state on the way to
 * members and one sentence, so "ready" never means two things. The states
 * come from the server (`delivery` per name, `usableCandidate` per find):
 *
 *   Suggested -> Being checked -> Waiting to be sent -> Waiting for a test
 *   -> In use. Off the way: Failing, Retired, Burned, Ignored, Not usable.
 *
 * Three filters: what needs you, what is in use, everything.
 */
import {
  usableCandidate,
  type SniCandidateRow,
  type SniFamilySummary,
  type SniNameRow,
} from '../../../../../../shared/contracts/sni';
import { suggestionReason } from './transportWords';
import { CHECK_WORDS, vantageWantsLook, type Dot } from './words';

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export type ListRowState =
  | 'suggested'
  | 'checking'
  | 'to_send'
  | 'idle'
  | 'waiting_test'
  | 'in_use'
  | 'failing'
  | 'retired'
  | 'burned'
  | 'ignored'
  | 'not_usable';

export interface ListRow {
  key: string;
  name: string;
  state: ListRowState;
  dot: Dot;
  /** The state and why, in one sentence. */
  sentence: string;
  /** A report or a check from inside a country singles it out: worth a look. */
  flagged: boolean;
  /** On how many nodes members are handed it (names only). */
  inUseOn: number;
  /** The list's own name, or a name found for it. */
  row: { kind: 'name'; name: SniNameRow } | { kind: 'found'; found: SniCandidateRow };
}

/** The order of the list: what needs a decision first, then what is on its way, then the rest. */
const ORDER: ListRowState[] = [
  'suggested',
  'waiting_test',
  'to_send',
  'failing',
  'checking',
  'in_use',
  'idle',
  'not_usable',
  'ignored',
  'retired',
  'burned',
];

export const STATE_LABEL: Record<ListRowState, string> = {
  suggested: 'Suggested',
  checking: 'Being checked',
  to_send: 'Waiting to be sent',
  idle: 'Checked',
  waiting_test: 'Waiting for a test',
  in_use: 'In use',
  failing: 'Failing',
  retired: 'Retired',
  burned: 'Burned',
  ignored: 'Ignored',
  not_usable: 'Not usable',
};

function nameRow(n: SniNameRow, bound: boolean): ListRow {
  const d = n.delivery;
  // Who gets it: on one node, simply members; on several, on how many.
  const members =
    d.nodes > 1
      ? d.inUseOn === d.nodes
        ? `Members get it on all ${d.nodes} nodes.`
        : `Members get it on ${d.inUseOn} of ${d.nodes} nodes.`
      : 'Members get it.';
  const reason = (n.code && CHECK_WORDS[n.code]) || null;
  const base = { key: `name:${n.name}`, name: n.name, inUseOn: d.inUseOn, flagged: false };
  const row = { kind: 'name' as const, name: n };
  const flagged = n.suspectIn.length > 0 || vantageWantsLook(n);
  if (n.status === 'burned')
    return {
      ...base,
      row,
      state: 'burned',
      dot: 'red',
      sentence: 'Burned: never used again, in this list or any other.',
    };
  if (n.status === 'retired')
    return {
      ...base,
      row,
      state: 'retired',
      dot: 'grey',
      sentence: 'Retired: no longer given out.',
    };
  const make = (state: ListRowState, dot: Dot, sentence: string): ListRow => ({
    ...base,
    row,
    flagged,
    state,
    dot,
    sentence,
  });
  switch (d.state) {
    case 'failing':
      return make(
        'failing',
        'red',
        n.status === 'suspended'
          ? `Suspended: the cover site kept failing it.${reason ? ` ${reason}` : ''}`
          : (reason ?? 'Its last check against the cover site failed.'),
      );
    case 'checking':
      return make('checking', 'grey', 'Being checked against the cover site.');
    case 'to_send':
      return make('to_send', 'amber', 'Checked. Waiting to be sent to the node.');
    case 'idle':
      return make(
        'idle',
        'grey',
        bound
          ? 'Checked. It goes to the node with the next send.'
          : 'Checked. Not used by any port yet.',
      );
    case 'waiting_test':
      return make(
        'waiting_test',
        'amber',
        `On the node, waiting for a test.${d.inUseOn > 0 ? ` ${members}` : ''}`,
      );
    case 'in_use':
      return make('in_use', 'green', members);
    case 'off':
      return make('retired', 'grey', 'Not given out.');
  }
}

function foundRow(c: SniCandidateRow): ListRow | null {
  // A found name the list holds now is its own row already.
  if (c.state === 'added') return null;
  const base = { key: `found:${c.id}`, name: c.name, inUseOn: 0, flagged: false };
  const row = { kind: 'found' as const, found: c };
  if (c.state === 'ignored')
    return {
      ...base,
      row,
      state: 'ignored',
      dot: 'grey',
      sentence: 'Ignored. Not suggested again.',
    };
  if (usableCandidate(c))
    return { ...base, row, state: 'suggested', dot: 'grey', sentence: suggestionReason(c) };
  if (c.state === 'new' && !c.check)
    return {
      ...base,
      row,
      state: 'checking',
      dot: 'grey',
      sentence: 'Found. Being checked against the cover site.',
    };
  const why =
    c.state === 'gone'
      ? 'It moved off the list’s network.'
      : ((c.check?.code && CHECK_WORDS[c.check.code]) ?? 'The cover site does not serve it.');
  return { ...base, row, state: 'not_usable', dot: 'grey', sentence: `Not usable. ${why}` };
}

/** The list's names and its finds as one list, in the order above (names by their order, finds best first). */
export function listRows(
  names: readonly SniNameRow[],
  found: readonly SniCandidateRow[],
  bound: boolean,
): ListRow[] {
  const held = new Set(names.map((n) => n.name));
  const rows = [
    ...names.map((n) => nameRow(n, bound)),
    ...found
      .filter((c) => !held.has(c.name))
      .map(foundRow)
      .filter((r): r is ListRow => r !== null),
  ];
  // Stable: within a state, names keep their order and finds the server's (best first).
  return rows
    .map((r, i) => ({ r, i }))
    .sort((a, b) => ORDER.indexOf(a.r.state) - ORDER.indexOf(b.r.state) || a.i - b.i)
    .map(({ r }) => r);
}

export const LIST_FILTERS = ['needs_you', 'in_use', 'all'] as const;
export type ListFilter = (typeof LIST_FILTERS)[number];
export const LIST_FILTER_LABEL: Record<ListFilter, string> = {
  needs_you: 'Needs you',
  in_use: 'In use',
  all: 'All',
};

export function matchesListFilter(r: ListRow, f: ListFilter): boolean {
  if (f === 'all') return true;
  if (f === 'in_use') return r.inUseOn > 0;
  return (
    r.flagged ||
    r.state === 'suggested' ||
    r.state === 'waiting_test' ||
    r.state === 'to_send' ||
    r.state === 'failing'
  );
}

// --- the Server names page --------------------------------------------------------------------

/** One line under a name list: what members get and what waits, the same counts as its page. */
export function listLine(f: SniFamilySummary): string {
  const d = f.delivery;
  const parts: string[] = [];
  if (d.inUse) parts.push(`${plural(d.inUse, 'name')} in use`);
  if (d.waitingTest) parts.push(`${d.waitingTest} waiting for a test`);
  if (d.toSend) parts.push(`${d.toSend} to send`);
  if (d.checking) parts.push(`${d.checking} being checked`);
  if (d.idle) parts.push(`${d.idle} checked`);
  if (d.failing) parts.push(`${d.failing} failing`);
  if (f.suggestions) parts.push(plural(f.suggestions, 'suggestion'));
  if (parts.length === 0)
    parts.push(d.off > 0 ? `No name in use (${d.off} retired or burned)` : 'No names yet');
  parts.push(f.bindings === 0 ? 'not used by any port' : `used by ${plural(f.bindings, 'port')}`);
  return parts.join(' · ');
}

export function listDot(f: SniFamilySummary): Dot {
  const d = f.delivery;
  if (!f.enabled) return 'grey';
  if (d.failing > 0 || d.waitingTest + d.toSend > 0) return 'amber';
  return d.inUse > 0 ? 'green' : 'grey';
}

/** Under the Server names switch: what is true now. */
export function namesSwitchLine(on: boolean): string {
  return on
    ? 'On. FCP checks the names of every name list and can send them to nodes.'
    : 'Off. Nothing is checked or sent. Members keep the names they have.';
}

/** Under a list's "Use this list" switch: what is true now. */
export function listSwitchLine(on: boolean): string {
  return on
    ? 'On. Its names are checked and can be sent to the node.'
    : 'Off. Nothing new is checked or sent. Members keep the names they have.';
}

/** What an action on picked names did (`POST sni/families/{slug}/names/{action}`). */
export function nameActionWords(
  action: 'retire' | 'reactivate' | 'burn' | 'recheck',
  r: {
    count: number;
    relays?: { listeners: number; retired: number; skipped: number; kept: number } | null;
  },
): string {
  const done = {
    retire: 'retired',
    reactivate: 'brought back',
    burn: 'burned',
    recheck: 'checked again soon',
  }[action];
  const parts = [`${plural(r.count, 'name')} ${done}.`];
  const relays = r.relays;
  if (relays?.kept)
    parts.push(
      `${plural(relays.kept, 'node')} ${relays.kept === 1 ? 'keeps' : 'keep'} handing out its last name.`,
    );
  // A node a send, a replacement or a removal is still changing is left alone:
  // it hands the names out until the action is made again.
  if (relays?.skipped)
    parts.push(
      `${plural(relays.skipped, 'node')} ${relays.skipped === 1 ? 'was' : 'were'} busy and still ${relays.skipped === 1 ? 'hands' : 'hand'} ${r.count === 1 ? 'it' : 'them'} out: ${action === 'burn' ? 'burn' : 'retire'} ${r.count === 1 ? 'it' : 'them'} again in a few minutes.`,
    );
  return parts.join(' ');
}
