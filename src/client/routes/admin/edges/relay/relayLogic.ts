/**
 * Pure display logic of the per-relay page (no Svelte, unit-tested in
 * relayLogic.test.ts).
 *
 * Exports:
 *   deriveDelivery(input)            edge-required delivery state of one relay, in words
 *   suspicionChip(suspicion)         the detector chip of the header (null = nothing to say)
 *   tupleLine / tuplesEqual          Host tuples of the quarantine resolver
 *   highlightedColumn(match)         which recorded binding the live Host matches
 *   MATCH_WORDS                      the match verdict in words
 *   recommendKeep(listeners)         the binding every inspected listener agrees on, or null
 *   justificationText(input)         the generated (editable) resolve reason, capped at 200 chars
 *   edgeAddress(edge)                the one address an edge is known by
 *   operatorFactsRows(edge)          "what FCP saw" for a needs-operator edge
 *   rotationDurationMs(rotation, now)
 *   relayProbeTargetKeys(relayId, edges)       the probe targets that belong to this relay
 *   originKindWords / hostModeWords / matchRuleWords / originTransportWords
 */
import type { z } from 'zod';
import type {
  AttentionItem,
  EdgeAdmin,
  EdgeRotationAdmin,
  HostMode,
  HostTuple,
  ListenerMatchRule,
  ListenerOriginTransport,
  QuarantineView,
  RelayAdmin,
  RelaySuspicion,
  SetupStatusResponse,
} from '@shared/contracts/edges';
import { codeExplain, codeFix, codeLabel, humanizeCode, type Tone } from '@client/lib/edgeCodes';
import type { KeyValueRow } from '../lib/types';

// --- delivery --------------------------------------------------------------------------------

export type DeliveryKind = 'manual' | 'serving' | 'degraded' | 'dark';
export interface DeliveryState {
  kind: DeliveryKind;
  tone: Tone;
  headline: string;
  /** What members on this origin get right now. */
  detail: string;
  /** The code behind the state (already worded in `reason` / `fix`). */
  code: string | null;
  reason: string | null;
  fix: string | null;
}

export interface DeliveryInput {
  relay: Pick<RelayAdmin, 'id' | 'origin' | 'enabled' | 'publishedCount'>;
  setup?: Pick<SetupStatusResponse, 'steps'> | null;
  attention?: AttentionItem[] | null;
}

const dark = (code: string): DeliveryState => ({
  kind: 'dark',
  tone: 'danger',
  headline: 'Members are dark',
  detail:
    'Subscriptions on this origin are answered "temporarily unavailable" instead of the direct address. Clients keep their last configuration until something can be served.',
  code,
  reason: `${codeLabel(code)}. ${codeExplain(code)}`.trim(),
  fix: codeFix(code) ?? null,
});

export function deriveDelivery(input: DeliveryInput): DeliveryState {
  const { relay } = input;
  if (relay.origin.kind === 'manual') {
    return {
      kind: 'manual',
      tone: 'muted',
      headline: 'Nothing to deliver',
      detail:
        'A manual origin has no subscriptions that FCP serves. Wire clients from the connection plan on this page.',
      code: null,
      reason: null,
      fix: null,
    };
  }
  const item = input.attention?.find((a) => a.kind === 'members_dark' && a.relayId === relay.id);
  if (item) return dark(item.code ?? 'empty_pool');
  if (relay.publishedCount === 0) return dark('empty_pool');
  if (!relay.enabled) return dark('relay_disabled');
  const rendering = input.setup?.steps.find((s) => s.id === 'rendering');
  if (rendering) {
    if (rendering.facts.renderEnabled === false) return dark('render_disabled');
    const soft = rendering.blockers.find((b) =>
      ['preview_not_applied', 'entry_mismatch', 'mirrors_unvalidated'].includes(b.code),
    );
    if (soft) {
      // `preview_not_applied` carries the delivery reason of the sample render as its detail.
      const code = soft.code === 'preview_not_applied' && soft.detail ? soft.detail : soft.code;
      return {
        kind: 'degraded',
        tone: 'warning',
        headline: 'Serving, with a problem',
        detail:
          'Edges are published, but a sample subscription did not render cleanly. Members whose subscription hits the same problem are answered "temporarily unavailable".',
        code,
        reason: `${codeLabel(code)}. ${codeExplain(code)}`.trim(),
        fix: codeFix(code) ?? null,
      };
    }
  }
  return {
    kind: 'serving',
    tone: 'success',
    headline: 'Serving through edges',
    detail:
      'Members on this origin receive edge addresses only. The origin address is never handed out.',
    code: null,
    reason: null,
    fix: null,
  };
}

// --- detector --------------------------------------------------------------------------------

type Suspicion = z.infer<typeof RelaySuspicion>;
export interface SuspicionChip {
  label: string;
  tone: Tone;
  title: string;
}
const HINT_WORDS: Record<Suspicion['hintLevel'], string> = {
  none: 'no evidence yet',
  reports: 'member reports',
  probes: 'probes',
  corroborated: 'member reports and probes',
};
export const hintLevelWords = (level: Suspicion['hintLevel']): string => HINT_WORDS[level];

export function suspicionChip(s: Suspicion | null | undefined): SuspicionChip | null {
  if (!s) return null;
  if (s.state === 'suspected') {
    const where =
      s.scope === 'regional' && s.countries.length > 0
        ? ` in ${s.countries.map((c) => c.code).join(', ')}`
        : '';
    if (s.veto) {
      return {
        label: `Block suspected, held: ${codeLabel(s.veto)}`,
        tone: 'warning',
        title: `${codeExplain(s.veto)} Evidence: ${HINT_WORDS[s.hintLevel]}${where}.`,
      };
    }
    return {
      label: `Block suspected${where}`,
      tone: 'danger',
      title: `Evidence: ${HINT_WORDS[s.hintLevel]}.`,
    };
  }
  if (s.veto) {
    return { label: codeLabel(s.veto), tone: 'muted', title: codeExplain(s.veto) };
  }
  return null;
}

// --- quarantine resolver ---------------------------------------------------------------------

type Tuple = HostTuple;
export type QuarantineListener = QuarantineView['listeners'][number];
export type QuarantineMatch = QuarantineListener['match'];

export function tupleLine(t: Tuple | null | undefined): string {
  if (!t) return '';
  return `${t.address}:${t.port}`;
}
export function tuplesEqual(a: Tuple | null | undefined, b: Tuple | null | undefined): boolean {
  if (!a || !b) return false;
  return a.address === b.address && a.port === b.port && a.sni === b.sni && a.host === b.host;
}
export function highlightedColumn(match: QuarantineMatch): 'previous' | 'current' | null {
  return match === 'previous' || match === 'current' ? match : null;
}
export const MATCH_WORDS: Record<QuarantineMatch, string> = {
  previous: 'The panel serves the previous binding',
  current: 'The panel serves the current binding',
  neither: 'The panel serves something else',
  absent: 'The panel has no Host for this listener',
  unknown: 'Not inspected yet',
};
export function matchTone(match: QuarantineMatch): Tone {
  if (match === 'previous' || match === 'current') return 'success';
  if (match === 'unknown') return 'muted';
  return 'danger';
}

/** The binding every inspected listener agrees on; null when mixed, unknown or nothing matches. */
export function recommendKeep(listeners: QuarantineListener[]): 'previous' | 'current' | null {
  if (listeners.length === 0) return null;
  const first = highlightedColumn(listeners[0]!.match);
  if (!first) return null;
  return listeners.every((l) => l.match === first) ? first : null;
}

export const REASON_MAX = 200;
export function justificationText(input: {
  keep: 'previous' | 'current';
  listeners: QuarantineListener[];
  inspectedAt: string | null;
}): string {
  const { keep, listeners, inspectedAt } = input;
  const agree = listeners.filter((l) => l.match === keep).map((l) => l.listenerKey);
  const differ = listeners
    .filter((l) => l.match !== keep && l.match !== 'unknown')
    .map((l) => l.listenerKey);
  let text: string;
  if (!inspectedAt) {
    text = `Keep ${keep} binding. The panel was not inspected before this decision.`;
  } else if (agree.length > 0 && differ.length === 0) {
    text = `Keep ${keep} binding. The panel serves it for ${agree.join(', ')} (inspected ${inspectedAt.slice(0, 16)}Z).`;
  } else if (agree.length > 0) {
    text = `Keep ${keep} binding. The panel serves it for ${agree.join(', ')}, not for ${differ.join(', ')} (inspected ${inspectedAt.slice(0, 16)}Z).`;
  } else {
    text = `Keep ${keep} binding by operator decision. The panel does not serve it for any listener (inspected ${inspectedAt.slice(0, 16)}Z).`;
  }
  return text.length <= REASON_MAX ? text : `${text.slice(0, REASON_MAX - 1).trimEnd()}.`;
}

// --- edges / rotations ---------------------------------------------------------------------------

export function edgeAddress(edge: Pick<EdgeAdmin, 'addresses'>): string {
  const a = edge.addresses;
  return a.hostname ?? a.v4 ?? a.v6 ?? '';
}

const DELETE_STATE_WORDS: Record<EdgeAdmin['resources'][number]['deleteState'], string> = {
  present: 'still there',
  delete_requested: 'delete requested, not confirmed',
  confirmed_gone: 'confirmed gone',
};

/** "What FCP saw" before it parked an edge for the operator. */
export function operatorFactsRows(edge: EdgeAdmin): KeyValueRow[] {
  const rows: KeyValueRow[] = [];
  if (edge.failure) {
    rows.push({ label: 'Stopped at step', value: humanizeCode(edge.failure.step) });
    if (edge.failure.code) rows.push({ label: 'Because', value: codeLabel(edge.failure.code) });
    if (edge.failure.status !== undefined)
      rows.push({ label: 'Provider answered', value: `HTTP ${edge.failure.status}` });
  }
  rows.push({ label: 'Destroy attempts', value: edge.destroyAttempts });
  if (edge.currentOp)
    rows.push({
      label: 'Unfinished call',
      value: `${humanizeCode(edge.currentOp.kind)}, attempt ${edge.currentOp.attempt}`,
    });
  for (const r of edge.resources) {
    rows.push({
      label: `${humanizeCode(r.kind)} (${r.ownership === 'adopted' ? 'imported' : 'created by FCP'})`,
      value: DELETE_STATE_WORDS[r.deleteState],
      hint: r.resourceId,
    });
  }
  if (!edge.managed)
    rows.push({
      label: 'Managed',
      value: 'No. FCP only observes this edge and never destroys it.',
    });
  return rows;
}

export function rotationDurationMs(
  r: Pick<EdgeRotationAdmin, 'startedAt' | 'finishedAt'>,
  now: number = Date.now(),
): number {
  const end = r.finishedAt ? new Date(r.finishedAt).getTime() : now;
  return Math.max(0, end - new Date(r.startedAt).getTime());
}

export function rotationOutcomeWords(
  r: Pick<EdgeRotationAdmin, 'terminal' | 'outcome' | 'reason'>,
): string {
  if (!r.terminal) return 'Running';
  const outcome = r.outcome ? humanizeCode(r.outcome) : 'Finished';
  return r.reason ? `${outcome}: ${codeLabel(r.reason)}` : outcome;
}

export function relayProbeTargetKeys(
  relayId: string,
  edges: Array<Pick<EdgeAdmin, 'id'>>,
): Set<string> {
  return new Set([`relay:${relayId}`, ...edges.map((e) => `edge:${e.id}`)]);
}

// --- words ---------------------------------------------------------------------------------------

export const ORIGIN_KIND_WORDS: Record<RelayAdmin['origin']['kind'], string> = {
  'panel-node': 'A node on a panel',
  'backend-server': 'A whole backend server',
  manual: 'Described by hand',
};

export const HOST_MODE_WORDS: Record<HostMode, { label: string; explain: string }> = {
  fcp: {
    label: 'FCP writes the Hosts',
    explain:
      'FCP creates, switches and deletes the client-facing panel Hosts itself. Rotations switch members over without anyone touching the panel.',
  },
  operator: {
    label: 'You write the Hosts',
    explain:
      'FCP never writes to the panel. You apply the Hosts plan by hand or through the node role. Replacing the first edge of a listener is refused unless forced, because FCP cannot switch members over.',
  },
  none: {
    label: 'No Hosts',
    explain:
      'This origin has no panel Host. Subscriptions are rewritten when they are served, nothing is written anywhere else.',
  },
};

export function matchRuleWords(rule: ListenerMatchRule, remark: string | null): string {
  switch (rule.kind) {
    case 'remark':
      return `By name: the subscription entry whose remark is "${rule.remark || remark || ''}".`;
    case 'address':
      return 'By address: the subscription entry that dials the origin address and this port.';
    case 'whole-body':
      return 'Whole body: the subscription holds a single entry, and it is this one.';
  }
}

export function originTransportWords(t: ListenerOriginTransport | null): string {
  if (!t) return 'Not declared. Edges forward raw TCP to the port (L4 only).';
  if (t.scheme === 'http') return 'Plain HTTP behind the front. Only an L7 front can carry it.';
  const cert = t.certPublic
    ? `a publicly trusted certificate for ${t.certNames.join(', ') || 'no names'}`
    : 'a certificate that is not publicly trusted';
  const host = t.acceptsHostHeader === 'any' ? 'any Host header' : 'only its own names as Host';
  return `HTTPS with ${cert}; the node accepts ${host}.`;
}

// --- timeline links --------------------------------------------------------------------------------

export interface TimelineLinkParams {
  tab?: 'listeners';
  edge?: string;
  rotation?: string;
  listener?: string;
}
/** Which drawer (or tab) a timeline entry opens; null when it has nothing to open. */
export function timelineLinkParams(entry: {
  targetType: string | null;
  targetId: string | null;
  payload?: unknown;
}): TimelineLinkParams | null {
  const p =
    entry.payload && typeof entry.payload === 'object'
      ? (entry.payload as Record<string, unknown>)
      : {};
  const str = (v: unknown): string | null => (typeof v === 'string' && v !== '' ? v : null);
  if (entry.targetType === 'edge_rotation' && entry.targetId) return { rotation: entry.targetId };
  const rotationId = str(p.rotationId);
  if (rotationId) return { rotation: rotationId };
  if (entry.targetType === 'edge' && entry.targetId) return { edge: entry.targetId };
  const edgeId = str(p.edgeId);
  if (edgeId) return { edge: edgeId };
  if (entry.targetType === 'relay_listener') {
    const key = str(p.listenerKey);
    return key ? { tab: 'listeners', listener: key } : { tab: 'listeners' };
  }
  return null;
}
