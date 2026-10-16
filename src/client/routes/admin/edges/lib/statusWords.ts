/**
 * The server's origin status in words (pure; unit-tested). The judgement
 * (which kind, which dot, which reason wins) is the server's ONE projection
 * (`convex/lib/edges/originStatus.ts`: the attention response's `origins[]`
 * and `fleet`, setup-status's `delivery`); every page reads it and only words
 * it here, so the Edges home, the node page, All origins and the Servers node
 * page always agree.
 *
 * Exports:
 *   originSentence(status)       one plain sentence for one origin
 *   fleetSentence(fleet)         the Edges home's headline
 *   deliveryWords(delivery)      the Delivery card: tone, headline, what members get, why, the fix
 *   statusOf(origins, slug)      one origin's status from the attention response, or null
 */
import type {
  FleetStatus,
  OriginDelivery,
  OriginStatus,
  OriginStatusRow,
} from '../../../../../shared/contracts/edges';
import { codeExplain, codeFix, codeLabel, type Tone } from '../../../../lib/edgeCodes';

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

function runSentence(s: OriginStatus): string {
  const step = s.step ?? 1;
  const again = s.runKind === 'reprotect';
  const lead = again ? `Protecting again, step ${step} of 4` : `Setting up, step ${step} of 4`;
  if (s.kind === 'needs-you') {
    if (s.code === 'node_not_approved')
      return 'Every address works. Waiting for you to approve go-live.';
    return `${lead}. It needs you.`;
  }
  return again ? `${lead}. Members keep what they have.` : `${lead}.`;
}

export function originSentence(s: OriginStatus): string {
  if (s.runId) return runSentence(s);
  switch (s.kind) {
    case 'removing':
      return s.code === 'restore' ? 'Removing protection.' : 'Being removed.';
    case 'paused':
      return 'Paused for safety. It needs you.';
    case 'needs-you':
      if (s.code === 'offline')
        return `${plural(s.offline, 'address is', 'addresses are')} offline.`;
      return `${codeLabel(s.code ?? 'needs_operator')}. It needs you.`;
    case 'off':
      return 'Protection is switched off (Advanced).';
    case 'not-live':
      return s.published > 0
        ? 'Address ready, not live yet. Members still use the direct address.'
        : 'Not protected yet. Members use the direct address.';
    case 'unprotected':
      return 'No address in use. Members get nothing.';
    case 'setting-up':
      return runSentence(s);
    case 'protected': {
      const spare = s.standbys > 0 ? `, ${plural(s.standbys, 'spare', 'spares')}` : '';
      return `Protected. ${plural(s.published, 'address', 'addresses')} in use${spare}.`;
    }
  }
}

export function fleetSentence(f: FleetStatus | null): string {
  if (!f) return '';
  switch (f.kind) {
    case 'empty':
      return 'No node is protected yet.';
    case 'needs-you':
      return `${plural(f.count, 'node needs', 'nodes need')} you.`;
    case 'setting-up':
      return `Setting up ${plural(f.count, 'node', 'nodes')}.`;
    case 'not-live':
      return `${plural(f.count, 'node is', 'nodes are')} not live yet.`;
    case 'protected':
      return f.total === 1 ? 'Your node is protected.' : `All ${f.total} nodes protected.`;
    case 'partial':
      return `${f.protected} of ${plural(f.total, 'node', 'nodes')} protected.`;
  }
}

export interface DeliveryWords {
  tone: Tone;
  headline: string;
  /** What members on this origin get right now. */
  detail: string;
  /** Why, and what fixes it (null while nothing is wrong). */
  reason: string | null;
  fix: string | null;
}

const why = (code: string | null) =>
  code ? `${codeLabel(code)}. ${codeExplain(code)}`.trim() : null;

export function deliveryWords(d: OriginDelivery): DeliveryWords {
  switch (d.kind) {
    case 'manual':
      return {
        tone: 'muted',
        headline: 'Nothing to deliver',
        detail:
          'A manual origin has no subscriptions that FCP serves. Wire clients from the connection plan on this page.',
        reason: null,
        fix: null,
      };
    case 'direct':
      return {
        tone: 'muted',
        headline: 'Members use the direct address',
        detail:
          'Nothing is live through edges for this node yet, so members receive its own address. Going live switches them over.',
        reason: null,
        fix: null,
      };
    case 'serving':
      return {
        tone: 'success',
        headline: 'Serving through edges',
        detail:
          'Members on this origin receive edge addresses only. The origin address is never handed out.',
        reason: null,
        fix: null,
      };
    case 'degraded':
      return {
        tone: 'warning',
        headline: 'Serving, with a problem',
        detail:
          'Edges are published, but a sample subscription did not render cleanly. Members whose subscription hits the same problem are answered "temporarily unavailable".',
        reason: why(d.code),
        fix: d.code ? (codeFix(d.code) ?? null) : null,
      };
    case 'dark':
      return {
        tone: 'danger',
        headline: 'Members are dark',
        detail:
          'Subscriptions on this origin are answered "temporarily unavailable" instead of the direct address. Clients keep their last configuration until something can be served.',
        reason: why(d.code),
        fix: d.code ? (codeFix(d.code) ?? null) : null,
      };
  }
}

export function statusOf(
  origins: readonly OriginStatusRow[] | undefined,
  slug: string,
): OriginStatus | null {
  return origins?.find((o) => o.relaySlug === slug)?.status ?? null;
}
