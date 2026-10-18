/**
 * Drains in plain words for the node page (pure, unit-tested in drainWords.test.ts).
 *
 * An address that is "retiring" (edge publication `draining`) is no longer
 * given to anyone; members who still hold it keep it until their app
 * refreshes, and the reconcile cron (every 5 minutes) deletes it once its
 * drain has passed (`drainUntil`). A replace drains for `edge.drainMinutes`
 * (or the origin's own drain), a burn for `edge.burnedDrainMinutes`; a retired
 * server name stays accepted for `edge.sniDrainMinutes`.
 *
 * Exports:
 *   drainLength(minutes)              '24 h', '1 h 30 min', '45 min', '3 d'
 *   clockWords(at, now)               '08:30', '08:30 tomorrow', '08:30 on 19 Oct'
 *   retiringWords(edge, now)          the row's line and which actions it offers
 *   endNowWords(edge, address, now)   "Delete now" (or "Stop tracking") and its confirm
 *   replaceDrainMinutes(kind, ...)    how long a replaced address drains
 */
import { durationLabel } from '../lib/time';

/** A drain length (minutes) in words: '24 h', '1 h 30 min', '45 min'; days past two. */
export function drainLength(minutes: number): string {
  const m = Math.max(0, Math.round(minutes));
  if (m < 60 || m > 2880) return durationLabel(m * 60_000);
  return m % 60 === 0 ? `${m / 60} h` : `${Math.floor(m / 60)} h ${m % 60} min`;
}

const pad = (n: number) => String(n).padStart(2, '0');
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const dayKey = (d: Date) => `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;

/** A local clock time, with the day when it is not today: '08:30', '08:30 tomorrow', '08:30 on 19 Oct'. */
export function clockWords(at: Date, now: Date): string {
  const hm = `${pad(at.getHours())}:${pad(at.getMinutes())}`;
  if (dayKey(at) === dayKey(now)) return hm;
  const tomorrow = new Date(now);
  tomorrow.setDate(now.getDate() + 1);
  if (dayKey(at) === dayKey(tomorrow)) return `${hm} tomorrow`;
  return `${hm} on ${at.getDate()} ${MONTHS[at.getMonth()]}`;
}

export interface RetiringEdge {
  status: string;
  publication: string;
  drainUntil: string | null;
  managed: boolean;
  burnedAt: string | null;
}

/**
 * A retiring address's line and the actions it offers. "Delete now" ends the
 * drain early; "Keep as a spare" stops it and makes the address a spare again,
 * never for one replaced as blocked (a burn). An address already being deleted
 * offers neither.
 */
export function retiringWords(
  e: RetiringEdge,
  now: number = Date.now(),
): {
  word: string;
  line: string;
  /** What is left of the drain: '9 h 12 min (around 08:30 tomorrow)'; null when nothing is. */
  left: string | null;
  canDelete: boolean;
  canKeep: boolean;
} {
  if (e.status === 'destroying')
    return {
      word: 'Being deleted',
      line: e.managed
        ? 'FCP removes it at the provider; billing stops once it is gone.'
        : 'FCP stops tracking it at its next check.',
      left: null,
      canDelete: false,
      canKeep: false,
    };
  const moved = e.burnedAt
    ? 'Replaced as blocked: members are moved off it.'
    : 'Members are moved off it.';
  const until = e.drainUntil ? Date.parse(e.drainUntil) : null;
  let when: string;
  let left: string | null = null;
  if (until === null) when = '';
  else if (until <= now)
    when = e.managed
      ? " Deleted at FCP's next check (every 5 minutes), then billing stops."
      : ' FCP stops tracking it at its next check (every 5 minutes). FCP did not create it, so delete it at your provider.';
  else {
    left = `${durationLabel(until - now)} (around ${clockWords(new Date(until), new Date(now))})`;
    when = e.managed
      ? ` Deleted in ${left}, then billing stops.`
      : ` FCP stops tracking it in ${left}. FCP did not create it, so delete it at your provider.`;
  }
  return {
    word: 'Retiring',
    line: `${moved}${when}`,
    left,
    canDelete: true,
    canKeep: !e.burnedAt,
  };
}

/**
 * Ending a retiring address's drain now: its row action and confirm. FCP
 * deletes an address it created at the provider; one it only observes is
 * forgotten (no provider call), so that one says to delete it there.
 */
export function endNowWords(
  e: RetiringEdge,
  address: string,
  now: number = Date.now(),
): { label: string; title: string; body: string; done: string } {
  const left = retiringWords(e, now).left;
  if (!e.managed)
    return {
      label: 'Stop tracking',
      title: `Stop tracking ${address} now?`,
      body:
        'FCP did not create this address, so it calls nothing at your provider: it only stops tracking it now. ' +
        'The address keeps working, and your provider keeps billing for it, until you delete it there. ' +
        'Members who have not refreshed their app since it was replaced use it until then.',
      done: `FCP no longer tracks ${address}. Delete it at your provider.`,
    };
  return {
    label: 'Delete now',
    title: `Delete ${address} now?`,
    body:
      'Members who have not refreshed their app since it was replaced still connect through it, and they lose it now; their app connects again once it refreshes.' +
      (left ? ` Left alone it would be deleted in ${left}.` : '') +
      ' FCP deletes it at the provider at its next check, within 5 minutes, and billing stops.',
    done: `Deleting ${address}.`,
  };
}

/**
 * How long the address a replace takes out drains: the origin's drain
 * (`drainMinutes`, its own override or `edge.drainMinutes`), or for a burn the
 * fleet's `edge.burnedDrainMinutes`; null while the fleet setting is unknown.
 */
export function replaceDrainMinutes(
  kind: 'rotate' | 'burn',
  originDrainMinutes: number,
  burnedDrainMinutes: number | null,
): number | null {
  return kind === 'burn' ? burnedDrainMinutes : originDrainMinutes;
}
