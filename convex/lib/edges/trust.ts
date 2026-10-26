/**
 * Suspicion (docs/edges.md "Address enumeration"): who gets a strike when a
 * trusted address is judged blocked, and when strikes make an account
 * suspected. Pure; the DB half is convex/edgeTrust.ts.
 *
 * The signal: a censor's account must be handed an address before it can block
 * it, and it blocks what it learns. Holders who had the address long before the
 * block are not "fresh" and never get a strike; when many accounts were handed
 * it recently (a new address taking a slice of the members, or a block found by
 * other means) the block is not attributable and nobody does. Because a blocked
 * address's holders scatter (`hrw1`), the censor's account is the one common
 * factor across successive blocks, while the members around it change.
 *
 * The account is named only by its MARK, an HMAC of its id under the
 * deployment's pepper: a database copy without the deployment's environment
 * cannot tie a row to an account.
 */
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

export interface TrustSettings {
  windowDays: number;
  maxFreshHolders: number;
  strikeSpacingHours: number;
  strikesToSuspect: number;
  strikeDays: number;
}

/**
 * The account's mark: HMAC-SHA256(pepper, `trust:` + userId), hex. Synchronous
 * (pure JS), so queries and mutations can compute it. Null without a pepper:
 * nothing is recorded and nobody is suspected (fail closed toward the member).
 */
export function trustMark(pepper: string | undefined | null, userId: string): string | null {
  if (!pepper) return null;
  return bytesToHex(hmac(sha256, utf8ToBytes(pepper), utf8ToBytes(`trust:${userId}`)));
}

/** The pepper the report marks use too (`EDGE_MARK_PEPPER`, else `IP_HASH_SALT`). */
export function trustPepper(env: Record<string, string | undefined>): string | null {
  return env.EDGE_MARK_PEPPER || env.IP_HASH_SALT || null;
}

/**
 * When handed counts as fresh for a block whose evidence began at
 * `evidenceAt`: in the `windowDays` before it (an account handed the address
 * after the block began cannot have caused it).
 */
export function freshWindow(evidenceAt: number, s: Pick<TrustSettings, 'windowDays'>) {
  return { from: evidenceAt - s.windowDays * DAY, to: evidenceAt };
}

/** Whether a block with `fresh` fresh holders strikes them (1 up to the cutoff). */
export function attributable(fresh: number, s: Pick<TrustSettings, 'maxFreshHolders'>): boolean {
  return fresh >= 1 && fresh <= s.maxFreshHolders;
}

/**
 * One more strike for an account: strikes older than `strikeDays` go; a strike
 * within `strikeSpacingHours` of the newest one does not count (one mass block
 * is one strike). Returns the strikes to store and whether this one counted.
 */
export function withStrike(
  strikes: readonly number[],
  now: number,
  s: Pick<TrustSettings, 'strikeSpacingHours' | 'strikeDays'>,
): { strikes: number[]; added: boolean } {
  const keep = strikes.filter((t) => now - t < s.strikeDays * DAY).sort((a, b) => a - b);
  const newest = keep[keep.length - 1];
  if (newest !== undefined && now - newest < s.strikeSpacingHours * HOUR)
    return { strikes: keep, added: false };
  return { strikes: [...keep, now], added: true };
}

/** Strikes still counting at `now`. */
export function liveStrikes(
  strikes: readonly number[],
  now: number,
  s: Pick<TrustSettings, 'strikeDays'>,
): number {
  return strikes.filter((t) => now - t < s.strikeDays * DAY).length;
}

/** Suspected: `strikesToSuspect` strikes still counting. */
export function isSuspected(
  strikes: readonly number[],
  now: number,
  s: Pick<TrustSettings, 'strikeDays' | 'strikesToSuspect'>,
): boolean {
  return liveStrikes(strikes, now, s) >= s.strikesToSuspect;
}

/** When the account's row can go: its newest strike has stopped counting. */
export function trustExpiresAt(
  strikes: readonly number[],
  s: Pick<TrustSettings, 'strikeDays'>,
): number {
  return Math.max(0, ...strikes) + s.strikeDays * DAY;
}
