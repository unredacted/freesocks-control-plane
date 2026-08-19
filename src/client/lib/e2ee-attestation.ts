/**
 * Pure mapping from a live key-attestation result to the UI verdict the chrome
 * renders. Kept out of `e2ee-status.svelte.ts` so it is unit-testable without the
 * Svelte compiler (that module carries runes) and out of `e2ee.ts` so reading it
 * costs no crypto chunk.
 */
import type { AttestationFailure, ConnectionAttestation } from './e2ee';

export type E2eeAttestation =
  | 'pending'
  | 'active'
  | 'warn'
  | 'stale'
  | 'unreachable'
  | 'unconfigured';

/** The failures that mean someone swapped the key, rather than that the server has none. */
const TAMPER_FAILURES: readonly AttestationFailure[] = ['signature', 'revoked'];

/**
 * Fold one attestation result into a UI verdict:
 *
 *  - `active`      key verified against the baked manifest key, unexpired, not revoked.
 *  - `warn`        the endpoint answered and the key it served FAILS to verify, or is
 *                  revoked. Only a CDN swapping the key produces this, so it is the
 *                  one state escalated loudly (the full-width <E2eeAlert/> bar).
 *  - `stale`       the endpoint answered but has no live epoch to offer (none
 *                  published, or the one we got had expired). The client keeps
 *                  sealing to the manifest-pinned STATIC key, so nothing is
 *                  unprotected and nothing points at tampering: this is an operator
 *                  signal (rotation wedged, or a cache handed us an old response)
 *                  and shows only as detail in the verify panel. It must NOT reuse
 *                  `warn` - saying "don't enter your account number" because a cron
 *                  is behind trains users to ignore the one alarm that counts.
 *  - `unreachable` couldn't reach the endpoint (a network blip); the pinned key is
 *                  still in use, so this is NOT an alarm either.
 */
export function classifyAttestation(att: ConnectionAttestation): E2eeAttestation {
  if (att.configured === false) return 'unconfigured'; // manifest key not baked: can't verify
  if (att.attested) return 'active';
  if (!att.reachable) return 'unreachable';
  return att.failure && TAMPER_FAILURES.includes(att.failure) ? 'warn' : 'stale';
}

/**
 * Fold a fresh verdict into the one already on screen. `warn` is STICKY: once a
 * swapped or revoked key has been observed, only a poll that positively attests
 * may clear the alarm.
 *
 * Without this, re-attesting hands an active CDN an off switch - having been
 * caught once, it clears the "don't enter your account number" banner just by
 * making the next poll inconclusive (block it → `unreachable`, or strip/expire the
 * epoch → `stale`). Inconclusive is not exculpatory, so it does not clear.
 */
export function nextAttestation(prev: E2eeAttestation, next: E2eeAttestation): E2eeAttestation {
  return prev === 'warn' && next !== 'active' ? 'warn' : next;
}
