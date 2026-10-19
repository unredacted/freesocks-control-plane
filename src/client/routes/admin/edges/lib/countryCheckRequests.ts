/**
 * The "Check from every country now" requests this tab made, so every view of
 * the checks (the node page, the edge drawer, the Probes page) says
 * "Checking" and reads faster until the round comes back (lib/countryChecks.ts
 * `checkPending`: a round newer than the one on record when it asked). Kept
 * for the page session only; never sent anywhere.
 *
 * Exports:
 *   noteCountryCheck(edgeId, before, at?)  remember a request (`before`: the edge's newest round then)
 *   countryCheckPending(data, edgeId, now?) that edge's request is still out
 *   anyCountryCheckPending(data, now?)     some request is still out (the query's busy signal)
 */
import { SvelteMap } from 'svelte/reactivity';
import type { EdgeCountriesResponse } from '../../../../../shared/contracts/edges';
import { checkPending, type CheckRequest } from './countryChecks';

const requested = new SvelteMap<string, CheckRequest>();

export function noteCountryCheck(
  edgeId: string,
  before: string | null,
  at: number = Date.now(),
): void {
  requested.set(edgeId, { at, before });
}

export function countryCheckPending(
  data: EdgeCountriesResponse | null | undefined,
  edgeId: string,
  now: number = Date.now(),
): boolean {
  const request = requested.get(edgeId);
  if (request === undefined) return false;
  return checkPending(request, data?.edges.find((e) => e.edgeId === edgeId) ?? null, now);
}

export function anyCountryCheckPending(
  data: EdgeCountriesResponse | null | undefined,
  now: number = Date.now(),
): boolean {
  for (const edgeId of requested.keys()) if (countryCheckPending(data, edgeId, now)) return true;
  return false;
}
