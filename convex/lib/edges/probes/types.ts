/**
 * Reachability probes: FCP asks measurement services (and its own host) to
 * open a TCP connection to ITS OWN edge addresses from vantage points in the
 * countries it cares about. No member data is involved anywhere in this layer
 * (docs/privacy.md §7): the target is an operator-owned address, the vantages
 * are third-party probes.
 */

export type ProbeSource = 'globalping' | 'checkhost' | 'ripeatlas' | 'internal';
export type VantageClass = 'eyeball' | 'datacenter' | 'unknown';

export interface ProbeResult {
  /** ISO-3166-1 alpha-2 (uppercase); 'XX' for the internal (non-country) probe. */
  country: string;
  asn?: string;
  network?: string;
  vantageClass: VantageClass;
  ok: boolean;
  rttMs?: number;
  /** Short, service-provided failure class (never a body or an address). */
  error?: string;
}

export interface ProbeTarget {
  address: string;
  port: number;
  ipVersion: 4 | 6;
}

export interface ProbeRequestOptions {
  countries: string[];
  perCountryLimit: number;
  preferEyeball: boolean;
}

/** A started measurement the caller polls (or an already-complete one). */
export interface ProbeStarted {
  externalId: string;
  /** Present when the service answered synchronously. */
  results?: ProbeResult[];
}

export interface ProbePoll {
  status: 'running' | 'finished';
  results: ProbeResult[];
}

export const DEFAULT_PROBE_TIMEOUT_MS = 45_000;

export function normalizeCountry(c: unknown): string | null {
  if (typeof c !== 'string') return null;
  const s = c.trim().toUpperCase();
  return /^[A-Z]{2}$/.test(s) ? s : null;
}

export function shortError(e: unknown, max = 60): string {
  const s =
    typeof e === 'string' ? e : e instanceof Error ? e.message : e == null ? 'error' : String(e);
  // Strip anything that looks like an address or a URL: errors are stored.
  return s
    .replace(/https?:\/\/\S+/g, '<url>')
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, '<ip>')
    .replace(/\[?[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}\]?/gi, '<ip6>')
    .slice(0, max);
}
