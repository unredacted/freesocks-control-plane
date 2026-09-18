/**
 * Reachability probes: FCP asks measurement services (and its own host) to
 * open a connection to ITS OWN edge addresses (or hostnames) from vantage
 * points in the countries it cares about. No member data is involved anywhere
 * in this layer (docs/privacy.md §7): the target is an operator-owned address,
 * the vantages are third-party probes.
 */

export type ProbeSource = 'globalping' | 'checkhost' | 'ripeatlas' | 'internal';
export type VantageClass = 'eyeball' | 'datacenter' | 'unknown';

/** What kind of thing the run addressed: an IP literal or a DNS name. */
export type ProbeAddressKind = 'ip' | 'name';
/**
 * What the probe speaks. `tcp` is a bare connect (a TLS alert still means the
 * peer answered: a REALITY endpoint never presents a certificate for a random
 * SNI). `tls` is a real handshake with SNI, so a certificate or handshake
 * failure IS unreachable. `https` adds a request on top of `tls`. `tls-sni` is
 * the INTERNAL protocol-shape check of an L4 edge in front of a REALITY / TLS
 * listener: a full handshake to the edge ADDRESS with SNI = one of the
 * listener's active names (`servername`), chain verified for that name, no
 * HTTP. It is shape evidence only: a forwarder aimed at the camouflage site
 * presents that site's certificate and passes it. External vantages cannot
 * set an SNI against an IP literal, so they treat it as `tcp`.
 */
export type ProbeProtocol = 'tcp' | 'tls' | 'https' | 'tls-sni';

/** A bare connect from a vantage (`tcp`, and `tls-sni` seen from outside). */
export function isBareConnect(p: ProbeProtocol | undefined): boolean {
  return (p ?? 'tcp') === 'tcp' || p === 'tls-sni';
}
/** The family FCP asked for; `any` for a name (the resolver decides). */
export type RequestedFamily = 4 | 6 | 'any';

export interface ProbeResult {
  /** ISO-3166-1 alpha-2 (uppercase); 'XX' for the internal (non-country) probe. */
  country: string;
  asn?: string;
  network?: string;
  vantageClass: VantageClass;
  ok: boolean;
  rttMs?: number;
  /** Short, service-provided failure class (never a body, an address or a hostname). */
  error?: string;
}

export interface ProbeTarget {
  /** IP literal or DNS name, per `addressKind`. */
  address: string;
  port: number;
  addressKind: ProbeAddressKind;
  protocol: ProbeProtocol;
  /** `tls-sni` only: the listener name presented as SNI and verified against the chain. */
  servername?: string;
  requestedFamily: RequestedFamily;
  /**
   * The family of an IP-literal target, and the observed family of a name a
   * source managed to pin. Absent for a name nobody pinned.
   */
  ipVersion?: 4 | 6;
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

/** `[v6]:port` / `name:port` / `v4:port` as the wire formats want it. */
export function targetHost(t: Pick<ProbeTarget, 'address' | 'ipVersion' | 'addressKind'>): string {
  return t.addressKind === 'ip' && t.ipVersion === 6 ? `[${t.address}]` : t.address;
}

export function normalizeCountry(c: unknown): string | null {
  if (typeof c !== 'string') return null;
  const s = c.trim().toUpperCase();
  return /^[A-Z]{2}$/.test(s) ? s : null;
}

/**
 * Anything that looks like a DNS name: probe errors are STORED, and a hostname
 * edge's name is exactly the thing an error string must not carry (a leaked
 * name is a censor's shortcut to the front). Matched conservatively (labels +
 * an alphabetic TLD) so short error codes (`EAI_AGAIN`, `ECONNREFUSED`) and
 * plain prose survive.
 */
const HOSTNAME_LIKE_RE = /\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b\.?/gi;

/**
 * Reduce an error to a short, storable class. Strips URLs, IP literals and
 * DNS names; `redact` additionally removes the caller's own target spellings
 * (a name that does not match the generic shape, e.g. a single label).
 */
export function shortError(e: unknown, max = 60, redact: readonly string[] = []): string {
  const raw =
    typeof e === 'string' ? e : e instanceof Error ? e.message : e == null ? 'error' : String(e);
  let s = raw.replace(/https?:\/\/\S+/g, '<url>');
  for (const host of redact) {
    const h = host.trim();
    if (h.length < 2) continue;
    s = s.replace(new RegExp(h.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), '<host>');
  }
  return s
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, '<ip>')
    .replace(/\[?[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}\]?/gi, '<ip6>')
    .replace(HOSTNAME_LIKE_RE, '<host>')
    .slice(0, max);
}
