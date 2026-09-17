/**
 * Hostname minting for L7 (CDN) edges. An L7 edge is ONE hostname under an
 * operator-owned zone; the label is derived deterministically from the edge's
 * provider-side resource name so every provider call and every discovery
 * agree on it without persisting anything first (the result is frozen into
 * the edge's provisionIntent anyway). The label is random-looking (a hash) so
 * hostnames carry no pattern; `spec.name` itself is never a public hostname.
 *
 * Rule: a SINGLE first-level label directly under the zone apex. Cloudflare
 * Universal SSL covers the apex and first-level names only, and a Fastly TLS
 * subscription is per name either way; deeper labels are always refused.
 */
import { addressFamily } from './ip';

const HOSTNAME_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
/** Base-32 alphabet without vowels/ambiguous glyphs so labels never spell words. */
const ALPHABET = '0123456789bcdfghjklmnpqrstvwxz';

export interface HostnameLabelOptions {
  labelLength: number;
  labelPrefix?: string;
}

/** Two independent FNV-1a 32-bit hashes (different offsets) over UTF-8: 64 bits of seed material. */
function fnv1a32(s: string, offset: number): number {
  let h = offset >>> 0;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}
function fnv1a64(s: string): [number, number] {
  return [fnv1a32(s, 0x811c9dc5), fnv1a32(`${s}\u0001`, 0xcbf29ce4)];
}

/** A deterministic label of `length` characters from `seed` (no prefix applied). */
export function labelFromSeed(seed: string, length: number): string {
  let out = '';
  let round = 0;
  while (out.length < length) {
    const [hi, lo] = fnv1a64(`${seed}#${round}`);
    let n = hi * 0x100000000 + lo;
    for (let i = 0; i < 12 && out.length < length; i++) {
      out += ALPHABET[n % ALPHABET.length];
      n = Math.floor(n / ALPHABET.length);
    }
    round += 1;
  }
  // A label must start with a letter or digit (it does) and never end with a dash (alphabet has none).
  return out;
}

export function isValidLabel(label: string): boolean {
  return LABEL_RE.test(label);
}

export function isValidHostname(name: string): boolean {
  return HOSTNAME_RE.test(name) && addressFamily(name) === null;
}

export function normalizeZoneName(zone: string): string {
  return zone.trim().toLowerCase().replace(/\.$/, '');
}

/**
 * `<prefix><label>.<zone>`: deterministic for (specName, zone, options).
 * Throws on an invalid zone or when the result is not a first-level label.
 */
export function edgeHostnameFor(
  specName: string,
  zoneName: string,
  opts: HostnameLabelOptions,
): string {
  const zone = normalizeZoneName(zoneName);
  if (!isValidHostname(zone)) throw new Error('hostname: invalid zone name');
  const prefix = (opts.labelPrefix ?? '').toLowerCase();
  if (prefix && !/^[a-z0-9-]{1,8}$/.test(prefix)) throw new Error('hostname: invalid label prefix');
  const length = Math.min(16, Math.max(8, Math.floor(opts.labelLength)));
  const label = `${prefix}${labelFromSeed(`${zone}/${specName}`, length)}`;
  if (!isValidLabel(label)) throw new Error('hostname: invalid label');
  const hostname = `${label}.${zone}`;
  if (!isFirstLevelUnder(hostname, zone)) throw new Error('hostname: not a first-level label');
  return hostname;
}

/** True iff `hostname` is exactly one label below `zone` (Universal SSL coverage rule). */
export function isFirstLevelUnder(hostname: string, zoneName: string): boolean {
  const h = hostname.toLowerCase().replace(/\.$/, '');
  const z = normalizeZoneName(zoneName);
  if (!h.endsWith(`.${z}`)) return false;
  const label = h.slice(0, -(z.length + 1));
  return isValidLabel(label) && !label.includes('.');
}

/** `_acme-challenge.<hostname>` (the DNS-01 validation record name Fastly's managed-dns challenge uses). */
export function acmeChallengeName(hostname: string): string {
  return `_acme-challenge.${hostname.toLowerCase().replace(/\.$/, '')}`;
}
