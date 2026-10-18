/**
 * Validators and freshness for the member subscription route
 * (`GET /api/v1/sub/<token>`, docs/edges.md "Asking whether a configuration
 * changed"). An app sends `If-None-Match` with the tag it holds and gets a 304
 * when nothing it would receive has changed, so polling every minute costs a
 * few hundred bytes instead of a configuration.
 *
 * The tag names the CONTENT (weak, `W/"fs1-<22 chars>"`): a SHA-256 over the
 * exact identity bytes served plus the headers an app applies (content type,
 * `profile-title`, `profile-update-interval`), cut to 128 bits. It does not
 * name one encoding of it, so a compressing proxy has no reason to rewrite it.
 * `subscription-userinfo` is left out on purpose: its traffic numbers move on
 * almost every refetch and would turn every poll into a 200.
 *
 * Comparison is RFC 9110 §8.8.3.2 weak comparison (`W/` ignored on both sides,
 * the quoted opaque tags must be identical); a header that does not parse as
 * `"*"` or a list of entity tags is treated as absent (a 200, never an error).
 */

const TAG_PREFIX = 'fs1-';

export interface EtagInput {
  content: string;
  contentType: string;
  title: string;
  /** The `profile-update-interval` value served, or null when none is sent. */
  updateInterval: string | null;
}

function base64url(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** The weak entity tag of one subscription response. */
export async function subscriptionEtag(input: EtagInput): Promise<string> {
  const enc = new TextEncoder();
  // Length-prefixed fields: no two different inputs share the hashed bytes.
  const fields = [input.contentType, input.title, input.updateInterval ?? '', input.content].map(
    (f) => enc.encode(f),
  );
  const total = fields.reduce((n, f) => n + 4 + f.length, 0);
  const buf = new Uint8Array(total);
  const view = new DataView(buf.buffer);
  let at = 0;
  for (const f of fields) {
    view.setUint32(at, f.length);
    buf.set(f, at + 4);
    at += 4 + f.length;
  }
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
  return `W/"${TAG_PREFIX}${base64url(digest.slice(0, 16))}"`;
}

/** `etagc` (RFC 9110 §8.8.3): any visible character but DQUOTE, or obs-text. */
const isEtagc = (code: number): boolean =>
  code === 0x21 || (code >= 0x23 && code <= 0x7e) || (code >= 0x80 && code <= 0xff);
const isOws = (ch: string): boolean => ch === ' ' || ch === '\t';

/**
 * The opaque tags (quotes included, `W/` dropped) of an `If-None-Match` value,
 * `'*'` for the wildcard, or null when the value does not parse (then the
 * condition is ignored). Empty list elements are allowed, as the `#` rule does.
 */
export function parseIfNoneMatch(header: string): string[] | '*' | null {
  const value = header.trim();
  if (value === '') return null;
  if (value === '*') return '*';
  const tags: string[] = [];
  let i = 0;
  const n = value.length;
  while (i < n) {
    while (i < n && (isOws(value[i]) || value[i] === ',')) i++;
    if (i >= n) break;
    if (value.startsWith('W/', i)) i += 2;
    if (value[i] !== '"') return null;
    const start = i;
    i++;
    while (i < n && value[i] !== '"') {
      if (!isEtagc(value.charCodeAt(i))) return null;
      i++;
    }
    if (i >= n) return null; // unterminated
    i++;
    tags.push(value.slice(start, i));
    while (i < n && isOws(value[i])) i++;
    if (i < n && value[i] !== ',') return null; // junk after a tag
  }
  return tags.length > 0 ? tags : null;
}

const opaque = (tag: string): string => (tag.startsWith('W/') ? tag.slice(2) : tag);

/** Whether `If-None-Match` names this response's tag (weak comparison). */
export function ifNoneMatchHits(header: string | null | undefined, etag: string): boolean {
  if (!header) return false;
  const tags = parseIfNoneMatch(header);
  if (tags === null) return false;
  if (tags === '*') return true;
  const mine = opaque(etag);
  return tags.some((t) => t === mine);
}

/** How long a shared cache may keep an unbound subscription response. */
export const SUBSCRIPTION_MAX_AGE_SECONDS = 30;

/**
 * `Cache-Control` of a public subscription response. A body that holds L7
 * fronts is only as good as their proofs (`validUntil`, the earliest expiry
 * among them): no cache may call it fresh past that moment, and once stale it
 * must be revalidated (RFC 9111 §5.2.2.2). The same value goes on a 304, which
 * renews a cache's stored freshness, so a 304 never extends it either.
 */
export function publicCacheControl(validUntil: number | null | undefined, now: number): string {
  if (validUntil === null || validUntil === undefined)
    return `public, max-age=${SUBSCRIPTION_MAX_AGE_SECONDS}`;
  const left = Math.floor((validUntil - now) / 1000);
  const maxAge = Math.min(SUBSCRIPTION_MAX_AGE_SECONDS, Math.max(0, left));
  return `public, max-age=${maxAge}, must-revalidate`;
}

/** Whether a cached body may still be served at `now` (old-format entries never reach here). */
export function withinValidity(validUntil: number | null | undefined, now: number): boolean {
  return validUntil === null || validUntil === undefined || validUntil > now;
}

let clock: () => number = () => Date.now();

/**
 * The clock the subscription route reads when it judges a proof's expiry and
 * when it builds a response. Production reads `Date.now()`; a test can move
 * time between the render and the response through the seam below.
 */
export function subscriptionNow(): number {
  return clock();
}

/** Test seam: replace the route's clock; `null` restores `Date.now()`. */
export function __setSubscriptionClockForTests(fn: (() => number) | null): void {
  clock = fn ?? (() => Date.now());
}
