/**
 * Pure, runtime-agnostic E2EE envelope + canonicalization helpers for the
 * CDN-blinding channel. This module imports no crypto library and executes no
 * key-schedule crypto, so it is safe to import from the Convex default V8
 * isolate (which lacks subtle HKDF). The HPKE seal/open primitives that need
 * full WebCrypto live in ./hpke.ts and run only in the browser and the
 * "use node" server action.
 *
 * Design: docs/e2ee-phase0-spike.md and the threat model. The wire envelope is
 * `{ fsSealed: { v, suiteId?, kid?, enc?, responseNonce?, ct } }` with all byte
 * fields base64url-encoded.
 */

/** Versioned suite identifier, folded into the HPKE `info` so a substituted suite fails Open(). */
export const SUITE_ID = 'FCP-E2EE-v1/xwing-hkdfsha256-chacha20poly1305';

/** HPKE `info` human-readable prefix. */
const INFO_PREFIX = 'FCP-E2EE v1';
const NUL = 0x00;

const te = new TextEncoder();

// --- base64url (no padding) ---------------------------------------------------

export function bytesToB64Url(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64UrlToBytes(s: string): Uint8Array {
  let b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// --- canonicalization (shared by buildInfo and, later, the PoP signature) -----

/** Strip query, force a leading slash, drop a trailing slash (except root). */
export function normalizePath(path: string): string {
  let p = path || '/';
  const q = p.indexOf('?');
  if (q >= 0) p = p.slice(0, q);
  if (!p.startsWith('/')) p = '/' + p;
  if (p.length > 1) p = p.replace(/\/+$/, '');
  return p || '/';
}

/** Stable, sorted, percent-encoded query string (so client and server agree). */
export function canonicalQuery(query?: string | URLSearchParams): string {
  if (!query) return '';
  const sp =
    typeof query === 'string'
      ? new URLSearchParams(query.startsWith('?') ? query.slice(1) : query)
      : query;
  const pairs: Array<[string, string]> = [];
  for (const [k, v] of sp) pairs.push([k, v]);
  pairs.sort((a, b) =>
    a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0,
  );
  return pairs.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
}

export interface CanonParts {
  method: string;
  host: string;
  path: string;
  query?: string | URLSearchParams;
}

/** The single canonical request representation. Used by both the HPKE info builder and PoP. */
export function canonicalize(p: CanonParts): string {
  return [
    p.method.toUpperCase(),
    p.host.toLowerCase(),
    normalizePath(p.path),
    canonicalQuery(p.query),
  ].join('\n');
}

export interface InfoParts {
  suiteId: string;
  kid: string;
  method: string;
  path: string;
  /** Direction marker so a request-sealed blob can never be read as a response-sealed one. */
  dir: 'req' | 'resp';
}

/**
 * HPKE `info`: PREFIX \0 suiteId \0 kid \0 METHOD \0 path \0 dir. No time window
 * (see spike doc). `host` is deliberately NOT bound here: a dev reverse proxy
 * rewrites Host, and recipient-key binding already prevents cross-app misuse;
 * host-binding for replay lives in the PoP canonical request (Phase 2,
 * canonicalize()).
 */
export function buildInfo(p: InfoParts): Uint8Array {
  const parts = [
    INFO_PREFIX,
    p.suiteId,
    p.kid,
    p.method.toUpperCase(),
    normalizePath(p.path),
    p.dir,
  ].map((x) => te.encode(x));
  const total = parts.reduce((n, x) => n + x.length, 0) + (parts.length - 1);
  const out = new Uint8Array(total);
  let o = 0;
  parts.forEach((x, i) => {
    if (i) out[o++] = NUL;
    out.set(x, o);
    o += x.length;
  });
  return out;
}

// --- wire envelope ------------------------------------------------------------

export interface SealedEnvelope {
  v: number;
  suiteId?: string;
  kid?: string;
  enc?: string; // base64url
  responseNonce?: string; // base64url
  ct: string; // base64url
}

export interface SealedWire {
  fsSealed: SealedEnvelope;
}

export function isSealedWire(o: unknown): o is SealedWire {
  const e = (o as { fsSealed?: unknown })?.fsSealed as SealedEnvelope | undefined;
  return !!e && typeof e === 'object' && typeof e.ct === 'string' && typeof e.v === 'number';
}

export interface EnvelopeParts {
  v?: number;
  suiteId?: string;
  kid?: string;
  enc?: Uint8Array;
  responseNonce?: Uint8Array;
  ct: Uint8Array;
}

export function encodeEnvelope(parts: EnvelopeParts): SealedWire {
  const e: SealedEnvelope = { v: parts.v ?? 1, ct: bytesToB64Url(parts.ct) };
  if (parts.suiteId) e.suiteId = parts.suiteId;
  if (parts.kid) e.kid = parts.kid;
  if (parts.enc) e.enc = bytesToB64Url(parts.enc);
  if (parts.responseNonce) e.responseNonce = bytesToB64Url(parts.responseNonce);
  return { fsSealed: e };
}

export interface DecodedEnvelope {
  v: number;
  suiteId?: string;
  kid?: string;
  enc?: Uint8Array;
  responseNonce?: Uint8Array;
  ct: Uint8Array;
}

export function decodeEnvelope(w: SealedWire): DecodedEnvelope {
  const e = w.fsSealed;
  return {
    v: e.v,
    suiteId: e.suiteId,
    kid: e.kid,
    enc: e.enc ? b64UrlToBytes(e.enc) : undefined,
    responseNonce: e.responseNonce ? b64UrlToBytes(e.responseNonce) : undefined,
    ct: b64UrlToBytes(e.ct),
  };
}

// --- hashing ------------------------------------------------------------------

/** SHA-256 (subtle.digest is available in the isolate, the browser, and Node). */
export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const d = await crypto.subtle.digest('SHA-256', bytes as unknown as ArrayBuffer);
  return new Uint8Array(d);
}

/** kid = first 8 bytes of SHA-256(serialized public key), hex. */
export async function kidFromPublicKey(pkBytes: Uint8Array): Promise<string> {
  const h = await sha256(pkBytes);
  return [...h.slice(0, 8)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Raw SHA-256 of the exact UTF-8 base64url string, as lowercase hex (64 chars,
 * ungrouped). The hashing primitive behind the out-of-band fingerprint: the
 * ungrouped form goes verbatim into a single-line DNS TXT pin record (no
 * spaces), while `fingerprintB64Url` groups it for on-screen display. Keeping
 * one primitive guarantees the DNS value and the displayed fingerprint are the
 * same hash.
 */
export async function sha256HexOfB64Url(b64url: string): Promise<string> {
  const h = await sha256(new TextEncoder().encode(b64url));
  return [...h].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Out-of-band verification fingerprint of a baked base64url public-key string:
 * the FULL SHA-256 of the exact UTF-8 base64url string (NOT the decoded key
 * bytes — that is `kidFromPublicKey`), as lowercase hex grouped in 4-char chunks.
 * This is the single source of truth shared by the in-app "Verify connection"
 * panel and the `scripts/e2ee-fingerprint.mjs` publisher, so the value a user
 * sees in the browser is byte-identical to the one published out of band (signed
 * release / .onion). Comparing the two off-CDN is what makes the pinned key
 * meaningful against an active CDN.
 */
export async function fingerprintB64Url(b64url: string): Promise<string> {
  const hex = await sha256HexOfB64Url(b64url);
  return (hex.match(/.{4}/g) ?? []).join(' ');
}

// --- route policy -------------------------------------------------------------

/**
 * Per-route sealing policy. `request: 'seal'` seals the request body to the
 * server static key (the account number on login). `response: 'reveal'` seals
 * the response to a fresh client ephemeral (the reveal leg: forward-secret
 * against server-key compromise, used for every sensitive response). Both the
 * client `request()` seam and the server `sealed()` wrapper read this, so it is
 * the single source of truth and lives here (pure, isolate-safe).
 */
export interface RoutePolicy {
  request: 'seal' | 'plain';
  response: 'reveal' | 'plain';
}

const SEAL_REQ: RoutePolicy = { request: 'seal', response: 'plain' };
const REVEAL: RoutePolicy = { request: 'plain', response: 'reveal' };

/**
 * Keyed by `"METHOD /path"` (method-aware): several admin paths serve BOTH a GET
 * list (no seal) and a POST create (seal) at the same path, so a path-only policy
 * couldn't seal the create without breaking the list. Member account routes are
 * unchanged in behavior, just method-keyed. Admin entries seal SECRET bodies only:
 * `REVEAL` = the server hands back a freshly-minted secret (token/invite/codes);
 * `SEAL_REQ` = the admin uploads a long-lived infra credential. This is PASSIVE-CDN
 * confidentiality, NOT an anti-tamper measure (an active CDN that rewrites the
 * bundle is out of scope for sealing — see docs/oob-verification.md).
 */
export const SEALED_ROUTES: Record<string, RoutePolicy> = {
  // Member account-plane. POST /account mints+reveals the account number (and binds
  // the PoP key); GET /account reveals the authenticated view. Both reveal.
  'POST /api/v1/auth/account-login': SEAL_REQ,
  'GET /api/v1/account': REVEAL,
  'POST /api/v1/account': REVEAL,
  'POST /api/v1/account/regenerate': REVEAL,
  'POST /api/v1/account/switch-backend': REVEAL,
  'POST /api/v1/account/switch-mode': REVEAL,
  'POST /api/v1/account/account-id/rotate': REVEAL,
  // Admin secret reveals (server returns a fresh secret once).
  'POST /api/v1/admin/tokens': REVEAL,
  'POST /api/v1/admin/membership-codes': REVEAL,
  'POST /api/v1/admin/admins/invite': REVEAL,
  // Admin credential uploads (admin sends infra secrets). Dual-mode server keeps
  // plaintext `fsv1_`-token / Ansible callers working.
  'POST /api/v1/admin/backend-servers': SEAL_REQ,
  'POST /api/v1/admin/backend-servers/test-connection': SEAL_REQ,
  'POST /api/v1/admin/mirror-providers': SEAL_REQ,
  'POST /api/v1/admin/mirror-providers/test-connection': SEAL_REQ,
  'PATCH /api/v1/admin/billing/config': SEAL_REQ,
};

/**
 * Parameterized routes (path params), matched by method + prefix when the exact
 * lookup misses. Method-scoped so the read verbs under a prefix (GET/DELETE, no
 * body) are never asked to seal an empty request body.
 */
const SEALED_PREFIXES: { method: string; prefix: string; policy: RoutePolicy }[] = [
  // by-slug/by-name BEFORE the shorter prefix so the specific rule wins; they're
  // PUT (the shorter prefixes are PATCH), so there's no method overlap anyway.
  { method: 'PUT', prefix: '/api/v1/admin/backend-servers/by-slug/', policy: SEAL_REQ },
  { method: 'PATCH', prefix: '/api/v1/admin/backend-servers/', policy: SEAL_REQ },
  { method: 'PUT', prefix: '/api/v1/admin/mirror-providers/by-name/', policy: SEAL_REQ },
  { method: 'PATCH', prefix: '/api/v1/admin/mirror-providers/', policy: SEAL_REQ },
  // Member gift-code reveal (same secret class; the buyer polls this GET).
  { method: 'GET', prefix: '/api/v1/billing/order/', policy: REVEAL },
];

export function routePolicy(path: string, method: string): RoutePolicy | undefined {
  const p = normalizePath(path);
  const m = method.toUpperCase();
  return (
    SEALED_ROUTES[`${m} ${p}`] ??
    SEALED_PREFIXES.find((r) => r.method === m && p.startsWith(r.prefix))?.policy
  );
}

/** Request body field carrying the client's base64url response-ephemeral public key (reveal leg). */
export const RESP_EPH_FIELD = 'fsRespEph';
