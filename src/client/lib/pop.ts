/**
 * Main-thread seam for proof-of-possession sessions (CDN-blinding Phase 2). A
 * thin RPC wrapper over the signing Worker (./pop-worker.ts), plus the policy
 * for which requests get signed and where the public key is posted.
 *
 * The private key lives only in the Worker (non-extractable, IndexedDB-backed);
 * this module never holds key material. Everything fails SOFT: if the Worker is
 * unavailable (no Worker support, blocked by CSP, init error) or no session key
 * exists yet (anonymous, pre-login), the helpers return null/unchanged and the
 * request goes out without PoP. The server's dual-mode + legacy fallback handle
 * that during rollout; once POP_REQUIRED is enabled, a bound session with no
 * signature is rejected (re-auth), which is the point.
 */
import { normalizePath } from '../../shared/crypto/envelope';
import {
  POP_ALG_FIELD,
  POP_HOST_HEADER,
  POP_NONCE_HEADER,
  POP_PUBKEY_FIELD,
  POP_SIG_HEADER,
  POP_TS_HEADER,
  POP_VERSION,
  POP_VERSION_HEADER,
} from '../../shared/crypto/pop';

/** Keys are scoped so member and admin never share one (see pop-worker.ts). */
export type Realm = 'member' | 'admin';

/** Member login establishes a session key and posts the pubkey. */
const MEMBER_LOGIN_PATH = '/api/v1/auth/account-login';
/** Anonymous account creation also establishes a member session (auto sign-in). */
const MEMBER_CREATE_PATH = '/api/v1/account';

/**
 * POSTs that establish a member session by binding a freshly-minted PoP key.
 * They cannot themselves be PoP-signed (the key is bound by this very request)
 * and instead carry the public key in the body. Method-scoped so the
 * GET /api/v1/account view stays signed like any other authenticated read.
 */
function isMemberSessionEstablish(path: string, method: string): boolean {
  if (method.toUpperCase() !== 'POST') return false;
  const p = normalizePath(path);
  return p === MEMBER_LOGIN_PATH || p === MEMBER_CREATE_PATH;
}

/** Admin resources live under these prefixes; everything else authenticated is a member route. */
function realmForPath(path: string): Realm {
  const p = normalizePath(path);
  return p.startsWith('/api/v1/admin/') || p.startsWith('/api/admin/') ? 'admin' : 'member';
}

/** Paths that must NOT be PoP-signed: the session-establish ceremonies + logout. */
function signEligible(path: string, method: string): boolean {
  const p = normalizePath(path);
  // Session-establishing POSTs (login, account creation) bind the key in-body;
  // they are never signed. GET /api/v1/account, by contrast, IS signed.
  if (isMemberSessionEstablish(p, method)) return false;
  if (p === '/api/v1/auth/logout') return false;
  // The whole admin auth surface is unsigned: the ceremonies + logout bind/clear
  // the session key, and the status READ is detection-only (cookie-checked
  // server-side, no PoP) so a fresh /admin visit isn't gated on a signature.
  if (p.startsWith('/api/admin/auth/')) return false;
  return p.startsWith('/api/');
}

// --- public per-session token (PoP sid-binding) -------------------------------
// The server mints a non-secret token per session and returns it in the login
// response BODY; the client persists it (localStorage, per realm) and signs it
// into every PoP message so a signature is bound to exactly one session. Read on
// the main thread (Workers have no localStorage) and passed to the Worker.

const popSidKey = (realm: Realm): string => `fs_pop_sid:${realm}`;

/** Persist (or clear) the realm's public per-session token. */
export function setSessionToken(realm: Realm, token: string | null | undefined): void {
  try {
    if (token) localStorage.setItem(popSidKey(realm), token);
    else localStorage.removeItem(popSidKey(realm));
  } catch {
    // localStorage unavailable (private mode / disabled): the request then signs
    // an empty token and the server rejects it → re-auth. Fails safe.
  }
}

/** The realm's stored public per-session token, or '' if none. */
function readSessionToken(realm: Realm): string {
  try {
    return localStorage.getItem(popSidKey(realm)) ?? '';
  } catch {
    return '';
  }
}

/**
 * After a MEMBER session-establish response (login / account creation), persist
 * the returned public per-session token. Called from the apiClient once the
 * (sealed) response is opened. No-op for any other route.
 */
export function captureSessionToken(path: string, method: string, body: unknown): void {
  if (!isMemberSessionEstablish(normalizePath(path), method)) return;
  const token =
    body && typeof body === 'object'
      ? (body as Record<string, unknown>).popSessionToken
      : undefined;
  if (typeof token === 'string') setSessionToken('member', token);
}

// --- worker RPC ---------------------------------------------------------------

let worker: Worker | null = null;
let unavailable = false;
let seq = 0;
const pending = new Map<number, (r: WorkerReply) => void>();

interface WorkerReply {
  ok: boolean;
  pubB64?: string;
  alg?: string;
  sigB64?: string;
  ts?: number;
  nonceB64?: string;
  error?: string;
}

function ensureWorker(): Worker | null {
  if (unavailable) return null;
  if (worker) return worker;
  if (typeof Worker === 'undefined') {
    unavailable = true;
    return null;
  }
  try {
    worker = new Worker(new URL('./pop-worker.ts', import.meta.url), { type: 'module' });
    worker.onmessage = (e: MessageEvent) => {
      const data = e.data as WorkerReply & { id: number };
      const resolve = pending.get(data.id);
      if (resolve) {
        pending.delete(data.id);
        resolve(data);
      }
    };
    worker.onerror = () => {
      // A hard worker error fails all in-flight calls soft and disables PoP.
      unavailable = true;
      for (const [, resolve] of pending) resolve({ ok: false, error: 'worker-error' });
      pending.clear();
    };
    return worker;
  } catch {
    unavailable = true;
    return null;
  }
}

function call(msg: Record<string, unknown>): Promise<WorkerReply> {
  const w = ensureWorker();
  if (!w) return Promise.resolve({ ok: false, error: 'no-worker' });
  const id = ++seq;
  return new Promise<WorkerReply>((resolve) => {
    // A signing round-trip is sub-millisecond; this only guards a wedged worker.
    const timer = setTimeout(() => {
      if (pending.delete(id)) resolve({ ok: false, error: 'timeout' });
    }, 4000);
    pending.set(id, (r: WorkerReply) => {
      clearTimeout(timer);
      resolve(r);
    });
    w.postMessage({ id, ...msg });
  });
}

// --- public API ---------------------------------------------------------------

/**
 * Generate the realm's session key if absent and return its base64url raw public
 * point + algorithm ('EdDSA' | 'ES256'), or null if PoP is unavailable.
 */
export async function ensureSessionKey(
  realm: Realm = 'member',
): Promise<{ pub: string; alg: string } | null> {
  const r = await call({ type: 'ensureKey', realm });
  return r.ok && r.pubB64 && r.alg ? { pub: r.pubB64, alg: r.alg } : null;
}

/** Delete the realm's session key + per-session token (logout); next login re-binds. */
export async function clearSessionKey(realm: Realm = 'member'): Promise<void> {
  setSessionToken(realm, null);
  await call({ type: 'clear', realm });
}

/**
 * Boot-warm (pre-`POP_REQUIRED` requirement): spin up the signing worker (so the
 * persisted session key is loaded) and fetch the server-time offset BEFORE the
 * first authenticated request, instead of paying both on its critical path.
 * Call once when a session is known to exist (authenticated). Fire-and-forget;
 * fails soft like everything else here.
 */
export async function prewarm(realm: Realm = 'member'): Promise<void> {
  await Promise.all([ensureSessionKey(realm), serverTimeOffset()]);
}

/**
 * If `path`+`method` establishes a member session (login or account creation),
 * make sure a session key exists and merge its public point into the
 * (about-to-be-sealed) request body. Returns the body string to send (augmented
 * or unchanged). Admin passkey verify is wired separately because it does not
 * flow through apiClient.
 */
export async function augmentLoginBody(
  path: string,
  method: string,
  bodyStr: string | undefined,
): Promise<string | undefined> {
  if (!isMemberSessionEstablish(path, method)) return bodyStr;
  const key = await ensureSessionKey();
  if (!key) return bodyStr;
  return injectPopPub(bodyStr, key.pub, key.alg);
}

/** Merge the PoP public key + algorithm into a JSON body string (used at login). */
export function injectPopPub(bodyStr: string | undefined, pubB64: string, alg: string): string {
  let obj: Record<string, unknown> = {};
  if (bodyStr) {
    try {
      obj = JSON.parse(bodyStr) as Record<string, unknown>;
    } catch {
      obj = {};
    }
  }
  obj[POP_PUBKEY_FIELD] = pubB64;
  obj[POP_ALG_FIELD] = alg;
  return JSON.stringify(obj);
}

// --- server-time offset (Phase 3 clock-skew handling) -------------------------
// Fetched once from /healthz; the worker signs with ts = Date.now() + offset, so
// a device whose clock is off by more than the +/-60s window still lands in it.
// Any failure leaves the offset at 0 (rely on the window). Stable per session.
let _tsOffset = 0;
let _tsFetched = false;
let _tsFetch: Promise<void> | null = null;

async function refreshTimeOffset(): Promise<void> {
  try {
    const t0 = Date.now();
    const res = await fetch('/healthz', { credentials: 'omit' });
    if (!res.ok) return;
    const body = (await res.json()) as { timestamp?: string };
    const serverMs = body.timestamp ? Date.parse(body.timestamp) : NaN;
    if (!Number.isFinite(serverMs)) return;
    const t1 = Date.now();
    _tsOffset = serverMs - (t0 + (t1 - t0) / 2); // server time at round-trip midpoint
  } catch {
    /* keep 0 */
  }
}

async function serverTimeOffset(): Promise<number> {
  if (_tsFetched) return _tsOffset;
  _tsFetch ??= refreshTimeOffset().then(() => {
    _tsFetched = true;
  });
  await _tsFetch;
  return _tsOffset;
}

/**
 * PoP headers for an authenticated request, or null if the route is not
 * eligible or no session key exists (then the request goes unsigned). `wireBody`
 * must be the EXACT body string sent on the wire (post-seal), so the server's
 * bodyHash over the raw bytes matches. `respEph` is the reveal-leg
 * response-ephemeral (the x-fs-resp-eph header value) for GET reveal routes,
 * bound into the v2 message so an active CDN cannot swap it undetected.
 */
export async function signedHeaders(
  path: string,
  method: string,
  wireBody: string | undefined,
  respEph?: string,
): Promise<Record<string, string> | null> {
  if (!signEligible(path, method)) return null;
  const p = normalizePath(path);
  const qIdx = path.indexOf('?');
  const query = qIdx >= 0 ? path.slice(qIdx + 1) : undefined;
  const host = typeof location !== 'undefined' ? location.host : '';
  const r = await call({
    type: 'sign',
    realm: realmForPath(path),
    method: method.toUpperCase(),
    path: p,
    query,
    host,
    respEph: respEph ?? '',
    sessionToken: readSessionToken(realmForPath(path)),
    body: wireBody ?? '',
    tsOffset: await serverTimeOffset(),
  });
  if (!r.ok || !r.sigB64 || r.ts === undefined || !r.nonceB64) return null;
  return {
    [POP_SIG_HEADER]: r.sigB64,
    [POP_TS_HEADER]: String(r.ts),
    [POP_NONCE_HEADER]: r.nonceB64,
    [POP_VERSION_HEADER]: POP_VERSION,
    [POP_HOST_HEADER]: host,
  };
}
