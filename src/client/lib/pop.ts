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
  POP_NONCE_HEADER,
  POP_PUBKEY_FIELD,
  POP_SIG_HEADER,
  POP_TS_HEADER,
  POP_VERSION,
  POP_VERSION_HEADER,
} from '../../shared/crypto/pop';

/** Keys are scoped so member and admin never share one (see pop-worker.ts). */
export type Realm = 'member' | 'admin';

/** Member login + admin passkey verify establish a session key and post the pubkey. */
const MEMBER_LOGIN_PATH = '/api/v1/auth/account-login';

/** Admin resources live under these prefixes; everything else authenticated is a member route. */
function realmForPath(path: string): Realm {
  const p = normalizePath(path);
  return p.startsWith('/api/v1/admin/') || p.startsWith('/api/admin/') ? 'admin' : 'member';
}

/** Paths that must NOT be PoP-signed: the auth ceremonies (no session yet) + logout. */
function signEligible(path: string): boolean {
  const p = normalizePath(path);
  if (p === MEMBER_LOGIN_PATH || p === '/api/v1/auth/logout') return false;
  if (p.startsWith('/api/admin/auth/')) return false;
  return p.startsWith('/api/');
}

// --- worker RPC ---------------------------------------------------------------

let worker: Worker | null = null;
let unavailable = false;
let seq = 0;
const pending = new Map<number, (r: WorkerReply) => void>();

interface WorkerReply {
  ok: boolean;
  pubB64?: string;
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

/** Generate the realm's session key if absent and return its base64url raw public point. */
export async function ensureSessionKey(realm: Realm = 'member'): Promise<string | null> {
  const r = await call({ type: 'ensureKey', realm });
  return r.ok && r.pubB64 ? r.pubB64 : null;
}

/** Delete the realm's session key (logout), so the next login binds a fresh one. */
export async function clearSessionKey(realm: Realm = 'member'): Promise<void> {
  await call({ type: 'clear', realm });
}

/**
 * If `path` establishes a session (member login), make sure a session key
 * exists and merge its public point into the (about-to-be-sealed) request body.
 * Returns the body string to send (augmented or unchanged). Admin passkey verify
 * is wired separately because it does not flow through apiClient.
 */
export async function augmentLoginBody(
  path: string,
  bodyStr: string | undefined,
): Promise<string | undefined> {
  if (normalizePath(path) !== MEMBER_LOGIN_PATH) return bodyStr;
  const pub = await ensureSessionKey();
  if (!pub) return bodyStr;
  return injectPopPub(bodyStr, pub);
}

/** Merge the PoP public key into a JSON body string (used at login). */
export function injectPopPub(bodyStr: string | undefined, pubB64: string): string {
  let obj: Record<string, unknown> = {};
  if (bodyStr) {
    try {
      obj = JSON.parse(bodyStr) as Record<string, unknown>;
    } catch {
      obj = {};
    }
  }
  obj[POP_PUBKEY_FIELD] = pubB64;
  return JSON.stringify(obj);
}

/**
 * PoP headers for an authenticated request, or null if the route is not
 * eligible or no session key exists (then the request goes unsigned). `wireBody`
 * must be the EXACT body string sent on the wire (post-seal), so the server's
 * bodyHash over the raw bytes matches.
 */
export async function signedHeaders(
  path: string,
  method: string,
  wireBody: string | undefined,
): Promise<Record<string, string> | null> {
  if (!signEligible(path)) return null;
  const p = normalizePath(path);
  const qIdx = path.indexOf('?');
  const query = qIdx >= 0 ? path.slice(qIdx + 1) : undefined;
  const r = await call({
    type: 'sign',
    realm: realmForPath(path),
    method: method.toUpperCase(),
    path: p,
    query,
    body: wireBody ?? '',
  });
  if (!r.ok || !r.sigB64 || r.ts === undefined || !r.nonceB64) return null;
  return {
    [POP_SIG_HEADER]: r.sigB64,
    [POP_TS_HEADER]: String(r.ts),
    [POP_NONCE_HEADER]: r.nonceB64,
    [POP_VERSION_HEADER]: POP_VERSION,
  };
}
