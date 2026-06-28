/**
 * Proof-of-possession signing Worker (CDN-blinding Phase 2). Owns the session's
 * NON-EXTRACTABLE ECDSA P-256 private key. The key is generated here, persisted
 * in IndexedDB (so it survives a reload without forcing re-login), and used only
 * to sign canonical requests; it can never be read out (non-extractable) and is
 * never posted to the main thread, so neither page script nor the CDN ever sees
 * the private scalar. The Worker exposes only three operations and validates the
 * request path against an allowlist, so a compromised main thread cannot turn it
 * into a general-purpose signing oracle.
 *
 * Bundled by Vite as a same-origin module Worker (the `new URL(..., import.meta.url)`
 * form, NOT a `blob:`), so the strict CSP `worker-src 'self'` allows it.
 *
 * Keys are scoped by `realm` ('member' | 'admin') so the two trust levels never
 * share a key: a member logout cannot break a concurrent admin session, and a
 * captured member context cannot sign admin requests.
 *
 * Messages (each carries an `id` echoed back):
 *   { type:'ensureKey', realm }                       -> { ok, pubB64 }   (generate if absent)
 *   { type:'sign', realm, method, path, query, body } -> { ok, sigB64, ts, nonceB64 }
 *   { type:'clear', realm }                           -> { ok }           (logout)
 */
import { bytesToB64Url } from '../../shared/crypto/envelope';
import { buildPopMessage, digestB64Url, signP1363 } from '../../shared/crypto/pop';

// Worker globals, typed narrowly so this file compiles under the project's DOM
// lib (the webworker lib is not enabled, and pulling it in would clash on `self`).
const ctx = self as unknown as {
  postMessage: (m: unknown) => void;
  addEventListener: (t: 'message', cb: (e: MessageEvent) => void) => void;
};

const DB_NAME = 'fcp-pop';
const STORE = 'keys';

type Realm = 'member' | 'admin';
function keyId(realm: Realm): string {
  return `session:${realm === 'admin' ? 'admin' : 'member'}`;
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function loadKeyPair(realm: Realm): Promise<CryptoKeyPair | null> {
  const db = await openDb();
  try {
    return await new Promise<CryptoKeyPair | null>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly');
      const req = tx.objectStore(STORE).get(keyId(realm));
      req.onsuccess = () => resolve((req.result as CryptoKeyPair | undefined) ?? null);
      req.onerror = () => reject(req.error);
    });
  } finally {
    db.close();
  }
}

async function storeKeyPair(realm: Realm, kp: CryptoKeyPair): Promise<void> {
  const db = await openDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      // A CryptoKeyPair is structured-cloneable, including a non-extractable
      // private key (the clone preserves non-extractability).
      tx.objectStore(STORE).put(
        { privateKey: kp.privateKey, publicKey: kp.publicKey },
        keyId(realm),
      );
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

async function deleteKeyPair(realm: Realm): Promise<void> {
  const db = await openDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.objectStore(STORE).delete(keyId(realm));
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

/** Only ever sign requests to our own API surface (oracle-scope limiter). */
function pathAllowed(path: string): boolean {
  return typeof path === 'string' && path.startsWith('/api/');
}

async function ensureKey(realm: Realm): Promise<string> {
  let kp = await loadKeyPair(realm);
  if (!kp) {
    kp = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;
    await storeKeyPair(realm, kp);
  }
  const pubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  return bytesToB64Url(pubRaw);
}

interface SignMsg {
  realm: Realm;
  method: string;
  path: string;
  query?: string;
  body?: string;
  /** The host to bind (location.host). */
  host?: string;
  /** The reveal-leg response-ephemeral (x-fs-resp-eph value), if any. */
  respEph?: string;
  /** The public per-session token (fs_pop_sid cookie value), '' if none yet. */
  sessionToken?: string;
  /** Server-time offset (serverTime - localTime) so a skewed client signs in-window. */
  tsOffset?: number;
}

async function sign(
  msg: SignMsg,
): Promise<{ sigB64: string; ts: number; nonceB64: string } | { error: string }> {
  if (!pathAllowed(msg.path)) return { error: 'path' };
  const kp = await loadKeyPair(msg.realm);
  if (!kp) return { error: 'no-key' };
  const ts = Date.now() + (msg.tsOffset ?? 0);
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const nonceB64 = bytesToB64Url(nonce);
  const bodyHashB64 = await digestB64Url(new TextEncoder().encode(msg.body ?? ''));
  const message = buildPopMessage({
    method: msg.method,
    path: msg.path,
    query: msg.query,
    host: msg.host,
    respEph: msg.respEph,
    sessionToken: msg.sessionToken ?? '',
    bodyHashB64,
    ts,
    nonceB64,
  });
  const sig = await signP1363(kp.privateKey, message);
  return { sigB64: bytesToB64Url(sig), ts, nonceB64 };
}

ctx.addEventListener('message', (e: MessageEvent) => {
  const data = e.data as { id: number; type: string } & SignMsg;
  const realm: Realm = data.realm === 'admin' ? 'admin' : 'member';
  void (async () => {
    try {
      if (data.type === 'ensureKey') {
        ctx.postMessage({ id: data.id, ok: true, pubB64: await ensureKey(realm) });
      } else if (data.type === 'sign') {
        const r = await sign({ ...data, realm });
        if ('error' in r) ctx.postMessage({ id: data.id, ok: false, error: r.error });
        else ctx.postMessage({ id: data.id, ok: true, ...r });
      } else if (data.type === 'clear') {
        await deleteKeyPair(realm);
        ctx.postMessage({ id: data.id, ok: true });
      } else {
        ctx.postMessage({ id: data.id, ok: false, error: 'unknown' });
      }
    } catch (err) {
      ctx.postMessage({ id: data.id, ok: false, error: String(err) });
    }
  })();
});
