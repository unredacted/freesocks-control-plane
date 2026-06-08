/**
 * Client-side CDN-blinding seam. Seals outbound requests and opens sealed
 * responses per the route policy, using the server public key + kid baked into
 * the bundle at build (VITE_FS_SERVER_HPKE_PK / VITE_FS_SERVER_HPKE_KID).
 *
 * Gated on the pinned key being present: a build without it leaves sealing off
 * and every request goes plaintext (the server's dual-mode handles that), so the
 * SPA still works in environments where the key was not baked.
 *
 * The HPKE crypto here runs in the browser, which has full WebCrypto including
 * HKDF, so importing ./hpke (via channel) is fine on the client.
 */
import {
  b64UrlToBytes,
  isSealedWire,
  routePolicy,
  type RoutePolicy,
} from '../../shared/crypto/envelope';
import { clientOpenResponse, clientPrepareRequest } from '../../shared/crypto/channel';
import { deserializePublicKey } from '../../shared/crypto/hpke';
import { epochStatement, revocationStatement, verifyManifest } from '../../shared/crypto/manifest';

const PK_B64 = import.meta.env.VITE_FS_SERVER_HPKE_PK as string | undefined;
const KID = import.meta.env.VITE_FS_SERVER_HPKE_KID as string | undefined;
const MANIFEST_PK = import.meta.env.VITE_FS_MANIFEST_PK as string | undefined;

export function sealingEnabled(): boolean {
  return !!PK_B64 && !!KID;
}

let _serverPub: Promise<CryptoKey> | null = null;
function serverPub(): Promise<CryptoKey> {
  return (_serverPub ??= deserializePublicKey(b64UrlToBytes(PK_B64!)));
}

// --- epoch keys (Phase 3): seal the login to a short-lived, manifest-signed key
// instead of the multi-day static key, so a later server-key compromise cannot
// decrypt a logged login. Verified against the baked manifest public key; ANY
// failure (no manifest key, network error, bad signature, expired) falls back to
// the static key, preserving dual-mode and never trusting an unverified key.

interface EpochKey {
  kid: string;
  pub: CryptoKey;
  notAfter: number;
}
let _epoch: EpochKey | null = null;
let _epochFetch: Promise<void> | null = null;
/** Stop using an epoch this long before its notAfter (clock skew + in-flight margin). */
const EPOCH_MARGIN_MS = 30_000;

// --- revoked-kid list (Phase 3c): a manifest-signed, monotonic-versioned list
// of compromised kids. Persisted so it survives reload and applies before the
// first fetch; a CDN cannot roll it back to a lower version. The client refuses
// to seal the login to a revoked kid (fail closed rather than leak plaintext).
const REV_STORAGE_KEY = 'fs_e2ee_revocation';
let _revVersion = -1;
let _revokedKids = new Set<string>();

(function loadPersistedRevocation() {
  try {
    const raw = localStorage.getItem(REV_STORAGE_KEY);
    if (!raw) return;
    const s = JSON.parse(raw) as { version: number; revokedKids: string[] };
    if (typeof s.version === 'number' && Array.isArray(s.revokedKids)) {
      _revVersion = s.version;
      _revokedKids = new Set(s.revokedKids);
    }
  } catch {
    /* no/unreadable storage */
  }
})();

function isRevoked(kid: string): boolean {
  return _revokedKids.has(kid);
}

function applyRevocation(r: {
  version: number;
  revokedKids: string[];
  notAfter: number;
  sig: string;
}) {
  if (!MANIFEST_PK) return;
  // Anti-rollback: never accept a version lower than the last we trusted.
  if (r.version < _revVersion) return;
  const ok = verifyManifest(
    b64UrlToBytes(MANIFEST_PK),
    revocationStatement({ version: r.version, notAfter: r.notAfter, revokedKids: r.revokedKids }),
    b64UrlToBytes(r.sig),
  );
  if (!ok) return; // tampered -> keep the persisted list (still fail-closed on known kids)
  _revVersion = r.version;
  _revokedKids = new Set(r.revokedKids);
  try {
    localStorage.setItem(
      REV_STORAGE_KEY,
      JSON.stringify({ version: r.version, revokedKids: r.revokedKids }),
    );
  } catch {
    /* storage unavailable */
  }
}

async function refreshEpoch(): Promise<void> {
  if (!MANIFEST_PK) return;
  try {
    const res = await fetch('/api/v1/e2ee/keys', { credentials: 'omit' });
    if (!res.ok) return;
    const body = (await res.json()) as {
      epoch?: { kid: string; publicKey: string; notAfter: number; sig: string } | null;
      revocation?: { version: number; revokedKids: string[]; notAfter: number; sig: string } | null;
    };
    if (body.revocation) applyRevocation(body.revocation);
    const e = body.epoch;
    if (!e) return;
    const ok = verifyManifest(
      b64UrlToBytes(MANIFEST_PK),
      epochStatement({ kid: e.kid, publicKeyB64: e.publicKey, notAfter: e.notAfter }),
      b64UrlToBytes(e.sig),
    );
    // Ignore a tampered, expired, or revoked epoch key -> fall back to static.
    if (!ok || e.notAfter <= Date.now() || isRevoked(e.kid)) return;
    _epoch = {
      kid: e.kid,
      pub: await deserializePublicKey(b64UrlToBytes(e.publicKey)),
      notAfter: e.notAfter,
    };
  } catch {
    // network/parse error -> keep whatever we have (or none); fall back to static.
  }
}

/** The current verified epoch key, or null to fall back to the static key. */
async function currentEpoch(): Promise<{ kid: string; pub: CryptoKey } | null> {
  const fresh = () =>
    _epoch && _epoch.notAfter - EPOCH_MARGIN_MS > Date.now() && !isRevoked(_epoch.kid)
      ? _epoch
      : null;
  if (fresh()) return { kid: _epoch!.kid, pub: _epoch!.pub };
  _epochFetch ??= refreshEpoch().finally(() => {
    _epochFetch = null;
  });
  await _epochFetch;
  const e = fresh();
  return e ? { kid: e.kid, pub: e.pub } : null;
}

export interface OutboundSeal {
  policy: RoutePolicy;
  /** Replacement request body string (sealed envelope, or plain JSON carrying fsRespEph). */
  body?: string;
  /** Header to add (GET reveal routes carry the ephemeral pubkey in a header). */
  header?: { name: string; value: string };
  /** Kept to open a reveal-leg response. */
  respEphPriv?: CryptoKey;
}

/** Prepare a sealed outbound request, or undefined if the route is not sealed (then send plaintext). */
export async function prepareOutbound(
  path: string,
  method: string,
  bodyStr: string | undefined,
): Promise<OutboundSeal | undefined> {
  if (!sealingEnabled()) return undefined;
  const policy = routePolicy(path);
  if (!policy) return undefined;
  const m = method.toUpperCase();
  // Seal target: for a request-seal route (login) prefer the current epoch key;
  // the reveal leg ignores serverPub/serverKid here (it seals the response to a
  // client ephemeral and opens with the static KID), so static is fine there.
  let sealPub = await serverPub();
  let sealKid = KID!;
  if (policy.request === 'seal') {
    const ep = await currentEpoch();
    if (ep) {
      sealPub = ep.pub;
      sealKid = ep.kid;
    }
    // Fail closed: if even the chosen seal target is revoked (e.g. the static key
    // is compromised and no valid epoch key is available), refuse to send the
    // login rather than leak the account number in plaintext.
    if (isRevoked(sealKid)) throw new Error('fcp_e2ee_seal_key_revoked');
  }
  const prep = await clientPrepareRequest({
    serverPub: sealPub,
    serverKid: sealKid,
    method: m,
    path,
    policy,
    bodyObj: bodyStr ? safeParse(bodyStr) : undefined,
  });
  const out: OutboundSeal = { policy, respEphPriv: prep.respEphPriv };
  if (policy.request === 'seal') {
    out.body = JSON.stringify(prep.body);
  } else if (policy.response === 'reveal') {
    if (m === 'GET' || m === 'HEAD') {
      out.header = { name: 'x-fs-resp-eph', value: prep.respEphPubB64! };
    } else {
      out.body = JSON.stringify(prep.body);
    }
  }
  return out;
}

/** Open a sealed reveal-leg response; pass through anything that is not sealed. */
export async function openInbound(
  seal: OutboundSeal,
  path: string,
  method: string,
  json: unknown,
): Promise<unknown> {
  if (seal.policy.response === 'reveal' && seal.respEphPriv && isSealedWire(json)) {
    return clientOpenResponse({
      serverKid: KID!,
      method: method.toUpperCase(),
      path,
      respEphPriv: seal.respEphPriv,
      wire: json,
    });
  }
  return json;
}

function safeParse(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return undefined;
  }
}
