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
  fingerprintB64Url,
  isSealedWire,
  routePolicy,
  SUITE_ID,
  type RoutePolicy,
} from '../../shared/crypto/envelope';
import { clientOpenResponse, clientPrepareRequest } from '../../shared/crypto/channel';
import { deserializePublicKey } from '../../shared/crypto/hpke';
import {
  epochStatement,
  revocationStatement,
  verifyManifest,
  verifyManifestPq,
} from '../../shared/crypto/manifest';
import { markSealedResponse } from './e2ee-status.svelte';

const PK_B64 = import.meta.env.VITE_FS_SERVER_HPKE_PK as string | undefined;
const KID = import.meta.env.VITE_FS_SERVER_HPKE_KID as string | undefined;
const MANIFEST_PK = import.meta.env.VITE_FS_MANIFEST_PK as string | undefined;
const MANIFEST_PK_PQ = import.meta.env.VITE_FS_MANIFEST_PK_PQ as string | undefined;

/**
 * Hybrid manifest verify (Phase 4): Ed25519 is required; ML-DSA-65 is ALSO
 * required when its public key is baked (no downgrade -- a baked PQ key with a
 * missing/invalid PQ signature is rejected). To forge, an attacker must break
 * both, so it holds if either does. Never throws.
 */
function verifyManifestHybrid(
  message: Uint8Array,
  sigB64: string,
  sigPqB64: string | undefined,
): boolean {
  if (!MANIFEST_PK) return false;
  if (!verifyManifest(b64UrlToBytes(MANIFEST_PK), message, b64UrlToBytes(sigB64))) return false;
  if (MANIFEST_PK_PQ) {
    if (!sigPqB64) return false;
    if (!verifyManifestPq(b64UrlToBytes(MANIFEST_PK_PQ), message, b64UrlToBytes(sigPqB64))) {
      return false;
    }
  }
  return true;
}

export function sealingEnabled(): boolean {
  return !!PK_B64 && !!KID;
}

/**
 * The baked public E2EE identity, for the "Verify connection" panel (all
 * base64url strings; the key fields are undefined in a dark build). Non-secret by
 * design — these are the public halves baked into the bundle.
 */
export function e2eePins(): {
  hpkePk?: string;
  hpkeKid?: string;
  manifestPk?: string;
  manifestPkPq?: string;
  suiteId: string;
} {
  return {
    hpkePk: PK_B64,
    hpkeKid: KID,
    manifestPk: MANIFEST_PK,
    manifestPkPq: MANIFEST_PK_PQ,
    suiteId: SUITE_ID,
  };
}

/**
 * Out-of-band-comparable fingerprints of the baked public keys — the SAME values
 * `scripts/e2ee-fingerprint.mjs` publishes (both call `fingerprintB64Url`), so a
 * user can compare what the browser shows against the signed release / .onion
 * mirror. Undefined fields mean that key isn't baked.
 */
export async function connectionFingerprints(): Promise<{
  hpke?: string;
  manifest?: string;
  manifestPq?: string;
}> {
  return {
    hpke: PK_B64 ? await fingerprintB64Url(PK_B64) : undefined,
    manifest: MANIFEST_PK ? await fingerprintB64Url(MANIFEST_PK) : undefined,
    manifestPq: MANIFEST_PK_PQ ? await fingerprintB64Url(MANIFEST_PK_PQ) : undefined,
  };
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
  sigPq?: string;
}) {
  if (!MANIFEST_PK) return;
  // Anti-rollback: never accept a version lower than the last we trusted.
  if (r.version < _revVersion) return;
  const ok = verifyManifestHybrid(
    revocationStatement({ version: r.version, notAfter: r.notAfter, revokedKids: r.revokedKids }),
    r.sig,
    r.sigPq,
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
      epoch?: {
        kid: string;
        publicKey: string;
        notAfter: number;
        sig: string;
        sigPq?: string;
      } | null;
      revocation?: {
        version: number;
        revokedKids: string[];
        notAfter: number;
        sig: string;
        sigPq?: string;
      } | null;
    };
    if (body.revocation) applyRevocation(body.revocation);
    const e = body.epoch;
    if (!e) return;
    const ok = verifyManifestHybrid(
      epochStatement({ kid: e.kid, publicKeyB64: e.publicKey, notAfter: e.notAfter }),
      e.sig,
      e.sigPq,
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

export interface ConnectionAttestation {
  /** The /api/v1/e2ee/keys endpoint responded. */
  reachable: boolean;
  /** The current epoch key verified against the baked manifest key(s), unexpired + not revoked. */
  attested: boolean;
  epochKid?: string;
  notAfter?: number;
  /** The verified revoked-kid list version (anti-rollback), if present. */
  revocationVersion?: number;
}

/**
 * Live, READ-ONLY attestation check for the "Verify connection" panel + the
 * banner's active state: fetch the server-attested epoch key and verify the
 * manifest chain in-browser exactly as the seal path does, but WITHOUT mutating
 * the seal state machine (a pure diagnostic). `attested:false` with
 * `reachable:true` is the tell that a CDN may be tampering with the epoch
 * endpoint. The endpoint is `cache-control: max-age=60`, so this is cheap even
 * alongside the seal path's own fetch. Never throws.
 */
export async function verifyConnection(): Promise<ConnectionAttestation> {
  if (!sealingEnabled() || !MANIFEST_PK) return { reachable: false, attested: false };
  try {
    const res = await fetch('/api/v1/e2ee/keys', { credentials: 'omit' });
    if (!res.ok) return { reachable: false, attested: false };
    const body = (await res.json()) as {
      epoch?: {
        kid: string;
        publicKey: string;
        notAfter: number;
        sig: string;
        sigPq?: string;
      } | null;
      revocation?: {
        version: number;
        revokedKids: string[];
        notAfter: number;
        sig: string;
        sigPq?: string;
      } | null;
    };
    let revocationVersion: number | undefined;
    const r = body.revocation;
    if (
      r &&
      verifyManifestHybrid(
        revocationStatement({
          version: r.version,
          notAfter: r.notAfter,
          revokedKids: r.revokedKids,
        }),
        r.sig,
        r.sigPq,
      )
    ) {
      revocationVersion = r.version;
    }
    const e = body.epoch;
    if (!e) return { reachable: true, attested: false, revocationVersion };
    const attested =
      verifyManifestHybrid(
        epochStatement({ kid: e.kid, publicKeyB64: e.publicKey, notAfter: e.notAfter }),
        e.sig,
        e.sigPq,
      ) &&
      e.notAfter > Date.now() &&
      !isRevoked(e.kid);
    return { reachable: true, attested, epochKid: e.kid, notAfter: e.notAfter, revocationVersion };
  } catch {
    return { reachable: false, attested: false };
  }
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
    const opened = await clientOpenResponse({
      serverKid: KID!,
      method: method.toUpperCase(),
      path,
      respEphPriv: seal.respEphPriv,
      wire: json,
    });
    markSealedResponse(); // a sealed response was actually opened (drives the "active" UI)
    return opened;
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
