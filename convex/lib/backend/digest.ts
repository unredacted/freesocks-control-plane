/**
 * Digests of a backend config profile (pure; WebCrypto only, so it runs in the
 * default runtime). A config profile carries the REALITY private key, the short
 * ids and the client list. FCP never persists those values, yet it must be able
 * to tell that a profile CHANGED, and that what it changed is what it meant to.
 * Three digests answer three different questions:
 *
 *  - `shapeHash`: a plain SHA-256 over the REDACTED config. Safe to store and
 *    show; it drives diffs and "this profile looks different". It is blind to a
 *    change that touches only secrets (a key rotation hashes the same).
 *  - `changeToken`: a KEYED digest over the COMPLETE config, secrets included,
 *    so a key or short-id rotation moves it too. This is the token a write is
 *    conditioned on and verified against. Keyed so the stored value is not a
 *    hash an attacker with the database could test guesses against (short ids
 *    are low-entropy).
 *  - `realityAuthDigest`: a keyed digest over exactly the settings that decide
 *    whether a REALITY client that connected yesterday still connects today:
 *    the key pair (derived from the PRIVATE key, never trusted from a stored
 *    public one), the short ids and the client version / clock bounds. It
 *    joins an endpoint confirmation's binding, so changing any of them
 *    correctly returns the endpoint to "needs a test".
 *
 * The backend NORMALISES a config on write (measured, docs/backends.md
 * "Management contract"): it trims each `serverNames` entry and clears
 * `settings.clients`. `normalizeForToken` applies the same two rules, so a
 * token computed from what FCP is about to send equals the token of what the
 * backend then stores. It does nothing else: the backend neither lowercases nor
 * de-duplicates names.
 *
 * None of these functions log, throw with a value, or return key material.
 */
import { x25519 } from '@noble/curves/ed25519.js';
import { hmacSha256Hex, sha256Hex } from '../crypto';

/** What replaces a secret leaf in the redacted view. */
export const REDACTED = '[redacted]';

/** Keys whose VALUE is secret wherever they appear in an Xray config. */
const SECRET_KEYS = new Set([
  'privatekey',
  'shortids',
  'shortid',
  'mldsa65seed',
  'certificates',
  'certificate',
  'key',
  'keyfile',
  'password',
  'pass',
  'secret',
  'clients',
  'users',
  'accounts',
  'psk',
  'seed',
  'auth',
]);
/** A belt over the list: anything that names itself a secret is treated as one. */
const SECRET_KEY_RE = /(private|secret|passw|token|seed|credential)/i;

export function isSecretKey(key: string): boolean {
  return SECRET_KEYS.has(key.toLowerCase()) || SECRET_KEY_RE.test(key);
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === 'object' && !Array.isArray(v);

/** Deterministic JSON: object keys sorted, so jsonb key reordering never moves a digest. */
export function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  if (isObj(v)) {
    return `{${Object.keys(v)
      .filter((k) => v[k] !== undefined)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(v ?? null);
}

/**
 * The config with every secret leaf replaced by a marker. An empty secret
 * stays visibly empty (`[]` / `''`): "no clients" and "no short ids" are facts
 * an operator may see, the values are not.
 */
export function redactConfig(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(redactConfig);
  if (!isObj(v)) return v;
  const out: Record<string, unknown> = {};
  for (const [k, val] of Object.entries(v)) {
    if (!isSecretKey(k)) out[k] = redactConfig(val);
    else if (Array.isArray(val)) out[k] = val.length === 0 ? [] : REDACTED;
    else out[k] = val === '' || val === null || val === undefined ? val : REDACTED;
  }
  return out;
}

/** Apply exactly the backend's own write-time normalisation (see the header). */
export function normalizeForToken(config: unknown): unknown {
  if (!isObj(config)) return config;
  const inbounds = Array.isArray(config.inbounds) ? config.inbounds : null;
  if (!inbounds) return config;
  return {
    ...config,
    inbounds: inbounds.map((ib) => {
      if (!isObj(ib)) return ib;
      const next: Record<string, unknown> = { ...ib };
      if (isObj(ib.settings) && 'clients' in ib.settings)
        next.settings = { ...ib.settings, clients: [] };
      const stream = ib.streamSettings;
      if (isObj(stream) && isObj(stream.realitySettings)) {
        const rs = stream.realitySettings;
        if (Array.isArray(rs.serverNames))
          next.streamSettings = {
            ...stream,
            realitySettings: {
              ...rs,
              serverNames: rs.serverNames.map((n) => (typeof n === 'string' ? n.trim() : n)),
            },
          };
      }
      return next;
    }),
  };
}

/** Storable, showable: SHA-256 over the redacted, normalised config. */
export function shapeHash(config: unknown): Promise<string> {
  return sha256Hex(canonicalJson(redactConfig(normalizeForToken(config))));
}

/** The write-conditioning token: keyed, over the complete normalised config. */
export function changeToken(config: unknown, key: string): Promise<string> {
  return hmacSha256Hex(key, `fcp.panel.change.v1\n${canonicalJson(normalizeForToken(config))}`);
}

function base64UrlToBytes(s: string): Uint8Array | null {
  const b64 = s.trim().replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) return null;
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function bytesToBase64Url(b: Uint8Array): string {
  let bin = '';
  for (const x of b) bin += String.fromCharCode(x);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** The X25519 public key for a REALITY private key (base64url, 32 bytes); null when malformed. */
export function realityPublicKey(privateKey: unknown): string | null {
  if (typeof privateKey !== 'string') return null;
  const sk = base64UrlToBytes(privateKey);
  if (!sk || sk.length !== 32) return null;
  try {
    return bytesToBase64Url(x25519.getPublicKey(sk));
  } catch {
    return null;
  }
}

export interface RealityAuth {
  /** Keyed digest of the authentication-relevant settings; null when the private key is unusable. */
  digest: string | null;
  /** The public key derived from the private one. Public by nature: it is in every share link. */
  publicKey: string | null;
  /** A stored `publicKey` that does NOT belong to the private key (clients holding it cannot connect). */
  publicKeyMismatch: boolean;
}

/**
 * The authentication identity of one REALITY transport. `realitySettings` is the
 * raw object; nothing of it is returned except the derived PUBLIC key.
 */
export async function realityAuthDigest(
  realitySettings: unknown,
  key: string,
): Promise<RealityAuth> {
  const rs = isObj(realitySettings) ? realitySettings : {};
  const publicKey = realityPublicKey(rs.privateKey);
  if (!publicKey) return { digest: null, publicKey: null, publicKeyMismatch: false };
  const stored = typeof rs.publicKey === 'string' ? rs.publicKey.trim() : '';
  const shortIds = (Array.isArray(rs.shortIds) ? rs.shortIds : [])
    .filter((s): s is string => typeof s === 'string')
    .map((s) => s.trim().toLowerCase())
    .sort();
  // A further authentication seed is hashed in, never carried: only whether
  // and what it is can matter, and its digest says both.
  const seed = typeof rs.mldsa65Seed === 'string' && rs.mldsa65Seed ? rs.mldsa65Seed : null;
  const material = canonicalJson({
    publicKey,
    shortIds,
    minClientVer: rs.minClientVer ?? null,
    maxClientVer: rs.maxClientVer ?? null,
    maxTimeDiff: rs.maxTimeDiff ?? null,
    mldsa65: seed ? await sha256Hex(seed) : null,
  });
  return {
    digest: await hmacSha256Hex(key, `fcp.panel.reality-auth.v1\n${material}`),
    publicKey,
    publicKeyMismatch: stored !== '' && stored !== publicKey,
  };
}
