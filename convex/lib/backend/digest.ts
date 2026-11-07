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
 *    public one), the short ids and the client version / clock bounds. On an
 *    ENROLLED node it is the intent's `authRevision`: a change is drift (a
 *    live node closes under maintenance), it binds the direct test link and
 *    the rehearsal vector, and it is folded into each L4 endpoint
 *    confirmation's binding (lib/edges/verification.ts), so changing any of
 *    them returns the node's endpoints to "needs a test". An unmanaged node's
 *    confirmations do not carry it.
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
import { certificatePins } from './hysteriaCert';

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

/**
 * The authentication identity of one Hysteria 2 inbound: what a member's
 * client verifies (the certificate's two pins, the server name it presents,
 * the ALPN) and whether Salamander wraps the packets. All public except the
 * Salamander password, which is only hashed into `digest`.
 */
export interface HysteriaAuth {
  /** Keyed digest over everything below plus the Salamander password; null without a readable certificate. */
  digest: string | null;
  /** SHA-256 of the certificate DER, lowercase hex (Xray, Hysteria, Mihomo pins). */
  pinHex: string | null;
  /** SHA-256 of the SubjectPublicKeyInfo DER, base64 (sing-box's pin). */
  spkiB64: string | null;
  serverName: string | null;
  alpn: string[];
  /** Salamander obfuscation is on. */
  obfs: boolean;
}

/**
 * The Hysteria identity of an inbound's `streamSettings` (`tlsSettings` with
 * an inline certificate, `finalmask.udp` with Salamander). The digest moves on
 * a new certificate, server name, ALPN, Salamander on/off or a new Salamander
 * password: every change a member's copied config would stop matching.
 */
export async function hysteriaAuthDigest(
  streamSettings: unknown,
  key: string,
): Promise<HysteriaAuth> {
  const ss = isObj(streamSettings) ? streamSettings : {};
  const tls = isObj(ss.tlsSettings) ? ss.tlsSettings : {};
  const certs = Array.isArray(tls.certificates) ? tls.certificates : [];
  const first = certs.find(isObj);
  const lines = first?.certificate;
  const pins =
    Array.isArray(lines) && lines.every((l) => typeof l === 'string')
      ? certificatePins(lines as string[])
      : typeof lines === 'string'
        ? certificatePins(lines)
        : null;
  const serverName =
    typeof tls.serverName === 'string' && tls.serverName.trim()
      ? tls.serverName.trim().toLowerCase()
      : null;
  const alpn = (Array.isArray(tls.alpn) ? tls.alpn : []).filter(
    (a): a is string => typeof a === 'string',
  );
  const fm = isObj(ss.finalmask) ? ss.finalmask : {};
  const salamander = (Array.isArray(fm.udp) ? fm.udp : []).find(
    (u) => isObj(u) && u.type === 'salamander',
  );
  const password =
    isObj(salamander) &&
    isObj(salamander.settings) &&
    typeof salamander.settings.password === 'string'
      ? salamander.settings.password
      : null;
  const obfs = !!salamander;
  if (!pins) return { digest: null, pinHex: null, spkiB64: null, serverName, alpn, obfs };
  const material = canonicalJson({
    pinHex: pins.pinHex,
    spkiB64: pins.spkiB64,
    serverName,
    alpn,
    obfs: password ? await sha256Hex(password) : obfs,
  });
  return {
    digest: await hmacSha256Hex(key, `fcp.panel.hysteria-auth.v1\n${material}`),
    pinHex: pins.pinHex,
    spkiB64: pins.spkiB64,
    serverName,
    alpn,
    obfs,
  };
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
