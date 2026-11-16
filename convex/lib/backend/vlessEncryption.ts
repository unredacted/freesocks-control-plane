/**
 * VLESS Encryption key material (pure apart from randomness): the layer Xray
 * runs INSIDE a VLESS stream, between the member's app and the node, so
 * whatever carries the stream (a CDN that ends the member's TLS, a relay)
 * sees ciphertext only: no member id, no destination, no payload
 * (docs/backends.md "VLESS Encryption").
 *
 * One method exists, `mlkem768x25519plus`: every session's key exchange is
 * the hybrid of X25519 and ML-KEM-768 whatever the key below is. The key in
 * the string is what the member's app verifies the NODE by, and it comes in
 * two kinds:
 *
 *   ML-KEM-768   a 64-byte seed on the server, a 1184-byte key on the client.
 *                What FCP makes: the node stays verified against an attacker
 *                with a quantum computer.
 *   X25519       a 32-byte private key, a 32-byte public one. Read (a
 *                transport someone else made may use it), never made here.
 *
 * The server string is an inbound's `settings.decryption`, the client string
 * the `encryption` of every entry a member gets for it:
 *
 *   server   mlkem768x25519plus.<mode>.<ticket>[.<padding>...].<key>[.<key>...]
 *   client   mlkem768x25519plus.<mode>.<0rtt|1rtt>[.<padding>...].<key>[.<key>...]
 *
 * The backend derives the client string from the server one on its own and
 * writes it into the bodies it renders; `clientEncryption` is the same
 * derivation, so what FCP expects is what members hold. An inbound that sets
 * a server string refuses every client that does not speak it (measured in
 * Xray's VLESS inbound): a transport is encrypted or plain, never both.
 *
 * The server string is a SECRET (it holds the private half). Made inside the
 * attempt that writes it, never stored, logged or returned over HTTP, exactly
 * like a REALITY private key (realityKeys.ts).
 */
import { x25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

export const VLESS_ENCRYPTION_METHOD = 'mlkem768x25519plus';

/** How the handshake looks on the wire: as it is, with the public key masked, or as random bytes. */
export type VlessEncryptionMode = 'native' | 'xorpub' | 'random';
const MODES: readonly VlessEncryptionMode[] = ['native', 'xorpub', 'random'];

/** What a member's app verifies the node by. */
export type VlessEncryptionKeyKind = 'mlkem768' | 'x25519';

/** What FCP writes: the handshake as it is (the carrier already hides it), 10-minute tickets. */
export const VLESS_ENCRYPTION_DEFAULTS = { mode: 'native', ticket: '600s' } as const;

/** An inbound's VLESS Encryption secret: its `settings.decryption`. */
export interface VlessEncryptionMaterial {
  decryption: string;
}

const X25519_KEY_BYTES = 32;
const MLKEM768_SEED_BYTES = 64;
/** `600s`, or a range the server picks from (`300-600s`); `0s` turns tickets off. */
const TICKET_RE = /^\d{1,6}(?:-\d{1,6})?s$/;
/** `probability-min-max`, of a padding length or of a delay. */
const PADDING_RE = /^\d{1,3}-\d{1,6}-\d{1,6}$/;

function bytesToBase64Url(b: Uint8Array): string {
  let bin = '';
  for (const x of b) bin += String.fromCharCode(x);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Unpadded base64url only, as Xray reads a key block; null for anything else. */
function base64UrlToBytes(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(s)) return null;
  try {
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/** Whether a `settings.decryption` value turns VLESS Encryption on (absent, empty and `none` do not). */
export function isVlessEncrypted(decryption: unknown): boolean {
  return typeof decryption === 'string' && decryption.trim() !== '' && decryption.trim() !== 'none';
}

/** A server string for a new transport: a fresh ML-KEM-768 seed under FCP's defaults. */
export function generateVlessEncryption(
  random: (n: number) => Uint8Array = (n) => crypto.getRandomValues(new Uint8Array(n)),
): VlessEncryptionMaterial {
  const seed = random(MLKEM768_SEED_BYTES);
  if (seed.length !== MLKEM768_SEED_BYTES)
    throw new Error('vless encryption: 64 random bytes expected');
  const { mode, ticket } = VLESS_ENCRYPTION_DEFAULTS;
  return {
    decryption: [VLESS_ENCRYPTION_METHOD, mode, ticket, bytesToBase64Url(seed)].join('.'),
  };
}

interface ServerKey {
  kind: VlessEncryptionKeyKind;
  /** The private half, as read. Never leaves this module. */
  secret: Uint8Array;
}

interface ParsedDecryption {
  mode: VlessEncryptionMode;
  ticket: string;
  padding: string[];
  keys: ServerKey[];
}

/**
 * A server string taken apart, or null when it is not one Xray would run. A
 * block is a key when it decodes to exactly a key's length (a padding block is
 * base64url too, but never 32 or 64 bytes long); padding comes before the
 * first key and nothing but keys after it.
 */
function parseDecryption(decryption: unknown): ParsedDecryption | null {
  if (!isVlessEncrypted(decryption)) return null;
  const [method, mode, ticket, ...rest] = (decryption as string).trim().split('.');
  if (method !== VLESS_ENCRYPTION_METHOD) return null;
  if (!MODES.includes(mode as VlessEncryptionMode)) return null;
  if (!ticket || !TICKET_RE.test(ticket)) return null;
  const padding: string[] = [];
  const keys: ServerKey[] = [];
  for (const block of rest) {
    const bytes = base64UrlToBytes(block);
    const kind: VlessEncryptionKeyKind | null =
      bytes?.length === MLKEM768_SEED_BYTES
        ? 'mlkem768'
        : bytes?.length === X25519_KEY_BYTES
          ? 'x25519'
          : null;
    if (kind) keys.push({ kind, secret: bytes! });
    else if (keys.length === 0 && PADDING_RE.test(block)) padding.push(block);
    else return null;
  }
  if (keys.length === 0) return null;
  return { mode: mode as VlessEncryptionMode, ticket, padding, keys };
}

/** What a server string says about itself, with the client string that belongs to it. All public. */
export interface VlessEncryptionIdentity {
  mode: VlessEncryptionMode;
  /**
   * What the node is verified by: `mlkem768` holds against a quantum computer,
   * `x25519` does not, `mixed` is a chain holding both.
   */
  auth: VlessEncryptionKeyKind | 'mixed';
  /** The `encryption` every member entry of this transport carries. Public by nature. */
  encryption: string;
}

/**
 * The public side of a server string: null when the value is not a usable one
 * (so a caller can tell "plain" from "encrypted but unreadable" with
 * `isVlessEncrypted`). Tickets on means the client resumes (`0rtt`), exactly
 * as the backend writes it.
 */
export function vlessEncryptionIdentity(decryption: unknown): VlessEncryptionIdentity | null {
  const parsed = parseDecryption(decryption);
  if (!parsed) return null;
  const publicKeys: string[] = [];
  try {
    for (const k of parsed.keys)
      publicKeys.push(
        bytesToBase64Url(
          k.kind === 'mlkem768'
            ? ml_kem768.keygen(k.secret).publicKey
            : x25519.getPublicKey(k.secret),
        ),
      );
  } catch {
    return null;
  }
  const kinds = new Set(parsed.keys.map((k) => k.kind));
  return {
    mode: parsed.mode,
    auth: kinds.size > 1 ? 'mixed' : parsed.keys[0]!.kind,
    encryption: [
      VLESS_ENCRYPTION_METHOD,
      parsed.mode,
      /^0+s$/.test(parsed.ticket) ? '1rtt' : '0rtt',
      ...parsed.padding,
      ...publicKeys,
    ].join('.'),
  };
}

/** The client string of a server string, or null (see `vlessEncryptionIdentity`). */
export function clientEncryption(decryption: unknown): string | null {
  return vlessEncryptionIdentity(decryption)?.encryption ?? null;
}

const MLKEM768_CLIENT_KEY_BYTES = 1184;

/**
 * Why FCP's own sessions cannot speak a client string (the front check,
 * lib/edges/frontCheck/vlessEncryption.ts), or null when they can: a string
 * that is not one, the `random` appearance (it masks the whole stream), or a
 * chain of several keys (relays). A transport FCP is to hand out as an
 * encrypted twin has to pass this: FCP proves a twin before members get it.
 */
export type ClientEncryptionProblem = 'unreadable' | 'mode' | 'chain';

export function clientEncryptionProblem(encryption: unknown): ClientEncryptionProblem | null {
  const parsed = parseClientEncryption(encryption);
  if (!parsed) return 'unreadable';
  if (parsed.mode === 'random') return 'mode';
  if (parsed.keys.length !== 1) return 'chain';
  return null;
}

/** A client string taken apart: what a client needs to open a session. All public. */
export interface ParsedClientEncryption {
  mode: VlessEncryptionMode;
  /** `1rtt`: a full handshake every time; `0rtt`: the client may resume a ticket. */
  resume: boolean;
  /** One key verifies the node; more are a chain of relays, each opening its own layer. */
  keys: Array<{ kind: VlessEncryptionKeyKind; publicKey: Uint8Array }>;
}

/**
 * A client string (`encryption`) taken apart, or null when it is not one Xray
 * would take. Padding blocks are the client's own business (how it shapes its
 * first bytes) and are not returned: any padding is valid on the wire.
 */
export function parseClientEncryption(encryption: unknown): ParsedClientEncryption | null {
  if (!isVlessEncrypted(encryption)) return null;
  const [method, mode, rtt, ...rest] = (encryption as string).trim().split('.');
  if (method !== VLESS_ENCRYPTION_METHOD) return null;
  if (!MODES.includes(mode as VlessEncryptionMode)) return null;
  if (rtt !== '0rtt' && rtt !== '1rtt') return null;
  const keys: ParsedClientEncryption['keys'] = [];
  for (const block of rest) {
    const bytes = base64UrlToBytes(block);
    const kind: VlessEncryptionKeyKind | null =
      bytes?.length === MLKEM768_CLIENT_KEY_BYTES
        ? 'mlkem768'
        : bytes?.length === X25519_KEY_BYTES
          ? 'x25519'
          : null;
    if (kind) keys.push({ kind, publicKey: bytes! });
    else if (keys.length > 0 || !PADDING_RE.test(block)) return null;
  }
  if (keys.length === 0) return null;
  return { mode: mode as VlessEncryptionMode, resume: rtt === '0rtt', keys };
}
