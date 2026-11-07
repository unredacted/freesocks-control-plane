/**
 * The Hysteria 2 transport's certificate (pure apart from randomness): a
 * self-signed ECDSA P-256 certificate for one server name, and the two pins a
 * client verifies it by.
 *
 * Hysteria's password is the member's VLESS id, so a client that does not
 * verify the server would hand that credential to anyone in the path. Members
 * verify ONLY by pin (docs/privacy.md §5c), never by a CA:
 *
 *   pinHex   SHA-256 of the certificate DER, lowercase hex. Xray's
 *            `pinnedPeerCertSha256`, Hysteria's `pinSHA256` and Mihomo's
 *            `fingerprint` all take this value.
 *   spkiB64  SHA-256 of the SubjectPublicKeyInfo DER, standard base64.
 *            sing-box's `certificate_public_key_sha256` takes this one. It is
 *            a different digest: neither is ever derived from the other.
 *
 * Generated inside the setup action right before the profile write, like a
 * REALITY key (realityKeys.ts): the private key exists only in the backend's
 * config profile and is never persisted, logged or returned by FCP. The
 * certificate is public; FCP reads its pins back from the observed profile
 * (`hysteriaAuthOf`).
 *
 * The encoder writes exactly the DER this one certificate shape needs; the
 * reader walks only as far as the public key.
 */
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  generateObfsPassword,
  type HysteriaMaterial,
  type ModeTemplateInput,
} from './profileTemplate';

/** About ten years: a member's copied raw config keeps working that long. */
export const HYSTERIA_CERT_DAYS = 3650;

// --- DER -------------------------------------------------------------------------------------------

function len(n: number): number[] {
  if (n < 0x80) return [n];
  const out: number[] = [];
  for (let x = n; x > 0; x >>= 8) out.unshift(x & 0xff);
  return [0x80 | out.length, ...out];
}
function tlv(tag: number, body: Uint8Array | number[]): Uint8Array {
  const b = body instanceof Uint8Array ? body : Uint8Array.from(body);
  const head = [tag, ...len(b.length)];
  const out = new Uint8Array(head.length + b.length);
  out.set(head, 0);
  out.set(b, head.length);
  return out;
}
function cat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
const seq = (...parts: Uint8Array[]) => tlv(0x30, cat(...parts));
const set = (...parts: Uint8Array[]) => tlv(0x31, cat(...parts));
function oid(dotted: string): Uint8Array {
  const [a, b, ...rest] = dotted.split('.').map(Number);
  const out = [a! * 40 + b!];
  for (const n of rest) {
    const chunk: number[] = [];
    let x = n;
    do {
      chunk.unshift(x & 0x7f);
      x = Math.floor(x / 128);
    } while (x > 0);
    for (let i = 0; i < chunk.length - 1; i++) chunk[i]! |= 0x80;
    out.push(...chunk);
  }
  return tlv(0x06, out);
}
/** A non-negative INTEGER from big-endian bytes (a 0x00 pad keeps it positive). */
function uint(bytes: Uint8Array): Uint8Array {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  const b = bytes.slice(i);
  return tlv(0x02, b[0]! & 0x80 ? cat(Uint8Array.of(0), b) : b);
}
const utf8 = (s: string) => tlv(0x0c, new TextEncoder().encode(s));
function utcTime(d: Date): Uint8Array {
  const p = (n: number) => String(n).padStart(2, '0');
  const s = `${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(
    d.getUTCHours(),
  )}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return tlv(0x17, new TextEncoder().encode(s));
}

const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';
const OID_P256 = '1.2.840.10045.3.1.7';
const OID_ECDSA_SHA256 = '1.2.840.10045.4.3.2';
const OID_CN = '2.5.4.3';
const OID_SAN = '2.5.29.17';
const OID_BASIC_CONSTRAINTS = '2.5.29.19';
const OID_KEY_USAGE = '2.5.29.15';
const OID_EXT_KEY_USAGE = '2.5.29.37';
const OID_SERVER_AUTH = '1.3.6.1.5.5.7.3.1';

function pem(label: string, der: Uint8Array): string[] {
  let bin = '';
  for (const x of der) bin += String.fromCharCode(x);
  const b64 = btoa(bin);
  const lines = [`-----BEGIN ${label}-----`];
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  lines.push(`-----END ${label}-----`);
  return lines;
}

function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}
function b64(b: Uint8Array): string {
  let bin = '';
  for (const x of b) bin += String.fromCharCode(x);
  return btoa(bin);
}

// --- generation ------------------------------------------------------------------------------------

export interface HysteriaCertificate {
  /** PEM lines, as Xray's inline `certificate: [...]` takes them. */
  certificate: string[];
  /** PEM lines of the SEC1 private key, as Xray's inline `key: [...]` takes them. */
  key: string[];
  pinHex: string;
  spkiB64: string;
}

const HOSTNAME_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$/;

export function generateHysteriaCertificate(
  serverName: string,
  opts: {
    now?: Date;
    random?: (n: number) => Uint8Array;
  } = {},
): HysteriaCertificate {
  const name = serverName.trim().toLowerCase();
  if (!HOSTNAME_RE.test(name)) throw new Error('hysteria certificate: server name');
  const random = opts.random ?? ((n: number) => crypto.getRandomValues(new Uint8Array(n)));
  const now = opts.now ?? new Date();
  // A random secret key in [1, n-1] (noble rejects out-of-range keys).
  let sk: Uint8Array;
  do sk = random(32);
  while (!p256.utils.isValidSecretKey(sk));
  const pub = p256.getPublicKey(sk, false);

  const spki = seq(
    seq(oid(OID_EC_PUBLIC_KEY), oid(OID_P256)),
    tlv(0x03, cat(Uint8Array.of(0), pub)),
  );
  const dn = seq(set(seq(oid(OID_CN), utf8(name))));
  // Backdated an hour so a client clock a little behind still accepts it.
  const notBefore = new Date(now.getTime() - 3_600_000);
  const notAfter = new Date(now.getTime() + HYSTERIA_CERT_DAYS * 86_400_000);
  const serial = random(16);
  serial[0]! &= 0x7f;
  const extensions = tlv(
    0xa3,
    seq(
      // CA:false, critical.
      seq(oid(OID_BASIC_CONSTRAINTS), tlv(0x01, [0xff]), tlv(0x04, seq())),
      // digitalSignature, critical.
      seq(oid(OID_KEY_USAGE), tlv(0x01, [0xff]), tlv(0x04, tlv(0x03, [0x07, 0x80]))),
      seq(oid(OID_EXT_KEY_USAGE), tlv(0x04, seq(oid(OID_SERVER_AUTH)))),
      seq(oid(OID_SAN), tlv(0x04, seq(tlv(0x82, new TextEncoder().encode(name))))),
    ),
  );
  const sigAlg = seq(oid(OID_ECDSA_SHA256));
  const tbs = seq(
    tlv(0xa0, uint(Uint8Array.of(2))),
    uint(serial),
    sigAlg,
    dn,
    seq(utcTime(notBefore), utcTime(notAfter)),
    dn,
    spki,
    extensions,
  );
  const sig = p256.sign(tbs, sk, { prehash: true, format: 'der' });
  const cert = seq(tbs, sigAlg, tlv(0x03, cat(Uint8Array.of(0), sig)));
  // SEC1 ECPrivateKey: version 1, the key, the curve, the public key.
  const ecKey = seq(
    uint(Uint8Array.of(1)),
    tlv(0x04, sk),
    tlv(0xa0, oid(OID_P256)),
    tlv(0xa1, tlv(0x03, cat(Uint8Array.of(0), pub))),
  );
  return {
    certificate: pem('CERTIFICATE', cert),
    key: pem('EC PRIVATE KEY', ecKey),
    pinHex: hex(sha256(cert)),
    spkiB64: b64(sha256(spki)),
  };
}

/**
 * Fresh material for every Hysteria mode in `modes`: a certificate for its
 * server name and, when Salamander is on, a password. Made inside the attempt
 * right before the profile write; never stored.
 */
export function hysteriaMaterialFor(
  modes: readonly ModeTemplateInput[],
): Record<string, HysteriaMaterial> {
  const out: Record<string, HysteriaMaterial> = {};
  for (const m of modes) {
    if (m.shape.transport !== 'hysteria' || !('hysteria' in m)) continue;
    const cert = generateHysteriaCertificate(m.hysteria.serverName);
    out[m.slug] = {
      certificate: cert.certificate,
      key: cert.key,
      ...(m.hysteria.salamander ? { obfsPassword: generateObfsPassword() } : {}),
    };
  }
  return out;
}

// --- reading ---------------------------------------------------------------------------------------

/** DER of the first PEM CERTIFICATE block in `lines` (Xray's inline form or one string), or null. */
export function certificateDer(lines: readonly string[] | string): Uint8Array | null {
  const text = Array.isArray(lines) ? lines.join('\n') : (lines as string);
  const m = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/.exec(text);
  if (!m) return null;
  try {
    const bin = atob(m[1]!.replace(/\s+/g, ''));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

/** One TLV at `o`: its tag, where its body starts and ends, and where the TLV ends. */
function readTlv(d: Uint8Array, o: number): { tag: number; start: number; end: number } | null {
  if (o + 2 > d.length) return null;
  const tag = d[o]!;
  let l = d[o + 1]!;
  let start = o + 2;
  if (l & 0x80) {
    const n = l & 0x7f;
    if (n === 0 || n > 4 || start + n > d.length) return null;
    l = 0;
    for (let i = 0; i < n; i++) l = l * 256 + d[start + i]!;
    start += n;
  }
  const end = start + l;
  return end > d.length ? null : { tag, start, end };
}

/** The SubjectPublicKeyInfo TLV of a certificate, or null when it is not one. */
export function spkiOf(cert: Uint8Array): Uint8Array | null {
  const c = readTlv(cert, 0);
  if (!c || c.tag !== 0x30) return null;
  const tbs = readTlv(cert, c.start);
  if (!tbs || tbs.tag !== 0x30) return null;
  let o = tbs.start;
  let first = readTlv(cert, o);
  if (first?.tag === 0xa0) o = first.end; // [0] version
  // serial, signature, issuer, validity, subject: skip five.
  for (let i = 0; i < 5; i++) {
    first = readTlv(cert, o);
    if (!first) return null;
    o = first.end;
  }
  const spki = readTlv(cert, o);
  if (!spki || spki.tag !== 0x30) return null;
  return cert.slice(o, spki.end);
}

/** The two pins of a certificate in PEM (lines or text), or null when it cannot be read. */
export function certificatePins(
  lines: readonly string[] | string,
): { pinHex: string; spkiB64: string } | null {
  const der = certificateDer(lines);
  if (!der) return null;
  const spki = spkiOf(der);
  if (!spki) return null;
  return { pinHex: hex(sha256(der)), spkiB64: b64(sha256(spki)) };
}

/**
 * A pin as clients write it, normalized for comparison: lowercase hex without
 * `:` or `-` separators (Hysteria and Xray accept either form).
 */
export function normalizePinHex(pin: string): string {
  return pin.trim().toLowerCase().replace(/[:-]/g, '');
}
