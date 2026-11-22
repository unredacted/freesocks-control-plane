/**
 * The key exchange of a TLS 1.3 handshake, read off the wire (pure; no
 * dependencies, so the test harnesses' plain TCP forwarders can load it as one
 * file next to them).
 *
 * A TLS 1.3 Client Hello and Server Hello travel in the clear, REALITY's
 * included (its server answers with a genuine TLS 1.3 Server Hello): the
 * client lists the groups it supports (`supported_groups`) and sends a key
 * share for some of them (`key_share`); the server names the ONE group it
 * picked in its own `key_share`. That pick is the key exchange of the
 * connection. A Hello Retry Request (a Server Hello with a fixed random) asks
 * the client for another share first, and the next Server Hello is the pick.
 *
 * Used by docs/client-compatibility.md § "Post-quantum key exchange": the
 * edge-connection gate's fake L4 edge (docker/edge-connection-test/forwarder.ts)
 * and the REALITY key share harness's tap (docker/compat/hello-tap.ts) record
 * every connection they carry, and the tests read which group each engine
 * ended up with. Never records a key, a session id, a name or anything else
 * from the hellos: the group numbers only.
 */

/** TLS named groups (IANA "TLS Supported Groups"). */
export const GROUPS = {
  secp256r1: 0x0017,
  secp384r1: 0x0018,
  secp521r1: 0x0019,
  x25519: 0x001d,
  x448: 0x001e,
  /** ML-KEM-768 + X25519 hybrid: the post-quantum group browsers and Xray use. */
  X25519MLKEM768: 0x11ec,
  SecP256r1MLKEM768: 0x11eb,
  SecP384r1MLKEM1024: 0x11ed,
  /** The pre-standard draft Kyber hybrid (Chrome 124 to 130). */
  X25519Kyber768Draft00: 0x6399,
} as const;

/** The groups that make a key exchange post-quantum (a hybrid with ML-KEM or Kyber). */
export const PQ_GROUPS: ReadonlySet<number> = new Set([
  GROUPS.X25519MLKEM768,
  GROUPS.SecP256r1MLKEM768,
  GROUPS.SecP384r1MLKEM1024,
  GROUPS.X25519Kyber768Draft00,
]);

const NAMES = new Map<number, string>(Object.entries(GROUPS).map(([k, v]) => [v, k]));

/** RFC 8701 GREASE values (0x0a0a, 0x1a1a, ... 0xfafa): placeholders, never a real group. */
export const isGrease = (g: number) => (g & 0x0f0f) === 0x0a0a && g >> 8 === (g & 0xff);

/** A group's name, `GREASE` for a GREASE value, its hex otherwise. */
export function groupName(g: number): string {
  if (isGrease(g)) return 'GREASE';
  return NAMES.get(g) ?? `0x${g.toString(16).padStart(4, '0')}`;
}

export interface ClientHelloGroups {
  /** `supported_groups`, in the client's order, GREASE removed. */
  supportedGroups: number[];
  /** The groups of the `key_share` entries, in order, GREASE removed. */
  keyShares: number[];
}

export interface ServerHelloGroup {
  /** The group of the server's `key_share` (a Hello Retry Request names the one it asks for). */
  group: number | null;
  /** A Hello Retry Request (asks for another key share), not the pick. */
  helloRetry: boolean;
  /** From `supported_versions`: 0x0304 for TLS 1.3, null when absent (TLS 1.2 or older). */
  version: number | null;
}

/** SHA-256 of "HelloRetryRequest" (RFC 8446 §4.1.3): the random of a Hello Retry Request. */
const HRR_RANDOM = [
  0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
  0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

const EXT_SUPPORTED_GROUPS = 10;
const EXT_SUPPORTED_VERSIONS = 43;
const EXT_KEY_SHARE = 51;

/** A bounds-checked reader: any read past the end throws, and the caller treats it as "not a hello". */
class Reader {
  constructor(
    private readonly b: Uint8Array,
    private o = 0,
    private readonly end = b.length,
  ) {}
  get left() {
    return this.end - this.o;
  }
  private need(n: number) {
    if (n < 0 || this.o + n > this.end) throw new RangeError('truncated');
  }
  u8() {
    this.need(1);
    return this.b[this.o++]!;
  }
  u16() {
    this.need(2);
    const v = (this.b[this.o]! << 8) | this.b[this.o + 1]!;
    this.o += 2;
    return v;
  }
  bytes(n: number) {
    this.need(n);
    const v = this.b.subarray(this.o, this.o + n);
    this.o += n;
    return v;
  }
  /** A sub-reader over the next `n` bytes (a length-prefixed vector). */
  sub(n: number) {
    this.need(n);
    const r = new Reader(this.b, this.o, this.o + n);
    this.o += n;
    return r;
  }
}

/** Each extension's type and body, in order. */
function extensions(r: Reader): Array<{ type: number; body: Reader }> {
  if (r.left === 0) return [];
  const all = r.sub(r.u16());
  const out: Array<{ type: number; body: Reader }> = [];
  while (all.left > 0) {
    const type = all.u16();
    out.push({ type, body: all.sub(all.u16()) });
  }
  return out;
}

/** The groups of a Client Hello BODY (after the 4-byte handshake header); null if it is not one. */
export function parseClientHello(body: Uint8Array): ClientHelloGroups | null {
  try {
    const r = new Reader(body);
    r.u16(); // legacy_version
    r.bytes(32); // random
    r.bytes(r.u8()); // legacy_session_id
    r.bytes(r.u16()); // cipher_suites
    r.bytes(r.u8()); // legacy_compression_methods
    const out: ClientHelloGroups = { supportedGroups: [], keyShares: [] };
    for (const ext of extensions(r)) {
      if (ext.type === EXT_SUPPORTED_GROUPS) {
        const list = ext.body.sub(ext.body.u16());
        while (list.left > 0) out.supportedGroups.push(list.u16());
      } else if (ext.type === EXT_KEY_SHARE) {
        const list = ext.body.sub(ext.body.u16());
        while (list.left > 0) {
          out.keyShares.push(list.u16());
          list.bytes(list.u16());
        }
      }
    }
    out.supportedGroups = out.supportedGroups.filter((g) => !isGrease(g));
    out.keyShares = out.keyShares.filter((g) => !isGrease(g));
    return out;
  } catch {
    return null;
  }
}

/** The pick of a Server Hello BODY (after the 4-byte handshake header); null if it is not one. */
export function parseServerHello(body: Uint8Array): ServerHelloGroup | null {
  try {
    const r = new Reader(body);
    r.u16(); // legacy_version
    const random = r.bytes(32);
    r.bytes(r.u8()); // legacy_session_id_echo
    r.u16(); // cipher_suite
    r.u8(); // legacy_compression_method
    const helloRetry = HRR_RANDOM.every((v, i) => random[i] === v);
    const out: ServerHelloGroup = { group: null, helloRetry, version: null };
    for (const ext of extensions(r)) {
      // A Server Hello's (and a Hello Retry Request's) key_share starts with the group.
      if (ext.type === EXT_KEY_SHARE) out.group = ext.body.u16();
      else if (ext.type === EXT_SUPPORTED_VERSIONS) out.version = ext.body.u16();
    }
    return out;
  } catch {
    return null;
  }
}

const RECORD_HANDSHAKE = 22;
const RECORD_CHANGE_CIPHER_SPEC = 20;
const HS_CLIENT_HELLO = 1;
const HS_SERVER_HELLO = 2;
/** Enough for any hello (a post-quantum Client Hello is about 1.8 KB); past it nothing is read. */
const MAX_BUFFER = 64 * 1024;

/**
 * One direction of a connection, fed the bytes as they pass: reassembles TLS
 * records and the handshake messages inside them, and hands each Client or
 * Server Hello to `onHello`. Stops reading (and holds nothing) at the first
 * record that is neither a handshake nor a Change Cipher Spec, which in TLS
 * 1.3 is where the encrypted part starts, or when the bytes are not TLS.
 */
export class HelloStream {
  private records: Uint8Array = new Uint8Array(0);
  private handshake: Uint8Array = new Uint8Array(0);
  private done = false;

  constructor(private readonly onHello: (type: 1 | 2, body: Uint8Array) => void) {}

  push(chunk: Uint8Array): void {
    if (this.done) return;
    this.records = concat(this.records, chunk);
    if (this.records.length > MAX_BUFFER) return this.stop();
    while (this.records.length >= 5) {
      const type = this.records[0]!;
      const len = (this.records[3]! << 8) | this.records[4]!;
      if (type !== RECORD_HANDSHAKE && type !== RECORD_CHANGE_CIPHER_SPEC) return this.stop();
      if (this.records[1] !== 3) return this.stop();
      if (this.records.length < 5 + len) return;
      const fragment = this.records.subarray(5, 5 + len);
      this.records = this.records.slice(5 + len);
      if (type === RECORD_HANDSHAKE) this.handshakeBytes(fragment);
      if (this.done) return;
    }
  }

  private handshakeBytes(fragment: Uint8Array) {
    this.handshake = concat(this.handshake, fragment);
    while (this.handshake.length >= 4) {
      const msgType = this.handshake[0]!;
      const len = (this.handshake[1]! << 16) | (this.handshake[2]! << 8) | this.handshake[3]!;
      if (this.handshake.length < 4 + len) return;
      const body = this.handshake.slice(4, 4 + len);
      this.handshake = this.handshake.slice(4 + len);
      if (msgType === HS_CLIENT_HELLO || msgType === HS_SERVER_HELLO) this.onHello(msgType, body);
      // Anything after a TLS 1.3 Server Hello is encrypted; a TLS 1.2 server's
      // later messages are not hellos either.
      else return this.stop();
    }
  }

  private stop() {
    this.done = true;
    this.records = new Uint8Array(0);
    this.handshake = new Uint8Array(0);
  }
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length === 0) return b.slice();
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

/** What one connection's handshake said about its key exchange. */
export interface HelloObservation {
  /** Every Client Hello (a second one follows a Hello Retry Request). */
  clientHellos: ClientHelloGroups[];
  /** Every Server Hello, Hello Retry Requests included. */
  serverHellos: ServerHelloGroup[];
}

/** Both directions of one connection, observed into one record. */
export function observeConnection(): {
  observation: HelloObservation;
  fromClient: HelloStream;
  fromServer: HelloStream;
} {
  const observation: HelloObservation = { clientHellos: [], serverHellos: [] };
  const fromClient = new HelloStream((type, body) => {
    const ch = type === HS_CLIENT_HELLO ? parseClientHello(body) : null;
    if (ch) observation.clientHellos.push(ch);
  });
  const fromServer = new HelloStream((type, body) => {
    const sh = type === HS_SERVER_HELLO ? parseServerHello(body) : null;
    if (sh) observation.serverHellos.push(sh);
  });
  return { observation, fromClient, fromServer };
}

/** The group the connection's key exchange used: the last Server Hello that is not a retry request. */
export function negotiatedGroup(o: HelloObservation): number | null {
  const pick = o.serverHellos.filter((s) => !s.helloRetry).at(-1);
  return pick?.group ?? null;
}

/** One connection's key exchange in words, for a test's assertions and failure messages. */
export function describeObservation(o: HelloObservation): {
  offered: string[];
  shares: string[];
  negotiated: string | null;
  helloRetry: boolean;
  tls13: boolean;
} {
  const first = o.clientHellos[0];
  const pick = o.serverHellos.filter((s) => !s.helloRetry).at(-1);
  return {
    offered: (first?.supportedGroups ?? []).map(groupName),
    shares: (first?.keyShares ?? []).map(groupName),
    negotiated: pick?.group == null ? null : groupName(pick.group),
    helloRetry: o.serverHellos.some((s) => s.helloRetry),
    tls13: pick?.version === 0x0304,
  };
}
