'use node';
/**
 * The client side of VLESS Encryption (`mlkem768x25519plus`), as far as the
 * front check needs it: one full handshake, then sealed records both ways.
 * It lets the check authenticate through an encrypted transport exactly as a
 * member's app does, so a passing proof says the same thing it says for a
 * plain one (docs/backends.md "VLESS Encryption").
 *
 * Written from Xray-core's own implementation (`proxy/vless/encryption`,
 * v26.7.28, the version the node image runs) and proved against that version
 * in the front-check integration test. The wire, for ONE key and a full
 * handshake:
 *
 *   client hello   iv(16)
 *                  relay: an ML-KEM-768 ciphertext (1088) to the node's key,
 *                         or an ephemeral X25519 public key (32)
 *                  sealed length(18) + sealed session key share(1184+32+16):
 *                         a fresh ML-KEM-768 key and a fresh X25519 key
 *                  sealed length(18) + sealed padding
 *   server hello   sealed session key share(1088+32+16)
 *                  sealed ticket(32), sealed length(18), sealed padding
 *   records        header(5: 23 3 3 len) + sealed data, the header as
 *                  associated data
 *
 * The hello is sealed under the key only the node's holder can derive (so the
 * node is verified, and a carrier in the middle cannot answer), the records
 * under that key joined with both fresh shares (so a session cannot be read
 * later, whatever happens to the node's key). Every seal uses a counter nonce
 * that is stepped BEFORE use; keys come from BLAKE3's key derivation with the
 * context the peer can also compute.
 *
 * Not done here, and reported as unsupported instead: tickets (a check never
 * resumes), the `random` appearance (it masks the whole stream) and a chain of
 * several keys (relays).
 */
import { createCipheriv, createDecipheriv } from 'node:crypto';
import { x25519 } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { clientEncryptionProblem, parseClientEncryption } from '../../backend/vlessEncryption';

const TAG = 16;
const SEALED_LENGTH = 2 + TAG;
const MLKEM_CIPHERTEXT = 1088;
const MLKEM_PUBLIC = 1184;
const X25519_KEY = 32;
const SERVER_SHARE = MLKEM_CIPHERTEXT + X25519_KEY + TAG;
const SEALED_TICKET = 16 + TAG;
const RECORD_HEADER = 5;
/** Xray never writes more than this in one record; neither do we. */
const MAX_RECORD_DATA = 8192;
/** The largest record body a peer may announce (a TLS 1.3 record's bound). */
const MAX_RECORD_BODY = 16640;
export const MAX_NONCE = new Uint8Array(12).fill(0xff);

/** Why a client string cannot be spoken by this client; `null` when it can. */
export type EncryptionRefusal = 'unreadable' | 'mode' | 'chain';

export function encryptionRefusal(encryption: string): EncryptionRefusal | null {
  return clientEncryptionProblem(encryption);
}

/** The handshake or a record did not open: the peer does not hold the node's key, or spoke something else. */
export class EncryptionError extends Error {
  constructor(readonly reason: 'handshake' | 'record') {
    super(`vless encryption: ${reason}`);
  }
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export const length16 = (n: number) => Uint8Array.of((n >> 8) & 0xff, n & 0xff);

/** AES-256-GCM under a BLAKE3-derived key, with Xray's counter nonce (stepped before each use). */
export class Aead {
  private readonly key: Uint8Array;
  private readonly nonce = new Uint8Array(12);
  constructor(context: Uint8Array, secret: Uint8Array) {
    this.key = blake3(secret, { context, dkLen: 32 });
  }
  private next(): Uint8Array {
    for (let i = 11; i >= 0; i--) {
      this.nonce[i] = (this.nonce[i]! + 1) & 0xff;
      if (this.nonce[i] !== 0) break;
    }
    return this.nonce;
  }
  seal(plain: Uint8Array, aad?: Uint8Array, nonce?: Uint8Array): Uint8Array {
    const c = createCipheriv('aes-256-gcm', this.key, nonce ?? this.next());
    if (aad) c.setAAD(aad);
    return concat(c.update(plain), c.final(), c.getAuthTag());
  }
  open(sealed: Uint8Array, aad?: Uint8Array, nonce?: Uint8Array): Uint8Array {
    if (sealed.length < TAG) throw new EncryptionError('record');
    const d = createDecipheriv('aes-256-gcm', this.key, nonce ?? this.next());
    if (aad) d.setAAD(aad);
    d.setAuthTag(sealed.subarray(sealed.length - TAG));
    return concat(d.update(sealed.subarray(0, sealed.length - TAG)), d.final());
  }
}

/** Xray's `NewCTR`: AES-256-CTR under a key derived with the context `VLESS`. */
export function xorStream(secret: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
  const key = blake3(secret, { context: new TextEncoder().encode('VLESS'), dkLen: 32 });
  const c = createCipheriv('aes-256-ctr', key, iv);
  return concat(c.update(data), c.final());
}

export interface EncryptionDeps {
  randomBytes: (n: number) => Uint8Array;
}

/**
 * One session. `hello()` gives the bytes to send first; `receive()` takes
 * whatever the peer sent and returns the plain bytes it carried (none until
 * the handshake is through); `seal()` wraps plain bytes once `ready`.
 */
export class VlessEncryptionSession {
  private readonly nfs: Aead;
  private readonly helloBytes: Uint8Array;
  private readonly sessionSecret: Uint8Array;
  private readonly x25519Secret: Uint8Array;
  private readonly clientShare: Uint8Array;
  private readonly nfsKey: Uint8Array;
  private out: Aead | null = null;
  private peer: Aead | null = null;
  private buf: Uint8Array = new Uint8Array(0);
  private stage: 'share' | 'ticket' | 'length' | 'padding' | 'records' = 'share';
  private paddingLength = 0;

  constructor(encryption: string, deps: EncryptionDeps) {
    const parsed = parseClientEncryption(encryption);
    if (!parsed || encryptionRefusal(encryption)) throw new Error('vless encryption: unsupported');
    const node = parsed.keys[0]!;
    const iv = deps.randomBytes(16);

    // The share only the node's key can open: this is what verifies the node.
    let relay: Uint8Array;
    if (node.kind === 'mlkem768') {
      const { cipherText, sharedSecret } = ml_kem768.encapsulate(node.publicKey);
      relay = cipherText;
      this.nfsKey = sharedSecret;
    } else {
      const { secretKey, publicKey } = x25519.keygen();
      relay = publicKey;
      this.nfsKey = x25519.getSharedSecret(secretKey, node.publicKey);
    }
    // `xorpub` masks that share with a stream anyone holding the client string can undo.
    if (parsed.mode === 'xorpub') relay = xorStream(node.publicKey, iv, relay);
    this.nfs = new Aead(iv, this.nfsKey);

    // Fresh shares for this session alone.
    const kem = ml_kem768.keygen();
    const dh = x25519.keygen();
    this.sessionSecret = kem.secretKey;
    this.x25519Secret = dh.secretKey;
    this.clientShare = concat(kem.publicKey, dh.publicKey);

    // Padding as Xray's default first block shapes it: 111 to 1111 bytes, sealed.
    const r = deps.randomBytes(2);
    const padding = 111 + (((r[0]! << 8) | r[1]!) % 1001);
    this.helloBytes = concat(
      iv,
      relay,
      this.nfs.seal(length16(MLKEM_PUBLIC + X25519_KEY + TAG)),
      this.nfs.seal(this.clientShare),
      this.nfs.seal(length16(padding - SEALED_LENGTH)),
      this.nfs.seal(new Uint8Array(padding - SEALED_LENGTH - TAG)),
    );
  }

  hello(): Uint8Array {
    return this.helloBytes;
  }

  get ready(): boolean {
    return this.stage === 'records';
  }

  private take(n: number): Uint8Array | null {
    if (this.buf.length < n) return null;
    const head = this.buf.subarray(0, n);
    this.buf = this.buf.subarray(n);
    return head;
  }

  /** Plain bytes out of what the peer sent. Throws `EncryptionError` when something does not open. */
  receive(chunk: Uint8Array): Uint8Array[] {
    this.buf = this.buf.length === 0 ? chunk : concat(this.buf, chunk);
    const plain: Uint8Array[] = [];
    for (;;) {
      if (this.stage === 'share') {
        const sealed = this.take(SERVER_SHARE);
        if (!sealed) break;
        let share: Uint8Array;
        try {
          // The one seal with a fixed nonce: the server answers under the hello's key.
          share = this.nfs.open(sealed, undefined, MAX_NONCE);
        } catch {
          throw new EncryptionError('handshake');
        }
        let kemKey: Uint8Array;
        let dhKey: Uint8Array;
        try {
          kemKey = ml_kem768.decapsulate(share.subarray(0, MLKEM_CIPHERTEXT), this.sessionSecret);
          dhKey = x25519.getSharedSecret(this.x25519Secret, share.subarray(MLKEM_CIPHERTEXT));
        } catch {
          throw new EncryptionError('handshake');
        }
        const united = concat(kemKey, dhKey, this.nfsKey);
        this.out = new Aead(this.clientShare, united);
        this.peer = new Aead(share, united);
        this.stage = 'ticket';
      } else if (this.stage === 'ticket') {
        const sealed = this.take(SEALED_TICKET);
        if (!sealed) break;
        this.open(sealed, 'handshake');
        this.stage = 'length';
      } else if (this.stage === 'length') {
        const sealed = this.take(SEALED_LENGTH);
        if (!sealed) break;
        const l = this.open(sealed, 'handshake');
        this.paddingLength = (l[0]! << 8) | l[1]!;
        this.stage = 'padding';
      } else if (this.stage === 'padding') {
        const sealed = this.take(this.paddingLength);
        if (!sealed) break;
        this.open(sealed, 'handshake');
        this.stage = 'records';
      } else {
        if (this.buf.length < RECORD_HEADER) break;
        const h = this.buf.subarray(0, RECORD_HEADER);
        const l = (h[3]! << 8) | h[4]!;
        if (h[0] !== 23 || h[1] !== 3 || h[2] !== 3 || l < TAG + 1 || l > MAX_RECORD_BODY)
          throw new EncryptionError('record');
        if (this.buf.length < RECORD_HEADER + l) break;
        const header = this.take(RECORD_HEADER)!;
        plain.push(this.open(this.take(l)!, 'record', header));
      }
    }
    return plain;
  }

  private open(sealed: Uint8Array, reason: 'handshake' | 'record', aad?: Uint8Array): Uint8Array {
    try {
      return this.peer!.open(sealed, aad);
    } catch {
      throw new EncryptionError(reason);
    }
  }

  /** Records carrying `data`. Only once `ready`. */
  seal(data: Uint8Array): Uint8Array {
    if (!this.out || !this.ready) throw new Error('vless encryption: not ready');
    const records: Uint8Array[] = [];
    for (let at = 0; at < data.length; at += MAX_RECORD_DATA) {
      const part = data.subarray(at, at + MAX_RECORD_DATA);
      const l = part.length + TAG;
      const header = Uint8Array.of(23, 3, 3, (l >> 8) & 0xff, l & 0xff);
      records.push(header, this.out.seal(part, header));
    }
    return concat(...records);
  }
}
