/**
 * TEST ONLY: the node's side of a VLESS Encryption session, for the offline
 * tests of the front check (vlessEncryption.test.ts, session.test.ts). It
 * follows Xray-core's server (`proxy/vless/encryption/server.go`) for one key
 * and a full handshake, and shares the sealing primitives with the client, so
 * what it proves is the client's state machine and its failure codes. That the
 * bytes are the ones real Xray speaks is proved by
 * frontCheck.integration.test.ts against the pinned Xray-core.
 */
import { randomBytes as nodeRandomBytes } from 'node:crypto';
import { x25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { Aead, MAX_NONCE, concat, length16, xorStream } from './vlessEncryption';

const TAG = 16;

function fromBase64Url(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64url'));
}

export class FakeEncryptedNode {
  private readonly mode: string;
  private readonly secret: Uint8Array;
  private readonly kind: 'mlkem768' | 'x25519';
  private readonly publicKey: Uint8Array;
  private buf: Uint8Array = new Uint8Array(0);
  private stage: 'hello' | 'padding-length' | 'padding' | 'records' = 'hello';
  private nfs: Aead | null = null;
  private out: Aead | null = null;
  private peer: Aead | null = null;
  private paddingLength = 0;
  /** Set when a client's bytes did not open: the node hangs up, as Xray does. */
  refused = false;

  constructor(decryption: string) {
    const blocks = decryption.split('.');
    this.mode = blocks[1]!;
    this.secret = fromBase64Url(blocks[blocks.length - 1]!);
    this.kind = this.secret.length === 64 ? 'mlkem768' : 'x25519';
    this.publicKey =
      this.kind === 'mlkem768'
        ? ml_kem768.keygen(this.secret).publicKey
        : x25519.getPublicKey(this.secret);
  }

  private take(n: number): Uint8Array | null {
    if (this.buf.length < n) return null;
    const head = this.buf.subarray(0, n);
    this.buf = this.buf.subarray(n);
    return head;
  }

  /** What the client sent: bytes to send back, and the plain bytes it carried. */
  receive(chunk: Uint8Array): { send: Uint8Array[]; plain: Uint8Array[] } {
    const send: Uint8Array[] = [];
    const plain: Uint8Array[] = [];
    if (this.refused) return { send, plain };
    this.buf = concat(this.buf, chunk);
    try {
      for (;;) {
        if (this.stage === 'hello') {
          const relayLength = this.kind === 'mlkem768' ? 1088 : 32;
          const need = 16 + relayLength + (2 + TAG) + (1184 + 32 + TAG);
          if (this.buf.length < need) break;
          const iv = this.take(16)!;
          let relay = this.take(relayLength)!;
          if (this.mode === 'xorpub') relay = xorStream(this.publicKey, iv, relay);
          const nfsKey =
            this.kind === 'mlkem768'
              ? ml_kem768.decapsulate(relay, ml_kem768.keygen(this.secret).secretKey)
              : x25519.getSharedSecret(this.secret, relay);
          this.nfs = new Aead(iv, nfsKey);
          this.nfs.open(this.take(2 + TAG)!);
          const clientShare = this.nfs.open(this.take(1184 + 32 + TAG)!);
          const kem = ml_kem768.encapsulate(clientShare.subarray(0, 1184));
          const dh = x25519.keygen();
          const dhKey = x25519.getSharedSecret(dh.secretKey, clientShare.subarray(1184));
          const united = concat(kem.sharedSecret, dhKey, nfsKey);
          const serverShare = concat(kem.cipherText, dh.publicKey);
          this.out = new Aead(serverShare, united);
          this.peer = new Aead(clientShare, united);
          const padding = 111 + (nodeRandomBytes(1)[0]! % 200);
          send.push(
            concat(
              this.nfs.seal(serverShare, undefined, MAX_NONCE),
              this.out.seal(new Uint8Array(16)),
              this.out.seal(length16(padding - 2 - TAG)),
              this.out.seal(new Uint8Array(padding - 2 - TAG - TAG)),
            ),
          );
          this.stage = 'padding-length';
        } else if (this.stage === 'padding-length') {
          const sealed = this.take(2 + TAG);
          if (!sealed) break;
          const l = this.nfs!.open(sealed);
          this.paddingLength = (l[0]! << 8) | l[1]!;
          this.stage = 'padding';
        } else if (this.stage === 'padding') {
          const sealed = this.take(this.paddingLength);
          if (!sealed) break;
          this.nfs!.open(sealed);
          this.stage = 'records';
        } else {
          if (this.buf.length < 5) break;
          const l = (this.buf[3]! << 8) | this.buf[4]!;
          if (this.buf.length < 5 + l) break;
          const header = this.take(5)!;
          plain.push(this.peer!.open(this.take(l)!, header));
        }
      }
    } catch {
      this.refused = true;
    }
    return { send, plain };
  }

  seal(data: Uint8Array): Uint8Array {
    const l = data.length + TAG;
    const header = Uint8Array.of(23, 3, 3, (l >> 8) & 0xff, l & 0xff);
    return concat(header, this.out!.seal(data, header));
  }
}
