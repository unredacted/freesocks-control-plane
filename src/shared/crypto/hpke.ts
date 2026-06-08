/**
 * HPKE (RFC 9180) seal/open over the post-quantum hybrid KEM X-Wing
 * (X25519 + ML-KEM-768), via @hpke/core + @hpke/hybridkem-x-wing. The audited
 * library is used unforked.
 *
 * RUNTIME: this module performs the HPKE key schedule, which needs subtle HKDF.
 * The Convex DEFAULT V8 isolate does NOT implement subtle HKDF, so on the server
 * this runs ONLY inside the "use node" action (convex/lib/e2eeCrypto.ts). In the
 * browser it runs natively (full WebCrypto). Never import this from an isolate
 * query/mutation/httpAction; import ./envelope.ts there instead.
 *
 * The server static private key is stored and reconstructed as a 32-byte X-Wing
 * SEED (generateKeyPairDerand), never a separately cached expanded ML-KEM key
 * (see docs/e2ee-phase0-spike.md and the X-Wing draft binding caveat).
 */
import { CipherSuite, HkdfSha256 } from '@hpke/core';
import { XWing } from '@hpke/hybridkem-x-wing';
import { Chacha20Poly1305 } from '@hpke/chacha20poly1305';
import { SUITE_ID } from './envelope';

export { SUITE_ID };

/** Label for the OHTTP-style response key derived from the request context (P1). */
export const RESPONSE_EXPORT_LABEL = 'fcp/response/v1';

let _kem: XWing | null = null;
let _suite: CipherSuite | null = null;

function kem(): XWing {
  return (_kem ??= new XWing());
}

/** Lazily construct the single pinned suite (no negotiation). */
export function suite(): CipherSuite {
  return (_suite ??= new CipherSuite({
    kem: kem(),
    kdf: new HkdfSha256(),
    aead: new Chacha20Poly1305(),
  }));
}

const u8 = (b: ArrayBuffer | Uint8Array): Uint8Array =>
  b instanceof Uint8Array ? b : new Uint8Array(b);

// --- keys ---------------------------------------------------------------------

/** Reconstruct the server keypair deterministically from its 32-byte seed. */
export function serverKeyPairFromSeed(seed: Uint8Array): Promise<CryptoKeyPair> {
  if (seed.length !== 32) throw new Error('X-Wing server seed must be 32 bytes');
  return kem().generateKeyPairDerand(seed);
}

/** A fresh per-request ephemeral keypair (used by the client and the reveal leg). */
export function generateEphemeralKeyPair(): Promise<CryptoKeyPair> {
  return kem().generateKeyPair();
}

export async function serializePublicKey(pk: CryptoKey): Promise<Uint8Array> {
  return u8(await kem().serializePublicKey(pk));
}

export function deserializePublicKey(bytes: Uint8Array): Promise<CryptoKey> {
  return kem().deserializePublicKey(bytes as unknown as ArrayBuffer);
}

// --- single-shot seal / open --------------------------------------------------
// Each call creates a context, performs exactly one operation, and drops it
// (the single-use discipline that avoids the concurrent-seal nonce-reuse class).

export interface Sealed {
  enc: Uint8Array;
  ct: Uint8Array;
}

/** Seal `pt` to a recipient public key (static server key, or an ephemeral for the reveal leg). */
export async function sealTo(
  recipientPublicKey: CryptoKey,
  info: Uint8Array,
  aad: Uint8Array,
  pt: Uint8Array,
): Promise<Sealed> {
  const sender = await suite().createSenderContext({
    recipientPublicKey,
    info: info as unknown as ArrayBuffer,
  });
  const ct = u8(await sender.seal(pt as unknown as ArrayBuffer, aad as unknown as ArrayBuffer));
  return { enc: u8(sender.enc), ct };
}

/** Open a single-shot sealed ciphertext with the recipient private key. */
export async function openFrom(
  recipientKey: CryptoKey,
  enc: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  ct: Uint8Array,
): Promise<Uint8Array> {
  const recipient = await suite().createRecipientContext({
    recipientKey,
    enc: enc as unknown as ArrayBuffer,
    info: info as unknown as ArrayBuffer,
  });
  return u8(await recipient.open(ct as unknown as ArrayBuffer, aad as unknown as ArrayBuffer));
}
