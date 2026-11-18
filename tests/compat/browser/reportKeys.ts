import { bytesToB64Url, kidFromPublicKey } from '../../../src/shared/crypto/envelope';
import { serializePublicKey, serverKeyPairFromSeed } from '../../../src/shared/crypto/hpke';

/** The fixture origin and Playwright derive the same test key; only its public pin goes into Vite. */
export async function reportKeys() {
  const pair = await serverKeyPairFromSeed(new Uint8Array(32).fill(9));
  const raw = await serializePublicKey(pair.publicKey);
  return {
    privateKey: pair.privateKey,
    publicPin: bytesToB64Url(raw),
    kid: await kidFromPublicKey(raw),
  };
}
