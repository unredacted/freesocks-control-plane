// @vitest-environment node
import { describe, expect, test } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToB64Url } from './envelope';
import { epochStatement, revocationStatement, signManifest, verifyManifest } from './manifest';

function keypair() {
  const { secretKey, publicKey } = ed25519.keygen();
  return { secretKey, publicKey };
}

describe('manifest epoch statement', () => {
  test('a signed epoch statement verifies against the manifest public key', () => {
    const { secretKey, publicKey } = keypair();
    const msg = epochStatement({ kid: 'abc123', publicKeyB64: 'PUB', notAfter: 1_700_000_000_000 });
    const sig = signManifest(secretKey, msg);
    expect(verifyManifest(publicKey, msg, sig)).toBe(true);
  });

  test('a tampered epoch field fails (the client would reject a swapped key)', () => {
    const { secretKey, publicKey } = keypair();
    const sig = signManifest(
      secretKey,
      epochStatement({ kid: 'abc123', publicKeyB64: 'PUB', notAfter: 1_700_000_000_000 }),
    );
    const swapped = epochStatement({
      kid: 'abc123',
      publicKeyB64: 'ATTACKER',
      notAfter: 1_700_000_000_000,
    });
    expect(verifyManifest(publicKey, swapped, sig)).toBe(false);
  });

  test('a signature from a different manifest key fails', () => {
    const signer = keypair();
    const stranger = keypair();
    const msg = epochStatement({ kid: 'k', publicKeyB64: 'P', notAfter: 1 });
    const sig = signManifest(signer.secretKey, msg);
    expect(verifyManifest(stranger.publicKey, msg, sig)).toBe(false);
  });
});

describe('manifest revocation statement', () => {
  test('a signed revocation list verifies and is order-independent', () => {
    const { secretKey, publicKey } = keypair();
    const a = revocationStatement({ version: 3, notAfter: 9_000, revokedKids: ['k2', 'k1'] });
    const b = revocationStatement({ version: 3, notAfter: 9_000, revokedKids: ['k1', 'k2'] });
    expect(bytesToB64Url(a)).toBe(bytesToB64Url(b)); // sorted -> deterministic
    const sig = signManifest(secretKey, a);
    expect(verifyManifest(publicKey, b, sig)).toBe(true);
  });

  test('a bumped version is a different statement (no silent rollback reuse)', () => {
    const { secretKey, publicKey } = keypair();
    const sig = signManifest(
      secretKey,
      revocationStatement({ version: 5, notAfter: 9_000, revokedKids: ['k1'] }),
    );
    const older = revocationStatement({ version: 4, notAfter: 9_000, revokedKids: ['k1'] });
    expect(verifyManifest(publicKey, older, sig)).toBe(false);
  });
});
