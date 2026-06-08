// @vitest-environment node
import { describe, expect, test } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { bytesToB64Url } from './envelope';
import {
  epochStatement,
  revocationStatement,
  signManifest,
  signManifestPq,
  verifyManifest,
  verifyManifestPq,
} from './manifest';

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

describe('manifest ML-DSA-65 signatures (Phase 4 post-quantum leg)', () => {
  test('a signed statement verifies against the ML-DSA public key', () => {
    const { secretKey, publicKey } = ml_dsa65.keygen();
    const msg = epochStatement({ kid: 'k', publicKeyB64: 'P', notAfter: 1 });
    const sig = signManifestPq(secretKey, msg);
    expect(verifyManifestPq(publicKey, msg, sig)).toBe(true);
  });

  test('a tampered statement fails', () => {
    const { secretKey, publicKey } = ml_dsa65.keygen();
    const sig = signManifestPq(
      secretKey,
      epochStatement({ kid: 'k', publicKeyB64: 'P', notAfter: 1 }),
    );
    const swapped = epochStatement({ kid: 'k', publicKeyB64: 'ATTACKER', notAfter: 1 });
    expect(verifyManifestPq(publicKey, swapped, sig)).toBe(false);
  });

  test('a signature from a different ML-DSA key fails', () => {
    const signer = ml_dsa65.keygen();
    const stranger = ml_dsa65.keygen();
    const msg = epochStatement({ kid: 'k', publicKeyB64: 'P', notAfter: 1 });
    expect(verifyManifestPq(stranger.publicKey, msg, signManifestPq(signer.secretKey, msg))).toBe(
      false,
    );
  });

  test('hybrid: the same statement is independently signed + verified by both schemes', () => {
    const ed = ed25519.keygen();
    const pq = ml_dsa65.keygen();
    const msg = epochStatement({ kid: 'k', publicKeyB64: 'P', notAfter: 42 });
    const sigEd = signManifest(ed.secretKey, msg);
    const sigPq = signManifestPq(pq.secretKey, msg);
    // Both verify under their own key...
    expect(verifyManifest(ed.publicKey, msg, sigEd)).toBe(true);
    expect(verifyManifestPq(pq.publicKey, msg, sigPq)).toBe(true);
    // ...and neither verifies under the other's key/sig (independent legs).
    expect(verifyManifestPq(pq.publicKey, msg, sigEd)).toBe(false);
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
