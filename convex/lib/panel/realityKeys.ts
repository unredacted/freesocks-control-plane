/**
 * REALITY key generation (pure apart from randomness). An X25519 private key
 * as Xray expects it: 32 random bytes, clamped as RFC 7748 does, base64url
 * without padding; the public key derived from it the same way
 * `realityPublicKey` (digest.ts) derives it from a stored profile. Generated
 * inside the setup action immediately before the profile create and never
 * persisted, logged or returned over HTTP.
 */
import { x25519 } from '@noble/curves/ed25519.js';

function bytesToBase64Url(b: Uint8Array): string {
  let bin = '';
  for (const x of b) bin += String.fromCharCode(x);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export interface RealityKeyPair {
  privateKey: string;
  publicKey: string;
}

export function generateRealityKey(
  random: (n: number) => Uint8Array = (n) => crypto.getRandomValues(new Uint8Array(n)),
): RealityKeyPair {
  const sk = random(32);
  if (sk.length !== 32) throw new Error('reality key: 32 random bytes expected');
  sk[0]! &= 248;
  sk[31]! &= 127;
  sk[31]! |= 64;
  return { privateKey: bytesToBase64Url(sk), publicKey: bytesToBase64Url(x25519.getPublicKey(sk)) };
}
