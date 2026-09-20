import { describe, expect, test } from 'vitest';
import { realityPublicKey } from './digest';
import { generateRealityKey } from './realityKeys';

describe('generateRealityKey', () => {
  test('makes a 32-byte clamped key whose public half the digest derives identically', () => {
    const k = generateRealityKey();
    expect(k.privateKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(k.publicKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(realityPublicKey(k.privateKey)).toBe(k.publicKey);
    expect(generateRealityKey().privateKey).not.toBe(k.privateKey);
  });
  test('clamps whatever randomness it is given', () => {
    const k = generateRealityKey(() => new Uint8Array(32).fill(0xff));
    const raw = Uint8Array.from(atob(k.privateKey.replace(/-/g, '+').replace(/_/g, '/')), (c) =>
      c.charCodeAt(0),
    );
    expect(raw[0]! & 7).toBe(0);
    expect(raw[31]! & 128).toBe(0);
    expect(raw[31]! & 64).toBe(64);
  });
});
