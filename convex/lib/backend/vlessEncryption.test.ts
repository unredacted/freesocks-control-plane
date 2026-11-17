import { describe, expect, test } from 'vitest';
import { sha256Hex } from '../crypto';
import {
  clientEncryption,
  generateVlessEncryption,
  isVlessEncrypted,
  vlessEncryptionIdentity,
} from './vlessEncryption';

// Two pairs printed by the real thing (`xray vlessenc`, Xray-core 26.7.28, the
// version the node image runs), made for this test and used nowhere. The
// ML-KEM-768 client string is 1,610 characters, so its SHA-256 stands in.
const XRAY_X25519 = {
  decryption: 'mlkem768x25519plus.native.600s.gKcizb1S38QLEf6BU2hhJ71xnyP-RPUaQFcnV4KPClE',
  encryption: 'mlkem768x25519plus.native.0rtt.H4IxTqXJvCNUFKgfokVsahz7nf_GuIKYgdtkgYu5tHM',
};
const XRAY_MLKEM768 = {
  decryption:
    'mlkem768x25519plus.native.600s.Fvh2r1IFz2xQPXUqrNnCHhdPaqQY_ZSylKqHCfP0LCTlXBjPM7rBgU8y_qzQwFgXLVerLACnrIkcidp6SwRxKw',
  encryptionLength: 1610,
  encryptionSha256: 'e6776094ddf348a3fc78b641d3893f1c5dfa2c9fbc28b4bd300461fcee8e88ab',
};

describe('clientEncryption', () => {
  test('derives exactly the client string Xray prints for an ML-KEM-768 seed and for an X25519 key', async () => {
    expect(clientEncryption(XRAY_X25519.decryption)).toBe(XRAY_X25519.encryption);
    const pq = clientEncryption(XRAY_MLKEM768.decryption)!;
    expect(pq).toHaveLength(XRAY_MLKEM768.encryptionLength);
    expect(await sha256Hex(pq)).toBe(XRAY_MLKEM768.encryptionSha256);
  });

  test('says what the node is verified by', () => {
    expect(vlessEncryptionIdentity(XRAY_MLKEM768.decryption)).toMatchObject({
      mode: 'native',
      auth: 'mlkem768',
    });
    expect(vlessEncryptionIdentity(XRAY_X25519.decryption)?.auth).toBe('x25519');
    const [, , , x] = XRAY_X25519.decryption.split('.');
    expect(vlessEncryptionIdentity(`${XRAY_MLKEM768.decryption}.${x}`)?.auth).toBe('mixed');
  });

  test('carries the mode and the padding over, and resumes only while tickets are on', () => {
    const key = XRAY_X25519.decryption.split('.')[3]!;
    const pub = XRAY_X25519.encryption.split('.')[3]!;
    expect(
      clientEncryption(`mlkem768x25519plus.random.300-600s.100-111-1111.75-0-111.${key}`),
    ).toBe(`mlkem768x25519plus.random.0rtt.100-111-1111.75-0-111.${pub}`);
    expect(clientEncryption(`mlkem768x25519plus.xorpub.0s.${key}`)).toBe(
      `mlkem768x25519plus.xorpub.1rtt.${pub}`,
    );
  });

  test('gives nothing for a value Xray would not run', () => {
    const key = XRAY_X25519.decryption.split('.')[3]!;
    for (const bad of [
      undefined,
      null,
      7,
      '',
      'none',
      'mlkem768x25519plus.native.600s',
      `mlkem1024.native.600s.${key}`,
      `mlkem768x25519plus.loud.600s.${key}`,
      `mlkem768x25519plus.native.soon.${key}`,
      `mlkem768x25519plus.native.600s.${key}.100-111-1111`,
      `mlkem768x25519plus.native.600s.${key.slice(0, 20)}`,
      `mlkem768x25519plus.native.600s.${key}=`,
    ])
      expect(clientEncryption(bad)).toBeNull();
  });
});

describe('isVlessEncrypted', () => {
  test('is off for absent, empty and none, on for anything else (readable or not)', () => {
    for (const off of [undefined, null, '', ' ', 'none', ' none ', 7, {}])
      expect(isVlessEncrypted(off)).toBe(false);
    expect(isVlessEncrypted(XRAY_MLKEM768.decryption)).toBe(true);
    expect(isVlessEncrypted('something-else')).toBe(true);
  });
});

describe('generateVlessEncryption', () => {
  test('makes a fresh ML-KEM-768 server string under the defaults, with a client string to match', () => {
    const a = generateVlessEncryption();
    expect(a.decryption).toMatch(/^mlkem768x25519plus\.native\.600s\.[A-Za-z0-9_-]{86}$/);
    expect(generateVlessEncryption().decryption).not.toBe(a.decryption);
    const id = vlessEncryptionIdentity(a.decryption)!;
    expect(id.auth).toBe('mlkem768');
    expect(id.encryption).toMatch(/^mlkem768x25519plus\.native\.0rtt\.[A-Za-z0-9_-]{1579}$/);
    // The public string never holds the seed.
    expect(id.encryption).not.toContain(a.decryption.split('.')[3]!);
  });

  test('is the seed it was given, and refuses a short one', () => {
    const seed = Uint8Array.from({ length: 64 }, (_, i) => i);
    const a = generateVlessEncryption(() => seed);
    expect(generateVlessEncryption(() => seed)).toEqual(a);
    expect(() => generateVlessEncryption(() => new Uint8Array(32))).toThrow(/64 random bytes/);
  });
});
