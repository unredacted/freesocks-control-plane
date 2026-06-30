// @vitest-environment node
import { describe, expect, test } from 'vitest';
import { createHash } from 'node:crypto';
import { fingerprintB64Url, sha256HexOfB64Url } from './envelope';

/** The EXACT form scripts/e2ee-fingerprint.mjs publishes, computed independently
 *  with node:crypto. If fingerprintB64Url (crypto.subtle) ever diverges from this,
 *  the in-app "Verify connection" panel would show a value that doesn't match the
 *  out-of-band-published anchor — defeating the whole point. */
function scriptForm(s: string): string {
  const hex = createHash('sha256').update(s, 'utf8').digest('hex');
  return (hex.match(/.{4}/g) ?? []).join(' ');
}

describe('fingerprintB64Url', () => {
  test('is the 4-char-grouped hex SHA-256 of the UTF-8 string (16 groups)', async () => {
    const fp = await fingerprintB64Url('AbCd_base64url-example');
    expect(fp).toMatch(/^([0-9a-f]{4} ){15}[0-9a-f]{4}$/); // 32-byte digest = 64 hex = 16 groups
  });

  test('matches the e2ee-fingerprint.mjs published form exactly (client === published)', async () => {
    for (const s of ['', 'A', 'VITE_FS_SERVER_HPKE_PK-example-value', 'x'.repeat(120)]) {
      expect(await fingerprintB64Url(s)).toBe(scriptForm(s));
    }
  });

  test('hashes the base64url STRING (distinct inputs → distinct fingerprints)', async () => {
    expect(await fingerprintB64Url('aaaa')).not.toBe(await fingerprintB64Url('bbbb'));
  });
});

describe('sha256HexOfB64Url (the DNS TXT pin form)', () => {
  test('is ungrouped 64-char lowercase hex (no spaces — safe for a single-line TXT value)', async () => {
    const hex = await sha256HexOfB64Url('AbCd_base64url-example');
    expect(hex).toMatch(/^[0-9a-f]{64}$/);
  });

  test('matches node:crypto AND is exactly the ungrouped form of fingerprintB64Url', async () => {
    for (const s of ['', 'A', 'VITE_FS_SERVER_HPKE_PK-example-value', 'x'.repeat(120)]) {
      const hex = await sha256HexOfB64Url(s);
      expect(hex).toBe(createHash('sha256').update(s, 'utf8').digest('hex'));
      // grouping the ungrouped hex reproduces the displayed fingerprint byte-for-byte,
      // so the value published in DNS and the value shown on screen are one hash.
      expect((hex.match(/.{4}/g) ?? []).join(' ')).toBe(await fingerprintB64Url(s));
    }
  });
});
