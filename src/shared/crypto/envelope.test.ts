// @vitest-environment node
import { describe, expect, test } from 'vitest';
import { createHash } from 'node:crypto';
import { fingerprintB64Url } from './envelope';

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
