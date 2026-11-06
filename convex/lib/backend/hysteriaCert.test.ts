/**
 * The Hysteria certificate is a real X.509 certificate a TLS stack accepts,
 * self-signed by the key it ships with, for exactly the one server name, and
 * its two pins are the digests clients compute (checked against Node's own
 * X.509 parser, not against this module).
 */
import { createHash, createPrivateKey, X509Certificate } from 'node:crypto';
import { describe, expect, test } from 'vitest';
import {
  certificatePins,
  generateHysteriaCertificate,
  HYSTERIA_CERT_DAYS,
  normalizePinHex,
} from './hysteriaCert';

describe('generateHysteriaCertificate', () => {
  const now = new Date('2026-11-06T00:00:00Z');
  const made = generateHysteriaCertificate('Quic.Example', { now });
  const x = new X509Certificate(made.certificate.join('\n'));

  test('a self-signed ECDSA P-256 certificate for the one name', () => {
    expect(x.subject).toBe('CN=quic.example');
    expect(x.issuer).toBe('CN=quic.example');
    expect(x.subjectAltName).toBe('DNS:quic.example');
    expect(x.checkHost('quic.example')).toBe('quic.example');
    expect(x.checkHost('other.example')).toBeUndefined();
    expect(x.ca).toBe(false);
    expect(x.publicKey.asymmetricKeyDetails).toMatchObject({ namedCurve: 'prime256v1' });
    expect(x.verify(x.publicKey)).toBe(true);
    expect(x.keyUsage).toEqual(['1.3.6.1.5.5.7.3.1']);
  });

  test('valid from an hour ago for about ten years', () => {
    expect(new Date(x.validFrom).getTime()).toBe(now.getTime() - 3_600_000);
    expect(new Date(x.validTo).getTime()).toBe(now.getTime() + HYSTERIA_CERT_DAYS * 86_400_000);
  });

  test('the key is the certificate key, in a form Xray loads (SEC1 PEM)', () => {
    expect(made.key[0]).toBe('-----BEGIN EC PRIVATE KEY-----');
    const key = createPrivateKey(made.key.join('\n'));
    expect(x.checkPrivateKey(key)).toBe(true);
  });

  test('the pins are the certificate DER digest (hex) and the SPKI digest (base64)', () => {
    expect(made.pinHex).toBe(createHash('sha256').update(x.raw).digest('hex'));
    const spki = x.publicKey.export({ type: 'spki', format: 'der' });
    expect(made.spkiB64).toBe(createHash('sha256').update(spki).digest('base64'));
    // Node's fingerprint is the same digest, colon-separated upper case.
    expect(normalizePinHex(x.fingerprint256)).toBe(made.pinHex);
    expect(made.pinHex).not.toBe(Buffer.from(made.spkiB64, 'base64').toString('hex'));
  });

  test('reading the pins back from the PEM gives the same values', () => {
    expect(certificatePins(made.certificate)).toEqual({
      pinHex: made.pinHex,
      spkiB64: made.spkiB64,
    });
    expect(certificatePins(made.certificate.join('\n'))).toEqual({
      pinHex: made.pinHex,
      spkiB64: made.spkiB64,
    });
  });

  test('every certificate is fresh: new key, new serial, new pins', () => {
    const again = generateHysteriaCertificate('quic.example', { now });
    expect(again.pinHex).not.toBe(made.pinHex);
    expect(again.spkiB64).not.toBe(made.spkiB64);
    expect(new X509Certificate(again.certificate.join('\n')).serialNumber).not.toBe(x.serialNumber);
  });

  test('refuses a name that is not a host name', () => {
    expect(() => generateHysteriaCertificate('not a name')).toThrow(/server name/);
    expect(() => generateHysteriaCertificate('')).toThrow(/server name/);
  });
});

describe('certificatePins', () => {
  test('null for anything that is not a certificate', () => {
    expect(certificatePins([])).toBeNull();
    expect(certificatePins('no pem here')).toBeNull();
    expect(
      certificatePins(['-----BEGIN CERTIFICATE-----', '!!', '-----END CERTIFICATE-----']),
    ).toBeNull();
    expect(
      certificatePins(['-----BEGIN CERTIFICATE-----', 'AAAA', '-----END CERTIFICATE-----']),
    ).toBeNull();
  });

  test('normalizePinHex strips separators and case', () => {
    expect(normalizePinHex(' AB:cd-EF ')).toBe('abcdef');
  });
});
