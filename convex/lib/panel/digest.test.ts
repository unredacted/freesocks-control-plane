import { x25519 } from '@noble/curves/ed25519.js';
import { describe, expect, test } from 'vitest';
import {
  REDACTED,
  canonicalJson,
  changeToken,
  isSecretKey,
  normalizeForToken,
  realityAuthDigest,
  realityPublicKey,
  redactConfig,
  shapeHash,
} from './digest';

const KEY = 'test-digest-key';
const b64u = (b: Uint8Array) =>
  btoa(String.fromCharCode(...b))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

const SK = b64u(new Uint8Array(32).fill(7));
const SK2 = b64u(new Uint8Array(32).fill(9));
const PK = b64u(x25519.getPublicKey(new Uint8Array(32).fill(7)));

const SECRETS = ['PRIVATE_KEY_VALUE', 'ab12cd34', 'client-uuid-value', 'CERT_PEM', 'ss-password'];

const config = (over: { sk?: string; shortIds?: string[]; names?: string[] } = {}) => ({
  log: { loglevel: 'none' },
  inbounds: [
    {
      tag: 'reality-in',
      port: 443,
      protocol: 'vless',
      settings: { clients: [{ id: 'client-uuid-value', email: 'u1' }], decryption: 'none' },
      streamSettings: {
        network: 'tcp',
        security: 'reality',
        realitySettings: {
          target: 'target.example:443',
          serverNames: over.names ?? ['a.example', 'b.example'],
          privateKey: over.sk ?? 'PRIVATE_KEY_VALUE',
          shortIds: over.shortIds ?? ['ab12cd34'],
        },
      },
    },
    {
      tag: 'tls-in',
      port: 8443,
      protocol: 'trojan',
      settings: { clients: [] },
      streamSettings: {
        security: 'tls',
        tlsSettings: { serverName: 'c.example', certificates: [{ certificate: ['CERT_PEM'] }] },
      },
    },
    { tag: 'ss-in', port: 8388, protocol: 'shadowsocks', settings: { password: 'ss-password' } },
  ],
  outbounds: [{ protocol: 'freedom', tag: 'DIRECT' }],
});

describe('redactConfig', () => {
  test('no secret value survives, structure and non-secrets do', () => {
    const blob = JSON.stringify(redactConfig(config()));
    for (const s of SECRETS) expect(blob).not.toContain(s);
    expect(blob).toContain('a.example');
    expect(blob).toContain('target.example:443');
    expect(blob).toContain('"port":443');
    expect(blob).toContain(REDACTED);
  });

  test('an empty secret stays visibly empty', () => {
    const red = redactConfig({ settings: { clients: [] }, shortIds: [], password: '' }) as Record<
      string,
      unknown
    >;
    expect(red).toEqual({ settings: { clients: [] }, shortIds: [], password: '' });
  });

  test('anything that names itself a secret is one', () => {
    for (const k of [
      'privateKey',
      'shortIds',
      'apiToken',
      'mySecretThing',
      'mldsa65Seed',
      'clients',
    ])
      expect(isSecretKey(k)).toBe(true);
    for (const k of ['serverNames', 'target', 'port', 'tag', 'network', 'publicKey'])
      expect(isSecretKey(k)).toBe(false);
  });
});

describe('canonicalJson / shapeHash', () => {
  test('key order never moves a digest (jsonb reorders keys)', async () => {
    const a = { b: 1, a: { d: [1, { y: 2, x: 1 }], c: 'z' } };
    const b = { a: { c: 'z', d: [1, { x: 1, y: 2 }] }, b: 1 };
    expect(canonicalJson(a)).toBe(canonicalJson(b));
    expect(await shapeHash(a)).toBe(await shapeHash(b));
  });

  test('shapeHash sees a non-secret change and is blind to a secret-only one', async () => {
    const base = await shapeHash(config());
    expect(await shapeHash(config({ names: ['a.example'] }))).not.toBe(base);
    expect(await shapeHash(config({ sk: 'ANOTHER_PRIVATE_KEY' }))).toBe(base);
    expect(await shapeHash(config({ shortIds: ['ffff0000'] }))).toBe(base);
  });
});

describe('changeToken', () => {
  test('moves on a secret-only change, and is keyed', async () => {
    const base = await changeToken(config(), KEY);
    expect(await changeToken(config({ sk: 'ANOTHER_PRIVATE_KEY' }), KEY)).not.toBe(base);
    expect(await changeToken(config({ shortIds: ['ffff0000'] }), KEY)).not.toBe(base);
    expect(await changeToken(config(), 'another-key')).not.toBe(base);
    expect(await changeToken(config(), KEY)).toBe(base);
    expect(base).toMatch(/^[0-9a-f]{64}$/);
  });

  test('what FCP sends and what the panel stores hash alike (panel write normalisation)', async () => {
    // The panel trims each server name and clears the client list; nothing else.
    const sent = config({ names: [' a.example ', 'b.example'] });
    const stored = config({ names: ['a.example', 'b.example'] });
    stored.inbounds[0].settings = { clients: [], decryption: 'none' } as never;
    expect(await changeToken(sent, KEY)).toBe(await changeToken(stored, KEY));
    // It neither lowercases nor de-duplicates, so neither may the token.
    expect(await changeToken(config({ names: ['A.example', 'b.example'] }), KEY)).not.toBe(
      await changeToken(stored, KEY),
    );
  });

  test('normalizeForToken leaves a config without inbounds, and non-objects, alone', () => {
    expect(normalizeForToken({ log: {} })).toEqual({ log: {} });
    expect(normalizeForToken(null)).toBeNull();
    expect(normalizeForToken('x')).toBe('x');
  });
});

describe('realityAuthDigest', () => {
  const rs = (over: Record<string, unknown> = {}) => ({
    target: 'target.example:443',
    serverNames: ['a.example'],
    privateKey: SK,
    shortIds: ['AB12', 'cd34'],
    ...over,
  });

  test('derives the public key from the PRIVATE key', async () => {
    expect(realityPublicKey(SK)).toBe(PK);
    const a = await realityAuthDigest(rs(), KEY);
    expect(a.publicKey).toBe(PK);
    expect(a.publicKeyMismatch).toBe(false);
    expect(a.digest).toMatch(/^[0-9a-f]{64}$/);
  });

  test('moves with the key, the short ids and the client bounds; not with names or target', async () => {
    const base = (await realityAuthDigest(rs(), KEY)).digest;
    expect((await realityAuthDigest(rs({ privateKey: SK2 }), KEY)).digest).not.toBe(base);
    expect((await realityAuthDigest(rs({ shortIds: ['ab12'] }), KEY)).digest).not.toBe(base);
    expect((await realityAuthDigest(rs({ minClientVer: '1.8.0' }), KEY)).digest).not.toBe(base);
    expect((await realityAuthDigest(rs({ maxTimeDiff: 60000 }), KEY)).digest).not.toBe(base);
    expect((await realityAuthDigest(rs({ mldsa65Seed: 'seed-1' }), KEY)).digest).not.toBe(base);
    // Order and case of short ids, the names and the target are not authentication.
    expect((await realityAuthDigest(rs({ shortIds: ['cd34', 'ab12'] }), KEY)).digest).toBe(base);
    expect((await realityAuthDigest(rs({ serverNames: ['z.example'] }), KEY)).digest).toBe(base);
    expect((await realityAuthDigest(rs({ target: 'other.example:443' }), KEY)).digest).toBe(base);
  });

  test('a stored public key that does not belong to the private key is flagged', async () => {
    expect((await realityAuthDigest(rs({ publicKey: PK }), KEY)).publicKeyMismatch).toBe(false);
    const wrong = await realityAuthDigest(rs({ publicKey: realityPublicKey(SK2) }), KEY);
    expect(wrong.publicKeyMismatch).toBe(true);
    // The identity is still the PRIVATE key's: a lying stored key changes nothing.
    expect(wrong.digest).toBe((await realityAuthDigest(rs(), KEY)).digest);
  });

  test('an unusable private key yields no digest and never throws', async () => {
    for (const bad of [undefined, '', 'not base64!!', b64u(new Uint8Array(8))])
      expect(await realityAuthDigest(rs({ privateKey: bad }), KEY)).toEqual({
        digest: null,
        publicKey: null,
        publicKeyMismatch: false,
      });
  });

  test('nothing returned contains key material', async () => {
    const out = JSON.stringify(await realityAuthDigest(rs({ mldsa65Seed: 'seed-1' }), KEY));
    expect(out).not.toContain(SK);
    expect(out).not.toContain('seed-1');
    expect(out).not.toContain('ab12');
  });
});
