import { x25519 } from '@noble/curves/ed25519.js';
import { generateHysteriaCertificate } from './hysteriaCert';
import { describe, expect, test } from 'vitest';
import {
  REDACTED,
  canonicalJson,
  changeToken,
  isSecretKey,
  normalizeForToken,
  hysteriaAuthDigest,
  realityAuthDigest,
  realityPublicKey,
  redactConfig,
  shapeHash,
  vlessEncryptionAuthDigest,
} from './digest';
import { clientEncryption, generateVlessEncryption } from './vlessEncryption';

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

  test("a VLESS Encryption server string is a secret; 'none' is a fact that stays visible", () => {
    const server = generateVlessEncryption().decryption;
    const blob = JSON.stringify(redactConfig({ settings: { clients: [], decryption: server } }));
    expect(blob).not.toContain(server.split('.')[3]);
    expect(blob).toContain(REDACTED);
    for (const plain of ['none', ''])
      expect(redactConfig({ settings: { clients: [], decryption: plain } })).toEqual({
        settings: { clients: [], decryption: plain },
      });
    expect(isSecretKey('decryption')).toBe(true);
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

describe('a plain profile', () => {
  // The hash this exact profile had before `decryption` became a secret key:
  // every profile stored before then is plain, and must not read as changed.
  test('hashes as it did before VLESS Encryption existed', async () => {
    const plain = {
      log: { loglevel: 'none' },
      inbounds: [
        {
          tag: 'ws-in',
          listen: '127.0.0.1',
          port: 8443,
          protocol: 'vless',
          settings: { clients: [], decryption: 'none' },
          streamSettings: { network: 'ws', security: 'none', wsSettings: { path: '/ws' } },
        },
      ],
    };
    expect(await shapeHash(plain)).toBe(
      '90cc9572d4e2fc6177a3ed3f801a5e17d2beeaeb1743c909c0d097e82d7ae2ea',
    );
  });
});

describe('vlessEncryptionAuthDigest', () => {
  const server = generateVlessEncryption(() => new Uint8Array(64).fill(3)).decryption;
  const other = generateVlessEncryption(() => new Uint8Array(64).fill(4)).decryption;
  const settings = (decryption: unknown) => ({
    clients: [{ id: 'client-uuid-value' }],
    decryption,
  });

  test('a plain transport has none', async () => {
    for (const plain of [undefined, '', 'none'])
      expect(await vlessEncryptionAuthDigest(settings(plain), KEY)).toBeNull();
    expect(await vlessEncryptionAuthDigest(undefined, KEY)).toBeNull();
  });

  test('says how the node is verified, and never carries the server string or the client one', async () => {
    const a = await vlessEncryptionAuthDigest(settings(server), KEY);
    expect(a).toEqual({
      digest: expect.stringMatching(/^[0-9a-f]{64}$/),
      mode: 'native',
      auth: 'mlkem768',
    });
    const blob = JSON.stringify(a);
    expect(blob).not.toContain(server.split('.')[3]);
    expect(blob).not.toContain(clientEncryption(server)!.split('.')[3]);
  });

  test('moves with the key, the mode and the tickets; is keyed; and is stable', async () => {
    const digest = async (d: string, key = KEY) =>
      (await vlessEncryptionAuthDigest(settings(d), key))!.digest;
    const base = await digest(server);
    expect(await digest(server)).toBe(base);
    expect(await digest(other)).not.toBe(base);
    expect(await digest(server.replace('.native.', '.random.'))).not.toBe(base);
    expect(await digest(server.replace('.600s.', '.0s.'))).not.toBe(base);
    expect(await digest(server, 'another-key')).not.toBe(base);
    // The ticket LIFETIME is the server's own business: members' entries hold.
    expect(await digest(server.replace('.600s.', '.300s.'))).toBe(base);
  });

  test('a server string FCP cannot read is still reported as encrypted', async () => {
    expect(
      await vlessEncryptionAuthDigest(settings('mlkem768x25519plus.native.600s'), KEY),
    ).toEqual({
      digest: null,
      mode: null,
      auth: null,
    });
  });

  test('a rotation is invisible to the shape hash and moves the change token', async () => {
    const profile = (d: string) => ({
      inbounds: [{ tag: 'ws-e', protocol: 'vless', settings: { clients: [], decryption: d } }],
    });
    expect(await shapeHash(profile(other))).toBe(await shapeHash(profile(server)));
    expect(await shapeHash(profile('none'))).not.toBe(await shapeHash(profile(server)));
    expect(await changeToken(profile(other), KEY)).not.toBe(
      await changeToken(profile(server), KEY),
    );
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

  test('what FCP sends and what the backend stores hash alike (backend write normalisation)', async () => {
    // The backend trims each server name and clears the client list; nothing else.
    const sent = config({ names: [' a.example ', 'b.example'] });
    const stored = config({ names: ['a.example', 'b.example'] });
    stored.inbounds[0].settings = { clients: [], decryption: 'none' } as never;
    expect(await changeToken(sent, KEY)).toBe(await changeToken(stored, KEY));
    // It neither lowercases nor de-duplicates, so neither may the token.
    expect(await changeToken(config({ names: ['A.example', 'b.example'] }), KEY)).not.toBe(
      await changeToken(stored, KEY),
    );
  });

  test('normalizeForToken leaves a config without transports, and non-objects, alone', () => {
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

describe('hysteriaAuthDigest', () => {
  const cert = generateHysteriaCertificate('quic.example');
  const stream = (over: Record<string, unknown> = {}, fm: Record<string, unknown> = {}) => ({
    network: 'hysteria',
    security: 'tls',
    tlsSettings: {
      serverName: 'quic.example',
      alpn: ['h3'],
      certificates: [{ certificate: cert.certificate, key: cert.key }],
      ...over,
    },
    finalmask: { quicParams: { congestion: 'bbr' }, ...fm },
  });

  test('carries the pins of the certificate, the name and the ALPN, never the key', async () => {
    const a = await hysteriaAuthDigest(stream(), 'k1');
    expect(a).toMatchObject({
      pinHex: cert.pinHex,
      spkiB64: cert.spkiB64,
      serverName: 'quic.example',
      alpn: ['h3'],
      obfs: false,
    });
    expect(JSON.stringify(a)).not.toContain(cert.key[1]!.slice(0, 20));
  });

  test('moves on a new certificate, name, ALPN, Salamander or Salamander password', async () => {
    const base = (await hysteriaAuthDigest(stream(), 'k1')).digest;
    const other = generateHysteriaCertificate('quic.example');
    const changed = [
      stream({ certificates: [{ certificate: other.certificate, key: other.key }] }),
      stream({ serverName: 'other.example' }),
      stream({ alpn: ['h3', 'h2'] }),
      stream({}, { udp: [{ type: 'salamander', settings: { password: 'one' } }] }),
    ];
    const digests = await Promise.all(changed.map((s) => hysteriaAuthDigest(s, 'k1')));
    for (const d of digests) expect(d.digest).not.toBe(base);
    const two = await hysteriaAuthDigest(
      stream({}, { udp: [{ type: 'salamander', settings: { password: 'two' } }] }),
      'k1',
    );
    expect(two.obfs).toBe(true);
    expect(two.digest).not.toBe(digests[3]!.digest);
    // Keyed: another key gives another digest of the same settings.
    expect((await hysteriaAuthDigest(stream(), 'k2')).digest).not.toBe(base);
  });

  test('no readable certificate: no pins and no digest', async () => {
    const a = await hysteriaAuthDigest(stream({ certificates: [] }), 'k1');
    expect(a).toMatchObject({ digest: null, pinHex: null, spkiB64: null });
    expect(await hysteriaAuthDigest(null, 'k1')).toMatchObject({ digest: null, alpn: [] });
  });
});
