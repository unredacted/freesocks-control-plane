// @vitest-environment node
import { randomBytes } from 'node:crypto';
import { describe, expect, test } from 'vitest';
import { clientEncryption, generateVlessEncryption } from '../../backend/vlessEncryption';
import { EncryptionError, VlessEncryptionSession, encryptionRefusal } from './vlessEncryption';
import { FakeEncryptedNode } from './vlessEncryption.fake';

const deps = { randomBytes: (n: number) => new Uint8Array(randomBytes(n)) };
const text = (b: Uint8Array) => new TextDecoder().decode(b);
const bytes = (s: string) => new TextEncoder().encode(s);
const join = (parts: Uint8Array[]) => Buffer.concat(parts.map((p) => Buffer.from(p)));

/** An X25519 server string (a fresh private key), for the key kind FCP reads but never makes. */
function x25519Server(mode = 'native'): string {
  return `mlkem768x25519plus.${mode}.600s.${Buffer.from(randomBytes(32)).toString('base64url')}`;
}

/** Runs the handshake to its end, delivering each side's bytes `step` at a time. */
function connect(server: string, client = clientEncryption(server)!, step = 4096) {
  const node = new FakeEncryptedNode(server);
  const session = new VlessEncryptionSession(client, deps);
  const toNode = (data: Uint8Array) => {
    const plain: Uint8Array[] = [];
    for (let at = 0; at < data.length; at += step) {
      const r = node.receive(data.subarray(at, at + step));
      plain.push(...r.plain);
      for (const back of r.send) toSession(back);
    }
    return plain;
  };
  const fromNode: Uint8Array[] = [];
  const toSession = (data: Uint8Array) => {
    for (let at = 0; at < data.length; at += step)
      fromNode.push(...session.receive(data.subarray(at, at + step)));
  };
  toNode(session.hello());
  return { node, session, toNode, toSession, fromNode };
}

describe('VlessEncryptionSession', () => {
  for (const [name, server] of [
    ['an ML-KEM-768 key (what FCP makes)', generateVlessEncryption().decryption],
    ['an X25519 key', x25519Server()],
    ['an X25519 key with the share masked (xorpub)', x25519Server('xorpub')],
    [
      'an ML-KEM-768 key with the share masked (xorpub)',
      generateVlessEncryption().decryption.replace('.native.', '.xorpub.'),
    ],
  ] as const)
    test(`${name}: the handshake completes and records open both ways`, () => {
      const c = connect(server);
      expect(c.node.refused).toBe(false);
      expect(c.session.ready).toBe(true);
      expect(text(join(c.toNode(c.session.seal(bytes('request')))))).toBe('request');
      c.toSession(c.node.seal(bytes('answer')));
      expect(text(join(c.fromNode))).toBe('answer');
    });

  test('bytes may arrive one at a time, and a large write is cut into records', () => {
    const c = connect(generateVlessEncryption().decryption, undefined, 1);
    expect(c.session.ready).toBe(true);
    const big = new Uint8Array(20_000).map((_, i) => i % 251);
    const sealed = c.session.seal(big);
    // Three records: 8192 + 8192 + 3616, each with its header and tag.
    expect(sealed.length).toBe(20_000 + 3 * (5 + 16));
    expect(join(c.toNode(sealed)).equals(Buffer.from(big))).toBe(true);
  });

  test('nothing can be sealed before the handshake is through', () => {
    const session = new VlessEncryptionSession(
      clientEncryption(generateVlessEncryption().decryption)!,
      deps,
    );
    expect(session.ready).toBe(false);
    expect(() => session.seal(bytes('early'))).toThrow(/not ready/);
  });

  test("a node holding another key cannot answer: the client's hello does not open there", () => {
    const c = connect(
      generateVlessEncryption().decryption,
      clientEncryption(generateVlessEncryption().decryption)!,
    );
    expect(c.node.refused).toBe(true);
    expect(c.session.ready).toBe(false);
  });

  test('an answer that is not the node (a web page, a carrier in the middle) is refused', () => {
    const session = new VlessEncryptionSession(
      clientEncryption(generateVlessEncryption().decryption)!,
      deps,
    );
    const page = new Uint8Array(2000).fill(0x3c);
    expect(() => session.receive(page)).toThrow(EncryptionError);
  });

  test('a record that was changed on the way does not open', () => {
    const c = connect(generateVlessEncryption().decryption);
    const sealed = c.node.seal(bytes('answer'));
    sealed[sealed.length - 1] ^= 1;
    expect(() => c.session.receive(sealed)).toThrow(EncryptionError);
    // Neither does something that is not a record at all.
    const other = connect(generateVlessEncryption().decryption);
    expect(() => other.session.receive(bytes('HTTP/1.1 200 OK\r\n\r\n'))).toThrow(EncryptionError);
  });

  test('two sessions to one node never share a hello', () => {
    const client = clientEncryption(generateVlessEncryption().decryption)!;
    const a = new VlessEncryptionSession(client, deps).hello();
    const b = new VlessEncryptionSession(client, deps).hello();
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });
});

describe('encryptionRefusal', () => {
  const server = generateVlessEncryption().decryption;
  const client = clientEncryption(server)!;
  test('one key, as it is or with the share masked, can be spoken', () => {
    expect(encryptionRefusal(client)).toBeNull();
    expect(encryptionRefusal(client.replace('.native.', '.xorpub.'))).toBeNull();
    expect(encryptionRefusal(client.replace('.0rtt.', '.1rtt.'))).toBeNull();
  });
  test('what this client does not speak is named, never guessed at', () => {
    expect(encryptionRefusal(client.replace('.native.', '.random.'))).toBe('mode');
    expect(encryptionRefusal(`${client}.${client.split('.')[3]}`)).toBe('chain');
    for (const bad of ['', 'none', 'mlkem768x25519plus.native.0rtt', server])
      expect(encryptionRefusal(bad)).toBe('unreadable');
    expect(() => new VlessEncryptionSession('', deps)).toThrow(/unsupported/);
  });
});
