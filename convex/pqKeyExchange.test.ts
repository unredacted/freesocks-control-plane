// @vitest-environment node
import { readFileSync } from 'node:fs';
import { describe, expect, test } from 'vitest';
import {
  GROUPS,
  HelloStream,
  describeObservation,
  groupName,
  isGrease,
  negotiatedGroup,
  observeConnection,
  parseClientHello,
} from '../docker/compat/tlsHello';
import {
  PQ_APPS,
  PQ_ENGINES,
  PQ_HEADER,
  PQ_MODES,
  pqCell,
  pqRows,
  renderPqTable,
} from '../tests/compat/pqMatrix';
import { clients } from '../tests/compat/manifest';
import { DEFAULT_CONNECTION_MODES } from './lib/connectionModes';
import {
  RENDER_CLIENT_FAMILIES,
  defaultClientRule,
  type RenderClientFamily,
} from './lib/edgeConfig';
import { classifyClient } from './lib/edges/clientFamilies';

/**
 * The post-quantum matrix (tests/compat/pqMatrix.ts) against the code and the
 * docs, and the parser the harnesses read handshakes with
 * (docker/compat/tlsHello.ts). The engines themselves are asserted by the
 * Docker jobs (docs/client-compatibility.md § "Post-quantum key exchange").
 */

// --- building hellos ---------------------------------------------------------------------------

const u16 = (n: number) => [n >> 8, n & 0xff];
const ext = (type: number, body: number[]) => [...u16(type), ...u16(body.length), ...body];
const handshake = (type: number, body: number[]) => [
  type,
  body.length >> 16,
  (body.length >> 8) & 0xff,
  body.length & 0xff,
  ...body,
];
const record = (type: number, payload: number[]) => [
  type,
  3,
  1,
  ...u16(payload.length),
  ...payload,
];
const share = (g: number, size = 32) => [...u16(g), ...u16(size), ...Array(size).fill(0x42)];

function clientHelloBody(groups: number[], shares: number[]): number[] {
  const ks = shares.flatMap((g) => share(g, g === GROUPS.X25519MLKEM768 ? 1216 : 32));
  const exts = [
    ...ext(0, [0, 3, 0, 0, 0]), // a server_name, unread
    ...ext(10, [...u16(groups.length * 2), ...groups.flatMap(u16)]),
    ...ext(51, [...u16(ks.length), ...ks]),
  ];
  return [
    3,
    3,
    ...Array(32).fill(7),
    32,
    ...Array(32).fill(9),
    ...u16(2),
    0x13,
    0x01,
    1,
    0,
    ...u16(exts.length),
    ...exts,
  ];
}

const HRR = [
  0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
  0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];
function serverHelloBody(group: number | null, opts: { retry?: boolean; tls13?: boolean } = {}) {
  const exts = [
    ...(opts.tls13 === false ? [] : ext(43, u16(0x0304))),
    ...(group === null ? [] : ext(51, opts.retry ? u16(group) : share(group))),
  ];
  const random = opts.retry ? HRR : Array(32).fill(5);
  return [3, 3, ...random, 32, ...Array(32).fill(9), 0x13, 0x01, 0, ...u16(exts.length), ...exts];
}

/** Feed `bytes` in pieces of `step` (a TCP stream splits anywhere). */
function feed(stream: HelloStream, bytes: number[], step: number) {
  for (let i = 0; i < bytes.length; i += step)
    stream.push(Uint8Array.from(bytes.slice(i, i + step)));
}

const GREASE = 0x3a3a;
const CHROME_LIKE = [
  GREASE,
  GROUPS.X25519MLKEM768,
  GROUPS.x25519,
  GROUPS.secp256r1,
  GROUPS.secp384r1,
];

describe('the hello parser', () => {
  test('a Client Hello: supported groups and key shares in order, GREASE removed', () => {
    const ch = parseClientHello(
      Uint8Array.from(clientHelloBody(CHROME_LIKE, [GREASE, GROUPS.X25519MLKEM768, GROUPS.x25519])),
    );
    expect(ch).toEqual({
      supportedGroups: [GROUPS.X25519MLKEM768, GROUPS.x25519, GROUPS.secp256r1, GROUPS.secp384r1],
      keyShares: [GROUPS.X25519MLKEM768, GROUPS.x25519],
    });
  });

  test('GREASE and names', () => {
    for (const g of [0x0a0a, 0x1a1a, 0xfafa]) expect(isGrease(g)).toBe(true);
    for (const g of [0x0a1a, GROUPS.x25519, GROUPS.X25519MLKEM768]) expect(isGrease(g)).toBe(false);
    expect(groupName(0x11ec)).toBe('X25519MLKEM768');
    expect(groupName(0x001d)).toBe('x25519');
    expect(groupName(0x2a2a)).toBe('GREASE');
    expect(groupName(0x0101)).toBe('0x0101');
  });

  test.each([1, 3, 7, 100, 5000])(
    'a whole handshake split every %i bytes: the pick is the server key share',
    (step) => {
      const { observation, fromClient, fromServer } = observeConnection();
      // A post-quantum Client Hello is larger than one record here on purpose:
      // the handshake message spans two records.
      const ch = handshake(1, clientHelloBody(CHROME_LIKE, [GROUPS.X25519MLKEM768, GROUPS.x25519]));
      const half = Math.floor(ch.length / 2);
      feed(fromClient, [...record(22, ch.slice(0, half)), ...record(22, ch.slice(half))], step);
      // Then the encrypted part, which ends the reading.
      feed(fromClient, [...record(20, [1]), ...record(23, Array(40).fill(1))], step);
      feed(fromServer, record(22, handshake(2, serverHelloBody(GROUPS.X25519MLKEM768))), step);
      feed(fromServer, [...record(20, [1]), ...record(23, Array(300).fill(2))], step);
      expect(negotiatedGroup(observation)).toBe(GROUPS.X25519MLKEM768);
      expect(describeObservation(observation)).toEqual({
        offered: ['X25519MLKEM768', 'x25519', 'secp256r1', 'secp384r1'],
        shares: ['X25519MLKEM768', 'x25519'],
        negotiated: 'X25519MLKEM768',
        helloRetry: false,
        tls13: true,
      });
    },
  );

  test('a Hello Retry Request is not the pick: the next Server Hello is', () => {
    const { observation, fromClient, fromServer } = observeConnection();
    feed(fromClient, record(22, handshake(1, clientHelloBody(CHROME_LIKE, [GROUPS.x25519]))), 9);
    feed(
      fromServer,
      record(22, handshake(2, serverHelloBody(GROUPS.X25519MLKEM768, { retry: true }))),
      9,
    );
    feed(fromClient, record(20, [1]), 9);
    feed(
      fromClient,
      record(22, handshake(1, clientHelloBody(CHROME_LIKE, [GROUPS.X25519MLKEM768]))),
      9,
    );
    feed(fromServer, record(22, handshake(2, serverHelloBody(GROUPS.X25519MLKEM768))), 9);
    const d = describeObservation(observation);
    expect(observation.clientHellos).toHaveLength(2);
    expect(d.helloRetry).toBe(true);
    expect(d.negotiated).toBe('X25519MLKEM768');
    // The FIRST Client Hello's shares: what the client offered by itself.
    expect(d.shares).toEqual(['x25519']);
  });

  test('a classic handshake reads as X25519', () => {
    const { observation, fromClient, fromServer } = observeConnection();
    feed(
      fromClient,
      record(22, handshake(1, clientHelloBody([GROUPS.x25519, GROUPS.secp256r1], [GROUPS.x25519]))),
      64,
    );
    feed(fromServer, record(22, handshake(2, serverHelloBody(GROUPS.x25519))), 64);
    expect(describeObservation(observation)).toMatchObject({
      offered: ['x25519', 'secp256r1'],
      negotiated: 'x25519',
      tls13: true,
    });
  });

  test('a TLS 1.2 Server Hello has no version and no key share; nothing past it is read', () => {
    const { observation, fromClient, fromServer } = observeConnection();
    feed(
      fromClient,
      record(22, handshake(1, clientHelloBody([GROUPS.x25519], [GROUPS.x25519]))),
      50,
    );
    // Server Hello then Certificate in one record: the second message stops the reading.
    feed(
      fromServer,
      record(22, [
        ...handshake(2, serverHelloBody(null, { tls13: false })),
        ...handshake(11, [0, 0, 0]),
      ]),
      50,
    );
    expect(describeObservation(observation)).toMatchObject({ negotiated: null, tls13: false });
  });

  test('bytes that are not TLS are never a hello', () => {
    const { observation, fromClient, fromServer } = observeConnection();
    feed(fromClient, [...Buffer.from('GET / HTTP/1.1\r\nHost: x\r\n\r\n')], 4);
    feed(fromServer, [...Buffer.from('HTTP/1.1 200 OK\r\n\r\n')], 4);
    expect(observation).toEqual({ clientHellos: [], serverHellos: [] });
    // A truncated hello body is not one either.
    expect(
      parseClientHello(Uint8Array.from(clientHelloBody(CHROME_LIKE, [GROUPS.x25519]).slice(0, 60))),
    ).toBeNull();
  });
});

// --- the matrix --------------------------------------------------------------------------------

/** Whether a family is handed a connection's encrypted twin (its default rule is not `plain`). */
const twinOf = (f: string) => defaultClientRule(f as RenderClientFamily).encryption !== 'plain';
const familyOf = (ua: string) => classifyClient(ua).family;

/** The table between the markers in docs/client-compatibility.md, as cell text. */
function docsRows(): string[][] {
  const doc = readFileSync('docs/client-compatibility.md', 'utf8');
  const start = doc.indexOf('<!-- pq-matrix:start -->');
  const end = doc.indexOf('<!-- pq-matrix:end -->');
  if (start < 0 || end < start)
    throw new Error('docs/client-compatibility.md has no pq-matrix markers');
  return doc
    .slice(start, end)
    .split('\n')
    .filter((l) => l.trim().startsWith('|'))
    .map((l) =>
      l
        .trim()
        .replace(/^\||\|$/g, '')
        .split('|')
        .map((c) => c.trim()),
    )
    .filter((cells) => !cells.every((c) => /^:?-+:?$/.test(c)));
}

describe('the post-quantum matrix', () => {
  test('covers every mode FCP ships, and nothing else', () => {
    expect(PQ_MODES.map((m) => m.mode).sort()).toEqual(
      DEFAULT_CONNECTION_MODES.map((m) => m.slug).sort(),
    );
  });

  test('covers every catalogued app and every client family', () => {
    for (const c of clients.filter((x) => x.format !== 'outline'))
      expect(
        PQ_APPS.map((a) => a.name),
        c.name,
      ).toContain(c.name);
    const families = new Set(PQ_APPS.map((a) => familyOf(a.userAgent)));
    for (const f of RENDER_CLIENT_FAMILIES) expect([...families], f).toContain(f);
  });

  // The rule each family is handed where a connection has an encrypted twin.
  // A change here changes who gets VLESS Encryption on `freedom-ws`: update
  // tests/compat/pqMatrix.ts and the docs table with it, on purpose.
  test('which families are handed the encrypted twin', () => {
    expect(Object.fromEntries(RENDER_CLIENT_FAMILIES.map((f) => [f, twinOf(f)]))).toEqual({
      singbox: false,
      mihomo: true,
      'xray-links': true,
      happ: true,
      hiddify: false,
      streisand: true,
      v2rayng: true,
      other: false,
    });
  });

  test('no family is handed an encrypted entry its engine is known not to use', () => {
    for (const app of PQ_APPS)
      if (twinOf(familyOf(app.userAgent)))
        expect(PQ_ENGINES[app.engine].vlessEncryption, `${app.name} (${app.engine})`).not.toBe(
          false,
        );
  });

  // An engine CI shows speaking VLESS Encryption on a plain family is a member
  // left without the post-quantum layer they could have: turn the family's rule
  // on (convex/lib/edgeConfig.ts PLAIN_FAMILIES) or say here why not.
  test('every app whose engine uses the encrypted entry is handed it', () => {
    for (const app of PQ_APPS)
      if (PQ_ENGINES[app.engine].vlessEncryption === true)
        expect(twinOf(familyOf(app.userAgent)), app.name).toBe(true);
  });

  test('every measured engine is post-quantum in every REALITY mode it can use, except the pinned ones', () => {
    // The pinned exceptions: sing-box removes the X25519MLKEM768 key share
    // (no body can help it). An engine that learns it must flip its entry.
    const pinnedClassic = Object.entries(PQ_ENGINES)
      .filter(([, e]) => e.reality === 'x25519')
      .map(([k]) => k);
    expect(pinnedClassic).toEqual(['singbox']);
    for (const app of PQ_APPS)
      for (const m of PQ_MODES.filter((x) => x.layer === 'reality')) {
        const c = pqCell(app, m.mode, twinOf(familyOf(app.userAgent)));
        if (PQ_ENGINES[app.engine].reality === 'X25519MLKEM768')
          expect(c.pq, `${app.name} ${m.mode}`).toBe('yes');
      }
  });

  test('the table in docs/client-compatibility.md is the matrix', () => {
    const want = pqRows(familyOf, twinOf);
    // On a mismatch the message is the table to paste (`bun tests/compat/pqMatrix.ts` prints it too).
    expect(docsRows(), `paste this table:\n${renderPqTable(want)}\n`).toEqual([PQ_HEADER, ...want]);
  });
});
