// @vitest-environment node
/**
 * The front check's wire codecs, on fixtures.
 *
 * These are the bytes a censor-facing front and a real Xray inbound see, so
 * they are pinned against the specifications themselves (RFC 6455's own example
 * frame and accept key, gRPC's length prefix, protobuf's varint) rather than
 * against what our encoder happens to produce. A decoder that only agrees with
 * our encoder proves nothing.
 */
import { describe, expect, test } from 'vitest';
import {
  buildWsHandshake,
  checkWsHandshake,
  createWsDecoder,
  encodeWsClose,
  encodeWsFrame,
  newWsKey,
  splitHandshake,
  wsAcceptKey,
  WS_OPCODE,
} from './ws';
import { buildUpgradeRequest, checkUpgradeResponse, DEFAULT_UPGRADE_TOKEN } from './httpupgrade';
import {
  createGrpcDecoder,
  decodeHunk,
  decodeVarint,
  encodeGrpcFrame,
  encodeHunk,
  encodeHunkFrame,
  encodeVarint,
  grpcPath,
} from './grpc';
import { buildVlessRequest, isUuid, parseVlessResponse, uuidToBytes } from './vless';
import { headerHasToken, looksFrontGenerated, parseHttpHead, tunnelProbeRequest } from './http1';

const enc = (s: string) => new TextEncoder().encode(s);
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

describe('http/1.1 head parsing', () => {
  test('returns null until the blank line arrives', () => {
    expect(parseHttpHead(enc('HTTP/1.1 101 Switching Protocols\r\nUpgrade: web'))).toBeNull();
  });

  test('parses status and lowercased headers and reports what it consumed', () => {
    const head = parseHttpHead(
      enc(
        'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nXX',
      ),
    );
    expect(head).not.toBeNull();
    expect(head!.status).toBe(101);
    expect(head!.headers['upgrade']).toBe('websocket');
    expect(head!.headerLength).toBe(77);
  });

  test('joins repeated headers instead of losing one', () => {
    const head = parseHttpHead(enc('HTTP/1.1 200 OK\r\nVia: a\r\nVia: b\r\n\r\n'));
    expect(head!.headers['via']).toBe('a, b');
  });

  test('a malformed status line is a protocol error, not "need more bytes"', () => {
    expect(() => parseHttpHead(enc('GARBAGE\r\n\r\n'))).toThrow();
  });

  test('headerHasToken reads comma lists case-insensitively', () => {
    expect(headerHasToken('keep-alive, Upgrade', 'upgrade')).toBe(true);
    expect(headerHasToken('keep-alive', 'upgrade')).toBe(false);
    expect(headerHasToken(undefined, 'upgrade')).toBe(false);
  });

  test('recognises a front-generated answer by its own headers', () => {
    const head = parseHttpHead(
      enc('HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\ncf-ray: 1\r\n\r\n'),
    )!;
    expect(looksFrontGenerated(head)).toBe(true);
    const node = parseHttpHead(
      enc('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n'),
    )!;
    expect(looksFrontGenerated(node)).toBe(false);
  });

  test('the tunnel probe asks for the target by name and closes after it', () => {
    const text = Buffer.from(tunnelProbeRequest('www.gstatic.com', '/generate_204')).toString();
    expect(text).toBe(
      'GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n',
    );
  });
});

describe('websocket', () => {
  test('accept key matches the RFC 6455 §1.3 example', () => {
    expect(wsAcceptKey('dGhlIHNhbXBsZSBub25jZQ==')).toBe('s3pPLMBiTxaQ9kYGzzhZRbK+xOo=');
  });

  test('a fresh key is 16 random bytes, base64', () => {
    const key = newWsKey((n) => new Uint8Array(n).fill(7));
    expect(Buffer.from(key, 'base64')).toHaveLength(16);
  });

  test('masked client frame matches the RFC 6455 §5.7 example', () => {
    const frame = encodeWsFrame(
      WS_OPCODE.text,
      enc('Hello'),
      new Uint8Array([0x37, 0xfa, 0x21, 0x3d]),
    );
    expect(hex(frame)).toBe('818537fa213d7f9f4d5158');
  });

  test('the handshake request carries the path, host and key', () => {
    const text = Buffer.from(
      buildWsHandshake({ path: '/ws-path', host: 'front.example', key: 'KEY' }),
    ).toString();
    expect(text).toContain('GET /ws-path HTTP/1.1\r\n');
    expect(text).toContain('Host: front.example\r\n');
    expect(text).toContain('Sec-WebSocket-Key: KEY\r\n');
    expect(text).toContain('Sec-WebSocket-Version: 13\r\n');
  });

  test('every part of the server handshake is checked', () => {
    const key = 'dGhlIHNhbXBsZSBub25jZQ==';
    const ok = parseHttpHead(
      enc(
        'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
          'Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n',
      ),
    )!;
    expect(checkWsHandshake(ok, key).ok).toBe(true);

    const badAccept = parseHttpHead(
      enc(
        'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
          'Sec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n',
      ),
    )!;
    expect(checkWsHandshake(badAccept, key)).toMatchObject({ ok: false, reason: 'accept' });

    const notUpgraded = parseHttpHead(enc('HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\n\r\n'))!;
    expect(checkWsHandshake(notUpgraded, key)).toMatchObject({ ok: false, reason: 'status' });
  });

  test('decoder reassembles fragments and surfaces control frames', () => {
    const dec = createWsDecoder();
    expect(dec.push(new Uint8Array([0x82, 0x03, 1, 2]))).toEqual([]);
    expect(dec.push(new Uint8Array([3]))).toEqual([
      { type: 'message', data: new Uint8Array([1, 2, 3]) },
    ]);
    // Fragmented: first data frame without FIN, then a continuation with FIN.
    expect(dec.push(new Uint8Array([0x02, 0x01, 0xaa]))).toEqual([]);
    expect(dec.push(new Uint8Array([0x80, 0x01, 0xbb]))).toEqual([
      { type: 'message', data: new Uint8Array([0xaa, 0xbb]) },
    ]);
    expect(dec.push(new Uint8Array([0x88, 0x02, 0x03, 0xe8]))).toEqual([
      { type: 'close', code: 1000 },
    ]);
  });

  test('decoder handles the 16-bit length form and a masked server frame', () => {
    const dec = createWsDecoder();
    const payload = new Uint8Array(200).fill(9);
    const framed = encodeWsFrame(WS_OPCODE.binary, payload, new Uint8Array([1, 2, 3, 4]));
    expect(framed[1] & 0x7f).toBe(126);
    expect(dec.push(framed)).toEqual([{ type: 'message', data: payload }]);
  });

  test('a close frame carries the status code', () => {
    const dec = createWsDecoder();
    const close = encodeWsClose(1000, new Uint8Array([0, 0, 0, 0]));
    expect(dec.push(close)).toEqual([{ type: 'close', code: 1000 }]);
  });

  test('splitHandshake keeps the frames that shared the segment', () => {
    const buf = new Uint8Array([
      ...enc('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n'),
      0x82,
      0x01,
      0x41,
    ]);
    const split = splitHandshake(buf)!;
    expect(split.head.status).toBe(101);
    expect(hex(split.rest)).toBe('820141');
  });
});

describe('httpupgrade', () => {
  test('sends the configured token and requires it back', () => {
    const text = Buffer.from(
      buildUpgradeRequest({ path: '/up', host: 'front.example', token: 'custom' }),
    ).toString();
    expect(text).toContain('Connection: Upgrade\r\n');
    expect(text).toContain('Upgrade: custom\r\n');

    const echoed = parseHttpHead(
      enc('HTTP/1.1 101 Switching Protocols\r\nUpgrade: custom\r\nConnection: Upgrade\r\n\r\n'),
    )!;
    expect(checkUpgradeResponse(echoed, 'custom')).toEqual({ ok: true });

    const wrong = parseHttpHead(
      enc('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'),
    )!;
    expect(checkUpgradeResponse(wrong, 'custom')).toEqual({ ok: false, reason: 'upgrade' });
    expect(DEFAULT_UPGRADE_TOKEN).toBe('websocket');
  });
});

describe('grpc framing and Hunk', () => {
  test('varints follow the protobuf encoding', () => {
    expect(hex(encodeVarint(0))).toBe('00');
    expect(hex(encodeVarint(127))).toBe('7f');
    expect(hex(encodeVarint(128))).toBe('8001');
    expect(hex(encodeVarint(300))).toBe('ac02');
    expect(decodeVarint(new Uint8Array([0xac, 0x02]), 0)).toEqual({ value: 300, next: 2 });
    expect(decodeVarint(new Uint8Array([0x80]), 0)).toBeNull();
  });

  test('a message is a compressed flag plus a big-endian length', () => {
    expect(hex(encodeGrpcFrame(new Uint8Array([1, 2, 3])))).toBe('0000000003010203');
  });

  test('Hunk puts the payload in field 1, wire type 2', () => {
    expect(hex(encodeHunk(enc('hi')))).toBe('0a026869');
    expect(Buffer.from(decodeHunk(encodeHunk(enc('hi')))).toString()).toBe('hi');
  });

  test('unknown Hunk fields are skipped rather than breaking the read', () => {
    // field 2 varint (tag 0x10) before field 1.
    const msg = new Uint8Array([0x10, 0x07, ...encodeHunk(enc('ok'))]);
    expect(Buffer.from(decodeHunk(msg)).toString()).toBe('ok');
  });

  test('the decoder waits for a whole message across chunk boundaries', () => {
    const dec = createGrpcDecoder();
    const framed = encodeHunkFrame(enc('payload'));
    expect(dec.push(framed.subarray(0, 4))).toEqual([]);
    const out = dec.push(framed.subarray(4));
    expect(out).toHaveLength(1);
    expect(Buffer.from(decodeHunk(out[0])).toString()).toBe('payload');
  });

  test('a compressed message is refused rather than silently misread', () => {
    const dec = createGrpcDecoder();
    expect(() => dec.push(new Uint8Array([1, 0, 0, 0, 1, 0]))).toThrow();
  });

  test('the path is the service name plus Tun', () => {
    expect(grpcPath('relay-svc')).toBe('/relay-svc/Tun');
    expect(grpcPath('/relay-svc/')).toBe('/relay-svc/Tun');
  });
});

describe('vless', () => {
  const uuid = '01234567-89ab-cdef-0123-456789abcdef';

  test('uuid parsing is strict', () => {
    expect(isUuid(uuid)).toBe(true);
    expect(isUuid('7:42')).toBe(false);
    expect(hex(uuidToBytes(uuid))).toBe('0123456789abcdef0123456789abcdef');
    expect(() => uuidToBytes('nope')).toThrow();
  });

  test('request header follows the version-0 layout', () => {
    const req = buildVlessRequest({ uuid, host: 'a.test', port: 80, payload: enc('GET /') });
    expect(hex(req.subarray(0, 1))).toBe('00'); // version
    expect(hex(req.subarray(1, 17))).toBe('0123456789abcdef0123456789abcdef');
    expect(req[17]).toBe(0x00); // no addons
    expect(req[18]).toBe(0x01); // TCP
    expect(req[19]).toBe(0x00);
    expect(req[20]).toBe(80);
    expect(req[21]).toBe(0x02); // domain
    expect(req[22]).toBe('a.test'.length);
    expect(Buffer.from(req.subarray(23, 29)).toString()).toBe('a.test');
    expect(Buffer.from(req.subarray(29)).toString()).toBe('GET /');
  });

  test('response header is consumed, addons included', () => {
    expect(parseVlessResponse(new Uint8Array([0x00]))).toBeNull();
    expect(parseVlessResponse(new Uint8Array([0x00, 0x00]))).toEqual({
      addonsLength: 0,
      headerLength: 2,
    });
    expect(parseVlessResponse(new Uint8Array([0x00, 0x02, 1]))).toBeNull();
    expect(parseVlessResponse(new Uint8Array([0x00, 0x02, 1, 2, 9]))).toEqual({
      addonsLength: 2,
      headerLength: 4,
    });
  });

  test('a non-VLESS first byte is a protocol error', () => {
    // What a front's own HTML error page looks like at this point ("<").
    expect(() => parseVlessResponse(enc('<html>'))).toThrow();
  });
});
