/**
 * RFC 6455 client side, only as much as the front check needs: the opening
 * handshake (including the `Sec-WebSocket-Accept` proof), masked binary frames
 * out, and an incremental decoder for what comes back.
 *
 * A WebSocket library is deliberately not used. The point of the check is to
 * observe exactly what the front and the node do on the wire, so the bytes are
 * built and parsed here and pinned by fixtures; a library would also open its
 * own socket, and this handshake has to ride the TLS socket we already hold.
 */
import { createHash, randomBytes as nodeRandomBytes } from 'node:crypto';
import { headerHasToken, parseHttpHead, type HttpHead } from './http1';

/** RFC 6455 §1.3. A wire constant: never "clean this up". */
export const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

export const WS_OPCODE = {
  continuation: 0x0,
  text: 0x1,
  binary: 0x2,
  close: 0x8,
  ping: 0x9,
  pong: 0xa,
} as const;

function toBase64(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function wsAcceptKey(secWebSocketKey: string): string {
  return createHash('sha1').update(`${secWebSocketKey}${WS_GUID}`).digest('base64');
}

/** 16 random bytes, base64. The seam exists so a test can pin the handshake. */
export function newWsKey(randomBytes: (n: number) => Uint8Array = nodeRandomBytes): string {
  return toBase64(randomBytes(16));
}

export function buildWsHandshake(opts: { path: string; host: string; key: string }): Uint8Array {
  const head =
    `GET ${opts.path} HTTP/1.1\r\n` +
    `Host: ${opts.host}\r\n` +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    `Sec-WebSocket-Key: ${opts.key}\r\n` +
    'Sec-WebSocket-Version: 13\r\n' +
    '\r\n';
  return new TextEncoder().encode(head);
}

export type HandshakeVerdict =
  | { ok: true; head: HttpHead }
  | { ok: false; reason: 'status' | 'upgrade' | 'connection' | 'accept'; head: HttpHead };

/** RFC 6455 §4.1 client validation of the server's opening handshake. */
export function checkWsHandshake(head: HttpHead, key: string): HandshakeVerdict {
  if (head.status !== 101) return { ok: false, reason: 'status', head };
  if ((head.headers['upgrade'] ?? '').toLowerCase() !== 'websocket')
    return { ok: false, reason: 'upgrade', head };
  if (!headerHasToken(head.headers['connection'], 'upgrade'))
    return { ok: false, reason: 'connection', head };
  if (head.headers['sec-websocket-accept'] !== wsAcceptKey(key))
    return { ok: false, reason: 'accept', head };
  return { ok: true, head };
}

/** Client frames are always masked (RFC 6455 §5.3) and always FIN here. */
export function encodeWsFrame(
  opcode: number,
  payload: Uint8Array,
  maskKey: Uint8Array,
): Uint8Array {
  const len = payload.length;
  const extra = len < 126 ? 0 : len < 65536 ? 2 : 8;
  const out = new Uint8Array(2 + extra + 4 + len);
  out[0] = 0x80 | opcode;
  if (extra === 0) out[1] = 0x80 | len;
  else if (extra === 2) {
    out[1] = 0x80 | 126;
    out[2] = (len >> 8) & 0xff;
    out[3] = len & 0xff;
  } else {
    out[1] = 0x80 | 127;
    // Lengths above 2^32 cannot occur here; the high word stays zero.
    const view = new DataView(out.buffer);
    view.setUint32(2, 0);
    view.setUint32(6, len);
  }
  out.set(maskKey, 2 + extra);
  const off = 2 + extra + 4;
  for (let i = 0; i < len; i++) out[off + i] = payload[i] ^ maskKey[i & 3];
  return out;
}

export function encodeWsClose(code = 1000, maskKey: Uint8Array): Uint8Array {
  const payload = new Uint8Array([(code >> 8) & 0xff, code & 0xff]);
  return encodeWsFrame(WS_OPCODE.close, payload, maskKey);
}

export type WsEvent =
  | { type: 'message'; data: Uint8Array }
  | { type: 'close'; code: number | null }
  | { type: 'ping'; data: Uint8Array }
  | { type: 'pong'; data: Uint8Array };

export interface WsDecoder {
  /** Feed bytes; returns every event that completed with this chunk. */
  push(chunk: Uint8Array): WsEvent[];
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/**
 * Incremental frame decoder. Data frames are reassembled across continuation
 * frames; control frames (never fragmented, ≤125 bytes) surface immediately.
 * Server frames should not be masked, but one that is gets unmasked rather than
 * rejected: the check is about the tunnel working, not about policing peers.
 */
export function createWsDecoder(): WsDecoder {
  let buf: Uint8Array = new Uint8Array(0);
  let fragments: Uint8Array | null = null;
  return {
    push(chunk: Uint8Array): WsEvent[] {
      buf = concat(buf, chunk);
      const events: WsEvent[] = [];
      for (;;) {
        if (buf.length < 2) return events;
        const fin = (buf[0] & 0x80) !== 0;
        const opcode = buf[0] & 0x0f;
        const masked = (buf[1] & 0x80) !== 0;
        let len = buf[1] & 0x7f;
        let off = 2;
        if (len === 126) {
          if (buf.length < 4) return events;
          len = (buf[2] << 8) | buf[3];
          off = 4;
        } else if (len === 127) {
          if (buf.length < 10) return events;
          const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
          const high = view.getUint32(2);
          if (high !== 0) throw new Error('ws frame too large');
          len = view.getUint32(6);
          off = 10;
        }
        let maskKey: Uint8Array | null = null;
        if (masked) {
          if (buf.length < off + 4) return events;
          maskKey = buf.subarray(off, off + 4);
          off += 4;
        }
        if (buf.length < off + len) return events;
        let payload: Uint8Array = buf.slice(off, off + len);
        if (maskKey) for (let i = 0; i < payload.length; i++) payload[i] ^= maskKey[i & 3];
        buf = buf.slice(off + len);

        if (opcode === WS_OPCODE.close) {
          const code = payload.length >= 2 ? (payload[0] << 8) | payload[1] : null;
          events.push({ type: 'close', code });
          continue;
        }
        if (opcode === WS_OPCODE.ping) {
          events.push({ type: 'ping', data: payload });
          continue;
        }
        if (opcode === WS_OPCODE.pong) {
          events.push({ type: 'pong', data: payload });
          continue;
        }
        if (opcode === WS_OPCODE.continuation) {
          payload = fragments ? concat(fragments, payload) : payload;
        } else if (fragments) {
          throw new Error('ws interleaved data frame');
        }
        if (!fin) {
          fragments = payload;
          continue;
        }
        fragments = null;
        events.push({ type: 'message', data: payload });
      }
    },
  };
}

/**
 * Split a handshake response from the frames that may already follow it in the
 * same TCP segment. Returns null while the head is incomplete.
 */
export function splitHandshake(buf: Uint8Array): { head: HttpHead; rest: Uint8Array } | null {
  const head = parseHttpHead(buf);
  if (!head) return null;
  return { head, rest: buf.slice(head.headerLength) };
}
