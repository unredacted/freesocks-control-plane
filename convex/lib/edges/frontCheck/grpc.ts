/**
 * Xray's `grpc` transport, on the wire: an HTTP/2 stream to
 * `POST /<serviceName>/Tun` carrying gRPC length-prefixed messages, each one a
 * protobuf `Hunk { bytes data = 1; }` wrapping a slice of the proxied stream.
 *
 * A gRPC library is not used: it would own the connection, the ALPN and the
 * error mapping, and the whole point here is to observe what the front returns
 * (a CDN with gRPC disabled answers the HTTP/2 request itself, or closes the
 * stream with trailers, and that must be reported as such rather than as a
 * generic RPC error).
 */

/** gRPC message framing: 1 byte compressed flag + 4 byte big-endian length. */
export function encodeGrpcFrame(message: Uint8Array): Uint8Array {
  const out = new Uint8Array(5 + message.length);
  out[0] = 0; // not compressed
  new DataView(out.buffer).setUint32(1, message.length);
  out.set(message, 5);
  return out;
}

/** Protobuf varint, unsigned. */
export function encodeVarint(n: number): Uint8Array {
  const bytes: number[] = [];
  let v = n;
  do {
    let b = v & 0x7f;
    v = Math.floor(v / 128);
    if (v > 0) b |= 0x80;
    bytes.push(b);
  } while (v > 0);
  return new Uint8Array(bytes);
}

export function decodeVarint(
  buf: Uint8Array,
  offset: number,
): { value: number; next: number } | null {
  let value = 0;
  let shift = 1;
  for (let i = offset; i < buf.length; i++) {
    value += (buf[i] & 0x7f) * shift;
    if ((buf[i] & 0x80) === 0) return { value, next: i + 1 };
    shift *= 128;
    if (i - offset > 9) throw new Error('varint too long');
  }
  return null;
}

/** `Hunk { bytes data = 1; }`: field 1, wire type 2 (tag byte 0x0a). */
export function encodeHunk(data: Uint8Array): Uint8Array {
  const len = encodeVarint(data.length);
  const out = new Uint8Array(1 + len.length + data.length);
  out[0] = 0x0a;
  out.set(len, 1);
  out.set(data, 1 + len.length);
  return out;
}

/**
 * Read `data` out of a Hunk. Unknown fields are skipped so a peer that adds one
 * does not break the check; a message without field 1 yields an empty slice.
 */
export function decodeHunk(message: Uint8Array): Uint8Array {
  let out = new Uint8Array(0);
  let i = 0;
  while (i < message.length) {
    const tag = decodeVarint(message, i);
    if (!tag) break;
    i = tag.next;
    const field = Math.floor(tag.value / 8);
    const wire = tag.value & 7;
    if (wire === 2) {
      const len = decodeVarint(message, i);
      if (!len) break;
      i = len.next;
      const slice = message.subarray(i, i + len.value);
      i += len.value;
      if (field === 1) {
        const merged = new Uint8Array(out.length + slice.length);
        merged.set(out, 0);
        merged.set(slice, out.length);
        out = merged;
      }
    } else if (wire === 0) {
      const v = decodeVarint(message, i);
      if (!v) break;
      i = v.next;
    } else if (wire === 5) i += 4;
    else if (wire === 1) i += 8;
    else break;
  }
  return out;
}

export function encodeHunkFrame(data: Uint8Array): Uint8Array {
  return encodeGrpcFrame(encodeHunk(data));
}

export interface GrpcDecoder {
  /** Feed DATA-frame bytes; returns every complete gRPC message payload. */
  push(chunk: Uint8Array): Uint8Array[];
}

export function createGrpcDecoder(): GrpcDecoder {
  let buf: Uint8Array = new Uint8Array(0);
  return {
    push(chunk: Uint8Array): Uint8Array[] {
      const merged = new Uint8Array(buf.length + chunk.length);
      merged.set(buf, 0);
      merged.set(chunk, buf.length);
      buf = merged;
      const out: Uint8Array[] = [];
      for (;;) {
        if (buf.length < 5) return out;
        if (buf[0] !== 0) throw new Error('compressed grpc message');
        const len = new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint32(1);
        if (buf.length < 5 + len) return out;
        out.push(buf.slice(5, 5 + len));
        buf = buf.slice(5 + len);
      }
    },
  };
}

/** Xray serves the bidirectional stream as `Tun` under the configured service. */
export function grpcPath(serviceName: string): string {
  const name = serviceName.replace(/^\/+|\/+$/g, '');
  return `/${name}/Tun`;
}
