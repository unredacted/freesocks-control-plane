/**
 * The little bit of HTTP/1.1 the front check needs, hand-rolled.
 *
 * `node:http` cannot be used for either end of this: the transport handshakes
 * are 101 upgrades whose socket we must keep, and the 204 we look for comes
 * back from INSIDE the tunnel (a byte stream the runtime knows nothing about).
 * Everything here is incremental (call it again as more bytes arrive) and pure,
 * so the codec tests can drive it on fixtures.
 */

const CRLF = '\r\n';

export interface HttpHead {
  status: number;
  /** Lowercased header names; repeats joined with ", " as RFC 9110 allows. */
  headers: Record<string, string>;
  /** Bytes consumed by the status line + headers + the blank line. */
  headerLength: number;
}

const decoder = new TextDecoder('latin1');

function indexOfDoubleCrlf(buf: Uint8Array): number {
  for (let i = 3; i < buf.length; i++) {
    if (buf[i] === 10 && buf[i - 1] === 13 && buf[i - 2] === 10 && buf[i - 3] === 13) return i + 1;
  }
  return -1;
}

/**
 * Parse a response head. Returns null while the head is still incomplete, so a
 * caller can simply retry on every chunk. Throws only on a malformed status
 * line, which is a protocol error rather than "more bytes needed".
 */
export function parseHttpHead(buf: Uint8Array): HttpHead | null {
  const end = indexOfDoubleCrlf(buf);
  if (end < 0) return null;
  const text = decoder.decode(buf.subarray(0, end));
  const lines = text.split(CRLF);
  const statusLine = lines[0] ?? '';
  const m = /^HTTP\/1\.[01] (\d{3})/.exec(statusLine);
  if (!m) throw new Error('malformed status line');
  const headers: Record<string, string> = {};
  for (const line of lines.slice(1)) {
    if (!line) continue;
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    const name = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    headers[name] = headers[name] === undefined ? value : `${headers[name]}, ${value}`;
  }
  return { status: Number(m[1]), headers, headerLength: end };
}

/** A header whose comma-separated tokens contain `token`, case-insensitively. */
export function headerHasToken(value: string | undefined, token: string): boolean {
  if (!value) return false;
  return value
    .split(',')
    .map((t) => t.trim().toLowerCase())
    .includes(token.toLowerCase());
}

/**
 * Response headers that identify a CDN-generated answer. Used only to describe
 * a failure precisely; the decision is always "did the transport answer".
 */
const FRONT_HEADERS = ['cf-ray', 'x-served-by', 'x-cache', 'fastly-io-info'];

export function looksFrontGenerated(head: HttpHead): boolean {
  if (FRONT_HEADERS.some((h) => head.headers[h] !== undefined)) return true;
  const server = head.headers['server'];
  // A `server` header at all on a 101 path is unusual; only flag known fronts.
  return server !== undefined && /^(cloudflare|varnish|artifactory-cdn)/i.test(server);
}

export function buildRequest(
  method: string,
  path: string,
  headers: ReadonlyArray<readonly [string, string]>,
): Uint8Array {
  const head =
    `${method} ${path} HTTP/1.1${CRLF}` +
    headers.map(([k, v]) => `${k}: ${v}${CRLF}`).join('') +
    CRLF;
  return new TextEncoder().encode(head);
}

/**
 * The probe sent through the tunnel. `Connection: close` so the origin ends the
 * stream itself, which is what makes the orderly-close step observable.
 */
export function tunnelProbeRequest(host: string, path: string): Uint8Array {
  return buildRequest('GET', path, [
    ['Host', host],
    ['Connection', 'close'],
  ]);
}
