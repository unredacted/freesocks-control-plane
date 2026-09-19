/**
 * Xray's `xhttp` transport in `packet-up` mode, on the wire (XTLS/Xray-core
 * discussion #4113): the downstream is one long `GET <path>/<session>` answered
 * as a server-sent-events body (`Content-Type: text/event-stream`, no
 * buffering), the upstream is a sequence of `POST <path>/<session>/<seq>`
 * requests, each carrying one slice of the proxied byte stream, which the
 * server reorders by `seq`. Nothing is framed: the bodies ARE the stream.
 *
 * Packet-up is the one mode every CDN can pass (the stream modes need a front
 * that streams request bodies, which Cloudflare gates behind its gRPC switch),
 * so it is the mode the proof speaks whatever the inbound declares as long as
 * the inbound accepts it (`auto` and `packet-up`; the stream-only modes refuse
 * a packet-up client, so they are reported as unsupported rather than tried).
 *
 * Both directions ride one HTTP/2 session (Xray serves h2 behind TLS and every
 * CDN speaks it to clients), so the check needs a single TLS connection like the
 * other transports. An HTTP library is not used for the same reason as gRPC:
 * what the front answers for itself must be observable as such.
 */

/** The modes a packet-up client can talk to. */
export const XHTTP_PACKET_UP_MODES: ReadonlySet<string> = new Set(['auto', 'packet-up']);

export const XHTTP_DEFAULT_MODE = 'auto';

/** `<path>/<session>` with exactly one slash between, whatever the path ends with. */
export function xhttpSessionPath(path: string, session: string): string {
  const base = (path || '/').replace(/\/+$/, '');
  return `${base}/${session}`;
}

export function xhttpUploadPath(path: string, session: string, seq: number): string {
  return `${xhttpSessionPath(path, session)}/${seq}`;
}

/** A session id from 16 random bytes, in the UUID shape Xray's own client uses. */
export function xhttpSessionId(randomBytes: (n: number) => Uint8Array): string {
  const b = randomBytes(16);
  const hex = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export type XhttpDownVerdict =
  | { ok: true }
  | { ok: false; reason: 'status' | 'content_type'; status: number };

/**
 * The downstream response head. Xray answers 200 with `text/event-stream`
 * (or no content type at all under `noSSEHeader`); a 200 that is HTML or JSON
 * is the front answering for itself and never reaches the inbound.
 */
export function checkXhttpDownResponse(
  status: number,
  contentType: string | undefined,
): XhttpDownVerdict {
  if (status !== 200) return { ok: false, reason: 'status', status };
  const ct = (contentType ?? '').toLowerCase();
  if (ct === '' || ct.startsWith('text/event-stream') || ct.startsWith('application/octet-stream'))
    return { ok: true };
  return { ok: false, reason: 'content_type', status };
}

/**
 * The padding every XHTTP request must carry: Xray's server answers 400 unless
 * `x_padding` is 100 to 1000 bytes long (its `xPaddingBytes` default), read
 * from the `Referer`'s query, which is where Xray's own client puts it so the
 * request line stays clean for caches and needs no CORS preflight.
 */
export function xhttpReferer(
  hostname: string,
  path: string,
  randomBytes: (n: number) => Uint8Array,
): string {
  const r = randomBytes(2);
  // 100..899: well inside the default range at both ends.
  const length = 100 + (((r[0] << 8) | r[1]) % 800);
  return `https://${hostname}${path || '/'}?x_padding=${'X'.repeat(length)}`;
}
