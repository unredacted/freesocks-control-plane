/**
 * Xray's `httpupgrade` transport: a bare RFC 9110 Upgrade dance with no
 * WebSocket framing at all. After the 101 the connection is a raw byte stream,
 * which is why this file only builds a request and validates a response head.
 *
 * The upgrade token is configurable on the transport; Xray's default is
 * `websocket` (it makes the request indistinguishable from a WebSocket opening
 * handshake to anything that only reads headers), so the slot's declared token
 * is used and `websocket` is only the fallback.
 */
import { headerHasToken, type HttpHead } from './http1';

export const DEFAULT_UPGRADE_TOKEN = 'websocket';

export function buildUpgradeRequest(opts: {
  path: string;
  host: string;
  token: string;
}): Uint8Array {
  const head =
    `GET ${opts.path} HTTP/1.1\r\n` +
    `Host: ${opts.host}\r\n` +
    'Connection: Upgrade\r\n' +
    `Upgrade: ${opts.token}\r\n` +
    '\r\n';
  return new TextEncoder().encode(head);
}

export type UpgradeVerdict =
  | { ok: true }
  | { ok: false; reason: 'status' | 'upgrade' | 'connection' };

export function checkUpgradeResponse(head: HttpHead, token: string): UpgradeVerdict {
  if (head.status !== 101) return { ok: false, reason: 'status' };
  // The token must be echoed: a front that answers 101 for something else has
  // not connected us to the transport.
  if ((head.headers['upgrade'] ?? '').toLowerCase() !== token.toLowerCase())
    return { ok: false, reason: 'upgrade' };
  if (!headerHasToken(head.headers['connection'], 'upgrade'))
    return { ok: false, reason: 'connection' };
  return { ok: true };
}
