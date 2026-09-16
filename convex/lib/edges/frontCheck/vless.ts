/**
 * The VLESS request/response header, which is what makes the front check an
 * AUTHENTICATED proof rather than a handshake heuristic: only the node holding
 * the qualification account's UUID can answer it, and only a node that actually
 * proxies can return the target's bytes after it.
 *
 * Request layout (VLESS version 0):
 *   version(1) uuid(16) addonsLen(1) addons(n) command(1) port(2 BE)
 *   addrType(1) addr(...) payload(...)
 * Response layout:
 *   version(1) addonsLen(1) addons(n) payload(...)
 */

export const VLESS_VERSION = 0x00;
export const VLESS_CMD_TCP = 0x01;
export const VLESS_ADDR_DOMAIN = 0x02;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(value: string): boolean {
  return UUID_RE.test(value);
}

export function uuidToBytes(uuid: string): Uint8Array {
  if (!isUuid(uuid)) throw new Error('not a uuid');
  const hex = uuid.replace(/-/g, '');
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export interface VlessRequest {
  uuid: string;
  /** Destination host; only the domain address type is used by the check. */
  host: string;
  port: number;
  payload?: Uint8Array;
}

export function buildVlessRequest(req: VlessRequest): Uint8Array {
  const domain = new TextEncoder().encode(req.host);
  if (domain.length === 0 || domain.length > 255) throw new Error('bad domain length');
  const payload = req.payload ?? new Uint8Array(0);
  const out = new Uint8Array(1 + 16 + 1 + 1 + 2 + 1 + 1 + domain.length + payload.length);
  let i = 0;
  out[i++] = VLESS_VERSION;
  out.set(uuidToBytes(req.uuid), i);
  i += 16;
  out[i++] = 0x00; // no addons
  out[i++] = VLESS_CMD_TCP;
  out[i++] = (req.port >> 8) & 0xff;
  out[i++] = req.port & 0xff;
  out[i++] = VLESS_ADDR_DOMAIN;
  out[i++] = domain.length;
  out.set(domain, i);
  i += domain.length;
  out.set(payload, i);
  return out;
}

export interface VlessResponse {
  addonsLength: number;
  /** Bytes the response header consumed; the tunnel payload starts here. */
  headerLength: number;
}

/**
 * Returns null while the header is incomplete. Throws when the first byte is
 * not version 0: that is a peer speaking something else (or a front injecting
 * its own body), which the caller reports as a failed authentication.
 */
export function parseVlessResponse(buf: Uint8Array): VlessResponse | null {
  if (buf.length < 2) return null;
  if (buf[0] !== VLESS_VERSION) throw new Error('bad vless version');
  const addonsLength = buf[1];
  const headerLength = 2 + addonsLength;
  if (buf.length < headerLength) return null;
  return { addonsLength, headerLength };
}
