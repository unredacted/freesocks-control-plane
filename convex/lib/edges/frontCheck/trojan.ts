'use node';
/**
 * The Trojan request header: the authenticated leg of the front check for a
 * Trojan transport, as `vless.ts` is for a VLESS one. Only a node holding the
 * qualification account's Trojan password accepts the request; anything else
 * (a front answering for itself, a node that does not know the account) never
 * returns the target's bytes. Trojan has no response header: the target's
 * bytes are the answer.
 *
 * Request layout (trojan-gfw protocol, as Xray serves it):
 *   hex(SHA-224(password))(56) CRLF command(1) addrType(1) addr(...) port(2 BE) CRLF payload(...)
 */
import { createHash } from 'node:crypto';

export const TROJAN_CMD_CONNECT = 0x01;
export const TROJAN_ADDR_DOMAIN = 0x03;
const CRLF = [0x0d, 0x0a];

export interface TrojanRequest {
  password: string;
  /** Destination host; only the domain address type is used by the check. */
  host: string;
  port: number;
  payload?: Uint8Array;
}

/** The 56 hex characters a Trojan server keys its accounts by. */
export function trojanKey(password: string): Uint8Array {
  return new TextEncoder().encode(createHash('sha224').update(password, 'utf8').digest('hex'));
}

export function buildTrojanRequest(req: TrojanRequest): Uint8Array {
  if (!req.password) throw new Error('empty password');
  const domain = new TextEncoder().encode(req.host);
  if (domain.length === 0 || domain.length > 255) throw new Error('bad domain length');
  const key = trojanKey(req.password);
  const payload = req.payload ?? new Uint8Array(0);
  const out = new Uint8Array(key.length + 2 + 1 + 1 + 1 + domain.length + 2 + 2 + payload.length);
  let i = 0;
  out.set(key, i);
  i += key.length;
  out.set(CRLF, i);
  i += 2;
  out[i++] = TROJAN_CMD_CONNECT;
  out[i++] = TROJAN_ADDR_DOMAIN;
  out[i++] = domain.length;
  out.set(domain, i);
  i += domain.length;
  out[i++] = (req.port >> 8) & 0xff;
  out[i++] = req.port & 0xff;
  out.set(CRLF, i);
  i += 2;
  out.set(payload, i);
  return out;
}
