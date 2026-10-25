/**
 * Request signing between FCP and its client-check service: HMAC-SHA256 under
 * the shared `EDGE_CLIENT_CHECK_SECRET` over the method, the path, the request
 * time and the body's SHA-256. WebCrypto only, so the same code runs in Convex's
 * default runtime and in the service (Bun).
 *
 * The service refuses a time outside `CLIENT_CHECK_MAX_SKEW_MS` and a signature
 * it has already seen within twice that window (`ReplayGuard`), so a captured
 * request cannot be sent again.
 */
import { CLIENT_CHECK_MAX_SKEW_MS } from './protocol';

const enc = new TextEncoder();

function hex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function sha256Hex(text: string): Promise<string> {
  return hex(await crypto.subtle.digest('SHA-256', enc.encode(text)));
}

/** The text the signature covers. */
export async function signedText(
  method: string,
  path: string,
  time: string,
  body: string,
): Promise<string> {
  return `${method.toUpperCase()}\n${path}\n${time}\n${await sha256Hex(body)}`;
}

export async function signRequest(
  secret: string,
  method: string,
  path: string,
  time: string,
  body: string,
): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return hex(
    await crypto.subtle.sign('HMAC', key, enc.encode(await signedText(method, path, time, body))),
  );
}

/** Equal-length comparison without an early exit. */
export function sameHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Signatures seen recently; one is accepted once. */
export class ReplayGuard {
  private seen = new Map<string, number>();
  constructor(private readonly windowMs = 2 * CLIENT_CHECK_MAX_SKEW_MS) {}

  /** False when the signature was already used inside the window. */
  admit(signature: string, now: number): boolean {
    for (const [s, at] of this.seen) if (at < now - this.windowMs) this.seen.delete(s);
    if (this.seen.has(signature)) return false;
    this.seen.set(signature, now);
    return true;
  }
}

export type VerifyOutcome = 'ok' | 'bad_time' | 'bad_signature' | 'replayed';

export async function verifyRequest(
  secret: string,
  req: {
    method: string;
    path: string;
    time: string | null;
    signature: string | null;
    body: string;
  },
  now: number,
  guard: ReplayGuard,
): Promise<VerifyOutcome> {
  const t = Number(req.time);
  if (!req.time || !/^\d{1,16}$/.test(req.time) || Math.abs(now - t) > CLIENT_CHECK_MAX_SKEW_MS)
    return 'bad_time';
  if (!req.signature || !/^[0-9a-f]{64}$/.test(req.signature)) return 'bad_signature';
  const expected = await signRequest(secret, req.method, req.path, req.time, req.body);
  if (!sameHex(expected, req.signature)) return 'bad_signature';
  return guard.admit(req.signature, now) ? 'ok' : 'replayed';
}
