/**
 * Client-side CDN-blinding seam. Seals outbound requests and opens sealed
 * responses per the route policy, using the server public key + kid baked into
 * the bundle at build (VITE_FS_SERVER_HPKE_PK / VITE_FS_SERVER_HPKE_KID).
 *
 * Gated on the pinned key being present: a build without it leaves sealing off
 * and every request goes plaintext (the server's dual-mode handles that), so the
 * SPA still works in environments where the key was not baked.
 *
 * The HPKE crypto here runs in the browser, which has full WebCrypto including
 * HKDF, so importing ./hpke (via channel) is fine on the client.
 */
import {
  b64UrlToBytes,
  isSealedWire,
  routePolicy,
  type RoutePolicy,
} from '../../shared/crypto/envelope';
import { clientOpenResponse, clientPrepareRequest } from '../../shared/crypto/channel';
import { deserializePublicKey } from '../../shared/crypto/hpke';

const PK_B64 = import.meta.env.VITE_FS_SERVER_HPKE_PK as string | undefined;
const KID = import.meta.env.VITE_FS_SERVER_HPKE_KID as string | undefined;

export function sealingEnabled(): boolean {
  return !!PK_B64 && !!KID;
}

let _serverPub: Promise<CryptoKey> | null = null;
function serverPub(): Promise<CryptoKey> {
  return (_serverPub ??= deserializePublicKey(b64UrlToBytes(PK_B64!)));
}

export interface OutboundSeal {
  policy: RoutePolicy;
  /** Replacement request body string (sealed envelope, or plain JSON carrying fsRespEph). */
  body?: string;
  /** Header to add (GET reveal routes carry the ephemeral pubkey in a header). */
  header?: { name: string; value: string };
  /** Kept to open a reveal-leg response. */
  respEphPriv?: CryptoKey;
}

/** Prepare a sealed outbound request, or undefined if the route is not sealed (then send plaintext). */
export async function prepareOutbound(
  path: string,
  method: string,
  bodyStr: string | undefined,
): Promise<OutboundSeal | undefined> {
  if (!sealingEnabled()) return undefined;
  const policy = routePolicy(path);
  if (!policy) return undefined;
  const m = method.toUpperCase();
  const prep = await clientPrepareRequest({
    serverPub: await serverPub(),
    serverKid: KID!,
    method: m,
    path,
    policy,
    bodyObj: bodyStr ? safeParse(bodyStr) : undefined,
  });
  const out: OutboundSeal = { policy, respEphPriv: prep.respEphPriv };
  if (policy.request === 'seal') {
    out.body = JSON.stringify(prep.body);
  } else if (policy.response === 'reveal') {
    if (m === 'GET' || m === 'HEAD') {
      out.header = { name: 'x-fs-resp-eph', value: prep.respEphPubB64! };
    } else {
      out.body = JSON.stringify(prep.body);
    }
  }
  return out;
}

/** Open a sealed reveal-leg response; pass through anything that is not sealed. */
export async function openInbound(
  seal: OutboundSeal,
  path: string,
  method: string,
  json: unknown,
): Promise<unknown> {
  if (seal.policy.response === 'reveal' && seal.respEphPriv && isSealedWire(json)) {
    return clientOpenResponse({
      serverKid: KID!,
      method: method.toUpperCase(),
      path,
      respEphPriv: seal.respEphPriv,
      wire: json,
    });
  }
  return json;
}

function safeParse(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return undefined;
  }
}
