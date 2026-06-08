/**
 * The CDN-blinding channel protocol: how a sealed request/response is built and
 * opened, shared by the client (browser) and the server "use node" action so
 * both agree on the wire format. Built on ./hpke.ts (seal/open) + ./envelope.ts
 * (codec, info, policy). Like hpke.ts, this needs full WebCrypto and runs only
 * in the browser and the Node action, never the default isolate.
 *
 * Two constructions:
 *   request 'seal': the client seals the request body to the server STATIC key
 *     (login: hides the account number). dir = 'req'.
 *   response 'reveal': the client sends a fresh ephemeral public key in the
 *     (plaintext) request; the server seals the response TO that ephemeral.
 *     Forward-secret against server-key compromise, used for every sensitive
 *     response. dir = 'resp'.
 */
import {
  RESP_EPH_FIELD,
  SUITE_ID,
  b64UrlToBytes,
  buildInfo,
  bytesToB64Url,
  decodeEnvelope,
  encodeEnvelope,
  type RoutePolicy,
  type SealedWire,
} from './envelope';
import {
  deserializePublicKey,
  generateEphemeralKeyPair,
  openFrom,
  sealTo,
  serializePublicKey,
} from './hpke';

const EMPTY_AAD = new Uint8Array(0);
const te = (s: string) => new TextEncoder().encode(s);
const td = (b: Uint8Array) => new TextDecoder().decode(b);

function reqInfo(kid: string, method: string, path: string): Uint8Array {
  return buildInfo({ suiteId: SUITE_ID, kid, method, path, dir: 'req' });
}
function respInfo(kid: string, method: string, path: string): Uint8Array {
  return buildInfo({ suiteId: SUITE_ID, kid, method, path, dir: 'resp' });
}

// --- client (browser) ---------------------------------------------------------

export interface ClientPrepared {
  /** The body to actually send (a `{fsSealed}` envelope for 'seal', else the plain object with fsRespEph added). */
  body: unknown;
  /** Present for 'reveal' routes: the ephemeral private key needed to open the response. */
  respEphPriv?: CryptoKey;
  /**
   * Present for 'reveal' routes: the base64url ephemeral public key. The caller
   * places it in the body for a POST (already done in `body`) or in the
   * `x-fs-resp-eph` header for a GET (which has no body).
   */
  respEphPubB64?: string;
}

/** Prepare an outbound request per the route policy. */
export async function clientPrepareRequest(opts: {
  serverPub: CryptoKey;
  serverKid: string;
  method: string;
  path: string;
  policy: RoutePolicy;
  bodyObj?: unknown;
}): Promise<ClientPrepared> {
  const outBody: Record<string, unknown> = { ...((opts.bodyObj as object) ?? {}) };
  let respEphPriv: CryptoKey | undefined;
  let respEphPubB64: string | undefined;

  if (opts.policy.response === 'reveal') {
    const eph = await generateEphemeralKeyPair();
    respEphPriv = eph.privateKey;
    respEphPubB64 = bytesToB64Url(await serializePublicKey(eph.publicKey));
    outBody[RESP_EPH_FIELD] = respEphPubB64;
  }

  if (opts.policy.request === 'seal') {
    const pt = te(JSON.stringify(outBody));
    const { enc, ct } = await sealTo(
      opts.serverPub,
      reqInfo(opts.serverKid, opts.method, opts.path),
      EMPTY_AAD,
      pt,
    );
    return {
      body: encodeEnvelope({ suiteId: SUITE_ID, kid: opts.serverKid, enc, ct }),
      respEphPriv,
      respEphPubB64,
    };
  }
  return { body: outBody, respEphPriv, respEphPubB64 };
}

/** Open a sealed response with the ephemeral private key from clientPrepareRequest. */
export async function clientOpenResponse(opts: {
  serverKid: string;
  method: string;
  path: string;
  respEphPriv: CryptoKey;
  wire: SealedWire;
}): Promise<unknown> {
  const d = decodeEnvelope(opts.wire);
  if (!d.enc) throw new Error('sealed response missing enc');
  const pt = await openFrom(
    opts.respEphPriv,
    d.enc,
    respInfo(opts.serverKid, opts.method, opts.path),
    EMPTY_AAD,
    d.ct,
  );
  return JSON.parse(td(pt));
}

// --- server (the "use node" action) -------------------------------------------

/** Open a sealed request body with the server static private key. Returns the plaintext object. */
export async function serverOpenRequest(opts: {
  serverPriv: CryptoKey;
  serverKid: string;
  method: string;
  path: string;
  wireBody: SealedWire;
}): Promise<unknown> {
  const d = decodeEnvelope(opts.wireBody);
  if (!d.enc) throw new Error('sealed request missing enc');
  const pt = await openFrom(
    opts.serverPriv,
    d.enc,
    reqInfo(opts.serverKid, opts.method, opts.path),
    EMPTY_AAD,
    d.ct,
  );
  return JSON.parse(td(pt));
}

/** Seal a response to the client's ephemeral public key (reveal leg). */
export async function serverSealResponse(opts: {
  serverKid: string;
  method: string;
  path: string;
  respEphPubB64: string;
  responseObj: unknown;
}): Promise<SealedWire> {
  const respPub = await deserializePublicKey(b64UrlToBytes(opts.respEphPubB64));
  const pt = te(JSON.stringify(opts.responseObj));
  const { enc, ct } = await sealTo(
    respPub,
    respInfo(opts.serverKid, opts.method, opts.path),
    EMPTY_AAD,
    pt,
  );
  return encodeEnvelope({ enc, ct });
}
