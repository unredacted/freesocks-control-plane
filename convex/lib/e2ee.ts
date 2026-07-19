/**
 * Isolate-side sealing wrapper for the CDN-blinding channel. `sealed(handler)`
 * wraps a public httpAction: it opens a sealed request and/or seals the response
 * by delegating the actual HPKE to the "use node" action in ./e2eeCrypto.ts (the
 * default isolate lacks subtle HKDF, Phase 0 finding).
 *
 * Per-route behavior comes from SEALED_ROUTES (envelope.ts). This module imports
 * only the pure ./envelope helpers, never ./hpke, so it is isolate-safe.
 *
 * Dual-mode (so this rolls out without a flag day): a request that is not sealed
 * (no envelope on a 'seal' route, no fsRespEph on a 'reveal' route) passes
 * through and the response is returned in plaintext. Error responses (non-2xx)
 * are never sealed; the client treats them as plaintext.
 */
import { httpAction } from '../_generated/server';
import type { ActionCtx } from '../_generated/server';
import { internal } from '../_generated/api';
import { errorJson, PayloadTooLargeError, readBodyTextCapped } from './http';
import {
  RESP_EPH_FIELD,
  isSealedWire,
  routePolicy,
  type SealedWire,
} from '../../src/shared/crypto/envelope';

type RawHandler = (ctx: ActionCtx, req: Request) => Promise<Response>;

/**
 * A Request-like view over the inbound request with a replacement parsed body.
 * We do NOT reconstruct a real Request: the Convex isolate does not let you read
 * a body back out of `new Request(url, { body })`, which silently breaks the
 * handler's readJson(). The handlers only touch `.headers`, `.json()`, `.text()`,
 * `.url`, and `.method`, so this delegating object suffices and keeps the
 * original headers (cookie, etc.).
 *
 * `__fsWireBody` carries the ORIGINAL wire body bytes (before decrypt/strip) so
 * the PoP bodyHash in lib/http.wireBodyText hashes exactly what the client
 * signed, while the handler's `.text()` sees the transformed (decrypted /
 * fsRespEph-stripped) body.
 */
function proxyReq(req: Request, bodyObj: unknown, rawWireBody: string): Request {
  const text = JSON.stringify(bodyObj ?? {});
  return {
    url: req.url,
    method: req.method,
    headers: req.headers,
    json: async () => JSON.parse(text),
    text: async () => text,
    __fsWireBody: rawWireBody,
  } as unknown as Request;
}

export function sealed(handler: RawHandler) {
  return httpAction(async (ctx, req): Promise<Response> => {
    try {
      return await sealedInner(ctx, req, handler);
    } catch (e) {
      // The wrapper reads the wire body itself (before the handler's readJson),
      // so the body cap surfaces here for sealed routes.
      if (e instanceof PayloadTooLargeError) {
        return errorJson('request.too_large', 'Request body too large', 413);
      }
      // Mirror guard(): an uncaught handler error must not surface runtime 500
      // text (internal detail) — generic envelope + server-side log.
      console.error(
        `[http] unhandled sealed-route error: ${e instanceof Error ? e.message : String(e)}`,
      );
      return errorJson('server.error', 'Something went wrong. Please try again later.', 500);
    }
  });
}

async function sealedInner(ctx: ActionCtx, req: Request, handler: RawHandler): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;
  const method = req.method.toUpperCase();
  const policy = routePolicy(path, method);
  if (!policy) return handler(ctx, req);

  // H1 (CDN-blinding posture): with FS_E2EE_REQUIRED=true the dual-mode rollout
  // ends for MEMBER routes — an unsealed login body (or a reveal request with no
  // response ephemeral) is REJECTED instead of passed through in plaintext, so
  // the account number can never transit TLS-terminating infrastructure in the
  // clear. Member routes only: admin SEAL_REQ routes must keep accepting
  // plaintext from `fsv1_` token / Ansible callers, which cannot seal.
  // Flip this on ONLY once the deployed SPA was built with the HPKE keys baked
  // (VITE_FS_SERVER_HPKE_PK/KID) — a dark client cannot seal and will be
  // refused. The e2ee.sealed_required code makes the posture debuggable.
  const e2eeRequired =
    process.env.FS_E2EE_REQUIRED === 'true' && !path.startsWith('/api/v1/admin/');
  const sealedRequired = (): Response =>
    errorJson(
      'e2ee.sealed_required',
      'This deployment requires an end-to-end encrypted client. Please update your app or use the official web client.',
      400,
    );

  let handlerReq = req;
  let respEphPubB64: string | undefined;

  if (policy.response === 'reveal') {
    if (method === 'GET' || method === 'HEAD') {
      respEphPubB64 = req.headers.get('x-fs-resp-eph') ?? undefined;
    } else {
      const raw = await readBodyTextCapped(req);
      let bodyObj: Record<string, unknown> = {};
      if (raw) {
        try {
          bodyObj = JSON.parse(raw) as Record<string, unknown>;
        } catch {
          bodyObj = {};
        }
      }
      const eph = bodyObj[RESP_EPH_FIELD];
      if (typeof eph === 'string') respEphPubB64 = eph;
      delete bodyObj[RESP_EPH_FIELD];
      // PoP hashes `raw` (the wire body WITH fsRespEph, as the client signed);
      // the handler sees the stripped body.
      handlerReq = proxyReq(req, bodyObj, raw);
    }
    // The account number (account create/rotate) rides the RESPONSE on these
    // routes; with no response ephemeral it would go out in plaintext.
    if (e2eeRequired && !respEphPubB64) return sealedRequired();
  } else if (policy.request === 'seal') {
    const raw = await readBodyTextCapped(req);
    let parsed: unknown;
    try {
      parsed = raw ? JSON.parse(raw) : undefined;
    } catch {
      parsed = undefined;
    }
    if (isSealedWire(parsed)) {
      const opened = await ctx.runAction(internal.lib.e2eeCrypto.openRequest, {
        method,
        path,
        wireBody: parsed,
      });
      handlerReq = proxyReq(req, opened.plaintext ?? {}, raw);
    } else {
      // The account number rides the REQUEST on the login route.
      if (e2eeRequired) return sealedRequired();
      handlerReq = proxyReq(req, parsed ?? {}, raw);
    }
  }

  const res = await handler(ctx, handlerReq);

  if (policy.response === 'reveal' && respEphPubB64 && res.ok) {
    const ct = res.headers.get('content-type') ?? '';
    if (ct.includes('json')) {
      const responseObj = await res.json();
      const sealedWire: SealedWire = await ctx.runAction(internal.lib.e2eeCrypto.sealResponse, {
        method,
        path,
        respEphPubB64,
        responseObj,
      });
      const headers = new Headers(res.headers);
      headers.set('content-type', 'application/json');
      headers.set('x-fs-sealed', '1');
      return new Response(JSON.stringify(sealedWire), { status: res.status, headers });
    }
  }
  return res;
}
