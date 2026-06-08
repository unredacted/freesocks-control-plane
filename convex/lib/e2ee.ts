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
 */
function proxyReq(req: Request, bodyObj: unknown): Request {
  const text = JSON.stringify(bodyObj ?? {});
  return {
    url: req.url,
    method: req.method,
    headers: req.headers,
    json: async () => JSON.parse(text),
    text: async () => text,
  } as unknown as Request;
}

export function sealed(handler: RawHandler) {
  return httpAction(async (ctx, req): Promise<Response> => {
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method.toUpperCase();
    const policy = routePolicy(path);
    if (!policy) return handler(ctx, req);

    let handlerReq = req;
    let respEphPubB64: string | undefined;

    if (policy.response === 'reveal') {
      if (method === 'GET' || method === 'HEAD') {
        respEphPubB64 = req.headers.get('x-fs-resp-eph') ?? undefined;
      } else {
        const raw = await req.text();
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
        handlerReq = proxyReq(req, bodyObj);
      }
    } else if (policy.request === 'seal') {
      const raw = await req.text();
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
        handlerReq = proxyReq(req, opened.plaintext ?? {});
      } else {
        handlerReq = proxyReq(req, parsed ?? {});
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
  });
}
