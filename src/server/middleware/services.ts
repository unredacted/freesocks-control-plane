import type { MiddlewareHandler } from 'hono';
import type { AppEnv } from '../env';
import type { PlatformAdapter } from '../platform/interface';
import { buildServices } from '../services/container';

/**
 * Resolve the client IP, with strict trust rules. The free-tier rate-limit
 * keys off this value (`rl:free:ip:{ipHash}:{dayBucket}`), so a wrong answer
 * here lets an attacker mint unlimited free keys.
 *
 * Trust rules:
 *   - Cloudflare Workers: trust `cf-connecting-ip` ONLY. Cloudflare sets it
 *     directly from the TLS-terminated connection; clients can't spoof it.
 *     `x-forwarded-for` is ignored on this path.
 *   - Other runtimes (Bun self-host, Fastly Compute): no header is universally
 *     trustworthy. Operators must front the app with a reverse proxy that
 *     overwrites `x-forwarded-for` and set the `TRUSTED_PROXY=true` env var
 *     for that header to be honored. Default-deny prevents naive deploys
 *     from being spoofable.
 *
 * Returns `null` rather than a fallback IP — better to skip rate-limiting on
 * an un-resolvable request than to bucket every "no ip" caller together
 * (which would itself be a bypass vector since they'd share one bucket).
 */
function resolveClientIp(
  c: { req: { header: (k: string) => string | undefined } },
  platform: PlatformAdapter,
): string | null {
  // Workers: cf-connecting-ip is set by the edge and cannot be spoofed.
  const cf = c.req.header('cf-connecting-ip');
  if (cf) {
    const trimmed = cf.trim();
    return trimmed.length > 0 ? trimmed : null;
  }
  // Off-Workers: only trust X-Forwarded-For when the operator has flagged
  // that the app sits behind a proxy via the platform config. We read it
  // through the platform adapter (rather than process.env) so it works
  // identically on Bun, Fastly, and any future runtime.
  if (platform.config.TRUSTED_PROXY) {
    const xff = c.req.header('x-forwarded-for');
    if (xff) {
      const first = xff.split(',')[0]?.trim();
      if (first && first.length > 0) return first;
    }
  }
  return null;
}

export function servicesMw(platform: PlatformAdapter): MiddlewareHandler<AppEnv> {
  // Build the service container ONCE per adapter, not per request. The
  // container closes over nothing request-scoped (it takes only `platform`),
  // and several services hold cross-request caches that a per-request rebuild
  // silently defeated — most importantly AuthentikJwtVerifier's JWKS/discovery
  // cache. Only `clientIp` is genuinely per-request and stays in the handler.
  const services = buildServices(platform);
  return async (c, next) => {
    c.set('platform', platform);
    c.set('services', services);
    const ip = resolveClientIp(c, platform);
    if (ip) c.set('clientIp', ip);
    await next();
  };
}
