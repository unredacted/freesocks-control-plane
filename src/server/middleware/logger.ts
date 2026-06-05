import type { MiddlewareHandler } from 'hono';
import type { AppEnv } from '../env';

export const loggerMw: MiddlewareHandler<AppEnv> = async (c, next) => {
  const platform = c.var.platform;
  const child = platform.logger.child({
    requestId: c.var.requestId,
    method: c.req.method,
    path: new URL(c.req.url).pathname,
  });
  c.set('logger', child);
  const start = performance.now();
  await next();
  const durationMs = Math.round(performance.now() - start);
  child.info('request_complete', {
    status: c.res.status,
    durationMs,
  });
};
