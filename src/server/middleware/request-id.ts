import type { MiddlewareHandler } from 'hono';
import type { AppEnv } from '../env';

export const requestIdMw: MiddlewareHandler<AppEnv> = async (c, next) => {
  const incoming = c.req.header('x-request-id');
  const id = incoming && /^[a-zA-Z0-9-]{8,128}$/.test(incoming) ? incoming : crypto.randomUUID();
  c.set('requestId', id);
  c.header('x-request-id', id);
  await next();
};
