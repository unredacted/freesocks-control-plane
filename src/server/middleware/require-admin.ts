import type { MiddlewareHandler } from 'hono';
import { UnauthenticatedError } from '../lib/errors';
import type { AppEnv } from '../env';

export const requireAdmin: MiddlewareHandler<AppEnv> = async (c, next) => {
  if (!c.var.admin) {
    throw new UnauthenticatedError('Admin authentication required');
  }
  await next();
};
