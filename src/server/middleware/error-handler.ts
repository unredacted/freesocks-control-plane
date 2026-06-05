import type { Context, ErrorHandler, NotFoundHandler } from 'hono';
import { ZodError } from 'zod';
import { AppError } from '../lib/errors';
import type { AppEnv } from '../env';

export const errorHandler: ErrorHandler<AppEnv> = (err, c) => {
  const logger = c.var.logger;
  const requestId = c.var.requestId;
  if (err instanceof AppError) {
    logger.warn('app_error', { code: err.code, status: err.status, meta: err.meta });
    return c.json(
      {
        error: { code: err.code, message: err.publicMessage ?? 'Request failed' },
        requestId,
      },
      err.status as 400 | 401 | 403 | 404 | 409 | 429 | 500 | 502,
    );
  }
  if (err instanceof ZodError) {
    logger.warn('validation_error', { issues: err.issues });
    return c.json(
      {
        error: { code: 'validation', message: 'Validation failed', details: err.issues },
        requestId,
      },
      400,
    );
  }
  logger.error('unhandled_error', {
    message: err.message,
    stack: err.stack,
  });
  return c.json({ error: { code: 'internal', message: 'Internal error' }, requestId }, 500);
};

export const notFoundHandler: NotFoundHandler<AppEnv> = (c: Context<AppEnv>) => {
  return c.json(
    { error: { code: 'not_found', message: 'Not found' }, requestId: c.var.requestId },
    404,
  );
};
