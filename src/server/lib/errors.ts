export class AppError extends Error {
  constructor(
    public readonly code: string,
    public readonly status: number,
    message: string,
    public readonly meta?: Record<string, unknown>,
    public readonly publicMessage?: string,
  ) {
    super(message);
    this.name = this.constructor.name;
  }
}

export class NotFoundError extends AppError {
  constructor(resource: string, meta?: Record<string, unknown>) {
    super('not_found', 404, `${resource} not found`, meta, 'Not found');
  }
}

export class UnauthenticatedError extends AppError {
  constructor(message = 'Authentication required', meta?: Record<string, unknown>) {
    super('auth.unauthenticated', 401, message, meta, 'Authentication required');
  }
}

export class ForbiddenError extends AppError {
  constructor(message = 'Forbidden', meta?: Record<string, unknown>) {
    super('auth.forbidden', 403, message, meta, 'Forbidden');
  }
}

export class ValidationError extends AppError {
  constructor(message: string, meta?: Record<string, unknown>) {
    super('validation', 400, message, meta, message);
  }
}

export class UpstreamError extends AppError {
  constructor(upstream: string, message: string, meta?: Record<string, unknown>) {
    super(`upstream.${upstream}`, 502, message, meta, 'Upstream service error, please try again');
  }
}

export class RateLimitError extends AppError {
  constructor(retryAfterSeconds: number, message = 'Rate limit exceeded') {
    super(
      'rate_limit.exceeded',
      429,
      message,
      { retryAfterSeconds },
      'You are being rate-limited. Try again later.',
    );
  }
}

export class ConflictError extends AppError {
  constructor(message: string, meta?: Record<string, unknown>) {
    super('conflict', 409, message, meta, message);
  }
}
