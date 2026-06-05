/**
 * Outline Manager API error wrapper. Keeps the underlying HTTP status so
 * callers (notably the BackendRegistry health checks and the admin
 * "Test connection" button) can distinguish a TLS failure from a 401 from
 * a 404 without parsing the message string.
 *
 * Critically: the `apiUrl` is NEVER captured here — it contains the
 * Outline Manager secret. The error stays scoped to the path + status.
 */
export interface OutlineApiErrorMeta {
  status?: number;
  /** Endpoint path (e.g. `/access-keys/42`) — safe to log, never includes the secret. */
  path?: string;
  /** Raw upstream body, truncated to 200 chars. NEVER includes the apiUrl. */
  bodyExcerpt?: string;
}

export class OutlineApiError extends Error {
  readonly meta: OutlineApiErrorMeta;

  constructor(message: string, meta: OutlineApiErrorMeta = {}) {
    super(message);
    this.name = 'OutlineApiError';
    this.meta = meta;
  }

  static async fromResponse(res: Response, path: string): Promise<OutlineApiError> {
    const body = await res.text().catch(() => '');
    return new OutlineApiError(`Outline ${res.status} on ${path}`, {
      status: res.status,
      path,
      bodyExcerpt: body.slice(0, 200),
    });
  }
}
