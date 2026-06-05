/**
 * Outline Manager API client. Single Outline server per instance. The
 * `apiUrl` includes the secret path segment (`https://HOST:PORT/<secret>/`)
 * — treat it as a credential.
 *
 * Auth model: there is no header-based auth. The "auth" is the secret in
 * the URL itself. Anyone who can construct the URL can call the API. This
 * is why the URL must never be logged, echoed in error responses, or stored
 * outside the `outline_servers` table (which already redacts it via the
 * audit-log scrubber).
 *
 * The API surface is documented at
 * https://github.com/Jigsaw-Code/outline-server/blob/master/src/shadowbox/server/api.yml
 *
 * Notes on the non-stock WS fork:
 *   - The original FreeSocks repo used a fork of Outline that accepts a
 *     `websocket: {…}` body on POST /access-keys to provision a key whose
 *     traffic is wrapped in WSS. Stock Outline ignores the field.
 *   - We surface this as an optional `websocket` parameter on `createKey`;
 *     the OutlineBackend decides whether to pass it based on the
 *     `outline_servers.websocket_enabled` row.
 */
import { z } from 'zod';
import type { Logger } from '../../lib/logger';
import { OutlineApiError } from './errors';
import {
  OutlineAccessKey,
  OutlineAccessKeysList,
  OutlineTransferMetrics,
  type OutlineWebsocketBody,
} from './types';

export interface OutlineClientOptions {
  /** Full Outline Manager URL, INCLUDING the random secret path segment. */
  apiUrl: string;
  fetcher?: typeof fetch;
  logger: Logger;
  timeoutMs?: number;
}

export class OutlineClient {
  constructor(private readonly opts: OutlineClientOptions) {}

  private async call<T>(args: {
    method: 'GET' | 'POST' | 'PUT' | 'DELETE';
    path: string;
    body?: unknown;
    responseSchema: z.ZodType<T>;
  }): Promise<T> {
    // The apiUrl already has the secret path segment; join paths carefully
    // so we don't strip it. Always append the desired path to the trailing
    // slash of apiUrl.
    const base = this.opts.apiUrl.endsWith('/') ? this.opts.apiUrl : `${this.opts.apiUrl}/`;
    const url = new URL(args.path.replace(/^\//, ''), base).toString();
    const fetchImpl = this.opts.fetcher ?? fetch;
    const timeoutMs = this.opts.timeoutMs ?? 8000;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetchImpl(url, {
        method: args.method,
        headers: {
          'content-type': 'application/json',
          accept: 'application/json',
        },
        body: args.body !== undefined ? JSON.stringify(args.body) : undefined,
        signal: controller.signal,
      });
      if (!res.ok) {
        throw await OutlineApiError.fromResponse(res, args.path);
      }
      // Some Outline endpoints return 204 No Content (DELETE, PUT). Pass
      // them through as `undefined` to the schema (callers should use
      // z.unknown() / z.void() for those).
      if (res.status === 204) {
        const parsed = args.responseSchema.safeParse(undefined);
        if (!parsed.success) {
          throw new OutlineApiError('Unexpected 204 from Outline', {
            status: res.status,
            path: args.path,
          });
        }
        return parsed.data;
      }
      const json: unknown = await res.json().catch(() => undefined);
      const parsed = args.responseSchema.safeParse(json);
      if (!parsed.success) {
        this.opts.logger.warn('outline_schema_mismatch', {
          path: args.path,
          issues: parsed.error.issues,
        });
        throw new OutlineApiError('Outline schema mismatch', {
          path: args.path,
        });
      }
      return parsed.data;
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Create a new access key. Pass `websocket` only when the target server
   * runs the WSS-wrapped FreeSocks fork — stock Outline returns 400 for
   * unrecognized body fields on some versions.
   */
  async createKey(opts: { name?: string; websocket?: OutlineWebsocketBody } = {}) {
    const body: Record<string, unknown> = {};
    if (opts.name) body.name = opts.name;
    if (opts.websocket) body.websocket = opts.websocket;
    return this.call({
      method: 'POST',
      path: '/access-keys',
      body: Object.keys(body).length > 0 ? body : undefined,
      responseSchema: OutlineAccessKey,
    });
  }

  async getKey(id: string) {
    return this.call({
      method: 'GET',
      path: `/access-keys/${encodeURIComponent(id)}`,
      responseSchema: OutlineAccessKey,
    });
  }

  async listKeys() {
    const result = await this.call({
      method: 'GET',
      path: '/access-keys',
      responseSchema: OutlineAccessKeysList,
    });
    return result.accessKeys;
  }

  async deleteKey(id: string): Promise<void> {
    await this.call({
      method: 'DELETE',
      path: `/access-keys/${encodeURIComponent(id)}`,
      responseSchema: z.unknown(),
    });
  }

  async renameKey(id: string, name: string): Promise<void> {
    await this.call({
      method: 'PUT',
      path: `/access-keys/${encodeURIComponent(id)}/name`,
      body: { name },
      responseSchema: z.unknown(),
    });
  }

  /** Set a per-key bandwidth limit. Pass `null` to remove the limit. */
  async setKeyDataLimit(id: string, bytes: number | null): Promise<void> {
    if (bytes === null) {
      await this.call({
        method: 'DELETE',
        path: `/access-keys/${encodeURIComponent(id)}/data-limit`,
        responseSchema: z.unknown(),
      });
      return;
    }
    await this.call({
      method: 'PUT',
      path: `/access-keys/${encodeURIComponent(id)}/data-limit`,
      body: { limit: { bytes } },
      responseSchema: z.unknown(),
    });
  }

  /**
   * Returns `{ accessKeyId -> bytesTransferred }` since the server's
   * collection window started. Outline's window is configurable on the
   * server side; for FreeSocks it's typically the current period.
   */
  async getMetricsTransfer(): Promise<Record<string, number>> {
    const result = await this.call({
      method: 'GET',
      path: '/metrics/transfer',
      responseSchema: OutlineTransferMetrics,
    });
    return result.bytesTransferredByUserId;
  }

  /**
   * Health probe — `GET /access-keys` with a short timeout. Returns the
   * key count on success so callers can update `outline_servers.access_key_count`
   * in one round trip.
   */
  async healthCheck(): Promise<{ ok: true; keyCount: number } | { ok: false; error: string }> {
    try {
      const keys = await this.listKeys();
      return { ok: true, keyCount: keys.length };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  }
}
