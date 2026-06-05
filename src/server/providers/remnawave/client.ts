import { z } from 'zod';
import type { Logger } from '../../lib/logger';
import { RemnawaveApiError } from './errors';
import {
  CreateUserInput,
  HwidDevicesResponse,
  RemnawaveUser,
  RawSubscriptionResponse,
  UpdateUserPatch,
  type HwidDevice,
} from './types';

export interface RemnawaveClientOptions {
  baseUrl: string;
  apiToken: string;
  fetcher?: typeof fetch;
  logger: Logger;
  timeoutMs?: number;
}

export class RemnawaveClient {
  constructor(private readonly opts: RemnawaveClientOptions) {}

  private async call<T>(args: {
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
    path: string;
    body?: unknown;
    responseSchema: z.ZodType<T>;
  }): Promise<T> {
    const url = new URL(args.path, this.opts.baseUrl).toString();
    const fetchImpl = this.opts.fetcher ?? fetch;
    const timeoutMs = this.opts.timeoutMs ?? 8000;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetchImpl(url, {
        method: args.method,
        headers: {
          authorization: `Bearer ${this.opts.apiToken}`,
          'content-type': 'application/json',
          accept: 'application/json',
        },
        body: args.body !== undefined ? JSON.stringify(args.body) : undefined,
        signal: controller.signal,
      });
      if (!res.ok) {
        throw await RemnawaveApiError.fromResponse(res, args.path);
      }
      const json: unknown = await res.json();
      const wrapped = unwrap(json);
      const parsed = args.responseSchema.safeParse(wrapped);
      if (!parsed.success) {
        this.opts.logger.warn('remnawave_schema_mismatch', {
          path: args.path,
          issues: parsed.error.issues,
        });
        throw new RemnawaveApiError('Schema mismatch', { issues: parsed.error.issues });
      }
      return parsed.data;
    } finally {
      clearTimeout(timer);
    }
  }

  async createUser(input: CreateUserInput) {
    return this.call({
      method: 'POST',
      path: '/api/users',
      body: CreateUserInput.parse(input),
      responseSchema: RemnawaveUser,
    });
  }

  async getUser(uuid: string) {
    return this.call({
      method: 'GET',
      path: `/api/users/${uuid}`,
      responseSchema: RemnawaveUser,
    });
  }

  async updateUser(uuid: string, patch: UpdateUserPatch) {
    return this.call({
      method: 'PATCH',
      path: `/api/users/${uuid}`,
      body: UpdateUserPatch.parse(patch),
      responseSchema: RemnawaveUser,
    });
  }

  async disableUser(uuid: string) {
    return this.updateUser(uuid, { status: 'DISABLED' });
  }

  async enableUser(uuid: string) {
    return this.updateUser(uuid, { status: 'ACTIVE' });
  }

  async resetUserTraffic(uuid: string): Promise<void> {
    await this.call({
      method: 'POST',
      path: `/api/users/${uuid}/actions/reset-traffic`,
      responseSchema: z.unknown(),
    });
  }

  async deleteUser(uuid: string): Promise<void> {
    await this.call({
      method: 'DELETE',
      path: `/api/users/${uuid}`,
      responseSchema: z.unknown(),
    });
  }

  async getSubscriptionRaw(shortUuid: string) {
    return this.call({
      method: 'GET',
      path: `/api/subscriptions/by-short-uuid/${shortUuid}/raw`,
      responseSchema: RawSubscriptionResponse,
    });
  }

  /**
   * Lists registered HWID devices for a user. Returns `[]` (not throws) on a
   * 404 from upstream since some panel versions don't expose this endpoint —
   * the SPA degrades to "no devices known" rather than failing the page.
   *
   * The exact endpoint path varies by Remnawave version; this targets the
   * documented shape in @remnawave/backend-contract@2.8 (`/api/hwid-devices`).
   */
  async listUserDevices(userUuid: string): Promise<HwidDevice[]> {
    try {
      const result = await this.call({
        method: 'GET',
        path: `/api/hwid-devices?userUuid=${encodeURIComponent(userUuid)}`,
        responseSchema: HwidDevicesResponse,
      });
      return result.devices;
    } catch (err) {
      const status = (err as { meta?: { status?: number } }).meta?.status;
      if (status === 404) return [];
      this.opts.logger.warn('remnawave_hwid_list_failed', { userUuid, error: String(err) });
      return [];
    }
  }

  async fetchSubscriptionContent(
    shortUuid: string,
    userAgent?: string,
  ): Promise<{ content: string; contentType: string }> {
    const url = new URL(`/api/subscriptions/${shortUuid}`, this.opts.baseUrl).toString();
    const headers: Record<string, string> = {
      authorization: `Bearer ${this.opts.apiToken}`,
    };
    if (userAgent) headers['user-agent'] = userAgent;
    const fetchImpl = this.opts.fetcher ?? fetch;
    const timeoutMs = this.opts.timeoutMs ?? 8000;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetchImpl(url, { headers, signal: controller.signal });
      if (!res.ok) throw await RemnawaveApiError.fromResponse(res, url);
      return {
        content: await res.text(),
        contentType: res.headers.get('content-type') ?? 'text/plain',
      };
    } finally {
      clearTimeout(timer);
    }
  }
}

function unwrap(json: unknown): unknown {
  // Remnawave wraps responses in { response: {...} } in some endpoints; tolerate both shapes.
  if (json && typeof json === 'object' && 'response' in json) {
    return (json as { response: unknown }).response;
  }
  return json;
}
