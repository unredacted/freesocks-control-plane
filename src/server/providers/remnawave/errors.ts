import { UpstreamError } from '../../lib/errors';

export class RemnawaveApiError extends UpstreamError {
  constructor(message: string, meta?: Record<string, unknown>) {
    super('remnawave', message, meta);
  }

  static async fromResponse(res: Response, path: string): Promise<RemnawaveApiError> {
    let body: string | undefined;
    try {
      body = await res.text();
    } catch {
      body = undefined;
    }
    return new RemnawaveApiError(`Remnawave ${res.status} on ${path}`, {
      status: res.status,
      path,
      body: body?.slice(0, 200),
    });
  }
}
