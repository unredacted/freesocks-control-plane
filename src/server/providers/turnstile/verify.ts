import type { Logger } from '../../lib/logger';

export interface TurnstileVerifyResult {
  success: boolean;
  hostname?: string;
  challengeTs?: string;
  action?: string;
  cdata?: string;
  errorCodes?: string[];
}

export class TurnstileVerifier {
  constructor(
    private readonly secretKey: string,
    private readonly logger: Logger,
    private readonly fetcher: typeof fetch = fetch,
  ) {}

  async verify(token: string, remoteIp?: string): Promise<TurnstileVerifyResult> {
    if (!token) return { success: false, errorCodes: ['missing-token'] };
    const body = new URLSearchParams();
    body.set('secret', this.secretKey);
    body.set('response', token);
    if (remoteIp) body.set('remoteip', remoteIp);
    try {
      const res = await this.fetcher('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
      });
      if (!res.ok) {
        this.logger.warn('turnstile_verify_http_error', { status: res.status });
        return { success: false, errorCodes: [`http-${res.status}`] };
      }
      const json = (await res.json()) as {
        success: boolean;
        hostname?: string;
        challenge_ts?: string;
        action?: string;
        cdata?: string;
        'error-codes'?: string[];
      };
      return {
        success: json.success,
        hostname: json.hostname,
        challengeTs: json.challenge_ts,
        action: json.action,
        cdata: json.cdata,
        errorCodes: json['error-codes'],
      };
    } catch (err) {
      this.logger.warn('turnstile_verify_exception', { error: String(err) });
      return { success: false, errorCodes: ['exception'] };
    }
  }
}
