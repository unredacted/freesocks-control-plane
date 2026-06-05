/**
 * Cloudflare Turnstile siteverify (P6) — pure async fn ported from
 * providers/turnstile/verify.ts. Called from actions (fetch is available).
 * Gates account-number login + anonymous free-tier issuance.
 *
 * Local testing: set TURNSTILE_SECRET_KEY to Cloudflare's "always passes" test
 * secret `1x0000000000000000000000000000000AA` — siteverify then returns
 * success:true for any response token.
 */
export interface TurnstileResult {
  success: boolean;
  action?: string;
  cdata?: string;
  errorCodes?: string[];
}

const SITEVERIFY = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

export async function verifyTurnstile(
  secret: string,
  token: string,
  remoteIp?: string,
): Promise<TurnstileResult> {
  if (!token) return { success: false, errorCodes: ['missing-token'] };
  const body = new URLSearchParams();
  body.set('secret', secret);
  body.set('response', token);
  if (remoteIp) body.set('remoteip', remoteIp);
  try {
    const res = await fetch(SITEVERIFY, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    if (!res.ok) return { success: false, errorCodes: [`http-${res.status}`] };
    const json = (await res.json()) as {
      success: boolean;
      action?: string;
      cdata?: string;
      'error-codes'?: string[];
    };
    return {
      success: json.success,
      action: json.action,
      cdata: json.cdata,
      errorCodes: json['error-codes'],
    };
  } catch {
    return { success: false, errorCodes: ['exception'] };
  }
}
