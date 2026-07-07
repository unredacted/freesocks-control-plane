/**
 * Captcha siteverify (W1): self-hosted **Cap** (trycap.dev) replaces Cloudflare
 * Turnstile, so the app has ZERO third-party runtime dependencies — the whole
 * point of the CDN-blinding/censorship-resistance posture, and it removes the
 * GFW-reachability risk Turnstile carried for the zh audience.
 *
 * Server verify: `POST <CAP_API_ENDPOINT>/<CAP_SITE_KEY>/siteverify` with a JSON
 * body `{ secret, response }` → `{ success }`. `CAP_API_ENDPOINT` is the
 * backend-internal URL of the Cap service (e.g. http://cap:3000 over the compose
 * network); the browser widget uses the same-origin public path instead.
 *
 * Fail-closed: any network/HTTP/parse error → success:false. `configured:false`
 * (CAP_* unset) lets the caller answer 503 (misconfig) distinctly from a failed
 * challenge (403). Local dev with no Cap server: set ENVIRONMENT=development +
 * CAP_DEV_BYPASS=true to treat every token as valid (double-gated, never prod).
 *
 * SINGLE-USE (third-pass audit): a Cap token is CONSUMED on the first siteverify —
 * a second verify of the same token returns success:false. Callers verify BEFORE
 * the account-validity checks (auth.accountLogin / freeTier), so a token is spent
 * even when the submission then fails for another reason (e.g. a mistyped account
 * number). The CLIENT must therefore remount its captcha widget on any post-submit
 * error to mint a fresh token, or every retry fails "captcha" until a page reload
 * (see CapWidget.reset(), wired into Login.svelte + GetAccount.svelte onError).
 * The gated captcha.integration.test.ts asserts the double-verify → false against a
 * live Cap.
 */
export interface CaptchaResult {
  success: boolean;
  configured: boolean;
  errorCodes?: string[];
}

export async function verifyCaptcha(token: string): Promise<CaptchaResult> {
  const endpoint = process.env.CAP_API_ENDPOINT;
  const siteKey = process.env.CAP_SITE_KEY;
  const secret = process.env.CAP_SECRET;

  if (!endpoint || !siteKey || !secret) {
    // Dev convenience: double-gated bypass so the get-account/login flows work
    // locally without a Cap server. A production deployment (ENVIRONMENT unset or
    // 'production') ignores this and reports unconfigured.
    if (process.env.ENVIRONMENT === 'development' && process.env.CAP_DEV_BYPASS === 'true') {
      return { success: true, configured: true };
    }
    return { success: false, configured: false, errorCodes: ['not-configured'] };
  }
  if (!token) return { success: false, configured: true, errorCodes: ['missing-token'] };

  const url = `${endpoint.replace(/\/$/, '')}/${siteKey}/siteverify`;
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ secret, response: token }),
    });
    if (!res.ok) return { success: false, configured: true, errorCodes: [`http-${res.status}`] };
    const json = (await res.json()) as { success?: boolean };
    return { success: Boolean(json.success), configured: true };
  } catch {
    return { success: false, configured: true, errorCodes: ['exception'] };
  }
}
