/**
 * Map an API error to a localized, user-facing message (P1-9). Consumers use
 * this in their onError handlers instead of reading `err.payload.error.message`
 * raw — so a 429 reads "too many attempts", a network failure reads "offline",
 * and a backend outage / parse failure reads a friendly localized string rather
 * than an opaque code or a TypeError.
 *
 * ERROR-SURFACE CONVENTION (pass 2): one surface per failure, never both.
 *  - Query/load errors and form-blocking errors render INLINE, next to the
 *    thing the user is looking at (and its Retry affordance).
 *  - Background mutation outcomes (the user may have scrolled/moved on) use a
 *    TOAST.
 * GetAccount's create flows are inline; Account's actions are toasts.
 */
import { ApiCallError } from './api';
import { t } from './i18n/index.svelte';

export function apiErrorMessage(err: unknown): string {
  if (err instanceof ApiCallError) {
    if (err.status === 0) return t('error.offline');
    if (err.status === 429) return t('error.rateLimited');
    const code = err.payload.error.code;
    if (code === 'backend.unavailable') return t('error.backendUnavailable');
    if (code.startsWith('auth.captcha')) return t('error.captchaFailed');
    if (
      code === 'client.parse_error' ||
      code === 'issuance.failed' ||
      code === 'account.create_failed'
    )
      return t('error.generic');
    // A real, specific server message (e.g. a validation detail) — show it.
    return err.payload.error.message || t('error.generic');
  }
  return t('error.generic');
}
