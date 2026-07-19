/**
 * Map an API error to a localized, user-facing message (P1-9). Consumers use
 * this in their onError handlers instead of reading `err.payload.error.message`
 * raw - so a 429 reads "too many attempts", a network failure reads "offline",
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
import type { ZodError } from 'zod';
import { ApiCallError } from './api';
import { t } from './i18n/index.svelte';

/**
 * First human-readable issue out of a ZodError - for client-side form
 * validation (safeParse BEFORE mutate). Never surface a raw ZodError string
 * (a multi-line path dump) in a toast.
 */
export function firstIssueMessage(err: ZodError): string {
  const issue = err.issues[0];
  if (!issue) return 'Invalid input';
  const path = issue.path.join('.');
  return path ? `${path}: ${issue.message}` : issue.message;
}

/**
 * Business-logic codes → catalog keys. Server error messages are English; a
 * member in fa/ar/ru/zh must get a translated string for every code they can
 * realistically hit, so unmapped codes should be the exception (they fall back
 * to the raw server message below). Add here when introducing a member-facing
 * error code.
 */
const CODE_MESSAGES: Record<string, () => string> = {
  'auth.unauthenticated': () => t('error.sessionExpired'),
  'auth.invalid_account_id': () => t('error.invalidAccountId'),
  'code.invalid': () => t('error.codeInvalid'),
  'issuance.in_progress': () => t('error.changeInProgress'),
  'backend.disabled': () => t('error.backendDisabled'),
  'tier.no_peer': () => t('error.noPeerTier'),
  'devices.not_found': () => t('error.deviceNotFound'),
  'devices.unsupported': () => t('error.deviceUnsupported'),
  'devices.no_subscription': () => t('error.generic'),
  'devices.unavailable': () => t('error.backendUnavailable'),
  'e2ee.sealed_required': () => t('error.serverError'),
  'server.error': () => t('error.serverError'),
  'billing.error': () => t('error.billing'),
  'content.unavailable': () => t('error.backendUnavailable'),
  'mode.unavailable': () => t('error.modeUnavailable'),
  'backend.placement_unresolved': () => t('error.backendUnavailable'),
  config: () => t('error.captchaUnconfigured'),
  not_found: () => t('error.generic'),
};

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
    const mapped = CODE_MESSAGES[code];
    if (mapped) return mapped();
    // `http.<status>` means the body carried no structured envelope at all
    // (e.g. a reverse-proxy 502 page) - never worth echoing.
    if (code.startsWith('http.')) {
      return err.status >= 500 ? t('error.serverError') : t('error.generic');
    }
    // An unmapped, specific server message (e.g. a validation detail) - show it.
    return err.payload.error.message || t('error.generic');
  }
  return t('error.generic');
}
