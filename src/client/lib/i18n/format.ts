/**
 * Locale-aware date formatting. `getLocale()` reads the i18n $state, so any
 * template calling these re-renders when the user switches language — the same
 * reactivity contract as t(). Passing the APP locale (not `undefined`) matters:
 * a user who picks Farsi with an English browser gets Persian-digit dates.
 */
import { getLocale } from './index.svelte';

export function formatDate(
  value: string | number | Date,
  opts: Intl.DateTimeFormatOptions = { year: 'numeric', month: 'short', day: 'numeric' },
): string {
  return new Date(value).toLocaleDateString(getLocale(), opts);
}

export function formatDateTime(value: string | number | Date): string {
  return new Date(value).toLocaleString(getLocale());
}
