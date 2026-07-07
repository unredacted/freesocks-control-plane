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
  // Guard unparseable input (e.g. the deliberately-lenient plain-string device
  // firstSeen/lastSeen fields): toLocaleDateString on an Invalid Date renders the
  // literal "Invalid Date". Fall back to the raw value instead.
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleDateString(getLocale(), opts);
}

export function formatDateTime(value: string | number | Date): string {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString(getLocale());
}

/**
 * Locale-aware money formatting from minor units (cents). Reactive via
 * getLocale() like the date helpers. Falls back to a plain `<amount> <CUR>`
 * string if the currency code is non-standard (Intl throws on a bad code).
 */
export function formatMoney(amountCents: number, currency: string): string {
  const amount = amountCents / 100;
  try {
    return new Intl.NumberFormat(getLocale(), { style: 'currency', currency }).format(amount);
  } catch {
    return `${amount.toFixed(2)} ${currency}`;
  }
}
