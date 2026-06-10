/**
 * i18n store (P1-15). A tiny reactive layer over the per-locale catalogs:
 *  - `locale` is $state; `t(key, params?)` reads it, so any template that calls
 *    t() re-renders when the locale changes (Svelte 5 tracks the state read).
 *  - Missing translations fall back to the English source catalog.
 *  - setLocale persists to localStorage and sets <html lang/dir> (RTL for fa/ar).
 *  - Initial locale: saved choice → navigator.languages → English.
 */
import { en, type MessageKey, type Messages } from './messages/en';
import { fa } from './messages/fa';
import { ar } from './messages/ar';
import { ru } from './messages/ru';
import { zh } from './messages/zh';
import {
  DEFAULT_LOCALE,
  dirForLocale,
  isLocaleCode,
  LOCALES,
  normalizeDigits,
  type LocaleCode,
} from './locales';

const CATALOGS: Record<LocaleCode, Partial<Messages>> = { en, fa, ar, ru, zh };
const STORAGE_KEY = 'fs_locale';

function detectInitial(): LocaleCode {
  if (typeof window === 'undefined') return DEFAULT_LOCALE;
  try {
    const saved = window.localStorage.getItem(STORAGE_KEY);
    if (saved && isLocaleCode(saved)) return saved;
  } catch {
    /* localStorage blocked (private mode); fall through to navigator */
  }
  for (const pref of navigator.languages ?? [navigator.language]) {
    const base = pref.toLowerCase().split('-')[0];
    if (base && isLocaleCode(base)) return base;
  }
  return DEFAULT_LOCALE;
}

let locale = $state<LocaleCode>(detectInitial());

/** Apply <html lang> + <html dir> for the current locale. */
function applyHtml(code: LocaleCode): void {
  if (typeof document === 'undefined') return;
  document.documentElement.lang = code;
  document.documentElement.dir = dirForLocale(code);
}

export function initI18n(): void {
  applyHtml(locale);
}

export function getLocale(): LocaleCode {
  return locale;
}

export function setLocale(code: LocaleCode): void {
  locale = code;
  try {
    window.localStorage.setItem(STORAGE_KEY, code);
  } catch {
    /* ignore */
  }
  applyHtml(code);
}

/** Reactive translate. Reads `locale` ($state), so callers re-render on change. */
export function t(key: MessageKey, params?: Record<string, string | number>): string {
  const entry = (CATALOGS[locale]?.[key] ?? en[key]) as
    | string
    | ((p: Record<string, string | number>) => string)
    | undefined;
  if (entry === undefined) return key; // last-resort: surface the key, never crash
  return typeof entry === 'function' ? entry(params ?? {}) : entry;
}

export { LOCALES, normalizeDigits, type LocaleCode };
