/**
 * i18n runtime: a thin reactive layer over the Paraglide-compiled messages.
 *
 *  - Messages live in `messages/{locale}.json` (inlang message-format) - the
 *    source of truth. The Vite plugin (and `bun run i18n:compile`) compiles them
 *    to tree-shaken JS in `src/lib/paraglide`; `bun run i18n:translate`
 *    machine-fills the non-base locales so they no longer need hand-editing.
 *  - `locale` is $state; `t(key, params?)` reads it and passes it EXPLICITLY to
 *    the Paraglide message fn, so any template calling t() re-renders on a locale
 *    change with NO page reload (Paraglide's own getLocale/strategy is unused).
 *  - Missing translations fall back to the base locale (Paraglide aliases them).
 *  - setLocale persists to localStorage + sets <html lang/dir> (RTL for fa/ar).
 *
 * `t()` keeps its original `(MessageKey, params)` signature, so every existing
 * call site is unchanged; only this module + the message store moved.
 */
import { m } from '@/lib/paraglide/messages.js';
import type { MessageKey } from './message-keys';
import {
  DEFAULT_LOCALE,
  dirForLocale,
  isLocaleCode,
  LOCALES,
  normalizeDigits,
  type LocaleCode,
} from './locales';

const STORAGE_KEY = 'fs_locale';

// Each compiled message is `(inputs?, options?) => string`, re-exported under its
// original dotted id. Cast `m` to a uniform record so a dynamic `t(key)` lookup
// type-checks (the per-message input unions aren't callable through one signature)
// while `MessageKey` (generated from messages/en.json) keeps call sites checked.
type MsgFn = (
  inputs?: Record<string, string | number>,
  options?: { locale?: LocaleCode },
) => string;
const messages = m as unknown as Record<MessageKey, MsgFn>;

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

/** Reactive translate: reads `locale` ($state) + passes it to the Paraglide
 *  message, so callers re-render on a locale change. */
export function t(key: MessageKey, params?: Record<string, string | number>): string {
  const fn = messages[key];
  return fn ? fn(params ?? {}, { locale }) : key; // last-resort: surface the key
}

export { LOCALES, normalizeDigits, type LocaleCode, type MessageKey };
