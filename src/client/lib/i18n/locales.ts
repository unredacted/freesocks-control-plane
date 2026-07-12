/**
 * i18n (P1-15): launch locales. English + the four censored-region audiences the
 * service targets, two of them RTL. The catalog is a plain typed object per
 * locale (en is the source of truth; the others fall back to en for any missing
 * key), so locales tree-shake and there's no runtime i18n dependency - in keeping
 * with the project's "bundle everything, zero third-party" stance.
 */
export const LOCALES = [
  { code: 'en', name: 'English', dir: 'ltr' },
  { code: 'fa', name: 'فارسی', dir: 'rtl' },
  { code: 'ar', name: 'العربية', dir: 'rtl' },
  { code: 'ru', name: 'Русский', dir: 'ltr' },
  { code: 'zh', name: '中文', dir: 'ltr' },
] as const;

export type LocaleCode = (typeof LOCALES)[number]['code'];
export type Direction = 'ltr' | 'rtl';

export const DEFAULT_LOCALE: LocaleCode = 'en';

export function dirForLocale(code: LocaleCode): Direction {
  return LOCALES.find((l) => l.code === code)?.dir ?? 'ltr';
}

export function isLocaleCode(value: string): value is LocaleCode {
  return LOCALES.some((l) => l.code === value);
}

/**
 * Normalize Persian (۰-۹) and Arabic-Indic (٠-٩) digits to ASCII 0-9. The
 * account number + redemption code inputs run this so a Farsi/Arabic keyboard's
 * native numerals are accepted. Idempotent on ASCII input.
 */
export function normalizeDigits(input: string): string {
  return input.replace(/[۰-۹٠-٩]/g, (ch) => {
    const code = ch.charCodeAt(0);
    if (code >= 0x06f0 && code <= 0x06f9) return String(code - 0x06f0); // Persian
    return String(code - 0x0660); // Arabic-Indic
  });
}
