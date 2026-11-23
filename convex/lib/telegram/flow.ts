/**
 * Pure helpers for the Telegram gift shop (convex/telegramBot.ts): language,
 * text, the stateless button protocol, and which durations are for sale (for
 * Telegram Stars, the only way to pay in the bot). No Convex or network access, so all of it is unit-tested.
 *
 * STATELESS BY DESIGN: the bot keeps no per-chat session. Everything a step
 * needs (language, duration, quantity, order ref)
 * travels in the button's callback_data, at most 64 bytes.
 */
import {
  BOT_LOCALES,
  BOT_MESSAGES,
  BOT_MESSAGES_EN,
  type BotLocale,
  type BotMessageKey,
} from './botMessages.generated';
import type { StarsPrice, TelegramConfig } from '../telegramConfig';
import { MAX_DURATION_MONTHS } from '../billingConfig';
import { MAX_STARS_PER_CODE } from '../telegramConfig';

export type { BotLocale, BotMessageKey };
export { BOT_LOCALES };

/** Each language's own name, for the language picker (not translated copy). */
export const LOCALE_NAMES: Record<BotLocale, string> = {
  en: 'English',
  fa: 'فارسی',
  ar: 'العربية',
  ru: 'Русский',
  zh: '中文',
};

/** The bot's language from the Telegram client's language_code ('fa', 'zh-hans', ...). */
export function pickLocale(code: string | undefined | null): BotLocale {
  const base = (code ?? '').toLowerCase().split(/[-_]/)[0] ?? '';
  return (BOT_LOCALES as readonly string[]).includes(base) ? (base as BotLocale) : 'en';
}

export function isBotLocale(v: string): v is BotLocale {
  return (BOT_LOCALES as readonly string[]).includes(v);
}

export function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/**
 * A bot string in `locale` (English when not yet translated), with `{name}`
 * placeholders filled. Every value is HTML-escaped: messages go out in HTML
 * parse mode, and only the templates themselves may carry markup.
 */
export function tr(
  locale: BotLocale,
  key: BotMessageKey,
  params: Record<string, string | number> = {},
): string {
  const template = BOT_MESSAGES[locale][key] ?? BOT_MESSAGES_EN[key];
  return template.replace(/\{(\w+)\}/g, (whole, name: string) =>
    name in params ? escapeHtml(String(params[name])) : whole,
  );
}

/** `tr` without HTML escaping, for plain-text places: button labels, invoices, toasts. */
export function trPlain(
  locale: BotLocale,
  key: BotMessageKey,
  params: Record<string, string | number> = {},
): string {
  const template = BOT_MESSAGES[locale][key] ?? BOT_MESSAGES_EN[key];
  return template.replace(/\{(\w+)\}/g, (whole, name: string) =>
    name in params ? String(params[name]) : whole,
  );
}

/** A duration in words, plain text ("3 months"); escape it when it goes into HTML. */
export function durationLabel(locale: BotLocale, months: number): string {
  return months === 1
    ? trPlain(locale, 'durationOne')
    : trPlain(locale, 'durationMany', { months });
}

/** The quantities the bot offers (the billing core allows up to 50). */
export const QUANTITIES = [1, 2, 3, 5, 10] as const;

// --- the button protocol ------------------------------------------------------

export type Action =
  | { k: 'menu' }
  | { k: 'langs' }
  | { k: 'lang'; lang: BotLocale }
  | { k: 'privacy' }
  | { k: 'terms' }
  | { k: 'buy' }
  | { k: 'dur'; months: number }
  /** Show the terms and the price for this order, with Accept and pay. */
  | { k: 'qty'; months: number; qty: number }
  /**
   * The buyer accepted the terms at this price per code: create the order and
   * send the Stars invoice. A price that changed since is refused, never swapped.
   */
  | { k: 'accept'; months: number; qty: number; stars: number }
  | { k: 'ack'; ref: string };

const REF = /^[0-9a-f]{32}$/;

function intIn(s: string | undefined, min: number, max: number): number | null {
  if (!s || !/^\d{1,6}$/.test(s)) return null;
  const n = Number(s);
  return n >= min && n <= max ? n : null;
}

/** callback_data for an action, in a language: `<code>|<lang>|<fields...>`. */
export function encodeAction(lang: BotLocale, a: Action): string {
  switch (a.k) {
    case 'menu':
      return `m|${lang}`;
    case 'langs':
      return `L|${lang}`;
    case 'lang':
      return `l|${a.lang}`;
    case 'privacy':
      return `v|${lang}`;
    case 'terms':
      return `T|${lang}`;
    case 'buy':
      return `b|${lang}`;
    case 'dur':
      return `d|${lang}|${a.months}`;
    case 'qty':
      return `q|${lang}|${a.months}|${a.qty}`;
    case 'accept':
      return `t|${lang}|${a.months}|${a.qty}|${a.stars}`;
    case 'ack':
      return `a|${lang}|${a.ref}`;
  }
}

/** Parse callback_data strictly; anything unexpected is null (never trusted). */
export function decodeAction(data: string | undefined): { lang: BotLocale; action: Action } | null {
  if (!data || data.length > 64) return null;
  const [code, lang, f1, f2, f3, f4] = data.split('|');
  if (f4 !== undefined || !lang || !isBotLocale(lang)) return null;
  // Only Accept carries a third field (the price per code it showed).
  if (f3 !== undefined && code !== 't') return null;
  const months = intIn(f1, 1, MAX_DURATION_MONTHS);
  const qty = intIn(f2, 1, 50);
  const bare = f1 === undefined;
  switch (code) {
    case 'm':
      return bare ? { lang, action: { k: 'menu' } } : null;
    case 'L':
      return bare ? { lang, action: { k: 'langs' } } : null;
    case 'l':
      return bare ? { lang, action: { k: 'lang', lang } } : null;
    case 'v':
      return bare ? { lang, action: { k: 'privacy' } } : null;
    case 'T':
      return bare ? { lang, action: { k: 'terms' } } : null;
    case 'b':
      return bare ? { lang, action: { k: 'buy' } } : null;
    case 'd':
      return months !== null && f2 === undefined ? { lang, action: { k: 'dur', months } } : null;
    case 'q':
      return months !== null && qty !== null ? { lang, action: { k: 'qty', months, qty } } : null;
    case 't': {
      const stars = intIn(f3, 1, MAX_STARS_PER_CODE);
      return months !== null && qty !== null && stars !== null
        ? { lang, action: { k: 'accept', months, qty, stars } }
        : null;
    }
    case 'a':
      return f1 !== undefined && REF.test(f1) && f2 === undefined
        ? { lang, action: { k: 'ack', ref: f1 } }
        : null;
    default:
      return null;
  }
}

/** A bot command (`/buy`, `/start`, `/buy@SomeBot`) -> name + argument. */
export function parseCommand(text: string | undefined): { name: string; arg?: string } | null {
  const m = /^\/([a-z]+)(?:@[A-Za-z0-9_]+)?(?:\s+(\S+))?\s*$/.exec((text ?? '').trim());
  return m ? { name: m[1]!, ...(m[2] ? { arg: m[2] } : {}) } : null;
}

// --- what can be bought ---------------------------------------------------------
//
// Telegram Stars only: Telegram's rules say a bot selling digital goods takes
// Stars and nothing else (no crypto, no outside payment page).

/** The slice of the billing config the shop needs (see telegramBot.shopContext). */
export interface ShopBilling {
  enabled: boolean;
  durations: { months: number }[];
}

/** The ShopBilling slice of a resolved billing config. */
export function toShopBilling(b: ShopBilling): ShopBilling {
  return { enabled: b.enabled, durations: b.durations.map(({ months }) => ({ months })) };
}

export function starsPriceFor(prices: StarsPrice[], months: number): number | null {
  return prices.find((p) => p.months === months)?.stars ?? null;
}

/** Stars for one code of `months`, or null when it isn't sold. */
export function starsOffer(
  tg: TelegramConfig,
  billing: ShopBilling,
  months: number,
): number | null {
  if (!tg.starsEnabled || !billing.enabled) return null;
  if (!billing.durations.some((d) => d.months === months)) return null;
  return starsPriceFor(tg.starsPrices, months);
}

/** Durations the shop sells, shortest first. */
export function sellableDurations(tg: TelegramConfig, billing: ShopBilling): number[] {
  return billing.durations
    .map((d) => d.months)
    .filter((m) => starsOffer(tg, billing, m) !== null)
    .sort((a, b) => a - b);
}

/** The shop is open: switched on, billing on, and something to sell. */
export function shopOpen(tg: TelegramConfig, billing: ShopBilling): boolean {
  return tg.enabled && sellableDurations(tg, billing).length > 0;
}

/** The short order reference shown to a buyer for support (the admin list shows the same prefix). */
export function refPrefix(ref: string): string {
  return ref.slice(0, 8);
}
