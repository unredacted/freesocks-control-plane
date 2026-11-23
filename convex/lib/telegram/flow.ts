/**
 * Pure helpers for the Telegram gift shop (convex/telegramBot.ts): language,
 * text, the stateless button protocol, and which payment methods a duration
 * can be bought with. No Convex or network access, so all of it is unit-tested.
 *
 * STATELESS BY DESIGN: the bot keeps no per-chat session. Everything a step
 * needs (language, duration, quantity, payment method, coin, order ref)
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

/** A catalog price in minor units, e.g. 1400 USD -> "$14.00". */
export function formatFiat(minor: number, currency: string): string {
  try {
    return new Intl.NumberFormat('en-US', { style: 'currency', currency }).format(minor / 100);
  } catch {
    return `${(minor / 100).toFixed(2)} ${currency}`;
  }
}

/** The quantities the bot offers (the billing core allows up to 50). */
export const QUANTITIES = [1, 2, 3, 5, 10] as const;

/** Payment methods: s = Telegram Stars, n = NOWPayments crypto, b = BTCPay Bitcoin. */
export type PayMethod = 's' | 'n' | 'b';
export const METHOD_PROCESSOR = { n: 'nowpayments', b: 'btcpay' } as const;

// --- the button protocol ------------------------------------------------------

export type Action =
  | { k: 'menu' }
  | { k: 'langs' }
  | { k: 'lang'; lang: BotLocale }
  | { k: 'privacy' }
  | { k: 'buy' }
  | { k: 'dur'; months: number }
  | { k: 'qty'; months: number; qty: number }
  | { k: 'pay'; months: number; qty: number; method: PayMethod }
  | { k: 'coin'; months: number; qty: number; ticker: string }
  | { k: 'check'; ref: string }
  | { k: 'ack'; ref: string };

const REF = /^[0-9a-f]{32}$/;
const TICKER = /^[a-z0-9]{2,20}$/;

function intIn(s: string | undefined, min: number, max: number): number | null {
  if (!s || !/^\d{1,3}$/.test(s)) return null;
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
    case 'buy':
      return `b|${lang}`;
    case 'dur':
      return `d|${lang}|${a.months}`;
    case 'qty':
      return `q|${lang}|${a.months}|${a.qty}`;
    case 'pay':
      return `p|${lang}|${a.months}|${a.qty}|${a.method}`;
    case 'coin':
      return `c|${lang}|${a.months}|${a.qty}|${a.ticker}`;
    case 'check':
      return `k|${lang}|${a.ref}`;
    case 'ack':
      return `a|${lang}|${a.ref}`;
  }
}

/** Parse callback_data strictly; anything unexpected is null (never trusted). */
export function decodeAction(data: string | undefined): { lang: BotLocale; action: Action } | null {
  if (!data || data.length > 64) return null;
  const [code, lang, f1, f2, f3, ...rest] = data.split('|');
  if (rest.length > 0 || !lang || !isBotLocale(lang)) return null;
  const months = intIn(f1, 1, 36);
  const qty = intIn(f2, 1, 50);
  switch (code) {
    case 'm':
      return f1 === undefined ? { lang, action: { k: 'menu' } } : null;
    case 'L':
      return f1 === undefined ? { lang, action: { k: 'langs' } } : null;
    case 'l':
      return f1 === undefined ? { lang, action: { k: 'lang', lang } } : null;
    case 'v':
      return f1 === undefined ? { lang, action: { k: 'privacy' } } : null;
    case 'b':
      return f1 === undefined ? { lang, action: { k: 'buy' } } : null;
    case 'd':
      return months !== null && f2 === undefined ? { lang, action: { k: 'dur', months } } : null;
    case 'q':
      return months !== null && qty !== null && f3 === undefined
        ? { lang, action: { k: 'qty', months, qty } }
        : null;
    case 'p':
      return months !== null && qty !== null && (f3 === 's' || f3 === 'n' || f3 === 'b')
        ? { lang, action: { k: 'pay', months, qty, method: f3 } }
        : null;
    case 'c':
      return months !== null && qty !== null && f3 !== undefined && TICKER.test(f3)
        ? { lang, action: { k: 'coin', months, qty, ticker: f3 } }
        : null;
    case 'k':
      return f1 !== undefined && REF.test(f1) && f2 === undefined
        ? { lang, action: { k: 'check', ref: f1 } }
        : null;
    case 'a':
      return f1 !== undefined && REF.test(f1) && f2 === undefined
        ? { lang, action: { k: 'ack', ref: f1 } }
        : null;
    default:
      return null;
  }
}

/** `/start o_<ref>` (the processor's return link) -> the order ref, else null. */
export function startOrderRef(param: string | undefined): string | null {
  const m = /^o_([0-9a-f]{32})$/.exec(param ?? '');
  return m ? m[1]! : null;
}

/** A bot command (`/buy`, `/start o_...`, `/buy@SomeBot`) -> name + argument. */
export function parseCommand(text: string | undefined): { name: string; arg?: string } | null {
  const m = /^\/([a-z]+)(?:@[A-Za-z0-9_]+)?(?:\s+(\S+))?\s*$/.exec((text ?? '').trim());
  return m ? { name: m[1]!, ...(m[2] ? { arg: m[2] } : {}) } : null;
}

// --- what can be bought, and how --------------------------------------------

/** The slice of the billing config the shop needs (see telegramBot.shopContext). */
export interface ShopBilling {
  enabled: boolean;
  currency: string;
  durations: { months: number; amountCents: number }[];
  rails: { nowpayments: boolean; btcpay: boolean };
  cryptoMinMonths: number;
  btcpayMinMonths: number;
}

export interface MethodOffer {
  method: PayMethod;
  /** Price for the whole order: Stars (whole) for 's', catalog minor units otherwise. */
  amount: number;
}

export function starsPriceFor(prices: StarsPrice[], months: number): number | null {
  return prices.find((p) => p.months === months)?.stars ?? null;
}

/** The ways to pay for `qty` codes of `months`, in display order. */
export function methodsFor(
  tg: TelegramConfig,
  billing: ShopBilling,
  months: number,
  qty: number,
): MethodOffer[] {
  const duration = billing.durations.find((d) => d.months === months);
  if (!billing.enabled || !duration) return [];
  const out: MethodOffer[] = [];
  const stars = starsPriceFor(tg.starsPrices, months);
  if (tg.starsEnabled && stars !== null) out.push({ method: 's', amount: stars * qty });
  if (tg.cryptoEnabled) {
    const fiat = duration.amountCents * qty;
    if (billing.rails.nowpayments && months >= billing.cryptoMinMonths) {
      out.push({ method: 'n', amount: fiat });
    }
    if (billing.rails.btcpay && months >= billing.btcpayMinMonths) {
      out.push({ method: 'b', amount: fiat });
    }
  }
  return out;
}

/** Durations that at least one payment method can sell (any quantity). */
export function sellableDurations(tg: TelegramConfig, billing: ShopBilling): number[] {
  return billing.durations
    .map((d) => d.months)
    .filter((m) => methodsFor(tg, billing, m, 1).length > 0)
    .sort((a, b) => a - b);
}

/** The shop is open: switched on, billing on, and something to sell. */
export function shopOpen(tg: TelegramConfig, billing: ShopBilling): boolean {
  return tg.enabled && billing.enabled && sellableDurations(tg, billing).length > 0;
}

/** The label of one payment method button, with the order's price. */
export function methodLabel(locale: BotLocale, offer: MethodOffer, currency: string): string {
  if (offer.method === 's') {
    return trPlain(locale, 'payStars', {
      amount: trPlain(locale, 'starsAmount', { stars: offer.amount }),
    });
  }
  const amount = formatFiat(offer.amount, currency);
  return offer.method === 'b'
    ? trPlain(locale, 'payBitcoin', { amount })
    : trPlain(locale, 'payCrypto', { amount });
}

/** The short order reference shown to a buyer for support (the admin list shows the same prefix). */
export function refPrefix(ref: string): string {
  return ref.slice(0, 8);
}
