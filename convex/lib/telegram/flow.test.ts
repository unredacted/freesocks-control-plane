import { readFileSync } from 'node:fs';
import { describe, expect, test } from 'vitest';
import { buildBotMessagesSource, BOT_MESSAGES_PATH } from '../../../scripts/gen-bot-messages';
import { BOT_MESSAGES, BOT_MESSAGES_EN } from './botMessages.generated';
import {
  decodeAction,
  encodeAction,
  methodsFor,
  parseCommand,
  pickLocale,
  sellableDurations,
  shopOpen,
  startOrderRef,
  tr,
  type Action,
  type ShopBilling,
} from './flow';
import { TELEGRAM_DEFAULTS, telegramConfigWrites, type TelegramConfig } from '../telegramConfig';

const REF = '0123456789abcdef0123456789abcdef';

describe('the button protocol', () => {
  const actions: Action[] = [
    { k: 'menu' },
    { k: 'langs' },
    { k: 'lang', lang: 'fa' },
    { k: 'privacy' },
    { k: 'buy' },
    { k: 'dur', months: 12 },
    { k: 'qty', months: 3, qty: 10 },
    { k: 'accept', months: 120, qty: 50 },
    { k: 'terms' },
    { k: 'pay', months: 3, qty: 2, method: 's' },
    { k: 'coin', months: 3, qty: 2, ticker: 'usdttrc20' },
    { k: 'check', ref: REF },
    { k: 'ack', ref: REF },
  ];

  test('every action round-trips and fits in 64 bytes', () => {
    for (const a of actions) {
      const data = encodeAction('ru', a);
      expect(data.length).toBeLessThanOrEqual(64);
      const back = decodeAction(data);
      expect(back?.action).toEqual(a);
      expect(back?.lang).toBe(a.k === 'lang' ? a.lang : 'ru');
    }
  });

  test('anything off is refused', () => {
    for (const bad of [
      undefined,
      '',
      'x|en',
      'b|xx',
      'b|en|1',
      'd|en|0',
      'd|en|121',
      'q|en|3|51',
      'p|en|3|1|z',
      'c|en|3|1|USDT',
      'c|en|3|1|a;b',
      `k|en|${REF.toUpperCase()}`,
      `k|en|${REF}|x`,
      'a|en|short',
      `b|en|${'x'.repeat(70)}`,
    ]) {
      expect(decodeAction(bad), String(bad)).toBeNull();
    }
  });

  test('commands and the return deep link', () => {
    expect(parseCommand('/buy')).toEqual({ name: 'buy' });
    expect(parseCommand('/start@FreeSocksShopBot o_abc')).toEqual({ name: 'start', arg: 'o_abc' });
    expect(parseCommand('hello')).toBeNull();
    expect(startOrderRef(`o_${REF}`)).toBe(REF);
    expect(startOrderRef('o_nope')).toBeNull();
    expect(startOrderRef(undefined)).toBeNull();
  });
});

describe('language and text', () => {
  test('picks the client language, else English', () => {
    expect(pickLocale('fa')).toBe('fa');
    expect(pickLocale('zh-hans')).toBe('zh');
    expect(pickLocale('ru-RU')).toBe('ru');
    expect(pickLocale('de')).toBe('en');
    expect(pickLocale(undefined)).toBe('en');
  });

  test('escapes every value put into HTML', () => {
    expect(tr('en', 'orderRef', { ref: '<b>&' })).toBe('Order &lt;b&gt;&amp;');
  });

  test('falls back to English until a translation lands', () => {
    expect(tr('fa', 'buttonBuy')).toBe(BOT_MESSAGES.fa.buttonBuy ?? BOT_MESSAGES_EN.buttonBuy);
  });

  test('the generated catalog matches messages/*.json', () => {
    expect(readFileSync(BOT_MESSAGES_PATH, 'utf8')).toBe(buildBotMessagesSource());
  });

  test('bot text uses no em dashes, and translations keep the same placeholders', () => {
    const holes = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
    for (const [key, en] of Object.entries(BOT_MESSAGES_EN)) {
      for (const [locale, msgs] of Object.entries(BOT_MESSAGES)) {
        const s = (msgs as Record<string, string>)[key];
        if (s === undefined) continue;
        expect(s, `${locale} bot.${key}`).not.toContain('—');
        expect(holes(s), `${locale} bot.${key}`).toEqual(holes(en));
      }
    }
  });
});

describe('what the shop sells', () => {
  const billing: ShopBilling = {
    enabled: true,
    currency: 'USD',
    durations: [
      { months: 1, amountCents: 500 },
      { months: 3, amountCents: 1400 },
    ],
    rails: { nowpayments: true, btcpay: true },
    cryptoMinMonths: 3,
    btcpayMinMonths: 1,
  };
  const cfg = (over: Partial<TelegramConfig>): TelegramConfig => ({
    ...TELEGRAM_DEFAULTS,
    enabled: true,
    botUsername: 'FreeSocksShopBot',
    ...over,
  });

  test('each method needs its switch, its rail and its minimum', () => {
    const all = cfg({
      starsEnabled: true,
      cryptoEnabled: true,
      starsPrices: [{ months: 1, stars: 250 }],
    });
    expect(methodsFor(all, billing, 1, 2)).toEqual([
      { method: 's', amount: 500 },
      { method: 'b', amount: 1000 },
    ]);
    expect(methodsFor(all, billing, 3, 1)).toEqual([
      { method: 'n', amount: 1400 },
      { method: 'b', amount: 1400 },
    ]);
    expect(methodsFor(cfg({ cryptoEnabled: true }), { ...billing, enabled: false }, 3, 1)).toEqual(
      [],
    );
    expect(methodsFor(cfg({}), billing, 3, 1)).toEqual([]);
  });

  test('the shop is open only with something to sell', () => {
    expect(shopOpen(cfg({}), billing)).toBe(false);
    expect(shopOpen(cfg({ cryptoEnabled: true }), billing)).toBe(true);
    expect(shopOpen(cfg({ cryptoEnabled: true, enabled: false }), billing)).toBe(false);
    expect(
      sellableDurations(cfg({ cryptoEnabled: true }), {
        ...billing,
        rails: { nowpayments: true, btcpay: false },
      }),
    ).toEqual([3]);
  });
});

describe('admin settings validation', () => {
  test('accepts good values and refuses bad ones', () => {
    expect(telegramConfigWrites({ botUsername: '@FreeSocksShopBot', enabled: true })).toEqual([
      { key: 'telegram.enabled', value: true },
      { key: 'telegram.botUsername', value: 'FreeSocksShopBot' },
    ]);
    expect(telegramConfigWrites({ botUsername: '' })).toEqual([
      { key: 'telegram.botUsername', value: '' },
    ]);
    expect(() => telegramConfigWrites({ botUsername: 'a b' })).toThrow();
    expect(() => telegramConfigWrites({ starsPrices: [{ months: 3, stars: 0 }] })).toThrow();
    expect(() =>
      telegramConfigWrites({
        starsPrices: [
          { months: 3, stars: 10 },
          { months: 3, stars: 20 },
        ],
      }),
    ).toThrow();
  });
});
