/**
 * The Telegram gift shop bot (docs/billing.md § "Telegram gift shop"). It
 * sells membership GIFT CODES and nothing else; buyers redeem a code in the
 * app like any other. The bot never asks for, sees or stores an account
 * number, so a Telegram identity never meets a FreeSocks account.
 *
 * Privacy rules this module keeps:
 * - No chat id, user id, name or update is stored. The only trace of a chat
 *   is its per-chat rate-limit row, keyed by a salted HMAC (swept like every
 *   rate-limit row). Update ids are kept two days for dedupe, nothing else.
 * - No per-chat state: every step's data rides in the button (lib/telegram/flow.ts).
 * - Delivery is pull-only: a crypto buyer taps "Check payment" (or returns
 *   through the processor's t.me deep link); a Stars buyer gets the codes in
 *   the same update as Telegram's successful_payment. The bot can't message
 *   anyone later, because it doesn't know who they are.
 * - Nothing here logs a chat id or a message: errors log a kind only.
 *
 * Bot API calls go through lib/telegram/api.ts (the token is part of the URL,
 * so errors there never carry one). TELEGRAM_BOT_TOKEN is env only.
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import { internal } from './_generated/api';
import { hmacSha256Hex, randomHex } from './lib/crypto';
import { recordHeartbeat } from './cronHeartbeat';
import {
  resolveBillingConfig,
  resolveDirectCoins,
  resolveProcessorSecrets,
} from './lib/billingConfig';
import { resolveTelegramConfig, type TelegramConfig } from './lib/telegramConfig';
import * as tg from './lib/telegram/api';
import type { InlineKeyboard } from './lib/telegram/api';
import {
  BOT_LOCALES,
  LOCALE_NAMES,
  QUANTITIES,
  decodeAction,
  durationLabel,
  encodeAction,
  escapeHtml,
  formatFiat,
  methodLabel,
  methodsFor,
  parseCommand,
  pickLocale,
  refPrefix,
  sellableDurations,
  shopOpen,
  starsPriceFor,
  startOrderRef,
  tr,
  trPlain,
  type Action,
  type BotLocale,
  type ShopBilling,
} from './lib/telegram/flow';
import type { BotOrderStatus } from './billing';

const DAY = 86_400_000;
/** How long update ids are kept for dedupe (Telegram retries for far less). */
const UPDATE_RETENTION_MS = 2 * DAY;

// --- DB side ------------------------------------------------------------------

export interface ShopContext {
  tg: TelegramConfig;
  billing: ShopBilling;
  /** NOWPayments coins with a direct (in-chat) checkout; empty = hosted page only. */
  coins: { ticker: string; label: string; network: string }[];
  /** The website, for links ('' when unset). */
  site: string;
}

export const shopContext = internalQuery({
  args: {},
  handler: async (ctx): Promise<ShopContext> => {
    const [tgConfig, billing, secrets] = await Promise.all([
      resolveTelegramConfig(ctx.db),
      resolveBillingConfig(ctx.db),
      resolveProcessorSecrets(ctx.db),
    ]);
    const coins =
      billing.enabled && billing.rails.nowpayments
        ? (await resolveDirectCoins(ctx.db, billing)).map(({ ticker, label, network }) => ({
            ticker,
            label,
            network,
          }))
        : [];
    return {
      tg: tgConfig,
      billing: {
        enabled: billing.enabled,
        currency: billing.currency,
        durations: billing.durations.map(({ months, amountCents }) => ({ months, amountCents })),
        rails: { nowpayments: billing.rails.nowpayments, btcpay: billing.rails.btcpay },
        cryptoMinMonths: billing.cryptoMinMonths,
        btcpayMinMonths: billing.btcpayMinMonths,
      },
      coins,
      site: (secrets.publicBaseUrl ?? '').replace(/\/$/, ''),
    };
  },
});

/** Dedupe one update id (Telegram redelivers until it sees a 200). */
export const claimUpdate = internalMutation({
  args: { updateId: v.number() },
  handler: async (ctx, { updateId }): Promise<{ fresh: boolean }> => {
    const seen = await ctx.db
      .query('telegramUpdates')
      .withIndex('by_update_id', (q) => q.eq('updateId', updateId))
      .first();
    if (seen) return { fresh: false };
    await ctx.db.insert('telegramUpdates', { updateId });
    return { fresh: true };
  },
});

/** Forget an update id so Telegram's redelivery is handled again (a payment that failed). */
export const releaseUpdate = internalMutation({
  args: { updateId: v.number() },
  handler: async (ctx, { updateId }): Promise<void> => {
    const row = await ctx.db
      .query('telegramUpdates')
      .withIndex('by_update_id', (q) => q.eq('updateId', updateId))
      .first();
    if (row) await ctx.db.delete(row._id);
  },
});

/** Daily: drop update ids older than two days (nothing else is ever stored). */
export const sweepUpdates = internalMutation({
  args: { rounds: v.optional(v.number()) },
  handler: async (ctx, { rounds }): Promise<{ removed: number }> => {
    await recordHeartbeat(ctx, 'retention-telegram-updates');
    const cutoff = Date.now() - UPDATE_RETENTION_MS;
    const page = 1000;
    const rows = await ctx.db
      .query('telegramUpdates')
      .withIndex('by_creation_time', (q) => q.lt('_creationTime', cutoff))
      .take(page);
    for (const r of rows) await ctx.db.delete(r._id);
    const n = rounds ?? 0;
    if (rows.length === page && n < 50) {
      await ctx.scheduler.runAfter(0, internal.telegramBot.sweepUpdates, { rounds: n + 1 });
    }
    return { removed: rows.length };
  },
});

// --- the update shape (only the fields the shop reads) -----------------------

interface TgUser {
  id: number;
  language_code?: string;
}
interface TgChat {
  id: number;
  type: string;
}
interface TgPayment {
  currency: string;
  total_amount: number;
  invoice_payload: string;
  telegram_payment_charge_id: string;
}
interface TgMessage {
  message_id: number;
  chat: TgChat;
  from?: TgUser;
  text?: string;
  successful_payment?: TgPayment;
  refunded_payment?: TgPayment;
}
interface TgUpdate {
  update_id: number;
  message?: TgMessage;
  callback_query?: { id: string; from: TgUser; data?: string; message?: TgMessage };
  pre_checkout_query?: {
    id: string;
    from: TgUser;
    currency: string;
    total_amount: number;
    invoice_payload: string;
  };
}

function parseUpdate(raw: string): TgUpdate | null {
  try {
    const u = JSON.parse(raw) as TgUpdate;
    return u && typeof u === 'object' && Number.isSafeInteger(u.update_id) ? u : null;
  } catch {
    return null;
  }
}

/** The per-chat rate-limit subject: a salted HMAC, never the chat id itself. */
async function chatSubject(chatId: number): Promise<string> {
  const salt = process.env.IP_HASH_SALT;
  if (!salt) throw new Error('IP_HASH_SALT must be set');
  return hmacSha256Hex(salt, `telegram:${chatId}`);
}

// --- one conversation step ---------------------------------------------------

type Out = { text: string; keyboard?: InlineKeyboard };

class Bot {
  constructor(
    private readonly ctx: ActionCtx,
    private readonly token: string,
    private readonly shop: ShopContext,
    private readonly chatId: number,
    private readonly lang: BotLocale,
    /** The message a button sits on: menus edit it in place instead of piling up. */
    private readonly editId?: number,
  ) {}

  private btn(text: string, action: Action, lang: BotLocale = this.lang) {
    return { text, callback_data: encodeAction(lang, action) };
  }

  /** Show a step: edit the button's message when there is one, else send. */
  async show(out: Out): Promise<void> {
    if (this.editId !== undefined) {
      try {
        await tg.editMessageText(this.token, this.chatId, this.editId, out.text, {
          html: true,
          keyboard: out.keyboard,
        });
        return;
      } catch {
        // Too old to edit, or unchanged: send a fresh one instead.
      }
    }
    await this.send(out);
  }

  async send(out: Out): Promise<void> {
    await tg.sendMessage(this.token, this.chatId, out.text, { html: true, keyboard: out.keyboard });
  }

  private siteLine(): string {
    return this.shop.site || 'FreeSocks';
  }

  closed(): Out {
    return { text: tr(this.lang, 'closed', { site: this.siteLine() }) };
  }

  menu(): Out {
    return {
      text: tr(this.lang, 'welcome', { site: this.siteLine() }),
      keyboard: [
        [this.btn(trPlain(this.lang, 'buttonBuy'), { k: 'buy' })],
        [
          this.btn(trPlain(this.lang, 'buttonPrivacy'), { k: 'privacy' }),
          this.btn(trPlain(this.lang, 'buttonLanguage'), { k: 'langs' }),
        ],
      ],
    };
  }

  languages(): Out {
    const row = BOT_LOCALES.map((l) => this.btn(LOCALE_NAMES[l], { k: 'lang', lang: l }, l));
    return { text: tr(this.lang, 'chooseLanguage'), keyboard: [row.slice(0, 3), row.slice(3)] };
  }

  privacy(): Out {
    return {
      text: tr(this.lang, 'privacy'),
      keyboard: [[this.btn(trPlain(this.lang, 'buttonBack'), { k: 'menu' })]],
    };
  }

  durations(): Out {
    const rows = sellableDurations(this.shop.tg, this.shop.billing).map((months) => [
      this.btn(durationLabel(this.lang, months), { k: 'dur', months }),
    ]);
    rows.push([this.btn(trPlain(this.lang, 'buttonBack'), { k: 'menu' })]);
    return { text: tr(this.lang, 'chooseDuration'), keyboard: rows };
  }

  quantities(months: number): Out {
    const row = QUANTITIES.map((qty) => this.btn(String(qty), { k: 'qty', months, qty }));
    return {
      text: tr(this.lang, 'chooseQuantity'),
      keyboard: [row, [this.btn(trPlain(this.lang, 'buttonBack'), { k: 'buy' })]],
    };
  }

  methods(months: number, qty: number): Out {
    const offers = methodsFor(this.shop.tg, this.shop.billing, months, qty);
    const rows = offers.map((o) => [
      this.btn(methodLabel(this.lang, o, this.shop.billing.currency), {
        k: 'pay',
        months,
        qty,
        method: o.method,
      }),
    ]);
    rows.push([this.btn(trPlain(this.lang, 'buttonBack'), { k: 'dur', months })]);
    const summary = tr(this.lang, 'orderSummary', {
      quantity: qty,
      duration: durationLabel(this.lang, months),
    });
    return { text: `${summary}\n\n${tr(this.lang, 'choosePayment')}`, keyboard: rows };
  }

  coins(months: number, qty: number): Out {
    const rows = this.shop.coins.slice(0, 24).map((c) => [
      this.btn(`${c.label} (${c.network})`.slice(0, 60), {
        k: 'coin',
        months,
        qty,
        ticker: c.ticker,
      }),
    ]);
    rows.push([this.btn(trPlain(this.lang, 'buttonBack'), { k: 'qty', months, qty })]);
    return { text: tr(this.lang, 'chooseCoin'), keyboard: rows };
  }

  private checkRow(ref: string) {
    return [this.btn(trPlain(this.lang, 'buttonCheck'), { k: 'check', ref })];
  }

  /** The payment step for a crypto order: deposit details, or the hosted page. */
  payment(ref: string, status: BotOrderStatus, hostedUrl: string, fiat: number): Out {
    const summary = tr(this.lang, 'orderSummary', {
      quantity: status.quantity,
      duration: durationLabel(this.lang, status.months),
    });
    const head = `${summary}\n${tr(this.lang, 'orderRef', { ref: refPrefix(ref) })}`;
    const p = status.payment;
    if (!p || p.methods.length === 0) {
      return {
        text: `${head}\n\n${tr(this.lang, 'payHosted', { amount: formatFiat(fiat, this.shop.billing.currency) })}`,
        keyboard: [
          [{ text: trPlain(this.lang, 'buttonOpenPayment'), url: hostedUrl }],
          this.checkRow(ref),
        ],
      };
    }
    const blocks = p.methods.map((m) => {
      const lines = [
        tr(this.lang, 'payDirect', { amount: m.amount, unit: m.unit, address: m.address }),
      ];
      if (m.network) lines.push(tr(this.lang, 'payNetwork', { network: m.network }));
      if (m.memo) lines.push(tr(this.lang, 'payMemo', { memo: m.memo }));
      return lines.join('\n');
    });
    const tail: string[] = [];
    if (p.expiresAt) {
      tail.push(
        tr(this.lang, 'payExpires', { expires: p.expiresAt.slice(0, 16).replace('T', ' ') }),
      );
    }
    tail.push(tr(this.lang, 'payAfter'));
    return {
      text: [head, ...blocks, tail.join('\n')].join('\n\n'),
      keyboard: [
        [{ text: trPlain(this.lang, 'buttonOpenPayment'), url: p.hostedUrl }],
        this.checkRow(ref),
      ],
    };
  }

  /** The codes, with the delete button. Sent as a NEW message so it can be deleted alone. */
  async sendCodes(ref: string, status: BotOrderStatus): Promise<void> {
    const codes = status.giftCodes.map((c) => `<code>${escapeHtml(c)}</code>`).join('\n');
    const keyboard: InlineKeyboard = [
      [this.btn(trPlain(this.lang, 'buttonSaved'), { k: 'ack', ref })],
    ];
    if (this.shop.site) {
      keyboard.push([
        { text: trPlain(this.lang, 'buttonRedeem'), url: `${this.shop.site}/account` },
      ]);
    }
    await tg.sendMessage(
      this.token,
      this.chatId,
      [
        tr(this.lang, 'codesTitle'),
        codes,
        tr(this.lang, 'codesHelp', { duration: durationLabel(this.lang, status.months) }),
        tr(this.lang, 'orderRef', { ref: refPrefix(ref) }),
      ].join('\n\n'),
      { html: true, keyboard },
    );
  }

  /** Where an order stands, as the buyer sees it. Paid + unseen codes are sent. */
  async check(ref: string): Promise<void> {
    const status = await this.ctx.runQuery(internal.billing.botOrderStatus, { orderRef: ref });
    if (!status) {
      await this.send({ text: tr(this.lang, 'orderNotFound') });
      return;
    }
    const r = { ref: refPrefix(ref) };
    switch (status.status) {
      case 'paid':
        if (status.giftCodes.length > 0) await this.sendCodes(ref, status);
        else await this.send({ text: tr(this.lang, 'codesGone', r) });
        return;
      case 'pending':
        await this.send({ text: tr(this.lang, 'notPaidYet'), keyboard: [this.checkRow(ref)] });
        return;
      case 'confirming':
        await this.send({ text: tr(this.lang, 'confirming'), keyboard: [this.checkRow(ref)] });
        return;
      case 'underpaid':
        await this.send({ text: tr(this.lang, 'underpaid', r) });
        return;
      case 'expired':
        await this.send({ text: tr(this.lang, 'expired') });
        return;
      case 'failed':
        await this.send({ text: tr(this.lang, 'failed') });
        return;
    }
  }

  /** The buyer saved the codes: clear them server-side, then delete the message. */
  async ack(ref: string, messageId: number | undefined): Promise<void> {
    await this.ctx.runMutation(internal.billing.ackBotGiftReveal, { orderRef: ref });
    if (messageId !== undefined) {
      await tg.deleteMessage(this.token, this.chatId, messageId).catch(() => undefined);
    }
    await this.send({ text: tr(this.lang, 'deleted') });
  }

  /** Create the order for a chosen method (and coin), then show how to pay. */
  async pay(months: number, qty: number, method: 's' | 'n' | 'b', ticker?: string): Promise<void> {
    const offer = methodsFor(this.shop.tg, this.shop.billing, months, qty).find(
      (o) => o.method === method,
    );
    if (!offer) {
      await this.show({ text: tr(this.lang, 'unavailable') });
      return;
    }
    // Crypto with a coin list: pick the coin first (no order exists yet).
    if (method === 'n' && !ticker && this.shop.coins.length > 0) {
      await this.show(this.coins(months, qty));
      return;
    }
    const limit = await this.ctx.runMutation(internal.rateLimits.enforce, {
      policyKey: 'bot.telegram.checkout',
      subject: await chatSubject(this.chatId),
    });
    if (!limit.allowed) {
      await this.send({ text: tr(this.lang, 'rateLimited') });
      return;
    }

    if (method === 's') {
      const perCode = starsPriceFor(this.shop.tg.starsPrices, months);
      if (perCode === null) {
        await this.show({ text: tr(this.lang, 'unavailable') });
        return;
      }
      const { orderRef, totalStars } = await this.ctx.runMutation(
        internal.billing.createStarsOrder,
        { opaqueRef: randomHex(16), months, quantity: qty, starsPerCode: perCode },
      );
      const duration = durationLabel(this.lang, months);
      await tg.sendStarsInvoice(this.token, this.chatId, {
        title: trPlain(this.lang, 'starsTitle'),
        description: trPlain(this.lang, 'starsDescription', { quantity: qty, duration }),
        payload: orderRef,
        label: trPlain(this.lang, 'starsLabel'),
        stars: totalStars,
      });
      return;
    }

    let res: { redirectUrl: string; orderRef: string; direct: boolean };
    try {
      res = await this.ctx.runAction(internal.billing.createCheckout, {
        processor: method === 'b' ? 'btcpay' : 'nowpayments',
        months,
        kind: 'gift',
        quantity: qty,
        channel: 'telegram',
        botUsername: this.shop.tg.botUsername,
        ...(ticker ? { payCurrency: ticker } : {}),
      });
    } catch (err) {
      const code = err instanceof ConvexError ? (err.data as { code?: string }).code : undefined;
      await this.send({
        text: tr(this.lang, code === 'billing.coin_minimum' ? 'belowMinimum' : 'unavailable'),
      });
      return;
    }
    const status = await this.ctx.runQuery(internal.billing.botOrderStatus, {
      orderRef: res.orderRef,
    });
    if (!status) throw new Error('order vanished after checkout');
    await this.show(this.payment(res.orderRef, status, res.redirectUrl, offer.amount));
  }
}

// --- the entry point ------------------------------------------------------------

/** A Stars payment that must be redelivered (its grant failed). */
class PaymentRetry extends Error {
  constructor(readonly cause: unknown) {
    super('payment retry');
  }
}

/**
 * Handle one verified update (the webhook route checked the secret header).
 * Never throws for a buyer's mistake: the route answers 200, so a bad update
 * isn't redelivered forever. The one exception is a Stars payment whose grant
 * failed: its update id is released and the error rethrown, so the route
 * answers 500 and Telegram delivers the payment again.
 */
export const handleUpdate = internalAction({
  args: { rawBody: v.string() },
  handler: async (ctx, { rawBody }): Promise<{ handled: boolean }> => {
    const token = process.env.TELEGRAM_BOT_TOKEN;
    const update = parseUpdate(rawBody);
    if (!token || !update) return { handled: false };
    const claim = await ctx.runMutation(internal.telegramBot.claimUpdate, {
      updateId: update.update_id,
    });
    if (!claim.fresh) return { handled: false };

    const shop = await ctx.runQuery(internal.telegramBot.shopContext, {});
    const open = shopOpen(shop.tg, shop.billing) && shop.tg.botUsername !== '';

    try {
      // Telegram waits at most 10 seconds for this answer: no rate limit here.
      const pq = update.pre_checkout_query;
      if (pq) {
        const verdict = open
          ? await ctx.runQuery(internal.billing.starsPreCheckout, {
              orderRef: pq.invoice_payload,
              totalAmount: pq.total_amount,
              currency: pq.currency,
            })
          : { ok: false as const };
        await tg.answerPreCheckoutQuery(
          token,
          pq.id,
          verdict.ok,
          verdict.ok ? undefined : trPlain(pickLocale(pq.from.language_code), 'starsRefused'),
        );
        return { handled: true };
      }

      const msg = update.message ?? update.callback_query?.message;
      // Private chats only: in a group, gift codes would be shown to everyone.
      if (!msg || msg.chat.type !== 'private') return { handled: false };
      const chatId = msg.chat.id;

      // Money moved: always process, never rate-limited or closed.
      const paid = update.message?.successful_payment;
      const refunded = update.message?.refunded_payment;
      if (paid || refunded) {
        const p = (paid ?? refunded)!;
        let res: { duplicate: boolean };
        try {
          res = await ctx.runAction(internal.billing.ingestStarsPayment, {
            orderRef: p.invoice_payload,
            chargeId: p.telegram_payment_charge_id,
            totalAmount: p.total_amount,
            currency: p.currency,
            event: paid ? 'paid' : 'refunded',
          });
        } catch (err) {
          await ctx.runMutation(internal.telegramBot.releaseUpdate, {
            updateId: update.update_id,
          });
          throw new PaymentRetry(err);
        }
        if (paid && !res.duplicate) {
          const lang = pickLocale(update.message?.from?.language_code);
          await new Bot(ctx, token, shop, chatId, lang).check(p.invoice_payload);
        }
        return { handled: true };
      }

      const cq = update.callback_query;
      const decoded = cq ? decodeAction(cq.data) : null;
      const lang = decoded?.lang ?? pickLocale((cq?.from ?? update.message?.from)?.language_code);

      const limit = await ctx.runMutation(internal.rateLimits.enforce, {
        policyKey: 'bot.telegram.chat',
        subject: await chatSubject(chatId),
      });
      if (!limit.allowed) {
        if (cq) await tg.answerCallbackQuery(token, cq.id, trPlain(lang, 'rateLimited'));
        return { handled: true };
      }

      if (cq) {
        await tg.answerCallbackQuery(token, cq.id).catch(() => undefined);
        if (!decoded) return { handled: true };
        const bot = new Bot(ctx, token, shop, chatId, lang, cq.message?.message_id);
        const a = decoded.action;
        // Checking or clearing an order, privacy and language work even while
        // the shop is closed; everything that sells needs it open.
        const sells = !['check', 'ack', 'privacy', 'langs'].includes(a.k);
        if (sells && !open) {
          await bot.show(bot.closed());
          return { handled: true };
        }
        switch (a.k) {
          case 'check':
            await bot.check(a.ref);
            break;
          case 'ack':
            await bot.ack(a.ref, cq.message?.message_id);
            break;
          case 'privacy':
            await bot.show(bot.privacy());
            break;
          case 'langs':
            await bot.show(bot.languages());
            break;
          case 'menu':
          case 'lang':
            await bot.show(bot.menu());
            break;
          case 'buy':
            await bot.show(bot.durations());
            break;
          case 'dur':
            await bot.show(bot.quantities(a.months));
            break;
          case 'qty':
            await bot.show(bot.methods(a.months, a.qty));
            break;
          case 'pay':
            await bot.pay(a.months, a.qty, a.method);
            break;
          case 'coin':
            await bot.pay(a.months, a.qty, 'n', a.ticker);
            break;
        }
        return { handled: true };
      }

      const cmd = parseCommand(update.message?.text);
      const bot = new Bot(ctx, token, shop, chatId, lang);
      const ref = cmd?.name === 'start' ? startOrderRef(cmd.arg) : null;
      if (ref) await bot.check(ref);
      else if (cmd?.name === 'privacy') await bot.send(bot.privacy());
      else if (cmd?.name === 'language') await bot.send(bot.languages());
      else if (cmd?.name === 'help') await bot.send({ text: tr(lang, 'help') });
      else if (!open) await bot.send(bot.closed());
      else if (cmd?.name === 'buy') await bot.send(bot.durations());
      else if (cmd?.name === 'start') await bot.send(bot.menu());
      else await bot.send({ text: tr(lang, 'unknown') });
      return { handled: true };
    } catch (err) {
      if (err instanceof PaymentRetry) throw new Error('telegram payment not applied; retry');
      // A kind only: never the update, the chat or (from the API client) a URL.
      console.error(
        '[telegram] update failed:',
        err instanceof tg.TelegramApiError
          ? err.message
          : err instanceof Error
            ? err.name
            : 'error',
      );
      return { handled: false };
    }
  },
});
