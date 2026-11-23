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
 * - Payment is Telegram Stars only (Telegram's rule for digital goods in a
 *   bot). The codes go out in the same update as Telegram's
 *   successful_payment; the bot can't message anyone later, because it
 *   doesn't know who they are.
 * - Nothing here logs a chat id or a message: errors log a kind only.
 *
 * Bot API calls go through lib/telegram/api.ts (the token is part of the URL,
 * so errors there never carry one). The token comes from telegramAdmin.secrets.
 */
import { v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import { internal } from './_generated/api';
import { hmacSha256Hex, randomHex } from './lib/crypto';
import { recordHeartbeat } from './cronHeartbeat';
import { resolveBillingConfig, resolveProcessorSecrets } from './lib/billingConfig';
import { resolveTelegramConfig, type TelegramConfig } from './lib/telegramConfig';
import { resolveSiteConfig } from './lib/siteConfig';
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
  parseCommand,
  pickLocale,
  refPrefix,
  sellableDurations,
  shopOpen,
  starsOffer,
  toShopBilling,
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
  /** The website, for links ('' when unset). */
  site: string;
  /** Where buyers write for payment help ('' when unset). */
  supportEmail: string;
}

export const shopContext = internalQuery({
  args: {},
  handler: async (ctx): Promise<ShopContext> => {
    const [tgConfig, billing, secrets, site] = await Promise.all([
      resolveTelegramConfig(ctx.db),
      resolveBillingConfig(ctx.db),
      resolveProcessorSecrets(ctx.db),
      resolveSiteConfig(ctx.db),
    ]);
    return {
      tg: tgConfig,
      billing: toShopBilling(billing),
      site: (secrets.publicBaseUrl ?? '').replace(/\/$/, ''),
      supportEmail: site.supportEmail,
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
      } catch (err) {
        // Unchanged (a repeated tap): nothing to do, and no extra copy.
        if (err instanceof tg.TelegramApiError && /not modified/i.test(err.description ?? '')) {
          return;
        }
        // Too old to edit, or gone: send a fresh one instead.
      }
    }
    await this.send(out);
  }

  async send(out: Out): Promise<void> {
    await tg.sendMessage(this.token, this.chatId, out.text, { html: true, keyboard: out.keyboard });
  }

  /** One line of bot text in this chat's language. */
  say(key: Parameters<typeof tr>[1], params?: Parameters<typeof tr>[2]): string {
    return tr(this.lang, key, params);
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
          this.btn(trPlain(this.lang, 'buttonTerms'), { k: 'terms' }),
          this.btn(trPlain(this.lang, 'buttonLanguage'), { k: 'langs' }),
        ],
      ],
    };
  }

  /**
   * The terms of sale. With an order they come with its price, and the only
   * way on is the accept button, which opens the Stars invoice: Telegram's
   * rule that buyers accept the terms before paying.
   */
  terms(order?: { months: number; qty: number }): Out {
    const parts: string[] = [];
    let price: string | null = null;
    if (order) {
      const perCode = starsOffer(this.shop.tg, this.shop.billing, order.months);
      if (perCode === null) return { text: tr(this.lang, 'unavailable') };
      price = trPlain(this.lang, 'starsAmount', { stars: perCode * order.qty });
      parts.push(
        [
          tr(this.lang, 'orderSummary', {
            quantity: order.qty,
            duration: durationLabel(this.lang, order.months),
          }),
          tr(this.lang, 'orderPrice', { amount: price }),
        ].join('\n'),
        tr(this.lang, 'termsAsk'),
      );
    }
    parts.push(tr(this.lang, 'terms'));
    if (this.shop.tg.termsUrl) {
      parts.push(tr(this.lang, 'termsMore', { url: this.shop.tg.termsUrl }));
    }
    const keyboard: InlineKeyboard =
      order && price
        ? [
            [
              this.btn(trPlain(this.lang, 'buttonAccept', { amount: price }), {
                k: 'accept',
                ...order,
              }),
            ],
            [this.btn(trPlain(this.lang, 'buttonBack'), { k: 'dur', months: order.months })],
          ]
        : [[this.btn(trPlain(this.lang, 'buttonBack'), { k: 'menu' })]];
    return { text: parts.join('\n\n'), keyboard };
  }

  /** /paysupport: where payment problems go (Telegram's support can't help). */
  support(): Out {
    return {
      text: this.shop.supportEmail
        ? tr(this.lang, 'paySupport', { email: this.shop.supportEmail })
        : tr(this.lang, 'paySupportSite', { site: this.siteLine() }),
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

  /** The codes, with the delete button. A new message, so it can be deleted alone. */
  codes(ref: string, status: BotOrderStatus): Out {
    const codes = status.giftCodes.map((c) => `<code>${escapeHtml(c)}</code>`).join('\n');
    const keyboard: InlineKeyboard = [
      [this.btn(trPlain(this.lang, 'buttonSaved'), { k: 'ack', ref })],
    ];
    if (this.shop.site) {
      keyboard.push([
        { text: trPlain(this.lang, 'buttonRedeem'), url: `${this.shop.site}/account` },
      ]);
    }
    return {
      text: [
        tr(this.lang, 'codesTitle'),
        codes,
        tr(this.lang, 'codesHelp', { duration: durationLabel(this.lang, status.months) }),
        tr(this.lang, 'orderRef', { ref: refPrefix(ref) }),
      ].join('\n\n'),
      keyboard,
    };
  }

  /**
   * Send a paid order's codes (or say they were already shown). Throws if
   * Telegram refuses the message, so the payment is redelivered.
   */
  async deliver(ref: string): Promise<void> {
    const status = await this.ctx.runQuery(internal.billing.botOrderStatus, { orderRef: ref });
    if (!status) {
      await this.send({ text: tr(this.lang, 'orderNotFound') });
    } else if (status.status !== 'paid') {
      await this.send({ text: tr(this.lang, 'failed') });
    } else if (status.giftCodes.length > 0) {
      await this.send(this.codes(ref, status));
    } else {
      await this.send({ text: tr(this.lang, 'codesGone', { ref: refPrefix(ref) }) });
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

  /** The buyer accepted the terms: create the order and send its Stars invoice. */
  async buy(months: number, qty: number): Promise<void> {
    const perCode = starsOffer(this.shop.tg, this.shop.billing, months);
    if (perCode === null) {
      await this.show({ text: tr(this.lang, 'unavailable') });
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
    const { orderRef, totalStars } = await this.ctx.runMutation(internal.billing.createStarsOrder, {
      opaqueRef: randomHex(16),
      months,
      quantity: qty,
      starsPerCode: perCode,
    });
    const duration = durationLabel(this.lang, months);
    await tg.sendStarsInvoice(this.token, this.chatId, {
      title: trPlain(this.lang, 'starsTitle'),
      description: trPlain(this.lang, 'starsDescription', { quantity: qty, duration }),
      payload: orderRef,
      label: trPlain(this.lang, 'starsLabel'),
      stars: totalStars,
    });
  }
}

// --- the entry point ------------------------------------------------------------

/**
 * Refund a Stars payment the shop could not fulfil, and tell the buyer. The
 * payer's id comes from this update only; it is never stored.
 */
async function refundUnfulfilled(
  bot: Bot,
  token: string,
  payerId: number | undefined,
  p: TgPayment,
): Promise<void> {
  try {
    if (payerId === undefined) throw new Error('no payer');
    await tg.refundStarPayment(token, payerId, p.telegram_payment_charge_id);
    await bot.send({ text: bot.say('starsNotFulfilled') });
  } catch (err) {
    console.error(
      '[telegram] stars refund failed:',
      err instanceof tg.TelegramApiError ? err.message : 'error',
    );
    await bot
      .send({ text: bot.say('starsRefundFailed', { ref: refPrefix(p.invoice_payload) }) })
      .catch(() => undefined);
  }
}

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
    const { botToken: token } = await ctx.runQuery(internal.telegramAdmin.secrets, {});
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
        let res: { duplicate: boolean; granted: boolean };
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
        if (paid) {
          const payer = update.message?.from;
          const lang = pickLocale(payer?.language_code);
          const bot = new Bot(ctx, token, shop, chatId, lang);
          if (!res.duplicate && !res.granted) {
            // Paid but not fulfilled (the order was already paid, or refused):
            // Telegram's rule is a full refund.
            await refundUnfulfilled(bot, token, payer?.id, p);
            return { handled: true };
          }
          // The codes have exactly one way to the buyer: this message. Its
          // delivery is claimed once per payment (a resent payment does not
          // send them twice). If Telegram refuses it, the claim stays
          // retryable, the update is released and the route answers 500, so
          // the payment is redelivered and the codes are sent again.
          const deliveryId = `telegram_stars:${p.telegram_payment_charge_id}:delivery`;
          const delivery = await ctx.runMutation(internal.webhooks.claimEvent, {
            eventId: deliveryId,
            source: 'billing.telegram_stars.delivery',
            payload: JSON.stringify({ event: 'delivery' }),
          });
          if (delivery.proceed) {
            try {
              await bot.deliver(p.invoice_payload);
              await ctx.runMutation(internal.webhooks.markEventProcessed, {
                eventId: deliveryId,
              });
            } catch (err) {
              await ctx.runMutation(internal.webhooks.markEventFailed, { eventId: deliveryId });
              await ctx.runMutation(internal.telegramBot.releaseUpdate, {
                updateId: update.update_id,
              });
              throw new PaymentRetry(err);
            }
          }
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
        // Clearing codes, privacy, terms and language work even while the
        // shop is closed; everything that sells needs it open.
        const sells = !['ack', 'privacy', 'langs', 'terms'].includes(a.k);
        if (sells && !open) {
          await bot.show(bot.closed());
          return { handled: true };
        }
        switch (a.k) {
          case 'ack':
            await bot.ack(a.ref, cq.message?.message_id);
            break;
          case 'privacy':
            await bot.show(bot.privacy());
            break;
          case 'terms':
            await bot.show(bot.terms());
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
            await bot.show(bot.terms({ months: a.months, qty: a.qty }));
            break;
          case 'accept':
            await bot.buy(a.months, a.qty);
            break;
        }
        return { handled: true };
      }

      const cmd = parseCommand(update.message?.text);
      const bot = new Bot(ctx, token, shop, chatId, lang);
      if (cmd?.name === 'privacy') await bot.send(bot.privacy());
      else if (cmd?.name === 'terms') await bot.send(bot.terms());
      else if (cmd?.name === 'paysupport' || cmd?.name === 'support') {
        await bot.send(bot.support());
      } else if (cmd?.name === 'language') await bot.send(bot.languages());
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
