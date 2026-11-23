/**
 * Admin -> Billing -> Telegram bot: the gift shop's settings, its webhook,
 * and the bot's command menu. Secrets stay in env (TELEGRAM_BOT_TOKEN,
 * TELEGRAM_WEBHOOK_SECRET); the view says only whether each is set.
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import { upsertSettingRow } from './appSettings';
import { writeAuditLog } from './lib/audit';
import { resolveProcessorSecrets } from './lib/billingConfig';
import { resolveTelegramConfig, telegramConfigWrites, type StarsPrice } from './lib/telegramConfig';
import * as tg from './lib/telegram/api';
import { BOT_LOCALES, trPlain, type BotLocale } from './lib/telegram/flow';

const WEBHOOK_PATH = '/api/webhooks/telegram';
const ALLOWED_UPDATES = ['message', 'callback_query', 'pre_checkout_query'];

export interface TelegramAdminView {
  enabled: boolean;
  botUsername: string;
  starsEnabled: boolean;
  starsPrices: StarsPrice[];
  cryptoEnabled: boolean;
  tokenSet: boolean;
  secretSet: boolean;
  /** Where the webhook must point (null while PUBLIC_BASE_URL is unset). */
  webhookUrl: string | null;
}

export const view = internalQuery({
  args: {},
  handler: async (ctx): Promise<TelegramAdminView> => {
    const [cfg, secrets] = await Promise.all([
      resolveTelegramConfig(ctx.db),
      resolveProcessorSecrets(ctx.db),
    ]);
    const base = (secrets.publicBaseUrl ?? '').replace(/\/$/, '');
    return {
      ...cfg,
      tokenSet: !!process.env.TELEGRAM_BOT_TOKEN,
      secretSet: !!process.env.TELEGRAM_WEBHOOK_SECRET,
      webhookUrl: base ? `${base}${WEBHOOK_PATH}` : null,
    };
  },
});

export const setConfig = internalMutation({
  args: {
    enabled: v.optional(v.boolean()),
    botUsername: v.optional(v.string()),
    starsEnabled: v.optional(v.boolean()),
    starsPrices: v.optional(v.array(v.object({ months: v.number(), stars: v.number() }))),
    cryptoEnabled: v.optional(v.boolean()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { actorAdminId, ...patch }): Promise<null> => {
    let writes: { key: string; value: unknown }[];
    try {
      writes = telegramConfigWrites(patch);
    } catch (err) {
      throw new ConvexError({
        code: 'validation',
        message: err instanceof Error ? err.message : 'Invalid Telegram settings',
      });
    }
    const cur = await resolveTelegramConfig(ctx.db);
    const nextUsername =
      patch.botUsername !== undefined
        ? ((writes.find((w) => w.key === 'telegram.botUsername')?.value as string) ?? '')
        : cur.botUsername;
    if ((patch.enabled ?? cur.enabled) && !nextUsername) {
      throw new ConvexError({
        code: 'validation',
        message: 'Set the bot username before opening the shop',
      });
    }
    for (const w of writes) {
      await upsertSettingRow(ctx, w.key, JSON.stringify(w.value), actorAdminId);
    }
    const next = await resolveTelegramConfig(ctx.db);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'admin.telegram.change',
      targetType: 'telegram',
      payload: {
        enabled: next.enabled,
        starsEnabled: next.starsEnabled,
        cryptoEnabled: next.cryptoEnabled,
        starsPriceCount: next.starsPrices.length,
        usernameChanged: next.botUsername !== cur.botUsername,
      },
    });
    return null;
  },
});

export interface TelegramWebhookStatus {
  /** getWebhookInfo answered. */
  reachable: boolean;
  /** The webhook points at this deployment's route. */
  pointsHere: boolean;
  /** Any webhook at all is set. */
  set: boolean;
  pendingUpdates: number;
  lastErrorAt: string | null;
  lastErrorMessage: string | null;
  /** The token's bot username, to compare with the configured one. */
  tokenUsername: string | null;
}

/** Ask Telegram how the webhook stands (read-only). */
export const webhookStatus = internalAction({
  args: {},
  handler: async (ctx): Promise<TelegramWebhookStatus | null> => {
    const token = process.env.TELEGRAM_BOT_TOKEN;
    if (!token) return null;
    const view = await ctx.runQuery(internal.telegramAdmin.view, {});
    try {
      const [info, me] = await Promise.all([tg.getWebhookInfo(token), tg.getMe(token)]);
      return {
        reachable: true,
        pointsHere: !!view.webhookUrl && info.url === view.webhookUrl,
        set: info.url !== '',
        pendingUpdates: info.pending_update_count,
        lastErrorAt: info.last_error_date
          ? new Date(info.last_error_date * 1000).toISOString()
          : null,
        lastErrorMessage: info.last_error_message?.slice(0, 200) ?? null,
        tokenUsername: me.username ?? null,
      };
    } catch {
      return {
        reachable: false,
        pointsHere: false,
        set: false,
        pendingUpdates: 0,
        lastErrorAt: null,
        lastErrorMessage: null,
        tokenUsername: null,
      };
    }
  },
});

function commandsFor(locale: BotLocale) {
  return [
    { command: 'buy', description: trPlain(locale, 'commandBuy') },
    { command: 'language', description: trPlain(locale, 'commandLanguage') },
    { command: 'privacy', description: trPlain(locale, 'commandPrivacy') },
    { command: 'help', description: trPlain(locale, 'commandHelp') },
  ];
}

/**
 * Point Telegram's webhook at this deployment (with the secret header) and
 * set the command menu in every language, or remove the webhook. Pending
 * updates are dropped either way: they may predate the current settings.
 */
export const setWebhook = internalAction({
  args: {
    action: v.union(v.literal('register'), v.literal('remove')),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a): Promise<{ ok: true }> => {
    const token = process.env.TELEGRAM_BOT_TOKEN;
    const secret = process.env.TELEGRAM_WEBHOOK_SECRET;
    if (!token) {
      throw new ConvexError({ code: 'validation', message: 'TELEGRAM_BOT_TOKEN is not set' });
    }
    try {
      if (a.action === 'remove') {
        await tg.deleteWebhook(token);
      } else {
        const view = await ctx.runQuery(internal.telegramAdmin.view, {});
        if (!secret || !/^[A-Za-z0-9_-]{1,256}$/.test(secret)) {
          throw new ConvexError({
            code: 'validation',
            message: 'TELEGRAM_WEBHOOK_SECRET must be set (1-256 of A-Z, a-z, 0-9, _ and -)',
          });
        }
        if (!view.webhookUrl) {
          throw new ConvexError({ code: 'validation', message: 'PUBLIC_BASE_URL is not set' });
        }
        await tg.setWebhook(token, view.webhookUrl, secret, ALLOWED_UPDATES);
        await tg.setMyCommands(token, commandsFor('en'));
        for (const l of BOT_LOCALES) {
          if (l !== 'en') await tg.setMyCommands(token, commandsFor(l), l);
        }
      }
    } catch (err) {
      if (err instanceof ConvexError) throw err;
      throw new ConvexError({
        code: 'upstream',
        message: err instanceof tg.TelegramApiError ? err.message : 'Telegram did not answer',
      });
    }
    await ctx.runMutation(internal.telegramAdmin.auditWebhook, {
      action: a.action,
      actorAdminId: a.actorAdminId,
    });
    return { ok: true };
  },
});

export const auditWebhook = internalMutation({
  args: {
    action: v.union(v.literal('register'), v.literal('remove')),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a): Promise<null> => {
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'admin.telegram.webhook',
      targetType: 'telegram',
      payload: { action: a.action },
    });
    return null;
  },
});
