/**
 * A small hand-written Telegram Bot API client (no SDK: plain fetch, so the
 * backend bundle gains no runtime package). Pure: the token is passed in.
 *
 * The token is PART OF EVERY URL (`/bot<token>/<method>`), so nothing here
 * ever puts a URL in an error, a log line or a return value: errors carry the
 * method name, a kind, the HTTP status and Telegram's own description only.
 */
import { readBoundedBody } from '../readBoundedBody';

const API_ORIGIN = 'https://api.telegram.org';
const TIMEOUT_MS = 8_000;
const MAX_RESPONSE_BYTES = 256 * 1024;

export type TelegramErrorKind = 'timeout' | 'network' | 'redirect' | 'too_large' | 'http' | 'api';

export class TelegramApiError extends Error {
  constructor(
    readonly method: string,
    readonly kind: TelegramErrorKind,
    readonly status?: number,
    /** Telegram's own description (e.g. "Bad Request: message to delete not found"). */
    readonly description?: string,
  ) {
    super(
      `telegram ${method}: ${kind}${status ? ` ${status}` : ''}${description ? `: ${description}` : ''}`,
    );
    this.name = 'TelegramApiError';
  }
}

/** Call one Bot API method with a JSON body; resolves to its `result`. */
export async function callTelegram<T = unknown>(
  token: string,
  method: string,
  params: Record<string, unknown> = {},
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let res: Response;
  try {
    res = await fetch(`${API_ORIGIN}/bot${token}/${method}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(params),
      redirect: 'manual',
      signal: controller.signal,
    });
  } catch (err) {
    // The thrown error may quote the URL: never pass it on.
    throw new TelegramApiError(
      method,
      err instanceof Error && err.name === 'AbortError' ? 'timeout' : 'network',
    );
  } finally {
    clearTimeout(timer);
  }
  if (res.type === 'opaqueredirect' || (res.status >= 300 && res.status < 400)) {
    throw new TelegramApiError(method, 'redirect', res.status || undefined);
  }
  const text = await readBoundedBody(res, MAX_RESPONSE_BYTES);
  if (text === null) throw new TelegramApiError(method, 'too_large', res.status);
  let parsed: unknown = null;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = null;
  }
  if (!parsed || typeof parsed !== 'object') {
    throw new TelegramApiError(method, 'http', res.status);
  }
  const body = parsed as { ok?: unknown; result?: unknown; description?: unknown };
  if (body.ok !== true) {
    const description =
      typeof body.description === 'string' ? body.description.slice(0, 200) : undefined;
    throw new TelegramApiError(method, 'api', res.status, description);
  }
  return body.result as T;
}

// --- the subset of the Bot API the shop uses --------------------------------

export interface InlineButton {
  text: string;
  callback_data?: string;
  url?: string;
}
export type InlineKeyboard = InlineButton[][];

export interface SendOptions {
  keyboard?: InlineKeyboard;
  /** Render with HTML parse mode (the text must already be escaped). */
  html?: boolean;
}

function messageParams(text: string, o: SendOptions): Record<string, unknown> {
  return {
    text,
    ...(o.html ? { parse_mode: 'HTML' } : {}),
    // Never unfurl link previews: they would fetch our pages from Telegram's side.
    link_preview_options: { is_disabled: true },
    ...(o.keyboard ? { reply_markup: { inline_keyboard: o.keyboard } } : {}),
  };
}

export function sendMessage(
  token: string,
  chatId: number,
  text: string,
  o: SendOptions = {},
): Promise<{ message_id: number }> {
  return callTelegram(token, 'sendMessage', { chat_id: chatId, ...messageParams(text, o) });
}

export function editMessageText(
  token: string,
  chatId: number,
  messageId: number,
  text: string,
  o: SendOptions = {},
): Promise<unknown> {
  return callTelegram(token, 'editMessageText', {
    chat_id: chatId,
    message_id: messageId,
    ...messageParams(text, o),
  });
}

export function deleteMessage(token: string, chatId: number, messageId: number): Promise<unknown> {
  return callTelegram(token, 'deleteMessage', { chat_id: chatId, message_id: messageId });
}

export function answerCallbackQuery(
  token: string,
  callbackQueryId: string,
  text?: string,
): Promise<unknown> {
  return callTelegram(token, 'answerCallbackQuery', {
    callback_query_id: callbackQueryId,
    ...(text ? { text } : {}),
  });
}

/** A Telegram Stars invoice: currency XTR, no provider token, one price line. */
export function sendStarsInvoice(
  token: string,
  chatId: number,
  inv: { title: string; description: string; payload: string; label: string; stars: number },
): Promise<unknown> {
  return callTelegram(token, 'sendInvoice', {
    chat_id: chatId,
    title: inv.title,
    description: inv.description,
    payload: inv.payload,
    provider_token: '',
    currency: 'XTR',
    prices: [{ label: inv.label, amount: inv.stars }],
  });
}

export function answerPreCheckoutQuery(
  token: string,
  queryId: string,
  ok: boolean,
  errorMessage?: string,
): Promise<unknown> {
  return callTelegram(token, 'answerPreCheckoutQuery', {
    pre_checkout_query_id: queryId,
    ok,
    ...(ok ? {} : { error_message: errorMessage ?? 'This order can no longer be paid.' }),
  });
}

export interface WebhookInfo {
  url: string;
  pending_update_count: number;
  last_error_date?: number;
  last_error_message?: string;
}

export function getWebhookInfo(token: string): Promise<WebhookInfo> {
  return callTelegram(token, 'getWebhookInfo');
}

export function setWebhook(
  token: string,
  url: string,
  secretToken: string,
  allowedUpdates: string[],
): Promise<unknown> {
  return callTelegram(token, 'setWebhook', {
    url,
    secret_token: secretToken,
    allowed_updates: allowedUpdates,
    drop_pending_updates: true,
    max_connections: 10,
  });
}

export function deleteWebhook(token: string): Promise<unknown> {
  return callTelegram(token, 'deleteWebhook', { drop_pending_updates: true });
}

export function getMe(token: string): Promise<{ id: number; username?: string }> {
  return callTelegram(token, 'getMe');
}

export function setMyCommands(
  token: string,
  commands: { command: string; description: string }[],
  languageCode?: string,
): Promise<unknown> {
  return callTelegram(token, 'setMyCommands', {
    commands,
    ...(languageCode ? { language_code: languageCode } : {}),
  });
}
