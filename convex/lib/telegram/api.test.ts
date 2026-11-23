import { afterEach, describe, expect, test, vi } from 'vitest';
import { callTelegram, TelegramApiError } from './api';

const TOKEN = '123456:SECRET-bot-token';

afterEach(() => vi.unstubAllGlobals());

async function failure(impl: () => Promise<Response>): Promise<TelegramApiError> {
  vi.stubGlobal('fetch', vi.fn(impl));
  try {
    await callTelegram(TOKEN, 'sendMessage', { chat_id: 1, text: 'hi' });
  } catch (err) {
    return err as TelegramApiError;
  }
  throw new Error('expected a failure');
}

describe('callTelegram', () => {
  test('returns the result', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => Response.json({ ok: true, result: { message_id: 7 } })),
    );
    expect(await callTelegram(TOKEN, 'sendMessage')).toEqual({ message_id: 7 });
  });

  test('never puts the token in an error, whatever went wrong', async () => {
    const errs = [
      // A network error whose text quotes the URL (and so the token).
      await failure(async () => {
        throw new Error(`fetch failed for https://api.telegram.org/bot${TOKEN}/sendMessage`);
      }),
      await failure(async () => new Response(null, { status: 302, headers: { location: '/x' } })),
      await failure(async () => new Response('not json', { status: 502 })),
      await failure(async () =>
        Response.json({ ok: false, description: 'Bad Request: chat not found' }, { status: 400 }),
      ),
      await failure(async () => new Response('x'.repeat(300_000))),
    ];
    expect(errs.map((e) => e.kind)).toEqual(['network', 'redirect', 'http', 'api', 'too_large']);
    for (const e of errs) {
      expect(e).toBeInstanceOf(TelegramApiError);
      expect(e.message).not.toContain(TOKEN);
      expect(e.message).not.toContain('api.telegram.org');
    }
    expect(errs[3]!.description).toBe('Bad Request: chat not found');
  });
});
