import type { Logger } from '../../lib/logger';
import { UpstreamError } from '../../lib/errors';
import type { EmailMessage, EmailProvider, EmailSendResult } from './interface';

export class ResendEmailProvider implements EmailProvider {
  readonly name = 'resend';

  constructor(
    private readonly apiKey: string,
    private readonly fromAddress: string,
    private readonly logger: Logger,
    private readonly fetcher: typeof fetch = fetch,
  ) {}

  async send(message: EmailMessage): Promise<EmailSendResult> {
    const res = await this.fetcher('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        authorization: `Bearer ${this.apiKey}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        from: this.fromAddress,
        to: [message.to],
        subject: message.subject,
        text: message.text,
        html: message.html,
        reply_to: message.replyTo,
      }),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      this.logger.warn('resend_send_failed', { status: res.status, body: body.slice(0, 500) });
      throw new UpstreamError('email', `Resend send failed: ${res.status}`);
    }
    const json = (await res.json()) as { id?: string };
    return { providerName: this.name, providerMessageId: json.id };
  }
}
