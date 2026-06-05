import type { Logger } from '../../lib/logger';
import { UpstreamError } from '../../lib/errors';
import type { EmailMessage, EmailProvider, EmailSendResult } from './interface';

interface SendEmailBinding {
  send(message: { from: string; to: string; raw: string }): Promise<void>;
}

export class CloudflareEmailProvider implements EmailProvider {
  readonly name = 'cloudflare';

  constructor(
    private readonly binding: SendEmailBinding,
    private readonly fromAddress: string,
    private readonly logger: Logger,
  ) {}

  async send(message: EmailMessage): Promise<EmailSendResult> {
    const raw = buildRawMime({
      from: this.fromAddress,
      to: message.to,
      subject: message.subject,
      text: message.text,
      html: message.html,
      replyTo: message.replyTo,
    });
    try {
      await this.binding.send({ from: this.fromAddress, to: message.to, raw });
      return { providerName: this.name };
    } catch (err) {
      this.logger.warn('cloudflare_email_send_failed', { error: String(err) });
      throw new UpstreamError('email', `Cloudflare email send failed: ${String(err)}`);
    }
  }
}

function buildRawMime(opts: {
  from: string;
  to: string;
  subject: string;
  text: string;
  html?: string;
  replyTo?: string;
}): string {
  const boundary = `=_FreeSocks_${crypto.randomUUID()}`;
  const headers = [
    `From: ${opts.from}`,
    `To: ${opts.to}`,
    `Subject: ${encodeMimeHeader(opts.subject)}`,
    'MIME-Version: 1.0',
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${crypto.randomUUID()}@freesocks.org>`,
  ];
  if (opts.replyTo) headers.push(`Reply-To: ${opts.replyTo}`);
  if (opts.html) {
    headers.push(`Content-Type: multipart/alternative; boundary="${boundary}"`);
    return [
      headers.join('\r\n'),
      '',
      `--${boundary}`,
      'Content-Type: text/plain; charset=utf-8',
      'Content-Transfer-Encoding: 7bit',
      '',
      opts.text,
      '',
      `--${boundary}`,
      'Content-Type: text/html; charset=utf-8',
      'Content-Transfer-Encoding: 7bit',
      '',
      opts.html,
      '',
      `--${boundary}--`,
      '',
    ].join('\r\n');
  }
  headers.push('Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: 7bit');
  return [headers.join('\r\n'), '', opts.text].join('\r\n');
}

function encodeMimeHeader(value: string): string {
  if (/^[\x20-\x7E]*$/.test(value)) return value;
  return `=?UTF-8?B?${btoa(unescape(encodeURIComponent(value)))}?=`;
}
