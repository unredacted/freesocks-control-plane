import type { Logger } from '../../lib/logger';
import { UpstreamError } from '../../lib/errors';
import type { EmailMessage, EmailProvider, EmailSendResult } from './interface';

export interface SesProviderOptions {
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  fromAddress: string;
  logger: Logger;
}

export class SesEmailProvider implements EmailProvider {
  readonly name = 'ses';

  constructor(private readonly opts: SesProviderOptions) {}

  async send(message: EmailMessage): Promise<EmailSendResult> {
    // Lazy-load the AWS SDK so it's only pulled when actually used.
    const { SESv2Client, SendEmailCommand } = await import('@aws-sdk/client-sesv2');
    const client = new SESv2Client({
      region: this.opts.region,
      credentials: {
        accessKeyId: this.opts.accessKeyId,
        secretAccessKey: this.opts.secretAccessKey,
      },
    });
    try {
      const result = await client.send(
        new SendEmailCommand({
          FromEmailAddress: this.opts.fromAddress,
          Destination: { ToAddresses: [message.to] },
          ReplyToAddresses: message.replyTo ? [message.replyTo] : undefined,
          Content: {
            Simple: {
              Subject: { Data: message.subject, Charset: 'UTF-8' },
              Body: {
                Text: { Data: message.text, Charset: 'UTF-8' },
                ...(message.html ? { Html: { Data: message.html, Charset: 'UTF-8' } } : {}),
              },
            },
          },
        }),
      );
      return { providerName: this.name, providerMessageId: result.MessageId };
    } catch (err) {
      this.opts.logger.warn('ses_send_failed', { error: String(err) });
      throw new UpstreamError('email', `SES send failed: ${String(err)}`);
    }
  }
}
