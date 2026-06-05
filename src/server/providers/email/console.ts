import type { Logger } from '../../lib/logger';
import type { EmailMessage, EmailProvider, EmailSendResult } from './interface';

export class ConsoleEmailProvider implements EmailProvider {
  readonly name = 'console';

  constructor(private readonly logger: Logger) {}

  async send(message: EmailMessage): Promise<EmailSendResult> {
    this.logger.info('email_send_console', {
      to: message.to,
      subject: message.subject,
      text: message.text.slice(0, 500),
      dedupeKey: message.dedupeKey,
    });
    return { providerName: this.name };
  }
}
