import { eq } from 'drizzle-orm';
import type { Db } from '../db/client';
import { emailLog } from '../db/schema';
import type { Logger } from '../lib/logger';
import type { PlatformConfig } from '../platform/interface';
import type { EmailMessage, EmailProvider } from '../providers/email/interface';

export class EmailDeliveryService {
  constructor(
    private readonly provider: EmailProvider,
    private readonly db: Db,
    private readonly config: PlatformConfig,
    private readonly logger: Logger,
  ) {}

  async send(
    message: EmailMessage & { templateKey: string; params: Record<string, unknown> },
  ): Promise<void> {
    if (message.dedupeKey) {
      const existing = await this.db
        .select()
        .from(emailLog)
        .where(eq(emailLog.dedupeKey, message.dedupeKey))
        .limit(1)
        .all();
      if (existing.length > 0) {
        this.logger.debug('email_dedupe_skip', { dedupeKey: message.dedupeKey });
        return;
      }
    }
    const messageWithReplyTo: EmailMessage = {
      ...message,
      replyTo: message.replyTo ?? this.config.EMAIL_REPLY_TO,
    };
    try {
      const result = await this.provider.send(messageWithReplyTo);
      await this.db.insert(emailLog).values({
        toEmail: message.to,
        subject: message.subject,
        templateKey: message.templateKey,
        params: JSON.stringify(message.params),
        status: 'sent',
        providerMessageId: result.providerMessageId ?? null,
        dedupeKey: message.dedupeKey ?? null,
        sentAt: Date.now(),
      });
    } catch (err) {
      this.logger.warn('email_send_failed', { error: String(err), to: message.to });
      await this.db.insert(emailLog).values({
        toEmail: message.to,
        subject: message.subject,
        templateKey: message.templateKey,
        params: JSON.stringify(message.params),
        status: 'failed',
        error: String(err).slice(0, 1000),
        dedupeKey: message.dedupeKey ?? null,
      });
    }
  }
}
