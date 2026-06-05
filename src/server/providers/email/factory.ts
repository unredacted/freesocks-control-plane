import type { PlatformConfig } from '../../platform/interface';
import type { Logger } from '../../lib/logger';
import { CloudflareEmailProvider } from './cloudflare';
import { ConsoleEmailProvider } from './console';
import { ResendEmailProvider } from './resend';
import { SesEmailProvider } from './ses';
import type { EmailProvider } from './interface';

interface SendEmailBinding {
  send(message: { from: string; to: string; raw: string }): Promise<void>;
}

export interface EmailFactoryOptions {
  sendEmailBinding?: SendEmailBinding;
  logger: Logger;
}

export function selectEmailProvider(
  config: PlatformConfig,
  opts: EmailFactoryOptions,
): EmailProvider {
  switch (config.EMAIL_PROVIDER) {
    case 'cloudflare': {
      if (!opts.sendEmailBinding) {
        opts.logger.warn('email_provider_fallback', {
          reason: 'cloudflare provider requested but no SEND_EMAIL binding present, using console',
        });
        return new ConsoleEmailProvider(opts.logger);
      }
      return new CloudflareEmailProvider(opts.sendEmailBinding, config.EMAIL_FROM, opts.logger);
    }
    case 'resend': {
      if (!config.RESEND_API_KEY)
        throw new Error('RESEND_API_KEY required when EMAIL_PROVIDER=resend');
      return new ResendEmailProvider(config.RESEND_API_KEY, config.EMAIL_FROM, opts.logger);
    }
    case 'ses': {
      if (!config.AWS_ACCESS_KEY_ID || !config.AWS_SECRET_ACCESS_KEY || !config.AWS_SES_REGION) {
        throw new Error('AWS credentials and AWS_SES_REGION required when EMAIL_PROVIDER=ses');
      }
      return new SesEmailProvider({
        region: config.AWS_SES_REGION,
        accessKeyId: config.AWS_ACCESS_KEY_ID,
        secretAccessKey: config.AWS_SECRET_ACCESS_KEY,
        fromAddress: config.EMAIL_FROM,
        logger: opts.logger,
      });
    }
    case 'console':
      return new ConsoleEmailProvider(opts.logger);
  }
}
