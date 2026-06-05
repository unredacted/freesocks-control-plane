import { createSqliteClient } from '../db/client';
import { SqliteKvStore } from '../kv/sqlite';
import { Logger } from '../lib/logger';
import { selectEmailProvider } from '../providers/email/factory';
import { S3StorageProvider } from '../providers/storage/s3';
import { parseS3Providers } from '../providers/storage/config';
import type { PlatformAdapter, PlatformConfig } from './interface';

interface NodeAdapterOptions {
  sqlitePath: string;
  env: NodeJS.ProcessEnv;
}

export function buildNodeConfig(env: NodeJS.ProcessEnv): PlatformConfig {
  const must = (k: string): string => {
    const v = env[k];
    if (!v) throw new Error(`Missing required env var: ${k}`);
    return v;
  };
  const environment = (env.ENVIRONMENT ?? 'development') as PlatformConfig['ENVIRONMENT'];
  return {
    REMNAWAVE_BASE_URL: must('REMNAWAVE_BASE_URL'),
    REMNAWAVE_API_TOKEN: must('REMNAWAVE_API_TOKEN'),
    AUTHENTIK_ISSUER: must('AUTHENTIK_ISSUER'),
    AUTHENTIK_CLIENT_ID: must('AUTHENTIK_CLIENT_ID'),
    AUTHENTIK_CLIENT_SECRET: must('AUTHENTIK_CLIENT_SECRET'),
    AUTHENTIK_REDIRECT_URI: must('AUTHENTIK_REDIRECT_URI'),
    AUTHENTIK_SCOPES: env.AUTHENTIK_SCOPES ?? 'openid email profile',
    EMAIL_PROVIDER: (env.EMAIL_PROVIDER ?? 'console') as PlatformConfig['EMAIL_PROVIDER'],
    EMAIL_FROM: env.EMAIL_FROM ?? 'noreply@localhost',
    EMAIL_REPLY_TO: env.EMAIL_REPLY_TO,
    RESEND_API_KEY: env.RESEND_API_KEY,
    AWS_ACCESS_KEY_ID: env.AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY: env.AWS_SECRET_ACCESS_KEY,
    AWS_SES_REGION: env.AWS_SES_REGION,
    SESSION_SIGNING_KEY: must('SESSION_SIGNING_KEY'),
    ADMIN_SESSION_SIGNING_KEY: must('ADMIN_SESSION_SIGNING_KEY'),
    ADMIN_BOOTSTRAP_SECRET: env.ADMIN_BOOTSTRAP_SECRET,
    IP_HASH_SALT: must('IP_HASH_SALT'),
    TURNSTILE_SECRET_KEY: must('TURNSTILE_SECRET_KEY'),
    FREE_TIER_TURNSTILE_SITE_KEY: must('FREE_TIER_TURNSTILE_SITE_KEY'),
    FREE_TIER_DAILY_CAP: parseInt(env.FREE_TIER_DAILY_CAP ?? '1', 10),
    FREE_TIER_EXPIRY_DAYS: parseInt(env.FREE_TIER_EXPIRY_DAYS ?? '90', 10),
    SUBSCRIPTION_DEFAULT_FORMAT: env.SUBSCRIPTION_DEFAULT_FORMAT ?? 'auto',
    S3_MIRRORS_ENABLED: String(env.S3_MIRRORS_ENABLED ?? '') === 'true',
    S3_PROVIDERS: parseS3Providers(env as unknown as Record<string, unknown>),
    WEBAUTHN_RP_ID: must('WEBAUTHN_RP_ID'),
    WEBAUTHN_RP_NAME: must('WEBAUTHN_RP_NAME'),
    WEBAUTHN_ORIGIN: must('WEBAUTHN_ORIGIN'),
    CRON_TRIGGER_SECRET: env.CRON_TRIGGER_SECRET,
    TRUSTED_PROXY: String(env.TRUSTED_PROXY ?? '') === 'true',
    MEMBERS_JOIN_URL: env.MEMBERS_JOIN_URL || 'https://members.unredacted.org/join',
    MEMBERS_ACCOUNT_URL: env.MEMBERS_ACCOUNT_URL || 'https://members.unredacted.org/account',
    ENVIRONMENT: environment,
  };
}

const pendingTasks: Promise<unknown>[] = [];

export function buildNodeAdapter(opts: NodeAdapterOptions): PlatformAdapter {
  const config = buildNodeConfig(opts.env);
  const logLevel = (opts.env.LOG_LEVEL ?? 'info') as 'debug' | 'info' | 'warn' | 'error';
  const logger = new Logger(logLevel, { runtime: 'node', env: config.ENVIRONMENT });
  const db = createSqliteClient(opts.sqlitePath);
  const email = selectEmailProvider(config, { logger });
  const storage = new S3StorageProvider(config.S3_PROVIDERS, logger);
  return {
    config,
    db,
    kv: {
      sessions: new SqliteKvStore(db, 'sessions'),
      cache: new SqliteKvStore(db, 'cache'),
      rateLimit: new SqliteKvStore(db, 'ratelimit'),
    },
    email,
    storage,
    logger,
    waitUntil: (p) => {
      pendingTasks.push(p);
      void p
        .catch((err) => logger.error('background_task_error', { error: String(err) }))
        .finally(() => {
          const idx = pendingTasks.indexOf(p);
          if (idx >= 0) pendingTasks.splice(idx, 1);
        });
    },
  };
}

export async function flushPendingTasks(): Promise<void> {
  await Promise.allSettled(pendingTasks.slice());
}
