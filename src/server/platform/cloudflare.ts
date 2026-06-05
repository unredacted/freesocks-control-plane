import { createD1Client } from '../db/client';
import { CloudflareKvStore } from '../kv/cloudflare';
import { Logger } from '../lib/logger';
import { selectEmailProvider } from '../providers/email/factory';
import { S3StorageProvider } from '../providers/storage/s3';
import { parseS3Providers } from '../providers/storage/config';
import type { PlatformAdapter, PlatformConfig } from './interface';

export interface WorkersEnv {
  DB: D1Database;
  FS_SESSIONS_KV: KVNamespace;
  FS_CACHE_KV: KVNamespace;
  FS_RATELIMIT_KV: KVNamespace;
  ASSETS?: Fetcher;
  SEND_EMAIL?: SendEmail;

  ENVIRONMENT?: string;
  LOG_LEVEL?: string;

  REMNAWAVE_BASE_URL: string;
  REMNAWAVE_API_TOKEN: string;

  AUTHENTIK_ISSUER: string;
  AUTHENTIK_CLIENT_ID: string;
  AUTHENTIK_CLIENT_SECRET: string;
  AUTHENTIK_REDIRECT_URI: string;
  AUTHENTIK_SCOPES?: string;

  EMAIL_PROVIDER?: string;
  EMAIL_FROM: string;
  EMAIL_REPLY_TO?: string;
  RESEND_API_KEY?: string;
  AWS_ACCESS_KEY_ID?: string;
  AWS_SECRET_ACCESS_KEY?: string;
  AWS_SES_REGION?: string;

  SESSION_SIGNING_KEY: string;
  ADMIN_SESSION_SIGNING_KEY: string;
  ADMIN_BOOTSTRAP_SECRET?: string;
  IP_HASH_SALT: string;

  TURNSTILE_SECRET_KEY: string;
  FREE_TIER_TURNSTILE_SITE_KEY: string;
  FREE_TIER_DAILY_CAP?: string;
  FREE_TIER_EXPIRY_DAYS?: string;

  SUBSCRIPTION_DEFAULT_FORMAT?: string;

  S3_MIRRORS_ENABLED?: string;
  S3_PROVIDER_COUNT?: string;
  [key: string]: unknown;

  WEBAUTHN_RP_ID: string;
  WEBAUTHN_RP_NAME: string;
  WEBAUTHN_ORIGIN: string;

  MEMBERS_JOIN_URL?: string;
  MEMBERS_ACCOUNT_URL?: string;
}

interface SendEmail {
  send(message: { from: string; to: string; raw: ReadableStream | string }): Promise<void>;
}

export function buildCloudflareConfig(env: WorkersEnv): PlatformConfig {
  const environment = (env.ENVIRONMENT ?? 'production') as PlatformConfig['ENVIRONMENT'];
  return {
    REMNAWAVE_BASE_URL: env.REMNAWAVE_BASE_URL,
    REMNAWAVE_API_TOKEN: env.REMNAWAVE_API_TOKEN,
    AUTHENTIK_ISSUER: env.AUTHENTIK_ISSUER,
    AUTHENTIK_CLIENT_ID: env.AUTHENTIK_CLIENT_ID,
    AUTHENTIK_CLIENT_SECRET: env.AUTHENTIK_CLIENT_SECRET,
    AUTHENTIK_REDIRECT_URI: env.AUTHENTIK_REDIRECT_URI,
    AUTHENTIK_SCOPES: env.AUTHENTIK_SCOPES ?? 'openid email profile',
    EMAIL_PROVIDER: (env.EMAIL_PROVIDER ?? 'cloudflare') as PlatformConfig['EMAIL_PROVIDER'],
    EMAIL_FROM: env.EMAIL_FROM,
    EMAIL_REPLY_TO: env.EMAIL_REPLY_TO,
    RESEND_API_KEY: env.RESEND_API_KEY,
    AWS_ACCESS_KEY_ID: env.AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY: env.AWS_SECRET_ACCESS_KEY,
    AWS_SES_REGION: env.AWS_SES_REGION,
    SESSION_SIGNING_KEY: env.SESSION_SIGNING_KEY,
    ADMIN_SESSION_SIGNING_KEY: env.ADMIN_SESSION_SIGNING_KEY,
    ADMIN_BOOTSTRAP_SECRET: env.ADMIN_BOOTSTRAP_SECRET,
    IP_HASH_SALT: env.IP_HASH_SALT,
    TURNSTILE_SECRET_KEY: env.TURNSTILE_SECRET_KEY,
    FREE_TIER_TURNSTILE_SITE_KEY: env.FREE_TIER_TURNSTILE_SITE_KEY,
    FREE_TIER_DAILY_CAP: parseInt(env.FREE_TIER_DAILY_CAP ?? '1', 10),
    FREE_TIER_EXPIRY_DAYS: parseInt(env.FREE_TIER_EXPIRY_DAYS ?? '90', 10),
    SUBSCRIPTION_DEFAULT_FORMAT: env.SUBSCRIPTION_DEFAULT_FORMAT ?? 'auto',
    S3_MIRRORS_ENABLED: env.S3_MIRRORS_ENABLED === 'true',
    S3_PROVIDERS: parseS3Providers(env as Record<string, unknown>),
    WEBAUTHN_RP_ID: env.WEBAUTHN_RP_ID,
    WEBAUTHN_RP_NAME: env.WEBAUTHN_RP_NAME,
    WEBAUTHN_ORIGIN: env.WEBAUTHN_ORIGIN,
    CRON_TRIGGER_SECRET: env.CRON_TRIGGER_SECRET as string | undefined,
    // On Workers this value is ignored — `cf-connecting-ip` is always
    // trusted and `x-forwarded-for` always ignored. Setting to `false` here
    // makes that explicit so a future env-injected `TRUSTED_PROXY=true`
    // can't accidentally weaken Workers' IP resolution.
    TRUSTED_PROXY: false,
    MEMBERS_JOIN_URL: env.MEMBERS_JOIN_URL || 'https://members.unredacted.org/join',
    MEMBERS_ACCOUNT_URL: env.MEMBERS_ACCOUNT_URL || 'https://members.unredacted.org/account',
    ENVIRONMENT: environment,
  };
}

export function buildCloudflareAdapter(env: WorkersEnv, ctx: ExecutionContext): PlatformAdapter {
  const config = buildCloudflareConfig(env);
  const logLevel = (env.LOG_LEVEL ?? 'info') as 'debug' | 'info' | 'warn' | 'error';
  const logger = new Logger(logLevel, { runtime: 'cloudflare', env: config.ENVIRONMENT });
  const db = createD1Client(env.DB);
  const email = selectEmailProvider(config, { sendEmailBinding: env.SEND_EMAIL, logger });
  const storage = new S3StorageProvider(config.S3_PROVIDERS, logger);
  return {
    config,
    db,
    kv: {
      sessions: new CloudflareKvStore(env.FS_SESSIONS_KV),
      cache: new CloudflareKvStore(env.FS_CACHE_KV),
      rateLimit: new CloudflareKvStore(env.FS_RATELIMIT_KV),
    },
    email,
    storage,
    logger,
    waitUntil: (p) => ctx.waitUntil(p),
  };
}
