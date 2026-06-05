import type { Db } from '../db/client';
import type { KvStore } from '../kv/interface';
import type { EmailProvider } from '../providers/email/interface';
import type { StorageProvider } from '../providers/storage/interface';
import type { Logger } from '../lib/logger';

export interface PlatformConfig {
  // Remnawave
  REMNAWAVE_BASE_URL: string;
  REMNAWAVE_API_TOKEN: string;

  // Authentik
  AUTHENTIK_ISSUER: string;
  AUTHENTIK_CLIENT_ID: string;
  AUTHENTIK_CLIENT_SECRET: string;
  AUTHENTIK_REDIRECT_URI: string;
  AUTHENTIK_SCOPES: string;

  // Email
  EMAIL_PROVIDER: 'cloudflare' | 'resend' | 'ses' | 'console';
  EMAIL_FROM: string;
  EMAIL_REPLY_TO?: string;
  RESEND_API_KEY?: string;
  AWS_ACCESS_KEY_ID?: string;
  AWS_SECRET_ACCESS_KEY?: string;
  AWS_SES_REGION?: string;

  // Sessions / signing
  SESSION_SIGNING_KEY: string;
  ADMIN_SESSION_SIGNING_KEY: string;
  ADMIN_BOOTSTRAP_SECRET?: string;
  IP_HASH_SALT: string;

  // Turnstile
  TURNSTILE_SECRET_KEY: string;
  FREE_TIER_TURNSTILE_SITE_KEY: string;

  // Free tier
  FREE_TIER_DAILY_CAP: number;
  FREE_TIER_EXPIRY_DAYS: number;

  // Subscription
  SUBSCRIPTION_DEFAULT_FORMAT: string;

  // S3
  S3_MIRRORS_ENABLED: boolean;
  S3_PROVIDERS: S3ProviderConfig[];

  // WebAuthn
  WEBAUTHN_RP_ID: string;
  WEBAUTHN_RP_NAME: string;
  WEBAUTHN_ORIGIN: string;

  /**
   * Bearer secret that authenticates the external cron-trigger endpoint
   * `POST /api/internal/cron/run-task`. Required on platforms without native
   * scheduling (Fastly Compute, generic VPS without crond); optional on
   * Workers (which has cron triggers) and self-host (which uses
   * `node-cron`/Bun's scheduler) — leave unset and the endpoint refuses every
   * request.
   */
  CRON_TRIGGER_SECRET?: string;

  /**
   * Whether to trust the `X-Forwarded-For` header for client-IP resolution.
   * Off-Workers deployments (Bun self-host, Fastly Compute) MUST set this to
   * `true` ONLY when the app sits behind a reverse proxy that overwrites
   * (not appends to) `X-Forwarded-For` — otherwise an attacker can spoof
   * the header to bypass free-tier rate limits.
   *
   * On Cloudflare Workers this flag is ignored: `cf-connecting-ip` is always
   * trusted and `X-Forwarded-For` is always ignored, because Cloudflare sets
   * its own header directly from the TLS-terminated socket.
   */
  TRUSTED_PROXY: boolean;

  // Member portal — surfaced to the SPA via /api/v1/config so CTAs can link to
  // the right place without a redeploy.
  MEMBERS_JOIN_URL: string;
  MEMBERS_ACCOUNT_URL: string;

  ENVIRONMENT: 'production' | 'development' | 'test';
}

export interface S3ProviderConfig {
  name: string;
  endpoint: string;
  bucket: string;
  publicUrl: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
}

export interface PlatformAdapter {
  config: PlatformConfig;
  db: Db;
  kv: {
    sessions: KvStore;
    cache: KvStore;
    rateLimit: KvStore;
  };
  email: EmailProvider;
  storage: StorageProvider;
  logger: Logger;
  /**
   * Schedule a follow-up task to run after the response. On Workers this maps to
   * `executionCtx.waitUntil`; on Node/Bun it just registers the promise.
   */
  waitUntil(promise: Promise<unknown>): void;
}
