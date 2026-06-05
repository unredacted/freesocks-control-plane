import { createLibsqlClient } from '../db/client';
import { FastlyKvStore, type FastlyKVNamespace } from '../kv/fastly';
import { Logger } from '../lib/logger';
import { selectEmailProvider } from '../providers/email/factory';
import { S3StorageProvider } from '../providers/storage/s3';
import { parseS3Providers } from '../providers/storage/config';
import type { PlatformAdapter, PlatformConfig } from './interface';

/**
 * Fastly Compute platform adapter. Built once per request (Fastly Compute
 * does not maintain warm in-memory state across requests in the same way
 * Workers does, so any caching has to live in KV / D1-equivalent stores
 * rather than module-scope variables).
 *
 * Mapping to Fastly primitives:
 *   - **Database** → Turso (libSQL HTTP). Drizzle's `libsql/web` driver
 *     issues HTTP requests via `fetch`, which Fastly natively supports as
 *     long as the Turso hostname is declared as a backend in `fastly.toml`.
 *   - **KV** → three Fastly KV Stores (`FS_SESSIONS_KV`, `FS_CACHE_KV`,
 *     `FS_RATELIMIT_KV` — same binding names as Workers for parity). Fastly
 *     KV has no native TTL; `FastlyKvStore` simulates it via a JSON envelope
 *     on every value.
 *   - **Secrets** → Fastly Secret Store. The bootstrapping code below reads
 *     each value with a fallback chain: Secret Store > Config Store > env.
 *   - **Email** → Resend or SES via the existing pluggable provider. The
 *     Cloudflare `SEND_EMAIL` binding is not available on Fastly.
 *   - **S3** → unchanged. `@aws-sdk/client-s3` is fetch-based and works on
 *     Fastly as long as each S3 endpoint is declared as a backend.
 *   - **waitUntil** → Fastly Compute does not expose a true `waitUntil`
 *     equivalent. We fire-and-forget background work without awaiting it;
 *     if the request handler returns before the background promise resolves,
 *     the runtime may cut it off. Use sparingly on this target.
 *
 * @see ../../../docs/fastly-setup.md for the operator-facing setup guide.
 */

/**
 * Structural shape of the runtime objects Fastly Compute exposes to user
 * code. We type them locally rather than importing the real types from
 * `fastly:*` modules because those resolve only under the Fastly build
 * toolchain; the same source file has to typecheck under the Workers and
 * Node toolchains too.
 */
export interface FastlySecretStore {
  get(name: string): Promise<{ plaintext(): string } | null>;
}
export interface FastlyConfigStore {
  get(name: string): string | null;
}
export interface FastlyEnv {
  get(name: string): string;
}

export interface FastlyRuntimeBindings {
  /** Fastly KV stores keyed by binding name. */
  kv: Record<string, FastlyKVNamespace>;
  /** Optional Secret Store. If absent, secrets fall through to Config Store + env. */
  secretStore?: FastlySecretStore;
  /** Optional Config Store for non-secret runtime config. */
  configStore?: FastlyConfigStore;
  /** `fastly:env` shim, or a Map-backed fallback for tests. */
  env: FastlyEnv;
}

/**
 * Reads a string config value from the Fastly bindings, in priority order:
 *
 *   1. Secret Store (if a binding is present and the key exists)
 *   2. Config Store (if a binding is present and the key exists)
 *   3. Environment variable (`fastly:env`)
 *
 * This lets operators pick the right storage class per value without code
 * changes — secrets go to the Secret Store, public config to the Config
 * Store, and Fastly-injected runtime vars (e.g. `FASTLY_SERVICE_VERSION`)
 * fall through to env.
 */
async function readConfig(
  bindings: FastlyRuntimeBindings,
  key: string,
): Promise<string | undefined> {
  if (bindings.secretStore) {
    const secret = await bindings.secretStore.get(key);
    if (secret) return secret.plaintext();
  }
  if (bindings.configStore) {
    const cs = bindings.configStore.get(key);
    if (cs !== null) return cs;
  }
  const fromEnv = bindings.env.get(key);
  return fromEnv === '' ? undefined : fromEnv;
}

/** Synchronous env-only helper, used inside async building blocks. */
function envOnly(bindings: FastlyRuntimeBindings, key: string): string | undefined {
  const v = bindings.env.get(key);
  return v === '' ? undefined : v;
}

export async function buildFastlyConfig(bindings: FastlyRuntimeBindings): Promise<PlatformConfig> {
  const need = async (k: string): Promise<string> => {
    const v = await readConfig(bindings, k);
    if (!v) throw new Error(`Missing required config value: ${k}`);
    return v;
  };
  const opt = (k: string) => readConfig(bindings, k);

  const environment = (envOnly(bindings, 'ENVIRONMENT') ??
    'production') as PlatformConfig['ENVIRONMENT'];

  return {
    REMNAWAVE_BASE_URL: await need('REMNAWAVE_BASE_URL'),
    REMNAWAVE_API_TOKEN: await need('REMNAWAVE_API_TOKEN'),
    AUTHENTIK_ISSUER: await need('AUTHENTIK_ISSUER'),
    AUTHENTIK_CLIENT_ID: await need('AUTHENTIK_CLIENT_ID'),
    AUTHENTIK_CLIENT_SECRET: await need('AUTHENTIK_CLIENT_SECRET'),
    AUTHENTIK_REDIRECT_URI: await need('AUTHENTIK_REDIRECT_URI'),
    AUTHENTIK_SCOPES: (await opt('AUTHENTIK_SCOPES')) ?? 'openid email profile',
    EMAIL_PROVIDER: ((await opt('EMAIL_PROVIDER')) ?? 'resend') as PlatformConfig['EMAIL_PROVIDER'],
    EMAIL_FROM: (await opt('EMAIL_FROM')) ?? 'noreply@localhost',
    EMAIL_REPLY_TO: await opt('EMAIL_REPLY_TO'),
    RESEND_API_KEY: await opt('RESEND_API_KEY'),
    AWS_ACCESS_KEY_ID: await opt('AWS_ACCESS_KEY_ID'),
    AWS_SECRET_ACCESS_KEY: await opt('AWS_SECRET_ACCESS_KEY'),
    AWS_SES_REGION: await opt('AWS_SES_REGION'),
    SESSION_SIGNING_KEY: await need('SESSION_SIGNING_KEY'),
    ADMIN_SESSION_SIGNING_KEY: await need('ADMIN_SESSION_SIGNING_KEY'),
    ADMIN_BOOTSTRAP_SECRET: await opt('ADMIN_BOOTSTRAP_SECRET'),
    IP_HASH_SALT: await need('IP_HASH_SALT'),
    TURNSTILE_SECRET_KEY: await need('TURNSTILE_SECRET_KEY'),
    FREE_TIER_TURNSTILE_SITE_KEY: await need('FREE_TIER_TURNSTILE_SITE_KEY'),
    FREE_TIER_DAILY_CAP: parseInt((await opt('FREE_TIER_DAILY_CAP')) ?? '1', 10),
    FREE_TIER_EXPIRY_DAYS: parseInt((await opt('FREE_TIER_EXPIRY_DAYS')) ?? '90', 10),
    SUBSCRIPTION_DEFAULT_FORMAT: (await opt('SUBSCRIPTION_DEFAULT_FORMAT')) ?? 'auto',
    S3_MIRRORS_ENABLED: (await opt('S3_MIRRORS_ENABLED')) === 'true',
    S3_PROVIDERS: parseS3Providers(await collectEnvForS3(bindings)),
    WEBAUTHN_RP_ID: await need('WEBAUTHN_RP_ID'),
    WEBAUTHN_RP_NAME: await need('WEBAUTHN_RP_NAME'),
    WEBAUTHN_ORIGIN: await need('WEBAUTHN_ORIGIN'),
    CRON_TRIGGER_SECRET: await opt('CRON_TRIGGER_SECRET'),
    TRUSTED_PROXY: (await opt('TRUSTED_PROXY')) === 'true',
    MEMBERS_JOIN_URL: (await opt('MEMBERS_JOIN_URL')) || 'https://members.unredacted.org/join',
    MEMBERS_ACCOUNT_URL:
      (await opt('MEMBERS_ACCOUNT_URL')) || 'https://members.unredacted.org/account',
    ENVIRONMENT: environment,
  };
}

/**
 * S3 mirror provider parsing needs a flat key/value bag. Fastly does not give
 * us `Object.keys(env)`, so we materialize the well-known S3 key prefix into
 * a plain object before handing it to the parser.
 */
async function collectEnvForS3(bindings: FastlyRuntimeBindings): Promise<Record<string, unknown>> {
  const count = parseInt((await readConfig(bindings, 'S3_PROVIDER_COUNT')) ?? '0', 10);
  const out: Record<string, unknown> = { S3_PROVIDER_COUNT: String(count) };
  const fields = [
    'NAME',
    'ENDPOINT',
    'BUCKET',
    'PUBLIC_URL',
    'REGION',
    'ACCESS_KEY_ID',
    'SECRET_ACCESS_KEY',
  ];
  for (let i = 1; i <= count; i++) {
    for (const f of fields) {
      const k = `S3_PROVIDER_${i}_${f}`;
      const v = await readConfig(bindings, k);
      if (v !== undefined) out[k] = v;
    }
  }
  return out;
}

export interface FastlyAdapterOptions {
  bindings: FastlyRuntimeBindings;
  /** Turso URL + auth token. Both required for a working DB. */
  turso: { url: string; authToken?: string };
}

/**
 * Build the Fastly platform adapter. Note this is **async** unlike the
 * Workers/Node adapters — Fastly secrets resolve via async APIs and the
 * libSQL client setup is also async-imported. Call from the entry point's
 * fetch handler, not module top-level.
 */
export async function buildFastlyAdapter(opts: FastlyAdapterOptions): Promise<PlatformAdapter> {
  const config = await buildFastlyConfig(opts.bindings);
  const logLevel = (envOnly(opts.bindings, 'LOG_LEVEL') ?? 'info') as
    | 'debug'
    | 'info'
    | 'warn'
    | 'error';
  const logger = new Logger(logLevel, { runtime: 'fastly', env: config.ENVIRONMENT });
  const db = await createLibsqlClient(opts.turso);
  const email = selectEmailProvider(config, { logger });
  const storage = new S3StorageProvider(config.S3_PROVIDERS, logger);

  const requireKv = (name: string): FastlyKVNamespace => {
    const ns = opts.bindings.kv[name];
    if (!ns) throw new Error(`Fastly KV binding "${name}" is not declared in fastly.toml`);
    return ns;
  };

  /**
   * Fastly Compute does not expose `waitUntil`. We approximate it by firing
   * the promise and attaching an error handler so it can't crash the request,
   * but the runtime may cut it off when the response is returned. Use
   * intentionally — for fully durable background work, drive it from cron
   * (see /api/cron/run-task).
   */
  const waitUntil = (p: Promise<unknown>): void => {
    void p.catch((err) => logger.error('background_task_error', { error: String(err) }));
  };

  return {
    config,
    db,
    kv: {
      sessions: new FastlyKvStore(requireKv('FS_SESSIONS_KV')),
      cache: new FastlyKvStore(requireKv('FS_CACHE_KV')),
      rateLimit: new FastlyKvStore(requireKv('FS_RATELIMIT_KV')),
    },
    email,
    storage,
    logger,
    waitUntil,
  };
}
