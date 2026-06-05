import type { PlatformAdapter } from '../platform/interface';
import { RemnawaveClient } from '../providers/remnawave/client';
import { RemnawaveBackend } from '../providers/remnawave/backend';
import { OutlineBackend } from '../providers/outline/backend';
import { OutlineServerPool } from './outline-pool';
import type { BackendId, ProxyBackendProvider } from '../providers/backend';
import { AuthentikClient } from '../providers/authentik/client';
import { TurnstileVerifier } from '../providers/turnstile/verify';
import { WebAuthnService } from '../providers/webauthn/server';
import { AuditService } from './audit';
import { RateLimitService } from './rate-limit';
import { TierPolicyService } from './tier-policy';
import { SubscriptionDeliveryService } from './subscription-delivery';
import { FreeTierService } from './free-tier';
import { MembershipSyncService } from './membership-sync';
import { EmailDeliveryService } from './email-delivery';
import { ApiTokenService } from './api-tokens';
import { AppSettingsService } from './app-settings';
import { AuthentikJwtVerifier } from '../providers/authentik/jwt';
import { AccountIdService } from './account-id';
import { BackendRegistry } from './backend-registry';

export interface ServiceContainer {
  platform: PlatformAdapter;
  backends: BackendRegistry;
  authentik: AuthentikClient;
  turnstile: TurnstileVerifier;
  webauthn: WebAuthnService;
  audit: AuditService;
  rateLimit: RateLimitService;
  membershipSync: MembershipSyncService;
  tierPolicy: TierPolicyService;
  subscription: SubscriptionDeliveryService;
  freeTier: FreeTierService;
  emailDelivery: EmailDeliveryService;
  apiTokens: ApiTokenService;
  appSettings: AppSettingsService;
  authentikJwt: AuthentikJwtVerifier;
  accountId: AccountIdService;
}

export function buildServices(platform: PlatformAdapter): ServiceContainer {
  const remnawave = new RemnawaveClient({
    baseUrl: platform.config.REMNAWAVE_BASE_URL,
    apiToken: platform.config.REMNAWAVE_API_TOKEN,
    logger: platform.logger,
  });
  const appSettings = new AppSettingsService(platform.db, platform.kv.cache, platform.logger);
  const outlinePool = new OutlineServerPool({
    db: platform.db,
    logger: platform.logger,
    appSettings,
  });
  // Register every available backend in the BackendRegistry. Higher-level
  // services dispatch through this registry rather than holding a direct
  // reference to one client.
  const providers = new Map<BackendId, ProxyBackendProvider>();
  providers.set('remnawave', new RemnawaveBackend(remnawave));
  providers.set(
    'outline',
    new OutlineBackend({ db: platform.db, pool: outlinePool, logger: platform.logger }),
  );
  const backends = new BackendRegistry(providers);
  const authentik = new AuthentikClient(
    {
      issuer: platform.config.AUTHENTIK_ISSUER,
      clientId: platform.config.AUTHENTIK_CLIENT_ID,
      clientSecret: platform.config.AUTHENTIK_CLIENT_SECRET,
      redirectUri: platform.config.AUTHENTIK_REDIRECT_URI,
      scopes: platform.config.AUTHENTIK_SCOPES,
    },
    platform.logger,
  );
  const turnstile = new TurnstileVerifier(platform.config.TURNSTILE_SECRET_KEY, platform.logger);
  const webauthn = new WebAuthnService({
    rpId: platform.config.WEBAUTHN_RP_ID,
    rpName: platform.config.WEBAUTHN_RP_NAME,
    origin: platform.config.WEBAUTHN_ORIGIN,
  });
  const audit = new AuditService(platform.db, platform.logger);
  const rateLimit = new RateLimitService(platform.kv.rateLimit, platform.config.IP_HASH_SALT);
  const tierPolicy = new TierPolicyService(platform.db, platform.kv.cache, platform.logger);
  const subscription = new SubscriptionDeliveryService({
    backends,
    storage: platform.storage,
    audit,
    db: platform.db,
    logger: platform.logger,
    config: platform.config,
  });
  const freeTier = new FreeTierService({
    db: platform.db,
    rateLimit,
    tierPolicy,
    subscription,
    audit,
    logger: platform.logger,
    config: platform.config,
  });
  const emailDelivery = new EmailDeliveryService(
    platform.email,
    platform.db,
    platform.config,
    platform.logger,
  );
  const membershipSync = new MembershipSyncService({
    db: platform.db,
    backends,
    tierPolicy,
    audit,
    email: emailDelivery,
    logger: platform.logger,
    config: platform.config,
  });
  const apiTokens = new ApiTokenService(platform.db, platform.logger);
  // `appSettings` was constructed earlier (the OutlineServerPool depends on
  // it to read scoring weights). Don't reconstruct it here.
  const authentikJwt = new AuthentikJwtVerifier({
    issuer: platform.config.AUTHENTIK_ISSUER,
    audience: platform.config.AUTHENTIK_CLIENT_ID,
    logger: platform.logger,
  });
  const accountId = new AccountIdService(platform.db);
  return {
    platform,
    backends,
    authentik,
    turnstile,
    webauthn,
    audit,
    rateLimit,
    membershipSync,
    tierPolicy,
    subscription,
    freeTier,
    emailDelivery,
    apiTokens,
    appSettings,
    authentikJwt,
    accountId,
  };
}
