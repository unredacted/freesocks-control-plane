import type { PlatformAdapter } from './platform/interface';
import type { ServiceContainer } from './services/container';
import type { Logger } from './lib/logger';
import type { ApiScope } from '../shared/contracts/scopes';

export interface MemberSession {
  sessionId: string;
  userId: number;
  contactId: number | null;
  authentikSubject: string;
  email?: string;
  displayName?: string;
  /** Source of the member identity: 'cookie' (web SPA) or 'jwt' (mobile/API). */
  source: 'cookie' | 'jwt';
  /**
   * Unix ms when email/displayName were last refreshed from the DB. Used to
   * decide whether the cookie-session middleware should re-fetch from `users`
   * to pick up profile changes (e.g. email update on the Authentik side).
   */
  refreshedAt?: number;
}

export interface AdminSession {
  sessionId: string;
  adminUserId: number;
  username: string;
}

export interface ApiAuthContext {
  tokenId: number;
  scopes: ApiScope[];
  subjectType: 'service' | 'user';
  subjectUserId: number | null;
}

export type AppEnv = {
  Bindings: Record<string, never>;
  Variables: {
    requestId: string;
    logger: Logger;
    platform: PlatformAdapter;
    services: ServiceContainer;
    member?: MemberSession;
    admin?: AdminSession;
    apiAuth?: ApiAuthContext;
    clientIp?: string;
  };
};
