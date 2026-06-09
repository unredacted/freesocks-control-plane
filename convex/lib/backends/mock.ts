/**
 * Dev-only mock proxy backend. Lets the full issuance + account flow (and the
 * CDN-blinding reveal leg) be exercised locally WITHOUT a real Remnawave /
 * Outline instance. The returned "subscription URL" does not proxy anything; it
 * is a placeholder for UI / flow testing only.
 *
 * DOUBLE-GATED so it can never fire in production: it requires BOTH
 * DEV_MOCK_BACKEND=true AND ENVIRONMENT=development. A prod deployment
 * (ENVIRONMENT=production) ignores DEV_MOCK_BACKEND entirely.
 */
import { randomHex } from '../crypto';
import type { IssueUserSpec, IssuedUser, SubscriptionContent, UserState } from './types';

export function mockBackendEnabled(): boolean {
  return process.env.DEV_MOCK_BACKEND === 'true' && process.env.ENVIRONMENT === 'development';
}

export function mockIssueUser(spec: IssueUserSpec): IssuedUser {
  const shortId = randomHex(8);
  return {
    backendUserId: `mock-${randomHex(8)}`,
    backendShortId: shortId,
    subscriptionUrl: `https://mock.local/sub/${shortId}`,
    raw: { mock: true, username: spec.username },
  };
}

export function mockGetUser(): UserState {
  return {
    trafficLimitBytes: 50 * 1024 * 1024 * 1024,
    usedTrafficBytes: 1024 * 1024 * 1024,
    expireAt: new Date(Date.now() + 30 * 86_400_000).toISOString(),
    status: 'active',
    devices: [],
  };
}

export function mockFetchContent(): SubscriptionContent {
  return { content: '# mock subscription content (dev)\n', contentType: 'text/plain' };
}
