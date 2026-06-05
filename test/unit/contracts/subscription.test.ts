import { describe, expect, it } from 'vitest';
import {
  SubscriptionRequest,
  SubscriptionResponse,
} from '../../../src/shared/contracts/subscription';

describe('subscription contracts', () => {
  it('SubscriptionRequest accepts a turnstile-only request', () => {
    expect(SubscriptionRequest.parse({ turnstileToken: 'abc' })).toEqual({
      turnstileToken: 'abc',
    });
  });

  it('SubscriptionRequest rejects honeypot', () => {
    expect(() => SubscriptionRequest.parse({ honeypot: 'spam' })).toThrow();
  });

  it('SubscriptionResponse accepts the canonical shape', () => {
    const value = SubscriptionResponse.parse({
      subscriptionUrl: 'https://rw.example.org/sub/abc',
      tier: { slug: 'free', name: 'Free', monthlyTrafficGb: 50, deviceLimit: 1 },
      backend: 'remnawave',
      expiresAt: '2026-04-29T00:00:00.000Z',
      trafficLimitBytes: 50000000000,
      trafficUsedBytes: 0,
      isReissued: false,
    });
    expect(value.subscriptionUrl).toBe('https://rw.example.org/sub/abc');
    expect(value.mirrors).toEqual([]);
    expect(value.backend).toBe('remnawave');
  });

  it('SubscriptionResponse rejects unknown backend values', () => {
    expect(() =>
      SubscriptionResponse.parse({
        subscriptionUrl: 'https://rw.example.org/sub/abc',
        tier: { slug: 'free', name: 'Free', monthlyTrafficGb: 50, deviceLimit: 1 },
        backend: 'wireguard',
        expiresAt: null,
        trafficLimitBytes: null,
        trafficUsedBytes: 0,
        isReissued: false,
      }),
    ).toThrow();
  });

  it('SubscriptionRequest accepts an optional backend preference', () => {
    expect(SubscriptionRequest.parse({ turnstileToken: 'abc', backend: 'outline' })).toEqual({
      turnstileToken: 'abc',
      backend: 'outline',
    });
  });
});
