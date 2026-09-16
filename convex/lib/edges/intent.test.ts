/**
 * The frozen provisioning intent: what it captures, and that a qualification
 * binds to the exact configuration it proved.
 */
import { describe, expect, test } from 'vitest';
import {
  buildProvisionIntent,
  intentHash,
  IntentError,
  parseIntent,
  qualificationBinding,
  qualificationRefusal,
  qualificationVerdict,
  type ProvisionIntent,
} from './intent';

const originTransport = {
  scheme: 'https' as const,
  certPublic: true,
  certNames: ['origin.example'],
  acceptsHostHeader: 'any' as const,
};

const cloudflare = {
  id: 'acct-cf',
  provider: 'cloudflare',
  settings: { zoneId: 'z'.repeat(32), zoneName: 'example.org' },
};
const fastly = {
  id: 'acct-fastly',
  provider: 'fastly',
  settings: {
    dnsAccountId: 'acct-cf',
    certificateAuthority: 'certainly',
    tlsConfigurationId: 'tls-1',
  },
};

const args = {
  specName: 'fcp-relay-node-one-abcd1234',
  templateParams: { labelLength: 12 },
  templateHash: 'h1',
  slot: { originPort: 443, originTransport },
};

describe('buildProvisionIntent', () => {
  test('an L4 provider has no intent to freeze', () => {
    expect(
      buildProvisionIntent({
        ...args,
        account: { id: 'a', provider: 'upcloud', settings: { zone: 'de-fra1' } },
      }),
    ).toBeNull();
  });

  test('a Cloudflare edge freezes its own zone, the hostname and the origin transport', () => {
    const intent = buildProvisionIntent({ ...args, account: cloudflare })!;
    expect(intent.zoneId).toBe('z'.repeat(32));
    expect(intent.zoneName).toBe('example.org');
    expect(intent.hostname.endsWith('.example.org')).toBe(true);
    // A single label under the apex (Universal SSL covers one level only).
    expect(intent.hostname.split('.')).toHaveLength(3);
    expect(intent.originTransport).toEqual(originTransport);
    expect(intent.originPort).toBe(443);
    expect(intent.dnsAccountId).toBeUndefined();
  });

  test('a Fastly edge freezes the REFERENCED zone plus the CA and TLS configuration', () => {
    const intent = buildProvisionIntent({ ...args, account: fastly, dnsAccount: cloudflare })!;
    expect(intent.dnsAccountId).toBe('acct-cf');
    expect(intent.zoneName).toBe('example.org');
    expect(intent.certificateAuthority).toBe('certainly');
    expect(intent.tlsConfigurationId).toBe('tls-1');
  });

  test('the hostname is deterministic for one (name, zone, template)', () => {
    const a = buildProvisionIntent({ ...args, account: cloudflare })!;
    const b = buildProvisionIntent({ ...args, account: cloudflare })!;
    expect(a.hostname).toBe(b.hostname);
    const other = buildProvisionIntent({
      ...args,
      specName: 'fcp-relay-node-one-deadbeef',
      account: cloudflare,
    })!;
    expect(other.hostname).not.toBe(a.hostname);
  });

  test('a missing zone or origin transport is a coded refusal, never a guess', () => {
    expect(() =>
      buildProvisionIntent({
        ...args,
        account: { ...cloudflare, settings: { zoneId: 'z'.repeat(32) } },
      }),
    ).toThrow(IntentError);
    try {
      buildProvisionIntent({ ...args, account: cloudflare, slot: { originPort: 443 } });
      throw new Error('expected a refusal');
    } catch (err) {
      expect((err as IntentError).code).toBe('origin_transport_missing');
    }
  });
});

describe('parseIntent', () => {
  test('a malformed or absent blob is null, never a partial intent', () => {
    expect(parseIntent(null)).toBeNull();
    expect(parseIntent('not json')).toBeNull();
    expect(parseIntent('{"hostname":"x.example"}')).toBeNull();
  });

  test('a round trip preserves the hash', () => {
    const intent = buildProvisionIntent({ ...args, account: cloudflare })!;
    const back = parseIntent(JSON.stringify(intent))!;
    expect(intentHash(back)).toBe(intentHash(intent));
  });
});

describe('qualification binding', () => {
  const intent = buildProvisionIntent({ ...args, account: cloudflare })!;
  const slot = { _id: 's1', revision: 3, originPort: 443, originTransport };
  const profile = { _id: 'p1', revision: 2, protocol: 'ws' as const };
  const binding = qualificationBinding({ slot, profile, intent });
  const stored = { ok: true, checkedAt: 0, expiresAt: 10_000, binding };

  test('a current, passing proof of this exact configuration is ok', () => {
    expect(qualificationVerdict(stored, binding, 5_000)).toBe('ok');
    expect(qualificationRefusal('ok')).toBeNull();
  });

  test('missing / failed / expired each refuse with their own code', () => {
    expect(qualificationVerdict(null, binding, 5_000)).toBe('missing');
    expect(qualificationVerdict({ ...stored, ok: false }, binding, 5_000)).toBe('failed');
    expect(qualificationVerdict(stored, binding, 20_000)).toBe('expired');
    expect(qualificationRefusal('missing')).toBe('front_unqualified');
    expect(qualificationRefusal('expired')).toBe('front_qualification_stale');
    expect(qualificationRefusal('stale')).toBe('front_qualification_stale');
  });

  test('a slot, profile or intent write since the proof makes it STALE', () => {
    const slotWritten = qualificationBinding({
      slot: { ...slot, revision: 4 },
      profile,
      intent,
    });
    expect(qualificationVerdict(stored, slotWritten, 5_000)).toBe('stale');
    const profileWritten = qualificationBinding({
      slot,
      profile: { ...profile, revision: 3 },
      intent,
    });
    expect(qualificationVerdict(stored, profileWritten, 5_000)).toBe('stale');
    const movedIntent: ProvisionIntent = { ...intent, originPort: 8443 };
    expect(
      qualificationVerdict(
        stored,
        qualificationBinding({ slot, profile, intent: movedIntent }),
        5_000,
      ),
    ).toBe('stale');
  });

  test('different transport parameters hash differently (an absent one is not an empty one)', () => {
    const withPath = qualificationBinding({
      slot,
      profile,
      intent,
      transportParams: { path: '/a', host: null, serviceName: null, upgradeToken: null },
    });
    const withOther = qualificationBinding({
      slot,
      profile,
      intent,
      transportParams: { path: '/b', host: null, serviceName: null, upgradeToken: null },
    });
    expect(withPath.transportParamsHash).not.toBe(withOther.transportParamsHash);
    expect(withPath.transportParamsHash).not.toBe(binding.transportParamsHash);
  });
});
