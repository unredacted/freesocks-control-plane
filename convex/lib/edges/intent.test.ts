/**
 * The frozen provisioning intent: what it captures, and that a qualification
 * binds to the exact configuration it proved.
 */
import { describe, expect, test } from 'vitest';
import {
  buildProvisionIntent,
  frozenSettingsOf,
  intentHash,
  intentPlaceOf,
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

const cloudflare = { id: 'acct-cf', provider: 'cloudflare', settings: {} };
// A Cloudflare zone location: its encryption mode is OBSERVED by the zone
// check, never typed.
const zone = { zoneId: 'z'.repeat(32), zoneName: 'example.org', observed: { zoneSslMode: 'full' } };
const fastly = {
  id: 'acct-fastly',
  provider: 'fastly',
  settings: { certificateAuthority: 'certainly' },
};
// A Fastly front location: the DNS account writing its records, a zone of
// that account, the TLS configuration.
const front = {
  dnsAccountId: 'acct-cf',
  zoneId: 'z'.repeat(32),
  zoneName: 'example.org',
  tlsConfigurationId: 'tls-1',
};

const args = {
  specName: 'fcp-relay-node-one-abcd1234',
  templateParams: { labelLength: 12 },
  templateHash: 'h1',
  listener: { originPort: 443, originTransport },
};

describe('buildProvisionIntent', () => {
  test('an L4 provider has no intent to freeze', () => {
    expect(
      buildProvisionIntent({
        ...args,
        account: { id: 'a', provider: 'upcloud', settings: {} },
        place: {},
      }),
    ).toBeNull();
  });

  test("a Cloudflare edge freezes its location's zone, the hostname and the origin transport", () => {
    const intent = buildProvisionIntent({ ...args, account: cloudflare, place: zone })!;
    expect(intent.zoneId).toBe('z'.repeat(32));
    expect(intent.zoneName).toBe('example.org');
    expect(intent.hostname.endsWith('.example.org')).toBe(true);
    // A single label under the apex (Universal SSL covers one level only).
    expect(intent.hostname.split('.')).toHaveLength(3);
    expect(intent.originTransport).toEqual(originTransport);
    expect(intent.originPort).toBe(443);
    expect(intent.zoneSslMode).toBe('full');
    expect(intent.dnsAccountId).toBeUndefined();
  });

  test('two zones of one account mint names under each zone', () => {
    const other = { zoneId: 'y'.repeat(32), zoneName: 'example.net', observed: zone.observed };
    const a = buildProvisionIntent({ ...args, account: cloudflare, place: zone })!;
    const b = buildProvisionIntent({ ...args, account: cloudflare, place: other })!;
    expect(a.hostname.endsWith('.example.org')).toBe(true);
    expect(b.hostname.endsWith('.example.net')).toBe(true);
    expect(b.zoneId).toBe('y'.repeat(32));
  });

  test("a Fastly edge freezes its location's DNS account, zone and TLS configuration, and the account's CA", () => {
    const intent = buildProvisionIntent({ ...args, account: fastly, place: front })!;
    expect(intent.dnsAccountId).toBe('acct-cf');
    expect(intent.zoneName).toBe('example.org');
    expect(intent.certificateAuthority).toBe('certainly');
    expect(intent.tlsConfigurationId).toBe('tls-1');
    // How the provider is driven now: a versionless domain. The certificate
    // scope is frozen only when the account names one (absent = one per front).
    expect(intent.domainModel).toBe('versionless');
    expect(intent).not.toHaveProperty('certificateScope');
    const wild = buildProvisionIntent({
      ...args,
      account: { ...fastly, settings: { ...fastly.settings, certificateScope: 'wildcard' } },
      place: front,
    })!;
    expect(wild.certificateScope).toBe('wildcard');
    // The account may choose classic domains for its new fronts.
    const classic = buildProvisionIntent({
      ...args,
      account: { ...fastly, settings: { ...fastly.settings, domainModel: 'classic' } },
      place: front,
    })!;
    expect(classic.domainModel).toBe('classic');
    // Cloudflare is driven the same way it always was: no facts of its own.
    expect(buildProvisionIntent({ ...args, account: cloudflare, place: zone })).not.toHaveProperty(
      'domainModel',
    );
    const { tlsConfigurationId: _t, ...noTls } = front;
    expect(
      buildProvisionIntent({ ...args, account: fastly, place: noTls })!.tlsConfigurationId,
    ).toBeUndefined();
  });

  test('a Fastly location without a DNS account is a coded refusal', () => {
    const { dnsAccountId: _d, ...noDns } = front;
    try {
      buildProvisionIntent({ ...args, account: fastly, place: noDns });
      throw new Error('expected a refusal');
    } catch (err) {
      expect((err as IntentError).code).toBe('dns_account_missing');
    }
  });

  test('the hostname is deterministic for one (name, zone, template)', () => {
    const a = buildProvisionIntent({ ...args, account: cloudflare, place: zone })!;
    const b = buildProvisionIntent({ ...args, account: cloudflare, place: zone })!;
    expect(a.hostname).toBe(b.hostname);
    const other = buildProvisionIntent({
      ...args,
      specName: 'fcp-relay-node-one-deadbeef',
      account: cloudflare,
      place: zone,
    })!;
    expect(other.hostname).not.toBe(a.hostname);
  });

  test('an unchecked zone cannot be planned against: the zone mode is unknown', () => {
    try {
      buildProvisionIntent({ ...args, account: cloudflare, place: { ...zone, observed: {} } });
      throw new Error('expected a refusal');
    } catch (err) {
      expect((err as IntentError).code).toBe('zone_mode_unknown');
    }
  });

  test('a zone mode that cannot carry the listener origin is refused before anything exists', () => {
    // `flexible` dials the origin over plain HTTP; this origin speaks HTTPS.
    try {
      buildProvisionIntent({
        ...args,
        account: cloudflare,
        place: { ...zone, observed: { zoneSslMode: 'flexible' } },
      });
      throw new Error('expected a refusal');
    } catch (err) {
      expect((err as IntentError).code).toBe('origin_tls_mismatch');
    }
    // A privately issued origin certificate cannot be validated by `strict`.
    try {
      buildProvisionIntent({
        ...args,
        account: cloudflare,
        place: { ...zone, observed: { zoneSslMode: 'strict' } },
        listener: { originPort: 443, originTransport: { ...originTransport, certPublic: false } },
      });
      throw new Error('expected a refusal');
    } catch (err) {
      expect((err as IntentError).code).toBe('origin_tls_mismatch');
    }
  });

  test('the DNS zone mode only governs the provider that PROXIES the zone', () => {
    // The zone hosting the CNAMEs is set to the strictest mode. For a front
    // whose records are unproxied there, that mode describes nothing about the
    // origin leg: a plaintext origin behind it plans fine and freezes no mode.
    const plaintext = {
      originPort: 80,
      originTransport: { ...originTransport, scheme: 'http' as const },
    };
    const strict = { zoneSslMode: 'strict' };
    const intent = buildProvisionIntent({
      ...args,
      account: fastly,
      place: { ...front, observed: strict },
      listener: plaintext,
    })!;
    expect(intent.zoneSslMode).toBeUndefined();
    expect(intent.originTransport.scheme).toBe('http');
    // An explicit override does not smuggle the mode back in either.
    expect(
      buildProvisionIntent({
        ...args,
        account: fastly,
        place: { ...front, observed: strict },
        listener: plaintext,
        zoneSslMode: 'strict',
      })!.zoneSslMode,
    ).toBeUndefined();
    // The same zone in front of ITS OWN proxy still refuses the plaintext origin.
    try {
      buildProvisionIntent({
        ...args,
        account: cloudflare,
        place: { ...zone, observed: strict },
        listener: plaintext,
      });
      throw new Error('expected a refusal');
    } catch (err) {
      expect((err as IntentError).code).toBe('origin_tls_mismatch');
    }
  });

  test('a front the zone does not proxy plans against an UNCHECKED zone', () => {
    // `zone_mode_unknown` is a Cloudflare-proxy refusal: a Fastly edge only
    // needs the zone's name and id, not its encryption mode.
    const intent = buildProvisionIntent({ ...args, account: fastly, place: front })!;
    expect(intent.zoneSslMode).toBeUndefined();
    expect(intent.zoneName).toBe('example.org');
  });

  test('an imported front keeps the hostname it already serves', () => {
    const intent = buildProvisionIntent({
      ...args,
      account: cloudflare,
      place: zone,
      hostnameOverride: 'already.example.org',
    })!;
    expect(intent.hostname).toBe('already.example.org');
  });

  test('a missing zone or origin transport is a coded refusal, never a guess', () => {
    try {
      buildProvisionIntent({ ...args, account: cloudflare, place: { zoneId: 'z'.repeat(32) } });
      throw new Error('expected a refusal');
    } catch (err) {
      expect((err as IntentError).code).toBe('dns_zone_missing');
    }
    try {
      buildProvisionIntent({
        ...args,
        account: cloudflare,
        place: zone,
        listener: { originPort: 443 },
      });
      throw new Error('expected a refusal');
    } catch (err) {
      expect((err as IntentError).code).toBe('origin_transport_missing');
    }
  });
});

describe('intentPlaceOf / frozenSettingsOf', () => {
  test("a location's placement and observed facts become the intent's place", () => {
    expect(
      intentPlaceOf(
        { type: 'fastly', ...front },
        JSON.stringify({ zoneStatus: 'active', ignored: 1 }),
      ),
    ).toEqual({ ...front, observed: { zoneStatus: 'active' } });
    // An L4 placement (or none) names no zone.
    expect(intentPlaceOf({ type: 'upcloud', zone: 'de-fra1' })).toEqual({ observed: {} });
    expect(intentPlaceOf(null, 'not json')).toEqual({ observed: {} });
  });

  test('an existing edge keeps the zone and TLS configuration it froze', () => {
    const intent = buildProvisionIntent({ ...args, account: fastly, place: front })!;
    expect(frozenSettingsOf(intent)).toEqual({
      zoneId: 'z'.repeat(32),
      zoneName: 'example.org',
      tlsConfigurationId: 'tls-1',
    });
  });
});

describe('parseIntent', () => {
  test('a malformed or absent blob is null, never a partial intent', () => {
    expect(parseIntent(null)).toBeNull();
    expect(parseIntent('not json')).toBeNull();
    expect(parseIntent('{"hostname":"x.example"}')).toBeNull();
  });

  test('a round trip preserves the hash', () => {
    const intent = buildProvisionIntent({ ...args, account: cloudflare, place: zone })!;
    const back = parseIntent(JSON.stringify(intent))!;
    expect(intentHash(back)).toBe(intentHash(intent));
  });
});

describe('qualification binding', () => {
  const intent = buildProvisionIntent({ ...args, account: cloudflare, place: zone })!;
  const listener = {
    _id: 'l1',
    revision: 3,
    originPort: 443,
    originTransport,
    protocol: 'vless' as const,
    streamTransport: 'ws' as const,
    security: 'tls' as const,
  };
  const binding = qualificationBinding({ listener, intent });
  const stored = { ok: true, checkedAt: 0, expiresAt: 10_000, binding };

  test('the binding names the listener, its revision and what it speaks', () => {
    expect(binding).toMatchObject({
      hostname: intent.hostname,
      listenerId: 'l1',
      listenerRevision: 3,
      protocol: 'vless',
      streamTransport: 'ws',
      security: 'tls',
    });
    expect(binding.intentHash).toBe(intentHash(intent));
    expect(
      qualificationBinding({ listener: { ...listener, revision: undefined }, intent })
        .listenerRevision,
    ).toBe(0);
  });

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

  test('a listener write, a changed proto or an intent write since the proof makes it STALE', () => {
    const listenerWritten = qualificationBinding({
      listener: { ...listener, revision: 4 },
      intent,
    });
    expect(qualificationVerdict(stored, listenerWritten, 5_000)).toBe('stale');
    const protoChanged = qualificationBinding({
      listener: { ...listener, streamTransport: 'grpc' as const },
      intent,
    });
    expect(qualificationVerdict(stored, protoChanged, 5_000)).toBe('stale');
    const movedIntent: ProvisionIntent = { ...intent, originPort: 8443 };
    expect(
      qualificationVerdict(stored, qualificationBinding({ listener, intent: movedIntent }), 5_000),
    ).toBe('stale');
  });

  test('different transport parameters hash differently (an absent one is not an empty one)', () => {
    const withPath = qualificationBinding({
      listener,
      intent,
      transportParams: { path: '/a', host: null, serviceName: null, upgradeToken: null },
    });
    const withOther = qualificationBinding({
      listener,
      intent,
      transportParams: { path: '/b', host: null, serviceName: null, upgradeToken: null },
    });
    expect(withPath.transportParamsHash).not.toBe(withOther.transportParamsHash);
    expect(withPath.transportParamsHash).not.toBe(binding.transportParamsHash);
  });
});
