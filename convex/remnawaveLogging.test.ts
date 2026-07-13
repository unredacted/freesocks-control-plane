/// <reference types="vite/client" />
/**
 * The safety-critical merge helper behind FCP writing the Xray no-client-IP-logging
 * posture into a Remnawave config profile: it must touch ONLY log + policy, be
 * idempotent, and REFUSE a config with no inbounds (a full-replace PATCH of that
 * would wipe the node).
 */
import { describe, expect, test } from 'vitest';
import { hardenXrayLoggingConfig, PRIVACY_XRAY_LOG } from './lib/backends/remnawave';

type PolicyShape = {
  levels: Record<string, Record<string, unknown>>;
  system?: Record<string, unknown>;
};

const baseConfig = () => ({
  log: { loglevel: 'info' },
  inbounds: [
    {
      tag: 'vless-in',
      protocol: 'vless',
      streamSettings: { realitySettings: { privateKey: 'SECRET-KEY', shortIds: ['ab12'] } },
    },
  ],
  outbounds: [{ protocol: 'freedom' }],
  routing: { rules: [{ type: 'field', outboundTag: 'direct' }] },
});

describe('hardenXrayLoggingConfig', () => {
  test('sets the no-logging log + statsUserOnline, preserving everything else', () => {
    const src = baseConfig();
    const { config, changed } = hardenXrayLoggingConfig(src);
    expect(changed).toBe(true);
    expect(config.log).toEqual(PRIVACY_XRAY_LOG);
    expect((config.policy as PolicyShape).levels['0']!.statsUserOnline).toBe(false);
    // inbounds / outbounds / routing / Reality keys preserved verbatim
    expect(config.inbounds).toEqual(src.inbounds);
    expect(config.outbounds).toEqual(src.outbounds);
    expect(config.routing).toEqual(src.routing);
    // input is not mutated
    expect(src.log).toEqual({ loglevel: 'info' });
  });

  test('is idempotent — an already-hardened config reports no change', () => {
    const once = hardenXrayLoggingConfig(baseConfig()).config;
    expect(hardenXrayLoggingConfig(once).changed).toBe(false);
  });

  test('recognizes a hardened config after a jsonb round-trip (key order rewritten)', () => {
    // Remnawave persists the config in a Postgres jsonb column, which reorders
    // object keys canonically (by length, then bytewise). The posture check must
    // be key-order-independent or every re-check reports "logs IPs" forever.
    const once = hardenXrayLoggingConfig(baseConfig()).config;
    const jsonbOrderedLog = Object.fromEntries(
      Object.entries(once.log as Record<string, unknown>).sort(
        ([a], [b]) => a.length - b.length || (a < b ? -1 : 1),
      ),
    );
    expect(Object.keys(jsonbOrderedLog)).not.toEqual(Object.keys(once.log as object));
    const roundTripped = { ...once, log: jsonbOrderedLog };
    expect(hardenXrayLoggingConfig(roundTripped).changed).toBe(false);
  });

  test('an extra harmless log key does not force a rewrite; a wrong value does', () => {
    const once = hardenXrayLoggingConfig(baseConfig()).config;
    const withExtra = { ...once, log: { ...(once.log as object), somethingElse: true } };
    expect(hardenXrayLoggingConfig(withExtra).changed).toBe(false);
    const withAccessLog = { ...once, log: { ...(once.log as object), access: '/var/log/a.log' } };
    expect(hardenXrayLoggingConfig(withAccessLog).changed).toBe(true);
  });

  test('preserves other policy levels + keys while forcing level 0 statsUserOnline off', () => {
    const src = {
      ...baseConfig(),
      policy: {
        levels: { '0': { handshake: 4 }, '1': { connIdle: 300 } },
        system: { statsInboundUplink: true },
      },
    };
    const { config } = hardenXrayLoggingConfig(src);
    const policy = config.policy as PolicyShape;
    expect(policy.levels['0']!.statsUserOnline).toBe(false);
    expect(policy.levels['0']!.handshake).toBe(4); // preserved
    expect(policy.levels['1']).toEqual({ connIdle: 300 }); // preserved
    expect(policy.system).toEqual({ statsInboundUplink: true }); // preserved
  });

  test('REFUSES a config with no inbounds (would wipe the node)', () => {
    expect(() => hardenXrayLoggingConfig({ inbounds: [], outbounds: [] })).toThrow(/inbounds/i);
    expect(() => hardenXrayLoggingConfig({ outbounds: [] })).toThrow(/inbounds/i);
  });

  test('REFUSES a non-object config', () => {
    expect(() => hardenXrayLoggingConfig(null)).toThrow();
    expect(() => hardenXrayLoggingConfig('nope')).toThrow();
    expect(() => hardenXrayLoggingConfig([1, 2])).toThrow();
  });
});
