import { describe, expect, test } from 'vitest';
import { capEncryptionRule } from '../../../src/shared/encryptionRule';
import { classifyClient, detectBodyFormat } from './clientFamilies';

describe('classifyClient', () => {
  test.each([
    ['SFA/1.12.0 (sing-box 1.12.0)', 'singbox', 'singbox-json'],
    ['SFL/1.14.0', 'singbox', 'singbox-json'],
    ['SFW/1.14.0', 'singbox', 'singbox-json'],
    ['SFL (sing-box 1.14.0; language en_US)', 'singbox', 'singbox-json'],
    ['sing-box 1.13.0', 'singbox', 'singbox-json'],
    ['Karing/1.2', 'singbox', 'singbox-json'],
    ['clash-verge/v2.0.0', 'mihomo', 'clash-yaml'],
    ['mihomo/1.18', 'mihomo', 'clash-yaml'],
    ['Stash/2.5', 'mihomo', 'clash-yaml'],
    ['Happ/1.0', 'happ', 'links'],
    ['HiddifyNext/2.0', 'hiddify', 'links'],
    ['Streisand/1.5', 'streisand', 'links'],
    ['v2rayNG/1.9', 'v2rayng', 'links'],
    // Not known to read VLESS Encryption from a link: the plain rule (tests/compat/userAgents.ts).
    ['Shadowrocket/2.2', 'other', 'links'],
    ['Anywhere/1.0', 'xray-links', 'links'],
    // What the app's subscription fetch really sends.
    ['Anywhere', 'xray-links', 'links'],
    ['Anywhereelse/1.0', 'other', 'links'],
    ['Mozilla/5.0 (works anywhere)', 'other', 'links'],
    ['curl/8.0', 'other', 'links'],
    ['', 'other', 'links'],
  ])('%s → %s / %s', (ua, family, format) => {
    expect(classifyClient(ua)).toMatchObject({ family, expectedFormat: format });
  });

  test('a Hiddify older than 5.5.5 (or of no readable version) cannot speak VLESS Encryption', () => {
    const cap = (ua: string) => classifyClient(ua).encryptionCap;
    // What its subscription fetch sends.
    expect(cap('HiddifyNext/5.5.5 (android) like ClashMeta v2ray sing-box')).toBeUndefined();
    expect(cap('HiddifyNext/5.9.15 (windows) like ClashMeta v2ray sing-box')).toBeUndefined();
    expect(cap('HiddifyNext/6.0 (ios)')).toBeUndefined();
    expect(cap('Hiddify/5.5.5')).toBeUndefined();
    for (const old of [
      'HiddifyNext/5.5.4 (android) like ClashMeta v2ray sing-box',
      'HiddifyNext/5.4.0 (android)',
      'HiddifyNext/4.1.1 (macos)',
      'HiddifyNext/2.0',
      'HiddifyNext (android)',
    ])
      expect(cap(old), old).toBe('plain');
    // Every family is still its own; only the encryption rule follows the version.
    expect(classifyClient('HiddifyNext/4.1.1 (macos)')).toEqual({
      family: 'hiddify',
      expectedFormat: 'links',
      encryptionCap: 'plain',
    });
    // An app with no row, or a row that leaves a missing version to its family.
    for (const ua of ['SFA/1.11.9 (sing-box 1.11.9)', 'clash.meta/alpha-1a2b3c4', 'Happ/5.5.0/ios'])
      expect(classifyClient(ua), ua).not.toHaveProperty('encryptionCap');
  });

  test.each([
    // [User-Agent, cap] around each app's floor (undefined = its family's rule).
    ['clash.meta/v1.19.12', 'plain'],
    ['clash.meta/v1.19.13', undefined],
    ['clash.meta/v1.19.34', undefined],
    ['mihomo/1.19.30', undefined],
    ['clash-verge/v2.4.0', 'plain'],
    ['clash-verge/v2.4.1', undefined],
    ['clash-verge/v2.5.10', undefined],
    ['FlClash/v0.8.87 clash-verge Platform/android', 'plain'],
    ['FlClash/v0.8.88 clash-verge Platform/android', undefined],
    ['clash/v0.9.4 clash-verge Platform/windows', undefined],
    ['fl_clash/v0.8.80 clash-verge Platform/linux', 'plain'],
    ['ClashMetaForAndroid/2.11.15.Meta', 'plain'],
    ['ClashMetaForAndroid/2.11.16.Meta', undefined],
    ['mihomo.party/v1.8.5 (clash.meta)', 'plain'],
    ['mihomo.party/v2.0.5 (clash.meta)', undefined],
    ['prizrak-box/v1.0.20', undefined],
    // Prizrak-Box's fallback User-Agent poses as a Clash Verge Rev below its floor: plain (safe).
    ['clash-verge/v2.3.0', 'plain'],
    // Xray-based apps: the first release on the Xray wire of v25.8.31.
    ['v2rayNG/1.10.20', 'plain'],
    ['v2rayNG/1.10.21', undefined],
    ['v2rayNG/2.3.15', undefined],
    ['v2rayN/7.14.5', 'plain'],
    ['v2rayN/7.14.6', undefined],
    ['v2rayN/7.25.6', undefined],
    ['Throne/1.0.13', 'plain'],
    // 1.1.0-beta.1 and beta.2 (no encryption) send `Throne/1.1.0` too.
    ['Throne/1.1.0', 'plain'],
    ['Throne/1.1.1', undefined],
    ['Exclave/0.16.1', 'plain'],
    ['Exclave/0.16.2', undefined],
    ['husi/0.14.2-alpha (390; sing-box v1.12.0)', 'plain'],
    ['husi/0.15.0 (sing-box v1.12.12)', undefined],
    ['husi/2.4.0 (sing-box v1.15.0-alpha.13)', undefined],
    ['V2Box/9.8.7', 'plain'],
    ['V2Box/9.8.8', undefined],
    ['Streisand/1.6.61', 'plain'],
    ['Streisand/1.7.1', undefined],
    // A version that cannot be read: plain where the app always sends one...
    ['v2rayNG/dev', 'plain'],
    // ...its family's rule where a newer build sends none (Streisand's is a placeholder).
    ['Streisand', undefined],
    // Anywhere sends no version, and refuses the layer below iOS 26: both entries.
    ['Anywhere', 'prefer'],
    ['Anywhere/1.0', 'prefer'],
    // Karing names HiddifyNext among the apps it passes for: its own family's rule.
    ['Karing/1.2.10 HiddifyNext/2.0 mihomo/1.18 sing-box/1.12', undefined],
  ] as const)('%s → %s', (ua, cap) => {
    expect(classifyClient(ua).encryptionCap).toBe(cap);
  });
});

describe('capEncryptionRule', () => {
  test('lowers a family rule to the app cap, never raises it', () => {
    expect(capEncryptionRule('only', undefined)).toBe('only');
    expect(capEncryptionRule('only', 'prefer')).toBe('prefer');
    expect(capEncryptionRule('only', 'plain')).toBe('plain');
    expect(capEncryptionRule('prefer', 'prefer')).toBe('prefer');
    expect(capEncryptionRule('prefer', 'plain')).toBe('plain');
    expect(capEncryptionRule('plain', 'prefer')).toBe('plain');
    expect(capEncryptionRule('plain', undefined)).toBe('plain');
    // A rule with no encryption set reads as prefer.
    expect(capEncryptionRule(undefined, 'plain')).toBe('plain');
    expect(capEncryptionRule(undefined, 'prefer')).toBeUndefined();
    expect(capEncryptionRule(undefined, undefined)).toBeUndefined();
  });
});

describe('detectBodyFormat', () => {
  test('sniffs the body', () => {
    expect(detectBodyFormat('{"outbounds":[]}')).toBe('singbox-json');
    expect(detectBodyFormat('{"log":{}}')).toBe('unknown');
    expect(detectBodyFormat('proxies:\n  - name: a\n')).toBe('clash-yaml');
    expect(detectBodyFormat('mixed-port: 7890\nproxies:\n')).toBe('clash-yaml');
    expect(detectBodyFormat('<html>')).toBe('html');
    expect(detectBodyFormat('vless://u@h:443#x')).toBe('links');
    expect(detectBodyFormat('dmxlc3M6Ly8=')).toBe('links');
    expect(detectBodyFormat('   ')).toBe('unknown');
  });

  test('an Xray JSON body (an object or an array of configs) is neither sing-box nor links', () => {
    expect(
      detectBodyFormat('{"outbounds":[{"protocol":"vless","settings":{}},{"protocol":"freedom"}]}'),
    ).toBe('unknown');
    expect(detectBodyFormat('[{"outbounds":[{"protocol":"hysteria"}]}]')).toBe('unknown');
    // sing-box outbounds carry `type`.
    expect(detectBodyFormat('{"outbounds":[{"type":"direct","tag":"direct"}]}')).toBe(
      'singbox-json',
    );
  });
});
