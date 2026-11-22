import { describe, expect, test } from 'vitest';
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
    const capable = (ua: string) => classifyClient(ua).encryptionCapable !== false;
    // What its subscription fetch sends.
    expect(capable('HiddifyNext/5.5.5 (android) like ClashMeta v2ray sing-box')).toBe(true);
    expect(capable('HiddifyNext/5.9.15 (windows) like ClashMeta v2ray sing-box')).toBe(true);
    expect(capable('HiddifyNext/6.0 (ios)')).toBe(true);
    expect(capable('Hiddify/5.5.5')).toBe(true);
    for (const old of [
      'HiddifyNext/5.5.4 (android) like ClashMeta v2ray sing-box',
      'HiddifyNext/5.4.0 (android)',
      'HiddifyNext/4.1.1 (macos)',
      'HiddifyNext/2.0',
      'HiddifyNext (android)',
    ])
      expect(capable(old), old).toBe(false);
    // Every family is still its own; only the encryption rule follows the version.
    expect(classifyClient('HiddifyNext/4.1.1 (macos)')).toEqual({
      family: 'hiddify',
      expectedFormat: 'links',
      encryptionCapable: false,
    });
    // No other app is judged by a version.
    for (const ua of [
      'v2rayNG/1.0',
      'clash.meta/1.18.0',
      'Anywhere',
      'SFA/1.11.9 (sing-box 1.11.9)',
    ])
      expect(classifyClient(ua)).not.toHaveProperty('encryptionCapable');
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
