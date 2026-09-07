import { describe, expect, test } from 'vitest';
import { classifyClient, detectBodyFormat } from './clientFamilies';

describe('classifyClient', () => {
  test.each([
    ['SFA/1.12.0 (sing-box 1.12.0)', 'singbox', 'singbox-json'],
    ['sing-box 1.13.0', 'singbox', 'singbox-json'],
    ['Karing/1.2', 'singbox', 'singbox-json'],
    ['clash-verge/v2.0.0', 'mihomo', 'clash-yaml'],
    ['mihomo/1.18', 'mihomo', 'clash-yaml'],
    ['Stash/2.5', 'mihomo', 'clash-yaml'],
    ['Happ/1.0', 'happ', 'links'],
    ['HiddifyNext/2.0', 'hiddify', 'links'],
    ['Streisand/1.5', 'streisand', 'links'],
    ['v2rayNG/1.9', 'v2rayng', 'links'],
    ['Shadowrocket/2.2', 'xray-links', 'links'],
    ['curl/8.0', 'other', 'links'],
    ['', 'other', 'links'],
  ])('%s → %s / %s', (ua, family, format) => {
    expect(classifyClient(ua)).toEqual({ family, expectedFormat: format });
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
});
