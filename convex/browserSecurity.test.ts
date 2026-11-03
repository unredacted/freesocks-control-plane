import { describe, expect, test } from 'vitest';
import {
  assertPatchedChromium,
  assertLocalBrowser,
  assertSandboxArguments,
  MIN_CHROMIUM_VERSION,
} from '../tests/compat/browserSecurity';

describe('compatibility browser security', () => {
  test('the container keeps default-deny seccomp and the clone3 fallback needed by glibc', () => {
    const profile = JSON.parse(
      readFileSync(new URL('../docker/compat/seccomp_profile.json', import.meta.url), 'utf8'),
    ) as {
      defaultAction: string;
      syscalls: { names: string[]; action: string; errnoRet?: number }[];
    };
    expect(profile.defaultAction).toBe('SCMP_ACT_ERRNO');
    expect(profile.syscalls).toContainEqual(
      expect.objectContaining({
        names: ['clone3'],
        action: 'SCMP_ACT_ERRNO',
        errnoRet: 38,
      }),
    );
  });

  test('rejects both Playwright and Selenium remote browser overrides', () => {
    expect(() => assertLocalBrowser(undefined)).not.toThrow();
    expect(() => assertLocalBrowser({ wsEndpoint: 'ws://127.0.0.1:9' })).toThrow('local sandboxed');
    expect(() => assertLocalBrowser(undefined, 'http://127.0.0.1:9')).toThrow('local sandboxed');
  });

  test('rejects Playwright bundled builds and versions below the security update', () => {
    for (const version of ['145.0.7632.6', '156.0.8078.4', '156.0.8078.72', '156.0.8077.999']) {
      expect(() => assertPatchedChromium(version), version).toThrow('vulnerable');
    }
  });

  test('accepts the fixed release, newer patch releases and newer Chromium majors', () => {
    for (const version of [MIN_CHROMIUM_VERSION, '156.0.8078.80', '156.0.8079.0', '157.0.0.0']) {
      expect(() => assertPatchedChromium(version), version).not.toThrow();
    }
  });

  test('unrecognized browser versions cannot bypass the minimum', () => {
    for (const version of [
      '',
      'Chromium 156.0.8078.80',
      '156',
      '156.0.8078',
      '156.0.8078.80-beta',
      '999999999999999999999.0.0.0',
    ]) {
      expect(() => assertPatchedChromium(version), version).toThrow('Cannot verify');
    }
  });

  test('rejects sandbox-disabling switches, including boolean-looking values', () => {
    for (const flag of [
      '--no-sandbox',
      '--no-sandbox=false',
      '-no-sandbox',
      '/no-sandbox',
      '--NO-SANDBOX=false',
      '--disable-setuid-sandbox',
      '--disable-namespace-sandbox',
      '--disable-namespace-sandbox=false',
      '-disable-namespace-sandbox',
      '/DISABLE-NAMESPACE-SANDBOX=false',
      '--disable-seccomp-filter-sandbox=true',
      '--disable-gpu-sandbox',
      '--single-process',
      '--in-process-gpu',
    ]) {
      expect(
        () => assertSandboxArguments(['--enable-automation', '--enable-sandbox', flag]),
        flag,
      ).toThrow('sandbox');
    }
    expect(() =>
      assertSandboxArguments(['--enable-automation', '--headless', '--enable-sandbox']),
    ).not.toThrow();
  });
});
import { readFileSync } from 'node:fs';
