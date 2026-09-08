// @vitest-environment node
import { describe, expect, test } from 'vitest';
import { clients, artifacts } from '../tests/compat/manifest';
import { assertSubscription } from '../tests/compat/assertions';
import { DEFAULT_CLIENTS } from './lib/clientCatalog';

describe('client compatibility coverage', () => {
  test('every enabled recommendation has an explicit coverage entry', () => {
    expect(clients.map((c) => c.name).sort()).toEqual(
      DEFAULT_CLIENTS.filter((c) => c.enabled)
        .map((c) => c.name)
        .sort(),
    );
    expect(new Set(clients.map((c) => c.name)).size).toBe(clients.length);
    for (const client of clients) expect(client.limitation.length).toBeGreaterThan(15);
    for (const artifact of Object.values(artifacts))
      expect(artifact.sha256).toMatch(/^[a-f0-9]{64}$/);
  });
  test('base64 VLESS input cannot pass as sing-box JSON', () => {
    const body = Buffer.from(
      'vless://00000000-0000-4000-8000-000000000000@example.test:443',
    ).toString('base64');
    expect(() => assertSubscription(body, 'singbox')).toThrow('non-JSON');
    expect(() => assertSubscription(body, 'links')).not.toThrow();
  });
  test('empty configurations and HTTP error pages cannot produce a pass', () => {
    for (const body of ['{}', '{"outbounds":[]}', 'denied', '<html>error</html>', '']) {
      for (const format of ['singbox', 'mihomo', 'links'] as const)
        expect(() => assertSubscription(body, format)).toThrow();
    }
  });
});
