import { afterEach, expect, test, vi } from 'vitest';
import { outlineIssue } from './outline';

const cfg = { apiUrl: 'https://outline.test/secretpath/' };

/** Mock the Outline Manager POST /access-keys to return `key` as JSON. */
function stubCreateKey(key: Record<string, unknown>) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(JSON.stringify(key), { status: 200 })),
  );
}

afterEach(() => vi.unstubAllGlobals());

// Bug 15: a WSS / dynamic-config key may come back without an inline ss:// URL.
// The schema must not reject it at parse time, and issuance must fail with a
// clear message rather than handing back an empty subscription URL.
test('a key without accessUrl fails issuance with a clear WSS error', async () => {
  stubCreateKey({ id: 'k1' }); // no accessUrl
  await expect(outlineIssue(cfg, { username: 'u', trafficLimitBytes: null })).rejects.toThrow(
    /accessUrl|WSS/i,
  );
});

test('a normal key with accessUrl issues fine', async () => {
  stubCreateKey({ id: 'k2', accessUrl: 'ss://deadbeef@host:443' });
  const issued = await outlineIssue(cfg, { username: 'u', trafficLimitBytes: null });
  expect(issued.subscriptionUrl).toBe('ss://deadbeef@host:443');
  expect(issued.backendUserId).toBe('k2');
});
