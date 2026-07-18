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

test('a failed data-limit THROWS (no silent unlimited key; the saga compensates)', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL) => {
      const u = String(input);
      if (u.includes('/data-limit')) return new Response('boom', { status: 500 });
      return new Response(JSON.stringify({ id: 'k3', accessUrl: 'ss://aa@h:1' }), { status: 200 });
    }),
  );
  await expect(
    outlineIssue(cfg, { username: 'u', trafficLimitBytes: 50 * 1024 ** 3 }),
  ).rejects.toThrow(/data-limit|setDataLimit/i);
});

test('a successful data-limit applies (PUT to the key endpoint)', async () => {
  const calls: string[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL) => {
      const u = String(input);
      calls.push(u);
      if (u.includes('/data-limit')) return new Response('{}', { status: 200 });
      return new Response(JSON.stringify({ id: 'k4', accessUrl: 'ss://aa@h:1' }), { status: 200 });
    }),
  );
  const issued = await outlineIssue(cfg, { username: 'u', trafficLimitBytes: 12345 });
  expect(issued.backendUserId).toBe('k4');
  expect(calls.some((u) => u.includes('/access-keys/k4/data-limit'))).toBe(true);
});
