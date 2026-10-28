/// <reference types="vite/client" />
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { convexTest } from 'convex-test';
import { writeFileSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { spawn, execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import YAML from 'yaml';
import schema from '../../convex/schema';
import { defaultRouteFaults } from '../../convex/lib/backend/subscriptionTemplates/defaultRoute';
import { clients } from './manifest';
import { assertSubscription, subscriptionEntries } from './assertions';
import { COMPAT_ENDPOINTS } from './fixture';
import { COMPAT_NODE, COMPAT_REMARK, docker, seedPanel, useTemplates } from './panel';
import { routing, sandboxed, selectProxy } from './sandbox';

const modules = import.meta.glob('../../convex/**/*.*s');
const t = convexTest(schema, modules);
let panel: Awaited<ReturnType<typeof seedPanel>>;
const token = 'compat_subscription_capability';

beforeAll(async () => {
  panel = await seedPanel();
  await t.run(async (ctx) => {
    // Every fetch below is charged to ONE token's `subscription.fetch.token`
    // bucket (default 60/min, enforced before the cache lookup). The suite
    // issues ~50 per run and grows with the manifest, so lift the cap here;
    // a 429 would otherwise surface as a bogus format regression.
    await ctx.db.insert('appSettings', {
      key: 'ratelimit.subscription.fetch.token',
      value: JSON.stringify({ max: 100_000, windowMs: 60_000, enabled: true }),
      updatedAt: Date.now(),
    });
    const server = await ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'Compatibility',
      slug: 'compat',
      config: { type: 'remnawave', baseUrl: panel.cfg.baseUrl, apiToken: panel.cfg.apiToken },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: Date.now(),
    });
    const tierId = await ctx.db.insert('tiers', {
      slug: 'compat',
      name: 'Compatibility',
      backend: 'remnawave',
      monthlyTrafficGb: 1,
      deviceLimit: 0,
      trafficStrategy: 'MONTH',
      hwidLimit: 0,
      hwidEnabled: false,
      isDefaultFree: true,
      isActive: true,
      priority: 0,
      expirationDaysAfterMembershipLapse: 0,
      updatedAt: Date.now(),
    });
    const userId = await ctx.db.insert('users', {
      tierId,
      status: 'active',
      supportId: 'COMPAT',
      updatedAt: Date.now(),
    });
    const subId = await ctx.db.insert('subscriptions', {
      userId,
      backend: 'remnawave',
      backendServerId: server,
      backendUserId: panel.issued.backendUserId,
      backendShortId: panel.issued.backendShortId,
      subscriptionUrl: panel.issued.subscriptionUrl,
      subscriptionMirrors: [],
      subToken: token,
      state: 'active',
      updatedAt: Date.now(),
    });
    await ctx.db.patch(userId, { currentSubscriptionId: subId });
  });
});

/** The body as a member's app reads it (a link list may be base64-wrapped). */
function readable(body: string): string {
  const t = body.trim();
  return /^[a-z0-9]+:\/\//i.test(t) || t.startsWith('{') || /^proxies:/m.test(t)
    ? body
    : Buffer.from(t, 'base64').toString('utf8');
}

/** The panel's remark names the node and its template group the backend product; the member gets neutral names instead. */
function expectMemberNames(body: string, format: string): void {
  expect(readable(body)).not.toContain(COMPAT_NODE);
  expect(readable(body)).toContain('FreeSocks');
  expect(readable(body)).not.toMatch(/remnawave/i);
  if (format === 'singbox' || format === 'mihomo')
    expect(readable(body)).toContain('FreeSocks Select');
}

async function subscription(ua: string) {
  const response = await t.fetch(`/api/v1/sub/${token}`, { headers: { 'user-agent': ua } });
  expect(response.status).toBe(200);
  expect(response.headers.get('vary')?.toLowerCase()).toBe('user-agent');
  // The panel's page URL is the key's raw panel subscription URL.
  expect(response.headers.get('profile-web-page-url')).toBeNull();
  // Every answer carries the validator an app revalidates with.
  expect(response.headers.get('etag')).toMatch(/^W\/"fs1-[A-Za-z0-9_-]{22}"$/);
  return await response.text();
}

/** Drop every cached body: the next fetch asks the panel again. */
const clearSubCache = () =>
  t.run(async (ctx) => {
    const sub = await ctx.db.query('subscriptions').first();
    await ctx.db.patch(sub!._id, { subCache: undefined });
  });

/** Revalidate with the tag the last answer carried: nothing changed, so a 304 with no body. */
async function revalidated(ua: string): Promise<void> {
  const first = await t.fetch(`/api/v1/sub/${token}`, { headers: { 'user-agent': ua } });
  const tag = first.headers.get('etag')!;
  const again = await t.fetch(`/api/v1/sub/${token}`, {
    headers: { 'user-agent': ua, 'if-none-match': tag },
  });
  expect(again.status).toBe(304);
  expect(await again.text()).toBe('');
  expect(again.headers.get('etag')).toBe(tag);
}

describe('real panel → FCP HTTP handler → client format (Convex test runtime)', () => {
  for (const client of clients.filter((c) => c.format !== 'outline')) {
    for (const ua of client.userAgents) {
      test(`${client.name}: ${ua}`, async () => {
        const body = await subscription(ua);
        assertSubscription(body, client.format, COMPAT_ENDPOINTS);
        expectMemberNames(body, client.format);
        // An immediate repeat is a fresh-cache hit for this UA and must be byte-identical.
        expect(await subscription(ua)).toBe(body);
        await revalidated(ua);
      });
    }
  }
  test('a fresh cache entry is served only to its own User-Agent', async () => {
    // The per-sub cache keeps the newest SUB_CACHE_MAX entries, newest first,
    // and a hit is a lookup by exact UA. Prime one entry per format, then
    // re-request the OLDEST (sing-box) while a links body is the newest entry:
    // a lookup that ignored the UA would hand sing-box the links body.
    const byFormat = (format: string) => clients.find((c) => c.format === format)!.userAgents[0]!;
    const singbox = byFormat('singbox');
    const first = await subscription(singbox);
    assertSubscription(first, 'singbox', COMPAT_ENDPOINTS);
    assertSubscription(await subscription(byFormat('mihomo')), 'mihomo', COMPAT_ENDPOINTS);
    assertSubscription(await subscription(byFormat('links')), 'links', COMPAT_ENDPOINTS);
    const cache = await t.run(
      async (ctx) => (await ctx.db.query('subscriptions').first())!.subCache,
    );
    expect(cache).toBeTruthy();
    expect((JSON.parse(cache!) as Array<{ ua: string }>).map((e) => e.ua)).toEqual(
      expect.arrayContaining([singbox, byFormat('mihomo'), byFormat('links')]),
    );
    const again = await subscription(singbox);
    assertSubscription(again, 'singbox', COMPAT_ENDPOINTS);
    expect(again).toBe(first);
    assertSubscription(await subscription(byFormat('mihomo')), 'mihomo', COMPAT_ENDPOINTS);
  });
  test('unknown subscription is rejected', async () => {
    expect((await t.fetch('/api/v1/sub/unknown')).status).toBe(404);
  });
  test('every catalogued User-Agent refreshes all three endpoints after an upstream Host change', async () => {
    const hosts = await panel.api('hosts');
    const host = (hosts.hosts ?? hosts).find((h: { remark: string }) => h.remark === COMPAT_REMARK);
    if (!host) throw new Error('Missing refresh fixture Host');
    const cases = clients
      .filter((c) => c.format !== 'outline')
      .flatMap((client) => client.userAgents.map((ua) => ({ ua, format: client.format })));
    // Fetch every UA before the change; the bounded cache retains the newest.
    for (const { ua, format } of cases)
      assertSubscription(await subscription(ua), format, COMPAT_ENDPOINTS);
    await panel.api('hosts', 'PATCH', { uuid: host.uuid, address: 'compat-refreshed' });
    try {
      await clearSubCache();
      const refreshed = COMPAT_ENDPOINTS.map((e) => ({
        ...e,
        server: e.port === 443 ? 'compat-refreshed' : e.server,
      }));
      for (const { ua, format } of cases) {
        const body = await subscription(ua);
        assertSubscription(body, format, refreshed);
        expect(await subscription(ua)).toBe(body);
        await revalidated(ua);
      }
    } finally {
      await panel.api('hosts', 'PATCH', { uuid: host.uuid, address: COMPAT_ENDPOINTS[0].server });
      await clearSubCache();
    }
  });
});

function stopEngine() {
  try {
    docker('exec', 'compat-client', 'pkill', '-x', 'sing-box');
  } catch {
    /* not running */
  }
  try {
    docker('exec', 'compat-client', 'pkill', '-x', 'mihomo');
  } catch {
    /* not running */
  }
}
async function startEngine(engine: 'singbox' | 'mihomo', body: string) {
  stopEngine();
  const file = engine === 'singbox' ? 'client.json' : 'client.yaml';
  writeFileSync(`.cache/compat/runtime/${file}`, body);
  const binary = engine === 'singbox' ? 'sing-box' : 'mihomo';
  const check =
    engine === 'singbox' ? ['check', '-c', `/work/${file}`] : ['-t', '-f', `/work/${file}`];
  docker('exec', 'compat-client', binary, ...check);
  docker(
    'exec',
    '-d',
    'compat-client',
    binary,
    ...(engine === 'singbox' ? ['run', '-c', `/work/${file}`] : ['-f', `/work/${file}`]),
  );
  // Poll the SOCKS listener itself, not a public website.
  for (let i = 0; i < 30; i++) {
    try {
      docker(
        'exec',
        'compat-client',
        'python3',
        '-c',
        'import socket; socket.create_connection(("127.0.0.1",1080),1).close()',
      );
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 200));
    }
  }
  throw new Error(`${engine}: SOCKS listener never became ready`);
}
// curl exit codes that say the tunnel dropped or never answered THIS attempt
// rather than answering wrongly: 7 could not connect, 28 timed out, 35 TLS
// handshake broke (including "Send failure: Broken pipe"), 56 receive failed.
const TRANSIENT_CURL_EXITS = new Set([7, 28, 35, 56]);
const PROBE_BACKOFF_MS = [250, 500, 1000];
const PROBE_BUDGET_MS = 15_000;

/**
 * HTTPS to a fresh nonce on the isolated origin through the engine's SOCKS
 * listener. Retried a few times on transient curl failures only.
 *
 * The listener accepting TCP (startEngine's poll) is not the engine being
 * ready to proxy. mihomo binds its listeners inside hub/executor ApplyConfig
 * before `tunnel.OnRunning()`; a connection handed to the tunnel in that window
 * completes the SOCKS handshake and is then closed by `tunnel.isHandle`, which
 * curl reports as exit 35 "Send failure: Broken pipe". sing-box starts its
 * inbounds last, so only mihomo showed this. A wrong credential or a broken
 * REALITY handshake fails every attempt, so the budget stays tight and the
 * wrong-credential test below still fails closed.
 */
async function httpsProbe() {
  const started = Date.now();
  for (let attempt = 0; ; attempt++) {
    const nonce = randomUUID();
    try {
      const result = docker(
        'exec',
        'compat-client',
        'curl',
        '--silent',
        '--show-error',
        '--fail',
        '--max-time',
        '8',
        '--noproxy',
        '',
        '--socks5-hostname',
        '127.0.0.1:1080',
        '--cacert',
        '/work/cert.pem',
        `https://compat-origin:8443/${nonce}`,
      );
      expect(JSON.parse(result)).toMatchObject({ nonce, via: 'isolated-origin' });
      return;
    } catch (error) {
      const status = (error as { status?: unknown }).status;
      const backoff = PROBE_BACKOFF_MS[attempt];
      if (
        backoff === undefined ||
        typeof status !== 'number' ||
        !TRANSIENT_CURL_EXITS.has(status) ||
        Date.now() - started > PROBE_BUDGET_MS
      )
        throw error;
      await new Promise((r) => setTimeout(r, backoff));
    }
  }
}

describe('reference engines: real panel-generated REALITY connections', () => {
  test('origin cannot be reached directly from the client network', () => {
    expect(() =>
      docker(
        'exec',
        'compat-client',
        'curl',
        '--fail',
        '--silent',
        '--max-time',
        '3',
        '--noproxy',
        '*',
        '--cacert',
        '/work/cert.pem',
        'https://compat-origin:8443/direct',
      ),
    ).toThrow();
  });
  for (const [engine, ua] of [
    ['singbox', clients[0]!.userAgents[0]!],
    ['mihomo', 'mihomo/1.19.30'],
  ] as const) {
    test(`${engine}: native config validation, REALITY, remote DNS, HTTPS and UDP DNS`, async () => {
      try {
        const body = await subscription(ua);
        expectMemberNames(body, engine);
        await startEngine(engine, body);
        await httpsProbe();
        expect(
          docker(
            'exec',
            'compat-client',
            'python3',
            '/probe.py',
            docker('exec', 'compat-proxy', 'getent', 'ahostsv4', 'compat-origin')
              .trim()
              .split(/\s+/)[0]!,
          ).trim(),
        ).toBe('UDP_DNS_OK');
      } finally {
        stopEngine();
      }
    });
  }
  for (const engine of ['singbox', 'mihomo'] as const) {
    test(`${engine}: wrong VLESS credentials cannot pass through a fallback`, async () => {
      const ua = clients.find((c) => c.format === engine)!.userAgents[0]!;
      const body = await subscription(ua);
      const config = engine === 'singbox' ? JSON.parse(body) : YAML.parse(body);
      for (const outbound of engine === 'singbox' ? config.outbounds : config.proxies)
        if (outbound.type === 'vless') outbound.uuid = randomUUID();
      try {
        await startEngine(
          engine,
          engine === 'singbox' ? JSON.stringify(config) : YAML.stringify(config),
        );
        await expect(httpsProbe()).rejects.toThrow();
      } finally {
        stopEngine();
      }
    });
  }
});

/**
 * The checks above run on test-owned templates; these run on the ones FCP
 * installs on every panel, as a member's client receives them, changed only to
 * run in the container (./sandbox.ts). The origin answers only through the
 * proxy, so reaching it proves the body's own default route (Mihomo's mode and
 * final rule, sing-box's default outbound) takes the proxy: a body that sends
 * unmatched traffic direct, as `mode: global` did, fails here.
 */
describe('the templates FCP ships: a member reaches the origin through the proxy by default', () => {
  beforeAll(async () => {
    await useTemplates(panel.api, 'shipped');
    await clearSubCache();
  });
  afterAll(async () => {
    await useTemplates(panel.api, 'fixture');
    await clearSubCache();
  });
  test('the legacy Clash body routes by rule to the proxy group as the panel serves it', async () => {
    // Any other `clash…` User-Agent gets the panel's CLASH template. Legacy
    // Clash has no VLESS, so the panel leaves this stack's one entry out and no
    // engine can run the body; its routing is still the template's.
    const body = await subscription('ClashForWindows/0.20.39');
    expect((YAML.parse(body) as { mode?: unknown }).mode).toBe('rule');
    expect(defaultRouteFaults(body, 'FreeSocks Select')).toEqual([]);
  });
  for (const client of clients.filter((c) => c.format === 'singbox' || c.format === 'mihomo')) {
    for (const ua of client.userAgents) {
      const engine = client.format as 'singbox' | 'mihomo';
      test(`${client.name} (${ua}): default routing and each of three proxies carry HTTPS`, async () => {
        try {
          const body = await subscription(ua);
          assertSubscription(body, engine, COMPAT_ENDPOINTS);
          expectMemberNames(body, engine);
          expect(defaultRouteFaults(body, 'FreeSocks Select')).toEqual([]);
          const config = sandboxed(engine, body);
          expect(routing(engine, config)).toEqual(routing(engine, body));
          await startEngine(engine, config);
          await httpsProbe();
          for (const entry of subscriptionEntries(body, engine)) {
            // Keep the served endpoints; narrow the selector to one choice so a
            // good default cannot hide a broken secondary endpoint.
            await startEngine(engine, selectProxy(engine, config, entry.name));
            await httpsProbe();
          }
        } finally {
          stopEngine();
        }
      });
    }
  }
});

// Budget: the driver alone allows 30s (DevTools endpoint) + 30s (main window) +
// 30s per Playwright action; the container path adds image start, `bun build`,
// the daemon socket wait and Electron boot. Cold/Rosetta runners need headroom.
const SFL_KILL_AFTER_MS = 240_000;
test(
  'SFL 1.14.0 package: deep link, manual URL entry, native import and refresh',
  async () => {
    const requests: string[] = [];
    const server = createServer(async (req, res) => {
      if (req.url !== `/api/v1/sub/${token}`) {
        res.writeHead(404).end();
        return;
      }
      const ua = req.headers['user-agent'] ?? '';
      requests.push(ua);
      try {
        const response = await t.fetch(req.url, { headers: { 'user-agent': ua } });
        res.writeHead(response.status, Object.fromEntries(response.headers));
        res.end(await response.text());
      } catch {
        res.writeHead(500).end();
      }
    });
    await new Promise<void>((resolve) => server.listen(4179, '0.0.0.0', resolve));
    try {
      const executable = process.env.FCP_COMPAT_SFL_EXECUTABLE;
      const localUrl = `http://${executable ? '127.0.0.1' : 'host.docker.internal'}:4179/api/v1/sub/${token}`;
      const containerName = `fcp-compat-sfl-${randomUUID().slice(0, 8)}`;
      const args = executable
        ? ['--no-env-file', 'tests/compat/sfl.ts']
        : [
            'run',
            '--rm',
            '--name',
            containerName,
            '--platform',
            'linux/amd64',
            '--add-host',
            'host.docker.internal:host-gateway',
            '-v',
            `${resolve('tests/compat')}:/repo/tests/compat:ro`,
            '-v',
            `${resolve('src/client/lib/appLinks.ts')}:/repo/src/client/lib/appLinks.ts:ro`,
            '-v',
            `${resolve('node_modules')}:/repo/node_modules:ro`,
            '-v',
            `${resolve('.cache/compat/resolved-artifacts.json')}:/repo/.cache/compat/resolved-artifacts.json:ro`,
            '-v',
            `${resolve('.cache/compat/runtime')}:/repo/.cache/compat/runtime`,
            '-v',
            `${resolve('test-results')}:/repo/test-results`,
            '-e',
            `FCP_COMPAT_SUB_URL=${localUrl}`,
            'fcp-compat-desktop:local',
            // Starts the app's own daemon (no systemd in the container), then Xvfb + the driver.
            'sfl-entrypoint',
          ];
      // Asynchronous child: the host event loop must serve the app's real HTTP fetches.
      await new Promise<void>((resolve, reject) => {
        const child = spawn(executable ? 'bun' : 'docker', args, {
          env: { ...process.env, FCP_COMPAT_SUB_URL: localUrl },
          stdio: ['ignore', 'pipe', 'pipe'],
        });
        const timer = setTimeout(() => {
          if (!executable) {
            try {
              execFileSync('docker', ['rm', '-f', containerName], {
                stdio: 'ignore',
                timeout: 10_000,
              });
            } catch {
              /* already stopped */
            }
          }
          child.kill('SIGKILL');
        }, SFL_KILL_AFTER_MS);
        let output = '';
        child.stdout.on('data', (chunk) => {
          output += String(chunk);
        });
        child.stderr.on('data', (chunk) => {
          output += String(chunk);
        });
        child.on('error', (error) => {
          clearTimeout(timer);
          reject(error);
        });
        child.on('close', (code) => {
          clearTimeout(timer);
          if (code === 0 && output.includes('SFL_IMPORT_REFRESH_OK')) resolve();
          else
            reject(new Error(`Packaged SFL import failed (exit ${code}): ${output.slice(-2500)}`));
        });
      });
      expect(requests.length).toBeGreaterThanOrEqual(2);
      const version = JSON.parse(readFileSync('.cache/compat/resolved-artifacts.json', 'utf8')).sfl
        .version;
      expect(requests.every((ua) => ua.startsWith(`SFL (sing-box ${version}; language `))).toBe(
        true,
      );
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  },
  SFL_KILL_AFTER_MS + 30_000,
);
