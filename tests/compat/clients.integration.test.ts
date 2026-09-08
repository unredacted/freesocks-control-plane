/// <reference types="vite/client" />
import { beforeAll, describe, expect, test } from 'vitest';
import { convexTest } from 'convex-test';
import { writeFileSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { spawn, execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import schema from '../../convex/schema';
import { clients } from './manifest';
import { assertSubscription } from './assertions';
import { docker, seedPanel } from './panel';

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

async function subscription(ua: string) {
  const response = await t.fetch(`/api/v1/sub/${token}`, { headers: { 'user-agent': ua } });
  expect(response.status).toBe(200);
  expect(response.headers.get('vary')?.toLowerCase()).toBe('user-agent');
  return await response.text();
}

describe('real panel → FCP HTTP handler → client format (Convex test runtime)', () => {
  for (const client of clients.filter((c) => c.format !== 'outline')) {
    for (const ua of client.userAgents) {
      test(`${client.name}: ${ua}`, async () => {
        const body = await subscription(ua);
        assertSubscription(body, client.format);
        // An immediate repeat is a fresh-cache hit for this UA and must be byte-identical.
        expect(await subscription(ua)).toBe(body);
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
    assertSubscription(first, 'singbox');
    assertSubscription(await subscription(byFormat('mihomo')), 'mihomo');
    assertSubscription(await subscription(byFormat('links')), 'links');
    const cache = await t.run(
      async (ctx) => (await ctx.db.query('subscriptions').first())!.subCache,
    );
    expect(cache).toBeTruthy();
    expect((JSON.parse(cache!) as Array<{ ua: string }>).map((e) => e.ua)).toEqual(
      expect.arrayContaining([singbox, byFormat('mihomo'), byFormat('links')]),
    );
    const again = await subscription(singbox);
    assertSubscription(again, 'singbox');
    expect(again).toBe(first);
    assertSubscription(await subscription(byFormat('mihomo')), 'mihomo');
  });
  test('unknown subscription is rejected', async () => {
    expect((await t.fetch('/api/v1/sub/unknown')).status).toBe(404);
  });
  test('refresh after upstream Host change delivers the new endpoint', async () => {
    const hosts = await panel.api('hosts');
    const host = (hosts.hosts ?? hosts)[0];
    await panel.api('hosts', 'PATCH', { uuid: host.uuid, remark: 'compat-node-refreshed' });
    await t.run(async (ctx) => {
      const sub = await ctx.db.query('subscriptions').first();
      await ctx.db.patch(sub!._id, { subCache: undefined });
    });
    const body = await subscription(clients[0]!.userAgents[0]!);
    assertSubscription(body, 'singbox');
    expect(body.includes('compat-node-refreshed')).toBe(true);
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
function httpsProbe() {
  const nonce = randomUUID();
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
        await startEngine(engine, await subscription(ua));
        httpsProbe();
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
  test('wrong VLESS credential cannot pass through a direct fallback', async () => {
    const config = JSON.parse(await subscription(clients[0]!.userAgents[0]!));
    for (const outbound of config.outbounds)
      if (outbound.type === 'vless') outbound.uuid = randomUUID();
    try {
      await startEngine('singbox', JSON.stringify(config));
      expect(httpsProbe).toThrow();
    } finally {
      stopEngine();
    }
  });
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
