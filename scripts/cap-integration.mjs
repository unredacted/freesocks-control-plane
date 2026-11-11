// Real Cap + Valkey + the production Caddyfile. No live env files or services.
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import YAML from 'yaml';
import { testMigration } from '../tests/cap/migration.mjs';

process.chdir(new URL('..', import.meta.url).pathname);
const stack = YAML.parse(readFileSync('docker-compose.stack.yml', 'utf8'));
const project = `fcp-cap-test-${process.pid}`;
const targetImage = `${project}:v4`;
const legacy = JSON.parse(readFileSync('tests/cap/legacy.json', 'utf8'));
const env = {
  ...process.env,
  FCP_CAP_TEST_PROJECT: project,
  CAP_TEST_ADMIN_KEY: randomBytes(32).toString('hex'),
  CAP_TEST_IMAGE: legacy.image,
  CAP_TEST_VALKEY_IMAGE: stack.services.valkey.image,
  CAP_TEST_CADDY_IMAGE: readFileSync('docker/web.Dockerfile', 'utf8').match(
    /^FROM (caddy:\S+)/m,
  )[1],
  FCP_CAP_TEST_URL: `http://127.0.0.1:${process.env.FCP_CAP_TEST_PORT || 18340}`,
};
const composeArgs = [
  'compose',
  '--env-file',
  '/dev/null',
  '-p',
  project,
  '-f',
  'docker-compose.cap-test.yml',
];
function run(command, args, options = {}) {
  const result = spawnSync(command, args, { env, stdio: 'inherit', ...options });
  if (result.error || result.status !== 0) throw new Error(`${command} failed (${result.status})`);
  return result.stdout?.toString().trim();
}
const compose = (...args) => run('docker', [...composeArgs, ...args]);
const capture = (...args) =>
  run('docker', [...composeArgs, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
async function ready() {
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      const response = await fetch(`${env.FCP_CAP_TEST_URL}/cap/health`, {
        signal: AbortSignal.timeout(1000),
      });
      if (response.ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error('Cap did not become ready');
}
async function api(path, body, authorization) {
  const response = await fetch(`${env.FCP_CAP_TEST_URL}/cap${path}`, {
    method: body ? 'POST' : 'GET',
    headers: { 'content-type': 'application/json', ...(authorization && { authorization }) },
    ...(body && { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw new Error(`Cap ${path}: HTTP ${response.status}`);
  return response.json();
}
try {
  const build = stack.services.cap.build;
  run('docker', ['build', '-t', targetImage, build.context]);
  run('bun', ['run', 'i18n:compile']);
  run('bunx', ['vite', 'build', '--config', 'tests/cap/vite.config.ts']);
  compose('up', '-d');
  await ready();
  const session = await api('/auth/login', { admin_key: env.CAP_TEST_ADMIN_KEY });
  const authorization = `Bearer ${Buffer.from(JSON.stringify({ token: session.session_token, hash: session.hashed_token })).toString('base64')}`;
  const keys = {};
  for (const protocol of ['hashwx', 'sha256-pow']) {
    keys[protocol] = await api(
      '/server/keys',
      {
        name: `integration-${protocol}`,
        protocol,
        instrumentation: true,
        blockAutomatedBrowsers: false,
        hashwxDifficulty: 50000,
      },
      authorization,
    );
  }
  env.FCP_CAP_TEST_KEYS = JSON.stringify(keys);
  run('bunx', ['playwright', 'test', '--config', 'tests/cap/playwright.config.ts']);
  await testMigration({
    env,
    targetImage,
    compose,
    capture,
    ready,
    api,
    run,
    authorization,
    keys,
    composeArgs,
    healthcheck: stack.services.cap.healthcheck.test.slice(1),
  });
} catch (error) {
  compose('logs', '--tail=30');
  throw error;
} finally {
  // Preserve the original failure if an image pull/build failed before startup.
  spawnSync('docker', [...composeArgs, 'down', '-v', '--remove-orphans'], {
    env,
    stdio: 'inherit',
  });
  spawnSync('docker', ['image', 'rm', targetImage], { env, stdio: 'ignore' });
}
