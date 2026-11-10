// Real Cap + Valkey + the production Caddyfile. No live env files or services.
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import YAML from 'yaml';

process.chdir(new URL('..', import.meta.url).pathname);
const stack = YAML.parse(readFileSync('docker-compose.stack.yml', 'utf8'));
const project = `fcp-cap-test-${process.pid}`;
const env = {
  ...process.env,
  FCP_CAP_TEST_PROJECT: project,
  CAP_TEST_ADMIN_KEY: randomBytes(32).toString('hex'),
  CAP_TEST_IMAGE: stack.services.cap.image,
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
  run('bun', ['run', 'i18n:compile']);
  run('bunx', ['vite', 'build', '--config', 'tests/cap/vite.config.ts']);
  compose('up', '-d');
  let ready = false;
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      const response = await fetch(`${env.FCP_CAP_TEST_URL}/cap/health`, {
        signal: AbortSignal.timeout(1000),
      });
      if (response.ok) {
        ready = true;
        break;
      }
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  if (!ready) throw new Error('Cap did not become ready');
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
} catch (error) {
  compose('logs', '--tail=30');
  throw error;
} finally {
  compose('down', '-v', '--remove-orphans');
}
