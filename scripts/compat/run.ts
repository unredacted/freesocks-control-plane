import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compose } from '../../tests/compat/compose';

const bunVersion = JSON.parse(readFileSync('package.json', 'utf8')).packageManager.split('@')[1];
const root = resolve('.cache/compat/runtime');
mkdirSync(root, { recursive: true });
mkdirSync('test-results/compat', { recursive: true });
// Pass the variable explicitly: a mutation of process.env is not reliably
// inherited by child processes under every runtime.
const env = { ...process.env, FCP_COMPAT_BUN_VERSION: bunVersion };
// On the desktop-VM path the packaged app is installed on the runner itself, so
// the container image that carries it is never used.
const buildDesktopImage = !process.env.FCP_COMPAT_SFL_EXECUTABLE;
const docker = (...args: string[]) =>
  execFileSync('docker', [...compose, ...args], { stdio: 'inherit', env });
let status = 1;
try {
  execFileSync('bun', ['--no-env-file', 'scripts/compat/download.ts'], { stdio: 'inherit' });
  execFileSync(
    'openssl',
    [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      `${root}/key.pem`,
      '-out',
      `${root}/cert.pem`,
      '-days',
      '2',
      '-subj',
      '/CN=compat-origin',
      '-addext',
      'subjectAltName=DNS:compat-origin',
    ],
    { stdio: 'ignore' },
  );
  // Start the panel first: its migrations + healthcheck overlap the image builds.
  // (The compat services start later, from seedPanel, once server.json exists.)
  docker('up', '-d', 'rw-test-proxy');
  docker('build', 'compat-proxy');
  if (buildDesktopImage)
    execFileSync(
      'docker',
      [
        'build',
        '--platform',
        'linux/amd64',
        '-f',
        'docker/compat/desktop.Dockerfile',
        '--build-arg',
        `BUN_VERSION=${bunVersion}`,
        '-t',
        'fcp-compat-desktop:local',
        '.',
      ],
      { stdio: 'inherit' },
    );
  const bootstrap = execFileSync('bun', ['--no-env-file', 'scripts/remnawave-test-bootstrap.mjs'], {
    encoding: 'utf8',
    env: { ...process.env, REMNAWAVE_TEST_URL: 'http://localhost:3000' },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  const token = /^REMNAWAVE_TEST_TOKEN=(.+)$/m.exec(bootstrap)?.[1];
  if (!token || /\s/.test(token)) throw new Error('Test bootstrap returned no API token');
  if (process.env.GITHUB_ACTIONS) console.log(`::add-mask::${token}`);
  const result = spawnSync('bunx', ['vitest', 'run', '--config', 'tests/compat/vitest.config.ts'], {
    stdio: 'inherit',
    env: {
      ...env,
      REMNAWAVE_TEST_URL: 'http://localhost:3000',
      REMNAWAVE_TEST_TOKEN: token,
      FCP_COMPAT_ISOLATED: '1',
      DEV_MOCK_BACKEND: 'false',
      IP_HASH_SALT: 'compat-only',
    },
  });
  status = result.status ?? 1;
} finally {
  // No raw container logs or configs are uploaded: both may contain test credentials.
  try {
    docker('down', '-v', '--remove-orphans');
  } catch {
    status = 1;
  }
}
process.exitCode = status;
