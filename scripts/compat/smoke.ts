/** Read-only verification of deployed FCP fronts/mirrors, using a dedicated canary. */
import { mkdtemp, writeFile, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { clients } from '../../tests/compat/manifest';
import { assertSubscription } from '../../tests/compat/assertions';

const targets: Array<{ name: string; url: string }> = JSON.parse(
  process.env.FCP_COMPAT_SMOKE_TARGETS ?? '[]',
);
if (!targets.length)
  throw new Error('Configure FCP_COMPAT_SMOKE_TARGETS with dedicated test subscription URLs');
const results: Array<{ target: string; client: string; status: string }> = [];
let failed = false;
for (const target of targets) {
  const url = new URL(target.url);
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    !/^[a-z0-9-]{1,50}$/.test(target.name)
  )
    throw new Error('Each target needs an HTTPS URL and a non-secret slug name');
  if (process.env.GITHUB_ACTIONS) console.log(`::add-mask::${target.url}`);
  for (const client of clients.filter((c) => c.format !== 'outline')) {
    const dir = await mkdtemp(join(tmpdir(), 'fcp-smoke-'));
    try {
      const response = await fetch(target.url, {
        headers: { 'user-agent': client.userAgents[0]! },
        redirect: 'manual',
        signal: AbortSignal.timeout(20_000),
      });
      if (response.status !== 200) throw new Error('HTTP failure');
      const body = await response.text();
      if (body.length > 4 * 1024 * 1024) throw new Error('Oversize configuration');
      assertSubscription(body, client.format);
      if (
        !response.headers
          .get('vary')
          ?.toLowerCase()
          .split(',')
          .map((x) => x.trim())
          .includes('user-agent') &&
        !response.headers.get('cache-control')?.includes('no-store')
      )
        throw new Error('Unsafe shared-cache response');
      if (client.format === 'singbox' || client.format === 'mihomo') {
        const path = join(dir, 'config');
        await writeFile(path, body, { mode: 0o600 });
        const binary = `.cache/compat/bin/${client.format === 'singbox' ? 'sing-box' : 'mihomo'}`;
        execFileSync(
          binary,
          client.format === 'singbox' ? ['check', '-c', path] : ['-t', '-f', path],
          { stdio: 'pipe', timeout: 30_000 },
        );
      }
      results.push({ target: target.name, client: client.name, status: 'passed' });
    } catch {
      failed = true;
      results.push({ target: target.name, client: client.name, status: 'failed' });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
}
await mkdir('test-results/compat', { recursive: true });
await writeFile(
  'test-results/compat/deployed.json',
  JSON.stringify({ scope: 'deployed-format-and-native-validation', results }, null, 2),
);
for (const result of results) console.log(`${result.target}: ${result.client}: ${result.status}`);
process.exitCode = failed ? 1 : 0;
