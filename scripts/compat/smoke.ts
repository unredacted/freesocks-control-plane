/** Read-only verification of deployed FCP fronts/mirrors, using a dedicated canary. */
import { mkdtemp, writeFile, rm, mkdir, access } from 'node:fs/promises';
import { constants } from 'node:fs';
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
// A missing or non-executable engine is a runner defect, not a front failure:
// refuse to run rather than report every target as failed.
for (const binary of ['.cache/compat/bin/sing-box', '.cache/compat/bin/mihomo']) {
  await access(binary, constants.X_OK).catch(() => {
    throw new Error(`${binary} missing or not executable; run scripts/compat/download.ts first`);
  });
}
type Stage = 'fetch' | 'format' | 'cache-headers' | 'native-check';
const results: Array<{ target: string; client: string; status: string; stage?: Stage }> = [];
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
    // Only the stage name is recorded on failure — never the error text, which
    // could carry the response body or the target URL.
    let stage: Stage = 'fetch';
    try {
      const response = await fetch(target.url, {
        headers: { 'user-agent': client.userAgents[0]! },
        redirect: 'manual',
        signal: AbortSignal.timeout(20_000),
      });
      if (response.status !== 200) throw new Error('HTTP failure');
      const body = await response.text();
      if (body.length > 4 * 1024 * 1024) throw new Error('Oversize configuration');
      stage = 'format';
      assertSubscription(body, client.format);
      stage = 'cache-headers';
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
        stage = 'native-check';
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
      results.push({ target: target.name, client: client.name, status: 'failed', stage });
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
for (const result of results)
  console.log(
    `${result.target}: ${result.client}: ${result.status}${result.stage ? ` (${result.stage})` : ''}`,
  );
process.exitCode = failed ? 1 : 0;
