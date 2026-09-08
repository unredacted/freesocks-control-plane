import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile, chmod } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { resolve, join } from 'node:path';
import { artifacts } from '../../tests/compat/manifest';

const root = resolve('.cache/compat/bin');
await mkdir(root, { recursive: true });
const resolved: Record<string, { repo: string; version: string; asset: string; sha256: string }> =
  structuredClone(artifacts);
if (process.env.FCP_COMPAT_CHANNEL === 'latest') {
  for (const [id, artifact] of Object.entries(resolved)) {
    const response = await fetch(`https://api.github.com/repos/${artifact.repo}/releases/latest`, {
      headers: {
        accept: 'application/vnd.github+json',
        ...(process.env.GITHUB_TOKEN
          ? { authorization: `Bearer ${process.env.GITHUB_TOKEN}` }
          : {}),
      },
      signal: AbortSignal.timeout(30_000),
    });
    if (!response.ok) throw new Error(`${id}: release discovery HTTP ${response.status}`);
    const release = await response.json();
    const version = String(release.tag_name).replace(/^v/, '');
    if (!/^\d+\.\d+\.\d+$/.test(version))
      throw new Error(`${id}: unexpected stable release version`);
    const name =
      id === 'singbox'
        ? `sing-box-${version}-linux-amd64.tar.gz`
        : id === 'sfl'
          ? `SFL-${version}-amd64.deb`
          : `mihomo-linux-amd64-v${version}.gz`;
    const asset = release.assets.find((a: { name: string }) => a.name === name);
    if (!/^sha256:[a-f0-9]{64}$/.test(asset?.digest ?? ''))
      throw new Error(`${id}: upstream asset lacks a SHA-256 digest`);
    resolved[id] = { ...artifact, version, asset: name, sha256: asset.digest.slice(7) };
  }
}
for (const [id, artifact] of Object.entries(resolved)) {
  const dest = join(root, artifact.asset);
  let bytes: Buffer;
  try {
    bytes = await readFile(dest);
  } catch {
    bytes = Buffer.alloc(0);
  }
  if (createHash('sha256').update(bytes).digest('hex') !== artifact.sha256) {
    const response = await fetch(
      `https://github.com/${artifact.repo}/releases/download/v${artifact.version}/${artifact.asset}`,
      { signal: AbortSignal.timeout(120_000) },
    );
    if (!response.ok) throw new Error(`${id}: download HTTP ${response.status}`);
    bytes = Buffer.from(await response.arrayBuffer());
    if (createHash('sha256').update(bytes).digest('hex') !== artifact.sha256)
      throw new Error(`${id}: checksum mismatch`);
    await writeFile(dest, bytes);
  }
  if (id === 'singbox') {
    execFileSync('tar', ['-xzf', dest, '-C', root]);
    await writeFile(
      join(root, 'sing-box'),
      await readFile(join(root, `sing-box-${artifact.version}-linux-amd64/sing-box`)),
    );
    await chmod(join(root, 'sing-box'), 0o755);
  } else if (id === 'mihomo') {
    const { gunzipSync } = await import('node:zlib');
    await writeFile(join(root, 'mihomo'), gunzipSync(bytes), { mode: 0o755 });
  }
  if (id === 'sfl') await writeFile(join(root, 'sfl.deb'), bytes);
  console.log(`${id}: verified ${artifact.version}`);
}

await writeFile(
  resolve('.cache/compat/resolved-artifacts.json'),
  JSON.stringify(resolved, null, 2),
);
