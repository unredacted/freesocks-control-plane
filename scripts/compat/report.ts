import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { clients, artifacts } from '../../tests/compat/manifest';

const reports = [];
for (const name of ['integration', 'browser']) {
  try {
    const xml = await readFile(`test-results/compat/${name}.xml`, 'utf8');
    const cases = [...xml.matchAll(/<testcase\b([^>]*?)(?:\/>|>([\s\S]*?)<\/testcase>)/g)].map(
      (m) => ({
        name: /\bname="([^"]*)"/.exec(m[1]!)?.[1] ?? 'unnamed',
        status: /<(?:failure|error)\b/.test(m[2] ?? '')
          ? 'failed'
          : /<skipped\b/.test(m[2] ?? '')
            ? 'skipped'
            : 'passed',
      }),
    );
    reports.push({ suite: name, cases });
  } catch {
    reports.push({ suite: name, status: 'not-run' });
  }
}
let resolved = artifacts;
try {
  resolved = JSON.parse(await readFile('.cache/compat/resolved-artifacts.json', 'utf8'));
} catch {
  /* failed before download */
}
await mkdir('test-results/compat/public', { recursive: true });
await writeFile(
  'test-results/compat/public/coverage.json',
  JSON.stringify(
    {
      generatedAt: new Date().toISOString(),
      commit: process.env.GITHUB_SHA ?? null,
      artifacts: resolved,
      reports,
      limitations: clients.map((c) => ({
        client: c.name,
        applicationCoverage: c.application,
        limitation: c.limitation,
      })),
    },
    null,
    2,
  ),
);
const markdown = [
  '| Client | Format | Application coverage |',
  '| --- | --- | --- |',
  ...clients.map(
    (c) =>
      `| ${c.name} | ${c.format} | ${c.application === 'automated-sfl' ? 'SFL import/refresh; see run result' : 'Manual verification required'} |`,
  ),
].join('\n');
await writeFile('test-results/compat/public/coverage.md', markdown + '\n');
if (process.env.GITHUB_STEP_SUMMARY) {
  const { appendFile } = await import('node:fs/promises');
  await appendFile(process.env.GITHUB_STEP_SUMMARY, markdown + '\n');
}
