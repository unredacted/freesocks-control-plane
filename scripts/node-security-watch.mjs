#!/usr/bin/env bun
// Node security watch: compare every `FROM node:<version>-<variant>@sha256:<digest>`
// under docker/ with nodejs.org's release index, and re-pin the ones that a newer
// SECURITY release on the same major has left behind.
//
// Dependabot alone is too slow for this: its docker updater runs weekly, and
// GitHub's advisory database has no entries for the Node runtime, so a Node
// security release never triggers a Dependabot security update.
// .github/workflows/node-security-watch.yml runs this every few hours and opens
// the PR.
//
//   bun scripts/node-security-watch.mjs            report only
//   bun scripts/node-security-watch.mjs --apply    also rewrite the stale pins
//     --index <file>           read the release index from a file, not nodejs.org
//     --summary <file>         write a markdown summary (job summary, PR body)
//     --github-output <file>   append changed=, branch=, title= for the workflow
//
// A pin is stale when nodejs.org lists a release with `security: true` on the
// same major that is newer than the pin. The target is the newest release on
// that major (never a new major: that is a person's call), and only once Docker
// Hub serves it under the pin's variant. Until then the pin is reported as
// waiting, and the next run tries again.
import { execFileSync } from 'node:child_process';
import { appendFileSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const INDEX_URL = 'https://nodejs.org/dist/index.json';

const PIN =
  /^(FROM\s+)node:(\d+)\.(\d+)\.(\d+)-([a-z0-9][a-z0-9.-]*)@(sha256:[0-9a-f]{64})((?:\s.*)?)$/i;

export function parseVersion(v) {
  const m = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(String(v));
  return m ? m.slice(1, 4).map(Number) : null;
}

export function cmp(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

export const fmt = (v) => v.join('.');

/**
 * Every `FROM node:` line in a Dockerfile. `pin` is null when the line does not
 * name an exact version and digest (the watcher cannot read a floating tag).
 */
export function nodeFromLines(text) {
  return text.split('\n').flatMap((line, i) => {
    if (!/^FROM\s+node:/i.test(line)) return [];
    const m = PIN.exec(line);
    const pin = m
      ? {
          prefix: m[1],
          version: [Number(m[2]), Number(m[3]), Number(m[4])],
          variant: m[5],
          digest: m[6],
          rest: m[7],
        }
      : null;
    return [{ line: i + 1, text: line, pin }];
  });
}

/**
 * What the release index says about one pinned version: the newer security
 * releases on its major (stale when non-empty) and the newest release there.
 */
export function assess(version, index) {
  const sameMajor = index
    .map((r) => ({ v: parseVersion(r.version), security: r.security === true }))
    .filter((r) => r.v && r.v[0] === version[0]);
  const security = sameMajor
    .filter((r) => r.security && cmp(r.v, version) > 0)
    .map((r) => r.v)
    .sort(cmp);
  const latest = [version, ...sameMajor.map((r) => r.v)].sort(cmp).at(-1);
  return { security, latest };
}

export function renderPin(pin, version, digest) {
  return `${pin.prefix}node:${fmt(version)}-${pin.variant}@${digest}${pin.rest}`;
}

function dockerfiles(root) {
  const out = [];
  const walk = (rel) => {
    for (const e of readdirSync(path.join(root, rel), { withFileTypes: true })) {
      const child = `${rel}/${e.name}`;
      if (e.isDirectory()) walk(child);
      else if (/Dockerfile/.test(e.name)) out.push(child);
    }
  };
  walk('docker');
  return out.sort();
}

function imageDigest(ref) {
  try {
    const out = execFileSync(
      'docker',
      ['buildx', 'imagetools', 'inspect', ref, '--format', '{{.Manifest.Digest}}'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
    ).trim();
    return /^sha256:[0-9a-f]{64}$/.test(out) ? out : null;
  } catch {
    return null;
  }
}

async function main() {
  const args = process.argv.slice(2);
  const opt = (name) => {
    const i = args.indexOf(name);
    return i === -1 ? undefined : args[i + 1];
  };
  const apply = args.includes('--apply');
  const root = fileURLToPath(new URL('..', import.meta.url));

  const indexFile = opt('--index');
  const index = indexFile
    ? JSON.parse(readFileSync(indexFile, 'utf8'))
    : await fetch(INDEX_URL).then((r) => {
        if (!r.ok) throw new Error(`${INDEX_URL} answered ${r.status}`);
        return r.json();
      });

  const rows = [];
  const targets = new Set();
  let changed = false;
  for (const file of dockerfiles(root)) {
    const abs = path.join(root, file);
    const lines = readFileSync(abs, 'utf8').split('\n');
    let fileChanged = false;
    for (const { line, pin } of nodeFromLines(lines.join('\n'))) {
      if (!pin) {
        rows.push({
          file,
          line,
          pinned: '?',
          status: 'not an exact version + digest; cannot check',
        });
        continue;
      }
      const { security, latest } = assess(pin.version, index);
      const row = { file, line, pinned: fmt(pin.version), latest: fmt(latest) };
      if (security.length === 0) {
        rows.push({ ...row, status: 'current' });
        continue;
      }
      row.security = security.map(fmt).join(', ');
      const digest = apply ? imageDigest(`node:${fmt(latest)}-${pin.variant}`) : null;
      if (!apply) {
        rows.push({ ...row, status: `behind a security release; would move to ${fmt(latest)}` });
      } else if (!digest) {
        rows.push({
          ...row,
          status: `waiting: node:${fmt(latest)}-${pin.variant} is not on Docker Hub yet`,
        });
      } else {
        lines[line - 1] = renderPin(pin, latest, digest);
        fileChanged = true;
        targets.add(fmt(latest));
        rows.push({ ...row, status: `re-pinned to ${fmt(latest)}` });
      }
    }
    if (fileChanged) {
      writeFileSync(abs, lines.join('\n'));
      changed = true;
    }
  }

  const list = [...targets].sort((a, b) => cmp(parseVersion(a), parseVersion(b)));
  const title = `chore(docker): Node security release ${list.join(', ')}`;
  const table = rows
    .map(
      (r) =>
        `| \`${r.file}:${r.line}\` | ${r.pinned} | ${r.latest ?? ''} | ${r.security ?? ''} | ${r.status} |`,
    )
    .join('\n');
  const summary = [
    changed
      ? `Re-pins Node to ${list.map((v) => `[${v}](https://github.com/nodejs/node/releases/tag/v${v})`).join(', ')}: a newer **security** release on the same major had left these pins behind.`
      : 'No Node pin was re-pinned in this run.',
    '',
    '| pin | pinned | newest on its major | security releases since | result |',
    '|---|---|---|---|---|',
    table,
    '',
    'Advisories: https://nodejs.org/en/blog/vulnerability',
    '',
  ].join('\n');
  process.stdout.write(summary);

  const summaryFile = opt('--summary');
  if (summaryFile) writeFileSync(summaryFile, summary);
  const outFile = opt('--github-output');
  if (outFile) {
    appendFileSync(
      outFile,
      `changed=${changed}\nbranch=node-security/${list.join('+')}\ntitle=${title}\n`,
    );
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  await main();
}
