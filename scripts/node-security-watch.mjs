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
//     --schedule <file>        read the release schedule from a file, not GitHub
//     --summary <file>         write a markdown summary (job summary, PR body)
//     --eol <file>             write the majors near or past end of life (JSON)
//     --github-output <file>   append changed=, branch=, title= for the workflow
//
// A pin is stale when nodejs.org lists a release with `security: true` on the
// same major that is newer than the pin. The target is the newest release on
// that major (never a new major: that is a person's call), and only once Docker
// Hub serves it under the pin's variant. Until then the pin is reported as
// waiting, and the next run tries again.
//
// Why the release index and not a vulnerability database: the `security` flag is
// set the moment the release ships. The Node Security WG's database (behind
// nodejs/is-my-node-vulnerable) and NVD-fed image scanners follow days to weeks
// later; the WG database took four weeks to list the July 2026 CVEs.
//
// The flag says nothing once a major reaches end of life: an EOL line gets no
// security releases, so its pins would look current forever. The Release WG's
// schedule closes that gap: a pinned major within EOL_WARN_DAYS of its end is
// written to --eol, and the workflow keeps one issue open per such major.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { appendFileSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const INDEX_URL = 'https://nodejs.org/dist/index.json';
const SCHEDULE_URL = 'https://raw.githubusercontent.com/nodejs/Release/main/schedule.json';
export const EOL_WARN_DAYS = 90;

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

/**
 * Days until a major's end of life per the Release WG schedule (negative once
 * past), or null when the schedule does not list the major.
 */
export function endOfLife(major, schedule, now) {
  const end = schedule?.[`v${major}`]?.end;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(end ?? '')) return null;
  const days = Math.floor((Date.parse(`${end}T00:00:00Z`) - now.getTime()) / 86_400_000);
  return { end, days };
}

/**
 * The PR branch for one run's re-pins. It names the target versions and hashes
 * the exact set of rewritten refs: the workflow skips a branch whose PR exists
 * in any state, so a run that re-pins more (say, the pin a failed lookup left
 * behind last time) must land on a new branch, not on the old PR's name.
 */
export function branchName(targets, changes) {
  const set = [...new Set(changes)].sort().join('\n');
  const hash = createHash('sha256').update(set).digest('hex').slice(0, 8);
  return `node-security/${targets.join('+')}-${hash}`;
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

  const load = async (file, url) =>
    file
      ? JSON.parse(readFileSync(file, 'utf8'))
      : fetch(url).then((r) => {
          if (!r.ok) throw new Error(`${url} answered ${r.status}`);
          return r.json();
        });
  const index = await load(opt('--index'), INDEX_URL);
  // The schedule only feeds the end-of-life warning; never let it block a re-pin.
  let schedule = null;
  try {
    schedule = await load(opt('--schedule'), SCHEDULE_URL);
  } catch (e) {
    console.error(`node-security-watch: release schedule unavailable (${e.message})`);
  }
  const now = new Date();

  // One lookup per ref per run, so every pin moving to the same image moves
  // together: a transient registry failure cannot split them across PRs.
  const digests = new Map();
  const digestOf = (ref) => {
    if (!digests.has(ref)) digests.set(ref, imageDigest(ref));
    return digests.get(ref);
  };

  const rows = [];
  const targets = new Set();
  const changes = [];
  const eol = new Map(); // major -> { end, days, pins }
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
      const life = endOfLife(pin.version[0], schedule, now);
      if (life && life.days <= EOL_WARN_DAYS) {
        const entry = eol.get(pin.version[0]) ?? { ...life, pins: [] };
        entry.pins.push(`${file}:${line}`);
        eol.set(pin.version[0], entry);
      }
      if (security.length === 0) {
        rows.push({ ...row, status: 'current' });
        continue;
      }
      row.security = security.map(fmt).join(', ');
      const ref = `node:${fmt(latest)}-${pin.variant}`;
      const digest = apply ? digestOf(ref) : null;
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
        changes.push(`${file}=${ref}@${digest}`);
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
    ...[...eol].map(
      ([major, e]) =>
        `**Node ${major} ${e.days < 0 ? 'reached' : 'reaches'} end of life on ${e.end}**: no security releases after that, so this watcher cannot see its fixes. Pinned at ${e.pins.map((p) => `\`${p}\``).join(', ')}.\n`,
    ),
  ].join('\n');
  process.stdout.write(summary);

  const summaryFile = opt('--summary');
  if (summaryFile) writeFileSync(summaryFile, summary);
  const eolFile = opt('--eol');
  if (eolFile) {
    const issues = [...eol].map(([major, e]) => ({
      major,
      title: `Node ${major} reaches end of life on ${e.end}`,
      body: [
        e.days < 0
          ? `Node ${major} reached end of life on **${e.end}** and gets no more security releases.`
          : `Node ${major} reaches end of life on **${e.end}** (in ${e.days} days). After that it gets no security releases, and \`node-security-watch.yml\` can no longer see the fixes it misses.`,
        '',
        'Move these pins to a supported major:',
        '',
        ...e.pins.map((p) => `- \`${p}\``),
        '',
        e.pins.some((p) => p.startsWith('docker/convex-node.Dockerfile'))
          ? 'The Convex images run the `docker/convex-node.Dockerfile` pin, so its new major must be one Convex builds against: check `.nvmrc` in [convex/convex-backend](https://github.com/convex/convex-backend) at the pinned release, and re-pin Convex first if it is still on this major.\n'
          : '',
        'Schedule: https://github.com/nodejs/Release#release-schedule',
        '',
        '_Filed automatically by `.github/workflows/node-security-watch.yml`; it closes this issue once no pin is on this major._',
      ].join('\n'),
    }));
    writeFileSync(eolFile, JSON.stringify(issues, null, 2));
  }
  const outFile = opt('--github-output');
  if (outFile) {
    appendFileSync(
      outFile,
      `changed=${changed}\nbranch=${branchName(list, changes)}\ntitle=${title}\n`,
    );
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  await main();
}
