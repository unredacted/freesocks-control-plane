import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'vitest';
import {
  assess,
  branchName,
  endOfLife,
  EOL_WARN_DAYS,
  fmt,
  nodeFromLines,
  renderPin,
} from '../scripts/node-security-watch.mjs';

/**
 * scripts/node-security-watch.mjs (run every few hours by
 * .github/workflows/node-security-watch.yml) re-pins `FROM node:` lines when
 * nodejs.org flags a newer security release on the same major, and warns
 * before a pinned major's end of life. These pin those decisions, plus the repo
 * shape the watcher relies on.
 */
const repoRoot = fileURLToPath(new URL('..', import.meta.url));

const INDEX = [
  { version: 'v26.12.1', security: true },
  { version: 'v24.22.1', security: true },
  { version: 'v24.22.0', security: false },
  { version: 'v22.23.5', security: false },
  { version: 'v22.23.4', security: true },
  { version: 'v22.23.3', security: false },
  { version: 'v22.23.2', security: true },
  { version: 'v22.22.2', security: true },
];

describe('node security watch', () => {
  test('a pin behind a security release on its major is stale; the target is the newest there', () => {
    const r = assess([22, 22, 2], INDEX);
    expect(r.security.map(fmt)).toEqual(['22.23.2', '22.23.4']);
    expect(fmt(r.latest)).toBe('22.23.5');
  });

  test('newer ordinary releases alone do not make a pin stale, and no major is crossed', () => {
    const r = assess([22, 23, 4], INDEX);
    expect(r.security).toEqual([]);
    expect(fmt(r.latest)).toBe('22.23.5');
    expect(assess([24, 22, 1], INDEX).security).toEqual([]);
  });

  test('a pin newer than the index (a fresh release) is current', () => {
    const r = assess([24, 23, 0], INDEX);
    expect(r.security).toEqual([]);
    expect(fmt(r.latest)).toBe('24.23.0');
  });

  test('end of life: days left from the Release WG schedule, negative once past', () => {
    // An EOL major gets no security releases, so the index alone would call
    // its pins current forever; the schedule is what flags them.
    const schedule = { v22: { end: '2027-04-30' }, v24: { end: '2028-04-30' } };
    const now = new Date('2027-02-01T12:00:00Z');
    expect(endOfLife(22, schedule, now)).toEqual({ end: '2027-04-30', days: 87 });
    expect(endOfLife(22, schedule, now)!.days).toBeLessThanOrEqual(EOL_WARN_DAYS);
    expect(endOfLife(24, schedule, now)!.days).toBeGreaterThan(EOL_WARN_DAYS);
    expect(endOfLife(22, schedule, new Date('2027-05-02T00:00:00Z'))!.days).toBeLessThan(0);
    expect(endOfLife(30, schedule, now)).toBeNull();
    expect(endOfLife(22, null, now)).toBeNull();
  });

  test('the PR branch changes whenever the set of re-pinned refs does', () => {
    // The workflow skips a branch whose PR exists in any state. Named by target
    // versions alone, a partial re-pin (one lookup failed) would share its name
    // with the later run that fixes the rest, and that run would be skipped.
    const a = 'docker/a.Dockerfile=node:24.22.1-bookworm-slim@sha256:x';
    const b = 'docker/b.Dockerfile=node:24.22.1-bookworm-slim@sha256:x';
    const partial = branchName(['24.22.1'], [a]);
    const full = branchName(['24.22.1'], [a, b]);
    expect(partial).toMatch(/^node-security\/24\.22\.1-[0-9a-f]{8}$/);
    expect(full).not.toBe(partial);
    // Same change set, any order or repeats: same branch, so a re-run dedupes.
    expect(branchName(['24.22.1'], [b, a, a])).toBe(full);
  });

  test('parses a pin and rewrites only the version and digest', () => {
    const d1 = `sha256:${'a'.repeat(64)}`;
    const d2 = `sha256:${'b'.repeat(64)}`;
    const text = `ARG X\nFROM node:24.22.0-bookworm-slim@${d1} AS node\nFROM \${X}\n`;
    const [hit] = nodeFromLines(text);
    expect(hit.line).toBe(2);
    expect(hit.pin).toMatchObject({ version: [24, 22, 0], variant: 'bookworm-slim', digest: d1 });
    expect(renderPin(hit.pin!, [24, 22, 1], d2)).toBe(
      `FROM node:24.22.1-bookworm-slim@${d2} AS node`,
    );
    expect(nodeFromLines('FROM node:24-bookworm-slim AS node')[0].pin).toBeNull();
  });

  test('every Node base image under docker/ names its exact version and digest', () => {
    // A floating `node:24` tag (or a missing digest) hides which Node is pinned,
    // so the watcher would skip it and the image could sit on a vulnerable Node.
    const offenders: string[] = [];
    let pins = 0;
    const walk = (rel: string) => {
      for (const e of readdirSync(path.join(repoRoot, rel), { withFileTypes: true })) {
        const child = `${rel}/${e.name}`;
        if (e.isDirectory()) walk(child);
        else if (/Dockerfile/.test(e.name)) {
          for (const hit of nodeFromLines(readFileSync(path.join(repoRoot, child), 'utf8'))) {
            if (hit.pin) pins++;
            else offenders.push(`${child}:${hit.line} ${hit.text}`);
          }
        }
      }
    };
    walk('docker');
    expect(offenders, 'write these as node:<x.y.z>-<variant>@sha256:<digest>').toEqual([]);
    // The Convex overlay plus the two test images, at least.
    expect(pins).toBeGreaterThanOrEqual(3);
  });
});
