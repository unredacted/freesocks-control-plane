import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'vitest';
import YAML from 'yaml';

/**
 * Drift lock for image pins that are duplicated across files (sibling of
 * `envExample.test.ts`).
 *
 * Every image in the stack is pinned to an exact version and its digest, and
 * some of those pins appear in MORE THAN ONE file. Dependabot sees them through
 * two ecosystems, `docker-compose` at the repo root and `docker` at `/docker`,
 * which `.github/dependabot.yml` joins in one multi-ecosystem group so that a
 * release lands as ONE PR (until Oct 2026 it arrived as two, each failing or,
 * worse, passing alone). This file is the guard behind that group: it fails the
 * moment the halves disagree, whatever made the change (a hand re-pin, the group
 * split apart again, a file no ecosystem updates), and it checks the
 * multi-ecosystem rules whose breach would make the config invalid and stop
 * every update.
 *
 * The failures these prevent are not subtle:
 *
 *  - postgres server vs. the backup sidecar's `pg_dump`: an older pg_dump
 *    REFUSES to dump a newer-major server, so a compose-only bump to PG19 would
 *    break every backup cycle. The sidecar's healthcheck would go unhealthy and
 *    (per Aug 2026) nobody would necessarily be watching.
 *  - `oven/bun` vs. `packageManager` in package.json: the image and CI would
 *    silently build on different Bun versions. package.json is NOT enrolled in
 *    Dependabot, so nothing bumps that half automatically. CI itself is kept out
 *    of the duplication entirely — `.github/workflows/ci.yml` uses
 *    `bun-version-file: package.json`, and the last test here stops a literal
 *    `bun-version:` creeping back in.
 *  - caddy in docker/web.Dockerfile vs. the one CI validates the Caddyfile
 *    with: they drifted once and CI validated a different Caddy than the one
 *    deployed for weeks. CI now reads the image from web.Dockerfile, the way it
 *    reads Bun from package.json, and a test here stops a copy coming back.
 */
const read = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');
const repoRoot = fileURLToPath(new URL('..', import.meta.url));

const stack = read('../docker-compose.stack.yml');
const devCompose = read('../docker-compose.yml');
const envBetaExample = read('../.env.beta.example');
const backupDockerfile = read('../docker/backup.Dockerfile');
const webDockerfile = read('../docker/web.Dockerfile');
const deployDockerfile = read('../docker/deploy.Dockerfile');
const clientCheckDockerfile = read('../docker/edge-client-check/Dockerfile');
const convexNodeDockerfile = read('../docker/convex-node/Dockerfile');
const packageJson = read('../package.json');
const ciWorkflow = read('../.github/workflows/ci.yml');
const dependabotYml = read('../.github/dependabot.yml');
const dockerignore = read('../.dockerignore');
const gitignore = read('../.gitignore');

/** The pattern lines of an ignore file, comments and blanks dropped. */
function ignoreLines(text: string): string[] {
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '' && !line.startsWith('#'));
}

/**
 * Database exports, dumps and env captures as the operator docs write them
 * (docs/beta-deploy.md § Exports stay outside the checkout): the re-pin
 * checklist's `snapshots/*.zip`, the backup sidecar's `*.sql.gz[.age]`, and the
 * age-encrypted `convex-env-*.txt.age` env capture.
 */
const EXPORT_PATTERNS = ['snapshots', '*.zip', '*.sql', '*.sql.gz*', '*.age', 'convex-env-*'];

/** One service's block in a compose file (up to the next top-level key). */
function serviceBlock(name: string, compose = stack): string {
  const m = compose.match(new RegExp(`^  ${name}:\\n((?:(?:    .*)?\\n)*)`, 'm'));
  return m?.[1] ?? '';
}

/**
 * Backend log targets that print a request URI at INFO, and so a member's
 * subscription token (`/api/v1/sub/<subToken>`). Named in the backend source at
 * the pinned release: `convex-cloud-http` is the access line
 * (crates/common/src/http/mod.rs, `log_http_access`); `common::http` is the
 * module-path target of `stats_middleware: matched_path is None, uri: …`, which
 * fires for every HTTP action request because the site proxy's router is
 * fallback-only. docs/privacy.md §4.
 */
const URI_LOG_TARGETS = ['convex-cloud-http', 'common::http'];

/**
 * The level a `RUST_LOG` value gives one target, the way tracing-subscriber's
 * EnvFilter resolves it: the longest directive whose target is a prefix of it
 * (a plain string prefix, so `common=warn` covers `common::http`), else the
 * bare default level. A repeated target keeps its LAST value: EnvFilter's
 * directive set replaces an equal directive rather than keeping the first.
 */
function rustLogLevel(rustLog: string, target: string): string {
  let level = 'error'; // EnvFilter's default when no bare level is given
  let matched = -1;
  for (const directive of rustLog.split(',').map((d) => d.trim())) {
    const eq = directive.lastIndexOf('=');
    const [prefix, value] =
      eq < 0 ? ['', directive] : [directive.slice(0, eq), directive.slice(eq + 1)];
    if (target.startsWith(prefix) && prefix.length >= matched) {
      level = value.toLowerCase();
      matched = prefix.length;
    }
  }
  return level;
}

/** True when `RUST_LOG` keeps every URI-printing target below INFO. */
function silencesRequestUris(rustLog: string): boolean {
  return URI_LOG_TARGETS.every((t) => ['warn', 'error', 'off'].includes(rustLogLevel(rustLog, t)));
}

/** Values the check must accept / refuse. Pins its coverage. */
const RUST_LOG_CASES = {
  quiet: [
    'info,convex-cloud-http=warn,common::http=warn',
    'warn',
    'error,convex-cloud-http=error',
    'info,common=warn,convex-cloud-http=off', // a parent prefix covers common::http
    'warn,common::http=info,common::http=warn', // the later duplicate wins
  ],
  leaky: [
    'info,convex-cloud-http=warn', // the default until Oct 2026: common::http logged every URI
    'info,common::http=warn', // access line back on
    'warn,common::http=info',
    'info,common::http::fetch=warn', // a child module does not cover its parent
    'info',
    'warn,common::http=warn,common::http=info', // the later duplicate wins
    'warn,info', // so does a later bare level
  ],
};

/** Every `FROM <ref>` in a Dockerfile, stage aliases stripped. */
function fromRefs(dockerfile: string): string[] {
  return [...dockerfile.matchAll(/^FROM\s+(\S+)/gm)].map((m) => m[1]);
}

/** The compose files at the root and every Dockerfile under docker/: where image pins live. */
function imagePinFiles(): string[] {
  const out = readdirSync(repoRoot).filter((name) => /^docker-compose[\w.-]*\.ya?ml$/.test(name));
  const walk = (rel: string) => {
    for (const entry of readdirSync(path.join(repoRoot, rel), { withFileTypes: true })) {
      const child = `${rel}/${entry.name}`;
      if (entry.isDirectory()) walk(child);
      else if (/(^|\.)Dockerfile$/.test(entry.name)) out.push(child);
    }
  };
  walk('docker');
  return out;
}

/**
 * A tag that names one upstream release: at least `major.minor` (Postgres's own
 * versions have two parts), a build date (`debian:trixie-YYYYMMDD-slim`), or a
 * Convex release git sha. A floating `2-alpine`, `18` or `13-slim` fails.
 */
const EXACT_TAG = /^(?:v?\d+\.\d+[\w.-]*|[a-z]+-\d{8}(?:-[a-z]+)?|[0-9a-f]{40})$/;

/** The parts of .github/dependabot.yml the checks below read. */
interface DependabotUpdate {
  'package-ecosystem': string;
  directory?: string;
  directories?: string[];
  schedule?: unknown;
  patterns?: string[];
  'multi-ecosystem-group'?: string;
}
interface DependabotConfig {
  'multi-ecosystem-groups'?: Record<string, { schedule?: unknown }>;
  updates: DependabotUpdate[];
}

/**
 * A bun version written out as a literal, in any shape: `bun@1.2.3`,
 * `oven/bun:1.2.3`, `bun-version: '1.2.3'`, or prose ("bun `1.2.3`", "Bun
 * version 1.2.3", "bun release 1.2.3").
 *
 * The gap is "any run of up to 20 characters that is neither a newline nor a
 * digit" rather than an enumerated set. Enumerating punctuation missed
 * `Bun version 1.2.3` — the most natural way to write it in a README, and the
 * exact wording a person adding operational docs would reach for. Enumerating
 * words instead would just move the gap to whichever synonym nobody listed.
 *
 * Still anchored on a whole-word "bun" so unrelated semver in the same files
 * (image digests, action tags, Postgres versions) is ignored, and the
 * digit-free gap stops it leaping over a nearby number — `setup-bun@v2` cannot
 * reach a version on the following line.
 */
const BUN_VERSION_LITERAL = /\bbun\b[^\n\d]{0,20}\d+\.\d+\.\d+/i;

/** Shapes the pattern must catch / must not catch. Pins its coverage. */
const BUN_LITERAL_CASES = {
  matches: [
    '"packageManager": "bun@1.3.14"',
    'FROM oven/bun:1.3.14@sha256:abc',
    "          bun-version: '1.3.14'",
    'Pinned toolchain: bun `1.3.14`',
    'Requires Bun version 1.3.14 or newer',
    'built with bun release 1.3.14',
    "Bun's 1.3.14 runtime",
  ],
  ignores: [
    '- uses: oven-sh/setup-bun@v2', // action tag, and the digit blocks the gap
    'bun install --frozen-lockfile',
    'FROM postgres:18@sha256:4aabea78cf39b90e', // unrelated pin
    'caddy:2-alpine@sha256:5f5c8640aae01df965',
    'bun-version-file: package.json',
    'the exact version is `packageManager` in `package.json`',
  ],
};

/**
 * The three files allowed to name a bun version. `package.json` is the source of
 * truth; the two Dockerfiles carry the real base-image pin and are held equal to
 * it by the bun test above. Listed by exact path, so a NEW file introducing a
 * literal fails rather than slipping in under a pattern.
 */
const BUN_LITERAL_EXEMPT = new Set([
  'package.json',
  'docker/web.Dockerfile',
  'docker/deploy.Dockerfile',
  'docker/edge-client-check/Dockerfile',
]);

/**
 * Operational surfaces — deploy config, docs, scripts, CI — walked recursively
 * so a newly added doc or script is covered without editing a list here (a
 * hand-maintained file list would rot the same way the version literals did).
 * Application source under src/ and convex/ is out of scope: a toolchain pin has
 * no business there, and scanning it would trade real coverage for noise.
 */
function operationalFiles(): string[] {
  const out: string[] = [];
  const textFile = /\.(ts|md|ya?ml|sh|json|Dockerfile)$/;

  const walk = (rel: string) => {
    for (const entry of readdirSync(path.join(repoRoot, rel), { withFileTypes: true })) {
      const child = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isDirectory()) walk(child);
      else if (textFile.test(entry.name)) out.push(child);
    }
  };

  for (const dir of ['docs', 'scripts', '.github', 'docker']) walk(dir);
  // Root-level config/docs only — not a recursive walk of the repo.
  for (const entry of readdirSync(repoRoot, { withFileTypes: true })) {
    if (entry.isFile() && textFile.test(entry.name)) out.push(entry.name);
  }
  return out;
}

describe('cross-file image pins', () => {
  test('the backup sidecar builds on the exact postgres image the server runs', () => {
    const serverImage = stack.match(/image:\s*(postgres:\S+)/)?.[1];
    const sidecarBase = fromRefs(backupDockerfile).find((ref) => ref.startsWith('postgres:'));

    expect(serverImage, 'no `image: postgres:…` found in docker-compose.stack.yml').toBeTruthy();
    expect(sidecarBase, 'no `FROM postgres:…` found in docker/backup.Dockerfile').toBeTruthy();

    // Exact match including the digest. Tag-only equality is not enough: two
    // different `postgres:18` digests are still two different client builds, and
    // holding them identical is what makes "same image" a true statement rather
    // than an aspiration in a comment.
    expect(
      sidecarBase,
      'docker/backup.Dockerfile must pin the SAME postgres image (tag AND digest) as the ' +
        'postgres service in docker-compose.stack.yml, or pg_dump can end up older than the ' +
        'server it dumps. Dependabot moves both in one PR (the `stack-images` group in ' +
        '.github/dependabot.yml); a hand re-pin must change both too.',
    ).toBe(serverImage);
  });

  test('the bun base images match packageManager in package.json', () => {
    const declared = JSON.parse(packageJson).packageManager as string;
    expect(declared).toMatch(/^bun@\d+\.\d+\.\d+$/);
    const expected = `oven/bun:${declared.slice('bun@'.length)}`;

    for (const [name, dockerfile] of [
      ['docker/web.Dockerfile', webDockerfile],
      ['docker/deploy.Dockerfile', deployDockerfile],
      ['docker/edge-client-check/Dockerfile', clientCheckDockerfile],
    ] as const) {
      const bunBase = fromRefs(dockerfile).find((ref) => ref.startsWith('oven/bun:'));
      expect(bunBase, `no \`FROM oven/bun:…\` found in ${name}`).toBeTruthy();
      // Compare the tag only — the digest is Dependabot's to move.
      expect(
        bunBase!.split('@')[0],
        `${name} pins ${bunBase} but package.json declares ${declared}. A Dependabot bump of ` +
          'the base image does NOT touch package.json (the bun ecosystem is not enrolled), so ' +
          'update packageManager in the same PR or the image and CI build on different Bun ' +
          'versions.',
      ).toBe(expected);
    }
  });

  test('CI derives its Bun version from package.json rather than pinning a copy', () => {
    // `setup-bun` reads `packageManager` (then `engines.bun`) out of the file,
    // so `bun-version-file: package.json` keeps CI on the same Bun as the images
    // by construction. A literal `bun-version:` would be a copy Dependabot never
    // touches — and it is the input that actually WINS, so CI could build on a
    // different runtime than it ships while the pins above still looked clean.
    expect(ciWorkflow).toContain('bun-version-file: package.json');
    expect(
      ciWorkflow,
      'ci.yml pins a literal `bun-version:`. Use `bun-version-file: package.json` instead — ' +
        'a hardcoded version here silently overrides the single source of truth in package.json.',
    ).not.toMatch(/^\s*bun-version:/m);

    const setupSteps = (ciWorkflow.match(/uses:\s*oven-sh\/setup-bun@/g) ?? []).length;
    const versionFiles = (ciWorkflow.match(/bun-version-file:\s*package\.json/g) ?? []).length;
    expect(versionFiles, 'every setup-bun step must declare bun-version-file').toBe(setupSteps);
  });

  test('the bun-literal pattern catches every shape it claims to', () => {
    // A drift guard whose own coverage is unpinned is just a different place for
    // the gap to hide: two of the cases below (prose "version"/"release") went
    // undetected by an earlier punctuation-only pattern.
    for (const sample of BUN_LITERAL_CASES.matches) {
      expect(BUN_VERSION_LITERAL.test(sample), `should flag: ${sample}`).toBe(true);
    }
    for (const sample of BUN_LITERAL_CASES.ignores) {
      expect(BUN_VERSION_LITERAL.test(sample), `should ignore: ${sample}`).toBe(false);
    }
  });

  test('no operational file states a literal bun version', () => {
    // The reproducibility protocol is the sharpest case: docs/oob-verification.md
    // tells independent rebuilders which toolchain to use, and its own text warns
    // that a different bun MAY change the dist-sha256. A stale version there
    // would have an honest rebuilder publish dissent against a hash that was
    // never wrong — just built differently. So the docs name the FIELD, never
    // the value, and verify-reproducible.sh reads it at runtime.
    //
    // Matched by SHAPE, not by the value package.json happens to hold today.
    // Searching for the current version would invert the guard: the literal left
    // behind by a bump is the OLD one, so the only case worth catching is the one
    // a value-equality check cannot see.
    const offenders: string[] = [];
    for (const file of operationalFiles()) {
      if (BUN_LITERAL_EXEMPT.has(file)) continue;
      const hit = read(`../${file}`).match(BUN_VERSION_LITERAL);
      if (hit) offenders.push(`${file} (${hit[0].trim()})`);
    }
    expect(
      offenders,
      'these files state a bun version literally. Reference `packageManager` in package.json ' +
        'instead (or read it at runtime) — a Dependabot bump leaves the copy stale while every ' +
        'other guard stays green, which is exactly how a reproducibility instruction rots.',
    ).toEqual([]);
  });

  test('the Convex images are pinned to one release git sha, tag and digest', () => {
    // Convex is explicit that these two ship together: "Make sure to use the
    // same version of convex-backend and convex-dashboard. Different versions
    // are not guaranteed to be compatible with one another."
    // (convex/convex-backend, self-hosted/CHANGELOG.md.)
    //
    // Nothing else enforces that. Dependabot sees two unrelated images in two
    // PRs and cannot know they are halves of one release — the same cross-file
    // shape as postgres/pg_dump above, one ecosystem further out.
    // `image:` for the one-shot `keygen`; `CONVEX_IMAGE:` for the build arg the
    // backend and dashboard hand docker/convex-node/Dockerfile.
    const refs = [
      ...stack.matchAll(
        /(?:image|CONVEX_IMAGE):\s*ghcr\.io\/convex\/(convex-\w+):(\S+?)@(sha256:[a-f0-9]{64})/g,
      ),
    ].map(([, image, tag, digest]) => ({ image, tag, digest }));

    // backend x2 (the `backend` service + the one-shot `keygen`, which derives
    // the admin key with the same binary) + dashboard x1.
    expect(refs.length, 'expected three ghcr.io/convex/* refs in the stack').toBe(3);
    expect(new Set(refs.map((r) => r.image))).toEqual(
      new Set(['convex-backend', 'convex-dashboard']),
    );

    // A release tag is the full 40-char git sha. Rejecting `latest` here is the
    // point: a floating tag cannot be mapped back to a release, and
    // `git log <pinned>..<target>` is the only changelog Convex still publishes.
    for (const r of refs) {
      expect(
        r.tag,
        `${r.image} must be pinned to a 40-char release git sha, got "${r.tag}"`,
      ).toMatch(/^[0-9a-f]{40}$/);
    }

    const tags = new Set(refs.map((r) => r.tag));
    expect(
      tags.size,
      `Convex images span ${tags.size} release shas (${[...tags].map((t) => t.slice(0, 7)).join(', ')}). ` +
        'Backend and dashboard must be the SAME release, and both backend refs must match each other.',
    ).toBe(1);

    // One image, one digest — a copy/paste slip that left the two backend refs
    // on different digests would otherwise pass the tag check above.
    for (const image of ['convex-backend', 'convex-dashboard']) {
      const digests = new Set(refs.filter((r) => r.image === image).map((r) => r.digest));
      expect(digests.size, `${image} is pinned to ${digests.size} different digests`).toBe(1);
    }
  });

  test('the compose comment names the release the Convex images are pinned to', () => {
    // The `backend` service comment carries `<sha7> = precompiled-<date>-<sha7>`
    // (optionally suffixed `(the npm X.Y.Z anchor)` — written by every
    // scripts/convex-repin.sh run; pins predating the anchor policy lack it).
    // scripts/convex-repin.sh rewrites that comment with a pattern
    // substitution, and a reflow of the comment block would make the rewrite
    // silently no-op — the script's own count assertion catches that at repin
    // time, and this test catches a comment that already drifted from the pin.
    const comment = stack.match(
      /\b([0-9a-f]{7}) = (precompiled-\d{4}-\d{2}-\d{2}-\1)(?: \(the npm \d+\.\d+\.\d+ anchor\))?/,
    );
    expect(
      comment,
      'the backend service comment must name the pinned release as ' +
        '`<sha7> = precompiled-<date>-<sha7>` — scripts/convex-repin.sh rewrites ' +
        'exactly that shape, and convex-release-watch.yml relies on the tag being real.',
    ).not.toBeNull();

    const pinnedSha = stack.match(
      /(?:image|CONVEX_IMAGE):\s*ghcr\.io\/convex\/convex-backend:([0-9a-f]{40})@/,
    );
    expect(pinnedSha).not.toBeNull();
    expect(
      comment![1],
      `the comment says the pin is ${comment![1]} but the images are pinned to ` +
        `${pinnedSha![1].slice(0, 7)} — the release-name comment drifted from the actual pin ` +
        '(a hand-edit skipped scripts/convex-repin.sh, or the script rewrite broke).',
    ).toBe(pinnedSha![1].slice(0, 7));
  });

  test('the backend and dashboard run on the patched-Node overlay', () => {
    // Upstream installs the Node in its .nvmrc and has fallen behind Node
    // security releases (22.22.2 against 22.23.4 in Oct 2026). Going back to a
    // plain `image:` would silently undo the patch, so both services that run
    // Node build docker/convex-node/Dockerfile on their pinned Convex image.
    for (const [service, image] of [
      ['backend', 'convex-backend'],
      ['dashboard', 'convex-dashboard'],
    ] as const) {
      const block = serviceBlock(service);
      expect(block, `no \`${service}\` service found in docker-compose.stack.yml`).not.toBe('');
      expect(block, `${service} must build docker/convex-node/`).toMatch(
        /^\s+context:\s*docker\/convex-node$/m,
      );
      expect(block, `${service} must hand the overlay its pinned ${image}`).toMatch(
        new RegExp(`^\\s+CONVEX_IMAGE:\\s*ghcr\\.io/convex/${image}:`, 'm'),
      );
      expect(block, `${service} must not pull a plain image as well`).not.toMatch(/^\s+image:/m);
    }

    // An exact version and digest: Dependabot's PRs then name the versions, and
    // convex-repin.yml reads the version to compare it with upstream's .nvmrc.
    const nodeBase = fromRefs(convexNodeDockerfile).find((ref) => ref.startsWith('node:'));
    expect(
      nodeBase,
      'docker/convex-node/Dockerfile must pin node:<x.y.z>-<variant>@sha256:<digest>',
    ).toMatch(/^node:\d+\.\d+\.\d+-[a-z0-9.-]+@sha256:[0-9a-f]{64}$/);
  });

  test('CI validates the Caddyfile with the Caddy docker/web.Dockerfile deploys', () => {
    // ci.yml's `caddyfile` job reads its image from this FROM line. A copy in
    // the workflow is a `docker run` ref that no Dependabot ecosystem updates:
    // it drifted once, and the shell guard added then failed every Caddy bump.
    const caddyBases = fromRefs(webDockerfile).filter((ref) => ref.startsWith('caddy:'));
    expect(caddyBases, 'docker/web.Dockerfile must have exactly one `FROM caddy:…`').toHaveLength(
      1,
    );
    expect(caddyBases[0]).toMatch(/^caddy:\S+@sha256:[0-9a-f]{64}$/);
    expect(ciWorkflow, 'ci.yml must read the Caddy image from docker/web.Dockerfile').toMatch(
      /FROM caddy:.*docker\/web\.Dockerfile/,
    );
    expect(
      ciWorkflow,
      'ci.yml pins a Caddy image of its own. Read it from docker/web.Dockerfile instead, or ' +
        'every Caddy bump leaves CI validating the old one.',
    ).not.toMatch(/\bcaddy:[\w.-]+@sha256:/);
  });

  test('every digest pin names an exact upstream version', () => {
    // With a floating tag (`caddy:2-alpine`, `postgres:18`) Dependabot only sees
    // the digest move, so every PR read "bump caddy from 2-alpine to 2-alpine".
    // An exact tag makes it name the versions, and a rebuild of the same
    // version shows as one ("2.11.7-alpine to 2.11.7-alpine").
    const floating: string[] = [];
    let pins = 0;
    for (const file of imagePinFiles()) {
      for (const [ref, tag] of read(`../${file}`).matchAll(
        /[\w./-]+:([\w.-]+)@sha256:[0-9a-f]{64}/g,
      )) {
        pins++;
        if (!EXACT_TAG.test(tag)) floating.push(`${file}: ${ref}`);
      }
    }
    expect(pins, 'found no digest pins at all, so the scan itself is broken').toBeGreaterThan(10);
    expect(
      floating,
      'these pins float on a major-only tag. Pin the exact version tag and its digest ' +
        '(`docker buildx imagetools inspect <image>:<exact tag>`).',
    ).toEqual([]);
  });
});

describe('the Dependabot config', () => {
  const config = YAML.parse(dependabotYml) as DependabotConfig;
  const label = (u: DependabotUpdate) =>
    `${u['package-ecosystem']} ${u.directory ?? u.directories?.join(',')}`;

  test('the compose files and the /docker Dockerfiles update in one PR', () => {
    // The postgres and caddy pairs are one image in two ecosystems; only a
    // multi-ecosystem group puts both halves in the same PR.
    const compose = config.updates.find(
      (u) => u['package-ecosystem'] === 'docker-compose' && u.directory === '/',
    );
    const dockerfiles = config.updates.find(
      (u) =>
        u['package-ecosystem'] === 'docker' && (u.directories ?? [u.directory]).includes('/docker'),
    );
    const group = compose?.['multi-ecosystem-group'];
    expect(group, 'the root docker-compose entry must be in a multi-ecosystem group').toBeTruthy();
    expect(dockerfiles?.['multi-ecosystem-group'], 'the /docker entry must share it').toBe(group);
  });

  test('every grouped entry follows the multi-ecosystem rules', () => {
    // A breach makes the whole file invalid, and an invalid file stops EVERY
    // entry, the daily Node security one included. GitHub's rules: these keys
    // are group-only, each member needs `patterns`, and the group has the
    // schedule (`groups` has no meaning on a member, `patterns` replaces it).
    const groupOnly = ['commit-message', 'target-branch', 'milestone', 'pull-request-branch-name'];
    const groups = config['multi-ecosystem-groups'] ?? {};
    for (const [name, group] of Object.entries(groups)) {
      expect(group.schedule, `multi-ecosystem group ${name} needs a schedule`).toBeTruthy();
    }
    for (const u of config.updates) {
      const group = u['multi-ecosystem-group'];
      if (!group) {
        expect(u.schedule, `${label(u)} needs a schedule`).toBeTruthy();
        continue;
      }
      expect(groups[group], `${label(u)} names an undefined group ${group}`).toBeTruthy();
      expect(u.patterns?.length, `${label(u)} needs \`patterns\``).toBeGreaterThan(0);
      for (const key of [...groupOnly, 'schedule', 'groups']) {
        expect(u, `${label(u)}: \`${key}\` goes on the group, not a member`).not.toHaveProperty(
          key,
        );
      }
    }
  });
});

describe('backend log privacy', () => {
  test('the RUST_LOG check accepts and refuses what it claims to', () => {
    for (const value of RUST_LOG_CASES.quiet) {
      expect(silencesRequestUris(value), `should accept: ${value}`).toBe(true);
    }
    for (const value of RUST_LOG_CASES.leaky) {
      expect(silencesRequestUris(value), `should refuse: ${value}`).toBe(false);
    }
  });

  test('every backend RUST_LOG default keeps request URIs out of the log', () => {
    // The pre-Oct-2026 default silenced only the access line; common::http kept
    // writing `uri: /api/v1/sub/<subToken>` for every member request, and the
    // documented `grep 'GET /api'` check could not see it. The operator-facing
    // copy in .env.beta.example counts too: uncommenting a stale one re-leaks.
    const defaults: [string, string | undefined][] = [
      [
        'docker-compose.stack.yml (backend)',
        serviceBlock('backend').match(/^\s+- RUST_LOG=\$\{RUST_LOG:-(.+)\}$/m)?.[1],
      ],
      [
        'docker-compose.yml (backend)',
        serviceBlock('backend', devCompose).match(/^\s+- RUST_LOG=\$\{RUST_LOG:-(.+)\}$/m)?.[1],
      ],
      ['.env.beta.example', envBetaExample.match(/^#\s*RUST_LOG=(\S+)$/m)?.[1]],
    ];
    for (const [where, value] of defaults) {
      expect(value, `no RUST_LOG default found in ${where}`).toBeTruthy();
      expect(
        silencesRequestUris(value!),
        `${where} sets RUST_LOG=${value}, which logs request URIs (member subscription ` +
          `tokens) at INFO. Keep ${URI_LOG_TARGETS.map((t) => `${t}=warn`).join(' and ')}, ` +
          'or use plain `warn`. docs/privacy.md §4.',
      ).toBe(true);
    }
  });
});

describe('what the images take from the checkout', () => {
  test('.dockerignore keeps database exports out of every image, at any depth', () => {
    // The deployer image is `COPY . .` of the whole checkout, so an export left
    // in the repo directory (the old re-pin recipe made `snapshots/` there) was
    // baked into it: every account hash and live subscription token, in an
    // image layer that outlives the file. `**/` because a bare .dockerignore
    // pattern matches at the context root only, so `*.zip` alone would let
    // `snapshots/pre-upgrade.zip` through.
    const lines = ignoreLines(dockerignore);
    for (const pattern of EXPORT_PATTERNS) {
      expect(lines, `.dockerignore must exclude \`**/${pattern}\``).toContain(`**/${pattern}`);
    }

    // The last matching line wins, so a `!` exception could put one back.
    expect(
      lines.filter((line) => line.startsWith('!')),
      'a `!` line in .dockerignore can re-include an export. If you need one, scope it so it ' +
        'cannot match an export and relax this check.',
    ).toEqual([]);
  });

  test('.gitignore keeps the same exports from being committed', () => {
    // gitignore patterns without a slash match at any depth already.
    const lines = ignoreLines(gitignore);
    for (const pattern of EXPORT_PATTERNS) {
      const line = pattern === 'snapshots' ? 'snapshots/' : pattern;
      expect(lines, `.gitignore must exclude \`${line}\``).toContain(line);
    }
  });

  test('the web image ships only the built SPA and the Caddyfile', () => {
    // Its build stage copies the whole context; the final stage is what Caddy
    // runs, and it must not pick up anything beyond the build output.
    const finalStage = webDockerfile.split(/^FROM\s/m).at(-1) ?? '';
    const copies = [...finalStage.matchAll(/^(?:COPY|ADD)\s+(.+)$/gm)].map((m) => m[1].trim());
    expect(copies).toEqual(['--from=build /app/dist /srv/dist', 'Caddyfile /etc/caddy/Caddyfile']);
  });
});
