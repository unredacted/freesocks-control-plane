import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'vitest';

/**
 * Drift lock for image pins that are duplicated across files (sibling of
 * `envExample.test.ts`).
 *
 * Every image in the stack is digest-pinned, and three of those pins appear in
 * MORE THAN ONE file. Dependabot owns them through two independent updaters —
 * `docker-compose` at the repo root and `docker` at `/docker` (see
 * `.github/dependabot.yml`) — so a single upstream release arrives as two
 * separate PRs that can each pass CI and merge alone. Nothing in Dependabot can
 * group across ecosystems, so the guard has to live here: whichever PR lands
 * first fails this test until the other side is folded into it.
 *
 * The failures these prevent are not subtle:
 *
 *  - postgres server vs. the backup sidecar's `pg_dump`: an older pg_dump
 *    REFUSES to dump a newer-major server, so a compose-only bump to PG19 would
 *    break every backup cycle. The sidecar's healthcheck would go unhealthy and
 *    (per Aug 2026) nobody would necessarily be watching.
 *  - `oven/bun` vs. `packageManager` in package.json: the image and CI would
 *    silently build on different Bun versions. package.json is NOT enrolled in
 *    Dependabot, so nothing bumps that half automatically.
 */
const read = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');

const stack = read('../docker-compose.stack.yml');
const backupDockerfile = read('../docker/backup.Dockerfile');
const webDockerfile = read('../docker/web.Dockerfile');
const deployDockerfile = read('../docker/deploy.Dockerfile');
const packageJson = read('../package.json');

/** Every `FROM <ref>` in a Dockerfile, stage aliases stripped. */
function fromRefs(dockerfile: string): string[] {
  return [...dockerfile.matchAll(/^FROM\s+(\S+)/gm)].map((m) => m[1]);
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
        'server it dumps. Dependabot updates these through two separate updaters — fold both ' +
        'PRs into one before merging.',
    ).toBe(serverImage);
  });

  test('the bun base images match packageManager in package.json', () => {
    const declared = JSON.parse(packageJson).packageManager as string;
    expect(declared).toMatch(/^bun@\d+\.\d+\.\d+$/);
    const expected = `oven/bun:${declared.slice('bun@'.length)}`;

    for (const [name, dockerfile] of [
      ['docker/web.Dockerfile', webDockerfile],
      ['docker/deploy.Dockerfile', deployDockerfile],
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

  test('every convex-backend pin in the stack is the same digest', () => {
    const refs = [...stack.matchAll(/image:\s*(ghcr\.io\/get-convex\/convex-backend\S+)/g)].map(
      (m) => m[1],
    );
    // The backend image is referenced by both the `backend` service and the
    // one-shot `keygen` (it derives the admin key with the same binary).
    expect(refs.length).toBeGreaterThan(1);
    expect(
      new Set(refs).size,
      `convex-backend is pinned to ${new Set(refs).size} different refs`,
    ).toBe(1);
  });
});
