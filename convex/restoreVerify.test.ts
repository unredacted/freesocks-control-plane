// @vitest-environment node
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, test } from 'vitest';

/**
 * docker/restore-verify.sh is the restore drill the prod runbook leans on (before
 * an upgrade, and as the proof a §8 restore will work). It runs against a
 * stand-in `docker` here, so the drill's own logic is what is tested:
 *
 *  - an age-encrypted dump is decrypted by the backup image's age, never by an
 *    `age` on the host (a host without one used to fail the drill at `age: not
 *    found`), with the key on stdin;
 *  - the restore stops at the first SQL error, so a dump that breaks part-way
 *    fails the drill instead of passing on the rows that did load.
 */
const script = fileURLToPath(new URL('../docker/restore-verify.sh', import.meta.url));
const DUMP = '/backups/freesocks-freesocks_test-20261023T000000Z.sql.gz.age';
const SQL = 'CREATE TABLE documents (id int);\n';

// The stand-in: logs every call (one line of args), answers the drill's
// questions, and plays age inside the backup image by gzipping a known SQL
// text after checking the key it was handed on stdin.
const FAKE_DOCKER = `#!/bin/sh
printf '%s\\n' "$*" >> "$WORK/calls.log"
case "$*" in
  *" exec -T backup "*) echo "${DUMP}" ;;
  *" run --rm --no-deps -T --entrypoint age backup -d -i - ${DUMP}")
    cat > "$WORK/key.seen"
    printf '${SQL.replace(/\n/g, '\\n')}' | gzip -c ;;
  *"-q -v ON_ERROR_STOP=1")
    cat > "$WORK/restored.sql"
    exit "\${RESTORE_EXIT:-0}" ;;
  *"SELECT table_schema"*) echo public ;;
  *"SELECT count(*)"*) echo 42 ;;
esac
exit 0
`;

let work = '';
afterEach(() => {
  if (work) rmSync(work, { recursive: true, force: true });
  work = '';
});

function drill(env: Record<string, string> = {}) {
  work = mkdtempSync(path.join(tmpdir(), 'restore-verify-'));
  const bin = path.join(work, 'bin');
  mkdirSync(bin);
  writeFileSync(path.join(bin, 'docker'), FAKE_DOCKER);
  // A host age that must never run: the drill decrypts in the backup image.
  writeFileSync(path.join(bin, 'age'), `#!/bin/sh\necho host >> "$WORK/host-age"\nexit 99\n`);
  for (const f of ['docker', 'age']) chmodSync(path.join(bin, f), 0o755);
  writeFileSync(path.join(work, 'env'), 'POSTGRES_DB=freesocks_test\nPOSTGRES_PASSWORD=pw\n');
  writeFileSync(path.join(work, 'age-key.txt'), 'AGE-SECRET-KEY-1TEST\n');
  const res = spawnSync('sh', [script], {
    encoding: 'utf8',
    env: {
      PATH: `${bin}:${process.env.PATH}`,
      WORK: work,
      ENV_FILE: path.join(work, 'env'),
      AGE_KEY_FILE: path.join(work, 'age-key.txt'),
      ...env,
    },
  });
  const read = (f: string) => {
    try {
      return readFileSync(path.join(work, f), 'utf8');
    } catch {
      return null;
    }
  };
  return { res, read };
}

describe('docker/restore-verify.sh', () => {
  test('decrypts in the backup image with the key on stdin, never with a host age', () => {
    const { res, read } = drill();
    expect(res.stderr).not.toContain('not found');
    expect(res.status).toBe(0);
    expect(res.stdout).toContain('[restore-verify] OK');
    expect(read('host-age')).toBeNull();
    expect(read('key.seen')).toBe('AGE-SECRET-KEY-1TEST\n');
    expect(read('restored.sql')).toBe(SQL);
    // The encrypted dump is read in place; it is never copied to the host.
    expect(read('calls.log')).not.toMatch(/ cp backup:/);
  });

  test('a restore that hits an SQL error fails the drill', () => {
    const { res, read } = drill({ RESTORE_EXIT: '3' });
    expect(res.status).not.toBe(0);
    expect(res.stdout).not.toContain('[restore-verify] OK');
    expect(read('calls.log')).toContain('-q -v ON_ERROR_STOP=1');
    // The scratch database is dropped on the way out either way.
    expect(read('calls.log')).toMatch(/DROP DATABASE IF EXISTS restore_verify_/);
  });
});
