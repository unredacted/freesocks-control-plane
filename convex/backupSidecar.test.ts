// @vitest-environment node
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, test } from 'vitest';

/**
 * docker/backup.sh is the backup sidecar's loop. It runs here against stand-in
 * `psql`, `pg_dump`, `aws` and `sleep`, so the loop's own logic is what is
 * tested:
 *
 *  - a failed cycle is retried after BACKUP_RETRY_SECONDS, doubling on each
 *    further failure and never longer than the interval, and a success goes
 *    back to the interval (a first cycle that raced a Postgres restart used to
 *    leave the stack without a backup for a whole interval);
 *  - a failed offsite upload still prunes local dumps to the retention count,
 *    so the retries of a failing upload never fill the disk.
 *
 * The stand-in `sleep` records each wait and stops the loop after SLEEPS calls.
 */
const script = fileURLToPath(new URL('../docker/backup.sh', import.meta.url));

const FAKE_PSQL = `#!/bin/sh
case "$*" in
  *"SELECT table_schema"*)
    n=$(cat "$WORK/fails" 2>/dev/null || echo 0)
    if [ "$n" -gt 0 ]; then echo $((n - 1)) > "$WORK/fails"; exit 2; fi
    echo convex_test ;;
  *"SELECT 1 FROM"*) echo 1 ;;
esac
exit 0
`;
const FAKE_PG_DUMP = `#!/bin/sh\necho "-- dump"\n`;
const FAKE_AWS = `#!/bin/sh\necho "$*" >> "$WORK/aws.log"\nexit "\${AWS_EXIT:-0}"\n`;
const FAKE_SLEEP = `#!/bin/sh
echo "$1" >> "$WORK/sleeps"
[ "$(wc -l < "$WORK/sleeps")" -ge "$SLEEPS" ] && exit 1
exit 0
`;

let work = '';
afterEach(() => {
  if (work) rmSync(work, { recursive: true, force: true });
  work = '';
});

function run(env: Record<string, string>, opts: { fails?: number; oldDumps?: number } = {}) {
  work = mkdtempSync(path.join(tmpdir(), 'backup-sidecar-'));
  const bin = path.join(work, 'bin');
  const out = path.join(work, 'backups');
  mkdirSync(bin);
  mkdirSync(out);
  const fakes: Record<string, string> = {
    psql: FAKE_PSQL,
    pg_dump: FAKE_PG_DUMP,
    aws: FAKE_AWS,
    sleep: FAKE_SLEEP,
  };
  for (const [name, body] of Object.entries(fakes)) {
    writeFileSync(path.join(bin, name), body);
    chmodSync(path.join(bin, name), 0o755);
  }
  if (opts.fails) writeFileSync(path.join(work, 'fails'), `${opts.fails}\n`);
  for (let i = 0; i < (opts.oldDumps ?? 0); i++)
    writeFileSync(path.join(out, `freesocks-freesocks_test-2026010${i}T000000Z.sql.gz`), 'old');
  const res = spawnSync('sh', [script], {
    encoding: 'utf8',
    env: {
      PATH: `${bin}:${process.env.PATH}`,
      WORK: work,
      BACKUP_DIR: out,
      POSTGRES_DB: 'freesocks_test',
      POSTGRES_PASSWORD: 'pw',
      BACKUP_ALLOW_UNENCRYPTED: 'true',
      ...env,
    },
  });
  const sleeps = () =>
    readFileSync(path.join(work, 'sleeps'), 'utf8').trim().split('\n').map(Number);
  const dumps = () => readdirSync(out).filter((f) => f.startsWith('freesocks-'));
  return { res, sleeps, dumps, heartbeat: () => existsSync(path.join(out, '.heartbeat')) };
}

describe('docker/backup.sh', () => {
  test('a failed cycle retries soon, backing off up to the interval; a success resets', () => {
    // Four failed cycles, then a good one, then one more wait to stop the loop.
    const { res, sleeps, heartbeat } = run(
      {
        BACKUP_ALLOW_LOCAL_ONLY: 'true',
        BACKUP_INTERVAL_SECONDS: '2000',
        BACKUP_RETRY_SECONDS: '300',
        SLEEPS: '6',
      },
      { fails: 4 },
    );
    expect(sleeps()).toEqual([300, 600, 1200, 2000, 2000, 2000]);
    expect(res.stderr).toContain('retrying in 300s');
    expect(heartbeat()).toBe(true);
  });

  test('the first retry is never longer than the interval', () => {
    const { sleeps } = run(
      {
        BACKUP_ALLOW_LOCAL_ONLY: 'true',
        BACKUP_INTERVAL_SECONDS: '100',
        BACKUP_RETRY_SECONDS: '300',
        SLEEPS: '2',
      },
      { fails: 2 },
    );
    expect(sleeps()).toEqual([100, 100]);
  });

  test('a failed offsite upload keeps the heartbeat untouched and prunes local dumps', () => {
    const { res, sleeps, dumps, heartbeat } = run(
      {
        S3_ENDPOINT: 'https://s3.example.net',
        S3_BUCKET: 'bucket',
        AWS_EXIT: '1',
        BACKUP_RETENTION: '2',
        BACKUP_RETRY_SECONDS: '300',
        SLEEPS: '3',
      },
      { oldDumps: 3 },
    );
    expect(res.stderr).toContain('offsite upload failed');
    expect(heartbeat()).toBe(false);
    // The failed cycles wrote new dumps next to three old ones: pruned to two.
    expect(dumps().length).toBe(2);
    expect(sleeps()).toEqual([300, 600, 1200]);
  });
});
