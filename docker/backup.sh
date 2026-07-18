#!/usr/bin/env sh
# A3: automated, offsite Postgres backups. Runs as a long-lived sidecar that
# pg_dumps the Convex datastore on an interval and uploads the dump to
# S3-compatible object storage, then prunes old local copies. A host-disk loss
# otherwise means losing every account-number hash with NO recovery (accounts
# are anonymous by design).
#
# Encryption: set BACKUP_AGE_PUBLIC_KEY (an age X25519 recipient, age1...) and
# every dump is encrypted client-side before upload — the S3 bucket then holds
# ciphertext only (the dump contains accountIdHash + live subscription tokens,
# so a bucket compromise must not yield a readable datastore). Keep the age
# PRIVATE key OFF the host (password manager / offline). Restore an encrypted
# dump with `age -d -i key.txt <dump>.sql.gz.age | gunzip -c | psql ...`;
# an unencrypted one with `gunzip -c <dump>.sql.gz | psql ...` (docs/beta-deploy.md).
# A restore drill should be run before launch and periodically after.
#
# Env (set in .env.beta):
#   POSTGRES_HOST (default postgres), POSTGRES_USER (convex), POSTGRES_DB,
#   POSTGRES_PASSWORD, BACKUP_INTERVAL_SECONDS (default 86400),
#   BACKUP_RETENTION (local copies to keep, default 7),
#   BACKUP_AGE_PUBLIC_KEY (age recipient; encrypts dumps before upload),
#   BACKUP_ALLOW_UNENCRYPTED=true (silence the no-encryption warning),
#   and for offsite upload (all required to enable it):
#     S3_ENDPOINT, S3_BUCKET, S3_PREFIX (default db-backups),
#     AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION
set -eu

# Fail-fast gate: accounts are anonymous, so a host-disk loss without an
# offsite copy is unrecoverable. Refuse to run local-only unless the operator
# explicitly accepts the risk (a crash-looping container is impossible to miss
# in `docker compose ps`; a once-a-day WARNING line is easy to).
if [ -z "${S3_BUCKET:-}" ] || [ -z "${S3_ENDPOINT:-}" ]; then
  if [ "${BACKUP_ALLOW_LOCAL_ONLY:-}" != "true" ]; then
    echo "[backup] FATAL: BACKUP_S3_* unset — backups would be LOCAL ONLY and a" >&2
    echo "[backup]        host-disk loss is unrecoverable (anonymous accounts)." >&2
    echo "[backup]        Set the S3_ENDPOINT/S3_BUCKET + AWS_* creds in .env.beta," >&2
    echo "[backup]        or set BACKUP_ALLOW_LOCAL_ONLY=true to accept the risk." >&2
    exit 1
  fi
  echo "[backup] WARNING: BACKUP_ALLOW_LOCAL_ONLY=true — offsite backups DISABLED" >&2
fi
if [ -z "${BACKUP_AGE_PUBLIC_KEY:-}" ] && [ "${BACKUP_ALLOW_UNENCRYPTED:-}" != "true" ]; then
  echo "[backup] WARNING: BACKUP_AGE_PUBLIC_KEY unset — dumps are uploaded UNENCRYPTED" >&2
  echo "[backup]          (they contain accountIdHash + live sub tokens). Set an age" >&2
  echo "[backup]          recipient, or BACKUP_ALLOW_UNENCRYPTED=true to accept this." >&2
fi

PGHOST="${POSTGRES_HOST:-postgres}"
PGUSER="${POSTGRES_USER:-convex}"
PGDB="${POSTGRES_DB:-freesocks_beta}"
export PGPASSWORD="${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD}"
INTERVAL="${BACKUP_INTERVAL_SECONDS:-86400}"
RETENTION="${BACKUP_RETENTION:-7}"
OUT_DIR="${BACKUP_DIR:-/backups}"
mkdir -p "$OUT_DIR"

backup_once() {
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  base="$OUT_DIR/freesocks-${PGDB}-${ts}.sql.gz"
  file="$base"
  if [ -n "${BACKUP_AGE_PUBLIC_KEY:-}" ]; then file="${base}.age"; fi

  # Pre-dump sanity: a mis-pointed PGDB (e.g. INSTANCE_NAME changed without a
  # matching POSTGRES_DB) dumps an EMPTY or WRONG database with an otherwise
  # green heartbeat. `tiers` is seeded by every deploy cutover, so a missing
  # table or a zero-row count means this is not the live datastore — fail the
  # cycle (heartbeat not touched → healthcheck trips).
  tier_count="$(psql -h "$PGHOST" -U "$PGUSER" -d "$PGDB" -tAc 'SELECT count(*) FROM tiers' 2>/dev/null || true)"
  case "$tier_count" in
    ''|*[!0-9]*|0)
      echo "[backup] ERROR: sanity check failed — '${PGDB}.tiers' is missing or empty (count='${tier_count}')." >&2
      echo "[backup]        Is POSTGRES_DB in sync with INSTANCE_NAME? Refusing to dump the wrong DB." >&2
      return 1
      ;;
  esac

  echo "[backup] dumping ${PGDB} -> ${file}"
  if [ -n "${BACKUP_AGE_PUBLIC_KEY:-}" ]; then
    if ! pg_dump -h "$PGHOST" -U "$PGUSER" -d "$PGDB" | gzip -c | age -r "$BACKUP_AGE_PUBLIC_KEY" -o "$file"; then
      echo "[backup] ERROR: pg_dump/encrypt failed" >&2
      rm -f "$file"
      return 1
    fi
  else
    if ! pg_dump -h "$PGHOST" -U "$PGUSER" -d "$PGDB" | gzip -c >"$base"; then
      echo "[backup] ERROR: pg_dump failed" >&2
      rm -f "$base"
      return 1
    fi
  fi

  if [ -n "${S3_BUCKET:-}" ] && [ -n "${S3_ENDPOINT:-}" ]; then
    key="${S3_PREFIX:-db-backups}/$(basename "$file")"
    echo "[backup] uploading -> s3://${S3_BUCKET}/${key}"
    if ! aws --endpoint-url "$S3_ENDPOINT" s3 cp "$file" "s3://${S3_BUCKET}/${key}"; then
      # A failed OFFSITE copy is a failed backup (the local copy is kept): return
      # non-zero so the heartbeat stops and the container reads unhealthy.
      echo "[backup] ERROR: offsite upload failed (local copy kept)" >&2
      return 1
    fi
  else
    echo "[backup] WARNING: S3_* not set; backup is LOCAL ONLY (no offsite copy)" >&2
  fi

  # Prune old local dumps beyond the retention count (both plaintext + .age).
  ls -1t "$OUT_DIR"/freesocks-*.sql.gz* 2>/dev/null | tail -n +"$((RETENTION + 1))" | while read -r old; do
    echo "[backup] pruning ${old}"
    rm -f "$old"
  done
}

# Liveness heartbeat: touched only on a SUCCESSFUL cycle (dump + offsite upload
# when enabled) so the compose healthcheck doubles as the backup-failure alarm —
# a wedged OR silently-failing upload both read unhealthy. (A crash-loop is
# caught by the fail-fast gate + restart policy.)
HEARTBEAT="${OUT_DIR}/.heartbeat"

echo "[backup] sidecar up; interval=${INTERVAL}s retention=${RETENTION}"
while true; do
  if backup_once; then
    touch "$HEARTBEAT"
  else
    echo "[backup] cycle failed; heartbeat NOT touched (healthcheck will trip)" >&2
  fi
  sleep "$INTERVAL"
done
