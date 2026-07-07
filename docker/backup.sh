#!/usr/bin/env sh
# A3: automated, offsite Postgres backups. Runs as a long-lived sidecar that
# pg_dumps the Convex datastore on an interval and uploads the (optionally
# age-encrypted) dump to S3-compatible object storage, then prunes old local
# copies. A host-disk loss otherwise means losing every account-number hash with
# NO recovery (accounts are anonymous by design).
#
# Restore (documented in docs/beta-deploy.md): fetch a dump, then
#   gunzip -c <dump>.sql.gz | docker compose -f docker-compose.beta.yml exec -T postgres \
#     psql -U convex -d freesocks_beta
# A restore drill should be run before launch and periodically after.
#
# Env (set in .env.beta):
#   POSTGRES_HOST (default postgres), POSTGRES_USER (convex), POSTGRES_DB,
#   POSTGRES_PASSWORD, BACKUP_INTERVAL_SECONDS (default 86400),
#   BACKUP_RETENTION (local copies to keep, default 7),
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
  file="$OUT_DIR/freesocks-${PGDB}-${ts}.sql.gz"
  echo "[backup] dumping ${PGDB} -> ${file}"
  if ! pg_dump -h "$PGHOST" -U "$PGUSER" -d "$PGDB" | gzip -c >"$file"; then
    echo "[backup] ERROR: pg_dump failed" >&2
    rm -f "$file"
    return 1
  fi

  if [ -n "${S3_BUCKET:-}" ] && [ -n "${S3_ENDPOINT:-}" ]; then
    key="${S3_PREFIX:-db-backups}/$(basename "$file")"
    echo "[backup] uploading -> s3://${S3_BUCKET}/${key}"
    if ! aws --endpoint-url "$S3_ENDPOINT" s3 cp "$file" "s3://${S3_BUCKET}/${key}"; then
      echo "[backup] ERROR: offsite upload failed (local copy kept)" >&2
    fi
  else
    echo "[backup] WARNING: S3_* not set; backup is LOCAL ONLY (no offsite copy)" >&2
  fi

  # Prune old local dumps beyond the retention count.
  ls -1t "$OUT_DIR"/freesocks-*.sql.gz 2>/dev/null | tail -n +"$((RETENTION + 1))" | while read -r old; do
    echo "[backup] pruning ${old}"
    rm -f "$old"
  done
}

# Liveness heartbeat: touched at the top of every cycle so the compose
# healthcheck can tell a running loop from a wedged one (a crash-loop is already
# caught by the fail-fast gate + restart policy; this catches a hung dump/upload).
HEARTBEAT="${OUT_DIR}/.heartbeat"

echo "[backup] sidecar up; interval=${INTERVAL}s retention=${RETENTION}"
while true; do
  touch "$HEARTBEAT"
  backup_once || echo "[backup] cycle failed; will retry next interval" >&2
  sleep "$INTERVAL"
done
