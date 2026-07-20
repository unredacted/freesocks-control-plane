#!/usr/bin/env sh
# Restore-verification drill (A3 follow-up): restores the LATEST local dump into
# a SCRATCH database inside the compose postgres, asserts core-table row counts,
# then drops the scratch DB. A backup that has never been restored is not a
# backup — run this before launch and periodically after:
#
#   sh docker/restore-verify.sh
#
# Reads the stack env file (ENV_FILE, default .env.beta — prod: ENV_FILE=.env.prod)
# for POSTGRES_PASSWORD/POSTGRES_DB. If dumps are age-encrypted, point
# AGE_KEY_FILE at a file holding the age PRIVATE key (kept off the host;
# needed only for the drill). Idempotent: the scratch DB is dropped either way.
set -eu

cd "$(dirname "$0")/.."
ENV_FILE="${ENV_FILE:-.env.beta}"
COMPOSE="docker compose --env-file $ENV_FILE -f docker-compose.stack.yml"
SCRATCH="restore_verify_$(date -u +%Y%m%d%H%M%S)"

# shellcheck disable=SC1091
PGDB="$(grep -E '^POSTGRES_DB=' "$ENV_FILE" | cut -d= -f2- || true)"
PGDB="${PGDB:-freesocks_beta}"
export PGPASSWORD="$(grep -E '^POSTGRES_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"

latest="$($COMPOSE exec -T backup sh -c 'ls -1t /backups/freesocks-*.sql.gz* 2>/dev/null | head -1')"
if [ -z "$latest" ]; then
  echo "[restore-verify] FATAL: no dumps found in the backup volume" >&2
  exit 1
fi
echo "[restore-verify] latest dump: $latest"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"; $COMPOSE exec -T postgres psql -U convex -d postgres -c "DROP DATABASE IF EXISTS $SCRATCH" >/dev/null 2>&1 || true' EXIT

$COMPOSE cp "backup:$latest" "$tmp/dump"
dump="$tmp/dump"

if [ "${latest##*.}" = "age" ]; then
  : "${AGE_KEY_FILE:?set AGE_KEY_FILE to the age private-key file for encrypted dumps}"
  age -d -i "$AGE_KEY_FILE" -o "$tmp/dump.sql.gz" "$dump"
  dump="$tmp/dump.sql.gz"
fi

echo "[restore-verify] creating scratch DB $SCRATCH"
$COMPOSE exec -T postgres psql -U convex -d postgres -qAc "CREATE DATABASE $SCRATCH"

echo "[restore-verify] restoring…"
gunzip -c "$dump" | $COMPOSE exec -T postgres psql -U convex -d "$SCRATCH" -q

# Convex keeps every logical table inside internal tables (documents/indexes/…)
# in a schema named after the instance — schemas travel with pg_dump, so locate
# it inside the restored scratch DB and assert it carries document rows.
cx_schema="$($COMPOSE exec -T postgres psql -U convex -d "$SCRATCH" -tAc "SELECT table_schema FROM information_schema.tables WHERE table_name = 'documents' LIMIT 1")"
if [ -z "$cx_schema" ]; then
  echo "[restore-verify] FATAL: restored DB has no Convex 'documents' table — dump does not restore" >&2
  exit 1
fi
docs="$($COMPOSE exec -T postgres psql -U convex -d "$SCRATCH" -tAc "SELECT count(*) FROM \"${cx_schema}\".documents")"

echo "[restore-verify] restored: schema=$cx_schema document rows=$docs"
if [ "${docs:-0}" -lt 1 ] 2>/dev/null; then
  echo "[restore-verify] FATAL: restored DB has no document rows — dump does not restore" >&2
  exit 1
fi
echo "[restore-verify] OK — dump restores cleanly (scratch DB $SCRATCH dropped)"
